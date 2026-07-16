// Package mcp implements RFC-005's MVP enforcement point: a
// newline-delimited JSON-RPC stdio proxy between an MCP client (the
// agent) and an MCP server. Every tools/call passes the PDP with fresh
// registry state; tools/list responses are filtered to what policy
// admits; everything else passes through untouched. Payloads are never
// parsed beyond the envelope needed for the decision (method, id, tool
// name) and never stored.
package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	"github.com/chanceryhq/chancery/internal/policy"
)

// DeniedCode is Chancery's JSON-RPC error code for policy denials.
const DeniedCode = -32001

// maxFrame caps client-side envelopes (RFC-005 §7). Server frames are
// forwarded regardless — we do not corrupt streams we don't understand.
const maxFrame = 10 * 1024 * 1024

// Decider evaluates one concrete tool resource ("<ns>/<tool>") with
// fresh registry state. It is called per action — this is where
// revocation becomes "next call" instead of "next token expiry".
type Decider func(resource string) policy.Decision

// AuditFn records a decision or protocol event. Metadata only. An error
// from AuditFn on the allow path DENIES the action (RFC-006 §7): an
// unrecordable action does not happen.
type AuditFn func(event, tool, decision, reason string) error

type Proxy struct {
	ClientIn  io.Reader // from the agent
	ClientOut io.Writer // to the agent
	ServerIn  io.Writer // to the server's stdin
	ServerOut io.Reader // from the server's stdout
	Server    string    // namespace: resources are "<Server>/<tool>"
	Decide    Decider
	Audit     AuditFn
	// NetDecide, when non-nil, is the browser/URL guard (RFC-013): any
	// tools/call whose arguments carry a "url"/"uri" string is
	// additionally checked as net:<host>/<path> — per-navigation
	// scoping at the same boundary. nil = guard off.
	NetDecide Decider
	// Intent, when non-nil, is the intent socket (RFC-017): an external
	// checker consulted after every deterministic layer allows. It is
	// the only layer shown tool arguments (transiently — never stored).
	// IntentAdvise makes a checker DENY log-only instead of blocking.
	Intent       func(tool string, args map[string]json.RawMessage) policy.Decision
	IntentAdvise bool
	// Lease, when non-nil, mints a capability lease (RFC-015) for each
	// ADMITTED call, injected as params._meta["chancery/lease"] on the
	// forwarded frame. Cooperating servers verify it before committing
	// side effects; non-cooperating servers ignore _meta. Additive: a
	// minting failure forwards the original frame — the admission gate
	// above remains the floor.
	Lease func(resource string) (string, error)

	mu          sync.Mutex // guards ClientOut (both loops write to it)
	pendingList sync.Map   // request id (raw) -> struct{}: outstanding tools/list
	pendingCall sync.Map   // request id (raw) -> resource: admitted tools/call awaiting result
}

type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func (p *Proxy) writeClient(line []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.ClientOut.Write(append(line, '\n'))
	return err
}

func (p *Proxy) audit(event, tool, decision, reason string) error {
	if p.Audit == nil {
		return nil
	}
	return p.Audit(event, tool, decision, reason)
}

// Run pumps both directions until either side closes. The returned error
// is the first transport error, or nil on clean EOF.
func (p *Proxy) Run() error {
	errc := make(chan error, 2)
	go func() { errc <- p.clientLoop() }()
	go func() { errc <- p.serverLoop() }()
	return <-errc
}

// clientLoop is the security boundary: agent -> server traffic.
func (p *Proxy) clientLoop() error {
	sc := bufio.NewScanner(p.ClientIn)
	sc.Buffer(make([]byte, 64*1024), maxFrame)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if len(line) == 0 {
			continue
		}
		var env envelope
		if err := json.Unmarshal(line, &env); err != nil {
			// A confused or malicious model gets no partial-parse
			// gadget: drop, audit, continue (RFC-005 §7).
			p.audit("mcp.malformed", "", "drop", "unparseable client frame")
			continue
		}
		switch env.Method {
		case "tools/call":
			var params struct {
				Name      string                     `json:"name"`
				Arguments map[string]json.RawMessage `json:"arguments"`
			}
			if err := json.Unmarshal(env.Params, &params); err != nil || params.Name == "" {
				p.deny(env.ID, params.Name, policy.Decision{
					Effect: policy.Deny, Layer: "grammar", Reason: "tools/call without a tool name"})
				continue
			}
			resource := p.Server + "/" + params.Name
			d := p.Decide(resource)
			if d.Effect != policy.Allow {
				p.deny(env.ID, params.Name, d)
				continue
			}
			// URL guard (RFC-013): the tool is allowed — is the
			// destination? Checked against the writ's net capabilities;
			// fail closed on URLs the grammar cannot express.
			if p.NetDecide != nil {
				if blocked := p.checkNet(env.ID, params.Name, params.Arguments); blocked {
					continue
				}
			}
			// Intent socket (RFC-017): consulted last, veto only. In
			// advise mode a DENY is recorded but the call proceeds — how
			// an operator measures a checker before trusting it.
			if p.Intent != nil {
				if blocked := p.checkIntent(env.ID, params.Name, resource, params.Arguments); blocked {
					continue
				}
			}
			// Audit BEFORE forwarding: if the record cannot be written,
			// the action does not happen (RFC-006 §7). This is the
			// "admitted" lifecycle state (RFC-015); the result lands as
			// mcp.call_result (committed/failed) when the server answers.
			if err := p.audit("mcp.call", resource, "ALLOW", d.Reason); err != nil {
				p.deny(env.ID, params.Name, policy.Decision{
					Effect: policy.Deny, Layer: "audit",
					Reason: "audit unavailable; refusing unrecordable action"})
				continue
			}
			if env.ID != nil {
				p.pendingCall.Store(string(env.ID), resource)
			}
			// Capability lease (RFC-015): stamp the admitted call so a
			// cooperating server can re-verify liveness before the side
			// effect commits.
			if p.Lease != nil {
				if stamped := p.stampLease(line, resource); stamped != nil {
					line = stamped
				}
			}
		case "tools/list":
			if env.ID != nil {
				p.pendingList.Store(string(env.ID), struct{}{})
			}
		}
		if _, err := p.ServerIn.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return sc.Err()
}

// checkIntent consults the external intent checker (RFC-017) and
// returns true if the call was blocked. Verdicts and infrastructure
// failures audit as different events (a model's DENY and a broken
// checker are different facts); neither ever records the arguments.
func (p *Proxy) checkIntent(id json.RawMessage, tool, resource string, args map[string]json.RawMessage) bool {
	d := p.Intent(resource, args)
	if d.Effect == policy.Allow {
		return false
	}
	event := "mcp.intent_deny"
	if d.Layer == LayerIntentError {
		event = "mcp.intent_error"
	}
	if p.IntentAdvise {
		// Advise: record what WOULD have been blocked, let it pass.
		p.audit(event, resource, "ALLOW", "[advise] "+d.Reason)
		return false
	}
	p.audit(event, resource, "DENY", d.Reason)
	if id == nil {
		return true
	}
	resp, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]any{
			"code":    DeniedCode,
			"message": fmt.Sprintf("chancery: denied by %s policy: %s", d.Layer, d.Reason),
		},
	})
	p.writeClient(resp)
	return true
}

// urlArgKeys are the argument names the URL guard inspects. Browser
// MCP servers (Playwright, Puppeteer, fetch) all take the destination
// as a top-level "url" (occasionally "uri") string argument.
var urlArgKeys = []string{"url", "uri"}

// checkNet evaluates every URL argument as net:<host>/<path> and denies
// the call if any is outside the writ's net authority. Returns true if
// the call was blocked. Unexpressable URLs are DENIED, not skipped:
// a guard that can be confused into silence is not a guard.
func (p *Proxy) checkNet(id json.RawMessage, tool string, args map[string]json.RawMessage) bool {
	for _, key := range urlArgKeys {
		raw, ok := args[key]
		if !ok {
			continue
		}
		var u string
		if err := json.Unmarshal(raw, &u); err != nil {
			continue // not a string: nothing navigable
		}
		res, err := URLToResource(u)
		if err != nil {
			// Audit the scheme+host shape only — a raw URL can carry
			// query-string secrets, and audit is metadata-only (D6).
			safe, _, _ := strings.Cut(u, "?")
			if len(safe) > 128 {
				safe = safe[:128]
			}
			p.denyNet(id, tool, safe, policy.Decision{Effect: policy.Deny, Layer: "grammar",
				Reason: "url not expressible in the capability grammar: " + err.Error()})
			return true
		}
		if d := p.NetDecide(res); d.Effect != policy.Allow {
			p.denyNet(id, tool, res, d)
			return true
		}
		p.audit("mcp.net", res, "ALLOW", "tool="+p.Server+"/"+tool)
	}
	return false
}

// denyNet answers a URL-guard denial, auditing the net resource (host/
// path only — query strings and fragments are payload and never leave
// URLToResource).
func (p *Proxy) denyNet(id json.RawMessage, tool, res string, d policy.Decision) {
	p.audit("mcp.net", res, "DENY", "["+d.Layer+"] "+d.Reason+" tool="+p.Server+"/"+tool)
	if id == nil {
		return
	}
	resp, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]any{
			"code":    DeniedCode,
			"message": fmt.Sprintf("chancery: navigation denied by %s policy: %s", d.Layer, d.Reason),
		},
	})
	p.writeClient(resp)
}

// URLToResource maps a URL to a net-verb resource: lowercased host,
// then path segments — "https://GitHub.com/acme/repo?x=1#f" →
// "github.com/acme/repo". Query strings, fragments, and userinfo are
// dropped (payload, never policy or audit material). Errors on
// anything the capability grammar cannot express — schemes other than
// http(s), empty hosts, credentials in the URL, or path characters
// outside [a-z0-9_.-] after lowercasing.
func URLToResource(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("scheme %q is not http(s)", u.Scheme)
	}
	if u.User != nil {
		return "", errors.New("userinfo in url")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("empty host")
	}
	res := host
	for _, seg := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if seg == "" {
			continue
		}
		res += "/" + strings.ToLower(seg)
	}
	if err := policy.ValidateResource(res); err != nil {
		return "", err
	}
	return res, nil
}

// deny answers a tools/call with a protocol-native JSON-RPC error and
// audits the decision. The layer travels in the message; sealed names
// and values never do.
func (p *Proxy) deny(id json.RawMessage, tool string, d policy.Decision) {
	p.audit("mcp.call", p.Server+"/"+tool, "DENY", "["+d.Layer+"] "+d.Reason)
	if id == nil {
		return // notification-style call: nothing to answer
	}
	resp, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]any{
			"code":    DeniedCode,
			"message": fmt.Sprintf("chancery: denied by %s policy: %s", d.Layer, d.Reason),
		},
	})
	p.writeClient(resp)
}

// stampLease mints a lease for an admitted call and injects it into
// params._meta["chancery/lease"] on the outgoing frame. Returns nil on
// any failure — the lease is additive (RFC-015); the original frame
// then forwards unmodified and admission-time enforcement stands alone.
func (p *Proxy) stampLease(line []byte, resource string) []byte {
	lease, err := p.Lease(resource)
	if err != nil {
		return nil
	}
	var full map[string]json.RawMessage
	if err := json.Unmarshal(line, &full); err != nil {
		return nil
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(full["params"], &params); err != nil {
		return nil
	}
	meta := map[string]json.RawMessage{}
	if raw, ok := params["_meta"]; ok {
		json.Unmarshal(raw, &meta)
	}
	leaseJSON, _ := json.Marshal(lease)
	meta["chancery/lease"] = leaseJSON
	metaRaw, err := json.Marshal(meta)
	if err != nil {
		return nil
	}
	params["_meta"] = metaRaw
	paramsRaw, err := json.Marshal(params)
	if err != nil {
		return nil
	}
	full["params"] = paramsRaw
	out, err := json.Marshal(full)
	if err != nil {
		return nil
	}
	return out
}

// serverLoop forwards server -> agent traffic, filtering tools/list
// results to what the PDP admits and recording call lifecycle results
// (RFC-015: admitted ≠ happened).
func (p *Proxy) serverLoop() error {
	sc := bufio.NewScanner(p.ServerOut)
	sc.Buffer(make([]byte, 64*1024), maxFrame)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if len(line) == 0 {
			continue
		}
		var env envelope
		if err := json.Unmarshal(line, &env); err == nil && env.ID != nil {
			// Lifecycle result for an admitted call: committed (result)
			// or failed (error). Best-effort record — the action already
			// happened; there is nothing left to deny.
			if res, ok := p.pendingCall.LoadAndDelete(string(env.ID)); ok {
				if env.Error != nil {
					p.audit("mcp.call_result", res.(string), "", "failed")
				} else {
					p.audit("mcp.call_result", res.(string), "", "committed")
				}
			}
			if env.Result != nil {
				if _, ok := p.pendingList.LoadAndDelete(string(env.ID)); ok {
					if filtered, n := p.filterToolList(line, env); filtered != nil {
						p.audit("mcp.list_filtered", "", "", fmt.Sprintf("hidden=%d", n))
						if err := p.writeClient(filtered); err != nil {
							return err
						}
						continue
					}
				}
			}
		}
		if err := p.writeClient(line); err != nil {
			return err
		}
	}
	return sc.Err()
}

// filterToolList removes tools the PDP would deny from a tools/list
// result. Filtering is UX; tools/call enforcement is the boundary.
// On any shape surprise it returns (nil, 0) and the frame passes as-is.
func (p *Proxy) filterToolList(line []byte, env envelope) ([]byte, int) {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(env.Result, &result); err != nil {
		return nil, 0
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(result["tools"], &tools); err != nil {
		return nil, 0
	}
	kept := make([]json.RawMessage, 0, len(tools))
	hidden := 0
	for _, t := range tools {
		var meta struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(t, &meta); err != nil || meta.Name == "" {
			kept = append(kept, t) // unknown shape: do not silently hide
			continue
		}
		if d := p.Decide(p.Server + "/" + meta.Name); d.Effect == policy.Allow {
			kept = append(kept, t)
		} else {
			hidden++
		}
	}
	if hidden == 0 {
		return nil, 0
	}
	newTools, err := json.Marshal(kept)
	if err != nil {
		return nil, 0
	}
	result["tools"] = newTools
	newResult, err := json.Marshal(result)
	if err != nil {
		return nil, 0
	}
	var full map[string]json.RawMessage
	if err := json.Unmarshal(line, &full); err != nil {
		return nil, 0
	}
	full["result"] = newResult
	out, err := json.Marshal(full)
	if err != nil {
		return nil, 0
	}
	return out, hidden
}
