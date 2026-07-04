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
	"fmt"
	"io"
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

// AuditFn records a decision or protocol event. Metadata only.
type AuditFn func(event, tool, decision, reason string)

type Proxy struct {
	ClientIn  io.Reader // from the agent
	ClientOut io.Writer // to the agent
	ServerIn  io.Writer // to the server's stdin
	ServerOut io.Reader // from the server's stdout
	Server    string    // namespace: resources are "<Server>/<tool>"
	Decide    Decider
	Audit     AuditFn

	mu          sync.Mutex // guards ClientOut (both loops write to it)
	pendingList sync.Map   // request id (raw) -> struct{}: outstanding tools/list
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

func (p *Proxy) audit(event, tool, decision, reason string) {
	if p.Audit != nil {
		p.Audit(event, tool, decision, reason)
	}
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
				Name string `json:"name"`
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
			p.audit("mcp.call", resource, "ALLOW", d.Reason)
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

// serverLoop forwards server -> agent traffic, filtering tools/list
// results to what the PDP admits.
func (p *Proxy) serverLoop() error {
	sc := bufio.NewScanner(p.ServerOut)
	sc.Buffer(make([]byte, 64*1024), maxFrame)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if len(line) == 0 {
			continue
		}
		var env envelope
		if err := json.Unmarshal(line, &env); err == nil && env.ID != nil && env.Result != nil {
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
