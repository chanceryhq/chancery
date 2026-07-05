package mcp

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chanceryhq/chancery/internal/policy"
)

// fakeServer answers tools/list with two tools and echoes tools/call.
func fakeServer(t *testing.T, in io.Reader, out io.Writer) {
	t.Helper()
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		var env struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(sc.Bytes(), &env); err != nil {
			continue
		}
		switch env.Method {
		case "tools/list":
			resp, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": json.RawMessage(env.ID),
				"result": map[string]any{"tools": []map[string]any{
					{"name": "echo", "description": "echoes"},
					{"name": "delete_everything", "description": "dangerous"},
				}},
			})
			out.Write(append(resp, '\n'))
		case "tools/call":
			resp, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": json.RawMessage(env.ID),
				"result": map[string]any{"content": []map[string]any{{"type": "text", "text": "done"}}},
			})
			out.Write(append(resp, '\n'))
		}
	}
}

type auditRec struct {
	event, tool, decision, reason string
}

type harness struct {
	toProxy    io.WriteCloser // test writes as the agent
	fromProxy  *bufio.Scanner // test reads as the agent
	mu         sync.Mutex
	auditTrail []auditRec
}

func (h *harness) audits() []auditRec {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]auditRec(nil), h.auditTrail...)
}

func newHarness(t *testing.T, decide Decider) *harness {
	t.Helper()
	clientR, clientW := io.Pipe()       // agent -> proxy
	proxyR, proxyW := io.Pipe()         // proxy -> agent
	serverInR, serverInW := io.Pipe()   // proxy -> server
	serverOutR, serverOutW := io.Pipe() // server -> proxy

	h := &harness{toProxy: clientW, fromProxy: bufio.NewScanner(proxyR)}
	p := &Proxy{
		ClientIn: clientR, ClientOut: proxyW,
		ServerIn: serverInW, ServerOut: serverOutR,
		Server: "srv", Decide: decide,
		Audit: func(event, tool, decision, reason string) error {
			h.mu.Lock()
			h.auditTrail = append(h.auditTrail, auditRec{event, tool, decision, reason})
			h.mu.Unlock()
			return nil
		},
	}
	go fakeServer(t, serverInR, serverOutW)
	go p.Run()
	return h
}

func send(t *testing.T, h *harness, msg string) {
	t.Helper()
	if _, err := io.WriteString(h.toProxy, msg+"\n"); err != nil {
		t.Fatal(err)
	}
}

func recv(t *testing.T, h *harness) map[string]json.RawMessage {
	t.Helper()
	done := make(chan struct{})
	var out map[string]json.RawMessage
	go func() {
		defer close(done)
		if h.fromProxy.Scan() {
			json.Unmarshal(h.fromProxy.Bytes(), &out)
		}
	}()
	select {
	case <-done:
		return out
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for proxy output")
		return nil
	}
}

func allowOnlyEcho(resource string) policy.Decision {
	if resource == "srv/echo" {
		return policy.Decision{Effect: policy.Allow, Layer: "writ", Reason: "lineage user -> agent"}
	}
	return policy.Decision{Effect: policy.Deny, Layer: "writ", Reason: "outside effective authority"}
}

func TestAllowedCallForwards(t *testing.T) {
	h := newHarness(t, allowOnlyEcho)
	send(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}`)
	resp := recv(t, h)
	if resp["result"] == nil {
		t.Fatalf("allowed call must reach the server and return a result: %v", resp)
	}
	found := false
	for _, a := range h.audits() {
		if a.event == "mcp.call" && a.tool == "srv/echo" && a.decision == "ALLOW" {
			found = true
		}
	}
	if !found {
		t.Error("allowed call must be audited")
	}
}

func TestDeniedCallBlockedWithJSONRPCError(t *testing.T) {
	h := newHarness(t, allowOnlyEcho)
	send(t, h, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_everything"}}`)
	resp := recv(t, h)
	if resp["error"] == nil {
		t.Fatalf("denied call must return a JSON-RPC error: %v", resp)
	}
	var e struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	json.Unmarshal(resp["error"], &e)
	if e.Code != DeniedCode {
		t.Errorf("error code = %d, want %d", e.Code, DeniedCode)
	}
	if !strings.Contains(e.Message, "denied by writ policy") {
		t.Errorf("denial must name the deciding layer: %q", e.Message)
	}
	for _, a := range h.audits() {
		if a.event == "mcp.call" && a.decision == "DENY" && a.tool == "srv/delete_everything" {
			return
		}
	}
	t.Error("denied call must be audited")
}

func TestToolsListFiltered(t *testing.T) {
	h := newHarness(t, allowOnlyEcho)
	send(t, h, `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
	resp := recv(t, h)
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp["result"], &result); err != nil {
		t.Fatalf("bad list result: %v", err)
	}
	if len(result.Tools) != 1 || result.Tools[0].Name != "echo" {
		t.Errorf("model must only see admitted tools, got %+v", result.Tools)
	}
}

func TestUnlistedToolStillEnforced(t *testing.T) {
	// Filtering is UX; the call path is the boundary: calling a tool the
	// PDP denies must fail even if the client never listed.
	h := newHarness(t, allowOnlyEcho)
	send(t, h, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"delete_everything"}}`)
	resp := recv(t, h)
	if resp["error"] == nil {
		t.Fatal("unlisted-but-denied tool must still be blocked at tools/call")
	}
}

func TestMalformedClientFrameDropped(t *testing.T) {
	h := newHarness(t, allowOnlyEcho)
	send(t, h, `{"jsonrpc":"2.0", this is not json`)
	// The proxy must survive and keep serving.
	send(t, h, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo"}}`)
	resp := recv(t, h)
	if resp["result"] == nil {
		t.Fatal("proxy must keep working after a malformed frame")
	}
	found := false
	for _, a := range h.audits() {
		if a.event == "mcp.malformed" {
			found = true
		}
	}
	if !found {
		t.Error("malformed frame must be audited")
	}
}

func TestCallWithoutToolNameDenied(t *testing.T) {
	h := newHarness(t, allowOnlyEcho)
	send(t, h, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}}`)
	resp := recv(t, h)
	if resp["error"] == nil {
		t.Fatal("tools/call without a name must be denied, not forwarded")
	}
}

func TestNonToolTrafficPassesThrough(t *testing.T) {
	// initialize must reach the server untouched even under a
	// deny-everything decider.
	h := newHarness(t, func(string) policy.Decision {
		return policy.Decision{Effect: policy.Deny, Layer: "writ", Reason: "no"}
	})
	send(t, h, `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	resp := recv(t, h)
	if resp["result"] == nil {
		t.Fatal("tools/list must pass through (filtered), not be blocked")
	}
	var result struct {
		Tools []any `json:"tools"`
	}
	json.Unmarshal(resp["result"], &result)
	if len(result.Tools) != 0 {
		t.Errorf("deny-all decider must hide every tool, got %d", len(result.Tools))
	}
}

func TestAuditFailureDeniesAllowedCall(t *testing.T) {
	// RFC-006 §7: an unrecordable action does not happen. Even a call the
	// PDP allows must be denied if the audit record cannot be written.
	clientR, clientW := io.Pipe()
	proxyR, proxyW := io.Pipe()
	serverInR, serverInW := io.Pipe()
	serverOutR, serverOutW := io.Pipe()
	_ = serverInR
	_ = serverOutW

	p := &Proxy{
		ClientIn: clientR, ClientOut: proxyW,
		ServerIn: serverInW, ServerOut: serverOutR,
		Server: "srv", Decide: allowOnlyEcho,
		Audit: func(event, tool, decision, reason string) error {
			if decision == "ALLOW" {
				return io.ErrClosedPipe // simulate audit store down
			}
			return nil
		},
	}
	go p.Run()

	go io.WriteString(clientW, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`+"\n")
	sc := bufio.NewScanner(proxyR)
	done := make(chan map[string]json.RawMessage, 1)
	go func() {
		var out map[string]json.RawMessage
		if sc.Scan() {
			json.Unmarshal(sc.Bytes(), &out)
		}
		done <- out
	}()
	select {
	case resp := <-done:
		if resp["error"] == nil {
			t.Fatalf("allowed-but-unauditable call must be denied: %v", resp)
		}
		var e struct {
			Message string `json:"message"`
		}
		json.Unmarshal(resp["error"], &e)
		if !strings.Contains(e.Message, "audit") {
			t.Errorf("denial must name the audit layer: %q", e.Message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

// --- RFC-013: the URL guard ---

func newNetHarness(t *testing.T, decide, netDecide Decider) *harness {
	t.Helper()
	clientR, clientW := io.Pipe()
	proxyR, proxyW := io.Pipe()
	serverInR, serverInW := io.Pipe()
	serverOutR, serverOutW := io.Pipe()
	h := &harness{toProxy: clientW, fromProxy: bufio.NewScanner(proxyR)}
	p := &Proxy{
		ClientIn: clientR, ClientOut: proxyW,
		ServerIn: serverInW, ServerOut: serverOutR,
		Server: "browser", Decide: decide, NetDecide: netDecide,
		Audit: func(event, tool, decision, reason string) error {
			h.mu.Lock()
			h.auditTrail = append(h.auditTrail, auditRec{event, tool, decision, reason})
			h.mu.Unlock()
			return nil
		},
	}
	go fakeServer(t, serverInR, serverOutW)
	go p.Run()
	return h
}

func TestURLToResource(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"https://GitHub.com/Acme/Repo?token=secret#frag", "github.com/acme/repo", false},
		{"https://mail.google.com/", "mail.google.com", false},
		{"http://example.com/a/b/", "example.com/a/b", false},
		{"file:///etc/passwd", "", true},                     // non-http scheme
		{"https://user:pass@github.com/x", "", true},         // userinfo smuggling
		{"https://", "", true},                               // empty host
		{"javascript:alert(1)", "", true},                    // non-http scheme
	}
	for _, c := range cases {
		got, err := URLToResource(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("URLToResource(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("URLToResource(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestNetGuardScopesNavigation(t *testing.T) {
	allowAllTools := func(resource string) policy.Decision {
		return policy.Decision{Effect: policy.Allow, Layer: "writ", Reason: "ok"}
	}
	onlyGithub := func(resource string) policy.Decision {
		if strings.HasPrefix(resource, "github.com") {
			return policy.Decision{Effect: policy.Allow, Layer: "writ", Reason: "net ok"}
		}
		return policy.Decision{Effect: policy.Deny, Layer: "writ", Reason: "outside net authority"}
	}
	h := newNetHarness(t, allowAllTools, onlyGithub)

	// Allowed destination: forwarded, result comes back.
	send(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"navigate","arguments":{"url":"https://github.com/acme/repo"}}}`)
	if out := recv(t, h); out["result"] == nil {
		t.Fatalf("allowed navigation must reach the server, got %v", out)
	}

	// Denied destination: JSON-RPC error, never reaches the server.
	send(t, h, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"navigate","arguments":{"url":"https://evil.com/exfil"}}}`)
	out := recv(t, h)
	if out["error"] == nil || !strings.Contains(string(out["error"]), "navigation denied") {
		t.Fatalf("denied navigation must return the -32001 error, got %v", out)
	}

	// Unexpressable URL: fail closed, not fail open.
	send(t, h, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"navigate","arguments":{"url":"file:///etc/passwd"}}}`)
	if out := recv(t, h); out["error"] == nil {
		t.Fatalf("non-http url must be denied, got %v", out)
	}

	// A call with no url argument is untouched by the guard.
	send(t, h, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"screenshot","arguments":{}}}`)
	if out := recv(t, h); out["result"] == nil {
		t.Fatalf("url-less call must pass, got %v", out)
	}

	// Audit shows both net outcomes with query strings stripped.
	sawAllow, sawDeny := false, false
	for _, a := range h.audits() {
		if a.event == "mcp.net" && a.decision == "ALLOW" && a.tool == "github.com/acme/repo" {
			sawAllow = true
		}
		if a.event == "mcp.net" && a.decision == "DENY" && a.tool == "evil.com/exfil" {
			sawDeny = true
		}
	}
	if !sawAllow || !sawDeny {
		t.Errorf("net decisions must be audited (allow=%v deny=%v): %+v", sawAllow, sawDeny, h.audits())
	}
}

func TestNoNetGuardMeansNoURLChecks(t *testing.T) {
	// Guard off (writ grants no net caps): url arguments pass untouched —
	// backward compatible with call-only writs.
	h := newHarness(t, func(string) policy.Decision {
		return policy.Decision{Effect: policy.Allow, Layer: "writ", Reason: "ok"}
	})
	send(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"url":"https://anywhere.example/x"}}}`)
	if out := recv(t, h); out["result"] == nil {
		t.Fatalf("without a net guard, url args must not be evaluated, got %v", out)
	}
}

func TestNetGuardDenialAuditsNoQueryStrings(t *testing.T) {
	// D6 at the guard: even an unexpressable URL's audit trail must not
	// carry query-string payload.
	h := newNetHarness(t,
		func(string) policy.Decision { return policy.Decision{Effect: policy.Allow, Layer: "writ", Reason: "ok"} },
		func(string) policy.Decision { return policy.Decision{Effect: policy.Deny, Layer: "writ", Reason: "no"} })
	send(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"navigate","arguments":{"url":"ftp://host/p?apikey=hunter2"}}}`)
	if out := recv(t, h); out["error"] == nil {
		t.Fatalf("ftp url must be denied, got %v", out)
	}
	for _, a := range h.audits() {
		if strings.Contains(a.tool, "hunter2") || strings.Contains(a.reason, "hunter2") {
			t.Errorf("query payload leaked into audit: %+v", a)
		}
	}
}
