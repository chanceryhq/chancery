package mcp

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/chanceryhq/chancery/internal/policy"
)

// newIntentHarness wires a proxy with the intent socket configured.
func newIntentHarness(t *testing.T, decide Decider,
	intent func(string, map[string]json.RawMessage) policy.Decision, advise bool) *harness {
	t.Helper()
	clientR, clientW := io.Pipe()
	proxyR, proxyW := io.Pipe()
	serverInR, serverInW := io.Pipe()
	serverOutR, serverOutW := io.Pipe()

	h := &harness{toProxy: clientW, fromProxy: bufio.NewScanner(proxyR)}
	p := &Proxy{
		ClientIn: clientR, ClientOut: proxyW,
		ServerIn: serverInW, ServerOut: serverOutR,
		Server: "srv", Decide: decide,
		Intent: intent, IntentAdvise: advise,
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

func allowAll(resource string) policy.Decision {
	return policy.Decision{Effect: policy.Allow, Layer: "writ", Reason: "test"}
}

// TestIntentVetoBlocksAllowedCall: the writ allows, the checker denies —
// enforce mode blocks with -32001 and audits mcp.intent_deny. The
// checker is veto-only, layered after the deterministic checks.
func TestIntentVetoBlocksAllowedCall(t *testing.T) {
	checker := &IntentChecker{
		Cmd:   `read IN; echo '{"decision":"DENY","reason":"write op under read task"}'`,
		Agent: "bot", Task: "read some numbers", Timeout: 5 * time.Second,
	}
	h := newIntentHarness(t, allowAll, checker.Decide, false)
	send(t, h, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"sql":"DELETE FROM orders"}}}`)
	resp := recv(t, h)
	if resp["error"] == nil {
		t.Fatalf("intent-denied call must be blocked: %v", resp)
	}
	if !strings.Contains(string(resp["error"]), "write op under read task") {
		t.Errorf("denial must carry the checker's reason: %s", resp["error"])
	}
	found := false
	for _, a := range h.audits() {
		if a.event == "mcp.intent_deny" && a.decision == "DENY" {
			found = true
			if strings.Contains(a.reason, "DELETE FROM") {
				t.Error("audit must never record call arguments")
			}
		}
	}
	if !found {
		t.Error("intent denial must audit as mcp.intent_deny")
	}
}

// TestIntentAdviseLogsAndProceeds: advise mode records what would have
// been blocked and lets the call through — how a checker is measured
// before it earns a veto.
func TestIntentAdviseLogsAndProceeds(t *testing.T) {
	checker := &IntentChecker{
		Cmd:   `read IN; echo '{"decision":"DENY","reason":"suspicious"}'`,
		Agent: "bot", Timeout: 5 * time.Second,
	}
	h := newIntentHarness(t, allowAll, checker.Decide, true)
	send(t, h, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"echo","arguments":{}}}`)
	resp := recv(t, h)
	if resp["result"] == nil {
		t.Fatalf("advise mode must let the call proceed: %v", resp)
	}
	found := false
	for _, a := range h.audits() {
		if a.event == "mcp.intent_deny" && a.decision == "ALLOW" && strings.Contains(a.reason, "[advise]") {
			found = true
		}
	}
	if !found {
		t.Errorf("advise verdict must be recorded: %v", h.audits())
	}
}

// TestIntentCheckerFailureFailsClosed: a broken checker in enforce mode
// denies (fail closed) and audits mcp.intent_error — infrastructure
// failure is a different fact than a verdict.
func TestIntentCheckerFailureFailsClosed(t *testing.T) {
	checker := &IntentChecker{Cmd: `exit 1`, Agent: "bot", Timeout: 5 * time.Second}
	h := newIntentHarness(t, allowAll, checker.Decide, false)
	send(t, h, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{}}}`)
	resp := recv(t, h)
	if resp["error"] == nil {
		t.Fatalf("failed checker in enforce mode must deny: %v", resp)
	}
	found := false
	for _, a := range h.audits() {
		if a.event == "mcp.intent_error" && a.decision == "DENY" {
			found = true
		}
	}
	if !found {
		t.Errorf("checker failure must audit as mcp.intent_error: %v", h.audits())
	}
}

// TestIntentCheckerReceivesTaskToolArgs: the checker's stdin carries
// agent, task, tool, and the raw arguments — the context contract.
func TestIntentCheckerReceivesTaskToolArgs(t *testing.T) {
	// The checker allows iff its input mentions both the task and the
	// argument value — proving the contract end to end.
	checker := &IntentChecker{
		Cmd: `IN=$(cat); case "$IN" in *"review PR #123"*"srv/echo"*"payload-42"*) ` +
			`echo '{"decision":"ALLOW","reason":"ok"}';; *) echo '{"decision":"DENY","reason":"missing context"}';; esac`,
		Agent: "bot", Task: "review PR #123", Timeout: 5 * time.Second,
	}
	h := newIntentHarness(t, allowAll, checker.Decide, false)
	send(t, h, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"echo","arguments":{"v":"payload-42"}}}`)
	resp := recv(t, h)
	if resp["result"] == nil {
		t.Fatalf("checker did not receive the full context contract: %v", resp)
	}
}

// Call lifecycle (RFC-015): an admitted call gets a result event —
// committed on success — so the log distinguishes "allowed" from
// "happened".
func TestCallResultLifecycleAudited(t *testing.T) {
	h := newIntentHarness(t, allowAll, nil, false)
	send(t, h, `{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"echo","arguments":{}}}`)
	resp := recv(t, h)
	if resp["result"] == nil {
		t.Fatalf("call should succeed: %v", resp)
	}
	admitted, committed := false, false
	for _, a := range h.audits() {
		if a.event == "mcp.call" && a.decision == "ALLOW" {
			admitted = true
		}
		if a.event == "mcp.call_result" && a.reason == "committed" {
			committed = true
		}
	}
	if !admitted || !committed {
		t.Errorf("want admitted+committed lifecycle, got %v", h.audits())
	}
}

// Lease stamping (RFC-015): the forwarded frame carries the lease in
// params._meta["chancery/lease"]; the client-side frame is unchanged.
func TestLeaseStampedOnForwardedFrame(t *testing.T) {
	clientR, clientW := io.Pipe()
	proxyR, proxyW := io.Pipe()
	serverInR, serverInW := io.Pipe()
	_, serverOutR := io.Pipe()
	_ = serverOutR

	seen := make(chan []byte, 1)
	go func() { // capture what the SERVER receives
		sc := bufio.NewScanner(serverInR)
		for sc.Scan() {
			b := append([]byte(nil), sc.Bytes()...)
			seen <- b
			return
		}
	}()
	p := &Proxy{
		ClientIn: clientR, ClientOut: proxyW,
		ServerIn: serverInW, ServerOut: strings.NewReader(""),
		Server: "srv", Decide: allowAll,
		Lease: func(resource string) (string, error) { return "LEASE-TOKEN-" + resource, nil },
		Audit: func(e, t, d, r string) error { return nil },
	}
	go p.Run()
	go io.Copy(io.Discard, proxyR)
	io.WriteString(clientW, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}`+"\n")

	select {
	case frame := <-seen:
		var env struct {
			Params struct {
				Meta map[string]string          `json:"_meta"`
				Args map[string]json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		if err := json.Unmarshal(frame, &env); err != nil {
			t.Fatalf("server frame unparseable: %v\n%s", err, frame)
		}
		if env.Params.Meta["chancery/lease"] != "LEASE-TOKEN-srv/echo" {
			t.Errorf("lease not stamped: %s", frame)
		}
		if string(env.Params.Args["x"]) != "1" {
			t.Errorf("arguments must survive stamping: %s", frame)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never received the frame")
	}
}
