package main

// End-to-end test of `chancery mcp wrap` driving a real child MCP server
// process over stdio (a small Go stub built by the test — no external
// deps, CI-safe). Proves the RFC-005 enforcement path: list filtering,
// allow, policy deny, and mid-session revocation, all against a genuine
// separate process the proxy spawns and owns.

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubServerSource is a minimal MCP stdio server compiled by the test.
const stubServerSource = `package main

import (
	"bufio"
	"encoding/json"
	"os"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	out := json.NewEncoder(os.Stdout)
	for sc.Scan() {
		var req map[string]any
		if json.Unmarshal(sc.Bytes(), &req) != nil {
			continue
		}
		id, hasID := req["id"]
		switch req["method"] {
		case "initialize":
			out.Encode(map[string]any{"jsonrpc": "2.0", "id": id,
				"result": map[string]any{"serverInfo": map[string]any{"name": "stub"}}})
		case "tools/list":
			out.Encode(map[string]any{"jsonrpc": "2.0", "id": id,
				"result": map[string]any{"tools": []map[string]any{
					{"name": "read_thing"}, {"name": "delete_thing"}}}})
		case "tools/call":
			if !hasID {
				continue
			}
			out.Encode(map[string]any{"jsonrpc": "2.0", "id": id,
				"result": map[string]any{"content": []map[string]any{{"type": "text", "text": "ok"}}}})
		}
	}
}
`

func buildStubServer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte(stubServerSource), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "stubserver")
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GO111MODULE=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build stub server: %v\n%s", err, out)
	}
	return bin
}

func buildChancery(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "chancery")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build chancery: %v\n%s", err, out)
	}
	return bin
}

func runCLI(t *testing.T, bin, dataDir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "CHANCERY_DATA="+dataDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("chancery %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func TestMCPWrapEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds subprocesses; skipped in -short")
	}
	stub := buildStubServer(t)
	ch := buildChancery(t)
	data := t.TempDir()

	runCLI(t, ch, data, "init", "--trust-domain", "acme.com")
	runCLI(t, ch, data, "agent", "register", "fs-bot",
		"--owner", "user:a@acme.com", "--purpose", "t", "--prompt", "p", "--model", "m")
	grant := runCLI(t, ch, data, "writ", "grant", "--for", "user:a@acme.com",
		"--to", "fs-bot", "--cap", "call:stub/read_*", "--ttl", "10m")
	var wid string
	for _, line := range strings.Split(grant, "\n") {
		if strings.HasPrefix(line, "writ ") {
			wid = strings.Fields(line)[1]
		}
	}
	if wid == "" {
		t.Fatalf("no writ id in:\n%s", grant)
	}

	cmd := exec.Command(ch, "mcp", "wrap", "--agent", "fs-bot", "--writ", wid,
		"--server-name", "stub", "--", stub)
	cmd.Env = append(os.Environ(), "CHANCERY_DATA="+data)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	rpc := func(msg string) map[string]json.RawMessage {
		stdin.Write([]byte(msg + "\n"))
		done := make(chan map[string]json.RawMessage, 1)
		go func() {
			var m map[string]json.RawMessage
			if sc.Scan() {
				json.Unmarshal(sc.Bytes(), &m)
			}
			done <- m
		}()
		select {
		case m := <-done:
			return m
		case <-time.After(10 * time.Second):
			t.Fatal("timeout awaiting proxy response")
			return nil
		}
	}

	// list is filtered to the granted read tool.
	resp := rpc(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	var lr struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	json.Unmarshal(resp["result"], &lr)
	if len(lr.Tools) != 1 || lr.Tools[0].Name != "read_thing" {
		t.Errorf("list not filtered to granted tool: %+v", lr.Tools)
	}

	// allowed call forwards.
	resp = rpc(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_thing"}}`)
	if resp["result"] == nil {
		t.Errorf("allowed call should reach the server: %v", resp)
	}

	// ungranted call denied.
	resp = rpc(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_thing"}}`)
	if resp["error"] == nil {
		t.Error("ungranted call must be denied")
	}

	// revoke mid-session; next allowed call blocked at the registry.
	runCLI(t, ch, data, "agent", "revoke", "fs-bot")
	resp = rpc(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_thing"}}`)
	if resp["error"] == nil {
		t.Fatal("revocation must block the next call")
	}
	var e struct {
		Message string `json:"message"`
	}
	json.Unmarshal(resp["error"], &e)
	if !strings.Contains(e.Message, "registry") {
		t.Errorf("post-revocation denial should cite the registry layer: %q", e.Message)
	}

	stdin.Close()
	cmd.Wait()

	// audit chain intact across the whole session.
	if out := runCLI(t, ch, data, "audit", "verify"); !strings.Contains(out, "intact") {
		t.Errorf("audit chain should verify: %s", out)
	}
}

// browserStubSource is a browser-shaped MCP server: `navigate` takes a
// url; `whoami` returns the storage-state file contents it was handed
// via argv (the chancery-file: substitution) — proving the server got
// the session while the agent side never did.
const browserStubSource = `package main

import (
	"bufio"
	"encoding/json"
	"os"
)

func main() {
	state := ""
	if len(os.Args) > 1 {
		if b, err := os.ReadFile(os.Args[1]); err == nil {
			state = string(b)
		}
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	out := json.NewEncoder(os.Stdout)
	for sc.Scan() {
		var req map[string]any
		if json.Unmarshal(sc.Bytes(), &req) != nil {
			continue
		}
		id, hasID := req["id"]
		if req["method"] == "tools/call" && hasID {
			out.Encode(map[string]any{"jsonrpc": "2.0", "id": id,
				"result": map[string]any{"content": []map[string]any{{"type": "text", "text": state}}}})
		}
	}
}
`

// TestBrowserWrapNetGuardAndSessionFile is the RFC-013 e2e: a writ with
// net caps auto-enables per-navigation URL checks, and sealed session
// material reaches the SERVER as a private file (via chancery-file:
// substitution) without ever existing in the agent-side environment.
func TestBrowserWrapNetGuardAndSessionFile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds subprocesses; skipped in -short")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte(browserStubSource), 0o644); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(dir, "browserstub")
	bcmd := exec.Command("go", "build", "-o", stub, src)
	bcmd.Env = append(os.Environ(), "GO111MODULE=off")
	if out, err := bcmd.CombinedOutput(); err != nil {
		t.Fatalf("build browser stub: %v\n%s", err, out)
	}
	ch := buildChancery(t)
	data := t.TempDir()

	runCLI(t, ch, data, "init", "--trust-domain", "acme.com")
	runCLI(t, ch, data, "agent", "register", "web-bot",
		"--owner", "user:a@acme.com", "--purpose", "t", "--prompt", "p", "--model", "m")

	// Seal a fake browser storage state (cookies).
	stateSrc := filepath.Join(dir, "state.json")
	os.WriteFile(stateSrc, []byte(`{"cookies":[{"name":"session","value":"supersecret"}]}`), 0o600)
	runCLI(t, ch, data, "secret", "put", "gmail-session", "--from-file", stateSrc)

	// net caps on the writ => URL guard auto-enabled.
	grant := runCLI(t, ch, data, "writ", "grant", "--for", "user:a@acme.com",
		"--to", "web-bot", "--cap", "call:browser/*", "--cap", "net:github.com/*", "--ttl", "10m")
	var wid string
	for _, line := range strings.Split(grant, "\n") {
		if strings.HasPrefix(line, "writ ") {
			wid = strings.Fields(line)[1]
		}
	}
	if wid == "" {
		t.Fatalf("no writ id in:\n%s", grant)
	}

	cmd := exec.Command(ch, "mcp", "wrap", "--agent", "web-bot", "--writ", wid,
		"--server-name", "browser", "--secret-file", "STATE=gmail-session",
		"--", stub, "chancery-file:STATE")
	cmd.Env = append(os.Environ(), "CHANCERY_DATA="+data)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	rpc := func(msg string) map[string]json.RawMessage {
		stdin.Write([]byte(msg + "\n"))
		done := make(chan map[string]json.RawMessage, 1)
		go func() {
			var m map[string]json.RawMessage
			if sc.Scan() {
				json.Unmarshal(sc.Bytes(), &m)
			}
			done <- m
		}()
		select {
		case m := <-done:
			return m
		case <-time.After(10 * time.Second):
			t.Fatal("timeout awaiting proxy response")
			return nil
		}
	}

	// 1) The server holds the session (chancery-file: substitution worked)…
	resp := rpc(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}`)
	if resp["result"] == nil || !strings.Contains(string(resp["result"]), "supersecret") {
		t.Fatalf("server must have received the sealed session file: %v", resp)
	}

	// 2) Navigation inside the net grant passes.
	resp = rpc(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"navigate","arguments":{"url":"https://github.com/acme/repo?token=x"}}}`)
	if resp["result"] == nil {
		t.Fatalf("granted navigation must pass: %v", resp)
	}

	// 3) Navigation outside it is denied in-path.
	resp = rpc(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"navigate","arguments":{"url":"https://evil.example/exfil"}}}`)
	if resp["error"] == nil || !strings.Contains(string(resp["error"]), "navigation denied") {
		t.Fatalf("out-of-grant navigation must be denied: %v", resp)
	}

	// 4) file:// smuggling fails closed.
	resp = rpc(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"navigate","arguments":{"url":"file:///etc/passwd"}}}`)
	if resp["error"] == nil {
		t.Fatalf("non-http navigation must be denied: %v", resp)
	}

	stdin.Close()
	cmd.Wait()

	// 5) The audit stream has the net decisions, query string stripped.
	audit := runCLI(t, ch, data, "audit", "--limit", "20")
	if !strings.Contains(audit, "github.com/acme/repo") || strings.Contains(audit, "token=x") {
		t.Errorf("audit must carry net resources without query payload:\n%s", audit)
	}
	if !strings.Contains(audit, "evil.example/exfil") {
		t.Errorf("denied navigation must be audited:\n%s", audit)
	}
}

// Server pinning (RFC-016 T1): first wrap pins the server binary;
// swapping the binary behind the same name makes the next wrap refuse
// to start (fail closed, audited); repin is the deliberate override.
func TestServerPinDriftRefusalAndRepin(t *testing.T) {
	if testing.Short() {
		t.Skip("builds subprocesses; skipped in -short")
	}
	stub := buildStubServer(t)
	ch := buildChancery(t)
	data := t.TempDir()

	runCLI(t, ch, data, "init", "--trust-domain", "acme.com")
	runCLI(t, ch, data, "agent", "register", "pin-bot",
		"--owner", "user:a@acme.com", "--purpose", "t", "--prompt", "p", "--model", "m")
	grant := runCLI(t, ch, data, "writ", "grant", "--for", "user:a@acme.com",
		"--to", "pin-bot", "--cap", "call:stub/*", "--ttl", "10m")
	var wid string
	for _, line := range strings.Split(grant, "\n") {
		if strings.HasPrefix(line, "writ ") {
			wid = strings.Fields(line)[1]
		}
	}

	// First wrap pins. Run it briefly, then close stdin so it exits.
	wrap1 := exec.Command(ch, "mcp", "wrap", "--agent", "pin-bot", "--writ", wid,
		"--server-name", "stub", "--", stub)
	wrap1.Env = append(os.Environ(), "CHANCERY_DATA="+data)
	in1, _ := wrap1.StdinPipe()
	if err := wrap1.Start(); err != nil {
		t.Fatal(err)
	}
	in1.Close()
	wrap1.Wait()
	if !strings.Contains(runCLI(t, ch, data, "audit", "--limit", "20"), "mcp.server_pin") {
		t.Fatal("first wrap must record mcp.server_pin")
	}

	// Swap the binary: same path, different content.
	swapped := buildChancery(t) // any other binary
	raw, err := os.ReadFile(swapped)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stub, raw, 0o755); err != nil {
		t.Fatal(err)
	}

	// Second wrap must refuse to start.
	wrap2 := exec.Command(ch, "mcp", "wrap", "--agent", "pin-bot", "--writ", wid,
		"--server-name", "stub", "--", stub)
	wrap2.Env = append(os.Environ(), "CHANCERY_DATA="+data)
	out, err := wrap2.CombinedOutput()
	if err == nil {
		wrap2.Process.Kill()
		t.Fatalf("wrap of a drifted server must refuse to start:\n%s", out)
	}
	if !strings.Contains(string(out), "drifted from its pin") {
		t.Fatalf("expected drift refusal, got: %s", out)
	}
	if !strings.Contains(runCLI(t, ch, data, "audit", "--limit", "20"), "mcp.server_drift") {
		t.Fatal("drift refusal must audit mcp.server_drift")
	}

	// Deliberate upgrade: repin, then wrap starts again.
	repin := runCLI(t, ch, data, "mcp", "repin", "stub", "--", stub)
	if !strings.Contains(repin, "repinned stub") {
		t.Fatalf("repin failed: %s", repin)
	}
	wrap3 := exec.Command(ch, "mcp", "wrap", "--agent", "pin-bot", "--writ", wid,
		"--server-name", "stub", "--", stub)
	wrap3.Env = append(os.Environ(), "CHANCERY_DATA="+data)
	in3, _ := wrap3.StdinPipe()
	if err := wrap3.Start(); err != nil {
		t.Fatal(err)
	}
	in3.Close()
	if err := wrap3.Wait(); err != nil {
		t.Fatalf("wrap after repin must start cleanly: %v", err)
	}
}

// T2 tree pinning (RFC-016): --pin-tree hashes the whole directory —
// poisoning a nested "dependency" file (which T1 cannot see) makes the
// next wrap refuse to start; repin --pin-tree is the deliberate path.
func TestTreePinCatchesPoisonedDependency(t *testing.T) {
	if testing.Short() {
		t.Skip("builds subprocesses; skipped in -short")
	}
	ch := buildChancery(t)
	data := t.TempDir()

	// A server "install dir": the stub binary plus a fake dependency
	// tree, mimicking a node_modules layout.
	install := t.TempDir()
	stub := buildStubServer(t)
	raw, err := os.ReadFile(stub)
	if err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(install, "server")
	if err := os.WriteFile(binPath, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	dep := filepath.Join(install, "node_modules", "dep", "index.js")
	if err := os.MkdirAll(filepath.Dir(dep), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dep, []byte("module.exports = 1"), 0o644); err != nil {
		t.Fatal(err)
	}

	runCLI(t, ch, data, "init", "--trust-domain", "acme.com")
	runCLI(t, ch, data, "agent", "register", "tree-bot",
		"--owner", "user:a@acme.com", "--purpose", "t", "--prompt", "p", "--model", "m")
	grant := runCLI(t, ch, data, "writ", "grant", "--for", "user:a@acme.com",
		"--to", "tree-bot", "--cap", "call:tree/*", "--ttl", "10m")
	var wid string
	for _, line := range strings.Split(grant, "\n") {
		if strings.HasPrefix(line, "writ ") {
			wid = strings.Fields(line)[1]
		}
	}

	wrapArgs := []string{"mcp", "wrap", "--agent", "tree-bot", "--writ", wid,
		"--server-name", "tree", "--pin-tree", install, "--", binPath}

	// First wrap pins the tree.
	w1 := exec.Command(ch, wrapArgs...)
	w1.Env = append(os.Environ(), "CHANCERY_DATA="+data)
	in1, _ := w1.StdinPipe()
	if err := w1.Start(); err != nil {
		t.Fatal(err)
	}
	in1.Close()
	w1.Wait()
	if !strings.Contains(runCLI(t, ch, data, "audit", "--limit", "20"), "tree:") {
		t.Fatal("first wrap must record a tree-kind pin")
	}

	// Poison ONLY the nested dependency — the launched binary is
	// untouched, so a T1 binary pin would pass. The tree pin must not.
	if err := os.WriteFile(dep, []byte("module.exports = 666 // poisoned"), 0o644); err != nil {
		t.Fatal(err)
	}
	w2 := exec.Command(ch, wrapArgs...)
	w2.Env = append(os.Environ(), "CHANCERY_DATA="+data)
	out, err := w2.CombinedOutput()
	if err == nil {
		w2.Process.Kill()
		t.Fatalf("poisoned dependency must refuse to start:\n%s", out)
	}
	if !strings.Contains(string(out), "drifted from its pin") {
		t.Fatalf("expected tree drift refusal, got: %s", out)
	}

	// Deliberate accept: repin the tree, wrap starts again.
	runCLI(t, ch, data, "mcp", "repin", "tree", "--pin-tree", install, "--", binPath)
	w3 := exec.Command(ch, wrapArgs...)
	w3.Env = append(os.Environ(), "CHANCERY_DATA="+data)
	in3, _ := w3.StdinPipe()
	if err := w3.Start(); err != nil {
		t.Fatal(err)
	}
	in3.Close()
	if err := w3.Wait(); err != nil {
		t.Fatalf("wrap after tree repin must start cleanly: %v", err)
	}
}
