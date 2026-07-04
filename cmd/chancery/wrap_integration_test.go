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
