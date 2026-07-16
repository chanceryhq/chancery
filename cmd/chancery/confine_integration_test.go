package main

// applyConfinement (RFC-018) against the real OS: the sandbox must make
// the manifest a kernel boundary, not a convention. Sandbox assertions
// are darwin-gated (seatbelt); the egress proxy path is covered
// cross-platform in internal/confine.

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func netListen(t *testing.T) (net.Listener, error) {
	t.Helper()
	return net.Listen("tcp", "127.0.0.1:0")
}

func extractWritID(t *testing.T, grantOutput string) string {
	t.Helper()
	for _, line := range strings.Split(grantOutput, "\n") {
		if strings.HasPrefix(line, "writ ") {
			return strings.Fields(line)[1]
		}
	}
	t.Fatalf("no writ id in:\n%s", grantOutput)
	return ""
}

// buildCurlingStubServer compiles a stub MCP server whose fetch_denied
// tool makes an HTTP request to an off-manifest host through the
// standard proxy env vars — exactly what a well-behaved-but-compromised
// dependency would do.
func buildCurlingStubServer(t *testing.T) string {
	t.Helper()
	const src = `package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"time"
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
				"result": map[string]any{"tools": []map[string]any{{"name": "fetch_denied"}}}})
		case "tools/call":
			if !hasID {
				continue
			}
			status := "unreached"
			client := &http.Client{Timeout: 3 * time.Second}
			if resp, err := client.Get("http://denied.example/secret"); err == nil {
				status = resp.Status
				resp.Body.Close()
			} else {
				status = "error"
			}
			out.Encode(map[string]any{"jsonrpc": "2.0", "id": id,
				"result": map[string]any{"content": []map[string]any{{"type": "text", "text": status}}}})
		}
	}
}
`
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "curlstub")
	cmd := exec.Command("go", "build", "-o", bin, srcPath)
	cmd.Env = append(os.Environ(), "GO111MODULE=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build curling stub: %v\n%s", err, out)
	}
	return bin
}

// runMCPSession drives one wrapped stdio session: send each message,
// collect one response line per message, then close stdin and wait.
func runMCPSession(t *testing.T, ch, data string, cliArgs []string, msgs ...string) string {
	t.Helper()
	cmd := exec.Command(ch, cliArgs...)
	cmd.Env = append(os.Environ(), "CHANCERY_DATA="+data)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var lines []string
	for _, m := range msgs {
		stdin.Write([]byte(m + "\n"))
		done := make(chan bool, 1)
		go func() { done <- sc.Scan() }()
		select {
		case ok := <-done:
			if !ok {
				t.Fatalf("session closed early after %q; got so far:\n%s", m, strings.Join(lines, "\n"))
			}
			lines = append(lines, sc.Text())
		case <-time.After(20 * time.Second):
			t.Fatalf("timeout waiting for response to %q; got so far:\n%s", m, strings.Join(lines, "\n"))
		}
	}
	stdin.Close()
	cmd.Wait()
	return strings.Join(lines, "\n")
}

func runConfined(t *testing.T, egress, writable []string, cmdArgs []string) error {
	t.Helper()
	args, env, cleanup, err := applyConfinement(egress, writable, cmdArgs,
		[]string{"PATH=" + os.Getenv("PATH")}, func(string) {})
	if err != nil {
		t.Fatalf("applyConfinement: %v", err)
	}
	defer cleanup()
	c := exec.Command(args[0], args[1:]...)
	c.Env = env
	out, err := c.CombinedOutput()
	if err != nil {
		return &exec.ExitError{ProcessState: c.ProcessState, Stderr: out}
	}
	return nil
}

// TestConfineFilesystemBoundary: a confined process can write inside a
// declared writable path and CANNOT write outside it.
func TestConfineFilesystemBoundary(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("sandbox assertions are darwin-only (Linux uses bwrap); GOOS=%s", runtime.GOOS)
	}
	writable := t.TempDir()
	outside := filepath.Join(t.TempDir(), "escape.txt")

	if err := runConfined(t, nil, []string{writable},
		[]string{"/bin/sh", "-c", "echo ok > " + filepath.Join(writable, "in.txt")}); err != nil {
		t.Fatalf("write INSIDE the writable path was denied: %v", err)
	}
	if err := runConfined(t, nil, []string{writable},
		[]string{"/bin/sh", "-c", "echo escape > " + outside}); err == nil {
		t.Fatal("write OUTSIDE the writable path succeeded; the manifest is not a boundary")
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("escape file exists — the sandbox did not block the write")
	}
}

// TestConfineNetworkBoundary: outbound network from a confined process
// is loopback-only, so the auditing egress proxy is the only road out —
// even for a client that ignores proxy env vars.
func TestConfineNetworkBoundary(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("sandbox assertions are darwin-only; GOOS=%s", runtime.GOOS)
	}
	// Precompile a tiny dialer OUTSIDE the sandbox (the go toolchain
	// needs cache writes the sandbox rightly denies).
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte(`package main

import (
	"net"
	"os"
	"time"
)

func main() {
	c, err := net.DialTimeout("tcp", os.Args[1], 2*time.Second)
	if err != nil {
		os.Exit(1)
	}
	c.Close()
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	dialer := filepath.Join(dir, "dialer")
	build := exec.Command("go", "build", "-o", dialer, src)
	build.Env = append(os.Environ(), "GO111MODULE=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build dialer: %v\n%s", err, out)
	}

	// Loopback listener: dialing it confined must SUCCEED (proves the
	// sandbox is live and correctly scoped, not just broken).
	ln, err := netListen(t)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := runConfined(t, nil, nil, []string{dialer, ln.Addr().String()}); err != nil {
		t.Fatalf("loopback dial was denied — the proxy road is closed: %v", err)
	}
	// Non-loopback dial must FAIL locally (seatbelt EPERM — no real
	// network needed, so no flake offline).
	if err := runConfined(t, nil, nil, []string{dialer, "192.0.2.1:80"}); err == nil {
		t.Fatal("non-loopback dial succeeded under confinement; egress can bypass the proxy")
	}
}

// TestConfineWrapEndToEnd: full `mcp wrap --confine` — the stub server
// runs and answers through the proxy under the sandbox, and an egress
// attempt to an off-manifest host lands in the audit trail as
// mcp.server_egress_denied with only the host recorded.
func TestConfineWrapEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds subprocesses; skipped in -short")
	}
	if runtime.GOOS != "darwin" {
		t.Skipf("sandbox assertions are darwin-only; GOOS=%s", runtime.GOOS)
	}
	stub := buildCurlingStubServer(t)
	ch := buildChancery(t)
	data := t.TempDir()

	runCLI(t, ch, data, "init", "--trust-domain", "acme.com")
	runCLI(t, ch, data, "agent", "register", "net-bot",
		"--owner", "user:a@acme.com", "--purpose", "t", "--prompt", "p", "--model", "m")
	grant := runCLI(t, ch, data, "writ", "grant", "--for", "user:a@acme.com",
		"--to", "net-bot", "--cap", "call:stub/*", "--ttl", "10m")
	wid := extractWritID(t, grant)

	out := runMCPSession(t, ch, data, []string{"mcp", "wrap", "--agent", "net-bot", "--writ", wid,
		"--server-name", "stub", "--confine", "--egress", "allowed.example", "--", stub},
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch_denied"}}`,
	)
	if !strings.Contains(out, `"result"`) {
		t.Fatalf("confined wrap session broke:\n%s", out)
	}

	audit := runCLI(t, ch, data, "audit", "--json", "--limit", "50")
	if !strings.Contains(audit, "mcp.server_egress_denied") {
		t.Fatalf("no mcp.server_egress_denied event in audit:\n%s", audit)
	}
	if !strings.Contains(audit, "denied.example") {
		t.Fatalf("denied host not recorded:\n%s", audit)
	}
	if strings.Contains(audit, "/secret") {
		t.Fatalf("audit leaked a path — metadata-only is structural:\n%s", audit)
	}
}
