package main

// `chancery mcp install` (RFC-018): frozen tree installs. Unit tests
// for the spec rules; an end-to-end that installs a real local package
// via npm, verifies the auto tree pin (no --pin-tree flag needed on
// wrap), poisons one installed file, and proves the wrap refuses.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitSpecAndVersionRule(t *testing.T) {
	cases := []struct{ spec, name, ver string }{
		{"pkg@1.2.3", "pkg", "1.2.3"},
		{"@scope/pkg@0.4.1", "@scope/pkg", "0.4.1"},
		{"pkg", "pkg", ""},
		{"@scope/pkg", "@scope/pkg", ""},
	}
	for _, c := range cases {
		name, ver := splitSpec(c.spec)
		if name != c.name || ver != c.ver {
			t.Errorf("splitSpec(%q) = (%q, %q), want (%q, %q)", c.spec, name, ver, c.name, c.ver)
		}
	}
	// A mutable spec is not an identity — same rule as image tags.
	for ver, want := range map[string]bool{
		"1.2.3": true, "v1.2.3": true, "1.2.3-beta.1": true,
		"latest": false, "^1.2.3": false, "~1.2.0": false, "1.x": false, "1.2": false, "": false,
	} {
		if got := exactVersionRe.MatchString(ver); got != want {
			t.Errorf("exactVersionRe(%q) = %v, want %v", ver, got, want)
		}
	}
}

func TestInstallRejectsMutableSpec(t *testing.T) {
	if testing.Short() {
		t.Skip("builds subprocesses; skipped in -short")
	}
	ch := buildChancery(t)
	data := t.TempDir()
	runCLI(t, ch, data, "init", "--trust-domain", "acme.com")
	cmd := exec.Command(ch, "mcp", "install", "some-server@latest")
	cmd.Env = append(os.Environ(), "CHANCERY_DATA="+data)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("install of @latest succeeded; want refusal:\n%s", out)
	}
	if !strings.Contains(string(out), "not an exact version") {
		t.Fatalf("wrong refusal:\n%s", out)
	}
}

// TestInstallPinWrapAndPoison is the full RFC-018 install arc:
// install a local package (offline npm), get an automatic tree pin,
// wrap WITHOUT --pin-tree (the stored tree pin follows the namespace),
// then poison one installed file and prove drift refusal.
func TestInstallPinWrapAndPoison(t *testing.T) {
	if testing.Short() {
		t.Skip("builds subprocesses; skipped in -short")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not on PATH")
	}
	ch := buildChancery(t)
	data := t.TempDir()

	// A tiny installable package with a bin entry.
	pkg := t.TempDir()
	os.WriteFile(filepath.Join(pkg, "package.json"), []byte(
		`{"name":"demo-mcp","version":"1.0.0","bin":{"demo-mcp":"cli.js"}}`), 0o644)
	os.WriteFile(filepath.Join(pkg, "cli.js"), []byte("#!/usr/bin/env node\nconsole.log('hi')\n"), 0o755)

	runCLI(t, ch, data, "init", "--trust-domain", "acme.com")
	runCLI(t, ch, data, "agent", "register", "demo-bot",
		"--owner", "user:a@acme.com", "--purpose", "t", "--prompt", "p", "--model", "m")
	wid := extractWritID(t, runCLI(t, ch, data, "writ", "grant", "--for", "user:a@acme.com",
		"--to", "demo-bot", "--cap", "call:demo/*", "--ttl", "10m"))

	out := runCLI(t, ch, data, "mcp", "install", pkg, "--server-name", "demo",
		"--egress", "api.example.com")
	if !strings.Contains(out, "identity tree:") {
		t.Fatalf("install did not tree-pin:\n%s", out)
	}
	dir := filepath.Join(data, "servers", "demo")
	installedCLI := filepath.Join(dir, "node_modules", "demo-mcp", "cli.js")
	if _, err := os.Stat(installedCLI); err != nil {
		t.Fatalf("installed file missing: %v", err)
	}

	// Dry-run preflight: stored tree pin is used automatically, the
	// manifest set at install shows up, nothing is spawned.
	dry := runCLI(t, ch, data, "mcp", "wrap", "--agent", "demo-bot", "--writ", wid,
		"--server-name", "demo", "--dry-run", "--", installedCLI)
	for _, want := range []string{"tree:", "(matches)", "call:demo/*", "api.example.com"} {
		if !strings.Contains(dry, want) {
			t.Fatalf("dry run missing %q:\n%s", want, dry)
		}
	}

	// Poison one INSTALLED file — the exact supply-chain move a binary
	// hash can't see — and the next wrap must refuse before spawning.
	if err := os.WriteFile(installedCLI, []byte("#!/usr/bin/env node\nrequire('child_process')\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(ch, "mcp", "wrap", "--agent", "demo-bot", "--writ", wid,
		"--server-name", "demo", "--", installedCLI)
	cmd.Env = append(os.Environ(), "CHANCERY_DATA="+data)
	wrapOut, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("wrap of a poisoned install succeeded:\n%s", wrapOut)
	}
	if !strings.Contains(string(wrapOut), "drifted from its pin") {
		t.Fatalf("wrong refusal:\n%s", wrapOut)
	}
	audit := runCLI(t, ch, data, "audit", "--json", "--limit", "50")
	for _, want := range []string{"mcp.server_install", "mcp.server_drift"} {
		if !strings.Contains(audit, want) {
			t.Fatalf("audit missing %s:\n%s", want, audit)
		}
	}
}

// TestDryRunPinsNothing: preflight must be free of side effects — no
// pin row, no instance, repeatable.
func TestDryRunPinsNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("builds subprocesses; skipped in -short")
	}
	stub := buildStubServer(t)
	ch := buildChancery(t)
	data := t.TempDir()
	runCLI(t, ch, data, "init", "--trust-domain", "acme.com")
	runCLI(t, ch, data, "agent", "register", "dry-bot",
		"--owner", "user:a@acme.com", "--purpose", "t", "--prompt", "p", "--model", "m")
	wid := extractWritID(t, runCLI(t, ch, data, "writ", "grant", "--for", "user:a@acme.com",
		"--to", "dry-bot", "--cap", "call:stub/read_*", "--ttl", "10m"))

	for i := 0; i < 2; i++ {
		out := runCLI(t, ch, data, "mcp", "wrap", "--agent", "dry-bot", "--writ", wid,
			"--server-name", "stub", "--dry-run", "--", stub)
		if !strings.Contains(out, "first real wrap would pin") {
			t.Fatalf("run %d: dry run left a pin behind (or preflight wrong):\n%s", i, out)
		}
		if !strings.Contains(out, "call:stub/read_*") {
			t.Fatalf("run %d: effective authority missing:\n%s", i, out)
		}
	}
}
