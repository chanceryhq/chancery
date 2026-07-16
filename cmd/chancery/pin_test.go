package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chanceryhq/chancery/internal/store"
)

// T3 (RFC-016): only digest-pinned image references are identities; a
// mutable tag is not.
func TestExtractImageDigest(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	cases := []struct {
		args    []string
		wantRef string
	}{
		{[]string{"docker", "run", "-i", "--rm", "ghcr.io/acme/mcp@sha256:" + digest}, "ghcr.io/acme/mcp@sha256:" + digest},
		{[]string{"podman", "run", "-i", "quay.io/x/y:v1@sha256:" + digest}, "quay.io/x/y:v1@sha256:" + digest},
		{[]string{"docker", "run", "-i", "ghcr.io/acme/mcp:latest"}, ""},       // mutable tag: no identity
		{[]string{"docker", "run", "ghcr.io/acme/mcp@sha256:beef"}, ""},        // truncated digest
		{[]string{"npx", "@modelcontextprotocol/server-github"}, ""},           // no image at all
		{[]string{"docker", "run", "-e", "X=@sha256:" + digest, "img:v1"}, ""}, // digest not on an image ref
	}
	for _, c := range cases {
		ref, got := extractImageDigest(c.args)
		if c.wantRef == "" && got != "" {
			t.Errorf("args %v: unexpectedly extracted %q", c.args, ref)
		}
		if c.wantRef != "" && (ref != c.wantRef || got != digest) {
			t.Errorf("args %v: got ref=%q digest=%q", c.args, ref, got)
		}
	}
}

// T2 (RFC-016): the tree hash is stable across recomputation and
// changes when any file's content changes, a file is added, removed,
// or flips executability — the full-dependency-tree identity.
func TestHashTreeDetectsEveryChange(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string, mode os.FileMode) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("bin/server", "#!/bin/sh\necho hi", 0o755)
	write("node_modules/dep/index.js", "module.exports = 1", 0o644)

	base, err := hashTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := hashTree(dir)
	if err != nil || again != base {
		t.Fatalf("tree hash must be deterministic: %v %s vs %s", err, again, base)
	}

	// Content change in a nested dependency — the npx hole T1 misses.
	write("node_modules/dep/index.js", "module.exports = 666 // poisoned", 0o644)
	poisoned, err := hashTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if poisoned == base {
		t.Fatal("a modified transitive dependency must change the tree hash")
	}

	// Restore, then add a file.
	write("node_modules/dep/index.js", "module.exports = 1", 0o644)
	restored, _ := hashTree(dir)
	if restored != base {
		t.Fatal("restoring content must restore the hash")
	}
	write("node_modules/dep/extra.js", "x", 0o644)
	if h, _ := hashTree(dir); h == base {
		t.Fatal("an added file must change the tree hash")
	}
	os.Remove(filepath.Join(dir, "node_modules/dep/extra.js"))

	// Executability flip.
	if err := os.Chmod(filepath.Join(dir, "node_modules/dep/index.js"), 0o755); err != nil {
		t.Fatal(err)
	}
	if h, _ := hashTree(dir); h == base {
		t.Fatal("an executability flip must change the tree hash")
	}
}

// resolvePinIdentity picks the strongest applicable tier.
func TestResolvePinIdentityTiers(t *testing.T) {
	digest := strings.Repeat("cd", 32)
	// T3 wins even when a tree is also given.
	kind, ref, sha, err := resolvePinIdentity(
		[]string{"docker", "run", "-i", "img@sha256:" + digest}, t.TempDir())
	if err != nil || kind != store.PinDigest || sha != digest || !strings.Contains(ref, "@sha256:") {
		t.Fatalf("digest must win: %v %s %s", err, kind, sha)
	}
	// T2 when asked and no digest.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	kind, path, _, err := resolvePinIdentity([]string{"npx", "some-server"}, dir)
	if err != nil || kind != store.PinTree || path != dir {
		t.Fatalf("tree tier: %v %s %s", err, kind, path)
	}
	// T1 default: hash a real binary on PATH.
	kind, _, sha, err = resolvePinIdentity([]string{"sh"}, "")
	if err != nil || kind != store.PinBinary || len(sha) != 64 {
		t.Fatalf("binary tier: %v %s %s", err, kind, sha)
	}
}
