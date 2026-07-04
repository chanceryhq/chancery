package policy

import (
	"strings"
	"testing"
)

func TestGrammarValidation(t *testing.T) {
	valid := []string{"call:github/*", "call:github/get_*", "*:*", "read:a/b/c",
		"call:github/repos/acme-corp/create_issue", "net:api.example.com/v1/*"}
	for _, s := range valid {
		if _, err := ParseCap(s); err != nil {
			t.Errorf("%q should be valid: %v", s, err)
		}
	}
	invalid := map[string]string{
		"call:gith*ub/x":    "mid-pattern wildcard",
		"call:github//x":    "empty segment",
		"call:GitHub/x":     "uppercase",
		"frobnicate:x":      "unknown verb",
		"call:":             "empty resource",
		"nocolon":           "missing verb",
		"call:git hub/x":    "space in segment",
		"call:github/*/get": "wildcard not final",
	}
	for s, why := range invalid {
		if _, err := ParseCap(s); err == nil {
			t.Errorf("%q should be invalid (%s)", s, why)
		}
	}
}

func TestMatchSemantics(t *testing.T) {
	cases := []struct {
		pattern, resource string
		want              bool
	}{
		{"*", "anything/at/all", true},
		{"github/get_repo", "github/get_repo", true},
		{"github/get_repo", "github/get_repos", false},
		{"github/*", "github/get_repo", true},
		{"github/*", "github/repos/acme/issue", true}, // "/" prefix = subtree
		{"github/*", "githubx/get_repo", false},
		{"github/get_*", "github/get_repo", true},
		{"github/get_*", "github/getrepo", false},
		{"github/get*", "github/getrepo", true},      // documented, discouraged
		{"github/get_*", "github/get_x/deep", false}, // wildcard stays in final segment
		{"gith*", "github", true},
		{"gith*", "github/x", false}, // no crossing segment boundaries
	}
	for _, c := range cases {
		if got := MatchResource(c.pattern, c.resource); got != c.want {
			t.Errorf("MatchResource(%q, %q) = %v, want %v", c.pattern, c.resource, got, c.want)
		}
	}
}

type fakeAuthority struct{ caps []Cap }

func (f fakeAuthority) Check(verb, resource string) bool {
	for _, c := range f.caps {
		if c.Matches(verb, resource) {
			return true
		}
	}
	return false
}
func (f fakeAuthority) Lineage() []string { return []string{"user:test", "agent/a"} }

func TestDecideLayers(t *testing.T) {
	auth := fakeAuthority{caps: []Cap{{Verb: "call", Resource: "github/*"}}}

	// L1 allows, no allowlist restriction.
	d := Decide(auth, nil, "call", "github/get_repo")
	if d.Effect != Allow || d.Layer != "writ" {
		t.Errorf("want allow by writ, got %+v", d)
	}
	if !strings.Contains(d.Reason, "lineage") {
		t.Errorf("allow must carry lineage, got %q", d.Reason)
	}

	// L1 denies: nothing downstream can rescue it.
	d = Decide(auth, []string{"*"}, "call", "slack/post")
	if d.Effect != Deny || d.Layer != "writ" {
		t.Errorf("want deny by writ, got %+v", d)
	}

	// L2 subtracts from what L1 granted.
	d = Decide(auth, []string{"github/get_*"}, "call", "github/create_issue")
	if d.Effect != Deny || d.Layer != "allowlist" {
		t.Errorf("want deny by allowlist, got %+v", d)
	}
	d = Decide(auth, []string{"github/get_*"}, "call", "github/get_repo")
	if d.Effect != Allow {
		t.Errorf("allowlisted action must pass, got %+v", d)
	}

	// Empty allow-list = no additional restriction, NOT deny-all.
	d = Decide(auth, []string{}, "call", "github/get_repo")
	if d.Effect != Allow {
		t.Errorf("empty allowlist must not restrict, got %+v", d)
	}

	// Explicit deny-all sentinel.
	d = Decide(auth, []string{DenyAll}, "call", "github/get_repo")
	if d.Effect != Deny || d.Layer != "allowlist" {
		t.Errorf("want deny by %s sentinel, got %+v", DenyAll, d)
	}

	// No authority at all: default deny.
	d = Decide(nil, nil, "call", "github/get_repo")
	if d.Effect != Deny {
		t.Errorf("nil authority must deny, got %+v", d)
	}

	// Grammar layer: malformed inputs never reach matching.
	d = Decide(auth, nil, "call", "github/*")
	if d.Effect != Deny || d.Layer != "grammar" {
		t.Errorf("wildcard in concrete resource must deny at grammar layer, got %+v", d)
	}
	d = Decide(auth, nil, "shout", "github/x")
	if d.Effect != Deny || d.Layer != "grammar" {
		t.Errorf("unknown verb must deny at grammar layer, got %+v", d)
	}
}
