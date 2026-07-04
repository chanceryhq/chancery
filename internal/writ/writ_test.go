package writ

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func caps(t *testing.T, ss ...string) []Cap {
	t.Helper()
	var out []Cap
	for _, s := range ss {
		c, err := ParseCap(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func grant(t *testing.T, key *ecdsa.PrivateKey, capss ...string) *Writ {
	t.Helper()
	w, err := Grant("w_test", "user:aneesh@acme.com", "spiffe://acme.com/agent/parent",
		"sha256:p1", caps(t, capss...), 4, time.Now().Add(time.Hour), key, "kid1")
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestEffectiveAuthorityIntersects(t *testing.T) {
	key := testKey(t)
	w := grant(t, key, "call:github/*", "call:slack/post_message")

	if !w.Check("call", "github/create_issue") {
		t.Error("grant should allow github/create_issue")
	}
	if w.Check("call", "jira/create_issue") {
		t.Error("grant must not allow jira")
	}

	// Child narrowed to read-only-ish subset.
	child, err := Delegate(w, "spiffe://acme.com/agent/child", "sha256:c1",
		caps(t, "call:github/get_*"), time.Now().Add(30*time.Minute), key, "kid1")
	if err != nil {
		t.Fatal(err)
	}
	if !child.Check("call", "github/get_issue") {
		t.Error("child should keep github/get_issue")
	}
	if child.Check("call", "github/create_issue") {
		t.Error("attenuation failed: child kept create_issue")
	}
	if child.Check("call", "slack/post_message") {
		t.Error("attenuation failed: child kept slack")
	}
	// Parent unaffected.
	if !w.Check("call", "github/create_issue") {
		t.Error("parent authority must be unchanged")
	}
}

func TestWideningIsUnrepresentable(t *testing.T) {
	key := testKey(t)
	w := grant(t, key, "call:github/get_*")

	// A caveat "broader" than the grant changes nothing: effective
	// authority is the intersection.
	child, err := Delegate(w, "spiffe://acme.com/agent/child", "sha256:c1",
		caps(t, "call:github/*"), time.Now().Add(time.Minute), key, "kid1")
	if err != nil {
		t.Fatal(err)
	}
	if child.Check("call", "github/create_issue") {
		t.Error("child gained authority the parent never had")
	}
	if !child.Check("call", "github/get_issue") {
		t.Error("child should retain the granted subset")
	}
}

func TestTTLMonotonic(t *testing.T) {
	key := testKey(t)
	w := grant(t, key, "call:github/*")
	_, err := Delegate(w, "spiffe://acme.com/agent/child", "sha256:c1",
		nil, time.Now().Add(2*time.Hour), key, "kid1")
	if !errors.Is(err, ErrTTLExceeded) {
		t.Errorf("child outliving parent must be refused, got %v", err)
	}
}

func TestDepthLimit(t *testing.T) {
	key := testKey(t)
	w, err := Grant("w_d", "user:a@acme.com", "spiffe://acme.com/agent/a0", "sha256:0",
		caps(t, "call:x/*"), 2, time.Now().Add(time.Hour), key, "kid1")
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Minute)
	w, err = Delegate(w, "spiffe://acme.com/agent/a1", "sha256:1", nil, exp, key, "kid1")
	if err != nil {
		t.Fatal(err)
	}
	w, err = Delegate(w, "spiffe://acme.com/agent/a2", "sha256:2", nil, exp, key, "kid1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Delegate(w, "spiffe://acme.com/agent/a3", "sha256:3", nil, exp, key, "kid1"); !errors.Is(err, ErrDepthLimit) {
		t.Errorf("depth 3 on max_depth 2 must be refused, got %v", err)
	}
}

func TestNullAuthorityRefused(t *testing.T) {
	key := testKey(t)
	w := grant(t, key, "call:github/*")
	_, err := Delegate(w, "spiffe://acme.com/agent/child", "sha256:c1",
		caps(t, "call:snowflake/*"), time.Now().Add(time.Minute), key, "kid1")
	if !errors.Is(err, ErrNullAuthority) {
		t.Errorf("zero-intersection caveat must be refused at append, got %v", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	key := testKey(t)
	w := grant(t, key, "call:github/*")
	child, err := Delegate(w, "spiffe://acme.com/agent/child", "sha256:c1",
		caps(t, "call:github/get_*"), time.Now().Add(time.Minute), key, "kid1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(child.JWS, &key.PublicKey, time.Now()); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}

	// Dropping the middle of a 3-block chain must fail the prefix hash.
	grandchild, err := Delegate(child, "spiffe://acme.com/agent/gc", "sha256:g1",
		nil, time.Now().Add(time.Minute), key, "kid1")
	if err != nil {
		t.Fatal(err)
	}
	spliced := []string{grandchild.JWS[0], grandchild.JWS[2]}
	if _, err := Verify(spliced, &key.PublicKey, time.Now()); err == nil {
		t.Error("spliced chain must be rejected")
	}

	// A block signed by a different key must fail.
	otherKey := testKey(t)
	forged, err := Delegate(w, "spiffe://acme.com/agent/evil", "sha256:e1",
		nil, time.Now().Add(time.Minute), otherKey, "kid2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(forged.JWS, &key.PublicKey, time.Now()); !errors.Is(err, ErrTampered) {
		t.Errorf("foreign signature must be ErrTampered, got %v", err)
	}

	// Bit-flipped payload must fail.
	broken := append([]string{}, child.JWS...)
	broken[1] = strings.Replace(broken[1], ".", ".A", 1)
	if _, err := Verify(broken, &key.PublicKey, time.Now()); err == nil {
		t.Error("corrupted block must be rejected")
	}
}

func TestVerifyExpired(t *testing.T) {
	key := testKey(t)
	w := grant(t, key, "call:github/*")
	if _, err := Verify(w.JWS, &key.PublicKey, time.Now().Add(2*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired writ must be ErrExpired, got %v", err)
	}
}

func TestLineage(t *testing.T) {
	key := testKey(t)
	w := grant(t, key, "call:github/*")
	child, err := Delegate(w, "spiffe://acme.com/agent/child", "sha256:c1",
		nil, time.Now().Add(time.Minute), key, "kid1")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(child.Lineage(), " -> ")
	want := "user:aneesh@acme.com -> spiffe://acme.com/agent/parent -> spiffe://acme.com/agent/child"
	if got != want {
		t.Errorf("lineage = %q, want %q", got, want)
	}
}
