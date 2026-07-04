package writ

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// RFC-009 §2 (JOSE layer): the named regression set for algorithm
// confusion and cross-writ substitution.

// forgeUnsigned builds an alg:none JWS for a writ block.
func forgeUnsigned(t *testing.T, b Block) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	payload, _ := json.Marshal(blockClaims{Block: b})
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + "." + enc.EncodeToString(payload) + "."
}

func TestAlgNoneWritRejected(t *testing.T) {
	key := testKey(t)
	forged := forgeUnsigned(t, Block{
		WID: "w_forged", Idx: 0, For: "user:attacker@evil.com",
		To: "spiffe://acme.com/agent/evil", ToVer: "sha256:e",
		Cap:   []Cap{{Verb: "*", Resource: "*"}},
		Depth: 4, Exp: time.Now().Add(time.Hour).Unix(), Iat: time.Now().Unix(),
	})
	if _, err := Verify([]string{forged}, &key.PublicKey, time.Now()); err == nil {
		t.Fatal("alg:none writ block must be rejected")
	}
}

func TestAlgNoneDelegationBlockRejected(t *testing.T) {
	// A valid signed grant with an unsigned delegation block appended:
	// the attacker hopes only block 0 is checked.
	key := testKey(t)
	w := grant(t, key, "call:github/get_*")
	forged := forgeUnsigned(t, Block{
		WID: w.ID(), Idx: 1, To: "spiffe://acme.com/agent/evil", ToVer: "sha256:e",
		Exp: time.Now().Add(time.Minute).Unix(), Iat: time.Now().Unix(),
		Prev: prefixHash(w.JWS),
	})
	if _, err := Verify(append(w.JWS, forged), &key.PublicKey, time.Now()); err == nil {
		t.Fatal("unsigned delegation block on a signed chain must be rejected")
	}
}

func TestCrossWritBlockSubstitution(t *testing.T) {
	// Two legitimate writs; splice writ B's (broader) grant under writ
	// A's delegation, and vice versa. Both directions must fail.
	key := testKey(t)
	narrow := grant(t, key, "call:github/get_*")
	broad, err := Grant("w_broad", "user:aneesh@acme.com", "spiffe://acme.com/agent/parent",
		"sha256:p1", caps(t, "*:*"), 4, time.Now().Add(time.Hour), key, "kid1")
	if err != nil {
		t.Fatal(err)
	}
	child, err := Delegate(narrow, "spiffe://acme.com/agent/child", "sha256:c1",
		nil, time.Now().Add(time.Minute), key, "kid1")
	if err != nil {
		t.Fatal(err)
	}
	// Swap in the broad grant as block 0 of the narrow chain.
	spliced := []string{broad.JWS[0], child.JWS[1]}
	if _, err := Verify(spliced, &key.PublicKey, time.Now()); err == nil {
		t.Fatal("cross-writ grant substitution must be rejected")
	}
}

func TestGrantRequiresCapabilities(t *testing.T) {
	key := testKey(t)
	if _, err := Grant("w_x", "user:a@acme.com", "spiffe://acme.com/agent/a", "sha256:1",
		nil, 4, time.Now().Add(time.Hour), key, "kid1"); err == nil {
		t.Fatal("a grant with no capabilities must be refused")
	}
}
