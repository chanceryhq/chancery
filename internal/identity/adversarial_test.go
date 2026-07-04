package identity

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// RFC-009 §2 (JOSE layer): algorithm-confusion regression set for
// identity documents.

func TestAlgNoneDocumentRejected(t *testing.T) {
	iss := testIssuer(t)
	header, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"iss": "https://chancery.acme.com",
		"sub": "spiffe://acme.com/agent/evil",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"chancery": map[string]any{"agent": "evil", "inst": "01X",
			"owner": "user:attacker@evil.com"},
	})
	enc := base64.RawURLEncoding
	forged := enc.EncodeToString(header) + "." + enc.EncodeToString(payload) + "."
	if _, err := iss.Verify(forged); err == nil {
		t.Fatal("alg:none identity document must be rejected")
	}
}

func TestHS256KeyConfusionRejected(t *testing.T) {
	// Classic confusion attack: sign with HMAC using the issuer's PUBLIC
	// key bytes as the secret, hoping the verifier treats the public key
	// as an HMAC key. The ECDSA-only method check must refuse it.
	iss := testIssuer(t)
	pubDER, err := x509.MarshalPKIXPublicKey(&iss.Key().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":      "https://chancery.acme.com",
		"sub":      "spiffe://acme.com/agent/evil",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"chancery": map[string]any{"agent": "evil"},
	})
	forged, err := tok.SignedString(pubDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Verify(forged); err == nil {
		t.Fatal("HS256 key-confusion token must be rejected")
	}
}

func TestExpiryRequired(t *testing.T) {
	// A document without exp must not verify (WithExpirationRequired).
	iss := testIssuer(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":      "https://chancery.acme.com",
		"sub":      "spiffe://acme.com/agent/evil",
		"chancery": map[string]any{"agent": "evil"},
	})
	signed, err := tok.SignedString(iss.Key())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Verify(signed); err == nil {
		t.Fatal("document without exp must be rejected")
	}
}
