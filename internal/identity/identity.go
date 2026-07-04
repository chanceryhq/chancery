// Package identity issues and verifies Chancery identity documents
// (RFC-001 §4): short-lived ES256 JWTs naming the acting principal —
// agent (durable SPIFFE-compatible URI), version (content digest), and
// instance — wire-compatible with WIMSE WIT conventions. The cnf slot is
// present in the schema from day one; proof-of-possession enforcement is
// a v1 hardening item.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	DefaultTTL = 5 * time.Minute
	MaxTTL     = 60 * time.Minute
	// Leeway tolerates clock skew on iat/exp; beyond it, fail closed
	// with a distinct error (RFC-001 §7).
	Leeway = 60 * time.Second
)

// Document is the verified claim set of an identity document.
type Document struct {
	Issuer   string
	Subject  string // spiffe://<trust-domain>/agent/<name>
	Agent    string
	Version  string // sha256 version digest
	Instance string
	Owner    string
	Writ     string
	AttType  string
	Expires  time.Time
}

// Issuer holds the control plane's signing key.
type Issuer struct {
	key         *ecdsa.PrivateKey
	kid         string
	TrustDomain string
	IssuerURL   string
}

// LoadOrCreate loads the ES256 issuer key from dir, generating it on
// first run. Key material never leaves dir; 0600.
func LoadOrCreate(dir, trustDomain, issuerURL string) (*Issuer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "issuer.key")
	var key *ecdsa.PrivateKey
	raw, err := os.ReadFile(keyPath)
	switch {
	case err == nil:
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("malformed issuer key at %s", keyPath)
		}
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	case os.IsNotExist(err):
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		buf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(keyPath, buf, 0o600); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pub)
	return &Issuer{key: key, kid: hex.EncodeToString(sum[:8]),
		TrustDomain: trustDomain, IssuerURL: issuerURL}, nil
}

// SubjectURI is the durable agent identifier: stable across versions and
// instances, which live in claims, not the URI path (RFC-001 §4).
func (i *Issuer) SubjectURI(agentName string) string {
	return fmt.Sprintf("spiffe://%s/agent/%s", i.TrustDomain, agentName)
}

type IssueParams struct {
	AgentName     string
	VersionDigest string
	InstanceID    string
	Owner         string
	WritID        string
	AttType       string
	TTL           time.Duration
}

func (i *Issuer) Issue(p IssueParams) (string, error) {
	ttl := p.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		return "", fmt.Errorf("ttl %s exceeds maximum %s", ttl, MaxTTL)
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": i.IssuerURL,
		"sub": i.SubjectURI(p.AgentName),
		"jti": p.InstanceID + "." + fmt.Sprint(now.UnixNano()),
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		// cnf reserved for proof-of-possession (v1, RFC-001 §6).
		"cnf": nil,
		"chancery": map[string]any{
			"agent": p.AgentName,
			"ver":   p.VersionDigest,
			"inst":  p.InstanceID,
			"owner": p.Owner,
			"writ":  p.WritID,
			"att":   map[string]any{"type": p.AttType},
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = i.kid
	return tok.SignedString(i.key)
}

// Verify checks signature and time bounds and returns the document.
// Registry-side revocation is a separate in-path check (store.CheckIssuable)
// — a valid signature is necessary, never sufficient.
func (i *Issuer) Verify(token string) (*Document, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return &i.key.PublicKey, nil
	}, jwt.WithLeeway(Leeway), jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("identity document rejected: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("identity document rejected: malformed claims")
	}
	ch, ok := claims["chancery"].(map[string]any)
	if !ok {
		return nil, errors.New("identity document rejected: missing chancery claims")
	}
	exp, _ := claims.GetExpirationTime()
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	att := ""
	if a, ok := ch["att"].(map[string]any); ok {
		att = str(a, "type")
	}
	return &Document{
		Issuer:   str(claims, "iss"),
		Subject:  str(claims, "sub"),
		Agent:    str(ch, "agent"),
		Version:  str(ch, "ver"),
		Instance: str(ch, "inst"),
		Owner:    str(ch, "owner"),
		Writ:     str(ch, "writ"),
		AttType:  att,
		Expires:  exp.Time,
	}, nil
}

// Key exposes the signing key for the writ package (same issuer keys in
// MVP, RFC-002 §7).
func (i *Issuer) Key() *ecdsa.PrivateKey { return i.key }
func (i *Issuer) KeyID() string          { return i.kid }
