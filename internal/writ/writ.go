// Package writ implements RFC-002: the writ, a chain of signed blocks in
// which block 0 grants capabilities and every later block may only add
// caveats. Widening is unrepresentable: DelegationBlock has no capability
// field. Effective authority = grant caps ∩ every block's caveats.
package writ

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const DefaultMaxDepth = 4

var (
	ErrDepthLimit    = errors.New("writ: max delegation depth reached")
	ErrTTLExceeded   = errors.New("writ: child expiry exceeds parent expiry")
	ErrNullAuthority = errors.New("writ: delegation would grant no effective authority")
	ErrTampered      = errors.New("writ: chain integrity check failed")
	ErrExpired       = errors.New("writ: expired")
)

// Cap is a capability or caveat pattern: a verb and a resource pattern.
// Resource patterns are exact strings or trailing-'*' prefixes; the full
// grammar belongs to RFC-004 — the intersection algebra is locked here.
type Cap struct {
	Verb     string `json:"verb"`
	Resource string `json:"resource"`
}

func (c Cap) String() string { return c.Verb + ":" + c.Resource }

// ParseCap parses "verb:resource" (resource may contain ':').
func ParseCap(s string) (Cap, error) {
	verb, resource, ok := strings.Cut(s, ":")
	if !ok || verb == "" || resource == "" {
		return Cap{}, fmt.Errorf("writ: capability %q is not verb:resource", s)
	}
	return Cap{Verb: verb, Resource: resource}, nil
}

// matches reports whether the pattern admits the concrete (verb, resource).
func (c Cap) matches(verb, resource string) bool {
	if c.Verb != "*" && c.Verb != verb {
		return false
	}
	if p, ok := strings.CutSuffix(c.Resource, "*"); ok {
		return strings.HasPrefix(resource, p)
	}
	return c.Resource == resource
}

// overlaps reports whether two patterns can admit at least one common
// action — used to refuse null-authority delegations at append time
// (RFC-002 §7, caveat starvation).
func (c Cap) overlaps(o Cap) bool {
	if c.Verb != "*" && o.Verb != "*" && c.Verb != o.Verb {
		return false
	}
	cp, cw := strings.CutSuffix(c.Resource, "*")
	op, ow := strings.CutSuffix(o.Resource, "*")
	switch {
	case cw && ow:
		return strings.HasPrefix(cp, op) || strings.HasPrefix(op, cp)
	case cw:
		return strings.HasPrefix(o.Resource, cp)
	case ow:
		return strings.HasPrefix(c.Resource, op)
	default:
		return c.Resource == o.Resource
	}
}

// Block is one link in the chain. Exactly one of Cap (idx 0) or Caveat
// (idx > 0) is populated — enforced structurally at append and at verify.
type Block struct {
	WID    string `json:"wid"`
	Idx    int    `json:"idx"`
	For    string `json:"for,omitempty"` // block 0: whose authority
	To     string `json:"to"`            // subject: spiffe URI
	ToVer  string `json:"tover"`         // subject version digest
	Cap    []Cap  `json:"cap,omitempty"` // block 0 only
	Caveat []Cap  `json:"caveat,omitempty"`
	Depth  int    `json:"max_depth,omitempty"` // block 0 only
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
	Prev   string `json:"prev,omitempty"` // sha256 of serialized chain prefix
	// DK reserves the per-block delegation key for v1 offline
	// attenuation (RFC-002 §4); always empty in MVP.
	DK string `json:"dk,omitempty"`
}

// Writ is the full chain: decoded blocks plus their JWS encodings.
type Writ struct {
	Blocks []Block
	JWS    []string
}

func (w *Writ) ID() string { return w.Blocks[0].WID }

func prefixHash(jws []string) string {
	sum := sha256.Sum256([]byte(strings.Join(jws, ".")))
	return hex.EncodeToString(sum[:])
}

// blockClaims adapts Block to jwt.Claims. All getters return nil: time
// bounds are validated by Verify against the caller's clock (one code
// path, one error taxonomy), not by the JOSE library.
type blockClaims struct{ Block }

func (blockClaims) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }
func (blockClaims) GetIssuedAt() (*jwt.NumericDate, error)       { return nil, nil }
func (blockClaims) GetNotBefore() (*jwt.NumericDate, error)      { return nil, nil }
func (blockClaims) GetIssuer() (string, error)                   { return "", nil }
func (blockClaims) GetSubject() (string, error)                  { return "", nil }
func (blockClaims) GetAudience() (jwt.ClaimStrings, error)       { return nil, nil }

func signBlock(b Block, key *ecdsa.PrivateKey, kid string) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, blockClaims{Block: b})
	tok.Header["kid"] = kid
	return tok.SignedString(key)
}

// Grant mints block 0. `for` names the authority source (human/team/policy
// principal); `to` and `toVer` name the top-level agent per RFC-001.
func Grant(wid, forPrincipal, to, toVer string, caps []Cap, maxDepth int, exp time.Time,
	key *ecdsa.PrivateKey, kid string) (*Writ, error) {
	if len(caps) == 0 {
		return nil, errors.New("writ: grant requires at least one capability")
	}
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	b := Block{WID: wid, Idx: 0, For: forPrincipal, To: to, ToVer: toVer,
		Cap: caps, Depth: maxDepth, Exp: exp.Unix(), Iat: time.Now().UTC().Unix()}
	jws, err := signBlock(b, key, kid)
	if err != nil {
		return nil, err
	}
	return &Writ{Blocks: []Block{b}, JWS: []string{jws}}, nil
}

// Delegate appends a caveat block for a child principal. There is no way
// to pass capabilities here: the parameter does not exist (RFC-002 §4
// rule 1). Empty caveats are allowed — depth and TTL still narrow.
func Delegate(w *Writ, to, toVer string, caveats []Cap, exp time.Time,
	key *ecdsa.PrivateKey, kid string) (*Writ, error) {
	root := w.Blocks[0]
	parent := w.Blocks[len(w.Blocks)-1]
	if len(w.Blocks) > root.Depth {
		return nil, fmt.Errorf("%w (%d)", ErrDepthLimit, root.Depth)
	}
	if exp.Unix() > parent.Exp {
		return nil, fmt.Errorf("%w: child %s > parent %s", ErrTTLExceeded,
			exp.UTC().Format(time.RFC3339), time.Unix(parent.Exp, 0).UTC().Format(time.RFC3339))
	}
	// Refuse null-authority blocks: every caveat must overlap at least
	// one root capability, else the child could never act.
	for _, cv := range caveats {
		ok := false
		for _, c := range root.Cap {
			if cv.overlaps(c) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("%w: caveat %s intersects no granted capability", ErrNullAuthority, cv)
		}
	}
	b := Block{WID: root.WID, Idx: len(w.Blocks), To: to, ToVer: toVer,
		Caveat: caveats, Exp: exp.Unix(), Iat: time.Now().UTC().Unix(),
		Prev: prefixHash(w.JWS)}
	jws, err := signBlock(b, key, kid)
	if err != nil {
		return nil, err
	}
	return &Writ{Blocks: append(append([]Block{}, w.Blocks...), b),
		JWS: append(append([]string{}, w.JWS...), jws)}, nil
}

// Verify checks every block's signature, index sequence, prefix hashes,
// TTL monotonicity, and structural attenuation (no capability field after
// block 0). It does NOT check revocation — that is the registry's in-path
// job, per action, at the broker.
func Verify(jwsChain []string, pub *ecdsa.PublicKey, at time.Time) (*Writ, error) {
	if len(jwsChain) == 0 {
		return nil, errors.New("writ: empty chain")
	}
	w := &Writ{}
	for i, raw := range jwsChain {
		var bc blockClaims
		_, err := jwt.ParseWithClaims(raw, &bc, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
			}
			return pub, nil
		})
		if err != nil {
			return nil, fmt.Errorf("%w: block %d: %v", ErrTampered, i, err)
		}
		b := bc.Block
		switch {
		case b.Idx != i:
			return nil, fmt.Errorf("%w: block %d claims index %d", ErrTampered, i, b.Idx)
		case i == 0 && (len(b.Cap) == 0 || b.For == ""):
			return nil, fmt.Errorf("%w: block 0 missing grant", ErrTampered)
		case i > 0 && len(b.Cap) > 0:
			return nil, fmt.Errorf("%w: block %d carries capabilities", ErrTampered, i)
		case i > 0 && b.WID != w.Blocks[0].WID:
			return nil, fmt.Errorf("%w: block %d writ id mismatch", ErrTampered, i)
		case i > 0 && b.Prev != prefixHash(jwsChain[:i]):
			return nil, fmt.Errorf("%w: block %d prefix hash mismatch", ErrTampered, i)
		case i > 0 && b.Exp > w.Blocks[i-1].Exp:
			return nil, fmt.Errorf("%w: block %d", ErrTTLExceeded, i)
		}
		if at.Unix() > b.Exp {
			return nil, fmt.Errorf("%w: block %d expired %s", ErrExpired, i,
				time.Unix(b.Exp, 0).UTC().Format(time.RFC3339))
		}
		w.Blocks = append(w.Blocks, b)
		w.JWS = append(w.JWS, raw)
	}
	return w, nil
}

// Check evaluates a concrete action against the chain's effective
// authority: it must match a block-0 capability AND, in every delegation
// block with caveats, at least one caveat (RFC-002 §4: intersection).
func (w *Writ) Check(verb, resource string) bool {
	ok := false
	for _, c := range w.Blocks[0].Cap {
		if c.matches(verb, resource) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	for _, b := range w.Blocks[1:] {
		if len(b.Caveat) == 0 {
			continue
		}
		ok = false
		for _, cv := range b.Caveat {
			if cv.matches(verb, resource) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// Lineage renders the chain as for → to₀ → to₁ → … (RFC-002 §4 rule 4).
func (w *Writ) Lineage() []string {
	out := []string{w.Blocks[0].For}
	for _, b := range w.Blocks {
		out = append(out, b.To)
	}
	return out
}
