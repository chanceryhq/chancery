package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"
)

// Capability leases (RFC-015): a short-lived, signed token stamped onto
// each ADMITTED tool call. A cooperating tool server verifies the lease
// immediately before committing a side effect (and at checkpoints of
// long operations), so a revocation that lands while a call is in
// flight fails AT THE SERVER instead of landing. Admission-time denial
// remains the universal floor; the lease shrinks the in-flight window
// for servers that opt in.
//
// Revocation semantics: verification re-checks writ/block liveness in
// the registry. Chancery's revocations are monotonic (nothing is ever
// un-revoked), so a liveness re-check is equivalent to an epoch
// counter — with no extra state.

// LeaseTTL bounds how long an admitted call's lease is valid. Long
// operations re-verify at checkpoints, which also re-checks liveness.
const LeaseTTL = 30 * time.Second

type leaseClaims struct {
	Writ     string `json:"wid"`
	Block    string `json:"blk"`
	Agent    string `json:"agt"`
	Resource string `json:"res"`
	Nonce    string `json:"non"`
	jwt.RegisteredClaims
}

// MintLease signs a lease for one admitted call.
func (s *Service) MintLease(widID, blockID, agentName, resource string) (string, error) {
	now := time.Now().UTC()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, leaseClaims{
		Writ: widID, Block: blockID, Agent: agentName, Resource: resource,
		Nonce: ulid.Make().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(LeaseTTL)),
		},
	})
	tok.Header["kid"] = s.Iss.KeyID()
	return tok.SignedString(s.Iss.Key())
}

// LeaseInfo is what a verified lease attests to: this agent, on this
// resource, under this writ block, was admitted by the gate.
type LeaseInfo struct {
	Writ     string
	Block    string
	Agent    string
	Resource string
}

// VerifyLease checks a lease's signature and expiry, then re-checks the
// underlying writ/block liveness in the registry — a lease minted
// before a revocation fails here, mid-flight. Returns the reason a
// lease is invalid; valid leases return ("", true) plus the lease's
// claims (the server should match Resource against the operation it is
// about to commit).
func (s *Service) VerifyLease(lease string) (info *LeaseInfo, reason string, valid bool) {
	var claims leaseClaims
	_, err := jwt.ParseWithClaims(lease, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return &s.Iss.Key().PublicKey, nil
	}, jwt.WithExpirationRequired())
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, "lease expired", false
		}
		return nil, "lease invalid: " + err.Error(), false
	}
	// Liveness re-check: revocation of the writ, the block, or anything
	// on its path since minting invalidates the lease (RFC-015).
	path, err := s.St.Path(claims.Block)
	if err != nil {
		return nil, "authority revoked since minting: " + err.Error(), false
	}
	if path[0].WritID != claims.Writ {
		return nil, "lease block does not belong to lease writ", false
	}
	return &LeaseInfo{Writ: claims.Writ, Block: claims.Block,
		Agent: claims.Agent, Resource: claims.Resource}, "", true
}
