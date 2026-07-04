// Package service is the single implementation of Chancery's operations
// (RFC-008): the HTTP API and the CLI are thin clients over it. One code
// path to test, one to secure.
package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/chanceryhq/chancery/internal/identity"
	"github.com/chanceryhq/chancery/internal/policy"
	"github.com/chanceryhq/chancery/internal/store"
	"github.com/chanceryhq/chancery/internal/writ"
)

type Service struct {
	St  *store.Store
	Iss *identity.Issuer
}

// RegisterAgent creates the durable identity and its first version.
// Digests in, never content (RFC-008 §4).
func (s *Service) RegisterAgent(name, owner, purpose, promptSHA, configSHA, toolsSHA, model string) (*store.Agent, *store.Version, error) {
	a, err := s.St.CreateAgent(name, owner, purpose)
	if err != nil {
		return nil, nil, err
	}
	v, err := s.St.CreateVersion(a.ID, promptSHA, configSHA, toolsSHA, model)
	if err != nil {
		return nil, nil, err
	}
	s.St.Audit(store.AuditEvent{Event: "agent.register", AgentID: a.ID,
		Reason: fmt.Sprintf("owner=%s version=%s", owner, v.Digest())})
	return a, v, nil
}

// StartInstance registers a runtime instance and issues its first
// identity document (RFC-001).
func (s *Service) StartInstance(agentName string, ttl time.Duration) (*store.Instance, string, error) {
	a, err := s.St.GetAgentByName(agentName)
	if err != nil {
		return nil, "", err
	}
	if a.State != store.StateActive {
		return nil, "", fmt.Errorf("%w: agent %s is %s", store.ErrInactive, a.Name, a.State)
	}
	v, err := s.St.LatestVersion(a.ID)
	if err != nil {
		return nil, "", err
	}
	in, err := s.St.CreateInstance(a.ID, v.ID, "declared", "")
	if err != nil {
		return nil, "", err
	}
	tok, err := s.Iss.Issue(identity.IssueParams{
		AgentName: a.Name, VersionDigest: v.Digest(), InstanceID: in.ID,
		Owner: a.Owner, AttType: "declared", TTL: ttl,
	})
	if err != nil {
		return nil, "", err
	}
	s.St.Audit(store.AuditEvent{Event: "instance.start", AgentID: a.ID, Instance: in.ID})
	return in, tok, nil
}

// GrantWrit mints block 0 (RFC-002).
func (s *Service) GrantWrit(forPrincipal, agentName string, capStrs []string, ttl time.Duration, maxDepth int) (widID, blockID string, err error) {
	a, err := s.St.GetAgentByName(agentName)
	if err != nil {
		return "", "", err
	}
	v, err := s.St.LatestVersion(a.ID)
	if err != nil {
		return "", "", err
	}
	var caps []writ.Cap
	for _, cs := range capStrs {
		c, err := writ.ParseCap(cs)
		if err != nil {
			return "", "", err
		}
		caps = append(caps, c)
	}
	wid := "w_" + ulid.Make().String()
	exp := time.Now().UTC().Add(ttl)
	w, err := writ.Grant(wid, forPrincipal, s.Iss.SubjectURI(a.Name), v.Digest(),
		caps, maxDepth, exp, s.Iss.Key(), s.Iss.KeyID())
	if err != nil {
		return "", "", err
	}
	rootBlockID := "b_" + ulid.Make().String()
	if err := s.St.CreateWrit(wid, forPrincipal, a.ID, maxDepth, exp,
		rootBlockID, w.JWS[0], s.Iss.SubjectURI(a.Name)); err != nil {
		return "", "", err
	}
	s.St.Audit(store.AuditEvent{Event: "writ.grant", AgentID: a.ID, WritID: wid,
		Reason: fmt.Sprintf("for=%s caps=%d", forPrincipal, len(caps))})
	return wid, rootBlockID, nil
}

// DelegateWrit appends a caveat block for a child agent (RFC-002:
// authority can only narrow).
func (s *Service) DelegateWrit(widID, parentBlockID, childName string, caveatStrs []string, ttl time.Duration) (blockID string, lineage []string, err error) {
	if parentBlockID == "" {
		b, err := s.St.LatestBlock(widID)
		if err != nil {
			return "", nil, err
		}
		parentBlockID = b.ID
	}
	w, err := s.verifiedPath(parentBlockID)
	if err != nil {
		return "", nil, err
	}
	child, err := s.St.GetAgentByName(childName)
	if err != nil {
		return "", nil, err
	}
	if child.State != store.StateActive {
		return "", nil, fmt.Errorf("%w: child agent %s is %s", store.ErrInactive, child.Name, child.State)
	}
	cv, err := s.St.LatestVersion(child.ID)
	if err != nil {
		return "", nil, err
	}
	var caveats []writ.Cap
	for _, cs := range caveatStrs {
		c, err := writ.ParseCap(cs)
		if err != nil {
			return "", nil, err
		}
		caveats = append(caveats, c)
	}
	exp := time.Now().UTC().Add(ttl)
	nw, err := writ.Delegate(w, s.Iss.SubjectURI(child.Name), cv.Digest(),
		caveats, exp, s.Iss.Key(), s.Iss.KeyID())
	if err != nil {
		return "", nil, err
	}
	blockID = "b_" + ulid.Make().String()
	if err := s.St.AppendWritBlock(blockID, widID, parentBlockID, len(nw.Blocks)-1,
		nw.JWS[len(nw.JWS)-1], s.Iss.SubjectURI(child.Name), exp); err != nil {
		return "", nil, err
	}
	s.St.Audit(store.AuditEvent{Event: "writ.delegate", AgentID: child.ID, WritID: widID,
		Reason: fmt.Sprintf("parent_block=%s caveats=%d", parentBlockID, len(caveats))})
	return blockID, nw.Lineage(), nil
}

// CheckAction is the full PDP evaluation for one concrete action
// (RFC-004), audited either way. This is the same conjunction the MCP
// proxy runs in-path.
func (s *Service) CheckAction(widID, leafBlockID, verb, resource string) policy.Decision {
	d := s.decide(widID, leafBlockID, verb, resource)
	decision := "DENY"
	if d.Effect == policy.Allow {
		decision = "ALLOW"
	}
	if err := s.St.Audit(store.AuditEvent{Event: "action.check", WritID: widID,
		Verb: verb, Resource: resource, Decision: decision,
		Reason: "[" + d.Layer + "] " + d.Reason}); err != nil && d.Effect == policy.Allow {
		// An unrecordable action does not happen (RFC-006 §7).
		return policy.Decision{Effect: policy.Deny, Layer: "audit",
			Reason: "audit unavailable; refusing unrecordable action"}
	}
	return d
}

// Decide evaluates one action WITHOUT auditing — the in-path decision
// used by PEPs (e.g. the MCP proxy) that own their own audit wiring so
// they can enforce deny-on-audit-failure at the transport boundary
// (RFC-006 §7). CLI/API callers use CheckAction, which audits.
func (s *Service) Decide(widID, leafBlockID, verb, resource string) policy.Decision {
	return s.decide(widID, leafBlockID, verb, resource)
}

func (s *Service) decide(widID, leafBlockID, verb, resource string) policy.Decision {
	if leafBlockID == "" {
		b, err := s.St.LatestBlock(widID)
		if err != nil {
			return policy.Decision{Effect: policy.Deny, Layer: "registry", Reason: err.Error()}
		}
		leafBlockID = b.ID
	}
	w, err := s.verifiedPath(leafBlockID)
	if err != nil {
		return policy.Decision{Effect: policy.Deny, Layer: "registry", Reason: err.Error()}
	}
	var allowlist []string
	leafURI := w.Blocks[len(w.Blocks)-1].To
	if name, ok := strings.CutPrefix(leafURI, "spiffe://"+s.Iss.TrustDomain+"/agent/"); ok {
		if a, err := s.St.GetAgentByName(name); err == nil {
			if a.State != store.StateActive {
				return policy.Decision{Effect: policy.Deny, Layer: "registry",
					Reason: fmt.Sprintf("acting agent %s is %s", name, a.State)}
			}
			allowlist, _ = s.St.GetAllowlist(a.ID)
		}
	}
	return policy.Decide(w, allowlist, verb, resource)
}

// verifiedPath loads a root→leaf block path (revocation-checked by the
// registry) and cryptographically verifies the chain.
func (s *Service) verifiedPath(leafBlockID string) (*writ.Writ, error) {
	path, err := s.St.Path(leafBlockID)
	if err != nil {
		return nil, err
	}
	var jws []string
	for _, b := range path {
		jws = append(jws, b.JWS)
	}
	return writ.Verify(jws, &s.Iss.Key().PublicKey, time.Now())
}
