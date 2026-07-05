// Package service is the single implementation of Chancery's operations
// (RFC-008): the HTTP API and the CLI are thin clients over it. One code
// path to test, one to secure.
package service

import (
	"errors"
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

// resolveAgent looks up an agent by name and, if it does not exist,
// records a shadow-agent observation before returning the error
// (RFC-000 Addendum A, Q7): every reference to an unregistered agent at
// a control-plane surface is a discovery signal in the audit stream —
// inventory as a byproduct of enforcement, not a scanner. `where` names
// the surface (e.g. "instance.start") for the audit reason.
func (s *Service) resolveAgent(name, where string) (*store.Agent, error) {
	a, err := s.St.GetAgentByName(name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.St.Audit(store.AuditEvent{Event: "agent.unregistered_ref",
				Reason: fmt.Sprintf("name=%s at=%s", name, where)})
		}
		return nil, err
	}
	return a, nil
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

// AddVersion records a new immutable version of an existing agent
// (RFC-001): change the prompt/config/tools/model and it is a new
// content-addressed version, superseding the prior one. Old versions are
// never edited — they remain queryable for attribution.
func (s *Service) AddVersion(agentName, promptSHA, configSHA, toolsSHA, model string) (*store.Agent, *store.Version, error) {
	a, err := s.resolveAgent(agentName, "agent.version")
	if err != nil {
		return nil, nil, err
	}
	v, err := s.St.CreateVersion(a.ID, promptSHA, configSHA, toolsSHA, model)
	if err != nil {
		return nil, nil, err
	}
	s.St.Audit(store.AuditEvent{Event: "agent.version", AgentID: a.ID,
		Reason: fmt.Sprintf("seq=%d version=%s", v.Seq, v.Digest())})
	return a, v, nil
}

// StartInstance registers a runtime instance and issues its first
// identity document (RFC-001).
func (s *Service) StartInstance(agentName string, ttl time.Duration) (*store.Instance, string, error) {
	a, err := s.resolveAgent(agentName, "instance.start")
	if err != nil {
		return nil, "", err
	}
	if err := a.ActiveErr(); err != nil {
		return nil, "", err
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
	a, err := s.resolveAgent(agentName, "writ.grant")
	if err != nil {
		return "", "", err
	}
	if err := a.ActiveErr(); err != nil {
		return "", "", fmt.Errorf("cannot grant a writ: %w", err)
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
	child, err := s.resolveAgent(childName, "writ.delegate")
	if err != nil {
		return "", nil, err
	}
	if err := child.ActiveErr(); err != nil {
		return "", nil, fmt.Errorf("cannot delegate: %w", err)
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

// CreateTemplate locks a pre-approved shape for runtime-spawned agents
// (RFC-012 §4): the ceiling a human approves once, that every spawn
// must fit inside.
func (s *Service) CreateTemplate(name, purpose string, maxCapStrs []string, maxTTL time.Duration) (*store.Template, error) {
	// The template name becomes the spawn resource ("spawn/<name>"), so
	// it must be a valid concrete resource segment.
	if err := policy.ValidateResource("spawn/" + name); err != nil {
		return nil, fmt.Errorf("template name %q: %w", name, err)
	}
	if len(maxCapStrs) == 0 {
		return nil, errors.New("a template requires at least one max capability")
	}
	for _, cs := range maxCapStrs {
		if _, err := writ.ParseCap(cs); err != nil {
			return nil, err
		}
	}
	if maxTTL <= 0 {
		return nil, errors.New("a template requires a positive --max-ttl")
	}
	t, err := s.St.CreateTemplate(name, purpose, maxCapStrs, maxTTL)
	if err != nil {
		return nil, err
	}
	s.St.Audit(store.AuditEvent{Event: "template.create",
		Reason: fmt.Sprintf("name=%s max_caps=%s max_ttl=%s", name, strings.Join(maxCapStrs, ","), maxTTL)})
	return t, nil
}

// SpawnAgent is writ-gated runtime agent creation (RFC-012): an
// orchestrator whose writ carries `admin:spawn/<template>` registers an
// ephemeral child within a pre-approved template and delegates it a
// narrowed block of its own writ — one atomic operation, no admin token.
// The spawned agent can never exceed the template ceiling, the
// orchestrator's own authority (delegation attenuates), or the
// template's max TTL.
func (s *Service) SpawnAgent(widID, parentBlockID, parentName, templateName, childName string,
	capStrs []string, ttl time.Duration,
	promptSHA, configSHA, toolsSHA, model string) (*store.Agent, string, error) {

	refuse := func(reason string) (*store.Agent, string, error) {
		s.St.Audit(store.AuditEvent{Event: "agent.spawn_refused", WritID: widID,
			Reason: fmt.Sprintf("parent=%s template=%s child=%s: %s", parentName, templateName, childName, reason)})
		return nil, "", errors.New("spawn refused: " + reason)
	}

	parent, err := s.resolveAgent(parentName, "agent.spawn")
	if err != nil {
		return nil, "", err
	}
	if err := parent.ActiveErr(); err != nil {
		return refuse(err.Error())
	}
	// The parent acts under ITS OWN block (never another agent's).
	if parentBlockID == "" {
		b, err := s.St.BlockForSubject(widID, s.Iss.SubjectURI(parent.Name))
		if err != nil {
			return refuse(err.Error())
		}
		parentBlockID = b.ID
	} else {
		b, err := s.St.BlockForSubject(widID, s.Iss.SubjectURI(parent.Name))
		if err != nil || b.ID != parentBlockID {
			return refuse(fmt.Sprintf("block %s does not belong to agent %s on writ %s", parentBlockID, parent.Name, widID))
		}
	}
	// L1–L2 gate: spawning is an action like any other. The writ must
	// carry admin:spawn/<template> (or a pattern admitting it).
	if d := s.decide(widID, parentBlockID, "admin", "spawn/"+templateName); d.Effect != policy.Allow {
		return refuse(fmt.Sprintf("[%s] %s", d.Layer, d.Reason))
	}
	tpl, err := s.St.GetTemplate(templateName)
	if err != nil {
		return refuse(err.Error())
	}
	// Every requested capability must fit under some template max-cap.
	var caveats []string
	for _, cs := range capStrs {
		c, err := writ.ParseCap(cs)
		if err != nil {
			return refuse(err.Error())
		}
		ok := false
		for _, ms := range tpl.MaxCaps {
			if m, err := writ.ParseCap(ms); err == nil && m.Implies(c) {
				ok = true
				break
			}
		}
		if !ok {
			return refuse(fmt.Sprintf("capability %s exceeds template %s ceiling (%s)",
				c, tpl.Name, strings.Join(tpl.MaxCaps, ", ")))
		}
		caveats = append(caveats, cs)
	}
	if len(caveats) == 0 {
		// No explicit request = the full template ceiling.
		caveats = tpl.MaxCaps
	}
	if ttl <= 0 {
		ttl = tpl.MaxTTL
	}
	if ttl > tpl.MaxTTL {
		return refuse(fmt.Sprintf("ttl %s exceeds template max %s", ttl, tpl.MaxTTL))
	}
	expiresAt := time.Now().UTC().Add(ttl)
	child, err := s.St.CreateSpawnedAgent(childName, parent.Owner, tpl.Purpose,
		parent.Name, tpl.Name, expiresAt)
	if err != nil {
		return refuse(err.Error())
	}
	if _, err := s.St.CreateVersion(child.ID, promptSHA, configSHA, toolsSHA, model); err != nil {
		return nil, "", err
	}
	s.St.Audit(store.AuditEvent{Event: "agent.spawn", AgentID: child.ID, WritID: widID,
		Reason: fmt.Sprintf("parent=%s template=%s expires=%s", parent.Name, tpl.Name,
			expiresAt.Format(time.RFC3339))})
	blockID, _, err := s.DelegateWrit(widID, parentBlockID, childName, caveats, ttl)
	if err != nil {
		// The delegation is the child's authority; without it the spawn
		// is void. Retire the just-created identity so it cannot linger.
		s.St.SetAgentState(childName, store.StateRetired)
		return refuse("delegation failed: " + err.Error())
	}
	return child, blockID, nil
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
			if err := a.ActiveErr(); err != nil {
				return policy.Decision{Effect: policy.Deny, Layer: "registry", Reason: err.Error()}
			}
			allowlist, _ = s.St.GetAllowlist(a.ID)
		}
	}
	return policy.Decide(w, allowlist, verb, resource)
}

// GrantsVerb reports whether the writ's block-0 grant contains any
// capability with the given verb (or the * verb). Used by PEPs to
// auto-enable verb-specific guards — e.g. the MCP proxy turns on the
// URL guard iff the writ grants net (RFC-013): granting net:… IS the
// opt-in to navigation scoping.
func (s *Service) GrantsVerb(widID, leafBlockID, verb string) bool {
	if leafBlockID == "" {
		b, err := s.St.LatestBlock(widID)
		if err != nil {
			return false
		}
		leafBlockID = b.ID
	}
	w, err := s.verifiedPath(leafBlockID)
	if err != nil {
		return false
	}
	for _, c := range w.Blocks[0].Cap {
		if c.Verb == verb || c.Verb == "*" {
			return true
		}
	}
	return false
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
