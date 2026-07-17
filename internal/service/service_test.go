package service

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chanceryhq/chancery/internal/identity"
	"github.com/chanceryhq/chancery/internal/store"
)

func testService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "chancery.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	iss, err := identity.LoadOrCreate(dir, "acme.com", "https://chancery.acme.com")
	if err != nil {
		t.Fatal(err)
	}
	return &Service{St: st, Iss: iss}
}

func hasShadowEvent(t *testing.T, s *Service, name string) bool {
	t.Helper()
	events, err := s.St.AuditTimeline(50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Event == "agent.unregistered_ref" && strings.Contains(e.Reason, "name="+name) {
			return true
		}
	}
	return false
}

// Shadow-agent observation v0 (RFC-000 Addendum A, Q7): a control-plane
// reference to an unregistered agent is recorded as a discovery signal.
func TestShadowAgentObservation(t *testing.T) {
	s := testService(t)

	if _, _, err := s.StartInstance("ghost-bot", 0); err == nil {
		t.Fatal("expected error starting an instance for an unknown agent")
	}
	if !hasShadowEvent(t, s, "ghost-bot") {
		t.Error("unregistered instance.start must emit agent.unregistered_ref")
	}

	if _, _, err := s.GrantWrit("user:a@acme.com", "phantom-bot", []string{"call:x/*"}, 0, 0, ""); err == nil {
		t.Fatal("expected error granting to an unknown agent")
	}
	if !hasShadowEvent(t, s, "phantom-bot") {
		t.Error("unregistered writ.grant must emit agent.unregistered_ref")
	}
}

func TestAddVersionSupersedesAndKeepsHistory(t *testing.T) {
	// RFC-001: changing the content makes a new immutable version; old
	// versions are kept.
	s := testService(t)
	_, v1, err := s.RegisterAgent("bot", "user:a@acme.com", "t", "p1", "c1", "tl1", "m")
	if err != nil {
		t.Fatal(err)
	}
	_, v2, err := s.AddVersion("bot", "p2-changed", "c1", "tl1", "m")
	if err != nil {
		t.Fatal(err)
	}
	if v2.Seq != 2 {
		t.Errorf("new version seq = %d, want 2", v2.Seq)
	}
	if v1.Digest() == v2.Digest() {
		t.Error("a changed prompt must produce a different content digest")
	}
	all, err := s.St.ListVersions(v2.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("history length = %d, want 2 (old versions kept)", len(all))
	}
	// Versioning an unknown agent is a shadow-agent signal.
	if _, _, err := s.AddVersion("ghost", "p", "c", "tl", "m"); err == nil {
		t.Fatal("versioning an unknown agent must error")
	}
	if !hasShadowEvent(t, s, "ghost") {
		t.Error("versioning an unregistered agent must emit agent.unregistered_ref")
	}
}

func TestGrantRefusesInactiveAgent(t *testing.T) {
	// Finding #4: a writ cannot be granted to a revoked agent.
	s := testService(t)
	s.RegisterAgent("bot", "user:a@acme.com", "t", "p", "c", "tl", "m")
	if err := s.St.SetAgentState("bot", store.StateRevoked); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GrantWrit("user:a@acme.com", "bot", []string{"call:x/*"}, 0, 0, ""); !errors.Is(err, store.ErrInactive) {
		t.Errorf("granting to a revoked agent must be refused, got %v", err)
	}
}

func TestBlockForSubjectPicksTheAgentsBlock(t *testing.T) {
	// Finding #1: with a delegated writ, the block for the parent must be
	// the parent's grant block, not the child's (latest) block.
	s := testService(t)
	s.RegisterAgent("parent", "user:a@acme.com", "t", "p", "c", "tl", "m")
	s.RegisterAgent("child", "user:a@acme.com", "t", "p", "c", "tl", "m")
	wid, root, err := s.GrantWrit("user:a@acme.com", "parent", []string{"call:github/*"}, 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DelegateWrit(wid, "", "child", []string{"call:github/get_*"}, 0); err != nil {
		t.Fatal(err)
	}
	parentURI := s.Iss.SubjectURI("parent")
	childURI := s.Iss.SubjectURI("child")

	pb, err := s.St.BlockForSubject(wid, parentURI)
	if err != nil {
		t.Fatal(err)
	}
	if pb.ID != root {
		t.Errorf("parent's block = %s, want the grant block %s", pb.ID, root)
	}
	cb, err := s.St.BlockForSubject(wid, childURI)
	if err != nil {
		t.Fatal(err)
	}
	if cb.ID == root {
		t.Error("child's block must not be the parent's grant block")
	}
	// Evaluated at the parent's block, the full grant applies…
	if d := s.CheckAction(wid, pb.ID, "call", "github/create_issue"); d.Effect != "allow" {
		t.Errorf("parent block should allow create_issue, got %+v", d)
	}
	// …but at the child's block it's narrowed.
	if d := s.CheckAction(wid, cb.ID, "call", "github/create_issue"); d.Effect != "deny" {
		t.Errorf("child block must deny create_issue, got %+v", d)
	}
	// An agent that holds no block on the writ is an error, not a silent
	// fallback to some other agent's authority.
	if _, err := s.St.BlockForSubject(wid, s.Iss.SubjectURI("stranger")); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("subject with no block must be ErrNotFound, got %v", err)
	}
}

func TestRegisteredAgentEmitsNoShadowEvent(t *testing.T) {
	s := testService(t)
	if _, _, err := s.RegisterAgent("real-bot", "user:a@acme.com", "t", "p", "c", "tl", "m"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.StartInstance("real-bot", 0); err != nil {
		t.Fatal(err)
	}
	if hasShadowEvent(t, s, "real-bot") {
		t.Error("a registered agent must not produce a shadow-agent event")
	}
}

// Full lifecycle through the service layer, the same path the CLI and API
// share (RFC-008): register -> grant -> delegate -> allow -> revoke -> deny.
func TestServiceEndToEnd(t *testing.T) {
	s := testService(t)
	s.RegisterAgent("parent", "user:a@acme.com", "t", "p", "c", "tl", "m")
	s.RegisterAgent("child", "user:a@acme.com", "t", "p", "c", "tl", "m")

	wid, _, err := s.GrantWrit("user:a@acme.com", "parent", []string{"call:github/*"}, 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, lineage, err := s.DelegateWrit(wid, "", "child", []string{"call:github/get_*"}, 0); err != nil {
		t.Fatal(err)
	} else if len(lineage) != 3 {
		t.Errorf("lineage = %v", lineage)
	}
	if d := s.CheckAction(wid, "", "call", "github/get_repo"); d.Effect != "allow" {
		t.Errorf("expected allow, got %+v", d)
	}
	if d := s.CheckAction(wid, "", "call", "github/create_issue"); d.Effect != "deny" {
		t.Errorf("attenuation failed: %+v", d)
	}
}

// spawnFixture: an orchestrator holding a writ with work caps AND the
// admin:spawn/researcher capability, plus the researcher template.
func spawnFixture(t *testing.T) (*Service, string) {
	t.Helper()
	s := testService(t)
	if _, _, err := s.RegisterAgent("orchestrator", "user:a@acme.com", "t", "p", "c", "tl", "m"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTemplate("researcher", "reads github",
		[]string{"call:github/get_*", "call:github/search_*"}, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	wid, _, err := s.GrantWrit("user:a@acme.com", "orchestrator",
		[]string{"call:github/*", "admin:spawn/researcher"}, time.Hour, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	return s, wid
}

func TestSpawnWithinTemplate(t *testing.T) {
	// RFC-012 §4: writ-gated spawn registers an ephemeral child, owner
	// inherited, and delegates a narrowed block in one operation.
	s, wid := spawnFixture(t)
	child, blockID, err := s.SpawnAgent(wid, "", "orchestrator", "researcher", "worker-1",
		[]string{"call:github/get_*"}, 10*time.Minute, "p", "c", "tl", "m")
	if err != nil {
		t.Fatal(err)
	}
	if child.Owner != "user:a@acme.com" || child.SpawnedBy != "orchestrator" || child.Template != "researcher" {
		t.Errorf("provenance wrong: %+v", child)
	}
	if child.ExpiresAt == nil {
		t.Fatal("spawned agent must carry an expiry")
	}
	if d := s.CheckAction(wid, blockID, "call", "github/get_repo"); d.Effect != "allow" {
		t.Errorf("child should act within its caps: %+v", d)
	}
	if d := s.CheckAction(wid, blockID, "call", "github/create_issue"); d.Effect != "deny" {
		t.Errorf("child must be narrowed: %+v", d)
	}
	// The child holds no spawn capability: spawned agents cannot spawn
	// unless explicitly delegated admin:spawn/* — and here they are not.
	if _, _, err := s.SpawnAgent(wid, "", "worker-1", "researcher", "worker-2",
		nil, 0, "p", "c", "tl", "m"); err == nil {
		t.Error("a child without admin:spawn must not be able to spawn")
	}
}

func TestSpawnRefusedWithoutAdminCap(t *testing.T) {
	s := testService(t)
	s.RegisterAgent("plain", "user:a@acme.com", "t", "p", "c", "tl", "m")
	s.CreateTemplate("researcher", "r", []string{"call:github/get_*"}, time.Hour)
	wid, _, err := s.GrantWrit("user:a@acme.com", "plain", []string{"call:github/*"}, time.Hour, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SpawnAgent(wid, "", "plain", "researcher", "w",
		nil, 0, "p", "c", "tl", "m"); err == nil || !strings.Contains(err.Error(), "spawn refused") {
		t.Errorf("spawn without admin:spawn/<template> must be refused, got %v", err)
	}
	events, _ := s.St.AuditTimeline(10)
	found := false
	for _, e := range events {
		if e.Event == "agent.spawn_refused" {
			found = true
		}
	}
	if !found {
		t.Error("a refused spawn must be audited as agent.spawn_refused")
	}
}

func TestSpawnCapExceedingTemplateRefused(t *testing.T) {
	s, wid := spawnFixture(t)
	if _, _, err := s.SpawnAgent(wid, "", "orchestrator", "researcher", "w",
		[]string{"call:github/*"}, 0, "p", "c", "tl", "m"); err == nil ||
		!strings.Contains(err.Error(), "exceeds template") {
		t.Errorf("cap wider than the template ceiling must be refused, got %v", err)
	}
}

func TestSpawnTTLExceedingTemplateRefused(t *testing.T) {
	s, wid := spawnFixture(t)
	if _, _, err := s.SpawnAgent(wid, "", "orchestrator", "researcher", "w",
		nil, 2*time.Hour, "p", "c", "tl", "m"); err == nil ||
		!strings.Contains(err.Error(), "exceeds template max") {
		t.Errorf("ttl above the template max must be refused, got %v", err)
	}
}

func TestExpiredEphemeralIsDeniedAndSwept(t *testing.T) {
	// RFC-012 §4: expiry denies in-path lazily; the sweep retires.
	s, wid := spawnFixture(t)
	child, blockID, err := s.SpawnAgent(wid, "", "orchestrator", "researcher", "shortlived",
		nil, 0, "p", "c", "tl", "m")
	if err != nil {
		t.Fatal(err)
	}
	// Force the expiry into the past in the registry.
	if err := s.St.SetAgentExpiry("shortlived", time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if d := s.CheckAction(wid, blockID, "call", "github/get_repo"); d.Effect != "deny" ||
		!strings.Contains(d.Reason, "expired") {
		t.Errorf("expired ephemeral must be denied in-path, got %+v", d)
	}
	if _, _, err := s.GrantWrit("user:a@acme.com", "shortlived", []string{"call:x/y"}, time.Hour, 0, ""); err == nil {
		t.Error("granting to an expired ephemeral must be refused")
	}
	names, err := s.St.SweepExpired()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "shortlived" {
		t.Errorf("sweep = %v, want [shortlived]", names)
	}
	a, err := s.St.GetAgentByName("shortlived")
	if err != nil {
		t.Fatal(err)
	}
	if a.State != store.StateRetired {
		t.Errorf("swept agent state = %s, want retired", a.State)
	}
	_ = child
}

func TestGrantsVerbDetectsNetCaps(t *testing.T) {
	// RFC-013: granting net:… is the opt-in signal for the URL guard.
	s := testService(t)
	s.RegisterAgent("web-bot", "user:a@acme.com", "t", "p", "c", "tl", "m")
	wNet, _, err := s.GrantWrit("user:a@acme.com", "web-bot",
		[]string{"call:browser/*", "net:github.com/*"}, 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	wCall, _, err := s.GrantWrit("user:a@acme.com", "web-bot", []string{"call:browser/*"}, 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if !s.GrantsVerb(wNet, "", "net") {
		t.Error("writ with net caps must report GrantsVerb(net)")
	}
	if s.GrantsVerb(wCall, "", "net") {
		t.Error("call-only writ must not report GrantsVerb(net)")
	}
}

// Task-bound grants (RFC-017): the declared purpose rides in the writ
// metadata (for intent checkers and the audit trail); oversized tasks
// are refused — the field is metadata, not a prompt.
func TestTaskBoundGrant(t *testing.T) {
	s := testService(t)
	if _, _, err := s.RegisterAgent("task-bot", "user:a@acme.com", "p", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	wid, _, err := s.GrantWrit("user:a@acme.com", "task-bot",
		[]string{"call:github/*"}, time.Hour, 0, "review PR #123")
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.St.GetWrit(wid)
	if err != nil {
		t.Fatal(err)
	}
	if w.Task != "review PR #123" {
		t.Errorf("task not stored: %q", w.Task)
	}
	long := strings.Repeat("x", 201)
	if _, _, err := s.GrantWrit("user:a@acme.com", "task-bot",
		[]string{"call:github/*"}, time.Hour, 0, long); err == nil {
		t.Error("a >200-char task must be refused")
	}
}

// Capability leases (RFC-015): valid while the authority lives, dead
// the moment the writ (or block path) is revoked — mid-flight
// revocation fails at the cooperating server, not after landing.
func TestLeaseMintVerifyAndRevocation(t *testing.T) {
	s := testService(t)
	if _, _, err := s.RegisterAgent("lease-bot", "user:a@acme.com", "p", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	wid, blk, err := s.GrantWrit("user:a@acme.com", "lease-bot",
		[]string{"call:stub/*"}, time.Hour, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := s.MintLease(wid, blk, "lease-bot", "stub/echo")
	if err != nil {
		t.Fatal(err)
	}
	info, reason, valid := s.VerifyLease(lease)
	if !valid || info.Resource != "stub/echo" || info.Writ != wid || info.Agent != "lease-bot" {
		t.Fatalf("fresh lease must verify with full claims (valid=%v reason=%q info=%+v)", valid, reason, info)
	}
	// Tampered lease: flip a byte in the signature.
	bad := lease[:len(lease)-2] + "xx"
	if _, _, valid := s.VerifyLease(bad); valid {
		t.Error("tampered lease must not verify")
	}
	// Revoke the writ: the SAME lease dies — liveness is re-checked at
	// verification, which is the whole point.
	if err := s.St.RevokeWrit(wid); err != nil {
		t.Fatal(err)
	}
	if _, reason, valid := s.VerifyLease(lease); valid {
		t.Error("lease must die when its writ is revoked")
	} else if !strings.Contains(reason, "revoked") {
		t.Errorf("reason should name revocation, got %q", reason)
	}
}
