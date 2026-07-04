package service

import (
	"path/filepath"
	"strings"
	"testing"

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

	if _, _, err := s.GrantWrit("user:a@acme.com", "phantom-bot", []string{"call:x/*"}, 0, 0); err == nil {
		t.Fatal("expected error granting to an unknown agent")
	}
	if !hasShadowEvent(t, s, "phantom-bot") {
		t.Error("unregistered writ.grant must emit agent.unregistered_ref")
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

	wid, _, err := s.GrantWrit("user:a@acme.com", "parent", []string{"call:github/*"}, 0, 0)
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
