package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "chancery.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func register(t *testing.T, s *Store, name string) (*Agent, *Version, *Instance) {
	t.Helper()
	a, err := s.CreateAgent(name, "user:aneesh@acme.com", "test agent")
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.CreateVersion(a.ID, "sha256:p", "sha256:c", "sha256:t", "claude-fable-5")
	if err != nil {
		t.Fatal(err)
	}
	in, err := s.CreateInstance(a.ID, v.ID, "declared", "")
	if err != nil {
		t.Fatal(err)
	}
	return a, v, in
}

func TestRegisterIssueRoundtrip(t *testing.T) {
	s := testStore(t)
	a, v, in := register(t, s, "deploy-bot")

	ga, gv, gi, err := s.CheckIssuable(in.ID)
	if err != nil {
		t.Fatalf("active instance must be issuable: %v", err)
	}
	if ga.ID != a.ID || gv.ID != v.ID || gi.ID != in.ID {
		t.Error("CheckIssuable returned wrong principals")
	}
	if gv.Seq != 1 {
		t.Errorf("first version seq = %d, want 1", gv.Seq)
	}
}

func TestDuplicateAgentRefused(t *testing.T) {
	s := testStore(t)
	register(t, s, "deploy-bot")
	if _, err := s.CreateAgent("deploy-bot", "user:x@acme.com", "dup"); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate name must be ErrConflict, got %v", err)
	}
}

func TestRevocationAtEachLayer(t *testing.T) {
	// RFC-001 §4: revocation works at agent, version, and instance layers,
	// each independently killing issuance.
	s := testStore(t)

	_, _, in := register(t, s, "by-agent")
	if err := s.SetAgentState("by-agent", StateRevoked); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.CheckIssuable(in.ID); !errors.Is(err, ErrInactive) {
		t.Errorf("revoked agent: want ErrInactive, got %v", err)
	}

	_, v2, in2 := register(t, s, "by-version")
	if err := s.RevokeVersion(v2.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.CheckIssuable(in2.ID); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked version: want ErrRevoked, got %v", err)
	}

	_, _, in3 := register(t, s, "by-instance")
	if err := s.RevokeInstance(in3.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.CheckIssuable(in3.ID); !errors.Is(err, ErrInactive) {
		t.Errorf("revoked instance: want ErrInactive, got %v", err)
	}
}

func TestSuspendIsReversible(t *testing.T) {
	s := testStore(t)
	_, _, in := register(t, s, "deploy-bot")
	if err := s.SetAgentState("deploy-bot", StateSuspended); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.CheckIssuable(in.ID); err == nil {
		t.Error("suspended agent must not be issuable")
	}
	if err := s.SetAgentState("deploy-bot", StateActive); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.CheckIssuable(in.ID); err != nil {
		t.Errorf("reactivated agent must be issuable: %v", err)
	}
}

func TestVersionsAreAppendOnly(t *testing.T) {
	s := testStore(t)
	a, _, _ := register(t, s, "deploy-bot")
	v2, err := s.CreateVersion(a.ID, "sha256:p2", "sha256:c2", "sha256:t2", "claude-fable-5")
	if err != nil {
		t.Fatal(err)
	}
	if v2.Seq != 2 {
		t.Errorf("second version seq = %d, want 2", v2.Seq)
	}
	latest, err := s.LatestVersion(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != v2.ID {
		t.Error("latest version is not the newest")
	}
	all, err := s.ListVersions(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("history length = %d, want 2 (versions are never edited)", len(all))
	}
}
