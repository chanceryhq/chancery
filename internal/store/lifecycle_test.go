package store

import (
	"errors"
	"testing"
)

// TestTransitionMatrix locks RFC-007 §4: every cell of the agent state
// machine, legal and illegal.
func TestTransitionMatrix(t *testing.T) {
	cases := []struct {
		from, to string
		legal    bool
	}{
		{StateActive, StateSuspended, true},
		{StateActive, StateRetired, true},
		{StateActive, StateRevoked, true},
		{StateActive, StateOrphaned, true},
		{StateSuspended, StateActive, true},
		{StateSuspended, StateRetired, true},
		{StateSuspended, StateRevoked, true},
		{StateSuspended, StateOrphaned, true},
		{StateOrphaned, StateRetired, true},
		{StateOrphaned, StateRevoked, true},
		// orphaned exits to active ONLY via TransferOwner.
		{StateOrphaned, StateActive, false},
		{StateOrphaned, StateSuspended, false},
		// terminal states have no exits, ever.
		{StateRetired, StateActive, false},
		{StateRetired, StateSuspended, false},
		{StateRetired, StateRevoked, false},
		{StateRevoked, StateActive, false},
		{StateRevoked, StateSuspended, false},
		{StateRevoked, StateRetired, false},
	}
	for _, c := range cases {
		s := testStore(t)
		register(t, s, "sm-bot")
		if c.from != StateActive {
			// Reach the starting state (all are reachable from active).
			if err := s.SetAgentState("sm-bot", c.from); err != nil {
				t.Fatalf("setup %s: %v", c.from, err)
			}
		}
		err := s.SetAgentState("sm-bot", c.to)
		if c.legal && err != nil {
			t.Errorf("%s → %s must be legal: %v", c.from, c.to, err)
		}
		if !c.legal && !errors.Is(err, ErrIllegalTransition) {
			t.Errorf("%s → %s must be ErrIllegalTransition, got %v", c.from, c.to, err)
		}
	}
}

func TestNoResurrection(t *testing.T) {
	// The no-resurrection property end-to-end: revoked agent cannot be
	// reactivated by any transition sequence, and issuance stays dead.
	s := testStore(t)
	_, _, in := register(t, s, "dead-bot")
	if err := s.SetAgentState("dead-bot", StateRevoked); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{StateActive, StateSuspended, StateRetired, StateOrphaned} {
		if err := s.SetAgentState("dead-bot", target); !errors.Is(err, ErrIllegalTransition) {
			t.Errorf("revoked → %s must fail, got %v", target, err)
		}
	}
	if err := s.TransferOwner("dead-bot", "user:new@acme.com"); !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("ownership transfer of revoked agent must fail, got %v", err)
	}
	if _, _, _, err := s.CheckIssuable(in.ID); err == nil {
		t.Error("revoked agent must never issue again")
	}
}

func TestOrphanBlocksIssuanceUntilTransfer(t *testing.T) {
	s := testStore(t)
	a, _, in := register(t, s, "orphan-bot")
	if err := s.SetAgentState("orphan-bot", StateOrphaned); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.CheckIssuable(in.ID); !errors.Is(err, ErrInactive) {
		t.Errorf("orphaned agent must not issue, got %v", err)
	}
	// The only way back: a new accountable owner.
	if err := s.TransferOwner("orphan-bot", "user:successor@acme.com"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAgentByName("orphan-bot")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateActive || got.Owner != "user:successor@acme.com" {
		t.Errorf("transfer must reactivate with new owner: %+v", got)
	}
	if _, _, _, err := s.CheckIssuable(in.ID); err != nil {
		t.Errorf("after transfer, issuance must work: %v", err)
	}
	_ = a
}

func TestRetiredNameIsNotReusedSilently(t *testing.T) {
	// Retirement keeps the row (nothing is ever deleted): re-registering
	// the same name conflicts rather than silently minting a doppelgänger.
	s := testStore(t)
	register(t, s, "old-bot")
	if err := s.SetAgentState("old-bot", StateRetired); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAgent("old-bot", "user:x@acme.com", "impostor"); !errors.Is(err, ErrConflict) {
		t.Errorf("retired name must not be silently reusable, got %v", err)
	}
	// History intact.
	a, err := s.GetAgentByName("old-bot")
	if err != nil || a.State != StateRetired {
		t.Errorf("retired record must remain queryable: %+v, %v", a, err)
	}
}
