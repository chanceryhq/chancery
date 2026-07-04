package store

import (
	"strings"
	"testing"
)

func seedAudit(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := s.Audit(AuditEvent{Event: "action.check", Verb: "call",
			Resource: "srv/tool", Decision: "ALLOW", Reason: "test"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditChainVerifiesClean(t *testing.T) {
	s := testStore(t)
	seedAudit(t, s, 5)
	n, err := s.VerifyAuditChain()
	if err != nil {
		t.Fatalf("clean chain must verify: %v", err)
	}
	if n != 5 {
		t.Errorf("verified %d events, want 5", n)
	}
}

func TestAuditChainLinksToGenesis(t *testing.T) {
	s := testStore(t)
	seedAudit(t, s, 1)
	events, err := s.AuditTimeline(1)
	if err != nil {
		t.Fatal(err)
	}
	if events[0].PrevHash != GenesisHash {
		t.Errorf("first event prev_hash = %q, want genesis", events[0].PrevHash)
	}
	if events[0].Hash == "" {
		t.Error("event hash must be set")
	}
}

func TestAuditEditDetected(t *testing.T) {
	s := testStore(t)
	seedAudit(t, s, 5)
	// Launder an embarrassing denial: rewrite a reason in place.
	if _, err := s.db.Exec(`UPDATE audit_events SET reason = 'nothing happened' WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	n, err := s.VerifyAuditChain()
	if err == nil {
		t.Fatal("edited event must break the chain")
	}
	if !strings.Contains(err.Error(), "seq 3") {
		t.Errorf("error must name the broken event, got: %v", err)
	}
	if n != 2 {
		t.Errorf("prefix property: %d intact events before break, want 2", n)
	}
}

func TestAuditDeletionDetected(t *testing.T) {
	s := testStore(t)
	seedAudit(t, s, 5)
	if _, err := s.db.Exec(`DELETE FROM audit_events WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAuditChain(); err == nil {
		t.Fatal("deleted event must break the chain")
	}
}

func TestAuditDecisionFieldsSurvive(t *testing.T) {
	s := testStore(t)
	a, _, in := register(t, s, "audited-bot")
	if err := s.Audit(AuditEvent{Event: "mcp.call", AgentID: a.ID, Instance: in.ID,
		WritID: "w_x", Verb: "call", Resource: "srv/tool", Decision: "DENY",
		Reason: "[writ] outside effective authority"}); err != nil {
		t.Fatal(err)
	}
	events, err := s.AuditTimeline(1)
	if err != nil {
		t.Fatal(err)
	}
	e := events[0]
	if e.AgentID != a.ID || e.Instance != in.ID || e.WritID != "w_x" ||
		e.Decision != "DENY" || e.Resource != "srv/tool" {
		t.Errorf("attribution fields must round-trip: %+v", e)
	}
}
