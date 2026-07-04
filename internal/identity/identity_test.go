package identity

import (
	"strings"
	"testing"
	"time"
)

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	iss, err := LoadOrCreate(t.TempDir(), "acme.com", "https://chancery.acme.com")
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func TestIssueAndVerify(t *testing.T) {
	iss := testIssuer(t)
	tok, err := iss.Issue(IssueParams{
		AgentName: "deploy-bot", VersionDigest: "sha256:9f2c", InstanceID: "01K1X4",
		Owner: "user:aneesh@acme.com", WritID: "w_01", AttType: "declared",
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := iss.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Subject != "spiffe://acme.com/agent/deploy-bot" {
		t.Errorf("subject = %q", doc.Subject)
	}
	if doc.Version != "sha256:9f2c" || doc.Instance != "01K1X4" || doc.Writ != "w_01" {
		t.Errorf("claims round-trip failed: %+v", doc)
	}
	if doc.AttType != "declared" {
		t.Errorf("attestation type = %q", doc.AttType)
	}
	if ttl := time.Until(doc.Expires); ttl > DefaultTTL+time.Minute {
		t.Errorf("default ttl too long: %s", ttl)
	}
}

func TestTTLCeiling(t *testing.T) {
	iss := testIssuer(t)
	if _, err := iss.Issue(IssueParams{AgentName: "a", TTL: 2 * time.Hour}); err == nil {
		t.Error("ttl above MaxTTL must be refused")
	}
}

func TestForeignSignatureRejected(t *testing.T) {
	a, b := testIssuer(t), testIssuer(t)
	tok, err := a.Issue(IssueParams{AgentName: "deploy-bot"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(tok); err == nil {
		t.Error("document signed by another issuer must be rejected")
	}
}

func TestTamperedTokenRejected(t *testing.T) {
	iss := testIssuer(t)
	tok, err := iss.Issue(IssueParams{AgentName: "deploy-bot"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	parts[1] = parts[1][:len(parts[1])-2] + "AA"
	if _, err := iss.Verify(strings.Join(parts, ".")); err == nil {
		t.Error("tampered payload must be rejected")
	}
}

func TestKeyPersistsAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreate(dir, "acme.com", "https://chancery.acme.com")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a.Issue(IssueParams{AgentName: "deploy-bot"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate(dir, "acme.com", "https://chancery.acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(tok); err != nil {
		t.Errorf("reloaded issuer must verify prior documents: %v", err)
	}
	if a.KeyID() != b.KeyID() {
		t.Error("key id changed across loads")
	}
}
