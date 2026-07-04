package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/chanceryhq/chancery/internal/api"
	"github.com/chanceryhq/chancery/internal/identity"
	"github.com/chanceryhq/chancery/internal/service"
	"github.com/chanceryhq/chancery/internal/store"
)

const token = "chy_sdk_test_token"

// The SDK is tested against a real control plane (httptest over the api
// package) — no mocks, so the client and server contract are verified
// together.
func testPlane(t *testing.T) *Client {
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
	svc := &service.Service{St: st, Iss: iss}
	// Seed a registered agent and a writ out-of-band (operator actions).
	svc.RegisterAgent("sdk-bot", "user:a@acme.com", "t", "p", "c", "tl", "m")
	sum := sha256.Sum256([]byte(token))
	srv := &api.Server{Svc: svc, AdminTokenHash: hex.EncodeToString(sum[:])}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return New(ts.URL, token)
}

func TestStartInstanceAndGuard(t *testing.T) {
	ctx := context.Background()
	c := testPlane(t)

	in, err := c.StartInstance(ctx, "sdk-bot")
	if err != nil {
		t.Fatal(err)
	}
	if in.IdentityDocument == "" || in.ID == "" {
		t.Fatalf("instance not fully populated: %+v", in)
	}

	// Grant a read-only writ via the API (operator step) then guard.
	var w struct {
		Writ string `json:"writ"`
	}
	if err := c.do(ctx, "POST", "/v1/writs", map[string]any{
		"for": "user:a@acme.com", "to": "sdk-bot",
		"caps": []string{"call:github/get_*"}, "ttl_seconds": 600,
	}, &w); err != nil {
		t.Fatal(err)
	}

	d, err := in.Guard(ctx, w.Writ, "call", "github/get_repo")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed {
		t.Errorf("granted action should be advisory-allowed: %+v", d)
	}

	d, err = in.Guard(ctx, w.Writ, "call", "github/delete_repo")
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Error("ungranted action must be advisory-denied")
	}

	// Guarded runs fn only on allow.
	ran := false
	if err := in.Guarded(ctx, w.Writ, "call", "github/get_repo", func() error { ran = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Error("Guarded should run fn on allow")
	}
	ran = false
	if err := in.Guarded(ctx, w.Writ, "call", "github/delete_repo", func() error { ran = true; return nil }); err == nil {
		t.Error("Guarded must return an error on deny")
	}
	if ran {
		t.Error("Guarded must not run fn on deny")
	}
}

func TestUnknownAgentErrors(t *testing.T) {
	c := testPlane(t)
	if _, err := c.StartInstance(context.Background(), "does-not-exist"); err == nil {
		t.Fatal("starting an instance of an unknown agent must error")
	}
}
