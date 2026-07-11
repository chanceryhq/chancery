package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chanceryhq/chancery/internal/identity"
	"github.com/chanceryhq/chancery/internal/service"
	"github.com/chanceryhq/chancery/internal/store"
)

const testToken = "chy_test_token_abc123"

func testServer(t *testing.T) *httptest.Server {
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
	sum := sha256.Sum256([]byte(testToken))
	srv := &Server{
		Svc:            &service.Service{St: st, Iss: iss},
		AdminTokenHash: hex.EncodeToString(sum[:]),
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func call(t *testing.T, ts *httptest.Server, method, path, token string, body any) (int, map[string]json.RawMessage) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]json.RawMessage
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func str(m map[string]json.RawMessage, k string) string {
	var s string
	json.Unmarshal(m[k], &s)
	return s
}

func TestAuthRequired(t *testing.T) {
	ts := testServer(t)
	for _, tok := range []string{"", "wrong-token"} {
		code, body := call(t, ts, "GET", "/v1/agents", tok, nil)
		if code != http.StatusUnauthorized {
			t.Errorf("token %q: status %d, want 401", tok, code)
		}
		if str(body, "code") != "unauthorized" {
			t.Errorf("token %q: code %q", tok, str(body, "code"))
		}
	}
	// healthz is the only unauthenticated route.
	code, _ := call(t, ts, "GET", "/healthz", "", nil)
	if code != http.StatusOK {
		t.Errorf("healthz must be open, got %d", code)
	}
}

func TestFullFlowOverHTTP(t *testing.T) {
	ts := testServer(t)

	// Register: digests in, never content.
	code, body := call(t, ts, "POST", "/v1/agents", testToken, map[string]any{
		"name": "api-bot", "owner": "user:aneesh@acme.com", "purpose": "api test",
		"prompt_sha256": "sha256:aaaa", "config_sha256": "sha256:bbbb",
		"tools_sha256": "sha256:cccc", "model": "claude-fable-5",
	})
	if code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, body)
	}
	if str(body, "subject") != "spiffe://acme.com/agent/api-bot" {
		t.Errorf("subject = %q", str(body, "subject"))
	}

	// Duplicate register maps to 409/conflict.
	code, body = call(t, ts, "POST", "/v1/agents", testToken, map[string]any{
		"name": "api-bot", "owner": "user:x@acme.com", "purpose": "dup",
	})
	if code != http.StatusConflict || str(body, "code") != "conflict" {
		t.Errorf("duplicate: %d %q", code, str(body, "code"))
	}

	// Instance + identity document.
	code, body = call(t, ts, "POST", "/v1/agents/api-bot/instances", testToken, nil)
	if code != http.StatusCreated || str(body, "identity_document") == "" {
		t.Fatalf("instance: %d %v", code, body)
	}

	// Grant.
	code, body = call(t, ts, "POST", "/v1/writs", testToken, map[string]any{
		"for": "user:aneesh@acme.com", "to": "api-bot",
		"caps": []string{"call:github/get_*"}, "ttl_seconds": 600,
	})
	if code != http.StatusCreated {
		t.Fatalf("grant: %d %v", code, body)
	}
	wid := str(body, "writ")

	// Check ALLOW.
	code, body = call(t, ts, "POST", "/v1/writs/"+wid+"/check", testToken,
		map[string]any{"resource": "github/get_repo"})
	if code != http.StatusOK || str(body, "decision") != "ALLOW" {
		t.Fatalf("check allow: %d %v", code, body)
	}

	// Check DENY is 200 with a DENY body — an evaluation, not an error.
	code, body = call(t, ts, "POST", "/v1/writs/"+wid+"/check", testToken,
		map[string]any{"resource": "github/delete_repo"})
	if code != http.StatusOK {
		t.Fatalf("DENY must be HTTP 200, got %d", code)
	}
	if str(body, "decision") != "DENY" || str(body, "layer") != "writ" {
		t.Errorf("deny body: %v", body)
	}

	// Revoke the agent over the API; the next check denies at registry.
	code, _ = call(t, ts, "POST", "/v1/agents/api-bot/state", testToken,
		map[string]any{"state": "revoked"})
	if code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	code, body = call(t, ts, "POST", "/v1/writs/"+wid+"/check", testToken,
		map[string]any{"resource": "github/get_repo"})
	if code != http.StatusOK || str(body, "decision") != "DENY" || str(body, "layer") != "registry" {
		t.Errorf("post-revocation check: %d %v", code, body)
	}

	// Terminality over the API: resurrect attempt maps to illegal_transition.
	code, body = call(t, ts, "POST", "/v1/agents/api-bot/state", testToken,
		map[string]any{"state": "active"})
	if code != http.StatusConflict || str(body, "code") != "illegal_transition" {
		t.Errorf("resurrection: %d %q", code, str(body, "code"))
	}

	// Audit chain is intact and the token never leaked into it.
	code, body = call(t, ts, "GET", "/v1/audit/verify", testToken, nil)
	if code != http.StatusOK {
		t.Fatalf("audit verify: %d", code)
	}
	var intact bool
	json.Unmarshal(body["intact"], &intact)
	if !intact {
		t.Error("audit chain must be intact")
	}
	_, events := call(t, ts, "GET", "/v1/audit?limit=100", testToken, nil)
	if strings.Contains(string(events["events"]), testToken) {
		t.Error("bearer token leaked into the audit stream")
	}
	// Failed auth earlier in this test run was audited.
	if !strings.Contains(string(events["events"]), "api.auth_failed") {
		// TestAuthRequired uses its own store; trigger one here.
		call(t, ts, "GET", "/v1/agents", "bad-token", nil)
		_, events = call(t, ts, "GET", "/v1/audit?limit=100", testToken, nil)
		if !strings.Contains(string(events["events"]), "api.auth_failed") {
			t.Error("failed auth must be audited")
		}
	}
}

func TestUnknownRoute404(t *testing.T) {
	ts := testServer(t)
	code, _ := call(t, ts, "GET", "/v1/nope", testToken, nil)
	if code != http.StatusNotFound {
		t.Errorf("unknown route: %d, want 404", code)
	}
}

func TestDelegationOverHTTP(t *testing.T) {
	ts := testServer(t)
	for _, name := range []string{"parent-bot", "child-bot"} {
		call(t, ts, "POST", "/v1/agents", testToken, map[string]any{
			"name": name, "owner": "user:aneesh@acme.com", "purpose": "t"})
	}
	_, body := call(t, ts, "POST", "/v1/writs", testToken, map[string]any{
		"for": "user:aneesh@acme.com", "to": "parent-bot",
		"caps": []string{"call:github/*"}, "ttl_seconds": 600,
	})
	wid := str(body, "writ")

	code, body := call(t, ts, "POST", "/v1/writs/"+wid+"/delegate", testToken, map[string]any{
		"to": "child-bot", "caveats": []string{"call:github/get_*"}, "ttl_seconds": 300,
	})
	if code != http.StatusCreated {
		t.Fatalf("delegate: %d %v", code, body)
	}
	var lineage []string
	json.Unmarshal(body["lineage"], &lineage)
	if len(lineage) != 3 || !strings.HasSuffix(lineage[2], "child-bot") {
		t.Errorf("lineage = %v", lineage)
	}

	// Attenuation holds over the API.
	_, body = call(t, ts, "POST", "/v1/writs/"+wid+"/check", testToken,
		map[string]any{"resource": "github/create_issue"})
	if str(body, "decision") != "DENY" {
		t.Error("child must not keep create_issue")
	}
	// Widening attempt maps to invalid.
	code, body = call(t, ts, "POST", "/v1/writs/"+wid+"/delegate", testToken, map[string]any{
		"to": "child-bot", "caveats": []string{"call:snowflake/*"}, "ttl_seconds": 60,
	})
	if code != http.StatusBadRequest {
		t.Errorf("null-authority delegation: %d %v", code, body)
	}
}

// RFC-012 over HTTP: POST /v1/spawn is writ-gated, not admin-token-
// gated. An orchestrator holding admin:spawn/<template> can spawn with
// NO bearer token; without the capability it is 403, never 401.
func TestSpawnOverHTTPWritGated(t *testing.T) {
	ts := testServer(t)
	call(t, ts, "POST", "/v1/agents", testToken, map[string]any{
		"name": "orch", "owner": "user:a@acme.com", "purpose": "orchestrates"})
	code, _ := call(t, ts, "POST", "/v1/templates", testToken, map[string]any{
		"name": "researcher", "purpose": "reads github",
		"max_caps": []string{"call:github/get_*"}, "max_ttl_seconds": 1800})
	if code != http.StatusCreated {
		t.Fatalf("template create = %d", code)
	}
	code, body := call(t, ts, "POST", "/v1/writs", testToken, map[string]any{
		"for": "user:a@acme.com", "to": "orch",
		"caps": []string{"call:github/*", "admin:spawn/researcher"}, "ttl_seconds": 3600})
	if code != http.StatusCreated {
		t.Fatalf("grant = %d", code)
	}
	var wid string
	json.Unmarshal(body["writ"], &wid)

	// No bearer token: the writ IS the authorization.
	code, body = call(t, ts, "POST", "/v1/spawn", "", map[string]any{
		"writ": wid, "agent": "orch", "template": "researcher", "name": "worker-1",
		"caps": []string{"call:github/get_*"}, "ttl_seconds": 600})
	if code != http.StatusCreated {
		t.Fatalf("spawn = %d, body %v", code, body)
	}
	var owner string
	json.Unmarshal(body["owner"], &owner)
	if owner != "user:a@acme.com" {
		t.Errorf("spawned owner = %q, want inherited user:a@acme.com", owner)
	}
	var block string
	json.Unmarshal(body["block"], &block)

	// The spawned block is enforceable immediately — and narrowed.
	code, body = call(t, ts, "POST", "/v1/writs/"+wid+"/check", testToken,
		map[string]any{"verb": "call", "resource": "github/create_issue", "block": block})
	var decision string
	json.Unmarshal(body["decision"], &decision)
	if code != http.StatusOK || decision != "DENY" {
		t.Errorf("child check = %d %s, want 200 DENY", code, decision)
	}

	// A template the writ does not admit: 403 spawn_refused.
	call(t, ts, "POST", "/v1/templates", testToken, map[string]any{
		"name": "deployer", "purpose": "deploys",
		"max_caps": []string{"call:deploy/*"}, "max_ttl_seconds": 1800})
	code, body = call(t, ts, "POST", "/v1/spawn", "", map[string]any{
		"writ": wid, "agent": "orch", "template": "deployer", "name": "worker-2"})
	if code != http.StatusForbidden {
		t.Errorf("unauthorized template spawn = %d, want 403 (%v)", code, body)
	}
}

// RFC-014: the dashboard page serves without auth but contains no data;
// the writ tree endpoint is authed and returns the lineage shape.
func TestDashboardAndWritTree(t *testing.T) {
	ts := testServer(t)

	resp, err := http.Get(ts.URL + "/ui")
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 1<<20)
	n, _ := resp.Body.Read(body)
	resp.Body.Close()
	page := string(body[:n])
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Chancery") {
		t.Fatalf("/ui = %d", resp.StatusCode)
	}
	// The static page must never embed data (RFC-014 §8).
	if strings.Contains(page, "acme.com") || strings.Contains(page, "w_01") {
		t.Error("/ui must not contain registry data")
	}

	call(t, ts, "POST", "/v1/agents", testToken, map[string]any{
		"name": "parent", "owner": "user:a@acme.com", "purpose": "p"})
	call(t, ts, "POST", "/v1/agents", testToken, map[string]any{
		"name": "child", "owner": "user:a@acme.com", "purpose": "p"})
	_, body2 := call(t, ts, "POST", "/v1/writs", testToken, map[string]any{
		"for": "user:a@acme.com", "to": "parent", "caps": []string{"call:x/*"}, "ttl_seconds": 600})
	var wid string
	json.Unmarshal(body2["writ"], &wid)
	call(t, ts, "POST", "/v1/writs/"+wid+"/delegate", testToken, map[string]any{
		"to": "child", "caveats": []string{"call:x/y*"}, "ttl_seconds": 300})

	// Unauthed: 401. Authed: two blocks, root->leaf, no JWS anywhere.
	code, _ := call(t, ts, "GET", "/v1/writs/"+wid, "", nil)
	if code != http.StatusUnauthorized {
		t.Errorf("unauthed writ tree = %d, want 401", code)
	}
	code, body3 := call(t, ts, "GET", "/v1/writs/"+wid, testToken, nil)
	if code != http.StatusOK {
		t.Fatalf("writ tree = %d", code)
	}
	var blocks []map[string]any
	json.Unmarshal(body3["blocks"], &blocks)
	if len(blocks) != 2 || blocks[0]["depth"].(float64) != 0 || blocks[1]["depth"].(float64) != 1 {
		t.Errorf("tree blocks wrong: %v", blocks)
	}
	if strings.Contains(string(body3["blocks"]), "eyJ") {
		t.Error("writ tree must not expose JWS material")
	}
	if code, _ := call(t, ts, "GET", "/v1/writs/w_nope", testToken, nil); code != http.StatusNotFound {
		t.Errorf("unknown writ = %d, want 404", code)
	}
}
