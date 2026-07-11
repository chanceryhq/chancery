// Package api is Chancery's HTTP control-plane surface (RFC-008):
// REST/JSON under /v1, Vault-style. Boring on purpose. Decisions are
// POSTs; a DENY is a successful evaluation (200), not a transport error.
package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chanceryhq/chancery/internal/policy"
	"github.com/chanceryhq/chancery/internal/service"
	"github.com/chanceryhq/chancery/internal/store"
)

type Server struct {
	Svc *service.Service
	// AdminTokenHash is the hex SHA-256 of the admin bearer token
	// (RFC-008 §4: hashed at rest, constant-time compare).
	AdminTokenHash string
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type apiError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// fail maps the store/policy error taxonomy to HTTP (RFC-008 §4).
func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, apiError{err.Error(), "not_found"})
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusConflict, apiError{err.Error(), "conflict"})
	case errors.Is(err, store.ErrIllegalTransition):
		writeJSON(w, http.StatusConflict, apiError{err.Error(), "illegal_transition"})
	case errors.Is(err, store.ErrInactive), errors.Is(err, store.ErrRevoked):
		writeJSON(w, http.StatusConflict, apiError{err.Error(), "inactive"})
	default:
		writeJSON(w, http.StatusBadRequest, apiError{err.Error(), "invalid"})
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if ok {
			sum := sha256.Sum256([]byte(tok))
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])),
				[]byte(s.AdminTokenHash)) == 1 {
				next(w, r)
				return
			}
		}
		// Audited without any token material.
		s.Svc.St.Audit(store.AuditEvent{Event: "api.auth_failed",
			Reason: r.Method + " " + r.URL.Path})
		writeJSON(w, http.StatusUnauthorized, apiError{"missing or invalid bearer token", "unauthorized"})
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	// The read-only dashboard (RFC-014). The page is static and holds
	// no data — every data call it makes carries the bearer token.
	mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(uiHTML)
	})

	mux.HandleFunc("POST /v1/agents", s.authed(s.registerAgent))
	mux.HandleFunc("GET /v1/agents", s.authed(s.listAgents))
	mux.HandleFunc("GET /v1/agents/{name}", s.authed(s.getAgent))
	mux.HandleFunc("POST /v1/agents/{name}/state", s.authed(s.setAgentState))
	mux.HandleFunc("POST /v1/agents/{name}/transfer", s.authed(s.transferAgent))
	mux.HandleFunc("POST /v1/agents/{name}/allowlist", s.authed(s.setAllowlist))
	mux.HandleFunc("POST /v1/agents/{name}/instances", s.authed(s.startInstance))
	mux.HandleFunc("POST /v1/instances/{id}/revoke", s.authed(s.revokeInstance))
	mux.HandleFunc("POST /v1/templates", s.authed(s.createTemplate))
	mux.HandleFunc("GET /v1/templates", s.authed(s.listTemplates))
	// Spawn is writ-gated, NOT admin-token-gated (RFC-012 §4): the
	// caller's authority is its writ block carrying admin:spawn/<tpl>.
	// An orchestrator never holds the admin token.
	mux.HandleFunc("POST /v1/spawn", s.spawnAgent)
	mux.HandleFunc("POST /v1/writs", s.authed(s.grantWrit))
	mux.HandleFunc("GET /v1/writs", s.authed(s.listWrits))
	mux.HandleFunc("GET /v1/writs/{id}", s.authed(s.getWrit))
	mux.HandleFunc("POST /v1/writs/{id}/delegate", s.authed(s.delegateWrit))
	mux.HandleFunc("POST /v1/writs/{id}/check", s.authed(s.checkWrit))
	mux.HandleFunc("POST /v1/writs/{id}/revoke", s.authed(s.revokeWrit))
	mux.HandleFunc("GET /v1/audit", s.authed(s.auditTimeline))
	mux.HandleFunc("GET /v1/audit/verify", s.authed(s.auditVerify))
	return mux
}

func (s *Server) registerAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		Owner        string `json:"owner"`
		Purpose      string `json:"purpose"`
		PromptSHA256 string `json:"prompt_sha256"`
		ConfigSHA256 string `json:"config_sha256"`
		ToolsSHA256  string `json:"tools_sha256"`
		Model        string `json:"model"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	if req.Name == "" || req.Owner == "" || req.Purpose == "" {
		writeJSON(w, http.StatusBadRequest, apiError{"name, owner, and purpose are required", "invalid"})
		return
	}
	a, v, err := s.Svc.RegisterAgent(req.Name, req.Owner, req.Purpose,
		req.PromptSHA256, req.ConfigSHA256, req.ToolsSHA256, req.Model)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": a.ID, "name": a.Name, "subject": s.Svc.Iss.SubjectURI(a.Name),
		"owner": a.Owner, "state": a.State, "version": v.Seq, "version_digest": v.Digest(),
	})
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.Svc.St.ListAgents()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": agents, "next": nil})
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	a, err := s.Svc.St.GetAgentByName(r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	versions, _ := s.Svc.St.ListVersions(a.ID)
	instances, _ := s.Svc.St.ListInstances(a.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"agent": a, "subject": s.Svc.Iss.SubjectURI(a.Name),
		"versions": versions, "instances": instances,
	})
}

func (s *Server) setAgentState(w http.ResponseWriter, r *http.Request) {
	var req struct {
		State string `json:"state"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	name := r.PathValue("name")
	a, err := s.Svc.St.GetAgentByName(name)
	if err != nil {
		fail(w, err)
		return
	}
	if err := s.Svc.St.SetAgentState(name, req.State); err != nil {
		fail(w, err)
		return
	}
	s.Svc.St.Audit(store.AuditEvent{Event: "agent." + req.State, AgentID: a.ID, Reason: "via api"})
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "state": req.State})
}

func (s *Server) transferAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Owner string `json:"owner"`
	}
	if err := decode(r, &req); err != nil || req.Owner == "" {
		writeJSON(w, http.StatusBadRequest, apiError{"owner is required", "invalid"})
		return
	}
	name := r.PathValue("name")
	a, err := s.Svc.St.GetAgentByName(name)
	if err != nil {
		fail(w, err)
		return
	}
	if err := s.Svc.St.TransferOwner(name, req.Owner); err != nil {
		fail(w, err)
		return
	}
	s.Svc.St.Audit(store.AuditEvent{Event: "agent.transfer", AgentID: a.ID,
		Reason: "from=" + a.Owner + " to=" + req.Owner})
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "owner": req.Owner})
}

func (s *Server) setAllowlist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Patterns []string `json:"patterns"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	a, err := s.Svc.St.GetAgentByName(r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	for _, p := range req.Patterns {
		if p == policy.DenyAll {
			continue
		}
		if err := policy.ValidateResourcePattern(p); err != nil {
			fail(w, err)
			return
		}
	}
	if err := s.Svc.St.SetAllowlist(a.ID, req.Patterns); err != nil {
		fail(w, err)
		return
	}
	s.Svc.St.Audit(store.AuditEvent{Event: "agent.allowlist", AgentID: a.ID,
		Reason: "patterns=" + strings.Join(req.Patterns, ",")})
	writeJSON(w, http.StatusOK, map[string]any{"name": a.Name, "patterns": req.Patterns})
}

func (s *Server) startInstance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	if r.ContentLength > 0 {
		if err := decode(r, &req); err != nil {
			fail(w, err)
			return
		}
	}
	in, tok, err := s.Svc.StartInstance(r.PathValue("name"), time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"instance": in.ID, "identity_document": tok,
	})
}

func (s *Server) revokeInstance(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Svc.St.RevokeInstance(id); err != nil {
		fail(w, err)
		return
	}
	s.Svc.St.Audit(store.AuditEvent{Event: "instance.revoke", Instance: id, Reason: "via api"})
	writeJSON(w, http.StatusOK, map[string]string{"instance": id, "state": "revoked"})
}

func (s *Server) createTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string   `json:"name"`
		Purpose       string   `json:"purpose"`
		MaxCaps       []string `json:"max_caps"`
		MaxTTLSeconds int      `json:"max_ttl_seconds"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	if req.Name == "" || len(req.MaxCaps) == 0 || req.MaxTTLSeconds <= 0 {
		writeJSON(w, http.StatusBadRequest, apiError{"name, max_caps, and max_ttl_seconds are required", "invalid"})
		return
	}
	t, err := s.Svc.CreateTemplate(req.Name, req.Purpose, req.MaxCaps,
		time.Duration(req.MaxTTLSeconds)*time.Second)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"template": t.Name, "max_caps": t.MaxCaps, "max_ttl_seconds": int(t.MaxTTL.Seconds()),
	})
}

func (s *Server) listTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.Svc.St.ListTemplates()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": templates, "next": nil})
}

func (s *Server) spawnAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Writ         string   `json:"writ"`
		Block        string   `json:"block"`
		Agent        string   `json:"agent"` // the spawning parent
		Template     string   `json:"template"`
		Name         string   `json:"name"` // the child's name
		Caps         []string `json:"caps"`
		TTLSeconds   int      `json:"ttl_seconds"`
		PromptSHA256 string   `json:"prompt_sha256"`
		ConfigSHA256 string   `json:"config_sha256"`
		ToolsSHA256  string   `json:"tools_sha256"`
		Model        string   `json:"model"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	if req.Writ == "" || req.Agent == "" || req.Template == "" || req.Name == "" {
		writeJSON(w, http.StatusBadRequest, apiError{"writ, agent, template, and name are required", "invalid"})
		return
	}
	child, blockID, err := s.Svc.SpawnAgent(req.Writ, req.Block, req.Agent,
		req.Template, req.Name, req.Caps, time.Duration(req.TTLSeconds)*time.Second,
		req.PromptSHA256, req.ConfigSHA256, req.ToolsSHA256, req.Model)
	if err != nil {
		// A refused spawn is an authorization outcome, not a transport
		// error — but unlike a check, the caller was asking to mutate.
		if strings.HasPrefix(err.Error(), "spawn refused: ") {
			writeJSON(w, http.StatusForbidden, apiError{err.Error(), "spawn_refused"})
			return
		}
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"agent": child.Name, "subject": s.Svc.Iss.SubjectURI(child.Name),
		"owner": child.Owner, "template": child.Template, "spawned_by": child.SpawnedBy,
		"expires_at": child.ExpiresAt, "block": blockID, "writ": req.Writ,
	})
}

func (s *Server) grantWrit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		For        string   `json:"for"`
		To         string   `json:"to"`
		Caps       []string `json:"caps"`
		TTLSeconds int      `json:"ttl_seconds"`
		MaxDepth   int      `json:"max_depth"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	if req.For == "" || req.To == "" || len(req.Caps) == 0 {
		writeJSON(w, http.StatusBadRequest, apiError{"for, to, and caps are required", "invalid"})
		return
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 3600
	}
	wid, blockID, err := s.Svc.GrantWrit(req.For, req.To, req.Caps,
		time.Duration(req.TTLSeconds)*time.Second, req.MaxDepth)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"writ": wid, "block": blockID})
}

func (s *Server) listWrits(w http.ResponseWriter, r *http.Request) {
	writs, err := s.Svc.St.ListWrits()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"writs": writs, "next": nil})
}

// getWrit returns a writ's metadata and its delegation tree (RFC-014;
// the route RFC-008 documented). JWS material is omitted: the UI needs
// shape and lineage, not signable credentials.
func (s *Server) getWrit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	meta, err := s.Svc.St.GetWrit(id)
	if err != nil {
		fail(w, err)
		return
	}
	blocks, err := s.Svc.St.Tree(id)
	if err != nil {
		fail(w, err)
		return
	}
	type uiBlock struct {
		ID        string     `json:"id"`
		ParentID  *string    `json:"parent_id"`
		Depth     int        `json:"depth"`
		ToAgent   string     `json:"to_agent"`
		Exp       time.Time  `json:"exp"`
		RevokedAt *time.Time `json:"revoked_at"`
	}
	out := make([]uiBlock, 0, len(blocks))
	for _, b := range blocks {
		out = append(out, uiBlock{ID: b.ID, ParentID: b.ParentID, Depth: b.Depth,
			ToAgent: b.ToAgent, Exp: b.Exp, RevokedAt: b.RevokedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"writ": meta, "blocks": out})
}

func (s *Server) delegateWrit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To          string   `json:"to"`
		Caveats     []string `json:"caveats"`
		TTLSeconds  int      `json:"ttl_seconds"`
		ParentBlock string   `json:"parent_block"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 1800
	}
	blockID, lineage, err := s.Svc.DelegateWrit(r.PathValue("id"), req.ParentBlock,
		req.To, req.Caveats, time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"block": blockID, "lineage": lineage})
}

func (s *Server) checkWrit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Verb     string `json:"verb"`
		Resource string `json:"resource"`
		Block    string `json:"block"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	if req.Verb == "" {
		req.Verb = "call"
	}
	d := s.Svc.CheckAction(r.PathValue("id"), req.Block, req.Verb, req.Resource)
	// A DENY is a successful evaluation, not a transport failure
	// (RFC-008 §4).
	writeJSON(w, http.StatusOK, map[string]string{
		"decision": strings.ToUpper(string(d.Effect)), "layer": d.Layer, "reason": d.Reason,
	})
}

func (s *Server) revokeWrit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Block string `json:"block"`
	}
	if r.ContentLength > 0 {
		if err := decode(r, &req); err != nil {
			fail(w, err)
			return
		}
	}
	id := r.PathValue("id")
	if req.Block != "" {
		if err := s.Svc.St.RevokeWritBlock(req.Block); err != nil {
			fail(w, err)
			return
		}
		s.Svc.St.Audit(store.AuditEvent{Event: "writ.revoke_block", WritID: id, Reason: "block=" + req.Block})
		writeJSON(w, http.StatusOK, map[string]string{"writ": id, "block": req.Block, "state": "revoked"})
		return
	}
	if err := s.Svc.St.RevokeWrit(id); err != nil {
		fail(w, err)
		return
	}
	s.Svc.St.Audit(store.AuditEvent{Event: "writ.revoke", WritID: id})
	writeJSON(w, http.StatusOK, map[string]string{"writ": id, "state": "revoked"})
}

func (s *Server) auditTimeline(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.Svc.St.AuditTimeline(limit)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "next": nil})
}

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	n, err := s.Svc.St.VerifyAuditChain()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"intact": false, "verified": n, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"intact": true, "verified": n})
}
