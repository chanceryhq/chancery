// Package store is Chancery's registry: the durable record of agents,
// versions, instances, and writs (RFC-001, RFC-002). SQLite for the MVP;
// the schema is the contract, the engine is replaceable (RFC-008).
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound          = errors.New("not found")
	ErrConflict          = errors.New("already exists")
	ErrInactive          = errors.New("principal is not active")
	ErrRevoked           = errors.New("revoked")
	ErrIllegalTransition = errors.New("illegal lifecycle transition")
)

// Agent lifecycle states (RFC-001 §4).
const (
	StateActive    = "active"
	StateSuspended = "suspended"
	StateRetired   = "retired"
	StateOrphaned  = "orphaned"
	StateRevoked   = "revoked"
)

type Agent struct {
	ID        string
	Name      string
	Owner     string
	Purpose   string
	State     string
	CreatedAt time.Time
	// Ephemeral spawn provenance (RFC-012): set only for agents created
	// at runtime by an orchestrator through the writ-gated spawn path.
	SpawnedBy string     // parent agent name, "" for durable agents
	Template  string     // template the spawn was constrained by
	ExpiresAt *time.Time // hard end-of-life; expired = denied in-path
}

// ActiveErr is THE liveness check for an agent as a principal: state
// must be active AND, for ephemeral spawned agents, the expiry must not
// have passed (RFC-012 §4: an expired ephemeral is denied in-path even
// before the sweep retires it — lazy expiry, fail closed).
func (a *Agent) ActiveErr() error {
	if a.State != StateActive {
		return fmt.Errorf("%w: agent %s is %s", ErrInactive, a.Name, a.State)
	}
	if a.ExpiresAt != nil && time.Now().UTC().After(*a.ExpiresAt) {
		return fmt.Errorf("%w: ephemeral agent %s expired %s", ErrInactive,
			a.Name, a.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// Template is a pre-approved shape for runtime-spawned agents
// (RFC-012 §4): a human locks the ceiling once; every spawn must fit
// inside it. MaxCaps bound what a spawned agent may be delegated;
// MaxTTL bounds how long it may live.
type Template struct {
	ID        string
	Name      string
	Purpose   string
	MaxCaps   []string
	MaxTTL    time.Duration
	CreatedAt time.Time
}

type Version struct {
	ID           string
	AgentID      string
	Seq          int
	PromptSHA256 string
	ConfigSHA256 string
	ToolsSHA256  string
	Model        string
	CreatedAt    time.Time
	RevokedAt    *time.Time
}

// Digest is the version's composite content address (RFC-001 §4): what
// the agent IS, as one comparable hash. Carried in identity documents
// and writ blocks.
func (v *Version) Digest() string {
	sum := sha256.Sum256([]byte(v.PromptSHA256 + "|" + v.ConfigSHA256 + "|" + v.ToolsSHA256 + "|" + v.Model))
	return "sha256:" + hex.EncodeToString(sum[:16])
}

type Instance struct {
	ID              string
	AgentID         string
	VersionID       string
	State           string
	AttestationType string
	AttestationEvid string
	CreatedAt       time.Time
	RevokedAt       *time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS config (
	key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
	id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
	owner TEXT NOT NULL, purpose TEXT NOT NULL,
	state TEXT NOT NULL DEFAULT 'active',
	created_at TIMESTAMP NOT NULL,
	spawned_by TEXT NOT NULL DEFAULT '',
	template TEXT NOT NULL DEFAULT '',
	expires_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS agent_templates (
	id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
	purpose TEXT NOT NULL,
	max_caps TEXT NOT NULL,
	max_ttl_secs INTEGER NOT NULL,
	created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_versions (
	id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id),
	seq INTEGER NOT NULL,
	prompt_sha256 TEXT NOT NULL, config_sha256 TEXT NOT NULL,
	tools_sha256 TEXT NOT NULL, model TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP,
	UNIQUE (agent_id, seq)
);
CREATE TABLE IF NOT EXISTS instances (
	id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id),
	version_id TEXT NOT NULL REFERENCES agent_versions(id),
	state TEXT NOT NULL DEFAULT 'active',
	attestation_type TEXT NOT NULL, attestation_evidence TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS writs (
	id TEXT PRIMARY KEY, for_principal TEXT NOT NULL,
	agent_id TEXT NOT NULL REFERENCES agents(id),
	state TEXT NOT NULL DEFAULT 'active',
	max_depth INTEGER NOT NULL, exp TIMESTAMP NOT NULL,
	task TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS server_pins (
	namespace TEXT PRIMARY KEY,
	kind TEXT NOT NULL DEFAULT 'binary',
	path TEXT NOT NULL, sha256 TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS writ_blocks (
	id TEXT PRIMARY KEY,
	writ_id TEXT NOT NULL REFERENCES writs(id),
	parent_id TEXT REFERENCES writ_blocks(id),
	depth INTEGER NOT NULL, jws TEXT NOT NULL,
	to_agent TEXT NOT NULL, exp TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tool_allowlists (
	agent_id TEXT NOT NULL REFERENCES agents(id),
	pattern TEXT NOT NULL,
	PRIMARY KEY (agent_id, pattern)
);
CREATE TABLE IF NOT EXISTS audit_events (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	id TEXT NOT NULL UNIQUE, at TIMESTAMP NOT NULL,
	event TEXT NOT NULL,
	agent_id TEXT, version_id TEXT, instance_id TEXT,
	writ_id TEXT, writ_block INTEGER,
	verb TEXT, resource TEXT, decision TEXT, reason TEXT,
	prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
`

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Additive migrations for databases created before RFC-012. SQLite
	// has no ADD COLUMN IF NOT EXISTS; a duplicate-column error means
	// the migration already ran.
	for _, ddl := range []string{
		`ALTER TABLE agents ADD COLUMN spawned_by TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agents ADD COLUMN template TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agents ADD COLUMN expires_at TIMESTAMP`,
		`ALTER TABLE writs ADD COLUMN task TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_pins ADD COLUMN kind TEXT NOT NULL DEFAULT 'binary'`,
	} {
		if _, err := db.Exec(ddl); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func newID() string { return ulid.Make().String() }

// --- config ---

func (s *Store) SetConfig(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO config (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *Store) GetConfig(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM config WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

// --- agents ---

func (s *Store) CreateAgent(name, owner, purpose string) (*Agent, error) {
	a := &Agent{ID: newID(), Name: name, Owner: owner, Purpose: purpose,
		State: StateActive, CreatedAt: time.Now().UTC()}
	_, err := s.db.Exec(`INSERT INTO agents (id, name, owner, purpose, state, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, a.ID, a.Name, a.Owner, a.Purpose, a.State, a.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: agent %q", ErrConflict, name)
	}
	return a, nil
}

// CreateSpawnedAgent creates an ephemeral runtime-spawned agent
// (RFC-012): provenance (spawning parent, template) and a hard expiry
// are part of the identity record, not an afterthought.
func (s *Store) CreateSpawnedAgent(name, owner, purpose, spawnedBy, template string, expiresAt time.Time) (*Agent, error) {
	exp := expiresAt.UTC()
	a := &Agent{ID: newID(), Name: name, Owner: owner, Purpose: purpose,
		State: StateActive, CreatedAt: time.Now().UTC(),
		SpawnedBy: spawnedBy, Template: template, ExpiresAt: &exp}
	_, err := s.db.Exec(`INSERT INTO agents (id, name, owner, purpose, state, created_at,
		spawned_by, template, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, a.Owner, a.Purpose, a.State, a.CreatedAt, a.SpawnedBy, a.Template, exp)
	if err != nil {
		return nil, fmt.Errorf("%w: agent %q", ErrConflict, name)
	}
	return a, nil
}

const agentCols = `id, name, owner, purpose, state, created_at,
	spawned_by, template, expires_at`

func scanAgent(row interface{ Scan(...any) error }) (*Agent, error) {
	a := &Agent{}
	err := row.Scan(&a.ID, &a.Name, &a.Owner, &a.Purpose, &a.State, &a.CreatedAt,
		&a.SpawnedBy, &a.Template, &a.ExpiresAt)
	return a, err
}

func (s *Store) GetAgentByName(name string) (*Agent, error) {
	a, err := scanAgent(s.db.QueryRow(`SELECT `+agentCols+` FROM agents WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: agent %q", ErrNotFound, name)
	}
	return a, err
}

func (s *Store) ListAgents() ([]Agent, error) {
	rows, err := s.db.Query(`SELECT ` + agentCols + ` FROM agents ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// SetAgentExpiry adjusts an ephemeral agent's hard end-of-life. Only
// meaningful for spawned agents; refuses agents without an expiry so a
// durable identity cannot silently become ephemeral (or vice versa).
func (s *Store) SetAgentExpiry(name string, at time.Time) error {
	res, err := s.db.Exec(`UPDATE agents SET expires_at = ?
		WHERE name = ? AND expires_at IS NOT NULL`, at.UTC(), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: ephemeral agent %q", ErrNotFound, name)
	}
	return nil
}

// SweepExpired retires every active ephemeral agent whose expiry has
// passed and returns their names. Expiry already denies in-path
// (ActiveErr); the sweep is registry hygiene, making end-of-life
// visible in `agent list` and the audit trail.
func (s *Store) SweepExpired() ([]string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	rows, err := tx.Query(`SELECT name FROM agents
		WHERE state = ? AND expires_at IS NOT NULL AND expires_at < ?`, StateActive, now)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE agents SET state = ?
		WHERE state = ? AND expires_at IS NOT NULL AND expires_at < ?`,
		StateRetired, StateActive, now); err != nil {
		return nil, err
	}
	return names, tx.Commit()
}

// --- agent templates (RFC-012) ---

func (s *Store) CreateTemplate(name, purpose string, maxCaps []string, maxTTL time.Duration) (*Template, error) {
	t := &Template{ID: newID(), Name: name, Purpose: purpose, MaxCaps: maxCaps,
		MaxTTL: maxTTL, CreatedAt: time.Now().UTC()}
	_, err := s.db.Exec(`INSERT INTO agent_templates (id, name, purpose, max_caps, max_ttl_secs, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.Purpose, strings.Join(maxCaps, "\x1f"), int64(maxTTL.Seconds()), t.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: template %q", ErrConflict, name)
	}
	return t, nil
}

func scanTemplate(row interface{ Scan(...any) error }) (*Template, error) {
	t := &Template{}
	var caps string
	var ttlSecs int64
	if err := row.Scan(&t.ID, &t.Name, &t.Purpose, &caps, &ttlSecs, &t.CreatedAt); err != nil {
		return nil, err
	}
	if caps != "" {
		t.MaxCaps = strings.Split(caps, "\x1f")
	}
	t.MaxTTL = time.Duration(ttlSecs) * time.Second
	return t, nil
}

func (s *Store) GetTemplate(name string) (*Template, error) {
	t, err := scanTemplate(s.db.QueryRow(`SELECT id, name, purpose, max_caps, max_ttl_secs, created_at
		FROM agent_templates WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: template %q", ErrNotFound, name)
	}
	return t, err
}

func (s *Store) ListTemplates() ([]Template, error) {
	rows, err := s.db.Query(`SELECT id, name, purpose, max_caps, max_ttl_secs, created_at
		FROM agent_templates ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// legalTransitions is the locked agent state machine (RFC-007 §4).
// retired and revoked are terminal: they have no exits, and the map
// having no entry for them is the enforcement. orphaned exits to active
// only via TransferOwner, never via SetAgentState.
var legalTransitions = map[string]map[string]bool{
	StateActive:    {StateSuspended: true, StateRetired: true, StateRevoked: true, StateOrphaned: true},
	StateSuspended: {StateActive: true, StateRetired: true, StateRevoked: true, StateOrphaned: true},
	StateOrphaned:  {StateRetired: true, StateRevoked: true},
}

// SetAgentState transitions lifecycle state, enforcing the transition
// table at the data layer: no client — including a compromised API
// handler — can resurrect a terminal identity. Takes effect on the next
// in-path check.
func (s *Store) SetAgentState(name, state string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current string
	err = tx.QueryRow(`SELECT state FROM agents WHERE name = ?`, name).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: agent %q", ErrNotFound, name)
	}
	if err != nil {
		return err
	}
	if !legalTransitions[current][state] {
		return fmt.Errorf("%w: %s → %s (agent %q)", ErrIllegalTransition, current, state, name)
	}
	if _, err := tx.Exec(`UPDATE agents SET state = ? WHERE name = ?`, state, name); err != nil {
		return err
	}
	return tx.Commit()
}

// TransferOwner assigns a new accountable owner. It is the ONLY exit
// from orphaned back to active (RFC-007 §4): no ownerless active
// agents, and no state-verb that skips re-establishing accountability.
func (s *Store) TransferOwner(name, newOwner string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current string
	err = tx.QueryRow(`SELECT state FROM agents WHERE name = ?`, name).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: agent %q", ErrNotFound, name)
	}
	if err != nil {
		return err
	}
	switch current {
	case StateRetired, StateRevoked:
		return fmt.Errorf("%w: cannot transfer ownership of a %s agent", ErrIllegalTransition, current)
	case StateOrphaned:
		if _, err := tx.Exec(`UPDATE agents SET owner = ?, state = ? WHERE name = ?`,
			newOwner, StateActive, name); err != nil {
			return err
		}
	default:
		if _, err := tx.Exec(`UPDATE agents SET owner = ? WHERE name = ?`, newOwner, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// --- versions ---

func (s *Store) CreateVersion(agentID, promptSHA, configSHA, toolsSHA, model string) (*Version, error) {
	var seq int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(seq), 0) + 1 FROM agent_versions
		WHERE agent_id = ?`, agentID).Scan(&seq); err != nil {
		return nil, err
	}
	v := &Version{ID: newID(), AgentID: agentID, Seq: seq, PromptSHA256: promptSHA,
		ConfigSHA256: configSHA, ToolsSHA256: toolsSHA, Model: model, CreatedAt: time.Now().UTC()}
	_, err := s.db.Exec(`INSERT INTO agent_versions
		(id, agent_id, seq, prompt_sha256, config_sha256, tools_sha256, model, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.AgentID, v.Seq, v.PromptSHA256, v.ConfigSHA256, v.ToolsSHA256, v.Model, v.CreatedAt)
	return v, err
}

func (s *Store) LatestVersion(agentID string) (*Version, error) {
	v := &Version{}
	err := s.db.QueryRow(`SELECT id, agent_id, seq, prompt_sha256, config_sha256,
		tools_sha256, model, created_at, revoked_at FROM agent_versions
		WHERE agent_id = ? ORDER BY seq DESC LIMIT 1`, agentID).
		Scan(&v.ID, &v.AgentID, &v.Seq, &v.PromptSHA256, &v.ConfigSHA256,
			&v.ToolsSHA256, &v.Model, &v.CreatedAt, &v.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: no versions for agent %s", ErrNotFound, agentID)
	}
	return v, err
}

func (s *Store) ListVersions(agentID string) ([]Version, error) {
	rows, err := s.db.Query(`SELECT id, agent_id, seq, prompt_sha256, config_sha256,
		tools_sha256, model, created_at, revoked_at FROM agent_versions
		WHERE agent_id = ? ORDER BY seq`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		var v Version
		if err := rows.Scan(&v.ID, &v.AgentID, &v.Seq, &v.PromptSHA256, &v.ConfigSHA256,
			&v.ToolsSHA256, &v.Model, &v.CreatedAt, &v.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) RevokeVersion(versionID string) error {
	res, err := s.db.Exec(`UPDATE agent_versions SET revoked_at = ?
		WHERE id = ? AND revoked_at IS NULL`, time.Now().UTC(), versionID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: version %s", ErrNotFound, versionID)
	}
	return nil
}

// --- instances ---

func (s *Store) CreateInstance(agentID, versionID, attType, attEvidence string) (*Instance, error) {
	in := &Instance{ID: newID(), AgentID: agentID, VersionID: versionID,
		State: StateActive, AttestationType: attType, AttestationEvid: attEvidence,
		CreatedAt: time.Now().UTC()}
	_, err := s.db.Exec(`INSERT INTO instances
		(id, agent_id, version_id, state, attestation_type, attestation_evidence, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		in.ID, in.AgentID, in.VersionID, in.State, in.AttestationType, in.AttestationEvid, in.CreatedAt)
	return in, err
}

func (s *Store) RevokeInstance(id string) error {
	res, err := s.db.Exec(`UPDATE instances SET state = ?, revoked_at = ?
		WHERE id = ? AND state = ?`, StateRevoked, time.Now().UTC(), id, StateActive)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: active instance %s", ErrNotFound, id)
	}
	return nil
}

func (s *Store) ListInstances(agentID string) ([]Instance, error) {
	rows, err := s.db.Query(`SELECT id, agent_id, version_id, state, attestation_type,
		attestation_evidence, created_at, revoked_at FROM instances
		WHERE agent_id = ? ORDER BY created_at`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		var in Instance
		if err := rows.Scan(&in.ID, &in.AgentID, &in.VersionID, &in.State, &in.AttestationType,
			&in.AttestationEvid, &in.CreatedAt, &in.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// --- tool allow-lists (RFC-004 L2) ---

// SetAllowlist replaces an agent's tool allow-list. Patterns are
// validated by the caller (policy grammar); empty list = no additional
// restriction.
func (s *Store) SetAllowlist(agentID string, patterns []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM tool_allowlists WHERE agent_id = ?`, agentID); err != nil {
		return err
	}
	for _, p := range patterns {
		if _, err := tx.Exec(`INSERT INTO tool_allowlists (agent_id, pattern) VALUES (?, ?)`,
			agentID, p); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetAllowlist(agentID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT pattern FROM tool_allowlists WHERE agent_id = ? ORDER BY pattern`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CheckIssuable is the in-path gate for identity document issuance and
// renewal: the agent must be active, the version unrevoked, the instance
// active. Fail closed on any other state (RFC-001 §7).
func (s *Store) CheckIssuable(instanceID string) (*Agent, *Version, *Instance, error) {
	in := &Instance{}
	err := s.db.QueryRow(`SELECT id, agent_id, version_id, state, attestation_type,
		attestation_evidence, created_at, revoked_at FROM instances WHERE id = ?`, instanceID).
		Scan(&in.ID, &in.AgentID, &in.VersionID, &in.State, &in.AttestationType,
			&in.AttestationEvid, &in.CreatedAt, &in.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, fmt.Errorf("%w: instance %s", ErrNotFound, instanceID)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if in.State != StateActive {
		return nil, nil, nil, fmt.Errorf("%w: instance %s is %s", ErrInactive, in.ID, in.State)
	}
	a, err := scanAgent(s.db.QueryRow(`SELECT `+agentCols+` FROM agents WHERE id = ?`, in.AgentID))
	if err != nil {
		return nil, nil, nil, err
	}
	if err := a.ActiveErr(); err != nil {
		return nil, nil, nil, err
	}
	v := &Version{}
	if err := s.db.QueryRow(`SELECT id, agent_id, seq, prompt_sha256, config_sha256,
		tools_sha256, model, created_at, revoked_at FROM agent_versions WHERE id = ?`, in.VersionID).
		Scan(&v.ID, &v.AgentID, &v.Seq, &v.PromptSHA256, &v.ConfigSHA256,
			&v.ToolsSHA256, &v.Model, &v.CreatedAt, &v.RevokedAt); err != nil {
		return nil, nil, nil, err
	}
	if v.RevokedAt != nil {
		return nil, nil, nil, fmt.Errorf("%w: version %d of %s", ErrRevoked, v.Seq, a.Name)
	}
	return a, v, in, nil
}

// --- server pins (RFC-016: callee identity) ---

// ServerPin records what code a wrapped MCP server namespace resolves
// to. Wrap re-verifies before every spawn and refuses on drift; changing
// a pin is an explicit, audited operator action (repin).
//
// Kind is the pinning tier (RFC-016): "binary" (T1, the resolved
// executable's hash), "tree" (T2, Merkle hash of a whole directory —
// full dependency tree), or "digest" (T3, a container image digest —
// the full filesystem, enforced by the container runtime's
// content-addressing).
type ServerPin struct {
	Namespace string
	Kind      string
	Path      string
	SHA256    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Pin kinds (RFC-016 tiers).
const (
	PinBinary = "binary" // T1: hash of the resolved executable
	PinTree   = "tree"   // T2: Merkle hash of a directory tree
	PinDigest = "digest" // T3: container image digest
)

func (s *Store) GetServerPin(namespace string) (*ServerPin, error) {
	p := &ServerPin{}
	err := s.db.QueryRow(`SELECT namespace, kind, path, sha256, created_at, updated_at
		FROM server_pins WHERE namespace = ?`, namespace).
		Scan(&p.Namespace, &p.Kind, &p.Path, &p.SHA256, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: server pin %q", ErrNotFound, namespace)
	}
	return p, err
}

// SetServerPin creates or replaces a namespace's pin (first wrap pins;
// repin updates). The caller audits — pin changes are security events.
func (s *Store) SetServerPin(namespace, kind, path, sha string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO server_pins (namespace, kind, path, sha256, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(namespace) DO UPDATE SET kind = excluded.kind,
			path = excluded.path, sha256 = excluded.sha256, updated_at = excluded.updated_at`,
		namespace, kind, path, sha, now, now)
	return err
}
