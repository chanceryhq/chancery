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
	"time"

	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
	ErrInactive = errors.New("principal is not active")
	ErrRevoked  = errors.New("revoked")
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
	created_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS writ_blocks (
	id TEXT PRIMARY KEY,
	writ_id TEXT NOT NULL REFERENCES writs(id),
	parent_id TEXT REFERENCES writ_blocks(id),
	depth INTEGER NOT NULL, jws TEXT NOT NULL,
	to_agent TEXT NOT NULL, exp TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_events (
	id TEXT PRIMARY KEY, at TIMESTAMP NOT NULL,
	event TEXT NOT NULL,
	agent_id TEXT, version_id TEXT, instance_id TEXT,
	writ_id TEXT, writ_block INTEGER,
	verb TEXT, resource TEXT, decision TEXT, reason TEXT
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

func (s *Store) GetAgentByName(name string) (*Agent, error) {
	a := &Agent{}
	err := s.db.QueryRow(`SELECT id, name, owner, purpose, state, created_at
		FROM agents WHERE name = ?`, name).
		Scan(&a.ID, &a.Name, &a.Owner, &a.Purpose, &a.State, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: agent %q", ErrNotFound, name)
	}
	return a, err
}

func (s *Store) ListAgents() ([]Agent, error) {
	rows, err := s.db.Query(`SELECT id, name, owner, purpose, state, created_at
		FROM agents ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Name, &a.Owner, &a.Purpose, &a.State, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetAgentState transitions lifecycle state. Revoking or suspending an agent
// takes effect on the next in-path check (RFC-001 §4: revocation at the
// identity layer kills all versions and instances).
func (s *Store) SetAgentState(name, state string) error {
	res, err := s.db.Exec(`UPDATE agents SET state = ? WHERE name = ?`, state, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: agent %q", ErrNotFound, name)
	}
	return nil
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
	a := &Agent{}
	if err := s.db.QueryRow(`SELECT id, name, owner, purpose, state, created_at
		FROM agents WHERE id = ?`, in.AgentID).
		Scan(&a.ID, &a.Name, &a.Owner, &a.Purpose, &a.State, &a.CreatedAt); err != nil {
		return nil, nil, nil, err
	}
	if a.State != StateActive {
		return nil, nil, nil, fmt.Errorf("%w: agent %s is %s", ErrInactive, a.Name, a.State)
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
