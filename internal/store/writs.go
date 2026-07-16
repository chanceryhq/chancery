package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Delegation is a tree in the registry (RFC-002 §4 rule 5): each block
// has a parent; a writ as held by an agent is one root-to-leaf path;
// revoking a block kills the subtree rooted there.

type WritBlock struct {
	ID        string
	WritID    string
	ParentID  *string
	Depth     int
	JWS       string
	ToAgent   string
	Exp       time.Time
	CreatedAt time.Time
	RevokedAt *time.Time
}

type WritMeta struct {
	ID           string
	ForPrincipal string
	AgentID      string
	State        string
	MaxDepth     int
	Exp          time.Time
	// Task is the declared purpose of the grant (RFC-017): operator-
	// written metadata carried into every decision an intent checker
	// sees. "" = no declared task.
	Task      string
	CreatedAt time.Time
}

func (s *Store) CreateWrit(id, forPrincipal, agentID string, maxDepth int, exp time.Time,
	task, rootBlockID, rootJWS, toAgent string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if _, err := tx.Exec(`INSERT INTO writs (id, for_principal, agent_id, state, max_depth, exp, task, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, forPrincipal, agentID, StateActive, maxDepth, exp, task, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO writ_blocks (id, writ_id, parent_id, depth, jws, to_agent, exp, created_at)
		VALUES (?, ?, NULL, 0, ?, ?, ?, ?)`, rootBlockID, id, rootJWS, toAgent, exp, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AppendWritBlock(blockID, writID, parentID string, depth int,
	jws, toAgent string, exp time.Time) error {
	_, err := s.db.Exec(`INSERT INTO writ_blocks (id, writ_id, parent_id, depth, jws, to_agent, exp, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		blockID, writID, parentID, depth, jws, toAgent, exp, time.Now().UTC())
	return err
}

func (s *Store) GetWrit(id string) (*WritMeta, error) {
	w := &WritMeta{}
	err := s.db.QueryRow(`SELECT id, for_principal, agent_id, state, max_depth, exp, task, created_at
		FROM writs WHERE id = ?`, id).
		Scan(&w.ID, &w.ForPrincipal, &w.AgentID, &w.State, &w.MaxDepth, &w.Exp, &w.Task, &w.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: writ %s", ErrNotFound, id)
	}
	return w, err
}

func (s *Store) getBlock(id string) (*WritBlock, error) {
	b := &WritBlock{}
	err := s.db.QueryRow(`SELECT id, writ_id, parent_id, depth, jws, to_agent, exp, created_at, revoked_at
		FROM writ_blocks WHERE id = ?`, id).
		Scan(&b.ID, &b.WritID, &b.ParentID, &b.Depth, &b.JWS, &b.ToAgent, &b.Exp, &b.CreatedAt, &b.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: writ block %s", ErrNotFound, id)
	}
	return b, err
}

// LatestBlock returns the most recently appended block of a writ — the
// default delegation parent and check target in the CLI.
func (s *Store) LatestBlock(writID string) (*WritBlock, error) {
	var id string
	err := s.db.QueryRow(`SELECT id FROM writ_blocks WHERE writ_id = ?
		ORDER BY depth DESC, created_at DESC LIMIT 1`, writID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: writ %s has no blocks", ErrNotFound, writID)
	}
	if err != nil {
		return nil, err
	}
	return s.getBlock(id)
}

// Path returns root→leaf blocks for a leaf block id. Fails with ErrRevoked
// if the writ or any block on the path is revoked — revocation anywhere on
// the path kills the leaf's authority (subtree semantics).
func (s *Store) Path(leafBlockID string) ([]WritBlock, error) {
	var path []WritBlock
	cur, err := s.getBlock(leafBlockID)
	for {
		if err != nil {
			return nil, err
		}
		path = append([]WritBlock{*cur}, path...)
		if cur.ParentID == nil {
			break
		}
		cur, err = s.getBlock(*cur.ParentID)
	}
	w, err := s.GetWrit(path[0].WritID)
	if err != nil {
		return nil, err
	}
	if w.State != StateActive {
		return nil, fmt.Errorf("%w: writ %s", ErrRevoked, w.ID)
	}
	for _, b := range path {
		if b.RevokedAt != nil {
			return nil, fmt.Errorf("%w: writ block %s (depth %d)", ErrRevoked, b.ID, b.Depth)
		}
	}
	return path, nil
}

// BlockForSubject returns the deepest (most specific) block of a writ
// whose subject is the given SPIFFE URI — the block that actually
// carries that agent's authority. Used so `mcp wrap --agent X` evaluates
// X's block, not whatever block happens to be latest (which may belong
// to a delegated sub-agent). Returns ErrNotFound if the agent holds no
// block on the writ.
func (s *Store) BlockForSubject(writID, subjectURI string) (*WritBlock, error) {
	var id string
	err := s.db.QueryRow(`SELECT id FROM writ_blocks WHERE writ_id = ? AND to_agent = ?
		ORDER BY depth DESC, created_at DESC LIMIT 1`, writID, subjectURI).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: agent %s holds no block on writ %s", ErrNotFound, subjectURI, writID)
	}
	if err != nil {
		return nil, err
	}
	return s.getBlock(id)
}

// Tree returns all blocks of a writ, root first, for rendering the
// delegation tree (the audit view of lineage).
func (s *Store) Tree(writID string) ([]WritBlock, error) {
	rows, err := s.db.Query(`SELECT id, writ_id, parent_id, depth, jws, to_agent, exp, created_at, revoked_at
		FROM writ_blocks WHERE writ_id = ? ORDER BY depth, created_at`, writID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WritBlock
	for rows.Next() {
		var b WritBlock
		if err := rows.Scan(&b.ID, &b.WritID, &b.ParentID, &b.Depth, &b.JWS, &b.ToAgent,
			&b.Exp, &b.CreatedAt, &b.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) ListWrits() ([]WritMeta, error) {
	rows, err := s.db.Query(`SELECT id, for_principal, agent_id, state, max_depth, exp, task, created_at
		FROM writs ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WritMeta
	for rows.Next() {
		var w WritMeta
		if err := rows.Scan(&w.ID, &w.ForPrincipal, &w.AgentID, &w.State, &w.MaxDepth,
			&w.Exp, &w.Task, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) RevokeWrit(id string) error {
	res, err := s.db.Exec(`UPDATE writs SET state = ?, revoked_at = ? WHERE id = ? AND state = ?`,
		StateRevoked, time.Now().UTC(), id, StateActive)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: active writ %s", ErrNotFound, id)
	}
	return nil
}

func (s *Store) RevokeWritBlock(blockID string) error {
	res, err := s.db.Exec(`UPDATE writ_blocks SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), blockID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: unrevoked writ block %s", ErrNotFound, blockID)
	}
	return nil
}

// --- audit (RFC-006: metadata only, hash-chained, tamper-evident) ---

// GenesisHash anchors the first event in the chain.
const GenesisHash = "chancery-genesis"

type AuditEvent struct {
	Seq      int64
	ID       string
	At       time.Time
	Event    string
	AgentID  string
	Instance string
	WritID   string
	Verb     string
	Resource string
	Decision string
	Reason   string
	PrevHash string
	Hash     string
}

// canonical is the hashed encoding (RFC-006 §4): \x1f-separated, fixed
// field order, timestamps in RFC3339Nano UTC. There is no field for
// payloads because the schema has none — D6 by DDL.
func (e *AuditEvent) canonical() string {
	return strings.Join([]string{e.ID, e.At.UTC().Format(time.RFC3339Nano), e.Event,
		e.AgentID, e.Instance, e.WritID, e.Verb, e.Resource, e.Decision, e.Reason}, "\x1f")
}

func chainHash(prev string, e *AuditEvent) string {
	sum := sha256.Sum256([]byte(prev + "\x1f" + e.canonical()))
	return hex.EncodeToString(sum[:])
}

// Audit appends a hash-chained event. Insertion is serialized on the
// chain head in one transaction — correctness over throughput (RFC-006
// §4). PEPs must treat an Audit error as a deny: an unrecordable action
// does not happen.
func (s *Store) Audit(e AuditEvent) error {
	if e.ID == "" {
		e.ID = newID()
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	prev := GenesisHash
	err = tx.QueryRow(`SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	e.PrevHash = prev
	e.Hash = chainHash(prev, &e)
	if _, err := tx.Exec(`INSERT INTO audit_events
		(id, at, event, agent_id, instance_id, writ_id, verb, resource, decision, reason, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.At, e.Event, e.AgentID, e.Instance, e.WritID, e.Verb, e.Resource,
		e.Decision, e.Reason, e.PrevHash, e.Hash); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) auditQuery(where string, args []any, limit int) ([]AuditEvent, error) {
	q := `SELECT seq, id, at, event,
		COALESCE(agent_id,''), COALESCE(instance_id,''), COALESCE(writ_id,''),
		COALESCE(verb,''), COALESCE(resource,''), COALESCE(decision,''), COALESCE(reason,''),
		prev_hash, hash FROM audit_events ` + where + ` ORDER BY seq DESC`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.Seq, &e.ID, &e.At, &e.Event, &e.AgentID, &e.Instance, &e.WritID,
			&e.Verb, &e.Resource, &e.Decision, &e.Reason, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AuditTimeline(limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.auditQuery("", nil, limit)
}

// AuditSince returns events with seq > afterSeq in chronological (append)
// order — the tail cursor for `audit --follow`.
func (s *Store) AuditSince(afterSeq int64) ([]AuditEvent, error) {
	rows, err := s.db.Query(`SELECT seq, id, at, event,
		COALESCE(agent_id,''), COALESCE(instance_id,''), COALESCE(writ_id,''),
		COALESCE(verb,''), COALESCE(resource,''), COALESCE(decision,''), COALESCE(reason,''),
		prev_hash, hash FROM audit_events WHERE seq > ? ORDER BY seq ASC`, afterSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.Seq, &e.ID, &e.At, &e.Event, &e.AgentID, &e.Instance, &e.WritID,
			&e.Verb, &e.Resource, &e.Decision, &e.Reason, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyAuditChain walks the full chain and returns the number of
// verified events, or an error naming the first broken one. Everything
// before the break remains trustworthy (prefix property).
func (s *Store) VerifyAuditChain() (int, error) {
	events, err := s.auditQuery("", nil, 0)
	if err != nil {
		return 0, err
	}
	// auditQuery returns newest-first; walk oldest-first.
	prev := GenesisHash
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.PrevHash != prev {
			return len(events) - 1 - i, fmt.Errorf("audit chain broken at seq %d (event %s): prev_hash mismatch — an event was edited, deleted, or reordered", e.Seq, e.ID)
		}
		if chainHash(prev, &e) != e.Hash {
			return len(events) - 1 - i, fmt.Errorf("audit chain broken at seq %d (event %s): content hash mismatch — the event was modified", e.Seq, e.ID)
		}
		prev = e.Hash
	}
	return len(events), nil
}
