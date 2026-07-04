# RFC-006: Audit and Attribution

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-04
- **Depends on:** RFC-001, RFC-002
- **Blocks:** RFC-008

---

## 1. Problem

Question 2 ends with "reconstruct what it did"; question 5 demands the
answer name a *specific agent*. Both die in today's logs: actions appear
under shared credentials, spread across the downstream services' own
logging (half of agents run with none), with no authority context — you
can sometimes see *that* something happened, never *under whose
delegated authority and as which version of which agent*. And for the
audit record to be worth anything to a regulator (Colorado now, EU Dec
2027), it must be tamper-evident: an audit trail an admin can silently
edit is testimony, not evidence.

The constraint that shapes everything: **payloads and prompts are never
stored** (RFC-000 D6). The audit system must be maximally informative
about *who/what/when/decision* while being structurally incapable of
leaking *content*.

## 2. Existing approaches and why they fall short

**AWS CloudTrail.** The reference for control-plane audit: append-only,
integrity-validated digests, per-principal attribution. Falls short for
agents: attribution stops at the IAM principal — an assumed role shared
by a fleet of agents is one principal; no version, no lineage, no
delegated-authority context. We copy its digest-chain integrity model.

**OpenTelemetry traces.** Superb causality (span parent/child ≈ our
lineage instinct) but wrong guarantees: sampled, mutable in transit,
payload-happy by default, and no integrity story. OTel is an *export
target* (v1), not the record.

**Sigstore/Rekor transparency logs.** The gold standard for
tamper-evidence (Merkle trees, external witnesses). Overkill as the MVP
substrate — an external log service dependency contradicts the
30-second install — but the right enterprise/federation upgrade path,
and our hash-chain is forward-compatible with anchoring into one.

**SIEM (Splunk/Sentinel).** Where the events must eventually land
(enterprise export, RFC-011), not where they're born: a SIEM ingests
what it's given; the attribution must already be in the event.

**Downstream service logs.** The status quo. Shared-credential
attribution, no authority context, retention owned by someone else.
The thing we exist to replace.

## 3. Alternatives considered

**A. Plain database rows.** What we have pre-006. Queryable, zero
integrity: any writer can rewrite history. Insufficient for the
"regulator-ready evidence" pillar.

**B. Hash-chained rows in the registry DB (chosen).** Each event caries
`prev_hash` and `hash = SHA-256(prev_hash ‖ canonical-fields)`. A single
`chancery audit verify` walk detects any edit, deletion, or reorder.
Cheap (one hash per event), embedded (no new service), and upgradeable:
periodic chain-head anchoring (to Rekor, to a customer's own store, to a
partner org) turns local tamper-evidence into external non-repudiation.

**C. Merkle-tree transparency log embedded.** Better proofs (inclusion/
consistency without full walks), meaningfully more machinery. Deferred
to enterprise/federation, where chain-head anchoring already gets most
of the value.

**D. Blockchain.** No.

## 4. Decision

**Every enforcement-relevant event is recorded as a fixed-schema,
metadata-only, hash-chained row in the registry. The chain is verifiable
offline; content fields do not exist in the schema.**

**Event schema (locked):** `id` (ULID), `at` (UTC), `event` (taxonomy
below), `agent_id`, `instance_id`, `writ_id`, `writ_block`, `verb`,
`resource`, `decision` (ALLOW/DENY/―), `reason`, `prev_hash`, `hash`.
There is no column for arguments, results, prompts, or payloads —
honoring D6 in DDL, not in policy. `reason` carries layer + lineage +
names (tool names, credential *names*), never values.

**Event taxonomy (locked, extensible by prefix):**
- `agent.register|suspend|resume|revoke|allowlist`
- `instance.start|revoke`
- `writ.grant|delegate|revoke|revoke_block`
- `secret.put|rm` (names only)
- `action.check` (CLI/API decision), `mcp.wrap_start|call|list_filtered|
  malformed|server_exit` — every future PEP adds `http.*`, `exec.*`,
  `browser.*` with the same shape.

**Integrity:** `hash_i = SHA-256(hash_{i-1} ‖ id ‖ at ‖ event ‖ agent_id
‖ instance_id ‖ writ_id ‖ verb ‖ resource ‖ decision ‖ reason)` over a
canonical `\x1f`-separated encoding; genesis uses a fixed sentinel.
`chancery audit verify` recomputes the walk and reports the first break.
Insertion is serialized on the chain head (single-writer transaction) —
correctness over throughput in MVP.

**Attribution is embedded, not joined:** the decision events carry agent,
instance, writ, and (via `reason`) the lineage rendered from the writ —
the answer to "which agent, which version, under whose authority" is one
row, because the writ that acted carried it (RFC-002 rule 4).

**Query surface:** `chancery audit [--agent|--writ|--event|--since]`
filters; NDJSON export (`--json`) as the universal SIEM bridge in MVP;
scheduled exporters are v1.

## 5. Why

Question 2's "reconstruct" becomes a filtered read of one table;
question 5 is satisfied per-row. Tamper-evidence converts the audit
corpus from logs into *evidence* — which is what makes moat #3 (the
lineage/audit corpus under retention) real money rather than disk usage.
And metadata-only-by-DDL is the sales weapon carried from Conduit: the
audit system the DPO doesn't need to review, provable by schema
inspection.

## 6. Trade-offs accepted

- **Single-writer chain serializes audit inserts.** Fine at MVP scale
  (SQLite is single-writer anyway); the Postgres/HA path (RFC-008)
  shards chains per stream with periodic cross-links — recorded now so
  the enterprise design doesn't fork the semantics.
- **Hash chain proves order and integrity, not absence:** events
  suppressed *before* insertion leave no trace. Mitigation is
  architectural: the PEP writes the audit row in the same transaction
  scope as the decision; a PEP that can't audit doesn't allow (§7).
- **`reason` is free-text** — the one field with leak potential.
  Constrained by convention + tests (secret values asserted absent);
  v1 structures it into typed fields.
- **No external anchoring in MVP:** a root-level attacker can rewrite
  the whole chain from genesis. Chain-head anchoring (print/export the
  head hash anywhere) is cheap and lands with v1; noted honestly in the
  threat model (RFC-009).

## 7. Failure scenarios

- **Audit write fails during a decision:** the action is **denied**
  (`layer=audit`). An unrecordable action does not happen — the inverse
  of every logging system that "fails open" into silence.
- **Chain verification fails:** `audit verify` names the first broken
  event; everything before it remains trustworthy (prefix property).
  Response runbook: export the intact prefix, investigate, re-anchor.
- **Clock regression:** `at` monotonicity is not assumed; the chain is
  the order of record, timestamps are best-effort metadata (stated
  explicitly so nobody builds on timestamp ordering).
- **DB restore from backup:** the chain is internally consistent but
  the head no longer matches any exported anchor — exactly what
  anchoring is for; detected, not hidden.

## 8. Security considerations

The audit table is append-only by convention and verifiable by chain —
SQLite offers no privilege separation, so MVP tamper-evidence is
detection, not prevention (honest scope; prevention arrives with
Postgres row security + anchoring). Reason-field hygiene is tested, not
assumed. The chain hash covers `reason`, so post-hoc laundering of an
embarrassing denial is detectable. Verification is O(n); at enterprise
scale checkpointed heads bound the walk (v1).

## 9. MVP impact

- `audit_events` gains `prev_hash`, `hash`; insert computes the chain
  under a transaction; genesis sentinel fixed.
- `chancery audit verify` (walks, reports first break) and
  `chancery audit --json` (NDJSON export).
- PEP wiring: deny-on-audit-failure in the MCP proxy decider path.
- Tests: chain verifies clean; UPDATE/DELETE/reorder detected; reason
  fields never contain sealed values (extends the existing integration
  assertion); deny-on-audit-failure.
- Stubbed: filters beyond `--limit` (v1 polish), exporters, anchoring,
  per-stream chains.
