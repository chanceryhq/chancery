# RFC-007: Lifecycle and Revocation

- **Status:** Locked
- **Author:** Aneesh Gupta
- **Created:** 2026-07-04
- **Locked:** 2026-07-20
- **Depends on:** RFC-001, RFC-002, RFC-005
- **Blocks:** RFC-008

---

## 1. Problem

Question 2's second half: "how quickly can anyone cut off its access?"
— and, just as important, *what exactly does "cut off" mean* across a
principal model with three identity layers (agent/version/instance,
RFC-001) and delegated authority trees (writs, RFC-002)? Without locked
state machines, lifecycle decays into ad-hoc flags: agents that are
"disabled" but still hold live writs, "deleted" agents whose history
vanished with them, revoked identities that a retry loop quietly
resurrects. Every prior identity system that got this wrong (dangling
OAuth grants, orphaned service accounts — the entire NHI industry is a
monument to it) got it wrong at exactly this layer.

## 2. Existing approaches and why they fall short

**X.509 CRL/OCSP.** The cautionary tale for revocation: revocation as a
*separately distributed artifact* means propagation delay, soft-fail
clients that ignore it, and stapling workarounds. Lesson taken
structurally: Chancery has **no revocation list to distribute** — the
enforcement point asks the registry per action (RFC-005), so revocation
has no propagation stage at all.

**OAuth token revocation (RFC 7009).** Revokes tokens at the AS; every
already-issued bearer token at every resource server lives until TTL.
Same lesson: revoke *state*, not *artifacts*; keep artifacts short-lived
so out-of-path exposure is bounded (our identity documents: ≤5 min).

**SCIM lifecycle.** The right model for human accounts
(provision/deprovision synced from HR), and our enterprise integration
point (v1: owner offboarding events drive agent orphaning). Falls short
alone: no notion of versions, instances, or delegated authority.

**Entra Agent ID lifecycle.** Enable/disable on agent service
principals, blueprint-level control. No version layer to govern, no
instance layer, and disable propagates at token-expiry speed, not
next-action speed.

**Kubernetes object lifecycle.** Finalizers and graceful deletion are
the right instincts for *cleanup ordering*; agents differ because the
record must outlive the principal (audit retention) — deletion in the
K8s sense must not exist.

## 3. Alternatives considered

**A. Boolean `enabled` flag per object.** Minimal; collapses suspend
(reversible, operational) into revoke (terminal, security) — the two
must be distinguishable in audit and in policy, and terminality must be
enforced, not hoped.

**B. Soft-delete with row removal for retired agents.** Cleans the
directory; destroys attribution history and violates audit retention
(moat #3). Rejected: nothing that ever acted is ever deleted.

**C. (Chosen) Explicit per-layer state machines with enforced
transitions, terminal security states, and in-path effect.** Detailed
below.

## 4. Decision

**Every principal layer has a locked state machine. Security-motivated
terminal states can never be exited. Nothing is ever deleted. All state
changes take effect at the next in-path check and are audited.**

```
Agent:    active ⇄ suspended        (reversible, operational)
          active|suspended → retired (terminal, administrative)
          active|suspended → revoked (terminal, security)
          active|suspended → orphaned (owner lost; → active only via
                                       ownership transfer; → retired/revoked)

          [RFC-012] ephemeral spawned agents additionally carry a hard
          expires_at: past it they are denied in-path while nominally
          active (lazy expiry, fail closed), and `agent sweep` moves
          them active → retired through this same legal transition.

Version:  active → revoked           (terminal; "recall this prompt")
Instance: active → revoked           (terminal; instances are ephemeral —
                                      there is nothing to resume)
Writ:     active → revoked | expired (terminal)
Block:    active → revoked           (terminal; kills the subtree)
```

- **Transition enforcement in the store, not the CLI:** an illegal
  transition (`revoked → active`, `retired → suspended`) is an error at
  the data layer — no client, including a future compromised API
  handler, can resurrect a revoked identity. Re-creating a same-named
  agent after retirement/revocation mints a **new** agent ID: the old
  record, its writs, and its audit trail remain intact and attributable.
- **Semantics of each verb (locked vocabulary):**
  - *suspend* — reversible operational pause (incident triage, migration).
    Issuance and actions deny; nothing is invalidated.
  - *revoke* — terminal security kill. At agent layer it implies: all
    instances dead, all versions unusable, every writ held by the agent
    refused at next use (leaf check in `Path`, RFC-002).
  - *retire* — terminal administrative end-of-life. Same enforcement
    effect as revoke, different audit meaning (planned vs. incident) —
    auditors and dashboards must be able to tell decommissioning from
    compromise response.
  - *orphan* — automatic state when the owner principal disappears
    (v1: SCIM/OIDC-driven; MVP: manual). Blocks new issuance, keeps
    running instances' state visible; exits only by ownership transfer
    or terminal states. No ownerless active agents, ever (RFC-001 §7).
- **Revocation SLO (locked):** revocation is effective at the **next
  brokered action** — zero propagation delay by construction, because
  the PDP reads registry state per call (RFC-005; proven in the
  integration test). The only out-of-path exposure is a still-valid
  identity document used *outside* any Chancery enforcement point,
  bounded by its TTL (≤5 min default, ≤60 min max). Stated SLO:
  in-path ≤ 1 action; out-of-path ≤ document TTL.
- **Cascade rules:** revoking an agent does not mutate version/instance/
  writ rows — the *check* is hierarchical (`CheckIssuable`, `Path`), so
  one state field flips and the whole subtree of authority is dead. No
  fan-out writes, no partial-cascade states, nothing to crash halfway
  through.

## 5. Why

Question 2 gets a numeric answer ("next action; ≤5 minutes worst case
off-path") instead of an architecture diagram. Suspend/revoke/retire as
distinct verbs is what makes the audit corpus *meaningful* under
regulatory review — Colorado's reasonable-care evidence distinguishes
"we decommissioned it" from "we killed it mid-incident." Terminal-state
enforcement at the data layer is the difference between a lifecycle
*policy* and a lifecycle *property*.

## 6. Trade-offs accepted

- **No hard delete = data grows forever.** Accepted: agents/versions/
  writs are small rows; audit retention is the product (enterprise
  tiering in RFC-011).
- **Suspend denies rather than pauses:** a suspended agent's in-flight
  task fails at its next call rather than resuming gracefully later.
  Accepted: graceful drain is an orchestration concern above us.
- **Cascade-by-check means reads walk the hierarchy** (agent+version+
  instance+writ path per action). Fine in SQLite/Postgres at MVP/v1
  scale; the caching story (short-TTL decision cache with revocation
  bump) is written down for the day latency data demands it — not
  before.
- **Same-name re-registration after retirement requires a new name or
  explicit `--succeeds` linkage (v1)** — mild operator friction,
  preserves unambiguous history.

## 7. Failure scenarios

- **Race: revoke lands during an in-flight allowed call.** The decision
  that already passed executes; the *next* call denies. Window = one
  action, stated honestly (same as every PDP that doesn't hold locks
  across downstream I/O).
- **Crash between state write and audit write:** state changes and their
  audit events commit in one transaction (v1 hardening: today CLI-level
  ordering); worst case is a state change whose audit event is missing —
  detectable by comparing state to timeline, listed in RFC-009.
- **Operator revokes the wrong agent:** terminality bites. Mitigation is
  the vocabulary itself: suspend exists precisely so revoke can stay
  terminal; CLI prints a terminality warning on revoke/retire.
- **Orphaned agent with a live long-TTL writ:** orphaning blocks new
  issuance but the writ check passes if the agent were still active —
  hence orphan also fails `CheckIssuable` (it is not `active`), closing
  the gap.

## 8. Security considerations

Terminal states enforced below the API boundary resist a compromised
admin session resurrecting an identity (the attacker must write SQL,
which the audit chain then exposes — RFC-006). Suspend must not be
usable as an audit-quieting tool: suspension itself is audited with
actor context (API auth arrives in RFC-008). Instance revocation is the
containment primitive for a hijacked runtime — one replica dies, the
fleet keeps working (proven in tests). Full treatment in RFC-009.

## 9. MVP impact

- `store.SetAgentState` enforces the transition table (illegal
  transitions = `ErrIllegalTransition`); `retire` verb added to CLI;
  revoke/retire print terminality warnings.
- Orphan state reachable via CLI (`chancery agent orphan` — manual in
  MVP), exits via `chancery agent transfer --owner` (new owner) only.
- Tests: full transition matrix (legal and illegal), no-resurrection
  property, orphan blocks issuance and exits only via transfer,
  revocation SLO already covered by the RFC-005 integration test.
- Stubbed: SCIM/OIDC-driven orphaning, `--succeeds` lineage linkage,
  transactional state+audit coupling (v1).
