# RFC-008: Data Model and APIs

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-04
- **Depends on:** RFC-001 … RFC-007
- **Blocks:** RFC-010, RFC-011

---

## 1. Problem

Everything so far runs CLI-against-local-SQLite. Real deployments split
the roles: the control plane runs somewhere durable; agents, wrapped
servers, CI jobs, and dashboards talk to it from elsewhere. That needs a
stable remote surface with authentication, a data contract that survives
the SQLite→Postgres transition (RFC-000 roadmap), and versioning
discipline so the OSS core can evolve without breaking every SDK — the
system-of-record moat (#1) is only as strong as the stability of its
record's contract.

## 2. Existing approaches and why they fall short (as models to copy)

**SPIRE APIs.** gRPC-first, workload API over Unix sockets. Right for
high-frequency SVID renewal; wrong as the *only* surface — nothing about
SPIRE is `curl`-able, and adoption friction shows it.
**Vault HTTP API.** The model to copy: boring REST/JSON, versioned under
`/v1`, token auth, everything scriptable in one line. Vault won ops
mindshare partly on this.
**Kubernetes API conventions.** Declarative spec/status split and
consistent verbs — right for config-as-code (`chancery apply`, v1);
heavier than a 30-second install wants day one.
**Okta/MS Graph.** Enterprise-grade pagination/filtering conventions;
the reminder that breaking API changes in an identity system are
unforgivable.

## 3. Alternatives considered

**A. gRPC-first.** Strong typing, streaming, codegen SDKs. Loses:
curl-ability (the bottom-up motion lives in terminals), gateway/proxy
friction, and codegen burden across Python/TS where agents live.
Reserved for the control-plane↔data-plane channel when remote proxies
arrive (v1, xDS-style), where its strengths actually bind.
**B. GraphQL.** Flexible reads, wrong shape for an enforcement control
plane: decisions and state transitions are verbs, not graph queries;
authz-per-field is a minefield.
**C. (Chosen) REST/JSON under `/v1`, Vault-style.** Boring on purpose.

## 4. Decision

**One HTTP API, REST/JSON, versioned under `/v1`, mirroring the
principal model. The DDL is the data contract; SQLite and Postgres are
interchangeable engines behind the `store` package. A shared `service`
layer is the single implementation of every operation — the CLI and the
API are thin clients over it.**

**Resources (MVP surface, locked shapes):**
```
POST /v1/agents                        register (digests in, never content)
GET  /v1/agents · GET /v1/agents/{name}
POST /v1/agents/{name}/state           {"state": "suspended|active|retired|orphaned|revoked"}
POST /v1/agents/{name}/transfer        {"owner": ...}
POST /v1/agents/{name}/allowlist       {"patterns": [...]}
POST /v1/agents/{name}/instances       → instance + identity document
POST /v1/instances/{id}/revoke
POST /v1/writs                         grant (block 0)
POST /v1/writs/{id}/delegate · /check · /revoke
GET  /v1/writs · GET /v1/writs/{id}    (tree)
GET  /v1/audit?limit= · GET /v1/audit/verify
GET  /healthz                          (unauthenticated liveness only)
```

- **Decisions are POSTs, state changes are POSTs** — no PATCH semantics
  arguments, no PUT idempotency traps on security verbs.
- **Content never crosses the API:** registration accepts *digests*
  (`prompt_sha256`, …). The hash-locally pattern in the CLI stays
  client-side; the control plane cannot leak what it never receives —
  D6 extended to the wire.
- **AuthN (MVP): one admin bearer token**, generated at `init`, stored
  as SHA-256, compared constant-time. Honest scope: single-operator
  MVP. **AuthZ roadmap is the interesting part:** API principals in v1
  are *Chancery's own identity documents* — an agent renews its
  document or requests a delegation using the document it already
  holds; operators get scoped operator tokens; SSO/RBAC is enterprise
  (RFC-011). We eat our own identity model rather than growing a
  parallel API-key system.
- **Errors:** `{"error": "...", "code": "not_found|conflict|
  illegal_transition|denied|unauthorized|invalid"}` mapped from the
  store/policy error taxonomy; HTTP status mirrors the code. Decision
  denials are **200 with a DENY body** — a deny is a successful
  evaluation, not a transport failure (and it must not trip generic
  retry logic into hammering the PDP).
- **Versioning:** `/v1` is additive-only after MVP lock (RFC-010).
  Breaking changes mean `/v2` beside `/v1`, never in place.
- **Engine path:** the `store` package's exported surface is the seam;
  Postgres lands there in v1 (`CHANCERY_DB=postgres://…`) with the
  identical DDL modulo autoincrement/serial dialect. The audit chain's
  single-writer constraint maps to one advisory-locked appender.

## 5. Why

The 30-second story extends to the second machine: `chancery serve` on
a VM, `curl` from anywhere, same mental model as Vault. The service
layer ends CLI/API divergence (one code path to test, one to secure).
Digest-only registration keeps the DPO story clean at the network
boundary. And using our own identity documents as v1 API credentials is
the moat eating its own dogfood — the registry secures access to
itself.

## 6. Trade-offs accepted

- **Admin-token MVP is all-or-nothing** — no scoping, no multi-operator.
  Accepted with the v1 path named above; the token never appears in
  audit reasons (hash-at-rest, tested).
- **REST latency on the renewal path:** fine for MVP (local/LAN);
  the high-frequency path gets gRPC/Unix-socket treatment in v1 when
  remote data planes exist, informed by measurements, not vibes.
- **200-for-DENY** surprises some client libraries; documented
  prominently, and it is the correct semantic.
- **No pagination in MVP** (limits only); Graph-style cursors reserved
  in the response envelope (`next` field, null today) so adding them is
  additive.

## 7. Failure scenarios

- **Token brute-force:** 256-bit random token, constant-time hash
  compare, and failed auth is audited (`api.auth_failed`) — rate limits
  arrive with multi-principal auth in v1.
- **Serve process dies:** stateless handler over the same files the CLI
  uses; restart resumes; CLI keeps working locally throughout (same
  store), which is itself the operational escape hatch.
- **Concurrent CLI + API writes:** SQLite busy-timeout + single-writer
  audit transaction serialize correctly (slow, not wrong); documented
  as the reason serve-mode deployments should treat the CLI as
  read-mostly until Postgres.
- **Schema drift between engines:** one schema constant, engine
  dialects generated from it, cross-engine tests in CI when Postgres
  lands (recorded now as the acceptance bar).

## 8. Security considerations

TLS is terminated in front of `chancery serve` in MVP (documented; we
do not ship a toy cert manager) — localhost default bind until then.
The API surfaces no secret values (seal store has no GET endpoint at
all in MVP: injection happens data-plane-side). Auth failures and state
changes are audited with source context. Full treatment: RFC-009.

## 9. MVP impact

- `internal/service`: the single implementation of register/instance/
  grant/delegate/check/revoke used by API (and progressively by the
  CLI — full CLI migration is an RFC-010 cleanup item).
- `internal/api`: `net/http` handlers, bearer auth middleware,
  error-code mapping, decision endpoint returning ALLOW/DENY bodies.
- `chancery serve --listen 127.0.0.1:7423`; `chancery init` now mints
  and prints the admin token once.
- Tests: httptest end-to-end (register → instance → grant → check ALLOW
  → revoke → check DENY), auth rejection, unknown-route 404, DENY-as-200
  semantics, token hash never in audit.
- Stubbed: pagination cursors, Postgres engine, gRPC data-plane channel,
  document-based API auth (v1).
