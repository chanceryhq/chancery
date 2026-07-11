# RFC-014: The Read-Only Dashboard

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-06
- **Depends on:** RFC-006, RFC-008, RFC-011
- **Blocks:** —

## 1. Problem

Chancery's most valuable output — the attributed, tamper-evident
timeline, and the delegation tree — is consumed today through
terminal tables. Operators can script it; humans evaluating the
product (a design partner in a first call, a security lead reviewing
an incident, the founder recording a demo) can't *see* it. The
product's core claims are visual claims — lineage is a tree, a
revocation is a state change rippling through it — rendered in the
least visual medium we have.

## 2. Existing approaches and why they fall short

- **"Pipe it to jq / build a Grafana panel."** Real operators will;
  evaluators won't. And Grafana over our SQLite shows rows, not
  lineage — the tree is the point.
- **Vault's precedent:** shipped CLI-first, added an embedded
  read-heavy UI once adoption began; the UI never became the
  operator surface. That sequencing worked and is the one we copy.
- **A full admin web app** (grant/revoke/seal from the browser):
  doubles the attack surface pre-launch (CSRF, browser-held admin
  credentials driving *writes*) for users — platform engineers — who
  script the control plane anyway.

## 3. Alternatives considered

1. **No UI; docs only.** Free, and loses every evaluator who thinks
   in pictures. The demo stays a wall of text.
2. **Separate SPA repo (React + Node toolchain).** Better widgets,
   but breaks the single-static-binary invariant, adds a supply
   chain, and forks the deploy story.
3. **(Chosen) One embedded, dependency-free HTML page** served by
   `chancery serve` at `/ui` via `go:embed` — read-only, calling the
   existing `/v1` API with the admin token.
4. **Write-capable UI.** Deferred deliberately (see §6).

## 4. Decision

**`chancery serve` ships an embedded read-only dashboard at `/ui`:
zero new dependencies, zero new write paths, one new read endpoint.**

1. **Read-only is structural, not stylistic:** the page contains no
   code path that issues anything but GETs (plus the POST-shaped
   `check` is deliberately excluded). Enforcement and administration
   remain CLI/API.
2. **Views:** the audit timeline (live-tailing, filterable, ALLOW/
   DENY/refusal colored, with a permanent integrity banner backed by
   `GET /v1/audit/verify`); agents (state, owner, spawn provenance,
   expiry); writs with the **delegation tree rendered as a tree**
   (lineage made visible — the demo moment); templates (the
   ceilings).
3. **`GET /v1/writs/{id}`** joins the API (writ meta + its block
   tree, JWS omitted from the payload) — closing the gap where
   RFC-008 documented this route but the MVP never implemented it.
4. **Auth:** the page itself is static and unauthenticated (it
   contains no data); every data call carries the admin bearer token,
   which the operator pastes once (kept in `sessionStorage`, never in
   the URL, gone when the tab closes).
5. **Single binary invariant holds:** plain HTML/CSS/JS in one file,
   `go:embed`, no CDN, no build step, works offline.
6. **Open-core placement (RFC-011):** this dashboard is core —
   single-trust-domain operability. Org-scale views (SIEM pivots,
   compliance reports, multi-tenant consoles) are the enterprise
   surface later.

## 5. Why

- Question 4 (*what did it do?*) deserves an answer a human can read
  at a glance; the timeline and the tree are the product's proof
  rendered honestly.
- Outreach economics: a screenshot of a live delegation tree over a
  verified timeline outperforms paragraphs; the demo recording gets a
  second act.
- The scope line (read-only) buys the value without new G-rows for
  CSRF or browser-driven writes.

## 6. Trade-offs accepted

- **The admin token enters a browser** (sessionStorage, localhost by
  default). Bounded: same token the operator already pastes into
  curl; read-only surface; dies with the tab. Still worth naming:
  gap **G12**, closed in v1 by scoped read-only viewer tokens.
- **No writes means no convenience:** you cannot revoke from the
  page you're staring at. Deliberate for now; a v1 "break glass"
  revoke button is the first candidate once viewer tokens exist.
- **Hand-rolled minimal JS** instead of a framework: fewer features,
  zero supply chain. Right trade for a security product's MVP.

## 7. Failure scenarios

- **Token pasted on a shared/exposed bind:** same exposure as curl
  with the token; deployment guidance (localhost bind, fronted TLS)
  already covers it; G5/G12 note it.
- **XSS via attacker-controlled registry strings** (agent names,
  purposes, audit reasons rendered in the page): all rendering is
  text-node based (no innerHTML of data), so injected markup is
  displayed, not executed.
- **API/UI drift:** the dashboard consumes only documented `/v1`
  responses; an API test locks the new endpoint's shape.

## 8. Security considerations

Read-only by construction; no new state transitions reachable from a
browser. New: G12 (admin token in browser session storage — v1
scoped viewer tokens). Text-node rendering as the XSS stance. The
`/ui` route serves static content without auth: it must never embed
data at render time (locked by this RFC).

## 9. What gets built (this RFC)

- `GET /v1/writs/{id}` (meta + block tree, JWS omitted).
- `internal/api/ui.html` + `go:embed` + `GET /ui`.
- Views: timeline (live tail, filters, integrity banner), agents,
  writ tree, templates.
- Tests: `/ui` serves without auth and contains no data; the writ
  endpoint returns the tree (authed) and 404s unknown ids.
- Docs: README, playbook step 8, SECURITY G12, RFC-000 table,
  CONTRIBUTING map.

Deferred: viewer tokens + revoke button (v1), charts/analytics,
SIEM/compliance views (enterprise), WebSocket tailing (polling is
fine at MVP scale).
