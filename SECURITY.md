# Security Policy

Chancery is a security product; its own security posture is documented,
not implied. The full threat model is
[RFC-009](rfcs/009-threat-model.md) (STRIDE, OWASP LLM Top 10 and
Agentic Top 10 mappings, abuse cases).

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** on this repository
(Security tab → "Report a vulnerability"). Please do not open public
issues for vulnerabilities. Target response: 48h acknowledgment,
90-day coordinated disclosure.

## Known limitations (pre-alpha) — the honest gap table

These are stated design gaps of the current MVP, each with an owner and
phase (RFC-009 §5). **All of them close in the open-source core** —
security is never paywalled ([RFC-011](rfcs/011-open-core-boundary.md)).

| # | Gap | Exposure | Phase |
|---|-----|----------|-------|
| G1 | Bearer identity documents (no proof-of-possession) | ≤5-min replay window for a stolen document | v1 |
| G2 | Single admin API token | No operator scoping or blast-radius control | v1 |
| G3 | No rate limiting | DoS on the API/PDP | v1 |
| G4 | Tool arguments unconstrained | Injection-driven misuse *within* an allowed tool | v1 |
| G5 | No shipped TLS (`serve` binds localhost) | Plaintext if an operator exposes the bind | v1 |
| G6 | Audit tampering is detected, not prevented, vs. root | Root can rewrite the chain from genesis | v1 (anchoring) |
| G7 | No memory locking/zeroization in the broker | Secrets in swappable memory during injection | hardening backlog |
| G8 | No key-rotation automation | Slow recovery from issuer-key compromise | v1 |
| G9 | Declared (unverified) runtime attestation | An instance can lie about where it runs | v1 (verifiers) |
| G10 | Writ-gated spawn (`/v1/spawn`) is capability-URL style, no proof-of-possession | Knowing a writ id + parent agent name acts as bearer, bounded by that writ's own spawn capability and template ceiling | v1 (PoP via the writ's reserved `dk` field, [RFC-012](rfcs/012-dynamic-agent-creation.md)) |
| G11 | Browser URL guard is heuristic in MVP | Only top-level `url`/`uri` tool arguments are net-checked, against the *requested* URL (server-side redirects unseen); in-page actions are tool-level only | v1 (per-server argument schemas) / v2 (CDP-native PEP, [RFC-013](rfcs/013-browser-sessions-and-tokens.md)) |
| G12 | The dashboard uses the admin token in the browser | The read-only `/ui` keeps the token in tab session storage; an XSS or exposed bind would leak the full admin token | v1 (scoped read-only viewer tokens, [RFC-014](rfcs/014-read-only-dashboard.md)) |
| G13 | Default server pinning is launcher-deep for interpreter servers | The default (T1) hashes the launcher binary (`npx`/`uvx`), not the package tree behind it — a poisoned transitive dependency passes **unless** the operator uses `--pin-tree` (T2) or launches by image digest (T3), both shipped | Mitigations shipped, opt-in ([RFC-016](rfcs/016-server-pinning.md)); making T2/T3 the guided default is v1 UX (`mcp install`, issue #5) |
| G14 | Capability leases require server cooperation | A non-cooperating tool server never checks its lease; a revocation landing mid-flight then still commits (admission-time denial remains the floor) | Inherent — per-server opt-in ([RFC-015](rfcs/015-call-lifecycle-and-leases.md)); one-shot third-party APIs stay the hard boundary |
| G15 | The intent checker sees call arguments | The socket hands `{agent, task, tool, args}` to the operator-chosen checker; a malicious checker is a payload processor (though veto-only: it can never widen authority) | Inherent — choosing the checker is choosing a payload processor; documented, args never stored ([RFC-017](rfcs/017-intent-socket.md)) |

## Deployment guidance

- Keep `serve` bound to localhost or behind your TLS terminator (G5).
- Store the seal key (`seal.key`) and the registry on separate volumes
  in anything beyond a laptop deployment (RFC-003 §7).
- Treat the audit chain head (`chancery audit verify`) as a value worth
  exporting somewhere the host can't rewrite (G6).

## Structural invariants you can hold us to

- Prompts, payloads, and tool arguments are **never stored** — the
  audit schema has no column for them (RFC-006).
- Agents **never hold real credentials** — sealed values are injected
  into the server side of the proxy only (RFC-003/005).
- Delegated authority **can only narrow** — the writ's delegation
  block format has no field that could widen it (RFC-002).
