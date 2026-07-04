# Security Policy

Chancery is a security product; its own security posture is documented,
not implied. The full threat model is
[RFC-009](rfcs/009-threat-model.md) (STRIDE, OWASP LLM Top 10 and
Agentic Top 10 mappings, abuse cases).

## Reporting a vulnerability

Email **security@chancery.dev** (GPG key published at launch). Please
do not open public issues for vulnerabilities. Target response: 48h
acknowledgment, 90-day coordinated disclosure.

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
