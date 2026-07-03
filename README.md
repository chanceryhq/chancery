# Chancery (working codename)

**The identity provider for AI agents** — the neutral, self-hosted system
of record for what every agent is, who it acts for, what it can do, and
what it has done.

Agents get their identities from Chancery, their credentials through it
(never holding real secrets), and every action attributed by it — by
construction, not log forensics. In-path enforcement: register, scope,
delegate, revoke — instantly, at the identity or instance level. Audit is
metadata-only as a structural invariant: prompts and payloads are never
stored.

Single Go binary. Apache-2.0 core. MCP-first, then HTTP, shell, browser.

## Design RFCs

Design happens as a series of locked decisions, one RFC at a time
([template](rfcs/TEMPLATE.md)).

| RFC | Title | Status |
|-----|-------|--------|
| [000](rfcs/000-vision-and-plan.md) | Vision and plan | In Review |
| 001 | Agent identity model | — |
| 002 | Lineage and delegation | — |
| 003 | Credential broker | — |
| 004 | Policy and authorization | — |
| 005 | Runtime enforcement (MCP → HTTP → shell → browser) | — |
| 006 | Audit and attribution | — |
| 007 | Lifecycle and revocation | — |
| 008 | Data model and APIs | — |
| 009 | Threat model | — |
| 010 | MVP scope (the 90-day build) | — |
| 011 | Open-core boundary | — |
