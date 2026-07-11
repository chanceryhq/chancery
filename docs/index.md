# Chancery

**The identity provider for AI agents** — the neutral, self-hosted system
of record for what every agent is, who it acts for, what it can do, and
what it has done.

Agents get their identities from Chancery, their credentials through it
(never holding real secrets), and every action attributed by it — by
construction, not log forensics. In-path enforcement: register, scope,
delegate, revoke — instantly. Audit is metadata-only by design: prompts
and payloads are never stored.

Single Go binary. Apache-2.0. MCP-first, then HTTP, shell, browser.

- [Quickstart](https://github.com/chanceryhq/chancery/blob/main/QUICKSTART.md) — govern a real MCP server in 5 minutes
- [Testing playbook](testing-playbook.md) — every feature, one guided ~20-minute run
- [Dashboard](https://github.com/chanceryhq/chancery/blob/main/rfcs/014-read-only-dashboard.md) — `chancery serve` + open `/ui`: timeline, roster, delegation tree
- [Concepts](concepts.md) — agent, version, instance, writ, template
- [Examples](https://github.com/chanceryhq/chancery/tree/main/examples) — Claude Code, browser agents, Go SDK, LangGraph
- [Design RFCs](https://github.com/chanceryhq/chancery/tree/main/rfcs) — every decision, argued
- [Security posture](https://github.com/chanceryhq/chancery/blob/main/SECURITY.md) — the honest gap table

## The 60-second story

An agent is working — reading files, calling tools. Security learns its
prompt was changed outside review. One command revokes it. Its very next
tool call is **blocked**, in-path, with a clean error. The audit timeline
shows which agent, which version, under whose authority — and
`chancery audit verify` proves the record wasn't edited.

Nothing open-source does this end-to-end today. That's the wedge.

## Two promises

1. **No license flip.** What ships open source stays Apache-2.0.
2. **Security is never paywalled.** Every gap in the threat model closes
   in the open core.

The boundary: whatever makes a single trust domain secure and operable is
open source; value that exists only at organizational scale (SSO/SCIM,
multi-tenancy, SIEM export, compliance packs, HA) is enterprise.
