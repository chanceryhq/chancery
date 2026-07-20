# Design RFCs

Chancery is built as a series of locked decisions, one RFC at a time.
Each states the problem, the existing approaches and why they fall
short, the alternatives considered, the decision, the trade-offs
accepted, and the failure modes. If you want to know *why* something
works the way it does, the argument is here.

**Locked** means the decision is settled and implemented, with tests
gating it. New work amends an RFC or supersedes it — locked RFCs are
not quietly rewritten. Start a new one from [TEMPLATE.md](TEMPLATE.md).

| RFC | Title | Status | Depends on |
|-----|-------|--------|------------|
| [000](000-vision-and-plan.md) | Vision and Plan — Chancery, the Identity Provider for AI Agents | Locked | — |
| [001](001-agent-identity-model.md) | Agent Identity Model | Locked | 000 |
| [002](002-lineage-and-delegation.md) | Lineage and Delegation — the Writ | Locked | 000, 001 |
| [003](003-credential-broker.md) | Credential Broker | Locked | 001, 002 |
| [004](004-policy-and-authorization.md) | Policy and Authorization | Locked | 001, 002 |
| [005](005-runtime-enforcement.md) | Runtime Enforcement — MCP → HTTP → Shell → Browser | Locked | 001, 002, 003, 004 |
| [006](006-audit-and-attribution.md) | Audit and Attribution | Locked | 001, 002 |
| [007](007-lifecycle-and-revocation.md) | Lifecycle and Revocation | Locked | 001, 002, 005 |
| [008](008-data-model-and-apis.md) | Data Model and APIs | Locked | 001 … 007 |
| [009](009-threat-model.md) | Threat Model | Locked | 001 … 008 |
| [010](010-mvp-scope.md) | MVP Scope — the 90-Day Build | Locked | 000 … 009 |
| [011](011-open-core-boundary.md) | Open-Core Boundary | Locked | 000 (D2), 008, 009, 010 |
| [012](012-dynamic-agent-creation.md) | Dynamic Agent Creation | Locked | 001, 002, 004, 007, 008 |
| [013](013-browser-sessions-and-tokens.md) | Browser Sessions and Tokens as Governed Credentials | Locked | 001, 002, 003, 004, 005 |
| [014](014-read-only-dashboard.md) | The Read-Only Dashboard | Locked | 006, 008, 011 |
| [015](015-call-lifecycle-and-leases.md) | Call Lifecycle and Capability Leases | Locked | 002, 005, 006, 008 |
| [016](016-server-pinning.md) | Server Pinning (Callee Trust) | Locked | 005, 006 |
| [017](017-intent-socket.md) | Task-Bound Grants and the Intent Socket | Locked | 002, 004, 005, 006 |
| [018](018-frozen-installs-and-confinement.md) | Frozen Installs and Manifest-Bounded Confinement | Locked | 005, 006, 016 |

## Reading order

New here? [000](000-vision-and-plan.md) is the thesis and the locked
product decisions. [001](001-agent-identity-model.md) and
[002](002-lineage-and-delegation.md) are the two that everything else
rests on — identity and the writ. [005](005-runtime-enforcement.md) is
where those become enforcement, and [009](009-threat-model.md) is the
honest account of what all of it does *not* do.
