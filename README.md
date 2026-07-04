# Chancery

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

## Try it (pre-alpha)

```sh
go build -o chancery ./cmd/chancery
./chancery init --trust-domain acme.com
./chancery agent register deploy-bot --owner user:you@acme.com \
    --purpose "deploys services" --prompt ./prompt.md --model claude-fable-5
./chancery writ grant --for user:you@acme.com --to deploy-bot --cap "call:github/*"
./chancery writ delegate <writ-id> --to test-runner --caveat "call:github/get_*"
./chancery writ check <writ-id> --resource github/get_pull_request   # ALLOW + lineage
./chancery writ revoke <writ-id>
./chancery writ check <writ-id> --resource github/get_pull_request   # DENY: revoked
./chancery audit                                                     # the timeline
```

Every action is attributed to a specific agent, version, and delegation
chain — and a delegated writ can only ever narrow: the block format has
no field for widening.

Enforce it live on any stdio MCP server (per-call policy, sealed
secrets injected server-side only, revocation on the next call):

```sh
./chancery secret put github-token --from-file ./token
./chancery mcp wrap --agent deploy-bot --writ <writ-id> \
    --secret GITHUB_TOKEN=github-token -- npx @yourorg/some-mcp-server
```

Run the control plane as an HTTP API with `./chancery serve`
(REST/JSON under `/v1`; the admin token is printed once at `init`).
The audit timeline is hash-chained — `./chancery audit verify` detects
any edit, deletion, or reorder. Known MVP gaps are published in
[RFC-009 §5](rfcs/009-threat-model.md).

## Design RFCs

Design happens as a series of locked decisions, one RFC at a time
([template](rfcs/TEMPLATE.md)).

| RFC | Title | Status |
|-----|-------|--------|
| [000](rfcs/000-vision-and-plan.md) | Vision and plan | In Review |
| [001](rfcs/001-agent-identity-model.md) | Agent identity model | In Review |
| [002](rfcs/002-lineage-and-delegation.md) | Lineage and delegation | In Review |
| [003](rfcs/003-credential-broker.md) | Credential broker | In Review |
| [004](rfcs/004-policy-and-authorization.md) | Policy and authorization | In Review |
| [005](rfcs/005-runtime-enforcement.md) | Runtime enforcement (MCP → HTTP → shell → browser) | In Review |
| [006](rfcs/006-audit-and-attribution.md) | Audit and attribution | In Review |
| [007](rfcs/007-lifecycle-and-revocation.md) | Lifecycle and revocation | In Review |
| [008](rfcs/008-data-model-and-apis.md) | Data model and APIs | In Review |
| [009](rfcs/009-threat-model.md) | Threat model | In Review |
| 010 | MVP scope (the 90-day build) | — |
| 011 | Open-core boundary | — |
