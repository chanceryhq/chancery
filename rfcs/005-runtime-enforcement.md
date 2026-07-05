# RFC-005: Runtime Enforcement — MCP → HTTP → Shell → Browser

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-04
- **Depends on:** RFC-001, RFC-002, RFC-003, RFC-004
- **Blocks:** RFC-010

---

## 1. Problem

Identity, writs, and policy are theater unless they bind to the actual
action at the moment it happens (questions 2 and 3). Agents act through
four channels — MCP tool calls, direct HTTP, shell commands, and
browsers — and today all four run ungoverned: the MCP server executes
whatever the model asks with whatever credentials it was started with;
HTTP happens with env tokens; shell and browser inherit the human's
session wholesale. The enforcement point must be **in the path and
unbypassable from inside the agent's context** — an agent that can be
prompt-injected can be talked out of any self-restraint.

## 2. Existing approaches and why they fall short

**SDK/framework-level enforcement (LangChain callbacks, OpenAI SDK
guardrails).** Advisory by construction: the checking code runs in the
same process as the model loop. A prompt-injected agent — or any code
path the framework doesn't wrap — bypasses it. Enforcement inside the
trust boundary being enforced is not enforcement.

**agentgateway / Envoy AI Gateway.** Real in-path MCP proxies with tool
filtering, OAuth validation, CEL authz. Falls short as covered in
RFC-000 §3: rules bind to routes and JWT claims, not to registered agent
identities with versions, writs, and lineage; no credential brokering
(the server still holds its own secrets); no revocation semantics beyond
config reload. These are data planes awaiting a control plane — our v1
adapter targets, not our MVP dependency.

**Network egress proxies / firewalls.** See TLS, not semantics: can
block `api.github.com`, cannot distinguish `get_repo` from
`delete_repo`. Necessary layer eventually (the `net` verb), useless as
the primary control.

**MCP 2026-07-28 authorization.** OAuth 2.1 between *client and server*
— answers "may this user's client connect," then every tool call rides
that session. No per-call authorization, no agent principal, no
delegation. We slot into exactly the gap the spec leaves.

**OS-level controls (seccomp/LSM/eBPF, macOS sandbox).** The right
long-term substrate for the `exec` verb (shell runtime, v1/v2);
per-tool-call semantics for MCP live above that layer.

## 3. Alternatives considered

**A. SDK-only enforcement.** Ship `chancery.Run(...)` wrappers and trust
them. Fastest integration, zero security: rejected as *the* mechanism,
kept as ergonomics on top of the proxy.

**B. Modify/fork MCP servers to check policy.** Per-server integration
burden across thousands of servers; trusts every server author to get it
right. Rejected.

**C. (Chosen) Protocol-aware proxy that owns the server boundary.** For
stdio servers: Chancery *spawns* the server as a child process and is
the only thing holding its stdin/stdout — the agent talks exclusively to
the proxy. For HTTP servers (v1): a reverse proxy in front of the
server's URL. Every `tools/call` passes the PDP; `tools/list` is
filtered to what policy admits; secrets are injected into the server
environment at spawn (RFC-003), never into the agent's.

**D. Wait and program agentgateway.** Avoids building a proxy; couples
the MVP demo to an external project's release cadence and leaves
identity/writ semantics unexpressed in their config model. Rejected for
MVP; locked as the v1 adapter path (RFC-000 D5).

## 4. Decision

**Chancery's MVP enforcement point is an MCP stdio proxy that owns the
server process:**

```
agent (MCP client) ──stdio──> chancery mcp wrap ──stdio──> real MCP server
                                    │
                              per tools/call:
                              1. resolve instance identity (RFC-001)
                              2. verify writ path from registry (RFC-002)
                              3. PDP: writ ∧ allow-list (RFC-004)
                              4. audit decision (RFC-006)
                              5. forward or JSON-RPC error −32001
```

- **Invocation:** `chancery mcp wrap --agent <name> --writ <id>
  [--block <id>] [--server-name <ns>] [--secret NAME=ENV_VAR]... --
  <server command>`. Drop-in: any MCP client config that ran
  `npx some-server` now runs `chancery mcp wrap ... -- npx some-server`.
- **Resource naming:** tool `t` on server namespace `ns` is resource
  `<ns>/<t>` under verb `call` — the writ/allow-list grammar (RFC-004)
  applies unchanged.
- **Per-call enforcement, fresh state:** the writ path is re-read from
  the registry on every call — this is where "revocation takes effect on
  the next action" is physically true. Registry unreachable ⇒ deny
  (fail closed).
- **`tools/list` filtering:** tools the PDP would deny are removed from
  the listing. The model never sees what it cannot call — smaller attack
  surface *and* fewer wasted turns. (Filtering is UX; `tools/call`
  enforcement is the security boundary — a client calling an unlisted
  tool still hits the PDP.)
- **Denials are protocol-native:** JSON-RPC error code **−32001**
  (`chancery: denied`) with the deciding layer in the message and the
  full decision in the audit stream. Agents see a clean tool error, not
  a hang.
- **Secret injection at spawn** (RFC-003): `--secret GITHUB_TOKEN=
  github-token` unseals into the child's env. The agent-side process
  tree never contains the value.
- **Passthrough for everything else:** initialize, notifications,
  resources/prompts requests flow untouched — we govern *actions*, not
  protocol mechanics. Payloads are never parsed beyond the envelope
  needed for the decision (method, id, tool name), honoring D6
  structurally.

**Sequence (locked):** MCP stdio (MVP) → MCP streamable-HTTP reverse
proxy + generic HTTP egress with header injection (v1, verb `net`) →
shell supervisor with argv policy (v1/v2, verb `exec`) → browser via CDP
domain/action allow-lists (v2). Each is a new PEP against the same PDP —
RFC-004's grammar already reserves the verbs.

*Amended 2026-07-05 by RFC-013:* the first `net`-verb enforcement
arrived early, *inside* the MCP PEP: when a writ grants `net:…`, the
stdio proxy additionally evaluates every `url`/`uri` tool argument as
`net:<host>/<path>` (fail-closed URL guard), and sealed browser
session state is injected as a server-only file (`--secret-file`).
The CDP-native browser PEP remains the v2 step; RFC-013 owns the
browser semantics.

## 5. Why

This is the wedge working end-to-end: question 2's demo (revoke → next
tool call blocked → attributed timeline) happens *here*; question 3 gets
its governance model (every runtime is a PEP on the same writ/policy/
audit spine); question 5 holds because the proxy stamps every decision
with the full principal tuple. And it is honest zero-trust: enforcement
lives outside the model's blast radius — prompt injection can ask for
anything and still hit the same wall.

## 6. Trade-offs accepted

- **The proxy adds a hop** (~sub-ms locally; registry check is a SQLite
  read in MVP). Accepted; latency budget tracked from day one.
- **Stdio-only in MVP** misses remote MCP servers. Accepted: local stdio
  is where developer agents overwhelmingly run today, and it's where
  spawn-env secret injection is uniquely clean.
- **A malicious *server* is out of scope in MVP** — we govern what the
  agent may invoke, not what the server does with it. Server-side
  behavior bounding is the sandbox layer (v2, `exec`).
- **One writ per wrapped server invocation** in MVP (the writ arrives by
  flag, not per-request negotiation). Multi-writ sessions arrive with
  the SDK handshake in v1.
- **The agent could be pointed at the raw server binary** by an operator
  who bypasses the wrap. Accepted: the operator is trusted (they hold
  the box); the *agent* is not. Attested "server only reachable via
  proxy" postures (network namespaces) are enterprise hardening.

## 7. Failure scenarios

- **Server process dies:** proxy propagates EOF and exits nonzero; audit
  records `mcp.server_exit`. Supervision belongs to the operator's
  process manager (MVP) — we don't hide crashes.
- **Registry unreachable mid-session:** every `tools/call` denies with
  layer `registry`; non-action traffic still flows. Agents degrade to
  read-only-of-nothing, never to ungoverned action (RFC-001 §7
  discipline).
- **Malformed JSON-RPC from either side:** envelope-unparseable lines
  from the *client* are dropped with an audit event (a confused or
  malicious model gets no partial parse gadget); from the *server*,
  forwarded as-is (don't corrupt streams we don't understand:
  IDs/notifications may be batched or extended).
- **Writ expires mid-task:** next call denies with `writ: expired` —
  exactly the demo, driven by TTL instead of revocation.
- **Clock skew:** broker clock rules (RFC-002 §7).
- **Giant messages / slow server:** line-buffered with a 10 MB envelope
  cap; oversized frames deny (client side) or pass through in chunks
  (server side, no decision needed).

## 8. Security considerations

The proxy is the PEP: it must never evaluate the *broker's* authority,
only the writ's (confused-deputy guard, RFC-002 §8). Tool *names* are
metadata (audited); tool *arguments* are payload (never parsed beyond
the envelope, never stored). `--secret` mappings are resolved at spawn
only; env of the proxy itself is scrubbed from the child except an
allow-listed PATH/HOME baseline. Denial messages carry the layer, never
sealed names or values. RFC-009 will treat: server impersonating tools
in `tools/list` (namespace pinning), argument-smuggling into allowed
tools (v1: argument-schema constraints — the `hold` layer's natural
home), and proxy binary substitution (cosign-signed releases, carried
from Conduit practice).

## 9. MVP impact

- `internal/mcp`: newline-delimited JSON-RPC stdio proxy: envelope
  parse, `tools/call` interception, `tools/list` filtering, −32001
  denials, passthrough, size caps. Pure io.Reader/Writer core —
  testable without processes.
- `chancery mcp wrap` command: spawn with sealed-secret env injection,
  writ resolution per call, audit wiring.
- Audit events: `mcp.call` (allow/deny + tool name), `mcp.list_filtered`
  (count), `mcp.server_exit`, `mcp.malformed`.
- Demo script (RFC-010) builds directly on this: wrap a real server,
  revoke mid-task, show the timeline.
- Stubbed: streamable-HTTP, SDK handshake, argument-schema constraints,
  shell/browser PEPs (verbs reserved).
