# Concepts

Five objects carry the whole model. If you understand these, you
understand Chancery.

## Agent → Version → Instance

Identity has three layers (RFC-001):

- **Agent** — the durable, named, owned thing. `deploy-bot`, owned by an
  accountable human or team, with a stated purpose. Its identifier is a
  SPIFFE-compatible URI, stable forever:
  `spiffe://acme.com/agent/deploy-bot`. Policies bind here.
- **Version** — an immutable, content-addressed snapshot of *what the
  agent is*: `sha256` digests of its prompt, config, and tool manifest,
  plus the model. Change the prompt and it's a new version. This is what
  makes "did this agent change since we reviewed it?" a hash comparison
  instead of a hope.
- **Instance** — a running embodiment. Ephemeral, holds a short-lived
  (≤5 min) identity document. Revoking one instance kills one runaway
  replica without touching the fleet.

Identity is **registry-born, attestation-confirmed**: it starts from an
accountable registration, not from wherever the process happens to run.

## Writ

A **writ** is delegated, attenuating authority (RFC-002): an ordered
chain of signed blocks. Block 0 grants capabilities under a named human's
authority; every later block can only *add restrictions*. Effective
authority is the grant intersected with every caveat.

**Widening is impossible** — not discouraged, impossible: the delegation
block format has no field that could add a capability. When an agent
spawns a sub-agent, the child's authority is the parent's minus caveats,
and the chain itself is the lineage (user → agent → sub-agent) embedded
in the credential that acts. Revoke any block and its whole subtree dies
on the next action.

Capabilities are `verb:resource` patterns — `call:github/get_*`,
`call:fs/read_*`. The verb registry and pattern grammar are locked in
RFC-004 (extended with the `admin` verb by RFC-012).

## Template (and spawned agents)

Many orchestrators create their workers **at runtime** — prompts
written on the fly, lifetimes of minutes. A **template** (RFC-012) is
the human-approved ceiling for that: a purpose, a set of max
capabilities, and a max lifetime, locked once by an operator.

An orchestrator whose writ carries `admin:spawn/<template>` can then
**spawn**: one atomic, writ-gated operation that registers an
ephemeral child agent and delegates it a narrowed block of the
orchestrator's own writ. No admin token is involved. The child:

- inherits the **owner** from its parent (accountability can't be
  laundered),
- carries `spawned_by`, `template`, and a hard `expires_at`,
- can never exceed the template ceiling, its parent's authority, or
  the template's max TTL,
- is denied in-path the moment it expires (`chancery agent sweep`
  later retires it for registry hygiene),
- cannot itself spawn unless deliberately delegated a spawn capability.

The spawn tree is the writ tree: attribution and revocation follow the
same chain.

## How they compose at enforcement time

When an agent makes a tool call through `chancery mcp wrap`, the proxy,
per call, with fresh registry state:

1. confirms the instance is live (RFC-001),
2. verifies the writ chain and checks revocation (RFC-002),
3. runs the policy conjunction — writ ∧ allow-list (RFC-004),
4. records the decision in the hash-chained audit log (RFC-006),
5. forwards to the real server, or returns a JSON-RPC denial.

Because state is read per call, **revocation takes effect on the next
action** — no propagation delay, no CRL, no cache to expire.

## Browser sessions (the credential agents actually inherit)

A browser agent doesn't log in — it inherits a human's cookies, which
authorize everything, attenuate nothing, and are invisible to the IdP.
RFC-013 applies the two rules above to them:

- **Session = sealed credential.** Storage state (cookies) lives
  AEAD-sealed; `mcp wrap --secret-file` materializes it as a private
  file only the browser *server* reads, deleted when the session ends.
  The agent's context never contains a cookie.
- **Navigation = action.** Granting `net:github.com/*` on the writ
  turns on the URL guard: every `url` tool argument is checked as
  `net:<host>/<path>` per call, fail-closed (non-http schemes and
  unexpressable URLs are denied). Query strings never reach policy or
  audit.
- **Session = instance.** `chancery instance revoke` is the kill
  switch browser sessions never had.

See [the browser-agent example](https://github.com/chanceryhq/chancery/tree/main/examples/browser-agent)
for the full Playwright MCP recipe, and RFC-013 §6 for the honest
boundaries (top-level `url` args, requested-URL only in MVP).

## The callee, the task, and the moment (RFC-015/016/017)

Three newer concepts complete the per-call picture:

- **Server pin (RFC-016).** The first `mcp wrap` records the server's
  identity; every later wrap re-verifies and refuses to start on
  drift. Permission is about the caller — the pin is about the callee.
  Three tiers, strongest wins: a container **image digest** in the
  server args (full filesystem), a **directory tree** via `--pin-tree`
  (full dependency tree — catches a poisoned `node_modules` file the
  binary hash can't see), or the **binary hash** by default. Deliberate
  upgrades are `chancery mcp repin` (explicit, audited). Honest limit:
  the *default* tier pins only the launcher for `npx`-style servers —
  use `--pin-tree` or a digest there.
- **Task (RFC-017).** `writ grant --task "review PR #123"` writes the
  grant's *purpose* onto the writ. It shows up in the audit trail and
  is handed to intent checkers — the one thing a checker can't infer.
- **Intent socket (RFC-017).** `mcp wrap --intent-check <cmd-or-url>`
  adds a sixth decision layer after the deterministic five: an external
  checker sees `{agent, task, tool, args}` and votes. Veto-only, fail
  closed in `enforce`, log-only in `advise`. Chancery ships no
  semantic judgment — detectors judge the moment; Chancery pulls the
  grant.
- **Capability lease (RFC-015).** `mcp wrap --lease` stamps each
  admitted call with a 30-second signed lease in `params._meta`; a
  cooperating server verifies it (`POST /v1/leases/verify`) right
  before committing, so a revocation landing mid-flight fails at the
  server. The trail also records `mcp.call_result`
  (committed/failed): "allowed" and "happened" are different facts.

## Two invariants you can rely on

- **Metadata-only audit.** The audit schema has no column for prompts,
  payloads, or tool arguments. Not policy — structure (RFC-006).
- **Agents never hold secrets.** Sealed credentials are injected into the
  *server's* environment at the proxy, never the agent's context
  (RFC-003). Rotation is one command; prompt injection can't exfiltrate
  what was never there.
