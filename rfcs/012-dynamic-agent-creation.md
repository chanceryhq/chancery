# RFC-012: Dynamic Agent Creation

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-05
- **Depends on:** RFC-001, RFC-002, RFC-004, RFC-007, RFC-008
- **Blocks:** —

## 1. Problem

Modern multi-agent systems do not have a fixed roster. An orchestrator
agent decides *at runtime* that it needs a researcher, a summarizer,
and a critic; it writes their prompts on the fly, runs them for
minutes, and discards them. Hermes-, Ruflo-, and Vantage-style systems
all work this way — the agent population is a function of the task,
not of a config file.

Chancery through RFC-011 assumes agents are registered ahead of time by
an operator holding the admin token. That leaves a dynamic system with
three bad options:

1. **Give the orchestrator the admin token.** Then a prompt-injected
   orchestrator can register anything, grant nothing-to-do-with-it
   writs, rewrite allow-lists, and read the whole registry. The token
   is root; agents must never hold root (RFC-003's own rule for
   downstream credentials, violated at the control plane).
2. **Don't register spawned workers.** They run as anonymous
   sub-processes under the orchestrator's identity. Attribution
   collapses to "the orchestrator did it"; the shadow-agent signal
   (RFC-000 Addendum A Q7) fires on every run — correctly, because the
   system is producing unregistered actors by design.
3. **Pre-register every possible worker.** Impossible when prompts are
   generated at runtime, and it produces a registry full of stale
   never-again-used identities.

The delegation core (RFC-002) already handles the *authority* half
perfectly — a writ chain is exactly a spawn tree, and attenuation means
a child can never exceed its creator. What is missing is the *identity*
half: a way to create the child's registry entry that is itself
governed, without root.

## 2. Existing approaches and why they fall short

- **Microsoft Entra Agent ID (GA April 2026)** has "agent blueprints":
  pre-approved shapes from which parent agents mint child identities.
  Right idea, but the mint is a directory write in Microsoft's cloud,
  gated by Conditional Access — not by the parent's own delegated,
  attenuating authority, and not portable across ecosystems.
- **SPIFFE/SPIRE** solves workload identity issuance at scale, but its
  registration entries are operator-defined selectors; a workload
  cannot create a *narrower* identity for a child it decided to spawn.
- **Okta XAA / Auth0 for GenAI** govern an agent's access to apps; they
  have no primitive for an agent creating another agent at all.
- **Kubernetes ServiceAccounts + RBAC** is the closest prior art
  (a controller with `create serviceaccounts` scoped by namespace),
  and it validates the pattern: creation as a scoped, auditable
  permission. But RBAC scoping cannot express "and the child's
  permissions must be a subset of yours" — Chancery's writ can,
  structurally.

## 3. Alternatives considered

1. **Do nothing — document the admin-token-in-a-shim pattern.** A
   sidecar holding the admin token registers workers on the
   orchestrator's behalf. Rejected: the shim is root-with-extra-steps;
   the blast radius of a compromised orchestrator is the whole
   registry.
2. **Scoped API tokens** (a second token class that can only
   register). Rejected: a parallel authorization system next to the
   writ, with its own revocation, TTL, and audit story — exactly the
   duplication RFC-004 forbids ("only the writ grants").
3. **Spawn as a writ-governed action within templates** —
   **chosen.** Creation is just another verb through the existing PDP;
   the ceiling a human approved once (the template) bounds what any
   runtime spawn can produce.
4. **Treat workers as instances of one generic agent.** Cheap, but it
   erases exactly what Chancery exists to record: each worker's own
   prompt digest, capability set, and lineage. Instances share a
   version; dynamic workers each have their own content.

## 4. Decision

**Runtime agent creation is a writ-governed action.** One new verb,
`admin`, joins the registry (extending RFC-004's grammar; everything
else about the grammar is unchanged). A writ capability
`admin:spawn/<template>` authorizes its holder to spawn agents from
that named template. Locked semantics:

1. **Templates are the human-approved ceiling.** A template
   (`chancery template create`) fixes a purpose, a set of **max
   capabilities**, and a **max TTL**. Templates are created with
   operator authority (CLI/admin API), never by agents.
2. **Spawn is one atomic, writ-gated operation**
   (`chancery agent spawn`, `POST /v1/spawn`): verify the parent is
   active and acting under **its own block** (RFC-002 lineage; same
   rule as `mcp wrap --agent`), evaluate `admin:spawn/<template>`
   through the full PDP (writ ∩ allow-list), then register the child
   and delegate it a block in the same operation. The requested
   capabilities must each be **implied by** a template max-cap
   (subsumption, strict), and the TTL may exceed neither the template
   max nor — via ordinary TTL monotonicity — the parent block's
   remaining life. The spawn endpoint requires **no admin token**: the
   writ is the authorization (capability semantics; proof-of-possession
   upgrades via the reserved `dk` field, RFC-002 §4, in v1).
3. **Spawned agents are ephemeral by construction.** They carry
   `spawned_by`, `template`, and a hard `expires_at` in the identity
   record. An expired ephemeral is **denied in-path immediately**
   (lazily, at every liveness check — no sweeper required for
   safety); `chancery agent sweep` retires expired ephemerals for
   registry hygiene and audits `agent.expired`.
4. **Ownership is inherited, never invented.** The child's owner is
   the parent's owner: accountability follows the human chain, and a
   spawned agent cannot launder ownership.
5. **Spawning does not propagate.** A spawned child holds only the
   caveats it was delegated; unless those include `admin:spawn/...`
   (within the template ceiling), it cannot spawn. Recursive
   orchestration is expressible, but only deliberately, and always
   inside both ceilings.
6. **Every outcome is audited**: `template.create`, `agent.spawn`
   (with parent, template, expiry), `agent.spawn_refused` (with
   reason), `agent.expired`.

## 5. Why

- *Who can it act as / what is it allowed to do?* Spawn produces a
  first-class identity with its own version digest and an attenuated
  block — the two questions stay answerable per-worker, not per-swarm.
- *What did it do?* The spawn tree IS the writ tree; lineage in every
  decision already names it.
- The alternative worlds both destroy the product's core claim:
  admin-token-holding orchestrators destroy least privilege;
  unregistered workers destroy attribution.
- Competitively (July 2026): blueprints-in-a-directory (Entra) is the
  incumbent answer; **ceiling-bounded spawn under attenuating
  delegated authority** is only expressible with a writ-shaped
  primitive. This RFC is where the writ design visibly pays rent.

## 6. Trade-offs accepted

- **A sixth verb.** The RFC-004 registry said five; control-plane
  self-service is a genuinely different action class and earns the
  slot. The grammar itself (resources, patterns, matching) is
  untouched.
- **Capability-URL semantics on `/v1/spawn` in MVP**: knowing a writ
  id + being first to name the parent agent is bearer-ish. Accepted
  because block ids are unguessable ULIDs, the PDP still binds the
  spawn to the parent's own block, and v1 upgrades to
  proof-of-possession. Tracked in RFC-009's gap list.
- **Registry growth.** Thousands of one-shot workers accumulate as
  retired rows. Accepted: rows are cheap, attribution history is the
  product; `agent sweep` keeps the *active* view clean.
- **Templates are another thing to manage.** Deliberate: the template
  is the human-oversight artifact (Colorado reasonable-care; EU AI Act
  human-oversight evidence) — removing it would remove the point.

## 7. Failure scenarios

- **Compromised orchestrator**: worst case, it spawns children up to
  the template ceiling ∩ its own writ — which is what it could already
  do *itself* with those capabilities. Blast radius unchanged by this
  RFC; revoking the orchestrator's writ kills the whole spawn subtree
  (RFC-002 subtree revocation).
- **Clock skew**: expiry uses registry-server time in `ActiveErr`;
  a skewed PEP cannot extend a child's life because the registry is
  consulted in-path per call (RFC-007).
- **Spawn half-failure**: if delegation fails after the child is
  registered, the child is immediately retired and the spawn is
  refused — no identity without authority lingers active.
- **Template deleted/renamed mid-flight**: spawn refuses
  (`not found`), audited; existing children are unaffected (their
  authority is their block, not the template).

## 8. Security considerations

Maps to RFC-009: ASI02 (tool misuse — spawn is a tool like any other,
now governed), ASI05 (unexpected code/agent execution — templates are
the pre-approval), ASI07 (rogue agents — expiry + sweep bounds
lifetime; shadow-agent signals still fire for out-of-band spawns).
New surface: template max-caps become a high-value write target —
they are admin-token-gated and audited. The `admin` verb namespace is
reserved for Chancery's own control plane; PEPs must never map
downstream tool names into it.

## 9. What gets built (MVP, this RFC)

- `admin` verb in the policy registry; `Cap.Implies` subsumption.
- `agent_templates` table; `spawned_by`/`template`/`expires_at` on
  agents (additive migration).
- `service.CreateTemplate`, `service.SpawnAgent` (atomic
  register+delegate, refusals audited), lazy expiry in every liveness
  check (`ActiveErr`), `store.SweepExpired`.
- CLI: `chancery template create|list`, `chancery agent spawn`,
  `chancery agent sweep`.
- API: `POST/GET /v1/templates` (admin), `POST /v1/spawn` (writ-gated,
  tokenless).
- Tests: subsumption table; spawn happy path; refusal without the
  spawn cap (audited); cap-over-ceiling; TTL-over-max; expired-child
  denied in-path then swept; HTTP spawn with no bearer token.

Deferred: proof-of-possession on spawn (v1, `dk`), template
versioning, per-owner spawn quotas, cross-writ spawn budgets.
