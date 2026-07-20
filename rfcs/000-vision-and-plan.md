# RFC-000: Vision and Plan — Chancery, the Identity Provider for AI Agents

- **Status:** Locked
- **Author:** Aneesh Gupta
- **Created:** 2026-07-03
- **Locked:** 2026-07-20
- **Depends on:** —
- **Blocks:** all subsequent RFCs

---

## 1. Vision

**Chancery is the identity provider for AI agents: the neutral, self-hosted
system of record for what every agent is, who it acts for, what it can do,
and what it has done.**

Organizations are deploying agents that hold browser sessions, run shell
commands, execute SQL, and call APIs — under shared human credentials, with
no registry, no scoped authority, no revocation path, and logs that cannot
name the agent that acted. 88% of organizations report AI-agent security
incidents; only 22% treat agents as identities with revocable access (Okta
research, 2025–26). Over half of agents run with no logging at all.

Chancery sits **in the request path**. Agents get their identity from it,
their credentials through it, and their every action attributed by it — by
construction, not by log forensics. It installs in 30 seconds as a single
Go binary, and it belongs to no cloud, no model vendor, and no IdP empire.

Category: **agent IAM platform**. Not a kill-switch product — revocation is
one verb in lifecycle management. We demo the revocation moment (the most
visceral 60 seconds we have); we sell the registry.

### The five defining questions

Every design decision in this RFC series must trace to one of these:

1. When an agent needs access to an external service, how does that
   credential get issued, scoped, rotated, and revoked — and does the org
   have visibility into what the agent can actually do once it's running?
2. If an agent does something it shouldn't, how quickly can anyone identify
   WHICH agent it was, reconstruct what it did, and cut off its access?
3. Agents control browsers, shells, SQL, UIs — not just APIs. How is that
   governed?
4. Is agent credential security a problem orgs are actively solving now?
5. When an agent acts, can logs name the SPECIFIC agent — not just the
   shared credential?

---

## 2. Market ground truth (verified July 2026)

This section corrects and extends the founding charter. Items marked ⚠
changed between the charter's research and now.

**Consolidation and funding.** Cisco completed its ~$400M acquisition of
Astrix Security. Oasis Security raised a $120M Series B. GitGuardian raised
$50M (Feb 2026) for NHI/agent security. Aggregate NHI funding over the past
year exceeds $340M. Non-human identities outnumber humans ~100:1 in
enterprise environments.

**⚠ Arcade raised a $60M Series A (June 2026)** — "the secure action layer
for production AI agents." Arcade authored the MCP tool-authorization spec
and sits on MCP security steering committees. It is the fastest-moving
adjacent player to our wedge, approaching from the builder side (SDK/runtime
for agent developers) rather than the org side (system of record for the
enterprise).

**⚠ The incumbent IdPs have shipped, not just announced.**
- **Microsoft Entra Agent ID reached GA in April 2026**: agent identity
  blueprints (templates with parent-child relationships), Conditional Access
  for agents, ID Protection for agents — bundled into Microsoft Agent 365
  and M365 E7 plans rolling out July–August 2026.
- **Okta Cross App Access (XAA)** — an agent-to-app delegation protocol —
  hits early access via Auth0 at the end of July 2026, alongside "Auth for
  GenAI" (Token Vault, fine-grained authorization for RAG).

Consequence: "agents are a third kind of principal" is no longer a
contrarian claim — it is the marketing headline of two incumbents. The
differentiation has moved (see §4).

**⚠ The OSS in-path data plane is being commoditized.**
- **agentgateway** (created by Solo.io, now a Linux Foundation project with
  contributors from AWS, Cisco, Microsoft, IBM, Red Hat) is an OSS proxy
  for MCP and A2A traffic with security, observability, and governance
  hooks.
- **Envoy AI Gateway v1.0** (Tetrate/CNCF) ships MCP routing, tool
  filtering, OAuth 2.0 with JWT claim forwarding, and CEL-based
  authorization.

Consequence: the charter's claim that "nobody owns the in-path,
self-hostable, open-core runtime layer" needs precision. The *pipe* is
being commoditized in the open. What remains unowned is the **control
plane**: the registry, the credential broker, the lineage model, the
lifecycle, the attribution record. See §4 and the build-vs-integrate
decision in §7.

**⚠ MCP now has an auth story — for users, not for agents.** The MCP
2026-07-28 specification release candidate is the largest revision since
launch: full OAuth 2.1 alignment, RFC 8707 resource indicators, RFC 9728
protected resource metadata. This *solves* "can this user's client talk to
this server" and *deliberately leaves open* everything we do: which agent
is acting, under whose delegated authority, with what org-registered
identity, recorded where, revocable how. The wedge builds **on** the new
spec, not against it. (The charter's line "MCP has no credential story" is
now half-true: no *agent* credential story.)

**⚠ The standards race has started at the IETF.** The WIMSE working group's
identifier model (with SPIFFE as reference implementation) is live, and
draft-klrc-aiagent-auth-00 ("AIMS," March 2026) composes WIMSE + SPIFFE +
OAuth 2.0 into an agent identity framework. Okta is pushing XAA as a de
facto standard. The federation moat must be played *inside* the IETF
stream with running code — not as a proprietary format.

**⚠ Regulatory timing changed — the EU hook moved out, a US hook moved in.**
The EU Digital Omnibus (provisional agreement May 2026, Council final
approval June 29, 2026) **defers the AI Act's high-risk obligations from
Aug 2, 2026 to Dec 2, 2027** (Annex III) and Aug 2028 (Annex I). The
charter's "effective Aug 2, 2026" is stale; EU compliance is a maturing
tailwind, not a this-quarter forcing function. Meanwhile the **Colorado AI
Act took effect June 30, 2026** with a "reasonable care" standard under
which adopted industry standards count as evidence — a live US hook, and
one that favors whoever ships the standard artifacts (audit trails,
oversight controls) that constitute "reasonable care."

Sources: Microsoft Learn (Entra Agent ID GA, whats-new), Okta press
releases (XAA partners, Auth for GenAI), modelcontextprotocol.io blog
(2026-07-28 RC), Linux Foundation press (agentgateway), Tetrate/PRNewswire
(Envoy AI Gateway v1.0), Gibson Dunn / Consilium / Hogan Lovells (Digital
Omnibus), SiliconANGLE (GitGuardian), SC Media (Oasis), Calcalist/Cisco
(Astrix), Businesswire (Arcade Series A), IETF drafts (WIMSE,
draft-klrc-aiagent-auth-00).

---

## 3. What everyone else gets wrong (per-class)

Four classes of competitor, four structural gaps:

**1. Incumbent IdPs (Entra Agent ID, Okta XAA/Auth0).**
Right: agents are principals; lifecycle and conditional access matter.
Structural gap: **ecosystem gravity**. Entra governs agents *in Microsoft's
directory, running on Microsoft's stack, billed through M365*. XAA secures
app-to-app delegation *between Okta-federated SaaS apps*. Neither governs a
LangGraph agent on a GPU box running shell commands against a self-hosted
Postgres, and neither ever will be neutral across clouds, model vendors,
and frameworks — neutrality is not a feature they can add; it contradicts
their business model. This is Vault vs. cloud KMS, replayed: the cloud KMSs
were fine, and Vault won the cross-environment enterprise anyway.

**2. NHI inventory/posture tools (Astrix→Cisco, Oasis, Entro, Token).**
Right: the NHI sprawl is real and CISOs pay for visibility.
Structural gap: **read-only**. They discover and score credentials that
already exist; they don't issue, scope, or revoke in-path. An inventory
tool can be replaced in a quarter. They are also sales-led and top-down —
they will meet us in accounts, not in the developer's terminal.

**3. Builder-side auth plumbing (Arcade, Composio).**
Right: developers need OAuth handled for them; tool calling needs tokens.
Structural gap: **they serve the agent builder, not the organization**.
Their customer embeds an SDK; the artifact is a working integration, not an
org-wide record. No registry of agents, no attribution across teams, no
answer to "show me every agent that can touch production and who owns
each." Arcade's $60M raise says the builder-side wedge works; it also pins
them to that side (their moat is integration count, ours is the record).

**4. OSS agent/MCP gateways (agentgateway, Envoy AI Gateway).**
Right: in-path enforcement, open source, self-hosted — our own theses.
Structural gap: **a data plane without a system of record**. They filter
tools and forward JWT claims, but there is no durable agent identity, no
lineage, no credential issuance, no lifecycle, no attribution corpus. A
proxy without a registry is a firewall; a registry that programs proxies is
an identity provider. They are more prospective *substrate* than competitor
(§7, decision D5).

---

## 4. Positioning and moats (restated with 2026 precision)

**Positioning: the neutral, self-hosted system of record for agent
identity.** "Neutral" is now load-bearing, not decorative: since Microsoft
and Okta shipped, the buyer's question is no longer "should agents have
identities?" (they've heard yes twice) but "who should hold the record —
my cloud vendor, my IdP, or something I run?" We are the third answer, and
for every org that is multi-cloud, multi-model, or self-hosting agents —
i.e., every org at enterprise scale — the third answer is the only
complete one.

Moats, restated:

1. **System-of-record gravity** — agents get their identities FROM us.
   Removal means re-identifying every agent and losing history. (Unchanged
   from charter; strengthened by incumbent validation of the category.)
2. **In-path + record coupling** — *revised*: in-path alone is being
   commoditized by OSS gateways. The moat is the coupling: our data plane
   is worthless without our registry, and our registry programs any data
   plane. Inventory tools get replaced in a quarter; in-path infrastructure
   gets a decade; in-path infrastructure that *owns the record* gets the
   category.
3. **The lineage/audit corpus** — years of attribution history under
   regulatory retention is irreplaceable compliance evidence. Colorado's
   "reasonable care" standard (live now) and the EU's Dec 2027 deadline
   both convert this corpus into money.
4. **Federation as protocol** — *revised*: play it inside IETF WIMSE/AIMS
   with running code, and interoperate with XAA rather than fighting it.
   Our differentiated contribution is the piece no current draft covers:
   **monotonically attenuating delegation with signed lineage** (the
   Biscuit-style capability chain). Okta will standardize *access*; we
   standardize *delegated authority and attribution*.
5. **Integration breadth** — frameworks (LangGraph, CrewAI, OpenAI SDK,
   Claude Code/MCP), runtimes (K8s, MCP, shell, browser), downstream
   services (GitHub, AWS, Snowflake). (Unchanged.)

---

## 5. The six pillars, MVP → v1 → Enterprise

| # | Pillar | MVP (90 days) | v1 | Enterprise |
|---|--------|---------------|----|------------|
| 1 | **Identity & registry** | Register agents (owner, purpose, config/prompt hash, version); ephemeral instance credentials | Attestation (K8s/host), agent versioning workflows, org directory UI | SCIM-driven ownership, blueprint governance, cross-org directory |
| 2 | **Credential brokering** | Sealed downstream secrets; per-request injection at the proxy; agents never see real tokens | OAuth token exchange, cloud STS federation (AWS/GCP), just-in-time issuance | HSM/KMS integration, BYO-Vault backend, credential compliance reports |
| 3 | **Authorization & policy** | Per-agent tool allow-lists | Policy-as-code (engine locked in RFC-004), delegation with attenuation, human approvals | Org-wide policy distribution, policy CI, approval workflows/SLAs |
| 4 | **Lifecycle** | Provision, suspend, revoke — instant, identity- and instance-level | Retirement workflows, version pinning/rollout, expiry policies | SCIM lifecycle sync, delegated admin, break-glass |
| 5 | **Attribution & audit** | Every action logged with agent, version, instance, tool, decision — metadata only, by construction | Signed lineage chain in every credential (user→agent→sub-agent→tool) | Long-term retention, legal hold, regulator evidence packs |
| 6 | **Observability & compliance** | CLI + minimal web timeline; queryable audit | Anomaly surfacing, usage analytics, basic SIEM export | SOC2/HIPAA/EU-AI-Act/Colorado packs, full SIEM/SOAR integrations |

**Structural invariant carried from Conduit: payloads and prompts are never
stored.** Metadata-only audit is an architectural property, not a policy
toggle. This is both the most defensible privacy stance and a sales weapon
(the audit system your DPO doesn't have to review).

---

## 6. Roadmap

Founder capacity: full-time, 40+ hrs/week. Dates assume start 2026-07-06.

### Phase 0 — Lock the load-bearing decisions (weeks 1–3, overlaps Phase 1)
RFCs 001 (identity model), 003 (credential broker), 005-MCP (enforcement),
and 010 (MVP scope) drafted and locked; 002 (lineage/delegation) drafted —
its *wire format* can be stubbed in MVP but its *shape* constrains 001 and
must be argued first. Repo, CI, license files, name verification/purchase.

### Phase 1 — MVP: the 60-second demo, shippable (days 0–90)
A single Go binary (`chancery`) containing control plane + MCP-proxy data
plane; SQLite default, Postgres optional. Scope:

- **Registry**: `chancery agent register` — owner, purpose, config hash,
  prompt hash, version. Durable Agent + ephemeral instance credential
  (short-lived, minutes, auto-rotated, SPIFFE-style).
- **MCP enforcement**: Chancery is an MCP proxy in front of any MCP server
  (stdio + streamable HTTP), tracking the 2026-07-28 spec: per-agent tool
  allow-lists, per-call attribution, credential injection from sealed
  storage so the agent's environment holds no real secrets.
- **Revocation**: `chancery agent revoke` — takes effect on the next tool
  call (in-path check, no cache TTL excuses). Works at identity and
  instance level.
- **Audit timeline**: metadata-only, queryable; minimal web UI that answers
  "which agent, which tool, when, under whose authority" in one screen.
- **The demo**: an agent is mid-task; it attempts a tool call; it was
  revoked two seconds ago; the call is blocked; the timeline shows agent,
  version, tool, decision, owner. Scripted, recorded, reproducible —
  `make demo`.
- **Integrations**: Claude Code / any MCP client via standard MCP config;
  one LangGraph example repo.
- **Quickstart ≤ 30 seconds**: `brew install` / `docker run` / single
  binary download.

Explicitly stubbed in MVP: delegation chains (single-level authority only;
lineage fields present in the schema, enforcement single-hop), policy
engine (allow-lists only), attestation (trust-on-first-register).

### Phase 2 — v1: from wedge to platform (months 4–8)
HTTP egress broker (generic credential injection beyond MCP), policy-as-
code (engine per RFC-004), full delegation/attenuation (RFC-002 wire
format), runtime attestation, OIDC ingress (agent owner identity from the
workforce IdP), framework SDKs (LangGraph, CrewAI, OpenAI Agents), adapter
that programs **agentgateway** as an alternative data plane, basic SIEM
export. Shell-command enforcement begins (RFC-005 sequence: MCP → HTTP →
shell → browser).

### Phase 3 — Enterprise edition (months 6–12, overlapping)
SSO/SAML/SCIM, multi-tenancy, org-wide RBAC, compliance packs (SOC2,
HIPAA, Colorado "reasonable care" evidence, EU AI Act readiness for Dec
2027), long-term audit retention, HA control plane, support/SLA. Motion:
5–10 design partners from OSS users; first paid conversions. We do not
hire salespeople to fight Cisco; we convert platform engineers who already
deployed us.

### Phase 4 — Federation (months 9+, standards track runs in parallel from month 4)
Cross-org agent trust: publish the delegation/lineage token format as an
internet-draft in the WIMSE/AIMS stream, with Chancery as the running
code. Interop with XAA where it exists (accept XAA-established app access;
add agent lineage on top). Success criterion: one real cross-org agent
interaction between two Chancery installs, then one with a non-Chancery
implementation.

---

## 7. Decisions this RFC locks

- **D1 — Category and positioning:** agent IAM platform; the neutral,
  self-hosted system of record (§4). Demo revocation, sell the registry.
- **D2 — Business model:** open-core enterprise infrastructure. **Apache-2.0
  core**, proprietary enterprise modules in a separate tree behind a
  license boundary designed day-one (final module boundary: RFC-011).
  Rationale: the federation play requires a protocol nobody hesitates to
  adopt, and the bottom-up motion requires zero legal review friction;
  BSL/AGPL would tax both to insure against a cloud-capture risk we won't
  face until we've already won distribution.
- **D3 — Stack:** Go. Single static binary is the 30-second story;
  SPIFFE/SPIRE, Vault, OPA, Teleport are Go — the ecosystem we hire from,
  integrate with, and get contributions from. (Rust data plane is a
  possible post-v1 optimization, not an MVP concern.)
- **D4 — Wedge:** MCP-first enforcement, sequenced MCP → HTTP → shell →
  browser. Sharpened: the wedge is NOT "add auth to MCP" (the 2026-07-28
  spec + gateways commoditize that); it is the **agent-side identity,
  delegated authority, and org record** that the MCP spec deliberately
  leaves out.
- **D5 — Build-vs-integrate on the data plane:** build our own *minimal*
  MCP proxy for the MVP (the demo cannot depend on integrating someone
  else's gateway), but architect the control plane → data plane contract
  (Envoy-style split, per charter) so that agentgateway / Envoy AI Gateway
  become programmable data planes in v1. We compete on the control plane;
  we treat proxies as a market we program, not a market we fight.
- **D6 — Metadata-only audit** is a structural invariant. Never stored:
  prompts, payloads, tool-call arguments/results bodies. Stored: identity,
  lineage, tool name, decision, policy, timestamps, hashes.
- **D7 — Name: Chancery** (§8). Confirmed as the product name by the
  founder 2026-07-04 (was: working codename), contingent on domain/org
  registration and a trademark search before public launch.
- **D8 — Standards posture:** engage IETF WIMSE/AIMS from month 4 with
  running code; interoperate with XAA rather than compete with it; our
  standards contribution is attenuating delegation + signed lineage.

### Deferred (and to which RFC)

- Exact principal tuple and identity document format → RFC-001
- Delegation token format (Biscuit vs. Macaroons vs. custom JWT chain) → RFC-002
- Broker architecture, sealing, downstream credential classes → RFC-003
- Policy engine (Cedar vs. OPA vs. embedded DSL) → RFC-004
- Enforcement architecture per runtime → RFC-005
- Audit schema and export formats → RFC-006
- Revocation propagation semantics and SLOs → RFC-007
- APIs, storage schema → RFC-008
- Threat model → RFC-009
- Final MVP cutlines → RFC-010
- OSS/enterprise module boundary, final license text, tenancy → RFC-011
- Final public name and trademark → pre-launch decision, criteria in §8

---

## 8. Naming

**Criteria:** infra-credible (short, lowercase-able, works as a CLI verb
and a Go module path); evokes identity/authority/record rather than
AI-hype; no conflicts in the identity/security space; GitHub org and at
least one of .dev/.com available; pronounceable in a sales call.

**Availability check (2026-07-03, via GitHub API and registry RDAP):**

| Candidate | Story | GitHub | .dev | Conflict check |
|-----------|-------|--------|------|----------------|
| **chancery** | The office that kept the great seal, issued writs, and held the record of grants — literally a system of record for delegated authority | `chancery` taken; **`chanceryhq` free** | **AVAILABLE** | Clean in tech/identity; Delaware Court of Chancery adds corporate-law gravitas |
| mandate | Delegated, revocable authority | taken (variants free) | taken | Clean-ish; keep as *vocabulary* (see below) |
| warrant | Authority to act | `warranthq` free | taken | **Conflict:** Warrant = WorkOS's authz product (ex-warrant.dev) |
| tessera | Roman identity/trust token | taken | taken | **Conflict:** Consensys Tessera |
| signet | Seal of delegated royal authority | taken | taken | **Conflict:** Bitcoin signet |
| nuncio | Envoy bearing credentials | `nunciohq` free | taken | Mostly clean |
| procura | Power of attorney (the legal term, many languages) | taken | taken | Mostly clean |
| portunus | Roman god of keys and doors | `portunushq` free | taken | **Conflict:** Portunus LDAP identity manager (OSS) |
| countersign | The authorizing second signature | free-ish | taken | Clean but long |
| legate / praetor / herald / sigil / bulla / rein / bridle | various | — | all taken | assorted conflicts (NVIDIA Legate, Phacility Herald, Sigil epub, …) |

**Decision (D7): codename Chancery.** Only candidate with an available
.dev, a free org-style GitHub handle, zero conflicts in the space, and the
best story: a chancery *is* the office of record for sealed, delegated
authority. Binary: `chancery`. Register chancery.dev immediately (~$12/yr
risk). Verify .ai/.io and trademark search before public launch.

**Product vocabulary bonus:** the delegation token — the signed, attenuating
capability an agent acts under — is called a **writ**. "Every agent acts
under a writ. Revocation quashes the writ." This vocabulary survives even
if the company name changes, and it is the kind of term a standard gets
named after.

---

## 9. What we deliberately do NOT build

1. **An LLM gateway.** No inference proxying, no model routing, no token
   budgets. Conduit was that; the market is commoditized; we govern
   *actions*, not *inference*.
2. **Prompt security / guardrails.** No prompt-injection scanning, no
   content filtering. Others (Lakera et al.) do this; it composes with us.
3. **NHI discovery/inventory.** We don't scan cloud accounts for stale
   service accounts. We are where *new* identities come from, not a census
   of old ones. (Also keeps us out of Cisco/Astrix's kill zone.)
4. **An agent framework or orchestrator.** We are Switzerland for
   LangGraph/CrewAI/OpenAI SDK/Claude; competing with frameworks would
   poison every integration.
5. **Payload/prompt storage.** Structural invariant (D6).
6. **A sales-led enterprise motion before v1.** No enterprise features
   before the OSS core has organic installs; no competing for CISO budget
   against Cisco field teams we cannot outspend.
7. **A proprietary federation protocol.** Standards track or nothing (D8).

---

## 10. RFC series sequencing

| RFC | Locks | Depends on | MVP-critical |
|-----|-------|-----------|--------------|
| 001 agent-identity-model | The principal tuple; Agent vs. instance; identity document format | 000 | **Yes** |
| 002 lineage-and-delegation | Attenuation semantics; writ (token) format; lineage chain | 001 | Shape yes; wire format no |
| 003 credential-broker | Sealing, injection, downstream credential classes | 001 | **Yes** |
| 004 policy-and-authorization | Policy engine choice; allow-list → policy-as-code path | 001, 002 | No (allow-lists suffice) |
| 005 runtime-enforcement | MCP proxy architecture (tracking 2026-07-28 spec); HTTP/shell/browser sequence | 001, 003 | **Yes (MCP part)** |
| 006 audit-and-attribution | Event schema; metadata-only enforcement; query model | 001, 002 | **Yes (schema)** |
| 007 lifecycle-and-revocation | Revocation propagation, SLOs, suspend/retire semantics | 001, 005 | **Yes (revoke path)** |
| 008 data-model-and-apis | Storage schema, API surface, versioning | 001–007 | **Yes** |
| 009 threat-model | STRIDE + OWASP LLM Top 10 against the whole design | 001–008 | Drafted during MVP, locked before v1 |
| 010 mvp-scope | The 90-day cutlines, demo script, launch checklist | all above | **Yes** |
| 011 open-core-boundary | Module boundary, license enforcement, tenancy seams | 000, 008 | Boundary *placeholder* now (D2); locked before enterprise work |
| 012 dynamic-agent-creation | Writ-gated runtime spawn: templates, `admin` verb, ephemeral lifecycle | 001, 002, 004, 007, 008 | Added 2026-07-05 from dogfooding: orchestrators that create agents at runtime are the common case, not the edge case |
| 013 browser-sessions-and-tokens | Sessions as sealed credentials; `net` verb semantics; the URL guard | 001–005 | Added 2026-07-05: browser agents inherit human sessions — the top-named 2026 enterprise concern, unanswered at the identity layer |
| 014 read-only-dashboard | Embedded `/ui`: timeline, agents, delegation tree, templates — reads only | 006, 008, 011 | Added 2026-07-06: the product's proof is visual; writes stay CLI/API |
| 015 call-lifecycle-and-leases | `mcp.call_result` lifecycle; capability leases so mid-flight revocation fails at cooperating servers | 002, 005, 006, 008 | Added 2026-07-16 from external design review: "admitted" and "happened" are different facts |
| 016 server-pinning | Callee trust T1: pin the wrapped server's hash at wrap, refuse on drift, audited repin | 005, 006 | Added 2026-07-16 from practitioner review: permission is about the caller, risk is about the callee |
| 017 intent-socket | Task-bound grants + a pluggable per-call intent checker (veto-only, advise/enforce) | 002, 004, 005, 006 | Added 2026-07-16: detectors judge the moment; Chancery stays the actuator — now with a socket |
| 018 frozen-installs-and-confinement | `mcp install` (frozen, tree-pinned server installs) + `--confine` (manifest-bounded egress/FS as an OS boundary, fail closed) | 005, 006, 016 | Added 2026-07-16: the guided default G13 asked for; the writ bounds the call, the manifest bounds the process |

Order of writing: **001 → 002 → 003 → 005 → 006 → 007 → 008 → 010**, with
004, 009, 011 drafted in parallel and locked later. One RFC at a time; an
RFC is locked when its decision has a build consequence scheduled.

---

## 11. Addendum A (2026-07-04): the extended question set

Research review at series close (OWASP Agentic Security Initiative /
Top 10 for Agentic Applications 2026, CSA MAESTRO + Agentic AI IAM,
Gartner guardian-agents Market Guide and agent-sprawl guidance) showed
the five defining questions are all **outbound and known-population**:
our agents, acting on services, already registered. Two questions were
missing and are hereby added to the invariant test:

6. **Inbound and agent-to-agent:** when an agent — another team's,
   another org's, a vendor's SaaS agent — initiates contact with YOUR
   agents or systems, how is it identified, verified, and bounded?
   (OWASP ASI07; only ~24% of orgs report visibility into
   agent-to-agent communication.) This is the federation phase's
   demand-side justification, not a v3 nicety: A2A traffic exists today
   and is unauthenticated by default.
7. **The unregistered agent:** how do you notice the agents that never
   registered? NHI *scanning* remains a non-goal (RFC-000 §9) — but
   **observation at the enforcement points we already hold** is in
   scope: a Chancery proxy or API can see and flag unregistered actors
   at the choke point (shadow-agent events in the audit stream), which
   is discovery as a byproduct of enforcement rather than a sales-led
   scanner. Gartner's agent-sprawl guidance makes inventory step one;
   our answer is "register here and the inventory builds itself — and
   the proxy tells you who hasn't."

Category-vocabulary notes (positioning, not architecture): Gartner's
guardian-agents Market Guide (Feb 2026) is the analyst box we will be
placed in — position Chancery as the **deterministic** guardian layer
(signed policy, not an LLM supervising LLMs; our decisions are
reproducible in court, theirs are probabilistic). Gartner's
proportional-governance finding (uniform controls across autonomy
levels fail) maps directly onto writ templates — autonomy tiers are
policy packs over the existing mechanism (v1), not a new mechanism.
Gartner's "40% of enterprises will demote or decommission agents by
2027 due to governance gaps found in production" is the demo's opening
line. CSA's Agentic AI IAM blueprint (DIDs + verifiable credentials):
we stay JOSE/SPIFFE for running code; a VC-compatible *export* of agent
identity is the federation-phase representation layer, recorded for
federation scoping.

## 12. What gets built (this RFC's build consequence)

1. This repo, initialized: README, RFC template, this RFC. ✅ (this commit)
2. Register **chancery.dev** and the **chanceryhq** GitHub org. (Founder
   action, ~15 minutes, do before someone reads this RFC on a livestream.)
3. RFC-001 (agent identity model) — next artifact, target within 5 days.
4. `make demo` exists by day 90 and runs the 60-second revocation demo
   end-to-end on a laptop.
