# RFC-001: Agent Identity Model

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-04
- **Depends on:** RFC-000
- **Blocks:** RFC-002, RFC-003, RFC-005, RFC-006, RFC-007, RFC-008

---

## 1. Problem

Today an "agent's identity" is whatever credential happened to be in its
environment: a human's OAuth session, a team's shared API key, a service
account created for something else. Three failures follow, mapping to
defining questions 1, 2, and 5 (RFC-000 §1):

1. **No answer to "what is this agent?"** An agent is a configuration: a
   model, a system prompt, a tool manifest, code. Change the prompt and it
   is a different actor with the same name — and no system records that.
   When the 3 a.m. question is "did the agent that dropped the table have
   the same instructions as the one we reviewed?", nothing can answer it.
2. **No answer to "which agent?"** Ten instances of five agents share one
   `GITHUB_TOKEN`. The audit log names the token.
3. **No revocation seam.** You can revoke the shared credential (breaking
   five agents) or nothing.

Before Chancery can broker a credential (RFC-003), attenuate a delegation
(RFC-002), or attribute an action (RFC-006), it must lock what an agent
identity **is**: what object is named, what is versioned, what runs, what
gets revoked, and what a relying party verifies.

## 2. Existing approaches and why they fall short

**OAuth 2.x clients (one client per agent) + RFC 8693 token exchange.**
The default answer today: register each agent as an OAuth client;
delegation via token exchange's `act`/`may_act` claims. Right: real
issuance, real audience scoping; `act` is genuine prior art for
acting-on-behalf-of chains. Falls short: a `client_id` is an opaque
registration with no version semantics (no record of *what* the client is,
or that it changed), no instance layer (every replica is the same client),
and delegation-by-impersonation rather than attenuation. Client sprawl
across N downstream authorization servers recreates the inventory problem
we exist to kill.

**SPIFFE/SPIRE and IETF WIMSE (WIT/WPT drafts).** The strongest identity
*mechanics* in production: URI-named identities in a trust domain,
short-lived documents (X509-SVID/JWT-SVID; WIMSE adds the WIT — a JWT with
ES256-mandatory signing and proof-of-possession key binding, plus WPTs
binding tokens to individual requests). Uber attests billions of SVIDs
daily. Falls short *for agents*: SPIFFE identity is **attestation-born** —
it answers "this process on this node is service X." It has no concept of
what the workload *is* (prompt, config, tools), who it *acts for*, or an
owner; a SPIRE registration entry is a selector match, not a registry
record. SPIFFE tells you where the agent runs; it cannot tell you whether
the agent changed. We adopt its naming and token mechanics (deliberately —
this is the federation substrate, RFC-000 D8) and reject its
attestation-only birth model.

**Microsoft Entra Agent ID (GA April 2026).** The closest prior art, and
validation of the two-layer instinct: an **agent identity blueprint**
(template, holds the auth credentials) creates **agent identities**
(single-tenant service principals with an "agent" subtype and a `ParentID`
back-reference); the blueprint performs token exchange so the agent
identity appears as the client in tokens and audit logs. Falls short:
(a) **directory-centric** — an entry in Entra with Conditional Access at
token-issuance time, not in-path enforcement of actions; (b) **no
immutable version** — a blueprint is a mutable template; nothing records
config/prompt hashes, so "did this agent change?" remains unanswerable;
(c) **no runtime instance principal** — replicas are indistinguishable;
(d) single-ecosystem by construction (the credential *is* an Entra token;
the trust domain *is* the tenant).

**Okta XAA / Auth0 Auth for GenAI.** Solves app-to-app delegated *access*
for agents inside an Okta-federated app estate. The agent itself is
modeled as the application it lives in; there is no independent agent
principal, no version, no instance. Access protocol, not identity model.

**API keys + Vault.** Vault issues and seals secrets superbly, but a
secret is not an identity: no name, no owner, no version, no lineage slot.
(Vault appears again in RFC-003 as a broker back-end, where it belongs.)

**Biscuit/Macaroons.** Authority tokens with attenuation — the leading
candidates for the *writ* (RFC-002). They presuppose an identity to
attenuate *from*; they are not identity models. Deferred.

## 3. Alternatives considered

**A. Agents as OAuth clients.** One `client_id` per agent, client-
credentials grant, token exchange for delegation. Optimizes for
compatibility — every downstream service already speaks it. Loses: no
version/instance semantics (the actual product), N-server client sprawl,
and it entangles our identity layer with downstream authorization servers
we don't control. OAuth remains how we *talk to downstream services*
(RFC-003), not what an agent *is*.

**B. Agents as pure SPIFFE workloads.** Run SPIRE, register agents as
workload entries, attestation-born SVIDs. Optimizes for battle-tested
mechanics and zero new token formats. Loses: identity collapses to
runtime location — redeploy the same agent elsewhere and it's a different
identity; change the prompt in place and it's the same identity. Exactly
backwards for agents. Also imports SPIRE's operational weight into the
30-second install.

**C. Agents as directory accounts (Entra-style subtype).** Model agents as
a new principal subtype in an existing IdP directory; inherit its
lifecycle tooling, groups, conditional access. Optimizes for enterprise
familiarity and org-chart integration. Loses: the directory is not in the
request path (question 2's "cut off access" becomes token-expiry-
eventually, not next-call-now); no version immutability; and it makes us a
plugin to someone else's system of record — surrendering RFC-000 moat #1.

**D. Registry-born, three-layer principal with SPIFFE-compatible naming
and WIMSE-compatible documents.** Chosen. Identity originates in
Chancery's registry (owner, purpose, versioned content), is *confirmed*
at runtime by attestation, and is expressed in credentials that SPIFFE/
WIMSE-speaking infrastructure can verify. Loses: we own a registry schema
and an issuance path ourselves (more build than A/B/C) and carry a
compatibility constraint. Accepted — this *is* the product.

## 4. Decision

**An agent is a third class of principal, distinct from humans and
workloads, defined by a three-layer identity:**

```
Agent            durable, named, owned            what policies bind to
 └── Version     immutable, content-addressed     what was reviewed/approved
      └── Instance  ephemeral, attested, credentialed   what actually runs
```

**Layer 1 — Agent.** The durable registered identity: a name in the org's
trust domain, an accountable **owner** (a human or team principal from the
org's IdP), a stated **purpose**, and a lifecycle state
(`active | suspended | retired`). Its identifier is a SPIFFE-compatible
URI, stable across versions and instances:

```
spiffe://<trust-domain>/agent/<agent-name>
e.g. spiffe://acme.com/agent/deploy-bot
```

**Layer 2 — Version.** An immutable, content-addressed snapshot of what
the agent *is*: `sha256` digests of system prompt, configuration, tool
manifest, and (optional) code/image, plus the model identifier. Any change
= new version. Versions are never edited, only superseded; the digest is
the review artifact ("v7 is what security approved").

**Layer 3 — Instance.** A running embodiment: instance ID (ULID), the
version it runs, attestation evidence of where/how it runs, and a
**short-lived identity document** (default TTL 5 minutes, max 60,
auto-renewed) that it presents to Chancery's broker on every action.

**The principal tuple.** Every identity document carries five slots —
`(identity, version, instance, authority, attestation)` — where
*authority* references the writ (the delegated, attenuating capability
chain, format locked in RFC-002) and *attestation* carries typed evidence.
The tuple is the unit that policies evaluate (RFC-004), brokers check
(RFC-003), and audit records (RFC-006). RFC-001 locks the slots; 002/004
lock the contents of `authority`.

**The identity document.** A JWT, wire-compatible with WIMSE WIT
conventions: **ES256 (default; Ed25519 optional)**, issued by the
Chancery control plane, with a `cnf` (proof-of-possession) slot present
in the schema from day one:

```json
{
  "iss": "https://chancery.acme.com",
  "sub": "spiffe://acme.com/agent/deploy-bot",
  "jti": "01K1X5...", "iat": 1751600000, "exp": 1751600300,
  "cnf": { "jwk": { } },
  "chancery": {
    "ver":   "sha256:9f2c...",
    "inst":  "01K1X4ZJ...",
    "owner": "user:aneesh@acme.com",
    "writ":  "w_01K1X3...",
    "att":   { "type": "declared", "evidence": null }
  }
}
```

Version and instance live in **claims, not the URI path**: policies,
federation partners, and downstream systems bind to the durable `sub`;
instances are too ephemeral to be policy targets, and a stable `sub`
keeps SPIFFE interop clean (one identifier per agent, per the WIMSE
identifier model).

**Birth and confirmation.** Identity is **registry-born, attestation-
confirmed**: created by an authenticated registration (owner credential
required), and each instance's identity document records attestation
evidence of its runtime. MVP ships `declared` attestation (evidence
recorded, unverified); the verifier interface (`k8s`, `host`, `cloud`) is
defined now and implemented in v1. This inverts SPIFFE (attestation-born)
deliberately: for agents, *what it is and who owns it* precedes *where it
runs*.

**Revocation semantics** (mechanics in RFC-007): revocation at any layer —
agent (all versions, all instances), version (e.g., a recalled prompt),
or instance (one runaway replica). Because the broker is in-path, a
revocation check is a registry lookup on the next action — token TTL is
the ceiling on out-of-path exposure, not the revocation latency.

## 5. Why

- **Question 5 (which SPECIFIC agent?):** `sub` + `ver` + `inst` in every
  credential, hence in every audit event, by construction.
- **Question 2 (identify, reconstruct, cut off):** three revocation
  layers, in-path enforcement, TTL-bounded exposure.
- **Question 1 (visibility into what it can do):** the registry is the
  directory: every agent, owner, purpose, version — queryable.
- **Version as content address** is the load-bearing novelty: it converts
  "we think the agent is unchanged" into a hash comparison, makes review
  meaningful (approve digests, not vibes), and gives Colorado
  "reasonable care" / EU AI Act evidence a concrete artifact.
- **SPIFFE/WIMSE compatibility** buys the federation play (RFC-000 D8)
  with running code instead of a novel format, and makes existing
  infrastructure (Envoy, Vault, service meshes) able to *verify* our
  documents.

## 6. Trade-offs accepted

- **Three objects instead of one API key** — more API surface and
  onboarding concepts. Mitigation: `chancery agent register` creates
  Agent + Version in one command; instances self-register on startup via
  SDK; the quickstart never says "version" out loud.
- **Registry-born trust bootstraps on registration credentials** — a
  stolen owner credential registers a plausible agent. Accepted: this is
  the same trust root every IdP has; mitigated by attestation in v1 and
  registration audit events from day one.
- **Bearer documents in MVP** (`cnf` present but unenforced): a stolen
  document is usable for ≤5 minutes against the broker. Accepted for MVP
  velocity; PoP enforcement (DPoP-style, WPT-compatible) is a v1
  hardening item in RFC-003's threat budget.
- **Declared attestation in MVP** can lie about runtime. Accepted and
  documented; the evidence field is recorded (auditable lie) and the
  verifier interface lands in v1.
- **SPIFFE compatibility constrains naming** (one URI per agent, trust
  domain = FQDN). Cheap today, valuable at federation time.

## 7. Failure scenarios

- **Control plane down:** instances can't renew documents; brokered
  actions **fail closed** at the broker within one TTL (≤5 min). Agents
  degrade to inaction, not to ungoverned action. (HA control plane is an
  enterprise-phase feature; MVP accepts the single point of refusal.)
- **Issuer key compromise:** rotate signing key; all outstanding documents
  invalid at next verification; instances re-attest and renew. Blast
  radius bounded by TTL. Key rotation is a v1 runbook item, key storage
  per RFC-003 sealing.
- **Clock skew:** ±60s leeway on `iat`/`exp` verification; skew beyond
  that fails closed with a distinct error code.
- **Owner offboarded:** agents whose owner leaves the IdP become
  `orphaned` — a queryable state that (per policy, RFC-004) blocks new
  instance issuance until ownership transfers. No ownerless agents, ever.
- **Hash gaming (registered prompt ≠ running prompt):** possible under
  `declared` attestation; closed in v1 when the SDK computes digests
  in-runtime and the verifier signs them. Documented MVP limitation.
- **Registry data loss:** identities are re-registerable from IaC
  (`chancery apply` config-as-code path, RFC-008), but audit lineage
  refers to registry IDs — backups are a launch checklist item (RFC-010).

## 8. Security considerations

Full treatment in RFC-009; introduced here: document theft/replay (TTL,
`aud`-binding to the broker, later PoP), registration-time impersonation
(owner credential strength — inherits org IdP policy), version-spoofing
(declared attestation gap above), registry as high-value target (it holds
*no downstream secrets* — those live in the broker's sealed store,
RFC-003; compromise of the registry alone forges identity but not
credentials), and privacy (prompt *hashes* are stored, prompts are not —
the digest reveals nothing; D6 invariant holds).

## 9. MVP impact

Built in the 90-day window:

- Registry schema: `agents`, `agent_versions`, `instances` (+ lifecycle
  states, owner references) — RFC-008 owns final DDL.
- Issuance path: instance startup → registration credential → identity
  document (ES256 JWT, 5-min TTL, auto-renew); verification middleware in
  the broker.
- CLI: `chancery agent register|describe|list|suspend|revoke`,
  `chancery version list`, `chancery instance list|revoke`.
- SDK surface (Go + TS): `chancery.Run(agent, fn)` — self-registers an
  instance, renews documents, injects them into MCP calls.
- Attestation: `declared` type only; `Attestor` interface defined with
  `k8s`/`host` implementations stubbed.
- Stubbed: PoP enforcement, attestation verifiers, X509-SVID issuance,
  ownership-transfer workflow (manual SQL acceptable at MVP).

Next: **RFC-002 (lineage and delegation)** — the writ: how authority
enters the tuple, attenuates across sub-agent spawning, and signs the
lineage chain.
