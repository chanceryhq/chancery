# RFC-002: Lineage and Delegation — the Writ

- **Status:** Locked
- **Author:** Aneesh Gupta
- **Created:** 2026-07-04
- **Locked:** 2026-07-20
- **Depends on:** RFC-000, RFC-001
- **Blocks:** RFC-004, RFC-006, RFC-007

---

## 1. Problem

Agents spawn agents. A planning agent forks three workers; a coding agent
launches a test runner; a browser agent hands a subtask to a summarizer.
Today, delegation is **credential copying**: the child inherits the
parent's environment, which means the parent's *entire* authority, forever,
with no record that a delegation happened. Three failures, mapping to
defining questions 1, 2, and 5 (RFC-000 §1):

1. **Authority widens by accident.** A sub-agent spawned to "read the
   docs repo" holds the same token that can push to main. Nothing narrows.
2. **Attribution collapses at the first fork.** The audit log shows the
   shared credential; whether the parent or any of its children acted is
   unrecoverable — reconstruction from timing forensics at best.
3. **The human authority source is lost.** Whose intent authorized this
   action? Two hops from the user who kicked off the workflow, no system
   can say.

RFC-001 gave every agent an identity with an `authority` slot. This RFC
locks what fills it: the **writ** — how authority enters, how it narrows
across spawning, and how the delegation chain doubles as the attribution
record. If the identity model (001) says *who is acting*, the writ says
*under whose authority and within what bounds* — and it must make
over-delegation structurally impossible rather than policy-discouraged.

## 2. Existing approaches and why they fall short

**OAuth 2.0 Token Exchange (RFC 8693).** The standards answer to
acting-on-behalf-of: exchange a token for a new one, recording actors in
`act` (chained) and constraining future exchange with `may_act`. Right:
the `act` claim chain is genuine prior-art for lineage; audience/scope
narrowing exists. Falls short: **narrowing is conventional, not
structural** — the authorization server *may* issue broader scopes on
exchange; nothing in the mechanism forbids it. Every hop is a round-trip
to an AS that must understand agent semantics. And the chain records
identities only — not the *capability bounds* at each hop, so audit can
see who touched the request but not what each hop was permitted.

**Macaroons (Google, 2014).** Bearer tokens with HMAC-chained caveats:
anyone holding a macaroon can append a caveat offline, and caveats only
restrict. Right: monotonic attenuation is the core mechanism — this is
the algebra we want. Falls short: **symmetric crypto** — verification
requires the minting key, so every verifier shares a secret with the
minter (untenable across trust domains, fatal for federation);
third-party caveats are awkward; no standard caveat language ever
emerged; largely unadopted outside Google despite a decade.

**Biscuit v2 (biscuit-auth).** The modern successor: public-key block
chains, offline attenuation via per-block ephemeral keypairs (each block
signs the next block's public key — holder can extend but never edit),
embedded Datalog for authorization logic. Right: *exactly* the
attenuation-by-construction we need, asymmetric, offline-capable. Falls
short **as an MVP dependency**: every SDK and verifier must embed a
Datalog engine (our policy language decision belongs to RFC-004, and
coupling it to the token format now would pre-empt that RFC); library
maturity is uneven across the languages agents are written in
(Python/TS are where agents live); and its authorization model wants to
own policy evaluation, which in Chancery belongs to the control plane.

**Okta XAA / Entra Agent ID.** XAA: IdP-mediated app-to-app token
issuance — hub-and-spoke, online-only, no capability bounds carried in
the token, no multi-hop chain. Entra: blueprint-impersonation mints
child tokens (parent-child recorded via `ParentID`), but the child's
*permissions* come from directory assignment, not from a narrowing of
the parent's — a child can hold permissions its parent never had.
Both record relationships; neither enforces attenuation.

**SPIFFE/WIMSE.** Identity documents, deliberately silent on delegation.
(The WIMSE stream is where we'll eventually *land* the writ format —
RFC-000 D8 — which is an argument for wire-format compatibility, not for
waiting.)

## 3. Alternatives considered

**A. Central re-issuance with plain scoped tokens.** Every spawn calls
the control plane; it mints the child a fresh, narrower token; narrowing
enforced server-side; lineage lives in the registry database, not the
token. Optimizes for simplicity — no chain format at all. Loses:
attribution is **reconstructed, not embedded** (the token in a downstream
log names only the child; the chain requires joining against our DB —
exactly the forensic posture RFC-000 rejects); federation impossible (a
partner org can verify a signature, not query our database); and the
registry becomes the single authority oracle even for reads.

**B. Biscuit as the writ, wholesale.** Adopt biscuit-go/biscuit-python/
biscuit-wasm, encode capabilities as Datalog facts. Optimizes for
maximum-strength offline attenuation and an existing spec. Loses: Datalog
engine in every verifier and SDK; token format decides RFC-004's policy
question by fait accompli; immature libraries in agent-land languages;
debugging Datalog unification failures is a support burden a solo founder
cannot carry in year one.

**C. Macaroons.** Optimizes for implementation simplicity (HMAC chains
are trivial). Loses: symmetric verification kills federation (moat #4)
and even multi-component deployment (every broker replica and every
partner needs the root secret). Disqualified.

**D. (Chosen) The writ: a JWS grant-chain with Biscuit-congruent
semantics — centrally appended in MVP, offline-attenuable by design.**
Detailed in §4. Loses relative to B: we own a format (spec burden is
ours); offline attenuation arrives in v1 rather than day one. Accepted:
the broker is in-path anyway (RFC-000 moat #2), so MVP delegation is
always within reach of the control plane; the format is designed so
holder-side attenuation is enabled by adding per-block keys, not by
redesign.

## 4. Decision

**Authority in Chancery is carried by a writ: an ordered chain of signed
blocks in which block 0 grants capabilities and every subsequent block
may only add caveats. A writ's effective authority is block 0's
capability set intersected with every caveat in the chain. Widening is
unrepresentable.**

### Structure

```
writ = [ grant-block, delegation-block*, ]        each block JWS-signed

grant-block (block 0, signed by Chancery control plane):
  wid:   writ id (ULID)
  for:   the authority source — human/team principal or org policy
         e.g. "user:aneesh@acme.com"                 (WHOSE authority)
  to:    subject principal — agent SPIFFE ID + version digest (RFC-001)
  cap:   capability set — array of (verb, resource-pattern) grants;
         grammar owned by RFC-004, algebra owned here
  exp:   expiry
  nbf/iat, key id

delegation-block (block N, signed by control plane in MVP;
                  by block N-1's delegation key in v1):
  to:     child principal (agent SPIFFE ID + version digest)
  caveat: restrictions only — capability subset patterns, tighter
          resource patterns, shorter expiry, max further depth,
          rate/count bounds
  exp:    ≤ parent block's exp (TTL can only shrink)
  prev:   hash of the serialized chain prefix (tamper-evidence)
```

Rules, enforced at append time and re-verified at use time:

1. **Monotonic attenuation:** a block carries no `cap` field after block
   0 — the field does not exist in the delegation-block schema. Authority
   = `cap ∩ caveat₁ ∩ … ∩ caveatₙ`. This is Biscuit's discipline in JWS
   clothing: narrowing is what the data structure *can express*, not what
   policy checks for.
2. **TTL monotonicity:** each block's `exp` ≤ its parent's. A child never
   outlives its parent's authority.
3. **Bounded depth:** block 0 sets `max_depth` (default 4); appends
   beyond it are refused. Runaway recursive spawning is an issuance
   failure, not a runtime surprise.
4. **The chain is the lineage:** `for` → `to₀` → `to₁` → … → `toₙ` reads
   as user → workflow → agent → sub-agent. Every audit event (RFC-006)
   records `(wid, block-index)`; attribution is embedded in the
   credential that acted — questions 2 and 5 answered by construction,
   zero joins.
5. **Revocation at any block** (mechanics RFC-007): revoking block N
   kills the subtree rooted there; revoking the writ kills the tree;
   revoking the agent (RFC-001) kills every writ it holds. Checked
   in-path at the broker per action.

### Issuance and verification

- **MVP (online append):** a parent spawning a child calls
  `POST /v1/writs/{wid}/delegate` with the proposed caveats; the control
  plane validates rules 1–3, appends, signs (ES256, same issuer keys as
  RFC-001 documents), returns the extended writ. The broker verifies
  signature chain + revocation on every brokered action.
- **v1 (offline attenuation):** each block gains an ephemeral delegation
  keypair — block N signs block N+1's public key (Biscuit's exact
  mechanism) — so a parent in a partner org or an air-gapped runtime can
  attenuate without calling us. The MVP schema reserves the field
  (`dk`, delegation key, nullable) so this is additive, not a migration.
- **Separation from identity:** the writ is not the identity document.
  RFC-001's document says *who is acting* (5-minute instance credential);
  the writ says *under what authority* (task-scoped lifetime, referenced
  by `writ` claim). An action requires both; they revoke independently.
  A stolen writ without an instance document is inert (and vice versa).

### Relationship to standards

Wire format is deliberately boring: JWS blocks, ES256, JSON claims —
verifiable with commodity JOSE libraries everywhere agents are written.
The novel part — the attenuation algebra and the `for`/`to` lineage
semantics — is exactly the piece missing from RFC 8693, XAA, and the
WIMSE drafts, and is what we take to the IETF stream with running code
(RFC-000 D8). If the community converges on Biscuit proper, the model
maps block-for-block; we lose serialization, not semantics.

## 5. Why

- **Question 1 (scoped issuance, org visibility):** authority is granted
  once at block 0 by a *named human or policy source* and can only shrink
  — the org can read any writ and know the outer bound of what the entire
  delegation tree can do, without evaluating any policy.
- **Question 2 (identify, cut off):** subtree revocation at any block;
  in-path checks make it next-action-fast.
- **Question 5 (which specific agent):** the acting block names the
  child's agent ID *and version digest*; combined with RFC-001's instance
  document, the audit event pins actor, code state, and authority chain.
- **Solo-founder economics:** commodity JOSE beats embedded Datalog for
  every SDK we must ship (Python, TS, Go) and every support ticket we
  must answer, while conceding nothing structural — attenuation is in
  the data model, not the engine.
- **The 60-second demo gets its second act:** revoke the *parent's* writ
  and watch three grandchildren go dark mid-task, each with its own
  attributed refusal in the timeline.

## 6. Trade-offs accepted

- **We own a token format.** Spec, test vectors, and fuzzing are our
  burden. Mitigated by JWS reuse (parsing/signing is commodity) and by
  Biscuit-congruence (a documented exit ramp).
- **MVP delegation requires the control plane online.** A spawn during a
  control-plane outage fails closed. Acceptable: RFC-001 already accepts
  fail-closed issuance; offline attenuation lands with v1 federation.
- **Chain size grows linearly with depth** (~0.5 KB/block). With
  `max_depth` 4–8 this stays under HTTP-header budgets; writs travel in
  request bodies to our broker anyway.
- **Capability grammar is deferred to RFC-004.** The writ carries
  `(verb, resource-pattern)` pairs whose *matching* semantics RFC-004
  owns. Risk of rework is contained: the algebra (intersection) is
  locked here and is grammar-independent.
- **`for` names a principal, not a session.** We record whose authority,
  not a live OIDC session binding (that's a v1 ingress feature). An org
  can lie to itself about user consent in MVP; the field is at least
  present, signed, and auditable.

## 7. Failure scenarios

- **Issuer key compromise:** forged writs possible until rotation; same
  blast radius and runbook as RFC-001 issuer keys (they are the same
  keys in MVP). Rotation invalidates all writs; agents re-request from
  block-0 sources. Task-scoped writ lifetimes bound the re-issuance storm.
- **Revoked block, cached verification:** the broker checks revocation
  per action against the registry; a registry partition means fail-closed
  (no action), never fail-open. There is no CRL propagation delay because
  there is no CRL — in-path check or refusal.
- **Depth exhaustion mid-task:** a legitimate deep workflow hits
  `max_depth`. Failure is at spawn time with a specific error; the fix is
  a wider block-0 grant, a human decision. Preferable to unbounded trees.
- **Caveat starvation:** intersected caveats can zero out authority (a
  child granted nothing). Detected at append time; the API refuses to
  mint a null-authority block with a distinct error rather than minting
  a writ that can only fail downstream.
- **Clock skew across blocks:** TTL monotonicity checked at append with
  ±60s leeway (matching RFC-001); verification uses broker clock only.
- **Parent revoked between child's spawn and child's action:** child's
  next brokered action fails the subtree check. The window equals one
  action, not one TTL.

## 8. Security considerations

(Full treatment RFC-009.) Writ theft: inert without an instance document
(§4); replay across brokers bounded by `aud` and revocation checks.
Malicious parent minting misleading caveats: cannot exceed own authority
(algebra), but can name a misleading `to` — mitigated because the control
plane validates the child principal exists in the registry at append
time. Confused-deputy at the broker: the broker evaluates the *writ's*
authority, never the broker's own — RFC-003 must preserve this. Privacy:
capability patterns may reveal resource names in audit storage — patterns
are metadata under D6, accepted and documented; payloads still never
stored. Collusion between siblings (capability union across writs): each
action is evaluated against exactly one writ — presenting two writs is
two actions with two audit trails; no union is computable at the broker.

## 9. MVP impact

Built in the 90-day window:

- `writs` + `writ_blocks` tables (RFC-008 owns DDL); `dk` column
  reserved, null.
- Issuance API: create (block 0, owner-authenticated), delegate
  (rules 1–3 enforced), revoke (block-level).
- Verification library in the broker: signature chain, TTL monotonicity,
  revocation, effective-capability intersection → allow/deny for RFC-005.
- CLI: `chancery writ grant|show|delegate|revoke`; `chancery writ show`
  renders the lineage chain as a tree — this *is* the demo's audit view.
- SDK: spawn helper that requests a delegated writ and injects it into
  the child's environment alongside the identity document.
- Stubbed: offline attenuation (`dk`), OIDC session binding for `for`,
  capability grammar beyond exact-match + `*`-suffix patterns
  (placeholder until RFC-004 locks the language).

Next: **RFC-003 (credential broker)** — how a writ plus an identity
document becomes a real downstream credential the agent never sees.
