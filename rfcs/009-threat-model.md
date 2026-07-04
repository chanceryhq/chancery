# RFC-009: Threat Model

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-04
- **Depends on:** RFC-001 … RFC-008
- **Blocks:** RFC-010 (launch checklist inherits the gap table)

---

## 1. Problem

Chancery asks organizations to route their agents' authority through it.
That concentration is the value and the target: a security product with
an unexamined attack surface is a liability amplifier. This RFC fixes
the trust boundaries, walks STRIDE across every component, maps the
OWASP LLM Top 10 to our mechanisms, and — most importantly — publishes
the **honest gap table** for the MVP, each gap with an owner and a
phase. A threat model that hides its gaps is marketing.

**Trust boundaries (locked):**
1. **The model/agent process is untrusted.** Anything reachable by
   prompt injection — the agent loop, its context, its env — is assumed
   adversarial. Enforcement lives outside it (RFC-005).
2. **The operator (box owner) is trusted in MVP.** Whoever can replace
   the `chancery` binary or write SQL owns the deployment. Detection
   (audit chain) exists; prevention (signed releases, split roles,
   external anchoring) is phased.
3. **The MCP server is semi-trusted:** we govern what the agent may
   invoke, not what the server does after an allowed call (sandboxing
   is the `exec` phase).
4. **Downstream services** enforce their own authz; our credentials to
   them are the crown jewels (seal store).

## 2. STRIDE, per component

**Registry & issuer (control plane).**
- *Spoofing:* agent registration under a stolen owner credential —
  inherits org credential policy; registration is audited with owner
  context. Identity documents are bearer in MVP (gap G1); ≤5-min TTL
  bounds replay; `cnf` slot reserved (RFC-001).
- *Tampering:* writ chains are ES256-signed with prefix hashes — splice,
  reorder, foreign-key, and cross-writ substitution are rejected
  (tested). Registry rows: SQLite has no privilege separation → operator
  tampering is detectable via the audit chain, not preventable (G6).
- *Repudiation:* every decision carries embedded attribution (RFC-006);
  suppression-before-insertion is closed on the PEP path by
  deny-on-audit-failure (tested); other components' best effort noted.
- *Info disclosure:* the registry stores digests, names, and metadata —
  no prompts, no payloads, no secrets (D6 by DDL; seal store separate).
- *DoS:* issuance and PDP are O(small); no rate limiting in MVP (G3).
- *Elevation:* terminal lifecycle states enforced at the data layer
  (tested); illegal transitions fail below the API.

**Seal store (broker).**
- *Tampering/disclosure:* AES-256-GCM, per-entry nonce, name-bound AEAD
  (swap/tamper tested); values never in logs/audit/errors (tested).
  Key file 0600; KMS unseal is enterprise. No memory locking/zeroization
  in MVP (G7).
- *Spoofing:* no GET endpoint exists; injection only at spawn into the
  server env — the agent process tree never holds values (tested live).

**MCP proxy (PEP).**
- *Spoofing:* a malicious *server* can advertise misleading tool names;
  namespace pinning (`--server-name`) scopes the blast radius to
  resources the writ already granted for that namespace. Argument
  smuggling into an allowed tool is real and unmitigated in MVP (G4):
  the envelope-only parse that protects payload privacy also means we
  do not constrain arguments — v1 argument-schema constraints under the
  `hold` layer (RFC-004).
- *Tampering:* JSON-RPC id spoofing by the server (answering with a
  fabricated id matching a pending tools/list) could suppress filtering
  — filtering is UX, the call path is the boundary (tested), so the
  worst case is the model *seeing* a tool it still cannot call.
- *DoS:* 10 MB frame cap; malformed frames dropped with audit (tested);
  a flooding client floods its own session.
- *Elevation:* confused-deputy guard — the proxy evaluates the writ's
  authority, never its own; the decider closure holds no ambient caps.
- *Bypass:* an operator can point the agent at the raw server binary
  (trust boundary 2); an *agent* cannot — it holds no server command,
  no secrets, and no writ-free path.

**HTTP API.**
- *Spoofing:* 256-bit token, hashed at rest, constant-time compare,
  failures audited (tested); single all-powerful token is G2.
- *Info disclosure:* token never enters the audit stream (tested);
  serve binds localhost by default; TLS is fronted, not shipped (G5).

**JOSE layer (both token types).**
- Algorithm confusion: verifiers accept ECDSA only — `alg:none` and
  HS256-with-public-key-as-secret are rejected (tested, both token
  types). Keys: single ES256 issuer key in MVP; rotation runbook is a
  v1 deliverable (G8); compromise = re-key, TTLs bound exposure
  (RFC-001 §7, RFC-002 §7).

## 3. OWASP LLM Top 10 (2025) mapping

| # | Risk | Chancery's answer |
|---|------|-------------------|
| LLM01 | Prompt injection | Enforcement outside the model's blast radius: an injected agent still hits the PDP (RFC-005); secrets absent from context can't be exfiltrated (RFC-003) |
| LLM02 | Sensitive info disclosure | Metadata-only audit by DDL; sealed credentials; digests not prompts |
| LLM03 | Supply chain | Minimal dep tree; cosign-signed multi-arch releases + SBOM at launch (RFC-010, Conduit practice) |
| LLM04 | Data/model poisoning | Out of scope (we don't touch training); version digests at least pin *which* prompt/config acted |
| LLM05 | Improper output handling | Out of scope for content; structurally, agent output cannot mint authority (writs come only from the control plane) |
| LLM06 | **Excessive agency** | The product: writs, monotonic attenuation, allow-lists, approvals (v1), instant revocation |
| LLM07 | System prompt leakage | We never hold the prompt — hash only |
| LLM08 | Vector/embedding weaknesses | Out of scope |
| LLM09 | Misinformation | Out of scope |
| LLM10 | Unbounded consumption | Writ TTL/depth/count bounds; rate limiting G3 |

## 4. Abuse cases walked

- **Hijacked agent (prompt injection):** asks for `delete_everything` →
  PDP deny; asks to read its own env for tokens → nothing there; asks
  the server to misbehave within an allowed tool → G4, honest gap.
- **Compromised parent agent:** can only delegate ≤ its own authority
  (widening unrepresentable, tested); org revokes its block — subtree
  dies next action (tested live).
- **Stolen writ JWS:** useless at the broker without live registry
  state (revocation/path checks) and, in v1, without the paired
  instance document + PoP; off-path it names patterns, not secrets.
- **Malicious insider with the admin token:** full control-plane API,
  fully audited; cannot read sealed values over any endpoint; G2/G6
  bound what "audited" is worth against a *root* insider.
- **Compromised control plane host:** identity forgery yes; downstream
  credentials only if the seal key is co-located (deployment guidance:
  split them; enterprise: KMS).

## 5. The honest gap table (MVP ships with these, stated)

| # | Gap | Exposure | Owner / phase |
|---|-----|----------|---------------|
| G1 | Bearer identity documents (no PoP) | ≤5-min replay window | RFC-001/003 · v1 |
| G2 | Single admin API token | No operator scoping/blast-radius | RFC-008 · v1 (document-based auth) |
| G3 | No rate limiting | DoS on serve/PDP | v1 |
| G4 | Tool *arguments* unconstrained | Injection-driven misuse of allowed tools | RFC-004 L4 + schemas · v1 |
| G5 | No shipped TLS | Plaintext if operator exposes the bind | fronted TLS documented · MVP; native · v1 |
| G6 | Audit = detection, not prevention, vs. root | Root can rewrite chain from genesis | anchoring · v1; Postgres row security · v1 |
| G7 | No mlock/zeroization in broker | Secrets in swappable memory during injection | hardening backlog |
| G8 | No key-rotation runbook/automation | Slow recovery from issuer-key compromise | v1 |
| G9 | Declared attestation | Instance can lie about runtime | RFC-001 verifiers · v1 |

## 6. What this means for RFC-010

The MVP launch checklist inherits: gap table verbatim in SECURITY.md;
cosign signing + SBOM in the release pipeline; deployment guidance
(seal-key separation, localhost bind, fronted TLS); the adversarial test
suite (below) as a permanent CI gate.

## 7. Addendum A (2026-07-04): OWASP Top 10 for Agentic Applications (2026) mapping

The ASI list (ASI01-ASI10) supersedes the LLM Top 10 as the audit
checklist for agentic systems; the LLM mapping above stays for
continuity.

| # | Risk | Chancery's answer |
|---|------|-------------------|
| ASI01 | Agent goal hijack | Cannot prevent hijack of the model; bounds its blast radius — a hijacked agent still holds only its writ (RFC-002/005) |
| ASI02 | Tool misuse & exploitation | Core: per-call PDP, allow-lists, writ caps; argument-schema constraints are the G4 roadmap |
| ASI03 | **Identity & privilege abuse** | The product: governable identities (RFC-001), attenuating privilege (RFC-002), terminal revocation (RFC-007) |
| ASI04 | Agentic supply chain | Partial: server namespace pinning, cosign/SBOM releases (RFC-010); MCP-server provenance registry is roadmap |
| ASI05 | Unexpected code execution | The exec verb phase (RFC-005 sequence); today: shell tools simply aren't granted |
| ASI06 | Memory & context poisoning | **Out of scope, deliberately:** we govern actions, not cognition — poisoned memory's damage is realized through actions, and actions are what we bound. Stated as the scope line, not hidden |
| ASI07 | Insecure inter-agent communication | Writs + lineage are the authenticated delegation substrate; cross-org is the federation phase (RFC-000 Addendum A, Q6) |
| ASI08 | Cascading failures | Depth/TTL/caveat bounds contain delegation trees; subtree revocation is the circuit breaker (tested live) |
| ASI09 | Human-agent trust exploitation | Approvals (hold, RFC-004 L4, v1) put the human decision outside the agent's persuasion channel |
| ASI10 | Rogue agents | Registry + version digests detect drift-by-change; instant revocation + audit timeline are the response; behavioral anomaly detection is observability-phase, on top of our data |

MAESTRO (CSA) is adopted as the *process* reference for future per-RFC
threat walks (its layer model maps cleanly onto our components); this
document remains the product threat model of record.

## 8. Build consequence (this RFC's tests)

`internal/writ` and `internal/identity` gain an adversarial suite:
`alg:none` rejection (both token types), HS256 key-confusion rejection,
cross-writ block substitution, and the existing tamper/splice/foreign-
key cases referenced above become the named regression set for this
RFC. All CI-gated.
