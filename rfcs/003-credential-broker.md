# RFC-003: Credential Broker

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-04
- **Depends on:** RFC-001, RFC-002
- **Blocks:** RFC-005, RFC-008

---

## 1. Problem

Agents hold real secrets. A `GITHUB_TOKEN` in the environment is readable
by the model (context leakage, prompt injection exfiltration), by every
library in the process, and by every log line that dumps env. Rotation
means redeploying every agent that embeds the credential; revocation means
finding them first. And a shared secret is exactly what destroys
attribution (question 5): the downstream log names the token, not the
agent. Question 1 — issued, scoped, rotated, revoked, with visibility —
has no answer while the agent itself is the credential store.

## 2. Existing approaches and why they fall short

**Vault (HashiCorp).** Superb sealed storage and dynamic secrets — but its
contract ends at *handing the secret to the workload*. After `vault read`,
the agent holds the credential and every failure above resumes. Dynamic
secrets (per-lease DB creds) are the right instinct, scoped to workloads
and TTLs, not to agent identity/version/writ. Vault is a fine *back-end*
for us (v1 `BYO-Vault` storage), not the broker.

**Cloud STS (AWS AssumeRole, GCP STS).** The pattern to copy — short-lived,
scoped, auditable credentials issued per assumption — but cloud-scoped:
nothing brokers GitHub, Slack, Snowflake, or an internal API. We federate
*into* STS (v1) rather than replicate it.

**Arcade / Composio / Auth0 Token Vault.** Builder-side token vaults: hold
end-users' OAuth tokens so the developer's agent can call Gmail/Slack.
Right mechanics, wrong principal and wrong customer: tokens are keyed to
the *human user* of the app, not to a registered agent identity with a
writ; there is no org registry behind it, and the org operating the agent
gets no record.

**Aembit.** The closest architecture: policy-driven workload credential
injection, no secrets in workloads. Falls short for agents the same way
SPIFFE does for identity (RFC-001): the principal is a workload — no
agent version, no delegated authority, no lineage. Also sales-led,
closed, cloud-managed.

## 3. Alternatives considered

**A. Agents fetch from a secrets manager directly.** (Status quo plus
Vault.) Simple; preserves every problem: agent holds the secret, rotation
touches agents, attribution dies at the shared credential.

**B. Sidecar-per-agent injection.** A local proxy per agent instance
holds its credentials. Isolates secrets from the model, but multiplies
operational surface (one sidecar per instance), and the sidecar still
holds long-lived secrets at the edge — N copies of the crown jewels.

**C. In-path broker at the enforcement point (chosen).** The component
that already mediates the action (RFC-005's proxy) injects the credential
into the *downstream* leg only. The agent's context never contains the
secret; there is exactly one sealed store; injection is per-action and
therefore per-writ-check.

**D. Per-service credential proxies.** A dedicated proxy per downstream
(GitHub-proxy, Slack-proxy). Cleanest isolation, unbounded build surface.
This is what integration breadth becomes *eventually* (adapters), not a
day-one architecture.

## 4. Decision

**Agents never hold real secrets. Downstream credentials live in one
sealed store owned by the control plane and are injected by the data
plane at the enforcement point, per action, only after the writ and
policy checks pass. The agent's execution context — env, prompt, tool
results — never contains a real credential.**

- **Sealed store:** AES-256-GCM, random 96-bit nonce per entry, key in a
  0600 file beside the registry in MVP (`seal.key`); KMS/HSM unsealing is
  the enterprise path (RFC-011). Entries are `(name, kind, ciphertext)`;
  names and kinds are metadata, values exist in plaintext only in broker
  memory during injection.
- **Credential classes,** sequenced: `static` secret (MVP) → OAuth2
  client-credentials + refresh (v1) → cloud STS federation (v1) → mTLS
  client certs (v2). The class determines injection mechanics, not the
  trust model.
- **Injection points** (mechanics per runtime in RFC-005): for stdio MCP
  servers, the proxy spawns the server process and injects secrets into
  the **server's** environment — the agent talks to the proxy, the proxy
  owns the process boundary; for HTTP egress (v1), header/body template
  injection on the downstream leg.
- **Rotation = one write.** `chancery secret put` re-seals; the next
  injection uses the new value. Zero agent redeploys, zero agent
  knowledge.
- **Attribution coupling:** an injection happens only inside a brokered
  action, so every credential use is already attributed to (agent,
  version, instance, writ) in the audit stream — the audit event records
  the credential *name*, never the value (D6).

## 5. Why

Question 1 becomes answerable end-to-end: issuance is `secret put` +
writ grant; scoping is the writ ∩ policy at the moment of injection;
rotation is a re-seal; revocation is writ/agent revocation (the
credential itself never travels). Question 5: the downstream sees a
credential the org controls at one point, and our audit binds every use
to a specific agent tuple. And structurally: prompt injection cannot
exfiltrate what the context never contained.

## 6. Trade-offs accepted

- **The broker is a high-value target** — one store holds the org's
  downstream credentials. Accepted: that store exists today as a wiki
  page and a hundred env files; centralizing it is the precondition for
  sealing, rotation, and audit. Mitigations in §8.
- **File-based seal key in MVP** is only as strong as filesystem
  permissions. Accepted for the 30-second install; KMS unseal is
  enterprise, and the key never leaves the data dir.
- **Static secrets first** — no dynamic minting in MVP, so blast radius
  of a downstream credential is its native scope, not per-action.
  Accepted; per-action minting arrives with OAuth/STS classes in v1.
- **Registry compromise ≠ credential compromise** (RFC-001 §8) is
  preserved: seal key and registry are separable artifacts; enterprise
  deployments split them.

## 7. Failure scenarios

- **Seal key lost:** credentials unrecoverable — re-add from upstream
  sources; identities, writs, audit unaffected. Backup guidance in the
  launch checklist (RFC-010).
- **Seal key stolen (with store):** downstream credentials exposed;
  identities/writs remain sound. Response: rotate downstream credentials
  (one `secret put` each), rotate seal key (`re-seal all`), audit stream
  shows every legitimate use for diffing.
- **Broker process compromise:** worst case — in-memory plaintext during
  injection. Bounded by minimal dependency surface (single Go binary),
  no plaintext persistence, and per-action injection (no long-lived
  decrypted cache).
- **Store corruption:** per-entry AEAD means one corrupt entry fails
  closed with a distinct error; others unaffected.
- **Missing secret at injection time:** the action fails closed with
  `secret not found: <name>` in the audit reason — never a silent
  passthrough of the agent's own env.

## 8. Security considerations

AEAD (AES-256-GCM) with per-entry nonces; key file 0600 in a 0700 dir;
values never logged, never in audit, never in error messages (names
only); no `secret get` CLI that prints values by default (explicit
`--reveal` with an audit event, for break-glass); constant-time
comparisons where tokens are checked. RFC-009 items: memory locking
(mlock) and zeroization are recorded as hardening TODOs, not MVP claims.

## 9. MVP impact

- `internal/seal`: AEAD store (`Put/Get/List/Delete`), key
  load-or-create; list returns names/kinds only.
- CLI: `chancery secret put|list|rm` (+ `--reveal` on a future `get`,
  deferred).
- RFC-005's `mcp wrap` gains `--secret NAME=ENV_VAR` spawn-env injection.
- Audit events: `secret.put`, `secret.rm`, and injection recorded inside
  `action.*` events by credential name.
- Stubbed: OAuth/STS/mTLS classes, KMS unseal, re-seal-all rotation
  command, Vault back-end.
