# RFC-011: Open-Core Boundary

- **Status:** Locked
- **Author:** Aneesh Gupta
- **Created:** 2026-07-04
- **Locked:** 2026-07-20
- **Depends on:** RFC-000 (D2), RFC-008, RFC-009, RFC-010
- **Blocks:** enterprise-phase work

---

## 1. Problem

RFC-000 D2 locked the model (Apache-2.0 core, proprietary enterprise
modules) and deferred the boundary. The boundary is a day-one
architectural concern because retrofits show: features built without a
seam get paywalled by surgery, communities notice, and trust — the only
distribution asset a solo founder has — dies. This RFC locks the test
for what goes where, the mechanics (repos, license, contributions,
tenancy), and the promises we make in public.

## 2. Existing approaches and why they fall short (or teach)

**HashiCorp.** A decade of MPL open core, then the 2023 BSL flip →
community fork (OpenTofu), Linux Foundation adoption of the fork, trust
damage outliving the license. Lesson: the flip is the sin; never take
the option. **GitLab.** The teachable success: buyer-based open core —
"who is the feature for?" (individual contributor → free; manager/org →
paid) — applied consistently for a decade with /ee code in the public
repo. Lesson: a *published test* beats a features list. **Elastic.**
SSPL flip → AWS forks OpenSearch → 2024 sheepish return to AGPL;
maximum damage, zero moat gained. **Sentry (FSL).** Honest about
non-compete goals, but source-available ≠ OSS and enterprises' legal
review knows it — friction exactly where our bottom-up motion lives.
**Grafana (AGPL core).** Works at scale, but AGPL is on enterprise
deny-lists; rejected in RFC-000 D2 already. **Cockroach (BUSL).**
Same lesson as HashiCorp, chosen earlier.

## 3. Alternatives considered

**A. Same-repo `/ee` directory (GitLab mechanics).** Discoverable,
one build, easy cross-review. Loses: proprietary code inside the OSS
repo muddies the "everything here is Apache-2.0" statement — the
single clearest trust sentence we can own; complicates CI, forks, and
vendor legal scans.
**B. All-OSS, sell hosting only.** Cleanest community story; wrong
buyer — our enterprise buyer *wants* self-hosted (the neutrality
thesis); selling only hosting concedes the self-hosted enterprise to
integrators.
**C. Source-available core (BSL/FSL).** Re-litigated and re-rejected:
the federation play needs a protocol nobody's counsel hesitates over
(RFC-000 D2).
**D. (Chosen) Two repos: this one 100 % Apache-2.0 forever;
`chancery-ee` private, importing the core as a Go module.**

## 4. Decision

**The boundary test (published, GitLab-style, adapted to our buyer):**

> A capability is **open source** if it makes a single trust domain
> secure and operable: identity, delegation, enforcement, revocation,
> audit integrity, and every security property. A capability is
> **enterprise** if its value exists only at organizational scale:
> many teams, many tenants, compliance attestation, fleet operations.

**Two hard promises, published in the README:**
1. **No license flip.** What ships Apache-2.0 stays Apache-2.0. The
   OSS repo contains no proprietary code, ever.
2. **Security is never paywalled.** Every RFC-009 gap (G1–G9) closes
   in OSS: PoP, rate limits, TLS, key rotation, attestation verifiers.
   An insecure free tier is not a funnel, it's a betrayal of the
   thesis.

**The ledger (locked assignments):**

| Open source (this repo) | Enterprise (`chancery-ee`) |
|---|---|
| Registry, versions, instances; writs & delegation; PDP incl. **Cedar L3** and **approvals L4**; all PEPs (MCP, HTTP, shell, browser); sealed store; audit chain + `verify` + NDJSON; lifecycle; REST API; CLI; SDKs; **Postgres**; document-based API auth; all G1–G9 closures | SSO/SAML/SCIM; org-wide RBAC & delegated admin; **multi-tenancy** (below); native SIEM exporters (Splunk/Sentinel/Chronicle); compliance packs (SOC2, HIPAA, Colorado reasonable-care, EU AI Act evidence); long-term retention tiers + **audit anchoring service**; HA control-plane orchestration (Postgres itself is OSS; automated failover/backup tooling is EE); KMS/HSM unseal + BYO-Vault backend; governance tiers / policy packs (Gartner proportional-governance packaging); priority support/SLA |

Judgment calls, argued: *Cedar and approvals are OSS* — they make one
trust domain secure (a solo platform engineer needs guardrails and
human-in-the-loop too); the *packaged governance tiers and compliance
mappings* on top are enterprise. *Anchoring:* the audit chain and local
verification are OSS (integrity is security); the managed cross-org
anchoring/witness service is enterprise (attestation at org scale).
*Postgres OSS* because self-hosting on real infrastructure is the core
promise; *HA orchestration* is enterprise because fleet operations are
the org-scale value.

**Tenancy seam (locked):** the OSS core stays **single trust domain**
— no `org_id` columns, no latent multi-tenant schema (complexity tax
on every OSS contributor for a feature they can't use). `chancery-ee`
is a multi-tenant **control plane of control planes**: it orchestrates
per-tenant OSS cores (cell architecture), owning tenant lifecycle,
cross-tenant RBAC, and aggregated audit. The seam is the RFC-008 API +
the Go module boundary — both already exist; EE is a consumer, not a
patch set.

**Contribution mechanics:** DCO, **no CLA.** Apache-2.0 inbound =
outbound; EE imports the module under the same license as everyone
else, so we never need relicensing rights over community code — and
"no CLA" is itself a trust signal the HashiCorp generation of
contributors reads fluently. Trademark ("Chancery", the seal) held by
the founder entity; forks may fork the code, not the name — standard
policy file at launch.

**Version discipline:** EE tracks OSS releases in lockstep
(same-day minor releases); EE never holds back an OSS fix.

## 5. Why

The bottom-up motion (RFC-000) requires that the artifact a platform
engineer evaluates is legally boring and completely functional — test
passed by construction: the OSS side of the ledger is a complete,
secure product for one trust domain. The enterprise side is exactly
what a CISO with many teams pays for and exactly what an individual
adopter never misses. And the two promises convert our biggest
structural weakness (solo founder vs. Cisco field teams) into the one
asset they cannot copy: believable permanence of the open core.

## 6. Trade-offs accepted

- **Cell-architecture multi-tenancy costs more EE engineering** than
  an `org_id` column. Accepted: it keeps the OSS schema honest and
  makes tenant isolation a *structural* claim in enterprise security
  reviews (better sales artifact, too).
- **No CLA forecloses future relicensing.** That is the point; the
  door is welded, not locked.
- **Two repos mean EE integration lag risk** — bounded by the
  lockstep-release rule and by EE consuming only the public API/module
  surface (dogfooding the stability promise of RFC-008).
- **Cedar/approvals in OSS gives away guardrail value** some vendors
  charge for. Accepted: guardrails drive installs; installs are the
  moat's raw material (system-of-record gravity).

## 7. Failure scenarios

- **A cloud vendor ships "Chancery-as-a-Service".** Apache-2.0 permits
  it; the record, the EE layer, trademark, and release velocity are
  the defense — and their managed offering validates the category
  (the Vault/cloud-KMS dynamic we chose eyes-open in D2).
- **EE feature turns out to be load-bearing for single-domain
  security** (misjudged boundary): the promise resolves the dispute —
  it moves to OSS. The test is the tiebreaker, published so the
  community can hold us to it.
- **Community submits an EE-ledger feature as an OSS PR** (the GitLab
  scenario): accept it into OSS if it passes the test as implemented;
  the ledger constrains *our* roadmap placement, not contributors'
  freedom — refusing good OSS code to protect EE revenue is the
  beginning of the HashiCorp path.
- **Acquirer pressure to flip the license:** the promise plus DCO
  (no relicensing rights over external contributions) makes a flip
  legally and practically expensive — deliberate poison pill.

## 8. Security considerations

The boundary itself is a security property: promise 2 means threat-
model gaps can never become upsell leverage, which keeps RFC-009's gap
table honest (no incentive to leave G-items open). EE's cell model
keeps tenant blast radii structurally separated. EE code sees the same
adversarial CI gates as core.

## 9. Build consequence

Today: `LICENSE` (Apache-2.0) at repo root; README gains the two
promises and the boundary test, one paragraph. At enterprise phase
(RFC-000 Phase 3): `chancery-ee` private repo scaffold, trademark
policy file, DCO check in CI. **This closes the RFC series 000–011;
the next artifact is code (RFC-010 week plan), and the next RFC (012,
federation) is earned by shipping, not written first.**
