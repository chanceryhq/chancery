# RFC-004: Policy and Authorization

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-04
- **Depends on:** RFC-001, RFC-002
- **Blocks:** RFC-005

---

## 1. Problem

The writ (RFC-002) answers "what authority was *delegated* to this
agent." It cannot answer two other questions an org must be able to
enforce (defining questions 1 and 3):

1. **Org-wide guardrails independent of any grant:** "no agent touches
   `prod-db/*` outside business hours," "every `github/merge_*` requires
   human approval," "this tool is banned org-wide." A writ is minted per
   task by someone who *has* the authority; guardrails must bind even
   the people minting writs.
2. **A precise capability grammar:** RFC-002 locked the algebra
   (intersection) but used a placeholder pattern language. Two
   implementations disagreeing on whether `github/get*` matches
   `github/getrepo` is a security bug, not a style issue.

## 2. Existing approaches and why they fall short

**OPA/Rego.** The CNCF default; enormous ecosystem. Falls short as our
embedded engine: Rego is a general-purpose query language whose
evaluation model (unification, partial evaluation) is powerful and
famously hard to reason about; policies can express anything, including
non-terminating surprises; and its shape is document-oriented, not
principal/action/resource. Great as an *integration target* (enterprises
with OPA estates), wrong as the core.

**Cedar (AWS, open-sourced).** Purpose-built authorization language:
`permit(principal, action, resource) when {…}`, formally verified
semantics, decidable analysis (can statically answer "can any principal
ever do X?"), a maintained Go implementation (cedar-go). Its
principal/action/resource shape maps one-to-one onto our tuple. The
right v1 engine.

**Zanzibar / SpiceDB / OpenFGA.** Relationship-based access control —
"user U is editor of doc D." Excellent for data-sharing graphs; the
wrong shape for action guardrails over tool calls with conditions.
Later, resource-level relationships may compose (v2), not core.

**XACML.** The cautionary tale: committee-designed XML PDP that
enterprises deployed and developers never adopted. Its lasting
contribution is vocabulary (PDP/PEP/PIP), which we keep.

**Allow-lists in gateways (agentgateway, Envoy AI GW: CEL filters).**
Right primitive, no principal model: rules bind to routes/headers, not
to registered identities with versions and writs. CEL itself is a fine
condition language but arrives attached to proxy config, not to an org
registry.

## 3. Alternatives considered

**A. Writ-only (no org policy layer).** Simplest; guardrails are then
only conventions on who mints writs. Fails requirement 1 outright —
rejected, but its discipline is kept: the writ remains the *only* source
of positive authority.

**B. Embed OPA/Rego now.** Maximum flexibility, ecosystem checkbox.
Rejected for the core: unbounded policy language = unbounded support
surface and unanalyzable policies; 40+ MB dependency; wrong shape.

**C. Invent a policy DSL.** Total control, zero ecosystem, and we'd
spend our credibility asking security teams to trust a language no one
has verified. Rejected — we already spend our novelty budget on the writ.

**D. (Chosen) Layered PDP: writ ∧ allow-list now; Cedar as the org
layer in v1.** Details below. Cost: two engines over time (our
matcher + Cedar). Contained by the decision that layers only *deny*.

## 4. Decision

**Authorization is a conjunction of independent layers, evaluated at the
enforcement point per action. Layer 1 grants; every other layer can only
deny. Default-deny throughout.**

```
decision = writ.Check(action)            L1: delegated authority (RFC-002)
         ∧ allowlist.Check(agent,action) L2: per-agent tool allow-list (MVP)
         ∧ orgpolicy.Check(tuple,action) L3: org guardrails — Cedar (v1)
         ∧ approval.Check(action)        L4: human-in-the-loop holds (v1)
```

- **Only the writ grants.** L2–L4 are subtractive filters; removing them
  never widens beyond the writ; misconfiguring them fails closed. This
  preserves RFC-002's core property globally: no path to authority that
  does not pass through a signed, lineage-bearing grant.
- **L2 (MVP): per-agent tool allow-lists** in the registry. Empty list =
  no additional restriction (the writ still binds). Non-empty = the tool
  must match a pattern. This is the "scoped MCP proxy with per-agent
  tool allow-lists" of the wedge, and it gives platform engineers a
  guardrail *today* without a policy language.
- **L3 (v1): Cedar** via cedar-go, principals/resources drawn from the
  registry (`Chancery::Agent::"deploy-bot"`), actions from the verb set.
  Chosen for verified semantics, decidable analysis, native
  principal/action/resource shape, small embed. OPA integration remains
  possible *behind* the PDP interface for enterprises that mandate it.
- **L4 (v1): approvals** — a policy outcome of `hold` parks the action
  for human approval (EU AI Act human-oversight evidence; Colorado
  reasonable-care artifact). MVP has no async machinery; the enum is
  reserved now: decisions are `allow | deny | hold`.

**The capability grammar (locked, closing RFC-002's placeholder):**

- Verbs: lowercase token from a small registry — `call` (tool/API
  invocation, MVP), `read`, `write`, `exec`, `net` (reserved for HTTP/
  shell/browser runtimes, RFC-005). `*` matches any verb.
  *Amended 2026-07-05 by RFC-012:* `admin` joins the registry for
  writ-governed control-plane self-service (`admin:spawn/<template>`);
  the grammar is otherwise unchanged.
- Resources: `/`-separated segments, lowercase `[a-z0-9_.-]+`;
  hierarchical, e.g. `github/repos/acme/create_issue`.
- Patterns: a literal resource, or a prefix ending in `*` where `*` is
  only valid as the final character and only matches (a) at a segment
  boundary or (b) as a suffix within the final segment —
  `github/*` matches `github/get_repo`; `github/get_*` matches
  `github/get_repo`; `github/get*` also matches `github/getrepo`
  (documented, discouraged). `*` alone matches everything. No mid-pattern
  wildcards, no regex — patterns must be auditable at a glance.
- Matching is pure string prefix comparison after validation —
  no normalization surprises; invalid patterns are rejected at *write*
  time (grant, delegate, allow-list set), never silently at check time.

## 5. Why

Question 1: the org can state what agents may do in two artifacts — the
writs (who granted what to whom, narrowing) and the org policy (global
bounds) — both queryable, both auditable. Question 3: the same PDP
serves every runtime RFC-005 adds; shell and browser enforcement are new
PEPs, not new authorization models. The grants-vs-denies split keeps the
trust story provable: auditors verify one grant path (writs) and any
number of deny filters.

## 6. Trade-offs accepted

- **Two pattern-matching engines over time** (our grammar in writs/
  allow-lists; Cedar conditions in L3). Accepted: the writ grammar must
  live inside signed tokens and be implementable in every SDK; Cedar
  must not be a token-format dependency (RFC-002 §3 argument).
- **No conditions (time-of-day, IP) until Cedar lands.** MVP guardrails
  are structural only. Accepted; the enum and PDP interface are shaped
  for it now.
- **`hold` reserved but non-functional in MVP** — honest gap, listed in
  RFC-010's cutlines.
- **Allow-lists are per-agent, not per-version.** Version pinning of
  tools arrives with the tool-manifest hash comparison (v1); MVP keeps
  the operator surface small.

## 7. Failure scenarios

- **Conflicting layers:** impossible by construction — layers don't
  merge, they conjoin; there is no combining algorithm to get wrong
  (XACML's `deny-overrides` bug class eliminated).
- **Empty allow-list misread as deny-all:** semantics locked as
  "no additional restriction"; the deny-all is an explicit sentinel
  pattern (`!none`) rather than an ambiguous empty state.
- **Invalid pattern reaches the store** (bug path): check-time validation
  re-runs and fails closed with a distinct audit reason.
- **Cedar outage/parse failure (v1):** L3 unavailable ⇒ deny (fail
  closed), with an operator alarm — org guardrails being down must never
  widen access.
- **Clock-dependent conditions (v1)** evaluate on broker clock, same
  ±60s discipline as RFC-001/002.

## 8. Security considerations

The PDP runs in the broker process (RFC-005): no network hop to lose,
no bypassable sidecar. Pattern grammar is deliberately non-Turing
(no regex, no recursion) — policy evaluation cost is O(patterns), so a
malicious writ cannot DoS the PDP. Approval flows (v1) must
re-verify the writ at approval time, not at request time (TOCTOU).
Full treatment in RFC-009.

## 9. MVP impact

- `internal/policy`: the grammar (validation + matching, shared by writ
  caveats and allow-lists), the PDP (`Decide(...) Decision` conjoining
  L1+L2), decision enum with `hold` reserved.
- RFC-002's `writ.Cap` matching delegates to this grammar (one
  implementation, one truth).
- Registry: `tool_allowlists` table + `chancery agent allow <name>
  --tool <pattern>...` CLI; empty = unrestricted, `!none` = deny-all.
- Every decision audited with the deciding layer in the reason.
- Stubbed: Cedar (L3) behind the PDP interface, approvals (L4), pattern
  conditions.
