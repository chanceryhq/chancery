# RFC-NNN: Title

- **Status:** Draft | In Review | Locked | Superseded by RFC-NNN
- **Author:** Aneesh Gupta
- **Created:** YYYY-MM-DD
- **Locked:** YYYY-MM-DD (only when Status: Locked)
- **Depends on:** RFC-NNN, RFC-NNN
- **Blocks:** RFC-NNN

<!--
Rules for every RFC in this series:
1. One locked decision at a time. An RFC that decides nothing is deleted.
2. Every claim about the market or a competitor is dated and sourced.
3. Every design decision traces to one of the five defining questions (RFC-000 §3).
4. Payloads/prompts are never stored — if a design requires storing them, the design is wrong.
5. The RFC ends with what gets built. No artifact without a build consequence.
-->

## 1. Problem

What breaks today, for whom, and why now. Concrete failure, not abstraction.

## 2. Existing approaches and why they fall short

Per-topic competitor/prior-art fold-in (Okta/Entra, SPIFFE/SPIRE, Vault,
OAuth/OIDC/XAA, Zanzibar/Cedar/OPA, Biscuit/Macaroons, Astrix, Aembit,
Arcade, Composio, agentgateway — whichever apply). What each gets right,
where each stops, and why that gap is structural rather than a missing feature.

## 3. Alternatives considered (minimum three)

For each: design sketch, what it optimizes, why it loses. Include the
"do nothing / use existing tool" alternative honestly.

## 4. Decision

The single locked decision, stated in one paragraph, then elaborated.

## 5. Why

The argument. Trace to the five defining questions.

## 6. Trade-offs accepted

What this decision makes worse, and why that is acceptable.

## 7. Failure scenarios

How this design fails: partial outage, clock skew, key compromise, malicious
agent, malicious operator, network partition. What the blast radius is and
what the recovery path is.

## 8. Security considerations

Threats introduced or mitigated. Reference RFC-009 (threat model) categories
once it exists.

## 9. MVP impact

What this decision means for the 90-day build: what gets built, what gets
stubbed, what gets explicitly deferred and behind which interface.
