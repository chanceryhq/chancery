# RFC-010: MVP Scope — the 90-Day Build

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-04
- **Depends on:** RFC-000 … RFC-009
- **Blocks:** launch

---

## 1. Problem

One founder, 90 days (started 2026-07-06), and a platform thesis that
could absorb 90 months. The failure mode is not building too little —
it is building evenly: six pillars at 40% each demos nothing. This RFC
draws the cutlines, locks the demo script word for word, and defines
"done" as observable events, not feelings. Per RFC-000: sequence the
10-year platform behind a 60-second demo that makes a platform engineer
say "I need this."

## 2. Existing approaches (to shipping) and why they fall short

**Ship the broad platform beta.** Every pillar shallow; the demo is a
tour, not a moment. Tours don't convert platform engineers.
**Ship a hosted SaaS waitlist first.** Contradicts the self-hosted
neutrality positioning (RFC-000 §4) and the buyer's trust model — an
identity system you can't inspect is a pitch, not a product.
**Ship a spec and evangelize.** Standards are won by running code
(charter law); a spec without a binary is a donation to incumbents with
more engineers.

## 3. Alternatives considered

**A. Wedge = SDK/framework integrations first** (meet developers in
LangGraph). Rejected as *first*: SDK enforcement is advisory (RFC-005
§3-A); leading with it teaches the market the wrong mental model.
**B. Wedge = the registry alone** ("Terraform state for agents").
Tempting and hollow: a registry without enforcement is an inventory
tool — the exact category we argue is replaceable (RFC-000 §3).
**C. (Chosen) Wedge = enforcement with the registry inside it** — the
`mcp wrap` moment, with the registry, writs, audit, and revocation
already behind it. The demo *is* the architecture.

## 4. Decision

**MVP = v0.1.0, tagged and public within the 90-day window, containing
exactly what is listed here. Everything else is named and cut.**

### Already built and tested (days 0–2 of 90 — series close)

Registry (three-layer identity, content-addressed versions), writs
(grant/delegate/check/revoke, tree registry), layered PDP + locked
grammar, sealed credential store, MCP stdio proxy with per-call
enforcement and spawn-env secret injection, hash-chained metadata-only
audit + `verify`, lifecycle state machines with terminal enforcement,
REST/JSON API + `serve`, adversarial JOSE suite, live integration test.

### Remaining scope (the next ~12 weeks, in order)

1. **CLI → service migration** (RFC-008 cleanup): one code path;
   integration tests move to the service layer. *(week 1)*
2. **`make demo`** — scripted, reproducible, <60s runtime (script
   locked in §5). *(week 1, ships with this RFC)*
3. **Packaging:** goreleaser — single static binaries (darwin/linux,
   arm64/amd64), Docker image, Homebrew tap; **cosign-signed + SBOM**
   (Conduit practice, ASI04). *(weeks 2–3)*
4. **Quickstart hardening:** `init → wrap` in under 5 minutes against a
   real MCP server (filesystem/github servers tested explicitly);
   README walkthrough recorded as an asciinema cast. *(weeks 2–4)*
5. **Integration examples:** Claude Code MCP config (wrap drop-in) and
   one LangGraph example repo. *(weeks 4–6)*
6. **Shadow-agent observation v0** (RFC-000 Addendum A, Q7): the wrap
   without a registered agent refuses to start — but `chancery serve`
   gains `mcp.unregistered_client` audit events when API calls
   reference unknown agents; full passive observation lands with the
   HTTP PEP (v1). Cheap now, coherent story. *(week 6)*
7. **Go SDK v0** (`chancery.Run` self-registration helper) — the
   ergonomics layer over the proxy, explicitly advisory (RFC-005 §3-A
   framing in its README). *(weeks 7–8)*
8. **Docs site** on GitHub Pages (chanceryhq.github.io — free) —
   quickstart, concepts (agent/version/instance/writ), RFC index,
   SECURITY.md. chancery.dev (~$12/yr, verified available 2026-07-04)
   is deferred until revenue by founder decision, accepting the
   squatting risk on a name that becomes public at launch; if bought
   later it aliases onto Pages with zero migration. *(weeks 8–10)*
9. **Design-partner motion:** 10 conversations from MCP/platform
   communities; 3 external users running `wrap` in a real workflow
   before tag. *(weeks 6–12, parallel)*
10. **v0.1.0 tag + launch** (Show HN, MCP community, r/selfhosted).
    *(week 12)*

### Cut from MVP (named, with the argument)

- **Web timeline UI** — *revises RFC-000's roadmap, explicitly.* The
  buyer persona lives in a terminal; `audit --json` + the API serve
  dashboards; a half-good UI weakens the demo and burns 2–3 weeks.
  First UI lands v1 with anomaly surfacing, where a UI earns its keep.
- **HTTP egress PEP, shell, browser** — v1 sequence per RFC-005.
- **PoP enforcement, attestation verifiers, rate limits, native TLS,
  key-rotation automation** — gap table items (RFC-009 G1–G9) with
  owners; SECURITY.md states them at launch.
- **Cedar (L3), approvals (L4)** — v1 per RFC-004.
- **Postgres** — v1 per RFC-008; SQLite is the 30-second story.
- **Python/TS SDKs** — after the Go SDK proves the shape.

## 5. The demo script (locked)

> *Setup (off-screen): `chancery init`; agent `deploy-bot` registered;
> writ granted for `call:github/*`; GitHub token sealed; Claude Code
> configured with `chancery mcp wrap … -- github-mcp-server`.*

1. **[0–15s]** Agent is mid-task: it lists issues, reads a PR —
   `tools/call` ALLOW events scroll in `chancery audit --follow`
   (follow flag ships with the script).
2. **[15–25s]** "Security just learned this agent's prompt was
   modified outside review." → `chancery agent revoke deploy-bot` —
   one command, terminal warning shown.
3. **[25–40s]** The agent tries its next tool call. **Blocked.** The
   model sees a clean JSON-RPC error naming the layer; no hang, no
   stack trace.
4. **[40–60s]** `chancery audit` — the timeline: ALLOW, ALLOW, revoke,
   DENY with `[registry] agent deploy-bot is revoked`, every row naming
   agent, version digest, instance, writ, lineage. Close:
   `chancery audit verify` → "chain intact." *"Which agent, which
   version, under whose authority, and it's evidence — not logs."*

Success criterion: a cold viewer can rerun it from the README in under
five minutes (`make demo` automates the whole arc against the fake
server; the live version uses a real one).

## 6. Trade-offs accepted

- Cutting the UI narrows the demo audience to terminal-native buyers —
  who are the wedge audience by thesis; accepted.
- Three external users is a low bar set deliberately: real workflows
  surface integration friction that ten more features would not.
- The SDK ships advisory-only and says so; the honest framing costs
  adoption among checkbox-seekers and buys trust with the audience
  that matters.

## 7. Failure scenarios

- **Slip:** the only protected scope is items 1–4 + 10 (the demo must
  ship signed and reproducible); 5–9 shed in reverse order.
- **MCP 2026-07-28 spec lands changes mid-window:** stdio framing is
  stable; auth changes affect the v1 HTTP PEP, not the MVP wrap.
  Tracked, not blocking.
- **A competitor ships "agent revocation" first:** the moat argument
  (in-path + record coupling) is the response, not speed alone; the
  demo's second act (delegation-tree revocation) is the differentiator
  nobody else has the writ model to copy quickly.

## 8. Security considerations

Launch inherits RFC-009 verbatim: SECURITY.md carries the gap table
G1–G9 with phases; cosign + SBOM on every artifact; the adversarial
suite is a CI gate; vulnerability reporting via GitHub private vulnerability reporting.

## 9. Build consequence

Ships with this RFC (today): `LICENSE` (Apache-2.0, per D2/RFC-011),
`SECURITY.md` (gap table + reporting), `Makefile` (`build/test/demo`),
`scripts/demo.sh` (the §5 arc, self-contained, CI-runnable). The rest
follows the week plan above.
