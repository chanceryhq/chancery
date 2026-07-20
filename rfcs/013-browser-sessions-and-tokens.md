# RFC-013: Browser Sessions and Tokens as Governed Credentials

- **Status:** Locked
- **Author:** Aneesh Gupta
- **Created:** 2026-07-05
- **Locked:** 2026-07-20
- **Depends on:** RFC-001, RFC-002, RFC-003, RFC-004, RFC-005
- **Blocks:** —

## 1. Problem

A browser agent does not authenticate — it **inherits a human's
session**. Inside a logged-in profile it holds the cookies, OAuth
refresh tokens, and "remember me" state of every authenticated tab:
email, CRM, source control, banking. Three properties make this the
worst credential class in the agent world:

1. **Sessions are bearer and unscoped.** A cookie authorizes
   everything the account can do; there is no "read Gmail but don't
   send."
2. **Sessions are invisible to IAM.** The IdP saw one login, weeks
   ago, by a human. Every agent action since is indistinguishable from
   that human — question 2 (*who does it act for?*) is unanswerable
   server-side.
3. **Sessions cannot attenuate.** Browser-world delegation is "hand
   over the whole profile or nothing" — the exact opposite of the
   writ.

This is not hypothetical: 48% of security professionals name agentic
AI their top 2026 concern, and the March 2026 "PleaseFix" disclosures
(Zenity Labs) showed agentic browsers being hijacked to act inside
authenticated sessions and steal credentials.

## 2. Existing approaches and why they fall short

- **Secure enterprise browsers** (Palo Alto Prisma Browser, Island,
  LayerX): put controls *inside a proprietary browser*. Right layer,
  wrong coupling — protection exists only in their browser, tied to
  their cloud, with no delegation semantics and no per-agent identity.
  It is the browser-shaped version of the Entra pattern.
- **Playwright/Puppeteer MCP servers**: excellent execution layer
  (isolated contexts, `--storage-state` injection) but **no
  authority model**: whoever reaches the server navigates anywhere
  with whatever state was loaded.
- **OAuth token vaults** (Auth0 Token Vault, Arcade): govern API
  tokens for first-party integrations; cookies and browser sessions —
  the credentials agents actually inherit — are out of scope.
- **Do nothing**: the agent runs in the user's own profile. This is
  the current industry default and the incident category CISOs
  fear most.

## 3. Alternatives considered

1. **Build/fork a hardened agent browser.** Wrong product (RFC-000
   non-goals: no runtimes); unwinnable against Chromium's pace.
2. **Network-level egress proxy (MITM TLS).** Strong enforcement but
   operationally hostile (cert trust, pinning breakage) and blind to
   *which agent* is acting. Remains the v2 escalation path behind the
   same writs.
3. **(Chosen) Govern the browser at its control interfaces:** the
   session store and the navigation boundary. Sessions become sealed
   credentials the agent never holds; navigation becomes a
   writ-checked action via the `net` verb, enforced today at the MCP
   boundary where browser agents already operate, and at the CDP
   boundary in v1.

## 4. Decision

**A browser session is a credential (RFC-003 rules apply) and a
navigation is an action (RFC-004 rules apply).** Locked semantics:

1. **Session custody, not session access.** Browser storage state
   (cookies, localStorage) lives AEAD-sealed in the credential store
   like any secret. At enforcement time it is **materialized as a
   0600 file in a private run directory readable by the browser
   *server* process only** (`mcp wrap --secret-file NAME=sealed-name`;
   the path is exposed as env `NAME` and substituted for
   `chancery-file:NAME` in server args, e.g. Playwright MCP's
   `--isolated --storage-state=chancery-file:NAME`). The run dir is
   deleted when the session ends. The agent-side context never
   contains a cookie: prompt injection cannot exfiltrate what was
   never there.
2. **The `net` verb activates.** Reserved since RFC-004, it now has
   concrete semantics: resources are `<lowercased-host>/<path
   segments>` (`net:github.com/acme/*`, `net:mail.google.com/*`).
   Query strings, fragments, and userinfo are **never** part of the
   resource — payload-free by construction, like all audit material.
3. **The URL guard at the MCP boundary.** When a wrapped tool call
   carries a `url`/`uri` argument, the destination is additionally
   evaluated as `net:<host>/<path>` through the same PDP — per
   navigation, fresh registry state, audited (`mcp.net`), denied with
   the standard `-32001`. **Fail closed:** a URL the grammar cannot
   express (non-http scheme, userinfo smuggling, unparseable) is
   denied, not skipped.
4. **Granting `net` is the opt-in.** The guard auto-enables iff the
   writ's grant carries any `net` capability (or `--net-guard` forces
   it). Call-only writs behave exactly as before — no breaking change.
5. **A browser session is an Instance** (already structural: every
   wrap registers one). `chancery instance revoke` is the session
   kill switch — the next tool call, including any navigation, dies at
   the registry.
6. **Delegation composes.** A spawned worker (RFC-012) delegated
   `net:github.com/acme/*` gets a browser scoped to that subtree —
   attenuating session scope, which raw cookies cannot express.

## 5. Why

- The wedge story writes itself: *"your agent browses with your
  session; we make the session revocable, the navigation scoped, and
  the whole thing attributed."* Every question 1–5 gets a browser
  answer; no incumbent (secure browsers, token vaults, MCP execution
  layers) answers at the identity/authority layer.
- Zero new infrastructure for the MVP slice: the seal store, the PDP,
  the proxy, and the instance model already existed. The slice is
  custody + the URL guard — small code, real enforcement.

## 6. Trade-offs accepted

- **URL-argument coverage is heuristic in MVP**: only top-level
  `url`/`uri` string arguments are guarded. A browser server with a
  differently-named parameter bypasses the *net* check (the tool-level
  `call` check still binds). Accepted: the popular browser MCP servers
  (Playwright, Puppeteer, fetch) all use `url`; v1 adds per-server
  argument schemas (the G4 machinery). Tracked as gap G11.
- **In-page actions are not URL-shaped.** Once on an allowed page,
  click/type tools carry no URL; scoping *within* a page is argument-
  schema (G4) and CDP-PEP (v2) territory. The honest claim is
  "scoped navigation + custodied sessions," not "DOM-level policy."
- **Session acquisition is manual in MVP**: a human logs in once and
  exports storage state (`playwright codegen --save-storage`), then
  seals it. Refresh/rotation automation is v1.
- **Host patterns, not eTLD+1 intelligence**: `net:github.com/*` does
  not match `gist.github.com` (different host) — correct for
  security, occasionally surprising; documented.

## 7. Failure scenarios

- **Prompt-injected agent tries to exfiltrate the session**: it can't
  read the file (server-side, private run dir) and can't navigate the
  session anywhere outside the net grant; the attempt is an audited
  DENY.
- **Compromised/malicious browser server**: it holds the session (it
  must — it drives the browser) and could misuse it *within allowed
  navigations*. Same trust position as RFC-003 env injection; the
  writ + guard bound the blast radius; server provenance is the
  operator's supply-chain duty (RFC-009).
- **Crash before cleanup**: the run dir may linger until OS temp
  cleanup. Bounded exposure (0600, same user); v1 adds startup
  sweeping of stale run dirs.
- **Redirects**: the guard checks the *requested* URL; a server-side
  redirect to another host lands outside the check in MVP (the next
  explicit navigation is checked again). CDP-level enforcement (v2)
  closes this; listed under G11.

## 8. Security considerations

Maps to RFC-009: ASI03 (privilege compromise — sessions no longer
sit in agent context), ASI06 (memory/context poisoning cannot reach
credentials), ASI07 (rogue agent's browser dies with its instance).
New gap **G11** (partial URL-guard coverage: argument-name heuristic,
redirect blindness) — tracked in the gap table, closes with argument
schemas (v1) and the CDP PEP (v2). The guard's fail-closed rule is
load-bearing: treat any bypass-by-confusion as a security bug
(SECURITY.md reporting).

## 9. What gets built

**This RFC (shipped with it):**
- `Proxy.NetDecide` + `URLToResource` (strict, fail-closed) + per-
  navigation `mcp.net` audit events in `internal/mcp`.
- `service.GrantsVerb` (auto-enable rule).
- `mcp wrap`: `--secret-file NAME=sealed-name` (0600 private run dir,
  env + `chancery-file:NAME` arg substitution, cleanup on exit) and
  `--net-guard`.
- `examples/browser-agent/`: the governed Playwright MCP recipe.
- Tests: `URLToResource` table (scheme/userinfo/case/query), guard
  allow/deny/fail-closed/absent, guard-off compatibility, GrantsVerb,
  and a full e2e (real wrapped process: session file delivered
  server-side, navigation allowed/denied, audit without query
  strings).

**v1:** per-server argument schemas (G4/G11), session
refresh/rotation, stale run-dir sweeping, PoP.
**v2:** CDP-native PEP — Chancery owns the browser context: cookie
injection without any file, per-request (not per-navigation)
enforcement, redirect coverage.
