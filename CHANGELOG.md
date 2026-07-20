# Changelog

All notable changes to Chancery. Versions follow semver; while at
`0.x`, breaking changes to the CLI or REST surface may land in a minor
release and are always called out here.

## v0.2.0 — 2026-07-20

**Beta.** Every design RFC is locked and implemented. This release
completes the callee-trust half of the gate — Chancery now verifies
what an agent is *calling*, not only what it is *allowed* to call.

### Added

- **Server pinning** ([RFC-016](rfcs/016-server-pinning.md)) — the
  first `mcp wrap` records a server's code identity and every later
  wrap refuses on drift. Three tiers, strongest wins: container image
  digest (`image@sha256:…`), whole install tree (`--pin-tree`), or the
  binary hash. `chancery mcp repin` is the deliberate, audited upgrade
  path.
- **Frozen installs and confinement**
  ([RFC-018](rfcs/018-frozen-installs-and-confinement.md)) —
  `chancery mcp install <pkg>@<exact-version>` replaces `npx` with a
  one-time, scripts-disabled, automatically tree-pinned install;
  mutable specs are refused. `mcp wrap --confine` turns the pin's
  manifest (`--egress` hosts, `--writable` paths) into an OS boundary:
  a loopback-only egress allow-list proxy plus a read-only filesystem
  outside the manifest. Where the sandbox layer is unavailable the
  spawn is refused, never silently unconfined.
- **Task-bound grants and the intent socket**
  ([RFC-017](rfcs/017-intent-socket.md)) — `writ grant --task` records
  a grant's purpose; `mcp wrap --intent-check <cmd-or-url>` gives an
  external detector a per-call vote. Veto-only, fail-closed in
  `enforce`, log-only in `advise`, arguments never stored.
- **Capability leases**
  ([RFC-015](rfcs/015-call-lifecycle-and-leases.md)) — `--lease`
  stamps each admitted call with a 30-second signed lease a
  cooperating server verifies (`POST /v1/leases/verify`) right before
  committing, so a revocation landing mid-flight fails at the server.
  The trail records `mcp.call_result`: admitted and committed are
  different facts.
- **Audit cross-references** (RFC-015 §10) — `/v1/leases/verify`
  accepts an optional `xref` (`<system>:<opaque-id>`), recorded as
  `mcp.call_xref`, so a tool with its own audit chain can be walked in
  either direction from Chancery's. Opaque by design; metadata-only
  stands.
- **`mcp wrap --dry-run`** — preflights effective authority, pin
  status, and manifest without spawning or pinning anything.
- **`writ example`** and a `TTL LEFT` column on `writ list` — CLI
  ergonomics from the first outside integrator.
- **Read-only dashboard** at `/ui`
  ([RFC-014](rfcs/014-read-only-dashboard.md)) — live audit timeline
  with a permanent integrity badge, agent roster with spawn
  provenance, and the delegation tree. Writes stay in the CLI/API.
- **Browser agents** ([RFC-013](rfcs/013-browser-sessions-and-tokens.md))
  — sealed, custodied sessions delivered to the browser *server* only,
  plus per-URL navigation scoping via `net:` capabilities.
- **Perseus Vault example** (`examples/perseus-vault/`) — provable
  authority composed with provable content.

### Changed

- All 19 RFCs moved from *In Review* to **Locked**.
- `VerifyLease` returns full lease claims (`LeaseInfo`) rather than
  just the resource.
- A tree pin now follows its namespace: plain wraps re-verify it
  without `--pin-tree`, so the tier can never silently degrade.
- Threat-model gap table: **G13 narrowed** (the guided default now
  exists), **G14–G16 added** (lease cooperation, checker sees
  arguments, host-granular confinement).

### Fixed

- Homebrew cask installs no longer break under Gatekeeper
  (quarantine attribute stripped in a post-install hook).

## v0.1.0 — 2026-07-13

Initial public release: three-layer identity (RFC-001), writs and
attenuating delegation (RFC-002), sealed credential broker (RFC-003),
layered policy (RFC-004), in-path MCP enforcement (RFC-005),
hash-chained metadata-only audit (RFC-006), lifecycle and revocation
(RFC-007), REST/JSON control plane (RFC-008), published threat model
(RFC-009), and writ-gated runtime spawn (RFC-012). Cosign-signed
binaries, SBOM, Homebrew tap, and a container image.
