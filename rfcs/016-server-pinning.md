# RFC-016: Server Pinning (Callee Trust, Phase 1)

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-16
- **Depends on:** RFC-005, RFC-006
- **Blocks:** —

## 1. Problem

Chancery scopes the **caller**: the agent's authority is a signed,
narrowing, revocable grant, checked per call. The **callee** — the MCP
server — gets none of that discipline. A server vetted at grant time
can be swapped an hour later (binary replaced, npm package updated to
a poisoned version) and every call still validates cleanly, because
every check is about who is calling, not what is answering.

Permission is about the caller; risk is about the callee. This is the
software supply-chain problem wearing MCP clothes: an MCP server is
unsigned code you launch on your own machine and hand scoped authority
to.

## 2. Existing approaches and why they fall short

- **OS package managers / lockfiles** pin at install time but nothing
  re-verifies at *launch* time — the moment that matters.
- **Sigstore/provenance** verifies publisher identity at download;
  same gap: no launch-time check, and most MCP servers ship unsigned.
- **Container image digests** are the strongest full-tree pin, but
  nothing today records "namespace X must be digest Y" and refuses
  drift — the digest is only as good as the human retyping it.

## 3. Alternatives considered

1. **Deny-list known-bad hashes.** Backwards: the set of bad servers
   is unbounded; the set of vetted ones is small and known.
2. **Verify on a schedule (scanner).** Off-path: the swap wins the
   race between scan and launch. Chancery's whole thesis is in-path.
3. **Pin at wrap, refuse on drift (chosen).** `mcp wrap` already owns
   the spawn — it is the only component structurally positioned to
   verify what it is about to launch, unilaterally.

## 4. Decision

- **First wrap pins:** the server command is resolved on PATH
  (symlinks followed) and its SHA-256 recorded against the
  `--server-name` namespace (`mcp.server_pin` audited).
- **Every later wrap re-verifies before spawning.** Hash mismatch →
  refuse to start, fail closed, audit `mcp.server_drift` with expected
  and found hashes.
- **Deliberate upgrades are explicit:** `chancery mcp repin <ns> --
  <cmd>` re-hashes and updates the pin, audited as `mcp.server_repin`
  with old→new. Pins are operator-owned, like allow-lists.

This is **T1 of three tiers**. T2 (Chancery-managed frozen installs,
whole-tree hashes) and T3 (container image digests + manifest-bounded
runtime confinement: egress allow-lists, read-only FS) are specified in
the tracking issue and deferred — they change the operational model and
deserve their own RFC when a consumer exists.

## 5. Why

Launch-time verification at the component that launches is the only
unilateral slice of callee trust: no cooperation from servers,
registries, or packagers required, and the failure mode is the right
one (refuse + audit, never silently proceed).

## 6. Trade-offs accepted

- **T1 is honest but shallow for interpreter launchers.** Hashing
  `npx` pins the launcher binary, not the package tree behind it — a
  poisoned transitive dependency walks straight through. The docs say
  this loudly; full-tree coverage is T2/T3.
- Auto-pin on first wrap trusts first use (TOFU). The alternative —
  mandatory explicit pinning — adds a step to every quickstart for
  protection most users would skip entirely.
- A moved-but-identical binary re-pins nothing: the pin is
  content-addressed, not path-addressed; the path is recorded for
  operator context only.

## 7. Failure scenarios

- **Binary swapped:** next wrap refuses; `mcp.server_drift` names both
  hashes. Recovery is `repin` after human review.
- **Legitimate upgrade forgotten:** same refusal — deliberately. The
  error message names the exact repin command.
- **Pin store tampered:** pins live in the same SQLite store as the
  registry; RFC-009's storage-trust boundary applies unchanged. Pin
  *changes* are visible in the hash-chained audit trail.

## 8. Security considerations

Drift refusal happens before instance creation and before any secret
is unsealed — a drifted server never sees a credential. The drift
audit event carries hashes and path only, never arguments or content.

## 9. What gets built (MVP, this RFC)

- `server_pins` table; `GetServerPin`/`SetServerPin`.
- Pin/verify/refuse logic in `mcp wrap`; `chancery mcp repin`.
- Audit events `mcp.server_pin`, `mcp.server_drift`,
  `mcp.server_repin`.
- Integration test: pin on first wrap → swap binary → wrap refuses +
  audits → repin → wrap starts.
