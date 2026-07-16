# RFC-016: Server Pinning (Callee Trust)

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

A pin is a **(kind, identity)** pair per `--server-name` namespace,
recorded at first wrap (`mcp.server_pin` audited), re-verified **before
every spawn**, refused on any mismatch (fail closed,
`mcp.server_drift` with expected and found identities), and changed
only by `chancery mcp repin <ns> -- <cmd>` — explicit, operator-owned,
audited as `mcp.server_repin` with old→new.

Three kinds; the strongest applicable wins automatically:

| Tier | Kind | Identity | When |
|---|---|---|---|
| T3 | `digest` | the container image digest in the server args (`image@sha256:…`) | auto-detected: a digest-pinned image reference is already a full-filesystem content address; Chancery makes it a refusal boundary instead of a convention. Mutable tags (`:latest`) are NOT identities. |
| T2 | `tree` | Merkle hash of a whole directory (`--pin-tree <dir>`): every file's relative path, executability, and content hash | the operator points at the server's install dir — closes the transitive-dependency hole for `npx`/`uvx`-style servers |
| T1 | `binary` | SHA-256 of the resolved executable (symlinks followed) | default when neither of the above applies |

A kind change (e.g. a binary-pinned namespace suddenly launched from a
container) is drift too — identity includes how it was measured.

## 5. Why

Launch-time verification at the component that launches is the only
unilateral slice of callee trust: no cooperation from servers,
registries, or packagers required, and the failure mode is the right
one (refuse + audit, never silently proceed).

## 6. Trade-offs accepted

- **The default (T1) is honest but shallow for interpreter
  launchers.** Hashing `npx` pins the launcher binary, not the package
  tree behind it — a poisoned transitive dependency walks straight
  through unless the operator opts into `--pin-tree` or launches by
  image digest. The gap stays documented (G13) because it is the
  *default's* gap, not the feature's.
- T2 re-hashes the whole tree at every wrap start — a
  `node_modules`-sized dir costs a moment at spawn time. Deliberate:
  spawn is rare, drift is expensive.
- T3 trusts the container runtime's digest enforcement and the image
  registry's content-addressing; Chancery verifies the *reference*,
  the runtime verifies the bytes.
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

- `server_pins` table (namespace, kind, path, sha256);
  `GetServerPin`/`SetServerPin`.
- Tiered identity resolution (digest > tree > binary); pin/verify/
  refuse logic in `mcp wrap`; `--pin-tree` on wrap and repin;
  `chancery mcp repin`.
- Audit events `mcp.server_pin`, `mcp.server_drift`,
  `mcp.server_repin` (all carrying `kind:hash…`).
- Tests: digest extraction (mutable tags rejected); tree hash detects
  content change / added file / executability flip in nested deps;
  tier precedence; integration — binary swap refused + repin; poisoned
  `node_modules` file (invisible to T1) refused under `--pin-tree` +
  tree repin.

**Deferred to follow-up (issue #5):** `chancery mcp install`
(Chancery-managed frozen installs — convenience over T2's primitive)
and manifest-bounded runtime confinement (egress allow-lists,
read-only FS) — a different operational model deserving its own RFC.
