# RFC-018: Frozen Installs and Manifest-Bounded Confinement

- **Status:** Locked
- **Author:** Aneesh Gupta
- **Created:** 2026-07-16
- **Locked:** 2026-07-20
- **Depends on:** RFC-005, RFC-006, RFC-016
- **Blocks:** —

## 1. Problem

RFC-016 answered *"is this the code I approved?"* with three pinning
tiers. Two gaps remain on the callee side:

1. **The strong tiers demand work.** T2 needs a hand-built directory
   to `--pin-tree`; T3 needs Docker. The default an operator actually
   reaches for — `npx some-server` — re-resolves the package tree on
   every run and pins only the launcher (G13). Security that requires
   ceremony becomes security nobody uses.
2. **A verified server can still misbehave.** The pin proves *which*
   code is running, not what it does after an allowed call: a
   correctly-pinned server whose transitive dependency was malicious
   *at pin time* can read the whole disk and exfiltrate to anywhere
   (trust boundary 3, RFC-009). Permission bounds the call; nothing
   bounds the process.

## 2. Existing approaches and why they fall short

- **Docker-everything** solves both but taxes every operator with a
  container runtime, image plumbing, and stdio-through-docker
  awkwardness for what is usually one npm package.
- **npm lockfiles** freeze *versions*, not *bytes on disk*, and
  nothing re-verifies at spawn time.
- **OS sandboxes by hand** (seatbelt profiles, bwrap invocations) are
  exactly the ceremony problem again — and they aren't tied to the
  identity system, so nothing audits the boundary or refuses on its
  absence.
- **Egress firewalls at the network layer** don't know which process
  is which; the wrap does.

## 3. Alternatives considered

- **Vendoring the package tree into the repo** — pushes supply-chain
  hygiene onto every user; no re-verification.
- **Per-call syscall filtering** — the right end state for the `exec`
  phase, wrong cost now; kernel-level per-call mediation of a Node
  process is a research project.
- **Egress rules on the writ** — rejected on principle: a GitHub MCP
  server needs `api.github.com` even when the writ grants no `net:…`
  caps. The writ bounds each *call* under a *grant*; what the process
  may reach is a property of the *server*, declared by the *operator*.
  Two authorities, deliberately separate.
- **Silently skipping confinement where the OS layer is missing** —
  rejected hard: the failure mode must be refused-and-audited, never
  silently-unconfined.

## 4. Decision

Two mechanisms, one manifest, all on the pin.

**Frozen installs.** `chancery mcp install <pkg>@<exact-version>`
performs a one-time npm install into `$CHANCERY_DATA/servers/<name>`
with lifecycle scripts disabled (`--ignore-scripts`) and local paths
copied, not symlinked (`--install-links` — a symlink's tree hash is
just its target string). The whole tree is Merkle-hashed and pinned as
T2 (RFC-016); the wrap thereafter launches from that directory and
re-verifies the tree before every spawn. Mutable specs (`latest`, `^`,
`~`, partial versions) are refused — same rule as image tags: a
mutable reference is not an identity. Once a namespace carries a tree
pin, plain wraps use it automatically — forgetting `--pin-tree` can
never silently degrade the tier.

**The confinement manifest.** Every pin gains two operator-declared
lists: `egress` (hosts the server process may reach; empty = no
network) and `writable` (paths it may write; empty = read-only). Set
at first pin (`mcp install`/`mcp wrap --egress/--writable`), changed
only via audited `mcp repin`.

**Enforcement (`mcp wrap --confine`).** Opt-in. The spawn applies the
manifest as an OS boundary:

- a Chancery-owned loopback egress proxy is started with the host
  allow-list; the child env routes HTTP(S) through it; every refused
  host is audited as `mcp.server_egress_denied` — host only, never
  paths or payloads (RFC-006 is structural);
- the command is wrapped in an OS sandbox: outbound network is
  loopback-only (the proxy is the only road out, even for a client
  that ignores proxy env vars) and the filesystem is read-only outside
  the writable paths and a private temp dir. macOS: `sandbox-exec`
  (seatbelt). Linux: bubblewrap for the filesystem boundary.
- where the OS layer is unavailable, the spawn is **refused** and
  audited (`mcp.confine_refused`).

**Preflight.** `mcp wrap --dry-run` prints everything the wrap would
enforce — effective authority, pin status (including would-drift),
manifest — spawning nothing and pinning nothing.

## 5. Why

The install command is the *guided default* G13 asked for: the easy
path and the safe path become the same path. The manifest lives on the
pin because it describes the pinned code, under the operator's
authority — the same trust boundary that approves the bytes approves
their blast radius. And the proxy design keeps judgment out of the
gate (RFC-017's line): host allow-listing is a hard yes/no rule, so it
belongs in-path.

## 6. Trade-offs accepted

- **npm-only today.** The install path covers the ecosystem where the
  hole (npx) actually is; pip/uvx later.
- **`--ignore-scripts` breaks packages needing build steps** — those
  need a manual install plus `--pin-tree`. Correct trade: install-time
  lifecycle scripts are arbitrary registry code.
- **Host-level egress**: a compromised server can still exfiltrate *to
  an allowed host* (api.github.com is a fine dropbox). Narrower rules
  are the argument-schema phase.
- **Linux egress is proxy-env cooperative** until the netns phase —
  bwrap here bounds the filesystem; a Linux server that ignores proxy
  env vars is not network-bounded yet. macOS bounds both.

## 7. Failure modes

- Sandbox binary missing / unsupported OS → spawn refused, audited.
  Never silently unconfined.
- Manifest flags on an already-pinned namespace → refused with the
  repin instruction (manifest changes are deliberate).
- Poisoned file inside a frozen install → next wrap refuses
  (`mcp.server_drift`) before any process starts (tested end-to-end).
- Denied egress → proxy 403 + `mcp.server_egress_denied`; the server
  keeps running (deny the road, not the process).

## 8. Security notes

- `sandbox-exec` is deprecated-but-functional; seatbelt itself is what
  macOS runs on. Sandboxes are kernel-bug-deep — this is
  defense-in-depth under RFC-009's trust boundaries, not a hypervisor.
- The install trusts the npm registry at install time; provenance /
  sigstore verification of the fetched tree is the natural next step.
- The egress proxy sees CONNECT hostnames, not TLS plaintext. It
  records hosts only.
- Container-launched servers should use container-native confinement
  (network policy) — `--confine` sandboxes the *client* process it
  spawns, which is not the container's boundary.

## 9. What gets built (this RFC's tests)

`internal/confine` (host matching, allow/deny proxy paths with
audit-hook, proxy env, profile rendering); `cmd/chancery`:
`TestConfineFilesystemBoundary` and `TestConfineNetworkBoundary`
against the real OS sandbox, `TestConfineWrapEndToEnd` (full wrap,
egress denial in the audit trail, no path leakage),
`TestInstallPinWrapAndPoison` (install → auto tree pin → dry-run →
poisoned file → drift refusal), `TestInstallRejectsMutableSpec`,
`TestDryRunPinsNothing`. All CI-gated.
