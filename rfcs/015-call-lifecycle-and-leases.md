# RFC-015: Call Lifecycle and Capability Leases

- **Status:** Locked
- **Author:** Aneesh Gupta
- **Created:** 2026-07-16
- **Locked:** 2026-07-20
- **Depends on:** RFC-002, RFC-005, RFC-006, RFC-008
- **Blocks:** —

## 1. Problem

Revocation through RFC-014 is enforced at **call admission**: the proxy
checks the writ before forwarding, so the next call after a revoke
dies. That guarantee is real but narrower than operators assume:

1. A call already forwarded to the tool server is not recalled. A
   revocation landing while a call is in flight does not stop it.
2. The audit trail records that a call was **admitted** and never says
   what happened to it. "Allowed" and "happened" are different facts;
   the log conflates them. A queued action can land after the operator
   believes everything stopped.

(Surfaced by external review of the public revocation writeup: 
"the practical test is whether in-flight tool calls carry an
expiration token — otherwise the UI says stopped while a queued action
can still land later.")

## 2. Existing approaches and why they fall short

- **Token expiry (OAuth-style):** the credential dies at TTL, not at
  revocation; the in-flight window is the whole remaining TTL.
- **Distributed cancellation (per-call cancel messages):** requires
  tracking every outstanding call and a reliable channel to each
  executor — heavy state, unreliable delivery, still races the commit.
- **Sagas/compensating transactions:** the right tool for *undoing*
  committed effects, but they live at the resource layer (only the
  tool knows how to reverse itself). The gate cannot un-send an email.

## 3. Alternatives considered

1. **Do nothing; document the boundary.** Honest but leaves the
   cheap-to-fix half (the log's silence about outcomes) unfixed.
2. **Cancellation tokens with per-call state at the control plane.**
   Bookkeeping grows with concurrency; delivery is unreliable.
3. **Capability lease + liveness re-check (chosen):** stamp each
   admitted call with a short-lived signed lease; a cooperating server
   verifies it immediately before committing. Verification re-checks
   registry liveness, so a revocation after admission fails the lease
   — no per-call state, no delivery problem (the server pulls).

## 4. Decision

**Lifecycle states.** The proxy records `mcp.call_result` when the
server answers an admitted call: reason `committed` (result) or
`failed` (JSON-RPC error). The trail now distinguishes admitted /
committed / failed. Compensation (`compensated`) is a resource-layer
concept and is deliberately NOT recorded by the gate — the gate would
be attesting to something it cannot see.

**Capability leases.** With `mcp wrap --lease`, every admitted call is
stamped with a compact ES256 JWS in `params._meta["chancery/lease"]`:
`{wid, blk, agt, res, non, iat, exp}` with a 30-second TTL. A
cooperating tool server POSTs it to `/v1/leases/verify` immediately
before committing a side effect (and at checkpoints of long
operations). Verification checks the signature and expiry, then
**re-checks writ/block liveness in the registry** — a lease minted
before a revocation is invalid after it.

Chancery's revocations are monotonic (nothing is ever un-revoked), so
the liveness re-check is equivalent to the revocation-epoch counter in
the original design sketch, with no extra state.

## 5. Why

- The lease closes the admission→commit window **for servers that opt
  in**, without weakening anything for servers that don't: `_meta` is
  reserved for exactly this kind of metadata in MCP, and
  non-cooperating servers ignore it.
- Pull-based verification has no delivery problem and no per-call
  control-plane state.
- Lifecycle results make the audit trail honest about outcomes at
  near-zero cost — the proxy already sees the response frames.

## 6. Trade-offs accepted

- **Server cooperation required** for the lease's guarantee; that is
  inherent (only the server stands between admission and commit).
  Admission-time denial remains the universal floor.
- Lease stamping mutates the forwarded frame. It is opt-in (`--lease`)
  and additive: any stamping failure forwards the original frame.
- `mcp.call_result` is best-effort: the action already happened;
  an audit failure there cannot deny anything retroactively.
- One-shot third-party APIs remain the hard boundary: nothing un-sends
  the email. The design says so instead of implying coverage.

## 7. Failure scenarios

- **Revocation lands mid-flight, server cooperates:** lease check at
  commit fails (`authority revoked since minting`) — the effect never
  lands. The window shrinks to the gap between lease check and commit.
- **Revocation lands mid-flight, server does not cooperate:** behavior
  identical to RFC-014: the effect lands; the NEXT call dies. The log
  now at least shows `committed` after the revoke — honest evidence.
- **Chancery API down at verify time:** the cooperating server cannot
  verify; its contract is to refuse to commit (fail closed on its
  side).
- **Lease replay:** leases carry a nonce and a 30s expiry and name one
  resource; replay within the window against the same resource is
  possible by the same holder — it proves liveness, not uniqueness of
  execution. Idempotency remains the tool's job.

## 8. Security considerations

Leases are signed by the issuer key (RFC-001) and verified against its
public key; they carry no secrets and no payloads. `/v1/leases/verify`
is admin-token-authed like every read surface. The lease names the
resource it was minted for; servers should match it against the
operation they are about to commit.

## 9. What gets built (MVP, this RFC)

- `mcp.call_result` lifecycle events in the proxy (committed/failed).
- `MintLease`/`VerifyLease` in the service; `--lease` on `mcp wrap`;
  stamping into `params._meta["chancery/lease"]`.
- `POST /v1/leases/verify` → `{valid, reason, resource}`.
- Tests: mint/verify/revoke-invalidates; tampered lease; stamped frame
  reaches the server with arguments intact; lifecycle events audited.

## 10. Amendment (2026-07-17): audit cross-references (issue #6)

The lease-verify callback is the one moment two audit chains describe
the same event — Chancery's authority chain and the tool's own content
chain (the composition Perseus Vault surfaced). `POST /v1/leases/verify`
therefore accepts an optional `xref` field, `<system>:<opaque-id>`
(system `[a-z0-9_-]{1,32}`, id 1–128 printable chars). On a VALID
lease it is recorded as an `mcp.call_xref` audit event carrying the
lease's writ, agent, and resource plus the opaque foreign id.

Locked properties: the id is **opaque** — Chancery attests its own
chain, not the foreign one; it is an identifier, never content
(metadata-only stands); an invalid lease records nothing (it attests
nothing); malformed xrefs are a 400, not a silent drop; and neither
chain depends on the other to function — the reference is an
annotation. The reverse direction needs no Chancery plumbing at all:
the cooperating server reads `wid`/`blk` out of the lease it already
holds and records them in its own trail. Tested:
`TestLeaseXrefRecorded`.
