# Verify every claim yourself

This is a hands-on checklist to confirm each RFC's core guarantee **on
your machine, by hand** — separate from the automated `go test` suite.
Every block is copy-paste, CLI-only, and self-contained; the expected
output is shown. Nothing here touches your real `~/.chancery` — it all
runs in a throwaway dir you can delete at the end.

```sh
# Setup: point at a built binary and an isolated, disposable state dir.
alias chancery="$PWD/chancery"          # or: brew install chanceryhq/tap/chancery
export CHANCERY_DATA="$(mktemp -d)"      # isolated; `rm -rf` when done
chancery init --trust-domain acme.com    # save the admin token it prints (for RFC-008)
```

---

## RFC-001 — Identity is versioned and revocable at three layers

**Claim:** an agent is a durable identity + immutable content-addressed
versions + ephemeral instances; changing the prompt makes a new version;
revocation works at any layer.

```sh
chancery agent register bot --owner user:me@acme.com --purpose "demo" \
  --prompt "version one prompt" --model claude-fable-5
chancery agent version bot --prompt "version TWO — changed" --model claude-fable-5
chancery agent describe bot
```
**Expect:** two versions with **different `sha256:` digests**, both listed
(old versions are kept, never edited). Change the prompt → new digest =
"did this agent change?" is a hash comparison.

```sh
chancery agent revoke bot          # terminal
chancery agent resume bot          # must fail
```
**Expect:** `resume` errors with an illegal-transition — revoked is
terminal and enforced at the data layer, not just the UI.

---

## RFC-002 — Delegated authority can only narrow

**Claim:** a sub-agent's authority = parent's minus caveats; widening is
unrepresentable; the chain is the lineage.

```sh
chancery agent register parent --owner user:me@acme.com --purpose p --prompt x --model m
chancery agent register child  --owner user:me@acme.com --purpose p --prompt x --model m
G=$(chancery writ grant --for user:me@acme.com --to parent --cap "call:github/*" --ttl 1h)
W=$(echo "$G" | awk '/^writ /{print $2}')

chancery writ delegate $W --to child --caveat "call:github/get_*" --ttl 30m
chancery writ check $W --resource github/get_repo        # ALLOW
chancery writ check $W --resource github/delete_repo     # DENY
```
**Expect:** the child keeps `get_*` but loses everything else. Now try to
*widen*:

```sh
chancery writ delegate $W --to child --caveat "call:snowflake/*" --ttl 5m
```
**Expect:** refused at mint time —
`delegation would grant no effective authority: caveat call:snowflake/*
intersects no granted capability`. You **cannot** delegate a capability
the parent never had. View the lineage tree:

```sh
chancery writ show $W
```

---

## RFC-003 — Agents never hold secrets; the store has no plaintext

**Claim:** sealed credentials are encrypted at rest; names/kinds are
metadata, values never leak.

```sh
echo "super-secret-token-123" | chancery secret put api-key --from-file /dev/stdin
chancery secret list                                  # names + kinds only
grep -c "super-secret-token-123" "$CHANCERY_DATA/sealed.json"
```
**Expect:** `secret list` shows `api-key` but no value; the `grep` prints
`0` — the plaintext is nowhere on disk (AES-256-GCM ciphertext only).

---

## RFC-004 — Only the writ grants; layers only deny; grammar is strict

**Claim:** the PDP is a conjunction where allow-lists can only subtract,
and invalid patterns are rejected when written, not silently at check.

```sh
# allow-list entries are RESOURCE patterns (no verb prefix) — they only subtract.
chancery agent allow parent --tool "github/get_*"
chancery writ check $W --resource github/create_issue     # DENY (allowlist)
chancery writ check $W --resource github/get_repo         # ALLOW
chancery agent allow parent --tool "gith*ub/x"            # malformed pattern
```
**Expect:** the allow-list narrows what the writ granted (`create_issue`
now denied even though the writ allowed `github/*`); the malformed
pattern is rejected immediately (`'*' is only valid as the final
character`), not at decision time.

---

## RFC-005 — In-path enforcement on a real MCP server

**Claim:** tool calls pass through the proxy; denied calls never reach the
tool; revocation binds on the next call.

The fastest proof is the scripted demo (throwaway state, ~10s):

```sh
make demo
```
**Expect:** ALLOW → DENY (out of authority) → revoke → DENY (registry) →
`audit chain intact`. For the real-server version against the official
filesystem MCP server, follow [QUICKSTART.md](../QUICKSTART.md).

---

## RFC-006 — Audit is tamper-evident (this is the good one)

**Claim:** the audit log is metadata-only and hash-chained; any edit,
deletion, or reorder is detectable.

```sh
chancery audit                     # every decision, attributed
chancery audit verify              # "audit chain intact: N events verified"

# Now tamper like a malicious insider would, straight in the DB:
sqlite3 "$CHANCERY_DATA/chancery.db" \
  "UPDATE audit_events SET decision='ALLOW' WHERE decision='DENY';"
chancery audit verify
```
**Expect:** the first `verify` says intact; after the edit it **fails**,
naming the first broken event (`content hash mismatch — the event was
modified`). Confirm no payloads are stored:

```sh
sqlite3 "$CHANCERY_DATA/chancery.db" ".schema audit_events"
```
**Expect:** columns for agent/writ/verb/resource/decision/hashes — and
**no column** for prompts, arguments, or results. Metadata-only by
structure, not policy.

---

## RFC-007 — Lifecycle: suspend is reversible, revoke/retire are terminal

```sh
chancery agent suspend child       # reversible operational pause
chancery agent resume child        # works
chancery agent retire child        # terminal
chancery agent resume child        # must fail
```
**Expect:** suspend↔resume round-trips; after retire (or revoke),
`resume` is refused. No terminal state can be exited — enforced in the
store, so even a compromised API caller can't resurrect an identity.

---

## RFC-008 — Same decisions over the HTTP API; a DENY is a 200

**Claim:** the CLI and API share one implementation; a denied check is a
successful *evaluation*, not a transport error.

```sh
chancery serve --listen 127.0.0.1:7423 &      # uses the token from init
TOKEN=<paste the admin token printed by init>
curl -s -H "Authorization: Bearer $TOKEN" 127.0.0.1:7423/v1/agents | python3 -m json.tool
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" \
  -X POST 127.0.0.1:7423/v1/writs/$W/check -d '{"verb":"call","resource":"github/delete_repo"}'
```
**Expect:** the API returns the same registry the CLI shows; the denied
check returns **HTTP 200** with a `"decision":"DENY"` body. Requests
without the token get 401 and are themselves audited.

---

## RFC-009 — Threat model: the guarantees hold under attack

Two you can see by hand:

- **Audit tamper is caught** — you just did it (RFC-006).
- **Forged/invalid tokens are rejected** — the adversarial suite proves
  `alg:none`, HS256 key-confusion, and cross-writ splicing all fail. This
  one is cryptographic, so it lives in tests; run it directly:

  ```sh
  go test ./internal/writ/ ./internal/identity/ -run 'Adversarial|AlgNone|KeyConfusion|Tamper|CrossWrit' -v
  ```
**Expect:** all pass — forged writs and identity documents are refused.
The full threat model and the honest list of known MVP gaps are in
[SECURITY.md](../SECURITY.md).

---

```sh
rm -rf "$CHANCERY_DATA"     # clean up the throwaway state
```

Every guarantee above is also locked by an automated test (see
[CONTRIBUTING.md](../CONTRIBUTING.md) for the package→RFC map); this doc
just lets you watch them hold with your own hands.
