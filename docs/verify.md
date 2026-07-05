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

## RFC-012 — Runtime spawn is writ-gated and ceiling-bounded

The claim: an orchestrator can create agents at runtime **without the
admin token**, and can never spawn beyond the template a human
approved.

```sh
chancery agent register orch --owner user:you@acme.com --purpose "orchestrates"
chancery template create researcher --purpose "reads github" \
    --max-cap "call:github/get_*" --max-ttl 30m

# A writ that carries work caps AND the spawn capability:
W=$(chancery writ grant --for user:you@acme.com --to orch \
    --cap "call:github/*" --cap "admin:spawn/researcher" --ttl 1h | grep -o 'w_[A-Z0-9]*' | head -1)

# 1) Spawn works — child registered, delegated, owner inherited, expiry set:
chancery agent spawn worker-1 --writ $W --agent orch --template researcher --ttl 10m

# 2) The ceiling binds — wider than the template is refused:
chancery agent spawn worker-2 --writ $W --agent orch --template researcher \
    --cap "call:github/*"
# expect: spawn refused: capability call:github/* exceeds template researcher ceiling

# 3) The writ gates — a template the writ doesn't name is refused:
chancery template create deployer --purpose d --max-cap "call:deploy/*" --max-ttl 10m
chancery agent spawn worker-3 --writ $W --agent orch --template deployer
# expect: spawn refused: [writ] outside effective authority (grant ∩ caveats)

# 4) Expiry is real — expired ephemerals are denied in-path and swept:
chancery audit --limit 8    # agent.spawn, agent.spawn_refused ×2, all attributed
chancery agent sweep        # retires any expired ephemerals (audits agent.expired)
```

**Expect:** the spawn, both refusals, and their audit events — and note
no admin token appeared anywhere after the template was created. Over
HTTP the same operation is `POST /v1/spawn` with **no bearer token**:
the writ is the authorization.

---

## RFC-013 — Sessions are custodied; navigation is scoped

The claim: a browser agent never holds the session, and can only
navigate where the writ's `net:` caps allow — checked per URL,
fail-closed. Verifiable without a real browser, because the guard
lives in the proxy:

```sh
chancery agent register web-bot --owner user:you@acme.com --purpose "browses"
echo '{"cookies":[{"name":"session","value":"supersecret"}]}' > /tmp/state.json
chancery secret put test-session --from-file /tmp/state.json && rm /tmp/state.json

# net caps on the writ auto-enable the URL guard:
WB=$(chancery writ grant --for user:you@acme.com --to web-bot \
    --cap "call:sh/*" --cap "net:github.com/*" --ttl 30m | grep -o 'w_[A-Z0-9]*' | head -1)

# `cat "$STATE"` stands in for a browser server reading its storage state —
# proving the sealed session reached the SERVER side (and only there):
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"c","arguments":{"url":"https://github.com/acme/repo?token=leak"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"c","arguments":{"url":"https://mail.google.com/"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"c","arguments":{"url":"file:///etc/passwd"}}}' \
| chancery mcp wrap --agent web-bot --writ $WB --server-name sh \
    --secret-file STATE=test-session \
    -- sh -c 'cat "$STATE" >&2; while read l; do echo "{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{}}"; done'
```

**Expect:** the sealed cookie JSON printed on *stderr* (that's the
server process holding it — the agent-side JSON stream never contains
it); call 1 forwarded (github.com allowed); calls 2 and 3 answered
with `-32001 navigation denied` (outside `net:github.com/*`; non-http
fails closed). Then:

```sh
chancery audit --limit 6
```

**Expect:** `mcp.net` events — `github.com/acme/repo` ALLOW **without
`token=leak`** (query strings are payload, never audited), and the
two DENYs. For the real thing, see
[examples/browser-agent](../examples/browser-agent/README.md).

---

```sh
rm -rf "$CHANCERY_DATA"     # clean up the throwaway state
```

Every guarantee above is also locked by an automated test (see
[CONTRIBUTING.md](../CONTRIBUTING.md) for the package→RFC map); this doc
just lets you watch them hold with your own hands.
