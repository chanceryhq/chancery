# The Chancery Testing Playbook

A complete, guided test run of every feature (RFC-001 → RFC-014) in
one sitting, ~20 minutes. Each step says **what you're testing**,
**the commands**, and **what you must see**. Every command here has
been run verbatim against the current build — if something differs,
that's a bug: [report it](../SECURITY.md).

This is the operator's companion to [verify.md](verify.md) (per-claim
proofs) and [QUICKSTART.md](../QUICKSTART.md) (the 5-minute demo).

> **Shell notes (read once, saves you three debugging sessions):**
> - Run everything in **one terminal**. `$CHANCERY_DATA`, `$W`, etc.
>   are shell variables — a new tab doesn't have them. If you must
>   reopen, re-export `CHANCERY_DATA` first.
> - In zsh, trailing `# comments` on an interactive command line are
>   arguments, not comments, unless you `setopt interactive_comments`.
> - Don't paste blank lines in the middle of a `\`-continued command.
> - Never add `2>/dev/null` while testing — refusals ARE the test.

## 0. Setup (isolated, disposable — never your real state)

```sh
cd chancery && make build
alias chancery="$PWD/chancery"
export CHANCERY_DATA="$(mktemp -d)"
chancery init --trust-domain acme.com
```

**Expect:** an admin token line (`chy_…`). Save it:

```sh
export TOKEN=chy_...        # paste yours
```

Everything below lives in that temp dir; step 14 deletes it.

---

## 1. Identity: agent → version → instance (RFC-001)

*Testing: identity has three layers, and content changes are
detectable by hash.*

```sh
chancery agent register deploy-bot --owner user:you@acme.com \
    --purpose "deploys services" --prompt "You deploy things." --model claude-fable-5
chancery agent version deploy-bot --prompt "You deploy things CAREFULLY." --model claude-fable-5
chancery agent describe deploy-bot
```

**Expect:** a `spiffe://acme.com/agent/deploy-bot` URI; two versions
with **different digests** — the prompt changed, so the content
address changed. That's "did this agent change since review?" as a
hash compare.

```sh
chancery instance start --agent deploy-bot --ttl 5m
```

**Expect:** an instance id and a JWT identity document. Optionally
`chancery token verify <that-jwt>` — note it checks signature **and**
registry state, not just crypto.

## 2. Writs: authority that can only narrow (RFC-002)

*Testing: block 0 grants; delegation only restricts; lineage is in
the credential.*

```sh
W=$(chancery writ grant --for user:you@acme.com --to deploy-bot \
    --cap "call:github/*" --ttl 1h | grep -o 'w_[A-Z0-9]*' | head -1)
echo $W

chancery agent register test-runner --owner user:you@acme.com --purpose "runs tests"
chancery writ delegate $W --to test-runner --caveat "call:github/get_*" --ttl 30m
chancery writ check $W --resource github/get_pull_request
chancery writ check $W --resource github/create_issue
```

**Expect:** delegate prints the lineage
(`user → deploy-bot → test-runner`); first check **ALLOW**, second
**DENY** — the child was narrowed to `get_*` and there is no flag, on
any command, that could widen it. Also try delegating a caveat wider
than the grant or a `--ttl` longer than the parent's: both refuse.

## 3. Sealed secrets: agents never hold credentials (RFC-003)

*Testing: no plaintext at rest; agents never see values.*

```sh
echo "hunter2" > /tmp/dbpass.txt
chancery secret put db-pass --from-file /tmp/dbpass.txt && rm /tmp/dbpass.txt
chancery secret list
grep -r hunter2 "$CHANCERY_DATA" || echo "NO PLAINTEXT ANYWHERE ✓"
```

**Expect:** the secret listed by name — and the grep finds
**nothing**: `sealed.json` holds only AES-256-GCM ciphertext,
name-bound so entries can't even be swapped. Values are injected into
*server* processes at enforcement time (steps 5 and 11), never shown,
never in an agent's context.

## 4. Layered policy: only the writ grants (RFC-004)

*Testing: allow-lists subtract, never add.*

Allow-lists bind to the **acting** agent — and the default
`writ check` acts at the writ's latest block, test-runner's — so we
set test-runner's list:

```sh
chancery agent allow test-runner --tool "github/get_repo"
chancery writ check $W --resource github/get_repo
chancery writ check $W --resource github/get_pull
chancery agent allow test-runner --tool "slack/*"
chancery writ check $W --resource slack/post_message
chancery agent allow test-runner       # clear the allow-list
```

**Expect:** check 1 ALLOW (writ ∩ allow-list both admit it). Check 2
**DENY at the `allowlist` layer** — the writ admits `get_*`, but the
allow-list narrowed further: subtraction works. Check 3 **DENY at
the `writ` layer** — putting `slack/*` on the allow-list granted
*nothing*, because the writ never did: addition is impossible.
Allow-list patterns are resource-only (no `verb:` prefix); layers
2–4 can only say no.

## 5. In-path MCP enforcement (RFC-005)

*Testing: the proxy is the boundary; it enforces the acting agent's
OWN (narrowed) block; denial is protocol-native.*

The wrapped "server" here is a stub (`sh` answering every call) so
you can watch pure enforcement; the [quickstart](../QUICKSTART.md)
does it against the real filesystem server. We wrap as
**test-runner** — the delegated agent from step 2, narrowed to
`call:github/get_*`:

```sh
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_repo"}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo"}}' \
| chancery mcp wrap --agent test-runner --writ $W --server-name github \
    -- sh -c 'while read l; do echo "{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{}}"; done'
```

**Expect:** two lines, **in either order** — denials are answered
instantly by the proxy while allowed calls round-trip through the
server, so the deny usually prints first:

```
{"error":{"code":-32001,"message":"chancery: denied by writ policy: …"},"id":2,…}
{"jsonrpc":"2.0","id":0,"result":{}}
```

The `error` is call 2 (`delete_repo`), answered by **Chancery
itself** — it never reached the server, because test-runner's block
admits only `get_*`. The `result` is call 1 forwarded and answered;
it says `id:0` only because this stub server always replies with id 0
(a real MCP server echoes the request id).
(Wrapping as `deploy-bot` would allow both: its grant is the wider
`call:github/*`. `--agent X` always selects X's *own* block — an
agent holding no block on the writ is refused at startup.) Note
`mcp wrap` is a *proxy*: with no client piping JSON-RPC into it, it
just waits — that's an MCP client's job (see the `.mcp.json` in
[examples/claude-code](../examples/claude-code/README.md)).

## 6. Tamper-evident audit (RFC-006)

*Testing: the log detects any edit, delete, or reorder; and it holds
no payloads.*

```sh
chancery audit --limit 12
chancery audit verify
sqlite3 "$CHANCERY_DATA/chancery.db" \
  "UPDATE audit_events SET reason='innocent' WHERE seq=(SELECT MAX(seq) FROM audit_events);"
chancery audit verify
```

**Expect:** first verify: `audit chain intact: N events verified`.
After the malicious UPDATE: **INTEGRITY FAILURE** naming the exact
event — everything before the break stays trustworthy. (The break is
permanent by design — this throwaway store stays "tampered" for the
rest of the run, which is exactly what you want from evidence.) Also
look at
the timeline you printed: agent names, tools, decisions, lineage —
and not one prompt, payload, or secret. The schema has no column for
them.

## 7. Lifecycle: reversible vs terminal (RFC-007)

*Testing: the state machine is enforced at the data layer.*

The default `writ check` evaluates the writ's latest block — which
belongs to **test-runner** (the delegated leaf), so test-runner is
the acting agent we toggle:

```sh
chancery agent suspend test-runner
chancery writ check $W --resource github/get_repo
chancery agent resume test-runner
chancery writ check $W --resource github/get_repo
chancery agent revoke test-runner
chancery agent resume test-runner
```

**Expect:** suspended → DENY (`agent test-runner is suspended`);
resumed → ALLOW again — suspend is the reversible pause. Then revoke
prints a TERMINAL warning, and the final resume **errors**: `illegal
lifecycle transition: revoked → active`. Revoked is terminal — no
client, not even the API, can resurrect it. (Re-registering the same
name later mints a *new* identity; history stays attributable.)

## 8. The HTTP API: same brain, different door (RFC-008)

*Testing: CLI and API are thin clients over one implementation; a
DENY is a 200; auth failures are audited.*

```sh
chancery serve &        # 127.0.0.1:7423
sleep 1
curl -s -H "Authorization: Bearer $TOKEN" -X POST \
  localhost:7423/v1/writs/$W/check -d '{"verb":"call","resource":"github/delete_repo"}'
curl -s -X POST localhost:7423/v1/writs/$W/check -d '{}'   # no token
```

**Expect:** first: HTTP 200 with `"decision":"DENY"` — a denial is a
*successful evaluation*, not a transport error. Second:
`unauthorized` — and check `chancery audit --limit 3`: the failed
auth attempt was itself recorded (with no token material). Leave
`serve` running for step 10.

**Now open the dashboard (RFC-014):** visit
`http://127.0.0.1:7423/ui` in a browser and paste `$TOKEN`. You get
the live timeline (with the integrity badge running `audit verify`
continuously), the agent roster, the **delegation tree drawn as a
tree**, and templates — all read-only: notice there is no button
that grants, revokes, or seals anything. That's RFC-014's locked
scope, not a missing feature.

## 9. Adversarial checks (RFC-009)

*Testing: forged credentials fail.*

You already proved audit tamper (step 6). The cryptographic attacks —
`alg:none`, HS256 key-confusion, cross-writ block splicing, TTL
forgery — live in the adversarial suite:

```sh
go test ./internal/writ/ ./internal/identity/ -run 'Adversarial|AlgNone|KeyConfusion|Tamper|CrossWrit' -v
```

**Expect:** all pass. The MVP's *known* gaps are public: [SECURITY.md](../SECURITY.md).

## 10. Runtime spawn: dynamic agents without root (RFC-012)

*Testing: an orchestrator creates agents at runtime with NO admin
token, inside a human-approved ceiling.*

```sh
chancery agent register orch --owner user:you@acme.com --purpose "orchestrates"
chancery template create researcher --purpose "reads github" \
    --max-cap "call:github/get_*" --max-ttl 30m
WO=$(chancery writ grant --for user:you@acme.com --to orch \
    --cap "call:github/*" --cap "admin:spawn/researcher" --ttl 1h | grep -o 'w_[A-Z0-9]*' | head -1)

# tokenless spawn over HTTP (serve is still running):
curl -s -X POST localhost:7423/v1/spawn -d '{"writ":"'$WO'","agent":"orch",
  "template":"researcher","name":"worker-1","caps":["call:github/get_*"],"ttl_seconds":600}'
```

**Expect:** 201 — child registered, owner **inherited**, narrowed
block delegated, expiry set. No bearer token anywhere: the writ was
the authorization. Now the refusals:

```sh
chancery agent spawn worker-2 --writ $WO --agent orch --template researcher --cap "call:github/*"
chancery template create deployer --purpose d --max-cap "call:deploy/*" --max-ttl 10m
chancery agent spawn worker-3 --writ $WO --agent orch --template deployer
chancery agent list
chancery agent sweep
```

**Expect:** worker-2 refused — `exceeds template researcher ceiling`;
worker-3 refused — the writ carries no `admin:spawn/deployer`. Both
appear in the audit as `agent.spawn_refused`. `agent list` shows
worker-1 with SPAWNED BY `orch` and an EXPIRES stamp; once past it,
the state column reads `expired` (denied in-path already) and `sweep`
retires it.

## 11. Browser sessions: custodied cookies + scoped navigation (RFC-013)

*Testing: the session reaches only the SERVER process; every
navigation is checked as `net:<host>/<path>`; fail closed.*

```sh
chancery agent register web-bot --owner user:you@acme.com --purpose "browses"
echo '{"cookies":[{"name":"session","value":"supersecret"}]}' > /tmp/state.json
chancery secret put test-session --from-file /tmp/state.json && rm /tmp/state.json
WB=$(chancery writ grant --for user:you@acme.com --to web-bot \
    --cap "call:sh/*" --cap "net:github.com/*" --ttl 30m | grep -o 'w_[A-Z0-9]*' | head -1)

printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"c","arguments":{"url":"https://github.com/acme/repo?token=leak"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"c","arguments":{"url":"https://mail.google.com/"}}}' \
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"c","arguments":{"url":"file:///etc/passwd"}}}' \
| chancery mcp wrap --agent web-bot --writ $WB --server-name sh \
    --secret-file STATE=test-session \
    -- sh -c 'cat "$STATE" >&2; while read l; do echo "{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{}}"; done'
```

**Expect, in order:**
- the cookie JSON on **stderr** — printed by the *server* process,
  which received the sealed session as a private 0600 file (the
  agent-side stream never contains it);
- call 1 forwarded — `github.com` is inside `net:github.com/*`
  (granting `net:` caps is what switched the URL guard on);
- call 2: `-32001 navigation denied` — your GitHub session cannot be
  taken to Google;
- call 3: denied, **fail closed** — `file://` isn't expressible in
  the grammar, so it doesn't pass.

```sh
chancery audit --limit 6
```

**Expect:** `mcp.net` events — `github.com/acme/repo` ALLOW **without
`token=leak`** (query strings are payload; they never reach policy or
audit), and both DENYs, attributed. The real-browser version of this
(Playwright MCP, real login) is
[examples/browser-agent](../examples/browser-agent/README.md).

## 12. The 60-second arc, end to end

```sh
kill %1 2>/dev/null          # stop serve
make demo
```

**Expect:** the full story — grant → act → delegate → revoke mid-task
→ blocked → attributed timeline — in one minute.

## 13. The automated versions of everything above

```sh
make test
```

**Expect:** `go vet` clean and 79 tests across 10 packages green —
every step in this playbook is also locked by at least one of them
(the map is in [CONTRIBUTING.md](../CONTRIBUTING.md)).

## 14. Cleanup

```sh
rm -rf "$CHANCERY_DATA"
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `unknown command` or weird args after a `# comment` | zsh treats `#` as an argument interactively; `setopt interactive_comments` or drop the comment |
| A multi-line command half-executes | A blank line inside a `\`-continuation splits it; paste as one block |
| `$W` / `$TOKEN` empty, `not found: writ` | New terminal = fresh shell; re-export `CHANCERY_DATA` and recapture ids |
| `mcp wrap` "hangs" | It's a proxy awaiting a client; drive it with `printf … \|` as above, or from a real MCP client |
| A refusal you expected "didn't happen" | You silenced it — remove `2>/dev/null`; denials print to stderr with a nonzero exit |
| `TTL exceeds parent` on delegate | Correct behavior: a child cannot outlive its parent block; pass a shorter `--ttl` |
| Wrap uses the "wrong" authority after delegation | It doesn't: `--agent X` selects X's **own** block on the writ; agents holding no block are refused loudly |
| `net` navigation denied that you expected allowed | Host match is exact (`net:github.com/*` ≠ `gist.github.com`); grant the extra host explicitly |
| Proxy output lines in a "wrong" order, or `result` with `id:0` | Normal: denials are answered immediately by the proxy, allowed calls round-trip through the server; and the playbook's `sh` stub always replies id 0 — match responses by content, not position |
