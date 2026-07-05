# Governing any agent (not just MCP)

**Chancery is MCP-first, not MCP-only.** The identity registry, writs and
delegation, policy, sealed credentials, and audit are all
framework-agnostic — they govern any agent (LangGraph, CrewAI, a cron
job, a shell script, a custom loop) in any language. MCP is simply the
first runtime where enforcement is *unbypassable*.

There are two ways an agent can be governed, and the honest difference
between them matters:

| Mode | How it works | Bypassable? | Available |
|---|---|---|---|
| **In-path (enforced)** | The agent's tool calls physically pass through `chancery mcp wrap`; a denied call never reaches the tool | **No** — a prompt-injected agent must speak through the proxy | **MCP today** (HTTP egress, shell, browser are the roadmap — RFC-005) |
| **Advisory (check)** | Your agent asks Chancery "may I?" via the API/SDK before acting, and honors the answer | Yes — it's opt-in, like server-side validation you chose to call | **Any agent, any language, today** |

Use **in-path** wherever you can (it's the real security boundary). Use
**advisory** everywhere else to get the same identity, delegation, policy,
and audit today — and swap it for in-path enforcement as the other
runtimes land, with no change to your writs or policies.

---

## Governing a non-MCP agent in 5 minutes

This governs a plain job — a database ETL agent — with no MCP involved.
The actions are modeled as `verb:resource`; the verbs are `call`, `read`,
`write`, `exec`, `net`, plus `admin` for writ-governed control-plane
self-service (RFC-004, RFC-012).

### 1. Set up the control plane

```sh
chancery init --trust-domain acme.com     # prints an admin token — save it
chancery serve &                          # HTTP API on 127.0.0.1:7423
```

### 2. Register the agent and scope it

```sh
chancery agent register etl-bot \
  --owner user:you@acme.com --purpose "nightly ETL job" \
  --prompt ./etl_agent.py --model none

# It may read analytics and write to staging — nothing else.
chancery writ grant --for user:you@acme.com --to etl-bot \
  --cap "read:db/analytics/*" --cap "write:db/staging/*" --ttl 8h
# → note the writ id, e.g. w_01ABC...
```

### 3. Have the agent ask before it acts

Any language can call the decision endpoint. In Python:

```python
import os, requests

CHANCERY = "http://127.0.0.1:7423"
TOKEN = os.environ["CHANCERY_TOKEN"]     # the admin token from init
WRIT  = os.environ["CHANCERY_WRIT"]      # w_01ABC...

def allowed(verb, resource):
    r = requests.post(f"{CHANCERY}/v1/writs/{WRIT}/check",
                      headers={"Authorization": f"Bearer {TOKEN}"},
                      json={"verb": verb, "resource": resource})
    return r.json()["decision"] == "ALLOW"

# In your agent loop, gate each real action:
if allowed("read", "db/analytics/events"):
    rows = read_analytics("events")        # proceeds
if allowed("write", "db/production/users"):
    write_users(rows)                      # never runs — outside the writ
```

Every check is recorded with full attribution (which agent, which
version, under whose authority) whether it's ALLOW or DENY.

### 4. The moment that sells it

While the job is running, revoke it:

```sh
chancery agent revoke etl-bot
```

The agent's next `allowed(...)` call returns DENY, cited to the registry
layer — it stops touching your data immediately, not at token expiry.
Then:

```sh
chancery audit --limit 20      # every decision, attributed
chancery audit verify          # the record is tamper-evident
```

### Secrets, the same way

If the job needs a real credential (a DB password, an API key), seal it
so the agent's code never holds it, and rotate it with one command:

```sh
chancery secret put analytics-db-pass --from-file ./db_pass
# your job fetches the sealed value at run time via your own wiring, or —
# once the HTTP-egress PEP lands — Chancery injects it in-path and the
# agent never sees it at all (the model already used for MCP servers).
```

---

## Orchestrators that create agents at runtime

If your system (Hermes/Ruflo/Vantage-style) spins up workers on the
fly, don't give the orchestrator the admin token — spawning is itself
writ-governed (RFC-012). Once, with operator authority:

```sh
chancery template create researcher --purpose "reads github" \
  --max-cap "call:github/get_*" --max-ttl 30m
chancery writ grant --for user:you@acme.com --to orchestrator \
  --cap "call:github/*" --cap "admin:spawn/researcher"
```

Then the orchestrator spawns tokenlessly, from any language:

```python
r = requests.post(f"{CHANCERY}/v1/spawn", json={
    "writ": WRIT_ID, "agent": "orchestrator",
    "template": "researcher", "name": "worker-1",
    "caps": ["call:github/get_*"], "ttl_seconds": 600,
})  # 201: registered + delegated a narrowed block; 403: spawn refused
```

The child inherits the owner, can never exceed the template ceiling or
the orchestrator's own authority, expires on its own, and shows up in
the audit trail as `agent.spawn` with full lineage.

---

## Which mode should I use?

- **Your agent reaches tools over MCP** → use `chancery mcp wrap`
  ([quickstart](../QUICKSTART.md)). Real, unbypassable enforcement today.
- **Your agent does anything else** (SQL, HTTP calls, shell, its own
  tools) → use the **advisory check** above now; you get identity,
  scoped/attenuating authority, instant revocation, sealed secrets, and
  tamper-evident audit immediately. When the in-path PEP for that runtime
  ships (RFC-005: HTTP → shell → browser), you flip to enforced with the
  same writs.

The [Go SDK](../sdk/) wraps the advisory check as `Guard`/`Guarded`; a
Python SDK follows once the Go one proves the shape.
