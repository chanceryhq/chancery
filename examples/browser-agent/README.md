# Governing a browser agent (Playwright MCP)

Browser agents inherit human sessions — cookies that authorize
*everything* your account can do, invisible to your IdP, impossible to
scope. This example governs a real browser agent with Chancery
(RFC-013): the **session is custodied** (the agent never holds a
cookie), **navigation is scoped** per-URL, and **revocation kills the
session on the next call**.

Works with any MCP client (Claude Code, Claude Desktop, …) and the
official [Playwright MCP server](https://github.com/microsoft/playwright-mcp).

## 1. Capture a session once, then seal it

A human logs in once and exports the browser storage state:

```sh
npx playwright codegen --save-storage=state.json https://github.com/login
# log in in the window that opens, then close it

chancery secret put github-session --from-file state.json
shred -u state.json 2>/dev/null || rm -P state.json   # no plaintext left behind
```

The session now exists only AEAD-sealed in Chancery's store.

## 2. Grant scoped browsing authority

`call:` caps govern *which browser tools*; `net:` caps govern *where
it may navigate*. Granting any `net:` cap auto-enables the URL guard —
every `url` argument is checked as `net:<host>/<path>` per call.

```sh
chancery agent register web-bot --owner user:you@acme.com \
    --purpose "triages github issues" --model claude-fable-5

chancery writ grant --for user:you@acme.com --to web-bot \
    --cap "call:browser/*" \
    --cap "net:github.com/*" \
    --ttl 2h
# → note the writ id, e.g. w_01ABC...
```

## 3. Run the browser behind the proxy

`--secret-file` materializes the sealed session as a 0600 file in a
private run directory that only the *server* process reads —
`chancery-file:STATE` in the server args is replaced with its path.
The agent-side context never contains the cookies.

```sh
chancery mcp wrap --agent web-bot --writ <writ-id> \
    --server-name browser \
    --secret-file STATE=github-session \
    -- npx @playwright/mcp@latest --isolated --storage-state=chancery-file:STATE
```

Or as a Claude Code / Claude Desktop `.mcp.json`:

```json
{
  "mcpServers": {
    "browser": {
      "command": "chancery",
      "args": ["mcp", "wrap", "--agent", "web-bot", "--writ", "w_01ABC...",
               "--server-name", "browser", "--secret-file", "STATE=github-session",
               "--", "npx", "@playwright/mcp@latest",
               "--isolated", "--storage-state=chancery-file:STATE"]
    }
  }
}
```

## 4. What you get

- **Navigate to `https://github.com/acme/issues`** → ALLOW, audited as
  `mcp.net github.com/acme/issues` (query strings never recorded).
- **Navigate to `https://mail.google.com`** → JSON-RPC `-32001`
  denial: outside `net:github.com/*`. A prompt-injected agent cannot
  take your GitHub session shopping elsewhere.
- **`file:///etc/passwd`, `javascript:`, userinfo-smuggled URLs** →
  denied, fail closed: what the grammar can't express doesn't pass.
- **`chancery instance revoke <id>`** (or revoking the writ/agent) →
  the *session* dies on the next tool call. This is the kill switch
  browser sessions never had.
- **The run directory is deleted when the session ends** — the
  unsealed state file does not outlive the wrap.

## Honest boundaries (RFC-013 §6)

The MVP guard checks top-level `url`/`uri` arguments — which covers
Playwright/Puppeteer/fetch MCP servers — and checks the *requested*
URL (server-side redirects land in v1/v2's CDP enforcement, gap G11
in [SECURITY.md](../../SECURITY.md)). In-page actions on an allowed
page are governed at the tool level (`call:browser/*`), not the DOM
level. The delegation story composes: spawn a worker (RFC-012) with
`net:github.com/acme/*` and its browser is confined to that subtree.
