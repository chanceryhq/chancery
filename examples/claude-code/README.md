# Wrapping an MCP server for Claude Code (or any MCP client)

Chancery is a drop-in wrapper: wherever your MCP client config launches a
server with a command, put `chancery mcp wrap … --` in front of it. The
client speaks plain MCP to Chancery; Chancery enforces per call and
forwards to the real server.

## 1. One-time setup

```sh
chancery init --trust-domain yourco.com

# Register the agent that will use the tools (owner is accountable).
chancery agent register code-assistant \
  --owner user:you@yourco.com --purpose "reads and edits the repo" \
  --prompt ./system-prompt.md --model claude-fable-5

# Grant it a scoped writ (read-only filesystem here).
chancery writ grant --for user:you@yourco.com --to code-assistant \
  --cap "call:fs/read_*" --cap "call:fs/list_*" --cap "call:fs/directory_tree" \
  --ttl 8h
# note the printed writ id, e.g. w_01ABC...
```

## 2. Point the client at the wrapper

`.mcp.json` (Claude Code project config) — before:

```json
{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/repo"]
    }
  }
}
```

After — same server, now governed:

```json
{
  "mcpServers": {
    "fs": {
      "command": "chancery",
      "args": [
        "mcp", "wrap",
        "--agent", "code-assistant",
        "--writ", "w_01ABC...",
        "--server-name", "fs",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/repo"
      ]
    }
  }
}
```

`--server-name fs` sets the resource namespace: the server's `read_text_file`
tool is checked as `call:fs/read_text_file` against the writ.

## 3. Watch it work

```sh
chancery audit --follow          # ALLOW/DENY per tool call, live
```

Revoke instantly, and the next tool call the assistant makes is blocked:

```sh
chancery agent revoke code-assistant
```

## Injecting secrets the agent must never see

If the server needs a credential (a token, an API key), seal it and let
Chancery inject it into the **server's** environment — never the agent's:

```sh
chancery secret put gh-token --from-file ./token
# add to the wrap args:  --secret GITHUB_TOKEN=gh-token
```

The agent's process tree never contains the value; rotation is one
`chancery secret put`, no client change.
