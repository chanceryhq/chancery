# LangGraph / Python agents

Chancery governs Python agents (LangGraph, CrewAI, the OpenAI Agents SDK)
the same way it governs any other: **the enforcement boundary is the
proxy, not a library in your agent process.** There is no trusted way for
code running inside a prompt-injectable agent to enforce its own limits
(RFC-009, trust boundary 1). So the integration is deployment-shaped, not
import-shaped.

## The pattern (works for any framework)

Your LangGraph agent almost certainly reaches tools through MCP (the
`langchain-mcp-adapters` / `MultiServerMCPClient` path). Wherever that
client launches an MCP server by command, wrap the command:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "fs": {
        "transport": "stdio",
        # was: "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/repo"]
        "command": "chancery",
        "args": [
            "mcp", "wrap",
            "--agent", "research-agent",
            "--writ", "w_01ABC...",       # scoped writ minted by an operator
            "--server-name", "fs",
            "--",
            "npx", "-y", "@modelcontextprotocol/server-filesystem", "/repo",
        ],
    }
})
tools = await client.get_tools()   # only tools the writ permits appear
```

Every `tools/call` your graph makes is now checked in-path; revoking the
agent (`chancery agent revoke research-agent`) blocks its next tool call
mid-run, and the whole run is attributed in `chancery audit`.

## Why not a Python decorator that checks first?

You can — for ergonomics and fast failure — by calling the control-plane
API (`POST /v1/writs/{id}/check`, the same endpoint the Go SDK's `Guard`
uses). Treat it exactly like client-side form validation: helpful, and
never the thing that actually stops a bad action. A prompt-injected agent
skips your decorator; it cannot skip the proxy it must speak through.

A native Python SDK (mirroring `sdk/` in Go) is planned once the Go SDK
proves the shape (RFC-010: "Python/TS SDKs after the Go SDK").

## Minimal check-first call today (no SDK needed)

```python
import requests

def guard(base, token, writ, resource, verb="call"):
    r = requests.post(f"{base}/v1/writs/{writ}/check",
                      headers={"Authorization": f"Bearer {token}"},
                      json={"verb": verb, "resource": resource})
    d = r.json()
    return d["decision"] == "ALLOW", d.get("reason", "")
```
