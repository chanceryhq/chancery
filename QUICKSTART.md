# Quickstart: govern a real MCP server in 5 minutes

This wraps the **official filesystem MCP server** so an agent can read
files but not write them — then revokes it mid-session. Every step below
is exercised by the test suite (`go test ./cmd/chancery/`), so it works.

## 0. Install

```sh
brew install chanceryhq/tap/chancery      # or: go build -o chancery ./cmd/chancery
```

## 1. Initialize a trust domain (once)

```sh
chancery init --trust-domain acme.com
```

## 2. Register the agent and scope it a writ

```sh
mkdir -p /tmp/sandbox && echo "hello" > /tmp/sandbox/notes.txt

chancery agent register fs-bot \
  --owner user:you@acme.com --purpose "reads project files" \
  --prompt "You read files." --model claude-fable-5

# Read-only: list + read granted; write tools are simply never granted.
chancery writ grant --for user:you@acme.com --to fs-bot \
  --cap "call:fs/read_*" --cap "call:fs/list_*" \
  --cap "call:fs/directory_tree" --cap "call:fs/search_files" \
  --ttl 1h
# → prints a writ id, e.g. w_01ABC...
```

## 3. Run the real server behind Chancery

Point any MCP client at this command (see
[examples/claude-code](examples/claude-code/README.md) for a `.mcp.json`),
or drive it directly:

```sh
chancery mcp wrap --agent fs-bot --writ w_01ABC... --server-name fs \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp/sandbox
```

- `tools/list` returns only the read tools — the model never sees
  `write_file`, `move_file`, `edit_file` (they're filtered out).
- A `read_text_file` call is allowed and reaches the server.
- A `write_file` call is denied in-path with a JSON-RPC error — the file
  is never written.

## 4. Watch, then revoke

```sh
chancery audit --follow          # live ALLOW/DENY per tool call
```

In another shell:

```sh
chancery agent revoke fs-bot     # terminal; takes effect on the NEXT call
```

The agent's next tool call is blocked instantly, cited to the registry
layer. Then prove the record is evidence, not logs:

```sh
chancery audit verify            # "audit chain intact: N events verified"
```

## What just happened

- The agent held **no credential** — if the server needed one you'd
  `chancery secret put` it and inject with `--secret`, into the server's
  environment, never the agent's.
- Every decision is attributed to the agent, its version digest, its
  instance, and the writ's full lineage — queryable in `chancery audit`.
- Revocation was one command and bound on the next action, not on token
  expiry.

Next: [concepts](docs/concepts.md) · [examples](examples/) ·
[design RFCs](rfcs/) · [security posture](SECURITY.md).
