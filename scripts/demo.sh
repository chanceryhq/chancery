#!/usr/bin/env bash
# The 60-second demo (RFC-010 §5), self-contained and CI-runnable:
# an agent works, is revoked mid-task, is blocked on its next call,
# and the hash-chained timeline attributes everything.
set -euo pipefail

CHANCERY="${CHANCERY:-./chancery}"
export CHANCERY_DATA="$(mktemp -d)"
trap 'rm -rf "$CHANCERY_DATA"' EXIT

step() { printf '\n\033[1m── %s\033[0m\n' "$*"; }

step "0. A fresh control plane (one binary, one command)"
"$CHANCERY" init --trust-domain acme.com | head -1

step "1. Register the agent: owner, purpose, content-addressed version"
"$CHANCERY" agent register deploy-bot \
  --owner user:aneesh@acme.com --purpose "deploys services" \
  --prompt "You deploy things safely." --model claude-fable-5

"$CHANCERY" agent register test-runner \
  --owner user:aneesh@acme.com --purpose "runs tests" \
  --prompt "You run tests." --model claude-haiku-4-5 >/dev/null

step "2. Grant a writ: named human authority, scoped capabilities, TTL"
GRANT=$("$CHANCERY" writ grant --for user:aneesh@acme.com --to deploy-bot \
  --cap "call:github/*" --ttl 1h)
echo "$GRANT"
WRIT=$(echo "$GRANT" | awk '/^writ /{print $2}')

step "3. Delegate to a sub-agent — authority can only narrow"
"$CHANCERY" writ delegate "$WRIT" --to test-runner --caveat "call:github/get_*" --ttl 30m

step "4. The sub-agent works (ALLOW, with full lineage)"
"$CHANCERY" writ check "$WRIT" --resource github/get_pull_request

step "5. It tries something the parent could do but it was never granted (DENY)"
"$CHANCERY" writ check "$WRIT" --resource github/create_release

step "6. INCIDENT: revoke the writ mid-task — one command"
"$CHANCERY" writ revoke "$WRIT"

step "7. The very next call is blocked, with the reason"
"$CHANCERY" writ check "$WRIT" --resource github/get_pull_request

step "8. The timeline: which agent, which version, under whose authority"
"$CHANCERY" audit --limit 8

step "9. And it's evidence, not logs"
"$CHANCERY" audit verify

printf '\n\033[1mEvery decision above is in-path, attributed, and tamper-evident.\033[0m\n'
printf 'Wrap a real MCP server the same way:\n'
printf '  chancery mcp wrap --agent deploy-bot --writ <id> -- npx <mcp-server>\n'
