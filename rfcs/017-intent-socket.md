# RFC-017: Task-Bound Grants and the Intent Socket

- **Status:** In Review
- **Author:** Aneesh Gupta
- **Created:** 2026-07-16
- **Depends on:** RFC-002, RFC-004, RFC-005, RFC-006
- **Blocks:** —

## 1. Problem

The gate runs five checks per call — agent alive (registry), request
well-formed (grammar), action inside the grant (writ), operator
allow-list, decision recorded (audit). All hard yes/no rules.

A case that passes all five: a db MCP server, never swapped, called by
an agent whose writ covers `call:db/query` — handed a destructive
query it is fully capable of running. Capability says yes, integrity
(RFC-016) says yes, but the user only asked it to read some numbers.

Two precise gaps:

1. **The gate never looks inside the call.** The writ check sees the
   tool name, not the SQL in the arguments (sole exception: the
   RFC-013 URL guard).
2. **Grants don't know why they exist.** Agents have a purpose; writs
   don't carry a task. A grant says what is allowed, never what it was
   for.

## 2. Existing approaches and why they fall short

- **CASA (Outshift/Cisco)** and the TBAC literature do semantic
  task-to-call matching with embeddings/LLM judges — the right idea at
  the wrong layer for us: probabilistic verdicts inside a gate that
  promises determinism poison the promise.
- **Prompt-injection guards** are detectors without an actuator: they
  write reports; nothing enforces them in-path.
- **Manual per-call approval** does not scale and trains humans to
  click yes.

## 3. Alternatives considered

1. **Build semantic matching into Chancery.** Breaks the actuator/
   detector split (RFC-000); we would ship a mediocre detector and a
   compromised promise.
2. **Argument-pattern caveats in the writ grammar.** Deterministic but
   combinatorially awkward; punts the real question (intent) into
   regexes.
3. **Task on the grant + a pluggable per-call checker (chosen).**
   Chancery owns the context and the socket; detectors own the
   judgment; the audit trail owns the distinction.

## 4. Decision

**Task-bound grants.** `writ grant --task "review PR #123"` stores the
declared purpose (≤200 chars, metadata not prompt) on the writ. It
appears in `writ.grant` audit reasons, the API, and the dashboard, and
is handed to intent checkers — the one thing a checker cannot infer.

**The intent socket.** `mcp wrap --intent-check <cmd-or-url>` adds a
sixth decision layer, consulted only after all deterministic layers
allow:

- The checker receives `{"agent","task","tool","args"}` — JSON on
  stdin for commands, POST body for http(s) URLs — and answers
  `{"decision":"ALLOW"|"DENY","reason":"..."}` within
  `--intent-timeout` (default 1s).
- **Veto only:** final decision = deterministic layers AND checker. A
  checker can turn allow into deny, never the reverse.
- `--intent-mode enforce` (default): checker DENY blocks with -32001;
  checker failure (timeout, non-JSON, non-zero exit) also blocks —
  fail closed. `--intent-mode advise`: verdicts are recorded but calls
  proceed — how a checker is measured before it earns a veto.
- Audit: `mcp.intent_deny` for verdicts, `mcp.intent_error` for
  checker failure — a model's DENY and a broken checker are different
  facts. **Arguments pass through the checker transiently and are
  never stored**; the metadata-only invariant (RFC-006) holds.

## 5. Why

The socket makes anyone's detector *enforceable* instead of a report
generator, without Chancery vouching for its judgment: everything the
gate itself asserts stays deterministic, and a deny "by intent" is
labeled as a checker verdict in the trail. Pin proves the server
(RFC-016), writ bounds the call (RFC-002), checker judges the moment.

## 6. Trade-offs accepted

- The socket is only as good as the detector behind it; false
  negatives pass, false positives annoy. Advise mode exists to
  measure.
- Task strings are *declared* intent: a compromised orchestrator can
  declare a misleading task. Attenuation and template ceilings remain
  the hard bounds.
- An in-path checker adds its budget to every call; local commands
  keep it small.
- The checker sees arguments (it must). Operators point the socket at
  checkers they trust with payload; Chancery still never stores any.

## 7. Failure scenarios

- **Checker down, enforce mode:** all calls deny with
  `mcp.intent_error` — loud, fail closed, operator switches to advise
  or fixes the checker.
- **Checker compromised:** worst case in enforce mode is denial of
  service (veto-only); it cannot widen authority. It does see
  arguments — choosing the checker is choosing a payload processor.
- **Slow checker:** timeout applies; enforce denies, advise proceeds.

## 8. Security considerations

The checker runs with the operator's privileges under `/bin/sh -c` (or
is a remote endpoint); the operator chooses it exactly as they choose
the MCP server itself. Checker I/O is bounded (64 KiB responses).
Audit rows carry verdict/reason only — never `args`.

## 9. What gets built (MVP, this RFC)

- `task` column on writs; `--task` on grant; task in grant audit,
  API (`/v1/writs`), and dashboard.
- `IntentChecker` (command + http), proxy layer, `--intent-check` /
  `--intent-mode` / `--intent-timeout` on wrap.
- Audit events `mcp.intent_deny`, `mcp.intent_error`.
- Tests: veto blocks an allowed call; advise logs and proceeds;
  checker failure fails closed; the checker receives agent/task/tool/
  args; arguments never reach the audit trail.
