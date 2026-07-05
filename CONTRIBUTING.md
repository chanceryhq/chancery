# Contributing to Chancery

Chancery is open-core infrastructure (Apache-2.0). This guide covers
building it, running and understanding the tests, the repo layout, and
how changes are proposed. If you just want to *use* Chancery, start with
the [README](README.md) and [QUICKSTART](QUICKSTART.md).

## Prerequisites

- **Go 1.26+** (see `go.mod`). No CGO — Chancery builds as a single
  static binary; the SQLite driver is pure Go (`modernc.org/sqlite`).
- That's it for the core. Optional, only for release work: `goreleaser`,
  `cosign`, `syft`, Docker.

## Build

```sh
git clone https://github.com/chanceryhq/chancery && cd chancery
make build          # -> ./chancery
./chancery --version
```

`make build` is just `go build -o chancery ./cmd/chancery`. Cross-
compiling is a plain `GOOS`/`GOARCH` away because there's no CGO.

## Run the tests

```sh
make test           # go vet ./... && go test ./...
```

- Runs in a few seconds; every test uses a temp dir or an in-memory
  httptest server, so **nothing touches your real `~/.chancery`**.
- The end-to-end proxy test (`cmd/chancery/wrap_integration_test.go`)
  compiles a small child MCP server and the `chancery` binary and drives
  a real stdio session. It builds subprocesses, so skip it in a hurry:

  ```sh
  go test -short ./...
  ```

- Run one package's tests with verbose output while developing:

  ```sh
  go test -v ./internal/writ/
  ```

### Try the whole product in 60 seconds

```sh
make demo           # scripted: grant -> delegate -> allow -> revoke -> deny -> verify
```

`make demo` runs `scripts/demo.sh` against a throwaway data dir and prints
the full enforcement + audit arc. It's the fastest way to see everything
work end to end, and it's what the README's "60-second story" refers to.

## How the tests map to the design

The tests are organized to prove the RFC each package implements — a
good way to learn the codebase is to read a package's `*_test.go`
alongside its RFC. 72 test functions across 10 packages:

| Package | Implements | The tests prove |
|---|---|---|
| `internal/store` | RFC-001, 006, 007 | three-layer revocation, append-only versions, lifecycle state machine (legal + illegal transitions), audit hash-chain + tamper detection |
| `internal/identity` | RFC-001 | ES256 issue/verify, TTL ceiling, key persistence, and the adversarial set: `alg:none` + HS256 key-confusion rejected (RFC-009) |
| `internal/writ` | RFC-002 | effective authority = grant ∩ caveats, **widening is unrepresentable**, TTL monotonicity, depth bound, tamper/splice/cross-writ rejection |
| `internal/policy` | RFC-004, 012 | capability grammar validation + match semantics, layered PDP (only the writ grants), empty-list vs `!none` sentinel, `admin` verb + `Implies` subsumption |
| `internal/seal` | RFC-003 | AEAD roundtrip, no plaintext on disk, name-bound (cross-name swap rejected), wrong-key/tamper fail-closed |
| `internal/mcp` | RFC-005 | tools/call allow/deny, tools/list filtering, malformed-frame handling, deny-on-audit-failure |
| `internal/service` | RFC-004, 008, 012 | the shared CLI+API path end-to-end; shadow-agent (`agent.unregistered_ref`) observation; writ-gated spawn (template ceiling, TTL cap, refusal audit, lazy expiry + sweep) |
| `internal/api` | RFC-008, 012 | httptest full flow, auth rejection, DENY-as-HTTP-200, terminality over the wire, token never in audit; tokenless writ-gated `/v1/spawn` |
| `sdk` | RFC-010 | the Go SDK against a real control plane (advisory Guard/Guarded) |
| `cmd/chancery` | RFC-005 | the `mcp wrap` binary driving a real child MCP server, incl. mid-session revocation + audit integrity |

## Repo layout

```
cmd/chancery/        the CLI (thin client over internal/service)
internal/
  store/             registry: agents, versions, instances, writs, audit (SQLite; schema is the contract)
  identity/          ES256 identity documents (RFC-001)
  writ/              the writ: signed attenuating delegation chains (RFC-002)
  seal/              sealed credential store (RFC-003)
  policy/            capability grammar + layered PDP (RFC-004)
  mcp/               the stdio enforcement proxy (RFC-005)
  service/           the single implementation shared by CLI and API (RFC-008)
  api/               REST/JSON /v1 control-plane surface (RFC-008)
sdk/                 Go SDK — advisory ergonomics over the API
examples/            claude-code (.mcp.json), go-agent, langgraph
rfcs/                every design decision, argued and locked (000–012)
scripts/demo.sh      the 60-second demo
```

The CLI and the HTTP API are both thin clients over `internal/service`
(RFC-008): put shared logic there, not in `cmd/` or `api/`.

## Conventions

- **Every design decision is an RFC.** Non-trivial changes to behavior
  should reference (or propose) an RFC in `rfcs/` — see
  [`rfcs/TEMPLATE.md`](rfcs/TEMPLATE.md). Bug fixes and small
  improvements don't need one.
- **`gofmt` and `go vet` are clean** on every commit (`make test` runs
  vet). No lint config beyond the standard toolchain.
- **Tests encode invariants, not just coverage.** A change that relaxes
  a security property (e.g. makes widening representable, or stores a
  payload) should fail an existing test — if it doesn't, the test was
  missing. Add it.
- **Two structural invariants are non-negotiable** (RFC-000 D6, RFC-002):
  payloads/prompts/tool-arguments are never stored (the audit schema has
  no column for them), and delegated authority can only narrow. Don't
  send a change that breaks either.

## Proposing a change

1. Open an issue or discussion first for anything non-trivial.
2. Fork, branch, make the change with tests, `make test` green.
3. Open a PR. Sign your commits off with the
   [DCO](https://developercertificate.org/) (`git commit -s`) — Chancery
   uses **DCO, not a CLA** (RFC-011): Apache-2.0 in, Apache-2.0 out, no
   rights assignment.

## Security

Do not open public issues for vulnerabilities — use GitHub private
vulnerability reporting (repo Security tab). See [SECURITY.md](SECURITY.md)
for the threat model and the honest list of known MVP gaps.
