# Perseus Vault behind Chancery — provable authority + provable content

[Perseus Vault](https://github.com/Perseus-Computing-LLC/perseus-vault)
is a deterministic, bi-temporal memory store behind MCP whose reads and
writes are crypto-chained. Chancery governs *who may call what, under
whose authority*; Perseus proves *what was actually read or written*.
Composed, you get end-to-end verifiable provenance:
authority → action → content → verification.

The canonical, maintained writ config lives in the Perseus repo:
[integrations/chancery/writ-config.md](https://github.com/Perseus-Computing-LLC/perseus-vault/blob/main/integrations/chancery/writ-config.md).
This example is the Chancery-side summary.

## The reader/writer split

Perseus exposes ~60 tools; an agent that only needs recall should not
be able to write. Two writs, not roles — delegation that can only
narrow (RFC-002):

```sh
# Reader: the six read-shaped tools
chancery writ grant --for user:admin@acme.com --to memory-reader \
  --cap "call:perseus/perseus_vault_get_entity" \
  --cap "call:perseus/perseus_vault_scan" \
  --cap "call:perseus/perseus_vault_context" \
  --cap "call:perseus/perseus_vault_recall" \
  --cap "call:perseus/perseus_vault_as_of" \
  --cap "call:perseus/perseus_vault_bitemporal" \
  --ttl 8h --task "project memory recall"

# Writer: separate identity, narrower TTL
chancery writ grant --for user:admin@acme.com --to memory-writer \
  --cap "call:perseus/perseus_vault_remember" \
  --cap "call:perseus/perseus_vault_forget" \
  --cap "call:perseus/perseus_vault_prune" \
  --ttl 4h
```

## Enforce

```sh
# Preflight first — prints the effective authority, spawns nothing:
chancery mcp wrap --agent memory-reader --writ <reader-writ-id> \
  --server-name perseus --dry-run -- perseus-vault serve

chancery mcp wrap --agent memory-reader --writ <reader-writ-id> \
  --server-name perseus -- perseus-vault serve
```

Write tools are denied before they reach Vault, `tools/list` is
filtered so the model never sees them, and revoking a writ kills
access on the next call — mid-session, no restart. The first wrap pins
the `perseus-vault` binary (RFC-016); upgrades go through
`chancery mcp repin perseus -- perseus-vault serve`.

## Audit chains that reference each other (planned)

Chancery's authority events are hash-chained; Perseus's content events
are crypto-chained. The planned cross-reference keeps them independent
(either works with the other down) but walkable in both directions:
Chancery records a `perseus_audit_hash`, Perseus records the
`chancery_writ_id`. Tracked in
[chancery#6](https://github.com/chanceryhq/chancery/issues/6) — see
the integration doc above for the spec draft.
