# Launch checklist (v0.1.0)

The release pipeline is built and **proven** — a private `v0.0.1` dry-run
on 2026-07-05 built all artifacts, signed them (cosign `verify-blob` →
Verified OK), and pushed the Homebrew cask. This is the go-live runbook.
Do NOT tag before the gates below are met (RFC-010: ship at ~week 12,
after real users).

## Gates before tagging (must all be true)

- [ ] **3 external users** have run `chancery mcp wrap` in a real
      workflow and given feedback (RFC-010 §4 item 9). This is the real
      gate; the product is ready, distribution is not.
- [ ] Demo recorded: `asciinema rec`, running `make demo`, < 90s, embedded
      in the README (RFC-010 §5). The single best conversion asset.
- [ ] `QUICKSTART.md` re-run start-to-finish on a clean machine or in
      Docker — the 5-minute claim must be literally true.

## One-time settings (do once, before the first public release)

- [ ] **Allow public packages in the org:**
      github.com/organizations/chanceryhq/settings/packages → Package
      creation → enable **Public**. (Currently disabled org-wide, which is
      why the dry-run image is private.)
- [ ] **Buy chancery.dev** (~$12) before the launch post — the name goes
      fully public at launch and squatters watch launches. Point it at the
      GitHub Pages docs (custom domain, zero content change).
- [ ] **Enable GitHub Pages:** repo Settings → Pages → Deploy from branch
      → `main` / `/docs`.
- [ ] **Enable private vulnerability reporting:** repo Settings → Security
      → enable (SECURITY.md already directs reporters there).

## Cut the release

- [ ] Confirm `main` is green in CI.
- [ ] `git tag v0.1.0 && git push origin v0.1.0`
- [ ] Watch the release workflow to green (`gh run watch`).
- [ ] Verify artifacts:
      - `gh release view v0.1.0` — 4 binaries, 4 SBOMs, checksums, `.sig`, `.pem`
      - `cosign verify-blob` per the release footer → **Verified OK**
      - `brew install chanceryhq/tap/chancery && chancery --version`
      - **Make the v0.1.0 ghcr image public** (Packages → chancery →
        settings → visibility → Public), then `docker pull` to confirm.

## Announce (only after the release is verified)

- [ ] Show HN: *"Show HN: Chancery – open-source identity & revocation for
      AI agents (MCP)"* — lead with the problem (agents on shared,
      unrevocable tokens), link the demo, be in the thread all day.
- [ ] MCP community / Discord, r/selfhosted, r/LocalLLaMA, lobste.rs.

## Known follow-ups (not blockers)

- The `cosign verify-blob` command in the release footer uses flags newer
  cosign marks deprecated (`--certificate`/`--signature`); it still
  verifies. Modernize to `--bundle` when convenient.
- ghcr image cosign signing is deferred until the `dockers_v2` signing
  surface stabilizes; binaries + checksums are signed (RFC-009).
