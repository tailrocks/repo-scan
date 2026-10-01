# Dependency-audit gate (RSF-SEC-AUDIT-GATE)

Status: ENFORCED. `.github/workflows/audit.yml` runs on every push
and pull request (plus a weekly schedule for advisories that land
between pushes). It fails the run on any RUSTSEC advisory affecting
the locked graph, any unlicensed dependency, or any dependency from
an unknown registry/git source.

## 1. Enforcement

Workflow: [.github/workflows/audit.yml](../.github/workflows/audit.yml)

- Triggers: `push`, `pull_request`, weekly cron (`0 6 * * 1`).
- Permissions: `contents: read` only.
- Actions are pinned to full commit SHAs (version noted in a
  trailing comment), not floating tags:
  `actions/checkout@11bd719…` (v4.2.2),
  `dtolnay/rust-toolchain@6bed07…` (stable).
- Steps: `cargo install cargo-audit --locked` then
  `cargo audit --deny warnings` (fails on vulnerabilities,
  unmaintained, unsound, and yanked advisories); `cargo install
  cargo-deny --locked` then `cargo deny check --locked`
  (advisories + licenses + sources per `deny.toml`, asserting
  `Cargo.lock` stays unchanged).

Policy: [`deny.toml`](../deny.toml) (repo root)

- `[advisories]`: vulnerability/unmaintained/unsound/yanked deny,
  notice warns.
- `[licenses]`: unlicensed denies; permissive allowlist
  (MIT/Apache-2.0/BSD/ISC/Zlib/Unicode/MPL-2.0 and close kin);
  copyleft warns. `[licenses.private] ignore = true`: the policy
  governs third-party dependencies, not the unpublished root crate.
- `[sources]`: only the crates.io registry index is allowed
  (`unknown-registry`/`unknown-git` deny), matching the current
  `Cargo.lock`, where every package resolves from
  `registry+https://github.com/rust-lang/crates.io-index`.

Regression test: `tests/sec_audit_gate.rs` asserts the workflow and
`deny.toml` exist with this enforced shape (triggers, pinned SHAs,
minimal permissions, both tools `--locked`, all three policy
sections).

## 2. Run locally (no CI needed)

```sh
cargo install cargo-audit --locked && cargo audit --deny warnings
cargo install cargo-deny --locked && cargo deny check --locked
```

Both commands read `Cargo.lock` at the repo root; neither modifies it.

## 3. Maintenance

- Bump a pinned action SHA only to a reviewed upstream commit, and
  update the trailing version comment in the same hunk.
- A new advisory/source/license failure is fixed by upgrading or
  replacing the dependency, not by widening the policy; any
  `deny.toml` exception needs an owner call with the advisory ID
  and expiry recorded inline.
