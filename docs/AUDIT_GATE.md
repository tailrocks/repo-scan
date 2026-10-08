# Dependency-audit policy (RSF-SEC-AUDIT-GATE)

Status: NOT ENFORCED BY GITHUB ACTIONS. The workflow specification at
`docs/workflows/audit.yml` is outside GitHub's recognized
`.github/workflows/` directory. `tests/sec_audit_gate.rs` checks the
specification's contents, but that does not schedule or run the workflow.
Do not treat an `audit` status check as active until the audit is wired into a
supported workflow and a live run confirms it. The intended policy fails on
any RUSTSEC advisory affecting the locked graph, any unlicensed dependency,
or any dependency from an unknown registry/git source.

## 1. Intended workflow

Workflow: [docs/workflows/audit.yml](workflows/audit.yml)

- Triggers: `push`, `pull_request`, weekly cron (`0 6 * * 1`).
- Permissions: `contents: read` only. No `pull_request_target`,
  caches, artifacts, or secrets.
- Actions are pinned to full commit SHAs (version noted in a
  trailing comment), not floating tags:
  `actions/checkout@11bd719…` (v4.2.2),
  `dtolnay/rust-toolchain@6bed07…` (1.85.0).
- Runner image and toolchain are pinned exactly (`ubuntu-24.04`,
  Rust `1.85.0`); audit tools install at exact versions with
  `--locked` (`cargo-audit 0.22.1`, `cargo-deny 0.18.3`).
  RS-CI-01 residual: a GitHub-hosted `runs-on` label takes no digest,
  so byte-immutability of the runner image is an owner action (move
  the job to a self-hosted or container runner pinned by digest).
  Until then the provenance step records the exact image version
  (`$ImageOS`/`$ImageVersion` plus `/etc/os-release`) with every run,
  so an image change is visible in the log, not silent.
  Expected crates.io sha256 digests are recorded in workflow
  comments and enforced by a `Verify pinned tool archives` step
  that downloads each `.crate` from `static.crates.io` and
  compares its sha256 before installation, failing closed on
  mismatch (in addition to `cargo install` verifying against
  the registry index).
- Checkout persists no credentials (`persist-credentials: false`)
  and a follow-up step fails closed if any
  `http.https://github.com/.extraheader` remains. Tool
  installation runs outside the checkout (`${{ runner.temp }}`)
  with per-run isolated `CARGO_HOME`/`CARGO_TARGET_DIR`, so
  PR-controlled `.cargo/config.toml` (wrappers, source
  replacement, `[env]`) cannot execute during compilation. Audit
  steps invoke the installed binaries directly with explicit
  lockfile/manifest paths and never compile repository code.
- A provenance step runs after the audits (`if: always()`, so a
  failing audit is still attributed) and records `rustc`
  (`--version --verbose`, including the toolchain commit hash),
  `cargo-audit`, and `cargo-deny` versions, the sha256 of the two
  installed audit binaries, the `Cargo.lock` sha256, the runner
  image version (`$ImageOS`/`$ImageVersion`, `/etc/os-release`),
  the source OID (`source_oid=$GITHUB_SHA` plus
  `git rev-parse HEAD`), and the advisory-database revision
  (`git rev-parse HEAD` in the fetched checkout under
  `$CARGO_HOME/advisory-db` or `$CARGO_HOME/advisory-dbs`, failing closed when absent). The
  advisory database is fetched live on each run (the weekly
  cron consumes current advisories); the pinned tool versions
  plus the lockfile hash and the recorded revisions bind each
  result to an exact input set.
- Bounded execution: `timeout-minutes: 20` on the job and a
  workflow `concurrency` group that cancels superseded runs. A
  timeout or cancellation is an incomplete audit, never a pass.

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
`deny.toml` exist with this enforced shape (triggers, exact-SHA
action allowlist, exact tool pins, `.crate` archive verification,
source-OID plus advisory-DB provenance, no persisted credentials,
isolated installs, timeout plus concurrency cancellation,
minimal permissions, both tools `--locked`, all three policy
sections).

## 2. Trust boundary and branch protection (CI-SC-03)

Current status: deferred. GitHub does not discover
`docs/workflows/audit.yml`, and the generated
`.github/workflows/ci.yml` has no `audit` job. No `audit` status
exists to require. Revisit the following owner actions only after an
audit workflow is generated under `.github/workflows/` and a live run
confirms its exact status on pull requests.

Planned external owner actions (GitHub settings — not verifiable from
this repository):

1. Settings → Branches → branch protection rule for the base
   branch: Require the `audit` status check before merging, but only
   after the workflow is generated and a live run confirms that exact
   job. Do not accept PR-tree renames or replacement jobs.
2. Same rule: require pull-request review (dismiss stale reviews
   on push) so workflow and policy edits get owner review.
3. Enforce action SHA pinning at repository or organization
   level (action allowlists where supported).

The workflow, policy, and regression test are PR-tree content, so a
pull request can propose changes to the policy it would be checked
against. The intended workflow has tamper-evident regression checks:
`tests/sec_audit_gate.rs` asserts its documented shape. That test is a
regression tripwire, not a security boundary, and does not prove GitHub
schedules the workflow. Until the audit workflow is live and the base
branch requires its exact status, this repository has no enforced
audit gate; do not treat a missing or green unrelated status as audit
evidence. A base-controlled reusable workflow would remove the
PR-tree trust dependency.

RS-CI-02 quarantine: the current absence of an `audit` status means
merges carry no audit-gate evidence. After activation, any merge while
the check is failing, pending-and-bypassed, or absent (admin merge,
unprotected base, renamed job) also carries no audit evidence for its
tree. Quarantine such trees before release: rerun the gate on the
exact merged commit on the protected base and reconfirm the policy
and workflow files are byte-identical to a reviewed revision; policy
or workflow edits merged under bypass get owner review regardless of
content.

`dtolnay/rust-toolchain` downloads `https://sh.rustup.rs` only as a
fallback when rustup is absent; the pinned `ubuntu-24.04` runner
image ships rustup, so qualification runs do not exercise that
unpinned fallback.

## 3. Intended execution budget and resources (CI-SC-04)

- Job wall-clock: `timeout-minutes: 20` (the two `--locked` tool
  installs dominate; well under the bound on a warm runner).
- Concurrency: one live `audit` run per PR/branch; superseded
  runs cancel automatically. Push, PR, and weekly triggers share
  the same bound.
- Per-run state only: `CARGO_HOME`/`CARGO_TARGET_DIR` live under
  the runner temp dir and are discarded with the run; no caches
  or artifacts persist between runs.
- Network during the run is limited to the crates.io registry,
  the RustSec advisory database, and (cold toolchain only) rustup
  static hosting. The audit steps only read
  `Cargo.toml`/`Cargo.lock`/`deny.toml` plus advisory metadata;
  they compile nothing.

## 4. Run locally (no CI needed)

```sh
cargo install cargo-audit --version 0.22.1 --locked && cargo audit --deny warnings
cargo install cargo-deny --version 0.18.3 --locked && cargo deny --locked check licenses sources
```

Both commands read `Cargo.lock` at the repo root; neither modifies it.

## 5. Maintenance

- Bump a pinned action SHA only to a reviewed upstream commit,
  updating the trailing version comment, this doc's pin list,
  and the exact-SHA allowlist in `tests/sec_audit_gate.rs` in
  the same hunk.
- Bump tool/toolchain/runner pins together (workflow, this doc,
  and the regression-test needles); record the new crates.io
  checksums from the registry API in the workflow comments and
  the `Verify pinned tool archives` expectations.
- A new advisory/source/license failure is fixed by upgrading or
  replacing the dependency, not by widening the policy; any
  `deny.toml` exception needs an owner call with the advisory ID
  and expiry recorded inline.
