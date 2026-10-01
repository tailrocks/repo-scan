# CI

## Provenance

`.github/workflows/ci.yml` and `.github/actionlint.yaml` are **hand-written
but velnor-shaped**, per `/tmp/velnor-gen.md` §3 (fallback specification; the
`§3.x` references below point at it). Real velnor generation is blocked: no
official `velnor-actions` release exists yet, so `velnor-actions plan` and
`velnor-actions generate` fail closed with
`consumer_requires_release_install` (§2). `init` was deliberately not run and
no `.velnor/config.toml` was created, so a future `velnor-actions init` still
starts from a clean slate.

Everything that could be taken verbatim from the generated shape was (§3.1):
workflow header (triggers, permissions, concurrency), `ubuntu-26.04` runner,
explicit `timeout-minutes`, full-SHA action pins, catalog tool versions, the
per-step env discipline (isolation quartet + install-disable pair + owned
homes + `RUSTUP_TOOLCHAIN` + blanked credential keys), and the cargo-form
obligation argv. Dropped: everything that needs the velnor binary at runtime
(§3.2 — Acquire Velnor, Plan/Merge, report artifacts, `covered_tasks` gates),
so all obligations run unconditionally. One noted deviation is commented
inline in `ci.yml`: `rust-cache` uses `save-if: "true"` because there is no
velnor plan job to own the shared-key save.

`.github/workflows/audit.yml` is untouched and coexists with `ci.yml` (§3.3.1).

## Jobs

| Job id     | Display           | Runs on      | Timeout | Steps                                              |
|------------|-------------------|--------------|---------|----------------------------------------------------|
| `actionlint` | Actionlint      | ubuntu-26.04 | 10 min  | Checkout, Setup Mise, actionlint over the tree     |
| `rust`     | Rust / repo-scan  | ubuntu-26.04 | 30 min  | Checkout, Setup Mise, pinned tools, rustup comps, rust-cache restore, fetch, Format, Clippy, Build, Tests, Doctests, Documentation |
| `macos`    | macOS / repo-scan | macos-15     | 30 min  | Checkout, pinned toolchain (dtolnay, cf. audit.yml), Clippy, Test, provenance |
| `required` | Required          | ubuntu-26.04 | 10 min  | Verdict from `needs.*.result` (`if: always()`)     |

Tool pins (velnor's qualified pins): checkout v7.0.1, mise-action v5.0.0,
rust-cache v2.9.2, mise 2026.9.18, rust 1.98.1, actionlint 1.7.12,
shellcheck 0.11.0, zizmor 1.30.1. Plain `cargo`/`cargo test` — no mbx, no
nextest (§3.3.3); default features only (§3.3.4); `rustfmt.toml` and
`.cargo/config.toml` honored automatically (§3.3.5–6).

## Required-check migration (human admin)

Branch protection must require **both**:

- `Required` — the `required` job in `ci.yml` (sole gate for this workflow).
- `audit` — the existing audit gate (`docs/AUDIT_GATE.md`); velnor has no
  consumer-side deny/audit equivalent, so it stays a separate required check.

Procedure (§1 Step 6): merge so `ci.yml` exists on `main`, let one run
complete so the `Required` check appears
(`gh run list --workflow ci.yml --branch main`), then in branch protection
require `Required` (and keep `audit`). The admin step cannot be automated.

## Why a macOS job (§3.3.2)

Velnor V1 is Linux-x64-only, but repo-scan is macOS-first: the
`objc2-core-services`/`dispatch2` FSEvents backends, `libc` getfsstat paths,
and cfg-gated modules under `src/platform/` and `src/walk/` get zero coverage
from an Ubuntu run — worse, `cargo build` on Linux silently compiles the macOS
backends out, so green Linux CI would prove nothing about them. The `macos`
job (clippy + test on `macos-15`) closes that gap. It is deliberately
non-velnor-faithful — velnor-faithful would be "no macOS job", which is wrong
for this repo. No velnor pin exists for any of it, so it uses the repo's
existing pinned toolchain approach (`dtolnay/rust-toolchain@6bed0761…`,
same as `audit.yml`) with the same provenance recording.

## Migration path back to real velnor (§3.5)

When the first official `velnor-actions` release lands:

1. Install the official release; commit `.velnor/config.toml` (`schema = 1`,
   `[workflow] default_branch = "main"` — required here because the repo has
   no `origin/HEAD`) plus the byte-identical official
   `.velnor/release-manifest.json`.
2. Preview: `velnor-actions generate --output-dir <fresh dir outside the repo>`
   (on macOS, not under symlinked `/tmp`), then `diff -r` against `.github`.
   Resolve the `audit.yml` deletion deliberately: either velnor has a consumer
   audit story by then, or re-apply `audit.yml` after each generate and
   document the drift.
3. In-place `generate`. The hand `macos` job cannot live inside velnor's
   whole-tree-owned `.github`: until velnor supports macOS runners, either
   re-apply it as a second workflow file after each generate (same drift
   problem as `audit.yml`) or drop it with explicitly reduced coverage.
   Record whichever is chosen.
4. Run the required-check migration (§1 Step 6 / above).
