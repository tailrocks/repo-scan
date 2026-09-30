# repo-scan

Deterministic, resource-conscious discovery of local copies of a GitHub repository.
Given a repository URL, `repo-scan` finds matching clones, worktrees, and bare stores,
inspects branches and working state, and writes a JSON report a recovery agent can consume.

Spec: [repo-scan-spec.md](/Users/donbeave/Projects/repo-scan/repo-scan-spec.md).
Adversarial command-path review: [docs/REVIEW_WF4.md](/Users/donbeave/Projects/repo-scan/docs/REVIEW_WF4.md).

## Install / build

Requires a Rust toolchain (stable) and, on macOS, Xcode command-line tools.

```sh
cargo build --release
# binary: target/release/repo-scan
```

No runtime dependencies: no LLM, cloud service, daemon, GUI, or TUI. Installed Git is
an optional compatibility backend only. Locked deps: `turso =0.8.1`, `dua-core =4.1.0`,
`gix =0.88.0` ([Cargo.toml](/Users/donbeave/Projects/repo-scan/Cargo.toml:19)).

## Test

```sh
cargo test            # unit + acceptance suites in tests/
cargo bench --bench walk_compare   # adapter equivalence (fails on mismatch)
cargo bench --bench scan_cycle     # traversal / cached-query / invalidate / resume
```

Details and results discipline: [docs/BENCHMARKS.md](/Users/donbeave/Projects/repo-scan/docs/BENCHMARKS.md).

## Usage: the six commands

```sh
# Discover matching copies and produce a report.
repo-scan scan https://github.com/OWNER/REPO \
  --scope machine \
  --report repository-report.json

# Query the catalog immediately, with freshness information (never scans).
repo-scan query https://github.com/OWNER/REPO --cached

# Continue unfinished work (restores saved options; cwd-independent).
repo-scan resume SCAN_ID

# Fresh traversal generation (old findings stay provisional until replaced).
repo-scan scan https://github.com/OWNER/REPO \
  --scope machine --force-rescan

# Rescan one area (durable; next scan/resume reconciles it).
repo-scan cache invalidate --root /private/var/folders

# Clear only this tool's saved state (foreign files preserved).
repo-scan cache clear --all
```

Exit codes: `0` success (zero matches is still success), `1` operational failure,
`2` invalid arguments, `3` usable result with unresolved gaps / no suitable catalog /
superseded resume, `130` interrupted after bounded progress save.

## Options

- `--state-dir PATH` (global): tool state location. Default on macOS is
  `~/Library/Application Support/repo-scan`; elsewhere `$XDG_STATE_HOME/repo-scan`
  or `~/.local/state/repo-scan`. Resolved to an absolute path once
  ([src/config.rs](/Users/donbeave/Projects/repo-scan/src/config.rs:148)). Layout:
  `instance.lock` (coordination, never deleted) + `payload/` (database, snapshots).
- `--status metadata|summary|full` (scan only, default `summary`): working-state
  depth. `metadata` skips status probes; `summary` collapses each untracked directory
  to one entry; `full` counts individual untracked files. Status never narrows
  discovery; unknown counts stay `null`, never zero.
- `--root PATH` (scan only, repeatable): scan exactly these paths (recorded as
  `roots` scope) instead of `--scope machine`.
- `--report PATH`: JSON report destination, resolved absolute at request creation and
  written atomically. Without it, a readable terminal summary goes to stdout and the
  versioned snapshot is retained in state. Progress/diagnostics always use stderr.

## Docs

- [docs/BENCHMARKS.md](/Users/donbeave/Projects/repo-scan/docs/BENCHMARKS.md) — reproducible bench commands + results tables.
- [docs/TROUBLESHOOTING.md](/Users/donbeave/Projects/repo-scan/docs/TROUBLESHOOTING.md) — lock contention, empty catalog, unsafe state dir, interrupted scans.
- [docs/CHECKLIST.md](/Users/donbeave/Projects/repo-scan/docs/CHECKLIST.md) — acceptance-ID traceability with test evidence.
- [docs/ARCHITECTURE.md](/Users/donbeave/Projects/repo-scan/docs/ARCHITECTURE.md), `docs/*_QUAL.md` — design and dependency qualification.
