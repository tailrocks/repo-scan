# repo-scan

Deterministic, resource-conscious discovery of local copies of a GitHub repository.
Given a repository URL, `repo-scan` finds matching clones, worktrees, and bare stores,
inspects branches and working state, and writes a JSON report a recovery agent can consume.

Architecture & design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Adversarial command-path review: [docs/REVIEW_WF4.md](docs/REVIEW_WF4.md).
Behavior contracts: [docs/GOAL_CONTRACTS.md](docs/GOAL_CONTRACTS.md).

## Install / build

Requires a Rust toolchain (stable) and, on macOS, Xcode command-line tools.

```sh
cargo build --release
# binary: target/release/repo-scan
```

No runtime dependencies: no LLM, cloud service, daemon, GUI, or TUI. Installed Git is
an optional compatibility backend only. Locked deps: `turso =0.8.1`, `dua-core =4.1.0`,
`gix =0.88.0` ([Cargo.toml](Cargo.toml:45)).

## Test

```sh
cargo test            # unit + acceptance suites in tests/
cargo bench --bench walk_compare   # adapter equivalence (fails on mismatch)
cargo bench --bench scan_cycle     # traversal / cached-query / invalidate / resume
```

Details and results discipline: [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Usage

Four top-level commands. Every example below was executed against the debug
binary during the Wave4b docs pass; `--state-dir` points at a scratch
directory and `--root` at a fixture tree holding one clone plus one bare store.

```sh
BIN=./target/debug/repo-scan   # or target/release/repo-scan
SD=/tmp/demo-state             # scratch tool state (default: see --state-dir)
ROOT=/path/to/search           # directory tree to scan

# Discover matching copies of one repo and write a JSON report.
$BIN --state-dir $SD scan https://github.com/OWNER/REPO \
  --root $ROOT --report ./repository-report.json
# exit 0 on a complete scan, 3 when the result is usable but has
# unresolved gaps or pending work (still writes the report).

# Short target form; repeatable — one filesystem pass serves all targets.
$BIN --state-dir $SD scan OWNER/REPO --root $ROOT --format human

# Filesystem discovery with no GitHub target matching (no inventory first).
$BIN --state-dir $SD scan --all --root $ROOT --format human

# Fresh traversal generation (old findings stay provisional until replaced).
$BIN --state-dir $SD scan OWNER/REPO --root $ROOT --force-rescan

# Query the catalog immediately (never scans). --cached is required:
# live queries are not supported.
$BIN --state-dir $SD query https://github.com/OWNER/REPO --cached

# Reprint / replay one saved scan from retained bytes + journal.
$BIN --state-dir $SD query --scan SCAN_ID --format json
$BIN --state-dir $SD query --scan SCAN_ID --follow --format jsonl

# Serve the latest finished scan (any scope) in the requested format.
$BIN --state-dir $SD query --all --cached --format json

# Continue unfinished work (restores ALL saved options; cwd-independent).
$BIN --state-dir $SD resume SCAN_ID

# Rescan one area (durable; next scan/resume reconciles it).
$BIN --state-dir $SD cache invalidate --root /private/var/folders

# Clear only this tool's saved state (foreign files preserved).
$BIN --state-dir $SD cache clear --all
```

## Output formats

An explicit `--format` always wins. With no `--format`, `scan`,
`resume`, `query --scan`, and `query --all` print the live human view
on a terminal and replay the journal as JSONL when redirected.
`query TARGET --cached` prints the short human summary by default and
serves the resolved scan's retained snapshot/replay only on explicit
machine formats.

| Lane | Producer | Content |
|---|---|---|
| default, on a TTY | `scan` | legacy terminal report below + footers (never the TUI) |
| default, on a TTY | `resume` | legacy footers (`replayed`, `report_id`) |
| default, on a TTY | `query --scan`, `query --all` | plain `live_text` lane (no footers) |
| default, redirected | `scan`, `resume`, `query --scan`, `query --all` | journal replay (JSONL envelopes) |
| default | `query TARGET --cached` | short human summary (always) |
| `--format human` on a TTY | `scan`, `query --scan --follow` | interactive TUI (keys: `j`/`k`, `/`, `f`, `s`, `v`, `h`, `q`) |
| `--format human` redirected | `scan`, `resume` | plain `live_text` lane: header, coverage, totals, `R`/`C`/`B`/`?`/`!` rows (cap 200 + overflow line), then legacy footers |
| `--format human` | `query --scan`, `query --all` | plain `live_text` lane only (no footers) |
| `--format human` | `query TARGET --cached` | short human summary |
| `--format json` | `scan`, `query --scan`, `query --all`, `query TARGET --cached`, `resume` | one JSON document: the retained snapshot (report schema `1.4.0`), plus a trailing newline on stdout |
| `--format jsonl` | `scan`, `query --scan`, `query --all`, `query TARGET --cached`, `resume` | the scan journal replayed as event envelopes (event schema `1.0.0`) |

`--follow` works with `human` and `jsonl` only: `--follow --format json`
is rejected (exit `2`). `--after CURSOR` requires `--follow`. Machine
lanes (json/jsonl) emit serialized bytes only — no prose, no ANSI, no CR;
diagnostics and progress go to stderr.

### Default terminal report (observed, trimmed)

```text
repo-scan 0.1.0 report report-scan-189-1791375831472-1
target acme/demo (incomplete)
scan scan-189-1791375831472-1 generation 4 revision 5 cached=false status_mode=summary
coverage filesystem=complete identity=unproven status=incomplete dirs=33 pending=0 gaps=0 unresolvable=1
boundary: Only 1 explicit root(s) were requested; machine scope was not scanned.
repositories: 2
  [confirmed] /tmp/w4b-docs/roots/demo/.git common=... bare=false sha1
    evidence: Effective fetch remote `https://github.com/acme/demo.git` matches the target ...
checkouts: 2
  [present] /tmp/w4b-docs/roots/demo head=branch status=complete staged=0 unstaged=0 untracked=0 collapsed_entries
branches: 4
  [local] refs/heads/main f1d53eaf597f8019e55218d1e5b375806b965ad7
  ...
candidates: 1
errors: 0
scan_id: scan-189-1791375831472-1
generation: 4
report_id: report-scan-189-1791375831472-1
snapshot: /tmp/w4b-docs/state1/payload/report-snapshots/report-scan-189-1791375831472-1.json
```

### Human lane (observed, `--format human` redirected)

```text
scan scan-94472-1791375775866-1 state=incomplete scope=roots target=acme/demo
coverage filesystem=complete identity=unproven status=incomplete gaps=0 pending=0
totals repositories=2 checkouts=2 branches=4 remotes=4 candidates=1 errors=0
R git:2f7072... git-files match=confirmed /tmp/w4b-docs/roots/demo/.git
C co:2f746d... kind=main avail=present head=branch status=complete
B ref:2f7072...:726566732f... kind=local cmp=no_upstream ahead=- behind=- refs/heads/main
? cand:git:2f7072... unresolvable_identity identifying remotes removed ...
scan_id: scan-94472-1791375775866-1
generation: 2
report_id: report-scan-94472-1791375775866-1
snapshot: /tmp/w4b-docs/state1/payload/report-snapshots/report-scan-94472-1791375775866-1.json
```

Row prefixes: `R` repository, `C` checkout, `B` branch, `?` candidate,
`!` error record. `ahead=-`/`behind=-` render null counts.

### JSON document (observed shape)

`--format json` prints the retained snapshot: one object with
`schema_version: "1.4.0"` and these top-level keys (observed key set;
record vecs in full, elided here):

```text
schema_version report_id created_at tool scan coverage resources
volumes paths roots repositories checkouts branches remotes
storage_links aliases candidates errors generated_artifacts
```

A small fixture scan observed
`repositories=2 checkouts=2 branches=4 remotes=4 candidates=1 errors=0`
with `coverage.filesystem=complete`, `coverage.identity=unproven`,
`coverage.status=incomplete`, `gaps=0`, `unresolvable_candidates=1`.
Validate against [schemas/report-v1.4.schema.json](schemas/report-v1.4.schema.json).

### JSONL event stream (observed)

One envelope per line: `{schema_version:"1.0.0", scan_id, seq,
catalog_rev, type, op, records}`. A fixture scan emitted, in order:

```text
scan_started → discovery_progress → repository_found → coverage_updated
→ location_found → repository_found → location_found → inventory_ready
→ location_updated → branch_batch → branch_batch → scan_incomplete
```

Envelope classes: `scan_started`, `discovery_progress` (gauge, coalesced
to the newest payload), `location_found`, `repository_found`,
`inventory_ready`, `branch_batch`, `location_updated`,
`coverage_updated`, `error`, `remote_updated`, `scan_completed` /
`scan_incomplete` / `scan_interrupted` / `scan_failed`.
Terminal payloads carry `counts` + `generation` + `report_id` +
`resume_cmd`; re-delivery of a `seq` is idempotent (consumers dedupe by
`seq` and drop buffered state on `reset:true`).
Full contract: [docs/GOAL_CONTRACTS.md](docs/GOAL_CONTRACTS.md) D4.

## Counts

Counts are record vec lengths plus three independent coverage
properties. There is no top-level `totals` object and no `groups[]` in
report `1.4.0`: count the vecs (`repositories`, `checkouts`, `branches`,
`remotes`, `candidates`, `errors`) — the human `totals` line prints
exactly those lengths.

- `coverage.filesystem`: `complete` / `incomplete` / `unknown`.
- `coverage.identity`: `complete_under_policy` / `unproven`.
- `coverage.status`: `complete` / `incomplete` / `not_requested`
  (`not_requested` under `--status metadata`).
- `coverage.gaps` equals the `errors` vec length;
  `coverage.unresolvable_candidates` equals the `candidates` vec entries
  with `unresolvable_identity` disposition.
- Unknown counts are `null` (rendered `-` in the human lane), never zero;
  pre-analysis fields read `pending`. Terminal JSONL payloads repeat the
  compact form: `matched_per_target`, `pending`, `open_gaps`,
  `unresolvable`, `status_pending`, `event_gaps`.
- Never a percentage of the discovery total: the total is unknown until
  traversal completes, so progress reports pending counts and rates only.

## Remote freshness (`--fetch`)

Without `--fetch`, every probe is offline and read-only: no helper exec
beyond the controlled installed-git fallback, no fetch, no hooks, no
index writes. `--fetch` runs after local Analysis and only when
explicitly passed:

```sh
$BIN --state-dir $SD scan OWNER/REPO --root $ROOT --fetch
# stderr: repo-scan: fetch: 1 refreshed, 1 failed, 0 unsupported, 0 resumed-skip
```

- What changes: remote-tracking refs, `FETCH_HEAD`, and fetched objects
  only. Checkout files and local branch tips are never moved. No prune,
  no tags, no submodules, no automatic maintenance.
- Unsafe refspecs report `unsupported` instead of writing.
- Branch `freshness` (report `1.2.0`+): `current` (this scan's `--fetch`
  observed the ref), `stale` (fetch ran but did not cover it), or
  `unknown` (no successful fetch covered it; local branches always read
  `unknown`). `freshness_at` timestamps the label.
- Per-remote `refresh` summary: `status` (`success` / `failed` /
  `unsupported`), `observed_at`, `duration_ms`, `refs_updated`.
- Post-fetch, comparisons recompute only for local branches whose
  resolved upstream the fetch observed `current`; other branches keep
  their analysis-pass label.

## Resume and exit codes

`resume SCAN_ID` restores ALL saved options (targets, scope, roots,
`--status`, `--format`, `--fetch`, `--workers`, report destination) and
reprints through the requested lane. Interrupting with Ctrl-C finishes
bounded work, commits what is safe, and exits `130`; resume from any
directory — destinations are stored absolute.

| Code | Meaning | Observed when |
|---|---|---|
| `0` | success (zero matches is still success) | complete scan, `query --scan`, `query --all`, cached query with matches, `cache invalidate`, `cache clear` |
| `1` | operational failure | owner busy after 5 s lock wait; failed report publication |
| `2` | invalid arguments | no TARGET and no `--all`; `--all` + targets; `--follow --format json`; `--after` without `--follow`; `--workers 0`; query without `--cached`; unknown scan id |
| `3` | usable result with gaps / no suitable catalog / superseded resume | scan with unresolvable candidates or pending work; cached query on a fresh state dir (`suitable_catalog: false`); query with no retained snapshot |
| `130` | interrupted after bounded progress save | Ctrl-C mid-scan |

## Options

- `--state-dir PATH` (global): tool state location. Default on macOS is
  `~/Library/Application Support/repo-scan`; elsewhere `$XDG_STATE_HOME/repo-scan`
  or `~/.local/state/repo-scan`. Resolved to an absolute path once
  ([src/config.rs](src/config.rs)). Layout:
  `instance.lock` (coordination, never deleted) + `payload/` (database, snapshots).
- `--status metadata|summary|full` (scan only, default `summary`): working-state
  depth. `metadata` skips status probes; `summary` collapses each untracked directory
  to one entry; `full` counts individual untracked files. Status never narrows
  discovery; unknown counts stay `null`, never zero.
- `--root PATH` (scan only, repeatable): scan exactly these paths (recorded as
  `roots` scope) instead of `--scope machine`. With no roots, machine scope applies:
  all mounted, addressable filesystem roots.
- `--report PATH`: JSON report destination, resolved absolute at request creation and
  written atomically. Without it, a readable terminal summary goes to stdout and the
  versioned snapshot is retained in state. Progress/diagnostics always use stderr.
  While a scan runs, `--report` holds a live `running` revision replaced atomically
  at phase boundaries (at most once per 2 s); every concurrent read is one valid
  JSON document.
- `--format human|json|jsonl` (scan, query, resume): explicit output lane;
  default is the legacy terminal report (interactive TUI for `scan --format human`
  on a TTY). `query TARGET --cached` always prints the short human summary.
- `--fetch` (scan only): fetch current remote state after local analysis.
  See "Remote freshness" above; the `--help` text states exactly which refs change.
- `--follow` / `--after CURSOR` (query only): follow committed scan data;
  human or jsonl lanes only. `--after` resumes after an opaque cursor.
- `--workers N` (scan only): parallel read workers for discovery and analysis.
  Default is the platform's available parallelism (4 when unknown); values above
  32 clamp to 32; `0` is rejected (exit `2`). Saved with the request, restored
  on resume. CPU target scales to one core per worker; process-wide budgets
  (helpers, descriptors, writer batches) stay fixed.
- `--color auto|always|never` (scan only): TUI color control. `NO_COLOR` set or
  `TERM=dumb` disables color in every mode. Query always uses auto.
- `--force-rescan` (scan only): fresh traversal generation, bypassing
  completion shortcuts; old findings stay provisional until replaced.
- `--cached` (query TARGET): required; reads only existing state, never probes.

## Docs

- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) — reproducible bench commands + results tables.
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — lock contention, empty catalog, unsafe state dir, interrupted scans.
- [docs/CHECKLIST.md](docs/CHECKLIST.md) — acceptance-ID traceability with test evidence.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), `docs/*_QUAL.md` — design and dependency qualification.
