# repo-scan architecture

Design contract and architecture for repo-scan. Qualification evidence: `docs/*_QUAL.md`. Report schema: `schemas/report-v1.4.schema.json`.
Gate record: `docs/GATE_DECISION.md` (do not edit).

## Ownership and process model (as shipped)

- One catalog-owning process per state directory. There is no IPC: a second
  command waits up to 5 s for the lock, then exits `1` with `owner busy`
  rather than opening the database beside the live owner
  (`src/main.rs`, `src/config.rs`). The coordination lock +
  ownership marker live outside the replaceable `payload/` namespace
  (`src/store/owner.rs:1-16`).
- Only the owner opens the catalog read-write, driving the durable frontier
  through a pool of parallel read workers (default: platform parallelism,
  `--workers`, max 32): claim bounded work, execute through the `Admission`
  gates, persist findings, complete under epoch/lease/revision guards.
  The one exception is `query --cached`, which opens the catalog read-only
  with no lock, no epoch claim, and no recovery writes (`src/main.rs`).
- Worker results go to one writer in bounded batches (row/byte/age caps);
  no per-task flush+completion transactions. Helper processes exist only
  through the controlled installed-git fallback and explicit `--fetch`;
  admission permits scale with the worker count while process-wide budgets
  (helpers 4, descriptors, prefetch, writer batches) stay fixed
  (`src/config.rs`: `effective_limits`).
- Every filesystem/Git access inside inspected scope runs inside the
  traversal fence (below); potentially blocking work is fenced, leased, and
  watchdog-guarded per task (`src/main.rs`). Tool-owned state
  I/O follows the qualified Turso storage contract (`docs/TURSO_QUAL.md`).

## Module boundaries

| Module | Owns | Contract |
|---|---|---|
| `cli` | clap surface: scan/query/resume/cache, targets XOR `--all`, `--format`, `--follow`/`--after`, `--fetch`, `--workers`, `--status`, `--state-dir` | `src/cli.rs` |
| `config` | resource table defaults, state-dir resolution | `src/config.rs` |
| `model` | `ScanId`, `GenerationId`, `TaskState`, `UrlTarget`, `StatusMode`, `ExitCode` | `src/model.rs` |
| `platform` | native seams: `MountTable`, `EventSource` | `src/platform/` (cfg-gated `macos`/`linux`) |
| `walk` | `OneDirAdapter`: one dir, immediate children, no recursion | `src/walk/mod.rs` |
| `scheduler` | durable tasks, leases, invalidation revisions | `src/scheduler/mod.rs` |
| `store` | Turso `Store` trait, migrations | `src/store/mod.rs` |
| `git` | read-only `GitInspect` (+ controlled fallback) | `src/git/mod.rs` |
| `identity` | `MatchDisposition`, URL normalization | `src/identity.rs` |
| `events` | `EventCursor` protocol, volume cursors | `src/events.rs` |
| `scan_events` | scan-event journal: envelope, classes, ops, cursor, retention (event schema `1.0.0`) | `src/scan_events.rs` |
| `report` | `ReportWriter`, schema validation, atomic publish | `src/report/mod.rs` |
| `report/live_text` | deterministic plain-text lane (header, coverage, totals, `R`/`C`/`B`/`?`/`!` rows, cap 200) | `src/report/live_text.rs` |
| `report/tui` | interactive live view, no new deps (termios + ANSI) | `src/report/tui.rs` |
| `telemetry` | <=1 Hz resource sampling | `src/telemetry.rs` |
| `error` | structured errors -> exit codes | `src/error.rs` |

## Key decisions (with qualification pointers)

1. **One durable scheduler.** Traversal backends must not own a job
   universe. The owner supplies one directory task, receives bounded child
   batches (256 entries / 256 KiB), persists discoveries, then decides what
   runs next. Task states: `pending/leased/complete/retry_wait/unavailable/
   unsupported/cancelled/superseded` (`src/model.rs`, `src/scheduler/mod.rs`).
2. **Walker contract.** `DuaAdapter` (dua-core 4.1.0 `read_dir` one-dir
   iterator, macOS) and `IgnoreAdapter` (`standard_filters(false)` +
   `max_depth(Some(1))`, sequential) implement the same `OneDirAdapter`
   trait; `StdEscape` is OFF unless a version bump proves unbounded
   materialization (WALKER_QUAL §3, FS-05).
3. **Storage.** turso =0.8.1, `default-features = false`, no experimental
   flags. `BEGIN IMMEDIATE` writer, explicit commit/rollback + autocommit
   assert, durability PRAGMAs set + queried back, BLOB path columns,
   streaming report reads, no recursive CTEs, no FTS (TURSO_QUAL).
4. **Git.** gix =0.88.0 minimal read-only features + sha1/sha256. Exact-path
   open only, config trust contained, no hooks/filters/fetch, no index
   writes; reftable/SSH-alias/index gaps route to the controlled
   installed-git fallback (GIT_QUAL).
5. **macOS history.** `objc2-core-services` per-volume FSEvents streams +
   UUID persistence; separate ingested/reconciled cursors; Linux fixtures
   (`MockLogSource`, `FixtureMountTable`) exercise the reconciler without
   macOS (MACOS_QUAL).
6. **Resources.** Hard admission scales with the worker count
   (`effective_limits`: enum N / git N / shared N, N = `--workers` or
   platform parallelism, max 32); process-wide budgets stay fixed
   (helpers 4, fds 64, prefetch 1024|4MiB, batches 256|256KiB, writer
   512|512KiB|250ms). CPU target is one core per worker; RSS target
   256 MiB with the 512 MiB pressure threshold in `src/config.rs`.
   The owner samples aggregate RSS each loop and calls `set_pressure`
   past the threshold (`src/main.rs`); the PERF-02/03 gate harness lives
   in `benches/perf_gates.rs`, asserted by `tests/accept_perf.rs`.
7. **Reports.** Draft 2020-12 schema at `schemas/report-v1.4.schema.json`
   (`schema_version` `1.4.0`: branch comparison/ahead/behind over 1.3.0
   status vocabulary over 1.2.0 freshness over 1.1.0); illustrative
   example at `tests/data/example-report.json`. The binary stages
   through the lib pipeline: stream from the store, verify, retain an
   immutable snapshot, then atomic publish (`src/main.rs`,
   `src/report/publish.rs`, `ReportPipeline` at
   `src/report/builder.rs`). Failed publication marks the snapshot and
   retries from it without repeating discovery
   (`src/main.rs`, `docs/TURSO_QUAL.md`, `schemas/report-v1.4.schema.json`).
8. **Phases.** `Discovery → inventory_ready → Analysis → (Fetch?) →
   Completed`. `inventory_ready` commits only when enumeration +
   metadata-expansion tasks are terminal, no Discovery worker is active,
   and no buffered discovery or pending retry remains; a stuck scope
   becomes a gap and the boundary closes `incomplete`. No branch/status/
   graph read starts before the generation's `inventory_ready` row
   commits. `Fetch` runs only with explicit `--fetch`, after local
   Analysis. Later refreshes open a NEW generation; a closed boundary is
   never edited. Contract: `docs/GOAL_CONTRACTS.md` D3.
9. **Events.** One envelope `{schema_version:"1.0.0", scan_id, seq,
   catalog_rev, type, op, records[]}` (`src/scan_events.rs`), classes
   per `docs/GOAL_CONTRACTS.md` D4. Events journal to the catalog
   (migration v2 `scan_events`, newest 50,000 rows per scan) only after
   their transaction commits; `discovery_progress` coalesces write-side
   to one newest-payload row. Catalog is at migration v6
   (`src/store/schema_v2.rs` … `schema_v6.rs`): `github_groups` journal
   + scope key (v2), `--fetch` (v3), `--workers` (v4), status
   conflicts/working-state (v5), branch comparison/ahead/behind (v6).

## Shipped hardening (not in the Phase-1 sketch)

- **Traversal fence.** `ScopeFence` (`src/walk/topology.rs:425`, built at
  `:440`, `allows_path` at `:513`) pins every enumeration and Git probe to
  descriptor-relative opens under the declared roots; swapped/out-of-scope
  paths park with a gap and persist nothing
  (`park_on_identity_change` at `src/main.rs:8122`, fence verify at
  `src/main.rs:7895`). Tests: `tests/sec_fence.rs:40,57`,
  `tests/sec_probe_fence.rs:35`.
- **Lossless planner keys.** `scope_key_for_dir/git` carry exact path bytes,
  so distinct byte paths never collide and planner keys agree 1:1 with
  scheduler scopes (`src/config.rs:529,534`, `parse_scope_key` at `:545`).
  Tests: `tests/sec_keys.rs:29`,
  `tests/sec_bounds.rs:13`.
- **Publish path.** Staging + snapshot retention + atomic publication with a
  sha256/byte-count receipt (`PublishReceipt` at `src/report/publish.rs:874`,
  `open_nofollow` at `:258`, `check_destination_inner` at `:411`); staged
  input is opened `O_NOFOLLOW`, byte-capped, and quarantined on failure.
  Tests: `tests/sec_publish.rs:33,77,95,109,288`,
  `tests/accept_report.rs:593,656,704`.
- **Audit gate.** Dependency audit/deny policy is CI-enforced and
  regression-tested (`docs/AUDIT_GATE.md`, `tests/sec_audit_gate.rs:20`).

## Data flow (steady state)

CLI -> owner lock (or read-only query / `OwnerBusy`) -> scheduler claims
bounded tasks -> N parallel workers through `Admission` gates -> fenced
walk/git probes -> one writer, bounded batches -> invalidation revisions
gate completions -> Discovery commits `inventory_ready` -> Analysis reads
branches/status/graph -> optional `--fetch` refreshes remote-tracking refs
-> events journal per commit -> report streams one catalog revision ->
staged snapshot -> verified, retained, atomically published -> served to
human/json/jsonl lanes from the same retained bytes.

## Output lanes (Step 6, Wave6)

One selector resolves every command's lane
(`OutputFormat::resolve` in `src/cli.rs`): an explicit `--format`
always wins; otherwise a terminal gets the live human view and
redirected output gets the JSONL journal replay. Concretely: a bare
`scan`/`resume` on a TTY keeps the legacy terminal report and footers,
while redirected it replays the journal (every line parses);
`query --scan`/`query --all` print the plain lane on a TTY and replay
when redirected; `query TARGET --cached` keeps its short summary by
default and serves the resolved scan's retained snapshot/replay only
on explicit machine formats. `--report` publishes the JSON snapshot
file in every lane. The interactive TUI (`src/report/tui.rs`) opens
only for explicit `--format human` on a TTY — never by default
(`scan_tui_gate`, pinned in `tests/cli_impl.rs`). `query --all` and
the machine lanes of `query TARGET --cached` resolve a scan id, then
delegate to the same `query --scan` replay core, so all three
selections share one snapshot printer, one envelope stream, and one
follow loop (`src/main.rs`).
