# repo-scan architecture

Design contract and architecture for repo-scan. Qualification evidence: `docs/*_QUAL.md`. Report schema: `schemas/report-v1.4.schema.json`.
Gate record: `docs/GATE_DECISION.md` (do not edit).

## Ownership and process model (as shipped)

- One catalog-owning process per state directory. There is no IPC: a second
  command waits up to 5 s for the lock, then exits `1` with `owner busy`
  rather than opening the database beside the live owner
  (`src/main.rs:170-190`, `src/config.rs:130`). The coordination lock +
  ownership marker live outside the replaceable `payload/` namespace
  (`src/store/owner.rs:1-16`).
- Only the owner opens the catalog read-write, on a single-threaded runtime,
  driving the durable frontier sequentially: claim bounded work, execute one
  task through the `Admission` gates, persist findings, complete under
  epoch/lease/revision guards (`src/main.rs:1-11`). The one exception is
  `query --cached`, which opens the catalog read-only with no lock, no epoch
  claim, and no recovery writes (`src/main.rs`).
- The owner spawns zero helper processes; the admission limits (enum
  2 / git 1 / shared 2 / helpers 4) are enforced as in-process caps, so
  exactly one operation is ever admitted at a time
  (`tests/accept_db.rs:9-16`). Scan writes buffer in a `WriterBatch` and
  commit at configured writer batch limits (`src/main.rs`).
- Every filesystem/Git access inside inspected scope runs inside the
  traversal fence (below); potentially blocking work is fenced, leased, and
  watchdog-guarded per task (`src/main.rs`). Tool-owned state
  I/O follows the qualified Turso storage contract (`docs/TURSO_QUAL.md`).

## Module boundaries

| Module | Owns | Contract |
|---|---|---|
| `cli` | clap surface: 6 exact commands, `--status`, `--state-dir` | `src/cli.rs` |
| `config` | resource table defaults, state-dir resolution | `src/config.rs` |
| `model` | `ScanId`, `GenerationId`, `TaskState`, `UrlTarget`, `StatusMode`, `ExitCode` | `src/model.rs` |
| `platform` | native seams: `MountTable`, `EventSource` | `src/platform/` (cfg-gated `macos`/`linux`) |
| `walk` | `OneDirAdapter`: one dir, immediate children, no recursion | `src/walk/mod.rs` |
| `scheduler` | durable tasks, leases, invalidation revisions | `src/scheduler/mod.rs` |
| `store` | Turso `Store` trait, migrations | `src/store/mod.rs` |
| `git` | read-only `GitInspect` (+ controlled fallback) | `src/git/mod.rs` |
| `identity` | `MatchDisposition`, URL normalization | `src/identity.rs` |
| `events` | `EventCursor` protocol, volume cursors | `src/events.rs` |
| `report` | `ReportWriter`, schema validation, atomic publish | `src/report/mod.rs` |
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
6. **Resources.** Hard admission (enum 2 / git 1 / shared 2 / helpers 4),
   buffer bounds (prefetch 1024|4MiB, batches 256|256KiB, writer
   512|512KiB|250ms, fds 64), measured targets (1 core, 256 MiB RSS,
   512 MiB pressure) in `src/config.rs:40-76`. The owner samples
   aggregate RSS each loop and calls `set_pressure` past the 512 MiB
   threshold (`src/main.rs`); the PERF-02/03 gate harness lives in
   `benches/perf_gates.rs`, asserted by `tests/accept_perf.rs:362`.
7. **Reports.** Draft 2020-12 schema at `schemas/report-v1.4.schema.json`;
   illustrative example at `tests/data/example-report.json`. The binary
   stages through the lib pipeline: stream from the store, verify, retain
   an immutable snapshot, then atomic publish (`src/main.rs`,
   `src/report/publish.rs`, `ReportPipeline` at
   `src/report/builder.rs`). Failed publication marks the snapshot and
   retries from it without repeating discovery
   (`src/main.rs`, `docs/TURSO_QUAL.md`, `schemas/report-v1.4.schema.json`).

## Shipped hardening (not in the Phase-1 sketch)

- **Traversal fence.** `ScopeFence` (`src/walk/topology.rs:240`, built at
  `:250`) pins every enumeration and Git probe to descriptor-relative opens
  under the declared roots; swapped/out-of-scope paths park with a gap and
  persist nothing (`src/main.rs:3840-3898`). Tests: `tests/sec_fence.rs:40,57`,
  `tests/sec_probe_fence.rs:35`.
- **Lossless planner keys.** `scope_key_for_dir/git` carry exact path bytes,
  so distinct byte paths never collide and planner keys agree 1:1 with
  scheduler scopes (`src/main.rs:1627-1628`). Tests: `tests/sec_keys.rs:29`,
  `tests/sec_bounds.rs:13`.
- **Publish path.** Staging + snapshot retention + atomic publication with a
  sha256/byte-count receipt (`src/report/publish.rs:256,411,706`); staged
  input is opened `O_NOFOLLOW`, byte-capped, and quarantined on failure.
  Tests: `tests/sec_publish.rs:33,77,95,109,285`,
  `tests/accept_report.rs:589,656,704`.
- **Audit gate.** Dependency audit/deny policy is CI-enforced and
  regression-tested (`docs/AUDIT_GATE.md`, `tests/sec_audit_gate.rs:13`).

## Data flow (steady state)

CLI -> owner lock (or read-only query / `OwnerBusy`) -> scheduler claims
bounded tasks -> inline execution through `Admission` gates -> fenced
walk/git probes -> bounded batches -> buffered writer commits ->
invalidation revisions gate completions -> report streams one catalog
revision -> staged snapshot -> verified, retained, atomically published.
