# repo-scan architecture (Phase 1)

Source of truth: `repo-scan-spec.md`. Qualification evidence: `docs/*_QUAL.md`.
Gate record: `docs/GATE_DECISION.md` (do not edit).

## Ownership and process model (spec §4)

- One catalog-owning process per state directory; other CLI invocations talk
  to it over local IPC. No owner -> a command acquires the instance lock and
  assumes ownership. The coordination lock + ownership marker live outside
  the replaceable `payload/` namespace.
- Only the owner opens the Turso database. It owns a bounded writer actor
  and any tested read connections. Enumeration/Git helpers exchange bounded
  messages and never open the database.
- Every potentially blocking operation against inspected scope runs through
  an admitted helper (enum, metadata, readlink, canonicalization, identity,
  mount validation, config includes, alternate-store access, status, report
  sinks). Tool-owned state I/O follows spec §10.

## Module boundaries (spec §4: these are sufficient)

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
   512 MiB pressure) in `src/config.rs` (spec §5).
7. **Reports.** Draft 2020-12 schema at `schemas/report-v1.schema.json`;
   illustrative example at `tests/data/example-report.json`. Stage-then-
   publish through an admitted helper; failed publication retries the saved
   snapshot (spec §§15-16).

## Data flow (steady state)

CLI -> owner -> scheduler claims bounded tasks -> admitted helpers run
walk/git probes -> bounded batches -> writer actor commits -> invalidation
revisions gate completions -> report streams one catalog revision -> staged
snapshot -> atomic publish.
