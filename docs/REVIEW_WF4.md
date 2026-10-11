# Adversarial review WF4: scan/resume/query/invalidate/clear + store tx + publish

Scope: `src/main.rs` command paths, `src/store` tx boundaries, report staging/publish
(`src/main.rs` binary path vs `src/report/*` lib path). Scope: command paths, store tx boundaries, and report staging/publishing.
Ordered by bug risk (highest first). Line refs verified against current tree.

## R1 — High: target-match disposition is global last-scan-wins; reports leak other targets' matches

- `exec_probe` classifies every probed instance against the *current* scan's
  canonical URL and upserts one global `disposition` per instance
  (`src/main.rs:1693`, `src/main.rs:1698-1712`).
- Report subject rows are `WHERE disposition != 'nonmatch'` with **no target filter**
  (`src/main.rs:2462-2468`). The lib builder has the same global filter
  (`src/report/builder.rs:453`).
- Consequence: scanning URL-B after URL-A emits URL-A's confirmed repos in URL-B's
  report (and vice versa re-labels them). Spec §16 "include all matching
  repositories" is per-target; the catalog cannot serve two targets. `query`
  is unaffected (it filters `remotes.canonical_url`, `src/main.rs:3788-3797`).
- Fix: classify per (instance, canonical-target) at report time from stored
  remotes, or scope dispositions per target; filter subjects by the scan target.

## R2 — High: `claim_tasks` ignores generation; force-rescan drains old work, accounting diverges

- Claim query has no generation predicate (`src/store/catalog.rs:714-718`), while
  boundary accounting is per-generation (`pending_count`,
  `src/store/catalog.rs:1025-1039`; `run_until_boundary`, `src/main.rs:1028`).
- A `--force-rescan` fresh generation claims pending tasks from older generations,
  and tasks claimed cross-generation are invisible to the run's `pending` count.
- Fix: add `AND generation = ?` to the claim query (sharing across requests of the
  *same* generation still works via `pick_generation`, `src/main.rs:585-623`).

## R3 — High: binary report path bypasses the tested lib path and is weaker

- The binary stages/publishes with its own `stage_report`/`emit_report`/`publish_to_dest`
  (`src/main.rs:2780-2869`, `src/main.rs:3565-3658`); `src/report/builder.rs`,
  `src/report/publish.rs`, `src/report/stream.rs` are exercised by
  `tests/report_impl.rs` but never called by the binary (no `report::` use in
  `src/main.rs`). REPORT-01/02 tests therefore do not cover shipped behavior.
- Concrete gaps in the binary path vs the lib path:
  - No canonicalized-parent check: symlinked parents can smuggle the report into a
    refused location (lib: `src/report/publish.rs:99-125`).
  - Staging via `std::fs::copy` follows symlinks; predictable tmp names, no
    `create_new`, no pre-rename revalidation (lib: `create_new` + re-check,
    `src/report/publish.rs:258-300`).
  - Staged bytes flushed but never `fsync`ed before rename
    (`src/main.rs:2864-2867`); lib syncs (`src/report/publish.rs:291,449-452`).
  - Checksum reads the whole staged file into memory (`src/main.rs:420`); lib
    streams (`src/report/publish.rs:37-53`).
  - `stage_report` preloads all instances/checkouts/remotes/refs/statuses into
    memory with N+1 queries (`src/main.rs:2792-2812`), violating the bounded-memory
    staging contract the lib builder honors row-by-row
    (`src/report/builder.rs:1-17`).
  - Prior-report verification omits the nonempty `report_id` check the lib requires
    (`src/main.rs:3663-3678` vs `src/report/publish.rs:181-203`).
- Fix: delete the binary-local duplication; route scan/resume through
  `report::builder` + `report::publish` (or move the binary path under the same tests).

## R4 — Med-High: breaker/admission skips leak leases until the 60 s TTL

- Claimed tasks that hit a closed breaker or a denied permit are skipped with
  `continue` while still leased (`src/main.rs:964-977`); nothing releases the lease.
  The run then ends at `!progressed` (`src/main.rs:1023-1026`) and reports exit 3
  over work that was claimable, and a prompt resume stalls until TTL expiry
  (`LEASE_TTL_MS`, `src/main.rs:46`) unless a new epoch requeues first.
- Fix: check breaker/admission *before* claiming, or add an explicit unclaim/release
  on skip.

## R5 — Med-High: FSEvents/incremental discovery is not wired into any command path

- `src/main.rs` never uses `src/events.rs`; emitted roots carry
  `event_history_uuid/ingested_cursor/reconciled_cursor: null`
  (`src/main.rs:3116-3118`) with a boundary note admitting cursors "are not yet
  wired" (`src/main.rs:2955-2958`).
- `tests/events_impl.rs` covers the module, but spec §13 (monitor-before-traverse,
  dual cursors, history-loss invalidation) is unmet end-to-end. EVENT-01/02 cannot
  pass until scan/resume/invalidate ingest and reconcile.

## R6 — Med: `invalidate_scope` directory mirror is dead code

- The mirror parses the `dir:` suffix as `i64` (`src/store/catalog.rs:971-980`),
  but `dir:` scope keys are hex-encoded path bytes
  (`src/config.rs:450-452`) and never parse as integers. `directories.invalidation_rev`
  is therefore never updated. The stale-completion guard works off
  `scope_revisions` so correctness holds, but the §11 mirrored invariant is fiction.
- Fix: look up the directory row by path/identity instead of parsing the key.

## R7 — Med: alias paths are dropped; `aliases[]` is always empty

- Enumeration task IDs dedupe by `(dev, ino)` (`src/main.rs:780-791`), so a second
  pathname alias of an already-enqueued object is never scheduled under its own path.
  The report emits no aliases (`src/main.rs:3300-3302`), against spec §7 (preserve
  all pathname aliases) and §16 (`Alias` records).
- Fix: key tasks by path scope with identity-based result sharing, and emit observed
  aliases.

## R8 — Med: no checkpoint coordination during scans; WAL grows unbounded

- Nothing in the scan loop calls `checkpoint_truncate`/`wal_status`
  (`src/store/catalog.rs:2598-2613`); only `close()` attempts a best-effort
  checkpoint (`src/store/catalog.rs:2662-2666`). Long scans accumulate WAL with no
  measurement, against spec §11 (coordinate checkpointing, measure WAL growth).

## R9 — Med: no per-operation watchdog with cancellation

- `SLOW_TASK_SECS` only prints a stderr diagnostic (`src/main.rs:50`, `src/main.rs:993-999`).
  There is no no-progress timer, no bounded termination grace, no helper containment —
  spec §14 requires cancel + grace + circuit-breaker behavior (only the breaker half
  exists, `src/main.rs:1048-1055`). A stuck `stat`/list/Git call stalls the
  single-threaded owner indefinitely.

## R10 — Med-Low: every op is its own transaction; writer batching is unused

- `exec_enumerate`/`persist_probe`/`exec_status` issue one autocommit statement per
  row plus a `with_tx` upsert/complete each; `WriterBatch`/`commit_batch`/`flush`
  (`src/store/catalog.rs:2539-2592`) are used only by `tests/store_impl.rs:597`.
- Spec §5/§10 require amortized durability (512 rows / 512 KiB / 250 ms). Current
  shape is N syncs per directory — the exact excessive-work pathology the spec warns
  about. Measure tx/sync rates (PERF-02) before claiming compliance.

## R11 — Low-Med: parent completion checks revision but not preserved child records

- `complete_task_on` validates `expected_rev` then marks complete
  (`src/store/catalog.rs:866-891`). Spec §10 additionally requires verifying
  "preserved child records" at final parent completion. A crash between child
  enqueue and parent completion is safe (children commit first), but there is no
  positive check that the children the completion claims are actually durable.

## R12 — Low-Med: cached query mutates the catalog and takes the exclusive lock

- `run_query_inner` opens via `open_owned_with_wait` (`src/main.rs:3755`), which
  claims a fresh epoch and runs recovery writes (`src/store/catalog.rs:339-351`).
  Every `--cached` query bumps the epoch and rewrites leases — not "read only the
  tool's existing state" (spec §3) — and serializes against scans via the exclusive
  flock. The no-catalog fast path correctly short-circuits before locking
  (`src/main.rs:3744-3754`).
- Fix: read-only open (no epoch claim, recovery only when leases actually block).

## R13 — Low: `resources.db_transactions` counts logical writes, not transactions

- The report writes `inputs.counters.db_writes` (incremented per upsert/enqueue/
  observation, e.g. `src/main.rs:1267,1445`) into `db_transactions`
  (`src/main.rs:3000-3011`). Spec §16 wants transaction counts. Relabel or count
  `with_tx`/commit calls.

## R14 — Low: resume ignores the saved generation

- `continue_saved_scan` re-enters `pick_generation` (`src/main.rs:4020-4087` →
  `run_scan_inner`), which prefers the newest generation with pending work
  (`src/main.rs:585-623`). After an interleaving force-rescan, resuming an old scan
  silently continues the *new* generation. Non-terminal scan rows also carry no
  recorded generation (`update_scan_state` with `outcome=None`, `src/main.rs:361-369`),
  so the original generation is unrecoverable. Persist the generation on the scan row.

## R15 — Low: `cache clear` identity is magic-bytes-only; pre-lock existence check

- DB identity is the 16-byte SQLite magic or empty file (`src/main.rs:4264-4304`);
  spec §15 asks for a verified ownership marker + database identity. A foreign
  SQLite database at the engine path would be deleted. The `payload.exists()`
  short-circuit runs before lock acquisition (`src/main.rs:4167-4172`) — benign
  race, but move it inside the guard. Unknown-file preservation, no-recursive-delete,
  and lock retention are correct (`src/main.rs:4207-4244`).

## R16 — Low (coverage gaps, honest but incomplete)

- Ref rows are always `state: "valid"` with `upstream: None`
  (`src/main.rs:1848-1860`); alternates/hard-link sharing is never inspected —
  `storage_links` covers `common_directory` only (`src/main.rs:3273-3298`), so
  GIT-02 hard-link evidence is absent.
- `Status.submodules` is hardcoded `"not_requested"` (`src/main.rs:2231`).
- Snapshot bytes are replaced in place across resume attempts under one deterministic
  report ID (`src/main.rs:2786-2790` + `INSERT OR IGNORE` row, `src/store/catalog.rs:2168`);
  unlike lib `retain_snapshot` (`src/report/publish.rs:334-396`) there is no
  checksum-identity check. Same-scan rewrite is arguably legal, but the file/row
  pair can disagree after a crash between rename and row write.

## Verified non-findings (checked, hold)

- Credentials are redacted at inspection time (`src/git/mod.rs:659-664`,
  `src/identity.rs:191-211`), so stored/reported remote URLs carry no secrets.
- Tx discipline is sound: `BEGIN IMMEDIATE` + awaited commit/rollback +
  `is_autocommit` assertion (`src/store/catalog.rs:375-410`); stale completions
  requeue inside the tx and report after commit (`src/store/catalog.rs:830-841`).
- Owner lock is never unlinked; contention fails closed without an independent DB
  open (`src/store/owner.rs:104-123`, `src/main.rs:131-152`).
- Completed resume replays the recorded outcome/snapshot without rescanning
  (`src/main.rs:3880-3903`); failed publication retries from the snapshot
  (`src/main.rs:3951-4016`); resume never consults the caller cwd
  (`src/main.rs:4027-4077`).
- Interrupt handling saves bounded progress and exits 130 (`src/main.rs:947-951`,
  `src/main.rs:1307-1310`, `src/main.rs:473-489`); new-epoch recovery requeues
  leaked leases on next open (`src/store/catalog.rs:613-643`).
