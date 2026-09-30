# Turso 0.8.1 qualification (spec §10)

Scope: `turso = { version = "=0.8.1", default-features = false }`.
Evidence below is from the vendored registry sources
(`R = ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f`).
No `cargo` commands were run. No network claims are made.

## 1. Exact APIs to use

```rust
let db = turso::Builder::new_local("/abs/path/catalog.db").build().await?;
let conn: turso::Connection = db.connect()?;
```

- `Builder::new_local(path: &str) -> Builder`
  (`R/turso-0.8.1/src/lib.rs:187`). All `experimental_*` flags default to
  `false` (lib.rs:189-200); do NOT enable `experimental_multiprocess_wal`,
  `experimental_without_rowid`, or `experimental_mvcc_passive_checkpoint`.
- `Builder::build(self) -> Result<Database>` is `async` (lib.rs:329); it drives
  open-time IO completions to completion before returning (lib.rs:347-355).
- `Database::connect(&self) -> Result<Connection>` (lib.rs:376). `Database` is
  `Clone` (lib.rs:364); each `connect()` yields an independent core connection
  (`R/turso_core-0.8.1/database.rs:2383`).
- Statements: `conn.prepare(sql).await`, `conn.prepare_cached(sql).await`,
  `conn.execute(sql, params).await -> u64`, `conn.query(sql, params).await -> Rows`
  (`R/turso-0.8.1/src/connection.rs:124-135,353-377`).
- `conn.execute_batch(sql)` for multi-statement schema/migration scripts
  (connection.rs:146-152). `conn.batch(..)` / `conn.transactional_batch(..)`
  buffer all rows (connection.rs:324-351: `while let Some(row)`) — do NOT use
  them for report streaming; use `prepare` + `Rows::next()` streaming instead.
- Introspection: `conn.is_autocommit() -> bool` (connection.rs:482),
  `conn.last_insert_rowid() -> i64` (connection.rs:469),
  `conn.cacheflush()` (connection.rs:476, writes dirty pages to WAL),
  `conn.busy_timeout(Duration)` (connection.rs:501; default handler is
  `BusyHandler::None`, i.e. immediate `Busy` errors —
  `R/turso_core-0.8.1/database.rs:2594`),
  `conn.pragma_query(name, f)` / `conn.pragma_update(name, value)` helpers
  (connection.rs:439-466).
- No `Connection::checkpoint()` exists on the local path (only
  `sync.rs:457` for the sync engine, out of scope). Checkpoint explicitly via
  SQL: `PRAGMA wal_checkpoint(TRUNCATE);` (§4).
- `Statement::reset()` (lib.rs:602). `execute`/`query` auto-reset before each
  run (lib.rs:464,505-507). A live `Rows` holds a shared operation guard; batch
  APIs require an exclusive guard (connection.rs:265,521-554), so drain or drop
  `Rows` before `execute_batch`/`batch` on the same connection.
- Nested transactions are rejected at runtime for the unchecked API
  (transaction.rs:470-498 test expects an error containing "transaction"); the
  `&mut self` API prevents nesting at compile time (transaction.rs:108-119).

## 2. Transaction begin/commit/rollback semantics

- `conn.transaction().await` (default `Deferred`) and
  `conn.transaction_with_behavior(b).await` take `&mut self`
  (`R/turso-0.8.1/src/transaction.rs:272-291`).
- `TransactionBehavior::{Deferred, Immediate, Exclusive, Concurrent}`
  map to `BEGIN DEFERRED|IMMEDIATE|EXCLUSIVE|CONCURRENT`
  (transaction.rs:26-34). `Concurrent` requires MVCC journal mode
  (transaction.rs:19-22) — do not use; use `Immediate` for the writer actor.
- `tx.commit().await` runs `COMMIT` and marks the handle finished
  (transaction.rs:164-174). `tx.rollback().await` runs `ROLLBACK`
  (transaction.rs:176-187). `tx.finish().await` applies the configured
  `DropBehavior` and surfaces errors (transaction.rs:194-217); it is a no-op
  if the connection is already in autocommit (transaction.rs:200-203).
- `Transaction` derefs to `Connection` (transaction.rs:219-226), so all
  statement APIs work through `&tx`.
- Destructor-rollback note: `Drop for Transaction` does NOT run SQL — it only
  records the `DropBehavior` flag (`Rollback` by default) in
  `conn.dangling_tx` (transaction.rs:228-241; field docs connection.rs:59-66:
  "We cannot do this eagerly on Drop because drop is not async").
  The pending rollback/commit executes lazily on the next
  `query`/`execute`/`transaction_with_behavior`/`execute_batch` via
  `maybe_handle_dangling_tx` (connection.rs:101-135,148-149,265-267).
  Dropping a transaction is therefore NOT proof cleanup completed.
  Rule: always explicitly `commit().await`, `rollback().await`, or
  `finish().await`; after errors/cancellation call `rollback().await`, then
  assert `is_autocommit()` before reusing the connection.

## 3. Supported PRAGMAs (with verification)

PRAGMA name universe: `PragmaName` enum
(`R/turso_parser-0.8.1/src/ast.rs:1875-1991`). Boolean setters accept numeric
nonzero, or `ON|TRUE|YES|1` case-insensitive; anything else is false
(`R/turso_core-0.8.1/translate/pragma.rs:328-341`).

| PRAGMA | Effect in 0.8.1 | Verify with |
|---|---|---|
| `synchronous=FULL` | Sets `SyncMode::Full` per database (translate/pragma.rs:656-677). WAL-commit fsync happens ONLY in `Full` (storage/pager.rs:4711). Default is already `Full` (database.rs:2591,3527) — set explicitly anyway. | `PRAGMA synchronous;` → `2` (translate/pragma.rs:1615-1622; `SyncMode::{Off=0,Normal=1,Full=2}`, core lib.rs:224-229) |
| `fullfsync=ON` (macOS only) | Sets `FileSyncType::FullFsync` (translate/pragma.rs:744-755). Unix `sync()` calls `fcntl(F_FULLFSYNC)`, else `fsync` (io/unix.rs:455-489). Variant and arm are `#[cfg(target_vendor="apple")]` (turso_parser ast.rs:1909-1911; core pragma.rs:222-226) — on Linux the name does not parse; cfg-gate it. | `PRAGMA fullfsync;` → `1` (translate/pragma.rs:1696-1703) |
| `data_sync_retry=ON` | REQUIRED. Default is `false` (database.rs:2593), and on WAL-commit fsync failure the engine `panic!`s when the flag is off; with it on, a `CompletionError`/`IOError` is returned instead (storage/pager.rs:4723-4741). Despite the name, no retry loop exists at that site — the observable effect is error-return vs panic. | `PRAGMA data_sync_retry;` → `1` (translate/pragma.rs:1624-1631) |
| `journal_mode=WAL` | Opcode-driven set returning the resulting mode (translate/pragma.rs:389-408). Only `wal` and `mvcc` are `supported()`; `delete|truncate|persist|memory|off` parse but are unsupported (storage/journal_mode.rs:28-33). New files are WAL; legacy files auto-convert to WAL on read-write open (database.rs:2070-2088). | `PRAGMA journal_mode;` → `wal` |
| `wal_checkpoint(TRUNCATE)` | Explicit checkpoint returning `(busy,log,checkpointed)` (translate/pragma.rs:931-965). Modes `PASSIVE|FULL|RESTART|TRUNCATE` (storage/wal.rs `CheckpointMode` enum + `FromStr`). Bare `PRAGMA wal_checkpoint;` defaults to `Passive` on WAL connections (translate/pragma.rs:954-961) — always pass `TRUNCATE` explicitly. `PASSIVE` on MVCC needs the experimental flag; irrelevant for WAL use. | Returned row: `busy=0`, `log`/`checkpointed` frame counts |
| `busy_timeout=N` | Installs the delay-schedule busy handler (translate/pragma.rs:359ff; core busy.rs:60-66 `DELAYS`). Default is no handler. Prefer the typed `Connection::busy_timeout(Duration)` (connection.rs:501). | `PRAGMA busy_timeout;` (translate/pragma.rs:840ff) |
| `foreign_keys`, `user_version`, `application_id`, `schema_version`, `cache_size`, `page_size`, `page_count`, `max_page_count`, `integrity_check`/`quick_check`, `table_info`, `index_list`, etc. | Standard implemented set (core pragma.rs:34-240). | Query-back per statement |

Qualification rule (spec DB-04): after opening, set the four durability
PRAGMAs (`synchronous`, `fullfsync` on macOS, `data_sync_retry`,
`journal_mode`) and assert their query-back values. Never assume a set
succeeded from lack of error.

## 4. What is NOT supported / must NOT be used

- `WITHOUT ROWID`: hard parse error unless the experimental flag is on:
  "WITHOUT ROWID tables are an experimental feature" (translate/schema.rs:1183-1190;
  gate `experimental_without_rowid_enabled`, database.rs:3440-3441, wired from
  `Builder::experimental_without_rowid`, turso lib.rs:262-265/315-317).
  Do not use; keep default rowid tables.
- `journal_size_limit`: does not exist — no such `PragmaName` variant
  (turso_parser ast.rs:1875-1991) and no reference in core pragma.rs.
- Multiprocess WAL: experimental only. Builder flag
  `experimental_multiprocess_wal` (turso lib.rs:257-260/312-314) enables the
  `.tshm` cross-process coordinator (storage/shared_wal_coordination.rs:1-40).
  Default off (database.rs:80,867,991,2926). MVCC + multiprocess is rejected
  outright (database.rs:2061-2067). Per spec, do not enable; single owner
  process only. Same-process concurrent connections on one `Database` ARE the
  supported topology (8-writer contention test with `Busy` retry:
  turso lib.rs:874-949).
- MVCC / `BEGIN CONCURRENT`: experimental path (`journal_mode` `mvcc`
  supported flag exists, journal_mode.rs:31, but MVCC has no cross-process
  coordination and needs its own checkpoint/GC tuning pragmas). Do not use.
- Recursive CTEs: PRESENT in 0.8.1 (planner support translate/planner.rs:140-177,1246;
  emitter `Plan::RecursiveCte` → `emit_recursive_cte`, translate/emitter/mod.rs:1181-1182;
  implementation translate/recursive_cte.rs). The spec's "do not assume"
  caution predates this; regardless, per spec §10 implement scheduler tree
  traversal as bounded iterative queries and do not depend on recursive CTEs.
- Auto-checkpoint: EXISTS and is ON by default — post-commit auto-checkpoint
  when `max_frame > checkpoint_threshold(1000) + nbackfills`
  (storage/wal.rs:4099-4102, threshold storage/wal.rs:4845; enabled by
  `WalAutoActions::all_enabled()`, storage/wal.rs:153-161, database.rs:2558;
  post-commit hook storage/pager.rs:3399-3425). Not controllable through the
  `turso` bindings API (no setter exposed; `wal_auto_actions_disable` is
  core-only, connection.rs:2492). Treat it as a safety net, not the plan:
  coordinate explicit `PRAGMA wal_checkpoint(TRUNCATE)` and measure WAL growth.
- Sync-engine / cloud APIs (`turso::sync`, `Builder::new_remote`, sync
  `checkpoint()` at sync.rs:457): out of scope; local file only.

## 5. Async-executor needs

- The local path needs NO async runtime from turso: `tokio` is an optional
  dependency used only by the `sync` feature (turso Cargo.toml.orig:24-31,42);
  `turso_sdk_kit` sources contain no `tokio` references; `tokio` appears only
  as a dev-dependency for turso's own tests (Cargo.toml.orig:61-67).
  Futures (`build`, `execute`, `query`, `Rows::next`) are waker-driven and
  executor-agnostic — the application provides the executor (any reactor
  driving `std::task::Waker` futures; `Builder::build` awaits IO completions,
  turso lib.rs:347-355).
- The qualified Unix backend performs SYNCHRONOUS syscalls despite the async
  API: `sync()` calls `fsync`/`fcntl(F_FULLFSYNC)` inline and completes
  immediately (io/unix.rs:455-489); `pread`/`pwrite` are direct `libc` calls
  (io/unix.rs:317-332). Per spec §10, run all database work on a separate
  storage execution context from the responsive coordinator; never hold a DB
  transaction across filesystem/Git/helper/external waits (§10 ¶4).
- With `default-features = false`, neither `mimalloc` (global allocator,
  turso lib.rs:35-37) nor `fts` is compiled in (features, turso
  Cargo.toml.orig:15-20). Consequence: FTS5 tables/functions are unavailable;
  use plain tables + `LIKE`/equality/prefix indexes only.

## 6. BLOB-for-paths plan

- Engine TEXT is UTF-8: core `Text { value: Cow<'static, str>, .. }`
  (types.rs:74-77); bindings `Value::Text(String)` (turso value.rs:6-12).
  The `encoding` PRAGMA refuses anything but UTF-8
  (translate/pragma.rs:385-388: "UTF-8 won").
- Bindings `Value::Blob(Vec<u8>)` with `From<&[u8]>` and `From<Vec<u8>>`
  (turso value.rs:11,221-231); reads via `as_blob()` (value.rs:104) and
  `ValueRef::Blob(&[u8])` (value.rs:258,336). Core `Value::Blob(ValueBlob)`
  (types.rs:525-531).
- Plan: store every raw path/component/ref-name/URL in `BLOB` columns (exact
  bytes, `OsStr::as_bytes` on Unix); index and compare with byte equality
  (`=`, `IN`) and range scans. Keep a separate UTF-8 `display` TEXT column
  ONLY for presentation/ordering where needed. Report encoding follows spec
  §16 (`utf8` value verbatim, else standard Base64 of the raw bytes) —
  computable directly from the stored BLOB. Parameterized binding
  (`?1...?N` positional, `:name` named; turso lib.rs:468-484,510-525) keeps
  arbitrary bytes safe without escaping.

## 7. Open verification items (for implementation tests, DB-01..DB-04)

1. Release↔commit correspondence: spec pins release commit
   `8549c16595d2faf1bdd6ee24aee0be8bfabb3d4a` for turso 0.8.1. The crates.io
   registry sources carry no commit hash, so this correspondence could not be
   verified from local sources — recheck via the upstream tag before locking.
2. Crash semantics (DB-03): first-checkpoint crash, checkpoint-backfill
   crash, WAL-reset + first-acknowledged-commit crash, disk-full and
   corrupt/truncated payload — must be covered by fault-injection tests, not
   by this static qualification.
3. Same-process read-connections-during-write: supported topology per the
   8-connection contention test (turso lib.rs:874-949, `Busy` + retry), but
   report-streaming snapshot behavior (read-tx vs writer interleaving, WAL
   growth under long reports) must be measured per spec §16 ¶4 before choosing
   concurrent snapshot readers vs a publication barrier.
4. `data_sync_retry=ON` must be part of the open sequence and its query-back
   asserted; add a sync-failure injection test proving `Err` (not panic)
   propagation on the commit path.
