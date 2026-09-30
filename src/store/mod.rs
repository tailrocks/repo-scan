//! Native Turso storage contract (spec §§10–11, docs/TURSO_QUAL.md).
//!
//! Rules baked into every implementation behind [`Store`]:
//! - `turso = "=0.8.1"`, `default-features = false`; no experimental flags.
//! - Open via `Builder::new_local(path).build().await` + `db.connect()`.
//! - Writer uses `BEGIN IMMEDIATE`; always explicit commit/rollback/finish,
//!   then assert `is_autocommit()` (drop is NOT cleanup).
//! - Open sequence sets `synchronous=FULL`, `data_sync_retry=ON`,
//!   `journal_mode=WAL` (+ `fullfsync=ON` on macOS) and asserts query-backs.
//! - Paths/ref-names/URLs live in BLOB columns (exact bytes); report encoding
//!   per spec §16 is computed from the stored BLOB.
//! - Report streaming uses `prepare` + `Rows::next()`; never buffering
//!   `batch()` APIs. No recursive CTEs for scheduler traversal. FTS5 is
//!   unavailable (no `fts` feature): plain tables + indexes only.

/// Current catalog schema version. Migrations are append-only.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// One append-only schema migration, applied inside a single transaction.
#[derive(Debug, Clone)]
pub struct Migration {
    /// 1-based schema version this migration produces.
    pub version: u32,
    /// Human-readable description.
    pub description: &'static str,
    /// Multi-statement SQL executed via `execute_batch`.
    pub sql: &'static str,
}

/// Ordered migration chain. TODO(phase-2): author the real DDL for the
/// spec §11 entities (catalog metadata, scan requests, generations, volumes,
/// directories, frontier tasks, observations, git instances, checkouts,
/// remotes/refs, status, event journal, errors, report snapshots) with the
/// required indexes; test against realistic data.
pub fn migrations() -> &'static [Migration] {
    // TODO(phase-2): return the real migration list.
    &[]
}

/// Durable catalog contract. Only the owner implements this; enumeration and
/// Git helpers exchange bounded messages and never open the database
/// (spec §4). All database work runs on a separate storage execution context
/// from the responsive coordinator; no transaction spans filesystem/Git/
/// helper/external waits (spec §10).
pub trait Store: Send {
    /// Open (or create) the catalog at `db_path`, run migrations, set and
    /// query-back the durability PRAGMAs, and verify the catalog identity.
    fn open(
        db_path: &std::path::Path,
    ) -> impl std::future::Future<Output = crate::Result<Self>> + Send
    where
        Self: Sized;

    /// Current committed schema version of the open catalog.
    fn schema_version(&self) -> crate::Result<u32>;

    /// Explicit `PRAGMA wal_checkpoint(TRUNCATE)`; returns
    /// `(busy, log_frames, checkpointed_frames)`. Coordinated with readers.
    fn checkpoint(
        &self,
    ) -> impl std::future::Future<Output = crate::Result<(u64, u64, u64)>> + Send;

    /// Durability query-backs: `(synchronous, data_sync_retry,
    /// journal_mode, fullfsync_or_none)`. Asserted after open (DB-04).
    fn durability_proof(
        &self,
    ) -> impl std::future::Future<Output = crate::Result<DurabilityProof>> + Send;
}

/// Observed durability PRAGMA values (TURSO_QUAL §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurabilityProof {
    /// `PRAGMA synchronous;` must be `2` (Full).
    pub synchronous: i64,
    /// `PRAGMA data_sync_retry;` must be `1`.
    pub data_sync_retry: i64,
    /// `PRAGMA journal_mode;` must be `wal`.
    pub journal_mode: String,
    /// `PRAGMA fullfsync;` must be `1` on macOS; `None` elsewhere
    /// (name does not parse on Linux; cfg-gated).
    pub fullfsync: Option<i64>,
}
