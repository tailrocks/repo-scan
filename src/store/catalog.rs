//! Owner-held Turso catalog: open sequence, transactions, frontier
//! leases, invalidation revisions, idempotent upserts, crash recovery, and
//! checkpoint coordination (spec §§10-12).
//!
//! Concurrency model: one owner process holds the database. All writer work
//! runs through one [`TursoStore`] on a dedicated storage execution context;
//! enumeration and Git helpers never open the database (spec §4). The writer
//! connection is used by one logical actor at a time — methods take `&self`
//! because the Turso API is `&self`, but concurrent calls from multiple
//! tasks would interleave transactions and must be serialized by the owner.
//!
//! Every multi-statement mutation goes through [`TursoStore::with_tx`]:
//! explicit `BEGIN IMMEDIATE`, explicit awaited `COMMIT`/`ROLLBACK`, then an
//! `is_autocommit()` assertion. Dropping is never treated as cleanup.

use crate::error::Error;
use crate::model::TaskState;
use crate::store::owner::{OwnerGuard, StateRootAnchor};
use crate::store::writer::WriterBatch;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::time::Duration;

/// Owner-held catalog handle. Only the owner constructs this.
///
/// SR-STATE-06: `state_anchor` pins the state root with a lifetime
/// `O_NOFOLLOW|O_DIRECTORY` FD plus `(dev, ino)`, verified pre/post-open
/// and periodically (`with_tx`, `open_reader`). A swap fails closed.
///
/// Engine-opens-by-path residual: Turso `Builder::new_local(path)` opens
/// the database by path string inside the engine, so the FD cannot force
/// the engine to use the pinned directory. The anchor detects a swap
/// before/after the engine open and on later verifies, but a swap that is
/// restored between two verifies is not observable at this layer.
pub struct TursoStore {
    db: turso::Database,
    conn: turso::Connection,
    db_path: PathBuf,
    epoch: u64,
    schema_version: u32,
    /// True for [`TursoStore::open_read_only`]: every writer entry point
    /// refuses, so cached queries cannot mutate the catalog.
    read_only: bool,
    counters: StoreCounters,
    state_anchor: Option<StateRootAnchor>,
    /// Catalog-file `(dev, ino)` bound at open (RS-PRIV-08, unix only;
    /// always `None` elsewhere). Re-checked by [`TursoStore::verify_state_root`].
    catalog_id: Option<(u64, u64)>,
}

/// Lock-free runtime counters behind [`TursoStore::stats`]. Open/migration
/// transactions (which run before any handle exists) are excluded; every
/// runtime transaction, batch, probe, and checkpoint is counted.
#[derive(Debug, Default)]
struct StoreCounters {
    transactions: AtomicU64,
    rollbacks: AtomicU64,
    batch_commits: AtomicU64,
    batch_ops: AtomicU64,
    checkpoints: AtomicU64,
    wal_probes: AtomicU64,
}

/// Transaction/sync-rate snapshot for PERF-02 evidence. Under
/// `synchronous = FULL` every counted transaction performs at least one WAL
/// sync on commit; explicit checkpoints are counted separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoreStats {
    /// Runtime transactions committed via `with_tx`.
    pub transactions: u64,
    /// Runtime transactions rolled back via `with_tx`.
    pub rollbacks: u64,
    /// Writer batches committed (`commit_batch` + `flush`).
    pub batch_commits: u64,
    /// Batched ops applied across all batch commits.
    pub batch_ops: u64,
    /// Explicit `checkpoint_truncate` calls.
    pub checkpoints: u64,
    /// `wal_status` probes.
    pub wal_probes: u64,
}

/// Monotonic in-process lease-token source, mixed with the pid so tokens
/// are unique per owner incarnation. All leases are requeued on open, so
/// in-process uniqueness is sufficient.
static LEASE_TOKENS: AtomicI64 = AtomicI64::new(1);

fn fresh_token() -> i64 {
    // fix10: pid is `u32`, statically lossless into `i64`.
    let base = i64::from(std::process::id()) << 48;
    let token = base ^ LEASE_TOKENS.fetch_add(1, Ordering::Relaxed);
    if token == 0 {
        1
    } else {
        token
    }
}

fn store_err(error: turso::Error) -> Error {
    Error::Store(error.to_string())
}

/// Refuse symlinked owned ancestors (SR-STATE-06): the database file, its
/// parent (payload), and its grandparent (state dir) must none be symlinks.
/// Final-component-only `O_NOFOLLOW` is insufficient — a symlinked `payload`
/// or state dir would redirect the catalog open. Only the owned namespace
/// is checked (never system ancestors like `/tmp`/`/var`, which are
/// legitimately symlinked on some platforms). Missing components are
/// skipped (the database file need not exist yet); other inspection
/// failures fail closed.
fn refuse_symlinked_owned_ancestors(db_path: &Path) -> crate::Result<()> {
    let mut current: Option<&Path> = Some(db_path);
    for _ in 0..3 {
        let Some(path) = current else {
            break;
        };
        if path.as_os_str().is_empty() {
            break;
        }
        match std::fs::symlink_metadata(path) {
            Ok(md) if md.file_type().is_symlink() => {
                return Err(Error::Store(format!(
                    "refusing symlinked state component: {}",
                    path.display()
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::Io(format!("cannot inspect {}: {e}", path.display())));
            }
        }
        current = path.parent();
    }
    Ok(())
}

/// State root for `db_path` (SR-STATE-06): `<state>/payload/catalog.db`
/// anchors `<state>`; any other layout anchors the immediate parent.
/// Never climbs into system ancestors.
fn state_root_for_db(db_path: &Path) -> Option<PathBuf> {
    let parent = db_path.parent()?;
    if parent.as_os_str().is_empty() {
        return None;
    }
    if parent.file_name().is_some_and(|n| n == "payload") {
        if let Some(grand) = parent.parent() {
            if !grand.as_os_str().is_empty() {
                return Some(grand.to_path_buf());
            }
        }
    }
    Some(parent.to_path_buf())
}

/// Engine sidecar suffixes hardened and bound with the catalog file.
/// `-tshm` is the multiprocess-WAL coordinator probe target: repo-scan
/// never enables `experimental_multiprocess_wal`, but the vendored engine
/// compiles WITH the `host_shared_wal` cfg on every 64-bit unix/windows
/// target (turso_core `build.rs` cfg_aliases; `cargo:rustc-cfg=host_shared_wal`
/// observed in this repo's own debug AND release build output), so every
/// legacy engine open path-probes `<db>-tshm`, follows a symlink there,
/// and mmaps a present file (RS-PRIV-11). Keep in sync with
/// `config::KNOWN_SIDECAR_FILES` (clear path).
const DB_SIDECAR_SUFFIXES: &[&str] = &["-wal", "-shm", "-journal", "-tshm"];

/// Harden the catalog file plus engine sidecars to `0600`, then verify
/// (RS-PRIV-03/11). The parent dir is pinned `O_NOFOLLOW|O_DIRECTORY` and
/// every candidate is opened with `openat(O_NOFOLLOW)` and `fstat`'d from
/// the FD: symlinks and non-regular files are refused (fail closed),
/// modes are applied with `fchmod` on the FD, and permission errors FAIL
/// (never ignored). Missing sidecars are skipped. Called BEFORE the engine
/// open (so a hostile sidecar never meets the path-following engine) and
/// again after (post-open re-verify). Unix only; no-op elsewhere.
#[cfg(unix)]
fn ensure_private_db_files(db_path: &Path) -> crate::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Some(file_name) = db_path.file_name() else {
        return Err(Error::Store(format!(
            "database path {} has no file name",
            db_path.display()
        )));
    };
    let parent = match db_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let dir = crate::store::owner::open_dir_nofollow(parent)?;
    let mut names: Vec<std::ffi::OsString> = vec![file_name.to_os_string()];
    for suffix in DB_SIDECAR_SUFFIXES {
        let mut name = file_name.to_os_string();
        name.push(suffix);
        names.push(name);
    }
    for name in &names {
        let file = match crate::store::owner::open_child_file(&dir, name) {
            Ok(file) => file,
            Err(e) => {
                if crate::store::owner::child_missing(&dir, name) {
                    continue;
                }
                return Err(e);
            }
        };
        if !file.metadata()?.is_file() {
            return Err(Error::Store(format!(
                "catalog component {name:?} under {} is not a regular file; refusing",
                parent.display()
            )));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::Store(format!(
                "catalog component {name:?} under {} mode is {mode:o}, want no group/other access",
                parent.display()
            )));
        }
    }
    Ok(())
}

/// Pre-engine catalog bind (RS-PRIV-08, unix): the payload dir stays
/// pinned across the engine open and the catalog file identity observed
/// before the open is re-compared after it. The engine opens by path
/// string, so a swap exactly inside the open window is invisible; the
/// re-compare catches every net change, and the lifetime re-check in
/// [`TursoStore::verify_state_root`] keeps catching later ones.
#[cfg(unix)]
struct CatalogBind {
    dir: std::fs::File,
    name: std::ffi::OsString,
    before: Option<(u64, u64)>,
}

#[cfg(unix)]
impl CatalogBind {
    fn preopen(db_path: &Path) -> crate::Result<Self> {
        let Some(file_name) = db_path.file_name() else {
            return Err(Error::Store(format!(
                "database path {} has no file name",
                db_path.display()
            )));
        };
        let parent = match db_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let dir = crate::store::owner::open_dir_nofollow(parent)?;
        let before = crate::store::owner::child_file_identity(&dir, file_name)?;
        Ok(Self {
            dir,
            name: file_name.to_os_string(),
            before,
        })
    }

    fn verify_postopen(&self, db_path: &Path) -> crate::Result<Option<(u64, u64)>> {
        let after = crate::store::owner::child_file_identity(&self.dir, &self.name)?;
        match (self.before, after) {
            (Some(was), Some(now)) if was == now => Ok(after),
            (None, _) => Ok(after),
            (Some(_), None) => Err(Error::Store(format!(
                "catalog {} was removed under the engine open; refusing",
                db_path.display()
            ))),
            (Some(_), Some(_)) => Err(Error::Store(format!(
                "catalog {} was swapped under the engine open; refusing",
                db_path.display()
            ))),
        }
    }
}

#[cfg(not(unix))]
fn ensure_private_db_files(_db_path: &Path) -> crate::Result<()> {
    Ok(())
}

fn v_int(value: i64) -> turso::Value {
    turso::Value::Integer(value)
}

fn v_text(value: impl Into<String>) -> turso::Value {
    turso::Value::Text(value.into())
}

fn v_blob(value: Vec<u8>) -> turso::Value {
    turso::Value::Blob(value)
}

fn v_opt_int(value: Option<i64>) -> turso::Value {
    value.map_or(turso::Value::Null, turso::Value::Integer)
}

fn v_opt_text(value: Option<String>) -> turso::Value {
    value.map_or(turso::Value::Null, turso::Value::Text)
}

fn v_opt_blob(value: Option<Vec<u8>>) -> turso::Value {
    value.map_or(turso::Value::Null, turso::Value::Blob)
}

/// Positional parameters for the `refs` observed-column statements
/// (`INSERT OR IGNORE` + `UPDATE` in [`TursoStore::upsert_ref`] and
/// [`TursoStore::buffer_upsert_ref`]): `?1..=?11` map to id,
/// instance_id, checkout_scope_id, kind, name, oid, algo,
/// symbolic_target, upstream, state, observed_at_ms. The v3
/// `freshness` label columns are intentionally absent: labeling is a
/// separate step and re-observation must preserve it.
fn ref_params(reference: &NewRef<'_>, observed_ms: i64) -> Vec<turso::Value> {
    vec![
        v_text(reference.id),
        v_text(reference.instance_id),
        v_opt_text(reference.checkout_scope_id.map(str::to_string)),
        v_text(reference.kind),
        v_blob(reference.name.to_vec()),
        v_opt_blob(reference.oid.map(<[u8]>::to_vec)),
        v_opt_text(reference.algo.map(str::to_string)),
        v_opt_blob(reference.symbolic_target.map(<[u8]>::to_vec)),
        v_opt_blob(reference.upstream.map(<[u8]>::to_vec)),
        v_text(reference.state),
        v_int(observed_ms),
    ]
}

/// Persist-safe scan-target bytes (RETEST-5): the catalog upholds the
/// no-credential-bytes invariant even when callers bypass CLI sanitization.
/// Valid UTF-8 targets are normalized with
/// [`crate::identity::sanitize_target_url`] (scp user → `git`, userinfo and
/// query/fragment tails stripped); non-UTF-8 targets are refused, never
/// persisted lossy. The refusal carries no input bytes (they may hold
/// secrets and may not be UTF-8).
fn sanitized_target_bytes(url_raw: &[u8], what: &str) -> crate::Result<Vec<u8>> {
    let text = std::str::from_utf8(url_raw)
        .map_err(|_| Error::InvalidArgs(format!("scan {what} URL is not valid UTF-8; refusing")))?;
    Ok(crate::identity::sanitize_target_url(text).into_bytes())
}

/// Sink-side remote-URL enforcement (FIXREADY4 R): the inspector already
/// redacts at observation, but the catalog never trusts its callers —
///
/// every stored remote `url`/`canonical_url` passes through
/// [`crate::identity::redact_remote_url`] (idempotent for clean values,
/// collapsing for `ext::`/unknown-scheme/malformed forms), so no
/// credential-shaped byte reaches durable state even on a direct or
/// legacy write path. Lossy conversion (never a refusal): remote bytes
/// arrive lossy from gix already, and a refusal here could strand a scan
/// on harmless non-UTF-8 residue.
fn redacted_remote_bytes(url: &[u8]) -> Vec<u8> {
    crate::identity::redact_remote_url(&String::from_utf8_lossy(url)).into_bytes()
}

fn req_i64(row: &turso::Row, idx: usize) -> crate::Result<i64> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Integer(value) => Ok(value),
        other => Err(Error::Store(format!(
            "column {idx} expected INTEGER, got {other:?}"
        ))),
    }
}

fn opt_i64(row: &turso::Row, idx: usize) -> crate::Result<Option<i64>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Null => Ok(None),
        turso::Value::Integer(value) => Ok(Some(value)),
        other => Err(Error::Store(format!(
            "column {idx} expected INTEGER or NULL, got {other:?}"
        ))),
    }
}

/// `u64` → `INTEGER` for catalog writes: values past `i64::MAX` are a
/// caller defect, never silently wrapped (fix10).
fn u64_to_i64(value: u64, what: &str) -> crate::Result<i64> {
    i64::try_from(value).map_err(|_| Error::Store(format!("{what} {value} exceeds i64 range")))
}

/// `u64` → `INTEGER` for the `buffer_*` family, which returns
/// `WriterBatch::should_flush` (`bool`) and cannot propagate `Error`.
/// Same fail-loud contract as [`u64_to_i64`]: out-of-range input is a
/// caller defect and panics instead of wrapping (fix10).
fn u64_to_i64_buf(value: u64, what: &str) -> i64 {
    u64_to_i64(value, what).unwrap_or_else(|err| panic!("{err}"))
}

/// `INTEGER` → `u64` for catalog reads: negative stored values are
/// catalog corruption, never silently wrapped (fix10).
fn i64_to_u64(value: i64, what: &str) -> crate::Result<u64> {
    u64::try_from(value)
        .map_err(|_| Error::Store(format!("{what} {value} in catalog is not a valid u64")))
}

fn req_text(row: &turso::Row, idx: usize) -> crate::Result<String> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Text(value) => Ok(value),
        other => Err(Error::Store(format!(
            "column {idx} expected TEXT, got {other:?}"
        ))),
    }
}

fn opt_text(row: &turso::Row, idx: usize) -> crate::Result<Option<String>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Null => Ok(None),
        turso::Value::Text(value) => Ok(Some(value)),
        other => Err(Error::Store(format!(
            "column {idx} expected TEXT or NULL, got {other:?}"
        ))),
    }
}

fn req_blob(row: &turso::Row, idx: usize) -> crate::Result<Vec<u8>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Blob(value) => Ok(value),
        other => Err(Error::Store(format!(
            "column {idx} expected BLOB, got {other:?}"
        ))),
    }
}

fn opt_blob(row: &turso::Row, idx: usize) -> crate::Result<Option<Vec<u8>>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Null => Ok(None),
        turso::Value::Blob(value) => Ok(Some(value)),
        other => Err(Error::Store(format!(
            "column {idx} expected BLOB or NULL, got {other:?}"
        ))),
    }
}

/// Persisted `frontier_tasks.state` spelling (spec §12).
pub fn task_state_as_str(state: TaskState) -> &'static str {
    match state {
        TaskState::Pending => "pending",
        TaskState::Leased => "leased",
        TaskState::Complete => "complete",
        TaskState::RetryWait => "retry_wait",
        TaskState::Unavailable => "unavailable",
        TaskState::Unsupported => "unsupported",
        TaskState::Cancelled => "cancelled",
        TaskState::Superseded => "superseded",
    }
}

/// Parse a persisted task state; unknown spellings are catalog corruption.
pub fn task_state_from_str(value: &str) -> crate::Result<TaskState> {
    match value {
        "pending" => Ok(TaskState::Pending),
        "leased" => Ok(TaskState::Leased),
        "complete" => Ok(TaskState::Complete),
        "retry_wait" => Ok(TaskState::RetryWait),
        "unavailable" => Ok(TaskState::Unavailable),
        "unsupported" => Ok(TaskState::Unsupported),
        "cancelled" => Ok(TaskState::Cancelled),
        "superseded" => Ok(TaskState::Superseded),
        other => Err(Error::Store(format!("unknown task state: {other}"))),
    }
}

/// Deterministic 63-bit directory ID derived from physical identity (R05).
///
/// In SQLite, `INTEGER PRIMARY KEY` is a 64-bit signed integer rowid. Using a
/// stable positive 63-bit FNV-1a hash of `(volume_id, object_id, incarnation)`
/// ensures that a directory's ID is known in memory before any database write,
/// eliminating the need to flush batches just to retrieve autoincrement IDs.
pub fn dir_identity_id(volume_id: &str, object_id: &str, incarnation: &str) -> i64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in volume_id.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash ^= 0x1f;
    hash = hash.wrapping_mul(0x100000001b3);
    for b in object_id.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash ^= 0x1f;
    hash = hash.wrapping_mul(0x100000001b3);
    for b in incarnation.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let id = (hash & 0x7fff_ffff_ffff_ffff) as i64;
    if id == 0 {
        1
    } else {
        id
    }
}

/// One durable frontier task (spec §12).
#[derive(Debug, Clone)]
pub struct FrontierTask {
    /// Stable deduplication key.
    pub id: String,
    /// Operation kind (`enumerate_dir`, `probe_git`, `status`, `reconcile`).
    pub kind: String,
    /// Traversal generation this task belongs to.
    pub generation: u64,
    /// Directory covered, if the task is directory-scoped.
    pub dir_id: Option<i64>,
    /// Invalidation scope; revisions live in `scope_revisions`.
    pub scope_key: String,
    /// Revision the claim observed; a completion at any other revision is
    /// stale and must not erase the newer invalidation.
    pub expected_rev: u64,
    /// Lifecycle state.
    pub state: TaskState,
    /// Current lease token, if leased.
    pub lease_token: Option<i64>,
    /// Epoch the lease was granted under.
    pub lease_epoch: Option<u64>,
    /// Lease expiry in unix milliseconds.
    pub lease_expires_ms: Option<i64>,
    /// Idempotency key: duplicate batches after restart apply once.
    pub idempotency_key: String,
    /// Earliest re-eligibility for `retry_wait` tasks.
    pub retry_after_ms: Option<i64>,
    /// Times this task has been claimed.
    pub attempts: u64,
}

impl FrontierTask {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_text(row, 0)?,
            kind: req_text(row, 1)?,
            generation: i64_to_u64(req_i64(row, 2)?, "task generation")?,
            dir_id: opt_i64(row, 3)?,
            scope_key: req_text(row, 4)?,
            expected_rev: i64_to_u64(req_i64(row, 5)?, "task expected_rev")?,
            state: task_state_from_str(&req_text(row, 6)?)?,
            lease_token: opt_i64(row, 7)?,
            lease_epoch: opt_i64(row, 8)?
                .map(|epoch| i64_to_u64(epoch, "task lease_epoch"))
                .transpose()?,
            lease_expires_ms: opt_i64(row, 9)?,
            idempotency_key: req_text(row, 10)?,
            retry_after_ms: opt_i64(row, 11)?,
            attempts: i64_to_u64(req_i64(row, 12)?, "task attempts")?,
        })
    }
}

/// Columns selected by [`FrontierTask::from_row`], in order.
const TASK_COLUMNS: &str = "id, kind, generation, dir_id, scope_key, expected_rev, \
    state, lease_token, lease_epoch, lease_expires_ms, idempotency_key, \
    retry_after_ms, attempts";

/// Process-wide R06 class-skew verdict (Step 9 fast-claim gate): `0` =
/// unknown (probe inside the first fast-path claim transaction), `1` =
/// clear, `2` = present. Upgrades only (`0->1`, `0->2`, `1->2`).
///
/// Every `frontier_tasks` insert path marks skewed `(kind, id)` pairs via
/// [`note_task_class`] *before* the row can commit, and the probe runs
/// inside the claiming transaction, so under the owner-serialized writer
/// model `clear` implies no claim-relevant skewed row exists. `present`
/// only costs the legacy window-query fallback, never correctness.
static TASK_CLASS_SKEW: AtomicU8 = AtomicU8::new(0);

/// ASCII case-insensitive byte-prefix match: the SQL `id LIKE 'probe:%'`
/// arms are engine-evaluated (SQLite `LIKE` folds ASCII case), so the
/// Rust mirror must fold too — byte `starts_with` would miss `PROBE:x`.
fn like_prefix(id: &str, prefix: &[u8]) -> bool {
    let bytes = id.as_bytes();
    bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// True when a task's R06 class (first-match over kind OR id-prefix, as
/// in the claim queries) differs from its kind-only class — i.e. the id
/// prefix pulls the row into an *earlier* class than its kind. All
/// in-repo enqueue sites use consistent kind/id pairs, so this is dead
/// defense in practice; the fast claim path still honors it exactly by
/// falling back to the window query whenever skew may exist.
fn task_class_skewed(kind: &str, id: &str) -> bool {
    match kind {
        "probe_git" => false,
        "reconcile" => like_prefix(id, b"probe:"),
        "enumerate_dir" => like_prefix(id, b"probe:") || like_prefix(id, b"reconcile:"),
        "status" => {
            like_prefix(id, b"probe:")
                || like_prefix(id, b"reconcile:")
                || like_prefix(id, b"enum:")
        }
        _ => {
            like_prefix(id, b"probe:")
                || like_prefix(id, b"reconcile:")
                || like_prefix(id, b"enum:")
                || like_prefix(id, b"status:")
        }
    }
}

/// Mark a to-be-inserted task's class skew (see [`TASK_CLASS_SKEW`]).
/// Called before the row can commit; upgrade-only, hence race-safe in
/// the conservative direction (a spurious `present` only falls back).
fn note_task_class(kind: &str, id: &str) {
    if task_class_skewed(kind, id) {
        TASK_CLASS_SKEW.store(2, Ordering::Relaxed);
    }
}

/// A task plus the lease just granted for it.
#[derive(Debug, Clone)]
pub struct ClaimedTask {
    /// Task state at claim time (state is `leased`).
    pub task: FrontierTask,
    /// Lease token; completions must present it.
    pub token: i64,
    /// Lease expiry in unix milliseconds.
    pub expires_ms: i64,
}

/// Outcome of one leased task execution.
#[derive(Debug, Clone)]
pub enum TaskOutcome {
    /// End-of-enumeration reached with revision validation.
    Complete,
    /// Partial progress plus a preserved gap; task returns to `retry_wait`.
    Retry {
        /// Stable error category for the gap record.
        category: String,
        /// Human-readable detail.
        detail: String,
        /// Re-eligibility in unix milliseconds.
        retry_after_ms: i64,
    },
    /// Scope parked durably; `state` must be `unavailable` or `unsupported`.
    Parked {
        /// Target state: `unavailable` or `unsupported`.
        state: TaskState,
        /// Reason recorded on the gap.
        reason: String,
    },
}

/// Gap row a completion just recorded (`Retry`/`Parked` arms of
/// [`TursoStore::complete_task`]), returned so the caller can journal the
/// matching `error` event after the completion transaction commits. The
/// store is the single source of truth for the id/category/detail — the
/// caller must not reconstruct them from the outcome.
#[derive(Debug, Clone)]
pub struct CompletionGap {
    /// Stable error id (`gap:<task id>`).
    pub id: String,
    /// Scope the error belongs to.
    pub scope_key: String,
    /// Stable category.
    pub category: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Gap delta of one task completion: the gap the outcome opened
/// (`Retry`/`Parked`), if any, and the gap id a `Complete` outcome
/// actually closed (rowcount-gated: tasks that never failed close
/// nothing).
#[derive(Debug, Clone, Default)]
pub struct CompletionDelta {
    /// Newly recorded open gap, when the outcome recorded one.
    pub opened: Option<CompletionGap>,
    /// Closed gap id, when the outcome closed a previously open row.
    pub closed: Option<String>,
}

/// New task for [`TursoStore::enqueue_task`] (insert is idempotent).
#[derive(Debug, Clone)]
pub struct NewTask<'a> {
    /// Stable deduplication key.
    pub id: &'a str,
    /// Operation kind.
    pub kind: &'a str,
    /// Traversal generation.
    pub generation: u64,
    /// Directory covered, if directory-scoped.
    pub dir_id: Option<i64>,
    /// Invalidation scope.
    pub scope_key: &'a str,
    /// Revision observed at enqueue time.
    pub expected_rev: u64,
    /// Idempotency key (unique across tasks).
    pub idempotency_key: &'a str,
}

/// Crash-recovery report from open (spec §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Leased tasks returned to `pending` (dead epoch or expired lease).
    pub requeued: u64,
    /// `uncertain` batch markers dropped (work preserved via requeued tasks).
    pub uncertain_dropped: u64,
}

/// WAL checkpoint status: `(busy, log_frames, checkpointed_frames)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalStatus {
    /// Nonzero when a reader blocked the checkpoint; caller retries.
    pub busy: u64,
    /// WAL frames present.
    pub log_frames: u64,
    /// Frames checkpointed by this call.
    pub checkpointed_frames: u64,
}

impl TursoStore {
    /// Open-or-create the owner catalog at `state_dir/payload/catalog.db`,
    /// holding the coordination lock at `state_dir/instance.lock`, claiming
    /// a fresh epoch, and running crash recovery.
    pub async fn open_owned(state_dir: &Path) -> crate::Result<(OwnerGuard, Self)> {
        let mut guard = OwnerGuard::acquire(state_dir)?;
        let store = Self::open_inner(&guard.db_path()).await?;
        guard.set_epoch(store.epoch());
        Ok((guard, store))
    }

    /// Fencing epoch claimed by this incarnation (the stored epoch,
    /// unbumped, for [`TursoStore::open_read_only`]).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Database file this handle opened.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// True when this handle was opened read-only: writer entry points
    /// refuse, so cached queries cannot mutate the catalog (spec §3).
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Current transaction/sync-rate counters (PERF-02 evidence).
    pub fn stats(&self) -> StoreStats {
        StoreStats {
            transactions: self.counters.transactions.load(Ordering::Relaxed),
            rollbacks: self.counters.rollbacks.load(Ordering::Relaxed),
            batch_commits: self.counters.batch_commits.load(Ordering::Relaxed),
            batch_ops: self.counters.batch_ops.load(Ordering::Relaxed),
            checkpoints: self.counters.checkpoints.load(Ordering::Relaxed),
            wal_probes: self.counters.wal_probes.load(Ordering::Relaxed),
        }
    }

    /// Refuse a writer entry point on a read-only handle.
    fn forbid_write(&self, op: &str) -> crate::Result<()> {
        if self.read_only {
            return Err(Error::Store(format!(
                "{op} refused: catalog opened read-only (cached query path)"
            )));
        }
        Ok(())
    }

    /// Enforce the single-owner invariant (SR-STATE-08): lease operations
    /// must carry this handle's fencing epoch. A foreign epoch is a caller
    /// defect (a replaced owner's workers are fenced), never silently
    /// accepted.
    fn check_owner_epoch(&self, epoch: u64, op: &str) -> crate::Result<()> {
        if epoch != self.epoch {
            return Err(Error::Store(format!(
                "{op} refused: epoch {epoch} is not this owner (epoch {})",
                self.epoch
            )));
        }
        Ok(())
    }

    /// Owner-only writer connection. Report streaming uses `prepare` plus
    /// `Rows::next()` on this or a dedicated reader; never buffering batch
    /// APIs. The owner serializes writer use.
    ///
    /// On a read-only handle the underlying database is engine-enforced
    /// read-only (`TursoStore::open_read_only`), so even raw `execute`
    /// calls through this handle fail in the engine; every writer entry
    /// point additionally refuses up front via `forbid_write`.
    pub fn connection(&self) -> &turso::Connection {
        &self.conn
    }

    /// Open (or create) the catalog at `db_path`: private parent
    /// directories (`0700`), `Builder::new_local` + `connect`, durability
    /// PRAGMAs with asserted query-backs, migrations, epoch claim, and
    /// crash recovery. Holds a lifetime state-root anchor (SR-STATE-06)
    /// and tightens the catalog/WAL files to `0600` post-create.
    async fn open_inner(db_path: &Path) -> crate::Result<Self> {
        refuse_symlinked_owned_ancestors(db_path)?;
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                crate::store::owner::ensure_private_dir_all(parent)?;
            }
        }
        // Re-bind after creation: a swap between check and create fails.
        refuse_symlinked_owned_ancestors(db_path)?;
        let state_anchor = state_root_for_db(db_path)
            .map(|root| StateRootAnchor::open(&root))
            .transpose()?;
        if let Some(anchor) = &state_anchor {
            anchor.verify()?;
        }
        // RS-PRIV-03/08: harden sidecars BEFORE the path-following engine
        // open, and bind the catalog file identity across the open.
        ensure_private_db_files(db_path)?;
        #[cfg(unix)]
        let pre_bind = CatalogBind::preopen(db_path)?;
        let path_str = db_path.to_str().ok_or_else(|| {
            Error::Store(format!("database path is not UTF-8: {}", db_path.display()))
        })?;
        let db = turso::Builder::new_local(path_str)
            .build()
            .await
            .map_err(store_err)?;
        let conn = db.connect().map_err(store_err)?;
        // Re-bind after open: fail closed if swapped under the open.
        refuse_symlinked_owned_ancestors(db_path)?;
        if let Some(anchor) = &state_anchor {
            anchor.verify()?;
        }
        ensure_private_db_files(db_path)?;
        #[cfg(unix)]
        let catalog_id = pre_bind.verify_postopen(db_path)?;
        #[cfg(not(unix))]
        let catalog_id: Option<(u64, u64)> = None;
        Self::apply_pragmas(&conn).await?;
        let schema_version = Self::migrate(&conn).await?;
        // Step 9 bounded-claim covering index (additive, idempotent): the
        // per-class fast-claim SELECTs constrain
        // `(generation, state, kind)` by equality and order by
        // `(attempts, updated_at_ms, id)`, so each class resolves to one
        // index range with `LIMIT` short-circuit instead of a whole-queue
        // window sort. `INTEGER`/`TEXT`-only key per the schema rules. Not
        // a versioned migration (those live in `schema.rs`, append-only):
        // `IF NOT EXISTS` converges old and new catalogs without a
        // version bump, and a first open on a large catalog pays one
        // index build. Read-only opens never create it (see
        // `TursoStore::open_read_only`, which does not run this path).
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tasks_claim ON frontier_tasks \
                (generation, state, kind, attempts, updated_at_ms, id)",
            (),
        )
        .await
        .map_err(store_err)?;
        let epoch = i64_to_u64(
            Self::with_tx_on(&conn, |tx| async move {
                let current = Self::read_meta_i64(tx, "epoch").await?.unwrap_or(0);
                let next = current
                    .checked_add(1)
                    .ok_or_else(|| Error::Store("catalog epoch overflow".to_string()))?;
                Self::write_meta_i64(tx, "epoch", next).await?;
                Ok::<i64, Error>(next)
            })
            .await?,
            "catalog epoch",
        )?;
        let now = crate::store::now_ms();
        Self::with_tx_on(&conn, |tx| async move {
            Self::recover_on(tx, epoch, now).await?;
            Ok::<(), Error>(())
        })
        .await?;
        Self::assert_autocommit(&conn)?;
        Ok(Self {
            db,
            conn,
            db_path: db_path.to_path_buf(),
            epoch,
            schema_version,
            read_only: false,
            counters: StoreCounters::default(),
            state_anchor,
            catalog_id,
        })
    }

    /// Open an existing catalog read-only for cached queries (spec §3):
    /// no epoch claim, no crash-recovery writes, no migrations, no PRAGMA
    /// assignments — only reads. The database itself opens engine-enforced
    /// read-only (`Builder::read_only`, Item 10), so mutations fail in the
    /// engine even through the raw `connection()` handle. The handle
    /// reports the stored epoch unbumped, and every writer entry point
    /// refuses. Recovery runs only
    /// when leases actually block, via
    /// [`TursoStore::recover_if_blocked`] on a read-write handle.
    /// Returns a store error (not a catalog) when the database file is
    /// absent or holds no suitable migrated catalog.
    pub async fn open_read_only(db_path: &Path) -> crate::Result<Self> {
        refuse_symlinked_owned_ancestors(db_path)?;
        if !db_path.exists() {
            return Err(Error::Store(format!(
                "no catalog at {}: nothing cached to read",
                db_path.display()
            )));
        }
        let state_anchor = state_root_for_db(db_path)
            .map(|root| StateRootAnchor::open(&root))
            .transpose()?;
        if let Some(anchor) = &state_anchor {
            anchor.verify()?;
        }
        let path_str = db_path.to_str().ok_or_else(|| {
            Error::Store(format!("database path is not UTF-8: {}", db_path.display()))
        })?;
        // Engine-enforced read-only (Item 10): the `read_only` builder
        // flag opens with `OpenFlags::ReadOnly`
        // (turso-0.8.1 lib.rs:284-285,341-344), so writes fail in the
        // engine even through the raw `connection()` handle. The
        // `read_only` flag plus `forbid_write` remain as the first
        // refusal layer for writer entry points.
        // RS-PRIV-03/08: same pre-engine hardening and file-identity bind
        // as the owner open, including the `-tshm` probe target.
        ensure_private_db_files(db_path)?;
        #[cfg(unix)]
        let pre_bind = CatalogBind::preopen(db_path)?;
        let db = turso::Builder::new_local(path_str)
            .read_only(true)
            .build()
            .await
            .map_err(store_err)?;
        let conn = db.connect().map_err(store_err)?;
        // Re-bind after open: fail closed if swapped under the open.
        refuse_symlinked_owned_ancestors(db_path)?;
        if let Some(anchor) = &state_anchor {
            anchor.verify()?;
        }
        ensure_private_db_files(db_path)?;
        #[cfg(unix)]
        let catalog_id = pre_bind.verify_postopen(db_path)?;
        #[cfg(not(unix))]
        let catalog_id: Option<(u64, u64)> = None;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(store_err)?;
        let journal_mode = Self::pragma_text(&conn, "journal_mode").await?;
        if journal_mode.to_lowercase() != "wal" {
            return Err(Error::Store(format!(
                "catalog at {} is not a WAL catalog (journal_mode {journal_mode:?}); \
                    refusing read-only open",
                db_path.display()
            )));
        }
        if !Self::has_table(&conn, "meta").await? {
            return Err(Error::Store(format!(
                "catalog at {} holds no repo-scan metadata; refusing read-only open",
                db_path.display()
            )));
        }
        let raw = Self::read_meta_text(&conn, "schema_version")
            .await?
            .ok_or_else(|| {
                Error::Store("catalog has no schema_version; refusing read-only open".to_string())
            })?;
        let schema_version: u32 = raw.parse::<u32>().map_err(|_| {
            Error::Store(format!("catalog schema_version is not a number: {raw:?}"))
        })?;
        // A read-only open never migrates: older and newer catalogs alike
        // are left for an owner open (or an honest no-suitable-catalog).
        if schema_version != crate::store::CURRENT_SCHEMA_VERSION {
            return Err(Error::Store(format!(
                "catalog schema version {schema_version} is not this binary's v{}; \
                    refusing read-only open",
                crate::store::CURRENT_SCHEMA_VERSION
            )));
        }
        let epoch = i64_to_u64(
            Self::read_meta_i64(&conn, "epoch").await?.unwrap_or(0),
            "catalog epoch",
        )?;
        Self::assert_autocommit(&conn)?;
        Ok(Self {
            db,
            conn,
            db_path: db_path.to_path_buf(),
            epoch,
            schema_version,
            read_only: true,
            counters: StoreCounters::default(),
            state_anchor,
            catalog_id,
        })
    }

    /// Re-verify the lifetime state-root anchor (SR-STATE-06). Fails closed
    /// when the state directory was swapped, replaced, or symlinked under
    /// the held FD. Called periodically by `with_tx` and `open_reader`.
    pub fn verify_state_root(&self) -> crate::Result<()> {
        if let Some(anchor) = &self.state_anchor {
            anchor.verify()?;
        }
        self.verify_catalog_identity()
    }

    /// Re-verify the catalog-file identity bound at open (RS-PRIV-08,
    /// unix): fail closed when the live path no longer names the same
    /// `(dev, ino)` regular file. A swap restored between verifies is not
    /// observable at this layer (same residual as the state anchor).
    fn verify_catalog_identity(&self) -> crate::Result<()> {
        #[cfg(not(unix))]
        let _ = self.catalog_id;
        #[cfg(unix)]
        {
            let Some((dev, ino)) = self.catalog_id else {
                return Ok(());
            };
            let meta = std::fs::metadata(&self.db_path).map_err(|e| {
                Error::Store(format!(
                    "catalog {} is unreachable; refusing: {e}",
                    self.db_path.display()
                ))
            })?;
            if !meta.is_file() {
                return Err(Error::Store(format!(
                    "catalog {} is no longer a regular file; refusing",
                    self.db_path.display()
                )));
            }
            {
                use std::os::unix::fs::MetadataExt;
                if (meta.dev(), meta.ino()) != (dev, ino) {
                    return Err(Error::Store(format!(
                        "catalog {} changed (dev,ino) under the open handle; refusing",
                        self.db_path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    /// Live `meta.db_id` of the open catalog (RS-PRIV-02/06): ownership
    /// binding compares this exact value against the marker's `db_id=`
    /// line. `None` when the row is absent (never on tool-created v1
    /// catalogs, which seed it in `seed_meta`).
    pub async fn catalog_db_id(&self) -> crate::Result<Option<String>> {
        Self::read_meta_text(&self.conn, "db_id").await
    }

    /// Catalog-file `(dev, ino)` bound at open (RS-PRIV-08): `Some` on
    /// unix when the pre/post-open bind succeeded, `None` elsewhere or
    /// when the bind observed no file. Lets consumers that opened the
    /// victim through a held FD first (clear's ownership check) prove
    /// this by-path engine open resolved to that SAME file instead of
    /// trusting the path — a mismatch reads as unbound (fail closed).
    pub fn catalog_identity(&self) -> Option<(u64, u64)> {
        self.catalog_id
    }

    /// Explicit transaction helper: `BEGIN IMMEDIATE`, run `f`, then an
    /// awaited `COMMIT` on success or an awaited `ROLLBACK` on error or
    /// commit failure, followed by an `is_autocommit()` assertion. Never
    /// hold the transaction across filesystem, Git, helper, or external
    /// waits (spec §10).
    pub async fn with_tx<'a, T, F, Fut>(&'a self, f: F) -> crate::Result<T>
    where
        F: FnOnce(&'a turso::Connection) -> Fut,
        Fut: std::future::Future<Output = crate::Result<T>>,
    {
        self.forbid_write("transaction")?;
        self.verify_state_root()?;
        let result = Self::with_tx_on(&self.conn, f).await;
        match &result {
            Ok(_) => {
                self.counters.transactions.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.counters.rollbacks.fetch_add(1, Ordering::Relaxed);
            }
        }
        result
    }

    async fn with_tx_on<'a, T, F, Fut>(conn: &'a turso::Connection, f: F) -> crate::Result<T>
    where
        F: FnOnce(&'a turso::Connection) -> Fut,
        Fut: std::future::Future<Output = crate::Result<T>>,
    {
        conn.execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(store_err)?;
        match f(conn).await {
            Ok(value) => {
                if let Err(error) = conn.execute("COMMIT", ()).await {
                    let _ = conn.execute("ROLLBACK", ()).await;
                    Self::assert_autocommit(conn)?;
                    return Err(store_err(error));
                }
                Self::assert_autocommit(conn)?;
                Ok(value)
            }
            Err(error) => {
                let _ = conn.execute("ROLLBACK", ()).await;
                Self::assert_autocommit(conn)?;
                Err(error)
            }
        }
    }

    fn assert_autocommit(conn: &turso::Connection) -> crate::Result<()> {
        let autocommit = conn.is_autocommit().map_err(store_err)?;
        if autocommit {
            Ok(())
        } else {
            Err(Error::Store(
                "connection left inside a transaction after commit/rollback".to_string(),
            ))
        }
    }

    /// Open sequence: durability PRAGMAs, then asserted query-backs
    /// (spec §10, DB-04). A set without a matching query-back is a failure,
    /// never silent acceptance.
    async fn apply_pragmas(conn: &turso::Connection) -> crate::Result<()> {
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(store_err)?;
        Self::pragma_assign(conn, "journal_mode = WAL").await?;
        Self::pragma_assign(conn, "synchronous = FULL").await?;
        // Required: without data_sync_retry, a WAL-commit fsync failure
        // panics the engine instead of returning an error.
        Self::pragma_assign(conn, "data_sync_retry = ON").await?;
        #[cfg(target_os = "macos")]
        Self::pragma_assign(conn, "fullfsync = ON").await?;
        let proof = Self::proof_on(conn).await?;
        if proof.synchronous != 2 {
            return Err(Error::Store(format!(
                "PRAGMA synchronous query-back is {}, want 2 (FULL)",
                proof.synchronous
            )));
        }
        if proof.data_sync_retry != 1 {
            return Err(Error::Store(format!(
                "PRAGMA data_sync_retry query-back is {}, want 1",
                proof.data_sync_retry
            )));
        }
        if proof.journal_mode.to_lowercase() != "wal" {
            return Err(Error::Store(format!(
                "PRAGMA journal_mode query-back is {:?}, want wal",
                proof.journal_mode
            )));
        }
        #[cfg(target_os = "macos")]
        if proof.fullfsync != Some(1) {
            return Err(Error::Store(format!(
                "PRAGMA fullfsync query-back is {:?}, want 1",
                proof.fullfsync
            )));
        }
        Ok(())
    }

    async fn proof_on(conn: &turso::Connection) -> crate::Result<crate::store::DurabilityProof> {
        let synchronous = Self::pragma_i64(conn, "synchronous").await?;
        let data_sync_retry = Self::pragma_i64(conn, "data_sync_retry").await?;
        let journal_mode = Self::pragma_text(conn, "journal_mode").await?;
        #[cfg(target_os = "macos")]
        let fullfsync = Some(Self::pragma_i64(conn, "fullfsync").await?);
        #[cfg(not(target_os = "macos"))]
        let fullfsync = None;
        Ok(crate::store::DurabilityProof {
            synchronous,
            data_sync_retry,
            journal_mode,
            fullfsync,
        })
    }

    /// Assignment PRAGMA (`PRAGMA name = value`) via the query path,
    /// draining the reported row(s). turso's `execute` rejects statements
    /// that return rows ("unexpected row during execution"), and assignment
    /// PRAGMAs report their new value as a row — so every set goes through
    /// `query` here. The asserted query-backs in the callers stay the proof
    /// of effect.
    async fn pragma_assign(conn: &turso::Connection, assignment: &str) -> crate::Result<()> {
        let sql = format!("PRAGMA {assignment}");
        let mut rows = conn.query(sql.as_str(), ()).await.map_err(store_err)?;
        while rows.next().await.map_err(store_err)?.is_some() {}
        Ok(())
    }

    async fn pragma_i64(conn: &turso::Connection, name: &str) -> crate::Result<i64> {
        let sql = format!("PRAGMA {name}");
        let mut rows = conn.query(sql.as_str(), ()).await.map_err(store_err)?;
        let row = rows
            .next()
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Store(format!("PRAGMA {name} returned no rows")))?;
        req_i64(&row, 0)
    }

    async fn pragma_text(conn: &turso::Connection, name: &str) -> crate::Result<String> {
        let sql = format!("PRAGMA {name}");
        let mut rows = conn.query(sql.as_str(), ()).await.map_err(store_err)?;
        let row = rows
            .next()
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Store(format!("PRAGMA {name} returned no rows")))?;
        req_text(&row, 0)
    }

    /// Apply every pending migration, each inside one transaction, then seed
    /// catalog-identity rows. Refuses a catalog newer than this binary.
    async fn migrate(conn: &turso::Connection) -> crate::Result<u32> {
        let mut current: u32 = 0;
        if Self::has_table(conn, "meta").await? {
            if let Some(raw) = Self::read_meta_text(conn, "schema_version").await? {
                current = raw.parse::<u32>().map_err(|_| {
                    Error::Store(format!("catalog schema_version is not a number: {raw:?}"))
                })?;
            }
        }
        if current > crate::store::CURRENT_SCHEMA_VERSION {
            return Err(Error::Store(format!(
                "catalog schema version {current} is newer than this binary (v{})",
                crate::store::CURRENT_SCHEMA_VERSION
            )));
        }
        for migration in crate::store::migrations() {
            if migration.version <= current {
                continue;
            }
            Self::with_tx_on(conn, |tx| async move {
                tx.execute_batch(migration.sql).await.map_err(store_err)?;
                Self::write_meta_text(tx, "schema_version", &migration.version.to_string()).await?;
                Ok::<(), Error>(())
            })
            .await?;
            current = migration.version;
        }
        Self::with_tx_on(conn, |tx| async move { Self::seed_meta(tx).await }).await?;
        Ok(current)
    }

    async fn has_table(conn: &turso::Connection, name: &str) -> crate::Result<bool> {
        let mut rows = conn
            .query(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                vec![v_text(name)],
            )
            .await
            .map_err(store_err)?;
        Ok(rows.next().await.map_err(store_err)?.is_some())
    }

    async fn seed_meta(conn: &turso::Connection) -> crate::Result<()> {
        let db_id = format!(
            "db-{:x}-{:x}-{}",
            std::process::id(),
            crate::store::now_ms(),
            fresh_token()
        );
        for (name, value) in [
            ("db_id", db_id.as_str()),
            ("epoch", "0"),
            ("committed_revision", "0"),
            ("engine_qual", crate::store::schema::ENGINE_QUAL),
        ] {
            conn.execute(
                "INSERT OR IGNORE INTO meta (name, value) VALUES (?1, ?2)",
                vec![v_text(name), v_text(value)],
            )
            .await
            .map_err(store_err)?;
        }
        Ok(())
    }

    async fn read_meta_text(conn: &turso::Connection, name: &str) -> crate::Result<Option<String>> {
        let mut rows = conn
            .query("SELECT value FROM meta WHERE name = ?1", vec![v_text(name)])
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(req_text(&row, 0)?)),
        }
    }

    async fn read_meta_i64(conn: &turso::Connection, name: &str) -> crate::Result<Option<i64>> {
        match Self::read_meta_text(conn, name).await? {
            None => Ok(None),
            Some(raw) => raw.parse::<i64>().map(Some).map_err(|_| {
                Error::Store(format!("catalog meta {name:?} is not a number: {raw:?}"))
            }),
        }
    }

    async fn write_meta_text(
        conn: &turso::Connection,
        name: &str,
        value: &str,
    ) -> crate::Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO meta (name, value) VALUES (?1, ?2)",
            vec![v_text(name), v_text(value)],
        )
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn write_meta_i64(conn: &turso::Connection, name: &str, value: i64) -> crate::Result<()> {
        Self::write_meta_text(conn, name, &value.to_string()).await
    }

    /// Crash recovery (spec §12): requeue leases held under dead epochs or
    /// past expiry, and drop `uncertain` batch markers whose work survives
    /// via the requeued tasks. Runs inside the caller's transaction.
    async fn recover_on(
        conn: &turso::Connection,
        epoch: u64,
        now_ms: i64,
    ) -> crate::Result<RecoveryReport> {
        let requeued = conn
            .execute(
                "UPDATE frontier_tasks SET state = 'pending', lease_token = NULL, \
                    lease_epoch = NULL, lease_expires_ms = NULL, updated_at_ms = ?1 \
                    WHERE state = 'leased' AND (lease_epoch IS NULL OR lease_epoch != ?2 \
                    OR (lease_expires_ms IS NOT NULL AND lease_expires_ms <= ?1))",
                vec![v_int(now_ms), v_int(u64_to_i64(epoch, "recovery epoch")?)],
            )
            .await
            .map_err(store_err)?;
        let mut rows = conn
            .query("SELECT COUNT(*) FROM batches WHERE state = 'uncertain'", ())
            .await
            .map_err(store_err)?;
        let uncertain = match rows.next().await.map_err(store_err)? {
            None => 0,
            Some(row) => i64_to_u64(req_i64(&row, 0)?, "uncertain batch count")?,
        };
        conn.execute("DELETE FROM batches WHERE state = 'uncertain'", ())
            .await
            .map_err(store_err)?;
        Ok(RecoveryReport {
            requeued,
            uncertain_dropped: uncertain,
        })
    }

    /// Run crash recovery now (same rules as open) and report what moved.
    pub async fn recover_now(&self, now_ms: i64) -> crate::Result<RecoveryReport> {
        let epoch = self.epoch;
        self.with_tx(|conn| async move { Self::recover_on(conn, epoch, now_ms).await })
            .await
    }

    /// Leases that would block scheduler progress at `now_ms`: tasks still
    /// `leased` under a foreign (or missing) epoch, or past expiry. Pure
    /// read; cached queries use it to decide without writing.
    pub async fn blocking_lease_count(&self, now_ms: i64) -> crate::Result<u64> {
        let mut rows = self
            .conn
            .query(
                "SELECT COUNT(*) FROM frontier_tasks WHERE state = 'leased' \
                    AND (lease_epoch IS NULL OR lease_epoch != ?1 \
                    OR (lease_expires_ms IS NOT NULL AND lease_expires_ms <= ?2))",
                vec![v_int(u64_to_i64(self.epoch, "store epoch")?), v_int(now_ms)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(0),
            Some(row) => Ok(i64_to_u64(req_i64(&row, 0)?, "blocking lease count")?),
        }
    }

    /// Run crash recovery only when leases actually block: zero blocking
    /// leases means zero writes (safe on a read-only handle). A read-only
    /// handle with blocking leases errors and names the read-write open
    /// recovery needs; cached queries never take that path.
    pub async fn recover_if_blocked(&self, now_ms: i64) -> crate::Result<RecoveryReport> {
        if self.blocking_lease_count(now_ms).await? == 0 {
            return Ok(RecoveryReport {
                requeued: 0,
                uncertain_dropped: 0,
            });
        }
        if self.read_only {
            return Err(Error::Store(
                "leases block this catalog; recovery needs a read-write open".to_string(),
            ));
        }
        self.recover_now(now_ms).await
    }
}

impl TursoStore {
    /// Enqueue a task idempotently (`INSERT OR IGNORE` on the dedup key).
    /// Returns true when the task was newly inserted.
    pub async fn enqueue_task(&self, task: &NewTask<'_>, now_ms: i64) -> crate::Result<bool> {
        self.forbid_write("enqueue_task")?;
        // Step 9: mark class skew before the row can commit (conservative
        // on `OR IGNORE` duplicates — a spurious mark only falls back).
        note_task_class(task.kind, task.id);
        let rows = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO frontier_tasks (id, kind, generation, dir_id, \
                    scope_key, expected_rev, state, idempotency_key, attempts, \
                    updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, 0, ?8)",
                vec![
                    v_text(task.id),
                    v_text(task.kind),
                    v_int(u64_to_i64(task.generation, "task generation")?),
                    v_opt_int(task.dir_id),
                    v_text(task.scope_key),
                    v_int(u64_to_i64(task.expected_rev, "task expected_rev")?),
                    v_text(task.idempotency_key),
                    v_int(now_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(rows == 1)
    }

    /// Fetch one task by id.
    pub async fn get_task(&self, id: &str) -> crate::Result<Option<FrontierTask>> {
        Self::get_task_on(&self.conn, id).await
    }

    async fn get_task_on(
        conn: &turso::Connection,
        id: &str,
    ) -> crate::Result<Option<FrontierTask>> {
        let sql = format!("SELECT {TASK_COLUMNS} FROM frontier_tasks WHERE id = ?1");
        let mut rows = conn
            .query(sql.as_str(), vec![v_text(id)])
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(FrontierTask::from_row(&row)?)),
        }
    }

    /// Durably claim up to `limit` eligible tasks for `epoch` (expired
    /// leases return to `pending` first, inside the same transaction).
    /// Leases last `ttl_ms` from `now_ms`. Bounded: at most 1,024 claims.
    ///
    /// Cross-generation legacy shape: the scan loop must prefer
    /// [`TursoStore::claim_tasks_in_generation`], which scopes the claim to
    /// the run's generation so boundary accounting (`pending_count`) and the
    /// claimed work cannot diverge across `--force-rescan` generations.
    pub async fn claim_tasks(
        &self,
        epoch: u64,
        limit: usize,
        ttl_ms: i64,
        now_ms: i64,
    ) -> crate::Result<Vec<ClaimedTask>> {
        // Fix10 probes before the owner gate: out-of-range epochs and
        // overflowing expiries fail with their own errors for any epoch.
        u64_to_i64(epoch, "lease epoch")?;
        now_ms.checked_add(ttl_ms).ok_or_else(|| {
            Error::Store(format!("lease expiry {now_ms} + {ttl_ms} overflows i64"))
        })?;
        self.check_owner_epoch(epoch, "claim_tasks")?;
        let limit = limit.clamp(1, 1024);
        self.with_tx(|conn| async move {
            Self::expire_leases_on(conn, now_ms).await?;
            // Bound literal is interpolated (numeric, owner-controlled) so
            // the query needs no bound LIMIT support.
            //
            // R06: Fair scheduling across task classes (probe, reconcile,
            // enumerate, status) using round-robin interleaving so probes and
            // early repository validations are never starved behind large
            // enumeration backlogs.
            let sql = format!(
                "SELECT {TASK_COLUMNS} FROM ( \
                    SELECT {TASK_COLUMNS}, \
                        ROW_NUMBER() OVER ( \
                            PARTITION BY generation, CASE \
                                WHEN kind = 'probe_git' OR id LIKE 'probe:%' THEN 1 \
                                WHEN kind = 'reconcile' OR id LIKE 'reconcile:%' THEN 2 \
                                WHEN kind = 'enumerate_dir' OR id LIKE 'enum:%' THEN 3 \
                                WHEN kind = 'status' OR id LIKE 'status:%' THEN 4 \
                                ELSE 5 \
                            END \
                            ORDER BY attempts ASC, updated_at_ms ASC, id ASC \
                        ) AS _rn, \
                        CASE \
                            WHEN kind = 'probe_git' OR id LIKE 'probe:%' THEN 1 \
                            WHEN kind = 'reconcile' OR id LIKE 'reconcile:%' THEN 2 \
                            WHEN kind = 'enumerate_dir' OR id LIKE 'enum:%' THEN 3 \
                            WHEN kind = 'status' OR id LIKE 'status:%' THEN 4 \
                            ELSE 5 \
                        END AS _cls \
                    FROM frontier_tasks \
                    WHERE state = 'pending' \
                        OR (state = 'retry_wait' AND retry_after_ms IS NOT NULL \
                        AND retry_after_ms <= ?1) \
                ) \
                ORDER BY generation ASC, _rn ASC, _cls ASC, id ASC LIMIT {limit}"
            );
            let mut rows = conn
                .query(sql.as_str(), vec![v_int(now_ms)])
                .await
                .map_err(store_err)?;
            let mut tasks = Vec::new();
            while let Some(row) = rows.next().await.map_err(store_err)? {
                tasks.push(FrontierTask::from_row(&row)?);
            }
            let mut claimed = Vec::with_capacity(tasks.len());
            for task in &tasks {
                let token = fresh_token();
                // fix10: checked — an overflowing expiry would silently
                // shorten the lease; near-`i64::MAX` clocks are a caller
                // defect and fail the claim loudly.
                let expires = now_ms.checked_add(ttl_ms).ok_or_else(|| {
                    Error::Store(format!("lease expiry {now_ms} + {ttl_ms} overflows i64"))
                })?;
                let rows = conn
                    .execute(
                        "UPDATE frontier_tasks SET state = 'leased', lease_token = ?1, \
                            lease_epoch = ?2, lease_expires_ms = ?3, \
                            attempts = attempts + 1, updated_at_ms = ?4 WHERE id = ?5 \
                            AND (state = 'pending' OR state = 'retry_wait')",
                        vec![
                            v_int(token),
                            v_int(u64_to_i64(epoch, "lease epoch")?),
                            v_int(expires),
                            v_int(now_ms),
                            v_text(task.id.clone()),
                        ],
                    )
                    .await
                    .map_err(store_err)?;
                if rows == 1 {
                    let mut leased = task.clone();
                    leased.state = TaskState::Leased;
                    leased.lease_token = Some(token);
                    leased.lease_epoch = Some(epoch);
                    leased.lease_expires_ms = Some(expires);
                    // fix10: saturating — `attempts` is a monotonic
                    // telemetry counter, not a boundary; reaching
                    // `u64::MAX` needs 2^64 claims, and saturating keeps
                    // the "retried many times" signal without failing a
                    // lease claim that already committed in SQL above.
                    leased.attempts = leased.attempts.saturating_add(1);
                    claimed.push(ClaimedTask {
                        task: leased,
                        token,
                        expires_ms: expires,
                    });
                }
            }
            Ok::<Vec<ClaimedTask>, Error>(claimed)
        })
        .await
    }

    /// Durably claim up to `limit` eligible tasks of one traversal
    /// `generation` for `epoch`: the claim carries `AND generation = ?`, so
    /// a force-rescan run never drains older generations' work and claimed
    /// tasks stay visible to that generation's `pending_count` boundary.
    /// Requests sharing the *same* generation still share work: repeated
    /// claims return disjoint pending tasks until the generation is
    /// exhausted. Lease expiry for this generation runs first, inside the
    /// same transaction; other generations' leases are untouched.
    /// Leases last `ttl_ms` from `now_ms`. Bounded: at most 1,024 claims.
    /// Durably claim up to `limit` eligible tasks of one traversal
    /// `generation` for `epoch`, across all task kinds (legacy
    /// unfiltered contract; phase gating uses
    /// [`TursoStore::claim_tasks_in_generation_kinds`]).
    pub async fn claim_tasks_in_generation(
        &self,
        generation: u64,
        epoch: u64,
        limit: usize,
        ttl_ms: i64,
        now_ms: i64,
    ) -> crate::Result<Vec<ClaimedTask>> {
        self.claim_tasks_in_generation_inner(generation, epoch, limit, ttl_ms, now_ms, None)
            .await
    }

    /// Durably claim up to `limit` eligible tasks of one traversal
    /// `generation` for `epoch`, restricted to `kinds` (phase gating,
    /// goal Step 8: the discovery drain claims enumeration/probe/
    /// reconcile only; analysis kinds wait for the post-`inventory_ready`
    /// drain). Empty `kinds` claims nothing. Kind strings are matched
    /// against an allowlist and bound as parameters, never interpolated.
    pub async fn claim_tasks_in_generation_kinds(
        &self,
        generation: u64,
        epoch: u64,
        limit: usize,
        ttl_ms: i64,
        now_ms: i64,
        kinds: &[&str],
    ) -> crate::Result<Vec<ClaimedTask>> {
        if kinds.is_empty() {
            return Ok(Vec::new());
        }
        for kind in kinds {
            if !matches!(
                *kind,
                "enumerate_dir" | "probe_git" | "status" | "reconcile" | "analyze_store"
            ) {
                return Err(Error::Store(format!("unknown task kind: {kind}")));
            }
        }
        self.claim_tasks_in_generation_inner(generation, epoch, limit, ttl_ms, now_ms, Some(kinds))
            .await
    }

    /// One R06 class stream: top-`limit` rows of one kind over the
    /// pending + eligible-`retry_wait` union in window-partition order
    /// (DB-M2: no whole-generation window fallback just because one
    /// retry turned eligible). Two indexed top-`limit` SELECTs (one per
    /// state, each a single `idx_tasks_claim` range with `LIMIT`
    /// short-circuit) merged in Rust by the partition key
    /// (`attempts, updated_at_ms, id`) — the merge reproduces the
    /// window's in-class order row for row, since both inputs arrive
    /// in that order and the union's top-`limit` needs at most
    /// `limit` rows from either side.
    async fn claim_class_top_on(
        conn: &turso::Connection,
        generation_i64: i64,
        kind: &str,
        limit: usize,
        now_ms: i64,
    ) -> crate::Result<Vec<FrontierTask>> {
        // Bound literal is interpolated (numeric, owner-controlled) so
        // the query needs no bound LIMIT support; kind stays a parameter.
        // `updated_at_ms` rides along (column 13, past the
        // `FrontierTask::from_row` shape) as the merge key.
        let pending_sql = format!(
            "SELECT {TASK_COLUMNS}, updated_at_ms FROM frontier_tasks WHERE generation = ?1 \
                AND state = 'pending' AND kind = ?2 \
                ORDER BY attempts ASC, updated_at_ms ASC, id ASC LIMIT {limit}"
        );
        let mut rows = conn
            .query(
                pending_sql.as_str(),
                vec![v_int(generation_i64), v_text(kind)],
            )
            .await
            .map_err(store_err)?;
        let mut pending: Vec<(FrontierTask, i64)> = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            pending.push((FrontierTask::from_row(&row)?, req_i64(&row, 13)?));
        }
        // Eligible-retry arm: exactly the window query's predicate
        // (`retry_after_ms IS NOT NULL AND retry_after_ms <= now`).
        let retry_sql = format!(
            "SELECT {TASK_COLUMNS}, updated_at_ms FROM frontier_tasks WHERE generation = ?1 \
                AND state = 'retry_wait' AND kind = ?2 \
                AND retry_after_ms IS NOT NULL AND retry_after_ms <= ?3 \
                ORDER BY attempts ASC, updated_at_ms ASC, id ASC LIMIT {limit}"
        );
        let mut rows = conn
            .query(
                retry_sql.as_str(),
                vec![v_int(generation_i64), v_text(kind), v_int(now_ms)],
            )
            .await
            .map_err(store_err)?;
        let mut retry: Vec<(FrontierTask, i64)> = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            retry.push((FrontierTask::from_row(&row)?, req_i64(&row, 13)?));
        }
        // Sorted-merge the two partition-ordered inputs, keeping the
        // first `limit` rows of the union.
        let key = |task: &FrontierTask, updated: i64| (task.attempts, updated);
        let mut tasks = Vec::new();
        let (mut i, mut j) = (0usize, 0usize);
        while tasks.len() < limit && (i < pending.len() || j < retry.len()) {
            let take_pending = match (pending.get(i), retry.get(j)) {
                (Some((p, pu)), Some((r, ru))) => {
                    (key(p, *pu), p.id.as_str()) <= (key(r, *ru), r.id.as_str())
                }
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            if take_pending {
                tasks.push(pending[i].0.clone());
                i += 1;
            } else {
                tasks.push(retry[j].0.clone());
                j += 1;
            }
        }
        Ok(tasks)
    }

    /// One-time (per process) skew probe over the claimed
    /// generation's rows: true when a pending/`retry_wait` row's id
    /// prefix pulls it into an earlier R06 class than its kind (the
    /// [`task_class_skewed`] mirror in SQL). Scoped to `generation`
    /// (DB-m1): the verdict only gates this generation's fast claim,
    /// and the `generation` equality resolves to the claim index
    /// prefix instead of a whole-DB scan. The once-per-process cache
    /// stays sound across generations: every insert path marks via
    /// [`note_task_class`] before its row can commit, and rows
    /// committed before this process came from the same binary,
    /// whose enqueue sites never emit skewed pairs — so a later
    /// generation can only gain skew through a self-marking insert.
    /// Runs inside the claiming transaction, so it observes a
    /// consistent snapshot.
    async fn task_class_skew_present_on(
        conn: &turso::Connection,
        generation: u64,
    ) -> crate::Result<bool> {
        let mut rows = conn
            .query(
                "SELECT 1 FROM frontier_tasks WHERE generation = ?1 \
                    AND (state = 'pending' OR state = 'retry_wait') \
                    AND ((kind = 'reconcile' AND id LIKE 'probe:%') \
                    OR (kind = 'enumerate_dir' \
                        AND (id LIKE 'probe:%' OR id LIKE 'reconcile:%')) \
                    OR (kind = 'status' \
                        AND (id LIKE 'probe:%' OR id LIKE 'reconcile:%' OR id LIKE 'enum:%')) \
                    OR (kind NOT IN ('probe_git', 'reconcile', 'enumerate_dir', 'status') \
                        AND (id LIKE 'probe:%' OR id LIKE 'reconcile:%' \
                        OR id LIKE 'enum:%' OR id LIKE 'status:%'))) LIMIT 1",
                vec![v_int(u64_to_i64(generation, "task generation")?)],
            )
            .await
            .map_err(store_err)?;
        Ok(rows.next().await.map_err(store_err)?.is_some())
    }

    /// Step 9 bounded claim selection: indexed top-`limit` SELECTs per
    /// R06 class (pending + eligible-`retry_wait` union streams,
    /// [`TursoStore::claim_class_top_on`]) plus a Rust round-robin
    /// merge. Returns `None` when the legacy window query must run
    /// instead (unfiltered claims, possible kind/id class skew, or a
    /// multi-kind else-class) — identical sequence either way.
    ///
    /// Exactness: with no skew, each class stream holds that class's
    /// pending + eligible-retry rows in partition order
    /// (`attempts, updated_at_ms, id`), and the overall `LIMIT` prefix
    /// of the `(_rn, _cls)` round-robin needs at most `limit` rows
    /// from any one class — so interleaving per-class top-`limit`
    /// streams reproduces the window query's sequence row for row.
    /// (`_rn` is unique within a class, so the window's trailing `id`
    /// tiebreak never fires.)
    async fn claim_select_fast(
        conn: &turso::Connection,
        generation: u64,
        kinds: Option<&[&str]>,
        limit: usize,
        now_ms: i64,
    ) -> crate::Result<Option<Vec<FrontierTask>>> {
        // Unfiltered claims have an unbounded else-class (`kind NOT IN`
        // over unknown kinds); the window query stays authoritative.
        // (Production discovery/analysis claims always filter.)
        let Some(kinds) = kinds else {
            return Ok(None);
        };
        if TASK_CLASS_SKEW.load(Ordering::Relaxed) != 1 {
            if Self::task_class_skew_present_on(conn, generation).await? {
                TASK_CLASS_SKEW.store(2, Ordering::Relaxed);
                return Ok(None);
            }
            TASK_CLASS_SKEW.store(1, Ordering::Relaxed);
        }
        let generation_i64 = u64_to_i64(generation, "task generation")?;
        const NAMED: [&str; 4] = ["probe_git", "reconcile", "enumerate_dir", "status"];
        let mut streams: Vec<Vec<FrontierTask>> = Vec::with_capacity(5);
        for class_kind in NAMED {
            if kinds.contains(&class_kind) {
                streams.push(
                    Self::claim_class_top_on(conn, generation_i64, class_kind, limit, now_ms)
                        .await?,
                );
            } else {
                streams.push(Vec::new());
            }
        }
        let else_kinds: Vec<&&str> = kinds.iter().filter(|kind| !NAMED.contains(*kind)).collect();
        streams.push(match else_kinds.as_slice() {
            [] => Vec::new(),
            [only] => Self::claim_class_top_on(conn, generation_i64, only, limit, now_ms).await?,
            // Multi-kind else-class: the window query stays authoritative.
            _ => return Ok(None),
        });
        let mut tasks = Vec::new();
        for rn in 0..limit {
            for stream in &streams {
                if let Some(task) = stream.get(rn) {
                    tasks.push(task.clone());
                    if tasks.len() == limit {
                        return Ok(Some(tasks));
                    }
                }
            }
        }
        Ok(Some(tasks))
    }

    /// Legacy whole-queue window selection (authoritative fallback for
    /// [`TursoStore::claim_select_fast`], and the only path for
    /// unfiltered claims): R06 round-robin interleave over all eligible
    /// rows of the generation. Unchanged semantics.
    async fn claim_select_window(
        conn: &turso::Connection,
        generation: u64,
        kinds: Option<&[&str]>,
        limit: usize,
        now_ms: i64,
    ) -> crate::Result<Vec<FrontierTask>> {
        // Bound literal is interpolated (numeric, owner-controlled) so
        // the query needs no bound LIMIT support.
        //
        // R06: Fair scheduling across task classes (probe, reconcile,
        // enumerate, status) using round-robin interleaving so discovered
        // Git repository candidates are scheduled and validated promptly
        // while directory enumeration continues in parallel/interleaved.
        let kind_predicate = match kinds {
            Some(kinds) => {
                let kind_params: Vec<String> =
                    (0..kinds.len()).map(|i| format!("?{}", i + 3)).collect();
                format!("AND kind IN ({})", kind_params.join(", "))
            }
            None => String::new(),
        };
        let sql = format!(
            "SELECT {TASK_COLUMNS} FROM ( \
                SELECT {TASK_COLUMNS}, \
                    ROW_NUMBER() OVER ( \
                        PARTITION BY CASE \
                            WHEN kind = 'probe_git' OR id LIKE 'probe:%' THEN 1 \
                            WHEN kind = 'reconcile' OR id LIKE 'reconcile:%' THEN 2 \
                            WHEN kind = 'enumerate_dir' OR id LIKE 'enum:%' THEN 3 \
                            WHEN kind = 'status' OR id LIKE 'status:%' THEN 4 \
                            ELSE 5 \
                        END \
                        ORDER BY attempts ASC, updated_at_ms ASC, id ASC \
                    ) AS _rn, \
                    CASE \
                        WHEN kind = 'probe_git' OR id LIKE 'probe:%' THEN 1 \
                        WHEN kind = 'reconcile' OR id LIKE 'reconcile:%' THEN 2 \
                        WHEN kind = 'enumerate_dir' OR id LIKE 'enum:%' THEN 3 \
                        WHEN kind = 'status' OR id LIKE 'status:%' THEN 4 \
                        ELSE 5 \
                    END AS _cls \
                FROM frontier_tasks \
                WHERE generation = ?1 \
                    AND (state = 'pending' OR (state = 'retry_wait' \
                    AND retry_after_ms IS NOT NULL AND retry_after_ms <= ?2)) \
                    {kind_predicate} \
            ) \
            ORDER BY _rn ASC, _cls ASC, id ASC LIMIT {limit}",
        );
        let generation_i64 = u64_to_i64(generation, "task generation")?;
        let mut params = vec![v_int(generation_i64), v_int(now_ms)];
        if let Some(kinds) = kinds {
            params.extend(kinds.iter().map(|k| v_text((*k).to_string())));
        }
        let mut rows = conn.query(sql.as_str(), params).await.map_err(store_err)?;
        let mut tasks = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            tasks.push(FrontierTask::from_row(&row)?);
        }
        Ok(tasks)
    }

    /// Shared generation-scoped claim body. `Some(kinds)` restricts the
    /// claim to those (already allowlisted) kinds; `None` applies no
    /// kind predicate (legacy unfiltered contract).
    async fn claim_tasks_in_generation_inner(
        &self,
        generation: u64,
        epoch: u64,
        limit: usize,
        ttl_ms: i64,
        now_ms: i64,
        kinds: Option<&[&str]>,
    ) -> crate::Result<Vec<ClaimedTask>> {
        // Fix10 probes before the owner gate (see `claim_tasks`).
        u64_to_i64(generation, "task generation")?;
        u64_to_i64(epoch, "lease epoch")?;
        now_ms.checked_add(ttl_ms).ok_or_else(|| {
            Error::Store(format!("lease expiry {now_ms} + {ttl_ms} overflows i64"))
        })?;
        self.check_owner_epoch(epoch, "claim_tasks_in_generation_kinds")?;
        let limit = limit.clamp(1, 1024);
        self.with_tx(|conn| async move {
            Self::expire_leases_in_generation_on(conn, generation, now_ms).await?;
            // Step 9: bounded indexed selection first; the window query
            // stays authoritative whenever the fast path declines
            // (unfiltered claims, R06 class skew, or a multi-kind
            // else-class) — identical sequence either way. Lease
            // issue below is unchanged.
            let tasks = match Self::claim_select_fast(conn, generation, kinds, limit, now_ms)
                .await?
            {
                Some(tasks) => tasks,
                None => Self::claim_select_window(conn, generation, kinds, limit, now_ms).await?,
            };
            let mut claimed = Vec::with_capacity(tasks.len());
            for task in &tasks {
                let token = fresh_token();
                // fix10: checked — see `claim_tasks`; an overflowing expiry
                // must fail the claim, never silently shorten the lease.
                let expires = now_ms.checked_add(ttl_ms).ok_or_else(|| {
                    Error::Store(format!("lease expiry {now_ms} + {ttl_ms} overflows i64"))
                })?;
                let rows = conn
                    .execute(
                        "UPDATE frontier_tasks SET state = 'leased', lease_token = ?1, \
                            lease_epoch = ?2, lease_expires_ms = ?3, \
                            attempts = attempts + 1, updated_at_ms = ?4 WHERE id = ?5 \
                            AND (state = 'pending' OR state = 'retry_wait')",
                        vec![
                            v_int(token),
                            v_int(u64_to_i64(epoch, "lease epoch")?),
                            v_int(expires),
                            v_int(now_ms),
                            v_text(task.id.clone()),
                        ],
                    )
                    .await
                    .map_err(store_err)?;
                if rows == 1 {
                    let mut leased = task.clone();
                    leased.state = TaskState::Leased;
                    leased.lease_token = Some(token);
                    leased.lease_epoch = Some(epoch);
                    leased.lease_expires_ms = Some(expires);
                    // fix10: saturating — see `claim_tasks`; `attempts` is
                    // monotonic telemetry, and the SQL increment above
                    // already committed.
                    leased.attempts = leased.attempts.saturating_add(1);
                    claimed.push(ClaimedTask {
                        task: leased,
                        token,
                        expires_ms: expires,
                    });
                }
            }
            Ok::<Vec<ClaimedTask>, Error>(claimed)
        })
        .await
    }

    /// Extend a live lease. Returns false when the lease is gone, expired
    /// into another incarnation, or held under a different token/epoch.
    pub async fn renew_lease(
        &self,
        task_id: &str,
        token: i64,
        epoch: u64,
        ttl_ms: i64,
        now_ms: i64,
    ) -> crate::Result<bool> {
        self.forbid_write("renew_lease")?;
        // fix10: checked — see `claim_tasks`; an overflowing expiry must
        // fail the renew, never silently shorten the lease. Probed before
        // the owner gate so range/overflow errors keep their own messages.
        let expires = now_ms.checked_add(ttl_ms).ok_or_else(|| {
            Error::Store(format!("lease expiry {now_ms} + {ttl_ms} overflows i64"))
        })?;
        u64_to_i64(epoch, "lease epoch")?;
        self.check_owner_epoch(epoch, "renew_lease")?;
        let rows = self
            .conn
            .execute(
                "UPDATE frontier_tasks SET lease_expires_ms = ?1, updated_at_ms = ?2 \
                    WHERE id = ?3 AND state = 'leased' AND lease_token = ?4 \
                    AND lease_epoch = ?5",
                vec![
                    v_int(expires),
                    v_int(now_ms),
                    v_text(task_id),
                    v_int(token),
                    v_int(u64_to_i64(epoch, "lease epoch")?),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(rows == 1)
    }

    /// Extend several live leases in ONE transaction (Step 9 scheduled
    /// renewal for the worker pool: the coordinator renews every in-flight
    /// task on a tick instead of each worker renewing inline). Returns the
    /// ids whose lease is gone — expired into another incarnation, or held
    /// under a different token/epoch — so the caller stops touching those
    /// scopes; never touches another owner's lease. Empty input commits
    /// nothing and returns empty.
    pub async fn renew_leases_batch(
        &self,
        leases: &[(&str, i64, u64)],
        ttl_ms: i64,
        now_ms: i64,
    ) -> crate::Result<Vec<String>> {
        if leases.is_empty() {
            return Ok(Vec::new());
        }
        self.forbid_write("renew_leases_batch")?;
        let expires = now_ms.checked_add(ttl_ms).ok_or_else(|| {
            Error::Store(format!("lease expiry {now_ms} + {ttl_ms} overflows i64"))
        })?;
        for (_, _, epoch) in leases {
            u64_to_i64(*epoch, "lease epoch")?;
            self.check_owner_epoch(*epoch, "renew_leases_batch")?;
        }
        self.with_tx(|conn| async move {
            let mut lost = Vec::new();
            for (task_id, token, epoch) in leases {
                let rows = conn
                    .execute(
                        "UPDATE frontier_tasks SET lease_expires_ms = ?1, updated_at_ms = ?2 \
                        WHERE id = ?3 AND state = 'leased' AND lease_token = ?4 \
                        AND lease_epoch = ?5",
                        vec![
                            v_int(expires),
                            v_int(now_ms),
                            v_text(*task_id),
                            v_int(*token),
                            v_int(u64_to_i64(*epoch, "lease epoch")?),
                        ],
                    )
                    .await
                    .map_err(store_err)?;
                if rows != 1 {
                    lost.push((*task_id).to_string());
                }
            }
            Ok(lost)
        })
        .await
    }

    /// Return expired leases to `pending`; reports how many moved.
    pub async fn expire_leases(&self, now_ms: i64) -> crate::Result<u64> {
        self.with_tx(|conn| async move { Self::expire_leases_on(conn, now_ms).await })
            .await
    }

    async fn expire_leases_on(conn: &turso::Connection, now_ms: i64) -> crate::Result<u64> {
        let rows = conn
            .execute(
                "UPDATE frontier_tasks SET state = 'pending', lease_token = NULL, \
                    lease_epoch = NULL, lease_expires_ms = NULL, updated_at_ms = ?1 \
                    WHERE state = 'leased' AND lease_expires_ms IS NOT NULL \
                    AND lease_expires_ms <= ?1",
                vec![v_int(now_ms)],
            )
            .await
            .map_err(store_err)?;
        Ok(rows)
    }

    /// Return expired leases of one generation to `pending` (SR-STATE-08):
    /// a generation-scoped claim must not expire other generations' leases.
    async fn expire_leases_in_generation_on(
        conn: &turso::Connection,
        generation: u64,
        now_ms: i64,
    ) -> crate::Result<u64> {
        let rows = conn
            .execute(
                "UPDATE frontier_tasks SET state = 'pending', lease_token = NULL, \
                    lease_epoch = NULL, lease_expires_ms = NULL, updated_at_ms = ?1 \
                    WHERE state = 'leased' AND generation = ?2 \
                    AND lease_expires_ms IS NOT NULL AND lease_expires_ms <= ?1",
                vec![
                    v_int(now_ms),
                    v_int(u64_to_i64(generation, "task generation")?),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(rows)
    }

    /// Accept a completion only when the task is still leased to this exact
    /// token and epoch and the scope revision still matches. A completion
    /// that arrives after an invalidation is stale: the task is requeued
    /// with the fresh revision (never marked complete) and a
    /// `stale-completion` scheduler error is returned. A token/epoch
    /// mismatch returns `lease-mismatch`. Stale results never erase
    /// newer invalidations (spec §12).
    /// Complete one claimed task, discarding any gap delta the outcome
    /// caused. Production completion goes through
    /// [`TursoStore::complete_task_report_gap`] so the delta can be
    /// journaled as `error` / `coverage_updated` events after the commit.
    pub async fn complete_task(
        &self,
        task_id: &str,
        token: i64,
        epoch: u64,
        outcome: &TaskOutcome,
        now_ms: i64,
    ) -> crate::Result<()> {
        self.complete_task_report_gap(task_id, token, epoch, outcome, now_ms)
            .await
            .map(|_| ())
    }

    /// Release a claim that never ran (breaker/admission denial, R4):
    /// the task returns to `pending` immediately instead of leaking
    /// until lease TTL. Compensates the claim's `attempts + 1` — a
    /// denied claim did no work, so it must not burn the retry budget
    /// (`fail_task` exhausts and backs off on attempts). Token/epoch
    /// mismatch releases nothing. Returns whether a lease was held.
    ///
    /// Deliberate per-task-transaction exception to the D5 batching
    /// rule (DB-m3): releases fire only on the rare denial path (a
    /// closed breaker or a full admission gate), never per completed
    /// task — batching them would hold denied leases (and their
    /// attempts compensation) until the next flush for no measurable
    /// gain. Production counts each release as its own transaction.
    pub async fn release_claim(
        &self,
        task_id: &str,
        token: i64,
        epoch: u64,
        now_ms: i64,
    ) -> crate::Result<bool> {
        self.forbid_write("release_claim")?;
        let rows = self
            .connection()
            .execute(
                "UPDATE frontier_tasks SET state = 'pending', lease_token = NULL, \
                 lease_epoch = NULL, lease_expires_ms = NULL, updated_at_ms = ?1, \
                 attempts = CASE WHEN attempts > 0 THEN attempts - 1 ELSE 0 END \
                 WHERE id = ?2 AND state = 'leased' AND lease_token = ?3 \
                 AND lease_epoch = ?4",
                vec![
                    v_int(now_ms),
                    v_text(task_id),
                    v_int(token),
                    v_int(u64_to_i64(epoch, "lease epoch")?),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(rows == 1)
    }

    /// Complete one claimed task. Returns the gap delta the outcome
    /// caused — opened row (`Retry`/`Parked`) and/or closed id
    /// (`Complete`) — so the caller can journal the matching `error` /
    /// `coverage_updated` events after this transaction commits.
    pub async fn complete_task_report_gap(
        &self,
        task_id: &str,
        token: i64,
        epoch: u64,
        outcome: &TaskOutcome,
        now_ms: i64,
    ) -> crate::Result<CompletionDelta> {
        self.check_owner_epoch(epoch, "complete_task")?;
        let (stale, delta) = self
            .with_tx(|conn| async move {
                Self::complete_task_on(conn, task_id, token, epoch, outcome, now_ms).await
            })
            .await?;
        // The stale requeue above committed; report it now. Returning the
        // error from inside the transaction would roll the requeue back.
        match stale {
            None => Ok(delta),
            Some(message) => Err(Error::Scheduler(message)),
        }
    }

    /// Lease gate shared by plain and verified completions: unknown
    /// tasks and token/epoch mismatches error before any write.
    async fn check_lease_on(
        conn: &turso::Connection,
        task_id: &str,
        token: i64,
        epoch: u64,
    ) -> crate::Result<FrontierTask> {
        let task = Self::get_task_on(conn, task_id)
            .await?
            .ok_or_else(|| Error::Scheduler(format!("unknown-task: {task_id}")))?;
        if task.state != TaskState::Leased
            || task.lease_token != Some(token)
            || task.lease_epoch != Some(epoch)
        {
            return Err(Error::Scheduler(format!(
                "lease-mismatch: task {task_id} is not leased to epoch {epoch} token {token}"
            )));
        }
        Ok(task)
    }

    /// Positive durability check for a parent's preserved child records
    /// (spec §10): every claimed child task id must already be durable in
    /// `frontier_tasks` before the parent may complete. A missing child is
    /// a scheduler defect — the parent stays leased (the caller's
    /// transaction rolls back with no write) so work is never silently
    /// dropped. Checked in 500-id chunks to stay under bound-variable
    /// limits; an empty list (leaf parent) passes vacuously. Callers using
    /// writer batches must flush before verified completion.
    async fn verify_child_records_on(
        conn: &turso::Connection,
        task_id: &str,
        child_task_ids: &[String],
    ) -> crate::Result<()> {
        for chunk in child_task_ids.chunks(500) {
            if chunk.is_empty() {
                continue;
            }
            let placeholders: Vec<String> =
                (1..=chunk.len()).map(|index| format!("?{index}")).collect();
            let sql = format!(
                "SELECT id FROM frontier_tasks WHERE id IN ({})",
                placeholders.join(", ")
            );
            let params: Vec<turso::Value> = chunk.iter().map(|id| v_text(id.as_str())).collect();
            let mut rows = conn.query(sql.as_str(), params).await.map_err(store_err)?;
            let mut found = HashSet::new();
            while let Some(row) = rows.next().await.map_err(store_err)? {
                found.insert(req_text(&row, 0)?);
            }
            let missing: Vec<&str> = chunk
                .iter()
                .map(String::as_str)
                .filter(|id| !found.contains(*id))
                .collect();
            if !missing.is_empty() {
                let shown: Vec<&str> = missing.iter().take(8).copied().collect();
                return Err(Error::Scheduler(format!(
                    "missing-child-record: parent {task_id} claims {} preserved child \
                        record(s) but {} are not durable (e.g. {})",
                    child_task_ids.len(),
                    missing.len(),
                    shown.join(", ")
                )));
            }
        }
        Ok(())
    }

    /// Revision gate plus outcome application shared by plain and verified
    /// completions. Returns the stale-completion message when the task was
    /// requeued (committed by the caller), `None` on a clean completion —
    /// plus the gap row the outcome recorded, if any, so the caller can
    /// journal the matching `error` event after this transaction commits.
    async fn apply_completion_on(
        conn: &turso::Connection,
        task: &FrontierTask,
        outcome: &TaskOutcome,
        now_ms: i64,
    ) -> crate::Result<(Option<String>, CompletionDelta)> {
        let current_rev = Self::scope_rev_on(conn, &task.scope_key).await?;
        if current_rev != task.expected_rev {
            conn.execute(
                "UPDATE frontier_tasks SET state = 'pending', lease_token = NULL, \
                    lease_epoch = NULL, lease_expires_ms = NULL, expected_rev = ?1, \
                    updated_at_ms = ?2 WHERE id = ?3",
                vec![
                    v_int(u64_to_i64(current_rev, "scope revision")?),
                    v_int(now_ms),
                    v_text(task.id.as_str()),
                ],
            )
            .await
            .map_err(store_err)?;
            return Ok((
                Some(format!(
                    "stale-completion: task {} expected rev {} but scope {:?} \
                    is at rev {current_rev}; task requeued",
                    task.id, task.expected_rev, task.scope_key
                )),
                CompletionDelta::default(),
            ));
        }
        let gap = match outcome {
            TaskOutcome::Complete => {
                conn.execute(
                    "UPDATE frontier_tasks SET state = 'complete', lease_token = NULL, \
                        lease_epoch = NULL, lease_expires_ms = NULL, updated_at_ms = ?1 \
                        WHERE id = ?2",
                    vec![v_int(now_ms), v_text(task.id.as_str())],
                )
                .await
                .map_err(store_err)?;
                // FIXREADY6 resume-gap: a successful (possibly retried)
                // completion supersedes this task's failure gap — close
                // `gap:<task>` so a stale in-flight-interrupt gap can
                // never poison verdicts permanently. The row stays for
                // audit (`open = 0`); tasks that never failed match zero
                // rows (no-op).
                let gap_id = format!("gap:{}", task.id);
                let closed_rows = conn
                    .execute(
                        "UPDATE errors SET open = 0, last_seen_ms = ?1 WHERE id = ?2 AND open = 1",
                        vec![v_int(now_ms), v_text(gap_id.clone())],
                    )
                    .await
                    .map_err(store_err)?;
                // Rowcount-gated: only a genuinely open row reports a
                // close. Close deltas belong to `coverage_updated`, not
                // `error`.
                CompletionDelta {
                    opened: None,
                    closed: if closed_rows > 0 { Some(gap_id) } else { None },
                }
            }
            TaskOutcome::Retry {
                category,
                detail,
                retry_after_ms,
            } => {
                conn.execute(
                    "UPDATE frontier_tasks SET state = 'retry_wait', lease_token = NULL, \
                        lease_epoch = NULL, lease_expires_ms = NULL, \
                        retry_after_ms = ?1, updated_at_ms = ?2 WHERE id = ?3",
                    vec![
                        v_int(*retry_after_ms),
                        v_int(now_ms),
                        v_text(task.id.as_str()),
                    ],
                )
                .await
                .map_err(store_err)?;
                let gap_id = format!("gap:{}", task.id);
                Self::record_error_on(
                    conn,
                    &gap_id,
                    &task.scope_key,
                    category,
                    detail,
                    Some(*retry_after_ms),
                    now_ms,
                )
                .await?;
                CompletionDelta {
                    opened: Some(CompletionGap {
                        id: gap_id,
                        scope_key: task.scope_key.clone(),
                        category: (*category).clone(),
                        detail: (*detail).clone(),
                    }),
                    closed: None,
                }
            }
            TaskOutcome::Parked { state, reason } => {
                if !matches!(state, TaskState::Unavailable | TaskState::Unsupported) {
                    return Err(Error::Scheduler(format!(
                        "invalid-parked-state: {state:?} (want unavailable or unsupported)"
                    )));
                }
                conn.execute(
                    "UPDATE frontier_tasks SET state = ?1, lease_token = NULL, \
                        lease_epoch = NULL, lease_expires_ms = NULL, updated_at_ms = ?2 \
                        WHERE id = ?3",
                    vec![
                        v_text(task_state_as_str(*state)),
                        v_int(now_ms),
                        v_text(task.id.as_str()),
                    ],
                )
                .await
                .map_err(store_err)?;
                let gap_id = format!("gap:{}", task.id);
                Self::record_error_on(
                    conn,
                    &gap_id,
                    &task.scope_key,
                    task_state_as_str(*state),
                    reason,
                    None,
                    now_ms,
                )
                .await?;
                CompletionDelta {
                    opened: Some(CompletionGap {
                        id: gap_id,
                        scope_key: task.scope_key.clone(),
                        category: task_state_as_str(*state).to_string(),
                        detail: (*reason).clone(),
                    }),
                    closed: None,
                }
            }
        };
        Ok((None, gap))
    }

    /// Returns the stale-completion message when the task was requeued
    /// (committed by the caller), `None` on a clean completion — plus the
    /// gap row the outcome recorded, if any. Lease and parked-state errors
    /// return before any write, so their rollback is a no-op; only the
    /// stale path writes-then-reports.
    async fn complete_task_on(
        conn: &turso::Connection,
        task_id: &str,
        token: i64,
        epoch: u64,
        outcome: &TaskOutcome,
        now_ms: i64,
    ) -> crate::Result<(Option<String>, CompletionDelta)> {
        let task = Self::check_lease_on(conn, task_id, token, epoch).await?;
        Self::apply_completion_on(conn, &task, outcome, now_ms).await
    }

    /// Verified parent completion (spec §10): the lease and revision gates
    /// of [`TursoStore::complete_task`], plus a positive check that every id
    /// in `child_task_ids` names a durable `frontier_tasks` record before a
    /// `Complete` outcome is applied. A missing child fails with a
    /// `missing-child-record` scheduler error and leaves the parent leased;
    /// non-`Complete` outcomes skip the child check (no children are claimed
    /// durable). Stale completions still requeue and report as before.
    /// Callers using writer batches must flush before calling this.
    /// Returns the gap row the outcome recorded, if any (see
    /// [`TursoStore::complete_task`]). Recorded gaps are discarded: no
    /// production caller completes verified parents yet, so there is no
    /// journal to report them to.
    pub async fn complete_task_with_children(
        &self,
        task_id: &str,
        token: i64,
        epoch: u64,
        outcome: &TaskOutcome,
        child_task_ids: &[String],
        now_ms: i64,
    ) -> crate::Result<()> {
        self.check_owner_epoch(epoch, "complete_task_with_children")?;
        let (stale, _gap) = self
            .with_tx(|conn| async move {
                let task = Self::check_lease_on(conn, task_id, token, epoch).await?;
                if matches!(outcome, TaskOutcome::Complete) {
                    Self::verify_child_records_on(conn, &task.id, child_task_ids).await?;
                }
                Self::apply_completion_on(conn, &task, outcome, now_ms).await
            })
            .await?;
        // The stale requeue above committed; report it now. Returning the
        // error from inside the transaction would roll the requeue back.
        match stale {
            None => Ok(()),
            Some(message) => Err(Error::Scheduler(message)),
        }
    }

    /// Durably invalidate a scope: bump its revision, mirror directory
    /// scopes into `directories.invalidation_rev`, and schedule one
    /// reconciliation task for the new revision. Returns the new revision.
    /// Invalidation success never claims the rescan is complete (spec §3).
    pub async fn invalidate_scope(
        &self,
        scope_key: &str,
        generation: u64,
        now_ms: i64,
    ) -> crate::Result<u64> {
        self.with_tx(|conn| async move {
            Self::invalidate_scope_on(conn, scope_key, generation, now_ms).await
        })
        .await
    }

    /// One scope invalidation inside the caller's transaction: revision
    /// bump, directory mirror, and reconcile-task enqueue. Shared by
    /// [`TursoStore::invalidate_scope`] and the atomic event ingest
    /// [`TursoStore::ingest_event_batch`] so both paths schedule identical
    /// work. Returns the new revision.
    ///
    /// Spelling fan-out (DB-M1): scope keys keep observed spellings
    /// (execution derives task paths from keys), so the same object
    /// may hold keys under several spellings. After the literal bump,
    /// every live-task key denoting the same object (compared through
    /// the shared [`crate::config::canonical_scope_path`]) is bumped
    /// from its own revision too — otherwise an invalidate issued
    /// under one spelling silently misses live tasks scheduled under
    /// another. One reconcile task still suffices (same object).
    async fn invalidate_scope_on(
        conn: &turso::Connection,
        scope_key: &str,
        generation: u64,
        now_ms: i64,
    ) -> crate::Result<u64> {
        let next = Self::scope_rev_on(conn, scope_key)
            .await?
            .checked_add(1)
            .ok_or_else(|| Error::Store("scope revision overflow".to_string()))?;
        let next_i64 = i64::try_from(next)
            .map_err(|_| Error::Store(format!("scope revision {next} exceeds i64 range")))?;
        let generation_i64 = i64::try_from(generation)
            .map_err(|_| Error::Store(format!("generation {generation} exceeds i64 range")))?;
        conn.execute(
            "INSERT OR REPLACE INTO scope_revisions (scope_key, rev, updated_at_ms) \
                VALUES (?1, ?2, ?3)",
            vec![v_text(scope_key), v_int(next_i64), v_int(now_ms)],
        )
        .await
        .map_err(store_err)?;
        // Mirror directory scopes into `directories.invalidation_rev`
        // (§11): `dir:` keys carry hex-encoded path bytes, never row ids,
        // so the directory rows are looked up by path, not parsed.
        Self::mirror_dir_invalidation(conn, scope_key, next).await?;
        // Cross-spelling fan-out (DB-M1): live tasks under another
        // spelling of this object requeue like directly-invalidated
        // ones. Each key bumps from its own revision with its own
        // mirror; failures are loud (caller's transaction rolls back).
        for fan_key in Self::same_object_live_keys(conn, scope_key).await? {
            let fan_next = Self::scope_rev_on(conn, &fan_key)
                .await?
                .checked_add(1)
                .ok_or_else(|| Error::Store("scope revision overflow".to_string()))?;
            let fan_next_i64 = i64::try_from(fan_next).map_err(|_| {
                Error::Store(format!("scope revision {fan_next} exceeds i64 range"))
            })?;
            conn.execute(
                "INSERT OR REPLACE INTO scope_revisions (scope_key, rev, updated_at_ms) \
                    VALUES (?1, ?2, ?3)",
                vec![v_text(fan_key.as_str()), v_int(fan_next_i64), v_int(now_ms)],
            )
            .await
            .map_err(store_err)?;
            Self::mirror_dir_invalidation(conn, &fan_key, fan_next).await?;
        }
        let task_id = format!("reconcile:{scope_key}:{next}");
        let idempotency = format!("idem:{task_id}");
        // Step 9: class-skew mark (no-op for this consistent pair; kept
        // so every `frontier_tasks` insert path is covered by construction).
        note_task_class("reconcile", &task_id);
        conn.execute(
            "INSERT OR IGNORE INTO frontier_tasks (id, kind, generation, dir_id, \
                scope_key, expected_rev, state, idempotency_key, attempts, \
                updated_at_ms) VALUES (?1, 'reconcile', ?2, NULL, ?3, ?4, \
                'pending', ?5, 0, ?6)",
            vec![
                v_text(task_id),
                v_int(generation_i64),
                v_text(scope_key),
                v_int(next_i64),
                v_text(idempotency),
                v_int(now_ms),
            ],
        )
        .await
        .map_err(store_err)?;
        Ok(next)
    }

    /// Live-task scope keys denoting the same object as `scope_key`
    /// under a different spelling (DB-M1 fan-out set). Only `dir:` and
    /// `git:` keys participate (other families carry no paths); only
    /// keys with live (`pending`/`leased`/`retry_wait`) tasks are
    /// returned — completed work needs no requeue, and future tasks
    /// read the bumped revision at creation. Identity compares
    /// through [`crate::config::canonical_scope_path`]; unparseable
    /// keys and unresolvable paths never match. The input key itself
    /// is excluded (the caller already bumped it). Runs inside the
    /// caller's transaction.
    async fn same_object_live_keys(
        conn: &turso::Connection,
        scope_key: &str,
    ) -> crate::Result<Vec<String>> {
        use crate::config::ScopeRef;
        let target = match crate::config::parse_scope_key(scope_key) {
            Some(ScopeRef::Dir(path)) | Some(ScopeRef::Git(path)) => {
                crate::config::canonical_scope_path(&path)
            }
            Some(ScopeRef::Status(_)) | None => return Ok(Vec::new()),
        };
        let mut rows = conn
            .query(
                "SELECT DISTINCT scope_key FROM frontier_tasks \
                    WHERE state IN ('pending', 'leased', 'retry_wait') \
                    AND (scope_key LIKE 'dir:%' OR scope_key LIKE 'git:%')",
                (),
            )
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let key = req_text(&row, 0)?;
            if key == scope_key {
                continue;
            }
            let same = match crate::config::parse_scope_key(&key) {
                Some(ScopeRef::Dir(path)) | Some(ScopeRef::Git(path)) => {
                    crate::config::canonical_scope_path(&path) == target
                }
                Some(ScopeRef::Status(_)) | None => false,
            };
            if same {
                out.push(key);
            }
        }
        Ok(out)
    }

    /// Mirror a `dir:` scope invalidation into every matching
    /// `directories` row (all incarnations of that path). The hex suffix is
    /// decoded to path bytes and matched against the stored `display` (the
    /// same lossy-escaped full path the enumeration path stores) plus exact
    /// final-component bytes, so a lossy-escape collision can never mirror
    /// into an unrelated directory. Non-`dir:` scopes and malformed keys
    /// mirror nothing; the `scope_revisions` bump (the correctness guard)
    /// always applies. Runs inside the caller's transaction.
    ///
    /// SR-STATE-09: paged with a bounded fanout — one 256-row keyset page
    /// at a time, at most 1,024 mirrored rows. Past the cap the whole
    /// invalidation fails loudly (the caller's transaction rolls back)
    /// instead of gathering unbounded IDs or mirroring partially.
    async fn mirror_dir_invalidation(
        conn: &turso::Connection,
        scope_key: &str,
        rev: u64,
    ) -> crate::Result<()> {
        const MIRROR_PAGE: usize = 256;
        const MIRROR_MAX: u64 = 1024;
        let Some(hex) = scope_key.strip_prefix("dir:") else {
            return Ok(());
        };
        let Some(path_bytes) = crate::config::decode_hex(hex) else {
            return Ok(());
        };
        if path_bytes.is_empty() {
            return Ok(());
        }
        let display: String = String::from_utf8_lossy(&path_bytes)
            .chars()
            .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
            .collect();
        let component: Vec<u8> =
            match crate::config::path_from_bytes(path_bytes.clone()).file_name() {
                Some(name) => crate::config::path_as_bytes(Path::new(name)),
                None => path_bytes,
            };
        let rev_i64 = i64::try_from(rev)
            .map_err(|_| Error::Store(format!("invalidation revision {rev} exceeds i64 range")))?;
        let mut last_id: i64 = 0;
        let mut mirrored: u64 = 0;
        loop {
            // Bound literal is interpolated (numeric, owner-controlled) so
            // the query needs no bound LIMIT support.
            let sql = format!(
                "SELECT id FROM directories WHERE display = ?1 AND component = ?2 \
                    AND id > ?3 ORDER BY id ASC LIMIT {MIRROR_PAGE}"
            );
            let mut rows = conn
                .query(
                    sql.as_str(),
                    vec![
                        v_text(display.as_str()),
                        v_blob(component.clone()),
                        v_int(last_id),
                    ],
                )
                .await
                .map_err(store_err)?;
            let mut ids = Vec::new();
            while let Some(row) = rows.next().await.map_err(store_err)? {
                ids.push(req_i64(&row, 0)?);
            }
            if ids.is_empty() {
                break;
            }
            for id in ids {
                mirrored += 1;
                if mirrored > MIRROR_MAX {
                    return Err(Error::Store(format!(
                        "invalidation fanout for {scope_key:?} exceeds {MIRROR_MAX} \
                            directory rows; refusing partial mirror"
                    )));
                }
                conn.execute(
                    "UPDATE directories SET invalidation_rev = ?1 WHERE id = ?2",
                    vec![v_int(rev_i64), v_int(id)],
                )
                .await
                .map_err(store_err)?;
                last_id = id;
            }
        }
        Ok(())
    }

    /// Current revision of a scope (0 when never invalidated).
    pub async fn scope_rev(&self, scope_key: &str) -> crate::Result<u64> {
        Self::scope_rev_on(&self.conn, scope_key).await
    }

    async fn scope_rev_on(conn: &turso::Connection, scope_key: &str) -> crate::Result<u64> {
        let mut rows = conn
            .query(
                "SELECT rev FROM scope_revisions WHERE scope_key = ?1",
                vec![v_text(scope_key)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(0),
            Some(row) => {
                let rev = req_i64(&row, 0)?;
                u64::try_from(rev).map_err(|_| {
                    Error::Store(format!(
                        "scope revision {rev} in catalog is not a valid u64"
                    ))
                })
            }
        }
    }

    /// Tasks in `generation` that still need scheduler action (any
    /// non-terminal state), for run-boundary accounting.
    pub async fn pending_count(&self, generation: u64) -> crate::Result<u64> {
        self.pending_count_kinds(
            generation,
            &[
                "enumerate_dir",
                "probe_git",
                "status",
                "reconcile",
                "analyze_store",
            ],
        )
        .await
    }

    /// Incomplete-task count for one generation restricted to `kinds`
    /// (phase gating, goal Step 8: the discovery boundary counts
    /// enumeration/probe/reconcile only — analysis kinds have not
    /// started yet, so counting them would poison the verdict).
    pub async fn pending_count_kinds(&self, generation: u64, kinds: &[&str]) -> crate::Result<u64> {
        if kinds.is_empty() {
            return Ok(0);
        }
        let kind_params: Vec<String> = (0..kinds.len()).map(|i| format!("?{}", i + 2)).collect();
        let sql = format!(
            "SELECT COUNT(*) FROM frontier_tasks WHERE generation = ?1 \
                AND state NOT IN ('complete', 'unsupported', 'cancelled', 'superseded') \
                AND kind IN ({})",
            kind_params.join(", ")
        );
        let mut params = vec![v_int(u64_to_i64(generation, "task generation")?)];
        params.extend(kinds.iter().map(|k| v_text((*k).to_string())));
        let mut rows = self
            .conn
            .query(sql.as_str(), params)
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(0),
            Some(row) => Ok(i64_to_u64(req_i64(&row, 0)?, "pending task count")?),
        }
    }
}

/// One durable directory record: parent/component path plus native identity.
#[derive(Debug, Clone)]
pub struct DirRecord {
    /// Row id, referenced by tasks and observations.
    pub id: i64,
    /// Parent directory row, if known.
    pub parent_id: Option<i64>,
    /// Final path component, exact bytes.
    pub component: Vec<u8>,
    /// Escaped presentation text.
    pub display: String,
    /// Owning volume id.
    pub volume_id: String,
    /// Filesystem object identity.
    pub object_id: String,
    /// Incarnation guard against identifier reuse.
    pub incarnation: String,
    /// Last observation time, if observed.
    pub last_observed_ms: Option<i64>,
    /// Invalidation revision mirrored from `scope_revisions`.
    pub invalidation_rev: u64,
}

impl DirRecord {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_i64(row, 0)?,
            parent_id: opt_i64(row, 1)?,
            component: req_blob(row, 2)?,
            display: req_text(row, 3)?,
            volume_id: req_text(row, 4)?,
            object_id: req_text(row, 5)?,
            incarnation: req_text(row, 6)?,
            last_observed_ms: opt_i64(row, 7)?,
            invalidation_rev: i64_to_u64(req_i64(row, 8)?, "dir invalidation_rev")?,
        })
    }
}

/// Enumeration observation for one directory in one generation.
#[derive(Debug, Clone)]
pub struct DirObservation {
    /// Directory row id.
    pub dir_id: i64,
    /// Traversal generation.
    pub generation: u64,
    /// End-of-enumeration reached with revision validation.
    pub completed: bool,
    /// Entry generation counter for change detection.
    pub entry_generation: u64,
    /// Entries seen during enumeration.
    pub entries_seen: u64,
    /// Enumeration error, if the observation is partial.
    pub error: Option<String>,
    /// Observation time.
    pub observed_at_ms: i64,
}

impl DirObservation {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            dir_id: req_i64(row, 0)?,
            generation: i64_to_u64(req_i64(row, 1)?, "dir observation generation")?,
            completed: req_i64(row, 2)? != 0,
            entry_generation: i64_to_u64(req_i64(row, 3)?, "dir entry_generation")?,
            entries_seen: i64_to_u64(req_i64(row, 4)?, "dir entries_seen")?,
            error: opt_text(row, 5)?,
            observed_at_ms: req_i64(row, 6)?,
        })
    }
}

/// One durable Git instance (common storage).
#[derive(Debug, Clone)]
pub struct GitInstanceRow {
    /// Stable instance id.
    pub id: String,
    /// Git directory path, exact bytes.
    pub git_path: Vec<u8>,
    /// Common directory path, exact bytes.
    pub common_path: Vec<u8>,
    /// Incarnation guard.
    pub incarnation: String,
    /// Storage format marker.
    pub format: String,
    /// Bare flag, if known.
    pub bare: Option<bool>,
    /// Object format (`sha1`, `sha256`).
    pub object_format: String,
    /// Identity disposition under the matching policy.
    pub disposition: String,
    /// Evidence JSON.
    pub evidence_json: String,
    /// Observation time.
    pub observed_at_ms: i64,
}

impl GitInstanceRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_text(row, 0)?,
            git_path: req_blob(row, 1)?,
            common_path: req_blob(row, 2)?,
            incarnation: req_text(row, 3)?,
            format: req_text(row, 4)?,
            bare: opt_i64(row, 5)?.map(|flag| flag != 0),
            object_format: req_text(row, 6)?,
            disposition: req_text(row, 7)?,
            evidence_json: req_text(row, 8)?,
            observed_at_ms: req_i64(row, 9)?,
        })
    }
}

/// New Git instance for [`TursoStore::upsert_git_instance`].
#[derive(Debug, Clone)]
pub struct NewGitInstance<'a> {
    /// Stable instance id.
    pub id: &'a str,
    /// Git directory path, exact bytes.
    pub git_path: &'a [u8],
    /// Common directory path, exact bytes.
    pub common_path: &'a [u8],
    /// Incarnation guard.
    pub incarnation: &'a str,
    /// Storage format marker.
    pub format: &'a str,
    /// Bare flag, if known.
    pub bare: Option<bool>,
    /// Object format.
    pub object_format: &'a str,
    /// Identity disposition.
    pub disposition: &'a str,
    /// Evidence JSON.
    pub evidence_json: &'a str,
}

/// One durable checkout (working tree) record.
#[derive(Debug, Clone)]
pub struct CheckoutRow {
    /// Stable checkout id.
    pub id: String,
    /// Owning instance id.
    pub instance_id: String,
    /// Worktree root path, exact bytes (absent for bare stores).
    pub root_path: Option<Vec<u8>>,
    /// Git directory path, exact bytes.
    pub git_path: Vec<u8>,
    /// Instance relationship (`main`, `linked`, `submodule`, `unknown`).
    pub relationship: String,
    /// Availability (`present`, `missing`, `inaccessible`, `broken`).
    pub availability: String,
    /// HEAD state (`branch`, `detached`, `unborn`, `invalid`, `unknown`).
    pub head_state: String,
    /// HEAD ref name, exact bytes, when on a branch.
    pub head_ref: Option<Vec<u8>>,
    /// HEAD object id, exact bytes, when known.
    pub head_oid: Option<Vec<u8>>,
    /// HEAD object-id algorithm, when known.
    pub head_algo: Option<String>,
    /// Observation time.
    pub observed_at_ms: i64,
}

impl CheckoutRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_text(row, 0)?,
            instance_id: req_text(row, 1)?,
            root_path: opt_blob(row, 2)?,
            git_path: req_blob(row, 3)?,
            relationship: req_text(row, 4)?,
            availability: req_text(row, 5)?,
            head_state: req_text(row, 6)?,
            head_ref: opt_blob(row, 7)?,
            head_oid: opt_blob(row, 8)?,
            head_algo: opt_text(row, 9)?,
            observed_at_ms: req_i64(row, 10)?,
        })
    }
}

/// New checkout for [`TursoStore::upsert_checkout`].
#[derive(Debug, Clone)]
pub struct NewCheckout<'a> {
    /// Stable checkout id.
    pub id: &'a str,
    /// Owning instance id.
    pub instance_id: &'a str,
    /// Worktree root path, exact bytes.
    pub root_path: Option<&'a [u8]>,
    /// Git directory path, exact bytes.
    pub git_path: &'a [u8],
    /// Instance relationship.
    pub relationship: &'a str,
    /// Availability.
    pub availability: &'a str,
    /// HEAD state.
    pub head_state: &'a str,
    /// HEAD ref name, exact bytes.
    pub head_ref: Option<&'a [u8]>,
    /// HEAD object id, exact bytes.
    pub head_oid: Option<&'a [u8]>,
    /// HEAD object-id algorithm.
    pub head_algo: Option<&'a str>,
}

/// One durable effective-remote observation.
#[derive(Debug, Clone)]
pub struct RemoteRow {
    /// Stable remote id.
    pub id: String,
    /// Owning instance id.
    pub instance_id: String,
    /// Checkout scope, when checkout-specific.
    pub checkout_scope_id: Option<String>,
    /// Remote name, exact bytes.
    pub name: Vec<u8>,
    /// Effective role (`fetch` or `push`).
    pub role: String,
    /// Redacted URL, exact bytes.
    pub url: Vec<u8>,
    /// Normalized canonical URL, exact bytes, when supported.
    pub canonical_url: Option<Vec<u8>>,
    /// Observation time.
    pub observed_at_ms: i64,
}

impl RemoteRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_text(row, 0)?,
            instance_id: req_text(row, 1)?,
            checkout_scope_id: opt_text(row, 2)?,
            name: req_blob(row, 3)?,
            role: req_text(row, 4)?,
            url: req_blob(row, 5)?,
            canonical_url: opt_blob(row, 6)?,
            observed_at_ms: req_i64(row, 7)?,
        })
    }
}

/// New remote for [`TursoStore::upsert_remote`].
#[derive(Debug, Clone)]
pub struct NewRemote<'a> {
    /// Stable remote id.
    pub id: &'a str,
    /// Owning instance id.
    pub instance_id: &'a str,
    /// Checkout scope, when checkout-specific.
    pub checkout_scope_id: Option<&'a str>,
    /// Remote name, exact bytes.
    pub name: &'a [u8],
    /// Effective role.
    pub role: &'a str,
    /// Redacted URL, exact bytes.
    pub url: &'a [u8],
    /// Normalized canonical URL, exact bytes.
    pub canonical_url: Option<&'a [u8]>,
}

/// One durable reference observation.
#[derive(Debug, Clone)]
pub struct RefRow {
    /// Stable ref id.
    pub id: String,
    /// Owning instance id.
    pub instance_id: String,
    /// Checkout scope, when checkout-specific.
    pub checkout_scope_id: Option<String>,
    /// Reference kind (`local`, `remote_tracking`, `other`).
    pub kind: String,
    /// Full ref name, exact bytes.
    pub name: Vec<u8>,
    /// Object id, exact bytes, when known.
    pub oid: Option<Vec<u8>>,
    /// Object-id algorithm, when known.
    pub algo: Option<String>,
    /// Symbolic target, exact bytes, when symbolic.
    pub symbolic_target: Option<Vec<u8>>,
    /// Upstream ref, exact bytes, when known.
    pub upstream: Option<Vec<u8>>,
    /// Reference state (`valid`, `unborn`, `invalid`, `unsupported`).
    pub state: String,
    /// Observation time.
    pub observed_at_ms: i64,
    /// v3: remote freshness (`current`|`stale`|`unknown`); `None` =
    /// legacy/unlabeled row or a non-remote-tracking ref, read as
    /// `unknown`. Only `kind = 'remote_tracking'` rows are labeled.
    pub freshness: Option<String>,
    /// v3: when the freshness label was assigned.
    pub freshness_at_ms: Option<i64>,
    /// v6: branch comparison state (D7 vocabulary); `None` = legacy
    /// pre-v6 row, a ref kind that is never compared, or a catalog
    /// whose v6 columns are absent — all read as `pending`.
    pub comparison_state: Option<String>,
    /// v6: ahead count; `None` = unknown (never zero-by-default).
    pub ahead: Option<i64>,
    /// v6: behind count; `None` = unknown (never zero-by-default).
    pub behind: Option<i64>,
}

impl RefRow {
    /// v5 column shape (indices 0–12); comparison fields read `None`.
    fn from_row_v5(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_text(row, 0)?,
            instance_id: req_text(row, 1)?,
            checkout_scope_id: opt_text(row, 2)?,
            kind: req_text(row, 3)?,
            name: req_blob(row, 4)?,
            oid: opt_blob(row, 5)?,
            algo: opt_text(row, 6)?,
            symbolic_target: opt_blob(row, 7)?,
            upstream: opt_blob(row, 8)?,
            state: req_text(row, 9)?,
            observed_at_ms: req_i64(row, 10)?,
            freshness: opt_text(row, 11)?,
            freshness_at_ms: opt_i64(row, 12)?,
            comparison_state: None,
            ahead: None,
            behind: None,
        })
    }

    /// v6 column shape (indices 0–15): v5 columns plus
    /// `comparison_state`, `ahead`, `behind`.
    fn from_row_v6(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_text(row, 0)?,
            instance_id: req_text(row, 1)?,
            checkout_scope_id: opt_text(row, 2)?,
            kind: req_text(row, 3)?,
            name: req_blob(row, 4)?,
            oid: opt_blob(row, 5)?,
            algo: opt_text(row, 6)?,
            symbolic_target: opt_blob(row, 7)?,
            upstream: opt_blob(row, 8)?,
            state: req_text(row, 9)?,
            observed_at_ms: req_i64(row, 10)?,
            freshness: opt_text(row, 11)?,
            freshness_at_ms: opt_i64(row, 12)?,
            comparison_state: opt_text(row, 13)?,
            ahead: opt_i64(row, 14)?,
            behind: opt_i64(row, 15)?,
        })
    }
}

/// True when the `refs` table physically carries the v6 comparison
/// columns (`comparison_state`, `ahead`, `behind`). Gates every
/// comparison read/write until the coordinator wires migration v6:
/// v5 catalogs take the legacy path (reads `pending`/null, writes
/// skipped) instead of failing on missing columns. Plain
/// `sqlite_master` SELECT — no exotic syntax.
pub async fn refs_has_comparison(conn: &turso::Connection) -> crate::Result<bool> {
    let mut rows = conn
        .query(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'refs'",
            (),
        )
        .await
        .map_err(store_err)?;
    let Some(row) = rows.next().await.map_err(store_err)? else {
        return Ok(false);
    };
    let sql = match row.get_value(0).map_err(store_err)? {
        turso::Value::Text(sql) => sql,
        _ => return Ok(false),
    };
    Ok(sql.contains("comparison_state") && sql.contains("ahead") && sql.contains("behind"))
}

/// One row of the v3 `remote_refreshes` table: the last `--fetch`
/// attempt for one local store + remote name. Only the remote NAME is
/// stored — never the URL (raw URLs may embed credentials; canonical
/// URLs already live in `remotes`).
#[derive(Debug, Clone)]
pub struct RemoteRefreshRow {
    /// Local-store (git instance) id.
    pub store_id: String,
    /// Remote name bytes (`origin`, ...).
    pub remote_name: Vec<u8>,
    /// Attempt status: `success`|`failed`|`unsupported`.
    pub status: String,
    /// Attempt observation (end) time.
    pub observed_at_ms: i64,
    /// Attempt duration; `None` when not measured.
    pub duration_ms: Option<i64>,
    /// Tracking refs the fetch updated.
    pub refs_updated: i64,
    /// JSON names observed current; `None` when none/unknown.
    pub refs_current_json: Option<String>,
    /// JSON names found deleted upstream (local tracking refs are
    /// KEPT, never pruned); `None` when none/unknown.
    pub refs_deleted_json: Option<String>,
    /// Scrubbed detail; `None` on clean success.
    pub detail: Option<String>,
}

impl RemoteRefreshRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            store_id: req_text(row, 0)?,
            remote_name: req_blob(row, 1)?,
            status: req_text(row, 2)?,
            observed_at_ms: req_i64(row, 3)?,
            duration_ms: opt_i64(row, 4)?,
            refs_updated: req_i64(row, 5)?,
            refs_current_json: opt_text(row, 6)?,
            refs_deleted_json: opt_text(row, 7)?,
            detail: opt_text(row, 8)?,
        })
    }
}

/// Insert shape for a v3 `remote_refreshes` row.
#[derive(Debug, Clone, Copy)]
pub struct NewRemoteRefresh<'a> {
    /// Local-store (git instance) id.
    pub store_id: &'a str,
    /// Remote name bytes.
    pub remote_name: &'a [u8],
    /// Attempt status: `success`|`failed`|`unsupported`.
    pub status: &'a str,
    /// Attempt observation (end) time.
    pub observed_at_ms: i64,
    /// Attempt duration; `None` when not measured.
    pub duration_ms: Option<i64>,
    /// Tracking refs the fetch updated.
    pub refs_updated: i64,
    /// JSON names observed current; `None` when none/unknown.
    pub refs_current_json: Option<&'a str>,
    /// JSON names found deleted upstream; `None` when none/unknown.
    pub refs_deleted_json: Option<&'a str>,
    /// Scrubbed detail; `None` on clean success.
    pub detail: Option<&'a str>,
}

/// New ref for [`TursoStore::upsert_ref`].
#[derive(Debug, Clone)]
pub struct NewRef<'a> {
    /// Stable ref id.
    pub id: &'a str,
    /// Owning instance id.
    pub instance_id: &'a str,
    /// Checkout scope, when checkout-specific.
    pub checkout_scope_id: Option<&'a str>,
    /// Reference kind.
    pub kind: &'a str,
    /// Full ref name, exact bytes.
    pub name: &'a [u8],
    /// Object id, exact bytes.
    pub oid: Option<&'a [u8]>,
    /// Object-id algorithm.
    pub algo: Option<&'a str>,
    /// Symbolic target, exact bytes.
    pub symbolic_target: Option<&'a [u8]>,
    /// Upstream ref, exact bytes.
    pub upstream: Option<&'a [u8]>,
    /// Reference state.
    pub state: &'a str,
}

/// One durable working-state observation.
#[derive(Debug, Clone)]
pub struct StatusRow {
    /// Row id.
    pub id: i64,
    /// Observed checkout id.
    pub checkout_id: String,
    /// Inspection mode (`metadata`, `summary`, `full`).
    pub mode: String,
    /// Observation state.
    pub state: String,
    /// Probe start, when probed.
    pub started_ms: Option<i64>,
    /// Probe finish, when probed.
    pub finished_ms: Option<i64>,
    /// Staged tracked paths, when known.
    pub staged: Option<i64>,
    /// Unstaged tracked paths, when known.
    pub unstaged: Option<i64>,
    /// Untracked entries, when known.
    pub untracked: Option<i64>,
    /// Distinct unmerged paths, when known (v5; `None` also covers
    /// legacy rows and metadata mode).
    pub conflicts: Option<i64>,
    /// Step 10 working-state vocabulary (v5; `None` on legacy rows).
    pub working_state: Option<String>,
    /// Untracked count units.
    pub untracked_units: String,
    /// Submodule coverage.
    pub submodules: String,
    /// Unknown-fields JSON.
    pub unknown_fields: String,
    /// Input fingerprint (HEAD/index/config observations).
    pub input_fingerprint: Option<Vec<u8>>,
    /// Observation revision (dedup key with checkout).
    pub observed_rev: u64,
    /// Observation time.
    pub observed_at_ms: i64,
}

impl StatusRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_i64(row, 0)?,
            checkout_id: req_text(row, 1)?,
            mode: req_text(row, 2)?,
            state: req_text(row, 3)?,
            started_ms: opt_i64(row, 4)?,
            finished_ms: opt_i64(row, 5)?,
            staged: opt_i64(row, 6)?,
            unstaged: opt_i64(row, 7)?,
            untracked: opt_i64(row, 8)?,
            conflicts: opt_i64(row, 15)?,
            working_state: opt_text(row, 16)?,
            untracked_units: req_text(row, 9)?,
            submodules: req_text(row, 10)?,
            unknown_fields: req_text(row, 11)?,
            input_fingerprint: opt_blob(row, 12)?,
            observed_rev: i64_to_u64(req_i64(row, 13)?, "status observed_rev")?,
            observed_at_ms: req_i64(row, 14)?,
        })
    }
}

/// New status observation for [`TursoStore::record_status`].
#[derive(Debug, Clone)]
pub struct NewStatus<'a> {
    /// Observed checkout id.
    pub checkout_id: &'a str,
    /// Inspection mode.
    pub mode: &'a str,
    /// Observation state.
    pub state: &'a str,
    /// Probe start.
    pub started_ms: Option<i64>,
    /// Probe finish.
    pub finished_ms: Option<i64>,
    /// Staged tracked paths.
    pub staged: Option<i64>,
    /// Unstaged tracked paths.
    pub unstaged: Option<i64>,
    /// Untracked entries.
    pub untracked: Option<i64>,
    /// Distinct unmerged paths, when known (v5).
    pub conflicts: Option<i64>,
    /// Step 10 working-state vocabulary (v5).
    pub working_state: &'a str,
    /// Untracked count units.
    pub untracked_units: &'a str,
    /// Submodule coverage.
    pub submodules: &'a str,
    /// Unknown-fields JSON.
    pub unknown_fields: &'a str,
    /// Input fingerprint.
    pub input_fingerprint: Option<&'a [u8]>,
    /// Observation revision (dedup key with checkout).
    pub observed_rev: u64,
}

/// One durable scan request.
#[derive(Debug, Clone)]
pub struct ScanRow {
    /// Scan id.
    pub id: String,
    /// Sanitized target URL bytes (rows predating RETEST-5 may still hold
    /// legacy credential forms; readers must redact before display).
    pub url_raw: Vec<u8>,
    /// Sanitized canonical URL bytes, when supported.
    pub url_canonical: Option<Vec<u8>>,
    /// Requested scope.
    pub scope: String,
    /// Status mode.
    pub status_mode: String,
    /// Absolute report destination, exact bytes, when requested.
    pub report_dest: Option<Vec<u8>>,
    /// Request state.
    pub state: String,
    /// Terminal outcome, when finished.
    pub outcome: Option<String>,
    /// Successor scan id, when superseded.
    pub successor_id: Option<String>,
    /// Creation time.
    pub created_at_ms: i64,
    /// Last update time.
    pub updated_at_ms: i64,
    /// v2: JSON array of `{raw, canonical}` for the multi-target request
    /// served by one filesystem pass; `None` = legacy single-target row
    /// addressed via `url_raw`.
    pub targets_json: Option<String>,
    /// v2: output format (`human|json|jsonl`); `None` = legacy/auto.
    pub format: Option<String>,
    /// v2: `--all` filesystem-discovery scan; `None` = legacy row.
    pub all_targets: Option<bool>,
    /// v3: `--fetch` remote refresh requested; `None` = legacy row, no
    /// fetch. Resume restores this.
    pub fetch: Option<bool>,
    /// v4: explicit `--workers` request; `None` = legacy row or flag
    /// absent, resolved at runtime. Resume restores this.
    pub workers: Option<u64>,
}

impl ScanRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_text(row, 0)?,
            url_raw: req_blob(row, 1)?,
            url_canonical: opt_blob(row, 2)?,
            scope: req_text(row, 3)?,
            status_mode: req_text(row, 4)?,
            report_dest: opt_blob(row, 5)?,
            state: req_text(row, 6)?,
            outcome: opt_text(row, 7)?,
            successor_id: opt_text(row, 8)?,
            created_at_ms: req_i64(row, 9)?,
            updated_at_ms: req_i64(row, 10)?,
            targets_json: opt_text(row, 11)?,
            format: opt_text(row, 12)?,
            all_targets: opt_i64(row, 13)?.map(|v| v != 0),
            fetch: opt_i64(row, 14)?.map(|v| v != 0),
            // A corrupt negative resolves to `None` (runtime default via
            // `restore_workers`) instead of failing the whole read —
            // resume stays resilient to a bad stored value.
            workers: opt_i64(row, 15)?.and_then(|v| u64::try_from(v).ok()),
        })
    }
}

/// New scan request for [`TursoStore::create_scan_request`].
#[derive(Debug, Clone)]
pub struct NewScan<'a> {
    /// Scan id.
    pub id: &'a str,
    /// Target URL bytes (UTF-8); sanitized on persist, never stored raw.
    pub url_raw: &'a [u8],
    /// Canonical URL bytes (UTF-8); sanitized on persist, never stored raw.
    pub url_canonical: Option<&'a [u8]>,
    /// Requested scope.
    pub scope: &'a str,
    /// Status mode.
    pub status_mode: &'a str,
    /// Absolute report destination, exact bytes.
    pub report_dest: Option<&'a [u8]>,
    /// v2: JSON array of `{raw, canonical}` targets; `None` = legacy row.
    pub targets_json: Option<&'a str>,
    /// v2: output format (`human|json|jsonl`); `None` = legacy/auto.
    pub format: Option<&'a str>,
    /// v2: `--all` scan; `None` = legacy row.
    pub all_targets: Option<bool>,
    /// v3: `--fetch` remote refresh; `None` = legacy row, no fetch.
    pub fetch: Option<bool>,
    /// v4: explicit `--workers` request; `None` = legacy row or flag
    /// absent.
    pub workers: Option<u64>,
}

/// One immutable report snapshot.
#[derive(Debug, Clone)]
pub struct ReportSnapshotRow {
    /// Snapshot/report id.
    pub id: String,
    /// Report schema version.
    pub schema_version: String,
    /// Catalog revision streamed.
    pub catalog_rev: u64,
    /// Traversal generation covered.
    pub generation: u64,
    /// Publication state.
    pub publication_state: String,
    /// Content checksum, exact bytes, when computed.
    pub checksum: Option<Vec<u8>>,
    /// Creation time.
    pub created_at_ms: i64,
}

impl ReportSnapshotRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_text(row, 0)?,
            schema_version: req_text(row, 1)?,
            catalog_rev: i64_to_u64(req_i64(row, 2)?, "snapshot catalog_rev")?,
            generation: i64_to_u64(req_i64(row, 3)?, "snapshot generation")?,
            publication_state: req_text(row, 4)?,
            checksum: opt_blob(row, 5)?,
            created_at_ms: req_i64(row, 6)?,
        })
    }
}

/// One durable error/gap record.
#[derive(Debug, Clone)]
pub struct ErrorRow {
    /// Stable error id.
    pub id: String,
    /// Scope the error belongs to.
    pub scope_key: String,
    /// Stable category.
    pub category: String,
    /// Human-readable detail.
    pub detail: String,
    /// Times recorded.
    pub attempts: u64,
    /// First-seen time.
    pub first_seen_ms: i64,
    /// Last-seen time.
    pub last_seen_ms: i64,
    /// Next retry eligibility, when scheduled.
    pub next_retry_ms: Option<i64>,
    /// True while the gap is open.
    pub open: bool,
}

impl ErrorRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_text(row, 0)?,
            scope_key: req_text(row, 1)?,
            category: req_text(row, 2)?,
            detail: req_text(row, 3)?,
            attempts: i64_to_u64(req_i64(row, 4)?, "error attempts")?,
            first_seen_ms: req_i64(row, 5)?,
            last_seen_ms: req_i64(row, 6)?,
            next_retry_ms: opt_i64(row, 7)?,
            open: req_i64(row, 8)? != 0,
        })
    }
}

/// One durable event-journal record.
#[derive(Debug, Clone)]
pub struct EventRow {
    /// Row id.
    pub id: i64,
    /// Volume id.
    pub volume_id: String,
    /// Event-history UUID.
    pub history_uuid: String,
    /// History cursor (opaque).
    pub cursor: String,
    /// Receipt time.
    pub received_ms: i64,
    /// True when the event invalidated scope.
    pub invalidated: bool,
    /// True when durably ingested.
    pub ingested: bool,
    /// True when reconciliation work is satisfied.
    pub reconciled: bool,
}

impl EventRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_i64(row, 0)?,
            volume_id: req_text(row, 1)?,
            history_uuid: req_text(row, 2)?,
            cursor: req_text(row, 3)?,
            received_ms: req_i64(row, 4)?,
            invalidated: req_i64(row, 5)? != 0,
            ingested: req_i64(row, 6)? != 0,
            reconciled: req_i64(row, 7)? != 0,
        })
    }
}

/// Outcome of one atomic event-batch ingest
/// ([`TursoStore::ingest_event_batch`], RSF-F940).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestedBatch {
    /// True when the journal row was newly inserted. False on duplicate
    /// `(volume, history UUID, cursor)` replays, which bump nothing.
    pub inserted: bool,
    /// New scope revision per requested scope, in order. Empty on
    /// duplicates (nothing was bumped) and when no scopes were requested.
    pub revs: Vec<u64>,
}

/// One durable volume record.
#[derive(Debug, Clone)]
pub struct VolumeRow {
    /// Opaque volume id.
    pub id: String,
    /// Native identity, when known.
    pub native_identity: Option<String>,
    /// Mount namespace.
    pub namespace: String,
    /// Filesystem name, when known.
    pub filesystem: Option<String>,
    /// Volume kind (`local`, `network`, `virtual`, `unknown`).
    pub kind: String,
    /// Access state.
    pub state: String,
    /// Last observation time.
    pub observed_at_ms: Option<i64>,
}

impl VolumeRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_text(row, 0)?,
            native_identity: opt_text(row, 1)?,
            namespace: req_text(row, 2)?,
            filesystem: opt_text(row, 3)?,
            kind: req_text(row, 4)?,
            state: req_text(row, 5)?,
            observed_at_ms: opt_i64(row, 6)?,
        })
    }
}

/// New volume for [`TursoStore::upsert_volume`].
#[derive(Debug, Clone)]
pub struct NewVolume<'a> {
    /// Opaque volume id.
    pub id: &'a str,
    /// Native identity.
    pub native_identity: Option<&'a str>,
    /// Mount namespace.
    pub namespace: &'a str,
    /// Filesystem name.
    pub filesystem: Option<&'a str>,
    /// Volume kind.
    pub kind: &'a str,
    /// Access state.
    pub state: &'a str,
}

/// One durable traversal generation.
#[derive(Debug, Clone)]
pub struct GenerationRow {
    /// Generation id.
    pub id: u64,
    /// Scope policy.
    pub scope_policy: String,
    /// Completion state.
    pub state: String,
    /// Prior generation, when superseding.
    pub prior_generation: Option<u64>,
    /// Creation time.
    pub created_at_ms: i64,
    /// v2: full scope key (roots + volume identities + exclusions +
    /// traversal policy); `None` = legacy policy-name key in
    /// `scope_policy`.
    pub scope_key: Option<String>,
}

impl GenerationRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: i64_to_u64(req_i64(row, 0)?, "generation id")?,
            scope_policy: req_text(row, 1)?,
            state: req_text(row, 2)?,
            prior_generation: opt_i64(row, 3)?
                .map(|prior| i64_to_u64(prior, "prior generation"))
                .transpose()?,
            created_at_ms: req_i64(row, 4)?,
            scope_key: opt_text(row, 5)?,
        })
    }
}

/// v2: one scan-event journal append (D4).
#[derive(Debug, Clone)]
pub struct NewScanEvent<'a> {
    /// Scan id.
    pub scan_id: &'a str,
    /// Scan-scoped sequence, assigned by the writer.
    pub seq: u64,
    /// Catalog revision committed with this event.
    pub catalog_rev: u64,
    /// Offset of this event within its revision.
    pub event_offset: u64,
    /// Event class (`scan_started`, `location_found`, ...).
    pub event_type: &'a str,
    /// `add` | `replace` | `remove`.
    pub op: &'a str,
    /// Consumer must drop buffered state.
    pub reset: bool,
    /// JSON bytes, stored byte-exact.
    pub records: &'a [u8],
}

/// v2: one journaled scan event.
#[derive(Debug, Clone)]
pub struct ScanEventRow {
    /// Scan id.
    pub scan_id: String,
    /// Scan-scoped sequence.
    pub seq: u64,
    /// Catalog revision committed with this event.
    pub catalog_rev: u64,
    /// Offset of this event within its revision.
    pub event_offset: u64,
    /// Event class.
    pub event_type: String,
    /// `add` | `replace` | `remove`.
    pub op: String,
    /// Consumer must drop buffered state.
    pub reset: bool,
    /// JSON bytes, byte-exact.
    pub records: Vec<u8>,
}

impl ScanEventRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            scan_id: req_text(row, 0)?,
            seq: i64_to_u64(req_i64(row, 1)?, "event seq")?,
            catalog_rev: i64_to_u64(req_i64(row, 2)?, "event catalog_rev")?,
            event_offset: i64_to_u64(req_i64(row, 3)?, "event offset")?,
            event_type: req_text(row, 4)?,
            op: req_text(row, 5)?,
            reset: req_i64(row, 6)? != 0,
            records: req_blob(row, 7)?,
        })
    }
}

/// v2: one GitHub group (D1): normalized host/account/repo.
#[derive(Debug, Clone)]
pub struct GithubGroupRow {
    /// Writer-computed `lower(host)/lower(account)/lower(repo)`.
    pub id: String,
    /// Normalized host.
    pub host: String,
    /// Normalized account or organization.
    pub account: String,
    /// Normalized repository name.
    pub repo: String,
    /// First observation time.
    pub observed_at_ms: i64,
}

impl GithubGroupRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            id: req_text(row, 0)?,
            host: req_text(row, 1)?,
            account: req_text(row, 2)?,
            repo: req_text(row, 3)?,
            observed_at_ms: req_i64(row, 4)?,
        })
    }
}

/// v2: one store-to-group edge via the observing remote (D1).
#[derive(Debug, Clone)]
pub struct GroupMemberRow {
    /// Group id.
    pub group_id: String,
    /// Local store id.
    pub instance_id: String,
    /// Observing remote name, exact bytes.
    pub remote_name: Vec<u8>,
    /// `fetch` | `push`.
    pub role: String,
    /// Observation time.
    pub observed_at_ms: i64,
}

impl GroupMemberRow {
    fn from_row(row: &turso::Row) -> crate::Result<Self> {
        Ok(Self {
            group_id: req_text(row, 0)?,
            instance_id: req_text(row, 1)?,
            remote_name: req_blob(row, 2)?,
            role: req_text(row, 3)?,
            observed_at_ms: req_i64(row, 4)?,
        })
    }
}

/// Re-observe one ref's oid (v3 fetch phase): single source for
/// [`TursoStore::update_ref_oid`] and
/// [`TursoStore::buffer_update_ref_oid`], so the direct round-trip
/// test covers the buffered statement text too.
const UPDATE_REF_OID_SQL: &str = "UPDATE refs SET oid = ?2, observed_at_ms = ?3 WHERE id = ?1";

/// Label one ref's branch comparison (v6 analysis phase): single
/// source for [`TursoStore::update_ref_comparison`] and
/// [`TursoStore::buffer_update_ref_comparison`].
const UPDATE_REF_COMPARISON_SQL: &str =
    "UPDATE refs SET comparison_state = ?2, ahead = ?3, behind = ?4 WHERE id = ?1";

impl TursoStore {
    /// Idempotent directory upsert keyed by physical identity
    /// (`volume_id`, `object_id`, `incarnation`). Returns the row id.
    /// Repeated calls with the same identity return the same id.
    // Parameters mirror the table columns 1:1; grouping would churn callers.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_dir(
        &self,
        parent_id: Option<i64>,
        component: &[u8],
        display: &str,
        volume_id: &str,
        object_id: &str,
        incarnation: &str,
        observed_ms: i64,
    ) -> crate::Result<i64> {
        self.with_tx(|conn| async move {
            conn.execute(
                "INSERT OR IGNORE INTO directories (parent_id, component, display, \
                    volume_id, object_id, incarnation, last_observed_ms, \
                    invalidation_rev) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                vec![
                    v_opt_int(parent_id),
                    v_blob(component.to_vec()),
                    v_text(display),
                    v_text(volume_id),
                    v_text(object_id),
                    v_text(incarnation),
                    v_int(observed_ms),
                ],
            )
            .await
            .map_err(store_err)?;
            conn.execute(
                "UPDATE directories SET parent_id = ?1, display = ?2, \
                    last_observed_ms = ?3 WHERE volume_id = ?4 AND object_id = ?5 \
                    AND incarnation = ?6",
                vec![
                    v_opt_int(parent_id),
                    v_text(display),
                    v_int(observed_ms),
                    v_text(volume_id),
                    v_text(object_id),
                    v_text(incarnation),
                ],
            )
            .await
            .map_err(store_err)?;
            let mut rows = conn
                .query(
                    "SELECT id FROM directories WHERE volume_id = ?1 AND object_id = ?2 \
                        AND incarnation = ?3",
                    vec![v_text(volume_id), v_text(object_id), v_text(incarnation)],
                )
                .await
                .map_err(store_err)?;
            let row = rows
                .next()
                .await
                .map_err(store_err)?
                .ok_or_else(|| Error::Store("directory upsert left no row".to_string()))?;
            req_i64(&row, 0)
        })
        .await
    }

    /// Resolve a directory row id by physical identity, for callers that
    /// buffered [`TursoStore::buffer_dir_upsert`] and flushed: the id is
    /// only knowable after the flush commits. Pure read.
    pub async fn lookup_dir_id(
        &self,
        volume_id: &str,
        object_id: &str,
        incarnation: &str,
    ) -> crate::Result<Option<i64>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id FROM directories WHERE volume_id = ?1 AND object_id = ?2 \
                    AND incarnation = ?3",
                vec![v_text(volume_id), v_text(object_id), v_text(incarnation)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(req_i64(&row, 0)?)),
        }
    }

    /// Fetch one directory by row id.
    pub async fn get_dir(&self, id: i64) -> crate::Result<Option<DirRecord>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, parent_id, component, display, volume_id, object_id, \
                    incarnation, last_observed_ms, invalidation_rev \
                    FROM directories WHERE id = ?1",
                vec![v_int(id)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(DirRecord::from_row(&row)?)),
        }
    }

    /// Idempotent enumeration observation keyed by (`dir_id`, `generation`).
    // Parameters mirror the table columns 1:1; grouping would churn callers.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_dir_observation(
        &self,
        dir_id: i64,
        generation: u64,
        completed: bool,
        entry_generation: u64,
        entries_seen: u64,
        error: Option<&str>,
        observed_ms: i64,
    ) -> crate::Result<()> {
        self.forbid_write("record_dir_observation")?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO dir_observations (dir_id, generation, completed, \
                    entry_generation, entries_seen, error, observed_at_ms) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                vec![
                    v_int(dir_id),
                    v_int(u64_to_i64(generation, "dir observation generation")?),
                    v_int(i64::from(completed)),
                    v_int(u64_to_i64(entry_generation, "dir entry_generation")?),
                    v_int(u64_to_i64(entries_seen, "dir entries_seen")?),
                    v_opt_text(error.map(str::to_string)),
                    v_int(observed_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// Fetch one directory observation.
    pub async fn get_dir_observation(
        &self,
        dir_id: i64,
        generation: u64,
    ) -> crate::Result<Option<DirObservation>> {
        let mut rows = self
            .conn
            .query(
                "SELECT dir_id, generation, completed, entry_generation, entries_seen, \
                    error, observed_at_ms FROM dir_observations \
                    WHERE dir_id = ?1 AND generation = ?2",
                vec![
                    v_int(dir_id),
                    v_int(u64_to_i64(generation, "dir observation generation")?),
                ],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(DirObservation::from_row(&row)?)),
        }
    }

    /// Idempotent Git-instance upsert keyed by stable id.
    pub async fn upsert_git_instance(
        &self,
        instance: &NewGitInstance<'_>,
        observed_ms: i64,
    ) -> crate::Result<()> {
        self.forbid_write("upsert_git_instance")?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO git_instances (id, git_path, common_path, \
                    incarnation, format, bare, object_format, disposition, evidence, \
                    observed_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                vec![
                    v_text(instance.id),
                    v_blob(instance.git_path.to_vec()),
                    v_blob(instance.common_path.to_vec()),
                    v_text(instance.incarnation),
                    v_text(instance.format),
                    v_opt_int(instance.bare.map(i64::from)),
                    v_text(instance.object_format),
                    v_text(instance.disposition),
                    v_text(instance.evidence_json),
                    v_int(observed_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// Fetch one Git instance by id.
    pub async fn get_git_instance(&self, id: &str) -> crate::Result<Option<GitInstanceRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, git_path, common_path, incarnation, format, bare, \
                    object_format, disposition, evidence, observed_at_ms \
                    FROM git_instances WHERE id = ?1",
                vec![v_text(id)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(GitInstanceRow::from_row(&row)?)),
        }
    }

    /// Idempotent checkout upsert keyed by stable id.
    /// Insert a checkout row only when its id is absent. Used for
    /// worktree-less observations of an instance (a bare-angle probe of a
    /// git dir that another probe already linked to a worktree root): the
    /// rootless row must never clobber the rooted one, regardless of probe
    /// completion order.
    pub async fn insert_checkout_if_absent(
        &self,
        checkout: &NewCheckout<'_>,
        observed_ms: i64,
    ) -> crate::Result<()> {
        self.forbid_write("insert_checkout_if_absent")?;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO checkouts (id, instance_id, root_path, git_path, \
                    relationship, availability, head_state, head_ref, head_oid, \
                    head_algo, observed_at_ms) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                vec![
                    v_text(checkout.id),
                    v_text(checkout.instance_id),
                    v_opt_blob(checkout.root_path.map(<[u8]>::to_vec)),
                    v_blob(checkout.git_path.to_vec()),
                    v_text(checkout.relationship),
                    v_text(checkout.availability),
                    v_text(checkout.head_state),
                    v_opt_blob(checkout.head_ref.map(<[u8]>::to_vec)),
                    v_opt_blob(checkout.head_oid.map(<[u8]>::to_vec)),
                    v_opt_text(checkout.head_algo.map(str::to_string)),
                    v_int(observed_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    pub async fn upsert_checkout(
        &self,
        checkout: &NewCheckout<'_>,
        observed_ms: i64,
    ) -> crate::Result<()> {
        self.forbid_write("upsert_checkout")?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO checkouts (id, instance_id, root_path, git_path, \
                    relationship, availability, head_state, head_ref, head_oid, \
                    head_algo, observed_at_ms) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                vec![
                    v_text(checkout.id),
                    v_text(checkout.instance_id),
                    v_opt_blob(checkout.root_path.map(<[u8]>::to_vec)),
                    v_blob(checkout.git_path.to_vec()),
                    v_text(checkout.relationship),
                    v_text(checkout.availability),
                    v_text(checkout.head_state),
                    v_opt_blob(checkout.head_ref.map(<[u8]>::to_vec)),
                    v_opt_blob(checkout.head_oid.map(<[u8]>::to_vec)),
                    v_opt_text(checkout.head_algo.map(str::to_string)),
                    v_int(observed_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// Fetch one checkout by id.
    pub async fn get_checkout(&self, id: &str) -> crate::Result<Option<CheckoutRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, instance_id, root_path, git_path, relationship, availability, \
                    head_state, head_ref, head_oid, head_algo, observed_at_ms \
                    FROM checkouts WHERE id = ?1",
                vec![v_text(id)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(CheckoutRow::from_row(&row)?)),
        }
    }

    /// Idempotent remote upsert keyed by stable id. Stored URLs pass
    /// through the sink-side redaction (see `redacted_remote_bytes`).
    pub async fn upsert_remote(
        &self,
        remote: &NewRemote<'_>,
        observed_ms: i64,
    ) -> crate::Result<()> {
        self.forbid_write("upsert_remote")?;
        let url = redacted_remote_bytes(remote.url);
        let canonical_url = remote.canonical_url.map(redacted_remote_bytes);
        self.conn
            .execute(
                "INSERT OR REPLACE INTO remotes (id, instance_id, checkout_scope_id, name, \
                    role, url, canonical_url, observed_at_ms) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                vec![
                    v_text(remote.id),
                    v_text(remote.instance_id),
                    v_opt_text(remote.checkout_scope_id.map(str::to_string)),
                    v_blob(remote.name.to_vec()),
                    v_text(remote.role),
                    v_blob(url),
                    v_opt_blob(canonical_url),
                    v_int(observed_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// List remotes for one instance, ordered by id.
    pub async fn list_remotes(&self, instance_id: &str) -> crate::Result<Vec<RemoteRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, instance_id, checkout_scope_id, name, role, url, \
                    canonical_url, observed_at_ms FROM remotes \
                    WHERE instance_id = ?1 ORDER BY id ASC",
                vec![v_text(instance_id)],
            )
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            out.push(RemoteRow::from_row(&row)?);
        }
        Ok(out)
    }

    /// Idempotent ref upsert keyed by stable id. v3: `INSERT OR
    /// IGNORE` plus an unconditional `UPDATE` of the observed columns
    /// only, so re-observation preserves the `freshness` label columns
    /// (`INSERT OR REPLACE` would null them). Insert-first order is
    /// race-safe: concurrent same-id upserts converge on
    /// last-writer-wins, never a lost insert. (`ON CONFLICT DO UPDATE`
    /// with `excluded.*` is avoided: turso 0.8.1 accepts the statement
    /// but mis-evaluates the `excluded` references.)
    pub async fn upsert_ref(&self, reference: &NewRef<'_>, observed_ms: i64) -> crate::Result<()> {
        self.forbid_write("upsert_ref")?;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO refs (id, instance_id, checkout_scope_id, kind, \
                    name, oid, algo, symbolic_target, upstream, state, observed_at_ms) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                ref_params(reference, observed_ms),
            )
            .await
            .map_err(store_err)?;
        self.conn
            .execute(
                "UPDATE refs SET instance_id = ?2, checkout_scope_id = ?3, kind = ?4, \
                    name = ?5, oid = ?6, algo = ?7, symbolic_target = ?8, \
                    upstream = ?9, state = ?10, observed_at_ms = ?11 WHERE id = ?1",
                ref_params(reference, observed_ms),
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// List refs for one instance, ordered by id. Reads the v6
    /// comparison columns when physically present; on v5 catalogs
    /// the comparison fields read `None` (`pending`/null).
    pub async fn list_refs(&self, instance_id: &str) -> crate::Result<Vec<RefRow>> {
        let v6 = self.supports_ref_comparison().await?;
        let sql = if v6 {
            "SELECT id, instance_id, checkout_scope_id, kind, name, oid, algo, \
                symbolic_target, upstream, state, observed_at_ms, freshness, \
                freshness_at_ms, comparison_state, ahead, behind FROM refs \
                WHERE instance_id = ?1 ORDER BY id ASC"
        } else {
            "SELECT id, instance_id, checkout_scope_id, kind, name, oid, algo, \
                symbolic_target, upstream, state, observed_at_ms, freshness, \
                freshness_at_ms FROM refs \
                WHERE instance_id = ?1 ORDER BY id ASC"
        };
        let mut rows = self
            .conn
            .query(sql, vec![v_text(instance_id)])
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            if v6 {
                out.push(RefRow::from_row_v6(&row)?);
            } else {
                out.push(RefRow::from_row_v5(&row)?);
            }
        }
        Ok(out)
    }

    /// True when this catalog's `refs` table carries the v6
    /// comparison columns. Gates comparison writes until the
    /// coordinator wires migration v6.
    pub async fn supports_ref_comparison(&self) -> crate::Result<bool> {
        refs_has_comparison(&self.conn).await
    }

    /// Label one ref's branch comparison (v6): updates
    /// `comparison_state` + `ahead`/`behind` only, leaving
    /// attribution, oid, upstream, state, and freshness untouched.
    /// Counts past `i64::MAX` fail loudly (caller defect), like
    /// every other catalog `u64` write. Returns true when a row was
    /// updated; on a pre-v6 catalog returns false WITHOUT executing
    /// (the columns do not exist yet) — callers treat false as
    /// "comparison not persisted", never as an error.
    pub async fn update_ref_comparison(
        &self,
        ref_id: &str,
        state: &str,
        ahead: Option<u64>,
        behind: Option<u64>,
    ) -> crate::Result<bool> {
        self.forbid_write("update_ref_comparison")?;
        if !self.supports_ref_comparison().await? {
            return Ok(false);
        }
        let ahead = ahead.map(|v| u64_to_i64(v, "ref ahead")).transpose()?;
        let behind = behind.map(|v| u64_to_i64(v, "ref behind")).transpose()?;
        let changed = self
            .conn
            .execute(
                UPDATE_REF_COMPARISON_SQL,
                vec![
                    v_text(ref_id),
                    v_text(state),
                    v_opt_int(ahead),
                    v_opt_int(behind),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(changed > 0)
    }

    /// Re-observe one persisted ref's object id after a `--fetch`
    /// (v3): updates `oid` + `observed_at_ms` only, leaving
    /// instance attribution, kind, upstream, state, and any freshness
    /// label untouched. The fetch phase pairs this with
    /// [`TursoStore::label_ref_freshness`] (existing row) or
    /// [`TursoStore::upsert_ref`] (fetch-created tracking branch).
    /// Returns true when a row was updated. [`UPDATE_REF_OID_SQL`]
    /// is the single source shared with
    /// [`TursoStore::buffer_update_ref_oid`].
    pub async fn update_ref_oid(
        &self,
        ref_id: &str,
        oid: &[u8],
        at_ms: i64,
    ) -> crate::Result<bool> {
        self.forbid_write("update_ref_oid")?;
        let changed = self
            .conn
            .execute(
                UPDATE_REF_OID_SQL,
                vec![v_text(ref_id), v_blob(oid.to_vec()), v_int(at_ms)],
            )
            .await
            .map_err(store_err)?;
        Ok(changed > 0)
    }

    /// Label the freshness of one persisted ref (v3). Only used for
    /// `kind = 'remote_tracking'` rows after a `--fetch` attempt;
    /// `freshness` is `current`|`stale`|`unknown`. Returns true when a
    /// row was updated.
    pub async fn label_ref_freshness(
        &self,
        ref_id: &str,
        freshness: &str,
        at_ms: i64,
    ) -> crate::Result<bool> {
        self.forbid_write("label_ref_freshness")?;
        let changed = self
            .conn
            .execute(
                "UPDATE refs SET freshness = ?2, freshness_at_ms = ?3 WHERE id = ?1",
                vec![v_text(ref_id), v_text(freshness), v_int(at_ms)],
            )
            .await
            .map_err(store_err)?;
        Ok(changed > 0)
    }

    /// Record the last `--fetch` attempt for one store + remote (v3).
    /// `INSERT OR REPLACE` keyed by (`store_id`, `remote_name`): the
    /// row always reflects the latest attempt.
    pub async fn record_remote_refresh(&self, refresh: &NewRemoteRefresh<'_>) -> crate::Result<()> {
        self.forbid_write("record_remote_refresh")?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO remote_refreshes (store_id, remote_name, \
                    status, observed_at_ms, duration_ms, refs_updated, \
                    refs_current_json, refs_deleted_json, detail) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                vec![
                    v_text(refresh.store_id),
                    v_blob(refresh.remote_name.to_vec()),
                    v_text(refresh.status),
                    v_int(refresh.observed_at_ms),
                    v_opt_int(refresh.duration_ms),
                    v_int(refresh.refs_updated),
                    v_opt_text(refresh.refs_current_json.map(str::to_string)),
                    v_opt_text(refresh.refs_deleted_json.map(str::to_string)),
                    v_opt_text(refresh.detail.map(str::to_string)),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// Read the last `--fetch` attempt for one store + remote (v3),
    /// or `None` when never attempted.
    pub async fn get_remote_refresh(
        &self,
        store_id: &str,
        remote_name: &[u8],
    ) -> crate::Result<Option<RemoteRefreshRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT store_id, remote_name, status, observed_at_ms, \
                    duration_ms, refs_updated, refs_current_json, \
                    refs_deleted_json, detail \
                    FROM remote_refreshes WHERE store_id = ?1 AND remote_name = ?2",
                vec![v_text(store_id), v_blob(remote_name.to_vec())],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            Some(row) => Ok(Some(RemoteRefreshRow::from_row(&row)?)),
            None => Ok(None),
        }
    }

    /// List all recorded `--fetch` attempts for one store (v3).
    pub async fn list_remote_refreshes(
        &self,
        store_id: &str,
    ) -> crate::Result<Vec<RemoteRefreshRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT store_id, remote_name, status, observed_at_ms, \
                    duration_ms, refs_updated, refs_current_json, \
                    refs_deleted_json, detail \
                    FROM remote_refreshes WHERE store_id = ?1 ORDER BY remote_name ASC",
                vec![v_text(store_id)],
            )
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            out.push(RemoteRefreshRow::from_row(&row)?);
        }
        Ok(out)
    }

    /// Idempotent status observation keyed by (`checkout_id`, `observed_rev`).
    /// Returns true when newly inserted.
    pub async fn record_status(
        &self,
        status: &NewStatus<'_>,
        observed_ms: i64,
    ) -> crate::Result<bool> {
        self.forbid_write("record_status")?;
        let rows = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO status_observations (checkout_id, mode, state, \
                    started_ms, finished_ms, staged, unstaged, untracked, \
                    untracked_units, submodules, unknown_fields, input_fingerprint, \
                    observed_rev, observed_at_ms, conflicts, working_state) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, \
                    ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                vec![
                    v_text(status.checkout_id),
                    v_text(status.mode),
                    v_text(status.state),
                    v_opt_int(status.started_ms),
                    v_opt_int(status.finished_ms),
                    v_opt_int(status.staged),
                    v_opt_int(status.unstaged),
                    v_opt_int(status.untracked),
                    v_text(status.untracked_units),
                    v_text(status.submodules),
                    v_text(status.unknown_fields),
                    v_opt_blob(status.input_fingerprint.map(<[u8]>::to_vec)),
                    v_int(u64_to_i64(status.observed_rev, "status observed_rev")?),
                    v_int(observed_ms),
                    v_opt_int(status.conflicts),
                    v_text(status.working_state),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(rows == 1)
    }

    /// List status observations for one checkout, newest revision first.
    pub async fn list_statuses(&self, checkout_id: &str) -> crate::Result<Vec<StatusRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, checkout_id, mode, state, started_ms, finished_ms, staged, \
                    unstaged, untracked, untracked_units, submodules, unknown_fields, \
                    input_fingerprint, observed_rev, observed_at_ms, conflicts, \
                    working_state \
                    FROM status_observations WHERE checkout_id = ?1 \
                    ORDER BY observed_rev DESC",
                vec![v_text(checkout_id)],
            )
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            out.push(StatusRow::from_row(&row)?);
        }
        Ok(out)
    }

    /// Create a scan request idempotently. Returns true when newly inserted.
    ///
    /// RETEST-5 no-credential-bytes boundary: `url_raw`/`url_canonical` are
    /// sanitized inside this method (see `sanitized_target_bytes`), so
    /// direct API callers that bypass CLI sanitization still persist no
    /// credential bytes. The CLI rejects credential forms loudly before
    /// calling; this layer normalizes silently (defense-in-depth) and only
    /// refuses non-UTF-8 targets.
    pub async fn create_scan_request(
        &self,
        scan: &NewScan<'_>,
        now_ms: i64,
    ) -> crate::Result<bool> {
        self.forbid_write("create_scan_request")?;
        let url_raw = sanitized_target_bytes(scan.url_raw, "target")?;
        let url_canonical = scan
            .url_canonical
            .map(|bytes| sanitized_target_bytes(bytes, "canonical"))
            .transpose()?;
        let workers = scan
            .workers
            .map(|w| u64_to_i64(w, "scan workers"))
            .transpose()?;
        let rows = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO scan_requests (id, url_raw, url_canonical, scope, \
                    status_mode, report_dest, state, created_at_ms, updated_at_ms, \
                    targets_json, format, all_targets, fetch, workers) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'running', ?7, ?7, ?8, ?9, ?10, ?11, ?12)",
                vec![
                    v_text(scan.id),
                    v_blob(url_raw),
                    v_opt_blob(url_canonical),
                    v_text(scan.scope),
                    v_text(scan.status_mode),
                    v_opt_blob(scan.report_dest.map(<[u8]>::to_vec)),
                    v_int(now_ms),
                    v_opt_text(scan.targets_json.map(str::to_string)),
                    v_opt_text(scan.format.map(str::to_string)),
                    v_opt_int(scan.all_targets.map(i64::from)),
                    v_opt_int(scan.fetch.map(i64::from)),
                    v_opt_int(workers),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(rows == 1)
    }

    /// Update a scan request's terminal-ish fields.
    pub async fn update_scan_state(
        &self,
        id: &str,
        state: &str,
        outcome: Option<&str>,
        successor_id: Option<&str>,
        now_ms: i64,
    ) -> crate::Result<()> {
        self.forbid_write("update_scan_state")?;
        self.conn
            .execute(
                "UPDATE scan_requests SET state = ?1, outcome = ?2, successor_id = ?3, \
                    updated_at_ms = ?4 WHERE id = ?5",
                vec![
                    v_text(state),
                    v_opt_text(outcome.map(str::to_string)),
                    v_opt_text(successor_id.map(str::to_string)),
                    v_int(now_ms),
                    v_text(id),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// Fetch one scan request by id.
    pub async fn get_scan(&self, id: &str) -> crate::Result<Option<ScanRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, url_raw, url_canonical, scope, status_mode, report_dest, \
                    state, outcome, successor_id, created_at_ms, updated_at_ms, \
                    targets_json, format, all_targets, fetch, workers \
                    FROM scan_requests WHERE id = ?1",
                vec![v_text(id)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(ScanRow::from_row(&row)?)),
        }
    }

    /// Save an immutable report snapshot (`INSERT OR IGNORE` by id: a saved
    /// snapshot is never mutated; a new scan produces a new id).
    // Parameters mirror the table columns 1:1; grouping would churn callers.
    #[allow(clippy::too_many_arguments)]
    pub async fn save_report_snapshot(
        &self,
        id: &str,
        schema_version: &str,
        catalog_rev: u64,
        generation: u64,
        publication_state: &str,
        checksum: Option<&[u8]>,
        now_ms: i64,
    ) -> crate::Result<bool> {
        self.forbid_write("save_report_snapshot")?;
        let rows = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO report_snapshots (id, schema_version, catalog_rev, \
                    generation, publication_state, checksum, created_at_ms) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                vec![
                    v_text(id),
                    v_text(schema_version),
                    v_int(u64_to_i64(catalog_rev, "snapshot catalog_rev")?),
                    v_int(u64_to_i64(generation, "snapshot generation")?),
                    v_text(publication_state),
                    v_opt_blob(checksum.map(<[u8]>::to_vec)),
                    v_int(now_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(rows == 1)
    }

    /// Update a snapshot's publication state (e.g. `published` after the
    /// external write succeeds, or `failed` with the snapshot retained).
    pub async fn set_snapshot_publication(
        &self,
        id: &str,
        publication_state: &str,
    ) -> crate::Result<()> {
        self.forbid_write("set_snapshot_publication")?;
        self.conn
            .execute(
                "UPDATE report_snapshots SET publication_state = ?1 WHERE id = ?2",
                vec![v_text(publication_state), v_text(id)],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// Fetch one report snapshot by id.
    pub async fn get_report_snapshot(&self, id: &str) -> crate::Result<Option<ReportSnapshotRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, schema_version, catalog_rev, generation, publication_state, \
                    checksum, created_at_ms FROM report_snapshots WHERE id = ?1",
                vec![v_text(id)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(ReportSnapshotRow::from_row(&row)?)),
        }
    }

    /// Record an error/gap: insert on first sight, otherwise bump attempts
    /// and refresh detail, retry, and last-seen. Gaps stay open until
    /// explicitly resolved, so failed scans never remove old findings.
    pub async fn record_error(
        &self,
        id: &str,
        scope_key: &str,
        category: &str,
        detail: &str,
        next_retry_ms: Option<i64>,
        now_ms: i64,
    ) -> crate::Result<()> {
        self.with_tx(|conn| async move {
            Self::record_error_on(conn, id, scope_key, category, detail, next_retry_ms, now_ms)
                .await
        })
        .await
    }

    async fn record_error_on(
        conn: &turso::Connection,
        id: &str,
        scope_key: &str,
        category: &str,
        detail: &str,
        next_retry_ms: Option<i64>,
        now_ms: i64,
    ) -> crate::Result<()> {
        let rows = conn
            .execute(
                "UPDATE errors SET attempts = attempts + 1, detail = ?1, \
                    last_seen_ms = ?2, next_retry_ms = ?3, open = 1 WHERE id = ?4",
                vec![
                    v_text(detail),
                    v_int(now_ms),
                    v_opt_int(next_retry_ms),
                    v_text(id),
                ],
            )
            .await
            .map_err(store_err)?;
        if rows == 0 {
            conn.execute(
                "INSERT OR IGNORE INTO errors (id, scope_key, category, detail, attempts, \
                    first_seen_ms, last_seen_ms, next_retry_ms, open) \
                    VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5, ?6, 1)",
                vec![
                    v_text(id),
                    v_text(scope_key),
                    v_text(category),
                    v_text(detail),
                    v_int(now_ms),
                    v_opt_int(next_retry_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        }
        Ok(())
    }

    /// Close a gap without deleting its evidence.
    pub async fn resolve_error(&self, id: &str, now_ms: i64) -> crate::Result<()> {
        self.forbid_write("resolve_error")?;
        self.conn
            .execute(
                "UPDATE errors SET open = 0, last_seen_ms = ?1 WHERE id = ?2",
                vec![v_int(now_ms), v_text(id)],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// Resolve a volume's event gaps after successful bounded recovery
    /// (RSF-GAP-RECOVERY): a later rescan or consumed `HistoryDone` closes
    /// BOTH `gap:event-batch:<volume>` and `gap:event-claim:<volume>` in
    /// ONE transaction, so one failed batch/claim can never pin every
    /// later generation incomplete. Evidence rows stay; only `open` flips.
    /// Returns true only when a transaction committed (an open gap
    /// existed); the no-gap path is read-only, keeping hot drains free of
    /// write transactions. Any later failure re-opens via `record_error`,
    /// so resolving on a proven recovery signal never hides fresh
    /// breakage.
    pub async fn resolve_event_gaps_for_volume(
        &self,
        volume: &str,
        now_ms: i64,
    ) -> crate::Result<bool> {
        let batch_gap = format!("gap:event-batch:{volume}");
        let claim_gap = format!("gap:event-claim:{volume}");
        let mut open = false;
        for gap_id in [&batch_gap, &claim_gap] {
            if self.get_error(gap_id).await?.is_some_and(|row| row.open) {
                open = true;
                break;
            }
        }
        if !open {
            return Ok(false);
        }
        self.with_tx(move |conn| async move {
            for gap_id in [&batch_gap, &claim_gap] {
                conn.execute(
                    "UPDATE errors SET open = 0, last_seen_ms = ?1 WHERE id = ?2",
                    vec![v_int(now_ms), v_text(gap_id.as_str())],
                )
                .await
                .map_err(store_err)?;
            }
            Ok::<(), Error>(())
        })
        .await?;
        Ok(true)
    }

    /// Fetch one error record by id.
    pub async fn get_error(&self, id: &str) -> crate::Result<Option<ErrorRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, scope_key, category, detail, attempts, first_seen_ms, \
                    last_seen_ms, next_retry_ms, open FROM errors WHERE id = ?1",
                vec![v_text(id)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(ErrorRow::from_row(&row)?)),
        }
    }

    /// Ids of currently open error rows. The runner preloads this once
    /// per scan so buffered gap closes report `coverage_updated` deltas
    /// only for genuine open→closed transitions.
    pub async fn list_open_error_ids(&self) -> crate::Result<Vec<String>> {
        let mut rows = self
            .conn
            .query("SELECT id FROM errors WHERE open = 1 ORDER BY id ASC", ())
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            out.push(req_text(&row, 0)?);
        }
        Ok(out)
    }

    /// Open task-completion gaps owned by `generation` (DB-m5): open
    /// `errors` rows whose id names a task of that generation
    /// (`gap:<task id>` joined to `frontier_tasks`, so volume/batch
    /// gaps — journaled inline, never post-commit — are excluded).
    /// The runner diffs this against the scan journal on resume and
    /// re-buffers `error` events for rows a crash left unjournaled.
    pub async fn list_open_task_gaps(&self, generation: u64) -> crate::Result<Vec<ErrorRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT e.id, e.scope_key, e.category, e.detail, e.attempts, \
                    e.first_seen_ms, e.last_seen_ms, e.next_retry_ms, e.open \
                    FROM errors e JOIN frontier_tasks t ON t.id = substr(e.id, 5) \
                    WHERE e.open = 1 AND e.id LIKE 'gap:%' AND t.generation = ?1 \
                    ORDER BY e.id ASC",
                vec![v_int(u64_to_i64(generation, "task generation")?)],
            )
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            out.push(ErrorRow::from_row(&row)?);
        }
        Ok(out)
    }

    /// Append an event-journal record idempotently
    /// (dedup key: volume, history UUID, cursor). Returns true when new.
    pub async fn append_event(
        &self,
        volume_id: &str,
        history_uuid: &str,
        cursor: &str,
        invalidated: bool,
        now_ms: i64,
    ) -> crate::Result<bool> {
        self.forbid_write("append_event")?;
        let rows = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO event_journal (volume_id, history_uuid, cursor, \
                    received_ms, invalidated, ingested, reconciled) \
                    VALUES (?1, ?2, ?3, ?4, ?5, 1, 0)",
                vec![
                    v_text(volume_id),
                    v_text(history_uuid),
                    v_text(cursor),
                    v_int(now_ms),
                    v_int(i64::from(invalidated)),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(rows == 1)
    }

    /// Mark one journal record reconciled (reconciliation work satisfied).
    pub async fn mark_event_reconciled(&self, id: i64) -> crate::Result<()> {
        self.forbid_write("mark_event_reconciled")?;
        self.conn
            .execute(
                "UPDATE event_journal SET reconciled = 1 WHERE id = ?1",
                vec![v_int(id)],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// List journal records for one volume/history, ordered by row id.
    pub async fn list_events(
        &self,
        volume_id: &str,
        history_uuid: &str,
    ) -> crate::Result<Vec<EventRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, volume_id, history_uuid, cursor, received_ms, invalidated, \
                    ingested, reconciled FROM event_journal \
                    WHERE volume_id = ?1 AND history_uuid = ?2 ORDER BY id ASC",
                vec![v_text(volume_id), v_text(history_uuid)],
            )
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            out.push(EventRow::from_row(&row)?);
        }
        Ok(out)
    }

    /// Atomically ingest one event batch: the cursor row plus every scope
    /// invalidation (revision bump, directory mirror, reconcile-task
    /// enqueue) commit in ONE transaction (RSF-F940). A kill leaves the
    /// cursor and its invalidations jointly present or jointly absent —
    /// never a persisted cursor with lost invalidations, the torn state
    /// the old separate `append_event` + `invalidate_scope` writes
    /// allowed. The owner ingests every batch through this method.
    ///
    /// Duplicate `(volume, history UUID, cursor)` replays (FullHistory
    /// overlap, restart replay) are idempotent no-ops: `inserted` is
    /// false, no revision is bumped, and no task is enqueued, so replays
    /// never schedule double work. An empty `scopes` slice still records
    /// the cursor (out-of-scope batches advance the boundary with no
    /// scheduled work).
    #[allow(clippy::too_many_arguments)]
    pub async fn ingest_event_batch(
        &self,
        volume_id: &str,
        history_uuid: &str,
        cursor: &str,
        invalidated: bool,
        scopes: &[String],
        generation: u64,
        now_ms: i64,
    ) -> crate::Result<IngestedBatch> {
        let volume = volume_id.to_string();
        let uuid = history_uuid.to_string();
        let cursor = cursor.to_string();
        let scopes = scopes.to_vec();
        self.with_tx(move |conn| async move {
            let inserted = conn
                .execute(
                    "INSERT OR IGNORE INTO event_journal (volume_id, history_uuid, cursor, \
                        received_ms, invalidated, ingested, reconciled) \
                        VALUES (?1, ?2, ?3, ?4, ?5, 1, 0)",
                    vec![
                        v_text(volume),
                        v_text(uuid),
                        v_text(cursor),
                        v_int(now_ms),
                        v_int(i64::from(invalidated)),
                    ],
                )
                .await
                .map_err(store_err)?
                == 1;
            if !inserted {
                return Ok::<IngestedBatch, Error>(IngestedBatch {
                    inserted: false,
                    revs: Vec::new(),
                });
            }
            let mut revs = Vec::with_capacity(scopes.len());
            for scope in &scopes {
                revs.push(Self::invalidate_scope_on(conn, scope, generation, now_ms).await?);
            }
            Ok::<IngestedBatch, Error>(IngestedBatch {
                inserted: true,
                revs,
            })
        })
        .await
    }

    /// Idempotent volume upsert keyed by stable id.
    pub async fn upsert_volume(
        &self,
        volume: &NewVolume<'_>,
        observed_ms: Option<i64>,
    ) -> crate::Result<()> {
        self.forbid_write("upsert_volume")?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO volumes (id, native_identity, namespace, \
                    filesystem, kind, state, observed_at_ms) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                vec![
                    v_text(volume.id),
                    v_opt_text(volume.native_identity.map(str::to_string)),
                    v_text(volume.namespace),
                    v_opt_text(volume.filesystem.map(str::to_string)),
                    v_text(volume.kind),
                    v_text(volume.state),
                    v_opt_int(observed_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// Fetch one volume by id.
    pub async fn get_volume(&self, id: &str) -> crate::Result<Option<VolumeRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, native_identity, namespace, filesystem, kind, state, \
                    observed_at_ms FROM volumes WHERE id = ?1",
                vec![v_text(id)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(VolumeRow::from_row(&row)?)),
        }
    }

    /// Create a traversal generation; returns its id.
    pub async fn create_generation(
        &self,
        scope_policy: &str,
        state: &str,
        prior_generation: Option<u64>,
        now_ms: i64,
    ) -> crate::Result<u64> {
        self.forbid_write("create_generation")?;
        self.conn
            .execute(
                "INSERT INTO generations (scope_policy, state, prior_generation, \
                    created_at_ms) VALUES (?1, ?2, ?3, ?4)",
                vec![
                    v_text(scope_policy),
                    v_text(state),
                    v_opt_int(
                        prior_generation
                            .map(|prior| u64_to_i64(prior, "prior generation"))
                            .transpose()?,
                    ),
                    v_int(now_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        i64_to_u64(self.conn.last_insert_rowid(), "generation id")
    }

    /// Update a generation's completion state.
    pub async fn set_generation_state(&self, id: u64, state: &str) -> crate::Result<()> {
        self.forbid_write("set_generation_state")?;
        self.conn
            .execute(
                "UPDATE generations SET state = ?1 WHERE id = ?2",
                vec![v_text(state), v_int(u64_to_i64(id, "generation id")?)],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// Fetch one generation by id.
    pub async fn get_generation(&self, id: u64) -> crate::Result<Option<GenerationRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, scope_policy, state, prior_generation, created_at_ms, scope_key \
                    FROM generations WHERE id = ?1",
                vec![v_int(u64_to_i64(id, "generation id")?)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(GenerationRow::from_row(&row)?)),
        }
    }

    /// v2: record the full scope key for a generation (D5). Never set
    /// (`NULL`) keeps the legacy policy-name key semantics.
    pub async fn set_generation_scope_key(&self, id: u64, scope_key: &str) -> crate::Result<()> {
        self.forbid_write("set_generation_scope_key")?;
        self.conn
            .execute(
                "UPDATE generations SET scope_key = ?1 WHERE id = ?2",
                vec![v_text(scope_key), v_int(u64_to_i64(id, "generation id")?)],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// v2: append one scan-event journal row (D4). `INSERT OR IGNORE` by
    /// `(scan_id, seq)`: redelivery of the same `seq` is idempotent.
    /// Returns true when newly inserted.
    pub async fn append_scan_event(&self, event: &NewScanEvent<'_>) -> crate::Result<bool> {
        self.forbid_write("append_scan_event")?;
        let rows = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO scan_events (scan_id, seq, catalog_rev, event_offset, \
                    event_type, op, reset, records) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                vec![
                    v_text(event.scan_id),
                    v_int(u64_to_i64(event.seq, "event seq")?),
                    v_int(u64_to_i64(event.catalog_rev, "event catalog_rev")?),
                    v_int(u64_to_i64(event.event_offset, "event offset")?),
                    v_text(event.event_type),
                    v_text(event.op),
                    v_int(i64::from(event.reset)),
                    v_blob(event.records.to_vec()),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(rows == 1)
    }

    /// v2: buffer one scan-event journal row into a writer batch (D4),
    /// committing atomically with the instance/checkout rows that caused
    /// it. Same `INSERT OR IGNORE` by `(scan_id, seq)` as
    /// [`Self::append_scan_event`]. Returns `WriterBatch::should_flush`.
    pub fn buffer_scan_event(
        batch: &mut WriterBatch,
        event: &NewScanEvent<'_>,
    ) -> crate::Result<bool> {
        Ok(batch.push(
            "INSERT OR IGNORE INTO scan_events (scan_id, seq, catalog_rev, event_offset, \
                event_type, op, reset, records) \
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            vec![
                v_text(event.scan_id),
                v_int(u64_to_i64(event.seq, "event seq")?),
                v_int(u64_to_i64(event.catalog_rev, "event catalog_rev")?),
                v_int(u64_to_i64(event.event_offset, "event offset")?),
                v_text(event.event_type),
                v_text(event.op),
                v_int(i64::from(event.reset)),
                v_blob(event.records.to_vec()),
            ],
        ))
    }

    /// v2: replay journal rows for a scan after `after_seq` (exclusive),
    /// oldest first, capped at `limit` rows (clamped to `[1, 10_000]`).
    pub async fn read_scan_events(
        &self,
        scan_id: &str,
        after_seq: u64,
        limit: u64,
    ) -> crate::Result<Vec<ScanEventRow>> {
        let limit = limit.clamp(1, 10_000);
        let mut rows = self
            .conn
            .query(
                "SELECT scan_id, seq, catalog_rev, event_offset, event_type, op, reset, records \
                    FROM scan_events WHERE scan_id = ?1 AND seq > ?2 \
                    ORDER BY seq ASC LIMIT ?3",
                vec![
                    v_text(scan_id),
                    v_int(u64_to_i64(after_seq, "after seq")?),
                    v_int(u64_to_i64(limit, "event limit")?),
                ],
            )
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            out.push(ScanEventRow::from_row(&row)?);
        }
        Ok(out)
    }

    /// v2: highest journaled `seq` for a scan (`None` when empty), so a
    /// restarted writer resumes numbering without reuse.
    pub async fn last_event_seq(&self, scan_id: &str) -> crate::Result<Option<u64>> {
        let mut rows = self
            .conn
            .query(
                "SELECT MAX(seq) FROM scan_events WHERE scan_id = ?1",
                vec![v_text(scan_id)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(opt_i64(&row, 0)?
                .map(|v| i64_to_u64(v, "event seq"))
                .transpose()?),
        }
    }

    /// v2: upsert one GitHub group (D1). The id is writer-computed
    /// `lower(host)/lower(account)/lower(repo)`; first observation wins
    /// (`INSERT OR IGNORE`). Returns true when newly inserted.
    pub async fn upsert_github_group(
        &self,
        id: &str,
        host: &str,
        account: &str,
        repo: &str,
        now_ms: i64,
    ) -> crate::Result<bool> {
        self.forbid_write("upsert_github_group")?;
        let rows = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO github_groups (id, host, account, repo, observed_at_ms) \
                    VALUES (?1, ?2, ?3, ?4, ?5)",
                vec![
                    v_text(id),
                    v_text(host),
                    v_text(account),
                    v_text(repo),
                    v_int(now_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(rows == 1)
    }

    /// v2: attach one store to a group via the observing remote's
    /// `(name, role)` (D1). Idempotent. Returns true when newly inserted.
    pub async fn add_group_member(
        &self,
        group_id: &str,
        instance_id: &str,
        remote_name: &[u8],
        role: &str,
        now_ms: i64,
    ) -> crate::Result<bool> {
        self.forbid_write("add_group_member")?;
        let rows = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO group_members (group_id, instance_id, remote_name, role, \
                    observed_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                vec![
                    v_text(group_id),
                    v_text(instance_id),
                    v_blob(remote_name.to_vec()),
                    v_text(role),
                    v_int(now_ms),
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(rows == 1)
    }

    /// v2: one group by id.
    pub async fn get_github_group(&self, id: &str) -> crate::Result<Option<GithubGroupRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, host, account, repo, observed_at_ms \
                    FROM github_groups WHERE id = ?1",
                vec![v_text(id)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            None => Ok(None),
            Some(row) => Ok(Some(GithubGroupRow::from_row(&row)?)),
        }
    }

    /// v2: member edges of one group.
    pub async fn list_group_members(&self, group_id: &str) -> crate::Result<Vec<GroupMemberRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT group_id, instance_id, remote_name, role, observed_at_ms \
                    FROM group_members WHERE group_id = ?1 \
                    ORDER BY instance_id ASC, role ASC",
                vec![v_text(group_id)],
            )
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            out.push(GroupMemberRow::from_row(&row)?);
        }
        Ok(out)
    }

    /// v2: groups one store belongs to (via any remote).
    pub async fn groups_for_instance(
        &self,
        instance_id: &str,
    ) -> crate::Result<Vec<GroupMemberRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT group_id, instance_id, remote_name, role, observed_at_ms \
                    FROM group_members WHERE instance_id = ?1 \
                    ORDER BY group_id ASC",
                vec![v_text(instance_id)],
            )
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            out.push(GroupMemberRow::from_row(&row)?);
        }
        Ok(out)
    }

    /// v2: all observed groups, ordered by id (unique-group totals read
    /// this; one row per distinct normalized identity, so no bound needed).
    pub async fn list_github_groups(&self) -> crate::Result<Vec<GithubGroupRow>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, host, account, repo, observed_at_ms \
                    FROM github_groups ORDER BY id ASC",
                (),
            )
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            out.push(GithubGroupRow::from_row(&row)?);
        }
        Ok(out)
    }
}

impl TursoStore {
    /// Current committed catalog revision (for report envelopes).
    pub async fn current_revision(&self) -> crate::Result<u64> {
        i64_to_u64(
            Self::read_meta_i64(&self.conn, "committed_revision")
                .await?
                .unwrap_or(0),
            "committed catalog revision",
        )
    }

    /// Advance the committed catalog revision; returns the new revision.
    pub async fn next_revision(&self) -> crate::Result<u64> {
        self.with_tx(|conn| async move {
            let next = Self::read_meta_i64(conn, "committed_revision")
                .await?
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| Error::Store("committed catalog revision overflow".to_string()))?;
            Self::write_meta_i64(conn, "committed_revision", next).await?;
            i64_to_u64(next, "committed catalog revision")
        })
        .await
    }

    /// Reconcile a batch idempotency key after a lost acknowledgment
    /// (spec §12): true means the batch committed — do not apply it again;
    /// false means it is safe to apply. Never assume an unobserved
    /// acknowledgment proves the transaction did not commit.
    pub async fn reconcile_idempotency_key(&self, key: &str) -> crate::Result<bool> {
        let mut rows = self
            .conn
            .query(
                "SELECT idempotency_key FROM batches WHERE idempotency_key = ?1",
                vec![v_text(key)],
            )
            .await
            .map_err(store_err)?;
        Ok(rows.next().await.map_err(store_err)?.is_some())
    }

    /// Best-effort marker for a batch whose commit outcome is uncertain
    /// (lost acknowledgment). Crash recovery drops these markers after
    /// requeueing the underlying work.
    pub async fn note_uncertain_batch(&self, key: &str, now_ms: i64) -> crate::Result<()> {
        self.forbid_write("note_uncertain_batch")?;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO batches (idempotency_key, state, created_at_ms) \
                    VALUES (?1, 'uncertain', ?2)",
                vec![v_text(key), v_int(now_ms)],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// Commit a writer batch atomically together with its idempotency
    /// marker. A duplicate key (restart replay) skips the batch and
    /// returns 0. Returns the number of applied ops.
    pub async fn commit_batch(
        &self,
        idempotency_key: &str,
        batch: &mut WriterBatch,
        now_ms: i64,
    ) -> crate::Result<usize> {
        self.forbid_write("commit_batch")?;
        let ops = batch.drain();
        let count = ops.len();
        if count == 0 {
            return Ok(0);
        }
        let key = idempotency_key.to_string();
        // SR-STATE-07: the duplicate check is authoritative only INSIDE the
        // `BEGIN IMMEDIATE` transaction. An outside check-then-insert races:
        // two committers can both observe absence, then both apply ops.
        // `INSERT OR IGNORE` returning 0 rows means a replay — skip ops.
        // Ops execute from clones so a failed transaction restores the
        // batch instead of losing buffered work.
        // Borrow through a shared ref so `async move` captures the ref,
        // not `ops`: a failed transaction restores `ops` into the batch.
        let ops_ref = &ops;
        let applied = match self
            .with_tx(|conn| async move {
                let inserted = conn
                    .execute(
                        "INSERT OR IGNORE INTO batches (idempotency_key, state, created_at_ms) \
                            VALUES (?1, 'committed', ?2)",
                        vec![v_text(key.as_str()), v_int(now_ms)],
                    )
                    .await
                    .map_err(store_err)?
                    == 1;
                if !inserted {
                    return Ok::<bool, Error>(false);
                }
                for op in ops_ref {
                    conn.execute(op.sql.as_str(), op.params.clone())
                        .await
                        .map_err(store_err)?;
                }
                Ok::<bool, Error>(true)
            })
            .await
        {
            Ok(applied) => applied,
            Err(error) => {
                for op in ops {
                    batch.push(op.sql, op.params);
                }
                return Err(error);
            }
        };
        if !applied {
            return Ok(0);
        }
        self.counters.batch_commits.fetch_add(1, Ordering::Relaxed);
        // fix10: op counts are `usize`; loud on 32-bit overflow, infallible on 64-bit.
        let count_u64 = u64::try_from(count)
            .map_err(|_| Error::Store(format!("batch op count {count} exceeds u64 range")))?;
        self.counters
            .batch_ops
            .fetch_add(count_u64, Ordering::Relaxed);
        Ok(count)
    }

    /// Commit a writer batch in one transaction without an idempotency
    /// marker. Returns the number of applied ops.
    pub async fn flush(&self, batch: &mut WriterBatch) -> crate::Result<usize> {
        self.forbid_write("flush")?;
        let ops = batch.drain();
        let count = ops.len();
        if count == 0 {
            return Ok(0);
        }
        // SR-STATE-07: execute from clones; a failed transaction restores
        // the batch instead of losing buffered work. Borrow through a
        // shared ref so `async move` captures the ref, not `ops`.
        let ops_ref = &ops;
        if let Err(error) = self
            .with_tx(|conn| async move {
                for op in ops_ref {
                    conn.execute(op.sql.as_str(), op.params.clone())
                        .await
                        .map_err(store_err)?;
                }
                Ok::<(), Error>(())
            })
            .await
        {
            for op in ops {
                batch.push(op.sql, op.params);
            }
            return Err(error);
        }
        self.counters.batch_commits.fetch_add(1, Ordering::Relaxed);
        // fix10: op counts are `usize`; loud on 32-bit overflow, infallible on 64-bit.
        let count_u64 = u64::try_from(count)
            .map_err(|_| Error::Store(format!("batch op count {count} exceeds u64 range")))?;
        self.counters
            .batch_ops
            .fetch_add(count_u64, Ordering::Relaxed);
        Ok(count)
    }

    /// Buffer an idempotent task enqueue for batched commit. The scan
    /// loop calls the `buffer_*` family during task execution instead of
    /// the one-statement-per-row single-shot writes, and flushes via
    /// [`TursoStore::flush`]/[`TursoStore::commit_batch`] whenever the
    /// return value reports a spec §5 limit (512 rows, 512 KiB, 250 ms),
    /// before any read that must observe the buffered rows, and before
    /// verified parent completion. Buffered rows are invisible until the
    /// flush commits. Returns `WriterBatch::should_flush`.
    pub fn buffer_enqueue_task(batch: &mut WriterBatch, task: &NewTask<'_>, now_ms: i64) -> bool {
        // fix10: `generation`/`expected_rev` round-trip from range-checked
        // `INTEGER` reads, so they always fit `i64` here; out-of-range
        // input is a caller defect and panics loudly (release builds must
        // fail too, so a `debug_assert`-only guard is not enough).
        // Step 9: mark class skew at buffer time — strictly before the
        // flush can commit the row (conservative on `OR IGNORE`
        // duplicates — a spurious mark only falls back).
        note_task_class(task.kind, task.id);
        let generation_i64 = u64_to_i64_buf(task.generation, "task generation");
        let expected_rev_i64 = u64_to_i64_buf(task.expected_rev, "task expected_rev");
        batch.push(
            "INSERT OR IGNORE INTO frontier_tasks (id, kind, generation, dir_id, \
                scope_key, expected_rev, state, idempotency_key, attempts, \
                updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, 0, ?8)",
            vec![
                v_text(task.id),
                v_text(task.kind),
                v_int(generation_i64),
                v_opt_int(task.dir_id),
                v_text(task.scope_key),
                v_int(expected_rev_i64),
                v_text(task.idempotency_key),
                v_int(now_ms),
            ],
        )
    }

    /// Deterministic 63-bit directory ID derived from physical identity (R05).
    pub fn dir_identity_id(volume_id: &str, object_id: &str, incarnation: &str) -> i64 {
        dir_identity_id(volume_id, object_id, incarnation)
    }

    /// Buffer the write half of [`TursoStore::upsert_dir`] (insert-or-ignore
    /// plus attribute refresh). The row id is derived deterministically from
    /// physical identity (R05) via [`dir_identity_id`], avoiding the need to
    /// flush just to observe an autoincrement id. Returns
    /// `WriterBatch::should_flush`.
    #[allow(clippy::too_many_arguments)]
    pub fn buffer_dir_upsert(
        batch: &mut WriterBatch,
        parent_id: Option<i64>,
        component: &[u8],
        display: &str,
        volume_id: &str,
        object_id: &str,
        incarnation: &str,
        observed_ms: i64,
    ) -> bool {
        let id = dir_identity_id(volume_id, object_id, incarnation);
        batch.push(
            "INSERT OR IGNORE INTO directories (id, parent_id, component, display, \
                volume_id, object_id, incarnation, last_observed_ms, \
                invalidation_rev) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
            vec![
                v_int(id),
                v_opt_int(parent_id),
                v_blob(component.to_vec()),
                v_text(display),
                v_text(volume_id),
                v_text(object_id),
                v_text(incarnation),
                v_int(observed_ms),
            ],
        );
        batch.push(
            "UPDATE directories SET parent_id = ?1, display = ?2, \
                last_observed_ms = ?3 WHERE volume_id = ?4 AND object_id = ?5 \
                AND incarnation = ?6",
            vec![
                v_opt_int(parent_id),
                v_text(display),
                v_int(observed_ms),
                v_text(volume_id),
                v_text(object_id),
                v_text(incarnation),
            ],
        );
        batch.should_flush()
    }

    /// Buffer an enumeration observation; see [`TursoStore::buffer_enqueue_task`]
    /// for the flush contract. Returns `WriterBatch::should_flush`.
    #[allow(clippy::too_many_arguments)]
    pub fn buffer_record_dir_observation(
        batch: &mut WriterBatch,
        dir_id: i64,
        generation: u64,
        completed: bool,
        entry_generation: u64,
        entries_seen: u64,
        error: Option<&str>,
        observed_ms: i64,
    ) -> bool {
        let generation_i64 = u64_to_i64_buf(generation, "dir observation generation");
        let entry_generation_i64 = u64_to_i64_buf(entry_generation, "dir entry_generation");
        let entries_seen_i64 = u64_to_i64_buf(entries_seen, "dir entries_seen");
        batch.push(
            "INSERT OR REPLACE INTO dir_observations (dir_id, generation, completed, \
                entry_generation, entries_seen, error, observed_at_ms) \
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            vec![
                v_int(dir_id),
                v_int(generation_i64),
                v_int(i64::from(completed)),
                v_int(entry_generation_i64),
                v_int(entries_seen_i64),
                v_opt_text(error.map(str::to_string)),
                v_int(observed_ms),
            ],
        )
    }

    /// Buffer an enumeration observation with the attempt counted in SQL
    /// (RSF-751/AC46/F06D): the unconditional `UPDATE` bumps
    /// `entry_generation` and refreshes the outcome columns, mirroring the
    /// `record_error` update-then-insert shape, while `INSERT OR IGNORE`
    /// seeds a first observation at generation 1. No read is needed, so
    /// callers never flush just to observe a buffered row before writing
    /// the next observation; two observations for one (`dir_id`,
    /// `generation`) in a single batch count 1 then 2 in op order. See
    /// [`TursoStore::buffer_enqueue_task`] for the flush contract. Returns
    /// `WriterBatch::should_flush`.
    #[allow(clippy::too_many_arguments)]
    pub fn buffer_record_dir_observation_bumped(
        batch: &mut WriterBatch,
        dir_id: i64,
        generation: u64,
        completed: bool,
        entries_seen: u64,
        error: Option<&str>,
        observed_ms: i64,
    ) -> bool {
        let generation_i64 = u64_to_i64_buf(generation, "dir observation generation");
        let entries_seen_i64 = u64_to_i64_buf(entries_seen, "dir entries_seen");
        batch.push(
            "UPDATE dir_observations SET entry_generation = entry_generation + 1, \
                completed = ?1, entries_seen = ?2, error = ?3, observed_at_ms = ?4 \
                WHERE dir_id = ?5 AND generation = ?6",
            vec![
                v_int(i64::from(completed)),
                v_int(entries_seen_i64),
                v_opt_text(error.map(str::to_string)),
                v_int(observed_ms),
                v_int(dir_id),
                v_int(generation_i64),
            ],
        );
        batch.push(
            "INSERT OR IGNORE INTO dir_observations (dir_id, generation, completed, \
                entry_generation, entries_seen, error, observed_at_ms) \
                VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)",
            vec![
                v_int(dir_id),
                v_int(generation_i64),
                v_int(i64::from(completed)),
                v_int(entries_seen_i64),
                v_opt_text(error.map(str::to_string)),
                v_int(observed_ms),
            ],
        );
        batch.should_flush()
    }

    /// Buffer a Git-instance upsert; see [`TursoStore::buffer_enqueue_task`]
    /// for the flush contract. Returns `WriterBatch::should_flush`.
    pub fn buffer_upsert_git_instance(
        batch: &mut WriterBatch,
        instance: &NewGitInstance<'_>,
        observed_ms: i64,
    ) -> bool {
        batch.push(
            "INSERT OR REPLACE INTO git_instances (id, git_path, common_path, \
                incarnation, format, bare, object_format, disposition, evidence, \
                observed_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            vec![
                v_text(instance.id),
                v_blob(instance.git_path.to_vec()),
                v_blob(instance.common_path.to_vec()),
                v_text(instance.incarnation),
                v_text(instance.format),
                v_opt_int(instance.bare.map(i64::from)),
                v_text(instance.object_format),
                v_text(instance.disposition),
                v_text(instance.evidence_json),
                v_int(observed_ms),
            ],
        )
    }

    /// Buffer an insert-if-absent checkout write; see
    /// [`TursoStore::buffer_enqueue_task`] for the flush contract. Returns
    /// `WriterBatch::should_flush`.
    pub fn buffer_insert_checkout_if_absent(
        batch: &mut WriterBatch,
        checkout: &NewCheckout<'_>,
        observed_ms: i64,
    ) -> bool {
        batch.push(
            "INSERT OR IGNORE INTO checkouts (id, instance_id, root_path, git_path, \
                relationship, availability, head_state, head_ref, head_oid, \
                head_algo, observed_at_ms) \
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            vec![
                v_text(checkout.id),
                v_text(checkout.instance_id),
                v_opt_blob(checkout.root_path.map(<[u8]>::to_vec)),
                v_blob(checkout.git_path.to_vec()),
                v_text(checkout.relationship),
                v_text(checkout.availability),
                v_text(checkout.head_state),
                v_opt_blob(checkout.head_ref.map(<[u8]>::to_vec)),
                v_opt_blob(checkout.head_oid.map(<[u8]>::to_vec)),
                v_opt_text(checkout.head_algo.map(str::to_string)),
                v_int(observed_ms),
            ],
        )
    }

    /// Buffer a checkout upsert; see [`TursoStore::buffer_enqueue_task`] for
    /// the flush contract. Returns `WriterBatch::should_flush`.
    pub fn buffer_upsert_checkout(
        batch: &mut WriterBatch,
        checkout: &NewCheckout<'_>,
        observed_ms: i64,
    ) -> bool {
        batch.push(
            "INSERT OR REPLACE INTO checkouts (id, instance_id, root_path, git_path, \
                relationship, availability, head_state, head_ref, head_oid, \
                head_algo, observed_at_ms) \
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            vec![
                v_text(checkout.id),
                v_text(checkout.instance_id),
                v_opt_blob(checkout.root_path.map(<[u8]>::to_vec)),
                v_blob(checkout.git_path.to_vec()),
                v_text(checkout.relationship),
                v_text(checkout.availability),
                v_text(checkout.head_state),
                v_opt_blob(checkout.head_ref.map(<[u8]>::to_vec)),
                v_opt_blob(checkout.head_oid.map(<[u8]>::to_vec)),
                v_opt_text(checkout.head_algo.map(str::to_string)),
                v_int(observed_ms),
            ],
        )
    }

    /// Buffer a remote upsert; see [`TursoStore::buffer_enqueue_task`] for
    /// the flush contract. Returns `WriterBatch::should_flush`. Stored
    /// URLs pass through the sink-side redaction (see
    /// `redacted_remote_bytes`).
    pub fn buffer_upsert_remote(
        batch: &mut WriterBatch,
        remote: &NewRemote<'_>,
        observed_ms: i64,
    ) -> bool {
        batch.push(
            "INSERT OR REPLACE INTO remotes (id, instance_id, checkout_scope_id, name, \
                role, url, canonical_url, observed_at_ms) \
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            vec![
                v_text(remote.id),
                v_text(remote.instance_id),
                v_opt_text(remote.checkout_scope_id.map(str::to_string)),
                v_blob(remote.name.to_vec()),
                v_text(remote.role),
                v_blob(redacted_remote_bytes(remote.url)),
                v_opt_blob(remote.canonical_url.map(redacted_remote_bytes)),
                v_int(observed_ms),
            ],
        )
    }

    /// Buffer a v2 GitHub group upsert (`INSERT OR IGNORE`, first
    /// observation wins); same SQL as [`TursoStore::upsert_github_group`].
    /// The id is the caller-computed `lower(host)/lower(account)/lower(repo)`
    /// (D1). Returns `WriterBatch::should_flush`.
    pub fn buffer_upsert_github_group(
        batch: &mut WriterBatch,
        id: &str,
        host: &str,
        account: &str,
        repo: &str,
        observed_ms: i64,
    ) -> bool {
        batch.push(
            "INSERT OR IGNORE INTO github_groups (id, host, account, repo, observed_at_ms) \
                VALUES (?1, ?2, ?3, ?4, ?5)",
            vec![
                v_text(id),
                v_text(host),
                v_text(account),
                v_text(repo),
                v_int(observed_ms),
            ],
        )
    }

    /// Buffer one v2 store-to-group edge (`INSERT OR IGNORE`); same SQL as
    /// [`TursoStore::add_group_member`]. Returns `WriterBatch::should_flush`.
    pub fn buffer_add_group_member(
        batch: &mut WriterBatch,
        group_id: &str,
        instance_id: &str,
        remote_name: &[u8],
        role: &str,
        observed_ms: i64,
    ) -> bool {
        batch.push(
            "INSERT OR IGNORE INTO group_members (group_id, instance_id, remote_name, role, \
                observed_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            vec![
                v_text(group_id),
                v_text(instance_id),
                v_blob(remote_name.to_vec()),
                v_text(role),
                v_int(observed_ms),
            ],
        )
    }

    /// Buffer a ref upsert; see [`TursoStore::buffer_enqueue_task`] for the
    /// flush contract. Two statements (`INSERT OR IGNORE` + `UPDATE`),
    /// mirroring [`TursoStore::upsert_ref`]: the pair preserves the v3
    /// `freshness` label columns and is race-safe. Returns
    /// `WriterBatch::should_flush` (true when either push trips it).
    pub fn buffer_upsert_ref(
        batch: &mut WriterBatch,
        reference: &NewRef<'_>,
        observed_ms: i64,
    ) -> bool {
        let insert = batch.push(
            "INSERT OR IGNORE INTO refs (id, instance_id, checkout_scope_id, kind, \
                name, oid, algo, symbolic_target, upstream, state, observed_at_ms) \
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            ref_params(reference, observed_ms),
        );
        let update = batch.push(
            "UPDATE refs SET instance_id = ?2, checkout_scope_id = ?3, kind = ?4, \
                name = ?5, oid = ?6, algo = ?7, symbolic_target = ?8, \
                upstream = ?9, state = ?10, observed_at_ms = ?11 WHERE id = ?1",
            ref_params(reference, observed_ms),
        );
        insert || update
    }

    /// Buffer a `--fetch` attempt record (v3); see
    /// [`TursoStore::buffer_enqueue_task`] for the flush contract.
    /// Same `INSERT OR REPLACE` semantics as
    /// [`TursoStore::record_remote_refresh`]. Returns
    /// `WriterBatch::should_flush`.
    pub fn buffer_record_remote_refresh(
        batch: &mut WriterBatch,
        refresh: &NewRemoteRefresh<'_>,
    ) -> bool {
        batch.push(
            "INSERT OR REPLACE INTO remote_refreshes (store_id, remote_name, \
                status, observed_at_ms, duration_ms, refs_updated, \
                refs_current_json, refs_deleted_json, detail) \
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            vec![
                v_text(refresh.store_id),
                v_blob(refresh.remote_name.to_vec()),
                v_text(refresh.status),
                v_int(refresh.observed_at_ms),
                v_opt_int(refresh.duration_ms),
                v_int(refresh.refs_updated),
                v_opt_text(refresh.refs_current_json.map(str::to_string)),
                v_opt_text(refresh.refs_deleted_json.map(str::to_string)),
                v_opt_text(refresh.detail.map(str::to_string)),
            ],
        )
    }

    /// Buffer a ref oid re-observation (v3); see
    /// [`TursoStore::buffer_enqueue_task`] for the flush contract.
    /// Same `UPDATE` semantics as [`TursoStore::update_ref_oid`]
    /// (shared [`UPDATE_REF_OID_SQL`]). Returns
    /// `WriterBatch::should_flush`.
    pub fn buffer_update_ref_oid(
        batch: &mut WriterBatch,
        ref_id: &str,
        oid: &[u8],
        at_ms: i64,
    ) -> bool {
        batch.push(
            UPDATE_REF_OID_SQL,
            vec![v_text(ref_id), v_blob(oid.to_vec()), v_int(at_ms)],
        )
    }

    /// Buffer a ref freshness label (v3); see
    /// [`TursoStore::buffer_enqueue_task`] for the flush contract.
    /// Same `UPDATE` semantics as [`TursoStore::label_ref_freshness`].
    /// Returns `WriterBatch::should_flush`.
    pub fn buffer_label_ref_freshness(
        batch: &mut WriterBatch,
        ref_id: &str,
        freshness: &str,
        at_ms: i64,
    ) -> bool {
        batch.push(
            "UPDATE refs SET freshness = ?2, freshness_at_ms = ?3 WHERE id = ?1",
            vec![v_text(ref_id), v_text(freshness), v_int(at_ms)],
        )
    }

    /// Buffer a ref comparison label (v6); see
    /// [`TursoStore::buffer_enqueue_task`] for the flush contract.
    /// Same `UPDATE` semantics as
    /// [`TursoStore::update_ref_comparison`] (shared
    /// [`UPDATE_REF_COMPARISON_SQL`]). Returns
    /// `WriterBatch::should_flush`. The caller MUST have verified
    /// [`TursoStore::supports_ref_comparison`] first: on a pre-v6
    /// catalog this statement would fail at flush, so pre-v6
    /// callers skip buffering entirely.
    pub fn buffer_update_ref_comparison(
        batch: &mut WriterBatch,
        ref_id: &str,
        state: &str,
        ahead: Option<u64>,
        behind: Option<u64>,
    ) -> bool {
        let ahead = ahead.map(|v| u64_to_i64_buf(v, "ref ahead"));
        let behind = behind.map(|v| u64_to_i64_buf(v, "ref behind"));
        batch.push(
            UPDATE_REF_COMPARISON_SQL,
            vec![
                v_text(ref_id),
                v_text(state),
                v_opt_int(ahead),
                v_opt_int(behind),
            ],
        )
    }

    /// Buffer a status observation; see [`TursoStore::buffer_enqueue_task`]
    /// for the flush contract. Unlike [`TursoStore::record_status`] the
    /// inserted-or-ignored outcome is only knowable after flush (by
    /// re-reading); the return value is `WriterBatch::should_flush`.
    pub fn buffer_record_status(
        batch: &mut WriterBatch,
        status: &NewStatus<'_>,
        observed_ms: i64,
    ) -> bool {
        let observed_rev_i64 = u64_to_i64_buf(status.observed_rev, "status observed_rev");
        batch.push(
            "INSERT OR IGNORE INTO status_observations (checkout_id, mode, state, \
                started_ms, finished_ms, staged, unstaged, untracked, \
                untracked_units, submodules, unknown_fields, input_fingerprint, \
                observed_rev, observed_at_ms, conflicts, working_state) \
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, \
                ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            vec![
                v_text(status.checkout_id),
                v_text(status.mode),
                v_text(status.state),
                v_opt_int(status.started_ms),
                v_opt_int(status.finished_ms),
                v_opt_int(status.staged),
                v_opt_int(status.unstaged),
                v_opt_int(status.untracked),
                v_text(status.untracked_units),
                v_text(status.submodules),
                v_text(status.unknown_fields),
                v_opt_blob(status.input_fingerprint.map(<[u8]>::to_vec)),
                v_int(observed_rev_i64),
                v_int(observed_ms),
                v_opt_int(status.conflicts),
                v_text(status.working_state),
            ],
        )
    }

    /// Explicit `PRAGMA wal_checkpoint(TRUNCATE)`; returns
    /// `(busy, log_frames, checkpointed_frames)`. Coordinate with readers:
    /// a nonzero `busy` means a reader held the WAL — keep serving reads
    /// and retry the checkpoint later instead of blocking them.
    pub async fn checkpoint_truncate(&self) -> crate::Result<(u64, u64, u64)> {
        self.forbid_write("checkpoint_truncate")?;
        let out = Self::wal_checkpoint(&self.conn, "TRUNCATE").await?;
        self.counters.checkpoints.fetch_add(1, Ordering::Relaxed);
        Ok(out)
    }

    /// Checkpoint progress probe that never blocks readers: runs
    /// `PRAGMA wal_checkpoint(PASSIVE)` and reports WAL depth. Use it to
    /// measure WAL growth and decide when to coordinate a truncate.
    pub async fn wal_status(&self) -> crate::Result<WalStatus> {
        let (busy, log_frames, checkpointed_frames) =
            Self::wal_checkpoint(&self.conn, "PASSIVE").await?;
        self.counters.wal_probes.fetch_add(1, Ordering::Relaxed);
        Ok(WalStatus {
            busy,
            log_frames,
            checkpointed_frames,
        })
    }

    async fn wal_checkpoint(
        conn: &turso::Connection,
        mode: &str,
    ) -> crate::Result<(u64, u64, u64)> {
        debug_assert!(mode == "TRUNCATE" || mode == "PASSIVE");
        let sql = format!("PRAGMA wal_checkpoint({mode})");
        let mut rows = conn.query(sql.as_str(), ()).await.map_err(store_err)?;
        let row =
            rows.next().await.map_err(store_err)?.ok_or_else(|| {
                Error::Store("PRAGMA wal_checkpoint returned no rows".to_string())
            })?;
        // turso reports only `busy` when the checkpoint cannot proceed
        // (busy=1, NULL counters), unlike SQLite which reports counts. The
        // counters surface as 0 there; callers key off `busy`.
        Ok((
            i64_to_u64(req_i64(&row, 0)?, "wal_checkpoint busy")?,
            i64_to_u64(opt_i64(&row, 1)?.unwrap_or(0), "wal_checkpoint log frames")?,
            i64_to_u64(
                opt_i64(&row, 2)?.unwrap_or(0),
                "wal_checkpoint checkpointed frames",
            )?,
        ))
    }

    /// Open a same-process read connection with the same durability
    /// PRAGMAs (plus a busy timeout for writer contention). Report
    /// streaming uses `prepare` plus `Rows::next()` on a dedicated
    /// reader; a reader must be drained or dropped before checkpoint
    /// coordination expects a non-busy truncate.
    pub async fn open_reader(&self) -> crate::Result<turso::Connection> {
        self.verify_state_root()?;
        let conn = self.db.connect().map_err(store_err)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(store_err)?;
        Self::pragma_assign(&conn, "synchronous = FULL").await?;
        Self::pragma_assign(&conn, "data_sync_retry = ON").await?;
        #[cfg(target_os = "macos")]
        Self::pragma_assign(&conn, "fullfsync = ON").await?;
        let journal_mode = Self::pragma_text(&conn, "journal_mode").await?;
        if journal_mode.to_lowercase() != "wal" {
            return Err(Error::Store(format!(
                "reader journal_mode query-back is {journal_mode:?}, want wal"
            )));
        }
        Ok(conn)
    }

    /// Best-effort final checkpoint, then release the database handles.
    /// A busy checkpoint (a same-process reader holds the WAL) is an
    /// expected coordination state, not a close failure: durability never
    /// depends on the final checkpoint, so its outcome is ignored.
    pub async fn close(self) -> crate::Result<()> {
        if !self.read_only {
            let _ = Self::wal_checkpoint(&self.conn, "TRUNCATE").await;
        }
        drop(self);
        Ok(())
    }
}

impl crate::store::Store for TursoStore {
    async fn open(db_path: &std::path::Path) -> crate::Result<Self> {
        Self::open_inner(db_path).await
    }

    fn schema_version(&self) -> crate::Result<u32> {
        Ok(self.schema_version)
    }

    async fn checkpoint(&self) -> crate::Result<(u64, u64, u64)> {
        self.checkpoint_truncate().await
    }

    async fn durability_proof(&self) -> crate::Result<crate::store::DurabilityProof> {
        Self::proof_on(&self.conn).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
    }

    /// DB-m1: the skew probe is scoped to the claimed generation — a
    /// skewed pair in another generation neither forces this claim's
    /// fallback nor hides from its own generation's probe.
    #[test]
    fn skew_probe_ignores_other_generations() {
        let rt = runtime();
        rt.block_on(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let db = dir.path().join("payload").join("catalog.db");
            let store = TursoStore::open(&db).await.expect("open");
            let now = crate::store::now_ms();
            // Skewed pair (kind/status pulled into the probe class by
            // its id) in generation 2 only.
            let idem = "idem:probe:2:skew".to_string();
            store
                .enqueue_task(
                    &NewTask {
                        id: "probe:2:skew",
                        kind: "status",
                        generation: 2,
                        dir_id: None,
                        scope_key: "status:skew",
                        expected_rev: 0,
                        idempotency_key: &idem,
                    },
                    now,
                )
                .await
                .expect("enqueue");
            assert!(
                !TursoStore::task_class_skew_present_on(store.connection(), 1)
                    .await
                    .expect("probe gen 1"),
                "other-generation skew must not gate this claim"
            );
            assert!(
                TursoStore::task_class_skew_present_on(store.connection(), 2)
                    .await
                    .expect("probe gen 2"),
                "own-generation skew must still be found"
            );
            store.close().await.expect("close");
        });
    }
}
