//! Build and stream the normative report from one consistent catalog
//! revision (spec §§15–16).
//!
//! The caller (owner lane) pins a catalog revision, holds a publication
//! barrier (no writer commits while streaming), and supplies the small
//! caller-owned sections (roots, aliases, storage links, candidates,
//! generated artifacts) plus coverage counters. This module streams every
//! catalog-backed section with `prepare`/`Rows::next()` semantics —
//! `Connection::query` plus row-by-row `next()` — so memory stays bounded
//! by the largest single record plus small pre-pass maps keyed by
//! repository/checkout (never by directory or path).
//!
//! ID resolution holds by construction: every emitted reference points at
//! an emitted or lookup-verified record; orphan rows (a checkout, ref, or
//! remote whose instance is not in the report) are skipped and counted in
//! [`StreamStats`]; caller inputs are verified up front and rejected loudly
//! when they dangle.

use crate::error::Error;
use crate::identity::{redact_remote_url, scrub_text};
use crate::model::StatusMode;
use crate::report::encode::{
    cap_report_field, encode_bytes, encode_name, guess_oid_algorithm, ms_to_rfc3339,
    oid_hex_from_bytes,
};
use crate::report::model::{
    Alias, AnalysisTotals, Branch, Candidate, Checkout, Coverage, ErrorRecord, GeneratedArtifact,
    Group, Head, ObjectId, PathRecord, Remote, RemoteRefresh, Report, Repository, Resources, Root,
    Scan, ScanTarget, Status, StorageLink, Tool, Totals, Volume,
};
use crate::report::publish::{
    check_report_id, check_staged_memory_budget, check_streaming_measurement_memory_budget,
    check_streaming_staged_memory_budget, publish_bound, retain_bound, BoundStaged, PublishReceipt,
};
use crate::report::stream::StreamingWriter;
use std::collections::{HashMap, HashSet};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Entry-count cap for the directory full-path cache ([`FullPathCache`];
/// cleared and rebuilt when full, so correctness never depends on it).
/// Paired with [`MAX_FULL_PATH_CACHE_BYTES`], which bounds aggregate
/// retained bytes: total retention never exceeds either bound.
const PATH_CACHE_CAP: usize = 4096;

/// Maximum parent-chain depth when reconstructing a full path. Deeper
/// chains (or cycles) fail loudly instead of looping.
const MAX_PATH_DEPTH: usize = 1024;

/// Caller-supplied scan root. Exactly one of `dir_id` (a `directories` row,
/// verified to exist) or `path_bytes` (interned as a synthetic path) must
/// be set.
#[derive(Debug, Clone)]
pub struct RootInput {
    pub id: String,
    pub dir_id: Option<i64>,
    pub path_bytes: Option<Vec<u8>>,
    pub volume_id: Option<String>,
    pub state: String,
    pub observed_at_ms: Option<i64>,
    pub event_history_uuid: Option<String>,
    pub ingested_cursor: Option<String>,
    pub reconciled_cursor: Option<String>,
    pub error_ids: Vec<String>,
}

/// Caller-supplied unresolved candidate. `repository_id` must name an
/// emitted repository when present; `error_ids` must exist.
#[derive(Debug, Clone)]
pub struct CandidateInput {
    pub id: String,
    pub path_bytes: Vec<u8>,
    pub repository_id: Option<String>,
    pub disposition: String,
    pub reason: String,
    pub retry_after_ms: Option<i64>,
    pub error_ids: Vec<String>,
}

/// Caller-supplied storage edge. `from_repository_id` must name an emitted
/// repository; the target path is interned as a synthetic path.
#[derive(Debug, Clone)]
pub struct StorageLinkInput {
    pub id: String,
    pub from_repository_id: String,
    pub to_path_bytes: Vec<u8>,
    pub kind: String,
    pub evidence: Vec<String>,
}

/// Caller-supplied pathname alias. Both ends are interned.
#[derive(Debug, Clone)]
pub struct AliasInput {
    pub path_bytes: Vec<u8>,
    pub target_path_bytes: Vec<u8>,
    pub kind: String,
    pub verified_at_ms: i64,
}

/// Caller-supplied generated artifact. A report published inside scanned
/// scope is listed with `created_after_status: true`; the owner lane
/// observes requested working state before publication.
#[derive(Debug, Clone)]
pub struct ArtifactInput {
    pub path_bytes: Vec<u8>,
    pub kind: String,
    pub created_after_status: bool,
}

/// Convenience: the inside-tree report artifact for `dest` bytes.
pub fn artifact_for_report(dest: &Path) -> ArtifactInput {
    ArtifactInput {
        path_bytes: dest.as_os_str().as_encoded_bytes().to_vec(),
        kind: "report".to_string(),
        created_after_status: true,
    }
}

/// Everything the builder needs beyond the catalog itself.
#[derive(Debug, Clone)]
pub struct ReportInputs {
    /// New immutable report ID (also the snapshot name).
    pub report_id: String,
    pub created_at_ms: i64,
    pub scan_id: String,
    pub generation: u64,
    pub epoch: u64,
    /// Catalog revision pinned by the caller under the publication barrier.
    /// Advisory: the envelope reports the revision actually observed
    /// stable across the pre-pass and the stream (RSP-009).
    pub catalog_revision: u64,
    pub target_url: String,
    pub canonical_url: Option<String>,
    /// Full requested target set in request order (empty for `--all`).
    pub targets: Vec<ScanTarget>,
    pub scope: String,
    pub scan_state: String,
    pub started_at_ms: i64,
    pub finished_at_ms: Option<i64>,
    pub superseded_by: Option<String>,
    pub cached: bool,
    pub status_mode: StatusMode,
    /// Traversal counters (summarize work, exempt from count agreement).
    pub directories_complete: u64,
    /// Legacy caller count, ignored by the builder (RSP-008): coverage
    /// uses the in-transaction pending/leased count for `generation`.
    /// Kept so the `main.rs` task-struct call site still compiles.
    pub tasks_pending: u64,
    pub scope_boundaries: Vec<String>,
    /// Resource accounting.
    pub profile: String,
    pub cpu_target_cores: f64,
    pub rss_target_bytes: u64,
    pub peak_rss_bytes: Option<u64>,
    pub cpu_seconds: Option<f64>,
    pub enumerated_entries: u64,
    pub db_transactions: u64,
    pub db_sync_calls: Option<u64>,
    pub source_commit: Option<String>,
    /// Include `nonmatch` repositories too (default target reports skip
    /// them; their catalog observations stay reusable for another URL).
    pub include_nonmatching: bool,
    /// Coverage overrides; `None` selects the computed value. A supplied
    /// value that contradicts the derived scan state is refused (RSP-008),
    /// so overrides can only restate the truth, never invent it.
    pub coverage_filesystem: Option<String>,
    pub coverage_identity: Option<String>,
    pub coverage_status: Option<String>,
    /// Caller-owned small sections.
    pub roots: Vec<RootInput>,
    pub storage_links: Vec<StorageLinkInput>,
    pub aliases: Vec<AliasInput>,
    pub candidates: Vec<CandidateInput>,
    pub generated_artifacts: Vec<ArtifactInput>,
}

/// Per-section emission counts for one streamed report.
#[derive(Debug, Clone, Default)]
pub struct StreamStats {
    pub volumes: u64,
    pub stub_volumes: u64,
    pub paths: u64,
    pub roots: u64,
    pub groups: u64,
    pub accounts: u64,
    pub repositories: u64,
    pub checkouts: u64,
    pub branches: u64,
    pub remotes: u64,
    pub storage_links: u64,
    pub aliases: u64,
    pub candidates: u64,
    pub errors: u64,
    pub generated_artifacts: u64,
    /// Rows skipped because their instance is not in the report.
    pub skipped_orphans: u64,
}

fn store_err(error: turso::Error) -> Error {
    Error::Store(error.to_string())
}

fn req_i64(row: &turso::Row, idx: usize) -> crate::Result<i64> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Integer(value) => Ok(value),
        other => Err(Error::Store(format!(
            "report: column {idx} expected INTEGER, got {other:?}"
        ))),
    }
}

fn opt_i64(row: &turso::Row, idx: usize) -> crate::Result<Option<i64>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Null => Ok(None),
        turso::Value::Integer(value) => Ok(Some(value)),
        other => Err(Error::Store(format!(
            "report: column {idx} expected INTEGER or NULL, got {other:?}"
        ))),
    }
}

fn req_text(row: &turso::Row, idx: usize) -> crate::Result<String> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Text(value) => Ok(value),
        other => Err(Error::Store(format!(
            "report: column {idx} expected TEXT, got {other:?}"
        ))),
    }
}

fn opt_text(row: &turso::Row, idx: usize) -> crate::Result<Option<String>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Null => Ok(None),
        turso::Value::Text(value) => Ok(Some(value)),
        other => Err(Error::Store(format!(
            "report: column {idx} expected TEXT or NULL, got {other:?}"
        ))),
    }
}

fn req_blob(row: &turso::Row, idx: usize) -> crate::Result<Vec<u8>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Blob(value) => Ok(value),
        other => Err(Error::Store(format!(
            "report: column {idx} expected BLOB, got {other:?}"
        ))),
    }
}

fn opt_blob(row: &turso::Row, idx: usize) -> crate::Result<Option<Vec<u8>>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Null => Ok(None),
        turso::Value::Blob(value) => Ok(Some(value)),
        other => Err(Error::Store(format!(
            "report: column {idx} expected BLOB or NULL, got {other:?}"
        ))),
    }
}

/// Nullable count column (`refs.ahead`/`refs.behind`, report 1.4.0):
/// NULL reads `None`; a negative stored value is catalog corruption
/// and fails loudly instead of wrapping.
fn opt_count(row: &turso::Row, idx: usize, what: &str) -> crate::Result<Option<u64>> {
    match opt_i64(row, idx)? {
        None => Ok(None),
        Some(value) if value >= 0 => Ok(Some(value as u64)),
        Some(value) => Err(Error::Store(format!(
            "report: refs {what} {value} is negative: catalog corruption"
        ))),
    }
}

/// Maximum raw bytes accepted for one stored JSON string array
/// (RSP-010): bounds the input before any parse work begins.
const MAX_STRING_ARRAY_RAW_BYTES: usize = 256 * 1024;
/// Maximum items retained from one stored JSON string array.
const MAX_STRING_ARRAY_ITEMS: usize = 1024;
/// Maximum aggregate capped bytes retained from one stored array.
const MAX_STRING_ARRAY_TOTAL_BYTES: usize = 256 * 1024;

/// Lenient JSON string-array parse for stored evidence/unknown-fields.
/// Parses element-by-element without materializing the whole vector, so
/// one hostile catalog row cannot exhaust memory (RSP-010): total input
/// bytes, item count, and aggregate output bytes are each bounded, with
/// an explicit truncation marker when a bound bites. Falls back to a
/// single line so observations are never dropped. Every emitted line is
/// privacy-scrubbed (RSP-001/RSP-011) and per-field capped: one huge
/// stored line must not blow the streaming memory bound.
fn parse_string_array(raw: &str) -> Vec<String> {
    if raw.is_empty() {
        return Vec::new();
    }
    if raw.len() > MAX_STRING_ARRAY_RAW_BYTES {
        return vec![format!(
            "…[stored list of {} bytes exceeds the {MAX_STRING_ARRAY_RAW_BYTES}-byte bound; content withheld]",
            raw.len()
        )];
    }
    match raw.trim_start().strip_prefix('[') {
        None => vec![scrubbed_field(raw)],
        Some(inner) => parse_capped_array(inner, raw),
    }
}

/// One privacy-scrubbed, field-capped emission line for persisted prose.
fn scrubbed_field(text: &str) -> String {
    cap_report_field(&scrub_text(text))
}

/// Trim JSON insignificant whitespace.
fn trim_json_ws(text: &str) -> &str {
    text.trim_start_matches([' ', '\t', '\r', '\n'])
}

/// Incrementally parse the elements of one JSON string array (`inner` is
/// the text after the opening `[`). At most one element is held at a
/// time; malformed JSON falls back to the whole observation as one
/// scrubbed, capped line so nothing is silently dropped.
fn parse_capped_array(mut inner: &str, raw: &str) -> Vec<String> {
    let fallback = || vec![scrubbed_field(raw)];
    let mut items: Vec<String> = Vec::new();
    let mut total_bytes = 0usize;
    let mut first = true;
    loop {
        inner = trim_json_ws(inner);
        if !first {
            match inner.strip_prefix(',') {
                Some(rest) => inner = trim_json_ws(rest),
                None => match inner.strip_prefix(']') {
                    Some(rest) if rest.trim().is_empty() => return items,
                    _ => return fallback(),
                },
            }
        } else if let Some(rest) = inner.strip_prefix(']') {
            return if rest.trim().is_empty() {
                items
            } else {
                fallback()
            };
        }
        let mut iter = serde_json::Deserializer::from_str(inner).into_iter::<String>();
        match iter.next() {
            Some(Ok(item)) => {
                inner = &inner[iter.byte_offset()..];
                if items.len() >= MAX_STRING_ARRAY_ITEMS {
                    items.push(format!(
                        "…[further items truncated at the {MAX_STRING_ARRAY_ITEMS}-item bound]"
                    ));
                    return items;
                }
                let capped = scrubbed_field(&item);
                total_bytes += capped.len();
                if total_bytes > MAX_STRING_ARRAY_TOTAL_BYTES {
                    items.push(format!(
                        "…[further content truncated at the {MAX_STRING_ARRAY_TOTAL_BYTES}-byte aggregate bound]"
                    ));
                    return items;
                }
                items.push(capped);
                first = false;
            }
            _ => return fallback(),
        }
    }
}

fn status_mode_as_str(mode: StatusMode) -> &'static str {
    match mode {
        StatusMode::Metadata => "metadata",
        StatusMode::Summary => "summary",
        StatusMode::Full => "full",
    }
}

fn untracked_units_for(mode: StatusMode) -> &'static str {
    match mode {
        StatusMode::Metadata => "not_requested",
        StatusMode::Summary => "collapsed_entries",
        StatusMode::Full => "files",
    }
}

/// Maximum interned synthetic paths (XSEC-08): bounds `PathInterner`
/// memory against hostile caller/store input instead of growing with it.
const MAX_INTERNED_PATHS: usize = 1_048_576;
/// Maximum aggregate bytes across interned synthetic paths.
const MAX_INTERNED_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum bytes of one reconstructed directory full path.
const MAX_FULL_PATH_BYTES: usize = 1024 * 1024;

/// Intern synthetic (non-`directories`) full paths to stable report IDs.
/// Memory is bounded by explicit count/byte caps, never by the directory
/// walk or unbounded caller/store input. One canonical store: the map is
/// the only owner of the raw bytes, so the 64MiB cap bounds the total
/// retained footprint with no duplicated second copy.
struct PathInterner {
    by_bytes: HashMap<Vec<u8>, String>,
    counter: u64,
    /// Monotonic raw-byte total, hence the peak interned footprint;
    /// checked against the caller's `rss_target_bytes` resource gate.
    total_bytes: u64,
}

impl PathInterner {
    fn new() -> Self {
        Self {
            by_bytes: HashMap::new(),
            counter: 0,
            total_bytes: 0,
        }
    }

    fn intern(&mut self, bytes: &[u8]) -> crate::Result<String> {
        if let Some(id) = self.by_bytes.get(bytes) {
            return Ok(id.clone());
        }
        if self.by_bytes.len() >= MAX_INTERNED_PATHS {
            return Err(Error::Report(format!(
                "interned path count exceeds the {MAX_INTERNED_PATHS} bound; refusing"
            )));
        }
        if self.total_bytes + bytes.len() as u64 > MAX_INTERNED_BYTES {
            return Err(Error::Report(format!(
                "interned path bytes exceed the {MAX_INTERNED_BYTES}-byte bound; refusing"
            )));
        }
        let id = format!("path-x{}", self.counter);
        self.counter += 1;
        self.total_bytes += bytes.len() as u64;
        self.by_bytes.insert(bytes.to_vec(), id.clone());
        Ok(id)
    }
}

/// Maximum aggregate retained bytes across the directory full-path
/// cache (RESOURCE-RECHECK item 7): together with [`PATH_CACHE_CAP`]
/// (entry count) this bounds total retention — the cache never holds
/// more than `PATH_CACHE_CAP` entries nor more than
/// `MAX_FULL_PATH_CACHE_BYTES` bytes, whichever binds first. Single
/// values over [`MAX_FULL_PATH_BYTES`] are refused before retention.
const MAX_FULL_PATH_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// Bounded cache of reconstructed directory full paths.
///
/// Retention bound: at most `PATH_CACHE_CAP` entries and at most
/// `MAX_FULL_PATH_CACHE_BYTES` aggregate bytes; the cache is cleared
/// and rebuilt when either bound would be exceeded, so correctness never
/// depends on it. Values longer than `MAX_FULL_PATH_BYTES` are refused
/// *before* retention (never stored): the per-path error is still raised
/// by `resolve_full_path` after reconstruction, but the oversize bytes
/// are never cached.
pub struct FullPathCache {
    map: HashMap<i64, Vec<u8>>,
    total_bytes: usize,
}

impl FullPathCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            total_bytes: 0,
        }
    }

    pub fn get(&self, key: &i64) -> Option<&Vec<u8>> {
        self.map.get(key)
    }

    /// Number of retained entries (bounded by `PATH_CACHE_CAP`).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Aggregate retained bytes (bounded by `MAX_FULL_PATH_CACHE_BYTES`).
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Insert a reconstructed path, enforcing the retention bounds before
    /// storing: overlong values (`> MAX_FULL_PATH_BYTES`) are dropped
    /// without retention, and the cache is cleared first when the
    /// entry-count or aggregate-byte bound would otherwise be exceeded.
    pub fn insert(&mut self, key: i64, value: Vec<u8>) {
        if value.len() > MAX_FULL_PATH_BYTES {
            return;
        }
        if let Some(old) = self.map.remove(&key) {
            self.total_bytes -= old.len();
        }
        if self.map.len() >= PATH_CACHE_CAP
            || self.total_bytes + value.len() > MAX_FULL_PATH_CACHE_BYTES
        {
            self.map.clear();
            self.total_bytes = 0;
        }
        self.total_bytes += value.len();
        self.map.insert(key, value);
    }
}

impl Default for FullPathCache {
    fn default() -> Self {
        Self::new()
    }
}

fn push_component(full: &mut Vec<u8>, component: &[u8]) {
    if !full.is_empty() && !full.ends_with(b"/") {
        full.push(b'/');
    }
    full.extend_from_slice(component);
}

/// Reconstruct a directory's full path bytes by walking `parent_id` links.
/// Bounded by [`MAX_PATH_DEPTH`] with cycle detection plus a
/// [`MAX_FULL_PATH_BYTES`] per-path byte cap (XSEC-08); a bounded
/// [`FullPathCache`] amortizes clustered lookups, and oversize paths are
/// refused before cache retention. A vanished parent ends the walk
/// (treated as a root boundary); under the publication barrier this
/// cannot happen.
async fn resolve_full_path(
    conn: &turso::Connection,
    dir_id: i64,
    cache: &mut FullPathCache,
) -> crate::Result<Vec<u8>> {
    let full = resolve_full_path_inner(conn, dir_id, cache).await?;
    if full.len() > MAX_FULL_PATH_BYTES {
        return Err(Error::Report(format!(
            "directory {dir_id} full path exceeds the {MAX_FULL_PATH_BYTES}-byte bound"
        )));
    }
    Ok(full)
}

async fn resolve_full_path_inner(
    conn: &turso::Connection,
    dir_id: i64,
    cache: &mut FullPathCache,
) -> crate::Result<Vec<u8>> {
    if let Some(hit) = cache.get(&dir_id) {
        return Ok(hit.clone());
    }
    let mut visited = HashSet::new();
    let mut suffix: Vec<Vec<u8>> = Vec::new();
    let mut current = dir_id;
    loop {
        if let Some(prefix) = cache.get(&current) {
            let mut full = prefix.clone();
            for component in suffix.iter().rev() {
                push_component(&mut full, component);
            }
            cache.insert(dir_id, full.clone());
            return Ok(full);
        }
        if !visited.insert(current) {
            return Err(Error::Report(format!(
                "directory {dir_id} has a parent cycle"
            )));
        }
        if visited.len() > MAX_PATH_DEPTH {
            return Err(Error::Report(format!(
                "directory {dir_id} exceeds the {MAX_PATH_DEPTH}-level parent depth cap"
            )));
        }
        let mut rows = conn
            .query(
                "SELECT parent_id, component FROM directories WHERE id = ?1",
                vec![turso::Value::Integer(current)],
            )
            .await
            .map_err(store_err)?;
        let row = rows.next().await.map_err(store_err)?;
        match row {
            None => {
                // Vanished mid-stream: end the walk here (barrier violation
                // tolerance, never a silent wrong path).
                let mut full = Vec::new();
                for component in suffix.iter().rev() {
                    push_component(&mut full, component);
                }
                cache.insert(dir_id, full.clone());
                return Ok(full);
            }
            Some(row) => {
                let parent = opt_i64(&row, 0)?;
                let component = req_blob(&row, 1)?;
                match parent {
                    Some(parent_id) => {
                        suffix.push(component);
                        current = parent_id;
                    }
                    None => {
                        let mut full = component;
                        for component in suffix.iter().rev() {
                            push_component(&mut full, component);
                        }
                        cache.insert(dir_id, full.clone());
                        return Ok(full);
                    }
                }
            }
        }
    }
}

async fn row_exists(
    conn: &turso::Connection,
    sql: &str,
    param: turso::Value,
) -> crate::Result<bool> {
    let mut rows = conn.query(sql, vec![param]).await.map_err(store_err)?;
    Ok(rows.next().await.map_err(store_err)?.is_some())
}

/// Pre-pass state: small maps keyed by repository/checkout plus the path
/// interner. Built before any JSON is written so header coverage counts and
/// the `paths` array (which precedes the sections that discover synthetic
/// paths) are complete.
struct PrePass {
    included_repos: HashSet<String>,
    included_groups: HashSet<String>,
    /// Explicit roots carried by this snapshot; `None` means machine scope.
    scope_roots: Option<Vec<PathBuf>>,
    /// Canonical roots used only to identify this request's derivation gap.
    scope_identity_roots: Option<Vec<PathBuf>>,
    unresolvable_repo: bool,
    checkout_repos: HashMap<String, String>,
    statuses: HashMap<String, Status>,
    /// Latest `--fetch` attempt per (store id, remote name bytes),
    /// scoped to emitted repositories (report 1.2.0).
    refreshes: HashMap<(String, Vec<u8>), RemoteRefresh>,
    included_volumes: HashSet<String>,
    scope_volumes: HashSet<String>,
    stub_volumes: Vec<String>,
    interner: PathInterner,
    open_errors: u64,
    tasks_pending: u64,
}

// ---------------------------------------------------------------------------
// SLICE-4 SHIM: scope-path identity helpers (B11 `config::*` shape).
// The shared helpers belong to `crate::config` / `crate::walk::topology`
// (`bounded_canonicalize`), owned by other slices; `store::catalog` carries
// the same SLICE-1 SHIM copies. Once the config/walk slice lands them,
// delete this block and call the shared functions. Until then these private
// copies keep the same fail-closed contract without touching files owned by
// other slices.
// ---------------------------------------------------------------------------

/// Normalize a scope path without consulting the filesystem (lexical
/// `.`/`..` collapse). Deterministic fallback of
/// [`try_canonical_scope_path`]; symlinks remain distinct under it.
/// Ported from B11 `config::normalize_scope_path` (see the SLICE-4 SHIM
/// note above).
fn normalize_scope_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    let mut rooted = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => {
                rooted = true;
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(
                    normalized.components().next_back(),
                    Some(Component::Normal(_))
                ) {
                    normalized.pop();
                } else if !rooted {
                    normalized.push("..");
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}

/// Report-local identity-I/O budget (mirrors the coordinator's
/// `IDENTITY_IO_*` bounds in `walk::topology` and the store's
/// `STORE_IDENTITY_IO_*` shim in `store::catalog`): at most 2 concurrent
/// resolves, a 1 s wait for a slot, and a 1 s timeout per resolve. Past
/// either bound the resolve fails unknown (`None`) and the caller fails
/// closed — the report lane never blocks indefinitely on a hung path.
const REPORT_IDENTITY_IO_CAP: usize = 2;
/// How long a resolve waits for an identity-I/O slot before failing unknown.
const REPORT_IDENTITY_IO_SLOT_WAIT: std::time::Duration = std::time::Duration::from_secs(1);
/// Timeout for one bounded identity resolve on its worker thread.
const REPORT_IDENTITY_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Live report identity-I/O workers (process-wide).
static REPORT_IDENTITY_IO_LIVE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Run blocking identity I/O (`canonicalize`) on a worker thread with
/// bounded admission plus a timeout. `None` means the slot wait expired,
/// the worker timed out, or the spawn failed: the caller must treat the
/// identity as unknown and fail closed. Same contract as the coordinator's
/// worker in `walk::topology`; duplicated report-locally only until the
/// shared helper lands (see SLICE-4 SHIM note above).
fn report_bounded_identity_io<T>(op: impl FnOnce() -> T + Send + 'static) -> Option<T>
where
    T: Send + 'static,
{
    use std::sync::atomic::Ordering;

    let start = std::time::Instant::now();
    let admitted = loop {
        let live = REPORT_IDENTITY_IO_LIVE.load(Ordering::Relaxed);
        if live < REPORT_IDENTITY_IO_CAP
            && REPORT_IDENTITY_IO_LIVE
                .compare_exchange_weak(live, live + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            break true;
        }
        if start.elapsed() >= REPORT_IDENTITY_IO_SLOT_WAIT {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    };
    if !admitted {
        return None;
    }
    struct SlotGuard;
    impl Drop for SlotGuard {
        fn drop(&mut self) {
            REPORT_IDENTITY_IO_LIVE.fetch_sub(1, Ordering::Relaxed);
        }
    }
    // The permit is owned by the detached worker, not the caller: the
    // live count covers the worker's full blocked lifetime, and
    // `recv_timeout` abandons only the wait.
    let (tx, rx) = std::sync::mpsc::channel();
    if std::thread::Builder::new()
        .name(String::from("report-identity-io"))
        .spawn({
            let guard = SlotGuard;
            move || {
                let _held = guard;
                let _ = tx.send(op());
            }
        })
        .is_err()
    {
        return None;
    }
    rx.recv_timeout(REPORT_IDENTITY_IO_TIMEOUT).ok()
}

/// Bounded form of scope-path canonicalization (B11
/// `config::try_canonical_scope_path` shape): absolute paths resolve
/// through a bounded identity-I/O worker (`canonicalize`, so symlink
/// spellings collapse onto the physical path); relative paths keep their
/// lexical spelling; a missing path falls back to the normalized lexical
/// spelling (a missing path has no live alias to fan out). `None` means
/// the identity could not be resolved within the admission/timeout
/// limits — callers must treat the alias as unverified.
fn try_canonical_scope_path(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return Some(path.to_path_buf());
    }
    let owned = path.to_path_buf();
    match report_bounded_identity_io(move || {
        std::fs::canonicalize(&owned).map_err(|error| error.kind())
    }) {
        Some(Ok(canonical)) => Some(canonical),
        // A missing path has no live alias to fan out, so its normalized
        // lexical spelling is a safe fallback. Other resolution failures
        // and worker timeouts are unknown identities and fail closed.
        Some(Err(std::io::ErrorKind::NotFound)) => Some(normalize_scope_path(path)),
        Some(Err(_)) | None => None,
    }
}

/// True when `path` is lexically at or below one of the explicit roots.
/// Both sides normalize `.`/`..` without filesystem access, so this is
/// safe for report filtering and remains component-boundary aware.
/// Ported from B11 `config::path_is_within_roots` (SLICE-4 SHIM).
fn path_is_within_roots(path: &Path, roots: &[PathBuf]) -> bool {
    let path = normalize_scope_path(path);
    roots
        .iter()
        .any(|root| path.starts_with(normalize_scope_path(root)))
}

/// Stable identity for report-derivation gaps attached to an explicit
/// root set. Paths are normalized lexically, sorted, and deduplicated so
/// root order does not create duplicate gap families. Ported from B11
/// `config::report_derivation_gap_scope_key` (SLICE-4 SHIM).
fn report_derivation_gap_scope_key(roots: Option<&[PathBuf]>) -> String {
    let Some(roots) = roots else {
        return String::from("gap:report-derivation");
    };
    use sha2::Digest;
    let mut paths: Vec<Vec<u8>> = roots
        .iter()
        .map(|root| crate::config::path_as_bytes(&normalize_scope_path(root)))
        .collect();
    paths.sort();
    paths.dedup();
    let mut hasher = sha2::Sha256::new();
    for path in paths {
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path);
    }
    format!(
        "gap:report-derivation:roots:{}",
        crate::config::encode_hex(&hasher.finalize())
    )
}

fn report_path_in_roots(path_bytes: &[u8], roots: &[PathBuf]) -> bool {
    let path = crate::config::path_from_bytes(path_bytes.to_vec());
    path_is_within_roots(&path, roots)
}

/// Extend an explicit report scope with a currently observed root alias.
/// Alias records are report evidence, but only a same-object edge that
/// touches an exact requested/identity root can extend scope. Re-resolve
/// both endpoints through the bounded canonicalizer before trusting the
/// persisted counterpart path; this rejects stale aliases and never
/// promotes a nested symlink target into the whole report scope.
fn extend_roots_with_verified_aliases(roots: &mut Vec<PathBuf>, aliases: &[AliasInput]) {
    let anchors: HashSet<PathBuf> = roots
        .iter()
        .map(|root| normalize_scope_path(root))
        .collect();
    for alias in aliases {
        if alias.kind != "same_object" {
            continue;
        }
        let path = crate::config::path_from_bytes(alias.path_bytes.clone());
        let target = crate::config::path_from_bytes(alias.target_path_bytes.clone());
        let path_key = normalize_scope_path(&path);
        let target_key = normalize_scope_path(&target);
        let counterpart = if anchors.contains(&path_key) {
            &target
        } else if anchors.contains(&target_key) {
            &path
        } else {
            continue;
        };
        let (Some(path_identity), Some(target_identity)) = (
            try_canonical_scope_path(&path),
            try_canonical_scope_path(&target),
        ) else {
            continue;
        };
        if path_identity != target_identity {
            continue;
        }
        let counterpart_key = normalize_scope_path(counterpart);
        if !roots
            .iter()
            .any(|root| normalize_scope_path(root) == counterpart_key)
        {
            roots.push(counterpart.clone());
        }
    }
}

fn report_error_in_scope(
    scope_key: &str,
    roots: Option<&[PathBuf]>,
    identity_roots: Option<&[PathBuf]>,
    checkouts: &HashMap<String, String>,
    volumes: &HashSet<String>,
) -> bool {
    let Some(roots) = roots else {
        return true;
    };
    match crate::config::parse_scope_key(scope_key) {
        Some(crate::config::ScopeRef::Dir(path) | crate::config::ScopeRef::Git(path)) => {
            path_is_within_roots(&path, roots)
        }
        Some(crate::config::ScopeRef::Status(checkout_id)) => checkouts.contains_key(&checkout_id),
        None => {
            scope_key == report_derivation_gap_scope_key(identity_roots.or(Some(roots)))
                || scope_key
                    .strip_prefix("volume:")
                    .is_some_and(|id| volumes.contains(id))
        }
    }
}

/// Return volume IDs represented by directory rows under the supplied roots.
/// The synthetic `explicit-roots` volume is deliberately not inferred here:
/// it represents the whole request and cannot safely attribute a volume event
/// to one root.
pub async fn volume_ids_within_roots(
    conn: &turso::Connection,
    roots: &[PathBuf],
) -> crate::Result<HashSet<String>> {
    let mut rows = conn
        .query("SELECT id, volume_id FROM directories ORDER BY id ASC", ())
        .await
        .map_err(store_err)?;
    let mut cache = FullPathCache::new();
    let mut volumes = HashSet::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        let dir_id = req_i64(&row, 0)?;
        let full = resolve_full_path(conn, dir_id, &mut cache).await?;
        if report_path_in_roots(&full, roots) {
            let volume = req_text(&row, 1)?;
            if volume != "explicit-roots" {
                volumes.insert(volume);
            }
        }
    }
    Ok(volumes)
}

async fn pre_pass(conn: &turso::Connection, inputs: &ReportInputs) -> crate::Result<PrePass> {
    let (mut scope_roots, scope_identity_roots) = if inputs.scope == "roots" {
        let mut roots = Vec::with_capacity(inputs.roots.len().saturating_mul(2));
        let mut identities = Vec::with_capacity(inputs.roots.len());
        let mut cache = FullPathCache::new();
        for root in &inputs.roots {
            let bytes = match (&root.dir_id, &root.path_bytes) {
                (Some(dir_id), None) => resolve_full_path(conn, *dir_id, &mut cache).await?,
                (None, Some(bytes)) => bytes.clone(),
                _ => {
                    return Err(Error::Report(format!(
                        "root {} must set exactly one of dir_id or path_bytes",
                        root.id
                    )))
                }
            };
            let requested = crate::config::path_from_bytes(bytes);
            // SLICE-4 SHIM: B11 carries the caller-resolved canonical
            // identity on `RootInput::scope_path_bytes`; that field is a
            // slice-5 wiring item (main.rs owns the call site), so the
            // builder resolves the same identity through the bounded
            // canonicalizer here. Unresolvable identity keeps the
            // requested spelling (lexical scoping stays honest).
            let identity =
                try_canonical_scope_path(&requested).unwrap_or_else(|| requested.clone());
            if !roots.contains(&requested) {
                roots.push(requested);
            }
            if !roots.contains(&identity) {
                roots.push(identity.clone());
            }
            identities.push(identity);
        }
        (Some(roots), Some(identities))
    } else {
        (None, None)
    };
    if let Some(roots) = scope_roots.as_mut() {
        extend_roots_with_verified_aliases(roots, &inputs.aliases);
    }
    let mut known_volumes = HashSet::new();
    {
        let mut rows = conn
            .query("SELECT id FROM volumes", ())
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            known_volumes.insert(req_text(&row, 0)?);
        }
    }
    let mut referenced_volumes = HashSet::new();
    if let Some(roots) = &scope_roots {
        let mut rows = conn
            .query("SELECT id, volume_id FROM directories ORDER BY id ASC", ())
            .await
            .map_err(store_err)?;
        let mut cache = FullPathCache::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let dir_id = req_i64(&row, 0)?;
            let full = resolve_full_path(conn, dir_id, &mut cache).await?;
            if report_path_in_roots(&full, roots) {
                referenced_volumes.insert(req_text(&row, 1)?);
            }
        }
        referenced_volumes.extend(
            inputs
                .roots
                .iter()
                .filter_map(|root| root.volume_id.clone()),
        );
    } else {
        let mut rows = conn
            .query("SELECT DISTINCT volume_id FROM directories", ())
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            referenced_volumes.insert(req_text(&row, 0)?);
        }
    }
    let included_volumes: HashSet<String> = known_volumes
        .intersection(&referenced_volumes)
        .cloned()
        .collect();
    let mut stub_volumes: Vec<String> = referenced_volumes
        .difference(&known_volumes)
        .cloned()
        .collect();
    stub_volumes.sort();
    let scope_volumes: HashSet<String> = referenced_volumes
        .iter()
        .filter(|id| id.as_str() != "explicit-roots")
        .cloned()
        .collect();
    // SLICE-4 SHIM: B11 additionally extends `scope_volumes` with
    // caller-supplied event-monitor volume identities
    // (`ReportInputs::event_volume_ids`); that field is a slice-5 wiring
    // item, so `volume:<id>` errors are scoped by catalog-derived volume
    // membership only.

    // Checkout paths are needed to recognize worktrees whose Git metadata
    // lives outside the requested roots. Keep only the owning store IDs,
    // then reload and intern just those checkout rows after repo filtering.
    let mut in_scope_checkout_repos = HashSet::new();
    if let Some(roots) = &scope_roots {
        let mut rows = conn
            .query(
                "SELECT instance_id, root_path, git_path FROM checkouts ORDER BY id ASC",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let instance_id = req_text(&row, 0)?;
            let path = opt_blob(&row, 1)?.unwrap_or(req_blob(&row, 2)?);
            if report_path_in_roots(&path, roots) {
                in_scope_checkout_repos.insert(instance_id);
            }
        }
    }

    let mut included_repos = HashSet::new();
    let mut unresolvable_repo = false;
    let mut interner = PathInterner::new();
    {
        let mut rows = conn
            .query(
                "SELECT id, git_path, common_path, disposition FROM git_instances ORDER BY id ASC",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let id = req_text(&row, 0)?;
            let git_path = req_blob(&row, 1)?;
            let common_path = req_blob(&row, 2)?;
            let disposition = req_text(&row, 3)?;
            let included = inputs.include_nonmatching || disposition != "nonmatch";
            let in_scope = scope_roots.as_ref().is_none_or(|roots| {
                report_path_in_roots(&git_path, roots) || in_scope_checkout_repos.contains(&id)
            });
            if !included || !in_scope {
                continue;
            }
            if disposition == "unresolvable_identity" {
                unresolvable_repo = true;
            }
            interner.intern(&git_path)?;
            interner.intern(&common_path)?;
            included_repos.insert(id);
        }
    }

    let mut checkout_repos = HashMap::new();
    {
        let mut rows = conn
            .query(
                "SELECT id, instance_id, root_path, git_path FROM checkouts ORDER BY id ASC",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let id = req_text(&row, 0)?;
            let instance_id = req_text(&row, 1)?;
            if !included_repos.contains(&instance_id) {
                continue;
            }
            if let Some(root_path) = opt_blob(&row, 2)? {
                interner.intern(&root_path)?;
            }
            interner.intern(&req_blob(&row, 3)?)?;
            checkout_repos.insert(id, instance_id);
        }
    }

    let mut included_groups = HashSet::new();
    {
        let mut rows = conn
            .query(
                "SELECT group_id, instance_id FROM group_members ORDER BY group_id ASC",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            if included_repos.contains(&req_text(&row, 1)?) {
                included_groups.insert(req_text(&row, 0)?);
            }
        }
    }

    let mut statuses = HashMap::new();
    {
        let mut rows = conn
            .query(
                "SELECT checkout_id, mode, state, started_ms, finished_ms, staged, \
                    unstaged, untracked, untracked_units, submodules, unknown_fields, \
                    observed_rev, conflicts, working_state FROM status_observations \
                    ORDER BY checkout_id ASC, observed_rev DESC",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let checkout_id = req_text(&row, 0)?;
            if statuses.contains_key(&checkout_id) {
                continue; // Older revision; newest-first ordering.
            }
            if !checkout_repos.contains_key(&checkout_id) {
                continue; // Scoped to emitted checkouts.
            }
            statuses.insert(
                checkout_id,
                Status {
                    state: req_text(&row, 2)?,
                    mode: req_text(&row, 1)?,
                    started_at: opt_i64(&row, 3)?.map(ms_to_rfc3339),
                    finished_at: opt_i64(&row, 4)?.map(ms_to_rfc3339),
                    staged: opt_i64(&row, 5)?.map(|v| v.max(0) as u64),
                    unstaged: opt_i64(&row, 6)?.map(|v| v.max(0) as u64),
                    untracked: opt_i64(&row, 7)?.map(|v| v.max(0) as u64),
                    conflicts: opt_i64(&row, 12)?.map(|v| v.max(0) as u64),
                    // Report 1.3.0: NULL (legacy pre-v5 rows) reads
                    // `unknown`, never a guessed state.
                    working_state: opt_text(&row, 13)?.unwrap_or_else(|| "unknown".to_string()),
                    untracked_units: req_text(&row, 8)?,
                    submodules: req_text(&row, 9)?,
                    unknown_fields: parse_string_array(&req_text(&row, 10)?),
                    error_ids: Vec::new(),
                },
            );
        }
    }

    // Intern caller-owned paths and verify caller-owned references before
    // any JSON is written, so dangling caller input fails loudly.
    for root in &inputs.roots {
        match (&root.dir_id, &root.path_bytes) {
            (Some(dir_id), None) => {
                if !row_exists(
                    conn,
                    "SELECT 1 FROM directories WHERE id = ?1",
                    turso::Value::Integer(*dir_id),
                )
                .await?
                {
                    return Err(Error::Report(format!(
                        "root {} references missing directory {dir_id}",
                        root.id
                    )));
                }
            }
            (None, Some(bytes)) => {
                interner.intern(bytes)?;
            }
            _ => {
                return Err(Error::Report(format!(
                    "root {} must set exactly one of dir_id or path_bytes",
                    root.id
                )));
            }
        }
        if let Some(volume_id) = &root.volume_id {
            if !known_volumes.contains(volume_id) {
                return Err(Error::Report(format!(
                    "root {} references missing volume {volume_id:?}",
                    root.id
                )));
            }
        }
        verify_error_ids(conn, &root.error_ids, &format!("root {}", root.id)).await?;
    }
    for candidate in &inputs.candidates {
        interner.intern(&candidate.path_bytes)?;
        if let Some(repository_id) = &candidate.repository_id {
            if !included_repos.contains(repository_id) {
                return Err(Error::Report(format!(
                    "candidate {} references repository {repository_id:?} \
                     which is not in this report",
                    candidate.id
                )));
            }
        }
        verify_error_ids(
            conn,
            &candidate.error_ids,
            &format!("candidate {}", candidate.id),
        )
        .await?;
    }
    for link in &inputs.storage_links {
        interner.intern(&link.to_path_bytes)?;
        if !included_repos.contains(&link.from_repository_id) {
            return Err(Error::Report(format!(
                "storage link {} references repository {:?} which is not in this report",
                link.id, link.from_repository_id
            )));
        }
    }
    for alias in &inputs.aliases {
        interner.intern(&alias.path_bytes)?;
        interner.intern(&alias.target_path_bytes)?;
    }
    for artifact in &inputs.generated_artifacts {
        interner.intern(&artifact.path_bytes)?;
    }

    let open_errors = {
        let mut rows = conn
            .query("SELECT scope_key FROM errors WHERE open = 1", ())
            .await
            .map_err(store_err)?;
        let mut count = 0u64;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            if report_error_in_scope(
                &req_text(&row, 0)?,
                scope_roots.as_deref(),
                scope_identity_roots.as_deref(),
                &checkout_repos,
                &scope_volumes,
            ) {
                count += 1;
            }
        }
        count
    };

    // RSP-008: pending/leased work is counted in this same read
    // transaction, never trusted from `inputs.tasks_pending`. Generation
    // scoped like `pending_count` so a force-rescan run cannot launder
    // another generation's completeness.
    let tasks_pending = {
        let generation_i64 = i64::try_from(inputs.generation).map_err(|_| {
            Error::Store(format!(
                "task generation {} exceeds i64 range",
                inputs.generation
            ))
        })?;
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM frontier_tasks WHERE generation = ?1 \
                    AND state IN ('pending', 'leased')",
                vec![turso::Value::Integer(generation_i64)],
            )
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            Some(row) => req_i64(&row, 0)?.max(0) as u64,
            None => 0,
        }
    };

    // Latest `--fetch` attempt per store + remote name (report
    // 1.2.0), scoped to emitted repositories like `statuses`.
    let mut refreshes = HashMap::new();
    {
        let mut rows = conn
            .query(
                "SELECT store_id, remote_name, status, observed_at_ms, duration_ms, \
                    refs_updated FROM remote_refreshes",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let store_id = req_text(&row, 0)?;
            if !included_repos.contains(&store_id) {
                continue;
            }
            let remote_name = req_blob(&row, 1)?;
            refreshes.insert(
                (store_id, remote_name),
                RemoteRefresh {
                    status: req_text(&row, 2)?,
                    observed_at: ms_to_rfc3339(req_i64(&row, 3)?),
                    duration_ms: opt_i64(&row, 4)?,
                    refs_updated: req_i64(&row, 5)?.max(0) as u64,
                },
            );
        }
    }

    // Resource gate: the interned-path peak is real report memory;
    // refuse loudly when it already exceeds the caller's RSS target
    // instead of streaming a report built over budget.
    if interner.total_bytes > inputs.rss_target_bytes {
        return Err(Error::Report(format!(
            "interned path peak {} bytes exceeds the rss_target_bytes {} resource gate; refusing",
            interner.total_bytes, inputs.rss_target_bytes
        )));
    }

    Ok(PrePass {
        included_repos,
        included_groups,
        scope_roots,
        scope_identity_roots,
        unresolvable_repo,
        checkout_repos,
        statuses,
        refreshes,
        included_volumes,
        scope_volumes,
        stub_volumes,
        interner,
        open_errors,
        tasks_pending,
    })
}

async fn verify_error_ids(
    conn: &turso::Connection,
    ids: &[String],
    context: &str,
) -> crate::Result<()> {
    for id in ids {
        if !row_exists(
            conn,
            "SELECT 1 FROM errors WHERE id = ?1",
            turso::Value::Text(id.clone()),
        )
        .await?
        {
            return Err(Error::Report(format!(
                "{context} references missing error {id:?}"
            )));
        }
    }
    Ok(())
}

fn default_status(mode: StatusMode) -> Status {
    let (state, submodules, working_state) = match mode {
        StatusMode::Metadata => ("not_requested", "not_requested", "unknown"),
        _ => ("pending", "unknown", "pending"),
    };
    Status {
        state: state.to_string(),
        mode: status_mode_as_str(mode).to_string(),
        started_at: None,
        finished_at: None,
        staged: None,
        unstaged: None,
        untracked: None,
        conflicts: None,
        working_state: working_state.to_string(),
        untracked_units: untracked_units_for(mode).to_string(),
        submodules: submodules.to_string(),
        unknown_fields: Vec::new(),
        error_ids: Vec::new(),
    }
}

fn object_id_from_parts(raw: Option<Vec<u8>>, algo: Option<String>) -> Option<ObjectId> {
    raw.map(|bytes| {
        let hex = oid_hex_from_bytes(&bytes);
        let algorithm = algo.unwrap_or_else(|| guess_oid_algorithm(&hex).to_string());
        ObjectId { algorithm, hex }
    })
}

fn operation_for_scope(scope_key: &str) -> &str {
    if scope_key.starts_with("dir:") {
        "enumerate_dir"
    } else if scope_key.starts_with("probe:") {
        "probe_git"
    } else if scope_key.starts_with("status:") {
        "status"
    } else if scope_key.starts_with("reconcile:") {
        "reconcile"
    } else if scope_key.starts_with("vol:") {
        "mount_validate"
    } else if scope_key.starts_with("gap:") {
        "scheduler"
    } else {
        "unknown"
    }
}

/// Committed catalog revision read through the report reader connection
/// (the same `meta.committed_revision` cell `TursoStore::current_revision`
/// reports; absent means a fresh catalog at revision 0).
async fn reader_revision(reader: &turso::Connection) -> crate::Result<u64> {
    let mut rows = reader
        .query(
            "SELECT value FROM meta WHERE name = ?1",
            vec![turso::Value::Text("committed_revision".to_string())],
        )
        .await
        .map_err(store_err)?;
    let row = rows.next().await.map_err(store_err)?;
    match row {
        None => Ok(0),
        Some(row) => {
            let raw = req_text(&row, 0)?;
            let value: i64 = raw.parse().map_err(|_| {
                Error::Store(format!(
                    "catalog meta \"committed_revision\" is not a number: {raw:?}"
                ))
            })?;
            u64::try_from(value).map_err(|_| {
                Error::Store(format!(
                    "catalog meta \"committed_revision\" is negative: {value}"
                ))
            })
        }
    }
}

/// Stream one consistent report from the catalog to `writer` (normally a
/// controlled staging file). The caller holds the publication barrier so
/// no writer commits while streaming; this function additionally opens an
/// explicit read transaction around the pre-pass and the stream and
/// verifies the committed revision did not advance across them (RSP-009),
/// so counts, statuses, evidence, and coverage always describe a single
/// catalog revision. The envelope reports the observed stable revision.
/// The dedicated reader is released before this returns; publication to an
/// external destination must only happen afterwards (spec §15).
pub async fn stream_report_from_store<W: Write>(
    store: &crate::store::TursoStore,
    inputs: &ReportInputs,
    writer: W,
) -> crate::Result<(W, StreamStats)> {
    let reader = store.open_reader().await?;
    reader.execute("BEGIN", ()).await.map_err(store_err)?;
    let outcome: crate::Result<(W, StreamStats)> = async {
        let observed = reader_revision(&reader).await?;
        let pre = pre_pass(&reader, inputs).await?;
        let (writer, stats) =
            stream_with_pre_pass(&reader, inputs, &pre, observed, writer).await?;
        let after = reader_revision(&reader).await?;
        if after != observed {
            Err(Error::Report(format!(
                "catalog revision advanced during report streaming ({observed} -> {after}); refusing an inconsistent report"
            )))
        } else {
            Ok((writer, stats))
        }
    }
    .await;
    let _ = reader.execute("ROLLBACK", ()).await;
    drop(reader);
    outcome
}

async fn stream_with_pre_pass<W: Write>(
    reader: &turso::Connection,
    inputs: &ReportInputs,
    pre: &PrePass,
    catalog_revision: u64,
    writer: W,
) -> crate::Result<(W, StreamStats)> {
    let mut stats = StreamStats::default();
    let mut totals = Totals {
        bare_stores: Some(0),
        ..Totals::default()
    };
    let unresolvable_candidates = inputs
        .candidates
        .iter()
        .filter(|c| c.disposition == "unresolvable_identity")
        .count() as u64;

    // Coverage is derived from store/task facts observed in this
    // transaction, never trusted from the caller (RSP-008): a supplied
    // override that contradicts the derived value is refused loudly
    // instead of laundering a false completeness claim into the report.
    // `inputs.tasks_pending` is ignored by design; `pre.tasks_pending`
    // is the in-transaction pending/leased count for this generation.
    let derived_filesystem = if pre.tasks_pending > 0 || pre.open_errors > 0 {
        "incomplete".to_string()
    } else {
        "complete".to_string()
    };
    if let Some(claimed) = &inputs.coverage_filesystem {
        if claimed != &derived_filesystem {
            return Err(Error::Report(format!(
                "coverage_filesystem override {claimed:?} contradicts scan state \
                 (tasks_pending={}, open_errors={})",
                pre.tasks_pending, pre.open_errors
            )));
        }
    }
    let derived_identity = if unresolvable_candidates > 0 || pre.unresolvable_repo {
        "unproven".to_string()
    } else {
        "complete_under_policy".to_string()
    };
    if let Some(claimed) = &inputs.coverage_identity {
        if claimed != &derived_identity {
            return Err(Error::Report(format!(
                "coverage_identity override {claimed:?} contradicts scan state \
                 (unresolvable_candidates={unresolvable_candidates}, unresolvable_repo={})",
                pre.unresolvable_repo
            )));
        }
    }
    let derived_status = if inputs.status_mode == StatusMode::Metadata {
        "not_requested".to_string()
    } else if pre
        .checkout_repos
        .keys()
        .any(|id| pre.statuses.get(id).is_none_or(|s| s.state != "complete"))
    {
        "incomplete".to_string()
    } else {
        "complete".to_string()
    };
    if let Some(claimed) = &inputs.coverage_status {
        if claimed != &derived_status {
            return Err(Error::Report(format!(
                "coverage_status override {claimed:?} contradicts scan state (derived {derived_status:?})"
            )));
        }
    }
    let coverage = Coverage {
        filesystem: derived_filesystem,
        identity: derived_identity,
        status: derived_status,
        directories_complete: inputs.directories_complete,
        tasks_pending: pre.tasks_pending,
        gaps: pre.open_errors,
        unresolvable_candidates,
        scope_boundaries: inputs.scope_boundaries.clone(),
    };
    let scan = Scan {
        id: inputs.scan_id.clone(),
        generation: inputs.generation,
        epoch: inputs.epoch,
        catalog_revision,
        target_url: redact_remote_url(&inputs.target_url),
        canonical_url: inputs
            .canonical_url
            .as_ref()
            .map(|url| redact_remote_url(url)),
        // SLICE-4 NOTE: B11 additionally wraps these in `scrub_text` for
        // defense-in-depth; that requires the identity slice's scp-form
        // redaction idempotency fix (`scp_remote_redaction_is_idempotent`),
        // otherwise an already-redacted scp-like target double-wraps.
        targets: inputs
            .targets
            .iter()
            .map(|t| ScanTarget {
                raw: redact_remote_url(&t.raw),
                canonical: t.canonical.as_ref().map(|url| redact_remote_url(url)),
                matched_repositories: t.matched_repositories,
            })
            .collect(),
        matching_policy: crate::identity::MATCHING_POLICY.to_string(),
        scope: inputs.scope.clone(),
        state: inputs.scan_state.clone(),
        started_at: ms_to_rfc3339(inputs.started_at_ms),
        finished_at: inputs.finished_at_ms.map(ms_to_rfc3339),
        superseded_by: inputs.superseded_by.clone(),
        cached: inputs.cached,
        status_mode: status_mode_as_str(inputs.status_mode).to_string(),
    };
    let tool = Tool {
        name: crate::report::model::TOOL_NAME.to_string(),
        version: crate::version().to_string(),
        source_commit: build_source_commit().or_else(|| {
            inputs
                .source_commit
                .as_deref()
                .and_then(parse_source_commit)
        }),
    };
    let resources = Resources {
        profile: inputs.profile.clone(),
        cpu_target_cores: inputs.cpu_target_cores,
        rss_target_bytes: inputs.rss_target_bytes,
        peak_rss_bytes: inputs.peak_rss_bytes,
        cpu_seconds: inputs.cpu_seconds,
        enumerated_entries: inputs.enumerated_entries,
        db_transactions: inputs.db_transactions,
        db_sync_calls: inputs.db_sync_calls,
    };

    let mut stream = StreamingWriter::new(writer);
    stream.begin_object()?;
    stream.field(
        "schema_version",
        &crate::report::model::SCHEMA_VERSION.to_string(),
    )?;
    stream.field("report_id", &inputs.report_id)?;
    stream.field("created_at", &ms_to_rfc3339(inputs.created_at_ms))?;
    stream.field("tool", &tool)?;
    stream.field("scan", &scan)?;
    stream.field("coverage", &coverage)?;
    stream.field("resources", &resources)?;

    // Volumes (plus stubs for volumes referenced by directories but absent
    // from the catalog, marked unknown so the reference stays visible).
    stream.begin_array_field("volumes")?;
    {
        let mut rows = reader
            .query(
                "SELECT id, native_identity, namespace, filesystem, kind, state, \
                    observed_at_ms FROM volumes ORDER BY id ASC",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let id = req_text(&row, 0)?;
            if pre.scope_roots.is_some() && !pre.included_volumes.contains(&id) {
                continue;
            }
            stream.array_item(&Volume {
                id,
                native_identity: opt_text(&row, 1)?,
                namespace: req_text(&row, 2)?,
                filesystem: opt_text(&row, 3)?,
                kind: req_text(&row, 4)?,
                state: req_text(&row, 5)?,
                observed_at: opt_i64(&row, 6)?.map(ms_to_rfc3339),
                error_ids: Vec::new(),
            })?;
            stats.volumes += 1;
        }
    }
    for stub in &pre.stub_volumes {
        stream.array_item(&Volume {
            id: stub.clone(),
            native_identity: None,
            namespace: "unknown".to_string(),
            filesystem: None,
            kind: "unknown".to_string(),
            state: "unknown".to_string(),
            observed_at: None,
            error_ids: Vec::new(),
        })?;
        stats.volumes += 1;
        stats.stub_volumes += 1;
    }
    stream.end_array()?;

    // Paths: every directory row (full path reconstructed from
    // parent/component links), then the interned synthetic paths.
    stream.begin_array_field("paths")?;
    {
        let mut cache = FullPathCache::new();
        let mut rows = reader
            .query(
                "SELECT id, volume_id, object_id, incarnation FROM directories ORDER BY id ASC",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let dir_id = req_i64(&row, 0)?;
            let volume_id = req_text(&row, 1)?;
            let full = resolve_full_path(reader, dir_id, &mut cache).await?;
            if pre
                .scope_roots
                .as_ref()
                .is_some_and(|roots| !report_path_in_roots(&full, roots))
            {
                continue;
            }
            let (encoding, value, display) = encode_bytes(&full);
            stream.array_item(&PathRecord {
                id: format!("path-{dir_id}"),
                display,
                encoding,
                value,
                volume_id: Some(volume_id),
                object_id: Some(req_text(&row, 2)?),
                incarnation: Some(req_text(&row, 3)?),
            })?;
            stats.paths += 1;
        }
    }
    // Sort references by report ID: the canonical map is never cloned,
    // so emission holds no second copy of the bounded path bytes.
    let mut synthetics: Vec<(&Vec<u8>, &String)> = pre.interner.by_bytes.iter().collect();
    synthetics.sort_by(|a, b| a.1.cmp(b.1));
    for (bytes, id) in synthetics {
        let (encoding, value, display) = encode_bytes(bytes);
        stream.array_item(&PathRecord {
            id: id.clone(),
            display,
            encoding,
            value,
            volume_id: None,
            object_id: None,
            incarnation: None,
        })?;
        stats.paths += 1;
    }
    stream.end_array()?;

    totals.observed_paths = stats.paths;

    // Caller-owned roots.
    stream.begin_array_field("roots")?;
    for root in &inputs.roots {
        let path_id = match (&root.dir_id, &root.path_bytes) {
            (Some(dir_id), None) => format!("path-{dir_id}"),
            (None, Some(bytes)) => {
                pre.interner.by_bytes.get(bytes).cloned().ok_or_else(|| {
                    Error::Report(format!("root {} path was not interned", root.id))
                })?
            }
            _ => {
                return Err(Error::Report(format!(
                    "root {} must set exactly one of dir_id or path_bytes",
                    root.id
                )))
            }
        };
        stream.array_item(&Root {
            id: root.id.clone(),
            path_id,
            volume_id: root.volume_id.clone(),
            state: root.state.clone(),
            observed_at: root.observed_at_ms.map(ms_to_rfc3339),
            event_history_uuid: root.event_history_uuid.clone(),
            ingested_cursor: root.ingested_cursor.clone(),
            reconciled_cursor: root.reconciled_cursor.clone(),
            error_ids: root.error_ids.clone(),
        })?;
        stats.roots += 1;
    }
    stream.end_array()?;

    // GitHub groups are distinct normalized identities linked through at
    // least one emitted store. The query stays catalog-backed and streams
    // rows in ID order; it does not materialize every group in memory.
    stream.begin_array_field("groups")?;
    {
        let mut rows = reader
            .query(
                "SELECT DISTINCT g.id, g.host, g.account, g.repo \
                    FROM github_groups g \
                    JOIN group_members gm ON gm.group_id = g.id \
                    JOIN git_instances gi ON gi.id = gm.instance_id \
                    WHERE (?1 = 1 OR gi.disposition != 'nonmatch') \
                    ORDER BY g.id ASC",
                vec![turso::Value::Integer(i64::from(inputs.include_nonmatching))],
            )
            .await
            .map_err(store_err)?;
        let mut last_account: Option<(String, String)> = None;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            if !pre.included_groups.contains(&req_text(&row, 0)?) {
                continue;
            }
            let host = req_text(&row, 1)?;
            let account = req_text(&row, 2)?;
            let account_key = (host.clone(), account.clone());
            if last_account.as_ref() != Some(&account_key) {
                stats.accounts += 1;
                last_account = Some(account_key);
            }
            stream.array_item(&Group {
                id: req_text(&row, 0)?,
                host,
                account,
                repo: req_text(&row, 3)?,
            })?;
            stats.groups += 1;
        }
    }
    stream.end_array()?;

    // Repositories (matching scope; nonmatching skipped unless requested).
    let interned = |bytes: &[u8]| -> crate::Result<String> {
        pre.interner.by_bytes.get(bytes).cloned().ok_or_else(|| {
            Error::Report("repository path was not interned in the pre-pass".to_string())
        })
    };
    stream.begin_array_field("repositories")?;
    {
        let mut rows = reader
            .query(
                "SELECT id, git_path, common_path, format, bare, object_format, \
                    disposition, evidence, observed_at_ms FROM git_instances ORDER BY id ASC",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let id = req_text(&row, 0)?;
            if !pre.included_repos.contains(&id) {
                continue;
            }
            let bare = opt_i64(&row, 4)?.map(|flag| flag != 0);
            match bare {
                Some(true) => {
                    if let Some(count) = totals.bare_stores.as_mut() {
                        *count += 1;
                    }
                }
                Some(false) => {}
                None => totals.bare_stores = None,
            }
            stream.array_item(&Repository {
                id,
                git_path_id: interned(&req_blob(&row, 1)?)?,
                common_path_id: interned(&req_blob(&row, 2)?)?,
                bare,
                format: req_text(&row, 3)?,
                object_format: req_text(&row, 5)?,
                match_disposition: req_text(&row, 6)?,
                evidence: parse_string_array(&req_text(&row, 7)?),
                observed_at: ms_to_rfc3339(req_i64(&row, 8)?),
                tool_managed: None,
                error_ids: Vec::new(),
            })?;
            stats.repositories += 1;
        }
    }
    stream.end_array()?;
    totals.stores = stats.repositories;

    // Checkouts with their latest status observation (or an honest
    // pending/not_requested placeholder when none was recorded).
    stream.begin_array_field("checkouts")?;
    {
        let mut rows = reader
            .query(
                "SELECT id, instance_id, root_path, git_path, relationship, availability, \
                    head_state, head_ref, head_oid, head_algo, observed_at_ms \
                    FROM checkouts ORDER BY id ASC",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let id = req_text(&row, 0)?;
            let instance_id = req_text(&row, 1)?;
            if !pre.checkout_repos.contains_key(&id) {
                stats.skipped_orphans += 1;
                continue;
            }
            let root_path_id = match opt_blob(&row, 2)? {
                Some(bytes) => Some(interned(&bytes)?),
                None => None,
            };
            let status = pre
                .statuses
                .get(&id)
                .cloned()
                .unwrap_or_else(|| default_status(inputs.status_mode));
            if req_text(&row, 5)? == "present" {
                totals.present_checkouts += 1;
                if req_text(&row, 4)? == "linked" {
                    totals.linked_worktrees += 1;
                }
            }
            record_analysis_total(&mut totals.analysis, &status.state);
            stream.array_item(&Checkout {
                id,
                repository_id: instance_id,
                root_path_id,
                git_path_id: interned(&req_blob(&row, 3)?)?,
                kind: req_text(&row, 4)?,
                availability: req_text(&row, 5)?,
                head: Head {
                    state: req_text(&row, 6)?,
                    ref_name: opt_blob(&row, 7)?.as_deref().map(encode_name),
                    oid: object_id_from_parts(opt_blob(&row, 8)?, opt_text(&row, 9)?),
                },
                status,
                observed_at: ms_to_rfc3339(req_i64(&row, 10)?),
                error_ids: Vec::new(),
            })?;
            stats.checkouts += 1;
        }
    }
    stream.end_array()?;

    // Branches (refs scoped to emitted repositories and checkouts).
    stream.begin_array_field("branches")?;
    {
        // Report 1.4.0: the v6 comparison columns ride the SELECT
        // when physically present; pre-v6 catalogs emit
        // `pending`/null (same legacy read as pre-1.4 snapshots).
        let v6 = crate::store::catalog::refs_has_comparison(reader).await?;
        let sql = if v6 {
            "SELECT id, instance_id, checkout_scope_id, kind, name, oid, algo, \
                symbolic_target, upstream, state, observed_at_ms, freshness, \
                freshness_at_ms, comparison_state, ahead, behind \
                FROM refs ORDER BY id ASC"
        } else {
            "SELECT id, instance_id, checkout_scope_id, kind, name, oid, algo, \
                symbolic_target, upstream, state, observed_at_ms, freshness, \
                freshness_at_ms \
                FROM refs ORDER BY id ASC"
        };
        let mut rows = reader.query(sql, ()).await.map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let instance_id = req_text(&row, 1)?;
            if !pre.included_repos.contains(&instance_id) {
                stats.skipped_orphans += 1;
                continue;
            }
            let checkout_scope = opt_text(&row, 2)?;
            if pre.scope_roots.is_some()
                && checkout_scope
                    .as_ref()
                    .is_some_and(|id| !pre.checkout_repos.contains_key(id))
            {
                continue;
            }
            let scope = checkout_scope.filter(|id| pre.checkout_repos.contains_key(id));
            let (comparison, ahead, behind) = if v6 {
                (
                    opt_text(&row, 13)?.unwrap_or_else(|| String::from("pending")),
                    opt_count(&row, 14, "ahead")?,
                    opt_count(&row, 15, "behind")?,
                )
            } else {
                (String::from("pending"), None, None)
            };
            let kind = req_text(&row, 3)?;
            match kind.as_str() {
                "local" => totals.local_branches += 1,
                "remote_tracking" => totals.remote_tracking_refs += 1,
                _ => {}
            }
            stream.array_item(&Branch {
                id: req_text(&row, 0)?,
                repository_id: instance_id,
                checkout_scope_id: scope,
                kind,
                name: encode_name(&req_blob(&row, 4)?),
                oid: object_id_from_parts(opt_blob(&row, 5)?, opt_text(&row, 6)?),
                symbolic_target: opt_blob(&row, 7)?.as_deref().map(encode_name),
                upstream: opt_blob(&row, 8)?.as_deref().map(encode_name),
                state: req_text(&row, 9)?,
                observed_at: ms_to_rfc3339(req_i64(&row, 10)?),
                error_ids: Vec::new(),
                // Report 1.2.0: NULL (legacy/unlabeled) reads `unknown`.
                freshness: opt_text(&row, 11)?.unwrap_or_else(|| String::from("unknown")),
                freshness_at: opt_i64(&row, 12)?.map(ms_to_rfc3339),
                comparison,
                ahead,
                behind,
            })?;
            stats.branches += 1;
        }
    }
    stream.end_array()?;

    // Remotes (effective fetch/push observations). URLs are redacted at
    // this last output boundary regardless of writer version (RSP-001):
    // legacy catalog rows may still carry credentials even though the
    // current inspector redacts before writing new rows.
    stream.begin_array_field("remotes")?;
    {
        let mut rows = reader
            .query(
                "SELECT id, instance_id, checkout_scope_id, name, role, url, \
                    canonical_url, observed_at_ms FROM remotes ORDER BY id ASC",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let instance_id = req_text(&row, 1)?;
            if !pre.included_repos.contains(&instance_id) {
                stats.skipped_orphans += 1;
                continue;
            }
            let checkout_scope = opt_text(&row, 2)?;
            if pre.scope_roots.is_some()
                && checkout_scope
                    .as_ref()
                    .is_some_and(|id| !pre.checkout_repos.contains_key(id))
            {
                continue;
            }
            let scope = checkout_scope.filter(|id| pre.checkout_repos.contains_key(id));
            let name_bytes = req_blob(&row, 3)?;
            stream.array_item(&Remote {
                id: req_text(&row, 0)?,
                repository_id: instance_id.clone(),
                checkout_scope_id: scope,
                name: encode_name(&name_bytes),
                role: req_text(&row, 4)?,
                url: cap_report_field(&redact_remote_url(&String::from_utf8_lossy(&req_blob(
                    &row, 5,
                )?))),
                canonical_url: opt_blob(&row, 6)?.map(|bytes| {
                    cap_report_field(&redact_remote_url(&String::from_utf8_lossy(&bytes)))
                }),
                observed_at: ms_to_rfc3339(req_i64(&row, 7)?),
                // Report 1.2.0: latest attempt for this store + remote
                // name (`None` when never attempted). Name-keyed, so
                // both role rows for one remote share the attempt.
                refresh: pre.refreshes.get(&(instance_id, name_bytes)).cloned(),
            })?;
            stats.remotes += 1;
        }
    }
    stream.end_array()?;

    // Caller-owned storage links, aliases, and candidates.
    stream.begin_array_field("storage_links")?;
    for link in &inputs.storage_links {
        let to_path_id = pre
            .interner
            .by_bytes
            .get(&link.to_path_bytes)
            .cloned()
            .ok_or_else(|| {
                Error::Report(format!("storage link {} path was not interned", link.id))
            })?;
        stream.array_item(&StorageLink {
            id: link.id.clone(),
            from_repository_id: link.from_repository_id.clone(),
            to_path_id,
            kind: link.kind.clone(),
            evidence: link
                .evidence
                .iter()
                .map(|line| scrubbed_field(line))
                .collect(),
        })?;
        stats.storage_links += 1;
    }
    stream.end_array()?;

    stream.begin_array_field("aliases")?;
    for alias in &inputs.aliases {
        let path_id = pre
            .interner
            .by_bytes
            .get(&alias.path_bytes)
            .cloned()
            .ok_or_else(|| Error::Report("alias path was not interned".to_string()))?;
        let target_path_id = pre
            .interner
            .by_bytes
            .get(&alias.target_path_bytes)
            .cloned()
            .ok_or_else(|| Error::Report("alias target was not interned".to_string()))?;
        stream.array_item(&Alias {
            path_id,
            target_path_id,
            kind: alias.kind.clone(),
            verified_at: ms_to_rfc3339(alias.verified_at_ms),
        })?;
        stats.aliases += 1;
    }
    stream.end_array()?;
    totals.aliases = stats.aliases;

    stream.begin_array_field("candidates")?;
    for candidate in &inputs.candidates {
        let path_id = pre
            .interner
            .by_bytes
            .get(&candidate.path_bytes)
            .cloned()
            .ok_or_else(|| {
                Error::Report(format!("candidate {} path was not interned", candidate.id))
            })?;
        stream.array_item(&Candidate {
            id: candidate.id.clone(),
            path_id,
            repository_id: candidate.repository_id.clone(),
            disposition: candidate.disposition.clone(),
            reason: scrubbed_field(&candidate.reason),
            retry_after: candidate.retry_after_ms.map(ms_to_rfc3339),
            error_ids: candidate.error_ids.clone(),
        })?;
        stats.candidates += 1;
    }
    stream.end_array()?;
    totals.unresolved_candidates = unresolvable_candidates;

    // Open errors; a `dir:{n}` scope resolves to its path when the row
    // exists, otherwise the linkage stays honestly null.
    stream.begin_array_field("errors")?;
    {
        let mut rows = reader
            .query(
                "SELECT id, scope_key, category, detail, attempts, first_seen_ms, \
                    last_seen_ms, next_retry_ms, open FROM errors \
                    WHERE open = 1 ORDER BY id ASC",
                (),
            )
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            let id = req_text(&row, 0)?;
            let scope_key = req_text(&row, 1)?;
            if !report_error_in_scope(
                &scope_key,
                pre.scope_roots.as_deref(),
                pre.scope_identity_roots.as_deref(),
                &pre.checkout_repos,
                &pre.scope_volumes,
            ) {
                continue;
            }
            let category = req_text(&row, 2)?;
            let path_id = error_path_id(reader, &scope_key).await?;
            let retryable = req_i64(&row, 8)? != 0
                && category != "unsupported"
                && category != "unresolvable_identity";
            stream.array_item(&ErrorRecord {
                id,
                path_id,
                operation: operation_for_scope(&scope_key).to_string(),
                category,
                message: scrubbed_field(&req_text(&row, 3)?),
                retryable,
                attempts: req_i64(&row, 4)?.max(0) as u64,
                first_seen: ms_to_rfc3339(req_i64(&row, 5)?),
                last_seen: ms_to_rfc3339(req_i64(&row, 6)?),
                next_retry: opt_i64(&row, 7)?.map(ms_to_rfc3339),
            })?;
            stats.errors += 1;
        }
    }
    stream.end_array()?;
    totals.gaps = stats.errors;

    stream.begin_array_field("generated_artifacts")?;
    for artifact in &inputs.generated_artifacts {
        let path_id = pre
            .interner
            .by_bytes
            .get(&artifact.path_bytes)
            .cloned()
            .ok_or_else(|| Error::Report("artifact path was not interned".to_string()))?;
        stream.array_item(&GeneratedArtifact {
            path_id,
            kind: artifact.kind.clone(),
            created_after_status: artifact.created_after_status,
        })?;
        stats.generated_artifacts += 1;
    }
    stream.end_array()?;

    totals.observed_paths = stats.paths;
    totals.groups = stats.groups;
    totals.accounts = stats.accounts;
    totals.stores = stats.repositories;
    totals.aliases = stats.aliases;
    stream.field("totals", &totals)?;
    stream.end_object()?;
    let writer = stream.finish()?;
    Ok((writer, stats))
}

fn record_analysis_total(totals: &mut AnalysisTotals, state: &str) {
    match state {
        "complete" => totals.completed += 1,
        "pending" | "not_requested" => totals.pending += 1,
        "unsupported" => totals.unavailable += 1,
        "partial" | "unstable" | "error" => totals.failed += 1,
        _ => totals.pending += 1,
    }
}

async fn error_path_id(
    reader: &turso::Connection,
    scope_key: &str,
) -> crate::Result<Option<String>> {
    let raw = match scope_key.strip_prefix("dir:") {
        Some(raw) => raw,
        None => return Ok(None),
    };
    let dir_id: i64 = match raw.parse() {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };
    if row_exists(
        reader,
        "SELECT 1 FROM directories WHERE id = ?1",
        turso::Value::Integer(dir_id),
    )
    .await?
    {
        Ok(Some(format!("path-{dir_id}")))
    } else {
        Ok(None)
    }
}

/// Default RSS target for staged-report verification when the caller
/// supplies none (R3): 256 MiB, matching the conservative profile default
/// and the `ReportInputs.rss_target_bytes` test value. Emit paths pass the
/// caller's configured target instead; the staged envelope's self-declared
/// target is never trusted for the budget.
pub const DEFAULT_STAGED_VERIFY_RSS_TARGET_BYTES: u64 = 256 * 1024 * 1024;

/// Exact source commit embedded by the build script, when supplied by a
/// trusted build input or available from a clean Git checkout. Dirty or
/// source-archive builds without an explicit commit retain the schema's
/// nullable fallback.
pub fn build_source_commit() -> Option<String> {
    option_env!("REPO_SCAN_SOURCE_COMMIT").and_then(parse_source_commit)
}

/// Validate a full SHA-1 or SHA-256 Git object ID and normalize its hex
/// spelling. Abbreviated and non-hex values are treated as unknown.
pub fn parse_source_commit(value: &str) -> Option<String> {
    let value = value.trim();
    if (value.len() == 40 || value.len() == 64)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

/// Parse staged bytes back into a validated [`Report`]. Used by the
/// REPORT-01 gate, the terminal renderer, and publication retries. The
/// staging file is opened once (`O_NOFOLLOW`, capped) and the bound bytes
/// are verified; production file publication reuses the same bound bytes
/// without re-opening the path.
pub fn verify_staged_report(staged: &Path) -> crate::Result<Report> {
    verify_staged_report_capped(staged, DEFAULT_STAGED_VERIFY_RSS_TARGET_BYTES)
}

/// Validate staged bytes under the caller's memory target without building
/// a complete typed [`Report`]. This is the path for publication gates that
/// only need proof that the report is valid.
pub fn validate_staged_report(staged: &Path) -> crate::Result<()> {
    validate_staged_report_capped(staged, DEFAULT_STAGED_VERIFY_RSS_TARGET_BYTES)
}

/// Streaming counterpart to [`verify_staged_report_capped`]. The staged
/// file cap and caller-supplied RSS target are unchanged; the streaming
/// estimate accounts for the source bytes, compact ID index, and one
/// decoded record at a time.
pub fn validate_staged_report_capped(staged: &Path, rss_target_bytes: u64) -> crate::Result<()> {
    let bound = BoundStaged::open(staged)?;
    validate_bound_staged_report_capped(&bound, rss_target_bytes).map_err(|e| {
        Error::Report(format!(
            "staged report {} is not valid: {e}",
            staged.display()
        ))
    })
}

/// Validate an already-bound staged report. Keeping this handle alive lets
/// callers validate, retain, and publish the exact same bytes.
pub fn validate_bound_staged_report(bound: &BoundStaged) -> crate::Result<()> {
    validate_bound_staged_report_capped(bound, DEFAULT_STAGED_VERIFY_RSS_TARGET_BYTES)
}

/// Capped counterpart to [`validate_bound_staged_report`].
pub fn validate_bound_staged_report_capped(
    bound: &BoundStaged,
    rss_target_bytes: u64,
) -> crate::Result<()> {
    validate_bound_staged_report_id_capped(bound, rss_target_bytes).map(|_| ())
}

/// Validate an already-bound report under the streaming memory budget and
/// return its validated report ID for snapshot-reference checks.
pub fn validate_bound_staged_report_id_capped(
    bound: &BoundStaged,
    rss_target_bytes: u64,
) -> crate::Result<String> {
    check_streaming_measurement_memory_budget(bound.len(), rss_target_bytes)?;
    let (array_items, owned_id_bytes, max_string_bytes, max_debug_string_bytes) =
        super::validate_stream::measure_report_streamed(bound.bytes())?;
    check_streaming_staged_memory_budget(
        bound.len(),
        array_items,
        owned_id_bytes,
        max_string_bytes,
        max_debug_string_bytes,
        rss_target_bytes,
    )?;
    super::validate_stream::validate_report_streamed(bound.bytes())
}

/// Parse staged bytes back into a validated [`Report`] under an explicit
/// aggregate budget (R3). The bound handle is consumed and its byte vector
/// moved out as the single copy; a bounded measurement pass counts array
/// items and string sizes, the aggregate budget is enforced against
/// `rss_target_bytes`, and only then is the typed report built. The byte
/// buffer is dropped before the
/// typed-only validation phase, so bytes and the typed report never
/// coexist past the parse call. Budget exhaustion refuses with an
/// incomplete-worded resource error instead of exceeding memory.
pub fn verify_staged_report_capped(staged: &Path, rss_target_bytes: u64) -> crate::Result<Report> {
    let bound = BoundStaged::open(staged)?;
    verify_owned_bound_report(bound, rss_target_bytes).map_err(|e| {
        Error::Report(format!(
            "staged report {} is not valid: {e}",
            staged.display()
        ))
    })
}

/// Owned-bound verification (R3): see [`verify_staged_report_capped`].
/// Consumes the bound handle, enforces the aggregate budget from the
/// measured array-item upper bound, builds the typed report, then drops the staging bytes
/// before validation.
fn verify_owned_bound_report(bound: BoundStaged, rss_target_bytes: u64) -> crate::Result<Report> {
    let bytes = bound.into_bytes();
    let (array_items, owned_id_bytes, max_string_bytes, max_debug_string_bytes) =
        measure_staged_report(&bytes, rss_target_bytes)?;
    check_streaming_staged_memory_budget(
        bytes.len() as u64,
        array_items,
        owned_id_bytes,
        max_string_bytes,
        max_debug_string_bytes,
        rss_target_bytes,
    )?;
    check_staged_memory_budget(
        bytes.len() as u64,
        array_items,
        max_debug_string_bytes,
        rss_target_bytes,
    )?;
    super::validate_stream::validate_report_streamed(&bytes)?;
    let report: Report = serde_json::from_slice(&bytes)
        .map_err(|error| super::validate_stream::staged_json_error(&error))?;
    drop(bytes);
    Ok(report)
}

/// Parse already-bound staged bytes into a validated [`Report`].
pub fn verify_bound_report(bound: &BoundStaged) -> crate::Result<Report> {
    verify_bound_report_capped(bound, DEFAULT_STAGED_VERIFY_RSS_TARGET_BYTES)
}

/// Parse already-bound staged bytes into a validated [`Report`] under an
/// explicit aggregate budget (R3). A bounded measurement pass counts array
/// items and the `rss_target_bytes` gate is enforced before the typed build, so the
/// transient bytes-plus-typed peak stays within budget; the bound bytes
/// stay borrowed for the caller's later retain/publish stages (same
/// binding, no re-read). Callers that neither retain nor publish
/// afterwards should prefer the owned path, which drops the byte buffer
/// before validation.
pub fn verify_bound_report_capped(
    bound: &BoundStaged,
    rss_target_bytes: u64,
) -> crate::Result<Report> {
    let (array_items, owned_id_bytes, max_string_bytes, max_debug_string_bytes) =
        measure_staged_report(bound.bytes(), rss_target_bytes)?;
    check_streaming_staged_memory_budget(
        bound.len(),
        array_items,
        owned_id_bytes,
        max_string_bytes,
        max_debug_string_bytes,
        rss_target_bytes,
    )?;
    check_staged_memory_budget(
        bound.len(),
        array_items,
        max_debug_string_bytes,
        rss_target_bytes,
    )?;
    super::validate_stream::validate_report_streamed(bound.bytes())?;
    let report: Report = serde_json::from_slice(bound.bytes())
        .map_err(|error| super::validate_stream::staged_json_error(&error))?;
    Ok(report)
}

fn measure_staged_report(
    bytes: &[u8],
    rss_target_bytes: u64,
) -> crate::Result<(u64, u64, u64, u64)> {
    check_streaming_measurement_memory_budget(bytes.len() as u64, rss_target_bytes)?;
    super::validate_stream::measure_report_streamed(bytes)
}

/// Emission pipeline: stage, retain the immutable snapshot, then publish
/// to a file or render to the terminal. Snapshot readers are always
/// released before any external write (spec §15).
pub struct ReportPipeline;

impl ReportPipeline {
    /// Stream the report into controlled staging, verify it, retain the
    /// snapshot, and publish to `dest`. On publication failure the snapshot
    /// is retained, its state is marked `failed`, and the error is returned;
    /// retry with [`ReportPipeline::retry_publication`] without repeating
    /// discovery.
    ///
    /// Call-graph note (RSF-751/AC46/F06D): production file publication
    /// does NOT call this function. `run_scan_inner` stages via
    /// `stream_report_from_store` and publishes via
    /// `verified_retain_and_publish` (`src/main.rs`), which gates on
    /// [`verify_staged_report`] before anything is retained or shipped;
    /// the terminal path uses [`ReportPipeline::emit_to_terminal`] and
    /// retries use [`ReportPipeline::retry_publication`] (both verify).
    /// This entry point is exercised only by the REPORT-01/02 suite, but
    /// it carries the same verify-before-retain gate so any future
    /// production wiring cannot ship unverified bytes.
    pub async fn emit_to_file(
        store: &crate::store::TursoStore,
        inputs: &ReportInputs,
        dest: &Path,
        state_dir: &Path,
        staging_dir: &Path,
        snapshot_dir: &Path,
        now_ms: i64,
    ) -> crate::Result<crate::report::Publication> {
        let staged = stage_report(store, inputs, staging_dir)
            .await
            .map_err(stage_refusal)?;
        let bound = BoundStaged::open(&staged).map_err(|e| {
            quarantine_staging(&staged);
            crate::error::Error::Report(format!(
                "refusing invalid staged report {}: {e}",
                staged.display()
            ))
        })?;
        let staged_report_id =
            validate_bound_staged_report_id_capped(&bound, inputs.rss_target_bytes).map_err(
                |e| {
                    quarantine_staging(&staged);
                    crate::error::Error::Report(format!(
                        "refusing invalid staged report {}: {e}",
                        staged.display()
                    ))
                },
            )?;
        if staged_report_id != inputs.report_id {
            quarantine_staging(&staged);
            return Err(Error::Report(format!(
                "staged report {} has a report_id that does not match the expected snapshot id",
                staged.display()
            )));
        }
        let receipt = retain_bound(
            store,
            &bound,
            snapshot_dir,
            &inputs.report_id,
            inputs.catalog_revision,
            inputs.generation,
            now_ms,
        )
        .await?;
        if receipt.sha256 != bound.sha256() {
            return Err(Error::Report(format!(
                "snapshot {} digest does not match staged bytes",
                receipt.path.display()
            )));
        }
        let published: crate::Result<PublishReceipt> = publish_bound(&bound, dest, state_dir);
        match published {
            Ok(file) => {
                store
                    .set_snapshot_publication(&inputs.report_id, "published")
                    .await?;
                let _ = std::fs::remove_file(&staged);
                Ok(crate::report::Publication {
                    report_id: inputs.report_id.clone(),
                    published: true,
                    checksum: file.checksum,
                })
            }
            Err(error) => {
                store
                    .set_snapshot_publication(&inputs.report_id, "failed")
                    .await?;
                Err(error)
            }
        }
    }

    /// Stream the report into controlled staging, verify it, retain the
    /// snapshot, and render a readable summary to `terminal` (normally
    /// stdout). Invalid staging is quarantined, never retained.
    pub async fn emit_to_terminal(
        store: &crate::store::TursoStore,
        inputs: &ReportInputs,
        staging_dir: &Path,
        snapshot_dir: &Path,
        now_ms: i64,
        terminal: &mut dyn std::io::Write,
    ) -> crate::Result<crate::report::Publication> {
        let staged = stage_report(store, inputs, staging_dir)
            .await
            .map_err(stage_refusal)?;
        let bound = BoundStaged::open(&staged).map_err(|e| {
            quarantine_staging(&staged);
            crate::error::Error::Report(format!(
                "refusing invalid staged report {}: {e}",
                staged.display()
            ))
        })?;
        let report = verify_bound_report_capped(&bound, inputs.rss_target_bytes).map_err(|e| {
            quarantine_staging(&staged);
            crate::error::Error::Report(format!(
                "refusing invalid staged report {}: {e}",
                staged.display()
            ))
        })?;
        if report.report_id != inputs.report_id {
            quarantine_staging(&staged);
            return Err(Error::Report(format!(
                "staged report {} has a report_id that does not match the expected snapshot id",
                staged.display()
            )));
        }
        let receipt = retain_bound(
            store,
            &bound,
            snapshot_dir,
            &inputs.report_id,
            inputs.catalog_revision,
            inputs.generation,
            now_ms,
        )
        .await?;
        if receipt.sha256 != bound.sha256() {
            store
                .set_snapshot_publication(&inputs.report_id, "failed")
                .await?;
            return Err(Error::Report(format!(
                "snapshot {} digest does not match staged bytes",
                receipt.path.display()
            )));
        }
        store
            .set_snapshot_publication(&inputs.report_id, "retained")
            .await?;
        // R3: the bound bytes are no longer needed once retained; drop them
        // before rendering so the typed report is the only live allocation.
        drop(bound);
        let _ = std::fs::remove_file(&staged);
        crate::report::render::render_terminal(&report, terminal)?;
        Ok(crate::report::Publication {
            report_id: inputs.report_id.clone(),
            published: false,
            checksum: receipt.checksum,
        })
    }

    /// Stream the report into controlled staging, verify it, retain the
    /// snapshot, and write the verified JSON document to `out` (normally
    /// stdout) — the Wave2b `scan --format json` lane. The bytes are the
    /// retained snapshot bytes verbatim plus one newline: no prose, no
    /// ANSI, no cursor codes. Invalid staging is quarantined, never
    /// retained. Returns `Ok(false)` when the consumer went away
    /// (broken pipe): the snapshot stays retained, the writer just stops.
    pub async fn emit_to_json(
        store: &crate::store::TursoStore,
        inputs: &ReportInputs,
        staging_dir: &Path,
        snapshot_dir: &Path,
        now_ms: i64,
        out: &mut dyn std::io::Write,
    ) -> crate::Result<bool> {
        let staged = stage_report(store, inputs, staging_dir)
            .await
            .map_err(stage_refusal)?;
        let bound = BoundStaged::open(&staged).map_err(|e| {
            quarantine_staging(&staged);
            crate::error::Error::Report(format!(
                "refusing invalid staged report {}: {e}",
                staged.display()
            ))
        })?;
        let staged_report_id =
            validate_bound_staged_report_id_capped(&bound, inputs.rss_target_bytes).map_err(
                |e| {
                    quarantine_staging(&staged);
                    crate::error::Error::Report(format!(
                        "refusing invalid staged report {}: {e}",
                        staged.display()
                    ))
                },
            )?;
        if staged_report_id != inputs.report_id {
            quarantine_staging(&staged);
            return Err(Error::Report(format!(
                "staged report {} has a report_id that does not match the expected snapshot id",
                staged.display()
            )));
        }
        let receipt = retain_bound(
            store,
            &bound,
            snapshot_dir,
            &inputs.report_id,
            inputs.catalog_revision,
            inputs.generation,
            now_ms,
        )
        .await?;
        if receipt.sha256 != bound.sha256() {
            store
                .set_snapshot_publication(&inputs.report_id, "failed")
                .await?;
            return Err(Error::Report(format!(
                "snapshot {} digest does not match staged bytes",
                receipt.path.display()
            )));
        }
        let pipe_open = crate::report::output::write_machine_bytes(out, bound.bytes())?;
        drop(bound);
        store
            .set_snapshot_publication(&inputs.report_id, "retained")
            .await?;
        let _ = std::fs::remove_file(&staged);
        Ok(pipe_open)
    }

    /// Stream the report into controlled staging, verify it, and retain
    /// the snapshot without rendering or publishing — the Wave2b
    /// `scan --format jsonl` lane (the journal replay on stdout is the
    /// output; the retained snapshot is the state the human/JSON lanes
    /// read). Returns the snapshot path.
    pub async fn stage_and_retain(
        store: &crate::store::TursoStore,
        inputs: &ReportInputs,
        staging_dir: &Path,
        snapshot_dir: &Path,
        now_ms: i64,
    ) -> crate::Result<PathBuf> {
        let staged = stage_report(store, inputs, staging_dir)
            .await
            .map_err(stage_refusal)?;
        let bound = BoundStaged::open(&staged).map_err(|e| {
            quarantine_staging(&staged);
            crate::error::Error::Report(format!(
                "refusing invalid staged report {}: {e}",
                staged.display()
            ))
        })?;
        let staged_report_id =
            validate_bound_staged_report_id_capped(&bound, inputs.rss_target_bytes).map_err(
                |e| {
                    quarantine_staging(&staged);
                    crate::error::Error::Report(format!(
                        "refusing invalid staged report {}: {e}",
                        staged.display()
                    ))
                },
            )?;
        if staged_report_id != inputs.report_id {
            quarantine_staging(&staged);
            return Err(Error::Report(format!(
                "staged report {} has a report_id that does not match the expected snapshot id",
                staged.display()
            )));
        }
        let receipt = retain_bound(
            store,
            &bound,
            snapshot_dir,
            &inputs.report_id,
            inputs.catalog_revision,
            inputs.generation,
            now_ms,
        )
        .await?;
        if receipt.sha256 != bound.sha256() {
            store
                .set_snapshot_publication(&inputs.report_id, "failed")
                .await?;
            return Err(Error::Report(format!(
                "snapshot {} digest does not match staged bytes",
                receipt.path.display()
            )));
        }
        store
            .set_snapshot_publication(&inputs.report_id, "retained")
            .await?;
        let _ = std::fs::remove_file(&staged);
        Ok(receipt.path)
    }

    /// Publish one live `--report` replacement (Wave2b case 17): stage,
    /// verify, and atomically replace `dest` — WITHOUT retaining a
    /// snapshot (snapshots are immutable by report ID, so accumulating
    /// one per live tick would be unbounded; the live destination is
    /// the replaceable snapshot). Every concurrently read file is valid
    /// JSON from exactly one revision: readers see either the old or
    /// the new destination, never a mix. Callers throttle (see
    /// [`crate::report::output::LiveThrottle`]) and treat failure as a
    /// best-effort skip: a live tick must never fail the scan.
    pub async fn publish_live(
        store: &crate::store::TursoStore,
        inputs: &ReportInputs,
        staging_dir: &Path,
        dest: &Path,
        state_dir: &Path,
    ) -> crate::Result<crate::report::publish::PublishReceipt> {
        let staged = stage_report(store, inputs, staging_dir)
            .await
            .map_err(stage_refusal)?;
        let bound = BoundStaged::open(&staged).map_err(|e| {
            quarantine_staging(&staged);
            crate::error::Error::Report(format!(
                "refusing invalid staged report {}: {e}",
                staged.display()
            ))
        })?;
        let staged_report_id =
            match validate_bound_staged_report_id_capped(&bound, inputs.rss_target_bytes) {
                Ok(id) => id,
                Err(e) => {
                    quarantine_staging(&staged);
                    return Err(crate::error::Error::Report(format!(
                        "refusing invalid staged report {}: {e}",
                        staged.display()
                    )));
                }
            };
        if staged_report_id != inputs.report_id {
            quarantine_staging(&staged);
            return Err(Error::Report(format!(
                "staged report {} has a report_id that does not match the expected snapshot id",
                staged.display()
            )));
        }
        let receipt =
            publish_bound(&bound, dest, state_dir).inspect_err(|_| quarantine_staging(&staged))?;
        if receipt.sha256 != bound.sha256() {
            quarantine_staging(&staged);
            return Err(Error::Report(format!(
                "live destination {} digest does not match staged bytes",
                dest.display()
            )));
        }
        drop(bound);
        let _ = std::fs::remove_file(&staged);
        Ok(receipt)
    }

    /// Retry a failed publication from retained snapshot bytes without
    /// repeating discovery. The snapshot is validated before shipping.
    pub async fn retry_publication(
        store: &crate::store::TursoStore,
        snapshot_path: &Path,
        report_id: &str,
        dest: &Path,
        state_dir: &Path,
    ) -> crate::Result<crate::report::Publication> {
        let bound = BoundStaged::open(snapshot_path)?;
        let snapshot_report_id =
            validate_bound_staged_report_id_capped(&bound, DEFAULT_STAGED_VERIFY_RSS_TARGET_BYTES)?;
        if snapshot_report_id != report_id {
            return Err(Error::Report(format!(
                "snapshot {} report_id does not match the requested report",
                snapshot_path.display(),
            )));
        }
        let snapshot = store.get_report_snapshot(report_id).await?.ok_or_else(|| {
            Error::Report(format!(
                "snapshot {} has no catalog row; refusing publication",
                snapshot_path.display()
            ))
        })?;
        let expected_sha256 = snapshot
            .checksum
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        if expected_sha256.as_deref() != Some(bound.sha256()) {
            store.set_snapshot_publication(report_id, "failed").await?;
            return Err(Error::Report(format!(
                "snapshot {} does not match its catalog checksum; refusing publication",
                snapshot_path.display()
            )));
        }
        match publish_bound(&bound, dest, state_dir) {
            Ok(file) => {
                store
                    .set_snapshot_publication(report_id, "published")
                    .await?;
                Ok(crate::report::Publication {
                    report_id: report_id.to_string(),
                    published: true,
                    checksum: file.checksum,
                })
            }
            Err(error) => {
                store.set_snapshot_publication(report_id, "failed").await?;
                Err(error)
            }
        }
    }

    /// Retry terminal rendering from a retained snapshot without repeating
    /// discovery. The snapshot is revalidated and matched to its catalog
    /// checksum before it is rendered again.
    pub async fn retry_terminal(
        store: &crate::store::TursoStore,
        snapshot_path: &Path,
        report_id: &str,
        terminal: &mut dyn std::io::Write,
    ) -> crate::Result<crate::report::Publication> {
        check_report_id(report_id)?;
        let bound = BoundStaged::open(snapshot_path)?;
        let report = verify_bound_report_capped(&bound, DEFAULT_STAGED_VERIFY_RSS_TARGET_BYTES)?;
        if report.report_id != report_id {
            return Err(Error::Report(format!(
                "snapshot {} report_id does not match the requested report",
                snapshot_path.display()
            )));
        }
        let snapshot = store.get_report_snapshot(report_id).await?.ok_or_else(|| {
            Error::Report(format!(
                "snapshot {} has no catalog row; refusing terminal retry",
                snapshot_path.display()
            ))
        })?;
        let expected_sha256 = snapshot
            .checksum
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        if expected_sha256.as_deref() != Some(bound.sha256()) {
            store.set_snapshot_publication(report_id, "failed").await?;
            return Err(Error::Report(format!(
                "snapshot {} does not match its catalog checksum; refusing terminal retry",
                snapshot_path.display()
            )));
        }
        let checksum = bound.sha256().to_string();
        store
            .set_snapshot_publication(report_id, "retained")
            .await?;
        drop(bound);
        crate::report::render::render_terminal(&report, terminal)?;
        Ok(crate::report::Publication {
            report_id: report_id.to_string(),
            published: false,
            checksum,
        })
    }
}

/// Quarantine a failed staging file: move it under
/// `<staging>/quarantine/` for forensics, deleting it when the move fails.
/// The quarantine directory is bound owner-only (`0700`) through
/// `ensure_private_dir_all`, and the move itself is dir-FD-relative on
/// unix, so a path race can neither redirect cleanup nor leave private
/// remnants exposed (XSEC-06/RSP-004). Best-effort; never fails.
pub fn quarantine_staging(staged: &Path) {
    if let (Some(parent), Some(name)) = (staged.parent(), staged.file_name()) {
        let dir = parent.join("quarantine");
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::io::AsRawFd;
            if crate::store::owner::ensure_private_dir_all(&dir).is_ok() {
                let moved = (|| {
                    let parent_fd = crate::store::owner::open_dir_nofollow(parent).ok()?;
                    let quarantine_fd = crate::store::owner::open_dir_nofollow(&dir).ok()?;
                    let from = std::ffi::CString::new(name.as_bytes()).ok()?;
                    // SAFETY: both FDs are open directories; the name is a
                    // NUL-free leaf resolved relative to each.
                    let rc = unsafe {
                        libc::renameat(
                            parent_fd.as_raw_fd(),
                            from.as_ptr(),
                            quarantine_fd.as_raw_fd(),
                            from.as_ptr(),
                        )
                    };
                    (rc == 0).then_some(())
                })();
                if moved.is_some() {
                    return;
                }
                if std::fs::rename(staged, dir.join(name)).is_ok() {
                    return;
                }
            }
        }
        #[cfg(not(unix))]
        {
            if std::fs::create_dir_all(&dir).is_ok()
                && std::fs::rename(staged, dir.join(name)).is_ok()
            {
                return;
            }
        }
    }
    let _ = std::fs::remove_file(staged);
}

/// Map a staging failure to the verify-before-retain refusal shape, so a
/// report that fails during streaming (contradicted coverage, dangling
/// input, catalog race) is refused with the same gate wording as a report
/// that fails verification after staging.
fn stage_refusal(error: Error) -> Error {
    match error {
        Error::Report(detail) => Error::Report(format!("refusing invalid staged report: {detail}")),
        other => other,
    }
}

/// Stream the report into a fresh staging file and sync it. The database
/// reader is released before this returns. The report ID is validated
/// before it is ever interpolated into the staging filename (RSP-006);
/// the staging directory is bound owner-only and held as a directory FD,
/// the file is created `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` relative to
/// that FD with an explicit `0600` mode (RSP-004/RSP-007, no
/// check-then-use by path), and any stream failure quarantines the
/// partial file instead of leaving residue.
async fn stage_report(
    store: &crate::store::TursoStore,
    inputs: &ReportInputs,
    staging_dir: &Path,
) -> crate::Result<PathBuf> {
    check_report_id(&inputs.report_id)?;
    crate::store::owner::ensure_private_dir_all(staging_dir)?;
    let leaf = format!(
        ".staging-{}-{}-{}.json",
        std::process::id(),
        crate::store::now_ms(),
        inputs.report_id
    );
    let staged = staging_dir.join(&leaf);
    #[cfg(unix)]
    let (file, staging_fd) = {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let dir = crate::store::owner::open_dir_nofollow(staging_dir)?;
        let name = std::ffi::CString::new(leaf.as_bytes())
            .map_err(|_| Error::Report(format!("refusing staging name with NUL byte: {leaf:?}")))?;
        // SAFETY: dirfd is an open directory FD; the name is a generated
        // NUL-free leaf resolved relative to it.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                crate::store::owner::STATE_FILE_MODE as libc::c_uint,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(Error::Report(format!(
                    "staging file already exists: {}",
                    staged.display()
                )));
            }
            return Err(Error::Report(format!(
                "cannot create staging file {}: {e}",
                staged.display()
            )));
        }
        // SAFETY: `openat` returned a new owned FD; it moves into `File` once.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            quarantine_staging(&staged);
            return Err(Error::Report(format!(
                "staging file {} mode is {mode:o}, want no group/other access",
                staged.display()
            )));
        }
        (file, dir)
    };
    #[cfg(not(unix))]
    let file = {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        opts.open(&staged).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Report(format!("staging file already exists: {}", staged.display()))
            } else {
                crate::Error::from(e)
            }
        })?
    };
    let outcome: crate::Result<()> = async {
        let (mut file, _stats) = stream_report_from_store(store, inputs, file).await?;
        file.flush()?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            let _ = staging_fd.sync_all();
        }
        Ok(())
    }
    .await;
    match outcome {
        Ok(()) => Ok(staged),
        Err(error) => {
            quarantine_staging(&staged);
            Err(error)
        }
    }
}
