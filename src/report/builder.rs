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
    Alias, Branch, Candidate, Checkout, Coverage, ErrorRecord, GeneratedArtifact, Head, ObjectId,
    PathRecord, Remote, RemoteRefresh, Report, Repository, Resources, Root, Scan, ScanTarget,
    Status, StorageLink, Tool, Volume,
};
use crate::report::publish::{
    check_report_id, check_staged_memory_budget, publish_bound, retain_bound, BoundStaged,
    PublishReceipt,
};
use crate::report::stream::StreamingWriter;
use crate::report::validate::validate_report;
use serde::de::IgnoredAny;
use serde::Deserialize;
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
    unresolvable_repo: bool,
    checkout_repos: HashMap<String, String>,
    statuses: HashMap<String, Status>,
    /// Latest `--fetch` attempt per (store id, remote name bytes),
    /// scoped to emitted repositories (report 1.2.0).
    refreshes: HashMap<(String, Vec<u8>), RemoteRefresh>,
    stub_volumes: Vec<String>,
    interner: PathInterner,
    open_errors: u64,
    tasks_pending: u64,
}

async fn pre_pass(conn: &turso::Connection, inputs: &ReportInputs) -> crate::Result<PrePass> {
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
    {
        let mut rows = conn
            .query("SELECT DISTINCT volume_id FROM directories", ())
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            referenced_volumes.insert(req_text(&row, 0)?);
        }
    }
    let mut stub_volumes: Vec<String> = referenced_volumes
        .difference(&known_volumes)
        .cloned()
        .collect();
    stub_volumes.sort();

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
            if !included {
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
            .query("SELECT COUNT(*) FROM errors WHERE open = 1", ())
            .await
            .map_err(store_err)?;
        match rows.next().await.map_err(store_err)? {
            Some(row) => req_i64(&row, 0)?.max(0) as u64,
            None => 0,
        }
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
        unresolvable_repo,
        checkout_repos,
        statuses,
        refreshes,
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
        source_commit: inputs.source_commit.clone(),
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
            stream.array_item(&Volume {
                id: req_text(&row, 0)?,
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
            stream.array_item(&Repository {
                id,
                git_path_id: interned(&req_blob(&row, 1)?)?,
                common_path_id: interned(&req_blob(&row, 2)?)?,
                bare: opt_i64(&row, 4)?.map(|flag| flag != 0),
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
            if !pre.included_repos.contains(&instance_id) {
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
        let mut rows = reader
            .query(
                "SELECT id, instance_id, checkout_scope_id, kind, name, oid, algo, \
                    symbolic_target, upstream, state, observed_at_ms, freshness, \
                    freshness_at_ms \
                    FROM refs ORDER BY id ASC",
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
            let scope = opt_text(&row, 2)?.filter(|id| pre.checkout_repos.contains_key(id));
            stream.array_item(&Branch {
                id: req_text(&row, 0)?,
                repository_id: instance_id,
                checkout_scope_id: scope,
                kind: req_text(&row, 3)?,
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
            let scope = opt_text(&row, 2)?.filter(|id| pre.checkout_repos.contains_key(id));
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

    stream.end_object()?;
    let writer = stream.finish()?;
    Ok((writer, stats))
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

/// Low-memory budget probe over staged bytes (R3): counts the records in
/// every report section without retaining any record content (`IgnoredAny`
/// elements occupy no heap), so the aggregate budget check runs while the
/// only live allocation is the staged byte vector itself. Section names
/// must match [`Report`]'s exactly; a missing section defaults to empty
/// (the full parse still rejects a malformed envelope afterwards).
#[derive(Debug, Deserialize)]
struct StagedBudgetProbe {
    #[serde(default)]
    volumes: Vec<IgnoredAny>,
    #[serde(default)]
    paths: Vec<IgnoredAny>,
    #[serde(default)]
    roots: Vec<IgnoredAny>,
    #[serde(default)]
    repositories: Vec<IgnoredAny>,
    #[serde(default)]
    checkouts: Vec<IgnoredAny>,
    #[serde(default)]
    branches: Vec<IgnoredAny>,
    #[serde(default)]
    remotes: Vec<IgnoredAny>,
    #[serde(default)]
    storage_links: Vec<IgnoredAny>,
    #[serde(default)]
    aliases: Vec<IgnoredAny>,
    #[serde(default)]
    candidates: Vec<IgnoredAny>,
    #[serde(default)]
    errors: Vec<IgnoredAny>,
    #[serde(default)]
    generated_artifacts: Vec<IgnoredAny>,
}

impl StagedBudgetProbe {
    fn total_records(&self) -> u64 {
        (self.volumes.len()
            + self.paths.len()
            + self.roots.len()
            + self.repositories.len()
            + self.checkouts.len()
            + self.branches.len()
            + self.remotes.len()
            + self.storage_links.len()
            + self.aliases.len()
            + self.candidates.len()
            + self.errors.len()
            + self.generated_artifacts.len()) as u64
    }
}

/// Count staged-report records with the low-memory probe (R3). Malformed
/// JSON fails here with the same wording the full parse uses, so error
/// precedence is unchanged.
fn probe_staged_records(bytes: &[u8]) -> crate::Result<u64> {
    let probe: StagedBudgetProbe = serde_json::from_slice(bytes)
        .map_err(|e| Error::Report(format!("staged report bytes are not valid JSON: {e}")))?;
    Ok(probe.total_records())
}

/// Parse staged bytes back into a validated [`Report`]. Used by the
/// REPORT-01 gate, the terminal renderer, and publication retries. The
/// staging file is opened once (`O_NOFOLLOW`, capped) and the bound bytes
/// are verified; production file publication reuses the same bound bytes
/// without re-opening the path.
pub fn verify_staged_report(staged: &Path) -> crate::Result<Report> {
    verify_staged_report_capped(staged, DEFAULT_STAGED_VERIFY_RSS_TARGET_BYTES)
}

/// Parse staged bytes back into a validated [`Report`] under an explicit
/// aggregate budget (R3). The bound handle is consumed and its byte vector
/// moved out as the single copy; a low-memory probe counts records, the
/// aggregate budget is enforced against `rss_target_bytes`, and only then
/// is the typed report built. The byte buffer is dropped before the
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
/// probe count, builds the typed report, then drops the staging bytes
/// before validation.
fn verify_owned_bound_report(bound: BoundStaged, rss_target_bytes: u64) -> crate::Result<Report> {
    let bytes = bound.into_bytes();
    let records = probe_staged_records(&bytes)?;
    check_staged_memory_budget(bytes.len() as u64, records, rss_target_bytes)?;
    let report: Report = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Report(format!("staged report bytes are not valid JSON: {e}")))?;
    drop(bytes);
    validate_report(&report)?;
    Ok(report)
}

/// Parse already-bound staged bytes into a validated [`Report`].
pub fn verify_bound_report(bound: &BoundStaged) -> crate::Result<Report> {
    verify_bound_report_capped(bound, DEFAULT_STAGED_VERIFY_RSS_TARGET_BYTES)
}

/// Parse already-bound staged bytes into a validated [`Report`] under an
/// explicit aggregate budget (R3). A low-memory probe counts records and
/// the `rss_target_bytes` gate is enforced before the typed build, so the
/// transient bytes-plus-typed peak stays within budget; the bound bytes
/// stay borrowed for the caller's later retain/publish stages (same
/// binding, no re-read). Callers that neither retain nor publish
/// afterwards should prefer the owned path, which drops the byte buffer
/// before validation.
pub fn verify_bound_report_capped(
    bound: &BoundStaged,
    rss_target_bytes: u64,
) -> crate::Result<Report> {
    let records = probe_staged_records(bound.bytes())?;
    check_staged_memory_budget(bound.len(), records, rss_target_bytes)?;
    let report: Report = serde_json::from_slice(bound.bytes())
        .map_err(|e| Error::Report(format!("staged report bytes are not valid JSON: {e}")))?;
    validate_report(&report)?;
    Ok(report)
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
        verify_bound_report_capped(&bound, inputs.rss_target_bytes).map_err(|e| {
            quarantine_staging(&staged);
            crate::error::Error::Report(format!(
                "refusing invalid staged report {}: {e}",
                staged.display()
            ))
        })?;
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
        // R3: the bound bytes are no longer needed once retained; drop them
        // before rendering so the typed report is the only live allocation.
        drop(bound);
        crate::report::render::render_terminal(&report, terminal)?;
        store
            .set_snapshot_publication(&inputs.report_id, "retained")
            .await?;
        let _ = std::fs::remove_file(&staged);
        Ok(crate::report::Publication {
            report_id: inputs.report_id.clone(),
            published: false,
            checksum: receipt.checksum,
        })
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
        {
            let report =
                verify_bound_report_capped(&bound, DEFAULT_STAGED_VERIFY_RSS_TARGET_BYTES)?;
            if report.report_id != report_id {
                return Err(Error::Report(format!(
                    "snapshot {} holds report {}, not {report_id}",
                    snapshot_path.display(),
                    report.report_id
                )));
            }
        } // R3: typed report dropped before publication; publish ships bytes only.
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
