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
use crate::model::StatusMode;
use crate::report::encode::{
    encode_bytes, encode_name, guess_oid_algorithm, ms_to_rfc3339, oid_hex_from_bytes,
};
use crate::report::model::{
    Alias, Branch, Candidate, Checkout, Coverage, ErrorRecord, GeneratedArtifact, Head, ObjectId,
    PathRecord, Remote, Report, Repository, Resources, Root, Scan, Status, StorageLink, Tool,
    Volume,
};
use crate::report::publish::{retain_snapshot, PublishReceipt};
use crate::report::stream::StreamingWriter;
use crate::report::validate::validate_report;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Cap for the directory full-path cache (entries; cleared and rebuilt
/// when full, so correctness never depends on it).
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
    pub catalog_revision: u64,
    pub target_url: String,
    pub canonical_url: Option<String>,
    pub scope: String,
    pub scan_state: String,
    pub started_at_ms: i64,
    pub finished_at_ms: Option<i64>,
    pub superseded_by: Option<String>,
    pub cached: bool,
    pub status_mode: StatusMode,
    /// Traversal counters (summarize work, exempt from count agreement).
    pub directories_complete: u64,
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
    /// Coverage overrides; `None` selects the computed value.
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

/// Lenient JSON string-array parse for stored evidence/unknown-fields.
/// Falls back to a single line so observations are never dropped.
fn parse_string_array(raw: &str) -> Vec<String> {
    if raw.is_empty() {
        return Vec::new();
    }
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_else(|_| vec![raw.to_string()])
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

/// Intern synthetic (non-`directories`) full paths to stable report IDs.
/// Memory is bounded by repository/checkout/caller-input counts, never by
/// the directory walk.
struct PathInterner {
    by_bytes: HashMap<Vec<u8>, String>,
    synthetics: Vec<(String, Vec<u8>)>,
    counter: u64,
}

impl PathInterner {
    fn new() -> Self {
        Self {
            by_bytes: HashMap::new(),
            synthetics: Vec::new(),
            counter: 0,
        }
    }

    fn intern(&mut self, bytes: &[u8]) -> String {
        if let Some(id) = self.by_bytes.get(bytes) {
            return id.clone();
        }
        let id = format!("path-x{}", self.counter);
        self.counter += 1;
        self.by_bytes.insert(bytes.to_vec(), id.clone());
        self.synthetics.push((id.clone(), bytes.to_vec()));
        id
    }
}

fn insert_capped(cache: &mut HashMap<i64, Vec<u8>>, key: i64, value: Vec<u8>) {
    if cache.len() >= PATH_CACHE_CAP {
        cache.clear();
    }
    cache.insert(key, value);
}

fn push_component(full: &mut Vec<u8>, component: &[u8]) {
    if !full.is_empty() && !full.ends_with(b"/") {
        full.push(b'/');
    }
    full.extend_from_slice(component);
}

/// Reconstruct a directory's full path bytes by walking `parent_id` links.
/// Bounded by [`MAX_PATH_DEPTH`] with cycle detection; a bounded cache
/// amortizes clustered lookups. A vanished parent ends the walk (treated
/// as a root boundary); under the publication barrier this cannot happen.
async fn resolve_full_path(
    conn: &turso::Connection,
    dir_id: i64,
    cache: &mut HashMap<i64, Vec<u8>>,
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
            insert_capped(cache, dir_id, full.clone());
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
                insert_capped(cache, dir_id, full.clone());
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
                        insert_capped(cache, dir_id, full.clone());
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
    stub_volumes: Vec<String>,
    interner: PathInterner,
    open_errors: u64,
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
            interner.intern(&git_path);
            interner.intern(&common_path);
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
                interner.intern(&root_path);
            }
            interner.intern(&req_blob(&row, 3)?);
            checkout_repos.insert(id, instance_id);
        }
    }

    let mut statuses = HashMap::new();
    {
        let mut rows = conn
            .query(
                "SELECT checkout_id, mode, state, started_ms, finished_ms, staged, \
                    unstaged, untracked, untracked_units, submodules, unknown_fields, \
                    observed_rev FROM status_observations \
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
                interner.intern(bytes);
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
        interner.intern(&candidate.path_bytes);
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
        interner.intern(&link.to_path_bytes);
        if !included_repos.contains(&link.from_repository_id) {
            return Err(Error::Report(format!(
                "storage link {} references repository {:?} which is not in this report",
                link.id, link.from_repository_id
            )));
        }
    }
    for alias in &inputs.aliases {
        interner.intern(&alias.path_bytes);
        interner.intern(&alias.target_path_bytes);
    }
    for artifact in &inputs.generated_artifacts {
        interner.intern(&artifact.path_bytes);
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

    Ok(PrePass {
        included_repos,
        unresolvable_repo,
        checkout_repos,
        statuses,
        stub_volumes,
        interner,
        open_errors,
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
    let (state, submodules) = match mode {
        StatusMode::Metadata => ("not_requested", "not_requested"),
        _ => ("pending", "unknown"),
    };
    Status {
        state: state.to_string(),
        mode: status_mode_as_str(mode).to_string(),
        started_at: None,
        finished_at: None,
        staged: None,
        unstaged: None,
        untracked: None,
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

/// Stream one consistent report from the catalog to `writer` (normally a
/// controlled staging file). The caller holds the publication barrier so
/// the pre-pass counts and the streamed rows describe the same revision.
/// The dedicated reader is released before this returns; publication to an
/// external destination must only happen afterwards (spec §15).
pub async fn stream_report_from_store<W: Write>(
    store: &crate::store::TursoStore,
    inputs: &ReportInputs,
    writer: W,
) -> crate::Result<(W, StreamStats)> {
    let reader = store.open_reader().await?;
    let pre = pre_pass(&reader, inputs).await?;
    let stats = stream_with_pre_pass(&reader, inputs, &pre, writer).await?;
    drop(reader);
    let (writer, stats) = stats;
    Ok((writer, stats))
}

async fn stream_with_pre_pass<W: Write>(
    reader: &turso::Connection,
    inputs: &ReportInputs,
    pre: &PrePass,
    writer: W,
) -> crate::Result<(W, StreamStats)> {
    let mut stats = StreamStats::default();
    let unresolvable_candidates = inputs
        .candidates
        .iter()
        .filter(|c| c.disposition == "unresolvable_identity")
        .count() as u64;

    let coverage = Coverage {
        filesystem: inputs.coverage_filesystem.clone().unwrap_or_else(|| {
            if inputs.tasks_pending > 0 || pre.open_errors > 0 {
                "incomplete".to_string()
            } else {
                "complete".to_string()
            }
        }),
        identity: inputs.coverage_identity.clone().unwrap_or_else(|| {
            if unresolvable_candidates > 0 || pre.unresolvable_repo {
                "unproven".to_string()
            } else {
                "complete_under_policy".to_string()
            }
        }),
        status: inputs.coverage_status.clone().unwrap_or_else(|| {
            if inputs.status_mode == StatusMode::Metadata {
                "not_requested".to_string()
            } else if pre
                .checkout_repos
                .keys()
                .any(|id| pre.statuses.get(id).is_none_or(|s| s.state != "complete"))
            {
                "incomplete".to_string()
            } else {
                "complete".to_string()
            }
        }),
        directories_complete: inputs.directories_complete,
        tasks_pending: inputs.tasks_pending,
        gaps: pre.open_errors,
        unresolvable_candidates,
        scope_boundaries: inputs.scope_boundaries.clone(),
    };
    let scan = Scan {
        id: inputs.scan_id.clone(),
        generation: inputs.generation,
        epoch: inputs.epoch,
        catalog_revision: inputs.catalog_revision,
        target_url: inputs.target_url.clone(),
        canonical_url: inputs.canonical_url.clone(),
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
        let mut cache: HashMap<i64, Vec<u8>> = HashMap::new();
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
    let mut synthetics = pre.interner.synthetics.clone();
    synthetics.sort_by(|a, b| a.0.cmp(&b.0));
    for (id, bytes) in &synthetics {
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
                    symbolic_target, upstream, state, observed_at_ms \
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
            })?;
            stats.branches += 1;
        }
    }
    stream.end_array()?;

    // Remotes (effective fetch/push observations; URLs already redacted at
    // inspection time, never carrying credentials into the report).
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
            stream.array_item(&Remote {
                id: req_text(&row, 0)?,
                repository_id: instance_id,
                checkout_scope_id: scope,
                name: encode_name(&req_blob(&row, 3)?),
                role: req_text(&row, 4)?,
                url: String::from_utf8_lossy(&req_blob(&row, 5)?).into_owned(),
                canonical_url: opt_blob(&row, 6)?
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
                observed_at: ms_to_rfc3339(req_i64(&row, 7)?),
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
            evidence: link.evidence.clone(),
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
            reason: candidate.reason.clone(),
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
                message: req_text(&row, 3)?,
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

/// Parse staged bytes back into a validated [`Report`]. Used by the
/// REPORT-01 gate, the terminal renderer, and publication retries. This
/// loads the report into memory; production file publication streams
/// without this step.
pub fn verify_staged_report(staged: &Path) -> crate::Result<Report> {
    let bytes = std::fs::read(staged)?;
    let report: Report = serde_json::from_slice(&bytes).map_err(|e| {
        Error::Report(format!(
            "staged report {} is not valid JSON: {e}",
            staged.display()
        ))
    })?;
    validate_report(&report)?;
    Ok(report)
}

/// Emission pipeline: stage, retain the immutable snapshot, then publish
/// to a file or render to the terminal. Snapshot readers are always
/// released before any external write (spec §15).
pub struct ReportPipeline;

impl ReportPipeline {
    /// Stream the report into controlled staging, retain the snapshot, and
    /// publish to `dest`. On publication failure the snapshot is retained,
    /// its state is marked `failed`, and the error is returned; retry with
    /// [`ReportPipeline::retry_publication`] without repeating discovery.
    pub async fn emit_to_file(
        store: &crate::store::TursoStore,
        inputs: &ReportInputs,
        dest: &Path,
        state_dir: &Path,
        staging_dir: &Path,
        snapshot_dir: &Path,
        now_ms: i64,
    ) -> crate::Result<crate::report::Publication> {
        let staged = stage_report(store, inputs, staging_dir).await?;
        let receipt = retain_snapshot(
            store,
            &staged,
            snapshot_dir,
            &inputs.report_id,
            inputs.catalog_revision,
            inputs.generation,
            now_ms,
        )
        .await?;
        let published: crate::Result<PublishReceipt> =
            crate::report::publish::publish_staged(&receipt.path, dest, state_dir);
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

    /// Stream the report into controlled staging, retain the snapshot, and
    /// render a readable summary to `terminal` (normally stdout).
    pub async fn emit_to_terminal(
        store: &crate::store::TursoStore,
        inputs: &ReportInputs,
        staging_dir: &Path,
        snapshot_dir: &Path,
        now_ms: i64,
        terminal: &mut dyn std::io::Write,
    ) -> crate::Result<crate::report::Publication> {
        let staged = stage_report(store, inputs, staging_dir).await?;
        let receipt = retain_snapshot(
            store,
            &staged,
            snapshot_dir,
            &inputs.report_id,
            inputs.catalog_revision,
            inputs.generation,
            now_ms,
        )
        .await?;
        let report = verify_staged_report(&receipt.path)?;
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
        let report = verify_staged_report(snapshot_path)?;
        if report.report_id != report_id {
            return Err(Error::Report(format!(
                "snapshot {} holds report {}, not {report_id}",
                snapshot_path.display(),
                report.report_id
            )));
        }
        match crate::report::publish::publish_staged(snapshot_path, dest, state_dir) {
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

/// Stream the report into a fresh staging file and sync it. The database
/// reader is released before this returns.
async fn stage_report(
    store: &crate::store::TursoStore,
    inputs: &ReportInputs,
    staging_dir: &Path,
) -> crate::Result<PathBuf> {
    std::fs::create_dir_all(staging_dir)?;
    let staged = staging_dir.join(format!(
        ".staging-{}-{}-{}.json",
        std::process::id(),
        crate::store::now_ms(),
        inputs.report_id
    ));
    if staged.exists() {
        return Err(Error::Report(format!(
            "staging file already exists: {}",
            staged.display()
        )));
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)?;
    let (mut file, _stats) = stream_report_from_store(store, inputs, file).await?;
    file.flush()?;
    file.sync_all()?;
    Ok(staged)
}
