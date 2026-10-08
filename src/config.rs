//! Configuration and the spec §5 resource table defaults.
//! Hard admission limits vs buffer bounds vs measured targets are kept
//! distinct, exactly as §5 requires.
//!
//! This module also carries the CLI-owned support helpers: state-directory
//! and report-destination resolution (absolute exactly once), scan/report
//! identity, scan-outcome encoding, durable scope-key codecs, and the
//! ownership-wait and payload-safety constants used by the binary.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Hard ceiling for parallel read workers (Step 8 explicit worker
/// limit): `--workers` values above this clamp down, never fail. The
/// bound keeps thread, descriptor, and helper pressure finite even on
/// large machines; admission permits below still gate each worker.
pub const MAX_WORKERS: usize = 32;

/// Fallback worker count when the platform reports no parallelism.
pub const DEFAULT_WORKERS_FALLBACK: usize = 4;

/// Default parallel read workers: the platform's available parallelism
/// clamped to `[1, MAX_WORKERS]`, or [`DEFAULT_WORKERS_FALLBACK`] when
/// the platform reports none. Step 16 measures worker settings against
/// this default; it is a starting point, not a tuned optimum.
pub fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(DEFAULT_WORKERS_FALLBACK)
        .clamp(1, MAX_WORKERS)
}

/// Effective worker count for a scan: the explicit `--workers` request
/// clamped to `[1, MAX_WORKERS]`, or [`default_workers`] when the flag
/// is absent. A zero request is a CLI error, not a clamp — it is
/// rejected at the argument boundary before this runs.
pub fn effective_workers(requested: Option<usize>) -> usize {
    requested
        .unwrap_or_else(default_workers)
        .clamp(1, MAX_WORKERS)
}

/// Restore a saved `--workers` request on resume (v4): `None` stays
/// `None` (the runtime default applies); a saved value clamps to
/// `[1, MAX_WORKERS]` before narrowing so a corrupt huge value can
/// neither overflow `usize` nor surprise. A saved zero resolves to
/// `None` — resume stays resilient instead of failing on a value the
/// CLI boundary would never have persisted.
pub fn restore_workers(saved: Option<u64>) -> Option<usize> {
    match saved {
        None | Some(0) => None,
        Some(w) => Some(w.min(MAX_WORKERS as u64) as usize),
    }
}

/// Scale [`ResourceLimits`] admission for `workers` parallel readers
/// (Step 8 worker pool): per-class operation permits and the shared
/// pool grow with the worker count, and the CPU governor target moves
/// from the legacy one-core policy to one core per worker. Absolute
/// process-wide budgets — helpers, descriptors, prefetch, writer
/// batches — stay fixed: more workers contend for the same bounded
/// resources instead of multiplying them.
pub fn effective_limits(workers: Option<usize>) -> ResourceLimits {
    let n = effective_workers(workers);
    ResourceLimits {
        max_enum_ops: n,
        max_git_probes: n,
        shared_permits: n,
        cpu_target_cores: n as f64,
        ..ResourceLimits::default()
    }
}

/// Hard admission + buffer defaults from the spec §5 resource table.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Active enumeration operations (hard max): 2.
    pub max_enum_ops: usize,
    /// Active Git probes (hard max): 1.
    pub max_git_probes: usize,
    /// Shared expensive-operation permits (hard max): 2. Enum + Git slots
    /// are NOT additive permission to exceed this.
    pub shared_permits: usize,
    /// Helper processes incl. idle and still-stuck (hard max): 4.
    pub max_helpers: usize,
    /// Scheduler prefetch task cap: 1,024.
    pub prefetch_tasks: usize,
    /// Scheduler prefetch byte cap: 4 MiB.
    pub prefetch_bytes: usize,
    /// Enumeration IPC batch entry cap: 256.
    pub batch_entries: usize,
    /// Enumeration IPC batch byte cap: 256 KiB.
    pub batch_bytes: usize,
    /// Pending producer batches per producer: 2.
    pub pending_batches_per_producer: usize,
    /// Writer batch row cap: 512.
    pub writer_rows: usize,
    /// Writer batch byte cap: 512 KiB.
    pub writer_bytes: usize,
    /// Writer maximum batch age (NOT a fixed sleep): 250 ms.
    pub writer_max_age: Duration,
    /// Application data descriptors under app control: 64.
    pub max_app_fds: usize,
    /// Progress refresh: at most 2 Hz.
    pub progress_max_hz: u32,
    /// Resource telemetry: at most 1 Hz.
    pub telemetry_max_hz: u32,
    /// CPU target: one logical core over rolling 10 s (feedback target).
    pub cpu_target_cores: f64,
    /// Aggregate RSS target incl. owner + helpers: 256 MiB.
    pub rss_target_bytes: u64,
    /// Memory-pressure response threshold: 512 MiB.
    pub pressure_threshold_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_enum_ops: 2,
            max_git_probes: 1,
            shared_permits: 2,
            max_helpers: 4,
            prefetch_tasks: 1024,
            prefetch_bytes: 4 * 1024 * 1024,
            batch_entries: 256,
            batch_bytes: 256 * 1024,
            pending_batches_per_producer: 2,
            writer_rows: 512,
            writer_bytes: 512 * 1024,
            writer_max_age: Duration::from_millis(250),
            max_app_fds: 64,
            progress_max_hz: 2,
            telemetry_max_hz: 1,
            cpu_target_cores: 1.0,
            rss_target_bytes: 256 * 1024 * 1024,
            pressure_threshold_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Effective tool configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Resolved absolute state directory.
    pub state_dir: PathBuf,
    /// Resource budgets.
    pub resources: ResourceLimits,
}

impl Config {
    /// Build from an optional `--state-dir` override. The directory is
    /// resolved to an absolute path exactly once, here; invalid values are
    /// exit 2.
    pub fn load(state_dir: Option<PathBuf>) -> crate::Result<Self> {
        let dir = resolve_state_dir(state_dir)?;
        Ok(Self {
            state_dir: dir,
            resources: ResourceLimits::default(),
        })
    }
}

/// Default state directory, resolved once to an absolute path (spec §3).
/// macOS: `~/Library/Application Support/repo-scan`. Never a temp dir.
pub fn default_state_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        match std::env::var("HOME") {
            Ok(home) => PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("repo-scan"),
            Err(_) => PathBuf::from("Library/Application Support/repo-scan"),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
            PathBuf::from(xdg).join("repo-scan")
        } else {
            match std::env::var("HOME") {
                Ok(home) => PathBuf::from(home).join(".local/state/repo-scan"),
                Err(_) => PathBuf::from(".local/state/repo-scan"),
            }
        }
    }
}

/// How long a second process waits for the owner lock before reporting a
/// clear error instead of opening the database independently.
pub const OWNER_WAIT_MAX_MS: u64 = 5_000;
/// Poll interval inside the bounded owner wait.
pub const OWNER_WAIT_POLL_MS: u64 = 100;

/// Payload subdirectory holding internal derived report snapshots.
pub const SNAPSHOTS_DIR_NAME: &str = "report-snapshots";
/// Payload subdirectory holding report staging files.
pub const STAGING_DIR_NAME: &str = "staging";
/// Exact known engine files inside `payload/` a clear may remove.
pub const KNOWN_ENGINE_FILES: &[&str] = &["catalog.db"];
/// Exact known engine sidecars inside `payload/` a clear may remove.
/// `catalog.db-tshm` is the multiprocess-WAL coordinator probe target: the
/// vendored engine compiles with `host_shared_wal` on 64-bit unix/windows
/// and path-probes it on every legacy open (RS-PRIV-11), so a planted or
/// stale file must clear with the rest. Keep in sync with
/// `store::catalog::DB_SIDECAR_SUFFIXES`.
pub const KNOWN_SIDECAR_FILES: &[&str] = &[
    "catalog.db-wal",
    "catalog.db-shm",
    "catalog.db-journal",
    "catalog.db-tshm",
];

/// Resolve the effective state directory to an absolute path exactly once:
/// leading `~` expansion, then one join against the current directory when
/// relative, then lexical cleanup. No filesystem access beyond reading the
/// current directory, so this never depends on the target existing.
pub fn resolve_state_dir(input: Option<PathBuf>) -> crate::Result<PathBuf> {
    let raw = input.unwrap_or_else(default_state_dir);
    absolutize_once(&expand_tilde(&raw)?)
}

/// Resolve a report destination (or explicit scan root) to an absolute path
/// exactly once, at request-creation time. Resume reuses the stored absolute
/// path and never consults the caller's current directory.
pub fn resolve_report_dest(path: &Path) -> crate::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(crate::Error::InvalidArgs(
            "empty report destination".to_string(),
        ));
    }
    absolutize_once(&expand_tilde(path)?)
}

/// Resolve a local target path (leading `~` expansion, current-directory join,
/// and lexical cleanup).
pub fn resolve_target_path(path: &Path) -> crate::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(crate::Error::InvalidArgs("empty target path".to_string()));
    }
    absolutize_once(&expand_tilde(path)?)
}

/// Join a relative path against the current directory exactly once, then
/// clean `.`/`..` lexically. Absolute paths are only cleaned.
fn absolutize_once(path: &Path) -> crate::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(clean_absolute(path));
    }
    let cwd = std::env::current_dir()
        .map_err(|e| crate::Error::Config(format!("cannot read working directory: {e}")))?;
    Ok(clean_absolute(&cwd.join(path)))
}

/// Lexical `.`/`..` cleanup that never touches the filesystem (so it works
/// for not-yet-existing destinations and never follows symlinks).
pub fn clean_absolute(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        out
    }
}

/// Expand a leading `~` or `~/...` against `HOME`, preserving non-UTF-8
/// remainder bytes on unix.
#[cfg(unix)]
fn expand_tilde(path: &Path) -> crate::Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if bytes != b"~" && !bytes.starts_with(b"~/") {
        return Ok(path.to_path_buf());
    }
    let home = std::env::var("HOME")
        .map_err(|_| crate::Error::Config("cannot expand ~: HOME is not set".to_string()))?;
    if home.is_empty() {
        return Err(crate::Error::Config(
            "cannot expand ~: HOME is empty".to_string(),
        ));
    }
    let mut out = PathBuf::from(home);
    if bytes.len() > 1 {
        out.push(std::ffi::OsStr::from_bytes(&bytes[2..]));
    }
    Ok(out)
}

/// Expand a leading `~` or `~/...` against `HOME` (non-unix fallback).
#[cfg(not(unix))]
fn expand_tilde(path: &Path) -> crate::Result<PathBuf> {
    let text = path.as_os_str().to_string_lossy();
    if text != "~" && !text.starts_with("~/") {
        return Ok(path.to_path_buf());
    }
    let home = std::env::var("HOME")
        .map_err(|_| crate::Error::Config("cannot expand ~: HOME is not set".to_string()))?;
    if home.is_empty() {
        return Err(crate::Error::Config(
            "cannot expand ~: HOME is empty".to_string(),
        ));
    }
    let mut out = PathBuf::from(home);
    let rest = text[1..].trim_start_matches('/');
    if !rest.is_empty() {
        out.push(rest);
    }
    Ok(out)
}

/// Exact path bytes, losslessly on unix.
#[cfg(unix)]
pub fn path_as_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

/// Best-effort path bytes (non-unix fallback).
#[cfg(not(unix))]
pub fn path_as_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_string_lossy().into_owned().into_bytes()
}

/// Rebuild a path from exact bytes, losslessly on unix.
#[cfg(unix)]
pub fn path_from_bytes(bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

/// Rebuild a path from bytes (non-unix fallback).
#[cfg(not(unix))]
pub fn path_from_bytes(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(&bytes).into_owned())
}

/// Lowercase hex encoding (path bytes in scope keys, stable row IDs).
pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decode [`encode_hex`] output; `None` on any malformed input.
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

static SCAN_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// A fresh unique scan-request ID. A per-process counter plus pid plus
/// wall-clock milliseconds keeps IDs unique across concurrent owners.
pub fn new_scan_id() -> String {
    let n = SCAN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("scan-{}-{}-{n}", std::process::id(), crate::store::now_ms())
}

/// Keep filename-safe characters for derived snapshot/report IDs.
pub fn sanitize_id(id: &str) -> String {
    let cleaned: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        String::from("unnamed")
    } else {
        cleaned
    }
}

/// Deterministic snapshot/report ID for a scan request, so a failed report
/// publication can be retried against the saved snapshot without repeating
/// discovery, and completed resumes replay the original snapshot.
pub fn report_id_for_scan(scan_id: &str) -> String {
    format!("report-{}", sanitize_id(scan_id))
}

/// Snapshot-bytes path inside the payload namespace:
/// `<state_dir>/payload/report-snapshots/<report_id>.json`. Refuses IDs
/// that could escape the snapshots directory.
pub fn snapshot_path(state_dir: &Path, report_id: &str) -> crate::Result<PathBuf> {
    if report_id.is_empty()
        || report_id == "."
        || report_id == ".."
        || !report_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
    {
        return Err(crate::Error::Config(format!(
            "unsafe report ID for snapshot storage: {report_id:?}"
        )));
    }
    Ok(crate::store::owner::payload_dir(state_dir)
        .join(SNAPSHOTS_DIR_NAME)
        .join(format!("{report_id}.json")))
}

/// Scan-request outcome persisted in `scan_requests.outcome`, parsed back by
/// resume for idempotent terminal replay and publication retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedOutcome {
    /// Final process exit code of the recorded run.
    pub exit_code: i32,
    /// Discovery verdict underneath publication (0 or 3); `None` when the
    /// run never reached publication.
    pub discovery_code: Option<i32>,
    /// Immutable snapshot/report ID retained in state.
    pub report_id: String,
    /// Whether the external destination holds the report.
    pub published: bool,
    /// Traversal generation the run covered, when known.
    pub generation: Option<u64>,
}

/// Encode a scan outcome as space-separated `key=value` pairs (report IDs
/// never contain whitespace, so this round-trips exactly).
pub fn encode_outcome(
    exit_code: i32,
    discovery_code: Option<i32>,
    report_id: &str,
    published: bool,
    generation: Option<u64>,
) -> String {
    let mut parts = vec![
        format!("exit={exit_code}"),
        format!("report={report_id}"),
        format!("published={}", i32::from(published)),
    ];
    if let Some(code) = discovery_code {
        parts.push(format!("discovery={code}"));
    }
    if let Some(generation) = generation {
        parts.push(format!("gen={generation}"));
    }
    parts.join(" ")
}

/// Parse [`encode_outcome`] output; `None` on any malformed input.
pub fn parse_outcome(text: &str) -> Option<DecodedOutcome> {
    let mut exit_code = None;
    let mut discovery_code = None;
    let mut report_id = None;
    let mut published = None;
    let mut generation = None;
    for part in text.split_whitespace() {
        let (key, value) = part.split_once('=')?;
        match key {
            "exit" => exit_code = Some(value.parse::<i32>().ok()?),
            "discovery" => discovery_code = Some(value.parse::<i32>().ok()?),
            "report" => {
                if value.is_empty() {
                    return None;
                }
                report_id = Some(value.to_string());
            }
            "published" => {
                published = Some(match value {
                    "0" => false,
                    "1" => true,
                    _ => return None,
                });
            }
            "gen" => generation = Some(value.parse::<u64>().ok()?),
            _ => return None,
        }
    }
    Some(DecodedOutcome {
        exit_code: exit_code?,
        discovery_code,
        report_id: report_id?,
        published: published?,
        generation,
    })
}

/// A parsed durable scope key. Directory and Git scopes carry exact path
/// bytes as hex (lossless, separator-safe); status scopes carry ASCII
/// checkout IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeRef {
    /// `dir:<hex path bytes>`: enumerate one directory.
    Dir(PathBuf),
    /// `git:<hex path bytes>`: probe one Git candidate.
    Git(PathBuf),
    /// `status:<checkout id>`: inspect one checkout's working state.
    Status(String),
}

/// Shared scope-path canonicalizer (DB-M1): absolute paths resolve
/// through the filesystem (`std::fs::canonicalize`, so symlink
/// spellings collapse onto the physical path); failures (missing
/// paths, permission errors) and relative paths pass through
/// unchanged. The generation key, execution paths, and invalidation
/// fan-out share this one spelling rule — while scope keys
/// themselves keep observed spellings (execution derives task paths
/// from keys, and reports show observed paths per goal Step 7).
pub fn canonical_scope_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    }
}

/// Normalize a scope path without consulting the filesystem. This is the
/// deterministic fallback used when bounded root identity lookup cannot
/// finish; symlinks remain distinct in that case, which may start a fresh
/// generation but cannot reuse coverage under an unverified alias.
pub fn normalize_scope_path(path: &Path) -> PathBuf {
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

/// Scope key for directory enumeration / reconciliation of `path`.
/// Keeps the observed spelling: execution derives task paths from
/// keys, and cross-spelling invalidation is closed by fan-out (see
/// `invalidate_scope_on`), not by collapsing spellings here.
pub fn scope_key_for_dir(path: &Path) -> String {
    format!("dir:{}", encode_hex(&path_as_bytes(path)))
}

/// Scope key for a Git probe at `path`. Keeps the observed spelling
/// like [`scope_key_for_dir`].
///
/// Never DIRECTLY invalidated (DB-m7): Git probes and status probes
/// are idempotent point reads — each generation enqueues its own
/// probe tasks, and a probe executes and completes under one
/// short-held lease. Only `dir:`/`volume:`/`mounts` scopes
/// (traversal coverage) invalidate directly; the DB-M1 spelling
/// fan-out may additionally bump a live probe's `git:` key when the
/// same object invalidates under another spelling (the probe then
/// requeues like any stale task — same gate, no special case).
pub fn scope_key_for_git(path: &Path) -> String {
    format!("git:{}", encode_hex(&path_as_bytes(path)))
}

/// Scope key for a working-state probe of `checkout_id`.
///
/// Intentionally never invalidated (DB-m7): see
/// [`scope_key_for_git`].
pub fn scope_key_for_status(checkout_id: &str) -> String {
    format!("status:{checkout_id}")
}

/// Parse a scope key; `None` on any malformed input. Status IDs must be
/// ASCII without path separators or whitespace.
pub fn parse_scope_key(key: &str) -> Option<ScopeRef> {
    if let Some(hex) = key.strip_prefix("dir:") {
        return Some(ScopeRef::Dir(path_from_bytes(decode_hex(hex)?)));
    }
    if let Some(hex) = key.strip_prefix("git:") {
        return Some(ScopeRef::Git(path_from_bytes(decode_hex(hex)?)));
    }
    if let Some(id) = key.strip_prefix("status:") {
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-'))
        {
            return None;
        }
        return Some(ScopeRef::Status(id.to_string()));
    }
    None
}

/// Non-terminal scan-state name, carrying the explicit roots (hex, comma
/// separated) for roots-scoped requests so resume restores them without
/// depending on the caller's current directory. Machine scope keeps the
/// bare base name; terminal states are always bare.
pub fn scan_state_name(base: &str, roots: Option<&[PathBuf]>) -> String {
    match roots {
        Some(roots) if !roots.is_empty() && base != "complete" && base != "superseded" => {
            let hexes: Vec<String> = roots
                .iter()
                .map(|r| encode_hex(&path_as_bytes(r)))
                .collect();
            format!("{base}:roots:{}", hexes.join(","))
        }
        _ => base.to_string(),
    }
}

/// Split a scan-state name into its base (`running`, `complete`, ...) plus
/// the carried explicit roots, if any.
pub fn split_scan_state(state: &str) -> (&str, Option<Vec<PathBuf>>) {
    let Some((base, rest)) = state.split_once(':') else {
        return (state, None);
    };
    let Some(hexes) = rest.strip_prefix("roots:") else {
        return (base, None);
    };
    let mut roots = Vec::new();
    for hex in hexes.split(',') {
        let Some(bytes) = decode_hex(hex) else {
            return (base, None);
        };
        roots.push(path_from_bytes(bytes));
    }
    if roots.is_empty() {
        (base, None)
    } else {
        (base, Some(roots))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_counts_clamp_and_scale_without_moving_absolutes() {
        assert_eq!(effective_workers(Some(4)), 4);
        assert_eq!(effective_workers(Some(1)), 1);
        assert_eq!(effective_workers(Some(usize::MAX)), MAX_WORKERS);
        let d = default_workers();
        assert!((1..=MAX_WORKERS).contains(&d));
        assert_eq!(effective_workers(None), d);
        assert_eq!(restore_workers(None), None);
        assert_eq!(restore_workers(Some(0)), None);
        assert_eq!(restore_workers(Some(5)), Some(5));
        assert_eq!(restore_workers(Some(u64::MAX)), Some(MAX_WORKERS));
        let limits = effective_limits(Some(6));
        assert_eq!(
            (
                limits.max_enum_ops,
                limits.max_git_probes,
                limits.shared_permits,
                limits.cpu_target_cores,
            ),
            (6, 6, 6, 6.0)
        );
        let base = ResourceLimits::default();
        assert_eq!(
            (
                limits.max_helpers,
                limits.max_app_fds,
                limits.prefetch_tasks,
                limits.writer_rows,
            ),
            (
                base.max_helpers,
                base.max_app_fds,
                base.prefetch_tasks,
                base.writer_rows,
            )
        );
    }

    #[test]
    fn normalize_scope_path_is_lexical_and_keeps_relative_roots_relative() {
        assert_eq!(
            normalize_scope_path(Path::new("a/./b/../c")),
            PathBuf::from("a/c")
        );
        assert_eq!(
            normalize_scope_path(Path::new("../../a/../b")),
            PathBuf::from("../../b")
        );
    }

    /// DB-M1: the shared canonicalizer collapses symlink spellings
    /// onto the physical path (symlink and target agree); scope keys
    /// themselves keep observed spellings (execution derives task
    /// paths from keys) while invalidation fan-out closes the miss.
    /// Missing paths fall back lexically, relative paths pass through
    /// untouched.
    #[cfg(unix)]
    #[test]
    fn canonical_scope_path_collapses_symlink_spellings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        std::fs::create_dir(&real).expect("mkdir");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert_eq!(canonical_scope_path(&link), canonical_scope_path(&real));
        // Keys keep observed spellings (execution + reports show what
        // the user scheduled, per goal Step 7).
        assert_ne!(scope_key_for_dir(&link), scope_key_for_dir(&real));
        assert_eq!(
            parse_scope_key(&scope_key_for_dir(&link)),
            Some(ScopeRef::Dir(link.clone())),
            "keys round-trip the observed spelling"
        );
        // Missing paths fall back to the lexical spelling (never an
        // error): a dangling link canonicalizes to itself.
        let missing = dir.path().join("missing");
        let missing_link = dir.path().join("missing-link");
        std::os::unix::fs::symlink(&missing, &missing_link).expect("symlink");
        assert_eq!(canonical_scope_path(&missing_link), missing_link);
        assert_ne!(
            canonical_scope_path(&missing_link),
            canonical_scope_path(&real)
        );
        // Relative paths pass through (no cwd consult at key time).
        let relative = PathBuf::from("some/relative/dir");
        assert_eq!(canonical_scope_path(&relative), relative);
    }
}
