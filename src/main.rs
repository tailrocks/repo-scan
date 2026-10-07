//! Binary entry point: parse CLI, dispatch to handlers, exit with the
//! spec §3 code (0/1/2/3/130). Clap parse failures exit 2 by default.
//!
//! Execution model: this process acquires the state-directory owner lock
//! (bounded wait, then a clear error — never an independent database open
//! beside a live owner), opens the catalog as the owner on a single-threaded
//! runtime, and drives the durable frontier sequentially: claim bounded
//! work, execute one task through the [`Admission`] gates, persist findings,
//! complete with the store's epoch/lease/revision guards. Sequential
//! execution keeps exactly one operation admitted at a time, inside every
//! spec §5 hard limit (2 enum, 1 Git probe, 2 shared, 0 helper processes).

use clap::Parser;
use repo_scan::cli::{CacheAction, Cli, Command};
use repo_scan::config;
use repo_scan::events::{self, CursorJournal};
use repo_scan::git::{self, GitInspect};
use repo_scan::identity;
use repo_scan::model::{ExitCode, Scope, StatusMode, TaskState};
use repo_scan::platform::MountTable;
use repo_scan::report::builder::{
    verify_staged_report, AliasInput, ArtifactInput, CandidateInput,
    ReportInputs as LibReportInputs, ReportPipeline, RootInput, StorageLinkInput,
};
use repo_scan::scan_events::{
    classify_cursor, is_progress_coalescible, is_terminal_event, retention_cutoff, Cursor,
    Envelope, EventType, Op, ResumeAction, MAX_RETAINED_SCAN_EVENTS,
};
use repo_scan::scheduler::{backoff_for_attempt, Admission, CircuitBreaker, OpClass, Permit};
#[cfg(test)]
use repo_scan::store::FrontierTask;
use repo_scan::store::{
    self, CheckpointCoordinator, CheckpointPolicy, ClaimedTask, CompletionDelta, CompletionGap,
    NewCheckout, NewGitInstance, NewRef, NewRemote, NewRemoteRefresh, NewScan, NewScanEvent,
    NewStatus, NewTask, NewVolume, OwnerGuard, ScanEventRow, Store, TaskOutcome, TursoStore,
    WriterBatch,
};
use repo_scan::telemetry::{live_helper_rss_bytes, FootprintSampler, SamplerInputs};
use repo_scan::walk::roots::{plan_machine_roots, PlannedRoot, RootPriority};
use repo_scan::walk::topology::{
    resolve_symlink, DirStat, FenceError, FenceOpen, PhysicalDirId, PinnedDir, ResolveError,
    ScopeFence, Topology,
};
use repo_scan::walk::{ChildKind, ListOptions, WalkItem};
use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};

/// Set by the SIGINT handler; the scan loop polls it between tasks and
/// between enumeration chunks, then performs the bounded save and exits 130.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Durable task kinds executed by the owner loop.
const KIND_ENUM: &str = "enumerate_dir";
const KIND_PROBE: &str = "probe_git";
const KIND_STATUS: &str = "status";
const KIND_RECONCILE: &str = "reconcile";
const KIND_ANALYZE: &str = "analyze_store";

/// Drain phase (goal Step 8): discovery claims enumeration, probes,
/// and reconciliation only; analysis kinds (`status`, `analyze_store`)
/// wait for the post-`inventory_ready` drain. Enqueue sites stay
/// unrestricted — execution is gated at claim time, so pre-boundary
/// enqueues (probe-scheduled status/analysis) simply wait their turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainPhase {
    Discovery,
    Analysis,
}

impl DrainPhase {
    fn kinds(self) -> &'static [&'static str] {
        match self {
            DrainPhase::Discovery => &[KIND_ENUM, KIND_PROBE, KIND_RECONCILE],
            DrainPhase::Analysis => &[KIND_ANALYZE, KIND_STATUS],
        }
    }
}

/// Tasks claimed per scheduler round (far below the 1,024 prefetch cap).
const CLAIM_BATCH: usize = 16;
/// Bound for the post-traversal history-close wait (RSF-F940): the
/// checked completeness claim needs the `HistoryDone` sentinel on
/// every history-expected volume, and delivery is asynchronous — the
/// pre-traversal drain races stream startup. The scan polls
/// non-blocking drains until every such volume's history closes or
/// this bound expires; expiry is a fail-closed timeout (the claim
/// fails honestly into gaps + exit 3), never a skip. Volumes without
/// live history pay nothing (the closed check is immediately true).
const HISTORY_CLOSE_WAIT: Duration = Duration::from_secs(15);
/// Poll interval inside the history-close wait while no batches arrive.
/// Short enough to catch the sentinel promptly at 0.3 s stream
/// latency, long enough to never busy-spin.
const HISTORY_CLOSE_POLL: Duration = Duration::from_millis(100);
/// Lease TTL granted per claim.
const LEASE_TTL_MS: i64 = 60_000;
/// Transient failures before a task parks as unavailable.
const MAX_ATTEMPTS: u64 = 5;
/// Per-task soft watchdog: slower tasks emit a stderr diagnostic.
const SLOW_TASK_SECS: u64 = 30;
/// Per-operation no-progress watchdog grace (R9): evaluated once per task
/// after it returns via [`watchdog_verdict`]. An over-grace task with no
/// observed progress is contained (volume breaker + preserved gap +
/// stderr); an over-grace task that produced entries or completed
/// directories is advancing and is never contained. Bounded: at most one
/// grace period of stall per operation before containment engages.
const WATCHDOG_GRACE_SECS: u64 = 120;
/// Circuit-breaker threshold and cooldown per volume (spec §14).
const BREAKER_THRESHOLD: u32 = 3;
const BREAKER_COOLDOWN: Duration = Duration::from_secs(60);
/// Tool-ownership marker filename inside the payload namespace (R15). Written
/// on every owned open; verified before any destructive `cache clear`.
/// Single definition in `store::owner` (RS-PRIV-02/05).
use repo_scan::store::owner::OWNER_MARKER_NAME;
/// Marker format tag (first line of the marker file).
use repo_scan::store::owner::OWNER_MARKER_TAG;
/// Pending-outcome exit sentinel (R14): a scan row carrying this exit in its
/// outcome column has no terminal outcome yet; the outcome only binds the
/// traversal generation the scan runs in.
const PENDING_EXIT: i32 = -1;
/// Cap on report-ID restage attempts for one scan (R16): every staging
/// attempt gets an immutable snapshot ID; suffixes beyond this are a bug.
const MAX_REPORT_ATTEMPTS: u32 = 1_000;
/// Bytes of the engine file scanned for catalog schema markers (R15).
const DB_IDENTITY_SCAN_BYTES: u64 = 64 * 1024;
/// RS-PRIV-09 budgets: snapshot/clear/query paths never do unbounded work.
/// Budget exhaustion is reported as INCOMPLETE coverage, never as a
/// complete cleanup or a full answer.
/// Max entries scanned per clear directory (snapshots/staging/payload).
const CLEAR_MAX_FILES_PER_DIR: usize = 50_000;
/// Max total bytes hashed while verifying clear candidates.
const CLEAR_MAX_BYTES_HASHED: u64 = 4 * 1024 * 1024 * 1024;
/// Max preserved entries accumulated (display already caps at 20).
const CLEAR_MAX_PRESERVED: usize = 10_000;
/// Wall-clock budget for one `cache clear`.
const CLEAR_DEADLINE_SECS: u64 = 600;
/// Max snapshot stems resolved to checksum rows per clear.
const SNAPSHOT_MAX_STEMS: usize = 10_000;
/// Max generations / matches served by one cached query.
const QUERY_MAX_GENERATIONS: usize = 1_024;
const QUERY_MAX_MATCHES: usize = 10_000;
/// Wall-clock budget for one cached query.
const QUERY_DEADLINE_SECS: u64 = 60;
/// Journal rows per replay page for `query --scan` (D4): bounded reads,
/// oldest first; a short page means the reader caught up to the tip.
const REPLAY_PAGE_ROWS: u64 = 500;
/// Poll interval for `query --scan --follow` while the scan is still
/// running and no terminal event is journaled yet.
const FOLLOW_POLL: Duration = Duration::from_millis(250);
/// Rows per catalog page for bounded report-derivation scans
/// (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1): errors, instances, and
/// reclassification reads never hold more than one page from the database
/// cursor at a time; only report-required derived records accumulate.
const LOAD_CHUNK_ROWS: i64 = 512;
/// Cap on distinct pathname aliases held per run (A-F5), mirroring
/// [`note_applied_scopes`]: past the cap new aliases drop and one
/// `alias-overflow` gap row documents the loss.
const MAX_ALIASES: usize = 4096;
/// Cap on distinct probed Git identities held per run (A-F5), mirroring
/// [`note_applied_scopes`]: past the cap new identities persist without
/// dedupe and one `probe-index-overflow` gap row documents the loss.
const MAX_PROBED_GIT_IDS: usize = 4096;
/// Identity re-verification poll interval DURING Git inspection (XSEC-01).
/// Between fast read stages the poll is interval-gated (a re-resolution
/// costs microseconds; Git reads cost milliseconds); stage boundaries
/// around slow reads and the pre-store gate always check. Residual: a
/// swap fully contained inside one poll gap AND restored before the next
/// check escapes detection — microseconds around a stage poll, up to one
/// interval inside the status watch thread. Post-run verification still
/// catches every net change.
const IDENT_POLL_INTERVAL: Duration = Duration::from_millis(25);
/// Per-task total execution budget (SR-STATE-01): wall time from admission
/// to abandonment, enforced cooperatively at every yield point (enum
/// items, probe read stages, status interrupt flag). Exceeding it abandons
/// the remaining work and parks the scope with a loud gap; a syscall that
/// never yields cannot be preempted in-process (see [`OpDeadline`).
const OP_DEADLINE_SECS: u64 = 300;

fn main() {
    std::process::exit(dispatch().code());
}

fn dispatch() -> ExitCode {
    install_sigint_handler();
    let cli = Cli::parse();
    let cfg = match config::Config::load(cli.state_dir.clone()) {
        Ok(cfg) => cfg,
        Err(e) => return fail(&e),
    };
    // Single-threaded owner: no backend thread pool can bypass the §5
    // admission gates, and all database work stays on this one context.
    // All drivers on: the pooled drain needs the timer (renewal ticks)
    // and the blocking pool (worker threads).
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return fail(&repo_scan::Error::Store(format!(
                "async runtime init failed: {e}"
            )));
        }
    };
    match &cli.command {
        Command::Scan(args) => rt.block_on(run_scan(&cfg, args)),
        Command::Query(args) => rt.block_on(run_query(&cfg, args)),
        Command::Resume(args) => rt.block_on(run_resume(&cfg, args)),
        Command::Cache(args) => match &args.action {
            CacheAction::Invalidate(args) => rt.block_on(run_invalidate(&cfg, args)),
            CacheAction::Clear(args) => rt.block_on(run_clear(&cfg, args)),
        },
    }
}

/// Report an operational failure on stderr and map it to its exit code.
///
/// The message passes the centralized scrubber (RETEST-7): error strings
/// can embed lower-layer URL material or secret pairs (credential-bearing
/// input echoed by validation, git/config paths), and terminal
/// diagnostics must never emit them raw.
fn fail(e: &repo_scan::Error) -> ExitCode {
    eprintln!("repo-scan: error: {}", identity::scrub_text(&e.to_string()));
    e.exit_code()
}

#[cfg(unix)]
fn install_sigint_handler() {
    // SAFETY: the handler only performs an atomic store, which is
    // async-signal-safe; no process-global state changes.
    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(not(unix))]
fn install_sigint_handler() {}

#[cfg(unix)]
extern "C" fn sigint_handler(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// True when `e` is owner-lock contention (as opposed to an IO/config
/// failure acquiring the lock).
fn is_lock_contention(e: &repo_scan::Error) -> bool {
    matches!(e, repo_scan::Error::Store(m) if m.starts_with("owner lock held"))
}

/// Acquire the owner lock, waiting boundedly for a live owner to finish.
/// Contention ends in a clear [`Error::OwnerBusy`][repo_scan::Error::OwnerBusy],
/// never in an independent database open beside the live owner.
fn acquire_guard(state_dir: &Path) -> repo_scan::Result<OwnerGuard> {
    acquire_guard_with(state_dir, OwnerGuard::acquire)
}

/// Bounded-wait owner lock for `cache clear`: the payload dir is left
/// untouched (possibly unlistable/foreign/absent) for clear's own
/// fail-closed inspection under the held lock.
fn acquire_guard_for_clear(state_dir: &Path) -> repo_scan::Result<OwnerGuard> {
    acquire_guard_with(state_dir, OwnerGuard::acquire_for_clear)
}

fn acquire_guard_with(
    state_dir: &Path,
    acquire: fn(&Path) -> repo_scan::Result<OwnerGuard>,
) -> repo_scan::Result<OwnerGuard> {
    let deadline = Instant::now() + Duration::from_millis(config::OWNER_WAIT_MAX_MS);
    loop {
        match acquire(state_dir) {
            Ok(guard) => return Ok(guard),
            Err(e) => {
                if !is_lock_contention(&e) {
                    return Err(e);
                }
                if Instant::now() >= deadline {
                    return Err(repo_scan::Error::OwnerBusy(format!(
                        "another repo-scan owner holds {} (waited {} ms); \
                         refusing to open the database independently",
                        store::owner::lock_path(state_dir).display(),
                        config::OWNER_WAIT_MAX_MS,
                    )));
                }
                std::thread::sleep(Duration::from_millis(config::OWNER_WAIT_POLL_MS));
            }
        }
    }
}

/// Acquire ownership (bounded wait) and open the catalog as the owner.
async fn open_owned_with_wait(state_dir: &Path) -> repo_scan::Result<(OwnerGuard, TursoStore)> {
    let mut guard = acquire_guard(state_dir)?;
    let store = TursoStore::open(&guard.db_path()).await?;
    guard.set_epoch(store.epoch());
    // Bind the ownership marker to the live catalog identity (R15): `cache
    // clear` later requires this marker (or tool-shaped bytes) before
    // removing the engine file. Best-effort: a marker write failure must
    // not fail the command that owns real work.
    if let Err(e) = write_owner_marker(&store, state_dir).await {
        eprintln!(
            "repo-scan: warning: cannot write ownership marker: {}",
            identity::scrub_text(&e.to_string())
        );
    }
    Ok((guard, store))
}

/// Marker path inside the payload namespace.
fn owner_marker_path(state_dir: &Path) -> PathBuf {
    store::owner::payload_dir(state_dir).join(OWNER_MARKER_NAME)
}

/// (Re)bind `<state_dir>/payload/owner.marker` to the open catalog's `db_id`
/// meta value. The marker proves this payload was opened by this tool; it is
/// verified (not trusted blindly) by `cache clear` alongside the database
/// identity checks.
async fn write_owner_marker(store: &TursoStore, state_dir: &Path) -> repo_scan::Result<()> {
    let db_id = store
        .catalog_db_id()
        .await?
        .unwrap_or_else(|| String::from("unknown"));
    let contents = format!(
        "{OWNER_MARKER_TAG}\ndb_id={db_id}\nwritten_ms={}\npid={}\n",
        store::now_ms(),
        std::process::id(),
    );
    let path = owner_marker_path(state_dir);
    if let Some(parent) = path.parent() {
        store::owner::ensure_private_dir_all(parent)?;
    }
    if is_symlink_path(&path)? {
        return Err(repo_scan::Error::Store(format!(
            "refusing to write through a symlinked ownership marker: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(store::owner::STATE_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    repo_scan::Error::Store(format!(
                        "refusing to write through a symlinked ownership marker: {}",
                        path.display()
                    ))
                } else {
                    repo_scan::Error::from(e)
                }
            })?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    #[cfg(unix)]
    {
        // RS-PRIV-05: fchmod the open FD, never the path (the parent comes
        // from the ancestor-pinned creation primitive above).
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(
            store::owner::STATE_FILE_MODE,
        ))?;
    }
    {
        use std::io::Write as _;
        file.write_all(contents.as_bytes())?;
    }
    Ok(())
}

/// Unix milliseconds as RFC 3339 UTC (`Time` in spec §16), without a
/// date/time dependency (Hinnant's days-from-civil algorithm).
fn ms_to_rfc3339(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// FNV-1a 64 as 16 lowercase hex digits: report checksums and stable
/// evidence IDs. A non-cryptographic integrity checksum, documented here.
fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Presentation text with terminal control characters escaped (lossy display
/// only; `value` always carries the exact bytes).
fn escape_display(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

fn status_mode_str(mode: StatusMode) -> &'static str {
    match mode {
        StatusMode::Metadata => "metadata",
        StatusMode::Summary => "summary",
        StatusMode::Full => "full",
    }
}

fn status_mode_from_str(text: &str) -> Option<StatusMode> {
    match text {
        "metadata" => Some(StatusMode::Metadata),
        "summary" => Some(StatusMode::Summary),
        "full" => Some(StatusMode::Full),
        _ => None,
    }
}

fn disposition_str(d: identity::MatchDisposition) -> &'static str {
    match d {
        identity::MatchDisposition::Confirmed => "confirmed",
        identity::MatchDisposition::Related => "related",
        identity::MatchDisposition::Probable => "probable",
        identity::MatchDisposition::Nonmatch => "nonmatch",
        identity::MatchDisposition::UnresolvableIdentity => "unresolvable_identity",
    }
}

/// True for evidence lines that carry a match verdict (single-target and
/// multi-target phrasings). Reclassification strips these before appending
/// fresh verdicts so repeated runs — including target-set changes between
/// runs — never accumulate stale lines. Probe-structural lines
/// (`matching-policy:`, `config files consulted:`, ...) never match.
fn is_match_verdict_line(line: &str) -> bool {
    line.starts_with("Effective ")
        || line.starts_with("No effective remotes")
        || line.starts_with("reclassified for ")
        || line.starts_with("for target ")
}

/// Best disposition across per-target verdicts (goal Step 6 union matching):
/// any `confirmed` wins, then `related`, then `probable`, then
/// `unresolvable_identity`, else `nonmatch`. Empty input yields `nonmatch`.
fn best_disposition(
    ranks: &[repo_scan::identity::MatchDisposition],
) -> repo_scan::identity::MatchDisposition {
    use repo_scan::identity::MatchDisposition as D;
    let has = |d: D| ranks.contains(&d);
    if has(D::Confirmed) {
        D::Confirmed
    } else if has(D::Related) {
        D::Related
    } else if has(D::Probable) {
        D::Probable
    } else if has(D::UnresolvableIdentity) {
        D::UnresolvableIdentity
    } else {
        D::Nonmatch
    }
}

/// True when stored instance `id` IS the local-target repository named by a
/// `file://` canonical: same path-identity rule as the single-target
/// reclassify/probe paths (common dir, git dir, or their parents).
async fn instance_matches_local_target(
    store: &TursoStore,
    id: &str,
    canonical: &str,
) -> repo_scan::Result<bool> {
    let target_path_str = canonical.strip_prefix("file://").unwrap_or(canonical);
    let t_canon =
        std::fs::canonicalize(target_path_str).unwrap_or_else(|_| PathBuf::from(target_path_str));
    let Ok(Some(inst)) = store.get_git_instance(id).await else {
        return Ok(false);
    };
    let gp = config::path_from_bytes(inst.git_path);
    let cp = config::path_from_bytes(inst.common_path);
    let gp_canon = std::fs::canonicalize(&gp).ok();
    let cp_canon = std::fs::canonicalize(&cp).ok();
    Ok(gp_canon == Some(t_canon.clone())
        || cp_canon == Some(t_canon.clone())
        || gp_canon
            .as_ref()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            == Some(t_canon.clone())
        || cp_canon
            .as_ref()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            == Some(t_canon.clone()))
}

/// Reclassify every stored instance against THIS scan's canonical target
/// from stored remotes (R1): dispositions are per (instance, target) at
/// report time, so scanning URL-B after URL-A never leaks URL-A's matches
/// into URL-B's report (or vice versa). Probe-structural evidence is kept;
/// stale match verdicts are replaced by fresh ones. Only disposition +
/// evidence are rewritten — observation times are untouched. Returns the
/// number of `confirmed` instances (for `scan.targets[].matched_repositories`).
async fn reclassify_for_target(
    store: &TursoStore,
    canonical: &str,
    counters: &mut RunCounters,
) -> repo_scan::Result<u64> {
    // RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1: chunked pages, one
    // in flight at a time; per-row work is unchanged.
    let mut offset: i64 = 0;
    let mut confirmed = 0u64;
    loop {
        let sql = format!(
            "SELECT id, evidence FROM git_instances ORDER BY id ASC \
             LIMIT {LOAD_CHUNK_ROWS} OFFSET {offset}"
        );
        let mut rows = store
            .connection()
            .query(sql.as_str(), ())
            .await
            .map_err(store_err)?;
        let mut page: Vec<(String, String)> = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            page.push((cell_text(&row, 0)?, cell_text(&row, 1)?));
            if page.len() as i64 >= LOAD_CHUNK_ROWS {
                break;
            }
        }
        if page.is_empty() {
            break;
        }
        let full_page = page.len() as i64 >= LOAD_CHUNK_ROWS;
        for (id, evidence_json) in &page {
            let remotes = store.list_remotes(id).await?;
            let pairs: Vec<(String, String)> = remotes
                .iter()
                .map(|r| (String::from_utf8_lossy(&r.url).into_owned(), r.role.clone()))
                .collect();
            let borrowed: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(url, role)| (url.as_str(), role.as_str()))
                .collect();
            let is_target_repo = if identity::is_local_target(canonical) {
                let target_path_str = canonical.strip_prefix("file://").unwrap_or(canonical);
                let t_canon = std::fs::canonicalize(target_path_str)
                    .unwrap_or_else(|_| PathBuf::from(target_path_str));
                if let Ok(Some(inst)) = store.get_git_instance(id).await {
                    let gp = config::path_from_bytes(inst.git_path);
                    let cp = config::path_from_bytes(inst.common_path);
                    let gp_canon = std::fs::canonicalize(&gp).ok();
                    let cp_canon = std::fs::canonicalize(&cp).ok();
                    gp_canon == Some(t_canon.clone())
                        || cp_canon == Some(t_canon.clone())
                        || gp_canon
                            .as_ref()
                            .and_then(|p| p.parent().map(Path::to_path_buf))
                            == Some(t_canon.clone())
                        || cp_canon
                            .as_ref()
                            .and_then(|p| p.parent().map(Path::to_path_buf))
                            == Some(t_canon.clone())
                } else {
                    false
                }
            } else {
                false
            };
            let (disposition, mut fresh) = if is_target_repo {
                (
                    identity::MatchDisposition::Confirmed,
                    vec![format!(
                        "reclassified for target {canonical} at report time: repository matches local target repository"
                    )],
                )
            } else {
                identity::classify_remotes(canonical, borrowed)
            };
            if disposition == identity::MatchDisposition::Confirmed {
                confirmed += 1;
            }
            let mut evidence: Vec<String> = serde_json::from_str(evidence_json).unwrap_or_default();
            evidence.retain(|line| !is_match_verdict_line(line));
            evidence.push(format!(
                "reclassified for target {canonical} at report time"
            ));
            evidence.append(&mut fresh);
            let evidence_json = serde_json::to_string(&evidence)
                .map_err(|e| repo_scan::Error::Report(e.to_string()))?;
            store
                .connection()
                .execute(
                    "UPDATE git_instances SET disposition = ?1, evidence = ?2 WHERE id = ?3",
                    vec![
                        turso::Value::Text(disposition_str(disposition).to_string()),
                        turso::Value::Text(evidence_json),
                        turso::Value::Text(id.clone()),
                    ],
                )
                .await
                .map_err(store_err)?;
            counters.db_transactions += 1;
        }
        if full_page {
            offset += page.len() as i64;
        } else {
            break;
        }
    }
    Ok(confirmed)
}

/// Reclassify every stored instance against a SET of canonical targets
/// (goal Step 6 union matching: one filesystem pass serves all targets) or
/// `--all` (empty `canonicals`: every discovered instance is in scope and
/// `confirmed`). Same paging shape as [`reclassify_for_target`]; local
/// `file://` canonicals keep the path-identity rule. Per-target evidence is
/// prefixed `for target {canonical}: ...` for attribution. Returns
/// per-target `confirmed` counts aligned with `canonicals` (empty for
/// `--all`).
async fn reclassify_for_targets(
    store: &TursoStore,
    canonicals: &[String],
    counters: &mut RunCounters,
) -> repo_scan::Result<Vec<u64>> {
    let mut matched = vec![0u64; canonicals.len()];
    let mut offset: i64 = 0;
    loop {
        let sql = format!(
            "SELECT id, evidence FROM git_instances ORDER BY id ASC \
             LIMIT {LOAD_CHUNK_ROWS} OFFSET {offset}"
        );
        let mut rows = store
            .connection()
            .query(sql.as_str(), ())
            .await
            .map_err(store_err)?;
        let mut page: Vec<(String, String)> = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            page.push((cell_text(&row, 0)?, cell_text(&row, 1)?));
            if page.len() as i64 >= LOAD_CHUNK_ROWS {
                break;
            }
        }
        if page.is_empty() {
            break;
        }
        let full_page = page.len() as i64 >= LOAD_CHUNK_ROWS;
        for (id, evidence_json) in &page {
            let remotes = store.list_remotes(id).await?;
            let pairs: Vec<(String, String)> = remotes
                .iter()
                .map(|r| (String::from_utf8_lossy(&r.url).into_owned(), r.role.clone()))
                .collect();
            let borrowed: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(url, role)| (url.as_str(), role.as_str()))
                .collect();
            let (disposition, mut fresh) = if canonicals.is_empty() {
                (
                    identity::MatchDisposition::Confirmed,
                    vec![String::from(
                        "matched by --all: no target filter; every discovered instance is in scope",
                    )],
                )
            } else {
                let mut ranks = Vec::with_capacity(canonicals.len());
                let mut lines = Vec::new();
                for (i, canonical) in canonicals.iter().enumerate() {
                    if identity::is_local_target(canonical)
                        && instance_matches_local_target(store, id, canonical).await?
                    {
                        ranks.push(identity::MatchDisposition::Confirmed);
                        matched[i] += 1;
                        lines.push(format!(
                            "for target {canonical}: repository matches local target repository"
                        ));
                        continue;
                    }
                    let (verdict, verdict_lines) =
                        identity::classify_remotes(canonical, borrowed.iter().copied());
                    if verdict == identity::MatchDisposition::Confirmed {
                        matched[i] += 1;
                    }
                    for line in verdict_lines {
                        lines.push(format!("for target {canonical}: {line}"));
                    }
                    ranks.push(verdict);
                }
                (best_disposition(&ranks), lines)
            };
            let mut evidence: Vec<String> = serde_json::from_str(evidence_json).unwrap_or_default();
            evidence.retain(|line| !is_match_verdict_line(line));
            if canonicals.is_empty() {
                evidence.push(String::from("reclassified for --all at report time"));
            } else {
                for canonical in canonicals {
                    evidence.push(format!(
                        "reclassified for target {canonical} at report time"
                    ));
                }
            }
            evidence.append(&mut fresh);
            let evidence_json = serde_json::to_string(&evidence)
                .map_err(|e| repo_scan::Error::Report(e.to_string()))?;
            store
                .connection()
                .execute(
                    "UPDATE git_instances SET disposition = ?1, evidence = ?2 WHERE id = ?3",
                    vec![
                        turso::Value::Text(disposition_str(disposition).to_string()),
                        turso::Value::Text(evidence_json),
                        turso::Value::Text(id.clone()),
                    ],
                )
                .await
                .map_err(store_err)?;
            counters.db_transactions += 1;
        }
        if full_page {
            offset += page.len() as i64;
        } else {
            break;
        }
    }
    Ok(matched)
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

/// Scan-scoped event journal writer (D4): assigns contiguous 1-based
/// `seq`s (`seq` 0 is the "before everything" cursor), tracks the
/// per-revision event offset, and dedupes found events per store/checkout
/// id so re-probes and resume re-runs never double-emit. `open` replays
/// the committed prefix to resume numbering AND the emitted sets: a task
/// whose flush committed but whose completion was lost re-persists its
/// rows idempotently while its found events stay single.
struct ScanJournal {
    scan_id: String,
    next_seq: u64,
    /// This run's catalog revision: `next_revision` runs once per scan,
    /// so every event this writer journals shares one `rev`.
    rev: u64,
    last_rev: Option<u64>,
    last_off: u64,
    last_seq: Option<u64>,
    emitted_stores: HashSet<String>,
    emitted_checkouts: HashSet<String>,
    emitted_branch_stores: HashSet<String>,
    /// Seq of the coalesced `discovery_progress` gauge row, if journaled
    /// (Step 12: progress coalesces by seq reuse — the first tick takes a
    /// fresh seq, later ticks update that row's payload in place at its
    /// immutable `(rev, off)` position, so exactly one progress row (the
    /// newest) survives per scan and replay order always matches seq
    /// order).
    progress_seq: Option<u64>,
    /// Highest seq known pruned by retention (heuristic for the
    /// over-bound check; the `COUNT(*)` confirm is authoritative).
    pruned_through: u64,
}

impl ScanJournal {
    async fn open(store: &TursoStore, scan_id: &str, rev: u64) -> repo_scan::Result<Self> {
        let mut max_seq = 0u64;
        let mut min_seq = None;
        let mut last_rev = None;
        let mut last_off = 0u64;
        let mut emitted_stores = HashSet::new();
        let mut emitted_checkouts = HashSet::new();
        let mut emitted_branch_stores = HashSet::new();
        let mut progress_seq = None;
        loop {
            let rows = store.read_scan_events(scan_id, max_seq, 500).await?;
            let short = rows.len() < 500;
            for row in &rows {
                if min_seq.is_none() {
                    min_seq = Some(row.seq);
                }
                max_seq = row.seq;
                last_rev = Some(row.catalog_rev);
                last_off = row.event_offset;
                if row.event_type == EventType::DiscoveryProgress.name() {
                    progress_seq = Some(row.seq);
                }
                let id_key = match row.event_type.as_str() {
                    "repository_found" => Some((&mut emitted_stores, "store_id")),
                    "location_found" => Some((&mut emitted_checkouts, "checkout_id")),
                    "branch_batch" => Some((&mut emitted_branch_stores, "store_id")),
                    _ => None,
                };
                if let Some((set, key)) = id_key {
                    let v: serde_json::Value =
                        serde_json::from_slice(&row.records).map_err(|e| {
                            repo_scan::Error::Report(format!(
                                "scan_events row seq {} carries corrupt records: {e}",
                                row.seq,
                            ))
                        })?;
                    if let Some(id) = v.get(key).and_then(|v| v.as_str()) {
                        set.insert(id.to_string());
                    }
                }
            }
            if short {
                break;
            }
        }
        Ok(Self {
            scan_id: scan_id.to_string(),
            next_seq: max_seq + 1,
            rev,
            last_rev,
            last_off,
            last_seq: if max_seq == 0 { None } else { Some(max_seq) },
            emitted_stores,
            emitted_checkouts,
            emitted_branch_stores,
            progress_seq,
            // Retention prunes a contiguous prefix, so everything below
            // the retained minimum is gone; a fresh journal starts at 1.
            pruned_through: min_seq.map(|m| m.saturating_sub(1)).unwrap_or(0),
        })
    }

    /// Cursor of the last committed event, for `scan_interrupted` /
    /// `scan_failed` payloads (`None` when nothing is journaled yet).
    fn cursor(&self) -> Option<Cursor> {
        match (self.last_seq, self.last_rev) {
            (Some(seq), Some(rev)) => Some(Cursor {
                seq,
                catalog_rev: rev,
                event_offset: self.last_off,
            }),
            _ => None,
        }
    }

    /// Assign the next `(seq, offset)` pair against this run's rev. The
    /// offset restarts at 0 when the rev changes (a resumed run journals
    /// under a fresh revision).
    fn assign(&mut self) -> (u64, u64) {
        let off = if self.last_rev == Some(self.rev) {
            self.last_off + 1
        } else {
            0
        };
        let seq = self.next_seq;
        self.next_seq += 1;
        self.last_rev = Some(self.rev);
        self.last_off = off;
        self.last_seq = Some(seq);
        (seq, off)
    }

    /// Highest seq assigned so far (`next_seq - 1`; 0 when empty).
    fn tip_seq(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    /// Journal one lifecycle event. Each call is its own transaction
    /// (lifecycle events are rare); per-record events buffer into the
    /// writer batch below instead.
    async fn emit(
        &mut self,
        store: &TursoStore,
        event_type: EventType,
        records: &serde_json::Value,
    ) -> repo_scan::Result<()> {
        let (seq, off) = self.assign();
        let bytes =
            serde_json::to_vec(records).map_err(|e| repo_scan::Error::Report(e.to_string()))?;
        let event = NewScanEvent {
            scan_id: &self.scan_id,
            seq,
            catalog_rev: self.rev,
            event_offset: off,
            event_type: event_type.name(),
            op: event_type.op().name(),
            reset: false,
            records: &bytes,
        };
        store.append_scan_event(&event).await?;
        Ok(())
    }

    /// Buffer one `repository_found` into the writer batch: it commits
    /// atomically with the store row that caused it. Returns `None` when
    /// this store already has a found event in this scan's journal
    /// (re-probe or resume re-run); otherwise `Some(should_flush)`.
    fn buffer_repository_found(
        &mut self,
        batch: &mut WriterBatch,
        store_id: &str,
        records: &[u8],
    ) -> repo_scan::Result<Option<bool>> {
        if !self.emitted_stores.insert(store_id.to_string()) {
            return Ok(None);
        }
        let (seq, off) = self.assign();
        let event = NewScanEvent {
            scan_id: &self.scan_id,
            seq,
            catalog_rev: self.rev,
            event_offset: off,
            event_type: EventType::RepositoryFound.name(),
            op: EventType::RepositoryFound.op().name(),
            reset: false,
            records,
        };
        Ok(Some(TursoStore::buffer_scan_event(batch, &event)?))
    }

    /// Buffer one `location_found` into the writer batch (same atomicity
    /// and dedupe contract as [`Self::buffer_repository_found`]).
    fn buffer_location_found(
        &mut self,
        batch: &mut WriterBatch,
        checkout_id: &str,
        records: &[u8],
    ) -> repo_scan::Result<Option<bool>> {
        if !self.emitted_checkouts.insert(checkout_id.to_string()) {
            return Ok(None);
        }
        let (seq, off) = self.assign();
        let event = NewScanEvent {
            scan_id: &self.scan_id,
            seq,
            catalog_rev: self.rev,
            event_offset: off,
            event_type: EventType::LocationFound.name(),
            op: EventType::LocationFound.op().name(),
            reset: false,
            records,
        };
        Ok(Some(TursoStore::buffer_scan_event(batch, &event)?))
    }

    /// Buffer one `location_updated` into the writer batch: it commits
    /// atomically with the status row that caused it. Unlike the found
    /// events there is no emitted-set dedupe — `replace` replays
    /// idempotently, so a retried status task re-emitting identical
    /// content converges to the same end state. Always `Some(should_flush)`.
    fn buffer_location_updated(
        &mut self,
        batch: &mut WriterBatch,
        records: &[u8],
    ) -> repo_scan::Result<Option<bool>> {
        let (seq, off) = self.assign();
        let event = NewScanEvent {
            scan_id: &self.scan_id,
            seq,
            catalog_rev: self.rev,
            event_offset: off,
            event_type: EventType::LocationUpdated.name(),
            op: EventType::LocationUpdated.op().name(),
            reset: false,
            records,
        };
        Ok(Some(TursoStore::buffer_scan_event(batch, &event)?))
    }

    /// Buffer one `error` into the writer batch: it commits atomically
    /// with the error row that caused it. No dedupe — errors are
    /// point-in-time observations (`add`), bounded by the same retry caps
    /// that bound the rows. Always `Some(should_flush)`.
    fn buffer_error(
        &mut self,
        batch: &mut WriterBatch,
        records: &[u8],
    ) -> repo_scan::Result<Option<bool>> {
        let (seq, off) = self.assign();
        let event = NewScanEvent {
            scan_id: &self.scan_id,
            seq,
            catalog_rev: self.rev,
            event_offset: off,
            event_type: EventType::Error.name(),
            op: EventType::Error.op().name(),
            reset: false,
            records,
        };
        Ok(Some(TursoStore::buffer_scan_event(batch, &event)?))
    }

    /// Buffer one `coverage_updated` into the writer batch: it commits
    /// atomically with the gap rows it describes. No dedupe — each call
    /// carries a genuine transition (callers gate on `Runner::open_gaps`),
    /// and `replace` replays in seq order. Always `Some(should_flush)`.
    fn buffer_coverage_updated(
        &mut self,
        batch: &mut WriterBatch,
        records: &[u8],
    ) -> repo_scan::Result<Option<bool>> {
        let (seq, off) = self.assign();
        let event = NewScanEvent {
            scan_id: &self.scan_id,
            seq,
            catalog_rev: self.rev,
            event_offset: off,
            event_type: EventType::CoverageUpdated.name(),
            op: EventType::CoverageUpdated.op().name(),
            reset: false,
            records,
        };
        Ok(Some(TursoStore::buffer_scan_event(batch, &event)?))
    }

    /// Buffer one `branch_batch` into the writer batch: it commits
    /// atomically with the ref rows it describes. First batch per store is
    /// `add`; a re-persisted store (retry, resume re-run) resends as
    /// `replace` (D4 `add/replace` cell), ordered by the payload `rev`.
    /// Always `Some(should_flush)`.
    fn buffer_branch_batch(
        &mut self,
        batch: &mut WriterBatch,
        store_id: &str,
        records: &[u8],
    ) -> repo_scan::Result<Option<bool>> {
        let first = self.emitted_branch_stores.insert(store_id.to_string());
        let op = if first { Op::Add } else { Op::Replace };
        let (seq, off) = self.assign();
        let event = NewScanEvent {
            scan_id: &self.scan_id,
            seq,
            catalog_rev: self.rev,
            event_offset: off,
            event_type: EventType::BranchBatch.name(),
            op: op.name(),
            reset: false,
            records,
        };
        Ok(Some(TursoStore::buffer_scan_event(batch, &event)?))
    }

    /// Buffer one `discovery_progress` tick: it commits with the writer
    /// batch (visible while later discovery is still active, never held
    /// to phase end). Coalescing is by seq reuse
    /// ([`is_progress_coalescible`]): the first tick takes a fresh seq;
    /// every later tick updates that same row's payload in place, so
    /// exactly one progress row (the newest) survives per scan. The
    /// row's `(seq, rev, off)` position is immutable after the first
    /// tick, so `(rev, off)` replay order always matches seq order; when
    /// retention pruned the row, the next tick re-inserts at a fresh
    /// seq. Always `Some(should_flush)`.
    fn buffer_discovery_progress(
        &mut self,
        batch: &mut WriterBatch,
        records: &[u8],
    ) -> repo_scan::Result<Option<bool>> {
        debug_assert!(is_progress_coalescible(EventType::DiscoveryProgress));
        // A pruned gauge row reads as absent: re-insert below at a fresh
        // seq (retention only deletes the prefix, so this test is exact).
        if self
            .progress_seq
            .is_some_and(|seq| seq <= self.pruned_through)
        {
            self.progress_seq = None;
        }
        match self.progress_seq {
            Some(seq) => {
                let seq_i64 = i64::try_from(seq).map_err(|_| {
                    repo_scan::Error::Store(format!("event seq {seq} exceeds i64 range"))
                })?;
                Ok(Some(batch.push(
                    "UPDATE scan_events SET records = ?1 \
                        WHERE scan_id = ?2 AND seq = ?3",
                    vec![
                        turso::Value::Blob(records.to_vec()),
                        turso::Value::Text(self.scan_id.clone()),
                        turso::Value::Integer(seq_i64),
                    ],
                )))
            }
            None => {
                let event_type = EventType::DiscoveryProgress;
                let (seq, off) = self.assign();
                self.progress_seq = Some(seq);
                let seq_i64 = i64::try_from(seq).map_err(|_| {
                    repo_scan::Error::Store(format!("event seq {seq} exceeds i64 range"))
                })?;
                let rev_i64 = i64::try_from(self.rev).map_err(|_| {
                    repo_scan::Error::Store(format!(
                        "event catalog_rev {} exceeds i64 range",
                        self.rev
                    ))
                })?;
                let off_i64 = i64::try_from(off).map_err(|_| {
                    repo_scan::Error::Store(format!("event offset {off} exceeds i64 range"))
                })?;
                Ok(Some(batch.push(
                    "INSERT OR IGNORE INTO scan_events (scan_id, seq, catalog_rev, event_offset, \
                        event_type, op, reset, records) \
                        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    vec![
                        turso::Value::Text(self.scan_id.clone()),
                        turso::Value::Integer(seq_i64),
                        turso::Value::Integer(rev_i64),
                        turso::Value::Integer(off_i64),
                        turso::Value::Text(event_type.name().to_string()),
                        turso::Value::Text(event_type.op().name().to_string()),
                        turso::Value::Integer(0),
                        turso::Value::Blob(records.to_vec()),
                    ],
                )))
            }
        }
    }
}

/// Retained rows for one scan (Step 12 retention confirm).
async fn scan_event_count(store: &TursoStore, scan_id: &str) -> repo_scan::Result<u64> {
    count_query(
        store,
        "SELECT COUNT(*) FROM scan_events WHERE scan_id = ?1",
        vec![turso::Value::Text(scan_id.to_string())],
    )
    .await
}

/// Delete one scan's journal prefix through `cutoff` (inclusive) in one
/// transaction. Position-based: everything at or below the cutoff goes,
/// so the retained window stays a contiguous `[cutoff+1..=tip]` and the
/// tip (a finished scan's terminal event) always survives.
async fn prune_scan_events_through(
    store: &TursoStore,
    scan_id: &str,
    cutoff: u64,
) -> repo_scan::Result<()> {
    let cutoff_i64 = i64::try_from(cutoff)
        .map_err(|_| repo_scan::Error::Store(format!("prune cutoff {cutoff} exceeds i64 range")))?;
    store
        .connection()
        .execute(
            "DELETE FROM scan_events WHERE scan_id = ?1 AND seq <= ?2",
            vec![
                turso::Value::Text(scan_id.to_string()),
                turso::Value::Integer(cutoff_i64),
            ],
        )
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?;
    Ok(())
}

/// Enforce Step 12 bounded retention after a flush committed: when the
/// journal's cheap suspected check fires, confirm with `COUNT(*)` and
/// prune to `keep_rows` (production passes
/// [`MAX_RETAINED_SCAN_EVENTS`]), advancing the watermark. Returns true
/// when a prune transaction committed (callers count it). Cursors the
/// retained window no longer covers resolve to an explicit-reset
/// snapshot via [`classify_cursor`], never a silent gap.
async fn maybe_prune_scan_journal(
    store: &TursoStore,
    journal: &mut ScanJournal,
    keep_rows: u64,
) -> repo_scan::Result<bool> {
    if journal.tip_seq().saturating_sub(journal.pruned_through) <= keep_rows.max(1) {
        return Ok(false);
    }
    if scan_event_count(store, &journal.scan_id).await? <= keep_rows.max(1) {
        return Ok(false);
    }
    let cutoff = retention_cutoff(journal.tip_seq(), keep_rows);
    prune_scan_events_through(store, &journal.scan_id, cutoff).await?;
    journal.pruned_through = cutoff.max(journal.pruned_through);
    Ok(true)
}

/// Resume command recorded in lifecycle payloads (D4): replays the exact
/// state dir + scan id a follower needs to reconnect.
fn resume_cmd_for(state_dir: &Path, scan_id: &str) -> String {
    format!(
        "repo-scan --state-dir {} resume {scan_id}",
        state_dir.display()
    )
}

/// `scan_failed` payload (Step 12): last committed cursor, scrubbed error,
/// resume capability + command. The staged snapshot survives a publication
/// failure, so `resumable` is always true here.
fn failed_records(
    journal: &ScanJournal,
    err: &str,
    state_dir: &Path,
    scan_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "cursor": journal.cursor().map(|c| serde_json::json!({
            "after": c.encode(),
            "seq": c.seq,
            "catalog_rev": c.catalog_rev,
            "event_offset": c.event_offset,
        })).unwrap_or(serde_json::Value::Null),
        "error": err,
        "resumable": true,
        "resume_cmd": resume_cmd_for(state_dir, scan_id),
    })
}

async fn run_scan(cfg: &config::Config, args: &repo_scan::cli::ScanArgs) -> ExitCode {
    // Goal Step 6: explicit targets XOR --all, validated once; execution
    // resolves the full set and serves it with one filesystem pass.
    if let Err(msg) = args.target_set() {
        return fail(&repo_scan::Error::InvalidArgs(msg));
    }
    match run_scan_inner(cfg, args, None).await {
        Ok(code) => code,
        Err(e) => fail(&e),
    }
}

/// Scan target set resolved once per request (goal Step 6): explicit
/// `(sanitized raw, canonical)` pairs in request order, or `--all` (no
/// target filter). Kept separate from inventory collection: one filesystem
/// pass serves the whole set.
struct ResolvedTargets {
    targets: Vec<(String, String)>,
    all: bool,
}

impl ResolvedTargets {
    /// Primary target (legacy single-target fields use this); `None` for `--all`.
    fn primary(&self) -> Option<(&str, &str)> {
        if self.all {
            return None;
        }
        self.targets
            .first()
            .map(|(raw, canonical)| (raw.as_str(), canonical.as_str()))
    }

    /// Canonical forms in request order (empty for `--all`).
    fn canonicals(&self) -> Vec<String> {
        self.targets
            .iter()
            .map(|(_, canonical)| canonical.clone())
            .collect()
    }

    /// True when union matching applies (multi-target or `--all`).
    /// Exactly one explicit target keeps the legacy single-target path.
    fn is_set(&self) -> bool {
        self.all || self.targets.len() > 1
    }
}

/// Validate and normalize the scan target set once per request (goal Step
/// 6). Credential-bearing inputs are rejected before any persistence; every
/// target resolves to canonical form; `--all` stays target-free.
fn resolve_scan_targets(args: &repo_scan::cli::ScanArgs) -> repo_scan::Result<ResolvedTargets> {
    match args.target_set() {
        Ok(repo_scan::cli::TargetSet::All) => Ok(ResolvedTargets {
            targets: Vec::new(),
            all: true,
        }),
        Ok(repo_scan::cli::TargetSet::Targets(list)) => {
            let mut targets = Vec::with_capacity(list.len());
            for raw in &list {
                // CLI boundary (RSF-SEC-TARGET-URL, EXACT-2): per target,
                // before any persistence or reporting; the error echoes
                // only the display-safe shape, never secret bytes.
                if identity::must_reject_target(raw) {
                    return Err(repo_scan::Error::InvalidArgs(format!(
                        "target URL must not embed credentials or a query/fragment tail; remove them and retry: {}",
                        identity::redact_target_for_display(raw),
                    )));
                }
                targets.push(resolve_target_identity(raw)?);
            }
            Ok(ResolvedTargets {
                targets,
                all: false,
            })
        }
        Err(msg) => Err(repo_scan::Error::InvalidArgs(msg)),
    }
}

/// Scan entry shared by `scan` and `resume`. `resumed` carries the restored
/// saved request for resume; `None` for a fresh scan (which mints a scan ID
/// and persists the request row first).
async fn run_scan_inner(
    cfg: &config::Config,
    args: &repo_scan::cli::ScanArgs,
    resumed: Option<ResumedRequest>,
) -> repo_scan::Result<ExitCode> {
    // CLI boundary (RSF-SEC-TARGET-URL, EXACT-2): credential-bearing
    // targets (userinfo, any query/fragment tail) are rejected before any
    // persistence or reporting; the error echoes only the display-safe
    // shape, never secret bytes.
    let resolved = resolve_scan_targets(args)?;
    // CLI boundary: `--workers 0` is meaningless (no reader could run);
    // reject it loudly instead of clamping to a surprise. (Resume maps
    // a corrupt saved zero to the runtime default before reaching here.)
    if args.workers == Some(0) {
        return Err(repo_scan::Error::InvalidArgs(String::from(
            "--workers must be at least 1",
        )));
    }
    // Legacy single-target fields: the primary target, or the `--all`
    // marker when no target filter applies (report 1.1.0 `scan.targets`
    // carries the full set; `--all` leaves it empty).
    let (target, canonical) = match resolved.primary() {
        Some((raw, canonical)) => (raw.to_string(), Some(canonical.to_string())),
        None => (String::from("--all"), None),
    };
    // Probe-time classification key: primary canonical, or "" for `--all`
    // (union-only instances are corrected by the post-traversal fix-up).
    let primary_canonical = canonical.as_deref().unwrap_or("");
    // Absolute report destination at request-creation time (spec §3).
    let report_dest = args
        .report
        .as_ref()
        .map(|p| config::resolve_report_dest(p))
        .transpose()?;
    let (policy, roots, state_roots) = plan_roots(args)?;
    let (_guard, store) = open_owned_with_wait(&cfg.state_dir).await?;
    let epoch = store.epoch();
    // Step 8 worker pool: admission scales with the effective worker
    // count (explicit `--workers` or platform default); absolute
    // process budgets stay fixed inside `effective_limits`.
    let effective = config::effective_limits(args.workers);
    let mut runner = Runner::new(&effective);
    // Finding 12: the traversal fence is built once from the planned
    // roots; every enum task re-verifies its directory against it through
    // a pinned descriptor-relative open before listing.
    let fence = ScopeFence::build(
        &roots
            .iter()
            .map(|root| root.path.clone())
            .collect::<Vec<_>>(),
    );
    // RSF-TOPOLOGY-ADMISSION: unverified root identities persist as durable
    // gaps, never a silent lexical fallback; execution parks them honestly.
    for unknown in fence.unknown_roots() {
        let scope_key = config::scope_key_for_dir(&unknown);
        store
            .record_error(
                &format!(
                    "gap:fence-identity:{}",
                    config::encode_hex(&config::path_as_bytes(&unknown))
                ),
                &scope_key,
                "fence-identity-unknown",
                &format!(
                    "root identity unverified for {}; bounded resolve failed or timed out",
                    unknown.display()
                ),
                None,
                store::now_ms(),
            )
            .await?;
        runner.counters.db_transactions += 1;
    }
    runner.fence = Some(fence);
    // Event monitoring opens before any traversal decision (R5).
    let mut events = open_event_session(&store, &cfg.state_dir, &policy, &roots).await?;
    // One fresh catalog revision per run: status observations keyed by it
    // refresh matching metadata on every scan without duplicating rows.
    let run_rev = store.next_revision().await?;
    runner.counters.db_transactions += 1;
    let now = store::now_ms();
    // Resume honors the saved generation (R14); a history loss forces a
    // fresh one exactly like `--force-rescan`.
    let saved_generation = resumed.as_ref().and_then(|r| r.generation);
    let events_live = events.live && events.degraded.is_empty();
    // Full scope key (D5): generation reuse requires equal coverage roots.
    let scope_key = repo_scan::walk::roots::generation_scope_key(&policy, &roots);
    let generation = match saved_generation {
        Some(saved) if store.get_generation(saved).await?.is_some() => {
            store.set_generation_state(saved, "running").await?;
            runner.counters.db_transactions += 1;
            saved
        }
        Some(saved) => {
            eprintln!("repo-scan: resume: saved generation {saved} is gone; picking a live one",);
            pick_generation(
                &store,
                &policy,
                &scope_key,
                args.force_rescan,
                events_live,
                now,
                &mut runner.counters,
            )
            .await?
        }
        None => {
            let force = args.force_rescan || events.history_invalid;
            if events.history_invalid && !args.force_rescan {
                eprintln!(
                    "repo-scan: events: history loss forced a fresh traversal generation; \
                     prior findings stay provisional until replaced"
                );
            }
            pick_generation(
                &store,
                &policy,
                &scope_key,
                force,
                events_live,
                now,
                &mut runner.counters,
            )
            .await?
        }
    };
    if args.force_rescan {
        eprintln!(
            "repo-scan: force rescan: fresh generation {generation}; \
             prior findings stay provisional until replaced"
        );
    }
    let scan_id = match &resumed {
        Some(r) => r.scan_id.clone(),
        None => {
            mint_scan_id(
                &store,
                &target,
                canonical.as_deref(),
                &policy,
                args.status,
                &report_dest,
                &resolved.targets,
                args.format,
                resolved.all,
                args.fetch,
                args.workers,
                &mut runner.counters,
            )
            .await?
        }
    };
    let started_ms = match &resumed {
        Some(r) => r.started_ms,
        None => now,
    };
    if resumed.is_none() {
        // Per-target supersede (`--all` has no canonical: nothing to match).
        for supersede_canonical in resolved.canonicals() {
            supersede_stale_scans(
                &store,
                &supersede_canonical,
                &policy,
                &scan_id,
                now,
                &mut runner.counters,
            )
            .await?;
        }
    }
    // Bind the generation on the running row (R14): the pending outcome
    // carries no terminal verdict (`exit=-1`), only the generation, so an
    // interleaving force-rescan can never divert this scan's resume.
    let pending_outcome = config::encode_outcome(
        PENDING_EXIT,
        None,
        &config::report_id_for_scan(&scan_id),
        false,
        Some(generation),
    );
    store
        .update_scan_state(
            &scan_id,
            &config::scan_state_name("running", state_roots.as_deref()),
            Some(&pending_outcome),
            None,
            now,
        )
        .await?;
    runner.counters.db_transactions += 1;
    // Lifecycle journal (D4): opened against this run's revision.
    // `open` replays the committed prefix, so resumed scans continue
    // numbering (and found-event dedupe) without repeating `scan_started`.
    runner.journal = Some(ScanJournal::open(&store, &scan_id, run_rev).await?);
    // Coverage-delta baseline (also on resume): gaps already open stay
    // silent until they close; closes of pre-existing rows still report.
    runner.open_gaps = store.list_open_error_ids().await?.into_iter().collect();
    if resumed.is_none() {
        let started = serde_json::json!({
            "scan_id": &scan_id,
            "scope": {
                "policy": &policy,
                "roots": roots.iter().map(|r| r.path.display().to_string()).collect::<Vec<_>>(),
                "scope_key": &scope_key,
            },
            "targets": resolved.targets.iter().map(|(raw, canonical)| {
                serde_json::json!({"raw": raw, "canonical": canonical})
            }).collect::<Vec<_>>(),
            "options": {
                "all": resolved.all,
                "format": format!("{:?}", args.format),
                "status": format!("{:?}", args.status),
                "force_rescan": args.force_rescan,
                "fetch": args.fetch,
                "workers": config::effective_workers(args.workers),
            },
            "resume_cmd": resume_cmd_for(&cfg.state_dir, &scan_id),
        });
        runner
            .journal
            .as_mut()
            .expect("scan journal opened above")
            .emit(&store, EventType::ScanStarted, &started)
            .await?;
        runner.counters.db_transactions += 1;
    }
    upsert_volumes(&store, &policy, &roots, now, &mut runner.counters).await?;
    // Ingest available event history before traversal (R5).
    let mut drain = ingest_available_events(
        &mut events,
        &store,
        generation,
        &roots,
        &mut runner.counters,
    )
    .await?;
    if drain.batches > 0 {
        eprintln!(
            "repo-scan: events: ingested {} batch(es), {} scope(s) invalidated",
            drain.batches, drain.scopes,
        );
    }
    seed_root_tasks(&store, &mut runner, generation, &roots, now).await?;
    // Per-target dispositions before traversal and staging (R1): status
    // refresh, probes, and the report all classify this scan's target.
    let mut matched_counts = if resolved.is_set() {
        reclassify_for_targets(&store, &resolved.canonicals(), &mut runner.counters).await?
    } else {
        vec![reclassify_for_target(&store, primary_canonical, &mut runner.counters).await?]
    };
    enqueue_status_refresh(&store, &mut runner, generation, run_rev, now).await?;
    // Pre-existing stores schedule branch/HEAD analysis here; stores
    // discovered this run schedule from their probe persist. Claims
    // gate execution to the post-boundary drain.
    enqueue_analysis_refresh(&store, &mut runner, generation, run_rev, now).await?;

    let mut outcome = run_until_boundary(
        &mut runner,
        &store,
        epoch,
        generation,
        run_rev,
        primary_canonical,
        args.status,
        &scan_id,
        DrainPhase::Discovery,
    )
    .await?;
    // Post-traversal recount (goal Step 6): the pre-traversal classify saw an
    // empty or partial catalog, so per-target `confirmed` counts are
    // recomputed here against the drained catalog. Set scans reclassify
    // set-aware — correcting union-only instances — and refresh their status
    // in this same run and generation (status task IDs are idempotent per
    // run, so the repeat refresh is safe). Single-target rows are already
    // primary-classified (pre-traversal reclassify + probe time), so a
    // count query suffices and no rewrite churn is added.
    if !outcome.interrupted {
        if resolved.is_set() {
            matched_counts =
                reclassify_for_targets(&store, &resolved.canonicals(), &mut runner.counters)
                    .await?;
            enqueue_status_refresh(&store, &mut runner, generation, run_rev, store::now_ms())
                .await?;
            let union_next = run_until_boundary(
                &mut runner,
                &store,
                epoch,
                generation,
                run_rev,
                primary_canonical,
                args.status,
                &scan_id,
                DrainPhase::Discovery,
            )
            .await?;
            outcome.interrupted |= union_next.interrupted;
            outcome.pending = union_next.pending;
            outcome.open_gaps = union_next.open_gaps;
            outcome.unresolvable = union_next.unresolvable;
            outcome.status_pending = union_next.status_pending;
        } else {
            matched_counts = vec![
                count_query(
                    &store,
                    "SELECT COUNT(*) FROM git_instances WHERE disposition = 'confirmed'",
                    Vec::new(),
                )
                .await?,
            ];
        }
    }
    if runner.watchdog.tripped > 0 {
        eprintln!(
            "repo-scan: watchdog tripped {} time(s) this run; stalled scopes were contained",
            runner.watchdog.tripped,
        );
    }
    // Bounded history-close wait (R5, RSF-F940): the pre-traversal
    // drain races stream startup, so history that arrived during
    // traversal — including the `HistoryDone` sentinel on resumed
    // volumes — is ingested here, before the completeness claim.
    // Polls non-blocking drains until every history-expected volume
    // closes or the bound expires; expiry fails the claim honestly
    // (gaps + exit 3), never silently. Work scheduled during the wait
    // runs back to boundary once, after it; later arrivals stay queued
    // for the next run (the claim is relative to the pinned boundary,
    // not the live tip).
    let wait_scopes_before = drain.scopes;
    let mut errored_volumes: HashSet<String> = HashSet::new();
    let close_deadline = Instant::now() + HISTORY_CLOSE_WAIT;
    loop {
        let post = ingest_available_events(
            &mut events,
            &store,
            generation,
            &roots,
            &mut runner.counters,
        )
        .await?;
        if post.batches > 0 {
            eprintln!(
                "repo-scan: events: ingested {} batch(es), {} scope(s) invalidated (post-traversal)",
                post.batches, post.scopes,
            );
        }
        drain.batches += post.batches;
        drain.scopes += post.scopes;
        drain.mount_changed |= post.mount_changed;
        errored_volumes.extend(post.failed_volumes);
        if volumes_history_closed(&events, &errored_volumes)
            || outcome.interrupted
            || Instant::now() >= close_deadline
        {
            break;
        }
        if post.batches == 0 {
            std::thread::sleep(HISTORY_CLOSE_POLL);
        }
    }
    if drain.scopes != wait_scopes_before && !outcome.interrupted {
        let next = run_until_boundary(
            &mut runner,
            &store,
            epoch,
            generation,
            run_rev,
            primary_canonical,
            args.status,
            &scan_id,
            DrainPhase::Discovery,
        )
        .await?;
        outcome.interrupted |= next.interrupted;
        outcome.pending = next.pending;
        outcome.open_gaps = next.open_gaps;
        outcome.unresolvable = next.unresolvable;
        outcome.status_pending = next.status_pending;
    }
    if drain.mount_changed {
        // A mount change during ingest asked for fresh volume rows (R5).
        upsert_volumes(
            &store,
            &policy,
            &roots,
            store::now_ms(),
            &mut runner.counters,
        )
        .await?;
    }
    // Advance reconciled cursors over satisfied work (R5). Claim
    // verdicts persist as explicit gaps inside (EXACT-2/3); the returned
    // verdicts feed scan status here so incomplete history surfaces as
    // non-complete status in the catalog, the report, and the exit code —
    // never stderr-only.
    let (cursors, claims) = reconcile_event_cursors(&mut events, &store).await?;
    let event_gaps = claims.iter().filter(|c| !c.complete).count() as u64;

    // Both re-stamp after the optional fetch phase below (fetch
    // duration belongs to the report window; failed refreshes are
    // unresolved gaps).
    let mut finished_ms = store::now_ms();
    let mut scan_incomplete = outcome.has_gaps() || event_gaps > 0;
    let gen_state = if outcome.interrupted {
        "interrupted"
    } else if scan_incomplete {
        "incomplete"
    } else {
        "complete"
    };
    store.set_generation_state(generation, gen_state).await?;
    runner.counters.db_transactions += 1;
    // Discovery boundary journal (D3/D4): committed right after the
    // generation state, before report staging. An interrupted run closes the
    // boundary as `incomplete` — the inventory is partial, never silent.
    let ready = serde_json::json!({
        "verdict": if gen_state == "complete" { "complete" } else { "incomplete" },
        "generation": generation,
        "counts": {
            "matched_per_target": &matched_counts,
            "pending": outcome.pending,
            "open_gaps": outcome.open_gaps,
            "unresolvable": outcome.unresolvable,
            "status_pending": outcome.status_pending,
            "event_gaps": event_gaps,
        },
        "gaps": {
            "open": outcome.open_gaps,
            "event_history": event_gaps,
        },
    });
    runner
        .journal
        .as_mut()
        .expect("scan journal opened above")
        .emit(&store, EventType::InventoryReady, &ready)
        .await?;
    runner.counters.db_transactions += 1;
    // Analysis drain (goal Step 8): detailed Git analysis starts only
    // after the catalog saves `inventory_ready`. Claims analysis kinds
    // (`status`, `analyze_store`) — including tasks probes enqueued
    // pre-boundary, which waited their turn. Interruption folds into
    // 130 below; residue folds into the final exit, never the already
    // journaled discovery verdict above.
    if !outcome.interrupted {
        let analysis = run_until_boundary(
            &mut runner,
            &store,
            epoch,
            generation,
            run_rev,
            primary_canonical,
            args.status,
            &scan_id,
            DrainPhase::Analysis,
        )
        .await?;
        outcome.interrupted |= analysis.interrupted;
        outcome.pending = analysis.pending;
        outcome.open_gaps = analysis.open_gaps;
        outcome.unresolvable = analysis.unresolvable;
        outcome.status_pending = analysis.status_pending;
        scan_incomplete = scan_incomplete || analysis.has_gaps();
        finished_ms = store::now_ms();
    }
    // Optional `--fetch` phase (Step 11): remote refresh runs after
    // the discovery boundary + local analysis, before report staging,
    // so staged reports include freshness. Failed refreshes are
    // unresolved gaps (exit 3); `unsupported` verdicts are examined
    // terminal states, not gaps; interruption folds into 130 below.
    if args.fetch {
        let fetch = run_fetch_phase(&mut runner, &store, started_ms).await?;
        outcome.interrupted |= fetch.interrupted;
        scan_incomplete |= fetch.failed > 0;
        eprintln!(
            "repo-scan: fetch: {} refreshed, {} failed, {} unsupported, {} resumed-skip{}",
            fetch.refreshed,
            fetch.failed,
            fetch.unsupported,
            fetch.skipped,
            if fetch.interrupted {
                " (interrupted)"
            } else {
                ""
            },
        );
        finished_ms = store::now_ms();
    }
    let discovery_code = if scan_incomplete { 3 } else { 0 };
    // The report's scan verdict covers the whole run (analysis + fetch),
    // not just the discovery boundary: `gen_state` above stays the
    // discovery verdict for the generation row and the `inventory_ready`
    // event, but a scan that exits 3 must not stage a file claiming
    // `complete` (Step 15.18/FETCH-E2E-07).
    let final_state = if outcome.interrupted {
        "interrupted"
    } else if scan_incomplete {
        "incomplete"
    } else {
        "complete"
    };
    // Stage first, publish second through the tested lib pipeline (R3): a
    // failed publication retains the saved snapshot and can be retried
    // without repeating discovery.
    let report_id = fresh_report_id(&store, &cfg.state_dir, &scan_id).await?;
    let catalog_rev = store.current_revision().await?;
    let dirs_complete = count_dirs_complete(&store, generation).await?;
    let snapshot_path = snapshots_dir(&cfg.state_dir).join(format!("{report_id}.json"));
    let mut event_note = events.note();
    if event_gaps > 0 {
        event_note.push_str(&format!(
            " {event_gaps} volume(s) event-history incomplete \
             (traversal covers scope; see event-history-incomplete gaps)."
        ));
    }
    let inputs = ScanReportInputs {
        scan_id: scan_id.clone(),
        generation,
        epoch,
        target_raw: target.clone(),
        canonical: canonical.clone(),
        targets: resolved
            .targets
            .iter()
            .enumerate()
            .map(
                |(i, (raw, canonical))| repo_scan::report::model::ScanTarget {
                    raw: raw.clone(),
                    canonical: Some(canonical.clone()),
                    matched_repositories: matched_counts.get(i).copied().unwrap_or(0),
                },
            )
            .collect(),
        scope_policy: policy.clone(),
        scan_state: final_state.to_string(),
        status_mode: args.status,
        started_ms,
        finished_ms,
        report_dest: report_dest.clone(),
        roots: roots.clone(),
        counters: runner.counters.clone(),
        pending: outcome.pending,
        aliases: runner.aliases.clone(),
        root_cursors: root_cursors_for(&roots, &events, &cursors),
        event_note,
    };
    let lib_inputs = build_lib_inputs(
        &store,
        &inputs,
        &report_id,
        catalog_rev,
        dirs_complete,
        &snapshot_path,
    )
    .await?;
    let published = match &report_dest {
        Some(dest) => {
            match emit_file_report(&store, &lib_inputs, dest, &cfg.state_dir, finished_ms).await {
                Ok(_) => true,
                Err(e) => {
                    let err = identity::scrub_text(&e.to_string());
                    eprintln!("repo-scan: report publication failed: {err}");
                    store
                        .update_scan_state(
                            &scan_id,
                            &config::scan_state_name("failed", state_roots.as_deref()),
                            Some(&config::encode_outcome(
                                1,
                                Some(discovery_code),
                                &report_id,
                                false,
                                Some(generation),
                            )),
                            None,
                            store::now_ms(),
                        )
                        .await?;
                    let failed = failed_records(
                        runner.journal.as_ref().expect("scan journal opened above"),
                        &err,
                        &cfg.state_dir,
                        &scan_id,
                    );
                    runner
                        .journal
                        .as_mut()
                        .expect("scan journal opened above")
                        .emit(&store, EventType::ScanFailed, &failed)
                        .await?;
                    let _ = store.close().await;
                    println!("scan_id: {scan_id}");
                    println!("report_id: {report_id}");
                    println!("snapshot: {}", snapshot_path.display());
                    return Ok(ExitCode::OperationalFailure);
                }
            }
        }
        None => {
            let stdout = std::io::stdout();
            let mut terminal = stdout.lock();
            match ReportPipeline::emit_to_terminal(
                &store,
                &lib_inputs,
                &staging_dir(&cfg.state_dir),
                &snapshots_dir(&cfg.state_dir),
                finished_ms,
                &mut terminal,
            )
            .await
            {
                Ok(_) => true,
                Err(e) => {
                    let err = identity::scrub_text(&e.to_string());
                    eprintln!("repo-scan: terminal report failed: {err}");
                    store
                        .update_scan_state(
                            &scan_id,
                            &config::scan_state_name("failed", state_roots.as_deref()),
                            Some(&config::encode_outcome(
                                1,
                                Some(discovery_code),
                                &report_id,
                                false,
                                Some(generation),
                            )),
                            None,
                            store::now_ms(),
                        )
                        .await?;
                    let failed = failed_records(
                        runner.journal.as_ref().expect("scan journal opened above"),
                        &err,
                        &cfg.state_dir,
                        &scan_id,
                    );
                    runner
                        .journal
                        .as_mut()
                        .expect("scan journal opened above")
                        .emit(&store, EventType::ScanFailed, &failed)
                        .await?;
                    let _ = store.close().await;
                    println!("scan_id: {scan_id}");
                    println!("report_id: {report_id}");
                    println!("snapshot: {}", snapshot_path.display());
                    return Ok(ExitCode::OperationalFailure);
                }
            }
        }
    };
    let exit = if outcome.interrupted {
        store
            .update_scan_state(
                &scan_id,
                &config::scan_state_name("interrupted", state_roots.as_deref()),
                Some(&config::encode_outcome(
                    130,
                    Some(discovery_code),
                    &report_id,
                    published,
                    Some(generation),
                )),
                None,
                store::now_ms(),
            )
            .await?;
        ExitCode::Interrupted
    } else if scan_incomplete {
        store
            .update_scan_state(
                &scan_id,
                &config::scan_state_name("incomplete", state_roots.as_deref()),
                Some(&config::encode_outcome(
                    3,
                    Some(3),
                    &report_id,
                    published,
                    Some(generation),
                )),
                None,
                store::now_ms(),
            )
            .await?;
        ExitCode::Incomplete
    } else {
        store
            .update_scan_state(
                &scan_id,
                "complete",
                Some(&config::encode_outcome(
                    0,
                    Some(0),
                    &report_id,
                    published,
                    Some(generation),
                )),
                None,
                store::now_ms(),
            )
            .await?;
        ExitCode::Success
    };
    // Terminal journal (D4): same predicates as the verdict above, so the
    // journaled class can never disagree with the scan row. Completed and
    // incomplete scans carry final counts + resume command; interrupted
    // scans carry the scan id, cursor, and saved scope/options.
    let (terminal, terminal_records) = if outcome.interrupted {
        (
            EventType::ScanInterrupted,
            serde_json::json!({
                "scan_id": &scan_id,
                "cursor": runner
                    .journal
                    .as_ref()
                    .expect("scan journal opened above")
                    .cursor()
                    .map(|c| c.encode()),
                "generation": generation,
                "scope": {
                    "policy": &policy,
                    "roots": roots.iter().map(|r| r.path.display().to_string()).collect::<Vec<_>>(),
                    "scope_key": &scope_key,
                },
                "options": {
                    "all": resolved.all,
                    "format": format!("{:?}", args.format),
                    "status": format!("{:?}", args.status),
                    "force_rescan": args.force_rescan,
                    "fetch": args.fetch,
                },
                "resume_cmd": resume_cmd_for(&cfg.state_dir, &scan_id),
            }),
        )
    } else {
        (
            if scan_incomplete {
                EventType::ScanIncomplete
            } else {
                EventType::ScanCompleted
            },
            serde_json::json!({
                "counts": {
                    "matched_per_target": &matched_counts,
                    "pending": outcome.pending,
                    "open_gaps": outcome.open_gaps,
                    "unresolvable": outcome.unresolvable,
                    "status_pending": outcome.status_pending,
                    "event_gaps": event_gaps,
                },
                "generation": generation,
                "report_id": &report_id,
                "published": published,
                "resume_cmd": resume_cmd_for(&cfg.state_dir, &scan_id),
            }),
        )
    };
    runner
        .journal
        .as_mut()
        .expect("scan journal opened above")
        .emit(&store, terminal, &terminal_records)
        .await?;
    let _ = store.close().await;
    println!("scan_id: {scan_id}");
    println!("generation: {generation}");
    println!("report_id: {report_id}");
    println!("snapshot: {}", snapshot_path.display());
    if let Some(dest) = &report_dest {
        println!("report: {}", dest.display());
    }
    Ok(exit)
}

/// A saved request restored by `resume`: never depends on the caller's
/// current directory (all paths stored absolute).
struct ResumedRequest {
    scan_id: String,
    started_ms: i64,
    /// Traversal generation bound on the scan row (R14).
    generation: Option<u64>,
}

/// True when `input` designates a local filesystem path (starts with `file://`,
/// is a relative/absolute path syntax, or exists as a path on disk).
fn is_local_path_target(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.starts_with("file://") {
        return true;
    }
    if trimmed == "."
        || trimmed == ".."
        || trimmed == "~"
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with('/')
        || trimmed.starts_with("~/")
    {
        return true;
    }
    Path::new(trimmed).exists()
}

/// Resolve scan target identity: supports remote GitHub URLs and local repository
/// paths (worktrees, bare repositories, or standard repositories with `.git`).
fn resolve_target_identity(input: &str) -> repo_scan::Result<(String, String)> {
    let trimmed = input.trim();
    if is_local_path_target(trimmed) {
        let raw_path = if let Some(stripped) = trimmed.strip_prefix("file://") {
            Path::new(stripped)
        } else {
            Path::new(trimmed)
        };
        let abs_path = config::resolve_target_path(raw_path)?;
        if !abs_path.exists() {
            return Err(repo_scan::Error::InvalidArgs(format!(
                "target path does not exist: {}",
                abs_path.display()
            )));
        }
        let canonical_path = std::fs::canonicalize(&abs_path).unwrap_or_else(|_| abs_path.clone());
        let inspector = git::GixInspector::new();
        let instance = inspector.open_exact(&canonical_path).map_err(|_| {
            repo_scan::Error::InvalidArgs(format!(
                "target path is not a git repository: {}",
                canonical_path.display()
            ))
        })?;
        let remotes = inspector.remotes(&instance).unwrap_or_default();
        let origin_remote = remotes
            .iter()
            .find(|r| r.name == b"origin" && r.role == git::RemoteRole::Fetch)
            .or_else(|| remotes.iter().find(|r| r.name == b"origin"))
            .or_else(|| remotes.iter().find(|r| r.canonical_url.is_some()))
            .or_else(|| remotes.first());

        if let Some(origin) = origin_remote {
            if let Some(canonical_url) = &origin.canonical_url {
                return Ok((input.to_string(), canonical_url.clone()));
            } else if let Some(canonical_url) = identity::normalize_github_url(&origin.url) {
                return Ok((input.to_string(), canonical_url));
            }
        }
        let file_url = format!("file://{}", canonical_path.display());
        return Ok((input.to_string(), file_url));
    }

    let target = identity::sanitize_target_url(input);
    let canonical = match identity::normalize_target_input(&target) {
        Some(canonical) => canonical,
        None => {
            return Err(repo_scan::Error::InvalidArgs(format!(
                "target is not a supported GitHub shape (owner/name or URL): {}",
                identity::redact_target_for_display(input),
            )));
        }
    };
    Ok((target, canonical))
}

/// Resolve scan roots: explicit `--root`s (absolute, recorded as `roots`
/// scope) or the machine plan (seeds plus every mount-table root).
fn plan_roots(
    args: &repo_scan::cli::ScanArgs,
) -> repo_scan::Result<(String, Vec<PlannedRoot>, Option<Vec<PathBuf>>)> {
    if !args.root.is_empty() {
        let mut roots = Vec::new();
        let mut paths = Vec::new();
        for root in &args.root {
            let abs = config::resolve_report_dest(root)?;
            if paths.contains(&abs) {
                continue;
            }
            paths.push(abs.clone());
            roots.push(PlannedRoot {
                path: abs,
                priority: repo_scan::walk::roots::RootPriority::Early,
                namespace: String::from("explicit"),
                volume: None,
            });
        }
        return Ok((String::from("roots"), roots, Some(paths)));
    }
    match args.scope {
        Scope::Roots => Err(repo_scan::Error::InvalidArgs(
            "--scope roots requires at least one --root".to_string(),
        )),
        Scope::Machine => {
            #[cfg(target_os = "macos")]
            let table = repo_scan::platform::macos::MacOsMountTable;
            #[cfg(not(target_os = "macos"))]
            let table = repo_scan::platform::linux::LinuxMountTable::new();
            let mounts = table.mounts()?;
            Ok((String::from("machine"), plan_machine_roots(&mounts), None))
        }
    }
}

/// Pick the traversal generation, reusing only key-compatible coverage
/// (goal Step 9, contract D5): a fresh one on `--force-rescan`, else the
/// newest generation whose scope key matches this request still holding
/// actionable work (compatible unfinished discovery is resumed and shared),
/// else the newest key-matching generation if live events are active, else
/// a fresh generation (when live events are unsupported or degraded,
/// minting a new generation ensures directory enumeration tasks run and
/// newly added repositories are discovered). Legacy rows (`NULL` scope key)
/// carry unknown root sets and never satisfy a keyed request; the lineage
/// `prior` stays the newest same-policy row. Fresh generations record the
/// requesting key before any seeding.
async fn pick_generation(
    store: &TursoStore,
    policy: &str,
    scope_key: &str,
    force: bool,
    events_live: bool,
    now_ms: i64,
    counters: &mut RunCounters,
) -> repo_scan::Result<u64> {
    let mut rows = store
        .connection()
        .query(
            "SELECT id, state, scope_key FROM generations WHERE scope_policy = ?1 ORDER BY id DESC",
            vec![turso::Value::Text(policy.to_string())],
        )
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?;
    let mut generations = Vec::new();
    let mut newest_same_policy = None;
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?
    {
        let id = cell_int(&row, 0)? as u64;
        if newest_same_policy.is_none() {
            newest_same_policy = Some(id);
        }
        if cell_opt_text(&row, 2)?.as_deref() == Some(scope_key) {
            generations.push((id, cell_text(&row, 1)?));
        }
    }
    if !force {
        for (id, _) in &generations {
            if store.pending_count(*id).await? > 0 {
                store.set_generation_state(*id, "running").await?;
                counters.db_transactions += 1;
                return Ok(*id);
            }
        }
        if events_live {
            if let Some((id, _)) = generations.first() {
                store.set_generation_state(*id, "running").await?;
                counters.db_transactions += 1;
                return Ok(*id);
            }
        }
    }
    let generation = store
        .create_generation(policy, "running", newest_same_policy, now_ms)
        .await?;
    counters.db_transactions += 1;
    store
        .set_generation_scope_key(generation, scope_key)
        .await?;
    counters.db_transactions += 1;
    Ok(generation)
}

/// Mint a scan ID and persist the request row (raw + optional canonical URL,
/// scope, status mode, absolute report destination, v2 target set / format /
/// `--all` marker, v3 `--fetch`, v4 `--workers`). Retries ID collisions.
/// `--all` scans persist the `--all` marker with no canonical, an empty
/// target set, and `all_targets`.
// Parameters mirror the scan-request row 1:1; grouping would churn the
// single caller for no clarity gain.
#[allow(clippy::too_many_arguments)]
async fn mint_scan_id(
    store: &TursoStore,
    raw_url: &str,
    canonical: Option<&str>,
    policy: &str,
    status: StatusMode,
    report_dest: &Option<PathBuf>,
    targets: &[(String, String)],
    format: Option<repo_scan::cli::OutputFormat>,
    all: bool,
    fetch: bool,
    workers: Option<usize>,
    counters: &mut RunCounters,
) -> repo_scan::Result<String> {
    // Defense-in-depth: the CLI boundary already rejected credential
    // forms; never persist one even on a direct call path (EXACT-2).
    if identity::must_reject_target(raw_url) {
        return Err(repo_scan::Error::InvalidArgs(format!(
            "target URL must not embed credentials or a query/fragment tail: {}",
            identity::redact_target_for_display(raw_url),
        )));
    }
    // Redact-before-persist (EXACT-2): the catalog row carries the
    // sanitized target (scp user normalized), never the raw login.
    let safe_url = identity::sanitize_target_url(raw_url);
    let now = store::now_ms();
    let dest_bytes = report_dest.as_ref().map(|p| config::path_as_bytes(p));
    // v2 request shape (D5/D6): the full target set served by one
    // filesystem pass, the output format, and the `--all` marker. The
    // CLI boundary already rejected credential-bearing targets.
    let targets_json = serde_json::to_string(
        &targets
            .iter()
            .map(|(raw, canonical)| serde_json::json!({"raw": raw, "canonical": canonical}))
            .collect::<Vec<_>>(),
    )
    .map_err(|e| repo_scan::Error::Report(e.to_string()))?;
    let format_str = format.map(|f| match f {
        repo_scan::cli::OutputFormat::Human => "human",
        repo_scan::cli::OutputFormat::Json => "json",
        repo_scan::cli::OutputFormat::Jsonl => "jsonl",
    });
    for _ in 0..3 {
        let id = config::new_scan_id();
        let inserted = store
            .create_scan_request(
                &NewScan {
                    id: &id,
                    url_raw: safe_url.as_bytes(),
                    url_canonical: canonical.map(str::as_bytes),
                    scope: policy,
                    status_mode: status_mode_str(status),
                    report_dest: dest_bytes.as_deref(),
                    targets_json: Some(targets_json.as_str()),
                    format: format_str,
                    all_targets: Some(all),
                    fetch: Some(fetch),
                    workers: workers.map(|w| w as u64),
                },
                now,
            )
            .await?;
        counters.db_transactions += 1;
        if inserted {
            return Ok(id);
        }
    }
    Err(repo_scan::Error::Store(
        "could not mint a unique scan ID".to_string(),
    ))
}

/// Mark stale `running` rows for the same canonical target + scope as
/// superseded by this scan, so their resumes report the successor (exit 3)
/// instead of silently switching targets. Interrupted/incomplete rows keep
/// their resumable state.
async fn supersede_stale_scans(
    store: &TursoStore,
    canonical: &str,
    policy: &str,
    successor: &str,
    now_ms: i64,
    counters: &mut RunCounters,
) -> repo_scan::Result<()> {
    store
        .connection()
        .execute(
            "UPDATE scan_requests SET state = 'superseded', successor_id = ?1, \
             updated_at_ms = ?2 WHERE state = 'running' AND scope = ?3 AND \
             url_canonical = ?4 AND id != ?1",
            vec![
                turso::Value::Text(successor.to_string()),
                turso::Value::Integer(now_ms),
                turso::Value::Text(policy.to_string()),
                turso::Value::Blob(canonical.as_bytes().to_vec()),
            ],
        )
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?;
    counters.db_transactions += 1;
    Ok(())
}

fn volume_kind_str(kind: repo_scan::platform::VolumeKind) -> &'static str {
    match kind {
        repo_scan::platform::VolumeKind::Local => "local",
        repo_scan::platform::VolumeKind::Network => "network",
        repo_scan::platform::VolumeKind::Virtual => "virtual",
        repo_scan::platform::VolumeKind::Unknown => "unknown",
    }
}

/// Persist the volume rows behind this run: mount-table volumes for machine
/// scope, one explicit volume for roots scope.
async fn upsert_volumes(
    store: &TursoStore,
    policy: &str,
    roots: &[PlannedRoot],
    now_ms: i64,
    counters: &mut RunCounters,
) -> repo_scan::Result<()> {
    if policy == "roots" {
        store
            .upsert_volume(
                &NewVolume {
                    id: "explicit-roots",
                    native_identity: None,
                    namespace: "explicit",
                    filesystem: None,
                    kind: "unknown",
                    state: "available",
                },
                Some(now_ms),
            )
            .await?;
        counters.db_transactions += 1;
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    let table = repo_scan::platform::macos::MacOsMountTable;
    #[cfg(not(target_os = "macos"))]
    let table = repo_scan::platform::linux::LinuxMountTable::new();
    for mount in table.mounts()?.iter() {
        store
            .upsert_volume(
                &NewVolume {
                    id: &mount.volume.0,
                    native_identity: Some(&mount.volume.0),
                    namespace: &mount.volume.0,
                    filesystem: mount.filesystem.as_deref(),
                    kind: volume_kind_str(mount.kind),
                    state: "available",
                },
                Some(now_ms),
            )
            .await?;
        counters.db_transactions += 1;
    }
    let _ = roots;
    Ok(())
}

/// Seed one enumeration task per planned root. Tasks are idempotent
/// (`INSERT OR IGNORE`), so reseeding a reused generation is a no-op for
/// already reconciled roots and only adds genuinely new scope.
async fn seed_root_tasks(
    store: &TursoStore,
    runner: &mut Runner,
    generation: u64,
    roots: &[PlannedRoot],
    now_ms: i64,
) -> repo_scan::Result<()> {
    for root in roots {
        let scope_key = config::scope_key_for_dir(&root.path);
        let id = enum_task_id_for_path(generation, &root.path);
        let expected_rev = store.scope_rev(&scope_key).await?;
        let idempotency = format!("idem:{id}");
        // RSF-AC461500-609D-4D55-991E-09C60D382D67: buffered enqueue.
        // Two requested roots naming the same object share results plus
        // a preserved alias (R7); the check is deferred to the flush.
        let task = NewTask {
            id: &id,
            kind: KIND_ENUM,
            generation,
            dir_id: None,
            scope_key: &scope_key,
            expected_rev,
            idempotency_key: &idempotency,
        };
        let due = TursoStore::buffer_enqueue_task(&mut runner.batch, &task, now_ms);
        runner.pending_alias_checks.push(PendingAliasCheck {
            task_id: id,
            scope_key,
            path: root.path.clone(),
            kind: "same_object",
            at_ms: now_ms,
        });
        flush_if_due(runner, store, due).await?;
    }
    // Seeded roots must be claimable before traversal starts.
    flush_runner_batch(runner, store).await?;
    Ok(())
}

/// Stable enumeration task ID from bounded physical identity, else an
/// explicit unknown marker (RSF-TOPOLOGY-ADMISSION). Identity follows
/// symlinks (R7) so alias spellings share one task and its results; the
/// bounded resolve refuses or times out on hung paths instead of stalling
/// the coordinator. Unknown IDs never collide with identity IDs and never
/// silently change meaning: execution stats through the fence and records
/// the gap durably when the path is truly unusable.
pub fn enum_task_id_for_path(generation: u64, path: &Path) -> String {
    let identity =
        repo_scan::walk::topology::bounded_dir_identity(path).filter(|key| *key != (0, 0));
    match identity {
        Some((dev, ino)) => format!("enum:{generation}:d{dev}:i{ino}"),
        None => format!(
            "enum:{generation}:unknown:{}",
            config::encode_hex(&config::path_as_bytes(path))
        ),
    }
}

/// `(dev, ino)` identity for durable dedupe (unix; zeros elsewhere).
#[cfg(unix)]
fn dir_identity(md: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (md.dev(), md.ino())
}

#[cfg(not(unix))]
fn dir_identity(_md: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// Enqueue a status refresh for every matching checkout, so a reused
/// generation refreshes matching metadata even when no probe runs this run.
/// Task IDs carry the run revision: one refresh per run, idempotent within it.
async fn enqueue_status_refresh(
    store: &TursoStore,
    runner: &mut Runner,
    generation: u64,
    run_rev: u64,
    now_ms: i64,
) -> repo_scan::Result<()> {
    let mut rows = store
        .connection()
        .query(
            "SELECT c.id FROM checkouts c JOIN git_instances g ON g.id = c.instance_id \
             WHERE g.disposition IN ('confirmed', 'related', 'probable')",
            (),
        )
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?;
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?
    {
        let checkout_id = cell_text(&row, 0)?;
        enqueue_status_task(store, runner, generation, run_rev, &checkout_id, now_ms).await?;
    }
    flush_runner_batch(runner, store).await?;
    Ok(())
}

async fn enqueue_status_task(
    store: &TursoStore,
    runner: &mut Runner,
    generation: u64,
    run_rev: u64,
    checkout_id: &str,
    now_ms: i64,
) -> repo_scan::Result<()> {
    let scope_key = config::scope_key_for_status(checkout_id);
    let id = format!("status:{checkout_id}:{run_rev}");
    let idempotency = format!("idem:{id}");
    let expected_rev = store.scope_rev(&scope_key).await?;
    // RSF-AC461500-609D-4D55-991E-09C60D382D67: buffered enqueue.
    let task = NewTask {
        id: &id,
        kind: KIND_STATUS,
        generation,
        dir_id: None,
        scope_key: &scope_key,
        expected_rev,
        idempotency_key: &idempotency,
    };
    let due = TursoStore::buffer_enqueue_task(&mut runner.batch, &task, now_ms);
    flush_if_due(runner, store, due).await?;
    Ok(())
}

/// Enqueue branch/HEAD analysis for every known local store (goal Step
/// 8/10): shared refs read once per store, HEAD per checkout. Mirrors
/// the status refresh: pre-existing instances enqueue here, instances
/// discovered this run enqueue from their probe persist. Task ids are
/// idempotent per run (`analyze:{instance}:{run_rev}`), so the repeat
/// enqueue is safe; claims gate execution to the post-`inventory_ready`
/// drain, so calling this pre-traversal only schedules, never starts,
/// analysis.
async fn enqueue_analysis_refresh(
    store: &TursoStore,
    runner: &mut Runner,
    generation: u64,
    run_rev: u64,
    now_ms: i64,
) -> repo_scan::Result<()> {
    let mut rows = store
        .connection()
        .query("SELECT id, common_path FROM git_instances", ())
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?;
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?
    {
        let instance_id = cell_text(&row, 0)?;
        let common = cell_blob(&row, 1)?;
        enqueue_analysis_task(
            store,
            runner,
            generation,
            run_rev,
            &instance_id,
            &config::path_from_bytes(common),
            now_ms,
        )
        .await?;
    }
    flush_runner_batch(runner, store).await?;
    Ok(())
}

/// Canonical execution path for a fenced task input. Observed
/// spellings may name a store or checkout through a symlink: the
/// instance row keeps the first-persisting probe's spelling (goal
/// Step 7), and under the pooled drain either spelling can win —
/// while the fence never follows links. Scheduling or executing at
/// the canonical path keeps the scope pinnable and deterministic
/// regardless of persist order. Mirrors the instance-id derivation
/// in [`persist_probe`]: absolute paths canonicalize with an
/// observed-spelling fallback, relative paths pass through.
fn canonical_exec_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    }
}

async fn enqueue_analysis_task(
    store: &TursoStore,
    runner: &mut Runner,
    generation: u64,
    run_rev: u64,
    instance_id: &str,
    common_dir: &Path,
    now_ms: i64,
) -> repo_scan::Result<()> {
    // Analysis addresses the store object, not the scheduling probe's
    // spelling: a symlinked `.git` spelling would refuse at the fence.
    let scope_key = config::scope_key_for_git(&canonical_exec_path(common_dir));
    let id = format!("analyze:{instance_id}:{run_rev}");
    let idempotency = format!("idem:{id}");
    let expected_rev = store.scope_rev(&scope_key).await?;
    // RSF-AC461500-609D-4D55-991E-09C60D382D67: buffered enqueue.
    let task = NewTask {
        id: &id,
        kind: KIND_ANALYZE,
        generation,
        dir_id: None,
        scope_key: &scope_key,
        expected_rev,
        idempotency_key: &idempotency,
    };
    let due = TursoStore::buffer_enqueue_task(&mut runner.batch, &task, now_ms);
    flush_if_due(runner, store, due).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Event-history ingest + reconcile wiring (R5)
// ---------------------------------------------------------------------------
//
// Scan, resume (via the scan path), and invalidate all run this protocol:
// open per-volume history streams BEFORE the initial traversal
// (monitor-before-traverse), ingest available batches into durable
// invalidations with persisted cursors, traverse, then advance reconciled
// cursors only over satisfied work. History loss invalidates the volume
// scope and forces a fresh traversal generation. macOS uses the live
// FSEvents history surface; other platforms degrade honestly to
// traversal-only with null cursors and an explicit boundary note (never
// fabricated events, never silent completeness).

/// Live event session for one command.
struct EventSession {
    reconciler: events::Reconciler<events::MemoryCursorJournal>,
    monitored: Vec<events::MonitoredVolume>,
    /// Mount path per monitored volume key (root mapping + UUID lookup).
    mounts: HashMap<String, PathBuf>,
    /// Dir scopes applied per volume this run (reconcile satisfaction).
    /// Deduped and capped (see [`note_applied_scopes`]); a volume past the
    /// cap lands in `applied_overflow` instead of growing without bound.
    applied_scopes: HashMap<String, HashSet<String>>,
    /// Volumes whose applied-scope set overflowed: reconciliation holds
    /// their cursors rather than advancing over unknown work.
    applied_overflow: HashSet<String>,
    /// True when a history loss forced a fresh traversal generation.
    history_invalid: bool,
    /// Volumes that degraded (no live history): named in the report note.
    degraded: Vec<String>,
    /// Whether any volume is live-monitored.
    live: bool,
}

/// One scanned volume: stable key plus its mount path.
#[cfg(target_os = "macos")]
struct ScanVolume {
    key: String,
    mount: PathBuf,
}

/// Volumes behind this command: every mount for machine scope, the mounts
/// containing the explicit roots for roots scope.
#[cfg(target_os = "macos")]
fn scan_volumes(policy: &str, roots: &[PlannedRoot]) -> repo_scan::Result<Vec<ScanVolume>> {
    let table = repo_scan::platform::macos::MacOsMountTable;
    let mounts = table.mounts()?;
    if policy == "roots" {
        let mut out: Vec<ScanVolume> = Vec::new();
        for root in roots {
            let deepest = mounts
                .iter()
                .filter(|m| root.path.starts_with(&m.mount_path))
                .max_by_key(|m| m.mount_path.as_os_str().len());
            if let Some(mount) = deepest {
                if !out.iter().any(|v| v.key == mount.volume.0) {
                    out.push(ScanVolume {
                        key: mount.volume.0.clone(),
                        mount: mount.mount_path.clone(),
                    });
                }
            }
        }
        return Ok(out);
    }
    Ok(mounts
        .into_iter()
        .map(|m| ScanVolume {
            key: m.volume.0,
            mount: m.mount_path,
        })
        .collect())
}

/// Durable per-volume cursors, read one volume at a time
/// (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1): the journal is never
/// materialized whole; each volume's cursor derives from bounded pages
/// (RSF-751/AC46/F06D), holding one page at a time.
async fn load_stored_cursors(
    store: &TursoStore,
) -> repo_scan::Result<HashMap<String, events::VolumeCursor>> {
    let mut id_rows = store
        .connection()
        .query(
            "SELECT DISTINCT volume_id FROM event_journal ORDER BY volume_id ASC",
            (),
        )
        .await
        .map_err(store_err)?;
    let mut keys = Vec::new();
    while let Some(row) = id_rows.next().await.map_err(store_err)? {
        keys.push(cell_text(&row, 0)?);
    }
    let mut out = HashMap::new();
    for key in keys {
        let scan = stored_cursor_for_volume(store, &key).await?;
        if let Some(cursor) = scan.cursor {
            out.insert(key, cursor);
        }
    }
    Ok(out)
}

/// One volume's stored cursor plus paging accounting. The cursor equals
/// [`events::volume_cursor_from_rows`] over the volume's whole history
/// (UUID = newest row's; ingested/reconciled = flagged maxima, cursor 0
/// excluded); only one page is ever held.
#[allow(dead_code)]
struct StoredCursorScan {
    cursor: Option<events::VolumeCursor>,
    pages: u64,
    peak_page: usize,
}

/// Derive one volume's stored cursor page by page
/// (RSF-751/AC46/F06D): id-ascending pages with the same
/// interpolated-bounds contract as [`load_open_errors_page`]; running
/// maxima plus the newest UUID accumulate, so completeness never depends
/// on fitting the volume's history in memory.
async fn stored_cursor_for_volume(
    store: &TursoStore,
    volume: &str,
) -> repo_scan::Result<StoredCursorScan> {
    let mut scan = StoredCursorScan {
        cursor: None,
        pages: 0,
        peak_page: 0,
    };
    let mut uuid: Option<String> = None;
    let mut ingested: Option<events::EventCursorId> = None;
    let mut reconciled: Option<events::EventCursorId> = None;
    let mut last_id: i64 = 0;
    loop {
        let sql = format!(
            "SELECT id, history_uuid, cursor, ingested, reconciled FROM event_journal \
             WHERE volume_id = ?1 AND id > {last_id} ORDER BY id ASC LIMIT {LOAD_CHUNK_ROWS}"
        );
        let mut rows = store
            .connection()
            .query(sql.as_str(), vec![turso::Value::Text(volume.to_string())])
            .await
            .map_err(store_err)?;
        let mut page: Vec<(i64, String, String, bool, bool)> = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            page.push((
                cell_int(&row, 0)?,
                cell_text(&row, 1)?,
                cell_text(&row, 2)?,
                cell_int(&row, 3)? != 0,
                cell_int(&row, 4)? != 0,
            ));
            if page.len() as i64 >= LOAD_CHUNK_ROWS {
                break;
            }
        }
        if page.is_empty() {
            break;
        }
        scan.pages += 1;
        scan.peak_page = scan.peak_page.max(page.len());
        let full_page = page.len() as i64 >= LOAD_CHUNK_ROWS;
        for (id, row_uuid, cursor, row_ingested, row_reconciled) in &page {
            uuid = Some(row_uuid.clone());
            if let Some(parsed) = events::parse_journal_cursor(cursor).filter(|c| c.0 != 0) {
                if *row_ingested {
                    ingested = Some(ingested.map_or(parsed, |max| max.max(parsed)));
                }
                if *row_reconciled {
                    reconciled = Some(reconciled.map_or(parsed, |max| max.max(parsed)));
                }
            }
            last_id = last_id.max(*id);
        }
        if !full_page {
            break;
        }
    }
    if uuid.is_some() {
        scan.cursor = Some(events::VolumeCursor {
            uuid: uuid.map(events::HistoryUuid),
            ingested,
            reconciled,
            flags_seen: Vec::new(),
        });
    }
    Ok(scan)
}

#[cfg(target_os = "macos")]
fn live_history_uuid_for(mount: &Path) -> Option<events::HistoryUuid> {
    let dev = events::native::device_of(mount).ok()?;
    events::native::live_history_uuid(dev)
}

/// Open per-volume history streams before any traversal. Stream-open
/// failures degrade that volume (stderr + report note), never the command:
/// the traversal is the source of truth and events only accelerate it.
async fn open_event_session(
    store: &TursoStore,
    state_dir: &Path,
    policy: &str,
    roots: &[PlannedRoot],
) -> repo_scan::Result<EventSession> {
    let stored = load_stored_cursors(store).await?;
    let mut session = EventSession {
        reconciler: events::Reconciler::new(events::MemoryCursorJournal::new()),
        monitored: Vec::new(),
        mounts: HashMap::new(),
        applied_scopes: HashMap::new(),
        applied_overflow: HashSet::new(),
        history_invalid: false,
        degraded: Vec::new(),
        live: false,
    };
    // RSF-F940: seed from durable cursors BEFORE note_stream_opened /
    // begin_traversal. Starting empty with stored state present loses
    // resume position, duplicate suppression, and unreconciled-gap
    // rescan.
    session.reconciler.restore_durable_cursors(&stored);
    // Tool-owned writes must never come back as foreign invalidations.
    let _ = session.reconciler.own_bookkeeping_mut().register(state_dir);
    #[cfg(target_os = "macos")]
    {
        let volumes = scan_volumes(policy, roots)?;
        let mut source = repo_scan::platform::macos::FsEventsSource;
        for volume in &volumes {
            let vid = repo_scan::platform::VolumeId(volume.key.clone());
            match events::monitor_volumes(&mut source, std::slice::from_ref(&vid), &stored) {
                Ok(mut opened) => {
                    let live_uuid = live_history_uuid_for(&volume.mount);
                    let live_id = events::native::current_event_id().0;
                    for mut m in opened.drain(..) {
                        let decision = session.reconciler.note_stream_opened(
                            &volume.key,
                            stored.get(&volume.key),
                            live_uuid.as_ref(),
                            live_id,
                            m.boundary,
                        );
                        // The checked completeness claim applies only
                        // where a historical phase exists (open-rule
                        // Resume). Fresh `SinceNow` opens requested no
                        // history, so no sentinel can arrive and no
                        // claim is attempted for them.
                        m.history_expected = decision.resumed();
                        if decision.history_invalid() {
                            session.history_invalid = true;
                            eprintln!(
                                "repo-scan: events: history loss on volume {}; \
                                 volume scope will be invalidated",
                                volume.key,
                            );
                        }
                        session
                            .mounts
                            .insert(volume.key.clone(), volume.mount.clone());
                        session.monitored.push(m);
                    }
                    session.live = true;
                }
                Err(e) => {
                    eprintln!(
                        "repo-scan: events: volume {} degraded ({}); traversal covers it",
                        volume.key,
                        identity::scrub_text(&e.to_string()),
                    );
                    session.degraded.push(volume.key.clone());
                }
            }
        }
        if session.live {
            session.reconciler.begin_traversal()?;
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (policy, roots, stored);
        session.degraded.push(String::from("all volumes"));
    }
    Ok(session)
}

impl EventSession {
    /// Honest event-history boundary note for the report.
    fn note(&self) -> String {
        if self.live {
            format!(
                "Event-history reconciliation: {} volume(s) monitored live, {} degraded \
                 (full traversal covers all scope; cursors recorded per root).",
                self.monitored.len(),
                self.degraded.len(),
            )
        } else if cfg!(target_os = "macos") {
            String::from(
                "Event-history monitoring unavailable for this run (all volumes degraded); \
                 full traversal only, cursors not recorded.",
            )
        } else {
            String::from(
                "Event history unavailable on this platform (no FSEvents); full traversal \
                 only, cursors not recorded.",
            )
        }
    }
}

/// What one ingest drain applied.
#[derive(Debug, Default)]
struct IngestApplied {
    batches: usize,
    scopes: usize,
    mount_changed: bool,
    /// Volumes whose batch read failed this drain (durable rescan with
    /// retry already scheduled by `apply_batch_error`). The history-close
    /// wait stops waiting on these: a dead stream's sentinel will never
    /// arrive, and its claim fails honestly instead of stalling the rest.
    failed_volumes: Vec<String>,
}

/// True when every history-expected volume's historical phase closed
/// (the reconcile path consumed `HistoryDone`) or errored (a dead
/// stream's sentinel will never arrive; its claim fails honestly).
/// Volumes without live history are vacuously closed: no historical
/// phase exists for them, so the history-close wait pays nothing.
fn volumes_history_closed(session: &EventSession, errored: &HashSet<String>) -> bool {
    session
        .monitored
        .iter()
        .filter(|m| m.history_expected)
        .all(|m| errored.contains(&m.volume_key) || session.reconciler.history_done(&m.volume_key))
}

/// Drain available batches from every monitored stream (bounded per call)
/// and apply them: persist cursors, invalidate scopes. Non-blocking: only
/// already-delivered history is consumed; later arrivals stay queued past
/// the pinned boundaries.
async fn ingest_available_events(
    session: &mut EventSession,
    store: &TursoStore,
    generation: u64,
    roots: &[PlannedRoot],
    counters: &mut RunCounters,
) -> repo_scan::Result<IngestApplied> {
    let mut applied = IngestApplied::default();
    let mut batches: Vec<events::EventBatch> = Vec::new();
    // Batch-read failures are collected, never dropped: each one
    // schedules a durable volume rescan with retry below (RSF-F940).
    let mut failures: Vec<(String, String)> = Vec::new();
    // SR-EVENT-01 liveness contract: `Ok(None)` below means "no batch is
    // available from a live stream on this drain", never "the stream is
    // caught up". The macOS backend proves that: a rotation-aged or
    // stall-suspect stream is recreated inline and yields a volume-wide
    // rescan batch instead of silence, and a dead stream errors into
    // `failures` (durable rescan with retry), never `None`.
    for m in session.monitored.iter_mut() {
        for _ in 0..16 {
            match m.batches.next_batch() {
                Ok(Some(batch)) => batches.push(batch),
                Ok(None) => break,
                Err(e) => {
                    failures.push((m.volume_key.clone(), e.to_string()));
                    break;
                }
            }
        }
    }
    for (volume_key, error) in &failures {
        apply_batch_error(
            session,
            store,
            generation,
            volume_key,
            error,
            counters,
            &mut applied,
        )
        .await?;
    }
    // Scope fence in both spellings: event paths are physical while
    // roots may carry an unclean spelling (`/var` vs `/private/var`).
    // Membership is `..`-normalized, never a raw `starts_with` (finding 12).
    let fence = ScopeFence::build(&roots.iter().map(|r| r.path.clone()).collect::<Vec<_>>());
    // RSF-TOPOLOGY-ADMISSION: the drain rebuilds its fence every call, so
    // unverified root identities persist here exactly as on the scan path.
    for unknown in fence.unknown_roots() {
        let scope_key = config::scope_key_for_dir(&unknown);
        store
            .record_error(
                &format!(
                    "gap:fence-identity:{}",
                    config::encode_hex(&config::path_as_bytes(&unknown))
                ),
                &scope_key,
                "fence-identity-unknown",
                &format!(
                    "root identity unverified for {}; bounded resolve failed or timed out",
                    unknown.display()
                ),
                None,
                store::now_ms(),
            )
            .await?;
        counters.db_transactions += 1;
    }
    for batch in &batches {
        apply_event_batch(
            session,
            store,
            generation,
            roots,
            &fence,
            counters,
            batch,
            &mut applied,
        )
        .await?;
        // RSF-GAP-RECOVERY: a successfully ingested batch proves bounded
        // recovery once the volume's history closed (`HistoryDone`) or its
        // scheduled rescan drained — resolve the matching event gaps in one
        // transaction so old failures never pin later generations. The
        // resolver is read-only without an open gap, so the hot path and
        // its transaction accounting are unchanged.
        let recovered = session.reconciler.history_done(&batch.volume_key)
            || scope_pending_work(store, &events::volume_scope_key(&batch.volume_key)).await? == 0;
        if recovered
            && store
                .resolve_event_gaps_for_volume(&batch.volume_key, store::now_ms())
                .await?
        {
            counters.db_transactions += 1;
        }
    }
    Ok(applied)
}

/// Durable retry for one failed event-batch read (RSF-F940): never
/// log-and-drop. The failed batch covered unknown paths, so per-path
/// retry is unsound; instead the stable gap row plus a volume-scope
/// invalidation schedule a volume rescan with retry. The rescan scope
/// joins the session's applied scopes so reconciled cursors wait for it.
#[allow(clippy::too_many_arguments)]
async fn apply_batch_error(
    session: &mut EventSession,
    store: &TursoStore,
    generation: u64,
    volume_key: &str,
    error: &str,
    counters: &mut RunCounters,
    applied: &mut IngestApplied,
) -> repo_scan::Result<()> {
    let action = events::plan_batch_error(volume_key, error);
    let now = store::now_ms();
    let retry_ms = now.saturating_add(backoff_for_attempt(1).as_millis() as i64);
    store
        .record_error(
            &action.gap_id,
            &action.scope_key,
            events::BATCH_ERROR_CATEGORY,
            &action.detail,
            Some(retry_ms),
            now,
        )
        .await?;
    counters.db_transactions += 1;
    store
        .invalidate_scope(&action.scope_key, generation, now)
        .await?;
    counters.db_transactions += 1;
    applied.scopes += 1;
    applied.failed_volumes.push(volume_key.to_string());
    note_applied_scopes(session, volume_key, std::slice::from_ref(&action.scope_key));
    eprintln!(
        "repo-scan: events: batch error on {volume_key}: {}; \
         volume rescan scheduled with retry",
        identity::scrub_text(error),
    );
    Ok(())
}

/// Apply one batch: durable ingest (cursor persisted with its
/// invalidations) plus scope invalidation. History loss invalidates the
/// volume scope and flags a fresh generation; path changes invalidate the
/// path and parent dir scopes so created/moved-in entries are discovered.
/// Path invalidations are fenced to the scan's planned roots: events are
/// volume-wide, but scheduling work outside the requested scope would leak
/// other trees' findings (and gaps) into this report.
#[allow(clippy::too_many_arguments)]
async fn apply_event_batch(
    session: &mut EventSession,
    store: &TursoStore,
    generation: u64,
    roots: &[PlannedRoot],
    fence: &ScopeFence,
    counters: &mut RunCounters,
    batch: &events::EventBatch,
    applied: &mut IngestApplied,
) -> repo_scan::Result<()> {
    let outcome = session.reconciler.ingest(batch)?;
    applied.batches += 1;
    let now = store::now_ms();
    if outcome.history_invalid {
        session.history_invalid = true;
        let scope = events::volume_scope_key(&outcome.volume_key);
        store.invalidate_scope(&scope, generation, now).await?;
        counters.db_transactions += 1;
        applied.scopes += 1;
        eprintln!(
            "repo-scan: events: history loss on volume {}; scope invalidated",
            outcome.volume_key,
        );
        return Ok(());
    }
    if outcome.duplicate {
        // Restart/overlap replay (RSF-F940): the cursor and its
        // invalidations are already recorded durably. Safe to drop,
        // never double-scheduled.
        return Ok(());
    }
    // The cursor row commits atomically with the scope invalidations
    // below (RSF-F940): no separate append here, so a kill can never
    // persist a cursor with lost invalidations.
    // Dir-key plans (RSF-F940): planner keys carry exact path bytes,
    // so every planner subtree key denotes exactly one scheduler scope
    // through `dir_scope_for_subtree_key` — no fan-out, no collision:
    // distinct siblings always hold distinct keys. Volume and mount
    // plans pass through. Out-of-scope paths are dropped: the journal
    // still records the cursor, but no work is scheduled outside the
    // requested roots.
    let mut scopes: Vec<String> = Vec::new();
    for plan in &outcome.plans {
        if plan.scope_key.starts_with("volume:") || plan.scope_key == events::mounts_scope_key() {
            scopes.push(plan.scope_key.clone());
            if plan.scope_key == events::mounts_scope_key() {
                applied.mount_changed = true;
            }
            continue;
        }
        let mapped = events::dir_scope_for_subtree_key(&plan.scope_key);
        let parsed = events::parse_subtree_scope_key(&plan.scope_key).map(|(_, path)| path);
        let (Some(dir), Some(planned)) = (mapped, parsed) else {
            continue;
        };
        if !fence.allows_path(&planned) {
            continue;
        }
        scopes.push(dir);
    }
    scopes.sort();
    scopes.dedup();
    if scopes.len() > events::MAX_PENDING_INVALIDATIONS {
        scopes = roots
            .iter()
            .map(|r| config::scope_key_for_dir(&r.path))
            .collect();
        scopes.sort();
        scopes.dedup();
        eprintln!(
            "repo-scan: events: invalidation overflow; rescanning {} root(s)",
            scopes.len(),
        );
    }
    note_applied_scopes(session, &outcome.volume_key, &scopes);
    let uuid = session
        .reconciler
        .journal()
        .load(&outcome.volume_key)
        .and_then(|c| c.uuid);
    match uuid {
        Some(uuid) if batch.high_water.0 != 0 => {
            // Atomic ingest (RSF-F940): the cursor row plus every scope
            // invalidation commits in ONE transaction — never a persisted
            // cursor with lost invalidations.
            let cursor = events::journal_cursor_string(batch.high_water);
            let ingested = store
                .ingest_event_batch(
                    &outcome.volume_key,
                    &uuid.0,
                    &cursor,
                    !scopes.is_empty(),
                    &scopes,
                    generation,
                    now,
                )
                .await?;
            counters.db_transactions += 1;
            applied.scopes += ingested.revs.len();
        }
        _ => {
            // No durable history identity (eventless volume) or a zero
            // cursor (RootChanged): invalidate scopes without a cursor row.
            for scope in &scopes {
                store.invalidate_scope(scope, generation, now).await?;
                counters.db_transactions += 1;
                applied.scopes += 1;
            }
        }
    }
    Ok(())
}

/// Non-terminal scheduler work outstanding for one scope.
async fn scope_pending_work(store: &TursoStore, scope_key: &str) -> repo_scan::Result<u64> {
    count_query(
        store,
        "SELECT COUNT(*) FROM frontier_tasks WHERE scope_key = ?1 AND state NOT IN \
         ('complete', 'unsupported', 'cancelled', 'superseded')",
        vec![turso::Value::Text(scope_key.to_string())],
    )
    .await
}

/// Record invalidation scopes applied for one volume
/// (RSF-751/AC46/F06D): deduped and capped per volume at
/// [`events::MAX_PENDING_INVALIDATIONS`]. Past the cap the volume is
/// flagged in `applied_overflow` and reconciliation holds its cursor
/// (see [`reconcile_event_cursors`]) instead of advancing over work the
/// capped set no longer proves satisfied. Invalidation itself is
/// unaffected: every scope is still invalidated and traversed.
fn note_applied_scopes(session: &mut EventSession, volume: &str, scopes: &[String]) {
    if session.applied_overflow.contains(volume) {
        return;
    }
    let mut overflowed = false;
    {
        let applied = session
            .applied_scopes
            .entry(volume.to_string())
            .or_default();
        for scope in scopes {
            if applied.len() >= events::MAX_PENDING_INVALIDATIONS {
                overflowed = true;
                break;
            }
            applied.insert(scope.clone());
        }
    }
    if overflowed {
        session.applied_overflow.insert(volume.to_string());
        eprintln!(
            "repo-scan: events: applied-scope overflow on {volume}; \
             holding reconciled cursor (work still traversed)"
        );
    }
}

/// Checked completeness-claim verdict for one monitored volume (RSF-F940).
struct VolumeClaim {
    volume: String,
    /// True when the history_done-gated claim held.
    complete: bool,
    /// Claim failure detail (empty when complete).
    detail: String,
}

/// Advance reconciled cursors post-traversal, only over satisfied work,
/// attempt the history_done-gated completeness claim per monitored
/// volume, and report per-volume cursors from durable rows (current UUID
/// only).
async fn reconcile_event_cursors(
    session: &mut EventSession,
    store: &TursoStore,
) -> repo_scan::Result<(HashMap<String, RootCursors>, Vec<VolumeClaim>)> {
    let keys: Vec<String> = session
        .monitored
        .iter()
        .map(|m| m.volume_key.clone())
        .collect();
    for key in &keys {
        if session.applied_overflow.contains(key) {
            // Scope set incomplete for this volume: hold the reconciled
            // cursor rather than advancing over unknown work. The work
            // itself is done; only the cursor claim stays conservative.
            continue;
        }
        let pending = session.reconciler.journal().pending(key);
        for boundary in pending {
            let mut scopes = boundary.scopes.clone();
            if let Some(applied) = session.applied_scopes.get(key) {
                scopes.extend(applied.iter().cloned());
            }
            scopes.sort();
            scopes.dedup();
            let mut satisfied = true;
            for scope in &scopes {
                if scope_pending_work(store, scope).await? > 0 {
                    satisfied = false;
                    break;
                }
            }
            if !satisfied {
                break;
            }
            session
                .reconciler
                .journal_mut()
                .mark_reconciled_through(key, boundary.cursor)?;
            mark_events_reconciled_through(store, key, boundary.cursor).await?;
        }
    }
    // Checked completeness claims (RSF-F940): a live volume's claim
    // requires the consumed `history_done` sentinel, so a volume whose
    // historical phase may still be replaying is never treated as
    // event-complete. Failures persist as explicit gaps (EXACT-2/3) plus
    // stderr: the traversal is the source of truth and events only
    // accelerate it, but the incomplete history must surface in report
    // coverage/gaps, catalog status, and exit status — never stderr-only.
    // Durability lives here (not in the caller) so no caller can discard
    // a claim verdict by dropping the returned vec. Volumes that opened
    // fresh (`SinceNow`, no stored cursors) requested no history, so no
    // historical phase exists to close and no claim is attempted for
    // them: attempting one would manufacture a permanent false gap
    // (no sentinel is ever delivered for history that was never
    // requested).
    let history_expected: HashSet<String> = session
        .monitored
        .iter()
        .filter(|m| m.history_expected)
        .map(|m| m.volume_key.clone())
        .collect();
    let mut claims = Vec::with_capacity(keys.len());
    for key in &keys {
        if !history_expected.contains(key) {
            claims.push(VolumeClaim {
                volume: key.clone(),
                complete: true,
                detail: String::new(),
            });
            continue;
        }
        let claim = match session
            .reconciler
            .claim_volume_complete_requiring_history(key)
        {
            Ok(()) => VolumeClaim {
                volume: key.clone(),
                complete: true,
                detail: String::new(),
            },
            Err(e) => VolumeClaim {
                volume: key.clone(),
                complete: false,
                detail: e.to_string(),
            },
        };
        if !claim.complete {
            eprintln!(
                "repo-scan: events: volume {} event completeness not claimed: {}",
                claim.volume,
                identity::scrub_text(&claim.detail),
            );
            let action = events::plan_claim_error(&claim.volume, &claim.detail);
            store
                .record_error(
                    &action.gap_id,
                    &action.scope_key,
                    events::CLAIM_ERROR_CATEGORY,
                    &action.detail,
                    None,
                    store::now_ms(),
                )
                .await?;
        } else {
            // RSF-GAP-RECOVERY: a held claim proves the rescan drained and
            // history closed — resolve this volume's event gaps in one
            // transaction so the old failure never pins later generations.
            // Read-only without an open gap; a later failure re-opens.
            store
                .resolve_event_gaps_for_volume(&claim.volume, store::now_ms())
                .await?;
        }
        claims.push(claim);
    }
    let cursors = report_cursors_from_store(store, session).await?;
    Ok((cursors, claims))
}

/// Mark journal rows at or below `through` reconciled (current UUID
/// only), paged by row id (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1):
/// the current UUID resolves from the newest row first, then marking
/// pages forward holding one page at a time.
async fn mark_events_reconciled_through(
    store: &TursoStore,
    volume: &str,
    through: events::EventCursorId,
) -> repo_scan::Result<()> {
    let mut tip = store
        .connection()
        .query(
            "SELECT history_uuid FROM event_journal WHERE volume_id = ?1 ORDER BY id DESC LIMIT 1",
            vec![turso::Value::Text(volume.to_string())],
        )
        .await
        .map_err(store_err)?;
    let Some(tip_row) = tip.next().await.map_err(store_err)? else {
        return Ok(());
    };
    let current = cell_text(&tip_row, 0)?;
    let mut last_id: i64 = 0;
    loop {
        let sql = format!(
            "SELECT id, history_uuid, cursor FROM event_journal \
             WHERE volume_id = ?1 AND id > {last_id} ORDER BY id ASC LIMIT {LOAD_CHUNK_ROWS}"
        );
        let mut rows = store
            .connection()
            .query(sql.as_str(), vec![turso::Value::Text(volume.to_string())])
            .await
            .map_err(store_err)?;
        let mut page: Vec<(i64, String, String)> = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            page.push((cell_int(&row, 0)?, cell_text(&row, 1)?, cell_text(&row, 2)?));
            if page.len() as i64 >= LOAD_CHUNK_ROWS {
                break;
            }
        }
        if page.is_empty() {
            break;
        }
        let full_page = page.len() as i64 >= LOAD_CHUNK_ROWS;
        for (id, uuid, cursor) in &page {
            if *uuid != current {
                continue;
            }
            let covered = events::parse_journal_cursor(cursor).is_some_and(|c| c.0 <= through.0);
            if covered {
                store.mark_event_reconciled(*id).await?;
            }
        }
        if full_page {
            last_id = page.last().map(|(id, _, _)| *id).unwrap_or(last_id);
        } else {
            break;
        }
    }
    Ok(())
}

/// Per-volume report cursors from durable rows (current UUID only):
/// monitored volumes plus any volume with persisted history. Each
/// volume's rows stream in bounded pages (RSF-751/AC46/F06D); only one
/// page is ever held.
async fn report_cursors_from_store(
    store: &TursoStore,
    session: &EventSession,
) -> repo_scan::Result<HashMap<String, RootCursors>> {
    let mut out = HashMap::new();
    let mut keys: Vec<String> = session
        .monitored
        .iter()
        .map(|m| m.volume_key.clone())
        .collect();
    let mut rows = store
        .connection()
        .query("SELECT DISTINCT volume_id FROM event_journal", ())
        .await
        .map_err(store_err)?;
    while let Some(row) = rows.next().await.map_err(store_err)? {
        let key = cell_text(&row, 0)?;
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    for key in keys {
        let scan = report_cursor_for_volume(store, &key).await?;
        if let Some(cursors) = scan.cursors {
            out.insert(key, cursors);
        }
    }
    Ok(out)
}

/// One volume's report cursors plus paging accounting.
#[allow(dead_code)]
struct ReportCursorScan {
    cursors: Option<RootCursors>,
    pages: u64,
    peak_page: usize,
}

/// Derive one volume's report cursors page by page (RSF-751/AC46/F06D):
/// the current UUID resolves from the newest row first (as in
/// [`mark_events_reconciled_through`]), then current-UUID rows page
/// forward accumulating flagged cursor maxima (cursor 0 excluded) — the
/// same values [`events::volume_cursor_from_rows`] yields over the
/// filtered history, without materializing it.
async fn report_cursor_for_volume(
    store: &TursoStore,
    volume: &str,
) -> repo_scan::Result<ReportCursorScan> {
    let mut scan = ReportCursorScan {
        cursors: None,
        pages: 0,
        peak_page: 0,
    };
    let mut tip = store
        .connection()
        .query(
            "SELECT history_uuid FROM event_journal WHERE volume_id = ?1 ORDER BY id DESC LIMIT 1",
            vec![turso::Value::Text(volume.to_string())],
        )
        .await
        .map_err(store_err)?;
    let Some(tip_row) = tip.next().await.map_err(store_err)? else {
        return Ok(scan);
    };
    let current = cell_text(&tip_row, 0)?;
    let mut ingested: Option<events::EventCursorId> = None;
    let mut reconciled: Option<events::EventCursorId> = None;
    let mut last_id: i64 = 0;
    loop {
        let sql = format!(
            "SELECT id, cursor, ingested, reconciled FROM event_journal \
             WHERE volume_id = ?1 AND history_uuid = ?2 AND id > {last_id} \
             ORDER BY id ASC LIMIT {LOAD_CHUNK_ROWS}"
        );
        let mut rows = store
            .connection()
            .query(
                sql.as_str(),
                vec![
                    turso::Value::Text(volume.to_string()),
                    turso::Value::Text(current.clone()),
                ],
            )
            .await
            .map_err(store_err)?;
        let mut page: Vec<(i64, String, bool, bool)> = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            page.push((
                cell_int(&row, 0)?,
                cell_text(&row, 1)?,
                cell_int(&row, 2)? != 0,
                cell_int(&row, 3)? != 0,
            ));
            if page.len() as i64 >= LOAD_CHUNK_ROWS {
                break;
            }
        }
        if page.is_empty() {
            break;
        }
        scan.pages += 1;
        scan.peak_page = scan.peak_page.max(page.len());
        let full_page = page.len() as i64 >= LOAD_CHUNK_ROWS;
        for (id, cursor, row_ingested, row_reconciled) in &page {
            if let Some(parsed) = events::parse_journal_cursor(cursor).filter(|c| c.0 != 0) {
                if *row_ingested {
                    ingested = Some(ingested.map_or(parsed, |max| max.max(parsed)));
                }
                if *row_reconciled {
                    reconciled = Some(reconciled.map_or(parsed, |max| max.max(parsed)));
                }
            }
            last_id = last_id.max(*id);
        }
        if !full_page {
            break;
        }
    }
    scan.cursors = Some(RootCursors {
        history_uuid: Some(current),
        ingested: ingested.map(|c| c.0.to_string()),
        reconciled: reconciled.map(|c| c.0.to_string()),
    });
    Ok(scan)
}

/// Per-root cursors aligned with `roots`, via the root's mount volume.
fn root_cursors_for(
    roots: &[PlannedRoot],
    session: &EventSession,
    cursors: &HashMap<String, RootCursors>,
) -> Vec<RootCursors> {
    roots
        .iter()
        .map(|root| {
            if let Some(volume) = &root.volume {
                if let Some(c) = cursors.get(&volume.0) {
                    return c.clone();
                }
            }
            let deepest = session
                .mounts
                .iter()
                .filter(|(_, mount)| root.path.starts_with(mount))
                .max_by_key(|(_, mount)| mount.as_os_str().len());
            deepest
                .and_then(|(key, _)| cursors.get(key).cloned())
                .unwrap_or_default()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Scheduler run loop
// ---------------------------------------------------------------------------

/// Run counters (report `resources` + stderr progress).
#[derive(Debug, Clone, Default)]
struct RunCounters {
    claimed: u64,
    dirs_complete: u64,
    entries: u64,
    repos_found: u64,
    probes_complete: u64,
    /// Real store transactions (R13): incremented once per mutating store
    /// call (one autocommit statement, one `with_tx`, or one writer-batch
    /// flush each), never per logical row. This is what the report's
    /// `db_transactions` carries.
    db_transactions: u64,
    stale_requeued: u64,
    /// Measured peak aggregate RSS bytes for the run
    /// (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1).
    peak_rss_bytes: u64,
    /// Measured cumulative CPU seconds at run end (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1).
    cpu_seconds: f64,
    /// Measured database sync calls for the run (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1).
    db_sync_calls: u64,
}

/// One observed pathname alias (R7): `path` names the same filesystem object
/// as `target` (verified by `(dev, ino)` identity at `verified_at_ms`).
#[derive(Debug, Clone)]
struct ObservedAlias {
    path: Vec<u8>,
    target: Vec<u8>,
    kind: &'static str,
    verified_at_ms: i64,
}

/// Boundary verdict for one run.
struct RunOutcome {
    interrupted: bool,
    pending: u64,
    open_gaps: u64,
    unresolvable: u64,
    status_pending: u64,
}

impl RunOutcome {
    fn has_gaps(&self) -> bool {
        self.pending > 0 || self.open_gaps > 0 || self.unresolvable > 0 || self.status_pending > 0
    }
}

/// One alias check deferred until the writer batch flushes
/// (RSF-AC461500-609D-4D55-991E-09C60D382D67): buffered enqueues cannot
/// report whether they won the `INSERT OR IGNORE`, so the
/// same-object/scope comparison runs post-commit via [`note_enum_alias`],
/// which no-ops unless the committed row carries another scope.
struct PendingAliasCheck {
    task_id: String,
    scope_key: String,
    path: PathBuf,
    kind: &'static str,
    at_ms: i64,
}

/// Owner-side run state: admission gates, per-volume breakers, topology
/// guard, and one lazily discovered installed-git fallback.
struct Runner {
    admission: Admission,
    /// Shared mirror of admission memory pressure for worker-owned
    /// [`ReadContext`]s (stored wherever the coordinator calls
    /// `set_pressure`; `Admission` itself stays single-threaded).
    pressure: Arc<AtomicBool>,
    breakers: HashMap<String, CircuitBreaker>,
    topology: Topology,
    /// Descriptor-relative traversal fence (finding 12): `Some` on every
    /// production scan (built from the planned roots in `run_scan_inner`);
    /// `None` only on unit-test runners, which keep the legacy open.
    fence: Option<ScopeFence>,
    inspector: git::GixInspector,
    /// Lazily discovered installed-git fallback, shared with worker
    /// read contexts: discovery runs at most once per run, on first
    /// need, from either side (P3a; replaces the `&mut`-gated probe).
    fallback: Arc<OnceLock<Option<git::fallback::FallbackGit>>>,
    counters: RunCounters,
    /// Pathname aliases observed this run (R7), emitted as `Alias` records.
    /// Insert-deduped via `alias_seen` (RSF-751/AC46/F06D): memory holds
    /// distinct aliases only, exactly what the report emits.
    aliases: Vec<ObservedAlias>,
    /// Distinct `(path, target, kind)` triples already recorded in
    /// `aliases` (RSF-751/AC46/F06D). The report's `alias_inputs`
    /// dedupes identically, so insert-time dedupe drops nothing the
    /// report would keep.
    alias_seen: HashSet<(Vec<u8>, Vec<u8>, &'static str)>,
    /// Set once `aliases`/`alias_seen` hit [`MAX_ALIASES`] (A-F5,
    /// mirroring [`note_applied_scopes`]): further aliases drop and one
    /// `alias-overflow` gap row documents the loss.
    alias_overflow: bool,
    /// Git-directory identities already persisted this run (R7):
    /// `(dev, ino)` of `instance.git_dir` to the first spelling's bytes.
    /// Keyed by the probed store's COMMON-dir identity: a second spelling of
    /// the same store records a path alias, and a linked-worktree admin dir
    /// attaches its checkout — neither duplicates the instance. One small
    /// entry per distinct identity; eviction would duplicate instances, so
    /// the map lives for the run.
    probed_git_ids: HashMap<(u64, u64), Vec<u8>>,
    /// Working-directory identities already persisted this run (R7):
    /// `(dev, ino)` of `instance.work_dir` to deduplicate checkouts
    /// across pathname aliases while preserving distinct working trees.
    probed_work_ids: HashSet<(u64, u64)>,
    /// Set once `probed_git_ids` hits [`MAX_PROBED_GIT_IDS`] (A-F5,
    /// mirroring [`note_applied_scopes`]): further identities persist
    /// without dedupe and one `probe-index-overflow` gap documents it.
    probed_overflow: bool,
    /// Per-operation no-progress watchdog (R9).
    watchdog: Watchdog,
    /// Buffered writer batch (RSF-AC461500-609D-4D55-991E-09C60D382D67):
    /// scan writes buffer here and commit at the spec §5 limits.
    batch: WriterBatch,
    /// Checkpoint cadence (RSF-AC461500-609D-4D55-991E-09C60D382D67).
    checkpoints: CheckpointCoordinator,
    /// Footprint sampler (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1).
    sampler: FootprintSampler,
    /// Peak aggregate RSS bytes observed this run (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1).
    peak_rss_bytes: u64,
    /// Last sampled cumulative CPU seconds (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1).
    cpu_seconds: f64,
    /// Memory-pressure threshold bytes from the effective limits (spec §5).
    pressure_threshold_bytes: u64,
    /// Run-loop start for progress elapsed time (RSF-CHAINARGOS-PROGRESS-001).
    run_started: Instant,
    /// Scope key of the task currently executing (progress position).
    current_scope: String,
    /// Breaker key of the task currently executing (progress volume).
    current_volume: String,
    /// Frontier denominator at the previous progress tick, for
    /// RSF-CHAINARGOS-PROGRESS-002 growth detection: `None` until the
    /// first tick, then the last tick's `total_tasks`.
    progress_last_total: Option<u64>,
    /// Alias checks awaiting the next batch flush (RSF-AC461500-609D-4D55-991E-09C60D382D67).
    /// Bounded by the writer-batch flush contract: every enqueue that
    /// pushes a check also pushes a batch op, and the batch flushes
    /// (draining the checks) at the spec §5 limits.
    pending_alias_checks: Vec<PendingAliasCheck>,
    /// This scan's event journal writer (D4): `Some` on every production
    /// scan (opened in `run_scan_inner` once the scan id exists); `None`
    /// only on unit-test runners, which persist without journaling.
    journal: Option<ScanJournal>,
    /// Error ids currently open (D4 `coverage_updated` gating): preloaded
    /// once per scan from the catalog, then tracked across buffered
    /// records/resolves so deltas fire only on genuine transitions —
    /// never for re-records or zero-row closes.
    open_gaps: HashSet<String>,
    /// Completions buffered into [`Self::batch`] but not yet flushed
    /// (Step 12 batched completion): each entry's conditional SQL commits
    /// with the writer batch, and [`classify_flushed_completions`]
    /// resolves every entry against committed rows after each flush.
    pending_completions: Vec<PendingCompletion>,
}

impl Runner {
    fn new(limits: &config::ResourceLimits) -> Self {
        Self {
            admission: Admission::new(limits.clone()),
            pressure: Arc::new(AtomicBool::new(false)),
            breakers: HashMap::new(),
            topology: Topology::new(),
            fence: None,
            inspector: git::GixInspector::new(),
            fallback: Arc::new(OnceLock::new()),
            counters: RunCounters::default(),
            aliases: Vec::new(),
            alias_seen: HashSet::new(),
            alias_overflow: false,
            probed_git_ids: HashMap::new(),
            probed_work_ids: HashSet::new(),
            probed_overflow: false,
            watchdog: Watchdog::new(Duration::from_secs(WATCHDOG_GRACE_SECS)),
            batch: WriterBatch::new(),
            checkpoints: CheckpointCoordinator::new(CheckpointPolicy::default()),
            sampler: FootprintSampler::new(),
            peak_rss_bytes: 0,
            cpu_seconds: 0.0,
            pressure_threshold_bytes: limits.pressure_threshold_bytes,
            run_started: Instant::now(),
            current_scope: String::new(),
            current_volume: String::new(),
            progress_last_total: None,
            pending_alias_checks: Vec::new(),
            journal: None,
            open_gaps: HashSet::new(),
            pending_completions: Vec::new(),
        }
    }

    /// Installed-git fallback, discovered once per run
    /// (probe-once-per-identity), shared with worker read contexts.
    fn fallback(&self) -> Option<&git::fallback::FallbackGit> {
        self.fallback.get_or_init(discover_fallback).as_ref()
    }

    /// Worker-owned read inputs for one task: everything the `collect_*`
    /// halves need, nothing they must not touch. The coordinator keeps
    /// `&mut Runner` (batch, journal, counters, dedupe maps); the read
    /// half reports heartbeat counts through its `renewals` out-param.
    fn read_context(&self) -> ReadContext {
        ReadContext {
            fence: self.fence.clone(),
            inspector: self.inspector,
            fallback: Arc::clone(&self.fallback),
            watchdog_grace: self.watchdog.grace,
            pressure: Arc::clone(&self.pressure),
        }
    }
}

/// Discover the installed-git fallback once (shared initializer for the
/// coordinator and worker read contexts; at most one discovery per run).
fn discover_fallback() -> Option<git::fallback::FallbackGit> {
    let found = git::fallback::FallbackGit::discover(&[]);
    if let Some(found) = &found {
        eprintln!(
            "repo-scan: installed-git fallback: {} ({})",
            identity::scrub_text(&found.path().display().to_string()),
            found.capabilities().version,
        );
    }
    found
}

/// Worker-owned read inputs for the `collect_*` halves (goal Step 8).
/// `Clone + Send + Sync`: the pool hands one per task to worker threads
/// while the coordinator keeps `&mut Runner`. The only store touch left
/// in the read halves is the lease heartbeat, which moves to the
/// coordinator's scheduled renewal with the pool (P3b).
#[derive(Debug, Clone)]
struct ReadContext {
    /// Traversal fence (`None` = legacy unfenced open in unit tests).
    fence: Option<ScopeFence>,
    /// Git inspector (zero-size `Copy` handle).
    inspector: git::GixInspector,
    /// Lazily discovered installed-git fallback (shared with the
    /// coordinator; discovery runs at most once per run).
    fallback: Arc<OnceLock<Option<git::fallback::FallbackGit>>>,
    /// No-progress watchdog grace (trip counts stay coordinator-side).
    watchdog_grace: Duration,
    /// Live mirror of admission memory pressure.
    pressure: Arc<AtomicBool>,
}

impl ReadContext {
    /// True while memory pressure stops admission (mirror of
    /// `Admission::under_pressure`, readable from worker threads).
    fn under_pressure(&self) -> bool {
        self.pressure.load(Ordering::SeqCst)
    }

    /// Installed-git fallback, discovered on first need.
    fn fallback(&self) -> Option<&git::fallback::FallbackGit> {
        self.fallback.get_or_init(discover_fallback).as_ref()
    }
}

/// Per-operation no-progress watchdog (R9) with bounded grace.
///
/// Attributed to the specific admitted operation: grace runs from admission,
/// and only that operation's own entries or completed directories count as
/// progress. The verdict runs once per task after it returns
/// ([`watchdog_verdict`]), so one stalled scope cannot silently stall the
/// run, and advancing work is never reported as stalled.
///
/// Honest single-owner limits: this process is the only worker and executes
/// operations synchronously, so a hard-hung `stat`/list/Git syscall cannot
/// be preempted — there is no helper to kill and no thread to cancel. The
/// in-loop abort ([`watchdog_inloop_abort`]) only fires between items when
/// no entry completed within grace, preserving the partial enumeration as
/// a `watchdog-no-progress` gap; it never claims cancellation it cannot
/// perform. [`OpDeadline`] extends the same honesty to total wall time:
/// abandonment happens at yield points, and an unkillable syscall (D-state
/// NFS, wedged FUSE) still wedges the process — the lease then expires
/// store-side (no renewal without a yield) so a later owner reclaims the
/// task, and the loud gap names the wedge for the operator.
struct Watchdog {
    grace: Duration,
    tripped: u64,
}

impl Watchdog {
    fn new(grace: Duration) -> Self {
        Self { grace, tripped: 0 }
    }

    /// True when the operation admitted at `admitted` has exhausted its
    /// no-progress grace at `now`. Pure and unit-testable.
    fn exceeded(&self, admitted: Instant, now: Instant) -> bool {
        now.duration_since(admitted) > self.grace
    }
}

/// Blocked-vs-advancing verdict for an admitted operation
/// (RSF-AD9D4AF7-3CC3-4B37-8168-E78DD6375C5B): an over-grace operation
/// that produced entries or completed directories is slow but advancing
/// and is never contained; only an over-grace operation with no observed
/// progress is contained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchdogVerdict {
    WithinGrace,
    Advancing,
    Contained,
}

fn watchdog_verdict(timed_out: bool, advanced: bool) -> WatchdogVerdict {
    match (timed_out, advanced) {
        (false, _) => WatchdogVerdict::WithinGrace,
        (true, true) => WatchdogVerdict::Advancing,
        (true, false) => WatchdogVerdict::Contained,
    }
}

/// In-loop no-progress gate for enumeration (RSF-SEC-WATCHDOG-ABORT):
/// abort only when no entry completed since the last progress mark and
/// the stall exceeds grace. A zero grace disables pre-emption: any
/// nonzero stall would otherwise exceed it before the first entry is
/// attempted, so judgment stays post-hoc via [`watchdog_verdict`]
/// (RSF-AD9D4AF7-3CC3-4B37-8168-E78DD6375C5B). Pure and unit-testable.
fn watchdog_inloop_abort(
    entries_seen: u64,
    progress_mark: u64,
    stalled: Duration,
    grace: Duration,
) -> bool {
    !grace.is_zero() && entries_seen == progress_mark && stalled > grace
}

/// Per-task execution deadline (SR-STATE-01): wall time from admission.
/// Created once per claimed task in [`run_until_boundary`] and enforced
/// cooperatively at every yield point — between enum items, between probe
/// read stages, and through the status interrupt flag. Enforcement is
/// abandonment, not preemption: expired work stops at the next yield,
/// parks the scope with a loud gap ([`park_on_timeout`]), and releases
/// its lease through the normal completion. Nothing leaks: no worker
/// thread is ever detached (the status watch thread always exits by
/// itself), so abandonment is leak-free by construction. Residual, stated
/// honestly: a syscall that never returns never reaches a yield point —
/// the process wedges, the lease expires store-side on its TTL with no
/// renewal, and a later owner reclaims the task; the wedge is bounded by
/// the TTL plus operator attention, not by this wrapper.
#[derive(Debug, Clone, Copy)]
pub struct OpDeadline {
    deadline: Instant,
}

impl OpDeadline {
    /// Deadline `budget` from now.
    pub fn new(budget: Duration) -> Self {
        Self {
            deadline: Instant::now() + budget,
        }
    }

    /// True once the budget is exhausted.
    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Time left, saturating at zero.
    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

/// Parked outcome for a deadline-abandoned op (SR-STATE-01): loud on
/// stderr now; `complete_task` records the durable gap row at completion,
/// so the wedge is evidence, not just a log line.
fn park_on_timeout(detail: &str) -> TaskOutcome {
    eprintln!("repo-scan: {}", identity::scrub_text(detail));
    TaskOutcome::Parked {
        state: TaskState::Unavailable,
        reason: detail.to_string(),
    }
}

/// Complete one finished task (buffered batched completion) and apply
/// the per-task accounting the sequential drain did inline: permit
/// release, slow-task log, watchdog verdict, breaker update, claimed /
/// probe counters, and progress emission. `finished` is the finish
/// output — coordinator-completed (`Done`) outcomes arrive as
/// `Ok((outcome, 0))`. A finished outcome that fails to buffer, or a
/// finish error, aborts the run loudly — same as the sequential drain.
/// Buffered completions commit with the writer batch (classified after
/// each flush); stale verdicts count and print at classify time.
#[allow(clippy::too_many_arguments)]
async fn account_task(
    runner: &mut Runner,
    store: &TursoStore,
    epoch: u64,
    scan_id: &str,
    generation: u64,
    phase: DrainPhase,
    record: &PrepRecord,
    finished: repo_scan::Result<(TaskOutcome, u64)>,
) -> repo_scan::Result<()> {
    let task_id = record.claimed.task.id.clone();
    let volume = record.volume.clone();
    let scope_key = record.claimed.task.scope_key.clone();
    let is_probe = record.claimed.task.kind == KIND_PROBE;
    let started = record.started;
    // Step 12 batched completion (D5): the outcome's conditional SQL
    // joins the writer batch — children buffered during execution
    // commit in the same transaction as the parent completion whenever
    // the batch holds both — and flushes at the row/byte/age caps.
    let units = match finished {
        Ok((outcome, units)) => {
            let due = buffer_completion(runner, store, &record.claimed, epoch, &outcome)?;
            flush_if_due(runner, store, due).await?;
            runner.admission.release(&record.permit);
            if is_probe {
                runner.counters.probes_complete += 1;
            }
            units
        }
        Err(e) => {
            // The permit still releases and the watchdog still evaluates
            // before the run aborts loudly. No outcome was produced, so
            // advancement is false.
            runner.admission.release(&record.permit);
            let elapsed = started.elapsed();
            if elapsed > Duration::from_secs(SLOW_TASK_SECS) {
                eprintln!("repo-scan: slow task: {task_id} ({}s)", elapsed.as_secs());
            }
            apply_watchdog_with_scope(
                runner, store, &task_id, &volume, &scope_key, started, elapsed, false,
            )
            .await?;
            return Err(e);
        }
    };
    let elapsed = started.elapsed();
    if elapsed > Duration::from_secs(SLOW_TASK_SECS) {
        eprintln!("repo-scan: slow task: {task_id} ({}s)", elapsed.as_secs());
    }
    // RSF-AD9D4AF7-3CC3-4B37-8168-E78DD6375C5B: a contained (timed-out,
    // non-advancing) task must never clear its containment via
    // success-after-timeout.
    let advanced = units > 0;
    let contained = apply_watchdog_with_scope(
        runner, store, &task_id, &volume, &scope_key, started, elapsed, advanced,
    )
    .await?;
    if !contained {
        runner.breaker_success(&volume);
    }
    runner.counters.claimed += 1;
    // At-most-2 Hz token-timer gate (RSF-CHAINARGOS-PROGRESS-001):
    // progress lines carry position, pending, and elapsed.
    // R06: Also emit promptly on probe completions to surface discovered repositories.
    // Journaled progress stays on due-ticks only (Step 12 bounded
    // rate): probe-prompt lines are stderr-only, since each probe
    // already journals its found events.
    let journal_tick = !is_probe && runner.admission.progress_due();
    if is_probe || journal_tick {
        emit_progress(runner, store, scan_id, generation, phase, journal_tick).await?;
    }
    Ok(())
}

/// Post-task watchdog verdict for one finished task
/// (RSF-AD9D4AF7-3CC3-4B37-8168-E78DD6375C5B, SR-STATE-01):
/// distinguishes blocked from advancing tasks. Progress reported
/// during the task counts even past grace; only a past-grace task with
/// no observed progress trips. `advanced` is the worker's own progress
/// report — parallel tasks share the global counters, so per-task
/// growth cannot be inferred from them. The operation already returned,
/// so the breaker below is re-admission delay for a slow volume, NOT
/// containment of the returned operation (nothing was stopped); the
/// stall itself is recorded durably as a gap so the run carries
/// evidence instead of stderr alone. Returns `contained`.
#[allow(clippy::too_many_arguments)]
async fn apply_watchdog_with_scope(
    runner: &mut Runner,
    store: &TursoStore,
    task_id: &str,
    volume: &str,
    scope_key: &str,
    started: Instant,
    elapsed: Duration,
    advanced: bool,
) -> repo_scan::Result<bool> {
    let timed_out = runner.watchdog.exceeded(started, Instant::now());
    match watchdog_verdict(timed_out, advanced) {
        WatchdogVerdict::WithinGrace => {}
        WatchdogVerdict::Advancing => {
            runner.watchdog.tripped += 1;
            eprintln!(
                "repo-scan: watchdog: {task_id} slow ({}s) but advancing; not contained",
                elapsed.as_secs(),
            );
        }
        WatchdogVerdict::Contained => {
            runner.watchdog.tripped += 1;
            runner.breaker_failure(volume);
            runner.breaker_failure(volume);
            runner.breaker_failure(volume);
            // SR-STATE-01: durable stall evidence. A past-grace
            // no-progress task that still completed did its work,
            // so the stall row is recorded then closed (auditable
            // in the catalog, not a false open gap); a failed task
            // keeps its own failure gap alongside.
            let stall_id = format!("watchdog-no-progress:{task_id}");
            let stall_detail = format!(
                "watchdog: {task_id} made no progress within {}s (elapsed {}s); \
                 volume {volume} breaker opened",
                runner.watchdog.grace.as_secs(),
                elapsed.as_secs(),
            );
            let stall_now = store::now_ms();
            buffer_record_error(
                runner,
                &stall_id,
                scope_key,
                "watchdog-no-progress",
                &stall_detail,
                None,
                stall_now,
            )?;
            buffer_resolve_error(runner, &stall_id, stall_now)?;
            let stall_due = runner.batch.should_flush();
            flush_if_due(runner, store, stall_due).await?;
            eprintln!(
                "repo-scan: watchdog: {task_id} made no progress within {}s; \
                 volume {volume} breaker opened (re-admission delayed), stall recorded",
                runner.watchdog.grace.as_secs(),
            );
        }
    }
    Ok(timed_out && !advanced)
}

/// Claim and execute tasks until the boundary: no claimable work remains
/// (only future backoffs, parked scopes, or nothing), or SIGINT arrives.
/// Every completion goes through the store's epoch/lease/revision guards.
#[allow(clippy::too_many_arguments)]
async fn run_until_boundary(
    runner: &mut Runner,
    store: &TursoStore,
    epoch: u64,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    status_mode: StatusMode,
    scan_id: &str,
    phase: DrainPhase,
) -> repo_scan::Result<RunOutcome> {
    loop {
        if interrupted() {
            eprintln!("repo-scan: interrupted; saving progress (bounded)");
            break;
        }
        // Step 12 batched completion: buffered completions are invisible
        // until flushed, so every claim round starts by committing them —
        // a claim must observe completed, stale-requeued, and retried
        // tasks, and an empty claim must mean an empty queue, never an
        // unflushed one. No-op when the batch is empty.
        flush_runner_batch(runner, store).await?;
        let now = store::now_ms();
        // RSF-3E2FDCF3-78C5-401A-84DD-A799688ED84F: claims are scoped to
        // this run's traversal generation, so a resumed or force-rescan
        // run never drains another generation's work and claimed tasks
        // stay visible to that generation's `pending_count` boundary.
        // Phase gating (goal Step 8): only this phase's kinds claim.
        let claimed = store
            .claim_tasks_in_generation_kinds(
                generation,
                epoch,
                CLAIM_BATCH,
                LEASE_TTL_MS,
                now,
                phase.kinds(),
            )
            .await?;
        runner.counters.db_transactions += 1;
        if claimed.is_empty() {
            break;
        }
        let mut progressed = false;
        // Phase 1: admit, prepare, and spawn. Workers run filesystem/Git
        // reads on pool threads while the coordinator keeps the store.
        // Phase 2 (below) joins every spawned worker before the next
        // claim, so the boundary always sees an empty in-flight set:
        // an empty queue never reads as completion while workers can
        // still add results.
        let mut set: tokio::task::JoinSet<(PrepRecord, repo_scan::Result<WorkerOut>)> =
            tokio::task::JoinSet::new();
        // In-flight lease tickets for the renewal tick, keyed by task id.
        let mut inflight: HashMap<String, (i64, u64)> = HashMap::new();
        for item in &claimed {
            if interrupted() {
                break;
            }
            let volume = breaker_key_for_task(&item.task.scope_key);
            let breaker_closed = runner
                .breakers
                .get(&volume)
                .is_some_and(|breaker| !breaker.allow(SystemTime::now()));
            if breaker_closed {
                // The lease is explicitly released (R4): breaker-held
                // work returns to `pending` immediately instead of
                // leaking until the 60 s TTL, so a prompt resume can
                // proceed the moment the breaker re-admits.
                release_claim(store, &mut runner.counters, item, epoch).await?;
                continue;
            }
            let class = match item.task.kind.as_str() {
                KIND_ENUM | KIND_RECONCILE => OpClass::Enumerate,
                KIND_PROBE | KIND_STATUS | KIND_ANALYZE => OpClass::GitProbe,
                _ => OpClass::Other,
            };
            let Some(permit) = runner.admission.try_acquire(class) else {
                // Same explicit release for admission denials (R4).
                release_claim(store, &mut runner.counters, item, epoch).await?;
                continue;
            };
            progressed = true;
            // RSF-CHAINARGOS-PROGRESS-001: progress position follows the
            // task actually executing.
            runner.current_scope = item.task.scope_key.clone();
            runner.current_volume = volume.clone();
            let started = Instant::now();
            // SR-STATE-01: one wall budget per admitted task, enforced at
            // every yield point of the worker and its finish.
            let deadline = OpDeadline::new(Duration::from_secs(OP_DEADLINE_SECS));
            let prepared = prepare_task(
                runner,
                store,
                status_mode,
                item,
                permit,
                volume,
                started,
                &deadline,
            )
            .await?;
            // RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1: at-most-1 Hz
            // footprint sample with pressure response.
            if runner.admission.telemetry_due() {
                sample_footprint(runner);
            }
            // CPU-governor pacing (spec §5): bounded pause between
            // admissions while throttled; zero otherwise.
            let pace = runner.admission.pace_delay();
            if !pace.is_zero() {
                std::thread::sleep(pace);
            }
            match prepared.action {
                PrepAction::Done(outcome) => {
                    account_task(
                        runner,
                        store,
                        epoch,
                        scan_id,
                        generation,
                        phase,
                        &prepared.record,
                        Ok((outcome, 0)),
                    )
                    .await?;
                }
                PrepAction::Spawn(job) => {
                    let record = prepared.record;
                    inflight.insert(
                        record.claimed.task.id.clone(),
                        (
                            record.claimed.token,
                            record.claimed.task.lease_epoch.unwrap_or(u64::MAX),
                        ),
                    );
                    set.spawn_blocking(move || (record, run_worker(job)));
                }
            }
        }
        // Phase 2: join every spawned worker, renewing in-flight leases
        // on schedule (Step 9) until the set drains.
        if !set.is_empty() {
            let mut ticker = tokio::time::interval(Duration::from_secs(RENEW_TICK_SECS));
            // The first interval tick completes immediately; consume it
            // so renewals run on cadence, not at join start.
            ticker.tick().await;
            while !set.is_empty() {
                if interrupted() {
                    // Stop admission: finish what already completed
                    // (bounded — no waiting), then detach the rest.
                    // Detached leases lapse without the tick and a resume
                    // reclaims them; committed work saves below.
                    while let Some(joined) = set.try_join_next() {
                        let (record, result) = joined.map_err(|join_err| {
                            repo_scan::Error::Scheduler(format!("worker task failed: {join_err}"))
                        })?;
                        inflight.remove(&record.claimed.task.id);
                        let finished = finish_task(
                            runner, store, generation, run_rev, canonical, &record, result,
                        )
                        .await;
                        account_task(
                            runner, store, epoch, scan_id, generation, phase, &record, finished,
                        )
                        .await?;
                    }
                    break;
                }
                tokio::select! {
                    joined = set.join_next() => {
                        let (record, result) = joined
                            .expect("drain JoinSet held a live task")
                            .map_err(|join_err| {
                                // A panicking worker is a scheduler bug,
                                // not a scope gap: abort the run loudly
                                // instead of hiding unfinished work.
                                repo_scan::Error::Scheduler(format!(
                                    "worker task failed: {join_err}"
                                ))
                            })?;
                        inflight.remove(&record.claimed.task.id);
                        let finished = finish_task(
                            runner, store, generation, run_rev, canonical, &record, result,
                        )
                        .await;
                        account_task(
                            runner,
                            store,
                            epoch,
                            scan_id,
                            generation,
                            phase,
                            &record,
                            finished,
                        )
                        .await?;
                    }
                    _ = ticker.tick() => {
                        if inflight.is_empty() {
                            continue;
                        }
                        let tickets: Vec<(&str, i64, u64)> = inflight
                            .iter()
                            .map(|(id, (token, lease_epoch))| {
                                (id.as_str(), *token, *lease_epoch)
                            })
                            .collect();
                        // `renew_leases_batch` returns the ids it could NOT
                        // renew (lost leases); the rest renewed.
                        let lost = store
                            .renew_leases_batch(&tickets, LEASE_TTL_MS, store::now_ms())
                            .await?;
                        runner.counters.db_transactions += 1;
                        if !lost.is_empty() {
                            eprintln!(
                                "repo-scan: renewal tick renewed {}/{} in-flight leases; \
                                 unrenewed results stop at the pre-persist gate",
                                tickets.len() - lost.len(),
                                tickets.len(),
                            );
                        }
                    }
                }
            }
        }
        if !progressed {
            // Everything claimable is breaker-held: the boundary for this run.
            break;
        }
    }
    // RSF-AC461500-609D-4D55-991E-09C60D382D67: buffered rows must be
    // committed before boundary accounting reads them.
    flush_runner_batch(runner, store).await?;
    // RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1: forced final sample so the
    // report carries measured resources, never None-after-run. Under
    // `synchronous = FULL` every counted transaction syncs at least once;
    // explicit checkpoints add their own syncs.
    sample_footprint(runner);
    runner.counters.peak_rss_bytes = runner.peak_rss_bytes;
    runner.counters.cpu_seconds = runner.cpu_seconds;
    let store_stats = store.stats();
    runner.counters.db_sync_calls = store_stats
        .transactions
        .saturating_add(store_stats.checkpoints);
    // Phase-scoped boundary accounting (goal Step 8): the discovery
    // outcome counts discovery kinds only. Analysis kinds have not
    // started yet, so they contribute neither `pending` (which would
    // poison the `inventory_ready` verdict) nor `status_pending`
    // (zero by construction pre-boundary). The analysis drain is the
    // last task drain, so its `pending` counts ALL kinds: analysis
    // residue plus any discovery stragglers a post-boundary
    // invalidation scheduled (those stay pending honestly instead of
    // executing out of phase).
    let pending = match phase {
        DrainPhase::Discovery => store.pending_count_kinds(generation, phase.kinds()).await?,
        DrainPhase::Analysis => store.pending_count(generation).await?,
    };
    let open_gaps = count_open_errors(store).await?;
    let unresolvable = count_unresolvable(store).await?;
    let status_pending = match phase {
        DrainPhase::Discovery => 0,
        DrainPhase::Analysis => count_status_pending(store, generation).await?,
    };
    Ok(RunOutcome {
        interrupted: interrupted(),
        pending,
        open_gaps,
        unresolvable,
        status_pending,
    })
}

/// Explicitly release one claimed task back to `pending` (R4) when a
/// breaker or admission gate denies it after the claim. The release verifies
/// the exact lease token/epoch (never touching another owner's lease) and
/// does not bump attempts: gate denial is scheduler state, not task failure.
/// One transaction, counted as such.
async fn release_claim(
    store: &TursoStore,
    counters: &mut RunCounters,
    claimed: &ClaimedTask,
    epoch: u64,
) -> repo_scan::Result<()> {
    store
        .release_claim(&claimed.task.id, claimed.token, epoch, store::now_ms())
        .await?;
    counters.db_transactions += 1;
    Ok(())
}

/// One footprint sample into run state with pressure response
/// (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1). The owner folds its live
/// admission snapshot into the sampler. Reaped-subprocess CPU
/// (`RUSAGE_CHILDREN`, e.g. installed-git fallback probes) is measured
/// automatically inside the sampler, so the owner passes 0.0 retained CPU
/// unless it tracks CPU the kernel cannot see. Live-helper RSS is
/// `Some(0)` (measured zero) while this sequential design spawns no helpers
/// and `None` (honest unknown, aggregate is owner-only) if helpers ever go
/// live without instrumentation — never a hardcoded fake zero. Pressure
/// trips on the aggregate reading against the 512 MiB threshold; when helper
/// RSS is unknown that reading is an owner-only lower bound and the pressure
/// line says so.
fn sample_footprint(runner: &mut Runner) {
    let admitted = runner.admission.snapshot();
    // RSF-FALLBACK-HELPER-SECURITY(6): installed-git spawns charge
    // HELPER_LEDGER at the spawn choke point, never the owner counters,
    // so the ledger is the source of truth here; stuck/unknown helpers
    // stay explicit and loud.
    let helper_tally = git::fallback::helper_telemetry();
    let helpers_live = admitted.helpers_live.max(helper_tally.live);
    if helper_tally.stuck + helper_tally.unknown > 0 {
        eprintln!(
            "repo-scan: helper telemetry: {} live (cap {}), {} stuck, {} unknown",
            helpers_live, helper_tally.cap, helper_tally.stuck, helper_tally.unknown,
        );
    }
    let sample = runner.sampler.sample_with(&SamplerInputs {
        helpers_rss_bytes: live_helper_rss_bytes(helpers_live),
        helpers_cpu_seconds: 0.0,
        app_fds: admitted.app_fds,
        admitted_enum_ops: admitted.enum_in_use,
        admitted_git_probes: admitted.git_in_use,
        helpers: helpers_live,
    });
    runner.peak_rss_bytes = runner.peak_rss_bytes.max(sample.aggregate_rss_bytes);
    runner.cpu_seconds = sample.cpu_seconds;
    let pressured = sample.aggregate_rss_bytes > runner.pressure_threshold_bytes;
    let rising = pressured && !runner.admission.under_pressure();
    runner.admission.set_pressure(pressured);
    runner.pressure.store(pressured, Ordering::SeqCst);
    // CPU governor (spec §5): sustained rolling-core excess reduces
    // admission and paces work; hysteresis lives in `observe_cpu`.
    let was_throttled = runner.admission.cpu_throttled();
    runner.admission.observe_cpu(sample.rolling_cores);
    if runner.admission.cpu_throttled() && !was_throttled {
        eprintln!(
            "repo-scan: CPU throttle: rolling {:.2} cores over target; admission reduced",
            sample.rolling_cores,
        );
    }
    if rising {
        let helper_note = match sample.helpers_rss_bytes {
            Some(_) => "measured",
            None => "owner-only lower bound; live-helper RSS unknown (not instrumented)",
        };
        eprintln!(
            "repo-scan: memory pressure: RSS {} bytes over threshold {} bytes \
             (helpers: {helper_note}); admission stopped",
            sample.aggregate_rss_bytes, runner.pressure_threshold_bytes,
        );
    }
}

/// Cumulative progress context for one generation
/// (RSF-F2865989-7199-472B-A9D8-9C54C88656EB, RSF-CHAINARGOS-RESUME-002,
/// RSF-CHAINARGOS-SPEED-003): frontier denominator plus cumulative totals
/// across resumes. The frontier denominator grows as discovery enqueues
/// children, so it is a lower bound, not a fixed scope total.
#[derive(Debug, Clone, Copy, Default)]
struct ProgressTotals {
    /// Frontier tasks still needing scheduler action (this generation).
    pending: u64,
    /// All frontier tasks enqueued so far (this generation; grows).
    total_tasks: u64,
    /// Cumulative completed directories (all runs, this generation).
    cum_dirs: u64,
    /// Cumulative entries seen (all runs, this generation).
    cum_entries: u64,
}

impl ProgressTotals {
    /// Frontier tasks finished so far (total minus pending).
    fn done_tasks(&self) -> u64 {
        self.total_tasks.saturating_sub(self.pending)
    }
}

/// Load the cumulative progress context for one progress tick (at most 2 Hz).
/// Four cheap indexed counts; failures propagate instead of printing stale
/// totals.
async fn load_progress_totals(
    store: &TursoStore,
    generation: u64,
) -> repo_scan::Result<ProgressTotals> {
    let pending = store.pending_count(generation).await?;
    let total_tasks = count_query(
        store,
        "SELECT COUNT(*) FROM frontier_tasks WHERE generation = ?1",
        vec![turso::Value::Integer(i64::try_from(generation).map_err(
            |_| repo_scan::Error::Store(format!("task generation {generation} exceeds i64 range")),
        )?)],
    )
    .await?;
    let cum_dirs = count_dirs_complete(store, generation).await?;
    let cum_entries = count_query(
        store,
        "SELECT COALESCE(SUM(entries_seen), 0) FROM dir_observations WHERE generation = ?1",
        vec![turso::Value::Integer(i64::try_from(generation).map_err(
            |_| repo_scan::Error::Store(format!("task generation {generation} exceeds i64 range")),
        )?)],
    )
    .await?;
    Ok(ProgressTotals {
        pending,
        total_tasks,
        cum_dirs,
        cum_entries,
    })
}

/// Session throughput for one progress tick (tasks/s), or an explicit
/// unknown with reason when the rate is not yet meaningful.
fn format_progress_rate(session_claimed: u64, elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64();
    if secs < 0.5 {
        return String::from("unknown (warming-up: <0.5s elapsed)");
    }
    format!("{:.1} tasks/s", session_claimed as f64 / secs)
}

/// ETA for one progress tick (RSF-F2865989-7199-472B-A9D8-9C54C88656EB,
/// RSF-CHAINARGOS-SPEED-003): `0s` when nothing is pending, a `~Ns` lower
/// bound from this session's claimed-task rate otherwise, or an explicit
/// `unknown (<reason>)` when no defensible rate exists yet. A known ETA is a
/// lower bound because the frontier denominator grows as discovery enqueues
/// children; the full machine dir count is unknowable until traversal
/// completes (see `scope_total` in the progress line).
fn format_progress_eta(session_claimed: u64, pending: u64, elapsed: Duration) -> String {
    if pending == 0 {
        return String::from("0s");
    }
    let secs = elapsed.as_secs_f64();
    if secs < 2.0 {
        return String::from("unknown (warming-up: <2s elapsed, rate unstable)");
    }
    if session_claimed == 0 {
        return String::from("unknown (no session progress yet, rate undefined)");
    }
    let rate = session_claimed as f64 / secs;
    if !rate.is_finite() || rate <= 0.0 {
        return String::from("unknown (session rate non-positive)");
    }
    let eta = (pending as f64 / rate).ceil().max(0.0) as u64;
    format!("~{eta}s (lower bound; denominator grows with discovery)")
}

/// Growth-aware ETA (RSF-CHAINARGOS-PROGRESS-002): when the frontier
/// denominator grew since the previous tick there is no stable total, so
/// the ETA is an explicit unknown naming the growth — never a `~Ns`
/// estimate over a moving denominator. `0s` still short-circuits when
/// nothing is pending; a stable denominator delegates to
/// [`format_progress_eta`].
fn format_progress_eta_growth(
    session_claimed: u64,
    pending: u64,
    elapsed: Duration,
    denominator_grew: bool,
    new_since_tick: u64,
) -> String {
    if pending == 0 {
        return String::from("0s");
    }
    if denominator_grew {
        return format!(
            "unknown (frontier denominator still growing: +{new_since_tick} tasks since last \
             tick; no stable total until discovery completes)"
        );
    }
    format_progress_eta(session_claimed, pending, elapsed)
}

/// `discovery_progress` records (D4): phase, elapsed, discovered
/// counts, pending, and open gaps — committed catalog reads only (the
/// event journals only after its underlying state commits), and no
/// percent of an unknown total.
fn discovery_progress_records(
    phase: DrainPhase,
    elapsed: Duration,
    totals: &ProgressTotals,
    open_gaps: u64,
) -> repo_scan::Result<Vec<u8>> {
    let phase_name = match phase {
        DrainPhase::Discovery => "discovery",
        DrainPhase::Analysis => "analysis",
    };
    let records = serde_json::json!({
        "phase": phase_name,
        "elapsed_s": elapsed.as_secs(),
        "discovered": {
            "tasks_done": totals.done_tasks(),
            "dirs": totals.cum_dirs,
            "entries": totals.cum_entries,
        },
        "pending": totals.pending,
        "gaps": { "open": open_gaps },
    });
    serde_json::to_vec(&records).map_err(|e| repo_scan::Error::Report(e.to_string()))
}

/// Buffer one `discovery_progress` tick when this runner journals
/// (production scans); unit-test runners (`journal: None`) persist
/// without journaling.
async fn journal_discovery_progress(
    runner: &mut Runner,
    store: &TursoStore,
    records: &[u8],
) -> repo_scan::Result<()> {
    let Some(journal) = runner.journal.as_mut() else {
        return Ok(());
    };
    if let Some(due) = journal.buffer_discovery_progress(&mut runner.batch, records)? {
        flush_if_due(runner, store, due).await?;
    }
    Ok(())
}

/// Emit one 2 Hz progress line with scan position and completion context
/// (RSF-CHAINARGOS-PROGRESS-001): current scope/volume, session counters,
/// cumulative scan totals, frontier denominator, throughput, ETA, and elapsed
/// run time. Session counters are per-invocation run totals
/// (RSF-CHAINARGOS-RESUME-002): a resume starts a new run at 1/1/1 and the
/// `session(this run)` vs `cumulative(scan total)` labels keep that
/// unambiguous. Still gated at most 2 Hz by the caller. On due-ticks
/// (`journal_progress`) the tick also journals a coalesced
/// `discovery_progress` gauge event (Step 12); probe-prompt lines stay
/// stderr-only.
async fn emit_progress(
    runner: &mut Runner,
    store: &TursoStore,
    scan_id: &str,
    generation: u64,
    phase: DrainPhase,
    journal_progress: bool,
) -> repo_scan::Result<()> {
    let totals = load_progress_totals(store, generation).await?;
    // RSF-CHAINARGOS-PROGRESS-002: compare the frontier denominator
    // against the previous tick; growth forces an explicit-unknown ETA.
    let (denominator_grew, new_since_tick) = match runner.progress_last_total {
        Some(last) => (
            totals.total_tasks > last,
            totals.total_tasks.saturating_sub(last),
        ),
        None => (false, 0),
    };
    runner.progress_last_total = Some(totals.total_tasks);
    let elapsed = runner.run_started.elapsed();
    let line = format_progress_line_full_with_growth(
        scan_id,
        generation,
        &runner.counters,
        &totals,
        elapsed,
        &runner.current_scope,
        &runner.current_volume,
        denominator_grew,
        new_since_tick,
    );
    eprintln!("{line}");
    if journal_progress {
        let open_gaps = count_open_errors(store).await?;
        let records = discovery_progress_records(phase, elapsed, &totals, open_gaps)?;
        journal_discovery_progress(runner, store, &records).await?;
    }
    Ok(())
}

/// Full progress line with store totals: session counters plus cumulative
/// scan totals, frontier denominator, rate, and ETA.
/// Test-only: production `emit_progress` uses the `_with_growth` variant.
#[cfg(test)]
fn format_progress_line_full(
    scan_id: &str,
    generation: u64,
    counters: &RunCounters,
    totals: &ProgressTotals,
    elapsed: Duration,
    scope: &str,
    volume: &str,
) -> String {
    let rate = format_progress_rate(counters.claimed, elapsed);
    let eta = format_progress_eta(counters.claimed, totals.pending, elapsed);
    format_progress_line_full_inner(
        scan_id, generation, counters, totals, elapsed, scope, volume, &rate, &eta, "",
    )
}

/// Full progress line with RSF-CHAINARGOS-PROGRESS-002 growth context:
/// growth-aware ETA plus a `denominator=` stability token. Production
/// `emit_progress` uses this; [`format_progress_line_full`] keeps the
/// growth-agnostic shape.
#[allow(clippy::too_many_arguments)]
fn format_progress_line_full_with_growth(
    scan_id: &str,
    generation: u64,
    counters: &RunCounters,
    totals: &ProgressTotals,
    elapsed: Duration,
    scope: &str,
    volume: &str,
    denominator_grew: bool,
    new_since_tick: u64,
) -> String {
    let rate = format_progress_rate(counters.claimed, elapsed);
    let eta = format_progress_eta_growth(
        counters.claimed,
        totals.pending,
        elapsed,
        denominator_grew,
        new_since_tick,
    );
    let growth = if denominator_grew {
        format!(" denominator=growing(+{new_since_tick} since last tick)")
    } else {
        String::from(" denominator=stable(since last tick)")
    };
    format_progress_line_full_inner(
        scan_id, generation, counters, totals, elapsed, scope, volume, &rate, &eta, &growth,
    )
}

/// Shared full-line renderer: `growth_note` is empty for the
/// growth-agnostic entry and a `denominator=` token otherwise.
#[allow(clippy::too_many_arguments)]
fn format_progress_line_full_inner(
    scan_id: &str,
    generation: u64,
    counters: &RunCounters,
    totals: &ProgressTotals,
    elapsed: Duration,
    scope: &str,
    volume: &str,
    rate: &str,
    eta: &str,
    growth_note: &str,
) -> String {
    format!(
        "repo-scan: scan {scan_id} gen {generation} session(this run): claimed={} dirs={} \
         entries={} repos={} probes={} stale-requeued={} | cumulative(scan total): tasks_done={}/{} dirs={} \
         entries={} pending={} | elapsed={}s rate={} eta={} scope={} volume={} \
         scope_total=unknown (full machine dir count unknowable until traversal completes)\
         {growth_note}",
        counters.claimed,
        counters.dirs_complete,
        counters.entries,
        counters.repos_found,
        counters.probes_complete,
        counters.stale_requeued,
        totals.done_tasks(),
        totals.total_tasks,
        totals.cum_dirs,
        totals.cum_entries,
        totals.pending,
        elapsed.as_secs(),
        rate,
        eta,
        if scope.is_empty() { "-" } else { scope },
        if volume.is_empty() { "-" } else { volume },
    )
}

#[cfg(test)]
fn format_progress_line(
    scan_id: &str,
    generation: u64,
    counters: &RunCounters,
    pending: u64,
    elapsed: Duration,
    scope: &str,
    volume: &str,
) -> String {
    // Backward-compatible entry without store totals: session-labeled
    // counters plus explicit unknowns with reasons. Production
    // `emit_progress` prefers `format_progress_line_full` with the frontier
    // denominator and cumulative totals.
    let rate = format_progress_rate(counters.claimed, elapsed);
    let eta = format_progress_eta(counters.claimed, pending, elapsed);
    format!(
        "repo-scan: scan {scan_id} gen {generation} session(this run): claimed={} dirs={} \
         entries={} repos={} probes={} stale-requeued={} | cumulative(scan total)=unknown (store totals not \
         loaded in this context) tasks_total=unknown (frontier denominator not loaded) \
         pending={pending} | elapsed={}s rate={} eta={} scope={} volume={} scope_total=unknown \
         (full machine dir count unknowable until traversal completes)",
        counters.claimed,
        counters.dirs_complete,
        counters.entries,
        counters.repos_found,
        counters.probes_complete,
        counters.stale_requeued,
        elapsed.as_secs(),
        rate,
        eta,
        if scope.is_empty() { "-" } else { scope },
        if volume.is_empty() { "-" } else { volume },
    )
}

/// Flush buffered writer ops in one transaction
/// (RSF-AC461500-609D-4D55-991E-09C60D382D67). Applied ops feed the
/// checkpoint cadence ([`CheckpointCoordinator::note_ops`] /
/// [`CheckpointCoordinator::maybe_checkpoint`], which calls `wal_status`
/// and, over budget, `checkpoint_truncate`); completions the flush
/// committed classify next (applied entries buffer their gap events for
/// the following flush); retention prunes last; deferred alias checks
/// then run against committed rows. Returns applied ops. One
/// transaction, counted as such (a prune commits its own, counted too).
async fn flush_runner_batch(runner: &mut Runner, store: &TursoStore) -> repo_scan::Result<u64> {
    if runner.batch.is_empty() {
        return Ok(0);
    }
    let applied = store.flush(&mut runner.batch).await? as u64;
    if applied == 0 {
        return Ok(0);
    }
    runner.counters.db_transactions += 1;
    // Step 12 batched completion: resolve every completion this flush
    // committed, in buffer order (unknown-tasks and lease mismatches
    // abort loudly; stale entries only count).
    classify_flushed_completions(runner, store).await?;
    // Step 12 bounded retention (unit-test runners have no journal).
    if let Some(journal) = runner.journal.as_mut() {
        if maybe_prune_scan_journal(store, journal, MAX_RETAINED_SCAN_EVENTS).await? {
            runner.counters.db_transactions += 1;
        }
    }
    if runner.checkpoints.note_ops(applied) {
        let _ = runner.checkpoints.maybe_checkpoint(store).await?;
    }
    let checks = std::mem::take(&mut runner.pending_alias_checks);
    for check in &checks {
        note_enum_alias(
            store,
            runner,
            &check.task_id,
            &check.scope_key,
            &check.path,
            check.kind,
            check.at_ms,
        )
        .await?;
    }
    Ok(applied)
}

/// Flush when a `buffer_*` call reports a spec §5 limit
/// (RSF-AC461500-609D-4D55-991E-09C60D382D67).
async fn flush_if_due(runner: &mut Runner, store: &TursoStore, due: bool) -> repo_scan::Result<()> {
    if due {
        flush_runner_batch(runner, store).await?;
    }
    Ok(())
}

/// Buffer the error upsert as its two statements (RSF-AC461500-609D-4D55-991E-09C60D382D67):
/// the unconditional `UPDATE` plus `INSERT OR IGNORE`, mirroring
/// `record_error`'s update-then-insert outcome without a read. Returns
/// `WriterBatch::should_flush`.
/// `error` records (D4): the gap row's stable id, scope, category,
/// and detail. Attempts are omitted: the UPDATE+INSERT pair means the
/// final count is only knowable after commit (the catalog row has it).
/// `coverage_updated` payload (D4): gap/candidate deltas only — opened
/// gap ids, closed gap ids, newly unresolvable instance ids. All three
/// keys are always present (possibly empty); consumers accumulate by id.
/// Totals live on `inventory_ready` and terminal events, never here, so
/// this path needs no aggregate queries.
fn coverage_updated_value(
    opened: &[String],
    closed: &[String],
    unresolvable_added: &[String],
) -> serde_json::Value {
    serde_json::json!({
        "opened": opened,
        "closed": closed,
        "unresolvable_added": unresolvable_added,
    })
}

fn coverage_updated_records(
    opened: &[String],
    closed: &[String],
    unresolvable_added: &[String],
) -> repo_scan::Result<Vec<u8>> {
    let records = coverage_updated_value(opened, closed, unresolvable_added);
    serde_json::to_vec(&records).map_err(|e| repo_scan::Error::Report(e.to_string()))
}

/// Buffer one `coverage_updated` delta (same journaling contract as
/// [`journal_repository_found`]).
async fn journal_coverage_updated(
    runner: &mut Runner,
    store: &TursoStore,
    opened: &[String],
    closed: &[String],
    unresolvable_added: &[String],
) -> repo_scan::Result<()> {
    let Some(journal) = runner.journal.as_mut() else {
        return Ok(());
    };
    let records = coverage_updated_records(opened, closed, unresolvable_added)?;
    if let Some(due) = journal.buffer_coverage_updated(&mut runner.batch, &records)? {
        flush_if_due(runner, store, due).await?;
    }
    Ok(())
}

fn error_records_value(
    id: &str,
    scope_key: &str,
    category: &str,
    detail: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "scope_key": scope_key,
        "category": category,
        "detail": detail,
    })
}

fn error_records(
    id: &str,
    scope_key: &str,
    category: &str,
    detail: &str,
) -> repo_scan::Result<Vec<u8>> {
    let records = error_records_value(id, scope_key, category, detail);
    serde_json::to_vec(&records).map_err(|e| repo_scan::Error::Report(e.to_string()))
}

fn buffer_record_error(
    runner: &mut Runner,
    id: &str,
    scope_key: &str,
    category: &str,
    detail: &str,
    next_retry_ms: Option<i64>,
    now_ms: i64,
) -> repo_scan::Result<bool> {
    runner.batch.push(
        "UPDATE errors SET attempts = attempts + 1, detail = ?1, last_seen_ms = ?2, \
         next_retry_ms = ?3, open = 1 WHERE id = ?4",
        vec![
            turso::Value::Text(detail.to_string()),
            turso::Value::Integer(now_ms),
            next_retry_ms.map_or(turso::Value::Null, turso::Value::Integer),
            turso::Value::Text(id.to_string()),
        ],
    );
    runner.batch.push(
        "INSERT OR IGNORE INTO errors (id, scope_key, category, detail, attempts, \
         first_seen_ms, last_seen_ms, next_retry_ms, open) \
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5, ?6, 1)",
        vec![
            turso::Value::Text(id.to_string()),
            turso::Value::Text(scope_key.to_string()),
            turso::Value::Text(category.to_string()),
            turso::Value::Text(detail.to_string()),
            turso::Value::Integer(now_ms),
            next_retry_ms.map_or(turso::Value::Null, turso::Value::Integer),
        ],
    );
    // Coverage delta only on a genuine open transition: re-records
    // (attempts bump on an already-open row) are not coverage changes.
    // Computed before the journal borrow below.
    let fresh_open = runner.open_gaps.insert(id.to_string());
    // Same batch as the error rows: the event is only readable once its
    // cause has committed. Unit-test runners (journal: None) persist rows
    // without journaling.
    if let Some(journal) = runner.journal.as_mut() {
        let records = error_records(id, scope_key, category, detail)?;
        journal.buffer_error(&mut runner.batch, &records)?;
        if fresh_open {
            let opened = vec![id.to_string()];
            let records = coverage_updated_records(&opened, &[], &[])?;
            journal.buffer_coverage_updated(&mut runner.batch, &records)?;
        }
    }
    Ok(runner.batch.should_flush())
}

/// Buffer a gap close (RSF-AC461500-609D-4D55-991E-09C60D382D67), mirroring
/// `resolve_error`. Takes the runner (not the batch) so the close delta
/// can gate on `open_gaps`: unconditional closes (e.g. every successful
/// probe persist) report nothing when no row was open. Returns
/// `WriterBatch::should_flush`.
fn buffer_resolve_error(runner: &mut Runner, id: &str, now_ms: i64) -> repo_scan::Result<bool> {
    runner.batch.push(
        "UPDATE errors SET open = 0, last_seen_ms = ?1 WHERE id = ?2",
        vec![
            turso::Value::Integer(now_ms),
            turso::Value::Text(id.to_string()),
        ],
    );
    // Transition first (see `buffer_record_error`): the batched UPDATE
    // cannot report its rowcount, so the open set is the authority.
    let was_open = runner.open_gaps.remove(id);
    if let Some(journal) = runner.journal.as_mut() {
        if was_open {
            let closed = vec![id.to_string()];
            let records = coverage_updated_records(&[], &closed, &[])?;
            journal.buffer_coverage_updated(&mut runner.batch, &records)?;
        }
    }
    Ok(runner.batch.should_flush())
}

impl Runner {
    fn breaker_success(&mut self, volume: &str) {
        if let Some(breaker) = self.breakers.get_mut(volume) {
            breaker.on_success();
        }
    }

    fn breaker_failure(&mut self, volume: &str) {
        let breaker = self
            .breakers
            .entry(volume.to_string())
            .or_insert_with(|| CircuitBreaker::new(BREAKER_THRESHOLD, BREAKER_COOLDOWN));
        breaker.on_failure(SystemTime::now());
    }

    /// Record an observed pathname alias once (RSF-751/AC46/F06D).
    /// Repeat observations of one `(path, target, kind)` triple are
    /// dropped at insert: the run holds distinct aliases only, exactly
    /// what the report emits (see `alias_inputs`). Capped at
    /// [`MAX_ALIASES`] (A-F5, mirroring [`note_applied_scopes`]): past
    /// the cap new triples drop and one `alias-overflow` gap row
    /// documents the loss. Returns `Ok(WriterBatch::should_flush)`.
    fn note_alias(
        &mut self,
        path: Vec<u8>,
        target: Vec<u8>,
        kind: &'static str,
        at_ms: i64,
    ) -> repo_scan::Result<bool> {
        if self.alias_overflow {
            return Ok(false);
        }
        let key = (path, target, kind);
        if self.alias_seen.contains(&key) {
            return Ok(false);
        }
        if self.alias_seen.len() >= MAX_ALIASES {
            self.alias_overflow = true;
            eprintln!("repo-scan: alias overflow; further aliases dropped (gap recorded)");
            return buffer_record_error(
                self,
                "alias-overflow",
                events::mounts_scope_key(),
                "alias-overflow",
                &format!("alias table past {MAX_ALIASES}; further aliases dropped"),
                None,
                at_ms,
            );
        }
        self.alias_seen.insert(key.clone());
        self.aliases.push(ObservedAlias {
            path: key.0,
            target: key.1,
            kind: key.2,
            verified_at_ms: at_ms,
        });
        Ok(false)
    }
}

/// Record one probed Git identity, capped at [`MAX_PROBED_GIT_IDS`]
/// (A-F5, mirroring [`note_applied_scopes`]): past the cap the identity
/// is not recorded (later spellings persist without dedupe) and one
/// `probe-index-overflow` gap row documents the loss. Returns
/// `Ok(WriterBatch::should_flush)`.
fn note_probed_git_id(
    runner: &mut Runner,
    key: (u64, u64),
    git_bytes: Vec<u8>,
    now_ms: i64,
) -> repo_scan::Result<bool> {
    if runner.probed_overflow {
        return Ok(false);
    }
    if runner.probed_git_ids.len() >= MAX_PROBED_GIT_IDS {
        runner.probed_overflow = true;
        eprintln!(
            "repo-scan: probe-index overflow; further identities persist without dedupe \
             (gap recorded)"
        );
        return buffer_record_error(
            runner,
            "probe-index-overflow",
            events::mounts_scope_key(),
            "probe-index-overflow",
            &format!(
                "probe index past {MAX_PROBED_GIT_IDS}; further identities persist without dedupe"
            ),
            None,
            now_ms,
        );
    }
    runner.probed_git_ids.insert(key, git_bytes);
    Ok(false)
}

/// Per-volume breaker key for a scope key (paths stat their volume;
/// anything unstattable shares the `unknown` bucket).
fn breaker_key_for_task(scope_key: &str) -> String {
    let path = match config::parse_scope_key(scope_key) {
        Some(config::ScopeRef::Dir(p) | config::ScopeRef::Git(p)) => p,
        Some(config::ScopeRef::Status(_)) | None => return String::from("status"),
    };
    match std::fs::symlink_metadata(&path) {
        Ok(md) => {
            let (dev, _) = dir_identity(&md);
            format!("dev:{dev}")
        }
        Err(_) => String::from("unknown"),
    }
}

/// A task execution that failed without completing: retried with backoff
/// while attempts remain, else parked with its gap preserved.
struct ExecFail {
    category: String,
    detail: String,
}

/// Dispatch one claimed task by kind. Returns `Err` only for scheduler
/// defects (lease mismatch, unknown task) that must abort the run; scope
/// failures complete as retry/parked with preserved gaps. `deadline` is
/// the task's wall budget (SR-STATE-01), enforced at each op's yield
/// points as abandon-and-park, never as silent overrun.
#[allow(clippy::too_many_arguments)]
/// Coordinator renewal tick (Step 9): while workers hold tasks, the
/// drain re-renews every in-flight lease on this cadence — one batch
/// transaction per tick, well inside the 60 s TTL.
const RENEW_TICK_SECS: u64 = 15;

/// Worker-side job: every input a pool thread needs, and no store
/// handle. (Step 8: filesystem and Git reads run here, off the
/// coordinator thread.)
enum WorkerJob {
    Enumerate {
        ctx: ReadContext,
        path: PathBuf,
        deadline: OpDeadline,
    },
    Probe {
        ctx: ReadContext,
        task_id: String,
        path: PathBuf,
        deadline: OpDeadline,
    },
    Analysis {
        ctx: ReadContext,
        path: PathBuf,
        common_dir: PathBuf,
        checkouts: Vec<store::CheckoutRow>,
        object_format: String,
        bare: bool,
        deadline: OpDeadline,
    },
    Status {
        ctx: ReadContext,
        target: StatusTarget,
        deadline: OpDeadline,
    },
}

/// Worker-side result, one variant per [`WorkerJob`].
enum WorkerOut {
    Enumerate(EnumCollected),
    Probe(ProbeCollected),
    Analysis(AnalysisCollected),
    Status(StatusCollected),
}

/// What [`prepare_task`] decided: the outcome is already complete on
/// the coordinator, or a worker must run first.
enum PrepAction {
    Done(TaskOutcome),
    Spawn(WorkerJob),
}

/// Per-kind finish inputs carried from prepare to finish on the
/// coordinator (never crossing to the worker).
enum PrepExtra {
    Enumerate {
        path: PathBuf,
    },
    Probe {
        path: PathBuf,
    },
    Analysis {
        path: PathBuf,
        instance_id: String,
        instance_row: Box<store::GitInstanceRow>,
    },
    Status,
    /// Coordinator-completed; no finish inputs.
    Done,
}

/// One admitted task's coordinator-side record: the claim, the held
/// admission permit, accounting inputs, and the kind's finish inputs.
struct PrepRecord {
    claimed: ClaimedTask,
    permit: Permit,
    volume: String,
    started: Instant,
    extra: PrepExtra,
}

/// One prepared task: the coordinator record plus the action.
struct PreparedTask {
    record: PrepRecord,
    action: PrepAction,
}

/// Run one worker job synchronously on a pool thread. No store handle
/// crosses here: the coordinator's scheduled tick owns lease renewal
/// and the pre-persist gates own staleness.
fn run_worker(job: WorkerJob) -> repo_scan::Result<WorkerOut> {
    match job {
        WorkerJob::Enumerate {
            ctx,
            path,
            deadline,
        } => collect_enum_reads(&ctx, &path, &deadline).map(WorkerOut::Enumerate),
        WorkerJob::Probe {
            ctx,
            task_id,
            path,
            deadline,
        } => run_probe_job(&ctx, &task_id, &path, &deadline).map(WorkerOut::Probe),
        WorkerJob::Analysis {
            ctx,
            path,
            common_dir,
            checkouts,
            object_format,
            bare,
            deadline,
        } => run_analysis_job(
            &ctx,
            &path,
            &common_dir,
            &checkouts,
            &object_format,
            bare,
            &deadline,
        )
        .map(WorkerOut::Analysis),
        WorkerJob::Status {
            ctx,
            target,
            deadline,
        } => collect_status_reads(&ctx, &target, &deadline).map(WorkerOut::Status),
    }
}

/// Coordinator half of one claimed task: scope decode, catalog reads,
/// and the pre-run lease renewal, dispatching to the kind's prepare.
/// Returns the record (claim, permit, accounting, finish inputs) plus
/// the action (already done, or spawn a worker).
#[allow(clippy::too_many_arguments)]
async fn prepare_task(
    runner: &mut Runner,
    store: &TursoStore,
    status_mode: StatusMode,
    claimed: &ClaimedTask,
    permit: Permit,
    volume: String,
    started: Instant,
    deadline: &OpDeadline,
) -> repo_scan::Result<PreparedTask> {
    // Event-continuity marker scopes (R5: `volume:`/`mounts:`) carry no
    // directory to re-enumerate; the enclosing traversal (or the fresh
    // generation a history loss forced) satisfies them, so they complete
    // without a gap. Directory reconciles re-enumerate below.
    if claimed.task.kind == KIND_RECONCILE
        && !matches!(
            config::parse_scope_key(&claimed.task.scope_key),
            Some(config::ScopeRef::Dir(_))
        )
    {
        return Ok(PreparedTask {
            record: PrepRecord {
                claimed: claimed.clone(),
                permit,
                volume,
                started,
                extra: PrepExtra::Done,
            },
            action: PrepAction::Done(TaskOutcome::Complete),
        });
    }
    let (extra, action) = match claimed.task.kind.as_str() {
        KIND_ENUM | KIND_RECONCILE => prepare_enumerate(runner, claimed, deadline),
        KIND_PROBE => prepare_probe(runner, store, claimed, deadline).await?,
        KIND_STATUS => prepare_status(runner, store, status_mode, claimed, deadline).await?,
        KIND_ANALYZE => prepare_analysis(runner, store, claimed, deadline).await?,
        other => {
            let detail = format!("unknown task kind: {other}");
            let due = buffer_record_error(
                runner,
                &format!("kind:{}", claimed.task.id),
                &claimed.task.scope_key,
                "unsupported-task-kind",
                &detail,
                None,
                store::now_ms(),
            )?;
            flush_if_due(runner, store, due).await?;
            (
                PrepExtra::Done,
                PrepAction::Done(TaskOutcome::Parked {
                    state: TaskState::Unsupported,
                    reason: detail,
                }),
            )
        }
    };
    Ok(PreparedTask {
        record: PrepRecord {
            claimed: claimed.clone(),
            permit,
            volume,
            started,
            extra,
        },
        action,
    })
}

/// Coordinator write half of one prepared task: applies a worker result
/// through the kind's finish (pre-persist gate plus persist). Returns
/// the outcome plus the worker's progress units for the watchdog
/// verdict. Task completion stays with the caller (the drain flushes
/// the batch, then completes with verification).
async fn finish_task(
    runner: &mut Runner,
    store: &TursoStore,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    record: &PrepRecord,
    result: repo_scan::Result<WorkerOut>,
) -> repo_scan::Result<(TaskOutcome, u64)> {
    let claimed = &record.claimed;
    match &record.extra {
        PrepExtra::Enumerate { path } => {
            finish_enumerate(runner, store, generation, claimed, path, result).await
        }
        PrepExtra::Probe { path } => {
            finish_probe(
                runner, store, generation, run_rev, canonical, claimed, path, result,
            )
            .await
        }
        PrepExtra::Analysis {
            path,
            instance_id,
            instance_row,
        } => {
            finish_analysis(
                runner,
                store,
                claimed,
                path,
                instance_id,
                instance_row,
                result,
            )
            .await
        }
        PrepExtra::Status => finish_status(runner, store, claimed, result).await,
        PrepExtra::Done => Err(repo_scan::Error::Scheduler(String::from(
            "finish called for a coordinator-completed task",
        ))),
    }
}

/// Sequential task driver (prepare, run inline, finish — no worker
/// pool, no completion): the regression hooks and unit tests execute
/// single tasks through the same prepare/worker/finish path the pooled
/// drain uses. Test-only: production always goes through
/// [`run_until_boundary`].
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn execute_task(
    runner: &mut Runner,
    store: &TursoStore,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    status_mode: StatusMode,
    claimed: &ClaimedTask,
    deadline: &OpDeadline,
) -> repo_scan::Result<TaskOutcome> {
    let class = match claimed.task.kind.as_str() {
        KIND_ENUM | KIND_RECONCILE => OpClass::Enumerate,
        KIND_PROBE | KIND_STATUS | KIND_ANALYZE => OpClass::GitProbe,
        _ => OpClass::Other,
    };
    let permit = runner.admission.try_acquire(class).ok_or_else(|| {
        repo_scan::Error::Scheduler(String::from("test driver: admission denied"))
    })?;
    let volume = breaker_key_for_task(&claimed.task.scope_key);
    let prepared = prepare_task(
        runner,
        store,
        status_mode,
        claimed,
        permit,
        volume,
        Instant::now(),
        deadline,
    )
    .await?;
    let outcome = match prepared.action {
        PrepAction::Done(outcome) => outcome,
        PrepAction::Spawn(job) => {
            let result = run_worker(job);
            finish_task(
                runner,
                store,
                generation,
                run_rev,
                canonical,
                &prepared.record,
                result,
            )
            .await?
            .0
        }
    };
    runner.admission.release(&prepared.record.permit);
    Ok(outcome)
}

/// One completion buffered into the writer batch (Step 12 batched
/// completion, D5: no per-task flush+completion transactions).
struct PendingCompletion {
    task_id: String,
    token: i64,
    epoch: u64,
    scope_key: String,
    outcome: TaskOutcome,
    /// Frontier state the outcome writes on the applied path
    /// (`complete` | `retry_wait` | `unavailable` | `unsupported`;
    /// validated at buffer time, also the `Parked` gap category).
    outcome_state: &'static str,
    /// `updated_at_ms` stamped by this completion's SQL: the classifier's
    /// "our write landed" signal.
    now_ms: i64,
}

/// Observed verdict for one flushed completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompletionVerdict {
    Applied,
    StaleRequeued,
}

/// Buffer one task completion into the writer batch (Step 12 batched
/// completion, D5): the completion's conditional SQL commits with the
/// batch, so children enqueued during execution commit in the same
/// transaction as the parent completion whenever the batch holds both —
/// and always at-or-before it (a spec §5 limit split commits children
/// first) — so a directory is never marked complete unless its
/// discovered children are saved. Lease/token/epoch guards and the
/// scope-revision gate evaluate at commit time inside the flush
/// transaction (the single owner writes these rows alone);
/// [`classify_flushed_completions`] resolves each entry against
/// committed rows after the flush. The owner-epoch and parked-state
/// checks run here (both are buffer-time facts). Returns
/// `WriterBatch::should_flush`: row/byte/age caps bound the transaction.
fn buffer_completion(
    runner: &mut Runner,
    store: &TursoStore,
    claimed: &ClaimedTask,
    epoch: u64,
    outcome: &TaskOutcome,
) -> repo_scan::Result<bool> {
    // Owner check first (SR-STATE-08, same refusal as the store gate):
    // neither this handle's epoch nor the run epoch changes mid-run, so
    // buffer-time refusal is exactly commit-time refusal.
    if epoch != store.epoch() {
        return Err(repo_scan::Error::Store(format!(
            "complete_task refused: epoch {epoch} is not this owner (epoch {})",
            store.epoch()
        )));
    }
    let outcome_state = match outcome {
        TaskOutcome::Complete => "complete",
        TaskOutcome::Retry { .. } => "retry_wait",
        TaskOutcome::Parked { state, .. } => match state {
            TaskState::Unavailable => "unavailable",
            TaskState::Unsupported => "unsupported",
            other => {
                return Err(repo_scan::Error::Scheduler(format!(
                    "invalid-parked-state: {other:?} (want unavailable or unsupported)"
                )));
            }
        },
    };
    let epoch_i64 = i64::try_from(epoch)
        .map_err(|_| repo_scan::Error::Store(format!("lease epoch {epoch} exceeds i64 range")))?;
    let now_ms = store::now_ms();
    let task_id = claimed.task.id.clone();
    let scope_key = claimed.task.scope_key.clone();
    let gap_id = format!("gap:{task_id}");
    // Applied path: outcome write guarded by the exact lease plus the
    // scope-revision match. The revision compares the row's own
    // `expected_rev` (what the store's in-transaction read compared)
    // against the live scope revision, defaulting to 0 for unscored
    // scopes exactly like the store gate.
    match outcome {
        TaskOutcome::Complete => {
            runner.batch.push(
                "UPDATE frontier_tasks SET state = 'complete', lease_token = NULL, \
                    lease_epoch = NULL, lease_expires_ms = NULL, updated_at_ms = ?1 \
                    WHERE id = ?2 AND state = 'leased' AND lease_token = ?3 \
                    AND lease_epoch = ?4 AND expected_rev = COALESCE( \
                    (SELECT rev FROM scope_revisions WHERE scope_key = ?5), 0)",
                vec![
                    turso::Value::Integer(now_ms),
                    turso::Value::Text(task_id.clone()),
                    turso::Value::Integer(claimed.token),
                    turso::Value::Integer(epoch_i64),
                    turso::Value::Text(scope_key.clone()),
                ],
            );
        }
        TaskOutcome::Retry { retry_after_ms, .. } => {
            runner.batch.push(
                "UPDATE frontier_tasks SET state = 'retry_wait', lease_token = NULL, \
                    lease_epoch = NULL, lease_expires_ms = NULL, retry_after_ms = ?1, \
                    updated_at_ms = ?2 WHERE id = ?3 AND state = 'leased' \
                    AND lease_token = ?4 AND lease_epoch = ?5 AND expected_rev = COALESCE( \
                    (SELECT rev FROM scope_revisions WHERE scope_key = ?6), 0)",
                vec![
                    turso::Value::Integer(*retry_after_ms),
                    turso::Value::Integer(now_ms),
                    turso::Value::Text(task_id.clone()),
                    turso::Value::Integer(claimed.token),
                    turso::Value::Integer(epoch_i64),
                    turso::Value::Text(scope_key.clone()),
                ],
            );
        }
        TaskOutcome::Parked { .. } => {
            runner.batch.push(
                "UPDATE frontier_tasks SET state = ?1, lease_token = NULL, lease_epoch = NULL, \
                    lease_expires_ms = NULL, updated_at_ms = ?2 WHERE id = ?3 \
                    AND state = 'leased' AND lease_token = ?4 AND lease_epoch = ?5 \
                    AND expected_rev = COALESCE( \
                    (SELECT rev FROM scope_revisions WHERE scope_key = ?6), 0)",
                vec![
                    turso::Value::Text(outcome_state.to_string()),
                    turso::Value::Integer(now_ms),
                    turso::Value::Text(task_id.clone()),
                    turso::Value::Integer(claimed.token),
                    turso::Value::Integer(epoch_i64),
                    turso::Value::Text(scope_key.clone()),
                ],
            );
        }
    }
    // Stale path: revision moved under the lease — requeue with the
    // fresh revision (never marked complete), exactly the store's stale
    // requeue. Guarded by the same lease plus the revision mismatch, so
    // exactly one of the two task updates can match per flush.
    runner.batch.push(
        "UPDATE frontier_tasks SET state = 'pending', lease_token = NULL, lease_epoch = NULL, \
            lease_expires_ms = NULL, expected_rev = COALESCE( \
            (SELECT rev FROM scope_revisions WHERE scope_key = ?1), 0), updated_at_ms = ?2 \
            WHERE id = ?3 AND state = 'leased' AND lease_token = ?4 AND lease_epoch = ?5 \
            AND expected_rev != COALESCE( \
            (SELECT rev FROM scope_revisions WHERE scope_key = ?6), 0)",
        vec![
            turso::Value::Text(scope_key.clone()),
            turso::Value::Integer(now_ms),
            turso::Value::Text(task_id.clone()),
            turso::Value::Integer(claimed.token),
            turso::Value::Integer(epoch_i64),
            turso::Value::Text(scope_key.clone()),
        ],
    );
    // Gap writes, gated on the applied path having landed (the outcome
    // state plus our stamp, visible because the flush executes ops in
    // order inside one transaction): a stale completion records and
    // closes nothing, exactly like the store path.
    match outcome {
        TaskOutcome::Complete => {
            runner.batch.push(
                "UPDATE errors SET open = 0, last_seen_ms = ?1 WHERE id = ?2 AND open = 1 \
                    AND EXISTS (SELECT 1 FROM frontier_tasks WHERE id = ?3 \
                    AND state = 'complete' AND updated_at_ms = ?4)",
                vec![
                    turso::Value::Integer(now_ms),
                    turso::Value::Text(gap_id),
                    turso::Value::Text(task_id.clone()),
                    turso::Value::Integer(now_ms),
                ],
            );
        }
        TaskOutcome::Retry {
            category,
            detail,
            retry_after_ms,
        } => {
            buffer_completion_gap(
                runner,
                &gap_id,
                &scope_key,
                category,
                detail,
                Some(*retry_after_ms),
                &task_id,
                outcome_state,
                now_ms,
            );
        }
        TaskOutcome::Parked { reason, .. } => {
            buffer_completion_gap(
                runner,
                &gap_id,
                &scope_key,
                outcome_state,
                reason,
                None,
                &task_id,
                outcome_state,
                now_ms,
            );
        }
    }
    runner.pending_completions.push(PendingCompletion {
        task_id,
        token: claimed.token,
        epoch,
        scope_key,
        outcome: outcome.clone(),
        outcome_state,
        now_ms,
    });
    Ok(runner.batch.should_flush())
}

/// Buffer the update-then-insert gap record for one applied `Retry`/`Parked`
/// completion (mirrors `record_error`'s outcome), gated on the applied
/// path: both statements no-op unless this completion's outcome write
/// landed in the same transaction.
#[allow(clippy::too_many_arguments)]
fn buffer_completion_gap(
    runner: &mut Runner,
    gap_id: &str,
    scope_key: &str,
    category: &str,
    detail: &str,
    next_retry_ms: Option<i64>,
    task_id: &str,
    outcome_state: &str,
    now_ms: i64,
) {
    runner.batch.push(
        "UPDATE errors SET attempts = attempts + 1, detail = ?1, last_seen_ms = ?2, \
            next_retry_ms = ?3, open = 1 WHERE id = ?4 AND EXISTS ( \
            SELECT 1 FROM frontier_tasks WHERE id = ?5 AND state = ?6 AND updated_at_ms = ?7)",
        vec![
            turso::Value::Text(detail.to_string()),
            turso::Value::Integer(now_ms),
            next_retry_ms.map_or(turso::Value::Null, turso::Value::Integer),
            turso::Value::Text(gap_id.to_string()),
            turso::Value::Text(task_id.to_string()),
            turso::Value::Text(outcome_state.to_string()),
            turso::Value::Integer(now_ms),
        ],
    );
    runner.batch.push(
        "INSERT OR IGNORE INTO errors (id, scope_key, category, detail, attempts, \
            first_seen_ms, last_seen_ms, next_retry_ms, open) \
            SELECT ?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, 1 WHERE EXISTS ( \
            SELECT 1 FROM frontier_tasks WHERE id = ?8 AND state = ?9 \
            AND updated_at_ms = ?10) AND NOT EXISTS (SELECT 1 FROM errors WHERE id = ?11)",
        vec![
            turso::Value::Text(gap_id.to_string()),
            turso::Value::Text(scope_key.to_string()),
            turso::Value::Text(category.to_string()),
            turso::Value::Text(detail.to_string()),
            turso::Value::Integer(now_ms),
            turso::Value::Integer(now_ms),
            next_retry_ms.map_or(turso::Value::Null, turso::Value::Integer),
            turso::Value::Text(task_id.to_string()),
            turso::Value::Text(outcome_state.to_string()),
            turso::Value::Integer(now_ms),
            turso::Value::Text(gap_id.to_string()),
        ],
    );
}

/// Committed task row fields one completion classification reads.
struct CompletionRowState {
    state: String,
    lease_token: Option<i64>,
    lease_epoch: Option<i64>,
    expected_rev: u64,
    updated_at_ms: i64,
}

/// Read one task's completion-classification fields (`None` when the task
/// row does not exist).
async fn completion_row_state(
    store: &TursoStore,
    task_id: &str,
) -> repo_scan::Result<Option<CompletionRowState>> {
    let mut rows = store
        .connection()
        .query(
            "SELECT state, lease_token, lease_epoch, expected_rev, updated_at_ms \
                FROM frontier_tasks WHERE id = ?1",
            vec![turso::Value::Text(task_id.to_string())],
        )
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?;
    let Some(row) = rows
        .next()
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?
    else {
        return Ok(None);
    };
    let expected_rev = cell_int(&row, 3)?;
    Ok(Some(CompletionRowState {
        state: cell_text(&row, 0)?,
        lease_token: cell_opt_int(&row, 1)?,
        lease_epoch: cell_opt_int(&row, 2)?,
        expected_rev: u64::try_from(expected_rev).map_err(|_| {
            repo_scan::Error::Store(format!(
                "task expected_rev {expected_rev} in catalog is not a valid u64"
            ))
        })?,
        updated_at_ms: cell_int(&row, 4)?,
    }))
}

/// Resolve every completion a flush just committed (Step 12 batched
/// completion): each buffered entry's conditional SQL either applied its
/// outcome, took the stale path, or matched nothing, and the observed
/// committed rows decide — never the buffer-time prediction, so an
/// invalidation committing between buffer and flush still requeues
/// instead of completing. Returns per-entry verdicts in buffer order.
/// Unknown tasks and lease mismatches abort loudly with the same errors
/// as the retired per-task path; stale entries are already requeued by
/// the committed flush and only count here. Applied entries journal
/// their gap events into the writer batch (next flush).
async fn classify_flushed_completions(
    runner: &mut Runner,
    store: &TursoStore,
) -> repo_scan::Result<Vec<CompletionVerdict>> {
    let pending = std::mem::take(&mut runner.pending_completions);
    let mut verdicts = Vec::with_capacity(pending.len());
    for item in &pending {
        verdicts.push(classify_one_completion(runner, store, item).await?);
    }
    Ok(verdicts)
}

/// Classify one flushed completion against its committed task row.
async fn classify_one_completion(
    runner: &mut Runner,
    store: &TursoStore,
    item: &PendingCompletion,
) -> repo_scan::Result<CompletionVerdict> {
    let Some(row) = completion_row_state(store, &item.task_id).await? else {
        return Err(repo_scan::Error::UnknownTask(format!(
            "unknown-task: {}",
            item.task_id
        )));
    };
    if row.state == item.outcome_state
        && row.lease_token.is_none()
        && row.lease_epoch.is_none()
        && row.updated_at_ms == item.now_ms
    {
        let delta = observed_completion_delta(item);
        journal_observed_delta(runner, &delta)?;
        return Ok(CompletionVerdict::Applied);
    }
    if row.state == "pending"
        && row.lease_token.is_none()
        && row.lease_epoch.is_none()
        && row.updated_at_ms == item.now_ms
        && row.expected_rev == store.scope_rev(&item.scope_key).await?
    {
        runner.counters.stale_requeued += 1;
        eprintln!(
            "repo-scan: stale completion requeued: {} (invalidation kept)",
            item.task_id
        );
        return Ok(CompletionVerdict::StaleRequeued);
    }
    Err(repo_scan::Error::LeaseMismatch(format!(
        "lease-mismatch: task {} is not leased to epoch {} token {}",
        item.task_id, item.epoch, item.token
    )))
}

/// Build the gap delta an applied completion caused, from the observed
/// outcome (same shape the store used to return: the conditional gap SQL
/// guarantees the recorded rows match exactly when the outcome applied).
fn observed_completion_delta(item: &PendingCompletion) -> CompletionDelta {
    let gap_id = format!("gap:{}", item.task_id);
    match &item.outcome {
        TaskOutcome::Complete => CompletionDelta {
            opened: None,
            closed: Some(gap_id),
        },
        TaskOutcome::Retry {
            category, detail, ..
        } => CompletionDelta {
            opened: Some(CompletionGap {
                id: gap_id,
                scope_key: item.scope_key.clone(),
                category: category.clone(),
                detail: detail.clone(),
            }),
            closed: None,
        },
        TaskOutcome::Parked { reason, .. } => CompletionDelta {
            opened: Some(CompletionGap {
                id: gap_id,
                scope_key: item.scope_key.clone(),
                category: item.outcome_state.to_string(),
                detail: reason.clone(),
            }),
            closed: None,
        },
    }
}

/// Journal one observed completion gap delta: the opened row (if any) as
/// an `error` event, then the open/close delta as `coverage_updated` —
/// buffered into the writer batch (next flush), after the completion
/// committed. The opened row always emits an `error` (point-in-time);
/// the coverage delta fires only on genuine transitions against
/// `open_gaps` (opens on newly opened rows; closes when the set held
/// the id — the batched close cannot report its rowcount, so the open
/// set is the authority, mirroring [`buffer_resolve_error`]).
/// Unit-test runners without a journal skip silently.
fn journal_observed_delta(runner: &mut Runner, delta: &CompletionDelta) -> repo_scan::Result<()> {
    if runner.journal.is_none() {
        return Ok(());
    }
    // Transition gating before the journal borrow below.
    let opened: Vec<String> = match delta.opened.as_ref() {
        Some(gap) if runner.open_gaps.insert(gap.id.clone()) => vec![gap.id.clone()],
        _ => Vec::new(),
    };
    let closed: Vec<String> = match delta.closed.as_ref() {
        Some(id) if runner.open_gaps.remove(id.as_str()) => vec![id.clone()],
        _ => Vec::new(),
    };
    let journal = runner.journal.as_mut().expect("journal checked above");
    if let Some(gap) = delta.opened.as_ref() {
        let records = error_records(&gap.id, &gap.scope_key, &gap.category, &gap.detail)?;
        journal.buffer_error(&mut runner.batch, &records)?;
    }
    if !opened.is_empty() || !closed.is_empty() {
        let records = coverage_updated_records(&opened, &closed, &[])?;
        journal.buffer_coverage_updated(&mut runner.batch, &records)?;
    }
    Ok(())
}

/// Translate an [`ExecFail`] into a retry (backoff from the attempt count)
/// or, when attempts are exhausted, a parked task with its preserved gap.
async fn fail_task(
    runner: &mut Runner,
    _store: &TursoStore,
    claimed: &ClaimedTask,
    fail: ExecFail,
) -> repo_scan::Result<TaskOutcome> {
    let now = store::now_ms();
    let attempts: u32 = claimed.task.attempts.min(u32::MAX as u64) as u32;
    if u64::from(attempts) >= MAX_ATTEMPTS {
        runner.breaker_failure(&breaker_key_for_task(&claimed.task.scope_key));
        return Ok(TaskOutcome::Parked {
            state: TaskState::Unavailable,
            reason: format!("{}: {} (attempts exhausted)", fail.category, fail.detail),
        });
    }
    let delay_ms = backoff_for_attempt(attempts)
        .as_millis()
        .min(i64::MAX as u128) as i64;
    Ok(TaskOutcome::Retry {
        category: fail.category,
        detail: fail.detail,
        retry_after_ms: now + delay_ms,
    })
}

/// Classify an IO failure on inspected scope: permission loss and
/// disappearance park immediately as coverage gaps; anything else retries.
fn classify_io_error(e: &std::io::Error) -> Option<TaskState> {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => Some(TaskState::Unavailable),
        std::io::ErrorKind::NotFound => Some(TaskState::Unavailable),
        _ => None,
    }
}

/// Outcome of the fenced open attempt for one enum task (finding 12).
enum FencedDir {
    /// No fence configured (unit-test runners): legacy pathname open.
    Unfenced,
    /// Pinned, verified directory: enumerate through the descriptor.
    Pinned(PinnedDir),
    /// The task path itself is a symlink: route to link handling.
    Link,
    /// Refused without filesystem writes (out of scope, cycle, ...).
    Refused { state: TaskState, reason: String },
    /// Open failed like the legacy stat: park or retry, no observation.
    StatFailed(std::io::Error),
}

/// Directory identity source for one enum task: pinned `fstat` parts or
/// legacy `symlink_metadata`.
enum OpenDirMeta {
    Pinned(DirStat),
    Legacy(std::fs::Metadata),
}

/// Fenced open of one enum task's directory: descriptor-relative
/// resolution plus the `(dev, ino)`-anchored scope check. Every refusal
/// fails closed (parked gap or retryable error), never an enumeration
/// outside the declared roots.
fn open_dir_fenced(fence: Option<&ScopeFence>, path: &Path) -> FencedDir {
    let Some(fence) = fence else {
        return FencedDir::Unfenced;
    };
    match fence.open_pinned(path) {
        Ok(FenceOpen::Dir(pinned)) => FencedDir::Pinned(pinned),
        Ok(FenceOpen::Symlink) => FencedDir::Link,
        Err(e) => map_enum_fence_error(path, e),
    }
}

/// Map one fenced-open failure to its enum outcome: every arm fails
/// closed — parked gap or retryable error — never an enumeration outside
/// the declared roots, and (PG-03) never a legacy pathname fallback where
/// descriptors cannot pin. Off-unix targets report `Unsupported` for every
/// fenced open, so enumeration parks `Unsupported` there with a preserved
/// gap instead of listing without a fence.
fn map_enum_fence_error(path: &Path, err: FenceError) -> FencedDir {
    match err {
        FenceError::OutOfScope(p) => FencedDir::Refused {
            state: TaskState::Unavailable,
            reason: format!("directory {} is outside the scan scope", p.display()),
        },
        FenceError::TooDeep(p) => FencedDir::Refused {
            state: TaskState::Unavailable,
            reason: format!("symlink chain too deep at {}", p.display()),
        },
        FenceError::NotAbsolute(p) => FencedDir::Refused {
            state: TaskState::Unavailable,
            reason: format!("scope path is not absolute: {}", p.display()),
        },
        // PG-03: descriptor pinning unavailable on this target fails
        // closed — the scope parks `Unsupported` with a preserved gap;
        // no legacy pathname enumeration runs without a fence.
        FenceError::Unsupported(detail) => FencedDir::Refused {
            state: TaskState::Unsupported,
            reason: format!(
                "directory {} cannot be pinned on this platform ({detail}); \
                 refusing unfenced enumeration",
                path.display()
            ),
        },
        FenceError::NotDirectory(p) => FencedDir::StatFailed(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            format!("not a directory: {}", p.display()),
        )),
        FenceError::Io(e) => FencedDir::StatFailed(e),
    }
}

/// Translate a directory-stat failure: permission loss and disappearance
/// park immediately as coverage gaps; anything else retries.
async fn fail_stat_open(
    runner: &mut Runner,
    store: &TursoStore,
    claimed: &ClaimedTask,
    path: &Path,
    e: &std::io::Error,
) -> repo_scan::Result<TaskOutcome> {
    let detail = format!("cannot stat {}: {e}", path.display());
    if let Some(state) = classify_io_error(e) {
        return Ok(TaskOutcome::Parked {
            state,
            reason: detail,
        });
    }
    fail_task(
        runner,
        store,
        claimed,
        ExecFail {
            category: String::from("stat-error"),
            detail,
        },
    )
    .await
}

/// Record a directory-open failure as the directory's enumeration error:
/// permission loss and disappearance park immediately as coverage gaps;
/// anything else retries.
#[allow(clippy::too_many_arguments)]
async fn fail_list_open(
    runner: &mut Runner,
    store: &TursoStore,
    claimed: &ClaimedTask,
    dir_id: i64,
    generation: u64,
    path: &Path,
    now: i64,
    e: &std::io::Error,
) -> repo_scan::Result<TaskOutcome> {
    let detail = format!("cannot list {}: {e}", path.display());
    let due = TursoStore::buffer_record_dir_observation(
        &mut runner.batch,
        dir_id,
        generation,
        false,
        1,
        0,
        Some(&detail),
        now,
    );
    flush_if_due(runner, store, due).await?;
    if let Some(state) = classify_io_error(e) {
        return Ok(TaskOutcome::Parked {
            state,
            reason: detail,
        });
    }
    fail_task(
        runner,
        store,
        claimed,
        ExecFail {
            category: String::from("enumerate-error"),
            detail,
        },
    )
    .await
}

/// One listed child: raw name + observed kind (Step 8 worker seam: the
/// read half collects these, the single writer replays enqueues from them).
#[derive(Debug, Clone)]
struct EnumChild {
    name: std::ffi::OsString,
    kind: ChildKind,
}

/// Filesystem read half of one enumeration: every observation collected
/// without catalog writes, on a worker thread. (The lease renewal that
/// once ran in this loop moved to the coordinator's scheduled tick; the
/// only admission touch left is the pressure abort, which stays as feed
/// control through the shared pressure mirror.)
struct EnumScan {
    dev: u64,
    ino: u64,
    volume_tag: String,
    dir_id: i64,
    ino_str: String,
    incarnation: String,
    component: Vec<u8>,
    display: String,
    children: Vec<EnumChild>,
    entries_seen: u64,
    mid_error: Option<String>,
    now_ms: i64,
}

/// Pre-listing fence/stat outcomes that bypass the child loop.
enum EnumCollected {
    Scan(EnumScan),
    /// Task path resolves to a symlink: enqueue its target, complete.
    Link,
    Refused {
        state: TaskState,
        reason: String,
    },
    StatFailed(std::io::Error),
    ListFailed {
        dir_id: i64,
        now_ms: i64,
        error: std::io::Error,
    },
}

/// Read half of enumeration ([`prepare_enumerate`]/[`finish_enumerate`]): fenced open, stat, and child
/// names/kinds. Worker-owned inputs only ([`ReadContext`]); applies no
/// catalog writes — lease renewal moved to the coordinator's scheduled
/// tick (Step 9), so this runs synchronously on a worker thread while
/// the writer applies everything via [`persist_enumeration`].
fn collect_enum_reads(
    ctx: &ReadContext,
    path: &Path,
    deadline: &OpDeadline,
) -> repo_scan::Result<EnumCollected> {
    // Finding 12: fenced runners open the task directory through
    // pinned descriptors and verify scope before touching it; unfenced
    // runners (unit tests) keep the legacy pathname stat.
    let pinned: Option<PinnedDir> = match open_dir_fenced(ctx.fence.as_ref(), path) {
        FencedDir::Unfenced => None,
        FencedDir::Pinned(pinned) => Some(pinned),
        FencedDir::Link => {
            return Ok(EnumCollected::Link);
        }
        FencedDir::Refused { state, reason } => {
            return Ok(EnumCollected::Refused { state, reason });
        }
        FencedDir::StatFailed(e) => {
            return Ok(EnumCollected::StatFailed(e));
        }
    };
    let opened_meta: OpenDirMeta = match &pinned {
        Some(pinned) => OpenDirMeta::Pinned(pinned.stat()),
        None => match std::fs::symlink_metadata(path) {
            Ok(md) => OpenDirMeta::Legacy(md),
            Err(e) => return Ok(EnumCollected::StatFailed(e)),
        },
    };
    let dir_path: &Path = if let Some(pinned) = &pinned {
        pinned.true_path()
    } else {
        path
    };
    let (dev, ino, incarnation) = match &opened_meta {
        OpenDirMeta::Pinned(stat) => {
            // Pre-1970 mtimes stay `None` ("unknown"), matching the
            // `SystemTime`-based legacy spelling exactly.
            let mtime = (stat.mtime_secs >= 0).then_some((stat.mtime_secs, stat.mtime_nanos));
            (
                stat.meta.dev,
                stat.meta.ino,
                incarnation_from_parts(stat.meta.nlink, mtime, stat.meta.len),
            )
        }
        OpenDirMeta::Legacy(md) => {
            let (dev, ino) = dir_identity(md);
            (dev, ino, incarnation_of(md))
        }
    };
    let volume_tag = format!("dev:{dev}");
    let now = store::now_ms();
    let component = dir_path
        .file_name()
        .map(|n| config::path_as_bytes(Path::new(n)))
        .unwrap_or_else(|| config::path_as_bytes(dir_path));
    // R05: stable directory ID is known in memory from physical identity;
    // no immediate flush is needed to retrieve an autoincrement id.
    let ino_str = ino.to_string();
    let dir_id = store::dir_identity_id(&volume_tag, &ino_str, &incarnation);
    let display = escape_display(&config::path_as_bytes(dir_path));

    let adapter = repo_scan::walk::primary_adapter();
    let listing: Box<dyn Iterator<Item = WalkItem> + '_> = match pinned {
        Some(pinned) => match pinned.into_children(true) {
            Ok(children) => Box::new(children),
            Err(e) => {
                return Ok(EnumCollected::ListFailed {
                    dir_id,
                    now_ms: now,
                    error: e,
                });
            }
        },
        None => match adapter.list_dir(
            path,
            ListOptions {
                skip_metadata: true,
            },
        ) {
            Ok(listing) => listing,
            Err(e) => {
                return Ok(EnumCollected::ListFailed {
                    dir_id,
                    now_ms: now,
                    error: e,
                });
            }
        },
    };
    let mut children = Vec::new();
    let mut entries_seen = 0u64;
    let mut mid_error: Option<String> = None;
    let watchdog_grace = ctx.watchdog_grace;
    let mut last_progress = Instant::now();
    let mut progress_mark = 0u64;
    for item in listing {
        // R04 / SR-STATE-01 lease bound: the coordinator's scheduled
        // renewal tick (Step 9, one batch for every in-flight task) keeps
        // this listing's lease alive — no in-loop heartbeat here, so the
        // worker never touches the store. A truly blocked `next()` wedges
        // its worker exactly like the old sequential drain; interruption
        // still stops admission (the tick stops with the drain, so the
        // lease lapses and a resume reclaims it), and the pre-persist
        // gate re-verifies before anything is written.
        // SR-STATE-01 lifetime bound: under memory pressure stop admitting
        // more enumeration work between items; the partial result below is
        // preserved and the task retries after pressure clears.
        if ctx.under_pressure() {
            mid_error = Some(format!(
                "memory pressure after {entries_seen} entries; partial enumeration",
            ));
            break;
        }
        // Progress-aware in-loop abort (RSF-SEC-WATCHDOG-ABORT): only a
        // stall with no completed entry inside grace aborts; the partial
        // enumeration below is preserved as a `watchdog-no-progress` gap.
        if watchdog_inloop_abort(
            entries_seen,
            progress_mark,
            last_progress.elapsed(),
            watchdog_grace,
        ) {
            mid_error = Some(format!(
                "watchdog: no progress within {}s after {entries_seen} entries; \
                 partial enumeration",
                watchdog_grace.as_secs(),
            ));
            break;
        }
        if interrupted() {
            mid_error = Some(String::from("interrupted; partial enumeration"));
            break;
        }
        // R04 / SR-STATE-01: progress-aware execution budget.
        // A healthy, advancing enumeration is never abandoned merely because total
        // elapsed wall time exceeded OP_DEADLINE_SECS. Timeout abandonment only occurs
        // if enumeration has stalled with no observed entries for OP_DEADLINE_SECS
        // (or deadline expired before any entry was observed).
        if last_progress.elapsed() >= Duration::from_secs(OP_DEADLINE_SECS)
            || (entries_seen == 0 && deadline.expired())
        {
            mid_error = Some(format!(
                "timeout-abandoned: enumeration of {} exceeded execution budget \
                 (stalled for {}s) after {entries_seen} entries; partial enumeration",
                path.display(),
                last_progress.elapsed().as_secs(),
            ));
            break;
        }
        let child = match item {
            Ok(child) => child,
            Err(e) => {
                mid_error = Some(format!("mid-enumeration error: {e}"));
                break;
            }
        };
        entries_seen += 1;
        progress_mark = entries_seen;
        last_progress = Instant::now();
        children.push(EnumChild {
            name: child.name,
            kind: child.kind,
        });
    }
    Ok(EnumCollected::Scan(EnumScan {
        dev,
        ino,
        volume_tag,
        dir_id,
        ino_str,
        incarnation,
        component,
        display,
        children,
        entries_seen,
        mid_error,
        now_ms: now,
    }))
}

/// Write half of enumeration ([`finish_enumerate`]): directory upsert, child enqueues
/// replayed from the collected names/kinds, observation row, and outcome
/// mapping. Runs on the single writer.
async fn persist_enumeration(
    runner: &mut Runner,
    store: &TursoStore,
    generation: u64,
    claimed: &ClaimedTask,
    path: &Path,
    collected: EnumCollected,
) -> repo_scan::Result<TaskOutcome> {
    match collected {
        EnumCollected::Link => {
            // The task path resolves to a symlink (swapped since
            // scheduling): resolve it through the topology layer like any
            // symlink child instead of following it blindly. The link
            // itself needs no enumeration.
            enqueue_symlink_target(store, runner, generation, path, store::now_ms()).await?;
            Ok(TaskOutcome::Complete)
        }
        EnumCollected::Refused { state, reason } => Ok(TaskOutcome::Parked { state, reason }),
        EnumCollected::StatFailed(e) => fail_stat_open(runner, store, claimed, path, &e).await,
        EnumCollected::ListFailed {
            dir_id,
            now_ms,
            error: e,
        } => fail_list_open(runner, store, claimed, dir_id, generation, path, now_ms, &e).await,
        EnumCollected::Scan(scan) => {
            runner.topology.observe(PhysicalDirId {
                dev: scan.dev,
                ino: scan.ino,
                namespace: scan.volume_tag.clone(),
            });
            let now = scan.now_ms;
            let due = TursoStore::buffer_dir_upsert(
                &mut runner.batch,
                None,
                &scan.component,
                &scan.display,
                &scan.volume_tag,
                &scan.ino_str,
                &scan.incarnation,
                now,
            );
            flush_if_due(runner, store, due).await?;
            let mut saw_head = false;
            let mut saw_objects = false;
            let mut saw_refs = false;
            let mut probed_self_for_dot_git = false;
            for child in &scan.children {
                let name = &child.name;
                let is_dot_git = name.as_os_str() == std::ffi::OsStr::new(".git");
                if is_dot_git && !probed_self_for_dot_git {
                    probed_self_for_dot_git = true;
                    enqueue_probe_task(store, runner, generation, claimed, path, now).await?;
                }
                track_bare_markers(
                    name,
                    child.kind,
                    &mut saw_head,
                    &mut saw_objects,
                    &mut saw_refs,
                );
                let child_path = path.join(name);
                match child.kind {
                    ChildKind::Directory => {
                        enqueue_enum_child(store, runner, generation, &child_path, now).await?;
                    }
                    ChildKind::Symlink => {
                        enqueue_symlink_target(store, runner, generation, &child_path, now).await?;
                    }
                    ChildKind::File | ChildKind::Other => {}
                }
            }
            runner.counters.entries += scan.entries_seen;
            if saw_head && saw_objects && saw_refs {
                // Bare-store marker evidence: exact-path validation decides.
                enqueue_probe_task(store, runner, generation, claimed, path, now).await?;
            }
            let completed = scan.mid_error.is_none();
            // RSF-751/AC46/F06D: read-free observation; the attempt counts in SQL,
            // so this write never needs a flush to observe buffered rows first.
            let due = TursoStore::buffer_record_dir_observation_bumped(
                &mut runner.batch,
                scan.dir_id,
                generation,
                completed,
                scan.entries_seen,
                scan.mid_error.as_deref(),
                store::now_ms(),
            );
            flush_if_due(runner, store, due).await?;
            if completed {
                runner.counters.dirs_complete += 1;
                Ok(TaskOutcome::Complete)
            } else {
                let detail = scan
                    .mid_error
                    .unwrap_or_else(|| String::from("partial enumeration"));
                // SR-STATE-01: a deadline abandonment parks (never retries into
                // the same wedge); `complete_task` records the loud gap row.
                if detail.starts_with("timeout-abandoned:") {
                    return Ok(park_on_timeout(&detail));
                }
                let category = if detail.starts_with("watchdog:") {
                    "watchdog-no-progress"
                } else {
                    "enumerate-error"
                };
                fail_task(
                    runner,
                    store,
                    claimed,
                    ExecFail {
                        category: String::from(category),
                        detail,
                    },
                )
                .await
            }
        }
    }
}

/// Enumerate one directory's immediate children: upsert the directory row,
/// enqueue unseen child directories (identity-deduped), resolve symlinks
/// through the topology layer, detect Git candidates by marker evidence
/// (`.git` entry; `HEAD`+`objects`+`refs` for bare stores) for exact-path
/// validation, and record the observation. Races are gaps, never absence.
/// `deadline` (SR-STATE-01) bounds the item loop: expiry abandons the
/// remainder and parks the scope instead of wedging the run.
/// Coordinator half of one enumeration task: scope decode. The
/// fenced listing runs on a pool thread ([`collect_enum_reads`]); the
/// outcome is applied by [`finish_enumerate`].
fn prepare_enumerate(
    runner: &Runner,
    claimed: &ClaimedTask,
    deadline: &OpDeadline,
) -> (PrepExtra, PrepAction) {
    let Some(config::ScopeRef::Dir(path)) = config::parse_scope_key(&claimed.task.scope_key) else {
        return (
            PrepExtra::Done,
            PrepAction::Done(TaskOutcome::Parked {
                state: TaskState::Unsupported,
                reason: format!("malformed dir scope key: {}", claimed.task.scope_key),
            }),
        );
    };
    let job = WorkerJob::Enumerate {
        ctx: runner.read_context(),
        path: path.clone(),
        deadline: *deadline,
    };
    (PrepExtra::Enumerate { path }, PrepAction::Spawn(job))
}

/// Coordinator write half of one enumeration task: applies a worker
/// result ([`EnumCollected`]) through the pre-persist lease gate and
/// [`persist_enumeration`]. Returns the outcome plus the listing's
/// child count for the watchdog verdict.
async fn finish_enumerate(
    runner: &mut Runner,
    store: &TursoStore,
    generation: u64,
    claimed: &ClaimedTask,
    path: &Path,
    result: repo_scan::Result<WorkerOut>,
) -> repo_scan::Result<(TaskOutcome, u64)> {
    let collected = match result {
        Ok(WorkerOut::Enumerate(collected)) => collected,
        Ok(_) => {
            return Err(repo_scan::Error::Scheduler(String::from(
                "enumeration finish received a non-enumeration worker result",
            )));
        }
        Err(e) => return Err(e),
    };
    let units = match &collected {
        EnumCollected::Scan(scan) => scan.children.len() as u64,
        _ => 0,
    };
    // R4 heartbeat: re-verify the lease before the first buffered write —
    // the listing may have consumed the window since the claim.
    // Observations under a lost lease are discarded and the scope retries
    // with a fresh lease (same pre-persist gate as probe/analysis/status).
    if !renew_claim_lease(store, &mut runner.counters.db_transactions, claimed).await? {
        let outcome = retry_on_lease_lost(
            runner,
            store,
            claimed,
            &format!(
                "lease lost before persisting enumeration of {}; observations discarded",
                path.display()
            ),
        )
        .await?;
        return Ok((outcome, units));
    }
    let outcome = persist_enumeration(runner, store, generation, claimed, path, collected).await?;
    Ok((outcome, units))
}

/// Incarnation guard from explicit parts (link count + mtime + size).
/// [`incarnation_of`] delegates here; the fenced open supplies pinned
/// `fstat` parts directly.
fn incarnation_from_parts(nlink: u64, mtime: Option<(i64, i64)>, len: u64) -> String {
    let mtime = mtime
        .map(|(secs, nanos)| format!("{secs}.{nanos}"))
        .unwrap_or_else(|| String::from("unknown"));
    format!("n{nlink}:m{mtime}:s{len}")
}

/// Incarnation guard against identifier reuse (link count + mtime + size).
#[cfg(unix)]
fn incarnation_of(md: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .and_then(|d| {
            i64::try_from(d.as_secs())
                .ok()
                .map(|secs| (secs, i64::from(d.subsec_nanos())))
        });
    incarnation_from_parts(md.nlink(), mtime, md.len())
}

#[cfg(not(unix))]
fn incarnation_of(md: &std::fs::Metadata) -> String {
    format!("s{}", md.len())
}

fn track_bare_markers(
    name: &std::ffi::OsStr,
    kind: ChildKind,
    saw_head: &mut bool,
    saw_objects: &mut bool,
    saw_refs: &mut bool,
) {
    if name == std::ffi::OsStr::new("HEAD") && matches!(kind, ChildKind::File) {
        *saw_head = true;
    } else if name == std::ffi::OsStr::new("objects") && matches!(kind, ChildKind::Directory) {
        *saw_objects = true;
    } else if (name == std::ffi::OsStr::new("refs") && matches!(kind, ChildKind::Directory))
        || (name == std::ffi::OsStr::new("packed-refs") && matches!(kind, ChildKind::File))
    {
        *saw_refs = true;
    }
}

async fn enqueue_enum_child(
    store: &TursoStore,
    runner: &mut Runner,
    generation: u64,
    child_path: &Path,
    now_ms: i64,
) -> repo_scan::Result<()> {
    let id = enum_task_id_for_path(generation, child_path);
    let scope_key = config::scope_key_for_dir(child_path);
    let expected_rev = store.scope_rev(&scope_key).await?;
    let idempotency = format!("idem:{id}");
    // RSF-AC461500-609D-4D55-991E-09C60D382D67: buffered enqueue. The
    // identity-dedupe alias check is deferred to the flush: when the
    // same object is already scheduled under another spelling, results
    // are shared (not dropped) and the alternate pathname is preserved
    // as an alias (R7); `note_enum_alias` no-ops on same-scope rows.
    let task = NewTask {
        id: &id,
        kind: KIND_ENUM,
        generation,
        dir_id: None,
        scope_key: &scope_key,
        expected_rev,
        idempotency_key: &idempotency,
    };
    let due = TursoStore::buffer_enqueue_task(&mut runner.batch, &task, now_ms);
    runner.pending_alias_checks.push(PendingAliasCheck {
        task_id: id,
        scope_key,
        path: child_path.to_path_buf(),
        kind: "same_object",
        at_ms: now_ms,
    });
    flush_if_due(runner, store, due).await?;
    Ok(())
}

/// Record a pathname alias when an enumeration task for `path` already
/// exists under a different scope key (R7). Same-path re-enqueues (roots
/// reseeded, children rediscovered) are not aliases and record nothing.
async fn note_enum_alias(
    store: &TursoStore,
    runner: &mut Runner,
    task_id: &str,
    scope_key: &str,
    path: &Path,
    kind: &'static str,
    now_ms: i64,
) -> repo_scan::Result<()> {
    let existing = match store.get_task(task_id).await? {
        Some(task) if task.scope_key != scope_key => task,
        _ => return Ok(()),
    };
    let Some(config::ScopeRef::Dir(first)) = config::parse_scope_key(&existing.scope_key) else {
        return Ok(());
    };
    let due = runner.note_alias(
        config::path_as_bytes(path),
        config::path_as_bytes(&first),
        kind,
        now_ms,
    )?;

    // Boxed: flush_runner_batch -> note_enum_alias -> flush_if_due ->
    // flush_runner_batch is a future-type cycle (E0733).
    Box::pin(flush_if_due(runner, store, due)).await?;
    Ok(())
}

/// Resolve a symlink child through the topology layer: unseen in-scope
/// directory targets become scheduled work; cycles, depth overflow, and
/// unresolvable targets become preserved gaps.
async fn enqueue_symlink_target(
    store: &TursoStore,
    runner: &mut Runner,
    generation: u64,
    link_path: &Path,
    now_ms: i64,
) -> repo_scan::Result<()> {
    match resolve_symlink(link_path) {
        Ok(target) => {
            if !matches!(target.kind, ChildKind::Directory) {
                return Ok(());
            }
            // Finding 12: never schedule work outside the declared
            // roots. The link alias is preserved; the out-of-scope
            // target simply schedules no work (execution re-verifies).
            if let Some(fence) = runner.fence.as_ref() {
                if !fence.allows_path(&target.path) {
                    let alias_due = runner.note_alias(
                        config::path_as_bytes(link_path),
                        config::path_as_bytes(&target.path),
                        "symlink",
                        now_ms,
                    )?;
                    flush_if_due(runner, store, alias_due).await?;
                    return Ok(());
                }
            }
            let id = format!(
                "enum:{generation}:d{}:i{}",
                target.metadata.dev, target.metadata.ino
            );
            let scope_key = config::scope_key_for_dir(&target.path);
            let expected_rev = store.scope_rev(&scope_key).await?;
            let idempotency = format!("idem:{id}");
            // RSF-AC461500-609D-4D55-991E-09C60D382D67: buffered enqueue;
            // the target's same-object check is deferred to the flush.
            let task = NewTask {
                id: &id,
                kind: KIND_ENUM,
                generation,
                dir_id: None,
                scope_key: &scope_key,
                expected_rev,
                idempotency_key: &idempotency,
            };
            let due = TursoStore::buffer_enqueue_task(&mut runner.batch, &task, now_ms);
            // The link pathname is an alias of its target pathname (R7),
            // whether or not this enqueue won the shared task.
            let alias_due = runner.note_alias(
                config::path_as_bytes(link_path),
                config::path_as_bytes(&target.path),
                "symlink",
                now_ms,
            )?;
            // The target itself may be scheduled under another spelling:
            // preserve that pair too (deferred; no-ops on same scope).
            runner.pending_alias_checks.push(PendingAliasCheck {
                task_id: id,
                scope_key,
                path: target.path.clone(),
                kind: "same_object",
                at_ms: now_ms,
            });
            flush_if_due(runner, store, due || alias_due).await?;
            Ok(())
        }
        Err(ResolveError::Cycle(p) | ResolveError::TooDeep(p)) => {
            let due = buffer_record_error(
                runner,
                &format!(
                    "symlink:{}",
                    config::encode_hex(&config::path_as_bytes(link_path))
                ),
                &config::scope_key_for_dir(link_path),
                "symlink-cycle",
                &format!("symlink cycle or excessive chain at {}", p.display()),
                None,
                now_ms,
            )?;
            flush_if_due(runner, store, due).await?;
            Ok(())
        }
        Err(ResolveError::Io(e)) => {
            let due = buffer_record_error(
                runner,
                &format!(
                    "symlink:{}",
                    config::encode_hex(&config::path_as_bytes(link_path))
                ),
                &config::scope_key_for_dir(link_path),
                "symlink-unresolvable",
                &format!("cannot resolve {}: {e}", link_path.display()),
                None,
                now_ms,
            )?;
            flush_if_due(runner, store, due).await?;
            Ok(())
        }
    }
}

/// Provenance of a scheduled probe task (PG-01): where the scheduler
/// observed the path. `Enum` probes come from directory enumeration and
/// must resolve in-scope; `Relationship` probes come from explicit
/// Git-relationship observations (registered worktree bases, spec §8) and
/// may resolve outside the roots on their own descriptor pin. The
/// provenance travels durably in the task id so execution-time
/// verification never infers the relationship from the spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeProvenance {
    /// Scheduled from directory enumeration: in-scope only.
    Enum,
    /// Scheduled from a Git-relationship observation: may sit outside.
    Relationship,
}

/// Schedule-time observation carried through a probe task (PG-01): the
/// `(dev, ino)` the path had when the scheduler saw it, plus the
/// provenance token. [`verify_probe_path`] compares the pre-run pin
/// against this identity; a mismatch is a schedule/execute swap and
/// refuses. Unknown identity (`None`: unstattable at schedule time, or a
/// non-unix target where [`dir_identity`] is `(0, 0)`) skips the
/// comparison but still enforces provenance. Residual: an inode number
/// reused for a replacement directory at the same spelling inside one
/// schedule/execute window aliases past the comparison — the window is
/// one claim latency, and the re-verification envelope still applies.
#[derive(Debug, Clone, Copy)]
pub struct ProbeSchedule {
    /// Schedule-time `(dev, ino)`; `None` when unknown.
    pub identity: Option<(u64, u64)>,
    /// Scheduler provenance token.
    pub provenance: ProbeProvenance,
}

impl ProbeSchedule {
    /// Schedule for a legacy probe id (no carried observation): in-scope
    /// only, no identity comparison — relationship routing refuses.
    fn legacy_enum() -> Self {
        Self {
            identity: None,
            provenance: ProbeProvenance::Enum,
        }
    }

    /// Schedule for a status task (pre-PG-01 shape, no carried
    /// observation): checkout rows always derive from Git observations,
    /// so relationship routing stays available; identity comparison is
    /// skipped and the pin/re-verify envelope still binds execution.
    fn status_legacy() -> Self {
        Self {
            identity: None,
            provenance: ProbeProvenance::Relationship,
        }
    }

    /// Schedule for an analysis task: store rows always derive from Git
    /// observations (same shape as [`ProbeSchedule::status_legacy`]), so
    /// relationship routing stays available; the pin/re-verify envelope
    /// still binds execution.
    fn analysis_legacy() -> Self {
        Self {
            identity: None,
            provenance: ProbeProvenance::Relationship,
        }
    }
}

/// Parse the schedule suffix off a probe task id:
/// `probe:{generation}:{hex}[:r{rev}]:s{dev}x{ino}:{enum|rel}`.
/// Anything else (legacy probe ids, status/enum/reconcile ids) yields
/// `None`. `(0, 0)` decodes to unknown identity, matching the codebase
/// convention that `(0, 0)` never denotes a real object.
pub fn parse_probe_schedule(task_id: &str) -> Option<ProbeSchedule> {
    let rest = task_id.strip_prefix("probe:")?;
    let mut parts = rest.rsplit(':');
    let provenance = match parts.next()? {
        "enum" => ProbeProvenance::Enum,
        "rel" => ProbeProvenance::Relationship,
        _ => return None,
    };
    let ident = parts.next()?;
    let pair = ident.strip_prefix('s')?;
    let (dev_text, ino_text) = pair.split_once('x')?;
    let dev: u64 = dev_text.parse().ok()?;
    let ino: u64 = ino_text.parse().ok()?;
    let identity = if (dev, ino) == (0, 0) {
        None
    } else {
        Some((dev, ino))
    };
    Some(ProbeSchedule {
        identity,
        provenance,
    })
}

/// Schedule suffix for a fresh probe task id: stat the path now (the
/// schedule-time observation) and encode `:s{dev}x{ino}:{provenance}`.
/// Unstattable paths and non-unix targets encode `(0, 0)` (unknown).
fn schedule_suffix_for(path: &Path, provenance: ProbeProvenance) -> String {
    let (dev, ino) = std::fs::symlink_metadata(path)
        .ok()
        .map(|md| dir_identity(&md))
        .unwrap_or((0, 0));
    let token = match provenance {
        ProbeProvenance::Enum => "enum",
        ProbeProvenance::Relationship => "rel",
    };
    format!(":s{dev}x{ino}:{token}")
}

/// Enqueue an exact-path Git probe. Reconcile-triggered probes carry the
/// revision suffix so metadata invalidation genuinely re-probes.
async fn enqueue_probe_task(
    store: &TursoStore,
    runner: &mut Runner,
    generation: u64,
    claimed: &ClaimedTask,
    path: &Path,
    now_ms: i64,
) -> repo_scan::Result<()> {
    let hex = config::encode_hex(&config::path_as_bytes(path));
    let suffix = if claimed.task.kind == KIND_RECONCILE {
        format!(":r{}", claimed.task.expected_rev)
    } else {
        String::new()
    };
    // PG-01: carry the schedule-time identity + enum provenance in the
    // task id so execution verifies against the observation, not the
    // spelling.
    let schedule = schedule_suffix_for(path, ProbeProvenance::Enum);
    let id = format!("probe:{generation}:{hex}{suffix}{schedule}");
    let scope_key = config::scope_key_for_git(path);
    let expected_rev = store.scope_rev(&scope_key).await?;
    let idempotency = format!("idem:{id}");
    // RSF-AC461500-609D-4D55-991E-09C60D382D67: buffered enqueue.
    let task = NewTask {
        id: &id,
        kind: KIND_PROBE,
        generation,
        dir_id: None,
        scope_key: &scope_key,
        expected_rev,
        idempotency_key: &idempotency,
    };
    let due = TursoStore::buffer_enqueue_task(&mut runner.batch, &task, now_ms);
    flush_if_due(runner, store, due).await?;
    Ok(())
}

/// Outcome of the pre-run fence verification for one probe/status path.
pub enum ProbeFence {
    /// No fence configured (unit-test runners): legacy unverified run.
    Unfenced,
    /// Pinned, in-scope execution: run Git, then re-verify identity.
    Pinned(PinnedDir),
    /// Pinned out-of-scope execution (explicit Git-relationship path,
    /// spec §8): the scope fence cannot cover it, so the path is pinned
    /// through the unscoped descriptor walk and re-verified after Git
    /// runs — untrusted worktree metadata names the spelling, the pin
    /// binds the execution (PATH-GIT-01).
    Relationship(PinnedDir),
    /// Refused without spawning Git: park with the reason, persist nothing.
    Refused { state: TaskState, reason: String },
    /// Open failed like the legacy stat: park or retry, no observation.
    StatFailed(std::io::Error),
}

/// True when the pre-run pin matches the schedule-time identity (PG-01).
/// Unknown schedule identity (`None`: unstattable at schedule time, or a
/// non-unix target) skips the comparison; every known identity must match
/// exactly, or the path was swapped between scheduling and execution.
fn schedule_identity_ok(pinned: &PinnedDir, schedule: &ProbeSchedule) -> bool {
    match schedule.identity {
        None => true,
        Some((dev, ino)) => {
            let stat = pinned.stat();
            stat.meta.dev == dev && stat.meta.ino == ino
        }
    }
}

/// Pre-run fence verification for one probe/status path (`what` names the
/// task kind for gap reasons): resolve through the pinned fence and compare
/// the pre-run pin against the schedule-time identity carried in the task
/// (PG-01) — never infer the relationship from the spelling. A scheduled
/// in-scope probe whose execution-time pin differs from the schedule-time
/// `(dev, ino)`, or whose resolution lands outside the declared roots, is a
/// swap between scheduling and execution and refuses. Only a probe that
/// carries relationship provenance (explicit Git-relationship path:
/// registered worktree base, external common dir — spec §8) may proceed
/// outside the roots, pinned through the unscoped descriptor walk with its
/// identity re-verified after Git runs. A task path that is itself a link
/// never proceeds: probes follow registry/pointer relationships, never a
/// swapped-in link. Descriptor pinning unavailable on this target refuses
/// (PATH-GIT-03): probes and status never run unfenced off a failed pin.
pub fn verify_probe_path(
    fence: Option<&ScopeFence>,
    what: &str,
    path: &Path,
    schedule: &ProbeSchedule,
) -> ProbeFence {
    let Some(fence) = fence else {
        return ProbeFence::Unfenced;
    };
    match fence.open_pinned(path) {
        Ok(FenceOpen::Dir(pinned)) => {
            if schedule_identity_ok(&pinned, schedule) {
                ProbeFence::Pinned(pinned)
            } else {
                let (dev, ino) = schedule.identity.unwrap_or((0, 0));
                ProbeFence::Refused {
                    state: TaskState::Unavailable,
                    reason: format!(
                        "{what} path {} schedule-time identity mismatch (expected d{dev}i{ino}); \
                         refusing swapped execution",
                        path.display()
                    ),
                }
            }
        }
        Ok(FenceOpen::Symlink) => ProbeFence::Refused {
            state: TaskState::Unavailable,
            reason: format!(
                "{what} path {} is a symlink; {what} never follows a swapped-in link",
                path.display()
            ),
        },
        Err(FenceError::OutOfScope(p)) => match schedule.provenance {
            // Explicitly scheduled out-of-scope relationship path: pin it
            // descriptor-relative (no scope check) so untrusted worktree
            // metadata cannot redirect execution; the caller re-verifies
            // the pinned identity after Git runs. Links, pin failures, and
            // schedule-identity mismatches refuse closed.
            ProbeProvenance::Relationship => match fence.open_relationship_pinned(path) {
                Ok(FenceOpen::Dir(pinned)) if schedule_identity_ok(&pinned, schedule) => {
                    ProbeFence::Relationship(pinned)
                }
                Ok(FenceOpen::Dir(_)) => {
                    let (dev, ino) = schedule.identity.unwrap_or((0, 0));
                    ProbeFence::Refused {
                        state: TaskState::Unavailable,
                        reason: format!(
                            "{what} relationship path {} schedule-time identity mismatch \
                             (expected d{dev}i{ino}); refusing swapped execution",
                            path.display()
                        ),
                    }
                }
                Ok(FenceOpen::Symlink) => ProbeFence::Refused {
                    state: TaskState::Unavailable,
                    reason: format!(
                        "{what} relationship path {} is a symlink; {what} never follows a swapped-in link",
                        path.display()
                    ),
                },
                Err(e) => ProbeFence::Refused {
                    state: TaskState::Unavailable,
                    reason: format!(
                        "{what} relationship path {} cannot be pinned: {e}",
                        path.display()
                    ),
                },
            },
            // No relationship provenance: an in-scope spelling resolving
            // out of scope is a schedule/execute swap (escape); an
            // out-of-scope spelling without provenance is not a scheduled
            // relationship. Both refuse — the spelling alone never
            // authorizes relationship routing (only the reason differs).
            ProbeProvenance::Enum if fence.allows_path(path) => ProbeFence::Refused {
                state: TaskState::Unavailable,
                reason: format!("{what} path {} escaped the scan scope", p.display()),
            },
            ProbeProvenance::Enum => ProbeFence::Refused {
                state: TaskState::Unavailable,
                reason: format!(
                    "{what} path {} is outside the scan scope and is not a scheduled Git \
                     relationship; refusing",
                    path.display()
                ),
            },
        },
        Err(FenceError::TooDeep(p)) => ProbeFence::Refused {
            state: TaskState::Unavailable,
            reason: format!("symlink chain too deep at {}", p.display()),
        },
        Err(FenceError::NotAbsolute(p)) => ProbeFence::Refused {
            state: TaskState::Unavailable,
            reason: format!("scope path is not absolute: {}", p.display()),
        },
        // Descriptor pinning unavailable on this target: fail closed
        // (PATH-GIT-03) — never an unfenced pathname run.
        Err(FenceError::Unsupported(detail)) => ProbeFence::Refused {
            state: TaskState::Unsupported,
            reason: format!(
                "{what} path {} cannot be pinned on this platform ({detail}); refusing unfenced execution",
                path.display()
            ),
        },
        Err(FenceError::NotDirectory(p)) => ProbeFence::StatFailed(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            format!("not a directory: {}", p.display()),
        )),
        Err(FenceError::Io(e)) => ProbeFence::StatFailed(e),
    }
}

/// Post-run fence re-verification for one probe/status path: re-resolve
/// `path` through the fence and require the same true path plus `(dev,
/// ino)` identity the pre-run pin observed. `false` means the path was
/// swapped mid-run (or left the scope): the caller must discard every
/// observation and park the scope, never persist. Unfenced runners (unit
/// tests) always pass; on non-unix targets the pinned open refuses with
/// `Unsupported`, which also passes through the legacy path before this
/// helper is ever reached.
pub fn reverify_probe_path(fence: Option<&ScopeFence>, path: &Path, before: &PinnedDir) -> bool {
    let Some(fence) = fence else {
        return true;
    };
    match fence.open_pinned(path) {
        Ok(FenceOpen::Dir(after)) => {
            let before_stat = before.stat();
            let after_stat = after.stat();
            after.true_path() == before.true_path()
                && after_stat.meta.dev == before_stat.meta.dev
                && after_stat.meta.ino == before_stat.meta.ino
        }
        _ => false,
    }
}

/// Owned identity snapshot for DURING-inspection re-verification (XSEC-01):
/// the pre-run pin's true path plus `(dev, ino)`, without the descriptor.
/// Owned (not borrowed) so stage polls and the status watch thread can
/// re-resolve freely.
#[derive(Debug, Clone)]
pub struct IdentitySnapshot {
    true_path: PathBuf,
    dev: u64,
    ino: u64,
}

/// Snapshot one pre-run pin.
pub fn snapshot_of(pinned: &PinnedDir) -> IdentitySnapshot {
    let stat = pinned.stat();
    IdentitySnapshot {
        true_path: pinned.true_path().to_path_buf(),
        dev: stat.meta.dev,
        ino: stat.meta.ino,
    }
}

/// Re-resolve `path` through the fence and require the snapshot's true
/// path plus `(dev, ino)` — the scoped walk first, falling back to the
/// relationship walk when the pin sits outside the declared roots (same
/// order as [`ScopeFence::reverify_pinned`]). `false` means the path was
/// swapped: the caller must discard every observation. Unfenced runners
/// (`None` fence or snapshot) always pass.
pub fn snapshot_matches(
    fence: Option<&ScopeFence>,
    path: &Path,
    snap: Option<&IdentitySnapshot>,
) -> bool {
    let (Some(fence), Some(snap)) = (fence, snap) else {
        return true;
    };
    let matches = |after: &PinnedDir| {
        let stat = after.stat();
        after.true_path() == snap.true_path
            && stat.meta.dev == snap.dev
            && stat.meta.ino == snap.ino
    };
    match fence.open_pinned(path) {
        Ok(FenceOpen::Dir(after)) => matches(&after),
        Err(FenceError::OutOfScope(_)) => match fence.open_relationship_pinned(path) {
            Ok(FenceOpen::Dir(after)) => matches(&after),
            _ => false,
        },
        _ => false,
    }
}

/// DURING-inspection identity poller (XSEC-01): owns the fence, path, and
/// pre-run snapshot (cloned once per probe — a few path buffers), so
/// polls borrow nothing from the runner. [`IdentityPoll::ok_now`] always
/// re-resolves; [`IdentityPoll::ok_throttled`] skips while the last check
/// is fresher than [`IDENT_POLL_INTERVAL`].
struct IdentityPoll {
    fence: Option<ScopeFence>,
    path: PathBuf,
    snap: Option<IdentitySnapshot>,
    last: Instant,
}

impl IdentityPoll {
    fn new(fence: Option<&ScopeFence>, path: &Path, pinned: Option<&PinnedDir>) -> Self {
        Self {
            fence: fence.cloned(),
            path: path.to_path_buf(),
            snap: pinned.map(snapshot_of),
            last: Instant::now(),
        }
    }

    /// Re-verify now; `false` means the identity changed.
    fn ok_now(&mut self) -> bool {
        self.last = Instant::now();
        snapshot_matches(self.fence.as_ref(), &self.path, self.snap.as_ref())
    }

    /// Re-verify unless the last check is within [`IDENT_POLL_INTERVAL`];
    /// `false` means the identity changed.
    fn ok_throttled(&mut self) -> bool {
        if self.last.elapsed() < IDENT_POLL_INTERVAL {
            return true;
        }
        self.ok_now()
    }
}

/// Parked outcome for an identity change found during inspection (XSEC-01):
/// every observation discards (nothing buffered yet — reads precede all
/// writes), loud on stderr now, durable gap row at completion.
fn park_on_identity_change(what: &str, path: &Path) -> TaskOutcome {
    let reason = format!(
        "{what} path {} changed during inspection; observations discarded",
        path.display()
    );
    eprintln!("repo-scan: {}", identity::scrub_text(&reason));
    TaskOutcome::Parked {
        state: TaskState::Unavailable,
        reason,
    }
}

/// Margin between a renewed lease's expiry and the longest blocking
/// call allowed under it (R4): the status call runs under `LEASE_TTL_MS`
/// minus this, so the guard trips and the observation is discarded
/// strictly before the lease can lapse — valid work is never reclaimed
/// mid-call.
const LEASE_WINDOW_MARGIN_MS: i64 = 15_000;

/// Renew one claimed task's lease (R4 heartbeat for probe/status paths):
/// extends `lease_expires_ms` by [`LEASE_TTL_MS`] iff the exact
/// token/epoch lease is still held. Goes through the store renewal API
/// (same call as the enumeration heartbeat): a `false` renewal means
/// the lease is gone (expired, reclaimed, or superseded) — the caller
/// must stop touching the scope and preserve a gap via [`fail_task`],
/// never race a completion. Never touches another owner's lease. One
/// transaction counted through `renewals` when the lease is held (the
/// coordinator passes its counter; read halves pass a local that the
/// coordinator replays, so the count survives early returns and errors).
async fn renew_claim_lease(
    store: &TursoStore,
    renewals: &mut u64,
    claimed: &ClaimedTask,
) -> repo_scan::Result<bool> {
    let lease_epoch = claimed.task.lease_epoch.unwrap_or(u64::MAX);
    let renewed = store
        .renew_lease(
            &claimed.task.id,
            claimed.token,
            lease_epoch,
            LEASE_TTL_MS,
            store::now_ms(),
        )
        .await?;
    if renewed {
        *renewals += 1;
    }
    Ok(renewed)
}

/// Retry outcome for a probe/status op that outlived its lease (R4):
/// observations are discarded (another owner may hold the scope) and the
/// scope retries with backoff — or parks when attempts are exhausted —
/// with the loss preserved as a gap. Mirrors the enumeration path, which
/// funnels its own lease loss through [`fail_task`].
async fn retry_on_lease_lost(
    runner: &mut Runner,
    store: &TursoStore,
    claimed: &ClaimedTask,
    detail: &str,
) -> repo_scan::Result<TaskOutcome> {
    eprintln!("repo-scan: {}", identity::scrub_text(detail));
    fail_task(
        runner,
        store,
        claimed,
        ExecFail {
            category: String::from("lease-lost"),
            detail: detail.to_string(),
        },
    )
    .await
}

/// Budget split for one blocking status call (R4): `(call_ms, lease_bound)`.
/// The call runs under the tighter of the remaining wall budget and the
/// freshly-renewed lease window (margin held back); `lease_bound` tells the
/// post-call check whether a window abandonment must retry with a fresh
/// lease rather than park valid-but-slow work. Pure and unit-testable.
fn lease_call_budget(wall_remaining_ms: u64) -> (u64, bool) {
    let lease_ms = (LEASE_TTL_MS - LEASE_WINDOW_MARGIN_MS).max(1) as u64;
    (
        wall_remaining_ms.min(lease_ms),
        lease_ms < wall_remaining_ms,
    )
}

/// R4 regression hook: budget split of one blocking status call.
#[cfg(test)]
pub fn test_lease_call_budget(wall_remaining_ms: u64) -> (u64, bool) {
    lease_call_budget(wall_remaining_ms)
}

/// Coordinator half of one probe task: scope decode plus the pre-run
/// lease renewal. Filesystem and Git reads (fence verify, validate,
/// identity-polled collection) run on a pool thread
/// ([`run_probe_job`]); the outcome is applied by [`finish_probe`].
/// Marker evidence that fails validation becomes a preserved
/// `probe-failed` gap (terminal for this probe; re-probe only after
/// invalidation or rescan), never a fake absence and never an endless
/// retry. Git reads run under DURING-inspection identity polls
/// (XSEC-01) with all observations collected before the first buffered
/// write, and under the task wall budget (SR-STATE-01).
async fn prepare_probe(
    runner: &mut Runner,
    store: &TursoStore,
    claimed: &ClaimedTask,
    deadline: &OpDeadline,
) -> repo_scan::Result<(PrepExtra, PrepAction)> {
    let done = |outcome: TaskOutcome| (PrepExtra::Done, PrepAction::Done(outcome));
    let Some(config::ScopeRef::Git(path)) = config::parse_scope_key(&claimed.task.scope_key) else {
        return Ok(done(TaskOutcome::Parked {
            state: TaskState::Unsupported,
            reason: format!("malformed git scope key: {}", claimed.task.scope_key),
        }));
    };
    // SR-STATE-01: abandon before the first Git read when the budget is
    // already gone. (The worker re-checks on arrival — a race the same
    // message covers — but the common expired case never spawns.)
    if deadline.expired() {
        return Ok(done(park_on_timeout(&format!(
            "timeout-abandoned: probe of {} exceeded the {OP_DEADLINE_SECS}s execution \
             budget; no Git reads ran",
            path.display()
        ))));
    }
    // R4 heartbeat: the claim may have aged in the batch before this op
    // started — renew before the worker spawns so the 60 s lease covers
    // the read stages below. A lost lease stops the op: nothing is
    // observed yet, so retry with a fresh lease instead of racing a
    // completion.
    if !renew_claim_lease(store, &mut runner.counters.db_transactions, claimed).await? {
        let outcome = retry_on_lease_lost(
            runner,
            store,
            claimed,
            &format!(
                "lease lost before probe of {}; retrying with a fresh lease",
                path.display()
            ),
        )
        .await?;
        return Ok(done(outcome));
    }
    let job = WorkerJob::Probe {
        ctx: runner.read_context(),
        task_id: claimed.task.id.clone(),
        path: path.clone(),
        deadline: *deadline,
    };
    Ok((PrepExtra::Probe { path }, PrepAction::Spawn(job)))
}
/// Coordinator write half of one probe task: applies a worker result
/// ([`ProbeCollected`]) through the pre-persist lease gate and
/// [`persist_probe`]. Returns the outcome plus the worker's progress
/// units for the watchdog verdict.
#[allow(clippy::too_many_arguments)]
async fn finish_probe(
    runner: &mut Runner,
    store: &TursoStore,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    claimed: &ClaimedTask,
    path: &Path,
    result: repo_scan::Result<WorkerOut>,
) -> repo_scan::Result<(TaskOutcome, u64)> {
    let collected = match result {
        Ok(WorkerOut::Probe(collected)) => collected,
        Ok(_) => {
            return Err(repo_scan::Error::Scheduler(String::from(
                "probe finish received a non-probe worker result",
            )));
        }
        // Operational Git read failures retry with backoff, then park with
        // the gap preserved; store failures abort the run (exit 1).
        Err(repo_scan::Error::Git(detail)) => {
            let outcome = fail_task(
                runner,
                store,
                claimed,
                ExecFail {
                    category: String::from("probe-read-error"),
                    detail,
                },
            )
            .await?;
            return Ok((outcome, 0));
        }
        Err(e) => return Err(e),
    };
    let units = collected.progress_units();
    let now = store::now_ms();
    let gap_id = format!("probe:{}", config::encode_hex(&config::path_as_bytes(path)));
    let outcome = match collected {
        ProbeCollected::Refused { state, reason } => TaskOutcome::Parked { state, reason },
        ProbeCollected::StatFailed(e) => fail_stat_open(runner, store, claimed, path, &e).await?,
        ProbeCollected::TimeoutBeforeReads => park_on_timeout(&format!(
            "timeout-abandoned: probe of {} exceeded the {OP_DEADLINE_SECS}s execution \
             budget; no Git reads ran",
            path.display()
        )),
        ProbeCollected::ValidateFailed {
            detail,
            unsupported,
        } => {
            let category = if unsupported {
                "unsupported-git-format"
            } else {
                "probe-failed"
            };
            let due = buffer_record_error(
                runner,
                &gap_id,
                &claimed.task.scope_key,
                category,
                &detail,
                None,
                now,
            )?;
            flush_if_due(runner, store, due).await?;
            TaskOutcome::Complete
        }
        ProbeCollected::Collected { validated, outcome } => match outcome {
            CollectOutcome::Reads(reads) => {
                // R4 heartbeat: re-verify the lease before the first
                // buffered write — a Git stage may have consumed the
                // window without tripping the identity polls.
                // Observations under a lost lease are discarded and the
                // scope retries with a fresh lease.
                if !renew_claim_lease(store, &mut runner.counters.db_transactions, claimed).await? {
                    let outcome = retry_on_lease_lost(
                        runner,
                        store,
                        claimed,
                        &format!(
                            "lease lost before persisting probe of {}; observations discarded",
                            path.display()
                        ),
                    )
                    .await?;
                    return Ok((outcome, units));
                }
                match persist_probe(
                    runner, store, generation, run_rev, canonical, path, &validated, *reads, now,
                )
                .await
                {
                    Ok(()) => {
                        let due = buffer_resolve_error(runner, &gap_id, store::now_ms())?;
                        flush_if_due(runner, store, due).await?;
                        TaskOutcome::Complete
                    }
                    // Operational Git failures retry with backoff, then park
                    // with the gap preserved; store failures abort the run
                    // (exit 1).
                    Err(repo_scan::Error::Git(detail)) => {
                        fail_task(
                            runner,
                            store,
                            claimed,
                            ExecFail {
                                category: String::from("probe-persist-error"),
                                detail,
                            },
                        )
                        .await?
                    }
                    Err(e) => return Err(e),
                }
            }
            CollectOutcome::IdentityChanged => park_on_identity_change("probe", path),
            CollectOutcome::TimedOut => park_on_timeout(&format!(
                "timeout-abandoned: probe of {} exceeded the {OP_DEADLINE_SECS}s execution \
                 budget during Git reads; observations discarded",
                path.display()
            )),
        },
    };
    Ok((outcome, units))
}

/// Execute one probe task under a fenced runner (probe-fence wiring
/// proof): the fence is built from `fence_roots` exactly like the scan
/// path builds it from the planned roots, then the production
/// the production task path runs against `scope_path`. `before_exec` runs between
/// claim and execution so the test can swap the scheduled path first —
/// the production schedule/execute race in miniature. Returns the
/// production outcome for the caller to match on.
#[cfg(test)]
pub async fn test_probe_fenced_outcome(
    store: &TursoStore,
    fence_roots: &[PathBuf],
    generation: u64,
    run_rev: u64,
    canonical: &str,
    scope_path: &Path,
    before_exec: Option<Box<dyn FnOnce() + Send>>,
) -> repo_scan::Result<TaskOutcome> {
    let deadline = OpDeadline::new(Duration::from_secs(OP_DEADLINE_SECS));
    test_probe_outcome_impl(
        store,
        fence_roots,
        generation,
        run_rev,
        canonical,
        scope_path,
        before_exec,
        deadline,
    )
    .await
}

/// Execute one probe task under a fenced runner with an explicit wall
/// budget (SR-STATE-01 wiring proof): identical to
/// [`test_probe_fenced_outcome`] except the deadline, so a zero budget
/// deterministically exercises the timeout-abandon path.
#[cfg(test)]
pub async fn test_probe_deadline_outcome(
    store: &TursoStore,
    fence_roots: &[PathBuf],
    generation: u64,
    run_rev: u64,
    canonical: &str,
    scope_path: &Path,
    budget: Duration,
) -> repo_scan::Result<TaskOutcome> {
    test_probe_outcome_impl(
        store,
        fence_roots,
        generation,
        run_rev,
        canonical,
        scope_path,
        None,
        OpDeadline::new(budget),
    )
    .await
}

/// Shared hook implementation: schedule-time observation (PG-01) is taken
/// at enqueue — the fence classifies the spelling only to pick the
/// scheduler provenance token — and `before_exec` swaps before execution.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn test_probe_outcome_impl(
    store: &TursoStore,
    fence_roots: &[PathBuf],
    generation: u64,
    run_rev: u64,
    canonical: &str,
    scope_path: &Path,
    before_exec: Option<Box<dyn FnOnce() + Send>>,
    deadline: OpDeadline,
) -> repo_scan::Result<TaskOutcome> {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    let schedule_fence = ScopeFence::build(fence_roots);
    let provenance = if schedule_fence.allows_path(scope_path) {
        ProbeProvenance::Enum
    } else {
        ProbeProvenance::Relationship
    };
    runner.fence = Some(schedule_fence);
    let scope_key = config::scope_key_for_git(scope_path);
    let hex = config::encode_hex(&config::path_as_bytes(scope_path));
    let schedule = schedule_suffix_for(scope_path, provenance);
    let id = format!("probe:{generation}:{hex}{schedule}");
    let expected_rev = store.scope_rev(&scope_key).await?;
    let idempotency = format!("idem:{id}");
    let task = NewTask {
        id: &id,
        kind: KIND_PROBE,
        generation,
        dir_id: None,
        scope_key: &scope_key,
        expected_rev,
        idempotency_key: &idempotency,
    };
    store.enqueue_task(&task, store::now_ms()).await?;
    let claimed = store
        .claim_tasks(store.epoch(), 16, LEASE_TTL_MS, store::now_ms())
        .await?;
    let claimed = claimed.into_iter().next().ok_or_else(|| {
        repo_scan::Error::Store(String::from("fenced probe hook: claim returned no task"))
    })?;
    if let Some(swap) = before_exec {
        swap();
    }
    // The sequential test driver runs the production prepare/worker/finish
    // path inline; the status mode only matters for status tasks.
    let outcome = execute_task(
        &mut runner,
        store,
        generation,
        run_rev,
        canonical,
        StatusMode::default(),
        &claimed,
        &deadline,
    )
    .await?;
    // Production flushes the writer batch before completing the task; the
    // hook does the same so "persists nothing" assertions are airtight.
    flush_runner_batch(&mut runner, store).await?;
    Ok(outcome)
}

/// Execute one enumeration task whose lease a rival reclaimed between
/// claim and execution (R4 pre-persist gate proof): the collection runs
/// against the stale claim, the gate finds the lease gone, and the scope
/// retries with a fresh lease having persisted nothing. The rival path
/// mirrors production expiry + reclaim (same-owner second claim, new
/// token), so `fail_task` sees a live leased row, not a terminal one.
#[cfg(test)]
pub async fn test_enumerate_stale_outcome(
    store: &TursoStore,
    fence_roots: &[PathBuf],
    generation: u64,
    scope_path: &Path,
) -> repo_scan::Result<TaskOutcome> {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    runner.fence = Some(ScopeFence::build(fence_roots));
    let scope_key = config::scope_key_for_dir(scope_path);
    let id = enum_task_id_for_path(generation, scope_path);
    let expected_rev = store.scope_rev(&scope_key).await?;
    let idempotency = format!("idem:{id}");
    let task = NewTask {
        id: &id,
        kind: KIND_ENUM,
        generation,
        dir_id: None,
        scope_key: &scope_key,
        expected_rev,
        idempotency_key: &idempotency,
    };
    store.enqueue_task(&task, store::now_ms()).await?;
    let epoch = store.epoch();
    let claimed = store
        .claim_tasks(epoch, 16, LEASE_TTL_MS, store::now_ms())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            repo_scan::Error::Store(String::from("stale enum hook: claim returned no task"))
        })?;
    // Rival reclaim: expire past the 60 s TTL, claim again (new token).
    store.expire_leases(store::now_ms() + 61_000).await?;
    let rival = store
        .claim_tasks(epoch, 16, LEASE_TTL_MS, store::now_ms())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            repo_scan::Error::Store(String::from("stale enum hook: rival claim found no task"))
        })?;
    assert_ne!(
        rival.token, claimed.token,
        "rival reclaim must mint a new token"
    );
    let deadline = OpDeadline::new(Duration::from_secs(OP_DEADLINE_SECS));
    // The sequential test driver runs the production prepare/worker/finish
    // path inline; run_rev/canonical only matter for probe tasks.
    let outcome = execute_task(
        &mut runner,
        store,
        generation,
        0,
        "test",
        StatusMode::default(),
        &claimed,
        &deadline,
    )
    .await?;
    flush_runner_batch(&mut runner, store).await?;
    Ok(outcome)
}

/// Git reads for one probe, collected with DURING-inspection identity
/// polls (XSEC-01) and deadline checks (SR-STATE-01) between stages.
/// Buffers nothing: on `IdentityChanged`/`TimedOut` the caller parks and
/// every in-memory observation drops, so a swapped identity can never
/// reach the catalog — not even through an early batch flush.
struct ProbeReads {
    incarnation: String,
    /// Physical identity of the COMMON dir: all worktree admin dirs of one
    /// store share it, so repeats attach instead of duplicating the store.
    common_identity: Option<(u64, u64)>,
    remotes: Vec<git::RemoteObservation>,
    remotes_note: Option<String>,
    // Discovery-only reads: identity, paths, remotes, worktrees.
    // Branch/HEAD analysis (refs, upstreams, HEAD) moved to the
    // post-`inventory_ready` analyze task (F2).
    relationship: &'static str,
    work_present: Option<bool>,
    worktrees: Vec<git::WorktreeObservation>,
    config_dep_count: usize,
}

/// Outcome of [`collect_probe_reads`]: full reads, or an abandon signal.
/// `IdentityChanged`/`TimedOut` mean "park, persist nothing". (Lease
/// liveness is the coordinator's job now — the scheduled tick renews
/// in-flight leases and the pre-persist gate discards stale results —
/// so there is no worker-side `LeaseLost` anymore.)
enum CollectOutcome {
    Reads(Box<ProbeReads>),
    IdentityChanged,
    TimedOut,
}

/// Worker-side result of one probe task (Step 8 worker seam): every
/// terminal mid-read condition as data, like [`StatusCollected`]. The
/// fence verify, open, and validate run on the pool thread; the single
/// writer applies rows/gaps/retries via [`finish_probe`].
enum ProbeCollected {
    Refused {
        state: TaskState,
        reason: String,
    },
    StatFailed(std::io::Error),
    TimeoutBeforeReads,
    ValidateFailed {
        detail: String,
        unsupported: bool,
    },
    Collected {
        validated: git::ValidatedCandidate,
        outcome: CollectOutcome,
    },
}

impl ProbeCollected {
    /// Observations produced, for the watchdog's per-task advancement
    /// verdict (parallel tasks share the global counters, so the drain
    /// cannot infer per-task progress from them).
    fn progress_units(&self) -> u64 {
        match self {
            ProbeCollected::Collected {
                outcome: CollectOutcome::Reads(_),
                ..
            } => 1,
            _ => 0,
        }
    }
}

/// Worker-side probe execution: schedule parse, fence verify, validate,
/// identity-poll envelope, and [`collect_probe_reads`]. Synchronous —
/// runs on a pool thread with worker-owned inputs only. The pre-run
/// lease renewal stays on the coordinator ([`prepare_probe`]); the
/// pre-persist gate stays on the coordinator ([`finish_probe`]).
fn run_probe_job(
    ctx: &ReadContext,
    task_id: &str,
    path: &Path,
    deadline: &OpDeadline,
) -> repo_scan::Result<ProbeCollected> {
    // Probe fence (pre-run, PG-01): verify the scheduled path against the
    // schedule-time identity carried in the task id — a swapped pin or an
    // unprovenanced out-of-scope spelling refuses before Git runs.
    // Explicitly scheduled out-of-scope relationship paths proceed on
    // their own descriptor pin (spec §8); refusals park with a preserved
    // gap and persist nothing.
    let schedule = parse_probe_schedule(task_id).unwrap_or(ProbeSchedule::legacy_enum());
    let pinned: Option<PinnedDir> =
        match verify_probe_path(ctx.fence.as_ref(), "probe", path, &schedule) {
            ProbeFence::Unfenced => None,
            ProbeFence::Pinned(pinned) | ProbeFence::Relationship(pinned) => Some(pinned),
            ProbeFence::Refused { state, reason } => {
                return Ok(ProbeCollected::Refused { state, reason });
            }
            ProbeFence::StatFailed(e) => return Ok(ProbeCollected::StatFailed(e)),
        };
    // SR-STATE-01: abandon before the first Git read when the budget is
    // already gone.
    if deadline.expired() {
        return Ok(ProbeCollected::TimeoutBeforeReads);
    }
    // The pin binds the execution (XSEC-01): Git runs between the
    // pre-run pin above and the DURING/post-run re-verification below, so a
    // path swapped mid-run discards every observation. Inspection keeps
    // the scheduling spelling, so persisted rows stay spelling-stable.
    let validated = match ctx.inspector.validate(path) {
        Ok(validated) => validated,
        Err(e) => {
            return Ok(ProbeCollected::ValidateFailed {
                detail: e.to_string(),
                unsupported: git::is_unsupported_error(&e),
            });
        }
    };
    // Probe fence (DURING + post-run, XSEC-01): re-verify after validate,
    // between every Git read stage in `collect_probe_reads`, and before
    // the first buffered write. A path swapped mid-run discards every
    // observation — nothing reaches the batch — and parks the scope
    // instead of persisting foreign rows. Relationship pins re-verify
    // through the unscoped descriptor walk.
    let mut poll = IdentityPoll::new(ctx.fence.as_ref(), path, pinned.as_ref());
    if !poll.ok_now() {
        return Ok(ProbeCollected::Collected {
            validated,
            outcome: CollectOutcome::IdentityChanged,
        });
    }
    let outcome = collect_probe_reads(ctx, &validated.instance, path, &mut poll, deadline)?;
    // Pre-store gate, worker side: the collection ends with a final
    // unthrottled poll, so no second coordinator poll is needed — no Git
    // read runs between the collection return and the persist gate.
    Ok(ProbeCollected::Collected { validated, outcome })
}

// One-shot mid-inspection swap hook for the XSEC-01 regression test:
// consumed between Git read stages (after remotes, before the poll), so
// the test swaps the inspected directory mid-collection — the production
// inspect-time race in miniature. Production builds have no hook. The slot
// is process-global (not thread-local) so the hook fires no matter which
// worker thread runs the collection, and it fires only for the armed path
// spelling so concurrent scans in other tests never trip it.
#[cfg(test)]
type MidInspectionSlot = Mutex<Option<(PathBuf, Box<dyn FnOnce() + Send>)>>;

#[cfg(test)]
static MID_INSPECTION_HOOK: OnceLock<MidInspectionSlot> = OnceLock::new();

#[cfg(test)]
fn mid_inspection_slot() -> &'static MidInspectionSlot {
    MID_INSPECTION_HOOK.get_or_init(|| Mutex::new(None))
}

/// Arm the one-shot mid-inspection hook, consumed by the next
/// [`collect_probe_reads`] of `path` between read stages.
#[cfg(test)]
pub fn test_set_mid_inspection_hook(path: &Path, hook: impl FnOnce() + Send + 'static) {
    *mid_inspection_slot().lock().unwrap() = Some((path.to_path_buf(), Box::new(hook)));
}

/// Fire the armed hook when this collection inspects the armed path. The
/// lock is released before the hook runs, so a panicking hook cannot
/// poison the slot.
#[cfg(test)]
fn fire_mid_inspection_hook(path: &Path) {
    let hook = {
        let mut slot = mid_inspection_slot().lock().unwrap();
        match slot.as_ref() {
            Some((armed, _)) if armed == path => slot.take().map(|(_, hook)| hook),
            _ => None,
        }
    };
    if let Some(hook) = hook {
        hook();
    }
}

/// Synchronous Git read worker: runs on a pool thread with no store
/// handle. Lease freshness comes from the coordinator's scheduled tick;
/// if the lease is gone by finish time, the pre-persist gate discards
/// these reads and the task retries with a fresh lease.
#[allow(clippy::too_many_arguments)]
fn collect_probe_reads(
    ctx: &ReadContext,
    instance: &git::GitInstance,
    path: &Path,
    poll: &mut IdentityPoll,
    deadline: &OpDeadline,
) -> repo_scan::Result<CollectOutcome> {
    if deadline.expired() {
        return Ok(CollectOutcome::TimedOut);
    }
    let incarnation = std::fs::symlink_metadata(&instance.common_dir)
        .map(|md| {
            let (dev, ino) = dir_identity(&md);
            format!("d{dev}i{ino}")
        })
        .unwrap_or_default();
    let common_identity = std::fs::metadata(&instance.common_dir)
        .ok()
        .map(|md| dir_identity(&md))
        .filter(|key| *key != (0, 0));
    let config_dep_count = ctx.inspector.config_dependencies(instance).len();
    let mut remotes_note = None;
    let remotes = match ctx.inspector.remotes(instance) {
        Ok(remotes) => remotes,
        Err(e) if git::is_unsupported_error(&e) => {
            remotes_note = Some(format!("remotes unsupported, treated as no remotes: {e}"));
            Vec::new()
        }
        Err(e) => {
            return Err(repo_scan::Error::Git(format!(
                "remotes unreadable for {}: {e}",
                path.display()
            )));
        }
    };
    #[cfg(test)]
    fire_mid_inspection_hook(path);
    if !poll.ok_now() {
        return Ok(CollectOutcome::IdentityChanged);
    }
    // R4 heartbeat point retired: the coordinator's scheduled tick owns
    // lease renewal now; the pre-persist gate retries on a lost lease.
    if deadline.expired() {
        return Ok(CollectOutcome::TimedOut);
    }
    // F2: HEAD/refs reads moved to the post-`inventory_ready` analyze
    // task; discovery probes keep only identity/relationship reads.
    let relationship = match ctx.inspector.checkout_kind(instance) {
        Ok(git::CheckoutKind::Main) => "main",
        Ok(git::CheckoutKind::Linked) => "linked",
        Ok(git::CheckoutKind::Submodule) => "submodule",
        Ok(git::CheckoutKind::Unknown) | Err(_) => "unknown",
    };
    if !poll.ok_throttled() {
        return Ok(CollectOutcome::IdentityChanged);
    }
    let work_present = instance.work_dir.as_ref().map(|root| root.exists());
    let worktrees = ctx.inspector.worktrees(instance).unwrap_or_default();
    if !poll.ok_throttled() {
        return Ok(CollectOutcome::IdentityChanged);
    }
    if deadline.expired() {
        return Ok(CollectOutcome::TimedOut);
    }
    // Final unthrottled identity check: after the hook and every fast
    // local stage, confirm the directory is still the lease's target.
    if !poll.ok_now() {
        return Ok(CollectOutcome::IdentityChanged);
    }
    Ok(CollectOutcome::Reads(Box::new(ProbeReads {
        incarnation,
        common_identity,
        remotes,
        remotes_note,
        relationship,
        work_present,
        worktrees,
        config_dep_count,
    })))
}

/// Identity summary for found-event payloads (D4: identity or
/// `unknown`): the first normalized canonical remote URL, else explicit
/// unknown. Remote URLs arrive pre-redacted from the probe reads.
fn found_identity(remotes: &[git::RemoteObservation]) -> (Option<&str>, &'static str) {
    match remotes.iter().find_map(|r| r.canonical_url.as_deref()) {
        Some(canonical) => (Some(canonical), "known"),
        None => (None, "unknown"),
    }
}

/// Split a normalized GitHub canonical URL into the D1 group id
/// `host/account/repo` plus its parts. The normalizer
/// ([`identity::normalize_github_url`]) always emits lowercase
/// `https://github.com/owner/repo`, so the group id is the URL tail and
/// needs no further lowering; `None` only fires on input no normalizer
/// produced (defensive: probe `canonical_url` values always are).
fn github_group_parts(canonical: &str) -> Option<(&str, &str, &str, &str)> {
    let id = canonical.strip_prefix("https://")?;
    let mut parts = id.split('/');
    let (host, account, repo) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || host.is_empty() || account.is_empty() || repo.is_empty() {
        return None;
    }
    Some((id, host, account, repo))
}

/// `repository_found` records (D4): store id + the remote evidence the
/// GitHub group association derives from + the derived `github_groups`
/// ids (sorted, deduped; the matching group/member rows land in the same
/// batch transaction) + `analysis: "pending"`.
fn repository_found_records(
    store_id: &str,
    remotes: &[git::RemoteObservation],
) -> repo_scan::Result<Vec<u8>> {
    let (identity, identity_state) = found_identity(remotes);
    let mut github_groups: Vec<&str> = remotes
        .iter()
        .filter_map(|r| {
            r.canonical_url
                .as_deref()
                .and_then(github_group_parts)
                .map(|(id, _, _, _)| id)
        })
        .collect();
    github_groups.sort_unstable();
    github_groups.dedup();
    let records = serde_json::json!({
        "store_id": store_id,
        "identity": identity,
        "identity_state": identity_state,
        "remotes": remotes.iter().map(|r| serde_json::json!({
            "name": String::from_utf8_lossy(&r.name),
            "role": match r.role {
                git::RemoteRole::Fetch => "fetch",
                git::RemoteRole::Push => "push",
            },
            "url": r.url,
            "canonical_url": r.canonical_url,
        })).collect::<Vec<_>>(),
        "github_groups": github_groups,
        "analysis": "pending",
    });
    serde_json::to_vec(&records).map_err(|e| repo_scan::Error::Report(e.to_string()))
}

/// `location_found` records (D4): checkout/store ids, observed path
/// (lossy display + exact hex), identity or `unknown`, and
/// `analysis: "pending"`. Alias deltas arrive via `location_updated`.
fn location_found_records(
    checkout_id: &str,
    store_id: &str,
    path: &[u8],
    git_path: &[u8],
    remotes: &[git::RemoteObservation],
) -> repo_scan::Result<Vec<u8>> {
    let (identity, identity_state) = found_identity(remotes);
    let records = serde_json::json!({
        "checkout_id": checkout_id,
        "store_id": store_id,
        "path": String::from_utf8_lossy(path),
        "path_hex": config::encode_hex(path),
        "git_path": String::from_utf8_lossy(git_path),
        "git_path_hex": config::encode_hex(git_path),
        "identity": identity,
        "identity_state": identity_state,
        "analysis": "pending",
    });
    serde_json::to_vec(&records).map_err(|e| repo_scan::Error::Report(e.to_string()))
}

/// Maximum branch records per `branch_batch` event (Step 12: bounded
/// batches — a store with thousands of refs journals several events).
const BRANCH_BATCH_CHUNK: usize = 500;

/// One branch record inside a `branch_batch` payload. Byte-exact fields
/// pair lossy text with hex; oids are hex ASCII already.
#[allow(clippy::too_many_arguments)]
fn branch_record_value(
    id: &str,
    kind: &str,
    name: &[u8],
    oid: Option<&[u8]>,
    algo: Option<&str>,
    symbolic_target: Option<&[u8]>,
    upstream: Option<&[u8]>,
    state: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "kind": kind,
        "name": String::from_utf8_lossy(name),
        "name_hex": config::encode_hex(name),
        "oid": oid.map(|o| String::from_utf8_lossy(o).into_owned()),
        "algo": algo,
        "symbolic_target": symbolic_target.map(|t| String::from_utf8_lossy(t).into_owned()),
        "symbolic_target_hex": symbolic_target.map(config::encode_hex),
        "upstream": upstream.map(|u| String::from_utf8_lossy(u).into_owned()),
        "upstream_hex": upstream.map(config::encode_hex),
        "state": state,
    })
}

/// `branch_batch` records (D4): store id, the observation `rev`
/// (`observed_at_ms`, orders re-sends), chunk position, and the branch
/// records.
fn branch_batch_records(
    store_id: &str,
    rev: i64,
    batch_index: usize,
    batch_count: usize,
    branches: &[serde_json::Value],
) -> repo_scan::Result<Vec<u8>> {
    let records = serde_json::json!({
        "store_id": store_id,
        "rev": rev,
        "batch_index": batch_index,
        "batch_count": batch_count,
        "branches": branches,
    });
    serde_json::to_vec(&records).map_err(|e| repo_scan::Error::Report(e.to_string()))
}

/// Buffer a `branch_batch` chunk (same journaling contract as
/// [`journal_repository_found`]).
async fn journal_branch_batch(
    runner: &mut Runner,
    store: &TursoStore,
    store_id: &str,
    records: &[u8],
) -> repo_scan::Result<()> {
    let Some(journal) = runner.journal.as_mut() else {
        return Ok(());
    };
    if let Some(due) = journal.buffer_branch_batch(&mut runner.batch, store_id, records)? {
        flush_if_due(runner, store, due).await?;
    }
    Ok(())
}

/// Buffer a `repository_found` when this runner journals (production
/// scans); unit-test runners (`journal: None`) persist without journaling.
async fn journal_repository_found(
    runner: &mut Runner,
    store: &TursoStore,
    store_id: &str,
    remotes: &[git::RemoteObservation],
) -> repo_scan::Result<()> {
    let Some(journal) = runner.journal.as_mut() else {
        return Ok(());
    };
    let records = repository_found_records(store_id, remotes)?;
    if let Some(due) = journal.buffer_repository_found(&mut runner.batch, store_id, &records)? {
        flush_if_due(runner, store, due).await?;
    }
    Ok(())
}

/// Buffer a `location_found` (same journaling contract as
/// [`journal_repository_found`]).
async fn journal_location_found(
    runner: &mut Runner,
    store: &TursoStore,
    checkout_id: &str,
    store_id: &str,
    path: &[u8],
    git_path: &[u8],
    remotes: &[git::RemoteObservation],
) -> repo_scan::Result<()> {
    let Some(journal) = runner.journal.as_mut() else {
        return Ok(());
    };
    let records = location_found_records(checkout_id, store_id, path, git_path, remotes)?;
    if let Some(due) = journal.buffer_location_found(&mut runner.batch, checkout_id, &records)? {
        flush_if_due(runner, store, due).await?;
    }
    Ok(())
}

/// `location_updated` records (D4): checkout/store ids, the status
/// observation that caused this update (state + mode + counts, unknown
/// counts stay null), and the observation `rev` consumers replay against.
/// No `analysis` claim: branch comparison is not implemented yet, so only
/// the observed status facts are stated.
#[allow(clippy::too_many_arguments)]
fn location_updated_records(
    checkout_id: &str,
    store_id: &str,
    mode: &str,
    state: &str,
    staged: Option<i64>,
    unstaged: Option<i64>,
    untracked: Option<i64>,
    observed_rev: u64,
) -> repo_scan::Result<Vec<u8>> {
    let records = serde_json::json!({
        "checkout_id": checkout_id,
        "store_id": store_id,
        "rev": observed_rev,
        "status_state": state,
        "mode": mode,
        "staged": staged,
        "unstaged": unstaged,
        "untracked": untracked,
    });
    serde_json::to_vec(&records).map_err(|e| repo_scan::Error::Report(e.to_string()))
}

/// Buffer a `location_updated` (same journaling contract as
/// [`journal_repository_found`]).
#[allow(clippy::too_many_arguments)]
async fn journal_location_updated(
    runner: &mut Runner,
    store: &TursoStore,
    checkout_id: &str,
    store_id: &str,
    mode: &str,
    state: &str,
    staged: Option<i64>,
    unstaged: Option<i64>,
    untracked: Option<i64>,
    observed_rev: u64,
) -> repo_scan::Result<()> {
    let Some(journal) = runner.journal.as_mut() else {
        return Ok(());
    };
    let records = location_updated_records(
        checkout_id,
        store_id,
        mode,
        state,
        staged,
        unstaged,
        untracked,
        observed_rev,
    )?;
    if let Some(due) = journal.buffer_location_updated(&mut runner.batch, &records)? {
        flush_if_due(runner, store, due).await?;
    }
    Ok(())
}

/// Persist collected observations from a validated probe. Remotes, refs, and
/// HEAD fall back to installed git only on structural gaps; operational
/// failures fail the task (retry, then park) instead of recording fake
/// unknowns. All Git reads happened in [`collect_probe_reads`] under
/// DURING-inspection polls — this phase only buffers rows and schedules
/// follow-up tasks, so a swap can no longer interleave reads with writes.
#[allow(clippy::too_many_arguments)]
async fn persist_probe(
    runner: &mut Runner,
    store: &TursoStore,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    path: &Path,
    validated: &git::ValidatedCandidate,
    reads: ProbeReads,
    now_ms: i64,
) -> repo_scan::Result<()> {
    let instance = &validated.instance;
    let git_bytes = config::path_as_bytes(&instance.git_dir);
    // Local-store identity (goal Step 5): the canonical COMMON dir. Linked
    // worktree admin dirs resolve to their shared store, and distinct
    // spellings of one directory merge — instance, remote, and ref IDs all
    // key on this. The stored PATH columns keep observed spellings (goal
    // Step 7: every spelling stays visible; second spellings add alias
    // rows), so only ID derivation uses the canonical form. Non-absolute
    // paths (should not happen: probe inputs are absolute) skip
    // canonicalization rather than resolving against the process working
    // directory.
    let canonical_common = if instance.common_dir.is_absolute() {
        std::fs::canonicalize(&instance.common_dir).unwrap_or_else(|_| instance.common_dir.clone())
    } else {
        instance.common_dir.clone()
    };
    let common_bytes = config::path_as_bytes(&canonical_common);
    let raw_common_bytes = config::path_as_bytes(&instance.common_dir);
    let instance_id = format!("git:{}", config::encode_hex(&common_bytes));
    let incarnation = reads.incarnation;

    // A repeat probe of an already-persisted STORE (same common dir: a
    // second spelling, or a linked-worktree admin dir) attaches its
    // checkout instead of duplicating the instance (R7 + goal Step 5).
    // Identity follows symlinks; the `(0, 0)` fallback (non-unix) never
    // dedupes. Shared refs/remotes persist once, on first sight.
    if let Some(key) = reads.common_identity {
        match runner.probed_git_ids.get(&key).cloned() {
            Some(first) if first != git_bytes => {
                // Same-directory spellings record a path alias; a worktree
                // admin dir is a DIFFERENT directory sharing the store, so
                // it attaches without an alias row (its admin path is
                // preserved on its checkout row).
                let same_dir = if instance.git_dir.is_absolute() {
                    std::fs::canonicalize(&instance.git_dir).ok() == Some(canonical_common.clone())
                } else {
                    instance.git_dir == instance.common_dir
                };
                if same_dir {
                    let due = runner.note_alias(
                        git_bytes.clone(),
                        first.clone(),
                        "same_object",
                        now_ms,
                    )?;
                    flush_if_due(runner, store, due).await?;
                }
                let work_identity = instance
                    .work_dir
                    .as_ref()
                    .and_then(|p| std::fs::metadata(p).ok())
                    .map(|md| dir_identity(&md))
                    .filter(|k| *k != (0, 0));
                let is_distinct_checkout = match work_identity {
                    Some(wid) => {
                        if runner.probed_work_ids.contains(&wid) {
                            false
                        } else {
                            if runner.probed_work_ids.len() < MAX_PROBED_GIT_IDS {
                                runner.probed_work_ids.insert(wid);
                            }
                            true
                        }
                    }
                    None => false,
                };
                if !is_distinct_checkout {
                    return Ok(());
                }
                let first_instance_id = format!("git:{}", config::encode_hex(&first));
                // Discovery records checkout presence only; HEAD resolves in
                // the Analysis phase (analyze task, post-`inventory_ready`).
                let (head_state, head_ref, head_oid, head_algo): HeadColumns =
                    ("unknown", None, None, None);
                let relationship = reads.relationship;
                let checkout_hex = config::encode_hex(&git_bytes);
                let main_checkout_id = format!("co:{checkout_hex}");
                let root_bytes = instance.work_dir.as_ref().map(|p| config::path_as_bytes(p));
                let availability = match reads.work_present {
                    Some(false) => "missing",
                    Some(true) | None => "present",
                };
                let main_checkout = NewCheckout {
                    id: &main_checkout_id,
                    instance_id: &first_instance_id,
                    root_path: root_bytes.as_deref(),
                    git_path: &git_bytes,
                    relationship,
                    availability,
                    head_state,
                    head_ref: head_ref.as_deref(),
                    head_oid: head_oid.as_deref(),
                    head_algo: head_algo.as_deref(),
                };
                let due = if root_bytes.is_none() {
                    TursoStore::buffer_insert_checkout_if_absent(
                        &mut runner.batch,
                        &main_checkout,
                        now_ms,
                    )
                } else {
                    TursoStore::buffer_upsert_checkout(&mut runner.batch, &main_checkout, now_ms)
                };
                flush_if_due(runner, store, due).await?;

                let pairs: Vec<(String, String)> = reads
                    .remotes
                    .iter()
                    .map(|r| {
                        let role = match r.role {
                            git::RemoteRole::Fetch => "fetch",
                            git::RemoteRole::Push => "push",
                        };
                        (r.url.clone(), role.to_string())
                    })
                    .collect();
                let borrowed: Vec<(&str, &str)> = pairs
                    .iter()
                    .map(|(url, role)| (url.as_str(), role.as_str()))
                    .collect();
                let is_target_repo = if identity::is_local_target(canonical) {
                    let target_path_str = canonical.strip_prefix("file://").unwrap_or(canonical);
                    let t_canon = std::fs::canonicalize(target_path_str)
                        .unwrap_or_else(|_| PathBuf::from(target_path_str));
                    let path_canon =
                        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
                    path_canon == t_canon
                        || instance
                            .work_dir
                            .as_ref()
                            .and_then(|p| std::fs::canonicalize(p).ok())
                            == Some(t_canon.clone())
                        || std::fs::canonicalize(&instance.git_dir).ok() == Some(t_canon.clone())
                        || std::fs::canonicalize(&instance.common_dir).ok() == Some(t_canon)
                } else {
                    false
                };
                let (disposition, _) = if is_target_repo {
                    (identity::MatchDisposition::Confirmed, vec![])
                } else {
                    identity::classify_remotes(canonical, borrowed)
                };
                // The store is already known (first sight journaled it);
                // this spelling only adds its checkout location.
                journal_location_found(
                    runner,
                    store,
                    &main_checkout_id,
                    &first_instance_id,
                    root_bytes.as_deref().unwrap_or(git_bytes.as_slice()),
                    &git_bytes,
                    &reads.remotes,
                )
                .await?;

                if matches!(
                    disposition,
                    identity::MatchDisposition::Confirmed
                        | identity::MatchDisposition::Related
                        | identity::MatchDisposition::Probable
                ) {
                    enqueue_status_task(
                        store,
                        runner,
                        generation,
                        run_rev,
                        &main_checkout_id,
                        now_ms,
                    )
                    .await?;
                }
                return Ok(());
            }
            Some(_) => {}
            None => {
                let due = note_probed_git_id(runner, key, common_bytes.clone(), now_ms)?;
                flush_if_due(runner, store, due).await?;
            }
        }
    }

    let mut evidence = validated.evidence.clone();
    evidence.push(format!("matching-policy: {}", identity::MATCHING_POLICY));
    evidence.push(format!(
        "config files consulted: {}",
        reads.config_dep_count
    ));

    let remotes = reads.remotes;
    if let Some(note) = reads.remotes_note {
        evidence.push(note);
    }
    let pairs: Vec<(String, String)> = remotes
        .iter()
        .map(|r| {
            let role = match r.role {
                git::RemoteRole::Fetch => "fetch",
                git::RemoteRole::Push => "push",
            };
            (r.url.clone(), role.to_string())
        })
        .collect();
    let borrowed: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(url, role)| (url.as_str(), role.as_str()))
        .collect();
    let is_target_repo = if identity::is_local_target(canonical) {
        let target_path_str = canonical.strip_prefix("file://").unwrap_or(canonical);
        let t_canon = std::fs::canonicalize(target_path_str)
            .unwrap_or_else(|_| PathBuf::from(target_path_str));
        let path_canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        path_canon == t_canon
            || instance
                .work_dir
                .as_ref()
                .and_then(|p| std::fs::canonicalize(p).ok())
                == Some(t_canon.clone())
            || std::fs::canonicalize(&instance.git_dir).ok() == Some(t_canon.clone())
            || std::fs::canonicalize(&instance.common_dir).ok() == Some(t_canon)
    } else {
        false
    };
    let (disposition, mut match_evidence) = if is_target_repo {
        (
            identity::MatchDisposition::Confirmed,
            vec![format!(
                "Repository at {} matches the requested local target repository ({}).",
                path.display(),
                canonical
            )],
        )
    } else {
        identity::classify_remotes(canonical, borrowed)
    };
    evidence.append(&mut match_evidence);
    let evidence_json =
        serde_json::to_string(&evidence).map_err(|e| repo_scan::Error::Report(e.to_string()))?;
    // RSF-AC461500-609D-4D55-991E-09C60D382D67: every probe write
    // buffers; the task-end flush commits them before completion.
    let new_instance = NewGitInstance {
        id: &instance_id,
        git_path: &git_bytes,
        common_path: &raw_common_bytes,
        incarnation: &incarnation,
        format: "git-files",
        bare: Some(instance.is_bare),
        object_format: &instance.object_format,
        disposition: disposition_str(disposition),
        evidence_json: &evidence_json,
    };
    let due = TursoStore::buffer_upsert_git_instance(&mut runner.batch, &new_instance, now_ms);
    runner.counters.repos_found += 1;
    flush_if_due(runner, store, due).await?;
    journal_repository_found(runner, store, &instance_id, &remotes).await?;
    // Unresolvable-identity candidates join the coverage delta stream in
    // the same batch as the instance row. Repeat probes return early, so
    // re-persist dupes are rare; consumers dedupe by id. (Report-time
    // reclassification can flip dispositions later; those flips surface
    // in the final report, not as live deltas.)
    if matches!(
        disposition,
        identity::MatchDisposition::UnresolvableIdentity
    ) {
        journal_coverage_updated(runner, store, &[], &[], std::slice::from_ref(&instance_id))
            .await?;
    }
    for remote in &remotes {
        let role = match remote.role {
            git::RemoteRole::Fetch => "fetch",
            git::RemoteRole::Push => "push",
        };
        let remote_id = format!(
            "remote:{}:{}:{role}",
            config::encode_hex(&common_bytes),
            config::encode_hex(&remote.name),
        );
        let canonical_bytes = remote.canonical_url.as_ref().map(|c| c.as_bytes());
        let new_remote = NewRemote {
            id: &remote_id,
            instance_id: &instance_id,
            checkout_scope_id: None,
            name: &remote.name,
            role,
            url: remote.url.as_bytes(),
            canonical_url: canonical_bytes,
        };
        let due = TursoStore::buffer_upsert_remote(&mut runner.batch, &new_remote, now_ms);
        flush_if_due(runner, store, due).await?;
        // D1/D5: every normalized remote observation links its store to one
        // GitHub group (same batch transaction as the remote row, so the
        // `repository_found.github_groups` ids above always resolve once
        // committed). Distinct canonicals stay distinct groups — a fork and
        // its upstream never merge — while URL spellings of one identity
        // share one group row (`INSERT OR IGNORE` keeps resume replays
        // idempotent).
        if let Some((group_id, host, account, repo)) =
            remote.canonical_url.as_deref().and_then(github_group_parts)
        {
            let due_group = TursoStore::buffer_upsert_github_group(
                &mut runner.batch,
                group_id,
                host,
                account,
                repo,
                now_ms,
            );
            let due_member = TursoStore::buffer_add_group_member(
                &mut runner.batch,
                group_id,
                &instance_id,
                &remote.name,
                role,
                now_ms,
            );
            flush_if_due(runner, store, due_group || due_member).await?;
        }
    }

    // Discovery records checkout presence only; HEAD resolves in the
    // Analysis phase (analyze task, post-`inventory_ready`).
    let (head_state, head_ref, head_oid, head_algo): HeadColumns = ("unknown", None, None, None);
    let relationship = reads.relationship;
    let checkout_hex = config::encode_hex(&git_bytes);
    let main_checkout_id = format!("co:{checkout_hex}");
    let root_bytes = instance.work_dir.as_ref().map(|p| config::path_as_bytes(p));
    let availability = match reads.work_present {
        Some(false) => "missing",
        Some(true) | None => "present",
    };
    let main_checkout = NewCheckout {
        id: &main_checkout_id,
        instance_id: &instance_id,
        root_path: root_bytes.as_deref(),
        git_path: &git_bytes,
        relationship,
        availability,
        head_state,
        head_ref: head_ref.as_deref(),
        head_oid: head_oid.as_deref(),
        head_algo: head_algo.as_deref(),
    };
    // A worktree-less angle on an instance (bare-dir probe of a git dir
    // that a pointer probe links to a worktree) must not erase the rooted
    // row: insert only when absent, independent of probe order.
    let due = if root_bytes.is_none() {
        TursoStore::buffer_insert_checkout_if_absent(&mut runner.batch, &main_checkout, now_ms)
    } else {
        TursoStore::buffer_upsert_checkout(&mut runner.batch, &main_checkout, now_ms)
    };
    flush_if_due(runner, store, due).await?;
    journal_location_found(
        runner,
        store,
        &main_checkout_id,
        &instance_id,
        root_bytes.as_deref().unwrap_or(git_bytes.as_slice()),
        &git_bytes,
        &remotes,
    )
    .await?;
    if let Some(wid) = instance
        .work_dir
        .as_ref()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|md| dir_identity(&md))
        .filter(|k| *k != (0, 0))
    {
        if runner.probed_work_ids.len() < MAX_PROBED_GIT_IDS {
            runner.probed_work_ids.insert(wid);
        }
    }

    // Registered linked worktrees: own checkout rows plus explicit probes
    // for bases outside already discovered paths.
    let mut checkout_ids = vec![main_checkout_id];
    // Worktrees were read + polled in `collect_probe_reads` (a read error
    // there maps to no worktrees, as before); only non-empty lists loop.
    if !reads.worktrees.is_empty() {
        for wt in &reads.worktrees {
            // Never list an instance as its own linked worktree: opening a
            // linked-worktree git dir reports the shared registry, which
            // includes this very checkout.
            if instance.work_dir.as_ref() == Some(&wt.base) {
                continue;
            }
            // A present worktree is probed directly below, which persists
            // the real checkout row; only absent/broken registrations need
            // a placeholder row of their own.
            let placeholder = !matches!(wt.availability, git::WorktreeAvailability::Present);
            let wt_id = format!(
                "co:{checkout_hex}:wt:{}",
                config::encode_hex(wt.id.as_bytes())
            );
            let wt_availability = match wt.availability {
                git::WorktreeAvailability::Present => "present",
                git::WorktreeAvailability::Missing => "missing",
                git::WorktreeAvailability::Inaccessible => "inaccessible",
                git::WorktreeAvailability::Broken | git::WorktreeAvailability::Unknown => "unknown",
            };
            let wt_git = config::path_as_bytes(&instance.common_dir.join("worktrees").join(&wt.id));
            let wt_root = config::path_as_bytes(&wt.base);
            if placeholder {
                let wt_checkout = NewCheckout {
                    id: &wt_id,
                    instance_id: &instance_id,
                    root_path: Some(&wt_root),
                    git_path: &wt_git,
                    relationship: "linked",
                    availability: wt_availability,
                    head_state: "unknown",
                    head_ref: None,
                    head_oid: None,
                    head_algo: None,
                };
                let due =
                    TursoStore::buffer_upsert_checkout(&mut runner.batch, &wt_checkout, now_ms);
                flush_if_due(runner, store, due).await?;
                journal_location_found(
                    runner,
                    store,
                    &wt_id,
                    &instance_id,
                    &wt_root,
                    &wt_git,
                    &remotes,
                )
                .await?;
                checkout_ids.push(wt_id);
            }
            enqueue_probe_task_for_path(store, runner, generation, &wt.base, now_ms).await?;
        }
    }

    // Branch/HEAD analysis runs post-boundary (F2): the analyze task reads
    // refs, upstreams, and per-checkout HEAD after `inventory_ready`; its
    // claim gate holds it out of the discovery drain.
    enqueue_analysis_task(
        store,
        runner,
        generation,
        run_rev,
        &instance_id,
        &instance.common_dir,
        now_ms,
    )
    .await?;

    // Detailed working state only for matching candidates (spec §9).
    if matches!(
        disposition,
        identity::MatchDisposition::Confirmed
            | identity::MatchDisposition::Related
            | identity::MatchDisposition::Probable
    ) {
        for checkout_id in &checkout_ids {
            enqueue_status_task(store, runner, generation, run_rev, checkout_id, now_ms).await?;
        }
    }
    Ok(())
}

/// Upstream (full local comparison ref) per local branch (R16, Step 10):
/// `[branch "X"]` with `remote = R` and `merge = M` resolves through the
/// remote's actual fetch refspecs to the full ref git's `@{upstream}`
/// names (e.g. `refs/remotes/origin/main`, or `refs/custom/main` under a
/// custom fetch refspec) — never a fabricated `remote/leaf` guess.
///
/// Effective config = `common_dir/config` with `include`/`includeIf`
/// chains expanded inline (bounded depth, cycle-safe, byte-capped),
/// overlaid per checkout by that checkout's own `config.worktree` when
/// the effective `extensions.worktreeConfig` is true. Every rule below
/// was probed against installed git 2.56.0: last-wins single values,
/// first-wins `branch.merge`, first-match-wins fetch mapping with no
/// fallback, `remote = .` resolving locally, case-sensitive
/// remote/subsection lookup, and existence of the mapped ref (absent
/// targets yield no upstream, exactly like git's `rev-parse
/// --symbolic-full-name '@{u}'` failing there).
///
/// Fail-closed throughout: unparseable lines stop that file with earlier
/// values kept (matching git's "earlier ones keep working"), missing
/// remotes/refspecs/targets yield no entry, and divergent per-checkout
/// overlays drop the branch rather than guess. Read-only and offline:
/// bounded regular-file reads only, no spawns.
fn load_branch_upstreams(
    instance: &git::GitInstance,
    checkouts: &[store::CheckoutRow],
    refs: &[git::RefObservation],
) -> HashMap<Vec<u8>, Vec<u8>> {
    let known: HashSet<&[u8]> = refs.iter().map(|r| r.name.as_slice()).collect();
    // Checkout git dirs in row order, deduplicated; the store instance
    // dir covers the degenerate no-checkout case.
    let mut git_dirs: Vec<std::path::PathBuf> = Vec::new();
    for checkout in checkouts {
        let dir = config::path_from_bytes(checkout.git_path.clone());
        if !git_dirs.contains(&dir) {
            git_dirs.push(dir);
        }
    }
    if git_dirs.is_empty() {
        git_dirs.push(instance.git_dir.clone());
    }
    // Base effective config from the common dir (+ includes). `gitdir:`
    // conditions match against any checkout git dir (documented at
    // `include_condition_matches`).
    let mut base = UpstreamConfig::default();
    let mut chain = IncludeChain::default();
    parse_config_tree(
        &instance.common_dir.join("config"),
        &mut base,
        &mut chain,
        &git_dirs,
    );
    let base_map = resolve_all_upstreams(&base, &known);
    // Worktree overlays apply only under the effective gate (read from
    // the common scope — a gate inside a worktree file itself never
    // counts, probed). Each overlay appends after the base, so last-wins
    // keys resolve to the worktree value while multi-value keys keep
    // file order (common first, probed).
    let gate = base
        .last(b"extensions", b"", b"worktreeconfig")
        .is_some_and(git::refspec::config_bool_is_true);
    if !gate {
        return base_map;
    }
    // Per-checkout effective maps. Checkouts without an overlay file
    // observe the base map; poisoned checkouts (present-but-unreadable
    // worktree file, where git itself fails) observe nothing.
    let mut participants: Vec<HashMap<Vec<u8>, Vec<u8>>> = Vec::new();
    let mut overlay_seen: HashSet<std::path::PathBuf> = HashSet::new();
    for dir in &git_dirs {
        let overlay = dir.join("config.worktree");
        if !overlay_seen.insert(overlay.clone()) {
            continue;
        }
        if std::fs::symlink_metadata(&overlay).is_err() {
            // Absent overlay: the checkout observes the base map.
            // (Duplicates across checkouts are harmless: merging below
            // is idempotent.)
            participants.push(base_map.clone());
        } else if git::read_bounded_bytes(&overlay, git::MAX_GIT_CONTROL_BYTES).is_none() {
            // Poisoned: directory, link, over-cap, or raced away. git
            // fails here too, so this checkout contributes nothing.
        } else {
            let mut effective = base.clone();
            let mut overlay_chain = IncludeChain::default();
            parse_config_tree(
                &overlay,
                &mut effective,
                &mut overlay_chain,
                std::slice::from_ref(dir),
            );
            participants.push(resolve_all_upstreams(&effective, &known));
        }
    }
    // Merge: present wins over absent (union), any divergent present
    // value drops the branch (fail closed). Deterministic and
    // order-independent.
    let mut merged: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut dropped: HashSet<Vec<u8>> = HashSet::new();
    for map in &participants {
        for (branch, upstream) in map {
            if dropped.contains(branch) {
                continue;
            }
            match merged.get(branch) {
                None => {
                    merged.insert(branch.clone(), upstream.clone());
                }
                Some(prev) if prev == upstream => {}
                Some(_) => {
                    merged.remove(branch);
                    dropped.insert(branch.clone());
                }
            }
        }
    }
    merged
}

/// Upstream bytes for one ref, if it is a local branch with config tracking.
/// Byte-exact: non-UTF-8 branch names resolve like any other.
fn upstream_for_ref(upstreams: &HashMap<Vec<u8>, Vec<u8>>, name: &[u8]) -> Option<Vec<u8>> {
    let short = name.strip_prefix(b"refs/heads/")?;
    upstreams.get(short).cloned()
}

/// Maximum include-chain depth followed for upstream resolution (mirrors
/// `GixInspector::config_dependencies`).
const UPSTREAM_INCLUDE_MAX_DEPTH: u8 = 4;
/// Maximum config files read per tree (mirrors the filter-guard scan).
const UPSTREAM_INCLUDE_MAX_FILES: usize = 256;
/// Maximum `gitdir:` pattern bytes evaluated (fail closed past it).
const UPSTREAM_GITDIR_PATTERN_MAX: usize = 1024;
/// Glob-match step budget per pattern (fail closed past it).
const UPSTREAM_GLOB_STEP_BUDGET: u64 = 100_000;

/// Bounded include traversal for one config tree: lexical cycle set (no
/// symlink following anywhere, so no canonicalization for identity —
/// the depth cap bounds missed aliases) plus a shared file budget.
#[derive(Default)]
struct IncludeChain {
    seen: HashSet<std::path::PathBuf>,
    files: usize,
}

/// Ordered config values: `(section, subsection, key)` (section/key
/// ASCII-lowercased, subsection raw bytes) to values in file order.
/// Callers pass lowercase section/key literals. Last-wins keys read
/// [`UpstreamConfig::last`], first-wins [`UpstreamConfig::first`],
/// ordered multi-values [`UpstreamConfig::all`].
/// Ordered config values keyed by `(section, subsection, key)`.
type UpstreamValues = HashMap<(Vec<u8>, Vec<u8>, Vec<u8>), Vec<Vec<u8>>>;

#[derive(Clone, Default)]
struct UpstreamConfig {
    values: UpstreamValues,
}

impl UpstreamConfig {
    fn push(&mut self, section: &[u8], subsection: &[u8], key: &[u8], value: Vec<u8>) {
        self.values
            .entry((
                section.to_ascii_lowercase(),
                subsection.to_vec(),
                key.to_ascii_lowercase(),
            ))
            .or_default()
            .push(value);
    }

    fn all(&self, section: &[u8], subsection: &[u8], key: &[u8]) -> &[Vec<u8>] {
        self.values
            .get(&(section.to_vec(), subsection.to_vec(), key.to_vec()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn last(&self, section: &[u8], subsection: &[u8], key: &[u8]) -> Option<&[u8]> {
        self.all(section, subsection, key).last().map(Vec::as_slice)
    }

    fn first(&self, section: &[u8], subsection: &[u8], key: &[u8]) -> Option<&[u8]> {
        self.all(section, subsection, key)
            .first()
            .map(Vec::as_slice)
    }

    /// Branch names carrying any config, sorted and deduplicated.
    fn branch_names(&self) -> Vec<&[u8]> {
        let mut names: Vec<&[u8]> = self
            .values
            .keys()
            .filter(|(section, _, _)| section == b"branch")
            .map(|(_, subsection, _)| subsection.as_slice())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

/// Parse one config tree root (common `config` or a worktree overlay):
/// a missing or unreadable root contributes nothing (fail closed).
fn parse_config_tree(
    path: &std::path::Path,
    cfg: &mut UpstreamConfig,
    chain: &mut IncludeChain,
    git_dirs: &[std::path::PathBuf],
) {
    if chain.files >= UPSTREAM_INCLUDE_MAX_FILES {
        return;
    }
    if !chain.seen.insert(path.to_path_buf()) {
        return;
    }
    chain.files += 1;
    let Some(bytes) = git::read_bounded_bytes(path, git::MAX_GIT_CONTROL_BYTES) else {
        return;
    };
    let base = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    parse_config_bytes(&bytes, cfg, chain, base, git_dirs, 0);
}

/// Parse one config file's bytes, following includes inline in file
/// order. Any construct git fatals on (bad header, bad key, bad escape,
/// content outside a section, NUL bytes, present-but-unreadable include
/// target) stops the file with earlier values kept — matching git's
/// "earlier ones keep working". CRLF, trailing comments/junk after `]`,
/// and valueless keys (empty value) are accepted, all probed.
fn parse_config_bytes(
    bytes: &[u8],
    cfg: &mut UpstreamConfig,
    chain: &mut IncludeChain,
    base: &std::path::Path,
    git_dirs: &[std::path::PathBuf],
    depth: u8,
) {
    // git skips a BOM at file start.
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let joined = join_config_continuations(bytes);
    let mut section: Option<(Vec<u8>, Vec<u8>)> = None;
    for logical in joined.split(|b| *b == b'\n') {
        let line = logical.strip_suffix(b"\r").unwrap_or(logical).trim_ascii();
        if line.is_empty() || matches!(line.first(), Some(b'#') | Some(b';')) {
            continue;
        }
        if line.contains(&b'\0') {
            return;
        }
        if line.first() == Some(&b'[') {
            let Some(header) = parse_config_header(line) else {
                return;
            };
            section = Some(header);
            continue;
        }
        let Some((name, subsection)) = section.as_ref() else {
            return;
        };
        let is_include = name == b"include" && subsection.is_empty();
        let is_include_if = name == b"includeif" && !subsection.is_empty();
        let (key, value): (&[u8], Vec<u8>) = match line.iter().position(|b| *b == b'=') {
            None => (strip_config_comment(line).trim_ascii(), Vec::new()),
            Some(eq) => {
                let raw = strip_config_comment(line[eq + 1..].trim_ascii()).trim_ascii();
                let Some(value) = unescape_config_value(raw) else {
                    return;
                };
                (line[..eq].trim_ascii(), value)
            }
        };
        if key.is_empty() || !key.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-') {
            return;
        }
        if is_include && key.eq_ignore_ascii_case(b"path") {
            if follow_config_include(&value, base, cfg, chain, git_dirs, depth) {
                return;
            }
        } else if is_include_if
            && key.eq_ignore_ascii_case(b"path")
            && include_condition_matches(subsection, git_dirs)
            && follow_config_include(&value, base, cfg, chain, git_dirs, depth)
        {
            return;
        } else {
            cfg.push(name, subsection, key, value);
        }
    }
}

/// Parse a section header line (already trimmed, starts with `[`):
/// `[name]` (no leading space, probed), `[name.sub]` dotted (probed:
/// defines the subsection), or `[name "quoted"]` (`]` immediately after
/// the closing quote, probed). Anything after a bare `]` is ignored
/// (probed: junk and comments both accepted). `None` = malformed.
fn parse_config_header(line: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let rest = &line[1..];
    let mut end = 0;
    while end < rest.len() && (rest[end].is_ascii_alphanumeric() || rest[end] == b'-') {
        end += 1;
    }
    if end == 0 {
        return None;
    }
    let name = rest[..end].to_ascii_lowercase();
    let rest = &rest[end..];
    if rest.first() == Some(&b']') {
        return Some((name, Vec::new()));
    }
    if rest.first() == Some(&b'.') {
        let after_dot = &rest[1..];
        let close = after_dot.iter().position(|b| *b == b']')?;
        let subsection = &after_dot[..close];
        if subsection.is_empty()
            || subsection
                .iter()
                .any(|b| b.is_ascii_whitespace() || *b == b'"')
        {
            return None;
        }
        return Some((name, subsection.to_vec()));
    }
    let mut indent = 0;
    while indent < rest.len() && (rest[indent] == b' ' || rest[indent] == b'\t') {
        indent += 1;
    }
    if indent == 0 || indent >= rest.len() || rest[indent] != b'"' {
        return None;
    }
    let inner = &rest[indent + 1..];
    let mut subsection = Vec::new();
    let mut next = 0;
    let mut closed = false;
    while next < inner.len() {
        match inner[next] {
            b'"' => {
                closed = true;
                next += 1;
                break;
            }
            b'\\' => {
                next += 1;
                match inner.get(next) {
                    Some(b'n') => subsection.push(b'\n'),
                    Some(b't') => subsection.push(b'\t'),
                    Some(b'b') => subsection.push(0x08),
                    Some(b'"') => subsection.push(b'"'),
                    Some(b'\\') => subsection.push(b'\\'),
                    _ => return None,
                }
                next += 1;
            }
            byte => {
                subsection.push(byte);
                next += 1;
            }
        }
    }
    if !closed || inner[next..].first() != Some(&b']') {
        return None;
    }
    Some((name, subsection))
}

/// Join git line continuations the way git 2.56.0 parses values: a `\`
/// IMMEDIATELY before `\n` (or `\r\n`) joins the next line by pure
/// concatenation (leading whitespace kept, inside and outside quotes);
/// the parity of a trailing `\` run decides (odd joins, even stays
/// literal); a trailing `\` at EOF is dropped (odd) or paired (even); a
/// `\` before anything else stays literal for the escape parser (which
/// fails the file there exactly as git fatals). Byte port of the
/// `git::join_continuations` rule-set (private there; this path needs
/// byte-exact values for non-UTF-8 names).
fn join_config_continuations(config: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(config.len());
    let mut i = 0;
    while i < config.len() {
        if config[i] != b'\\' {
            out.push(config[i]);
            i += 1;
            continue;
        }
        let mut run_end = i;
        while run_end < config.len() && config[run_end] == b'\\' {
            run_end += 1;
        }
        let run = run_end - i;
        let mut break_end = run_end;
        if break_end < config.len() && config[break_end] == b'\r' {
            break_end += 1;
        }
        if break_end < config.len() && config[break_end] == b'\n' {
            out.extend(std::iter::repeat_n(b'\\', run - run % 2));
            if run % 2 == 0 {
                out.extend_from_slice(&config[run_end..=break_end]);
            }
            i = break_end + 1;
        } else if run_end == config.len() {
            out.extend(std::iter::repeat_n(b'\\', run - run % 2));
            i = run_end;
        } else {
            out.extend(std::iter::repeat_n(b'\\', run));
            i = run_end;
        }
    }
    out
}

/// Strip a git trailing comment: `;`/`#` outside double quotes ends the
/// value (only double quotes protect); a backslash escapes the next
/// byte. Byte port of the `git::strip_git_comment` rule.
fn strip_config_comment(value: &[u8]) -> &[u8] {
    let mut in_quotes = false;
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'\\' => i += 2,
            b'"' => {
                in_quotes = !in_quotes;
                i += 1;
            }
            b';' | b'#' if !in_quotes => return &value[..i],
            _ => i += 1,
        }
    }
    value
}

/// Resolve git quote grouping + backslash escapes in an already
/// comment-stripped, trimmed value: drop `"` chars, map `\\` `\"` `\n`
/// `\t` `\b` (the full set git 2.56.0 accepts — anything else, or a
/// trailing lone `\`, makes git reject the file, reported here as
/// `None` so the caller stops the file too). Byte port of the
/// `git::unescape_git_value` rule.
fn unescape_config_value(value: &[u8]) -> Option<Vec<u8>> {
    if !value.contains(&b'"') && !value.contains(&b'\\') {
        return Some(value.to_vec());
    }
    let mut out = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'"' => {
                i += 1;
            }
            b'\\' => {
                i += 1;
                match value.get(i) {
                    Some(b'n') => out.push(b'\n'),
                    Some(b't') => out.push(b'\t'),
                    Some(b'b') => out.push(0x08),
                    Some(b'"') => out.push(b'"'),
                    Some(b'\\') => out.push(b'\\'),
                    _ => return None,
                }
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    Some(out)
}

/// Follow one `include.path` value inline (file order). Returns true when
/// the including file must stop (present-but-unreadable target — git
/// fatals there). Missing targets are silently skipped (probed), as are
/// revisits (cycles), depth/file cap overflows, and empty/unresolvable
/// spellings.
fn follow_config_include(
    value: &[u8],
    base: &std::path::Path,
    cfg: &mut UpstreamConfig,
    chain: &mut IncludeChain,
    git_dirs: &[std::path::PathBuf],
    depth: u8,
) -> bool {
    if value.is_empty() || depth >= UPSTREAM_INCLUDE_MAX_DEPTH {
        return false;
    }
    let Some(target) = resolve_include_target(value, base) else {
        return false;
    };
    if chain.seen.contains(&target) || chain.files >= UPSTREAM_INCLUDE_MAX_FILES {
        return false;
    }
    if std::fs::symlink_metadata(&target).is_err() {
        return false;
    }
    let Some(bytes) = git::read_bounded_bytes(&target, git::MAX_GIT_CONTROL_BYTES) else {
        return true;
    };
    chain.seen.insert(target.clone());
    chain.files += 1;
    let child_base = target.parent().unwrap_or_else(|| std::path::Path::new("."));
    parse_config_bytes(&bytes, cfg, chain, child_base, git_dirs, depth + 1);
    false
}

/// Resolve an include target the way git does: `~`/`~/` against HOME
/// (probed), relative against the including file's directory, absolute
/// as-is. Byte-exact on unix (a path, never lossy text). No variable
/// expansion (git does none).
fn resolve_include_target(value: &[u8], base: &std::path::Path) -> Option<std::path::PathBuf> {
    if value == b"~" || value.starts_with(b"~/") {
        let home = std::env::var_os("HOME")?;
        let mut out = std::path::PathBuf::from(home);
        if value.len() > 1 {
            out.push(git::os_str_from_bytes(&value[2..]));
        }
        return Some(out);
    }
    let path = std::path::Path::new(git::os_str_from_bytes(value));
    if path.is_absolute() {
        Some(path.to_path_buf())
    } else {
        Some(base.join(path))
    }
}

/// True when an `includeIf` subsection condition positively matches one of
/// the candidate git dirs. Only absolute `gitdir:`/`gitdir/i:` patterns
/// are evaluated (probed git 2.56.0, condition keywords case-sensitive:
/// `*` never crosses `/`, `?` matches one non-`/` byte, `**` crosses, a
/// trailing `/` appends `**`, matching runs against both the spelled and
/// canonicalized dir). Every other condition (`onbranch:`, `hasconfig:`,
/// unknown keywords, bare sections, relative patterns, over-long
/// patterns, exhausted match budgets) fails closed to false — its
/// include is skipped, never misapplied.
///
/// Multi-checkout approximation: conditions match when ANY checkout git
/// dir matches. Single-checkout stores are exact; a `gitdir:` include
/// that git would apply to only one checkout of a divergent store
/// over-applies here (its values are still real config bytes, attributed
/// store-wide like every other shared upstream input).
fn include_condition_matches(condition: &[u8], git_dirs: &[std::path::PathBuf]) -> bool {
    let (pattern, ignore_case) = if let Some(pattern) = condition.strip_prefix(b"gitdir:") {
        (pattern, false)
    } else if let Some(pattern) = condition.strip_prefix(b"gitdir/i:") {
        (pattern, true)
    } else {
        return false;
    };
    if pattern.is_empty()
        || !pattern.starts_with(b"/")
        || pattern.len() > UPSTREAM_GITDIR_PATTERN_MAX
    {
        return false;
    }
    let mut expanded;
    let mut pattern = pattern;
    if pattern.ends_with(b"/") {
        expanded = pattern.to_vec();
        expanded.extend_from_slice(b"**");
        pattern = &expanded;
    }
    git_dirs.iter().any(|dir| {
        gitdir_match_forms(dir).iter().any(|form| {
            let mut memo = HashSet::new();
            let mut budget = UPSTREAM_GLOB_STEP_BUDGET;
            glob_match(pattern, form, ignore_case, &mut memo, &mut budget)
        })
    })
}

/// Candidate spellings of one git dir for `gitdir:` matching: the spelled
/// path plus its canonicalized form when that succeeds (probed: git
/// matches both, e.g. `/tmp/…` and `/private/tmp/…` on macOS).
/// Canonicalization is for matching only — no file is read through it.
fn gitdir_match_forms(dir: &std::path::Path) -> Vec<Vec<u8>> {
    let mut forms = vec![os_bytes(dir.as_os_str())];
    if let Ok(canonical) = std::fs::canonicalize(dir) {
        let bytes = os_bytes(canonical.as_os_str());
        if !forms.contains(&bytes) {
            forms.push(bytes);
        }
    }
    forms
}

/// Match one expanded `gitdir:` pattern against one dir spelling: `**`
/// crosses `/`, `*`/`?` never do, `\` escapes the next byte, and `[`
/// classes are unsupported (fail closed). Bounded by a step budget plus
/// a visited-state memo (adversarial patterns cannot hang the scan).
fn glob_match(
    pattern: &[u8],
    value: &[u8],
    ignore_case: bool,
    memo: &mut HashSet<(usize, usize)>,
    budget: &mut u64,
) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    // Pointer-pair memo: every recursive slice derives from the same two
    // buffers, so pairs are unique positions; recursion always shrinks
    // `pattern.len() + value.len()`, so a revisited state already failed.
    if !memo.insert((pattern.as_ptr() as usize, value.as_ptr() as usize)) {
        return false;
    }
    if pattern.is_empty() {
        return value.is_empty();
    }
    if pattern[0] == b'*' {
        let mut end = 0;
        while end < pattern.len() && pattern[end] == b'*' {
            end += 1;
        }
        let rest = &pattern[end..];
        let double = end >= 2;
        let mut split = 0;
        loop {
            if glob_match(rest, &value[split..], ignore_case, memo, budget) {
                return true;
            }
            if split == value.len() || (!double && value[split] == b'/') {
                return false;
            }
            split += 1;
        }
    }
    if value.is_empty() {
        return false;
    }
    match pattern[0] {
        b'?' => {
            if value[0] == b'/' {
                return false;
            }
            glob_match(&pattern[1..], &value[1..], ignore_case, memo, budget)
        }
        b'\\' => {
            if pattern.len() < 2 || !glob_byte_eq(pattern[1], value[0], ignore_case) {
                return false;
            }
            glob_match(&pattern[2..], &value[1..], ignore_case, memo, budget)
        }
        b'[' => false,
        literal => {
            if !glob_byte_eq(literal, value[0], ignore_case) {
                return false;
            }
            glob_match(&pattern[1..], &value[1..], ignore_case, memo, budget)
        }
    }
}

/// Byte equality with optional ASCII case folding.
fn glob_byte_eq(left: u8, right: u8, ignore_case: bool) -> bool {
    left == right || (ignore_case && left.eq_ignore_ascii_case(&right))
}

/// Lossless `OsStr`-to-bytes on unix; lossy fallback elsewhere.
fn os_bytes(os: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStrExt::as_bytes(os).to_vec()
    }
    #[cfg(not(unix))]
    {
        os.to_string_lossy().into_owned().into_bytes()
    }
}

/// Resolve every branch in the effective config to its full comparison ref.
fn resolve_all_upstreams(
    cfg: &UpstreamConfig,
    known: &HashSet<&[u8]>,
) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut out = HashMap::new();
    for branch in cfg.branch_names() {
        if branch.is_empty() {
            continue;
        }
        if let Some(upstream) = resolve_branch_upstream(cfg, branch, known) {
            out.insert(branch.to_vec(), upstream);
        }
    }
    out
}

/// Resolve one branch to its full comparison ref: last `remote`, first
/// `merge` (both probed). `remote = .` resolves locally to the merge ref
/// itself. Otherwise the first positive fetch refspec (config order)
/// whose source matches the merge ref maps it to the local tracking ref
/// — with no fallback when that target is missing and no default when
/// the remote carries no fetch lines (all probed). The mapped ref must
/// exist in the same observation; anything else yields no upstream.
fn resolve_branch_upstream(
    cfg: &UpstreamConfig,
    branch: &[u8],
    known: &HashSet<&[u8]>,
) -> Option<Vec<u8>> {
    let remote = cfg.last(b"branch", branch, b"remote")?;
    if remote.is_empty() {
        return None;
    }
    let merge = cfg.first(b"branch", branch, b"merge")?;
    if merge.is_empty() {
        return None;
    }
    if remote == b"." {
        return known.contains(merge).then(|| merge.to_vec());
    }
    for fetch in cfg.all(b"remote", remote, b"fetch") {
        let Ok(text) = std::str::from_utf8(fetch) else {
            continue;
        };
        let Some(spec) = git::refspec::parse_fetch_refspec(text) else {
            continue;
        };
        if spec.negative || spec.dst.is_none() {
            continue;
        }
        let mapped = map_fetch_refspec(&spec, merge)?;
        return known.contains(mapped.as_slice()).then_some(mapped);
    }
    None
}

/// Map a merge ref through one positive fetch refspec with a destination:
/// a literal source requires equality, a `*` source substitutes the
/// middle capture into the destination pattern (exact bytes; the parser
/// guarantees at most one `*` per side with `*` in source iff `*` in
/// destination). `None` = no match.
fn map_fetch_refspec(spec: &git::refspec::FetchRefspec, merge: &[u8]) -> Option<Vec<u8>> {
    let dst = spec.dst.as_deref()?;
    match spec.src.split_once('*') {
        None => {
            if merge == spec.src.as_bytes() {
                Some(dst.as_bytes().to_vec())
            } else {
                None
            }
        }
        Some((pre, post)) => {
            let middle = merge
                .strip_prefix(pre.as_bytes())?
                .strip_suffix(post.as_bytes())?;
            let (dst_pre, dst_post) = dst.split_once('*')?;
            let mut out = Vec::with_capacity(dst_pre.len() + middle.len() + dst_post.len());
            out.extend_from_slice(dst_pre.as_bytes());
            out.extend_from_slice(middle);
            out.extend_from_slice(dst_post.as_bytes());
            Some(out)
        }
    }
}

/// Honest ref state (R16): directly observed targets are valid, as is
/// any symbolic ref whose target exists in the same observation (peel data
/// is backend-optional, never the validity proof). Only a dangling
/// symbolic ref is non-valid: unborn for a branch target, invalid else.
fn ref_state_for(reference: &git::RefObservation, known: &HashSet<&[u8]>) -> &'static str {
    match &reference.target {
        git::RefTarget::Object(_) => "valid",
        git::RefTarget::Symbolic(_) if reference.peeled.is_some() => "valid",
        git::RefTarget::Symbolic(target) if known.contains(target.as_slice()) => "valid",
        git::RefTarget::Symbolic(target) if target.starts_with(b"refs/heads/") => "unborn",
        git::RefTarget::Symbolic(_) => "invalid",
    }
}

/// Enqueue a probe for an explicitly related path (linked-worktree base).
async fn enqueue_probe_task_for_path(
    store: &TursoStore,
    runner: &mut Runner,
    generation: u64,
    path: &Path,
    now_ms: i64,
) -> repo_scan::Result<()> {
    let hex = config::encode_hex(&config::path_as_bytes(path));
    // PG-01: a worktree-base probe is an explicitly scheduled
    // relationship — carry that provenance plus the schedule-time
    // identity observed here.
    let schedule = schedule_suffix_for(path, ProbeProvenance::Relationship);
    let id = format!("probe:{generation}:{hex}{schedule}");
    let scope_key = config::scope_key_for_git(path);
    let expected_rev = store.scope_rev(&scope_key).await?;
    let idempotency = format!("idem:{id}");
    // RSF-AC461500-609D-4D55-991E-09C60D382D67: buffered enqueue.
    let task = NewTask {
        id: &id,
        kind: KIND_PROBE,
        generation,
        dir_id: None,
        scope_key: &scope_key,
        expected_rev,
        idempotency_key: &idempotency,
    };
    let due = TursoStore::buffer_enqueue_task(&mut runner.batch, &task, now_ms);
    flush_if_due(runner, store, due).await?;
    Ok(())
}

/// HEAD observation with installed-git fallback on structural gaps only.
fn observed_head(
    ctx: &ReadContext,
    instance: &git::GitInstance,
) -> repo_scan::Result<git::HeadState> {
    match ctx.inspector.head(instance) {
        Ok(head) => Ok(head),
        Err(e) if git::is_unsupported_error(&e) => {
            if let Some(fallback) = ctx.fallback() {
                match fallback.head(&instance.git_dir, instance.work_dir.as_deref()) {
                    Ok(head) => return Ok(head),
                    Err(fe) => {
                        eprintln!(
                            "repo-scan: fallback HEAD failed: {}",
                            identity::scrub_text(&fe.to_string())
                        );
                    }
                }
            }
            Ok(git::HeadState::Unknown)
        }
        Err(e) => Err(e),
    }
}

/// Ref observations with installed-git fallback on structural gaps only.
fn observed_refs(
    ctx: &ReadContext,
    instance: &git::GitInstance,
    evidence: &mut Vec<String>,
) -> repo_scan::Result<Vec<git::RefObservation>> {
    match ctx.inspector.refs(instance) {
        Ok(refs) => Ok(refs),
        Err(e) if git::is_unsupported_error(&e) => {
            if let Some(fallback) = ctx.fallback() {
                match fallback.refs(&instance.git_dir, instance.work_dir.as_deref()) {
                    Ok(refs) => {
                        evidence.push(String::from("refs via installed-git fallback"));
                        return Ok(refs);
                    }
                    Err(fe) => {
                        eprintln!(
                            "repo-scan: fallback refs failed: {}",
                            identity::scrub_text(&fe.to_string())
                        );
                    }
                }
            }
            evidence.push(format!(
                "refs unsupported, preserved without observations: {e}"
            ));
            Ok(Vec::new())
        }
        Err(e) => Err(e),
    }
}

/// HEAD observation mapped to checkout columns:
/// (state, ref-name bytes, OID hex bytes, OID algorithm).
type HeadColumns = (
    &'static str,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
);

/// Map a HEAD observation to checkout columns.
fn head_columns(head: &git::HeadState) -> HeadColumns {
    match head {
        git::HeadState::Branch { ref_name, oid } => (
            "branch",
            Some(ref_name.clone()),
            oid.as_ref().map(|o| o.hex.as_bytes().to_vec()),
            oid.as_ref().map(|o| o.algorithm.clone()),
        ),
        git::HeadState::Detached { target, .. } => (
            "detached",
            None,
            Some(target.hex.as_bytes().to_vec()),
            Some(target.algorithm.clone()),
        ),
        git::HeadState::Unborn { ref_name } => ("unborn", Some(ref_name.clone()), None, None),
        git::HeadState::Invalid => ("invalid", None, None, None),
        git::HeadState::Unknown => ("unknown", None, None, None),
    }
}

/// Watch guard for one blocking status call (XSEC-01 + SR-STATE-01): a
/// single short-lived thread polls identity every [`IDENT_POLL_INTERVAL`]
/// while the main thread sits in the blocking gix status iteration, and
/// trips the shared interrupt flag on identity change or deadline. The
/// thread always exits by itself — on `done`, on change, or at the
/// deadline — so even an unkillable status syscall leaks no thread; the
/// wedge itself is the documented SR-STATE-01 residual (lease expires
/// store-side, a later owner reclaims).
struct StatusGuard {
    interrupt: Arc<AtomicBool>,
    changed: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

fn spawn_status_guard(
    fence: Option<ScopeFence>,
    path: PathBuf,
    snap: Option<IdentitySnapshot>,
    deadline: OpDeadline,
) -> StatusGuard {
    let mut guard = StatusGuard {
        interrupt: Arc::new(AtomicBool::new(false)),
        changed: Arc::new(AtomicBool::new(false)),
        done: Arc::new(AtomicBool::new(false)),
        handle: None,
    };
    let (interrupt, changed, done) = (
        Arc::clone(&guard.interrupt),
        Arc::clone(&guard.changed),
        Arc::clone(&guard.done),
    );
    guard.handle = Some(std::thread::spawn(move || loop {
        if done.load(Ordering::SeqCst) {
            break;
        }
        if deadline.expired() {
            interrupt.store(true, Ordering::SeqCst);
            break;
        }
        if !snapshot_matches(fence.as_ref(), &path, snap.as_ref()) {
            changed.store(true, Ordering::SeqCst);
            interrupt.store(true, Ordering::SeqCst);
            break;
        }
        std::thread::sleep(IDENT_POLL_INTERVAL.min(deadline.remaining()));
    }));
    guard
}

impl StatusGuard {
    fn interrupt_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.interrupt)
    }

    /// Signal completion, join the watch thread (bounded: it wakes at
    /// least every [`IDENT_POLL_INTERVAL`]), and report whether the
    /// identity changed during the call.
    fn finish(mut self) -> bool {
        self.done.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.changed.load(Ordering::SeqCst)
    }
}

/// Per-store branch/HEAD reads (goal Step 8 analysis leg, Step 10):
/// shared references read once per local store, HEAD separately per
/// checkout, plus upstream config and ref errors. Collected only in
/// the post-`inventory_ready` drain — never during discovery.
struct AnalysisReads {
    refs: Vec<git::RefObservation>,
    refs_notes: Vec<String>,
    ref_errors: Vec<String>,
    branch_upstreams: HashMap<Vec<u8>, Vec<u8>>,
    /// `(checkout_id, HEAD)` per checkout of the store.
    heads: Vec<(String, git::HeadState)>,
    /// Branch-vs-upstream comparisons keyed by full local ref name
    /// (Step 10; local `refs/heads/` branches only — other kinds are
    /// never compared and persist no comparison).
    comparisons: HashMap<Vec<u8>, git::graph::Comparison>,
}

/// Outcome of [`collect_analysis_reads`]: full reads, or an abandon
/// signal with probe-identical meaning (park, persist nothing). Lease
/// liveness moved to the coordinator's scheduled tick (see
/// [`CollectOutcome`]).
enum AnalysisOutcome {
    Reads(AnalysisReads),
    IdentityChanged,
    TimedOut,
}

/// Collect one store's analysis reads with DURING-inspection identity
/// polls (XSEC-01) and deadline checks (SR-STATE-01) between stages —
/// the probe collection discipline, analysis stages only. Synchronous:
/// runs on a pool thread with no store handle. Buffers nothing:
/// abandonment drops every observation.
#[allow(clippy::too_many_arguments)]
fn collect_analysis_reads(
    ctx: &ReadContext,
    instance: &git::GitInstance,
    checkouts: &[store::CheckoutRow],
    object_format: &str,
    is_bare: bool,
    poll: &mut IdentityPoll,
    deadline: &OpDeadline,
) -> repo_scan::Result<AnalysisOutcome> {
    if deadline.expired() {
        return Ok(AnalysisOutcome::TimedOut);
    }
    let task_deadline = *deadline;
    let cancel = git::fallback::WaitCancel::new(
        move || INTERRUPTED.load(Ordering::SeqCst) || task_deadline.expired(),
        None,
    );
    // Shared refs, once per store (Step 10): the store instance points
    // at the first-seen git dir, exactly the read the discovery probe
    // used to make — one execution instead of one per checkout.
    let mut refs_notes = Vec::new();
    let refs =
        git::fallback::with_wait_cancel(&cancel, || observed_refs(ctx, instance, &mut refs_notes))?;
    if !poll.ok_now() {
        return Ok(AnalysisOutcome::IdentityChanged);
    }
    if deadline.expired() {
        return Ok(AnalysisOutcome::TimedOut);
    }
    let ref_errors = ctx.inspector.reference_errors(instance);
    let branch_upstreams = load_branch_upstreams(instance, checkouts, &refs);
    // Branch comparisons (Step 10): local branches against their
    // resolved full upstream refs, sharing one per-store result
    // cache (equal OID pairs reuse saved walks). Runs before the
    // checkout loop so identity-poll abandonment drops comparisons
    // together with the reads they derive from.
    let graph_cache = git::graph::ComparisonCache::new();
    let comparisons =
        compute_branch_comparisons(ctx, instance, &refs, &branch_upstreams, &graph_cache);
    if !poll.ok_throttled() {
        return Ok(AnalysisOutcome::IdentityChanged);
    }
    // HEAD separately per checkout (Step 10): each checkout's own git
    // dir observes its own HEAD. A checkout that went unreadable since
    // discovery keeps `unknown` (its row is simply not merged); the
    // store analysis still completes for the rest.
    let mut heads = Vec::with_capacity(checkouts.len());
    for checkout in checkouts {
        if deadline.expired() {
            return Ok(AnalysisOutcome::TimedOut);
        }
        let git_dir = config::path_from_bytes(checkout.git_path.clone());
        let work_dir = checkout
            .root_path
            .as_ref()
            .map(|bytes| config::path_from_bytes(bytes.clone()));
        let checkout_instance = git::GitInstance {
            git_dir,
            common_dir: instance.common_dir.clone(),
            work_dir,
            is_bare,
            object_format: object_format.to_string(),
        };
        let head =
            git::fallback::with_wait_cancel(&cancel, || observed_head(ctx, &checkout_instance))?;
        heads.push((checkout.id.clone(), head));
        if !poll.ok_throttled() {
            return Ok(AnalysisOutcome::IdentityChanged);
        }
    }
    Ok(AnalysisOutcome::Reads(AnalysisReads {
        refs,
        refs_notes,
        ref_errors,
        branch_upstreams,
        heads,
        comparisons,
    }))
}

/// Compare every local (`refs/heads/`) branch against its resolved
/// full upstream ref (goal Step 10, Step 15 case 9). The OID map
/// carries direct tips plus peeled symbolic tips; a branch or
/// upstream without an OID (unborn, dangling symbolic, broken ref)
/// compares as `error` via [`git::graph::compare_branch`] — never
/// `equal`. Non-local refs are skipped (they carry no upstream, so
/// no comparison is persisted and they read `pending`). Offline and
/// read-only: object walks only, with the installed-git `rev-list`
/// fallback behind the existing spawn guards.
fn compute_branch_comparisons(
    ctx: &ReadContext,
    instance: &git::GitInstance,
    refs: &[git::RefObservation],
    upstreams: &HashMap<Vec<u8>, Vec<u8>>,
    cache: &git::graph::ComparisonCache,
) -> HashMap<Vec<u8>, git::graph::Comparison> {
    let mut oids: HashMap<&[u8], (&str, &str)> = HashMap::new();
    for reference in refs {
        match &reference.target {
            git::RefTarget::Object(oid) => {
                oids.insert(
                    reference.name.as_slice(),
                    (oid.hex.as_str(), oid.algorithm.as_str()),
                );
            }
            git::RefTarget::Symbolic(_) => {
                if let Some(peeled) = reference.peeled.as_ref() {
                    oids.insert(
                        reference.name.as_slice(),
                        (peeled.hex.as_str(), peeled.algorithm.as_str()),
                    );
                }
            }
        }
    }
    // Cache store key: the common dir identifies this object
    // database for the cache's lifetime (one analysis pass).
    let store_key = instance.common_dir.to_string_lossy().into_owned();
    let graph_ctx = git::graph::CompareContext {
        git_dir: &instance.git_dir,
        common_dir: &instance.common_dir,
        store_id: &store_key,
        work_tree: instance.work_dir.as_deref(),
        cache: Some(cache),
        fallback: ctx.fallback(),
    };
    let mut out = HashMap::new();
    for reference in refs {
        if !reference.name.starts_with(b"refs/heads/") {
            continue;
        }
        let upstream = upstream_for_ref(upstreams, &reference.name);
        let local = oids.get(reference.name.as_slice()).copied();
        let (upstream_hex, upstream_algo, upstream_known) = match upstream.as_deref() {
            None => (None, None, false),
            Some(name) => match oids.get(name).copied() {
                Some((hex, algo)) => (Some(hex), Some(algo), true),
                None => (None, None, false),
            },
        };
        let tips = git::graph::BranchTips {
            local_hex: local.map(|(hex, _)| hex),
            local_algo: local.map(|(_, algo)| algo),
            upstream: upstream.as_deref(),
            upstream_hex,
            upstream_algo,
            upstream_known,
        };
        out.insert(
            reference.name.clone(),
            git::graph::compare_branch(&graph_ctx, &tips),
        );
    }
    out
}

/// Worker-side result of one analysis task (Step 8 worker seam): every
/// terminal mid-read condition as data, like [`StatusCollected`]. The
/// fence verify, open, and validate run on the pool thread; the single
/// writer applies rows/gaps/retries via [`finish_analysis`].
enum AnalysisCollected {
    Refused { state: TaskState, reason: String },
    StatFailed(std::io::Error),
    TimeoutBeforeReads,
    ValidateFailed { detail: String, unsupported: bool },
    Collected { outcome: AnalysisOutcome },
}

impl AnalysisCollected {
    /// Observations produced, for the watchdog's per-task advancement
    /// verdict (parallel tasks share the global counters, so the drain
    /// cannot infer per-task progress from them).
    fn progress_units(&self) -> u64 {
        match self {
            AnalysisCollected::Collected {
                outcome: AnalysisOutcome::Reads(reads),
            } => reads.refs.len() as u64 + reads.heads.len() as u64,
            _ => 0,
        }
    }
}

/// Worker-side analysis execution: fence verify, validate, the
/// identity-poll envelope, and [`collect_analysis_reads`]. Synchronous —
/// runs on a pool thread with worker-owned inputs only. The instance
/// row and checkout list come from the coordinator's catalog reads
/// ([`prepare_analysis`]); the pre-persist gate stays on the
/// coordinator ([`finish_analysis`]).
#[allow(clippy::too_many_arguments)]
fn run_analysis_job(
    ctx: &ReadContext,
    path: &Path,
    common_dir: &Path,
    checkouts: &[store::CheckoutRow],
    object_format: &str,
    is_bare: bool,
    deadline: &OpDeadline,
) -> repo_scan::Result<AnalysisCollected> {
    // Analysis ids carry no PG-01 schedule suffix; the store row is a Git
    // observation, so relationship routing applies (as for status).
    let schedule = ProbeSchedule::analysis_legacy();
    let pinned: Option<PinnedDir> =
        match verify_probe_path(ctx.fence.as_ref(), "analyze", path, &schedule) {
            ProbeFence::Unfenced => None,
            ProbeFence::Pinned(pinned) | ProbeFence::Relationship(pinned) => Some(pinned),
            ProbeFence::Refused { state, reason } => {
                return Ok(AnalysisCollected::Refused { state, reason });
            }
            ProbeFence::StatFailed(e) => return Ok(AnalysisCollected::StatFailed(e)),
        };
    if deadline.expired() {
        return Ok(AnalysisCollected::TimeoutBeforeReads);
    }
    let validated = match ctx.inspector.validate(common_dir) {
        Ok(validated) => validated,
        Err(e) => {
            return Ok(AnalysisCollected::ValidateFailed {
                detail: e.to_string(),
                unsupported: git::is_unsupported_error(&e),
            });
        }
    };
    let mut poll = IdentityPoll::new(ctx.fence.as_ref(), path, pinned.as_ref());
    if !poll.ok_now() {
        return Ok(AnalysisCollected::Collected {
            outcome: AnalysisOutcome::IdentityChanged,
        });
    }
    let outcome = collect_analysis_reads(
        ctx,
        &validated.instance,
        checkouts,
        object_format,
        is_bare,
        &mut poll,
        deadline,
    )?;
    // Pre-store gate, worker side: the collection's last poll ran inside
    // the checkout loop (or never, for a checkout-less store), so
    // re-verify here before the result crosses back to the writer.
    if matches!(outcome, AnalysisOutcome::Reads(_)) && !poll.ok_now() {
        return Ok(AnalysisCollected::Collected {
            outcome: AnalysisOutcome::IdentityChanged,
        });
    }
    Ok(AnalysisCollected::Collected { outcome })
}

/// Coordinator half of one store-analysis task: scope decode, the
/// pre-run lease renewal, and the instance-row/checkout catalog reads.
/// Fence verify, validate, and the identity-polled Git reads run on a
/// pool thread ([`run_analysis_job`]); the outcome is applied by
/// [`finish_analysis`]. The instance row must exist (discovery
/// persisted it); a missing row completes with an explicit gap.
async fn prepare_analysis(
    runner: &mut Runner,
    store: &TursoStore,
    claimed: &ClaimedTask,
    deadline: &OpDeadline,
) -> repo_scan::Result<(PrepExtra, PrepAction)> {
    let done = |outcome: TaskOutcome| (PrepExtra::Done, PrepAction::Done(outcome));
    let Some(config::ScopeRef::Git(path)) = config::parse_scope_key(&claimed.task.scope_key) else {
        return Ok(done(TaskOutcome::Parked {
            state: TaskState::Unsupported,
            reason: format!("malformed git scope key: {}", claimed.task.scope_key),
        }));
    };
    let Some(instance_id) = parse_analysis_instance(&claimed.task.id) else {
        return Ok(done(TaskOutcome::Parked {
            state: TaskState::Unsupported,
            reason: format!("malformed analysis task id: {}", claimed.task.id),
        }));
    };
    // SR-STATE-01: abandon before the first Git read when the budget is
    // already gone. (The worker re-checks on arrival; see `prepare_probe`.)
    if deadline.expired() {
        return Ok(done(park_on_timeout(&format!(
            "timeout-abandoned: analysis of {} exceeded the {OP_DEADLINE_SECS}s execution \
             budget; no Git reads ran",
            path.display()
        ))));
    }
    if !renew_claim_lease(store, &mut runner.counters.db_transactions, claimed).await? {
        let outcome = retry_on_lease_lost(
            runner,
            store,
            claimed,
            &format!(
                "lease lost before analysis of {}; retrying with a fresh lease",
                path.display()
            ),
        )
        .await?;
        return Ok(done(outcome));
    }
    let gap_id = format!(
        "analyze:{}",
        config::encode_hex(&config::path_as_bytes(&path))
    );
    let Some(instance_row) = store.get_git_instance(&instance_id).await? else {
        let due = buffer_record_error(
            runner,
            &gap_id,
            &claimed.task.scope_key,
            "unknown-instance",
            &format!("analysis task names unknown instance {instance_id}; dropping"),
            None,
            store::now_ms(),
        )?;
        flush_if_due(runner, store, due).await?;
        return Ok(done(TaskOutcome::Complete));
    };
    let checkouts = list_store_checkouts(store, &instance_id).await?;
    let job = WorkerJob::Analysis {
        ctx: runner.read_context(),
        path: path.clone(),
        common_dir: config::path_from_bytes(instance_row.common_path.clone()),
        checkouts,
        object_format: instance_row.object_format.clone(),
        bare: instance_row.bare.unwrap_or(false),
        deadline: *deadline,
    };
    let extra = PrepExtra::Analysis {
        path,
        instance_id,
        instance_row: Box::new(instance_row),
    };
    Ok((extra, PrepAction::Spawn(job)))
}
/// Coordinator write half of one analysis task: applies a worker
/// result ([`AnalysisCollected`]) through the pre-persist lease gate
/// and [`persist_analysis`]. Returns the outcome plus the worker's
/// progress units for the watchdog verdict.
async fn finish_analysis(
    runner: &mut Runner,
    store: &TursoStore,
    claimed: &ClaimedTask,
    path: &Path,
    instance_id: &str,
    instance_row: &store::GitInstanceRow,
    result: repo_scan::Result<WorkerOut>,
) -> repo_scan::Result<(TaskOutcome, u64)> {
    let collected = match result {
        Ok(WorkerOut::Analysis(collected)) => collected,
        Ok(_) => {
            return Err(repo_scan::Error::Scheduler(String::from(
                "analysis finish received a non-analysis worker result",
            )));
        }
        Err(repo_scan::Error::Git(detail)) => {
            let outcome = fail_task(
                runner,
                store,
                claimed,
                ExecFail {
                    category: String::from("analysis-read-error"),
                    detail,
                },
            )
            .await?;
            return Ok((outcome, 0));
        }
        Err(e) => return Err(e),
    };
    let units = collected.progress_units();
    let now = store::now_ms();
    let gap_id = format!(
        "analyze:{}",
        config::encode_hex(&config::path_as_bytes(path))
    );
    let outcome = match collected {
        AnalysisCollected::Refused { state, reason } => TaskOutcome::Parked { state, reason },
        AnalysisCollected::StatFailed(e) => {
            fail_stat_open(runner, store, claimed, path, &e).await?
        }
        AnalysisCollected::TimeoutBeforeReads => park_on_timeout(&format!(
            "timeout-abandoned: analysis of {} exceeded the {OP_DEADLINE_SECS}s execution \
             budget; no Git reads ran",
            path.display()
        )),
        AnalysisCollected::ValidateFailed {
            detail,
            unsupported,
        } => {
            let category = if unsupported {
                "unsupported-git-format"
            } else {
                "analysis-failed"
            };
            let due = buffer_record_error(
                runner,
                &gap_id,
                &claimed.task.scope_key,
                category,
                &detail,
                None,
                now,
            )?;
            flush_if_due(runner, store, due).await?;
            TaskOutcome::Complete
        }
        AnalysisCollected::Collected { outcome } => match outcome {
            AnalysisOutcome::Reads(reads) => {
                if !renew_claim_lease(store, &mut runner.counters.db_transactions, claimed).await? {
                    let outcome = retry_on_lease_lost(
                        runner,
                        store,
                        claimed,
                        &format!(
                            "lease lost before persisting analysis of {}; observations discarded",
                            path.display()
                        ),
                    )
                    .await?;
                    return Ok((outcome, units));
                }
                match persist_analysis(runner, store, instance_id, instance_row, reads, path, now)
                    .await
                {
                    Ok(()) => {
                        let due = buffer_resolve_error(runner, &gap_id, store::now_ms())?;
                        flush_if_due(runner, store, due).await?;
                        TaskOutcome::Complete
                    }
                    Err(repo_scan::Error::Git(detail)) => {
                        fail_task(
                            runner,
                            store,
                            claimed,
                            ExecFail {
                                category: String::from("analysis-persist-error"),
                                detail,
                            },
                        )
                        .await?
                    }
                    Err(e) => return Err(e),
                }
            }
            AnalysisOutcome::IdentityChanged => park_on_identity_change("analyze", path),
            AnalysisOutcome::TimedOut => park_on_timeout(&format!(
                "timeout-abandoned: analysis of {} exceeded the {OP_DEADLINE_SECS}s execution \
                 budget during Git reads; observations discarded",
                path.display()
            )),
        },
    };
    Ok((outcome, units))
}

/// Instance id from an analysis task id (`analyze:{instance}:{run}`).
/// The instance id itself contains `:` (`git:{hex}`), so the run
/// revision splits off the right.
fn parse_analysis_instance(task_id: &str) -> Option<String> {
    let rest = task_id.strip_prefix("analyze:")?;
    let (instance_id, _run_rev) = rest.rsplit_once(':')?;
    if instance_id.is_empty() {
        return None;
    }
    Some(instance_id.to_string())
}

/// Checkout rows for one store, id-ordered for deterministic analysis.
async fn list_store_checkouts(
    store: &TursoStore,
    instance_id: &str,
) -> repo_scan::Result<Vec<store::CheckoutRow>> {
    let mut out = Vec::new();
    let mut rows = store
        .connection()
        .query(
            "SELECT id FROM checkouts WHERE instance_id = ?1 ORDER BY id ASC",
            vec![turso::Value::Text(instance_id.to_string())],
        )
        .await
        .map_err(store_err)?;
    while let Some(row) = rows.next().await.map_err(store_err)? {
        let id = cell_text(&row, 0)?;
        if let Some(checkout) = store.get_checkout(&id).await? {
            out.push(checkout);
        }
    }
    Ok(out)
}

/// Persist one store's analysis: shared ref rows (upserted by the
/// canonical ref id, so re-analysis refreshes instead of duplicating),
/// one `branch_batch` journal per 500 refs, ref-error gaps, refs-note
/// evidence merged onto the instance row, and per-checkout HEAD merges
/// (full-row upsert carrying the discovery-persisted columns forward).
async fn persist_analysis(
    runner: &mut Runner,
    store: &TursoStore,
    instance_id: &str,
    instance_row: &store::GitInstanceRow,
    reads: AnalysisReads,
    path: &Path,
    now_ms: i64,
) -> repo_scan::Result<()> {
    // Ref-id rule: ids key on the canonical common dir, whose hex the
    // instance id already embeds (`git:{hex}`).
    let canonical_hex = instance_id
        .strip_prefix("git:")
        .map(str::to_string)
        .unwrap_or_else(|| config::encode_hex(&instance_row.common_path));
    let known: HashSet<&[u8]> = reads.refs.iter().map(|r| r.name.as_slice()).collect();
    // v6 comparison columns, once per store: pre-v6 catalogs skip
    // comparison writes (branches read `pending`/null there).
    let persist_comparison = store.supports_ref_comparison().await?;
    let mut branch_values = Vec::with_capacity(reads.refs.len());
    for reference in &reads.refs {
        let name_text = String::from_utf8_lossy(&reference.name);
        let kind = if name_text.starts_with("refs/heads/") {
            "local"
        } else if name_text.starts_with("refs/remotes/") {
            "remote_tracking"
        } else {
            "other"
        };
        let ref_id = format!(
            "ref:{}:{}",
            canonical_hex,
            config::encode_hex(&reference.name),
        );
        let (oid, algo, symbolic) = match &reference.target {
            git::RefTarget::Object(o) => (Some(o.hex.as_bytes()), Some(o.algorithm.as_str()), None),
            git::RefTarget::Symbolic(target) => {
                let (peeled_oid, peeled_algo) = reference
                    .peeled
                    .as_ref()
                    .map(|o| (Some(o.hex.as_bytes()), Some(o.algorithm.as_str())))
                    .unwrap_or((None, None));
                (peeled_oid, peeled_algo, Some(target.as_slice()))
            }
        };
        let upstream = upstream_for_ref(&reads.branch_upstreams, &reference.name);
        let state = ref_state_for(reference, &known);
        let new_ref = NewRef {
            id: &ref_id,
            instance_id,
            checkout_scope_id: None,
            kind,
            name: &reference.name,
            oid,
            algo,
            symbolic_target: symbolic,
            upstream: upstream.as_deref(),
            state,
        };
        let due = TursoStore::buffer_upsert_ref(&mut runner.batch, &new_ref, now_ms);
        flush_if_due(runner, store, due).await?;
        // Step 10 comparison label (local branches only; the map
        // holds no entry for other kinds).
        if persist_comparison {
            if let Some(comparison) = reads.comparisons.get(&reference.name) {
                let due = TursoStore::buffer_update_ref_comparison(
                    &mut runner.batch,
                    &ref_id,
                    comparison.state,
                    comparison.ahead,
                    comparison.behind,
                );
                flush_if_due(runner, store, due).await?;
            }
        }
        branch_values.push(branch_record_value(
            &ref_id,
            kind,
            &reference.name,
            oid,
            algo,
            symbolic,
            upstream.as_deref(),
            state,
        ));
    }
    // The ref rows above commit with these batches: one `branch_batch`
    // event per 500 refs, all sharing this observation's `rev`.
    if !branch_values.is_empty() {
        let chunks: Vec<&[serde_json::Value]> = branch_values.chunks(BRANCH_BATCH_CHUNK).collect();
        let batch_count = chunks.len();
        for (index, chunk) in chunks.iter().enumerate() {
            let records = branch_batch_records(instance_id, now_ms, index, batch_count, chunk)?;
            journal_branch_batch(runner, store, instance_id, &records).await?;
        }
    }
    for broken in &reads.ref_errors {
        let due = buffer_record_error(
            runner,
            &format!("ref-err:{instance_id}:{}", fnv1a_hex(broken.as_bytes())),
            &config::scope_key_for_git(path),
            "invalid-ref",
            broken,
            None,
            now_ms,
        )?;
        flush_if_due(runner, store, due).await?;
    }
    // Refs notes join the instance evidence (deduplicated: re-analysis
    // must not stack the same note every run).
    if !reads.refs_notes.is_empty() {
        let mut evidence: Vec<String> =
            serde_json::from_str(&instance_row.evidence_json).unwrap_or_default();
        for note in &reads.refs_notes {
            if !evidence.contains(note) {
                evidence.push(note.clone());
            }
        }
        let evidence_json = serde_json::to_string(&evidence)
            .map_err(|e| repo_scan::Error::Report(e.to_string()))?;
        store
            .connection()
            .execute(
                "UPDATE git_instances SET evidence = ?1 WHERE id = ?2",
                vec![
                    turso::Value::Text(evidence_json),
                    turso::Value::Text(instance_id.to_string()),
                ],
            )
            .await
            .map_err(store_err)?;
        runner.counters.db_transactions += 1;
    }
    // Per-checkout HEAD merge: discovery persisted the row (HEAD
    // `unknown`); analysis carries every column forward with fresh
    // HEAD observations.
    for (checkout_id, head) in &reads.heads {
        let Some(row) = store.get_checkout(checkout_id).await? else {
            continue;
        };
        let (head_state, head_ref, head_oid, head_algo) = head_columns(head);
        let merged = NewCheckout {
            id: &row.id,
            instance_id: &row.instance_id,
            root_path: row.root_path.as_deref(),
            git_path: &row.git_path,
            relationship: &row.relationship,
            availability: &row.availability,
            head_state,
            head_ref: head_ref.as_deref(),
            head_oid: head_oid.as_deref(),
            head_algo: head_algo.as_deref(),
        };
        let due = if row.root_path.is_none() {
            TursoStore::buffer_insert_checkout_if_absent(&mut runner.batch, &merged, now_ms)
        } else {
            TursoStore::buffer_upsert_checkout(&mut runner.batch, &merged, now_ms)
        };
        flush_if_due(runner, store, due).await?;
    }
    Ok(())
}

/// Inspect one matching checkout's working state at the requested mode.
/// `metadata` records a null-count observation without probing; `summary`
/// collapses untracked directories; `full` counts untracked files. Unknown
/// stays null — never zero, never clean. The blocking status call runs
/// under DURING-inspection identity polls plus the task wall budget
/// (XSEC-01 + SR-STATE-01): change or expiry discards the observation.
/// Catalog identity + observation window for one status task: resolved
/// by the writer before dispatch so the read half needs no catalog.
struct StatusTarget {
    checkout_id: String,
    instance_id: String,
    git_path: std::path::PathBuf,
    mode: StatusMode,
    now_ms: i64,
    observed_rev: u64,
}

/// Read-half outcome of one status task (Step 8 worker seam): full
/// observations plus every terminal mid-read condition, all as data.
/// The writer applies rows/gaps/retries via [`persist_status`].
enum StatusReadOutcome {
    Observed {
        started_ms: i64,
        finished_ms: i64,
        submodules: &'static str,
        observation: Option<git::StatusObservation>,
    },
    UnsupportedOpen {
        error: String,
    },
    OpenFailed {
        detail: String,
    },
    StatusFailed {
        detail: String,
    },
    LeaseRetry {
        detail: String,
    },
    Timeout {
        detail: String,
    },
    IdentityChanged,
    FenceChanged,
    Refused {
        state: TaskState,
        reason: String,
    },
    StatFailed(std::io::Error),
}

/// One status task's collected reads: target meta plus outcome.
struct StatusCollected {
    target: StatusTarget,
    outcome: StatusReadOutcome,
}

/// Read half of status ([`prepare_status`]/[`finish_status`]): fence verify, open, guarded blocking
/// status call, fallback counts, submodule coverage, and post-run
/// re-verification. Applies no catalog writes — lease renewal moved to
/// the coordinator's scheduled tick — so this runs synchronously on a
/// worker thread; the writer applies everything via [`persist_status`].
fn collect_status_reads(
    ctx: &ReadContext,
    target: &StatusTarget,
    deadline: &OpDeadline,
) -> repo_scan::Result<StatusCollected> {
    let git_path = &target.git_path;
    let mode = target.mode;
    // Status fence (pre-run): same verify-run-reverify envelope as probes.
    // Refusals park with a preserved gap; nothing is persisted.
    let schedule = ProbeSchedule::status_legacy();
    let pinned: Option<PinnedDir> =
        match verify_probe_path(ctx.fence.as_ref(), "status", git_path, &schedule) {
            ProbeFence::Unfenced => None,
            ProbeFence::Pinned(pinned) | ProbeFence::Relationship(pinned) => Some(pinned),
            ProbeFence::Refused { state, reason } => {
                return Ok(StatusCollected {
                    target: StatusTarget {
                        checkout_id: target.checkout_id.clone(),
                        instance_id: target.instance_id.clone(),
                        git_path: git_path.clone(),
                        mode,
                        now_ms: target.now_ms,
                        observed_rev: target.observed_rev,
                    },
                    outcome: StatusReadOutcome::Refused { state, reason },
                });
            }
            ProbeFence::StatFailed(e) => {
                return Ok(StatusCollected {
                    target: StatusTarget {
                        checkout_id: target.checkout_id.clone(),
                        instance_id: target.instance_id.clone(),
                        git_path: git_path.clone(),
                        mode,
                        now_ms: target.now_ms,
                        observed_rev: target.observed_rev,
                    },
                    outcome: StatusReadOutcome::StatFailed(e),
                });
            }
        };
    // The pin binds the execution (XSEC-01): Git runs between the
    // pre-run pin above and the DURING/post-run re-verification below, so a
    // path swapped mid-run discards every observation. Inspection keeps
    // the scheduling spelling, so persisted rows stay spelling-stable.
    let mut poll = IdentityPoll::new(ctx.fence.as_ref(), git_path, pinned.as_ref());
    let finish = |outcome: StatusReadOutcome| StatusCollected {
        target: StatusTarget {
            checkout_id: target.checkout_id.clone(),
            instance_id: target.instance_id.clone(),
            git_path: git_path.clone(),
            mode,
            now_ms: target.now_ms,
            observed_rev: target.observed_rev,
        },
        outcome,
    };
    let instance = match ctx.inspector.open_exact(git_path) {
        Ok(instance) => instance,
        Err(e) if git::is_unsupported_error(&e) => {
            return Ok(finish(StatusReadOutcome::UnsupportedOpen {
                error: e.to_string(),
            }));
        }
        Err(e) => {
            return Ok(finish(StatusReadOutcome::OpenFailed {
                detail: e.to_string(),
            }));
        }
    };
    // XSEC-01: the open is a read stage like any other — poll it.
    if !poll.ok_now() {
        return Ok(finish(StatusReadOutcome::IdentityChanged));
    }
    let started = store::now_ms();
    // R4: the blocking status call has no in-call yield point, so it runs
    // under the tighter of the wall budget and the lease window — the
    // coordinator's tick keeps the lease itself alive, while the guard
    // trips the interrupt at the window so a window-truncated call
    // retries instead of parking valid-but-slow work.
    let (call_ms, lease_bound) =
        lease_call_budget(deadline.remaining().as_millis().min(u128::from(u64::MAX)) as u64);
    let call_deadline = OpDeadline::new(Duration::from_millis(call_ms));
    // SR-STATE-01 + XSEC-01: the guard thread polls identity DURING the
    // blocking status call and trips the interrupt flag on change or
    // deadline. The flag is best-effort preemption; the checks after the
    // call are the guarantee — even if gix ignores the flag, an expired
    // or swapped observation never records.
    let guard = spawn_status_guard(
        ctx.fence.clone(),
        git_path.clone(),
        pinned.as_ref().map(snapshot_of),
        call_deadline,
    );
    let status_result =
        ctx.inspector
            .status_interruptible(&instance, mode, Some(guard.interrupt_flag()));
    let identity_changed = guard.finish();
    if identity_changed {
        return Ok(finish(StatusReadOutcome::IdentityChanged));
    }
    if deadline.expired() {
        return Ok(finish(StatusReadOutcome::Timeout {
            detail: format!(
                "timeout-abandoned: status of {} exceeded the {OP_DEADLINE_SECS}s execution budget; observation discarded",
                git_path.display()
            ),
        }));
    }
    if lease_bound && call_deadline.expired() {
        // R4: the lease window (not the wall budget) ended the call — the
        // observation is discarded and the scope retries. The coordinator
        // tick keeps the lease itself alive, so no reclaim or duplicate
        // is possible; parking here would strand valid-but-slow work.
        return Ok(finish(StatusReadOutcome::LeaseRetry {
            detail: format!(
                "status of {} exceeded its lease window; observation discarded",
                git_path.display()
            ),
        }));
    }
    if !poll.ok_now() {
        return Ok(finish(StatusReadOutcome::IdentityChanged));
    }
    let observation = match status_result {
        Ok(obs) => Some(obs),
        Err(e) if git::is_unsupported_error(&e) => {
            // RSF-FALLBACK-HELPER-SECURITY(5): fallback spawns inherit
            // the task deadline and SIGINT; cancellation ends even stuck
            // readers instead of hanging the status task.
            let task_deadline = *deadline;
            let cancel = git::fallback::WaitCancel::new(
                move || INTERRUPTED.load(Ordering::SeqCst) || task_deadline.expired(),
                None,
            );
            git::fallback::with_wait_cancel(&cancel, || {
                fallback_status_counts(ctx, &instance, mode, &e)
            })
        }
        Err(e) => {
            return Ok(finish(StatusReadOutcome::StatusFailed {
                detail: e.to_string(),
            }));
        }
    };
    let finished = store::now_ms();
    // Submodule coverage (R16): examined through the inspector alongside
    // the status probe — `checked` when the submodule relationships were
    // actually read, `unknown` when they could not be.
    let submodules = match ctx.inspector.submodules(&instance) {
        Ok(_) => "checked",
        Err(_) => "unknown",
    };
    // XSEC-01: one more read stage done — poll before recording.
    if !poll.ok_now() {
        return Ok(finish(StatusReadOutcome::IdentityChanged));
    }
    // R4: the pre-persist gate on the coordinator verifies the lease
    // before any status row is recorded — a lost lease discards the
    // observation and the scope retries instead of racing a completion.
    // Status fence (post-run): every Git read above is done; re-verify
    // identity before any status row is recorded. On mismatch the
    // observation is discarded and the scope parks. Relationship pins
    // re-verify through the unscoped descriptor walk.
    if let Some(pinned) = &pinned {
        let fence_ok = match ctx.fence.as_ref() {
            None => true,
            Some(fence) => fence.reverify_pinned(git_path, pinned),
        };
        if !fence_ok {
            return Ok(finish(StatusReadOutcome::FenceChanged));
        }
    }
    Ok(finish(StatusReadOutcome::Observed {
        started_ms: started,
        finished_ms: finished,
        submodules,
        observation,
    }))
}

/// Write half of status ([`finish_status`]): status rows, gaps, and retries for one
/// collected outcome. Runs on the single writer.
async fn persist_status(
    runner: &mut Runner,
    store: &TursoStore,
    claimed: &ClaimedTask,
    collected: StatusCollected,
) -> repo_scan::Result<TaskOutcome> {
    let target = &collected.target;
    match collected.outcome {
        StatusReadOutcome::Refused { state, reason } => Ok(TaskOutcome::Parked { state, reason }),
        StatusReadOutcome::StatFailed(e) => {
            fail_stat_open(runner, store, claimed, &target.git_path, &e).await
        }
        StatusReadOutcome::IdentityChanged => {
            Ok(park_on_identity_change("status", &target.git_path))
        }
        StatusReadOutcome::FenceChanged => Ok(TaskOutcome::Parked {
            state: TaskState::Unavailable,
            reason: format!(
                "status path {} changed during inspection; observations discarded",
                target.git_path.display()
            ),
        }),
        StatusReadOutcome::Timeout { detail } => Ok(park_on_timeout(&detail)),
        StatusReadOutcome::LeaseRetry { detail } => {
            retry_on_lease_lost(runner, store, claimed, &detail).await
        }
        StatusReadOutcome::OpenFailed { detail } => {
            fail_task(
                runner,
                store,
                claimed,
                ExecFail {
                    category: String::from("status-open-error"),
                    detail,
                },
            )
            .await
        }
        StatusReadOutcome::StatusFailed { detail } => {
            fail_task(
                runner,
                store,
                claimed,
                ExecFail {
                    category: String::from("status-error"),
                    detail,
                },
            )
            .await
        }
        StatusReadOutcome::UnsupportedOpen { error } => {
            let reason = format!(
                "status unsupported on {}: {error}",
                target.git_path.display()
            );
            record_status_row(
                runner,
                store,
                &target.checkout_id,
                &target.instance_id,
                target.mode,
                "unsupported",
                None,
                None,
                None,
                None,
                "unknown",
                status_units(target.mode),
                "unknown",
                &[error],
                target.now_ms,
                target.now_ms,
                target.observed_rev,
            )
            .await?;
            Ok(TaskOutcome::Parked {
                state: TaskState::Unsupported,
                reason,
            })
        }
        StatusReadOutcome::Observed {
            started_ms,
            finished_ms,
            submodules,
            observation,
        } => {
            let is_unsupported = observation.is_none();
            match observation {
                None => {
                    record_status_row(
                        runner,
                        store,
                        &target.checkout_id,
                        &target.instance_id,
                        target.mode,
                        "unsupported",
                        None,
                        None,
                        None,
                        None,
                        "unknown",
                        status_units(target.mode),
                        submodules,
                        &["status unsupported in both backends".to_string()],
                        started_ms,
                        finished_ms,
                        target.observed_rev,
                    )
                    .await?;
                }
                Some(obs) => {
                    let state = status_state_of(&obs);
                    let working_state = git::working_state_of(&obs);
                    record_status_row(
                        runner,
                        store,
                        &target.checkout_id,
                        &target.instance_id,
                        target.mode,
                        state,
                        obs.staged.map(|c| c.min(i64::MAX as u64) as i64),
                        obs.unstaged.map(|c| c.min(i64::MAX as u64) as i64),
                        obs.untracked.map(|c| c.min(i64::MAX as u64) as i64),
                        obs.conflicts.map(|c| c.min(i64::MAX as u64) as i64),
                        working_state,
                        status_units(target.mode),
                        submodules,
                        &obs.unknown_fields,
                        started_ms,
                        finished_ms,
                        target.observed_rev,
                    )
                    .await?;
                }
            }
            if is_unsupported {
                return Ok(TaskOutcome::Parked {
                    state: TaskState::Unsupported,
                    reason: format!(
                        "status unsupported on {}: status unsupported in both backends",
                        target.git_path.display()
                    ),
                });
            }
            Ok(TaskOutcome::Complete)
        }
    }
}

/// Coordinator half of one status task: scope decode, the checkout
/// catalog read, and the metadata-mode shortcut. The guarded Git
/// inspection runs on a pool thread ([`collect_status_reads`]); the
/// outcome is applied by [`finish_status`].
async fn prepare_status(
    runner: &mut Runner,
    store: &TursoStore,
    mode: StatusMode,
    claimed: &ClaimedTask,
    deadline: &OpDeadline,
) -> repo_scan::Result<(PrepExtra, PrepAction)> {
    let done = |outcome: TaskOutcome| (PrepExtra::Done, PrepAction::Done(outcome));
    let Some(config::ScopeRef::Status(checkout_id)) =
        config::parse_scope_key(&claimed.task.scope_key)
    else {
        return Ok(done(TaskOutcome::Parked {
            state: TaskState::Unsupported,
            reason: format!("malformed status scope key: {}", claimed.task.scope_key),
        }));
    };
    let now = store::now_ms();
    let Some(checkout) = store.get_checkout(&checkout_id).await? else {
        let due = buffer_record_error(
            runner,
            &format!("status:{checkout_id}"),
            &claimed.task.scope_key,
            "unknown-checkout",
            &format!("status task names unknown checkout {checkout_id}; dropping"),
            None,
            now,
        )?;
        flush_if_due(runner, store, due).await?;
        return Ok(done(TaskOutcome::Complete));
    };
    // Observation revision: the run revision would need threading through;
    // the current committed revision is the stable per-run key instead.
    let observed_rev = store.current_revision().await?;
    if mode == StatusMode::Metadata {
        record_status_row(
            runner,
            store,
            &checkout_id,
            &checkout.instance_id,
            mode,
            "not_requested",
            None,
            None,
            None,
            None,
            "unknown",
            "not_requested",
            "not_requested",
            &[],
            now,
            now,
            observed_rev,
        )
        .await?;
        return Ok(done(TaskOutcome::Complete));
    }
    let target = StatusTarget {
        checkout_id: checkout_id.clone(),
        instance_id: checkout.instance_id.clone(),
        // The worker fences this path: execute at the canonical
        // spelling so a symlinked checkout `.git` stays pinnable
        // (the row keeps the observed spelling; joins use the id).
        git_path: canonical_exec_path(&config::path_from_bytes(checkout.git_path.clone())),
        mode,
        now_ms: now,
        observed_rev,
    };
    let job = WorkerJob::Status {
        ctx: runner.read_context(),
        target,
        deadline: *deadline,
    };
    Ok((PrepExtra::Status, PrepAction::Spawn(job)))
}

/// Coordinator write half of one status task: applies a worker result
/// ([`StatusCollected`]) through the pre-persist lease gate and
/// [`persist_status`]. Returns the outcome plus the observation flag
/// for the watchdog verdict.
async fn finish_status(
    runner: &mut Runner,
    store: &TursoStore,
    claimed: &ClaimedTask,
    result: repo_scan::Result<WorkerOut>,
) -> repo_scan::Result<(TaskOutcome, u64)> {
    let collected = match result {
        Ok(WorkerOut::Status(collected)) => collected,
        Ok(_) => {
            return Err(repo_scan::Error::Scheduler(String::from(
                "status finish received a non-status worker result",
            )));
        }
        Err(e) => return Err(e),
    };
    let units = match &collected.outcome {
        StatusReadOutcome::Observed { .. } => 1,
        _ => 0,
    };
    // R4 heartbeat: re-verify the lease before the first buffered write —
    // a status stage may have consumed the window. Observations under a
    // lost lease are discarded and the scope retries with a fresh lease
    // (same pre-persist gate as probe/analysis/enumeration).
    if !renew_claim_lease(store, &mut runner.counters.db_transactions, claimed).await? {
        let outcome = retry_on_lease_lost(
            runner,
            store,
            claimed,
            &format!(
                "lease lost before persisting status of {}; observation discarded",
                collected.target.git_path.display()
            ),
        )
        .await?;
        return Ok((outcome, units));
    }
    let outcome = persist_status(runner, store, claimed, collected).await?;
    Ok((outcome, units))
}

fn status_units(mode: StatusMode) -> &'static str {
    match mode {
        StatusMode::Metadata => "not_requested",
        StatusMode::Summary => "collapsed_entries",
        StatusMode::Full => "files",
    }
}

/// Map a status observation to its report state (spec §9).
fn status_state_of(obs: &git::StatusObservation) -> &'static str {
    if obs.unknown_fields.iter().any(|f| f.contains("unstable")) {
        "unstable"
    } else if obs.unknown_fields.iter().any(|f| f.contains("no-worktree")) {
        "complete"
    } else if obs.unknown_fields.iter().any(|f| f.contains("truncat")) {
        "partial"
    } else {
        "complete"
    }
}

/// Installed-git status counts on structural gaps; `None` when no fallback
/// can serve the probe.
fn fallback_status_counts(
    ctx: &ReadContext,
    instance: &git::GitInstance,
    mode: StatusMode,
    cause: &repo_scan::Error,
) -> Option<git::StatusObservation> {
    let fallback = ctx.fallback()?;
    let (staged, unstaged, untracked, conflicts) = fallback
        .status_counts(
            &instance.git_dir,
            instance.work_dir.as_deref(),
            mode == StatusMode::Summary,
        )
        .ok()?;
    Some(git::StatusObservation {
        mode,
        staged: Some(staged),
        unstaged: Some(unstaged),
        untracked: Some(untracked),
        conflicts: Some(conflicts),
        // F-note1: the fallback spawn runs under the same empty
        // global/system config isolation as the gix path, so it carries
        // the same inspected-scope declaration.
        unknown_fields: vec![
            format!("counts via installed-git fallback ({cause})"),
            git::ISOLATED_SCOPE_DECLARATION.to_string(),
        ],
        fingerprints: Vec::new(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn record_status_row(
    runner: &mut Runner,
    store: &TursoStore,
    checkout_id: &str,
    store_id: &str,
    mode: StatusMode,
    state: &str,
    staged: Option<i64>,
    unstaged: Option<i64>,
    untracked: Option<i64>,
    conflicts: Option<i64>,
    working_state: &str,
    units: &str,
    submodules: &str,
    unknown_fields: &[String],
    started_ms: i64,
    finished_ms: i64,
    observed_rev: u64,
) -> repo_scan::Result<()> {
    let unknown_json = serde_json::to_string(unknown_fields)
        .map_err(|e| repo_scan::Error::Report(e.to_string()))?;
    // RSF-AC461500-609D-4D55-991E-09C60D382D67: buffered observation;
    // the task-end flush commits it before completion.
    let status = NewStatus {
        checkout_id,
        mode: status_mode_str(mode),
        state,
        started_ms: Some(started_ms),
        finished_ms: Some(finished_ms),
        staged,
        unstaged,
        untracked,
        conflicts,
        working_state,
        untracked_units: units,
        submodules,
        unknown_fields: &unknown_json,
        input_fingerprint: None,
        observed_rev,
    };
    let due = TursoStore::buffer_record_status(&mut runner.batch, &status, finished_ms);
    flush_if_due(runner, store, due).await?;
    // Same batch as the status row: the update is only readable once its
    // cause has committed.
    journal_location_updated(
        runner,
        store,
        checkout_id,
        store_id,
        status_mode_str(mode),
        state,
        staged,
        unstaged,
        untracked,
        observed_rev,
    )
    .await?;
    Ok(())
}

async fn count_open_errors(store: &TursoStore) -> repo_scan::Result<u64> {
    count_query(store, "SELECT COUNT(*) FROM errors WHERE open = 1", vec![]).await
}

async fn count_unresolvable(store: &TursoStore) -> repo_scan::Result<u64> {
    count_query(
        store,
        "SELECT COUNT(*) FROM git_instances WHERE disposition = 'unresolvable_identity'",
        vec![],
    )
    .await
}

async fn count_status_pending(store: &TursoStore, generation: u64) -> repo_scan::Result<u64> {
    count_query(
        store,
        "SELECT COUNT(*) FROM frontier_tasks WHERE generation = ?1 AND kind = 'status' \
         AND state NOT IN ('complete', 'cancelled', 'superseded')",
        vec![turso::Value::Integer(i64::try_from(generation).map_err(
            |_| repo_scan::Error::Store(format!("task generation {generation} exceeds i64 range")),
        )?)],
    )
    .await
}

async fn count_query(
    store: &TursoStore,
    sql: &str,
    params: Vec<turso::Value>,
) -> repo_scan::Result<u64> {
    let mut rows = store
        .connection()
        .query(sql, params)
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?;
    match rows
        .next()
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?
    {
        None => Ok(0),
        Some(row) => {
            let value = cell_int(&row, 0)?;
            u64::try_from(value).map_err(|_| {
                repo_scan::Error::Store(format!("count {value} in catalog is not a valid u64"))
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Report data loading
// ---------------------------------------------------------------------------

fn store_err(e: turso::Error) -> repo_scan::Error {
    repo_scan::Error::Store(e.to_string())
}

fn cell_text(row: &turso::Row, idx: usize) -> repo_scan::Result<String> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Text(value) => Ok(value),
        other => Err(repo_scan::Error::Store(format!(
            "column {idx} expected TEXT, got {other:?}"
        ))),
    }
}

fn cell_opt_text(row: &turso::Row, idx: usize) -> repo_scan::Result<Option<String>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Text(value) => Ok(Some(value)),
        turso::Value::Null => Ok(None),
        other => Err(repo_scan::Error::Store(format!(
            "column {idx} expected TEXT or NULL, got {other:?}"
        ))),
    }
}

fn cell_int(row: &turso::Row, idx: usize) -> repo_scan::Result<i64> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Integer(value) => Ok(value),
        other => Err(repo_scan::Error::Store(format!(
            "column {idx} expected INTEGER, got {other:?}"
        ))),
    }
}

fn cell_opt_int(row: &turso::Row, idx: usize) -> repo_scan::Result<Option<i64>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Null => Ok(None),
        turso::Value::Integer(value) => Ok(Some(value)),
        other => Err(repo_scan::Error::Store(format!(
            "column {idx} expected INTEGER or NULL, got {other:?}"
        ))),
    }
}

fn cell_blob(row: &turso::Row, idx: usize) -> repo_scan::Result<Vec<u8>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Blob(value) => Ok(value),
        other => Err(repo_scan::Error::Store(format!(
            "column {idx} expected BLOB, got {other:?}"
        ))),
    }
}

async fn count_dirs_complete(store: &TursoStore, generation: u64) -> repo_scan::Result<u64> {
    count_query(
        store,
        "SELECT COUNT(*) FROM dir_observations WHERE generation = ?1 AND completed = 1",
        vec![turso::Value::Integer(i64::try_from(generation).map_err(
            |_| repo_scan::Error::Store(format!("task generation {generation} exceeds i64 range")),
        )?)],
    )
    .await
}

// ---------------------------------------------------------------------------
// Report assembly through the tested lib path (R3)
// ---------------------------------------------------------------------------
//
// Scan/resume stage and publish exclusively through `report::builder` +
// `report::publish` (+ `report::stream` underneath): the same code the
// REPORT-01/02 suite exercises. The binary contributes only caller-owned
// sections (roots, aliases, storage links, candidates, artifacts) plus run
// accounting; every catalog-backed section streams row-by-row from one
// pinned revision with bounded memory, staging uses `create_new` sibling
// files with pre-rename revalidation, staged bytes are fsync'd, checksums
// stream, and prior reports require a nonempty `report_id`.

/// Per-root event cursors for the report (R5).
#[derive(Debug, Clone, Default)]
struct RootCursors {
    history_uuid: Option<String>,
    ingested: Option<String>,
    reconciled: Option<String>,
}

/// Scan-owned report inputs: run accounting plus caller-owned sections for
/// the lib builder. Catalog-backed sections stream straight from the store.
struct ScanReportInputs {
    scan_id: String,
    generation: u64,
    epoch: u64,
    target_raw: String,
    canonical: Option<String>,
    /// Full requested target set for report 1.1.0 (empty for `--all`).
    targets: Vec<repo_scan::report::model::ScanTarget>,
    scope_policy: String,
    scan_state: String,
    status_mode: StatusMode,
    started_ms: i64,
    finished_ms: i64,
    report_dest: Option<PathBuf>,
    roots: Vec<PlannedRoot>,
    counters: RunCounters,
    pending: u64,
    aliases: Vec<ObservedAlias>,
    /// Per-root event cursors, aligned with `roots` (R5).
    root_cursors: Vec<RootCursors>,
    /// Honest event-history boundary note (R5).
    event_note: String,
}

fn truncate_str(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars).collect();
    out.push('…');
    out
}

/// One open gap for candidate derivation.
struct OpenError {
    id: String,
    scope_key: String,
    category: String,
    detail: String,
    next_retry_ms: Option<i64>,
}

/// One page of open gaps, oldest first
/// (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1). Page bounds are
/// interpolated numerics (owner-controlled), never bound parameters:
/// the pinned engine needs no bound-`LIMIT` support. The defensive
/// length cap holds even if the engine ignored `LIMIT`.
async fn load_open_errors_page(
    store: &TursoStore,
    limit: i64,
    offset: i64,
) -> repo_scan::Result<Vec<OpenError>> {
    let limit = limit.max(1);
    let offset = offset.max(0);
    let sql = format!(
        "SELECT id, scope_key, category, detail, next_retry_ms FROM errors \
         WHERE open = 1 ORDER BY id ASC LIMIT {limit} OFFSET {offset}"
    );
    let mut rows = store
        .connection()
        .query(sql.as_str(), ())
        .await
        .map_err(store_err)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        out.push(OpenError {
            id: cell_text(&row, 0)?,
            scope_key: cell_text(&row, 1)?,
            category: cell_text(&row, 2)?,
            detail: cell_text(&row, 3)?,
            next_retry_ms: cell_opt_int(&row, 4)?,
        });
        if out.len() as i64 >= limit {
            break;
        }
    }
    Ok(out)
}

/// Report derivations over every open gap
/// (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1): the scan holds one page
/// from the database cursor at a time and retains only report-required
/// derived records (probe candidates, per-root error ids). The lib path
/// still streams every gap into the report (no cap), so `coverage.gaps`
/// agrees with the emitted records; nothing is dropped to fit memory.
/// Scan accounting (`scanned`/`chunks`/`peak_chunk`) is surfaced to the
/// regression hooks; production consumes only the derived records.
/// Aggregate bounds for report-derivation accumulators (SR-STATE-03): one
/// SQL page is small, but the derived vectors below once retained every
/// row of their tables. Past a cap (or under memory pressure) the scan
/// stops, records an explicit gap row, and leaves the remaining rows open
/// in the catalog for a later pass — the report stays bounded and honest.
#[derive(Debug, Clone, Copy)]
pub struct DerivationCaps {
    /// Maximum derived error candidates retained.
    pub max_error_candidates: usize,
    /// Maximum per-root error ids retained, summed over all roots.
    pub max_root_error_ids: usize,
    /// Maximum derived instance candidates retained.
    pub max_instance_candidates: usize,
    /// Maximum storage edges retained.
    pub max_storage_links: usize,
    /// Maximum common-path hubs retained.
    pub max_first_common: usize,
}

impl DerivationCaps {
    /// Production bounds: thousands of derived records (single-digit MiB),
    /// matching the run's other aggregate caps (`MAX_ALIASES`).
    pub const fn default_caps() -> Self {
        Self {
            max_error_candidates: 4096,
            max_root_error_ids: 16384,
            max_instance_candidates: 4096,
            max_storage_links: 16384,
            max_first_common: 16384,
        }
    }
}

#[allow(dead_code)]
pub struct ErrorDerivations {
    pub candidates: Vec<CandidateInput>,
    /// Per-root error ids, aligned with the requested `root_scopes`.
    pub root_error_ids: Vec<Vec<String>>,
    pub scanned: u64,
    pub chunks: u64,
    pub peak_chunk: usize,
    /// True when the scan stopped early (cap or pressure); the gap row
    /// named in `trunc_detail` carries the resume evidence.
    pub truncated: bool,
    /// Truncation detail (empty unless `truncated`).
    pub trunc_detail: String,
}

pub async fn scan_error_derivations(
    store: &TursoStore,
    root_scopes: &[String],
    caps: &DerivationCaps,
) -> repo_scan::Result<ErrorDerivations> {
    let mut out = ErrorDerivations {
        candidates: Vec::new(),
        root_error_ids: vec![Vec::new(); root_scopes.len()],
        scanned: 0,
        chunks: 0,
        peak_chunk: 0,
        truncated: false,
        trunc_detail: String::new(),
    };
    // Pressure backstop (SR-STATE-03): sample the aggregate footprint per
    // page against the spec §5 threshold (`Config::load` always installs
    // `ResourceLimits::default`, so this is the effective threshold).
    let sampler = FootprintSampler::new();
    let pressure_at = config::ResourceLimits::default().pressure_threshold_bytes;
    let mut root_id_total: usize = 0;
    let mut offset: i64 = 0;
    loop {
        let chunk = load_open_errors_page(store, LOAD_CHUNK_ROWS, offset).await?;
        if chunk.is_empty() {
            break;
        }
        out.chunks += 1;
        out.peak_chunk = out.peak_chunk.max(chunk.len());
        for error in &chunk {
            if out.candidates.len() >= caps.max_error_candidates
                || root_id_total >= caps.max_root_error_ids
            {
                out.truncated = true;
                out.trunc_detail = format!(
                    "error derivations stopped: {} candidates (cap {}) and {} root error ids \
                     (cap {}) after {} scanned rows; remaining rows stay open for a later pass",
                    out.candidates.len(),
                    caps.max_error_candidates,
                    root_id_total,
                    caps.max_root_error_ids,
                    out.scanned,
                );
                break;
            }
            out.scanned += 1;
            push_error_candidate(&mut out.candidates, error);
            for (n, scope) in root_scopes.iter().enumerate() {
                if error.scope_key == *scope {
                    out.root_error_ids[n].push(error.id.clone());
                    root_id_total += 1;
                }
            }
        }
        if out.truncated {
            break;
        }
        let pressured = sampler
            .sample_with(&SamplerInputs {
                helpers_rss_bytes: Some(0),
                ..SamplerInputs::default()
            })
            .aggregate_rss_bytes
            > pressure_at;
        if pressured {
            out.truncated = true;
            out.trunc_detail = format!(
                "error derivations stopped under memory pressure after {} scanned rows; \
                 remaining rows stay open for a later pass",
                out.scanned,
            );
            break;
        }
        if chunk.len() as i64 >= LOAD_CHUNK_ROWS {
            offset += chunk.len() as i64;
        } else {
            break;
        }
    }
    if out.truncated {
        // Stable gap id: repeated truncated runs refresh one row instead
        // of growing the table (attempts count the truncations). The gap
        // streams into the report's errors section with the resume note.
        store
            .record_error(
                "gap:report-derivation:errors",
                "gap:report-derivation",
                "report-derivation-truncated",
                &out.trunc_detail,
                None,
                store::now_ms(),
            )
            .await?;
        eprintln!("repo-scan: {}", out.trunc_detail);
    }
    Ok(out)
}

/// One gap's candidate contribution, if it is a failed/unsupported probe.
/// Pure coverage gaps (permission, symlink, status) are errors, not
/// candidates.
fn push_error_candidate(out: &mut Vec<CandidateInput>, error: &OpenError) {
    let disposition = match error.category.as_str() {
        "probe-failed" => "probe_failed",
        "unsupported-git-format" => "unsupported",
        _ => return,
    };
    let Some(path) = scope_path(&error.scope_key) else {
        return;
    };
    out.push(CandidateInput {
        id: format!("cand-err:{}", error.id),
        path_bytes: config::path_as_bytes(&path),
        repository_id: None,
        disposition: disposition.to_string(),
        reason: truncate_str(&error.detail, 512),
        retry_after_ms: error.next_retry_ms,
        error_ids: vec![error.id.clone()],
    });
}

/// One report-subject instance (matches the lib builder's own subject
/// filter: everything but `nonmatch`).
struct EmittedInstance {
    id: String,
    git_path: Vec<u8>,
    common_path: Vec<u8>,
    disposition: String,
    object_format: String,
}

/// Per-operation timeout for fetch-phase git spawns (Step 11:
/// bounded network operations; the spawn envelope group-kills past
/// it, and the SIGINT-aware cancel scope ends even stuck readers).
const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
/// Captured-bytes cap for `git fetch` stderr (fetch can be chatty on
/// large updates; past the cap the child is killed and the attempt
/// fails instead of using partial output).
const FETCH_CAPTURE_CAP: u64 = 1024 * 1024;
/// Emitted-instance page size for the fetch phase (one row per store:
/// instance ids key on the canonical common dir).
const FETCH_PAGE: i64 = 64;

/// Fetch-phase outcome: per-remote terminal counts. `failed` feeds
/// exit 3 (unresolved gaps); `unsupported` is an examined terminal
/// state, not a gap; `interrupted` folds into exit 130.
#[derive(Default)]
struct FetchOutcome {
    refreshed: u64,
    failed: u64,
    unsupported: u64,
    skipped: u64,
    interrupted: bool,
}

/// One tracking ref to apply after a fetch (owned; crosses the
/// git-borrow/persist-borrow boundary inside `fetch_one_remote`).
struct FetchApply {
    name: Vec<u8>,
    oid: Vec<u8>,
    symref: Vec<u8>,
    /// `ref_state_for` rules over the post-fetch observation (this
    /// path has no peel data — for-each-ref gives symref targets
    /// only — and empty oids, i.e. broken refs, are `invalid`).
    state: &'static str,
    /// `current`|`stale` label; applied only when the upstream audit
    /// completed (`label == true` on the attempt).
    freshness: &'static str,
}

/// Owned outcome of the git half of one remote refresh: everything
/// the sync spawn section learned, before any catalog write.
struct GitAttempt {
    /// `success`|`failed`|`unsupported`.
    status: &'static str,
    /// Scrubbed detail (`None` on clean success).
    detail: Option<String>,
    duration_ms: Option<i64>,
    applies: Vec<FetchApply>,
    /// False when the upstream audit failed after a successful fetch:
    /// oids are re-observed but no ref is labeled `current`.
    label: bool,
    current: Vec<Vec<u8>>,
    deleted: Vec<Vec<u8>>,
    refs_updated: i64,
}

impl GitAttempt {
    fn failed(detail: String, duration_ms: i64) -> Self {
        Self {
            status: "failed",
            detail: Some(detail),
            duration_ms: Some(duration_ms),
            applies: Vec::new(),
            label: false,
            current: Vec::new(),
            deleted: Vec::new(),
            refs_updated: 0,
        }
    }

    fn unsupported(reason: String, duration_ms: Option<i64>) -> Self {
        Self {
            status: "unsupported",
            detail: Some(reason),
            duration_ms,
            applies: Vec::new(),
            label: false,
            current: Vec::new(),
            deleted: Vec::new(),
            refs_updated: 0,
        }
    }
}

/// Effective-fetch plan for one remote (sync git section).
enum FetchPlan {
    /// All configured refspecs verified safe: fetch may proceed.
    Ready(Vec<String>),
    /// Do not fetch; the reason records as an `unsupported` refresh.
    Unsupported(String),
}

/// Resolve + inspect one remote's effective fetch config (sync git
/// section; honors includes and worktree scope exactly as git
/// resolves them). `Err` = config unreadable, the attempt fails. A
/// remote absent from config yields zero refspecs (a `Ready` plan —
/// git itself then reports "no such remote" and the attempt fails
/// honestly).
fn plan_remote_fetch(
    git: &git::fallback::FallbackGit,
    dir: &Path,
    name: &str,
) -> Result<FetchPlan, String> {
    let fetch_key = format!("remote.{name}.fetch");
    let values = git.git_config_get_all(dir, std::ffi::OsStr::new(&fetch_key), FETCH_TIMEOUT)?;
    let mirror_key = format!("remote.{name}.mirror");
    let mirror_vals =
        git.git_config_get_all(dir, std::ffi::OsStr::new(&mirror_key), FETCH_TIMEOUT)?;
    // `git config --get-all` yields precedence order; the last value wins.
    let mirror = mirror_vals
        .last()
        .is_some_and(|v| git::refspec::config_bool_is_true(v));
    let mut refspecs = Vec::with_capacity(values.len());
    for value in &values {
        match std::str::from_utf8(value) {
            Ok(text) => refspecs.push(text.to_string()),
            Err(_) => {
                return Ok(FetchPlan::Unsupported(
                    "fetch refspec is not UTF-8: cannot verify destination".to_string(),
                ));
            }
        }
    }
    let borrowed: Vec<&str> = refspecs.iter().map(String::as_str).collect();
    match git::refspec::inspect_remote_fetch(&borrowed, mirror) {
        git::refspec::FetchVerdict::Safe => Ok(FetchPlan::Ready(refspecs)),
        git::refspec::FetchVerdict::Unsupported { reason } => Ok(FetchPlan::Unsupported(reason)),
    }
}

/// Run the fetch + post-fetch audit (sync git section; called only
/// for a `Ready` plan). Snapshot tracking refs, fetch, re-read,
/// audit upstream via ls-remote, then attribute each post-fetch
/// tracking ref through this remote's destination patterns
/// (`git::refspec::covered_by_positive` — never a
/// `refs/remotes/<name>/` prefix, which misses custom destinations
/// and trips on `origin`/`origin2` boundaries) and classify it.
/// Only covered refs
/// produce applies; another remote's refs are not our statement.
/// All fresh state returns owned; the caller persists. A failed
/// upstream audit after a successful fetch still re-observes oids
/// but labels nothing `current` (`label == false`, status `failed`
/// so resume retries the audit).
fn execute_remote_fetch(
    git: &git::fallback::FallbackGit,
    dir: &Path,
    name: &str,
    refspecs: &[String],
    started: Instant,
) -> GitAttempt {
    let elapsed_ms = || started.elapsed().as_millis().min(i64::MAX as u128) as i64;
    let pre = match git.git_remote_tracking_refs(dir, FETCH_TIMEOUT) {
        Ok(refs) => refs,
        Err(e) => {
            return GitAttempt::failed(
                format!(
                    "cannot read pre-fetch tracking refs: {}",
                    identity::scrub_text(&e)
                ),
                elapsed_ms(),
            );
        }
    };
    let pre_map: HashMap<&[u8], &[u8]> = pre
        .iter()
        .map(|t| (t.name.as_slice(), t.oid.as_slice()))
        .collect();
    if let Err(e) = git.git_fetch_remote(
        dir,
        std::ffi::OsStr::new(name),
        FETCH_TIMEOUT,
        FETCH_CAPTURE_CAP,
    ) {
        return GitAttempt::failed(identity::scrub_text(&e), elapsed_ms());
    }
    let post = match git.git_remote_tracking_refs(dir, FETCH_TIMEOUT) {
        Ok(refs) => refs,
        Err(e) => {
            return GitAttempt::failed(
                format!(
                    "fetch succeeded but post-fetch ref read failed: {}",
                    identity::scrub_text(&e)
                ),
                elapsed_ms(),
            );
        }
    };
    let mut attempt = GitAttempt {
        status: "success",
        detail: None,
        duration_ms: Some(elapsed_ms()),
        applies: Vec::new(),
        label: true,
        current: Vec::new(),
        deleted: Vec::new(),
        refs_updated: 0,
    };
    let upstream_set: HashSet<Vec<u8>> = match git.git_ls_remote_refs(
        dir,
        std::ffi::OsStr::new(name),
        FETCH_TIMEOUT,
    ) {
        Ok(names) => names.into_iter().collect(),
        Err(e) => {
            attempt.status = "failed";
            attempt.detail = Some(format!(
                "fetch succeeded but upstream audit failed: {}; oids re-observed, no ref labeled current",
                identity::scrub_text(&e)
            ));
            attempt.label = false;
            HashSet::new()
        }
    };
    // `Ready` implies every refspec parsed; re-parse infallibly.
    let parsed: Vec<git::refspec::FetchRefspec> = refspecs
        .iter()
        .filter_map(|s| git::refspec::parse_fetch_refspec(s))
        .collect();
    debug_assert_eq!(parsed.len(), refspecs.len());
    let known: HashSet<&[u8]> = post.iter().map(|t| t.name.as_slice()).collect();
    // This remote's default namespace: refs this fetch could never
    // cover but owns (narrowed refspecs) label `stale` per Step 11
    // ("keep excluded refs stale"); refs under ANOTHER remote's
    // namespace are that fetch's business and stay untouched, so a
    // later-or-earlier fetch cannot downgrade their labels.
    let own_exact = format!("refs/remotes/{name}");
    let own_prefix = format!("refs/remotes/{name}/");
    for observed in &post {
        if !git::refspec::covered_by_positive(&parsed, &observed.name) {
            let in_own = observed.name.as_slice() == own_exact.as_bytes()
                || observed.name.starts_with(own_prefix.as_bytes());
            if !in_own {
                continue;
            }
            // Excluded: oid re-observed but never counted (this fetch
            // did not move it) and labeled `stale`, never `current`.
            attempt.applies.push(FetchApply {
                name: observed.name.clone(),
                oid: observed.oid.clone(),
                symref: observed.symref.clone(),
                state: git::fallback::tracking_ref_state(observed, &known),
                freshness: "stale",
            });
            continue;
        }
        let freshness = if !attempt.label {
            "stale"
        } else {
            match git::refspec::classify_tracking_ref(
                &parsed,
                &parsed,
                &observed.name,
                &upstream_set,
            ) {
                git::refspec::TrackingVerdict::Current => {
                    attempt.current.push(observed.name.clone());
                    "current"
                }
                git::refspec::TrackingVerdict::DeletedUpstream => {
                    attempt.deleted.push(observed.name.clone());
                    "stale"
                }
                git::refspec::TrackingVerdict::Excluded => "stale",
            }
        };
        if pre_map.get(observed.name.as_slice()) != Some(&observed.oid.as_slice()) {
            attempt.refs_updated += 1;
        }
        attempt.applies.push(FetchApply {
            name: observed.name.clone(),
            oid: observed.oid.clone(),
            symref: observed.symref.clone(),
            state: git::fallback::tracking_ref_state(observed, &known),
            freshness,
        });
    }
    attempt.duration_ms = Some(elapsed_ms());
    attempt
}

/// Lossless name list, one `{name, name_hex}` record per name
/// mirroring branch records. Empty in, empty out.
fn name_list_values(names: &[Vec<u8>]) -> Vec<serde_json::Value> {
    names
        .iter()
        .map(|n| {
            serde_json::json!({
                "name": String::from_utf8_lossy(n),
                "name_hex": config::encode_hex(n),
            })
        })
        .collect()
}

/// Serialized name list for refresh records: `None` when empty.
fn name_list_json(values: &[serde_json::Value]) -> repo_scan::Result<Option<String>> {
    if values.is_empty() {
        return Ok(None);
    }
    serde_json::to_string(values)
        .map(Some)
        .map_err(|e| repo_scan::Error::Report(e.to_string()))
}

/// Persist one remote attempt: oid re-observations for covered refs
/// (UPDATE when the probe already recorded the ref — attribution
/// preserved — INSERT for fetch-created tracking branches), freshness
/// labels when the upstream audit completed, the refresh record, and
/// the `remote_updated` journal event. Ref + refresh writes buffer at
/// the batch limits; the journal emit commits immediately like
/// `inventory_ready`.
#[allow(clippy::too_many_arguments)]
async fn persist_remote_attempt(
    runner: &mut Runner,
    store: &TursoStore,
    instance_id: &str,
    common_path: &[u8],
    object_format: &str,
    remote_name: &[u8],
    existing_refs: &HashMap<Vec<u8>, String>,
    attempt: &GitAttempt,
    at_ms: i64,
) -> repo_scan::Result<()> {
    // Ref-id rule (analysis persist): ids key on the CANONICAL common
    // dir, while the instance row stores the raw observed spelling —
    // so recomputing an id from `common_path` mismatches on any
    // aliased path (e.g. /tmp -> /private/tmp) and the UPDATE hits
    // zero rows. Existing rows therefore update by their STORED id;
    // only fetch-created rows derive an id, from the canonical hex
    // already embedded in the instance id (`git:<hex>`).
    let canonical_hex = instance_id
        .strip_prefix("git:")
        .map(str::to_owned)
        .unwrap_or_else(|| config::encode_hex(common_path));
    for apply in &attempt.applies {
        // Stored id for existing rows; canonical-derived id for rows
        // this fetch creates. Both arms bind `ref_id` for the label
        // below.
        let created_id;
        let ref_id = if let Some(stored) = existing_refs.get(&apply.name) {
            let due =
                TursoStore::buffer_update_ref_oid(&mut runner.batch, stored, &apply.oid, at_ms);
            flush_if_due(runner, store, due).await?;
            stored.as_str()
        } else {
            // Fetch-created tracking branch: insert the row this
            // observation justifies (store algo from the instance;
            // tracking refs never carry an upstream).
            created_id = format!("ref:{}:{}", canonical_hex, config::encode_hex(&apply.name),);
            let oid_opt = (!apply.oid.is_empty()).then_some(apply.oid.as_slice());
            let new_ref = NewRef {
                id: &created_id,
                instance_id,
                checkout_scope_id: None,
                kind: "remote_tracking",
                name: &apply.name,
                oid: oid_opt,
                algo: oid_opt.map(|_| object_format),
                symbolic_target: (!apply.symref.is_empty()).then_some(apply.symref.as_slice()),
                upstream: None,
                state: apply.state,
            };
            let due = TursoStore::buffer_upsert_ref(&mut runner.batch, &new_ref, at_ms);
            flush_if_due(runner, store, due).await?;
            created_id.as_str()
        };
        if attempt.label {
            let due = TursoStore::buffer_label_ref_freshness(
                &mut runner.batch,
                ref_id,
                apply.freshness,
                at_ms,
            );
            flush_if_due(runner, store, due).await?;
        }
    }
    let current_values = name_list_values(&attempt.current);
    let deleted_values = name_list_values(&attempt.deleted);
    let current_json = name_list_json(&current_values)?;
    let deleted_json = name_list_json(&deleted_values)?;
    let refresh = NewRemoteRefresh {
        store_id: instance_id,
        remote_name,
        status: attempt.status,
        observed_at_ms: at_ms,
        duration_ms: attempt.duration_ms,
        refs_updated: attempt.refs_updated,
        refs_current_json: current_json.as_deref(),
        refs_deleted_json: deleted_json.as_deref(),
        detail: attempt.detail.as_deref(),
    };
    let due = TursoStore::buffer_record_remote_refresh(&mut runner.batch, &refresh);
    flush_if_due(runner, store, due).await?;
    if let Some(journal) = runner.journal.as_mut() {
        let payload = serde_json::json!({
            "store_id": instance_id,
            "rev": at_ms,
            "remote": String::from_utf8_lossy(remote_name),
            "remote_hex": config::encode_hex(remote_name),
            "status": attempt.status,
            "refs_updated": attempt.refs_updated,
            "current": current_values,
            "deleted": deleted_values,
            "detail": attempt.detail,
        });
        journal
            .emit(store, EventType::RemoteUpdated, &payload)
            .await?;
        runner.counters.db_transactions += 1;
    }
    Ok(())
}

/// Refresh one store+remote: resume-skip, config plan, fetch+audit,
/// persist. All git spawns run inside the `with_wait_cancel` scope
/// (SIGINT-aware) while the `FallbackGit` borrow is live; the borrow
/// ends before any `&mut runner` persist below (NLL), so gathering
/// never overlaps mutation.
#[allow(clippy::too_many_arguments)]
async fn fetch_one_remote(
    runner: &mut Runner,
    store: &TursoStore,
    cancel: &git::fallback::WaitCancel,
    inst: &EmittedInstance,
    remote_name: &[u8],
    existing_refs: &HashMap<Vec<u8>, String>,
    started_ms: i64,
    outcome: &mut FetchOutcome,
) -> repo_scan::Result<()> {
    // Resume: a `success` recorded during this scan is completed work,
    // never repeated. `failed` retries; `unsupported` re-verdicts
    // (re-inspection is local-only and config may have changed).
    if let Some(prev) = store.get_remote_refresh(&inst.id, remote_name).await? {
        if prev.status == "success" && prev.observed_at_ms >= started_ms {
            outcome.skipped += 1;
            return Ok(());
        }
    }
    // Config keys are built from the remote name; a non-UTF-8 name
    // cannot resolve effective config. Fail closed (never lossy: a
    // lossy key could read ANOTHER remote's refspecs and misattribute
    // the safety verdict).
    let name_str = match std::str::from_utf8(remote_name) {
        Ok(name) => name,
        Err(_) => {
            let attempt = GitAttempt::unsupported(
                "remote name is not UTF-8: cannot resolve effective fetch config".to_string(),
                None,
            );
            persist_remote_attempt(
                runner,
                store,
                &inst.id,
                &inst.common_path,
                &inst.object_format,
                remote_name,
                existing_refs,
                &attempt,
                store::now_ms(),
            )
            .await?;
            outcome.unsupported += 1;
            return Ok(());
        }
    };
    if runner.fallback().is_none() {
        let attempt =
            GitAttempt::unsupported("installed git unavailable: cannot fetch".to_string(), None);
        persist_remote_attempt(
            runner,
            store,
            &inst.id,
            &inst.common_path,
            &inst.object_format,
            remote_name,
            existing_refs,
            &attempt,
            store::now_ms(),
        )
        .await?;
        outcome.unsupported += 1;
        return Ok(());
    }
    let attempt: GitAttempt = {
        // Checked above; `fallback()` caches, so this never re-probes.
        let git = runner.fallback().expect("installed git checked above");
        let dir = config::path_from_bytes(inst.common_path.clone());
        git::fallback::with_wait_cancel(cancel, || {
            let started = Instant::now();
            let elapsed_ms = || started.elapsed().as_millis().min(i64::MAX as u128) as i64;
            match plan_remote_fetch(git, &dir, name_str) {
                Err(e) => GitAttempt::failed(
                    format!(
                        "cannot read effective fetch config: {}",
                        identity::scrub_text(&e)
                    ),
                    elapsed_ms(),
                ),
                Ok(FetchPlan::Unsupported(reason)) => {
                    GitAttempt::unsupported(reason, Some(elapsed_ms()))
                }
                Ok(FetchPlan::Ready(refspecs)) => {
                    execute_remote_fetch(git, &dir, name_str, &refspecs, started)
                }
            }
        })
    };
    persist_remote_attempt(
        runner,
        store,
        &inst.id,
        &inst.common_path,
        &inst.object_format,
        remote_name,
        existing_refs,
        &attempt,
        store::now_ms(),
    )
    .await?;
    match attempt.status {
        "success" => outcome.refreshed += 1,
        "failed" => outcome.failed += 1,
        _ => outcome.unsupported += 1,
    }
    Ok(())
}

/// Refresh every fetch-role remote of one store. Push-only remotes
/// have no fetch mapping and are never fetched; a store with no
/// fetch-role remote records nothing (not necessary per Step 11).
async fn fetch_one_store(
    runner: &mut Runner,
    store: &TursoStore,
    cancel: &git::fallback::WaitCancel,
    inst: &EmittedInstance,
    started_ms: i64,
    outcome: &mut FetchOutcome,
) -> repo_scan::Result<()> {
    let remotes = store.list_remotes(&inst.id).await?;
    if !remotes.iter().any(|r| r.role == "fetch") {
        return Ok(());
    }
    // One ref read per fetched store: name -> STORED row id.
    // Existing rows take the UPDATE path by stored id (never a
    // recomputed id: the instance row keeps the raw path spelling
    // while ids key on the canonical dir), fetch-created tracking
    // branches take the INSERT path.
    let refs = store.list_refs(&inst.id).await?;
    let existing: HashMap<Vec<u8>, String> = refs.into_iter().map(|r| (r.name, r.id)).collect();
    for remote in remotes.iter().filter(|r| r.role == "fetch") {
        if interrupted() {
            outcome.interrupted = true;
            return Ok(());
        }
        fetch_one_remote(
            runner,
            store,
            cancel,
            inst,
            &remote.name,
            &existing,
            started_ms,
            outcome,
        )
        .await?;
    }
    Ok(())
}

/// Optional `--fetch` phase (goal Step 11): runs after the
/// `inventory_ready` boundary and local analysis, before report
/// staging, so staged reports include freshness. One pass over
/// emitted stores (instance ids key on the canonical common dir, so
/// one row is one store — linked worktrees never refetch); per
/// fetch-role remote: resolve + inspect effective refspecs, fetch on
/// `Safe`, audit via ls-remote, re-observe oids, label freshness,
/// record + journal. Sequential: one network operation at a time
/// (N=1 bounded worker); every spawn carries `FETCH_TIMEOUT` plus
/// the SIGINT-aware cancel scope, and `interrupted()` is polled
/// between stores and remotes. Comparison recompute after fetch is a
/// no-op: comparisons persist from the analysis pass
/// (`compute_branch_comparisons`) and fetch does not refresh them,
/// so freshness labels plus re-observed oids ARE the fetch output.
/// A post-fetch comparison may read stale until the next analysis.
async fn run_fetch_phase(
    runner: &mut Runner,
    store: &TursoStore,
    started_ms: i64,
) -> repo_scan::Result<FetchOutcome> {
    let mut outcome = FetchOutcome::default();
    let cancel = git::fallback::WaitCancel::new(|| INTERRUPTED.load(Ordering::SeqCst), None);
    let mut offset = 0i64;
    loop {
        if interrupted() {
            outcome.interrupted = true;
            break;
        }
        let page = load_emitted_instances_page(store, FETCH_PAGE, offset).await?;
        if page.is_empty() {
            break;
        }
        offset += page.len() as i64;
        for inst in &page {
            if interrupted() {
                outcome.interrupted = true;
                break;
            }
            fetch_one_store(runner, store, &cancel, inst, started_ms, &mut outcome).await?;
        }
        if outcome.interrupted {
            break;
        }
    }
    flush_runner_batch(runner, store).await?;
    Ok(outcome)
}

/// One page of report-subject instances
/// (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1): everything but
/// `nonmatch`, id-ascending, with the same interpolated-bounds contract
/// as [`load_open_errors_page`].
async fn load_emitted_instances_page(
    store: &TursoStore,
    limit: i64,
    offset: i64,
) -> repo_scan::Result<Vec<EmittedInstance>> {
    let limit = limit.max(1);
    let offset = offset.max(0);
    let sql = format!(
        "SELECT id, git_path, common_path, disposition, object_format FROM git_instances \
         WHERE disposition != 'nonmatch' ORDER BY id ASC LIMIT {limit} OFFSET {offset}"
    );
    let mut rows = store
        .connection()
        .query(sql.as_str(), ())
        .await
        .map_err(store_err)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        out.push(EmittedInstance {
            id: cell_text(&row, 0)?,
            git_path: cell_blob(&row, 1)?,
            common_path: cell_blob(&row, 2)?,
            disposition: cell_text(&row, 3)?,
            object_format: cell_text(&row, 4)?,
        });
        if out.len() as i64 >= limit {
            break;
        }
    }
    Ok(out)
}

/// Report derivations over every emitted instance
/// (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1): one page in flight at a
/// time; only report-required derived records (unresolvable candidates,
/// storage edges) accumulate. Scan accounting is hook-surfaced (see
/// [`ErrorDerivations`]).
#[allow(dead_code)]
pub struct InstanceDerivations {
    pub candidates: Vec<CandidateInput>,
    pub storage_links: Vec<StorageLinkInput>,
    pub scanned: u64,
    pub chunks: u64,
    pub peak_chunk: usize,
    /// True when the scan stopped early (cap or pressure); the gap row
    /// named in `trunc_detail` carries the resume evidence.
    pub truncated: bool,
    /// Truncation detail (empty unless `truncated`).
    pub trunc_detail: String,
}

pub async fn scan_instance_derivations(
    store: &TursoStore,
    caps: &DerivationCaps,
) -> repo_scan::Result<InstanceDerivations> {
    let mut out = InstanceDerivations {
        candidates: Vec::new(),
        storage_links: Vec::new(),
        scanned: 0,
        chunks: 0,
        peak_chunk: 0,
        truncated: false,
        trunc_detail: String::new(),
    };
    // First instance id per common path (the shared-store hub). Chunk
    // order is id-ascending, so the hub is the same lowest id the old
    // whole-load group-and-sort produced.
    let mut first_common: HashMap<Vec<u8>, String> = HashMap::new();
    // Pressure backstop (SR-STATE-03): same spec §5 threshold as the error
    // scan above; `Config::load` always installs the default limits.
    let sampler = FootprintSampler::new();
    let pressure_at = config::ResourceLimits::default().pressure_threshold_bytes;
    let mut offset: i64 = 0;
    loop {
        let chunk = load_emitted_instances_page(store, LOAD_CHUNK_ROWS, offset).await?;
        if chunk.is_empty() {
            break;
        }
        out.chunks += 1;
        out.peak_chunk = out.peak_chunk.max(chunk.len());
        for instance in &chunk {
            // Checked per row, before this instance's links: one instance
            // can add a bounded handful of edges, so the overshoot past
            // the cap is at most one instance's contribution.
            if out.candidates.len() >= caps.max_instance_candidates
                || out.storage_links.len() >= caps.max_storage_links
                || first_common.len() >= caps.max_first_common
            {
                out.truncated = true;
                out.trunc_detail = format!(
                    "instance derivations stopped: {} candidates (cap {}), {} storage links \
                     (cap {}), {} common hubs (cap {}) after {} scanned rows; remaining rows \
                     stay open for a later pass",
                    out.candidates.len(),
                    caps.max_instance_candidates,
                    out.storage_links.len(),
                    caps.max_storage_links,
                    first_common.len(),
                    caps.max_first_common,
                    out.scanned,
                );
                break;
            }
            out.scanned += 1;
            if instance.disposition == "unresolvable_identity" {
                out.candidates.push(CandidateInput {
                    id: format!("cand:{}", instance.id),
                    path_bytes: instance.git_path.clone(),
                    repository_id: Some(instance.id.clone()),
                    disposition: String::from("unresolvable_identity"),
                    reason: String::from(
                        "identifying remotes removed or uninterpretable under the matching policy; \
                         see repository evidence",
                    ),
                    retry_after_ms: None,
                    error_ids: Vec::new(),
                });
            }
            push_instance_links(&mut out.storage_links, &mut first_common, instance);
        }
        if out.truncated {
            break;
        }
        let pressured = sampler
            .sample_with(&SamplerInputs {
                helpers_rss_bytes: Some(0),
                ..SamplerInputs::default()
            })
            .aggregate_rss_bytes
            > pressure_at;
        if pressured {
            out.truncated = true;
            out.trunc_detail = format!(
                "instance derivations stopped under memory pressure after {} scanned rows; \
                 remaining rows stay open for a later pass",
                out.scanned,
            );
            break;
        }
        if chunk.len() as i64 >= LOAD_CHUNK_ROWS {
            offset += chunk.len() as i64;
        } else {
            break;
        }
    }
    if out.truncated {
        // Stable gap id (see the error scan above).
        store
            .record_error(
                "gap:report-derivation:instances",
                "gap:report-derivation",
                "report-derivation-truncated",
                &out.trunc_detail,
                None,
                store::now_ms(),
            )
            .await?;
        eprintln!("repo-scan: {}", out.trunc_detail);
    }
    Ok(out)
}

/// One instance's storage-edge contributions: common-directory
/// relationships, borrowed object stores (alternates), shared common
/// storage, and observed hard-link sharing (R16).
fn push_instance_links(
    out: &mut Vec<StorageLinkInput>,
    first_common: &mut HashMap<Vec<u8>, String>,
    instance: &EmittedInstance,
) {
    if instance.common_path != instance.git_path {
        out.push(StorageLinkInput {
            id: format!("link:{}:common", instance.id),
            from_repository_id: instance.id.clone(),
            to_path_bytes: instance.common_path.clone(),
            kind: String::from("common_directory"),
            evidence: vec![String::from("common directory differs from git directory")],
        });
    }
    for (n, target) in alternates_targets(&instance.git_path).iter().enumerate() {
        out.push(StorageLinkInput {
            id: format!("link:{}:alt:{n}", instance.id),
            from_repository_id: instance.id.clone(),
            to_path_bytes: target.clone(),
            kind: String::from("alternate_objects"),
            evidence: vec![format!(
                "borrows object store: {}",
                String::from_utf8_lossy(target)
            )],
        });
    }
    match first_common.entry(instance.common_path.clone()) {
        std::collections::hash_map::Entry::Vacant(hub) => {
            hub.insert(instance.id.clone());
        }
        std::collections::hash_map::Entry::Occupied(hub) => {
            let first = hub.get().clone();
            out.push(StorageLinkInput {
                id: format!("link:{}:shared", instance.id),
                from_repository_id: instance.id.clone(),
                to_path_bytes: instance.common_path.clone(),
                kind: String::from("shared_object_store"),
                evidence: vec![format!("shares common storage with {first}")],
            });
        }
    }
    if let Some(object) = first_hardlinked_object(&instance.git_path) {
        out.push(StorageLinkInput {
            id: format!("link:{}:hardlink", instance.id),
            from_repository_id: instance.id.clone(),
            to_path_bytes: object,
            kind: String::from("observed_hardlink"),
            evidence: vec![String::from(
                "object file has multiple hard links; store shared, not copied",
            )],
        });
    }
}

async fn load_volume_ids(store: &TursoStore) -> repo_scan::Result<HashSet<String>> {
    let mut rows = store
        .connection()
        .query("SELECT id FROM volumes", ())
        .await
        .map_err(store_err)?;
    let mut out = HashSet::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        out.insert(cell_text(&row, 0)?);
    }
    Ok(out)
}

/// Assemble the lib builder inputs from run accounting plus small
/// caller-owned sections.
async fn build_lib_inputs(
    store: &TursoStore,
    inputs: &ScanReportInputs,
    report_id: &str,
    catalog_rev: u64,
    dirs_complete: u64,
    snapshot_path: &Path,
) -> repo_scan::Result<LibReportInputs> {
    // RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1: bounded chunked
    // derivation scans — one page in flight, report-required records only.
    let root_scopes: Vec<String> = inputs
        .roots
        .iter()
        .map(|root| config::scope_key_for_dir(&root.path))
        .collect();
    // SR-STATE-03: bounded derivation scans — aggregate caps plus
    // per-page pressure sampling; truncation records a gap row and leaves
    // the remaining rows open for a later pass.
    let errors =
        scan_error_derivations(store, &root_scopes, &DerivationCaps::default_caps()).await?;
    let instances = scan_instance_derivations(store, &DerivationCaps::default_caps()).await?;
    let volumes = load_volume_ids(store).await?;
    let mut boundaries = Vec::new();
    if inputs.scope_policy == "roots" {
        boundaries.push(format!(
            "Only {} explicit root(s) were requested; machine scope was not scanned.",
            inputs.roots.len(),
        ));
    } else {
        boundaries.push(String::from(
            "Machine scope: seed locations plus all mount-table roots attempted.",
        ));
    }
    boundaries.push(String::from(
        "Unexposed VM/container filesystems are out of scope.",
    ));
    boundaries.push(inputs.event_note.clone());
    // Coverage claims derive from emitted records inside the builder
    // (RSP-008): an override must restate row truth, and the run-boundary
    // task accounting (R3: `status_pending`) is not row truth — an
    // emitted checkout with no status row (bare store, unresolvable
    // identity with no required probe) refutes a "complete" claim and
    // the builder refuses the publication. So no override is passed:
    // required-status accounting stays task-based where it belongs (the
    // scheduler boundary, scan state, and exit code), while
    // `coverage.status` reports what the records support.
    let mut artifacts = vec![ArtifactInput {
        path_bytes: config::path_as_bytes(snapshot_path),
        kind: String::from("tool_state"),
        created_after_status: true,
    }];
    if let Some(report) = &inputs.report_dest {
        artifacts.push(ArtifactInput {
            path_bytes: config::path_as_bytes(report),
            kind: String::from("report"),
            created_after_status: true,
        });
    }
    Ok(LibReportInputs {
        report_id: report_id.to_string(),
        created_at_ms: inputs.finished_ms,
        scan_id: inputs.scan_id.clone(),
        generation: inputs.generation,
        epoch: inputs.epoch,
        catalog_revision: catalog_rev,
        // Defense-in-depth (RSF-SEC-TARGET-URL): the report's `Scan.target_url`
        // never carries credentials even if a legacy stored target did.
        // Strict form (RETEST-2): opaque query/fragment tails drop too.
        target_url: identity::redact_remote_url(&inputs.target_raw),
        canonical_url: inputs.canonical.clone(),
        targets: inputs.targets.clone(),
        scope: inputs.scope_policy.clone(),
        scan_state: inputs.scan_state.clone(),
        started_at_ms: inputs.started_ms,
        finished_at_ms: Some(inputs.finished_ms),
        superseded_by: None,
        cached: false,
        status_mode: inputs.status_mode,
        directories_complete: dirs_complete,
        tasks_pending: inputs.pending,
        scope_boundaries: boundaries,
        profile: String::from("conservative"),
        cpu_target_cores: 1.0,
        rss_target_bytes: 268435456,
        // RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1: measured run-loop
        // telemetry — never None-after-run.
        peak_rss_bytes: Some(inputs.counters.peak_rss_bytes),
        cpu_seconds: Some(inputs.counters.cpu_seconds),
        enumerated_entries: inputs.counters.entries,
        db_transactions: inputs.counters.db_transactions,
        db_sync_calls: Some(inputs.counters.db_sync_calls),
        source_commit: None,
        include_nonmatching: false,
        coverage_filesystem: None,
        coverage_identity: None,
        coverage_status: None,
        roots: {
            // SR-STATE-03: a truncated derivation must never report a root
            // "complete" — its error list is partial. Force "error" (the
            // gap rows in `errors` name the truncation explicitly).
            let mut roots = root_inputs_chunked(inputs, &errors.root_error_ids, &volumes);
            if errors.truncated || instances.truncated {
                for root in &mut roots {
                    if root.state == "complete" {
                        root.state = String::from("error");
                    }
                }
            }
            roots
        },
        storage_links: instances.storage_links,
        aliases: alias_inputs(&inputs.aliases),
        candidates: {
            let mut candidates = instances.candidates;
            candidates.extend(errors.candidates);
            candidates
        },
        generated_artifacts: artifacts,
    })
}

fn root_inputs_chunked(
    inputs: &ScanReportInputs,
    root_error_ids: &[Vec<String>],
    volumes: &HashSet<String>,
) -> Vec<RootInput> {
    inputs
        .roots
        .iter()
        .enumerate()
        .map(|(n, root)| {
            let volume_id = match &root.volume {
                Some(volume) if volumes.contains(&volume.0) => Some(volume.0.clone()),
                _ if inputs.scope_policy == "roots" && volumes.contains("explicit-roots") => {
                    Some(String::from("explicit-roots"))
                }
                _ => None,
            };
            let error_ids: Vec<String> = root_error_ids.get(n).cloned().unwrap_or_default();
            let state = if !error_ids.is_empty() {
                "error"
            } else if inputs.pending > 0 {
                "pending"
            } else {
                "complete"
            };
            let cursors = inputs.root_cursors.get(n).cloned().unwrap_or_default();
            RootInput {
                id: format!("root-{}", n + 1),
                dir_id: None,
                path_bytes: Some(config::path_as_bytes(&root.path)),
                volume_id,
                state: state.to_string(),
                observed_at_ms: Some(inputs.finished_ms),
                event_history_uuid: cursors.history_uuid,
                ingested_cursor: cursors.ingested,
                reconciled_cursor: cursors.reconciled,
                error_ids,
            }
        })
        .collect()
}

fn scope_path(scope_key: &str) -> Option<PathBuf> {
    match config::parse_scope_key(scope_key) {
        Some(config::ScopeRef::Dir(p) | config::ScopeRef::Git(p)) => Some(p),
        _ => None,
    }
}

/// Borrowed object-store targets from `objects/info/alternates` (R16),
/// bounded to 64 entries per instance.
fn alternates_targets(git_path: &[u8]) -> Vec<Vec<u8>> {
    let path = config::path_from_bytes(git_path.to_vec()).join("objects/info/alternates");
    // Byte-capped, regular-file-only read (PATH-GIT-07): a giant,
    // special, or swapped alternates file yields no targets instead of
    // an unbounded allocation or a blocked scan.
    let bytes = match git::read_bounded_bytes(&path, git::MAX_GIT_CONTROL_BYTES) {
        Some(bytes) => bytes,
        None => return Vec::new(),
    };
    String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .take(64)
        .map(|line| line.as_bytes().to_vec())
        .collect()
}

/// First sampled loose object with more than one hard link (R16), or
/// `None`. Bounded: at most 8 fanout dirs, first file each.
#[cfg(unix)]
fn first_hardlinked_object(git_path: &[u8]) -> Option<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let objects = config::path_from_bytes(git_path.to_vec()).join("objects");
    let fanout = std::fs::read_dir(&objects).ok()?;
    for dir_entry in fanout.flatten().take(8) {
        let fan_dir = dir_entry.path();
        if !fan_dir.is_dir() {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&fan_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Ok(md) = std::fs::symlink_metadata(&path) {
                if md.nlink() > 1 {
                    return Some(config::path_as_bytes(&path));
                }
            }
            break;
        }
    }
    None
}

#[cfg(not(unix))]
fn first_hardlinked_object(_git_path: &[u8]) -> Option<Vec<u8>> {
    None
}

/// Caller-owned aliases (R7), deduplicated by `(path, target, kind)`.
fn alias_inputs(aliases: &[ObservedAlias]) -> Vec<AliasInput> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for alias in aliases {
        let key = (alias.path.clone(), alias.target.clone(), alias.kind);
        if !seen.insert(key) {
            continue;
        }
        out.push(AliasInput {
            path_bytes: alias.path.clone(),
            target_path_bytes: alias.target.clone(),
            kind: alias.kind.to_string(),
            verified_at_ms: alias.verified_at_ms,
        });
    }
    out
}

/// Immutable snapshot ID for this staging attempt (R16): the deterministic
/// scan ID while unused, else suffixed revisions. Every attempt gets its own
/// ID so retained snapshots are never rewritten; same-scan restages (resume)
/// keep history instead of mutating it.
async fn fresh_report_id(
    store: &TursoStore,
    state_dir: &Path,
    scan_id: &str,
) -> repo_scan::Result<String> {
    let base = config::report_id_for_scan(scan_id);
    let dir = snapshots_dir(state_dir);
    for attempt in 0..MAX_REPORT_ATTEMPTS {
        let id = if attempt == 0 {
            base.clone()
        } else {
            format!("{base}-r{}", attempt + 1)
        };
        let row_taken = store.get_report_snapshot(&id).await?.is_some();
        let file_taken = dir.join(format!("{id}.json")).exists();
        if !row_taken && !file_taken {
            return Ok(id);
        }
    }
    Err(repo_scan::Error::Report(format!(
        "could not mint a fresh report ID for scan {scan_id}"
    )))
}

/// Binary-side destination guard kept ahead of the lib publisher (R3):
/// refuse anything inside the tool state dir (the lib refuses the active
/// payload and lock; the state root itself stays refused here).
fn reject_state_dir_dest(dest: &Path, state_dir: &Path) -> repo_scan::Result<()> {
    if dest == state_dir || dest.starts_with(state_dir) {
        return Err(repo_scan::Error::Report(format!(
            "refusing to publish inside tool state dir: {}",
            dest.display()
        )));
    }
    Ok(())
}

/// Binary-side report-ID gate (mirrors the retention gate
/// `report::publish::check_report_id`, which is crate-private to the lib):
/// nonempty, at most 128 bytes, `[A-Za-z0-9._-]`, never `.`/`..`.
/// Called before the ID is ever interpolated into a staging filename
/// (RSP-006); shares the [`is_safe_report_id`] predicate with the
/// `cache clear` filters so the rules cannot drift apart.
fn check_binary_report_id(report_id: &str) -> repo_scan::Result<()> {
    if is_safe_report_id(report_id) {
        Ok(())
    } else if report_id.is_empty() {
        Err(repo_scan::Error::Report(
            "report_id must be nonempty".to_string(),
        ))
    } else {
        Err(repo_scan::Error::Report(format!(
            "report_id {report_id:?} is not a safe snapshot name"
        )))
    }
}

/// File emission through the tested lib pieces (R3), stage-first: the
/// staged report streams from the pinned catalog revision, is verified and
/// immutably retained as the snapshot, and only then does the destination
/// check + copy run. A refused destination therefore still leaves the
/// retained snapshot behind for retry — the same guarantee the old binary
/// path gave, now with lib validation, checksums, and no-clobber rules.
/// Staging mirrors the lib `stage_report` shape (RSP-004/RSP-006/RSP-007):
/// the report ID is validated before interpolation, the staging directory
/// is held as a directory FD, the file is created
/// `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` relative to that FD with an explicit
/// `0600` mode asserted after creation (no check-then-use by path), and a
/// stream failure quarantines the partial file instead of leaving residue.
/// Returns the snapshot path.
async fn emit_file_report(
    store: &TursoStore,
    inputs: &LibReportInputs,
    dest: &Path,
    state_dir: &Path,
    now_ms: i64,
) -> repo_scan::Result<PathBuf> {
    use repo_scan::report::builder::{quarantine_staging, stream_report_from_store};
    use std::io::Write;

    check_binary_report_id(&inputs.report_id)?;
    let staging = staging_dir(state_dir);
    // Owner-only report dirs; symlinked components are refused inside.
    store::owner::ensure_private_dir_all(&staging)?;
    store::owner::ensure_private_dir_all(&snapshots_dir(state_dir))?;
    let staged_name = format!(
        ".staging-{}-{}-{}.json",
        std::process::id(),
        store::now_ms(),
        inputs.report_id,
    );
    let staged = staging.join(&staged_name);
    #[cfg(unix)]
    let (file, staging_fd) = {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let dir = store::owner::open_dir_nofollow(&staging)?;
        let name = std::ffi::CString::new(staged_name.as_bytes()).map_err(|_| {
            repo_scan::Error::Report(format!(
                "refusing staging name with NUL byte: {staged_name:?}"
            ))
        })?;
        // SAFETY: dirfd is an open directory FD; the name is a generated
        // NUL-free leaf resolved relative to it.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                store::owner::STATE_FILE_MODE as libc::c_uint,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(repo_scan::Error::Report(format!(
                    "staging file already exists: {}",
                    staged.display()
                )));
            }
            return Err(repo_scan::Error::Report(format!(
                "cannot create staging file {}: {e}",
                staged.display()
            )));
        }
        // SAFETY: `openat` returned a new owned FD; it moves into `File` once.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            quarantine_staging(&staged);
            return Err(repo_scan::Error::Report(format!(
                "staging file {} mode is {mode:o}, want no group/other access",
                staged.display()
            )));
        }
        (file, dir)
    };
    #[cfg(not(unix))]
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)?;
    let outcome: repo_scan::Result<()> = async {
        let (mut file, _) = stream_report_from_store(store, inputs, file).await?;
        file.flush()?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            let _ = staging_fd.sync_all();
        }
        #[cfg(not(unix))]
        {
            if let Ok(dir) = std::fs::File::open(&staging) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = outcome {
        quarantine_staging(&staged);
        return Err(error);
    }
    verified_retain_and_publish(
        store,
        &staged,
        &inputs.report_id,
        inputs.catalog_revision,
        inputs.generation,
        dest,
        state_dir,
        now_ms,
    )
    .await
}

/// Verify staged bytes, retain the immutable snapshot, then publish
/// (RSF-7511725D-DC03-471A-9635-4F8173986489): production publication
/// calls [`verify_staged_report`] (schema + cross-field rules) and
/// refuses invalid output before it can be retained or shipped. Returns
/// the snapshot path.
#[allow(clippy::too_many_arguments)]
async fn verified_retain_and_publish(
    store: &TursoStore,
    staged: &Path,
    report_id: &str,
    catalog_rev: u64,
    generation: u64,
    dest: &Path,
    state_dir: &Path,
    now_ms: i64,
) -> repo_scan::Result<PathBuf> {
    use repo_scan::report::publish;

    verify_staged_report(staged).map_err(|e| {
        repo_scan::Error::Report(format!(
            "refusing invalid staged report {}: {e}",
            staged.display()
        ))
    })?;
    let receipt = publish::retain_snapshot(
        store,
        staged,
        &snapshots_dir(state_dir),
        report_id,
        catalog_rev,
        generation,
        now_ms,
    )
    .await?;
    let snapshot = receipt.path.clone();
    // Binary-side guard first (state root stays refused), then the lib's
    // destination policy; either refusal fails the publication without
    // touching the retained snapshot or the destination.
    let checked =
        reject_state_dir_dest(dest, state_dir).and(publish::check_destination(dest, state_dir));
    if let Err(e) = checked {
        store.set_snapshot_publication(report_id, "failed").await?;
        return Err(e);
    }
    match publish::publish_staged(&snapshot, dest, state_dir) {
        Ok(_) => {
            store
                .set_snapshot_publication(report_id, "published")
                .await?;
            Ok(snapshot)
        }
        Err(e) => {
            store.set_snapshot_publication(report_id, "failed").await?;
            Err(e)
        }
    }
}

fn staging_dir(state_dir: &Path) -> PathBuf {
    store::owner::payload_dir(state_dir).join(config::STAGING_DIR_NAME)
}

fn snapshots_dir(state_dir: &Path) -> PathBuf {
    store::owner::payload_dir(state_dir).join(config::SNAPSHOTS_DIR_NAME)
}

// ---------------------------------------------------------------------------
// Query (cached only)
// ---------------------------------------------------------------------------

/// Rebuild the wire [`Envelope`] for one journaled row. The journaled
/// `op` wins over the class default so a resent batch carrying
/// `replace` stays `replace` (D4 `add/replace` cell); unknown classes or
/// corrupt payloads fail loudly, never as silent skips.
fn envelope_for_row(row: &ScanEventRow) -> repo_scan::Result<Envelope> {
    let event_type: EventType =
        serde_json::from_value(serde_json::Value::String(row.event_type.clone())).map_err(|e| {
            repo_scan::Error::Report(format!(
                "scan_events row seq {} carries unknown class {:?}: {e}",
                row.seq, row.event_type,
            ))
        })?;
    let op: Op =
        serde_json::from_value(serde_json::Value::String(row.op.clone())).map_err(|e| {
            repo_scan::Error::Report(format!(
                "scan_events row seq {} carries unknown op {:?}: {e}",
                row.seq, row.op,
            ))
        })?;
    let records: serde_json::Value = serde_json::from_slice(&row.records).map_err(|e| {
        repo_scan::Error::Report(format!(
            "scan_events row seq {} carries corrupt records: {e}",
            row.seq,
        ))
    })?;
    let mut env = Envelope::new(
        row.scan_id.clone(),
        row.seq,
        row.catalog_rev,
        row.event_offset,
        event_type,
        row.reset,
        records,
    );
    env.op = op;
    Ok(env)
}

/// Write one JSONL line. `Ok(false)` means the consumer went away
/// (broken pipe): the follower stops quietly with committed catalog
/// records untouched (Step 12); any other IO error fails loudly.
fn write_jsonl_line(out: &mut impl std::io::Write, line: &str) -> repo_scan::Result<bool> {
    match writeln!(out, "{line}") {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(repo_scan::Error::Io(format!(
            "cannot write replay line: {e}"
        ))),
    }
}

/// True while the scan row can still journal more events: only the
/// `running` state (with or without the `:roots:` suffix) keeps a
/// follower waiting. Any other state — complete, incomplete,
/// interrupted, failed, superseded — ends the follow at the journal tip,
/// which also covers pre-journal scans that will never emit.
fn scan_still_running(state: &str) -> bool {
    state == "running" || state.starts_with("running:")
}

/// Where a scan replay starts (Step 12): an optional strictly-after
/// `(catalog_rev, event_offset)` position plus whether the first
/// delivered envelope must carry `reset:true`.
struct ReplayPosition {
    after: Option<(u64, u64)>,
    reset_first: bool,
}

/// Resolve an `--after` cursor to its replay position (Step 12): seq 0
/// replays from the start; otherwise the row at the cursor's seq
/// classifies via [`classify_cursor`] — covered cursors resume strictly
/// after the cursor's `(rev, off)` position (revision + event-offset
/// replay position, so reconnecting between two events of one
/// transaction loses nothing), while expired or diverged cursors replay
/// the retained window from its start with `reset:true` first
/// (explicit-reset snapshot, never a silent gap). Corrupt (undecodable)
/// cursors stay a usage error.
async fn resolve_after_cursor(
    store: &TursoStore,
    scan_id: &str,
    after: &str,
) -> repo_scan::Result<ReplayPosition> {
    let Some(cursor) = Cursor::decode(after) else {
        return Err(repo_scan::Error::InvalidArgs(format!(
            "corrupt --after cursor for scan {scan_id}; replay from the start instead"
        )));
    };
    if cursor.seq == 0 {
        return Ok(ReplayPosition {
            after: None,
            reset_first: false,
        });
    }
    let seq_i64 = i64::try_from(cursor.seq).map_err(|_| {
        repo_scan::Error::Store(format!("cursor seq {} exceeds i64 range", cursor.seq))
    })?;
    let mut rows = store
        .connection()
        .query(
            "SELECT event_type, catalog_rev, event_offset FROM scan_events \
                WHERE scan_id = ?1 AND seq = ?2",
            vec![
                turso::Value::Text(scan_id.to_string()),
                turso::Value::Integer(seq_i64),
            ],
        )
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?;
    let found = match rows
        .next()
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?
    {
        None => None,
        Some(row) => {
            let event_type: EventType = serde_json::from_value(serde_json::Value::String(
                cell_text(&row, 0)?,
            ))
            .map_err(|e| {
                repo_scan::Error::Report(format!(
                    "scan_events row seq {} carries unknown class: {e}",
                    cursor.seq,
                ))
            })?;
            let rev = cell_int(&row, 1)?;
            let off = cell_int(&row, 2)?;
            Some((
                event_type,
                u64::try_from(rev).map_err(|_| {
                    repo_scan::Error::Store(format!(
                        "event catalog_rev {rev} in catalog is not a valid u64"
                    ))
                })?,
                u64::try_from(off).map_err(|_| {
                    repo_scan::Error::Store(format!(
                        "event offset {off} in catalog is not a valid u64"
                    ))
                })?,
            ))
        }
    };
    match classify_cursor(&cursor, found) {
        ResumeAction::ResumeAfterCursor => Ok(ReplayPosition {
            after: Some((cursor.catalog_rev, cursor.event_offset)),
            reset_first: false,
        }),
        ResumeAction::ResetSnapshot => Ok(ReplayPosition {
            after: None,
            reset_first: true,
        }),
    }
}

/// Parse one `scan_events` row (same column order and range checks as
/// the store reader: negative seq/rev/off are catalog corruption).
fn scan_event_row_from_cells(row: &turso::Row) -> repo_scan::Result<ScanEventRow> {
    let seq = cell_int(row, 1)?;
    let rev = cell_int(row, 2)?;
    let off = cell_int(row, 3)?;
    Ok(ScanEventRow {
        scan_id: cell_text(row, 0)?,
        seq: u64::try_from(seq).map_err(|_| {
            repo_scan::Error::Store(format!("event seq {seq} in catalog is not a valid u64"))
        })?,
        catalog_rev: u64::try_from(rev).map_err(|_| {
            repo_scan::Error::Store(format!(
                "event catalog_rev {rev} in catalog is not a valid u64"
            ))
        })?,
        event_offset: u64::try_from(off).map_err(|_| {
            repo_scan::Error::Store(format!("event offset {off} in catalog is not a valid u64"))
        })?,
        event_type: cell_text(row, 4)?,
        op: cell_text(row, 5)?,
        reset: cell_int(row, 6)? != 0,
        records: cell_blob(row, 7)?,
    })
}

/// Replay journal rows for a scan in `(catalog_rev, event_offset)` order
/// (served by `idx_scan_events_cursor`), optionally strictly after one
/// position, oldest first, capped at `limit` rows (clamped to
/// `[1, 10_000]`, mirroring `read_scan_events`).
async fn read_scan_events_after_position(
    store: &TursoStore,
    scan_id: &str,
    after: Option<(u64, u64)>,
    limit: u64,
) -> repo_scan::Result<Vec<ScanEventRow>> {
    const COLUMNS: &str = "scan_id, seq, catalog_rev, event_offset, event_type, op, reset, records";
    let limit_i64 = i64::try_from(limit.clamp(1, 10_000))
        .map_err(|_| repo_scan::Error::Store(format!("event limit {limit} exceeds i64 range")))?;
    let (sql, params) = match after {
        None => (
            format!(
                "SELECT {COLUMNS} FROM scan_events WHERE scan_id = ?1 \
                ORDER BY catalog_rev ASC, event_offset ASC LIMIT ?2"
            ),
            vec![
                turso::Value::Text(scan_id.to_string()),
                turso::Value::Integer(limit_i64),
            ],
        ),
        Some((rev, off)) => {
            let rev_i64 = i64::try_from(rev).map_err(|_| {
                repo_scan::Error::Store(format!("event catalog_rev {rev} exceeds i64 range"))
            })?;
            let off_i64 = i64::try_from(off).map_err(|_| {
                repo_scan::Error::Store(format!("event offset {off} exceeds i64 range"))
            })?;
            (
                format!(
                    "SELECT {COLUMNS} FROM scan_events WHERE scan_id = ?1 \
                    AND (catalog_rev > ?2 OR (catalog_rev = ?2 AND event_offset > ?3)) \
                    ORDER BY catalog_rev ASC, event_offset ASC LIMIT ?4"
                ),
                vec![
                    turso::Value::Text(scan_id.to_string()),
                    turso::Value::Integer(rev_i64),
                    turso::Value::Integer(off_i64),
                    turso::Value::Integer(limit_i64),
                ],
            )
        }
    };
    let mut rows = store
        .connection()
        .query(sql.as_str(), params)
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?;
    let mut out = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?
    {
        out.push(scan_event_row_from_cells(&row)?);
    }
    Ok(out)
}

/// `query --scan SCAN_ID`: replay the scan's journaled event stream as
/// JSONL envelopes, oldest first, in `(catalog_rev, event_offset)` order.
/// `--after CURSOR` resumes strictly after the cursor's position; a
/// cursor the retained window no longer covers (or that diverges from
/// the journaled row) replays the retained window from its start with
/// `reset:true` on the first envelope. `--follow` keeps polling a
/// running scan until the terminal event, Ctrl-C (exit 130), or a broken
/// pipe (quiet exit 0). Read-only: no owner lock, no epoch claim,
/// servable while a scan holds the write lock. Unknown scan IDs exit 2
/// like `resume` on a missing ID.
async fn run_query_scan_replay(
    cfg: &config::Config,
    args: &repo_scan::cli::QueryArgs,
    scan_id: &str,
) -> repo_scan::Result<ExitCode> {
    use repo_scan::cli::OutputFormat;
    // Explicit format wins; the default is JSONL when redirected, the
    // live human view on a terminal (human replay: TUI slice).
    let format = match args.format {
        Some(f) => f,
        None if !std::io::stdout().is_terminal() => OutputFormat::Jsonl,
        None => {
            eprintln!(
                "repo-scan: not yet implemented: query --scan human replay executes in the TUI \
                 slice; use --format jsonl for now"
            );
            return Ok(ExitCode::OperationalFailure);
        }
    };
    if format != OutputFormat::Jsonl {
        // `--follow --format json` never reaches here: `selection()`
        // rejects it. Plain `--format json` folds the journal into one
        // snapshot in a later slice.
        eprintln!(
            "repo-scan: not yet implemented: query --scan --format json executes in a later \
             slice; use --format jsonl for now"
        );
        return Ok(ExitCode::OperationalFailure);
    }
    let db_path = store::owner::catalog_db_path(&cfg.state_dir);
    if !db_path.exists() {
        println!("cached: true");
        println!("suitable_catalog: false");
        println!(
            "note: no catalog at {}; no live verification performed",
            db_path.display()
        );
        return Ok(ExitCode::Incomplete);
    }
    let mut store = TursoStore::open_read_only(&db_path).await?;
    if !catalog_bound_to_marker(&store, &cfg.state_dir).await? {
        println!("cached: true");
        println!("suitable_catalog: false");
        println!(
            "note: catalog at {} is not bound to this tool's ownership marker; \
             no live verification performed",
            db_path.display()
        );
        let _ = store.close().await;
        return Ok(ExitCode::Incomplete);
    }
    let Some(scan) = store.get_scan(scan_id).await? else {
        let _ = store.close().await;
        return Err(repo_scan::Error::InvalidArgs(format!(
            "no such scan: {scan_id}"
        )));
    };
    let start = match &args.after {
        None => ReplayPosition {
            after: None,
            reset_first: false,
        },
        Some(after) => match resolve_after_cursor(&store, scan_id, after).await {
            Ok(position) => position,
            Err(e) => {
                let _ = store.close().await;
                return Err(e);
            }
        },
    };
    let mut after = start.after;
    // Explicit-reset snapshots override `reset` on the first envelope
    // actually delivered (even when the first rows arrive in the follow
    // loop rather than the initial replay).
    let mut reset_first = start.reset_first;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    // Initial replay: page through committed rows; a short page (or an
    // empty one) means the reader caught up to the tip.
    let mut terminal_seen = false;
    loop {
        let rows =
            read_scan_events_after_position(&store, scan_id, after, REPLAY_PAGE_ROWS).await?;
        let short_page = rows.len() < REPLAY_PAGE_ROWS as usize;
        for row in &rows {
            let mut env = envelope_for_row(row)?;
            if reset_first {
                env.reset = true;
                reset_first = false;
            }
            let line =
                serde_json::to_string(&env).map_err(|e| repo_scan::Error::Report(e.to_string()))?;
            if !write_jsonl_line(&mut out, &line)? {
                let _ = store.close().await;
                return Ok(ExitCode::Success);
            }
            after = Some((row.catalog_rev, row.event_offset));
            terminal_seen |= is_terminal_event(env.event_type);
        }
        if short_page {
            break;
        }
    }
    match out.flush() {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
            let _ = store.close().await;
            return Ok(ExitCode::Success);
        }
        Err(e) => {
            return Err(repo_scan::Error::Io(format!(
                "cannot flush replay output: {e}"
            )));
        }
    }
    if !args.follow || terminal_seen {
        let _ = store.close().await;
        return Ok(ExitCode::Success);
    }
    // Follow: a scan row that already left `running` will never journal
    // more (pre-journal scans included), so stop at the tip; otherwise
    // poll until the terminal event lands.
    if !scan_still_running(&scan.state) {
        let _ = store.close().await;
        return Ok(ExitCode::Success);
    }
    loop {
        if interrupted() {
            let _ = store.close().await;
            return Ok(ExitCode::Interrupted);
        }
        std::thread::sleep(FOLLOW_POLL);
        // A read-only handle pins its opening snapshot: later commits are
        // invisible until reopen (measured: a 60s poll never saw new rows,
        // a fresh open did). Reopen per poll and re-verify the ownership
        // bind, so a swapped or cleared catalog ends the follow loudly
        // instead of replaying stale or foreign rows.
        let _ = store.close().await;
        store = TursoStore::open_read_only(&db_path).await?;
        if !catalog_bound_to_marker(&store, &cfg.state_dir).await? {
            let _ = store.close().await;
            eprintln!(
                "repo-scan: follow: catalog at {} lost its ownership bind; \
                 stopping at the journal tip",
                db_path.display()
            );
            return Ok(ExitCode::Incomplete);
        }
        let rows =
            read_scan_events_after_position(&store, scan_id, after, REPLAY_PAGE_ROWS).await?;
        for row in &rows {
            let mut env = envelope_for_row(row)?;
            if reset_first {
                env.reset = true;
                reset_first = false;
            }
            let line =
                serde_json::to_string(&env).map_err(|e| repo_scan::Error::Report(e.to_string()))?;
            if !write_jsonl_line(&mut out, &line)? {
                let _ = store.close().await;
                return Ok(ExitCode::Success);
            }
            after = Some((row.catalog_rev, row.event_offset));
            terminal_seen |= is_terminal_event(env.event_type);
        }
        match out.flush() {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                let _ = store.close().await;
                return Ok(ExitCode::Success);
            }
            Err(e) => {
                return Err(repo_scan::Error::Io(format!(
                    "cannot flush replay output: {e}"
                )));
            }
        }
        if terminal_seen {
            let _ = store.close().await;
            return Ok(ExitCode::Success);
        }
        match store.get_scan(scan_id).await? {
            Some(s) if scan_still_running(&s.state) => {}
            Some(_) => {
                let _ = store.close().await;
                return Ok(ExitCode::Success);
            }
            None => {
                let _ = store.close().await;
                eprintln!("repo-scan: follow: scan {scan_id} is gone; stopping at the journal tip");
                return Ok(ExitCode::Incomplete);
            }
        }
    }
}

async fn run_query(cfg: &config::Config, args: &repo_scan::cli::QueryArgs) -> ExitCode {
    match run_query_inner(cfg, args).await {
        Ok(code) => code,
        Err(e) => fail(&e),
    }
}

/// Read only existing tool state: no repository reads, no mount enumeration,
/// no Git-config reads, no refresh, no fetch, no discovery. Exit 3 when no
/// suitable catalog exists.
async fn run_query_inner(
    cfg: &config::Config,
    args: &repo_scan::cli::QueryArgs,
) -> repo_scan::Result<ExitCode> {
    // Goal Step 6: exactly one of TARGET / --all / --scan. The cached
    // single-target path stays inline; --scan replays the journaled event
    // stream; --all follows in a later slice.
    let selection = match args.selection() {
        Ok(s) => s,
        Err(msg) => return Err(repo_scan::Error::InvalidArgs(msg)),
    };
    let url = match selection {
        repo_scan::cli::QuerySelection::Target(url) => url,
        repo_scan::cli::QuerySelection::Scan(id) => {
            return run_query_scan_replay(cfg, args, &id).await;
        }
        repo_scan::cli::QuerySelection::All => {
            eprintln!(
                "repo-scan: not yet implemented: query --all executes in a later slice; \
                 use one TARGET with --cached, or --scan SCAN_ID --format jsonl"
            );
            return Ok(ExitCode::OperationalFailure);
        }
    };
    if !args.cached {
        return Err(repo_scan::Error::InvalidArgs(
            "--cached is required: live queries are not supported".to_string(),
        ));
    }
    // Absent catalog short-circuits before any lock or file creation.
    let db_path = store::owner::catalog_db_path(&cfg.state_dir);
    if !db_path.exists() {
        println!("cached: true");
        println!("suitable_catalog: false");
        println!(
            "note: no catalog at {}; no live verification performed",
            db_path.display()
        );
        return Ok(ExitCode::Incomplete);
    }
    // RSF-02C3154D-7D7A-420E-A0C5-EA763B8B327D: the cached query opens
    // the catalog read-only — no owner lock, no epoch claim, no recovery
    // writes, no migrations — so it is servable while a scan owner holds
    // the write lock and can never mutate catalog state.
    let store = TursoStore::open_read_only(&db_path).await?;
    // RS-PRIV-06/08/12: an unbound catalog (no marker, or marker `db_id`
    // != live `meta.db_id`) is not served — it reports "no suitable
    // catalog", exactly like an absent one.
    if !catalog_bound_to_marker(&store, &cfg.state_dir).await? {
        println!("cached: true");
        println!("suitable_catalog: false");
        println!(
            "note: catalog at {} is not bound to this tool's ownership marker; \
             no live verification performed",
            db_path.display()
        );
        let _ = store.close().await;
        return Ok(ExitCode::Incomplete);
    }
    // RS-PRIV-09: row-count and time budgets; exhaustion truncates with
    // an explicit incomplete note, never a silent partial answer.
    let deadline = Instant::now() + Duration::from_secs(QUERY_DEADLINE_SECS);
    let expired = || Instant::now() > deadline;
    let generations_sql = format!(
        "SELECT id, scope_policy, state, created_at_ms FROM generations ORDER BY id DESC LIMIT {}",
        QUERY_MAX_GENERATIONS + 1
    );
    let mut rows = store
        .connection()
        .query(&generations_sql, ())
        .await
        .map_err(store_err)?;
    let mut generations = Vec::new();
    let mut generations_truncated = false;
    while let Some(row) = rows.next().await.map_err(store_err)? {
        if expired() {
            generations_truncated = true;
            break;
        }
        generations.push((
            cell_int(&row, 0)? as u64,
            cell_text(&row, 1)?,
            cell_text(&row, 2)?,
            cell_int(&row, 3)?,
        ));
        if generations.len() > QUERY_MAX_GENERATIONS {
            generations.pop();
            generations_truncated = true;
            break;
        }
    }
    if generations.is_empty() {
        println!("cached: true");
        println!("suitable_catalog: false");
        println!("note: catalog holds no traversal generation; no live verification performed");
        let _ = store.close().await;
        return Ok(ExitCode::Incomplete);
    }
    let Some(canonical) = normalize_query_cached(&url) else {
        println!("cached: true");
        println!("target: {}", identity::redact_target_for_display(&url));
        println!("canonical: unresolved (unsupported shape or unresolvable host alias)");
        println!("note: aliases resolve only from cached observations; no live probe performed");
        let _ = store.close().await;
        return Ok(ExitCode::Incomplete);
    };
    let matches_sql = format!(
        "SELECT g.id, g.git_path, g.disposition, g.observed_at_ms FROM git_instances g \
         JOIN remotes r ON r.instance_id = g.id WHERE r.canonical_url = ?1 \
         GROUP BY g.id ORDER BY g.id ASC LIMIT {}",
        QUERY_MAX_MATCHES + 1
    );
    let mut rows = store
        .connection()
        .query(
            &matches_sql,
            vec![turso::Value::Blob(canonical.as_bytes().to_vec())],
        )
        .await
        .map_err(store_err)?;
    let mut matches = Vec::new();
    let mut matches_truncated = false;
    while let Some(row) = rows.next().await.map_err(store_err)? {
        if expired() {
            matches_truncated = true;
            break;
        }
        matches.push((
            cell_text(&row, 0)?,
            cell_blob(&row, 1)?,
            cell_text(&row, 2)?,
            cell_int(&row, 3)?,
        ));
        if matches.len() > QUERY_MAX_MATCHES {
            matches.pop();
            matches_truncated = true;
            break;
        }
    }
    let open_gaps = count_open_errors(&store).await?;
    let pending_all = count_query(
        &store,
        "SELECT COUNT(*) FROM frontier_tasks WHERE state NOT IN \
         ('complete', 'unsupported', 'cancelled', 'superseded')",
        vec![],
    )
    .await?;
    println!("cached: true (no live verification performed)");
    println!("target: {}", identity::redact_target_for_display(&url));
    println!("canonical: {canonical}");
    for (id, policy, state, created) in &generations {
        println!(
            "generation: {id} scope={policy} state={state} created={}",
            ms_to_rfc3339(*created)
        );
    }
    println!("matches: {}", matches.len());
    for (_, git_path, disposition, observed) in &matches {
        // RS-PRIV-12: stored bytes are scrubbed for secrets before
        // display; escaping alone is not redaction.
        let shown =
            escape_display(identity::scrub_text(&String::from_utf8_lossy(git_path)).as_bytes());
        println!(
            "  {disposition}: {shown} (observed {})",
            ms_to_rfc3339(*observed),
        );
    }
    if generations_truncated {
        println!(
            "note: generations truncated at the {QUERY_MAX_GENERATIONS}-row budget; \
             coverage incomplete"
        );
    }
    if matches_truncated {
        println!(
            "note: matches truncated at the {QUERY_MAX_MATCHES}-row budget; coverage incomplete"
        );
    }
    println!("open_gaps: {open_gaps}");
    println!("pending_tasks: {pending_all}");
    let _ = store.close().await;
    Ok(ExitCode::Success)
}

/// Cached-only target normalization: direct `github.com` hosts take the
/// pure normalization path (no filesystem reads); alias and foreign hosts
/// cannot resolve without live configuration, so the query is unresolved.
fn normalize_query_cached(url: &str) -> Option<String> {
    let parsed = gix::url::parse(url.trim()).ok()?;
    match parsed.scheme {
        gix::url::Scheme::Https | gix::url::Scheme::Http | gix::url::Scheme::Ssh => {}
        _ => return None,
    }
    let host = parsed.host.as_deref()?;
    if !host.eq_ignore_ascii_case(identity::GITHUB_HOST) {
        return None;
    }
    identity::normalize_github_url(url)
}

// ---------------------------------------------------------------------------
// Resume
// ---------------------------------------------------------------------------

async fn run_resume(cfg: &config::Config, args: &repo_scan::cli::ResumeArgs) -> ExitCode {
    match run_resume_inner(cfg, args).await {
        Ok(code) => code,
        Err(e) => fail(&e),
    }
}

async fn run_resume_inner(
    cfg: &config::Config,
    args: &repo_scan::cli::ResumeArgs,
) -> repo_scan::Result<ExitCode> {
    let (guard, store) = open_owned_with_wait(&cfg.state_dir).await?;
    let Some(row) = store.get_scan(&args.scan_id).await? else {
        let _ = store.close().await;
        drop(guard);
        return Err(repo_scan::Error::UnknownScan(format!(
            "no saved scan request: {}",
            args.scan_id
        )));
    };
    let (base, saved_roots) = config::split_scan_state(&row.state);
    let outcome = row.outcome.as_deref().and_then(config::parse_outcome);
    match base {
        "complete" => {
            let Some(recorded) = outcome else {
                let _ = store.close().await;
                drop(guard);
                return Err(repo_scan::Error::Store(format!(
                    "scan {} is complete but has no recorded outcome",
                    row.id
                )));
            };
            let snapshot = config::snapshot_path(&cfg.state_dir, &recorded.report_id)?;
            println!("scan_id: {}", row.id);
            println!("state: complete (replayed; no new scan started)");
            println!("report_id: {}", recorded.report_id);
            println!("snapshot: {}", snapshot.display());
            let _ = store.close().await;
            drop(guard);
            Ok(match recorded.exit_code {
                0 => ExitCode::Success,
                3 => ExitCode::Incomplete,
                130 => ExitCode::Interrupted,
                _ => ExitCode::OperationalFailure,
            })
        }
        "superseded" => {
            println!("scan_id: {}", row.id);
            println!("state: superseded (no target or destination switch performed)");
            println!(
                "successor: {}",
                row.successor_id.as_deref().unwrap_or("unknown")
            );
            println!(
                "target: {}",
                identity::redact_target_for_display(&String::from_utf8_lossy(&row.url_raw))
            );
            let _ = store.close().await;
            drop(guard);
            Ok(ExitCode::Incomplete)
        }
        "failed" => {
            // A failed report publication retries against the saved snapshot
            // without repeating discovery.
            if let Some(recorded) = &outcome {
                if !recorded.published {
                    let snapshot = config::snapshot_path(&cfg.state_dir, &recorded.report_id)?;
                    if snapshot.exists() {
                        let code =
                            retry_publication(cfg, &store, &row, recorded, &snapshot).await?;
                        let _ = store.close().await;
                        drop(guard);
                        return Ok(code);
                    }
                }
            }
            continue_saved_scan(cfg, guard, store, &row, saved_roots).await
        }
        "running" | "interrupted" | "incomplete" => {
            continue_saved_scan(cfg, guard, store, &row, saved_roots).await
        }
        other => {
            let _ = store.close().await;
            drop(guard);
            Err(repo_scan::Error::Config(format!(
                "scan {} has unknown state: {other}",
                row.id
            )))
        }
    }
}

/// Retry a failed report publication from the retained snapshot bytes.
async fn retry_publication(
    cfg: &config::Config,
    store: &TursoStore,
    row: &store::ScanRow,
    recorded: &config::DecodedOutcome,
    snapshot: &Path,
) -> repo_scan::Result<ExitCode> {
    let discovery = recorded.discovery_code.unwrap_or(3);
    let dest = row
        .report_dest
        .as_ref()
        .map(|bytes| config::path_from_bytes(bytes.clone()));
    // The saved destination was absolute at request creation; a relative
    // path here is foreign corruption, never a reason to consult the cwd.
    if let Some(dest) = &dest {
        if !dest.is_absolute() {
            return Err(repo_scan::Error::Config(format!(
                "saved report destination is not absolute: {}",
                dest.display()
            )));
        }
    }
    // Retry through the tested lib publisher (R3): the snapshot is
    // revalidated and checksum-verified before it is copied out.
    if let Some(dest) = &dest {
        if let Err(e) = reject_state_dir_dest(dest, &cfg.state_dir) {
            eprintln!(
                "repo-scan: publication retry failed: {}",
                identity::scrub_text(&e.to_string())
            );
            return Ok(ExitCode::OperationalFailure);
        }
    }
    let published = match &dest {
        Some(dest) => {
            match ReportPipeline::retry_publication(
                store,
                snapshot,
                &recorded.report_id,
                dest,
                &cfg.state_dir,
            )
            .await
            {
                Ok(_) => true,
                Err(e) => {
                    eprintln!(
                        "repo-scan: publication retry failed: {}",
                        identity::scrub_text(&e.to_string())
                    );
                    store
                        .set_snapshot_publication(&recorded.report_id, "failed")
                        .await?;
                    return Ok(ExitCode::OperationalFailure);
                }
            }
        }
        None => true,
    };
    store
        .set_snapshot_publication(&recorded.report_id, "published")
        .await?;
    let (state, exit) = if discovery == 0 {
        ("complete", ExitCode::Success)
    } else {
        ("incomplete", ExitCode::Incomplete)
    };
    store
        .update_scan_state(
            &row.id,
            state,
            Some(&config::encode_outcome(
                exit.code(),
                Some(discovery),
                &recorded.report_id,
                published,
                recorded.generation,
            )),
            None,
            store::now_ms(),
        )
        .await?;
    println!("scan_id: {}", row.id);
    println!("state: {state} (publication retried from saved snapshot; no new scan)");
    println!("report_id: {}", recorded.report_id);
    if let Some(dest) = &dest {
        println!("report: {}", dest.display());
    }
    Ok(exit)
}

/// Restore a saved non-terminal request and continue its unfinished work.
/// Releases ownership first: re-entering the scan loop re-acquires it.
async fn continue_saved_scan(
    cfg: &config::Config,
    guard: OwnerGuard,
    store: TursoStore,
    row: &store::ScanRow,
    saved_roots: Option<Vec<PathBuf>>,
) -> repo_scan::Result<ExitCode> {
    // Redact-on-read (RSF-SEC-TARGET-URL, EXACT-2): rows persisted
    // before the CLI boundary reject may hold credential-bearing targets.
    // Reuse the stored canonical target (never credential-bearing) or a
    // sanitized raw URL so the resumed scan resolves the same repository
    // without carrying the secret forward into state or reports.
    let stored_url = String::from_utf8_lossy(&row.url_raw).into_owned();
    let url = if identity::must_reject_target(&stored_url) {
        match &row.url_canonical {
            Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            None => identity::sanitize_target_url(&stored_url),
        }
    } else {
        stored_url
    };
    let status = status_mode_from_str(&row.status_mode).ok_or_else(|| {
        repo_scan::Error::Config(format!("saved status mode is invalid: {}", row.status_mode))
    })?;
    let report = match &row.report_dest {
        Some(bytes) => {
            let dest = config::path_from_bytes(bytes.clone());
            if !dest.is_absolute() {
                return Err(repo_scan::Error::Config(format!(
                    "saved report destination is not absolute: {}",
                    dest.display()
                )));
            }
            Some(dest)
        }
        None => None,
    };
    let (scope, root) = match row.scope.as_str() {
        "roots" => {
            let Some(roots) = saved_roots else {
                return Err(repo_scan::Error::Config(format!(
                    "scan {} is roots-scoped but carries no saved roots",
                    row.id
                )));
            };
            (Scope::Roots, roots)
        }
        "machine" => (Scope::Machine, Vec::new()),
        other => {
            return Err(repo_scan::Error::Config(format!(
                "scan {} has unknown scope: {other}",
                row.id
            )));
        }
    };
    let started_ms = row.created_at_ms;
    let scan_id = row.id.clone();
    let _ = store.close().await;
    drop(guard);
    eprintln!(
        "repo-scan: resuming scan {scan_id} (scope {}, saved options restored)",
        row.scope
    );
    // v2: restore the `--all` marker (no target filter); without
    // this every `--all` resume re-resolves the literal `--all`
    // marker as a target and fails with InvalidArgs. Legacy rows
    // (NULL) resume single-target via `url_raw` as before.
    let all = row.all_targets.unwrap_or(false);
    let args = repo_scan::cli::ScanArgs {
        targets: if all { Vec::new() } else { vec![url] },
        all,
        scope,
        report,
        force_rescan: false,
        status,
        root,
        format: None,
        // v3: restore the saved `--fetch` request; legacy rows (NULL)
        // resume without a fetch phase.
        fetch: row.fetch.unwrap_or(false),
        color: None,
        // v4: restore the saved `--workers` request; legacy rows (NULL)
        // resume on the runtime default.
        workers: config::restore_workers(row.workers),
    };
    // The row's bound generation (R14), if any; `run_scan_inner`
    // honors it instead of re-picking.
    let generation = row
        .outcome
        .as_deref()
        .and_then(config::parse_outcome)
        .and_then(|d| d.generation);
    run_scan_inner(
        cfg,
        &args,
        Some(ResumedRequest {
            scan_id,
            started_ms,
            generation,
        }),
    )
    .await
}

// ---------------------------------------------------------------------------
// Cache invalidate
// ---------------------------------------------------------------------------

async fn run_invalidate(cfg: &config::Config, args: &repo_scan::cli::InvalidateArgs) -> ExitCode {
    match run_invalidate_inner(cfg, args).await {
        Ok(code) => code,
        Err(e) => fail(&e),
    }
}

/// Durably invalidate one scope and schedule reconciliation. Success never
/// claims the rescan is already complete.
async fn run_invalidate_inner(
    cfg: &config::Config,
    args: &repo_scan::cli::InvalidateArgs,
) -> repo_scan::Result<ExitCode> {
    let root = config::resolve_report_dest(&args.root)?;
    let (_guard, store) = open_owned_with_wait(&cfg.state_dir).await?;
    let now = store::now_ms();
    let generation = match latest_generation_any(&store).await? {
        Some((id, _)) => id,
        None => {
            store
                .create_generation("machine", "running", None, now)
                .await?
        }
    };
    let scope_key = config::scope_key_for_dir(&root);
    let rev = store.invalidate_scope(&scope_key, generation, now).await?;
    // Event ingest runs on invalidate too (R5): available history batches
    // become durable invalidations alongside the requested one. No
    // reconcile here: the checked completeness claim requires a
    // completed traversal (reconcile-before-claim), and invalidate
    // performs none — attempting it would manufacture a claim gap that
    // poisons the next scan's exit status. Cursor advancement is
    // redundant too: the next scan re-derives it after satisfying the
    // work this command just scheduled.
    let ingested = {
        let roots = [PlannedRoot {
            path: root.clone(),
            priority: RootPriority::Early,
            namespace: String::from("explicit"),
            volume: None,
        }];
        let mut events = open_event_session(&store, &cfg.state_dir, "roots", &roots).await?;
        let mut counters = RunCounters::default();
        ingest_available_events(&mut events, &store, generation, &roots, &mut counters).await?
    };
    let _ = store.close().await;
    println!(
        "invalidated {} rev={rev} generation={generation}; reconciliation scheduled \
         (rescan not complete)",
        root.display()
    );
    if ingested.batches > 0 {
        println!(
            "events: ingested {} batch(es), {} scope(s) invalidated",
            ingested.batches, ingested.scopes,
        );
    }
    Ok(ExitCode::Success)
}

async fn latest_generation_any(store: &TursoStore) -> repo_scan::Result<Option<(u64, String)>> {
    let mut rows = store
        .connection()
        .query(
            "SELECT id, scope_policy FROM generations ORDER BY id DESC LIMIT 1",
            (),
        )
        .await
        .map_err(store_err)?;
    match rows.next().await.map_err(store_err)? {
        None => Ok(None),
        Some(row) => Ok(Some((cell_int(&row, 0)? as u64, cell_text(&row, 1)?))),
    }
}

// ---------------------------------------------------------------------------
// Cache clear
// ---------------------------------------------------------------------------

async fn run_clear(cfg: &config::Config, args: &repo_scan::cli::ClearArgs) -> ExitCode {
    if !args.all {
        return fail(&repo_scan::Error::InvalidArgs(
            "cache clear requires --all".to_string(),
        ));
    }
    match run_clear_inner(&cfg.state_dir).await {
        Ok(()) => ExitCode::Success,
        Err(e) => fail(&e),
    }
}

/// Remove only verified tool-owned persisted payload (spec §15): exact
/// known engine files + sidecars and internal snapshot/staging files, each
/// with per-file ownership proof (a tool-shaped name plus a catalog-bound
/// checksum row or tool-marker bytes bound to its filename) and verified
/// as a regular file (never a symlink) before removal. Unknown files are
/// preserved; a foreign catalog authorizes nothing; symlink substitution
/// anywhere on the reset path refuses the whole reset. Never a recursive
/// delete of the configured directory; the coordination lock is always
/// retained.
///
/// RS-PRIV-01: the payload/snapshots/staging dirs are FD-pinned for the
/// whole clear and every victim is opened with `openat(O_NOFOLLOW)`,
/// `fstat`'d, hashed, `(dev,ino)` re-compared, and removed with
/// `unlinkat` — the path string never names the victim. RS-PRIV-02: the
/// ownership marker drops only on an exact live-`db_id` binding.
/// RS-PRIV-09: entry/byte/time budgets bound the work; exhaustion prints
/// INCOMPLETE lines and never reports a complete cleanup.
///
/// Ancestor-symlink policy (FIXREADY4 C, explicit): symlinked ancestors
/// strictly ABOVE `state_dir` resolve normally — the trust-root model
/// shared with [`store::owner::ensure_private_dir_all`] (system prefixes
/// like `/tmp`/`/var` are legitimately symlinked on some platforms, and
/// the operator configured this path). Deletion through such an alias is
/// FD-bound traversal: the payload dir is pinned once and every victim
/// leaves through the held FD with `(dev, ino)` binding, so a swap
/// mid-clear refuses instead of redirecting. Symlinks AT `state_dir`,
/// `payload/`, the known dirs, or any known victim refuse the clear.
/// Refusal is atomic: the full deletion set preflights (lstat every
/// victim) BEFORE any unlink, so a refusal mutates nothing.
async fn run_clear_inner(state_dir: &Path) -> repo_scan::Result<()> {
    let payload = store::owner::payload_dir(state_dir);
    // Coordinate first: clearing requires exclusive ownership. The
    // existence check lives inside the lock (R15) so the decision sees
    // the state the guard actually serializes. The clear lock leaves
    // payload/ untouched (possibly unlistable/foreign/absent) for the
    // fail-closed inspection below.
    let _guard = acquire_guard_for_clear(state_dir)?;
    // Lstat semantics (FIXREADY4 C): a dangling payload symlink is an
    // ERROR (refuse, nonzero exit), never "already absent" success —
    // `Path::exists` follows links and misreads dangling as missing.
    match std::fs::symlink_metadata(&payload) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("cache clear: no persisted state; already absent (success)");
            return Ok(());
        }
        Err(e) => {
            return Err(repo_scan::Error::Io(format!(
                "cannot inspect {}: {e}",
                payload.display()
            )));
        }
        Ok(md) if md.file_type().is_symlink() => {
            return Err(unsafe_reset("payload dir is a symlink"));
        }
        Ok(md) if !md.is_dir() => {
            return Err(unsafe_reset("payload dir is not a directory"));
        }
        Ok(_) => {}
    }
    if is_symlink_path(state_dir)? {
        return Err(unsafe_reset("state dir is a symlink"));
    }
    let snapshots = payload.join(config::SNAPSHOTS_DIR_NAME);
    let staging = payload.join(config::STAGING_DIR_NAME);
    // No `.exists()` gate (FIXREADY4 C): `is_symlink_path` already
    // reports false for missing paths, and a DANGLING known-dir symlink
    // must refuse like any reset-path symlink — never skip silently.
    if is_symlink_path(&snapshots)? {
        return Err(unsafe_reset("snapshots dir is a symlink"));
    }
    if is_symlink_path(&staging)? {
        return Err(unsafe_reset("staging dir is a symlink"));
    }
    let mut st = ClearState::new();
    let payload_pin = match ClearPinnedDir::pin(&payload) {
        Ok(pin) => pin,
        Err(e) => {
            // Un-openable payload dir FD (macOS denies O_RDONLY dir
            // opens without read permission even when w+x child access
            // still works): degrade to path-validated removal and
            // report INCOMPLETE, never success-with-uninspected. The
            // degraded pin re-validates symlink/dir-ness, so a swapped
            // victim still refuses instead of degrading.
            st.incomplete.push(format!(
                "cannot pin {} for FD-relative clear; path-validated removal only ({e})",
                payload.display()
            ));
            ClearPinnedDir::pin_degraded(&payload)?
        }
    };

    // Database identity (R15): a fresh empty file is ours; a
    // populated engine file must carry tool ownership evidence — the
    // ownership marker exactly bound to the live catalog `db_id`
    // (RS-PRIV-02), or tool-shaped catalog bytes. A foreign SQLite
    // database without either stays.
    let db_path = payload.join("catalog.db");
    let (db_ours, marker_bound) =
        verify_db_identity(state_dir, &db_path, &payload_pin, &mut st).await?;
    // Snapshot row checksums while the catalog still exists: per-file
    // ownership proof needs the rows before the engine files go. A
    // missing/foreign/unreadable catalog yields no rows, so those files
    // then need tool-marker bytes or stay preserved.
    let (snapshot_rows, snapshot_truncated) =
        load_snapshot_rows(&db_path, db_ours, &snapshots, &mut st).await;
    if snapshot_truncated {
        st.incomplete.push(format!(
            "snapshot checksum rows truncated at the {SNAPSHOT_MAX_STEMS}-stem budget; \
             unscanned files stay preserved"
        ));
    }
    // FIXREADY4 C: full deletion-set preflight BEFORE any unlink. Every
    // known victim (engine files, sidecars, ownership marker) is opened
    // through the pinned payload FD, and the known dirs pin here — a
    // symlink (or an un-pinnable known dir) refuses the whole clear with
    // ZERO mutation. Previously catalog.db was removed before a symlinked
    // WAL or marker was even discovered. FIXREADY4 C1: the preflight
    // identities are BOUND into `set` and threaded through the entire
    // removal phase below — nothing re-pins or re-opens by bare name.
    let set = preflight_deletion_set(&payload_pin, &snapshots, &staging)?;
    remove_preflighted_files(
        state_dir,
        &payload_pin,
        &set,
        &db_path,
        &snapshots,
        &staging,
        db_ours,
        marker_bound,
        &snapshot_rows,
        &mut st,
    )?;
    // Unknown payload-root entries are listed, never touched. A
    // listing/read failure is INCOMPLETE (never success with
    // uninspected entries): the unknown content stays preserved.
    let payload_entries = match std::fs::read_dir(&payload) {
        Ok(entries) => Some(entries),
        Err(e) => {
            st.incomplete.push(format!(
                "cannot list {}; payload-root coverage incomplete ({e})",
                payload.display()
            ));
            st.note_preserved(format!(
                "{} (unlistable; content preserved)",
                payload.display()
            ));
            None
        }
    };
    if let Some(entries) = payload_entries {
        let mut scanned = 0usize;
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    st.incomplete.push(format!(
                        "cannot read a payload-root entry; coverage incomplete ({e})"
                    ));
                    st.note_preserved(format!(
                        "{} (unreadable entry; preserved)",
                        payload.display()
                    ));
                    continue;
                }
            };
            scanned += 1;
            if scanned > CLEAR_MAX_FILES_PER_DIR {
                st.incomplete.push(format!(
                    "payload listing truncated at the {CLEAR_MAX_FILES_PER_DIR}-entry budget; \
                     coverage incomplete"
                ));
                break;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if config::KNOWN_ENGINE_FILES.contains(&name.as_str())
                || config::KNOWN_SIDECAR_FILES.contains(&name.as_str())
                || name == config::SNAPSHOTS_DIR_NAME
                || name == config::STAGING_DIR_NAME
                || name == OWNER_MARKER_NAME
            {
                continue;
            }
            st.note_preserved(format!("{} (unknown; preserved)", entry.path().display()));
        }
    }
    // Remove only provably empty known dirs through validated parent
    // FDs with a (dev, ino) identity guard (RS-PRIV-01) — never a
    // path-based `remove_dir`, so a swap between check and removal
    // cannot redirect the victim. Never the state dir or lock.
    // Divergence preserves + reports incomplete, never a retry.
    // FIXREADY4 C1: the guard compares against the HELD preflight pins,
    // never freshly re-pinned identities.
    remove_known_empty_dir_expected(
        &payload_pin,
        config::SNAPSHOTS_DIR_NAME,
        set.snapshots.as_ref(),
        &mut st,
    );
    remove_known_empty_dir_expected(
        &payload_pin,
        config::STAGING_DIR_NAME,
        set.staging.as_ref(),
        &mut st,
    );
    // Round-3 C1b binding argument for the fresh state-dir pin (kept
    // deliberately instead of a threaded preflight pin): the removal is
    // bound by the CHILD identity, not the parent pin age —
    // `remove_empty_child_dir` re-opens `payload` from this pin's FD and
    // re-compares its `(dev, ino)` against the HELD preflight
    // `payload_pin` identity, so a state dir swapped mid-clear (fresh
    // pin binds the new tree) mismatches and preserves. A threaded pin
    // would need the identical `verify()` at use (dirs can swap during
    // the clear), buying nothing over pin-here-plus-held-child-expect.
    match ClearPinnedDir::pin(state_dir) {
        Ok(state_pin) => {
            state_pin.remove_empty_child_dir("payload", payload_pin.identity(), &mut st);
        }
        Err(e) => {
            st.incomplete.push(format!(
                "cannot re-validate the state dir for payload removal; preserved ({e})"
            ));
            st.note_preserved(format!("{} (preserved)", payload.display()));
        }
    }
    if st.incomplete.is_empty() {
        println!("cache clear: removed {} tool-owned file(s)", st.removed);
    } else {
        println!("cache clear: INCOMPLETE: budgets exhausted; coverage incomplete");
        for line in &st.incomplete {
            println!("  incomplete: {line}");
        }
        println!(
            "cache clear: removed {} tool-owned file(s) before stopping; rerun or inspect manually",
            st.removed
        );
    }
    st.report_preserved();
    Ok(())
}

/// Mutable clear progress plus RS-PRIV-09 budget state.
struct ClearState {
    removed: u64,
    preserved: Vec<String>,
    preserved_overflow: usize,
    bytes_hashed: u64,
    deadline: Instant,
    incomplete: Vec<String>,
}

impl ClearState {
    fn new() -> Self {
        Self {
            removed: 0,
            preserved: Vec::new(),
            preserved_overflow: 0,
            bytes_hashed: 0,
            deadline: Instant::now() + Duration::from_secs(CLEAR_DEADLINE_SECS),
            incomplete: Vec::new(),
        }
    }

    /// Record a preserved entry; past [`CLEAR_MAX_PRESERVED`] only the
    /// overflow count grows (the list itself stays bounded).
    fn note_preserved(&mut self, item: String) {
        if self.preserved.len() < CLEAR_MAX_PRESERVED {
            self.preserved.push(item);
        } else {
            self.preserved_overflow += 1;
        }
    }

    fn expired(&self) -> bool {
        Instant::now() > self.deadline
    }

    fn report_preserved(&self) {
        let total = self.preserved.len() + self.preserved_overflow;
        if total == 0 {
            println!("cache clear: no foreign files encountered");
            return;
        }
        println!("cache clear: preserved {total} foreign file(s):");
        for item in self.preserved.iter().take(20) {
            println!("  preserved: {item}");
        }
        if total > 20 {
            println!("  ... and {} more", total - 20);
        }
        if self.preserved_overflow > 0 {
            println!("  (preserved list truncated at {CLEAR_MAX_PRESERVED}; coverage incomplete)");
        }
    }
}

/// FD-pinned clear directory (RS-PRIV-01): on unix an
/// `O_NOFOLLOW|O_DIRECTORY` FD plus the `(dev, ino)` observed at pin,
/// held for the whole clear. Victims open with `openat(O_NOFOLLOW)` from
/// this FD and leave with `unlinkat` after a `(dev, ino)` re-compare; the
/// path string never names the victim. Elsewhere the same checks run on
/// paths (documented residual: no FD pinning off-unix). A degraded unix
/// pin ([`ClearPinnedDir::pin_degraded`], `file: None`) covers
/// directories whose FD cannot be opened (macOS denies `O_RDONLY` dir
/// opens without read permission even when w+x child access still
/// works): the same checks run on paths with a `(dev, ino)` re-compare,
/// and the caller reports INCOMPLETE, never a complete cleanup.
struct ClearPinnedDir {
    path: PathBuf,
    #[cfg(unix)]
    file: Option<std::fs::File>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl ClearPinnedDir {
    fn pin(path: &Path) -> repo_scan::Result<Self> {
        #[cfg(unix)]
        {
            let file = store::owner::open_dir_nofollow(path)?;
            let (dev, ino) = store::owner::fd_identity(&file)?;
            Ok(Self {
                path: path.to_path_buf(),
                file: Some(file),
                dev,
                ino,
            })
        }
        #[cfg(not(unix))]
        {
            if is_symlink_path(path)? {
                return Err(unsafe_reset("clear directory is a symlink"));
            }
            Ok(Self {
                path: path.to_path_buf(),
            })
        }
    }

    /// Path-validated pin for a directory whose FD cannot be opened: the
    /// path must currently be a non-symlink directory, and its `(dev,
    /// ino)` is recorded for later re-compare. Symlinks and non-dirs
    /// refuse (fail closed), so only a permission-denied pin on a
    /// genuine directory degrades — never a swapped victim.
    #[cfg(unix)]
    fn pin_degraded(path: &Path) -> repo_scan::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        if is_symlink_path(path)? {
            return Err(unsafe_reset("clear directory is a symlink"));
        }
        let meta = std::fs::metadata(path)
            .map_err(|e| repo_scan::Error::Io(format!("cannot inspect {}: {e}", path.display())))?;
        if !meta.is_dir() {
            return Err(unsafe_reset("clear directory is not a directory"));
        }
        Ok(Self {
            path: path.to_path_buf(),
            file: None,
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }

    /// Off-unix pins are already path-validated, so the degraded pin is
    /// just the pin (a symlink still refuses).
    #[cfg(not(unix))]
    fn pin_degraded(path: &Path) -> repo_scan::Result<Self> {
        Self::pin(path)
    }

    /// Fail closed unless the pinned directory is unchanged: under the
    /// held FD for a pinned dir, or by path re-validation (`(dev, ino)`
    /// re-compare) for a degraded pin.
    fn verify(&self) -> repo_scan::Result<()> {
        #[cfg(unix)]
        {
            let Some(file) = self.file.as_ref() else {
                return self.verify_degraded();
            };
            let (fd_dev, fd_ino) = store::owner::fd_identity(file)?;
            if (fd_dev, fd_ino) != (self.dev, self.ino) {
                return Err(unsafe_reset("clear directory changed under the held FD"));
            }
            if is_symlink_path(&self.path)? {
                return Err(unsafe_reset("clear directory is now a symlink"));
            }
            let restated =
                std::fs::metadata(&self.path).map_err(|e| unsafe_reset(&e.to_string()))?;
            {
                use std::os::unix::fs::MetadataExt;
                if (restated.dev(), restated.ino()) != (self.dev, self.ino) || !restated.is_dir() {
                    return Err(unsafe_reset(
                        "clear directory changed (dev,ino) under the held FD",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Degraded-pin re-validation (unix only): the path must still be a
    /// non-symlink directory with the `(dev, ino)` observed at pin.
    #[cfg(unix)]
    fn verify_degraded(&self) -> repo_scan::Result<()> {
        use std::os::unix::fs::MetadataExt;
        if is_symlink_path(&self.path)? {
            return Err(unsafe_reset("clear directory is now a symlink"));
        }
        let restated = std::fs::metadata(&self.path).map_err(|e| unsafe_reset(&e.to_string()))?;
        if (restated.dev(), restated.ino()) != (self.dev, self.ino) || !restated.is_dir() {
            return Err(unsafe_reset(
                "clear directory changed (dev,ino) under the held path",
            ));
        }
        Ok(())
    }

    /// Open `name` for reading without following a trailing symlink:
    /// `openat(O_NOFOLLOW)` on unix, `symlink_metadata` + open elsewhere
    /// and for a degraded unix pin. Missing files yield `Ok(None)`;
    /// symlinks refuse the reset.
    fn open_child(&self, name: &str) -> repo_scan::Result<Option<std::fs::File>> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::io::{AsRawFd, FromRawFd};
            let bytes = std::ffi::OsStr::new(name).as_bytes();
            if bytes.is_empty() || bytes.contains(&0) || name.contains('/') {
                return Err(unsafe_reset("refusing unsafe clear name"));
            }
            let cname =
                std::ffi::CString::new(bytes).map_err(|_| unsafe_reset("bad clear name"))?;
            let Some(dir) = self.file.as_ref() else {
                return self.open_child_by_path(name);
            };
            // SAFETY: `openat` on the held dir FD with a valid
            // NUL-terminated single-component name; ownership moves into
            // `File` exactly once.
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    cname.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let errno = std::io::Error::last_os_error();
                if errno.raw_os_error() == Some(libc::ENOENT) {
                    return Ok(None);
                }
                if errno.raw_os_error() == Some(libc::ELOOP) {
                    return Err(unsafe_reset(&format!("engine path is a symlink: {name}")));
                }
                return Err(repo_scan::Error::Io(format!(
                    "cannot open {}: {errno}",
                    self.path.join(name).display()
                )));
            }
            // SAFETY: `fd` is a fresh owned FD from the successful `openat`.
            Ok(Some(unsafe { std::fs::File::from_raw_fd(fd) }))
        }
        #[cfg(not(unix))]
        {
            let path = self.path.join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(md) if md.file_type().is_symlink() => Err(unsafe_reset(&format!(
                    "engine path is a symlink: {}",
                    path.display()
                ))),
                Ok(_) => Ok(Some(std::fs::File::open(&path)?)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(repo_scan::Error::Io(format!(
                    "cannot inspect {}: {e}",
                    path.display()
                ))),
            }
        }
    }

    /// Degraded-pin child open (unix only): `symlink_metadata` + open,
    /// mirroring the off-unix branch. Round-3 C1b binding argument (kept
    /// deliberately): this path only READS — every degraded mutation
    /// downstream re-binds `(dev, ino)` against the caller-bound
    /// identity immediately before the unlink
    /// ([`ClearPinnedDir::remove_child_by_path`]) and refuses loudly on
    /// mismatch, so a by-path open can never silently authorize a
    /// by-path mutation. Reads feed content/identity gates (magic,
    /// hash, marker compare) whose failures preserve, never remove.
    #[cfg(unix)]
    fn open_child_by_path(&self, name: &str) -> repo_scan::Result<Option<std::fs::File>> {
        let path = self.path.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(md) if md.file_type().is_symlink() => Err(unsafe_reset(&format!(
                "engine path is a symlink: {}",
                path.display()
            ))),
            Ok(_) => match std::fs::File::open(&path) {
                Ok(file) => Ok(Some(file)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(repo_scan::Error::Io(format!(
                    "cannot open {}: {e}",
                    path.display()
                ))),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(repo_scan::Error::Io(format!(
                "cannot inspect {}: {e}",
                path.display()
            ))),
        }
    }

    /// True when `name` is present (any kind). Symlinks refuse the reset.
    fn child_present(&self, name: &str) -> repo_scan::Result<bool> {
        Ok(self.open_child(name)?.is_some())
    }

    /// Unlink one entry through the held dir FD with NO re-open
    /// (FIXREADY4 C1, round-3 C1b): the caller already bound the victim —
    /// engine files by an open-FD `(dev, ino)` re-compare against the
    /// preflight observation, snapshot/staging files by a content hash
    /// read from the open FD — so re-opening here would only widen the
    /// swap window. The parent still re-verifies first. Unix uses
    /// `unlinkat` from the pinned FD (a vanished entry reads as
    /// converged); a degraded unix pin removes through
    /// [`ClearPinnedDir::remove_child_by_path`], which re-binds
    /// `(dev, ino)` against `expect` immediately before the unlink and
    /// refuses loudly on mismatch (no silent by-path mutation).
    ///
    /// Accepted residual (round-3 C1b, documented honestly): POSIX has
    /// no unlink-by-FD, so a microsecond window stands between the last
    /// bind (caller hash/`fstat`, or the degraded `stat`) and the
    /// `unlinkat` name resolution. A rename-plant inside that window
    /// needs payload-dir write — and anyone holding payload-dir write
    /// can unlink directly, so the race buys an attacker nothing but
    /// attribution. `unlinkat` with flags 0 never follows a trailing
    /// symlink (a planted link is itself removed, its target
    /// untouched) — but that does NOT bound the blast to "link
    /// removal": a plant that renames a DIFFERENT same-dir entry (last
    /// link to live data) onto the victim name redirects this unlink
    /// onto that data. One same-dir entry per race won; window analysis
    /// above is why the residual is accepted rather than fixed.
    fn unlink_pinned_child(&self, name: &str, expect: (u64, u64)) -> repo_scan::Result<()> {
        self.verify()?;
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::io::AsRawFd;
            let bytes = std::ffi::OsStr::new(name).as_bytes();
            if bytes.is_empty() || bytes.contains(&0) || name.contains('/') {
                return Err(unsafe_reset("refusing unsafe clear name"));
            }
            let cname =
                std::ffi::CString::new(bytes).map_err(|_| unsafe_reset("bad clear name"))?;
            let Some(dir) = self.file.as_ref() else {
                return self.remove_child_by_path(name, expect);
            };
            let _ = expect;
            // SAFETY: `unlinkat` on the held dir FD with a valid
            // NUL-terminated single-component name unlinks only that entry.
            let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) };
            if rc != 0 {
                let errno = std::io::Error::last_os_error();
                if errno.raw_os_error() == Some(libc::ENOENT) {
                    return Ok(());
                }
                return Err(repo_scan::Error::Io(format!(
                    "cannot remove {}: {errno}",
                    self.path.join(name).display()
                )));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = expect;
            let path = self.path.join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(md) if md.file_type().is_symlink() => Err(unsafe_reset(&format!(
                    "engine path is a symlink: {}",
                    path.display()
                ))),
                Ok(_) => match std::fs::remove_file(&path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(repo_scan::Error::Io(format!(
                        "cannot remove {}: {e}",
                        path.display()
                    ))),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(repo_scan::Error::Io(format!(
                    "cannot inspect {}: {e}",
                    path.display()
                ))),
            }
        }
    }

    /// Degraded-pin child removal (unix only): the victim path is
    /// re-statted (symlinks refuse) and its `(dev, ino)` is re-bound
    /// against `expect` — the identity the caller bound (preflight
    /// observation for engine files, open-FD identity of the hashed
    /// bytes for snapshots/staging) — immediately before the unlink,
    /// mirroring [`ClearPinnedDir::remove_empty_child_dir_by_path`]. A
    /// mismatch refuses LOUDLY (round-3 C1b: no silent by-path
    /// mutation); a vanished victim reads as converged. Residual: the
    /// `stat`→`unlink` microsecond window (see
    /// [`ClearPinnedDir::unlink_pinned_child`); a swap inside it still
    /// needs payload-dir write.
    #[cfg(unix)]
    fn remove_child_by_path(&self, name: &str, expect: (u64, u64)) -> repo_scan::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let path = self.path.join(name);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(md) if md.file_type().is_symlink() => {
                return Err(unsafe_reset(&format!(
                    "engine path is a symlink: {}",
                    path.display()
                )));
            }
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(repo_scan::Error::Io(format!(
                    "cannot inspect {}: {e}",
                    path.display()
                )));
            }
        };
        if (meta.dev(), meta.ino()) != expect {
            return Err(unsafe_reset(&format!(
                "victim {name} changed between bind and unlink; refusing"
            )));
        }
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(repo_scan::Error::Io(format!(
                "cannot remove {}: {e}",
                path.display()
            ))),
        }
    }

    /// `(dev, ino)` observed at pin time (unix); `(0, 0)` elsewhere.
    fn identity(&self) -> (u64, u64) {
        #[cfg(unix)]
        {
            (self.dev, self.ino)
        }
        #[cfg(not(unix))]
        {
            (0, 0)
        }
    }

    /// Remove empty known child dir `name` from this validated parent:
    /// re-verify the parent, re-open the child with
    /// `openat(O_NOFOLLOW|O_DIRECTORY)` from the parent FD, re-compare
    /// its `(dev, ino)` against `expect`, and remove with
    /// `unlinkat(AT_REMOVEDIR)` — never a path-based `remove_dir`, so a
    /// swap between check and removal cannot redirect the victim (the
    /// syscall itself enforces emptiness atomically). A vanished child
    /// reads as converged; a non-empty child stays preserved with
    /// incomplete (entries may have raced in after the scan);
    /// divergence preserves + reports incomplete. Unix uses the pinned
    /// FD; elsewhere (and for a degraded unix pin) the path is
    /// re-statted and removed (documented residual: no FD pinning
    /// off-unix or degraded).
    fn remove_empty_child_dir(&self, name: &str, expect: (u64, u64), st: &mut ClearState) {
        let display = self.path.join(name);
        if let Err(e) = self.verify() {
            st.incomplete.push(format!(
                "parent {} changed during clear; {} preserved ({e})",
                self.path.display(),
                display.display()
            ));
            st.note_preserved(format!("{} (preserved)", display.display()));
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::io::{AsRawFd, FromRawFd};
            let bytes = std::ffi::OsStr::new(name).as_bytes();
            if bytes.is_empty() || bytes.contains(&0) || name.contains('/') {
                st.incomplete.push(format!(
                    "refusing unsafe clear name for {}; preserved",
                    display.display()
                ));
                st.note_preserved(format!("{} (preserved)", display.display()));
                return;
            }
            let cname = match std::ffi::CString::new(bytes) {
                Ok(cname) => cname,
                Err(_) => {
                    st.incomplete.push(format!(
                        "bad clear name for {}; preserved",
                        display.display()
                    ));
                    st.note_preserved(format!("{} (preserved)", display.display()));
                    return;
                }
            };
            let Some(dir) = self.file.as_ref() else {
                self.remove_empty_child_dir_by_path(name, expect, st);
                return;
            };
            // SAFETY: `openat` on the held dir FD with a valid
            // NUL-terminated single-component name; ownership moves into
            // `File` exactly once.
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    cname.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let errno = std::io::Error::last_os_error();
                if errno.raw_os_error() == Some(libc::ENOENT) {
                    return;
                }
                if errno.raw_os_error() == Some(libc::ELOOP) {
                    st.incomplete
                        .push(format!("{} is a symlink; preserved", display.display()));
                } else {
                    st.incomplete.push(format!(
                        "cannot open {}; preserved ({errno})",
                        display.display()
                    ));
                }
                st.note_preserved(format!("{} (preserved)", display.display()));
                return;
            }
            // SAFETY: `fd` is a fresh owned FD from the successful `openat`.
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            if store::owner::fd_identity(&file).unwrap_or((u64::MAX, u64::MAX)) != expect {
                st.incomplete.push(format!(
                    "{} changed (dev, ino) before removal; preserved",
                    display.display()
                ));
                st.note_preserved(format!("{} (preserved)", display.display()));
                return;
            }
            drop(file);
            // SAFETY: `unlinkat(AT_REMOVEDIR)` on the held dir FD with a
            // valid NUL-terminated single-component name removes only that
            // (provably empty) entry.
            let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), libc::AT_REMOVEDIR) };
            if rc != 0 {
                let errno = std::io::Error::last_os_error();
                if errno.raw_os_error() == Some(libc::ENOENT) {
                    return;
                }
                if matches!(
                    errno.raw_os_error(),
                    Some(libc::ENOTEMPTY) | Some(libc::EEXIST)
                ) {
                    st.incomplete.push(format!(
                        "{} is non-empty after clear; content preserved",
                        display.display()
                    ));
                } else {
                    st.incomplete.push(format!(
                        "cannot remove {}; preserved ({errno})",
                        display.display()
                    ));
                }
                st.note_preserved(format!("{} (preserved)", display.display()));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = expect;
            match std::fs::symlink_metadata(&display) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Ok(md) if md.file_type().is_symlink() => {
                    st.incomplete
                        .push(format!("{} is a symlink; preserved", display.display()));
                    st.note_preserved(format!("{} (preserved)", display.display()));
                }
                Ok(_) => match std::fs::remove_dir(&display) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        st.incomplete.push(format!(
                            "cannot remove {}; preserved ({e})",
                            display.display()
                        ));
                        st.note_preserved(format!("{} (preserved)", display.display()));
                    }
                },
                Err(e) => {
                    st.incomplete.push(format!(
                        "cannot inspect {}; preserved ({e})",
                        display.display()
                    ));
                    st.note_preserved(format!("{} (preserved)", display.display()));
                }
            }
        }
    }

    /// Degraded-pin empty-dir removal (unix only): the child path is
    /// re-statted (symlinks refuse, `(dev, ino)` must still match
    /// `expect`) and removed with `remove_dir` (which itself enforces
    /// emptiness atomically); a non-empty child stays preserved with
    /// incomplete. Mirrors the off-unix branch plus the identity
    /// re-compare.
    #[cfg(unix)]
    fn remove_empty_child_dir_by_path(&self, name: &str, expect: (u64, u64), st: &mut ClearState) {
        use std::os::unix::fs::MetadataExt;
        let display = self.path.join(name);
        let meta = match std::fs::symlink_metadata(&display) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                st.incomplete.push(format!(
                    "cannot inspect {}; preserved ({e})",
                    display.display()
                ));
                st.note_preserved(format!("{} (preserved)", display.display()));
                return;
            }
            Ok(md) if md.file_type().is_symlink() => {
                st.incomplete
                    .push(format!("{} is a symlink; preserved", display.display()));
                st.note_preserved(format!("{} (preserved)", display.display()));
                return;
            }
            Ok(md) => md,
        };
        if (meta.dev(), meta.ino()) != expect || !meta.is_dir() {
            st.incomplete.push(format!(
                "{} changed (dev, ino) before removal; preserved",
                display.display()
            ));
            st.note_preserved(format!("{} (preserved)", display.display()));
            return;
        }
        match std::fs::remove_dir(&display) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                st.incomplete.push(format!(
                    "{} is non-empty after clear; content preserved",
                    display.display()
                ));
                st.note_preserved(format!("{} (preserved)", display.display()));
            }
            Err(e) => {
                st.incomplete.push(format!(
                    "cannot remove {}; preserved ({e})",
                    display.display()
                ));
                st.note_preserved(format!("{} (preserved)", display.display()));
            }
        }
    }
}

/// Remove one known (possibly already absent) empty child directory
/// through the validated parent FD against the HELD preflight pin
/// (FIXREADY4 C1): the child is never re-pinned by name, so the
/// `(dev, ino)` compare in
/// [`ClearPinnedDir::remove_empty_child_dir`] is against the preflight
/// observation, not a fresh self-compare. Missing-at-preflight still
/// verifies absence via `symlink_metadata` (a raced-in entry preserves +
/// reports incomplete, never silently converges); a held pin that no
/// longer verifies preserves + reports incomplete. Never a path-based
/// `remove_dir`.
fn remove_known_empty_dir_expected(
    parent: &ClearPinnedDir,
    name: &str,
    held: Option<&ClearPinnedDir>,
    st: &mut ClearState,
) {
    let display = parent.path.join(name);
    let Some(pin) = held else {
        match std::fs::symlink_metadata(&display) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                st.incomplete.push(format!(
                    "cannot inspect {}; preserved ({e})",
                    display.display()
                ));
                st.note_preserved(format!("{} (preserved)", display.display()));
                return;
            }
            Ok(md) if md.file_type().is_symlink() => {
                st.incomplete.push(format!(
                    "{} raced in as a symlink after preflight; preserved",
                    display.display()
                ));
                st.note_preserved(format!("{} (symlink; preserved)", display.display()));
                return;
            }
            Ok(_) => {
                st.incomplete.push(format!(
                    "{} raced in after preflight; preserved",
                    display.display()
                ));
                st.note_preserved(format!("{} (preserved)", display.display()));
                return;
            }
        }
    };
    if let Err(e) = pin.verify() {
        st.incomplete.push(format!(
            "{} changed during clear; preserved ({e})",
            display.display()
        ));
        st.note_preserved(format!("{} (preserved)", display.display()));
        return;
    }
    parent.remove_empty_child_dir(name, pin.identity(), st);
}

fn unsafe_reset(detail: &str) -> repo_scan::Error {
    repo_scan::Error::Store(format!("refusing unsafe cache clear: {detail}"))
}

fn is_symlink_path(path: &Path) -> repo_scan::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(md) => Ok(md.file_type().is_symlink()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(repo_scan::Error::Io(format!(
            "cannot inspect {}: {e}",
            path.display()
        ))),
    }
}

/// Verify the engine path holds our database (or nothing). Returns
/// `(db_ours, marker_bound)`: symlinks refuse the reset; non-file or
/// foreign-content paths are preserved, not removed. Populated files
/// additionally require tool ownership evidence (R15): the marker exactly
/// bound to the live catalog `db_id` (RS-PRIV-02), else tool-shaped
/// catalog bytes. The victim opens through the pinned payload FD
/// (RS-PRIV-01), never by path.
async fn verify_db_identity(
    state_dir: &Path,
    db_path: &Path,
    payload_pin: &ClearPinnedDir,
    st: &mut ClearState,
) -> repo_scan::Result<(bool, bool)> {
    verify_db_identity_inner(state_dir, db_path, payload_pin, st, None).await
}

/// [`verify_db_identity`] with a deterministic pre-store-open plant hook
/// (round-3 C1b seam): `plant` runs after the victim FD opens (and the
/// magic check passes) but before the read-only store open, so the seam
/// test plants a swapped catalog between the two real opens. Production
/// passes `None`.
async fn verify_db_identity_inner(
    state_dir: &Path,
    db_path: &Path,
    payload_pin: &ClearPinnedDir,
    st: &mut ClearState,
    plant: Option<fn(&Path) -> std::io::Result<()>>,
) -> repo_scan::Result<(bool, bool)> {
    let mut file = match payload_pin.open_child("catalog.db")? {
        Some(file) => file,
        None => return Ok((true, false)),
    };
    if !file.metadata()?.is_file() {
        st.note_preserved(format!("{} (not a file; preserved)", db_path.display()));
        return Ok((false, false));
    }
    if file.metadata()?.len() == 0 {
        return Ok((true, false));
    }
    let mut magic = [0u8; 16];
    {
        use std::io::Read;
        if file.read_exact(&mut magic).is_err() {
            st.note_preserved(format!("{} (unreadable; preserved)", db_path.display()));
            return Ok((false, false));
        }
    }
    if magic != *b"SQLite format 3\0" {
        st.note_preserved(format!(
            "{} (not a database file; preserved)",
            db_path.display()
        ));
        return Ok((false, false));
    }
    if let Some(plant) = plant {
        plant(db_path).map_err(|e| repo_scan::Error::Io(format!("seam plant failed: {e}")))?;
    }
    // SQLite magic alone never proves ownership (R15): require the marker
    // exactly bound to the live catalog, else tool-shaped catalog bytes.
    // An un-openable catalog (e.g. its dir lost read permission, so the
    // store's own dir pin fails) still gets the shape check below: the
    // head bytes need only the already-open victim FD.
    //
    // Round-3 C1b: the store opens BY PATH after our FD open, so its
    // `db_id` is trusted only when the open resolved to our HELD victim
    // (`catalog_identity` re-bound against the FD's `(dev, ino)`).
    // Reading an unbound file's `db_id` would let a catalog swapped in
    // between the two opens authorize a FOREIGN victim (and its marker).
    // A mismatch (or an unbound open) falls through to the shape check
    // on the HELD bytes below — the marker then stays, fail closed.
    let store = TursoStore::open_read_only(db_path).await.ok();
    if let Some(store) = store {
        #[cfg(unix)]
        let bound_to_victim = store.catalog_identity() == Some(store::owner::fd_identity(&file)?);
        // Off-unix there is no FD identity to bind against (documented
        // platform residual: path-resolution trust, as everywhere else
        // off-unix).
        #[cfg(not(unix))]
        let bound_to_victim = true;
        if bound_to_victim {
            let bound = catalog_bound_to_marker(&store, state_dir).await?;
            let _ = store.close().await;
            if bound {
                return Ok((true, true));
            }
        } else {
            let _ = store.close().await;
        }
    }
    if catalog_head_looks_tool_owned(&read_head_bytes(&mut file)?) {
        // Tool-shaped but marker-unbound (e.g. built without a binary
        // open): the engine file may go, the marker (if any) stays.
        return Ok((true, false));
    }
    st.note_preserved(format!(
        "{} (SQLite database without tool ownership evidence; preserved)",
        db_path.display()
    ));
    Ok((false, false))
}

/// RS-PRIV-02/06: exact ownership binding between an open catalog and the
/// ownership marker. The live `meta.db_id` and the marker's `db_id=` line
/// must both exist and compare byte-equal; anything else (missing marker,
/// wrong tag, missing row, mismatch) is unbound. A substituted symlink or
/// non-regular marker fails closed via the pinned read.
async fn catalog_bound_to_marker(store: &TursoStore, state_dir: &Path) -> repo_scan::Result<bool> {
    let live = match store.catalog_db_id().await? {
        Some(id) => id,
        None => return Ok(false),
    };
    let Some(text) = store::owner::read_owner_marker_text(state_dir)? else {
        return Ok(false);
    };
    let mut lines = text.lines();
    if lines.next() != Some(OWNER_MARKER_TAG) {
        return Ok(false);
    }
    for line in lines {
        if let Some(id) = line.strip_prefix("db_id=") {
            return Ok(!id.is_empty() && id == live);
        }
    }
    Ok(false)
}

/// Catalog schema markers: tables every tool-created catalog carries from
/// schema v1. Catalogs built through the store without a binary open (no
/// marker) still verify through their bytes.
const DB_SCHEMA_MARKERS: [&[u8]; 4] = [
    b"frontier_tasks",
    b"report_snapshots",
    b"event_journal",
    b"scope_revisions",
];

/// Read the identity-scan head (rewinding first) from an already-open
/// victim FD. Short reads yield short heads; errors read as empty (the
/// shape check then fails, preserving the file).
fn read_head_bytes(file: &mut std::fs::File) -> repo_scan::Result<Vec<u8>> {
    use std::io::{Read, Seek};
    let _ = file.seek(std::io::SeekFrom::Start(0));
    let mut head = vec![0u8; DB_IDENTITY_SCAN_BYTES as usize];
    let len = file.read(&mut head).unwrap_or(0);
    head.truncate(len);
    Ok(head)
}

/// True when the engine file's head carries enough catalog schema markers
/// to be tool-shaped. At least two must match so a stray string in a
/// foreign database cannot qualify it.
fn catalog_head_looks_tool_owned(head: &[u8]) -> bool {
    let mut hits = 0;
    for marker in DB_SCHEMA_MARKERS {
        let marker: &[u8] = marker;
        if head.len() >= marker.len() && head.windows(marker.len()).any(|w| w == marker) {
            hits += 1;
        }
    }
    hits >= 2
}

/// Preflight-bound deletion set (FIXREADY4 C1): every identity the
/// removal phase may unlink is observed here and HELD through deletion —
/// victim `(dev, ino)` values plus the known-dir pins themselves (FDs on
/// unix). The removal phase re-opens victims only through the held
/// payload FD and unlinks only when the live identity still equals the
/// preflight one, so a swap between preflight and removal refuses
/// instead of deleting a substituted victim. A `(dev, ino)` compare
/// against a freshly observed identity would be vacuous (a file always
/// equals itself); binding through this set is what makes each compare
/// meaningful.
///
/// Residual: the final `fstat`-then-`unlinkat` step is two syscalls and
/// POSIX offers no unlink-by-FD, so a swap landing exactly between them
/// still unlinks the planted name. That window holds no other syscall
/// and never follows a link (`unlinkat` removes the entry itself), and
/// any wider race refuses loudly (never false success) — but
/// never-partial-on-RACE is unachievable without transactional unlink,
/// which is why the deterministic seam test pins refuse-loudly rather
/// than zero-mutation for mid-clear swaps.
struct PreflightedDeletionSet {
    /// Engine + sidecar victims in removal order: `(name,
    /// identity-at-preflight)`, where `None` means absent at preflight
    /// (a victim that races in afterwards refuses).
    engine: Vec<(String, Option<(u64, u64)>)>,
    /// Ownership-marker identity at preflight (`None` = absent).
    marker: Option<(u64, u64)>,
    /// Held known-dir pins (`None` = absent at preflight). The removal
    /// phase reuses these pins — it never re-pins by name.
    snapshots: Option<ClearPinnedDir>,
    staging: Option<ClearPinnedDir>,
}

impl PreflightedDeletionSet {
    /// Preflight identity for one engine/sidecar victim name.
    fn engine_expect(&self, name: &str) -> Option<(u64, u64)> {
        self.engine
            .iter()
            .find(|(known, _)| known == name)
            .and_then(|(_, expect)| *expect)
    }
}

/// Open every known clear victim through the pinned payload FD before
/// any unlink (FIXREADY4 C atomicity) and BIND the observed identities
/// into the returned set for the removal phase (FIXREADY4 C1).
/// Engine files, sidecars, and the ownership marker record their
/// `(dev, ino)` (or absence); `open_child` refuses symlinks (including
/// dangling ones), so a substituted victim refuses the whole clear here
/// with zero mutation. Snapshot/staging dirs pin here too and the pins
/// are HELD in the set, so an unusable known dir refuses before any
/// mutation rather than after the engine files are gone, and the
/// removal phase never re-resolves them by name.
/// Returns `Ok` only when the entire deletion set was inspected.
fn preflight_deletion_set(
    payload_pin: &ClearPinnedDir,
    snapshots: &Path,
    staging: &Path,
) -> repo_scan::Result<PreflightedDeletionSet> {
    payload_pin.verify()?;
    let mut engine = Vec::new();
    for name in config::KNOWN_ENGINE_FILES
        .iter()
        .chain(config::KNOWN_SIDECAR_FILES.iter())
    {
        engine.push((
            name.to_string(),
            preflight_victim_identity(payload_pin, name)?,
        ));
    }
    let marker = preflight_victim_identity(payload_pin, OWNER_MARKER_NAME)?;
    let mut pins = Vec::new();
    for dir in [snapshots, staging] {
        match std::fs::symlink_metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => pins.push(None),
            Err(e) => {
                return Err(repo_scan::Error::Io(format!(
                    "cannot inspect {}: {e}",
                    dir.display()
                )));
            }
            Ok(_) => {
                pins.push(Some(ClearPinnedDir::pin(dir)?));
            }
        }
    }
    let mut pins = pins.into_iter();
    Ok(PreflightedDeletionSet {
        engine,
        marker,
        snapshots: pins.next().unwrap_or(None),
        staging: pins.next().unwrap_or(None),
    })
}

/// `(dev, ino)` of one preflight victim opened through the held payload
/// FD: `None` when absent (nothing to remove — and anything raced in
/// afterwards refuses), the live identity otherwise. Symlinks (including
/// dangling ones) refuse; non-regular entries record their identity for
/// the removal phase, which preserves them only when still identical.
fn preflight_victim_identity(
    payload_pin: &ClearPinnedDir,
    name: &str,
) -> repo_scan::Result<Option<(u64, u64)>> {
    let Some(file) = payload_pin.open_child(name)? else {
        return Ok(None);
    };
    #[cfg(unix)]
    {
        Ok(Some(store::owner::fd_identity(&file)?))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(Some((0, 0)))
    }
}

/// Removal phase bound to a preflight set (FIXREADY4 C1): engine files,
/// sidecars, known-dir contents, and the ownership marker leave only
/// through the held payload FD against the preflight identities in
/// `set` — nothing here re-pins or re-opens by bare name. Order matches
/// the historical removal order (engine files, tool dirs, marker); the
/// payload listing and empty-dir removal stay in the caller, with the
/// empty-dir phase taking the same held pins. Shared by
/// [`run_clear_inner`] and the deterministic seam hook
/// [`test_clear_preflight_removal_seam`].
#[allow(clippy::too_many_arguments)]
fn remove_preflighted_files(
    state_dir: &Path,
    payload_pin: &ClearPinnedDir,
    set: &PreflightedDeletionSet,
    db_path: &Path,
    snapshots: &Path,
    staging: &Path,
    db_ours: bool,
    marker_bound: bool,
    snapshot_rows: &HashMap<String, String>,
    st: &mut ClearState,
) -> repo_scan::Result<()> {
    if db_ours {
        for name in config::KNOWN_ENGINE_FILES
            .iter()
            .chain(config::KNOWN_SIDECAR_FILES.iter())
        {
            remove_pinned_file_expected(payload_pin, name, set.engine_expect(name), st)?;
        }
    } else if db_path.exists() {
        st.note_preserved(format!(
            "{} (unknown content; database left in place)",
            db_path.display()
        ));
    }
    clear_tool_dir_expected(
        snapshots,
        set.snapshots.as_ref(),
        ClearDirKind::Snapshots,
        db_ours,
        snapshot_rows,
        st,
    )?;
    clear_tool_dir_expected(
        staging,
        set.staging.as_ref(),
        ClearDirKind::Staging,
        db_ours,
        snapshot_rows,
        st,
    )?;
    // RS-PRIV-02: the ownership marker drops only when it exactly binds
    // the live catalog; otherwise it stays (a substituted symlink
    // refuses, like any reset-path symlink).
    if marker_bound {
        remove_pinned_file_expected(payload_pin, OWNER_MARKER_NAME, set.marker, st)?;
    } else if payload_pin.child_present(OWNER_MARKER_NAME)? {
        st.note_preserved(format!(
            "{} (not bound to the live catalog; preserved)",
            owner_marker_path(state_dir).display()
        ));
    }
    Ok(())
}

/// Remove one exact known file from a pinned dir when — and only
/// when — its live identity still equals the PREFLIGHT one (FIXREADY4
/// C1): the victim re-opens through the held FD and its `(dev, ino)`
/// re-compares against `expect` immediately before `unlinkat`
/// (RS-PRIV-01), with no re-resolution between the compare and the
/// unlink. A victim that vanished reads as converged (`Ok`); a victim
/// whose identity changed, or that raced in after an absent preflight
/// (`expect == None`), refuses the reset. Non-regular victims preserve
/// (existing behavior) but only when still the preflight identity — a
/// swapped-in non-regular refuses like any other swap.
fn remove_pinned_file_expected(
    dir: &ClearPinnedDir,
    name: &str,
    expect: Option<(u64, u64)>,
    st: &mut ClearState,
) -> repo_scan::Result<()> {
    dir.verify()?;
    let file = match dir.open_child(name)? {
        Some(file) => file,
        None => return Ok(()),
    };
    let Some(want) = expect else {
        return Err(unsafe_reset(&format!(
            "victim {name} raced in after preflight; refusing"
        )));
    };
    #[cfg(unix)]
    let have = store::owner::fd_identity(&file)?;
    #[cfg(not(unix))]
    let have = (0u64, 0u64);
    if have != want {
        return Err(unsafe_reset(&format!(
            "victim {name} changed between preflight and unlink; refusing"
        )));
    }
    if !file.metadata()?.is_file() {
        st.note_preserved(format!(
            "{} (not a file; preserved)",
            dir.path.join(name).display()
        ));
        return Ok(());
    }
    drop(file);
    dir.unlink_pinned_child(name, want)?;
    st.removed += 1;
    Ok(())
}

/// Which tool-owned directory is being cleared: snapshot files are
/// `<report_id>.json`, staging files are
/// `.staging-<pid>-<ms>-<report_id>.json` (see `emit_file_report`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClearDirKind {
    Snapshots,
    Staging,
}

/// Snapshot-safe report IDs (mirrors the retention gate
/// `report::publish::check_report_id`): nonempty, at most 128 bytes,
/// `[A-Za-z0-9._-]`, never `.`/`..`.
fn is_safe_report_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && id != "."
        && id != ".."
}

/// Stem of a tool-shaped snapshot filename `<report_id>.json`.
fn snapshot_stem(file_name: &str) -> Option<String> {
    let stem = file_name.strip_suffix(".json")?;
    if !is_safe_report_id(stem) {
        return None;
    }
    Some(stem.to_string())
}

/// Report ID claimed by a tool-shaped staging filename
/// `.staging-<pid>-<ms>-<report_id>.json`.
fn staging_report_id(file_name: &str) -> Option<String> {
    let rest = file_name.strip_prefix(".staging-")?.strip_suffix(".json")?;
    let mut parts = rest.splitn(3, '-');
    let pid = parts.next()?;
    let ms = parts.next()?;
    let report_id = parts.next()?;
    if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if ms.is_empty() || !ms.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !is_safe_report_id(report_id) {
        return None;
    }
    Some(report_id.to_string())
}

/// Report ID claimed by tool-marker bytes: a JSON object carrying our
/// schema version, `tool.name`, a nonempty tool version, and a
/// snapshot-safe `report_id` (the lib's verified-prior-report fields).
fn tool_report_id(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let object = value.as_object()?;
    let schema_ok = object.get("schema_version").and_then(|v| v.as_str())
        == Some(repo_scan::report::model::SCHEMA_VERSION);
    let tool = object.get("tool")?.as_object()?;
    let tool_ok =
        tool.get("name").and_then(|v| v.as_str()) == Some(repo_scan::report::model::TOOL_NAME);
    let version_ok = tool
        .get("version")
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.is_empty());
    let id = object.get("report_id")?.as_str()?;
    if !(schema_ok && tool_ok && version_ok) || !is_safe_report_id(id) {
        return None;
    }
    Some(id.to_string())
}

/// Per-catalog-read bound inside snapshot loading (RS-PRIV-09): a
/// read slower than this stops further reads with INCOMPLETE while the
/// rows already gathered stay (state is preserved, never discarded).
/// Cooperative only — a read that never returns cannot be preempted
/// in-process (same residual as [`OP_DEADLINE_SECS`]).
const SNAPSHOT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Checksums (`report_id` -> SHA-256 hex) for tool-shaped snapshot files
/// currently on disk, read through a read-only catalog open that is
/// closed before any removal (spec §15). A missing/foreign/unreadable
/// catalog, or no tool-shaped files, yields no rows, so those files then
/// need tool-marker bytes or stay preserved. Never fails the reset.
/// RS-PRIV-09: stem collection and row queries are capped at
/// [`SNAPSHOT_MAX_STEMS`]; the flag reports truncation so the caller
/// prints incomplete coverage instead of a complete cleanup. The
/// [`ClearState`] deadline is enforced inside both loops and each row
/// read carries the [`SNAPSHOT_READ_TIMEOUT`] bound; on expiry the
/// gathered rows stay and the miss resolves to preserved content.
/// Listing/read failures are INCOMPLETE, never silent.
async fn load_snapshot_rows(
    db_path: &Path,
    db_ours: bool,
    snapshots: &Path,
    st: &mut ClearState,
) -> (HashMap<String, String>, bool) {
    let mut rows = HashMap::new();
    if !db_ours || !db_path.is_file() {
        return (rows, false);
    }
    let mut stems: HashSet<String> = HashSet::new();
    let mut truncated = false;
    let snapshot_entries = match std::fs::read_dir(snapshots) {
        Ok(entries) => Some(entries),
        Err(e) => {
            st.incomplete.push(format!(
                "cannot list {}; checksum rows unresolved, files stay preserved ({e})",
                snapshots.display()
            ));
            None
        }
    };
    if let Some(entries) = snapshot_entries {
        for entry in entries {
            if st.expired() {
                st.incomplete.push(format!(
                    "snapshot stem scan hit the {CLEAR_DEADLINE_SECS}s time budget; \
                     unresolved files stay preserved"
                ));
                break;
            }
            if stems.len() >= SNAPSHOT_MAX_STEMS {
                truncated = true;
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    st.incomplete.push(format!(
                        "cannot read a snapshot entry; its checksum row stays unresolved ({e})"
                    ));
                    continue;
                }
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(stem) = snapshot_stem(&name) {
                stems.insert(stem);
            }
        }
    }
    if stems.is_empty() {
        return (rows, truncated);
    }
    if st.expired() {
        st.incomplete.push(format!(
            "snapshot checksum loading hit the {CLEAR_DEADLINE_SECS}s time budget; \
             unresolved files stay preserved"
        ));
        return (rows, truncated);
    }
    let store = match TursoStore::open_read_only(db_path).await {
        Ok(store) => store,
        Err(_) => return (rows, truncated),
    };
    for stem in stems.iter().take(SNAPSHOT_MAX_STEMS) {
        if st.expired() {
            st.incomplete.push(format!(
                "snapshot checksum loading hit the {CLEAR_DEADLINE_SECS}s time budget; \
                 unresolved files stay preserved"
            ));
            break;
        }
        let read_start = Instant::now();
        let row = store.get_report_snapshot(stem).await;
        let slow = read_start.elapsed() > SNAPSHOT_READ_TIMEOUT;
        if let Ok(Some(row)) = row {
            if let Some(checksum) = row.checksum {
                rows.insert(
                    stem.clone(),
                    String::from_utf8_lossy(&checksum).into_owned(),
                );
            }
        }
        if slow {
            st.incomplete.push(format!(
                "a snapshot checksum read exceeded the {}s per-read bound; \
                 remaining rows unresolved, files stay preserved",
                SNAPSHOT_READ_TIMEOUT.as_secs()
            ));
            break;
        }
    }
    let _ = store.close().await;
    (rows, truncated)
}

/// Remove only tool-owned regular files directly inside a known
/// tool-owned directory (snapshots, staging): non-recursive,
/// symlink-safe, unknown entries kept. Each file needs per-file ownership
/// proof (spec §15): a tool-shaped name for its directory plus a
/// catalog-bound checksum row matching its bytes or tool-marker bytes
/// bound to its filename. A foreign catalog authorizes nothing; nested
/// directories and symlinks are always retained. RS-PRIV-01: victims
/// open with `openat(O_NOFOLLOW)` from the HELD preflight pin, hash from
/// the FD, and leave with `unlinkat` after a `(dev, ino)` re-compare
/// against the hash-time identity.
/// RS-PRIV-09: entry/byte/time budgets bound the scan; exhaustion stops
/// the dir with an incomplete report, never a silent partial clear.
///
/// FIXREADY4 C1: `held` is the preflight pin — the dir is NEVER re-pinned
/// by name here. The held pin re-verifies first, so a swapped known dir
/// refuses instead of clearing a substituted tree. FIXREADY4 C2: a
/// `None` pin (absent at preflight) still verifies absence via
/// `symlink_metadata` — a raced-in entry (notably a dangling symlink,
/// which `Path::exists` misreads as missing) refuses loudly instead of
/// returning silent success over uninspected entries.
fn clear_tool_dir_expected(
    dir: &Path,
    held: Option<&ClearPinnedDir>,
    kind: ClearDirKind,
    db_ours: bool,
    snapshot_rows: &HashMap<String, String>,
    st: &mut ClearState,
) -> repo_scan::Result<()> {
    let Some(pin) = held else {
        match std::fs::symlink_metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(repo_scan::Error::Io(format!(
                    "cannot inspect {}: {e}",
                    dir.display()
                )));
            }
            Ok(md) if md.file_type().is_symlink() => {
                return Err(unsafe_reset(&format!(
                    "known dir {} raced in as a symlink after preflight; refusing",
                    dir.display()
                )));
            }
            Ok(_) => {
                return Err(unsafe_reset(&format!(
                    "known dir {} raced in after preflight; refusing",
                    dir.display()
                )));
            }
        }
    };
    pin.verify()?;
    // Round-3 C1b binding argument for the by-path listing (kept
    // deliberately instead of held-FD enumeration): names from this
    // listing are UNTRUSTED HINTS, never trusted — every use below is
    // FD-relative (`open_child` via `openat` on the held pin, content
    // hashed from the open FD against a catalog row or the tool
    // marker, unlink via `unlinkat` on the held pin). A listing from a
    // swapped-in tree can only nominate names; each nominee still
    // resolves against the HELD dir and must carry tool-owned bytes to
    // move. Held-FD enumeration would bind nothing further (an attacker
    // with dir write plants names in the real dir either way).
    let entries = std::fs::read_dir(dir)
        .map_err(|e| repo_scan::Error::Io(format!("cannot inspect {}: {e}", dir.display())))?;
    let mut scanned = 0usize;
    for entry in entries {
        scanned += 1;
        if scanned > CLEAR_MAX_FILES_PER_DIR {
            st.incomplete.push(format!(
                "{} listing truncated at the {CLEAR_MAX_FILES_PER_DIR}-entry budget; \
                 coverage incomplete",
                dir.display()
            ));
            break;
        }
        if st.expired() {
            st.incomplete.push(format!(
                "{} scan hit the {CLEAR_DEADLINE_SECS}s time budget; coverage incomplete",
                dir.display()
            ));
            break;
        }
        let entry = entry
            .map_err(|e| repo_scan::Error::Io(format!("cannot read {}: {e}", dir.display())))?;
        let raw = entry.file_name();
        if raw.to_str().is_none() {
            st.note_preserved(format!(
                "{} (non-UTF8 name; preserved)",
                dir.join(&raw).display()
            ));
            continue;
        }
        let name = raw.to_string_lossy().into_owned();
        // Open through the pinned FD; the `DirEntry` file type is
        // advisory only and never trusted for the victim. A symlink here
        // is preserved (never followed, never unlinked): the advisory
        // by-path pre-check (round-3 C1b: kept deliberately — it decides
        // nothing) catches the static case and the FD-bound `ELOOP`
        // fallback in `open_child` catches a plant between check and
        // open. The BINDING symlink decision is `O_NOFOLLOW` on the held
        // FD, never this path stat.
        if is_symlink_path(&dir.join(&name))? {
            st.note_preserved(format!(
                "{} (symlink; preserved)",
                dir.join(&name).display()
            ));
            continue;
        }
        let mut file = match pin.open_child(&name) {
            Ok(Some(file)) => file,
            Ok(None) => continue,
            Err(e) if e.to_string().contains("is a symlink") => {
                st.note_preserved(format!(
                    "{} (symlink; preserved)",
                    dir.join(&name).display()
                ));
                continue;
            }
            Err(e) => return Err(e),
        };
        if !file.metadata()?.is_file() {
            st.note_preserved(format!(
                "{} (not a file; preserved)",
                dir.join(&name).display()
            ));
            continue;
        }
        let claimed = match kind {
            ClearDirKind::Snapshots => snapshot_stem(&name),
            ClearDirKind::Staging => staging_report_id(&name),
        };
        let claimed = match claimed {
            Some(claimed) => claimed,
            None => {
                st.note_preserved(format!(
                    "{} (unknown name; preserved)",
                    dir.join(&name).display()
                ));
                continue;
            }
        };
        if !db_ours {
            st.note_preserved(format!(
                "{} (catalog not verified; preserved)",
                dir.join(&name).display()
            ));
            continue;
        }
        // Bound read from the open FD: regular file, capped (RSP-005),
        // size re-checked after the read; the hash binds these exact
        // bytes to the removal decision below.
        let bytes = match read_pinned_capped(&mut file, &dir.join(&name)) {
            Ok(bytes) => bytes,
            Err(_) => {
                st.note_preserved(format!(
                    "{} (unreadable; preserved)",
                    dir.join(&name).display()
                ));
                continue;
            }
        };
        st.bytes_hashed += bytes.len() as u64;
        if st.bytes_hashed > CLEAR_MAX_BYTES_HASHED {
            st.incomplete.push(format!(
                "clear hashing hit the {CLEAR_MAX_BYTES_HASHED}-byte budget; coverage incomplete"
            ));
            st.note_preserved(format!(
                "{} (byte budget exhausted; preserved)",
                dir.join(&name).display()
            ));
            break;
        }
        let digest = repo_scan::report::publish::sha256_hex(&bytes);
        let row_ok = kind == ClearDirKind::Snapshots
            && snapshot_rows
                .get(claimed.as_str())
                .is_some_and(|sum| sum.as_str() == digest.as_str());
        let marker_ok = tool_report_id(&bytes).as_deref() == Some(claimed.as_str());
        if row_ok || marker_ok {
            // Round-3 C1b: the authorization above is CONTENT-bound
            // (bytes hashed from this open FD against a catalog row or
            // the tool marker), so the unlink takes NO re-open — the
            // bound identity travels as `expect` for the degraded
            // by-path re-bind only.
            #[cfg(unix)]
            let identity = store::owner::fd_identity(&file)?;
            #[cfg(not(unix))]
            let identity = (0u64, 0u64);
            drop(file);
            pin.unlink_pinned_child(&name, identity)?;
            st.removed += 1;
        } else {
            st.note_preserved(format!(
                "{} (unverified; preserved)",
                dir.join(&name).display()
            ));
        }
    }
    Ok(())
}

/// Bounded read from an already-open victim FD (mirrors
/// `BoundStaged::open_capped` over the FD instead of the path):
/// size-capped, with a size re-check after the read so a mutation
/// mid-read is detected rather than hashed.
fn read_pinned_capped(file: &mut std::fs::File, display: &Path) -> repo_scan::Result<Vec<u8>> {
    use std::io::Read;
    let cap = repo_scan::report::publish::MAX_STAGED_REPORT_BYTES;
    if file.metadata()?.len() > cap {
        return Err(repo_scan::Error::Report(format!(
            "staged report {} exceeds the {cap}-byte cap",
            display.display()
        )));
    }
    let mut bytes = Vec::new();
    Read::by_ref(file)
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(repo_scan::Error::Report(format!(
            "staged report {} exceeds the {cap}-byte cap",
            display.display()
        )));
    }
    if file.metadata()?.len() != bytes.len() as u64 {
        return Err(repo_scan::Error::Report(format!(
            "staged report {} changed during read; refusing",
            display.display()
        )));
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Integration-test hooks (compiled only under `cfg(test)`; the
// `tests/review_fix_main.rs` suite includes this file as a module). Each
// hook drives the same code the command paths use — never a parallel copy.
// ---------------------------------------------------------------------------

/// Deterministic preflight/removal seam swap (FIXREADY4 C1/C2
/// regression): applied between the REAL preflight and the REAL removal
/// phase inside [`test_clear_preflight_removal_seam`], so each race
/// plants deterministically instead of relying on thread timing. A
/// concurrent swapper/clearer stress cannot assert anything stronger:
/// any race caught after the first unlink is necessarily partial (POSIX
/// offers no transactional multi-unlink), so the pinned property is
/// refuse-loudly (never false success, never a followed link), with
/// zero-mutation guaranteed only for pre-preflight plants (the static
/// matrix in `tests/fail_clear.rs`).
#[cfg(all(test, unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestClearSeamSwap {
    /// No swap: the removal phase must succeed.
    None,
    /// Replace `catalog.db` with fresh bytes (new identity).
    ReplaceVictim,
    /// Replace `catalog.db-wal` with a symlink to an outside sentinel.
    PlantVictimSymlink,
    /// Create `catalog.db-shm`, absent at preflight.
    RaceInVictim,
    /// Replace the snapshots dir with a fresh dir (new identity).
    SwapSnapshotsDir,
    /// Plant a dangling symlink at the staging path, absent at preflight
    /// (C2: must refuse loudly, never silent success).
    RaceInStagingSymlink,
    /// Replace the marker-authorized snapshot with unauthorized bytes
    /// (new identity): content binding must preserve it without refusal
    /// (round-3 C1b: snapshot authorization survives the re-open
    /// removal because it is content-bound, not identity-bound).
    ReplaceSnapshotVictim,
    /// Rewrite the snapshot with byte-identical content (new identity):
    /// content binding must still remove it (round-3 C1b: removal does
    /// not depend on inode stability).
    ReplaceSnapshotIdenticalBytes,
}

/// Outcome of [`test_clear_preflight_removal_seam`].
#[cfg(all(test, unix))]
#[derive(Debug)]
pub struct TestClearSeamOutcome {
    pub refused: bool,
    pub detail: String,
    pub removed: u64,
    pub incomplete: Vec<String>,
    pub preserved: Vec<String>,
}

/// Drive the REAL preflight, plant one deterministic swap, then drive
/// the REAL removal phase (FIXREADY4 C1/C2): `state_dir` holds a caller-
/// built `payload/` tree. Removal runs with `db_ours = true` and an
/// empty checksum-row map (tool-marker bytes still authorize their own
/// files). Returns whether the removal refused and why — never a
/// parallel copy of the phase.
#[cfg(all(test, unix))]
pub fn test_clear_preflight_removal_seam(
    state_dir: &Path,
    swap: TestClearSeamSwap,
) -> TestClearSeamOutcome {
    let mut st = ClearState::new();
    let done = |st: &ClearState, result: repo_scan::Result<()>| TestClearSeamOutcome {
        refused: result.is_err(),
        detail: result.err().map(|e| e.to_string()).unwrap_or_default(),
        removed: st.removed,
        incomplete: st.incomplete.clone(),
        preserved: st.preserved.clone(),
    };
    let io_err = |e: std::io::Error| repo_scan::Error::Io(e.to_string());
    let payload = store::owner::payload_dir(state_dir);
    let payload_pin = match ClearPinnedDir::pin(&payload) {
        Ok(pin) => pin,
        Err(e) => return done(&st, Err(e)),
    };
    let snapshots = payload.join(config::SNAPSHOTS_DIR_NAME);
    let staging = payload.join(config::STAGING_DIR_NAME);
    let set = match preflight_deletion_set(&payload_pin, &snapshots, &staging) {
        Ok(set) => set,
        Err(e) => return done(&st, Err(e)),
    };
    // Deterministic race plant BETWEEN preflight and removal.
    let planted = match swap {
        TestClearSeamSwap::None => Ok(()),
        TestClearSeamSwap::ReplaceVictim => {
            let tmp_victim = payload.join("catalog.db.swap");
            std::fs::write(&tmp_victim, b"swapped catalog bytes")
                .map_err(io_err)
                .and_then(|()| {
                    std::fs::rename(&tmp_victim, payload.join("catalog.db")).map_err(io_err)
                })
        }
        TestClearSeamSwap::PlantVictimSymlink => {
            let sentinel = state_dir.join("seam-sentinel");
            std::fs::write(&sentinel, b"outside bytes")
                .map_err(io_err)
                .and_then(|()| std::fs::remove_file(payload.join("catalog.db-wal")).map_err(io_err))
                .and_then(|()| {
                    std::os::unix::fs::symlink(&sentinel, payload.join("catalog.db-wal"))
                        .map_err(io_err)
                })
        }
        TestClearSeamSwap::RaceInVictim => {
            std::fs::write(payload.join("catalog.db-shm"), b"raced-in sidecar bytes")
                .map(|_| ())
                .map_err(io_err)
        }
        TestClearSeamSwap::SwapSnapshotsDir => {
            std::fs::rename(&snapshots, state_dir.join("seam-orig-snapshots"))
                .and_then(|()| std::fs::create_dir(&snapshots))
                .map_err(io_err)
        }
        TestClearSeamSwap::RaceInStagingSymlink => {
            std::os::unix::fs::symlink(state_dir.join("seam-nowhere"), &staging).map_err(io_err)
        }
        TestClearSeamSwap::ReplaceSnapshotVictim => {
            let victim = snapshots.join("seam-report.json");
            std::fs::remove_file(&victim)
                .and_then(|()| std::fs::write(&victim, b"swapped snapshot bytes").map(|_| ()))
                .map_err(io_err)
        }
        TestClearSeamSwap::ReplaceSnapshotIdenticalBytes => {
            let victim = snapshots.join("seam-report.json");
            std::fs::read(&victim).map_err(io_err).and_then(|bytes| {
                std::fs::remove_file(&victim)
                    .and_then(|()| std::fs::write(&victim, bytes).map(|_| ()))
                    .map_err(io_err)
            })
        }
    };
    if let Err(e) = planted {
        return done(&st, Err(e));
    }
    let db_path = payload.join("catalog.db");
    let rows = HashMap::new();
    let result = remove_preflighted_files(
        state_dir,
        &payload_pin,
        &set,
        &db_path,
        &snapshots,
        &staging,
        true,
        false,
        &rows,
        &mut st,
    );
    done(&st, result)
}

/// Deterministic FD-open/store-open seam swap (round-3 C1b): applied
/// between the REAL victim-FD open and the REAL read-only store open
/// inside [`test_verify_db_identity_seam`], so the race plants
/// deterministically instead of relying on thread timing.
#[cfg(all(test, unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestDbIdentitySwap {
    /// No swap: a bound catalog reports `(true, true)`.
    None,
    /// Replace `catalog.db` with the caller-staged
    /// `staged-seam-catalog.db` sibling (new identity) after the FD
    /// open: the store opens a different file than the held victim.
    SwapDbAfterFdOpen,
}

/// Outcome of [`test_verify_db_identity_seam`].
#[cfg(all(test, unix))]
#[derive(Debug)]
pub struct TestDbIdentityOutcome {
    pub result: Result<(bool, bool), String>,
    pub incomplete: Vec<String>,
    pub preserved: Vec<String>,
}

/// Drive the REAL [`verify_db_identity_inner`] with a deterministic plant
/// between its FD open and its store open (round-3 C1b): `state_dir`
/// holds a caller-built `payload/` tree (plus a staged replacement
/// catalog for the swap variant). Never a parallel copy of the phase.
#[cfg(all(test, unix))]
pub async fn test_verify_db_identity_seam(
    state_dir: &Path,
    swap: TestDbIdentitySwap,
) -> TestDbIdentityOutcome {
    let mut st = ClearState::new();
    let payload = store::owner::payload_dir(state_dir);
    let payload_pin = match ClearPinnedDir::pin(&payload) {
        Ok(pin) => pin,
        Err(e) => {
            return TestDbIdentityOutcome {
                result: Err(e.to_string()),
                incomplete: st.incomplete.clone(),
                preserved: st.preserved.clone(),
            };
        }
    };
    let plant = match swap {
        TestDbIdentitySwap::None => None,
        TestDbIdentitySwap::SwapDbAfterFdOpen => {
            Some(staged_db_swap as fn(&Path) -> std::io::Result<()>)
        }
    };
    let db_path = payload.join("catalog.db");
    let result = verify_db_identity_inner(state_dir, &db_path, &payload_pin, &mut st, plant)
        .await
        .map_err(|e| e.to_string());
    TestDbIdentityOutcome {
        result,
        incomplete: st.incomplete.clone(),
        preserved: st.preserved.clone(),
    }
}

/// Swap `catalog.db` for the caller-staged `staged-seam-catalog.db`
/// sibling (new identity, caller-chosen bytes).
#[cfg(all(test, unix))]
fn staged_db_swap(db_path: &Path) -> std::io::Result<()> {
    let staged = db_path.with_file_name("staged-seam-catalog.db");
    std::fs::remove_file(db_path)?;
    std::fs::rename(staged, db_path)
}

/// Watchdog verdict over an already-measured operation age (R9).
#[cfg(test)]
pub fn test_watchdog_exceeded(grace_secs: u64, elapsed: Duration) -> bool {
    let watchdog = Watchdog::new(Duration::from_secs(grace_secs));
    let now = Instant::now();
    watchdog.exceeded(now - elapsed, now)
}

/// Explicit lease release (R4): returns transactions counted.
#[cfg(test)]
pub async fn test_release_claim(
    store: &TursoStore,
    claimed: &ClaimedTask,
    epoch: u64,
) -> repo_scan::Result<u64> {
    let mut counters = RunCounters::default();
    release_claim(store, &mut counters, claimed, epoch).await?;
    Ok(counters.db_transactions)
}

/// What one hook-driven ingest applied (R5).
#[cfg(test)]
pub struct TestIngestOutcome {
    pub history_invalid: bool,
    pub batches: usize,
    pub scopes: usize,
    pub tx: u64,
}

/// Drive one event batch through the scan's ingest path (R5): durable
/// cursor persistence plus scope invalidation, over a fresh session.
#[cfg(test)]
pub async fn test_apply_event_batch(
    store: &TursoStore,
    generation: u64,
    history_uuid: &str,
    batch: &events::EventBatch,
) -> repo_scan::Result<TestIngestOutcome> {
    let mut session = EventSession {
        reconciler: events::Reconciler::new(events::MemoryCursorJournal::new()),
        monitored: Vec::new(),
        mounts: HashMap::new(),
        applied_scopes: HashMap::new(),
        applied_overflow: HashSet::new(),
        history_invalid: false,
        degraded: Vec::new(),
        live: false,
    };
    // Open rule for the batch's volume so ingest pins a history identity.
    let stored = load_stored_cursors(store).await?;
    // Same open order as `open_event_session` (RSF-F940): restore durable
    // cursors before the open rule so replays dedupe.
    session.reconciler.restore_durable_cursors(&stored);
    let live = events::HistoryUuid(history_uuid.to_string());
    session.reconciler.note_stream_opened(
        &batch.volume_key,
        stored.get(&batch.volume_key),
        Some(&live),
        batch.high_water.0,
        batch.high_water,
    );
    let mut counters = RunCounters::default();
    let mut applied = IngestApplied::default();
    // Hook fence: the batch's own paths plus parents (`ScopeFence`
    // keeps each raw spelling alongside its canonicalization).
    let mut fence_paths: Vec<PathBuf> = Vec::new();
    for path in &batch.invalidations {
        fence_paths.push(path.clone());
        if let Some(parent) = path.parent() {
            fence_paths.push(parent.to_path_buf());
        }
    }
    let fence = ScopeFence::build(&fence_paths);
    apply_event_batch(
        &mut session,
        store,
        generation,
        &[],
        &fence,
        &mut counters,
        batch,
        &mut applied,
    )
    .await?;
    Ok(TestIngestOutcome {
        history_invalid: session.history_invalid,
        batches: applied.batches,
        scopes: applied.scopes,
        tx: counters.db_transactions,
    })
}

/// Durable reconcile marking (R5): rows at or below `through` reconcile.
#[cfg(test)]
pub async fn test_mark_reconciled(
    store: &TursoStore,
    volume: &str,
    through: u64,
) -> repo_scan::Result<()> {
    mark_events_reconciled_through(store, volume, events::EventCursorId(through)).await
}

// ---------------------------------------------------------------------------
// RSF-F940 production-wiring hooks (`tests/rsf_f940.rs` includes this file
// as a module). Each hook drives the same production code the command
// paths use: the scripted drain runs `ingest_available_events`, the
// scripted reconcile runs it plus `reconcile_event_cursors`.
// ---------------------------------------------------------------------------

/// One scripted drain item (RSF-F940): a delivered batch or a failed
/// batch read.
#[cfg(test)]
#[derive(Debug, Clone)]
pub enum TestDrainItem {
    /// A delivered event batch.
    Batch(events::EventBatch),
    /// A failed batch read (`next_batch` returns this error).
    Fail(String),
}

#[cfg(test)]
struct TestDrainIter {
    script: std::collections::VecDeque<TestDrainItem>,
}

#[cfg(test)]
impl repo_scan::platform::EventBatchIter for TestDrainIter {
    fn next_batch(&mut self) -> repo_scan::Result<Option<events::EventBatch>> {
        match self.script.pop_front() {
            None => Ok(None),
            Some(TestDrainItem::Batch(batch)) => Ok(Some(batch)),
            Some(TestDrainItem::Fail(error)) => Err(repo_scan::Error::Events(error)),
        }
    }
}

/// What one hook-driven scripted drain applied (RSF-F940).
#[cfg(test)]
pub struct TestDrainOutcome {
    pub history_invalid: bool,
    pub batches: usize,
    pub scopes: usize,
    pub mount_changed: bool,
    pub tx: u64,
}

/// Per-volume report cursors observed through the reconcile hook (RSF-F940).
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct TestCursors {
    pub history_uuid: Option<String>,
    pub ingested: Option<String>,
    pub reconciled: Option<String>,
}

/// One checked-claim verdict observed through the reconcile hook (RSF-F940).
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct TestClaimOutcome {
    pub volume: String,
    pub complete: bool,
    pub detail: String,
}

/// What one hook-driven scripted reconcile produced (RSF-F940).
#[cfg(test)]
pub struct TestReconcileOutcome {
    pub cursors: HashMap<String, TestCursors>,
    pub claims: Vec<TestClaimOutcome>,
    pub tx: u64,
}

/// Scripted live session for one volume (RSF-F940): the same open order
/// as `open_event_session` — restore durable cursors, open the stream
/// against stored state, begin traversal — with a scripted batch stream.
#[cfg(test)]
async fn test_drain_session(
    store: &TursoStore,
    volume_key: &str,
    history_uuid: &str,
    fence_roots: &[PathBuf],
    script: Vec<TestDrainItem>,
) -> repo_scan::Result<(EventSession, Vec<PlannedRoot>)> {
    let stored = load_stored_cursors(store).await?;
    let mut session = EventSession {
        reconciler: events::Reconciler::new(events::MemoryCursorJournal::new()),
        monitored: Vec::new(),
        mounts: HashMap::new(),
        applied_scopes: HashMap::new(),
        applied_overflow: HashSet::new(),
        history_invalid: false,
        degraded: Vec::new(),
        live: true,
    };
    session.reconciler.restore_durable_cursors(&stored);
    let boundary = script
        .iter()
        .filter_map(|item| match item {
            TestDrainItem::Batch(batch) => Some(batch.high_water.0),
            TestDrainItem::Fail(_) => None,
        })
        .max()
        .unwrap_or(0);
    let live = events::HistoryUuid(history_uuid.to_string());
    session.reconciler.note_stream_opened(
        volume_key,
        stored.get(volume_key),
        Some(&live),
        boundary,
        events::EventCursorId(boundary),
    );
    session.reconciler.begin_traversal()?;
    session.monitored.push(events::MonitoredVolume {
        volume_key: volume_key.to_string(),
        boundary: events::EventCursorId(boundary),
        batches: Box::new(TestDrainIter {
            script: script.into(),
        }),
        // Scripted volumes model live-history volumes: the scripted
        // batches are the historical phase, so the checked claim
        // applies exactly as on a resumed production volume.
        history_expected: true,
    });
    let roots: Vec<PlannedRoot> = fence_roots
        .iter()
        .map(|path| PlannedRoot {
            path: path.clone(),
            priority: RootPriority::Normal,
            namespace: String::from("test"),
            volume: None,
        })
        .collect();
    Ok((session, roots))
}

/// Drive scripted batches and batch failures through the production
/// drain (RSF-F940): the same `ingest_available_events` the scan and
/// invalidate paths execute.
#[cfg(test)]
pub async fn test_drain_scripted(
    store: &TursoStore,
    generation: u64,
    volume_key: &str,
    history_uuid: &str,
    fence_roots: &[PathBuf],
    script: Vec<TestDrainItem>,
) -> repo_scan::Result<TestDrainOutcome> {
    let (mut session, roots) =
        test_drain_session(store, volume_key, history_uuid, fence_roots, script).await?;
    let mut counters = RunCounters::default();
    let applied =
        ingest_available_events(&mut session, store, generation, &roots, &mut counters).await?;
    Ok(TestDrainOutcome {
        history_invalid: session.history_invalid,
        batches: applied.batches,
        scopes: applied.scopes,
        mount_changed: applied.mount_changed,
        tx: counters.db_transactions,
    })
}

/// Drive scripted batches through the production drain, satisfy the
/// scheduled work through the production claim/complete path, then run
/// the production reconcile (RSF-F940): the same
/// `ingest_available_events` + `reconcile_event_cursors` the scan path
/// executes.
#[cfg(test)]
pub async fn test_reconcile_scripted(
    store: &TursoStore,
    generation: u64,
    volume_key: &str,
    history_uuid: &str,
    fence_roots: &[PathBuf],
    batches: Vec<events::EventBatch>,
) -> repo_scan::Result<TestReconcileOutcome> {
    let script: Vec<TestDrainItem> = batches.into_iter().map(TestDrainItem::Batch).collect();
    let (mut session, roots) =
        test_drain_session(store, volume_key, history_uuid, fence_roots, script).await?;
    let mut counters = RunCounters::default();
    ingest_available_events(&mut session, store, generation, &roots, &mut counters).await?;
    let epoch = store.epoch();
    loop {
        let now = store::now_ms();
        let claimed = store.claim_tasks(epoch, 64, 60_000, now).await?;
        if claimed.is_empty() {
            break;
        }
        for task in &claimed {
            // Production completion semantics (batched completion):
            // stale completions are routine — the store already requeued
            // the task with a fresh expected rev, and this loop reclaims
            // it. Only non-stale errors abort.
            match store
                .complete_task(
                    &task.task.id,
                    task.token,
                    epoch,
                    &TaskOutcome::Complete,
                    now,
                )
                .await
            {
                Ok(()) => {}
                Err(repo_scan::Error::Scheduler(message))
                    if message.starts_with("stale-completion:") => {}
                Err(e) => return Err(e),
            }
        }
    }
    let (cursors, claims) = reconcile_event_cursors(&mut session, store).await?;
    let mut observed = HashMap::with_capacity(cursors.len());
    for (volume, cursor) in cursors {
        observed.insert(
            volume,
            TestCursors {
                history_uuid: cursor.history_uuid,
                ingested: cursor.ingested,
                reconciled: cursor.reconciled,
            },
        );
    }
    Ok(TestReconcileOutcome {
        cursors: observed,
        claims: claims
            .into_iter()
            .map(|claim| TestClaimOutcome {
                volume: claim.volume,
                complete: claim.complete,
                detail: claim.detail,
            })
            .collect(),
        tx: counters.db_transactions,
    })
}

// ---------------------------------------------------------------------------
// RSF consumer-findings hooks (`tests/rsf_main.rs` includes this file as a
// module). Each hook drives the same production code the command paths use.
// ---------------------------------------------------------------------------

/// Run-loop outcome plus measured run state (RSF-3E2/AC46/23D/AD9D).
#[cfg(test)]
#[derive(Debug)]
pub struct TestRunStats {
    pub interrupted: bool,
    pub pending: u64,
    pub open_gaps: u64,
    pub unresolvable: u64,
    pub status_pending: u64,
    pub claimed: u64,
    pub dirs_complete: u64,
    pub entries: u64,
    pub db_transactions: u64,
    pub peak_rss_bytes: u64,
    pub cpu_seconds: f64,
    pub db_sync_calls: u64,
    pub batch_commits: u64,
    pub batch_ops: u64,
    pub wal_probes: u64,
    pub checkpoints: u64,
    pub checkpoint_ops_pending: u64,
    pub watchdog_trips: u64,
    pub pressure: bool,
    /// Breaker keys currently open (contained), sorted.
    pub breakers_open: Vec<String>,
}

/// Drive the production run loop to its boundary (RSF-3E2FDCF3-78C5-401A-84DD-A799688ED84F):
/// the same `run_until_boundary` the scan path executes.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub async fn test_run_boundary(
    store: &TursoStore,
    epoch: u64,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    status_mode: StatusMode,
    scan_id: &str,
) -> repo_scan::Result<TestRunStats> {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    test_run_boundary_with(
        &mut runner,
        store,
        epoch,
        generation,
        run_rev,
        canonical,
        status_mode,
        scan_id,
    )
    .await
}

/// Run-loop with an overridden watchdog grace
/// (RSF-AD9D4AF7-3CC3-4B37-8168-E78DD6375C5B).
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub async fn test_run_boundary_with_grace(
    store: &TursoStore,
    epoch: u64,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    status_mode: StatusMode,
    scan_id: &str,
    grace_secs: u64,
) -> repo_scan::Result<TestRunStats> {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    runner.watchdog = Watchdog::new(Duration::from_secs(grace_secs));
    test_run_boundary_with(
        &mut runner,
        store,
        epoch,
        generation,
        run_rev,
        canonical,
        status_mode,
        scan_id,
    )
    .await
}

/// Run-loop with an eager checkpoint policy
/// (RSF-AC461500-609D-4D55-991E-09C60D382D67): a probe is due after
/// `ops_between_probes` applied ops with no time rate-limit.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub async fn test_run_boundary_with_checkpoint(
    store: &TursoStore,
    epoch: u64,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    status_mode: StatusMode,
    scan_id: &str,
    ops_between_probes: u64,
) -> repo_scan::Result<TestRunStats> {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    runner.checkpoints = CheckpointCoordinator::new(CheckpointPolicy {
        ops_between_probes,
        max_wal_frames: u64::MAX,
        min_probe_interval: Duration::ZERO,
    });
    test_run_boundary_with(
        &mut runner,
        store,
        epoch,
        generation,
        run_rev,
        canonical,
        status_mode,
        scan_id,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn test_run_boundary_with(
    runner: &mut Runner,
    store: &TursoStore,
    epoch: u64,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    status_mode: StatusMode,
    scan_id: &str,
) -> repo_scan::Result<TestRunStats> {
    // Test harness drains both phases like the scan path: discovery to
    // its boundary, then analysis — preserving "drain everything"
    // semantics for unit tests.
    let outcome = run_until_boundary(
        runner,
        store,
        epoch,
        generation,
        run_rev,
        canonical,
        status_mode,
        scan_id,
        DrainPhase::Discovery,
    )
    .await?;
    let analysis = run_until_boundary(
        runner,
        store,
        epoch,
        generation,
        run_rev,
        canonical,
        status_mode,
        scan_id,
        DrainPhase::Analysis,
    )
    .await?;
    let outcome = RunOutcome {
        interrupted: outcome.interrupted || analysis.interrupted,
        pending: analysis.pending,
        open_gaps: analysis.open_gaps,
        unresolvable: analysis.unresolvable,
        status_pending: analysis.status_pending,
    };
    let stats = store.stats();
    let now_sys = SystemTime::now();
    let mut breakers_open: Vec<String> = runner
        .breakers
        .iter()
        .filter(|(_, breaker)| !breaker.allow(now_sys))
        .map(|(key, _)| key.clone())
        .collect();
    breakers_open.sort();
    Ok(TestRunStats {
        interrupted: outcome.interrupted,
        pending: outcome.pending,
        open_gaps: outcome.open_gaps,
        unresolvable: outcome.unresolvable,
        status_pending: outcome.status_pending,
        claimed: runner.counters.claimed,
        dirs_complete: runner.counters.dirs_complete,
        entries: runner.counters.entries,
        db_transactions: runner.counters.db_transactions,
        peak_rss_bytes: runner.counters.peak_rss_bytes,
        cpu_seconds: runner.counters.cpu_seconds,
        db_sync_calls: runner.counters.db_sync_calls,
        batch_commits: stats.batch_commits,
        batch_ops: stats.batch_ops,
        wal_probes: stats.wal_probes,
        checkpoints: stats.checkpoints,
        checkpoint_ops_pending: runner.checkpoints.ops_since_probe(),
        watchdog_trips: runner.watchdog.tripped,
        pressure: runner.admission.under_pressure(),
        breakers_open,
    })
}

/// Drive crafted staged bytes through the real verified publish path
/// (RSF-7511725D-DC03-471A-9635-4F8173986489): the same
/// `verified_retain_and_publish` production file emission uses.
#[cfg(test)]
pub async fn test_verified_publish_bytes(
    store: &TursoStore,
    state_dir: &Path,
    report_id: &str,
    staged_bytes: &[u8],
    dest: &Path,
    now_ms: i64,
) -> repo_scan::Result<PathBuf> {
    let staging = staging_dir(state_dir);
    store::owner::ensure_private_dir_all(&staging)?;
    let staged = staging.join(format!(
        ".staging-test-{}-{report_id}.json",
        std::process::id()
    ));
    std::fs::write(&staged, staged_bytes)?;
    let catalog_rev = store.current_revision().await?;
    verified_retain_and_publish(
        store,
        &staged,
        report_id,
        catalog_rev,
        1,
        dest,
        state_dir,
        now_ms,
    )
    .await
}

/// Bounded-scan accounting (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1).
#[cfg(test)]
#[derive(Debug)]
pub struct TestDerivationScan {
    pub scanned: u64,
    pub chunks: u64,
    pub peak_chunk: usize,
    pub candidates: usize,
    pub storage_links: usize,
}

/// Production error-derivation scan over every open gap.
#[cfg(test)]
pub async fn test_scan_error_derivations(
    store: &TursoStore,
    root_scopes: &[String],
) -> repo_scan::Result<TestDerivationScan> {
    let derived =
        scan_error_derivations(store, root_scopes, &DerivationCaps::default_caps()).await?;
    Ok(TestDerivationScan {
        scanned: derived.scanned,
        chunks: derived.chunks,
        peak_chunk: derived.peak_chunk,
        candidates: derived.candidates.len(),
        storage_links: 0,
    })
}

/// Production instance-derivation scan over every emitted instance.
#[cfg(test)]
pub async fn test_scan_instance_derivations(
    store: &TursoStore,
) -> repo_scan::Result<TestDerivationScan> {
    let derived = scan_instance_derivations(store, &DerivationCaps::default_caps()).await?;
    Ok(TestDerivationScan {
        scanned: derived.scanned,
        chunks: derived.chunks,
        peak_chunk: derived.peak_chunk,
        candidates: derived.candidates.len(),
        storage_links: derived.storage_links.len(),
    })
}

/// Burst verdicts through the real 2 Hz progress gate
/// (RSF-CHAINARGOS-PROGRESS-001): the first call passes, immediate
/// followers are coalesced.
#[cfg(test)]
pub fn test_progress_burst(n: usize) -> Vec<bool> {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    (0..n).map(|_| runner.admission.progress_due()).collect()
}

/// Timed gate sample (RSF-CHAINARGOS-PROGRESS-001): `(first, immediate,
/// after_interval)` where the third sample follows a 600 ms sleep past
/// the 500 ms (2 Hz) interval.
#[cfg(test)]
pub fn test_progress_timed() -> (bool, bool, bool) {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    let first = runner.admission.progress_due();
    let immediate = runner.admission.progress_due();
    std::thread::sleep(Duration::from_millis(600));
    let after_interval = runner.admission.progress_due();
    (first, immediate, after_interval)
}

// ---------------------------------------------------------------------------
// Wave1d Step 12 hooks (`tests/events_impl.rs` includes this file as a
// module): batched completion, progress coalescing, retention, and
// cursor resolution through the production code the command paths use.
// ---------------------------------------------------------------------------

/// One scripted completion for [`test_drive_completions`].
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct TestCompletionItem {
    /// Task id (claimed by the test before driving; completions carry the
    /// claim token below).
    pub task_id: String,
    /// Lease token the completion presents.
    pub token: i64,
    /// Outcome to complete with.
    pub outcome: TaskOutcome,
    /// Child tasks to enqueue into the same batch before buffering this
    /// completion (crash-rule coverage).
    pub children: Vec<TestChildTask>,
}

/// One child task to enqueue (fields mirror `NewTask`; the idempotency
/// key derives as `idem:<id>` like production enqueues).
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct TestChildTask {
    pub id: String,
    pub kind: String,
    pub generation: u64,
    pub scope_key: String,
    pub expected_rev: u64,
}

/// Observed verdict for one driven completion.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestCompletionResult {
    pub task_id: String,
    pub stale: bool,
}

/// Drive scripted completions through the production batch path: buffer
/// each item's children plus its conditional completion SQL into one
/// writer batch, then (when `flush`) commit and classify exactly like
/// the drain loop, followed by the Phase-B event flush. `flush = false`
/// drops the batch uncommitted (a kill between buffer and flush: tasks
/// stay leased, children stay absent). Unknown tasks, lease mismatches,
/// bad epochs, and invalid parked states abort with the production
/// errors.
#[cfg(test)]
pub async fn test_drive_completions(
    store: &TursoStore,
    scan_id: &str,
    epoch: u64,
    items: Vec<TestCompletionItem>,
    flush: bool,
) -> repo_scan::Result<Vec<TestCompletionResult>> {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    let rev = store.next_revision().await?;
    runner.journal = Some(ScanJournal::open(store, scan_id, rev).await?);
    runner.open_gaps = store.list_open_error_ids().await?.into_iter().collect();
    let now = store::now_ms();
    for item in &items {
        for child in &item.children {
            let idempotency_key = format!("idem:{}", child.id);
            let task = NewTask {
                id: &child.id,
                kind: &child.kind,
                generation: child.generation,
                dir_id: None,
                scope_key: &child.scope_key,
                expected_rev: child.expected_rev,
                idempotency_key: &idempotency_key,
            };
            TursoStore::buffer_enqueue_task(&mut runner.batch, &task, now);
        }
        // Rebuild the claim the drain loop would hold; unknown tasks get
        // a synthetic claim so the production unknown-task error fires.
        let claimed = match store.get_task(&item.task_id).await? {
            Some(task) => ClaimedTask {
                task,
                token: item.token,
                expires_ms: 0,
            },
            None => ClaimedTask {
                task: FrontierTask {
                    id: item.task_id.clone(),
                    kind: String::from("enumerate_dir"),
                    generation: 1,
                    dir_id: None,
                    scope_key: String::from("dir:test"),
                    expected_rev: 0,
                    state: TaskState::Leased,
                    lease_token: Some(item.token),
                    lease_epoch: Some(epoch),
                    lease_expires_ms: None,
                    idempotency_key: String::from("idem:test"),
                    retry_after_ms: None,
                    attempts: 1,
                },
                token: item.token,
                expires_ms: 0,
            },
        };
        buffer_completion(&mut runner, store, &claimed, epoch, &item.outcome)?;
    }
    if !flush {
        return Ok(Vec::new());
    }
    flush_runner_batch(&mut runner, store).await?;
    // Phase-B gap events buffered by classification commit next (the
    // drain flushes them with following work; the hook flushes now).
    flush_runner_batch(&mut runner, store).await?;
    let mut out = Vec::with_capacity(items.len());
    for item in &items {
        // Verdicts are observable committed state: the applied path
        // leaves the outcome state, the stale path leaves `pending`.
        let state = store.get_task(&item.task_id).await?.map(|task| task.state);
        out.push(TestCompletionResult {
            task_id: item.task_id.clone(),
            stale: state == Some(TaskState::Pending),
        });
    }
    Ok(out)
}

/// Observed prune outcome for [`test_prune_scan_events`].
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestPruneOutcome {
    pub retained: u64,
    pub cutoff: u64,
    pub pruned: bool,
}

/// Enforce retention on one scan's journal with an explicit bound
/// through the production prune (the scan path passes
/// [`MAX_RETAINED_SCAN_EVENTS`]).
#[cfg(test)]
pub async fn test_prune_scan_events(
    store: &TursoStore,
    scan_id: &str,
    keep_rows: u64,
) -> repo_scan::Result<TestPruneOutcome> {
    let rev = store.next_revision().await?;
    let mut journal = ScanJournal::open(store, scan_id, rev).await?;
    let pruned = maybe_prune_scan_journal(store, &mut journal, keep_rows).await?;
    Ok(TestPruneOutcome {
        retained: scan_event_count(store, scan_id).await?,
        cutoff: journal.pruned_through,
        pruned,
    })
}

/// Observed cursor resolution for [`test_resolve_after_cursor`].
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestCursorResolution {
    pub reset_first: bool,
    pub after: Option<(u64, u64)>,
}

/// Resolve an `--after` cursor through the production resolver (`None`
/// replays from the start like a cursor-less query).
#[cfg(test)]
pub async fn test_resolve_after_cursor(
    store: &TursoStore,
    scan_id: &str,
    after: Option<String>,
) -> repo_scan::Result<TestCursorResolution> {
    match after {
        None => Ok(TestCursorResolution {
            reset_first: false,
            after: None,
        }),
        Some(cursor) => {
            let position = resolve_after_cursor(store, scan_id, &cursor).await?;
            Ok(TestCursorResolution {
                reset_first: position.reset_first,
                after: position.after,
            })
        }
    }
}

/// Observed coalescing outcome for [`test_journal_progress_ticks`].
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestProgressOutcome {
    pub progress_rows: u64,
    pub survivor_records: serde_json::Value,
    pub error_rows: u64,
}

/// Journal `ticks` progress payloads plus one interleaved error event
/// through the production journal + flush path (one flush per tick,
/// like the drain), then report the surviving progress rows, the
/// survivor payload, and the surviving error rows.
#[cfg(test)]
pub async fn test_journal_progress_ticks(
    store: &TursoStore,
    scan_id: &str,
    ticks: u64,
) -> repo_scan::Result<TestProgressOutcome> {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    let rev = store.next_revision().await?;
    runner.journal = Some(ScanJournal::open(store, scan_id, rev).await?);
    for tick in 0..ticks {
        let records = serde_json::json!({"tick": tick, "elapsed_s": tick});
        let bytes =
            serde_json::to_vec(&records).map_err(|e| repo_scan::Error::Report(e.to_string()))?;
        journal_discovery_progress(&mut runner, store, &bytes).await?;
        if tick == 0 {
            // One record event interleaved: coalescing must never drop it.
            let journal = runner.journal.as_mut().expect("journal opened above");
            let error = error_records("gap:test", "scope:test", "test-cat", "test detail")?;
            journal.buffer_error(&mut runner.batch, &error)?;
        }
        flush_runner_batch(&mut runner, store).await?;
    }
    let rows = store.read_scan_events(scan_id, 0, 10_000).await?;
    let mut progress_rows = 0u64;
    let mut survivor_records = serde_json::Value::Null;
    let mut error_rows = 0u64;
    for row in &rows {
        if row.event_type == EventType::DiscoveryProgress.name() {
            progress_rows += 1;
            survivor_records = serde_json::from_slice(&row.records)
                .map_err(|e| repo_scan::Error::Report(e.to_string()))?;
        } else if row.event_type == EventType::Error.name() {
            error_rows += 1;
        }
    }
    Ok(TestProgressOutcome {
        progress_rows,
        survivor_records,
        error_rows,
    })
}

/// Progress line content through the real formatter
/// (RSF-CHAINARGOS-PROGRESS-001).
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn test_format_progress(
    claimed: u64,
    dirs: u64,
    entries: u64,
    stale: u64,
    pending: u64,
    elapsed_secs: u64,
    scope: &str,
    volume: &str,
) -> String {
    let counters = RunCounters {
        claimed,
        dirs_complete: dirs,
        entries,
        repos_found: 0,
        probes_complete: 0,
        db_transactions: 0,
        stale_requeued: stale,
        peak_rss_bytes: 0,
        cpu_seconds: 0.0,
        db_sync_calls: 0,
    };
    format_progress_line(
        "scan-test",
        7,
        &counters,
        pending,
        Duration::from_secs(elapsed_secs),
        scope,
        volume,
    )
}

/// Production watchdog verdict (RSF-AD9D4AF7-3CC3-4B37-8168-E78DD6375C5B).
#[cfg(test)]
pub fn test_watchdog_verdict(timed_out: bool, advanced: bool) -> &'static str {
    match watchdog_verdict(timed_out, advanced) {
        WatchdogVerdict::WithinGrace => "within_grace",
        WatchdogVerdict::Advancing => "advancing",
        WatchdogVerdict::Contained => "contained",
    }
}

/// Full progress line through the real store-totals formatter
/// (RSF-F2865989-7199-472B-A9D8-9C54C88656EB, RSF-CHAINARGOS-RESUME-002,
/// RSF-CHAINARGOS-SPEED-003): session counters plus cumulative scan totals,
/// frontier denominator, rate, and ETA.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn test_format_progress_full(
    claimed: u64,
    dirs: u64,
    entries: u64,
    stale: u64,
    pending: u64,
    total_tasks: u64,
    cum_dirs: u64,
    cum_entries: u64,
    elapsed_secs: u64,
    scope: &str,
    volume: &str,
) -> String {
    let counters = RunCounters {
        claimed,
        dirs_complete: dirs,
        entries,
        repos_found: 0,
        probes_complete: 0,
        db_transactions: 0,
        stale_requeued: stale,
        peak_rss_bytes: 0,
        cpu_seconds: 0.0,
        db_sync_calls: 0,
    };
    let totals = ProgressTotals {
        pending,
        total_tasks,
        cum_dirs,
        cum_entries,
    };
    format_progress_line_full(
        "scan-test",
        7,
        &counters,
        &totals,
        Duration::from_secs(elapsed_secs),
        scope,
        volume,
    )
}

/// Production ETA formatting (RSF-F2865989-7199-472B-A9D8-9C54C88656EB).
#[cfg(test)]
pub fn test_format_eta(session_claimed: u64, pending: u64, elapsed_secs: u64) -> String {
    format_progress_eta(session_claimed, pending, Duration::from_secs(elapsed_secs))
}

/// Production growth-aware ETA (RSF-CHAINARGOS-PROGRESS-002).
#[cfg(test)]
pub fn test_format_eta_growth(
    session_claimed: u64,
    pending: u64,
    elapsed_secs: u64,
    denominator_grew: bool,
    new_since_tick: u64,
) -> String {
    format_progress_eta_growth(
        session_claimed,
        pending,
        Duration::from_secs(elapsed_secs),
        denominator_grew,
        new_since_tick,
    )
}

/// Full progress line through the growth-aware production formatter
/// (RSF-CHAINARGOS-PROGRESS-002).
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn test_format_progress_full_growth(
    claimed: u64,
    dirs: u64,
    entries: u64,
    stale: u64,
    pending: u64,
    total_tasks: u64,
    cum_dirs: u64,
    cum_entries: u64,
    elapsed_secs: u64,
    scope: &str,
    volume: &str,
    denominator_grew: bool,
    new_since_tick: u64,
) -> String {
    let counters = RunCounters {
        claimed,
        dirs_complete: dirs,
        entries,
        repos_found: 0,
        probes_complete: 0,
        db_transactions: 0,
        stale_requeued: stale,
        peak_rss_bytes: 0,
        cpu_seconds: 0.0,
        db_sync_calls: 0,
    };
    let totals = ProgressTotals {
        pending,
        total_tasks,
        cum_dirs,
        cum_entries,
    };
    format_progress_line_full_with_growth(
        "scan-test",
        7,
        &counters,
        &totals,
        Duration::from_secs(elapsed_secs),
        scope,
        volume,
        denominator_grew,
        new_since_tick,
    )
}

/// Production rate formatting.
#[cfg(test)]
pub fn test_format_rate(session_claimed: u64, elapsed_secs: u64) -> String {
    format_progress_rate(session_claimed, Duration::from_secs(elapsed_secs))
}

/// Production progress-totals load: `(pending, total_tasks, cum_dirs,
/// cum_entries)` for one generation.
#[cfg(test)]
pub async fn test_load_progress_totals(
    store: &TursoStore,
    generation: u64,
) -> repo_scan::Result<(u64, u64, u64, u64)> {
    let totals = load_progress_totals(store, generation).await?;
    Ok((
        totals.pending,
        totals.total_tasks,
        totals.cum_dirs,
        totals.cum_entries,
    ))
}

// ---------------------------------------------------------------------------
// RSF-751/AC46/F06D hooks (`tests/rsf_publish.rs` includes this file as a
// module). Each hook drives the same production code the command paths use.
// ---------------------------------------------------------------------------

/// Paging width the bounded scans hold in flight (one page at most).
#[cfg(test)]
pub fn test_load_chunk_rows() -> i64 {
    LOAD_CHUNK_ROWS
}

/// One stored cursor in test-comparable form.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestVolumeCursor {
    pub uuid: Option<String>,
    pub ingested: Option<u64>,
    pub reconciled: Option<u64>,
}

/// Production stored-cursor scan over every volume with journal history,
/// with paging accounting.
#[cfg(test)]
#[derive(Debug)]
pub struct TestStoredCursorScan {
    pub cursors: HashMap<String, TestVolumeCursor>,
    pub pages: u64,
    pub peak_page: usize,
}

/// Production stored cursors through the real per-volume paged scan.
#[cfg(test)]
pub async fn test_stored_cursors(store: &TursoStore) -> repo_scan::Result<TestStoredCursorScan> {
    let mut id_rows = store
        .connection()
        .query(
            "SELECT DISTINCT volume_id FROM event_journal ORDER BY volume_id ASC",
            (),
        )
        .await
        .map_err(store_err)?;
    let mut keys = Vec::new();
    while let Some(row) = id_rows.next().await.map_err(store_err)? {
        keys.push(cell_text(&row, 0)?);
    }
    let mut scan = TestStoredCursorScan {
        cursors: HashMap::new(),
        pages: 0,
        peak_page: 0,
    };
    for key in keys {
        let one = stored_cursor_for_volume(store, &key).await?;
        scan.pages += one.pages;
        scan.peak_page = scan.peak_page.max(one.peak_page);
        if let Some(cursor) = one.cursor {
            scan.cursors.insert(
                key,
                TestVolumeCursor {
                    uuid: cursor.uuid.map(|u| u.0),
                    ingested: cursor.ingested.map(|c| c.0),
                    reconciled: cursor.reconciled.map(|c| c.0),
                },
            );
        }
    }
    Ok(scan)
}

/// One volume's report cursors in test-comparable form.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestRootCursors {
    pub history_uuid: Option<String>,
    pub ingested: Option<String>,
    pub reconciled: Option<String>,
}

/// Production report cursors with paging accounting.
#[cfg(test)]
#[derive(Debug)]
pub struct TestReportCursorScan {
    pub cursors: HashMap<String, TestRootCursors>,
    pub pages: u64,
    pub peak_page: usize,
}

/// Production `report_cursors_from_store` over an unmonitored session
/// (keys come from persisted history alone), with paging totals through
/// the same per-volume production scan.
#[cfg(test)]
pub async fn test_report_cursors(store: &TursoStore) -> repo_scan::Result<TestReportCursorScan> {
    let session = EventSession {
        reconciler: events::Reconciler::new(events::MemoryCursorJournal::new()),
        monitored: Vec::new(),
        mounts: HashMap::new(),
        applied_scopes: HashMap::new(),
        applied_overflow: HashSet::new(),
        history_invalid: false,
        degraded: Vec::new(),
        live: false,
    };
    let cursors = report_cursors_from_store(store, &session).await?;
    let mut scan = TestReportCursorScan {
        cursors: HashMap::new(),
        pages: 0,
        peak_page: 0,
    };
    for (key, value) in &cursors {
        let one = report_cursor_for_volume(store, key).await?;
        scan.pages += one.pages;
        scan.peak_page = scan.peak_page.max(one.peak_page);
        scan.cursors.insert(
            key.clone(),
            TestRootCursors {
                history_uuid: value.history_uuid.clone(),
                ingested: value.ingested.clone(),
                reconciled: value.reconciled.clone(),
            },
        );
    }
    Ok(scan)
}

/// Production alias insert-dedupe: records one triple twice plus a
/// distinct triple; returns `(aliases, distinct)`.
#[cfg(test)]
pub fn test_alias_dedupe() -> (usize, usize) {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    runner
        .note_alias(b"/a".to_vec(), b"/b".to_vec(), "same_object", 1)
        .expect("note");
    runner
        .note_alias(b"/a".to_vec(), b"/b".to_vec(), "same_object", 2)
        .expect("note");
    runner
        .note_alias(b"/a".to_vec(), b"/c".to_vec(), "symlink", 3)
        .expect("note");
    (runner.aliases.len(), runner.alias_seen.len())
}

/// Production applied-scope cap: notes 5,000 scopes for one volume;
/// returns `(recorded, overflowed)`.
#[cfg(test)]
pub fn test_applied_scopes_cap() -> (usize, bool) {
    let mut session = EventSession {
        reconciler: events::Reconciler::new(events::MemoryCursorJournal::new()),
        monitored: Vec::new(),
        mounts: HashMap::new(),
        applied_scopes: HashMap::new(),
        applied_overflow: HashSet::new(),
        history_invalid: false,
        degraded: Vec::new(),
        live: false,
    };
    let scopes: Vec<String> = (0..5000).map(|n| format!("dir:{n:08x}")).collect();
    note_applied_scopes(&mut session, "vol-cap", &scopes);
    let recorded = session
        .applied_scopes
        .get("vol-cap")
        .map_or(0, HashSet::len);
    (recorded, session.applied_overflow.contains("vol-cap"))
}

/// Production alias cap (A-F5): notes `MAX_ALIASES + 10` distinct aliases
/// plus a repeat of the first; returns `(held, overflowed, gap_buffered)`.
#[cfg(test)]
pub fn test_alias_cap() -> (usize, bool, bool) {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    for n in 0..(MAX_ALIASES + 10) {
        let path = format!("/a/{n}").into_bytes();
        let target = format!("/b/{n}").into_bytes();
        let _ = runner.note_alias(path, target, "symlink", 1).expect("note");
    }
    let _ = runner
        .note_alias(b"/a/0".to_vec(), b"/b/0".to_vec(), "symlink", 2)
        .expect("note");
    (
        runner.aliases.len(),
        runner.alias_overflow,
        !runner.batch.is_empty(),
    )
}

/// Production probe-index cap (A-F5): notes `MAX_PROBED_GIT_IDS + 10`
/// distinct identities; returns `(held, overflowed, gap_buffered)`.
#[cfg(test)]
pub fn test_probed_git_ids_cap() -> (usize, bool, bool) {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    for n in 0..(MAX_PROBED_GIT_IDS + 10) {
        let _ = note_probed_git_id(
            &mut runner,
            (1, n as u64),
            format!("/g/{n}").into_bytes(),
            1,
        )
        .expect("note");
    }
    (
        runner.probed_git_ids.len(),
        runner.probed_overflow,
        !runner.batch.is_empty(),
    )
}

/// Production in-loop watchdog gate (RSF-SEC-WATCHDOG-ABORT): returns
/// `(fires_on_stall, quiet_on_progress, quiet_in_grace)`.
#[cfg(test)]
pub fn test_watchdog_inloop_abort() -> (bool, bool, bool) {
    let grace = Duration::from_secs(WATCHDOG_GRACE_SECS);
    let fires = watchdog_inloop_abort(10, 10, Duration::from_secs(WATCHDOG_GRACE_SECS + 1), grace);
    let quiet_progress = watchdog_inloop_abort(11, 10, Duration::from_secs(3600), grace);
    let quiet_grace = watchdog_inloop_abort(10, 10, Duration::from_secs(1), grace);
    (fires, quiet_progress, quiet_grace)
}

/// Production planner-key losslessness (A-F1, fix4): two distinct byte
/// paths with identical lossy display hold distinct planner keys, each
/// parsing byte-exact and denoting its own scheduler scope; returns the
/// distinct scope count (2: no sibling dropped, no fan-out needed).
#[cfg(all(test, unix))]
pub fn test_subtree_fanout() -> usize {
    use std::os::unix::ffi::OsStringExt;
    let a = PathBuf::from(std::ffi::OsString::from_vec(b"/fan/\xff".to_vec()));
    let b = PathBuf::from(std::ffi::OsString::from_vec(b"/fan/\xfe".to_vec()));
    let key_a = events::subtree_scope_key("vol-fanout", &a);
    let key_b = events::subtree_scope_key("vol-fanout", &b);
    assert_ne!(key_a, key_b, "lossless keys never collide");
    let mut scopes = std::collections::HashSet::new();
    for (key, path) in [(&key_a, &a), (&key_b, &b)] {
        let (volume, planned) = events::parse_subtree_scope_key(key).expect("planner key parses");
        assert_eq!(volume, "vol-fanout");
        assert_eq!(&planned, path, "byte-exact round-trip");
        let dir = events::dir_scope_for_subtree_key(key).expect("mapped scope");
        assert_eq!(dir, config::scope_key_for_dir(path), "scheduler agreement");
        scopes.insert(dir);
    }
    scopes.len()
}

/// Execute one enum task under a fenced runner (finding-12 wiring
/// proof): the fence is built from `fence_roots` exactly like the scan
/// path builds it from the planned roots, then the production
/// the production task path runs against `scope_path`. Returns the production
/// outcome for the caller to match on.
#[cfg(test)]
pub async fn test_enum_fenced_outcome(
    store: &TursoStore,
    fence_roots: &[PathBuf],
    generation: u64,
    scope_path: &Path,
) -> repo_scan::Result<TaskOutcome> {
    let mut runner = Runner::new(&config::ResourceLimits::default());
    runner.fence = Some(ScopeFence::build(fence_roots));
    let scope_key = config::scope_key_for_dir(scope_path);
    let id = enum_task_id_for_path(generation, scope_path);
    let expected_rev = store.scope_rev(&scope_key).await?;
    let idempotency = format!("idem:{id}");
    let task = NewTask {
        id: &id,
        kind: KIND_ENUM,
        generation,
        dir_id: None,
        scope_key: &scope_key,
        expected_rev,
        idempotency_key: &idempotency,
    };
    store.enqueue_task(&task, store::now_ms()).await?;
    let claimed = store
        .claim_tasks(store.epoch(), 16, LEASE_TTL_MS, store::now_ms())
        .await?;
    let claimed = claimed.into_iter().next().ok_or_else(|| {
        repo_scan::Error::Store(String::from("fenced enum hook: claim returned no task"))
    })?;
    let deadline = OpDeadline::new(Duration::from_secs(OP_DEADLINE_SECS));
    // The sequential test driver runs the production prepare/worker/finish
    // path inline; run_rev/canonical only matter for probe tasks.
    execute_task(
        &mut runner,
        store,
        generation,
        0,
        "test",
        StatusMode::default(),
        &claimed,
        &deadline,
    )
    .await
}

/// PG-03 wiring proof (all platforms): the enum fence-error mapping must
/// refuse `Unsupported` as `Unsupported` — never degrade to the legacy
/// unfenced pathname open.
#[cfg(test)]
pub fn test_enum_unsupported_is_refused() -> bool {
    matches!(
        map_enum_fence_error(
            Path::new("/unsupported-probe"),
            FenceError::Unsupported(String::from("descriptor-relative traversal requires unix")),
        ),
        FencedDir::Refused {
            state: TaskState::Unsupported,
            ..
        }
    )
}
