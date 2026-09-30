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
    AliasInput, ArtifactInput, CandidateInput, ReportInputs as LibReportInputs, ReportPipeline,
    RootInput, StorageLinkInput,
};
use repo_scan::scheduler::{backoff_for_attempt, Admission, CircuitBreaker, OpClass};
use repo_scan::store::{
    self, ClaimedTask, EventRow, NewCheckout, NewGitInstance, NewRef, NewRemote, NewScan,
    NewStatus, NewTask, NewVolume, OwnerGuard, Store, TaskOutcome, TursoStore,
};
use repo_scan::walk::roots::{plan_machine_roots, PlannedRoot, RootPriority};
use repo_scan::walk::topology::{resolve_symlink, PhysicalDirId, ResolveError, Topology};
use repo_scan::walk::{ChildKind, ListOptions};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Set by the SIGINT handler; the scan loop polls it between tasks and
/// between enumeration chunks, then performs the bounded save and exits 130.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Durable task kinds executed by the owner loop.
const KIND_ENUM: &str = "enumerate_dir";
const KIND_PROBE: &str = "probe_git";
const KIND_STATUS: &str = "status";
const KIND_RECONCILE: &str = "reconcile";

/// Tasks claimed per scheduler round (far below the 1,024 prefetch cap).
const CLAIM_BATCH: usize = 16;
/// Lease TTL granted per claim.
const LEASE_TTL_MS: i64 = 60_000;
/// Transient failures before a task parks as unavailable.
const MAX_ATTEMPTS: u64 = 5;
/// Per-task soft watchdog: slower tasks emit a stderr diagnostic.
const SLOW_TASK_SECS: u64 = 30;
/// Per-operation no-progress watchdog grace (R9): an admitted operation that
/// makes no progress for this long is contained (enumeration aborts its
/// admitted portion with a preserved gap; other operations trip the volume
/// breaker after they return). Bounded: at most one grace period of stall
/// per operation before containment engages.
const WATCHDOG_GRACE_SECS: u64 = 120;
/// Circuit-breaker threshold and cooldown per volume (spec §14).
const BREAKER_THRESHOLD: u32 = 3;
const BREAKER_COOLDOWN: Duration = Duration::from_secs(60);
/// Tool-ownership marker filename inside the payload namespace (R15). Written
/// on every owned open; verified before any destructive `cache clear`.
const OWNER_MARKER_NAME: &str = "owner.marker";
/// Marker format tag (first line of the marker file).
const OWNER_MARKER_TAG: &str = "repo-scan-owner-v1";
/// Pending-outcome exit sentinel (R14): a scan row carrying this exit in its
/// outcome column has no terminal outcome yet; the outcome only binds the
/// traversal generation the scan runs in.
const PENDING_EXIT: i32 = -1;
/// Cap on report-ID restage attempts for one scan (R16): every staging
/// attempt gets an immutable snapshot ID; suffixes beyond this are a bug.
const MAX_REPORT_ATTEMPTS: u32 = 1_000;
/// Bytes of the engine file scanned for catalog schema markers (R15).
const DB_IDENTITY_SCAN_BYTES: u64 = 64 * 1024;

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
    let rt = match tokio::runtime::Builder::new_current_thread().build() {
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
fn fail(e: &repo_scan::Error) -> ExitCode {
    eprintln!("repo-scan: error: {e}");
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
    let deadline = Instant::now() + Duration::from_millis(config::OWNER_WAIT_MAX_MS);
    loop {
        match OwnerGuard::acquire(state_dir) {
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
        eprintln!("repo-scan: warning: cannot write ownership marker: {e}");
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
    let mut rows = store
        .connection()
        .query("SELECT value FROM meta WHERE name = 'db_id'", ())
        .await
        .map_err(store_err)?;
    let db_id = match rows.next().await.map_err(store_err)? {
        Some(row) => cell_text(&row, 0)?,
        None => String::from("unknown"),
    };
    let contents = format!(
        "{OWNER_MARKER_TAG}\ndb_id={db_id}\nwritten_ms={}\npid={}\n",
        store::now_ms(),
        std::process::id(),
    );
    let path = owner_marker_path(state_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, contents)?;
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

/// Reclassify every stored instance against THIS scan's canonical target
/// from stored remotes (R1): dispositions are per (instance, target) at
/// report time, so scanning URL-B after URL-A never leaks URL-A's matches
/// into URL-B's report (or vice versa). Probe-structural evidence is kept;
/// stale match verdicts are replaced by fresh ones. Only disposition +
/// evidence are rewritten — observation times are untouched.
async fn reclassify_for_target(
    store: &TursoStore,
    canonical: &str,
    counters: &mut RunCounters,
) -> repo_scan::Result<()> {
    let mut rows = store
        .connection()
        .query("SELECT id, evidence FROM git_instances", ())
        .await
        .map_err(store_err)?;
    let mut instances: Vec<(String, String)> = Vec::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        instances.push((cell_text(&row, 0)?, cell_text(&row, 1)?));
    }
    for (id, evidence_json) in &instances {
        let remotes = store.list_remotes(id).await?;
        let pairs: Vec<(String, String)> = remotes
            .iter()
            .map(|r| (String::from_utf8_lossy(&r.url).into_owned(), r.role.clone()))
            .collect();
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(url, role)| (url.as_str(), role.as_str()))
            .collect();
        let (disposition, mut fresh) = identity::classify_remotes(canonical, borrowed);
        let mut evidence: Vec<String> = serde_json::from_str(evidence_json).unwrap_or_default();
        evidence.retain(|line| {
            !(line.starts_with("Effective ")
                || line.starts_with("No effective remotes")
                || line.starts_with("reclassified for target "))
        });
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
    Ok(())
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

async fn run_scan(cfg: &config::Config, args: &repo_scan::cli::ScanArgs) -> ExitCode {
    match run_scan_inner(cfg, args, None).await {
        Ok(code) => code,
        Err(e) => fail(&e),
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
    let canonical = match identity::normalize_github_url(&args.url) {
        Some(canonical) => canonical,
        None => {
            return Err(repo_scan::Error::InvalidArgs(format!(
                "target URL is not a supported GitHub shape: {}",
                identity::redact_credentials(&args.url),
            )));
        }
    };
    // Absolute report destination at request-creation time (spec §3).
    let report_dest = args
        .report
        .as_ref()
        .map(|p| config::resolve_report_dest(p))
        .transpose()?;
    let (policy, roots, state_roots) = plan_roots(args)?;
    let (_guard, store) = open_owned_with_wait(&cfg.state_dir).await?;
    let epoch = store.epoch();
    let mut runner = Runner::new(&cfg.resources);
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
                args.force_rescan,
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
            pick_generation(&store, &policy, force, now, &mut runner.counters).await?
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
                &args.url,
                &canonical,
                &policy,
                args.status,
                &report_dest,
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
        supersede_stale_scans(
            &store,
            &canonical,
            &policy,
            &scan_id,
            now,
            &mut runner.counters,
        )
        .await?;
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
    upsert_volumes(&store, &policy, &roots, now, &mut runner.counters).await?;
    // Ingest available event history before traversal (R5).
    let drain = ingest_available_events(
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
    reclassify_for_target(&store, &canonical, &mut runner.counters).await?;
    enqueue_status_refresh(&store, generation, run_rev, now, &mut runner.counters).await?;

    let outcome = run_until_boundary(
        &mut runner,
        &store,
        epoch,
        generation,
        run_rev,
        &canonical,
        args.status,
        &scan_id,
    )
    .await?;
    if runner.watchdog.tripped > 0 {
        eprintln!(
            "repo-scan: watchdog tripped {} time(s) this run; stalled scopes were contained",
            runner.watchdog.tripped,
        );
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
    // Advance reconciled cursors over satisfied work (R5).
    let cursors = reconcile_event_cursors(&mut events, &store).await?;

    let finished_ms = store::now_ms();
    let gen_state = if outcome.interrupted {
        "interrupted"
    } else if outcome.has_gaps() {
        "incomplete"
    } else {
        "complete"
    };
    store.set_generation_state(generation, gen_state).await?;
    runner.counters.db_transactions += 1;
    let discovery_code = if outcome.has_gaps() { 3 } else { 0 };
    // Stage first, publish second through the tested lib pipeline (R3): a
    // failed publication retains the saved snapshot and can be retried
    // without repeating discovery.
    let report_id = fresh_report_id(&store, &cfg.state_dir, &scan_id).await?;
    let catalog_rev = store.current_revision().await?;
    let dirs_complete = count_dirs_complete(&store, generation).await?;
    let snapshot_path = snapshots_dir(&cfg.state_dir).join(format!("{report_id}.json"));
    let inputs = ScanReportInputs {
        scan_id: scan_id.clone(),
        generation,
        epoch,
        target_raw: args.url.clone(),
        canonical: canonical.clone(),
        scope_policy: policy.clone(),
        scan_state: gen_state.to_string(),
        status_mode: args.status,
        started_ms,
        finished_ms,
        report_dest: report_dest.clone(),
        roots: roots.clone(),
        counters: runner.counters.clone(),
        pending: outcome.pending,
        status_pending: outcome.status_pending,
        aliases: runner.aliases.clone(),
        root_cursors: root_cursors_for(&roots, &events, &cursors),
        event_note: events.note(),
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
                    eprintln!("repo-scan: report publication failed: {e}");
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
                    eprintln!("repo-scan: terminal report failed: {e}");
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
    } else if outcome.has_gaps() {
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
            let table = repo_scan::platform::linux::FixtureMountTable;
            let mounts = table.mounts()?;
            Ok((String::from("machine"), plan_machine_roots(&mounts), None))
        }
    }
}

/// Pick the traversal generation: a fresh one on `--force-rescan`, else the
/// newest generation of this scope policy still holding actionable work
/// (compatible unfinished discovery is resumed and shared), else the newest
/// generation (valid catalog information is reused), else a new one.
async fn pick_generation(
    store: &TursoStore,
    policy: &str,
    force: bool,
    now_ms: i64,
    counters: &mut RunCounters,
) -> repo_scan::Result<u64> {
    let mut rows = store
        .connection()
        .query(
            "SELECT id, state FROM generations WHERE scope_policy = ?1 ORDER BY id DESC",
            vec![turso::Value::Text(policy.to_string())],
        )
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?;
    let mut generations = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| repo_scan::Error::Store(e.to_string()))?
    {
        generations.push((cell_int(&row, 0)? as u64, cell_text(&row, 1)?));
    }
    if !force {
        for (id, _) in &generations {
            if store.pending_count(*id).await? > 0 {
                store.set_generation_state(*id, "running").await?;
                counters.db_transactions += 1;
                return Ok(*id);
            }
        }
        if let Some((id, _)) = generations.first() {
            store.set_generation_state(*id, "running").await?;
            counters.db_transactions += 1;
            return Ok(*id);
        }
    }
    let prior = generations.first().map(|(id, _)| *id);
    let generation = store
        .create_generation(policy, "running", prior, now_ms)
        .await?;
    counters.db_transactions += 1;
    Ok(generation)
}

/// Mint a scan ID and persist the request row (raw + canonical URL, scope,
/// status mode, absolute report destination). Retries ID collisions.
async fn mint_scan_id(
    store: &TursoStore,
    raw_url: &str,
    canonical: &str,
    policy: &str,
    status: StatusMode,
    report_dest: &Option<PathBuf>,
    counters: &mut RunCounters,
) -> repo_scan::Result<String> {
    let now = store::now_ms();
    let dest_bytes = report_dest.as_ref().map(|p| config::path_as_bytes(p));
    for _ in 0..3 {
        let id = config::new_scan_id();
        let inserted = store
            .create_scan_request(
                &NewScan {
                    id: &id,
                    url_raw: raw_url.as_bytes(),
                    url_canonical: Some(canonical.as_bytes()),
                    scope: policy,
                    status_mode: status_mode_str(status),
                    report_dest: dest_bytes.as_deref(),
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
    let table = repo_scan::platform::linux::FixtureMountTable;
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
        let inserted = store
            .enqueue_task(
                &NewTask {
                    id: &id,
                    kind: KIND_ENUM,
                    generation,
                    dir_id: None,
                    scope_key: &scope_key,
                    expected_rev,
                    idempotency_key: &idempotency,
                },
                now_ms,
            )
            .await?;
        runner.counters.db_transactions += 1;
        if !inserted {
            // Two requested roots name the same object: shared results
            // plus a preserved alias (R7).
            note_enum_alias(
                store,
                runner,
                &id,
                &scope_key,
                &root.path,
                "same_object",
                now_ms,
            )
            .await?;
        }
    }
    Ok(())
}

/// Stable enumeration task ID from physical identity when the path stats,
/// else from the path bytes (execution then records the gap durably).
/// Identity follows symlinks (R7) so alias spellings share one task and
/// its results; the `(0, 0)` fallback (non-unix) never shares an ID.
fn enum_task_id_for_path(generation: u64, path: &Path) -> String {
    let identity = std::fs::metadata(path)
        .ok()
        .map(|md| dir_identity(&md))
        .filter(|key| *key != (0, 0));
    match identity {
        Some((dev, ino)) => format!("enum:{generation}:d{dev}:i{ino}"),
        None => format!(
            "enum:{generation}:path:{}",
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
    generation: u64,
    run_rev: u64,
    now_ms: i64,
    counters: &mut RunCounters,
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
        enqueue_status_task(store, generation, run_rev, &checkout_id, now_ms, counters).await?;
    }
    Ok(())
}

async fn enqueue_status_task(
    store: &TursoStore,
    generation: u64,
    run_rev: u64,
    checkout_id: &str,
    now_ms: i64,
    counters: &mut RunCounters,
) -> repo_scan::Result<()> {
    let scope_key = config::scope_key_for_status(checkout_id);
    let id = format!("status:{checkout_id}:{run_rev}");
    let idempotency = format!("idem:{id}");
    let expected_rev = store.scope_rev(&scope_key).await?;
    store
        .enqueue_task(
            &NewTask {
                id: &id,
                kind: KIND_STATUS,
                generation,
                dir_id: None,
                scope_key: &scope_key,
                expected_rev,
                idempotency_key: &idempotency,
            },
            now_ms,
        )
        .await?;
    counters.db_transactions += 1;
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
    applied_scopes: HashMap<String, Vec<String>>,
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

/// Durable per-volume cursors from every journal row, grouped by volume.
async fn load_stored_cursors(
    store: &TursoStore,
) -> repo_scan::Result<HashMap<String, events::VolumeCursor>> {
    let mut rows = store
        .connection()
        .query(
            "SELECT id, volume_id, history_uuid, cursor, received_ms, invalidated, \
             ingested, reconciled FROM event_journal ORDER BY id ASC",
            (),
        )
        .await
        .map_err(store_err)?;
    let mut all: Vec<EventRow> = Vec::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        all.push(EventRow {
            id: cell_int(&row, 0)?,
            volume_id: cell_text(&row, 1)?,
            history_uuid: cell_text(&row, 2)?,
            cursor: cell_text(&row, 3)?,
            received_ms: cell_int(&row, 4)?,
            invalidated: cell_int(&row, 5)? != 0,
            ingested: cell_int(&row, 6)? != 0,
            reconciled: cell_int(&row, 7)? != 0,
        });
    }
    let mut keys: Vec<String> = all.iter().map(|r| r.volume_id.clone()).collect();
    keys.sort();
    keys.dedup();
    let mut out = HashMap::new();
    for key in keys {
        if let Some(cursor) = events::volume_cursor_from_rows(&key, &all) {
            out.insert(key, cursor);
        }
    }
    Ok(out)
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
        history_invalid: false,
        degraded: Vec::new(),
        live: false,
    };
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
                    for m in opened.drain(..) {
                        let decision = session.reconciler.note_stream_opened(
                            &volume.key,
                            stored.get(&volume.key),
                            live_uuid.as_ref(),
                            live_id,
                            m.boundary,
                        );
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
                        volume.key, e,
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
    for m in session.monitored.iter_mut() {
        for _ in 0..16 {
            match m.batches.next_batch() {
                Ok(Some(batch)) => batches.push(batch),
                Ok(None) => break,
                Err(e) => {
                    eprintln!("repo-scan: events: batch error on {}: {e}", m.volume_key,);
                    break;
                }
            }
        }
    }
    // Scope fence in both spellings: event paths are physical while
    // roots may carry an unclean spelling (`/var` vs `/private/var`).
    let fence: Vec<PathBuf> = roots
        .iter()
        .flat_map(|r| {
            let canon = r.path.canonicalize().unwrap_or_else(|_| r.path.clone());
            if canon == r.path {
                vec![canon]
            } else {
                vec![r.path.clone(), canon]
            }
        })
        .collect();
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
    }
    Ok(applied)
}

/// True when `path` sits inside the scan's planned roots (canonical fence).
fn in_scan_scope(fence: &[PathBuf], path: &Path) -> bool {
    fence.iter().any(|root| path.starts_with(root))
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
    fence: &[PathBuf],
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
    if !outcome.duplicate && batch.high_water.0 != 0 {
        let uuid = session
            .reconciler
            .journal()
            .load(&outcome.volume_key)
            .and_then(|c| c.uuid);
        if let Some(uuid) = uuid {
            store
                .append_event(
                    &outcome.volume_key,
                    &uuid.0,
                    &events::journal_cursor_string(batch.high_water),
                    !outcome.plans.is_empty(),
                    now,
                )
                .await?;
            counters.db_transactions += 1;
        }
    }
    let mut scopes: Vec<String> = Vec::new();
    for plan in &outcome.plans {
        if plan.scope_key.starts_with("volume:") || plan.scope_key == events::mounts_scope_key() {
            scopes.push(plan.scope_key.clone());
            if plan.scope_key == events::mounts_scope_key() {
                applied.mount_changed = true;
            }
        }
    }
    // Path plans become dir-scope invalidations (path + parent, mirroring
    // the continuity plan): the scheduler re-enumerates exactly those dirs.
    // Recursive (MustScanSubDirs) subtrees re-enumerate one level here;
    // deeper changes carry their own events. Out-of-scope paths are
    // dropped: the journal still records the cursor, but no work is
    // scheduled outside the requested roots.
    for path in &batch.invalidations {
        if !in_scan_scope(fence, path) {
            continue;
        }
        scopes.push(config::scope_key_for_dir(path));
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && in_scan_scope(fence, parent) {
                scopes.push(config::scope_key_for_dir(parent));
            }
        }
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
    session
        .applied_scopes
        .entry(outcome.volume_key.clone())
        .or_default()
        .extend(scopes.iter().cloned());
    for scope in &scopes {
        store.invalidate_scope(scope, generation, now).await?;
        counters.db_transactions += 1;
        applied.scopes += 1;
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

/// Advance reconciled cursors post-traversal, only over satisfied work,
/// and report per-volume cursors from durable rows (current UUID only).
async fn reconcile_event_cursors(
    session: &mut EventSession,
    store: &TursoStore,
) -> repo_scan::Result<HashMap<String, RootCursors>> {
    let keys: Vec<String> = session
        .monitored
        .iter()
        .map(|m| m.volume_key.clone())
        .collect();
    for key in &keys {
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
    report_cursors_from_store(store, session).await
}

/// Mark journal rows at or below `through` reconciled (current UUID only).
async fn mark_events_reconciled_through(
    store: &TursoStore,
    volume: &str,
    through: events::EventCursorId,
) -> repo_scan::Result<()> {
    let mut rows = store
        .connection()
        .query(
            "SELECT id, history_uuid, cursor FROM event_journal WHERE volume_id = ?1 ORDER BY id ASC",
            vec![turso::Value::Text(volume.to_string())],
        )
        .await
        .map_err(store_err)?;
    let mut pending: Vec<(i64, String, String)> = Vec::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        pending.push((cell_int(&row, 0)?, cell_text(&row, 1)?, cell_text(&row, 2)?));
    }
    let Some(current) = pending.last().map(|(_, uuid, _)| uuid.clone()) else {
        return Ok(());
    };
    for (id, uuid, cursor) in pending {
        if uuid != current {
            continue;
        }
        let covered = events::parse_journal_cursor(&cursor).is_some_and(|c| c.0 <= through.0);
        if covered {
            store.mark_event_reconciled(id).await?;
        }
    }
    Ok(())
}

/// Per-volume report cursors from durable rows (current UUID only):
/// monitored volumes plus any volume with persisted history.
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
        let mut rows = store
            .connection()
            .query(
                "SELECT id, volume_id, history_uuid, cursor, received_ms, invalidated, \
                 ingested, reconciled FROM event_journal WHERE volume_id = ?1 ORDER BY id ASC",
                vec![turso::Value::Text(key.clone())],
            )
            .await
            .map_err(store_err)?;
        let mut all: Vec<EventRow> = Vec::new();
        while let Some(row) = rows.next().await.map_err(store_err)? {
            all.push(EventRow {
                id: cell_int(&row, 0)?,
                volume_id: cell_text(&row, 1)?,
                history_uuid: cell_text(&row, 2)?,
                cursor: cell_text(&row, 3)?,
                received_ms: cell_int(&row, 4)?,
                invalidated: cell_int(&row, 5)? != 0,
                ingested: cell_int(&row, 6)? != 0,
                reconciled: cell_int(&row, 7)? != 0,
            });
        }
        let Some(current) = all.last().map(|r| r.history_uuid.clone()) else {
            continue;
        };
        let current_rows: Vec<EventRow> = all
            .into_iter()
            .filter(|r| r.history_uuid == current)
            .collect();
        if let Some(cursor) = events::volume_cursor_from_rows(&key, &current_rows) {
            out.insert(
                key,
                RootCursors {
                    history_uuid: cursor.uuid.map(|u| u.0),
                    ingested: cursor.ingested.map(|c| c.0.to_string()),
                    reconciled: cursor.reconciled.map(|c| c.0.to_string()),
                },
            );
        }
    }
    Ok(out)
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
    /// Real store transactions (R13): incremented once per mutating store
    /// call (one autocommit statement or one `with_tx` each), never per
    /// logical row. This is what the report's `db_transactions` carries.
    db_transactions: u64,
    stale_requeued: u64,
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

/// Owner-side run state: admission gates, per-volume breakers, topology
/// guard, and one lazily discovered installed-git fallback.
struct Runner {
    admission: Admission,
    breakers: HashMap<String, CircuitBreaker>,
    topology: Topology,
    inspector: git::GixInspector,
    fallback: Option<git::fallback::FallbackGit>,
    fallback_probed: bool,
    counters: RunCounters,
    /// Pathname aliases observed this run (R7), emitted as `Alias` records.
    aliases: Vec<ObservedAlias>,
    /// Git-directory identities already persisted this run (R7):
    /// `(dev, ino)` of `instance.git_dir` to the first spelling's bytes.
    /// A second spelling of the same object records an alias instead of a
    /// duplicate instance.
    probed_git_ids: HashMap<(u64, u64), Vec<u8>>,
    /// Per-operation no-progress watchdog (R9).
    watchdog: Watchdog,
}

impl Runner {
    fn new(limits: &config::ResourceLimits) -> Self {
        Self {
            admission: Admission::new(limits.clone()),
            breakers: HashMap::new(),
            topology: Topology::new(),
            inspector: git::GixInspector::new(),
            fallback: None,
            fallback_probed: false,
            counters: RunCounters::default(),
            aliases: Vec::new(),
            probed_git_ids: HashMap::new(),
            watchdog: Watchdog::new(Duration::from_secs(WATCHDOG_GRACE_SECS)),
        }
    }

    /// Installed-git fallback, discovered once per run (probe-once-per-identity).
    fn fallback(&mut self) -> Option<&git::fallback::FallbackGit> {
        if !self.fallback_probed {
            self.fallback_probed = true;
            self.fallback = git::fallback::FallbackGit::discover(&[]);
            if let Some(found) = &self.fallback {
                eprintln!(
                    "repo-scan: installed-git fallback: {} ({})",
                    found.path().display(),
                    found.capabilities().version,
                );
            }
        }
        self.fallback.as_ref()
    }
}

/// Per-operation no-progress watchdog (R9) with bounded grace.
///
/// Attributed to the specific admitted operation: grace runs from admission,
/// and only that operation's own completion counts as progress. On expiry
/// the operation is contained (enumeration aborts its admitted portion with
/// a preserved gap; other operations trip the volume breaker once they
/// return), so one stalled scope cannot silently stall the run.
///
/// Honest single-owner limits: this process is the only worker and executes
/// operations synchronously, so a hard-hung `stat`/list/Git syscall cannot
/// be preempted — there is no helper to kill and no thread to cancel. The
/// watchdog therefore bounds *detected* stalls: chunk-interruptible work
/// (enumeration) is aborted in place, and every other over-grace operation
/// is contained after the fact (breaker + preserved gap + stderr). It never
/// claims cancellation it cannot perform.
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
) -> repo_scan::Result<RunOutcome> {
    loop {
        if interrupted() {
            eprintln!("repo-scan: interrupted; saving progress (bounded)");
            break;
        }
        let now = store::now_ms();
        let claimed = store
            .claim_tasks(epoch, CLAIM_BATCH, LEASE_TTL_MS, now)
            .await?;
        runner.counters.db_transactions += 1;
        if claimed.is_empty() {
            break;
        }
        let mut progressed = false;
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
                KIND_PROBE | KIND_STATUS => OpClass::GitProbe,
                _ => OpClass::Other,
            };
            let Some(permit) = runner.admission.try_acquire(class) else {
                // Same explicit release for admission denials (R4).
                release_claim(store, &mut runner.counters, item, epoch).await?;
                continue;
            };
            progressed = true;
            let started = Instant::now();
            let result = execute_task(
                runner,
                store,
                epoch,
                generation,
                run_rev,
                canonical,
                status_mode,
                item,
            )
            .await;
            runner.admission.release(&permit);
            let elapsed = started.elapsed();
            if elapsed > Duration::from_secs(SLOW_TASK_SECS) {
                eprintln!(
                    "repo-scan: slow task: {} ({}s)",
                    item.task.id,
                    elapsed.as_secs()
                );
            }
            if runner.watchdog.exceeded(started, Instant::now()) {
                // No-progress grace exhausted: contain the scope (R9). The
                // operation already returned, so containment isolates the
                // volume for the rest of the run instead of pretending to
                // cancel in flight.
                runner.watchdog.tripped += 1;
                runner.breaker_failure(&volume);
                runner.breaker_failure(&volume);
                runner.breaker_failure(&volume);
                eprintln!(
                    "repo-scan: watchdog: {} made no progress within {}s; \
                     volume {volume} contained (breaker opened)",
                    item.task.id, WATCHDOG_GRACE_SECS,
                );
            }
            match result {
                Ok(()) => {
                    runner.breaker_success(&volume);
                }
                Err(e) => {
                    // Lease/unknown-task failures are scheduler bugs, not
                    // scope gaps: abort the run loudly instead of hiding
                    // unfinished work behind a parked task.
                    return Err(e);
                }
            }
            runner.counters.claimed += 1;
            if runner.admission.progress_due() {
                eprintln!(
                    "repo-scan: scan {scan_id} gen {generation}: {} claimed, \
                     {} dirs, {} entries, {} stale-requeued",
                    runner.counters.claimed,
                    runner.counters.dirs_complete,
                    runner.counters.entries,
                    runner.counters.stale_requeued,
                );
            }
        }
        if !progressed {
            // Everything claimable is breaker-held: the boundary for this run.
            break;
        }
    }
    let pending = store.pending_count(generation).await?;
    let open_gaps = count_open_errors(store).await?;
    let unresolvable = count_unresolvable(store).await?;
    let status_pending = count_status_pending(store, generation).await?;
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
        .connection()
        .execute(
            "UPDATE frontier_tasks SET state = 'pending', lease_token = NULL, \
             lease_epoch = NULL, lease_expires_ms = NULL, updated_at_ms = ?1 \
             WHERE id = ?2 AND state = 'leased' AND lease_token = ?3 \
             AND lease_epoch = ?4",
            vec![
                turso::Value::Integer(store::now_ms()),
                turso::Value::Text(claimed.task.id.clone()),
                turso::Value::Integer(claimed.token),
                turso::Value::Integer(epoch as i64),
            ],
        )
        .await
        .map_err(store_err)?;
    counters.db_transactions += 1;
    Ok(())
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
/// failures complete as retry/parked with preserved gaps.
#[allow(clippy::too_many_arguments)]
async fn execute_task(
    runner: &mut Runner,
    store: &TursoStore,
    epoch: u64,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    status_mode: StatusMode,
    claimed: &ClaimedTask,
) -> repo_scan::Result<()> {
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
        match complete_claimed(store, runner, claimed, epoch, &TaskOutcome::Complete).await? {
            CompletionApplied::Applied => {}
            CompletionApplied::StaleRequeued => {
                runner.counters.stale_requeued += 1;
            }
        }
        return Ok(());
    }
    let outcome = match claimed.task.kind.as_str() {
        KIND_ENUM | KIND_RECONCILE => exec_enumerate(runner, store, generation, claimed).await?,
        KIND_PROBE => exec_probe(runner, store, generation, run_rev, canonical, claimed).await?,
        KIND_STATUS => exec_status(runner, store, status_mode, claimed).await?,
        other => {
            let detail = format!("unknown task kind: {other}");
            store
                .record_error(
                    &format!("kind:{}", claimed.task.id),
                    &claimed.task.scope_key,
                    "unsupported-task-kind",
                    &detail,
                    None,
                    store::now_ms(),
                )
                .await?;
            runner.counters.db_transactions += 1;
            TaskOutcome::Parked {
                state: TaskState::Unsupported,
                reason: detail,
            }
        }
    };
    match complete_claimed(store, runner, claimed, epoch, &outcome).await? {
        CompletionApplied::Applied => {}
        CompletionApplied::StaleRequeued => {
            runner.counters.stale_requeued += 1;
            eprintln!(
                "repo-scan: stale completion requeued: {} (invalidation kept)",
                claimed.task.id,
            );
        }
    }
    Ok(())
}

enum CompletionApplied {
    Applied,
    StaleRequeued,
}

/// Complete one claimed task, translating the store's scheduler signals:
/// stale completions (already requeued by the store) are routine; lease
/// mismatches and unknown tasks become typed errors that abort the run.
async fn complete_claimed(
    store: &TursoStore,
    runner: &mut Runner,
    claimed: &ClaimedTask,
    epoch: u64,
    outcome: &TaskOutcome,
) -> repo_scan::Result<CompletionApplied> {
    let now = store::now_ms();
    match store
        .complete_task(&claimed.task.id, claimed.token, epoch, outcome, now)
        .await
    {
        Ok(()) => {
            runner.counters.db_transactions += 1;
            Ok(CompletionApplied::Applied)
        }
        Err(repo_scan::Error::Scheduler(message)) if message.starts_with("stale-completion:") => {
            runner.counters.db_transactions += 1;
            Ok(CompletionApplied::StaleRequeued)
        }
        Err(repo_scan::Error::Scheduler(message)) if message.starts_with("lease-mismatch:") => {
            Err(repo_scan::Error::LeaseMismatch(message))
        }
        Err(repo_scan::Error::Scheduler(message)) if message.starts_with("unknown-task:") => {
            Err(repo_scan::Error::UnknownTask(message))
        }
        Err(e) => Err(e),
    }
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

/// Enumerate one directory's immediate children: upsert the directory row,
/// enqueue unseen child directories (identity-deduped), resolve symlinks
/// through the topology layer, detect Git candidates by marker evidence
/// (`.git` entry; `HEAD`+`objects`+`refs` for bare stores) for exact-path
/// validation, and record the observation. Races are gaps, never absence.
async fn exec_enumerate(
    runner: &mut Runner,
    store: &TursoStore,
    generation: u64,
    claimed: &ClaimedTask,
) -> repo_scan::Result<TaskOutcome> {
    let Some(config::ScopeRef::Dir(path)) = config::parse_scope_key(&claimed.task.scope_key) else {
        return Ok(TaskOutcome::Parked {
            state: TaskState::Unsupported,
            reason: format!("malformed dir scope key: {}", claimed.task.scope_key),
        });
    };
    let md = match std::fs::symlink_metadata(&path) {
        Ok(md) => md,
        Err(e) => {
            let detail = format!("cannot stat {}: {e}", path.display());
            if let Some(state) = classify_io_error(&e) {
                return Ok(TaskOutcome::Parked {
                    state,
                    reason: detail,
                });
            }
            return fail_task(
                runner,
                store,
                claimed,
                ExecFail {
                    category: String::from("stat-error"),
                    detail,
                },
            )
            .await;
        }
    };
    let (dev, ino) = dir_identity(&md);
    let volume_tag = format!("dev:{dev}");
    runner.topology.observe(PhysicalDirId {
        dev,
        ino,
        namespace: volume_tag.clone(),
    });
    let now = store::now_ms();
    let admitted = Instant::now();
    let component = path
        .file_name()
        .map(|n| config::path_as_bytes(Path::new(n)))
        .unwrap_or_else(|| config::path_as_bytes(&path));
    let dir_id = store
        .upsert_dir(
            None,
            &component,
            &escape_display(&config::path_as_bytes(&path)),
            &volume_tag,
            &ino.to_string(),
            &incarnation_of(&md),
            now,
        )
        .await?;
    runner.counters.db_transactions += 1;

    let adapter = repo_scan::walk::primary_adapter();
    let listing = match adapter.list_dir(
        &path,
        ListOptions {
            skip_metadata: false,
        },
    ) {
        Ok(listing) => listing,
        Err(e) => {
            let detail = format!("cannot list {}: {e}", path.display());
            store
                .record_dir_observation(dir_id, generation, false, 1, 0, Some(&detail), now)
                .await?;
            runner.counters.db_transactions += 1;
            if let Some(state) = classify_io_error(&e) {
                return Ok(TaskOutcome::Parked {
                    state,
                    reason: detail,
                });
            }
            return fail_task(
                runner,
                store,
                claimed,
                ExecFail {
                    category: String::from("enumerate-error"),
                    detail,
                },
            )
            .await;
        }
    };
    let mut entries_seen = 0u64;
    let mut mid_error: Option<String> = None;
    let mut saw_head = false;
    let mut saw_objects = false;
    let mut saw_refs = false;
    let mut probed_self_for_dot_git = false;
    for item in listing {
        if interrupted() {
            mid_error = Some(String::from("interrupted; partial enumeration"));
            break;
        }
        // No-progress watchdog (R9): chunk-interruptible work aborts its
        // admitted portion in place once grace expires. The partial
        // observation is recorded below and the task retries with backoff,
        // so the stall is bounded instead of open-ended.
        if runner.watchdog.exceeded(admitted, Instant::now()) {
            runner.watchdog.tripped += 1;
            runner.breaker_failure(&volume_tag);
            mid_error = Some(format!(
                "watchdog: no progress within {WATCHDOG_GRACE_SECS}s; \
                 partial enumeration contained",
            ));
            eprintln!(
                "repo-scan: watchdog: enumeration of {} exceeded grace; contained",
                path.display(),
            );
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
        let name = child.name.clone();
        let is_dot_git = name.as_os_str() == std::ffi::OsStr::new(".git");
        if is_dot_git && !probed_self_for_dot_git {
            probed_self_for_dot_git = true;
            enqueue_probe_task(store, runner, generation, claimed, &path, now).await?;
        }
        track_bare_markers(
            &name,
            child.kind,
            &mut saw_head,
            &mut saw_objects,
            &mut saw_refs,
        );
        let child_path = path.join(&name);
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
    runner.counters.entries += entries_seen;
    if saw_head && saw_objects && saw_refs {
        // Bare-store marker evidence: exact-path validation decides.
        enqueue_probe_task(store, runner, generation, claimed, &path, now).await?;
    }
    let entry_generation = store
        .get_dir_observation(dir_id, generation)
        .await?
        .map(|o| o.entry_generation + 1)
        .unwrap_or(1);
    let completed = mid_error.is_none();
    store
        .record_dir_observation(
            dir_id,
            generation,
            completed,
            entry_generation,
            entries_seen,
            mid_error.as_deref(),
            store::now_ms(),
        )
        .await?;
    runner.counters.db_transactions += 1;
    if completed {
        runner.counters.dirs_complete += 1;
        Ok(TaskOutcome::Complete)
    } else {
        let detail = mid_error.unwrap_or_else(|| String::from("partial enumeration"));
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

/// Incarnation guard against identifier reuse (link count + mtime + size).
#[cfg(unix)]
fn incarnation_of(md: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| format!("{}.{}", d.as_secs(), d.subsec_nanos()))
        .unwrap_or_else(|| String::from("unknown"));
    format!("n{}:m{mtime}:s{}", md.nlink(), md.len())
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
    let inserted = store
        .enqueue_task(
            &NewTask {
                id: &id,
                kind: KIND_ENUM,
                generation,
                dir_id: None,
                scope_key: &scope_key,
                expected_rev,
                idempotency_key: &idempotency,
            },
            now_ms,
        )
        .await?;
    runner.counters.db_transactions += 1;
    if !inserted {
        // Identity-deduped: the same object is already scheduled under
        // another spelling. Results are shared (not dropped), and the
        // alternate pathname is preserved as an alias (R7).
        note_enum_alias(
            store,
            runner,
            &id,
            &scope_key,
            child_path,
            "same_object",
            now_ms,
        )
        .await?;
    }
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
    runner.aliases.push(ObservedAlias {
        path: config::path_as_bytes(path),
        target: config::path_as_bytes(&first),
        kind,
        verified_at_ms: now_ms,
    });
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
            let id = format!(
                "enum:{generation}:d{}:i{}",
                target.metadata.dev, target.metadata.ino
            );
            let scope_key = config::scope_key_for_dir(&target.path);
            let expected_rev = store.scope_rev(&scope_key).await?;
            let idempotency = format!("idem:{id}");
            let inserted = store
                .enqueue_task(
                    &NewTask {
                        id: &id,
                        kind: KIND_ENUM,
                        generation,
                        dir_id: None,
                        scope_key: &scope_key,
                        expected_rev,
                        idempotency_key: &idempotency,
                    },
                    now_ms,
                )
                .await?;
            runner.counters.db_transactions += 1;
            // The link pathname is an alias of its target pathname (R7),
            // whether or not this enqueue won the shared task.
            runner.aliases.push(ObservedAlias {
                path: config::path_as_bytes(link_path),
                target: config::path_as_bytes(&target.path),
                kind: "symlink",
                verified_at_ms: now_ms,
            });
            if !inserted {
                // The target itself is scheduled under another spelling:
                // preserve that pair too.
                note_enum_alias(
                    store,
                    runner,
                    &id,
                    &scope_key,
                    &target.path,
                    "same_object",
                    now_ms,
                )
                .await?;
            }
            Ok(())
        }
        Err(ResolveError::Cycle(p) | ResolveError::TooDeep(p)) => {
            store
                .record_error(
                    &format!(
                        "symlink:{}",
                        config::encode_hex(&config::path_as_bytes(link_path))
                    ),
                    &config::scope_key_for_dir(link_path),
                    "symlink-cycle",
                    &format!("symlink cycle or excessive chain at {}", p.display()),
                    None,
                    now_ms,
                )
                .await?;
            runner.counters.db_transactions += 1;
            Ok(())
        }
        Err(ResolveError::Io(e)) => {
            store
                .record_error(
                    &format!(
                        "symlink:{}",
                        config::encode_hex(&config::path_as_bytes(link_path))
                    ),
                    &config::scope_key_for_dir(link_path),
                    "symlink-unresolvable",
                    &format!("cannot resolve {}: {e}", link_path.display()),
                    None,
                    now_ms,
                )
                .await?;
            runner.counters.db_transactions += 1;
            Ok(())
        }
    }
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
    let id = format!("probe:{generation}:{hex}{suffix}");
    let scope_key = config::scope_key_for_git(path);
    let expected_rev = store.scope_rev(&scope_key).await?;
    let idempotency = format!("idem:{id}");
    store
        .enqueue_task(
            &NewTask {
                id: &id,
                kind: KIND_PROBE,
                generation,
                dir_id: None,
                scope_key: &scope_key,
                expected_rev,
                idempotency_key: &idempotency,
            },
            now_ms,
        )
        .await?;
    runner.counters.db_transactions += 1;
    Ok(())
}

/// Validate one Git candidate at its exact path and persist the instance,
/// checkouts, remotes, refs, and HEAD observations. Marker evidence that
/// fails validation becomes a preserved `probe-failed` gap (terminal for
/// this probe; re-probe only after invalidation or rescan), never a fake
/// absence and never an endless retry.
async fn exec_probe(
    runner: &mut Runner,
    store: &TursoStore,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    claimed: &ClaimedTask,
) -> repo_scan::Result<TaskOutcome> {
    let Some(config::ScopeRef::Git(path)) = config::parse_scope_key(&claimed.task.scope_key) else {
        return Ok(TaskOutcome::Parked {
            state: TaskState::Unsupported,
            reason: format!("malformed git scope key: {}", claimed.task.scope_key),
        });
    };
    let now = store::now_ms();
    let gap_id = format!(
        "probe:{}",
        config::encode_hex(&config::path_as_bytes(&path))
    );
    let validated = match runner.inspector.validate(&path) {
        Ok(validated) => validated,
        Err(e) => {
            let category = if git::is_unsupported_error(&e) {
                "unsupported-git-format"
            } else {
                "probe-failed"
            };
            store
                .record_error(
                    &gap_id,
                    &claimed.task.scope_key,
                    category,
                    &e.to_string(),
                    None,
                    now,
                )
                .await?;
            runner.counters.db_transactions += 1;
            return Ok(TaskOutcome::Complete);
        }
    };
    match persist_probe(
        runner, store, generation, run_rev, canonical, &path, &validated, now,
    )
    .await
    {
        Ok(()) => {
            store.resolve_error(&gap_id, store::now_ms()).await?;
            runner.counters.db_transactions += 1;
            Ok(TaskOutcome::Complete)
        }
        // Operational Git failures retry with backoff, then park with the
        // gap preserved; store failures abort the run (exit 1).
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
            .await
        }
        Err(e) => Err(e),
    }
}

/// Persist every observation from a validated probe. Remotes, refs, and HEAD
/// fall back to installed git only on structural gaps; operational failures
/// fail the task (retry, then park) instead of recording fake unknowns.
#[allow(clippy::too_many_arguments)]
async fn persist_probe(
    runner: &mut Runner,
    store: &TursoStore,
    generation: u64,
    run_rev: u64,
    canonical: &str,
    path: &Path,
    validated: &git::ValidatedCandidate,
    now_ms: i64,
) -> repo_scan::Result<()> {
    let instance = &validated.instance;
    let git_bytes = config::path_as_bytes(&instance.git_dir);
    let common_bytes = config::path_as_bytes(&instance.common_dir);
    let instance_id = format!("git:{}", config::encode_hex(&git_bytes));
    let incarnation = std::fs::symlink_metadata(&instance.git_dir)
        .map(|md| {
            let (dev, ino) = dir_identity(&md);
            format!("d{dev}i{ino}")
        })
        .unwrap_or_default();

    // A second pathname spelling of an already-persisted object records an
    // alias instead of a duplicate instance (R7). Identity follows
    // symlinks; the `(0, 0)` fallback (non-unix) never dedupes.
    let git_identity = std::fs::metadata(&instance.git_dir)
        .ok()
        .map(|md| dir_identity(&md))
        .filter(|key| *key != (0, 0));
    if let Some(key) = git_identity {
        match runner.probed_git_ids.get(&key).cloned() {
            Some(first) if first != git_bytes => {
                runner.aliases.push(ObservedAlias {
                    path: git_bytes.clone(),
                    target: first,
                    kind: "same_object",
                    verified_at_ms: now_ms,
                });
                return Ok(());
            }
            Some(_) => {}
            None => {
                runner.probed_git_ids.insert(key, git_bytes.clone());
            }
        }
    }

    let mut evidence = validated.evidence.clone();
    evidence.push(format!("matching-policy: {}", identity::MATCHING_POLICY));
    let deps = runner.inspector.config_dependencies(instance);
    evidence.push(format!("config files consulted: {}", deps.len()));

    let remotes = match runner.inspector.remotes(instance) {
        Ok(remotes) => remotes,
        Err(e) if git::is_unsupported_error(&e) => {
            evidence.push(format!("remotes unsupported, treated as no remotes: {e}"));
            Vec::new()
        }
        Err(e) => {
            return Err(repo_scan::Error::Git(format!(
                "remotes unreadable for {}: {e}",
                path.display()
            )));
        }
    };
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
    let (disposition, mut match_evidence) = identity::classify_remotes(canonical, borrowed);
    evidence.append(&mut match_evidence);
    let evidence_json =
        serde_json::to_string(&evidence).map_err(|e| repo_scan::Error::Report(e.to_string()))?;
    store
        .upsert_git_instance(
            &NewGitInstance {
                id: &instance_id,
                git_path: &git_bytes,
                common_path: &common_bytes,
                incarnation: &incarnation,
                format: "git-files",
                bare: Some(instance.is_bare),
                object_format: &instance.object_format,
                disposition: disposition_str(disposition),
                evidence_json: &evidence_json,
            },
            now_ms,
        )
        .await?;
    runner.counters.db_transactions += 1;
    for remote in &remotes {
        let role = match remote.role {
            git::RemoteRole::Fetch => "fetch",
            git::RemoteRole::Push => "push",
        };
        let remote_id = format!(
            "remote:{}:{}:{role}",
            config::encode_hex(&git_bytes),
            config::encode_hex(&remote.name),
        );
        let canonical_bytes = remote.canonical_url.as_ref().map(|c| c.as_bytes());
        store
            .upsert_remote(
                &NewRemote {
                    id: &remote_id,
                    instance_id: &instance_id,
                    checkout_scope_id: None,
                    name: &remote.name,
                    role,
                    url: remote.url.as_bytes(),
                    canonical_url: canonical_bytes,
                },
                now_ms,
            )
            .await?;
        runner.counters.db_transactions += 1;
    }

    let head = observed_head(runner, instance)?;
    let (head_state, head_ref, head_oid, head_algo) = head_columns(&head);
    let relationship = match runner.inspector.checkout_kind(instance) {
        Ok(git::CheckoutKind::Main) => "main",
        Ok(git::CheckoutKind::Linked) => "linked",
        Ok(git::CheckoutKind::Submodule) => "submodule",
        Ok(git::CheckoutKind::Unknown) | Err(_) => "unknown",
    };
    let checkout_hex = config::encode_hex(&git_bytes);
    let main_checkout_id = format!("co:{checkout_hex}");
    let root_bytes = instance.work_dir.as_ref().map(|p| config::path_as_bytes(p));
    let availability = match &instance.work_dir {
        Some(root) if root.exists() => "present",
        Some(_) => "missing",
        None => "present",
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
    if root_bytes.is_none() {
        store
            .insert_checkout_if_absent(&main_checkout, now_ms)
            .await?;
    } else {
        store.upsert_checkout(&main_checkout, now_ms).await?;
    }
    runner.counters.db_transactions += 1;

    // Registered linked worktrees: own checkout rows plus explicit probes
    // for bases outside already discovered paths.
    let mut checkout_ids = vec![main_checkout_id];
    if let Ok(worktrees) = runner.inspector.worktrees(instance) {
        for wt in &worktrees {
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
                store
                    .upsert_checkout(
                        &NewCheckout {
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
                        },
                        now_ms,
                    )
                    .await?;
                runner.counters.db_transactions += 1;
                checkout_ids.push(wt_id);
            }
            enqueue_probe_task_for_path(store, runner, generation, &wt.base, now_ms).await?;
        }
    }

    let refs = observed_refs(runner, instance, &mut evidence)?;
    // Upstream tracking evidence from the repo config (R16), read once per
    // probe; absent/unreadable config yields no upstreams, never fake ones.
    let branch_upstreams = load_branch_upstreams(&instance.common_dir);
    let known: HashSet<&[u8]> = refs.iter().map(|r| r.name.as_slice()).collect();
    for reference in &refs {
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
            config::encode_hex(&git_bytes),
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
        store
            .upsert_ref(
                &NewRef {
                    id: &ref_id,
                    instance_id: &instance_id,
                    checkout_scope_id: None,
                    kind,
                    name: &reference.name,
                    oid,
                    algo,
                    symbolic_target: symbolic,
                    upstream: upstream_for_ref(&branch_upstreams, &reference.name).as_deref(),
                    state: ref_state_for(reference, &known),
                },
                now_ms,
            )
            .await?;
        runner.counters.db_transactions += 1;
    }
    for broken in runner.inspector.reference_errors(instance) {
        store
            .record_error(
                &format!("ref-err:{instance_id}:{}", fnv1a_hex(broken.as_bytes())),
                &config::scope_key_for_git(path),
                "invalid-ref",
                &broken,
                None,
                now_ms,
            )
            .await?;
        runner.counters.db_transactions += 1;
    }

    // Detailed working state only for matching candidates (spec §9).
    if matches!(
        disposition,
        identity::MatchDisposition::Confirmed
            | identity::MatchDisposition::Related
            | identity::MatchDisposition::Probable
    ) {
        for checkout_id in &checkout_ids {
            enqueue_status_task(
                store,
                generation,
                run_rev,
                checkout_id,
                now_ms,
                &mut runner.counters,
            )
            .await?;
        }
    }
    Ok(())
}

/// Upstream (`remote/branch`) per local branch from the repo config (R16):
/// `[branch "X"]` with `remote = R` and `merge = refs/heads/Y` means local
/// `X` tracks `R/Y`. Best-effort INI scan: only `[branch "<name>"]`
/// sections are read (first `remote`/`merge` each); anything unparseable
/// yields no upstreams rather than fake ones.
fn load_branch_upstreams(common_dir: &Path) -> HashMap<String, Vec<u8>> {
    fn flush(
        branch: &Option<String>,
        remote: &Option<String>,
        merge: &Option<String>,
        out: &mut HashMap<String, Vec<u8>>,
    ) {
        if let (Some(name), Some(remote_name), Some(merge_ref)) = (branch, remote, merge) {
            let leaf = merge_ref.strip_prefix("refs/heads/").unwrap_or(merge_ref);
            out.entry(name.clone())
                .or_insert_with(|| format!("{remote_name}/{leaf}").into_bytes());
        }
    }

    let mut out = HashMap::new();
    let bytes = match std::fs::read(common_dir.join("config")) {
        Ok(bytes) => bytes,
        Err(_) => return out,
    };
    let mut branch: Option<String> = None;
    let mut remote: Option<String> = None;
    let mut merge: Option<String> = None;
    for raw_line in String::from_utf8_lossy(&bytes).lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            flush(&branch, &remote, &merge, &mut out);
            branch = None;
            remote = None;
            merge = None;
            let inner = line
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or("");
            let mut parts = inner.splitn(2, char::is_whitespace);
            if parts
                .next()
                .is_some_and(|h| h.eq_ignore_ascii_case("branch"))
            {
                if let Some(name) = parts.next() {
                    let name = name.trim().trim_matches('"').to_string();
                    if !name.is_empty() {
                        branch = Some(name);
                    }
                }
            }
            continue;
        }
        if branch.is_none() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim().to_ascii_lowercase().as_str() {
            "remote" if remote.is_none() => {
                remote = Some(value);
            }
            "merge" if merge.is_none() => {
                merge = Some(value);
            }
            _ => {}
        }
    }
    flush(&branch, &remote, &merge, &mut out);
    out
}

/// Upstream bytes for one ref, if it is a local branch with config tracking.
fn upstream_for_ref(upstreams: &HashMap<String, Vec<u8>>, name: &[u8]) -> Option<Vec<u8>> {
    let name = std::str::from_utf8(name).ok()?;
    let short = name.strip_prefix("refs/heads/")?;
    upstreams.get(short).cloned()
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
    let id = format!("probe:{generation}:{hex}");
    let scope_key = config::scope_key_for_git(path);
    let expected_rev = store.scope_rev(&scope_key).await?;
    let idempotency = format!("idem:{id}");
    store
        .enqueue_task(
            &NewTask {
                id: &id,
                kind: KIND_PROBE,
                generation,
                dir_id: None,
                scope_key: &scope_key,
                expected_rev,
                idempotency_key: &idempotency,
            },
            now_ms,
        )
        .await?;
    runner.counters.db_transactions += 1;
    Ok(())
}

/// HEAD observation with installed-git fallback on structural gaps only.
fn observed_head(
    runner: &mut Runner,
    instance: &git::GitInstance,
) -> repo_scan::Result<git::HeadState> {
    match runner.inspector.head(instance) {
        Ok(head) => Ok(head),
        Err(e) if git::is_unsupported_error(&e) => {
            if let Some(fallback) = runner.fallback() {
                match fallback.head(&instance.git_dir, instance.work_dir.as_deref()) {
                    Ok(head) => return Ok(head),
                    Err(fe) => {
                        eprintln!("repo-scan: fallback HEAD failed: {fe}");
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
    runner: &mut Runner,
    instance: &git::GitInstance,
    evidence: &mut Vec<String>,
) -> repo_scan::Result<Vec<git::RefObservation>> {
    match runner.inspector.refs(instance) {
        Ok(refs) => Ok(refs),
        Err(e) if git::is_unsupported_error(&e) => {
            if let Some(fallback) = runner.fallback() {
                match fallback.refs(&instance.git_dir, instance.work_dir.as_deref()) {
                    Ok(refs) => {
                        evidence.push(String::from("refs via installed-git fallback"));
                        return Ok(refs);
                    }
                    Err(fe) => {
                        eprintln!("repo-scan: fallback refs failed: {fe}");
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

/// Inspect one matching checkout's working state at the requested mode.
/// `metadata` records a null-count observation without probing; `summary`
/// collapses untracked directories; `full` counts untracked files. Unknown
/// stays null — never zero, never clean.
async fn exec_status(
    runner: &mut Runner,
    store: &TursoStore,
    mode: StatusMode,
    claimed: &ClaimedTask,
) -> repo_scan::Result<TaskOutcome> {
    let Some(config::ScopeRef::Status(checkout_id)) =
        config::parse_scope_key(&claimed.task.scope_key)
    else {
        return Ok(TaskOutcome::Parked {
            state: TaskState::Unsupported,
            reason: format!("malformed status scope key: {}", claimed.task.scope_key),
        });
    };
    let now = store::now_ms();
    let Some(checkout) = store.get_checkout(&checkout_id).await? else {
        store
            .record_error(
                &format!("status:{checkout_id}"),
                &claimed.task.scope_key,
                "unknown-checkout",
                &format!("status task names unknown checkout {checkout_id}; dropping"),
                None,
                now,
            )
            .await?;
        runner.counters.db_transactions += 1;
        return Ok(TaskOutcome::Complete);
    };
    // Observation revision: the run revision would need threading through;
    // the current committed revision is the stable per-run key instead.
    let observed_rev = store.current_revision().await?;
    if mode == StatusMode::Metadata {
        record_status_row(
            runner,
            store,
            &checkout_id,
            mode,
            "not_requested",
            None,
            None,
            None,
            "not_requested",
            "not_requested",
            &[],
            now,
            now,
            observed_rev,
        )
        .await?;
        return Ok(TaskOutcome::Complete);
    }
    let git_path = config::path_from_bytes(checkout.git_path.clone());
    let instance = match runner.inspector.open_exact(&git_path) {
        Ok(instance) => instance,
        Err(e) if git::is_unsupported_error(&e) => {
            record_status_row(
                runner,
                store,
                &checkout_id,
                mode,
                "unsupported",
                None,
                None,
                None,
                status_units(mode),
                "unknown",
                &[e.to_string()],
                now,
                now,
                observed_rev,
            )
            .await?;
            return Ok(TaskOutcome::Complete);
        }
        Err(e) => {
            return fail_task(
                runner,
                store,
                claimed,
                ExecFail {
                    category: String::from("status-open-error"),
                    detail: e.to_string(),
                },
            )
            .await;
        }
    };
    let started = store::now_ms();
    let observation = match runner.inspector.status_interruptible(&instance, mode, None) {
        Ok(obs) => Some(obs),
        Err(e) if git::is_unsupported_error(&e) => {
            fallback_status_counts(runner, &instance, mode, &e)
        }
        Err(e) => {
            return fail_task(
                runner,
                store,
                claimed,
                ExecFail {
                    category: String::from("status-error"),
                    detail: e.to_string(),
                },
            )
            .await;
        }
    };
    let finished = store::now_ms();
    // Submodule coverage (R16): examined through the inspector alongside
    // the status probe — `checked` when the submodule relationships were
    // actually read, `unknown` when they could not be.
    let submodules = match runner.inspector.submodules(&instance) {
        Ok(_) => "checked",
        Err(_) => "unknown",
    };
    match observation {
        None => {
            record_status_row(
                runner,
                store,
                &checkout_id,
                mode,
                "unsupported",
                None,
                None,
                None,
                status_units(mode),
                submodules,
                &["status unsupported in both backends".to_string()],
                started,
                finished,
                observed_rev,
            )
            .await?;
        }
        Some(obs) => {
            let state = status_state_of(&obs);
            record_status_row(
                runner,
                store,
                &checkout_id,
                mode,
                state,
                obs.staged.map(|c| c.min(i64::MAX as u64) as i64),
                obs.unstaged.map(|c| c.min(i64::MAX as u64) as i64),
                obs.untracked.map(|c| c.min(i64::MAX as u64) as i64),
                status_units(mode),
                submodules,
                &obs.unknown_fields,
                started,
                finished,
                observed_rev,
            )
            .await?;
        }
    }
    Ok(TaskOutcome::Complete)
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
    runner: &mut Runner,
    instance: &git::GitInstance,
    mode: StatusMode,
    cause: &repo_scan::Error,
) -> Option<git::StatusObservation> {
    let fallback = runner.fallback()?;
    let (staged, unstaged, untracked) = fallback
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
        unknown_fields: vec![format!("counts via installed-git fallback ({cause})")],
        fingerprints: Vec::new(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn record_status_row(
    runner: &mut Runner,
    store: &TursoStore,
    checkout_id: &str,
    mode: StatusMode,
    state: &str,
    staged: Option<i64>,
    unstaged: Option<i64>,
    untracked: Option<i64>,
    units: &str,
    submodules: &str,
    unknown_fields: &[String],
    started_ms: i64,
    finished_ms: i64,
    observed_rev: u64,
) -> repo_scan::Result<()> {
    let unknown_json = serde_json::to_string(unknown_fields)
        .map_err(|e| repo_scan::Error::Report(e.to_string()))?;
    store
        .record_status(
            &NewStatus {
                checkout_id,
                mode: status_mode_str(mode),
                state,
                started_ms: Some(started_ms),
                finished_ms: Some(finished_ms),
                staged,
                unstaged,
                untracked,
                untracked_units: units,
                submodules,
                unknown_fields: &unknown_json,
                input_fingerprint: None,
                observed_rev,
            },
            finished_ms,
        )
        .await?;
    runner.counters.db_transactions += 1;
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
         AND state NOT IN ('complete', 'unsupported', 'cancelled', 'superseded')",
        vec![turso::Value::Integer(generation as i64)],
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
        Some(row) => Ok(cell_int(&row, 0)? as u64),
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
        vec![turso::Value::Integer(generation as i64)],
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
    canonical: String,
    scope_policy: String,
    scan_state: String,
    status_mode: StatusMode,
    started_ms: i64,
    finished_ms: i64,
    report_dest: Option<PathBuf>,
    roots: Vec<PlannedRoot>,
    counters: RunCounters,
    pending: u64,
    status_pending: u64,
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

/// All open gaps, oldest first. The lib path streams every gap into the
/// report (no cap), so `coverage.gaps` agrees with the emitted records.
async fn load_open_errors(store: &TursoStore) -> repo_scan::Result<Vec<OpenError>> {
    let mut rows = store
        .connection()
        .query(
            "SELECT id, scope_key, category, detail, next_retry_ms FROM errors \
             WHERE open = 1 ORDER BY id ASC",
            (),
        )
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
    }
    Ok(out)
}

/// One report-subject instance (matches the lib builder's own subject
/// filter: everything but `nonmatch`).
struct EmittedInstance {
    id: String,
    git_path: Vec<u8>,
    common_path: Vec<u8>,
    disposition: String,
}

async fn load_emitted_instances(store: &TursoStore) -> repo_scan::Result<Vec<EmittedInstance>> {
    let mut rows = store
        .connection()
        .query(
            "SELECT id, git_path, common_path, disposition FROM git_instances \
             WHERE disposition != 'nonmatch' ORDER BY id ASC",
            (),
        )
        .await
        .map_err(store_err)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        out.push(EmittedInstance {
            id: cell_text(&row, 0)?,
            git_path: cell_blob(&row, 1)?,
            common_path: cell_blob(&row, 2)?,
            disposition: cell_text(&row, 3)?,
        });
    }
    Ok(out)
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
    let errors = load_open_errors(store).await?;
    let instances = load_emitted_instances(store).await?;
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
    // Required-status accounting is task-based (R3): the scheduler boundary
    // counts enqueued-but-unfinished status work; checkouts that never
    // needed a probe (other targets' leftovers excluded by the subject
    // filter, unresolvable identities with no required probe) do not keep
    // the run incomplete. The lib default would derive this from emitted
    // checkout rows instead, so the override preserves the run boundary.
    let coverage_status = if inputs.status_mode == StatusMode::Metadata {
        "not_requested"
    } else if inputs.status_pending > 0 {
        "incomplete"
    } else {
        "complete"
    };
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
        target_url: inputs.target_raw.clone(),
        canonical_url: Some(inputs.canonical.clone()),
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
        peak_rss_bytes: None,
        cpu_seconds: None,
        enumerated_entries: inputs.counters.entries,
        db_transactions: inputs.counters.db_transactions,
        db_sync_calls: None,
        source_commit: None,
        include_nonmatching: false,
        coverage_filesystem: None,
        coverage_identity: None,
        coverage_status: Some(coverage_status.to_string()),
        roots: root_inputs(inputs, &errors, &volumes),
        storage_links: storage_link_inputs(&instances),
        aliases: alias_inputs(&inputs.aliases),
        candidates: candidate_inputs(&errors, &instances),
        generated_artifacts: artifacts,
    })
}

fn root_inputs(
    inputs: &ScanReportInputs,
    errors: &[OpenError],
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
            let root_scope = config::scope_key_for_dir(&root.path);
            let error_ids: Vec<String> = errors
                .iter()
                .filter(|e| e.scope_key == root_scope)
                .map(|e| e.id.clone())
                .collect();
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

/// Caller-owned candidates: unresolvable-identity subjects plus
/// failed/unsupported probes. Pure coverage gaps (permission, symlink,
/// status) are errors, not candidates.
fn candidate_inputs(errors: &[OpenError], instances: &[EmittedInstance]) -> Vec<CandidateInput> {
    let mut out = Vec::new();
    for instance in instances {
        if instance.disposition != "unresolvable_identity" {
            continue;
        }
        out.push(CandidateInput {
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
    for error in errors {
        let disposition = match error.category.as_str() {
            "probe-failed" => "probe_failed",
            "unsupported-git-format" => "unsupported",
            _ => continue,
        };
        let Some(path) = scope_path(&error.scope_key) else {
            continue;
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
    out
}

fn scope_path(scope_key: &str) -> Option<PathBuf> {
    match config::parse_scope_key(scope_key) {
        Some(config::ScopeRef::Dir(p) | config::ScopeRef::Git(p)) => Some(p),
        _ => None,
    }
}

/// Caller-owned storage edges: common-directory relationships, borrowed
/// object stores (alternates), shared common storage, and observed
/// hard-link sharing (R16).
fn storage_link_inputs(instances: &[EmittedInstance]) -> Vec<StorageLinkInput> {
    let mut out = Vec::new();
    for instance in instances {
        if instance.common_path != instance.git_path {
            out.push(StorageLinkInput {
                id: format!("link:{}:common", instance.id),
                from_repository_id: instance.id.clone(),
                to_path_bytes: instance.common_path.clone(),
                kind: String::from("common_directory"),
                evidence: vec![String::from("common directory differs from git directory")],
            });
        }
    }
    for instance in instances {
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
    }
    let mut by_common: HashMap<&Vec<u8>, Vec<&EmittedInstance>> = HashMap::new();
    for instance in instances {
        by_common
            .entry(&instance.common_path)
            .or_default()
            .push(instance);
    }
    for (_, mut group) in by_common {
        if group.len() < 2 {
            continue;
        }
        group.sort_by(|a, b| a.id.cmp(&b.id));
        let first = group[0].id.clone();
        for instance in group.into_iter().skip(1) {
            out.push(StorageLinkInput {
                id: format!("link:{}:shared", instance.id),
                from_repository_id: instance.id.clone(),
                to_path_bytes: instance.common_path.clone(),
                kind: String::from("shared_object_store"),
                evidence: vec![format!("shares common storage with {first}")],
            });
        }
    }
    for instance in instances {
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
    out
}

/// Borrowed object-store targets from `objects/info/alternates` (R16),
/// bounded to 64 entries per instance.
fn alternates_targets(git_path: &[u8]) -> Vec<Vec<u8>> {
    let path = config::path_from_bytes(git_path.to_vec()).join("objects/info/alternates");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return Vec::new(),
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

/// File emission through the tested lib pieces (R3), stage-first: the
/// staged report streams from the pinned catalog revision, is verified and
/// immutably retained as the snapshot, and only then does the destination
/// check + copy run. A refused destination therefore still leaves the
/// retained snapshot behind for retry — the same guarantee the old binary
/// path gave, now with lib validation, checksums, and no-clobber rules.
/// Returns the snapshot path.
async fn emit_file_report(
    store: &TursoStore,
    inputs: &LibReportInputs,
    dest: &Path,
    state_dir: &Path,
    now_ms: i64,
) -> repo_scan::Result<PathBuf> {
    use repo_scan::report::builder::stream_report_from_store;
    use repo_scan::report::publish;
    use std::io::Write;

    let staging = staging_dir(state_dir);
    let snapshots = snapshots_dir(state_dir);
    std::fs::create_dir_all(&staging)?;
    std::fs::create_dir_all(&snapshots)?;
    let staged_name = format!(
        ".staging-{}-{}-{}.json",
        std::process::id(),
        store::now_ms(),
        inputs.report_id,
    );
    let staged = staging.join(staged_name);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)?;
    let (mut file, _) = stream_report_from_store(store, inputs, file).await?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    if let Ok(dir) = std::fs::File::open(&staging) {
        let _ = dir.sync_all();
    }
    let receipt = publish::retain_snapshot(
        store,
        &staged,
        &snapshots,
        &inputs.report_id,
        inputs.catalog_revision,
        inputs.generation,
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
        store
            .set_snapshot_publication(&inputs.report_id, "failed")
            .await?;
        return Err(e);
    }
    match publish::publish_staged(&snapshot, dest, state_dir) {
        Ok(_) => {
            store
                .set_snapshot_publication(&inputs.report_id, "published")
                .await?;
            Ok(snapshot)
        }
        Err(e) => {
            store
                .set_snapshot_publication(&inputs.report_id, "failed")
                .await?;
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
    let (_guard, store) = open_owned_with_wait(&cfg.state_dir).await?;
    let mut rows = store
        .connection()
        .query(
            "SELECT id, scope_policy, state, created_at_ms FROM generations ORDER BY id DESC",
            (),
        )
        .await
        .map_err(store_err)?;
    let mut generations = Vec::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        generations.push((
            cell_int(&row, 0)? as u64,
            cell_text(&row, 1)?,
            cell_text(&row, 2)?,
            cell_int(&row, 3)?,
        ));
    }
    if generations.is_empty() {
        println!("cached: true");
        println!("suitable_catalog: false");
        println!("note: catalog holds no traversal generation; no live verification performed");
        let _ = store.close().await;
        return Ok(ExitCode::Incomplete);
    }
    let Some(canonical) = normalize_query_cached(&args.url) else {
        println!("cached: true");
        println!("target: {}", identity::redact_credentials(&args.url));
        println!("canonical: unresolved (unsupported shape or unresolvable host alias)");
        println!("note: aliases resolve only from cached observations; no live probe performed");
        let _ = store.close().await;
        return Ok(ExitCode::Incomplete);
    };
    let mut rows = store
        .connection()
        .query(
            "SELECT g.id, g.git_path, g.disposition, g.observed_at_ms FROM git_instances g \
             JOIN remotes r ON r.instance_id = g.id WHERE r.canonical_url = ?1 \
             GROUP BY g.id ORDER BY g.id ASC",
            vec![turso::Value::Blob(canonical.as_bytes().to_vec())],
        )
        .await
        .map_err(store_err)?;
    let mut matches = Vec::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        matches.push((
            cell_text(&row, 0)?,
            cell_blob(&row, 1)?,
            cell_text(&row, 2)?,
            cell_int(&row, 3)?,
        ));
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
    println!("target: {}", identity::redact_credentials(&args.url));
    println!("canonical: {canonical}");
    for (id, policy, state, created) in &generations {
        println!(
            "generation: {id} scope={policy} state={state} created={}",
            ms_to_rfc3339(*created)
        );
    }
    println!("matches: {}", matches.len());
    for (_, git_path, disposition, observed) in &matches {
        println!(
            "  {disposition}: {} (observed {})",
            escape_display(git_path),
            ms_to_rfc3339(*observed),
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
                identity::redact_credentials(&String::from_utf8_lossy(&row.url_raw))
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
            eprintln!("repo-scan: publication retry failed: {e}");
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
                    eprintln!("repo-scan: publication retry failed: {e}");
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
    let url = String::from_utf8_lossy(&row.url_raw).into_owned();
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
    let args = repo_scan::cli::ScanArgs {
        url,
        scope,
        report,
        force_rescan: false,
        status,
        root,
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
    // become durable invalidations alongside the requested one.
    let ingested = {
        let roots = [PlannedRoot {
            path: root.clone(),
            priority: RootPriority::Early,
            namespace: String::from("explicit"),
            volume: None,
        }];
        let mut events = open_event_session(&store, &cfg.state_dir, "roots", &roots).await?;
        let mut counters = RunCounters::default();
        let applied =
            ingest_available_events(&mut events, &store, generation, &roots, &mut counters).await?;
        let _ = reconcile_event_cursors(&mut events, &store).await;
        applied
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
    match run_clear_inner(&cfg.state_dir) {
        Ok(()) => ExitCode::Success,
        Err(e) => fail(&e),
    }
}

/// Remove only verified tool-owned persisted payload (spec §15): exact
/// known engine files + sidecars and internal snapshot/staging files, each
/// verified as a regular file (never a symlink) before removal. Unknown
/// files are preserved; symlink substitution anywhere on the reset path
/// refuses the whole reset. Never a recursive delete of the configured
/// directory; the coordination lock is always retained.
fn run_clear_inner(state_dir: &Path) -> repo_scan::Result<()> {
    let payload = store::owner::payload_dir(state_dir);
    // Coordinate first: clearing requires exclusive ownership. The
    // existence check lives inside the lock (R15) so the decision sees
    // the state the guard actually serializes.
    let _guard = acquire_guard(state_dir)?;
    if !payload.exists() {
        println!("cache clear: no persisted state; already absent (success)");
        return Ok(());
    }
    if is_symlink_path(state_dir)? {
        return Err(unsafe_reset("state dir is a symlink"));
    }
    if is_symlink_path(&payload)? {
        return Err(unsafe_reset("payload dir is a symlink"));
    }
    let snapshots = payload.join(config::SNAPSHOTS_DIR_NAME);
    let staging = payload.join(config::STAGING_DIR_NAME);
    if snapshots.exists() && is_symlink_path(&snapshots)? {
        return Err(unsafe_reset("snapshots dir is a symlink"));
    }
    if staging.exists() && is_symlink_path(&staging)? {
        return Err(unsafe_reset("staging dir is a symlink"));
    }
    let mut removed = 0u64;
    let mut preserved: Vec<String> = Vec::new();

    // Database identity (R15): a fresh empty file is ours; a
    // populated engine file must carry tool ownership evidence — the
    // ownership marker bound by an owned open, or tool-shaped catalog
    // bytes. A foreign SQLite database without either stays.
    let db_path = payload.join("catalog.db");
    let db_ours = verify_db_identity(state_dir, &db_path, &mut preserved)?;
    if db_ours {
        for name in config::KNOWN_ENGINE_FILES
            .iter()
            .chain(config::KNOWN_SIDECAR_FILES.iter())
        {
            remove_known_file(&payload.join(name), &mut removed, &mut preserved)?;
        }
    } else if db_path.exists() {
        preserved.push(format!(
            "{} (unknown content; database left in place)",
            db_path.display()
        ));
    }
    clear_tool_dir(&snapshots, &mut removed, &mut preserved)?;
    clear_tool_dir(&staging, &mut removed, &mut preserved)?;
    // The ownership marker is tool-owned by definition; drop it with the
    // state (a substituted symlink refuses, like any reset-path symlink).
    remove_known_file(&owner_marker_path(state_dir), &mut removed, &mut preserved)?;
    // Unknown payload-root entries are listed, never touched.
    if let Ok(entries) = std::fs::read_dir(&payload) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if config::KNOWN_ENGINE_FILES.contains(&name.as_str())
                || config::KNOWN_SIDECAR_FILES.contains(&name.as_str())
                || name == config::SNAPSHOTS_DIR_NAME
                || name == config::STAGING_DIR_NAME
                || name == OWNER_MARKER_NAME
            {
                continue;
            }
            preserved.push(format!("{} (unknown; preserved)", entry.path().display()));
        }
    }
    // Remove only provably empty known dirs; never the state dir or lock.
    for dir in [&snapshots, &staging, &payload] {
        if dir.exists() {
            let _ = std::fs::remove_dir(dir);
        }
    }
    println!("cache clear: removed {removed} tool-owned file(s)");
    if preserved.is_empty() {
        println!("cache clear: no foreign files encountered");
    } else {
        println!(
            "cache clear: preserved {} foreign file(s):",
            preserved.len()
        );
        for item in preserved.iter().take(20) {
            println!("  preserved: {item}");
        }
        if preserved.len() > 20 {
            println!("  ... and {} more", preserved.len() - 20);
        }
    }
    Ok(())
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

/// Verify the engine path holds our database (or nothing). Symlinks refuse
/// the reset; non-file or foreign-content paths are preserved, not removed.
/// Populated files additionally require tool ownership evidence (R15).
fn verify_db_identity(
    state_dir: &Path,
    db_path: &Path,
    preserved: &mut Vec<String>,
) -> repo_scan::Result<bool> {
    let md = match std::fs::symlink_metadata(db_path) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => {
            return Err(repo_scan::Error::Io(format!(
                "cannot inspect {}: {e}",
                db_path.display()
            )));
        }
    };
    if md.file_type().is_symlink() {
        return Err(unsafe_reset("engine file is a symlink"));
    }
    if !md.file_type().is_file() {
        preserved.push(format!("{} (not a file; preserved)", db_path.display()));
        return Ok(false);
    }
    if md.len() == 0 {
        return Ok(true);
    }
    let mut magic = [0u8; 16];
    match std::fs::File::open(db_path).and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut magic)
    }) {
        Ok(()) => {}
        Err(_) => {
            preserved.push(format!("{} (unreadable; preserved)", db_path.display()));
            return Ok(false);
        }
    }
    if magic != *b"SQLite format 3\0" {
        preserved.push(format!(
            "{} (not a database file; preserved)",
            db_path.display()
        ));
        return Ok(false);
    }
    // SQLite magic alone never proves ownership (R15): require the marker
    // bound by an owned open, else tool-shaped catalog bytes.
    if marker_binds_payload(state_dir) {
        return Ok(true);
    }
    if catalog_bytes_look_tool_owned(db_path) {
        return Ok(true);
    }
    preserved.push(format!(
        "{} (SQLite database without tool ownership evidence; preserved)",
        db_path.display()
    ));
    Ok(false)
}

/// True when the payload's ownership marker is a small regular file with
/// our tag line plus a `db_id` binding. Verified, not trusted: wrong tag,
/// symlink, or oversize file all fail closed.
fn marker_binds_payload(state_dir: &Path) -> bool {
    let path = owner_marker_path(state_dir);
    let md = match std::fs::symlink_metadata(&path) {
        Ok(md) => md,
        Err(_) => return false,
    };
    if !md.file_type().is_file() || md.len() > 4096 {
        return false;
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut lines = text.lines();
    if lines.next() != Some(OWNER_MARKER_TAG) {
        return false;
    }
    lines.any(|line| line.starts_with("db_id=") && line.len() > 6)
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

/// True when the engine file's head carries enough catalog schema markers
/// to be tool-shaped. At least two must match so a stray string in a
/// foreign database cannot qualify it.
fn catalog_bytes_look_tool_owned(db_path: &Path) -> bool {
    use std::io::Read;
    let mut file = match std::fs::File::open(db_path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut head = vec![0u8; DB_IDENTITY_SCAN_BYTES as usize];
    let len = match file.read(&mut head) {
        Ok(len) => len,
        Err(_) => return false,
    };
    head.truncate(len);
    let mut hits = 0;
    for marker in DB_SCHEMA_MARKERS {
        let marker: &[u8] = marker;
        if head.windows(marker.len()).any(|w| w == marker) {
            hits += 1;
        }
    }
    hits >= 2
}

/// Remove one exact known file after verifying it is a regular file.
fn remove_known_file(
    path: &Path,
    removed: &mut u64,
    preserved: &mut Vec<String>,
) -> repo_scan::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(md) => {
            if md.file_type().is_symlink() {
                return Err(unsafe_reset(&format!(
                    "engine path is a symlink: {}",
                    path.display()
                )));
            }
            if !md.file_type().is_file() {
                preserved.push(format!("{} (not a file; preserved)", path.display()));
                return Ok(());
            }
            std::fs::remove_file(path)?;
            *removed += 1;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(repo_scan::Error::Io(format!(
            "cannot inspect {}: {e}",
            path.display()
        ))),
    }
}

/// Remove regular files directly inside a known tool-owned directory
/// (snapshots, staging): non-recursive, symlink-safe, unknown entries kept.
fn clear_tool_dir(
    dir: &Path,
    removed: &mut u64,
    preserved: &mut Vec<String>,
) -> repo_scan::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|e| repo_scan::Error::Io(format!("cannot inspect {}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry
            .map_err(|e| repo_scan::Error::Io(format!("cannot read {}: {e}", dir.display())))?;
        let file_type = entry.file_type().map_err(|e| {
            repo_scan::Error::Io(format!("cannot inspect {}: {e}", entry.path().display()))
        })?;
        if file_type.is_symlink() {
            preserved.push(format!("{} (symlink; preserved)", entry.path().display()));
        } else if file_type.is_file() {
            std::fs::remove_file(entry.path())?;
            *removed += 1;
        } else {
            preserved.push(format!(
                "{} (not a file; preserved)",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Integration-test hooks (compiled only under `cfg(test)`; the
// `tests/review_fix_main.rs` suite includes this file as a module). Each
// hook drives the same code the command paths use — never a parallel copy.
// ---------------------------------------------------------------------------

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
        history_invalid: false,
        degraded: Vec::new(),
        live: false,
    };
    // Open rule for the batch's volume so ingest pins a history identity.
    let stored = load_stored_cursors(store).await?;
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
    // Hook fence: the batch's own paths (raw + canonical) plus parents.
    let mut fence: Vec<PathBuf> = Vec::new();
    for path in &batch.invalidations {
        fence.push(path.clone());
        fence.push(path.canonicalize().unwrap_or_else(|_| path.clone()));
        if let Some(parent) = path.parent() {
            fence.push(parent.to_path_buf());
            fence.push(
                parent
                    .canonicalize()
                    .unwrap_or_else(|_| parent.to_path_buf()),
            );
        }
    }
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
