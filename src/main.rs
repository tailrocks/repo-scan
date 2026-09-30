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
use repo_scan::git::{self, GitInspect};
use repo_scan::identity;
use repo_scan::model::{ExitCode, Scope, StatusMode, TaskState};
use repo_scan::platform::MountTable;
use repo_scan::scheduler::{backoff_for_attempt, Admission, CircuitBreaker, OpClass};
use repo_scan::store::{
    self, ClaimedTask, NewCheckout, NewGitInstance, NewRef, NewRemote, NewScan, NewStatus, NewTask,
    NewVolume, OwnerGuard, Store, TaskOutcome, TursoStore,
};
use repo_scan::walk::roots::{plan_machine_roots, PlannedRoot};
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
/// Circuit-breaker threshold and cooldown per volume (spec §14).
const BREAKER_THRESHOLD: u32 = 3;
const BREAKER_COOLDOWN: Duration = Duration::from_secs(60);
/// Cap on error records streamed into one report; the true total stays in
/// `coverage.gaps` plus a scope-boundary note when capped.
const REPORT_ERROR_CAP: usize = 10_000;
/// Largest pre-existing destination file inspected for safe replacement.
const DEST_INSPECT_CAP: u64 = 64 * 1024 * 1024;

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
    Ok((guard, store))
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

/// Standard Base64 with padding (spec §16 non-UTF-8 path encoding).
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[triple as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Presentation text with terminal control characters escaped (lossy display
/// only; `value` always carries the exact bytes).
fn escape_display(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

/// Spec §16 `EncodedName` / path value pair for exact `bytes`.
fn encoded_name(bytes: &[u8]) -> serde_json::Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => serde_json::json!({
            "display": escape_display(bytes),
            "encoding": "utf8",
            "value": text,
        }),
        Err(_) => serde_json::json!({
            "display": escape_display(bytes),
            "encoding": "base64",
            "value": base64_encode(bytes),
        }),
    }
}

/// Spec §16 `ObjectId` from stored hex bytes, or null when the bytes are
/// not well-formed lowercase hex (never emit an invalid OID shape).
fn oid_value(algorithm: &str, hex_bytes: &[u8]) -> serde_json::Value {
    let Ok(hex) = std::str::from_utf8(hex_bytes) else {
        return serde_json::Value::Null;
    };
    let hex = hex.to_lowercase();
    if hex.is_empty() || hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return serde_json::Value::Null;
    }
    serde_json::json!({"algorithm": algorithm, "hex": hex})
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
    // One fresh catalog revision per run: status observations keyed by it
    // refresh matching metadata on every scan without duplicating rows.
    let run_rev = store.next_revision().await?;
    let now = store::now_ms();
    let generation = pick_generation(&store, &policy, args.force_rescan, now).await?;
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
            )
            .await?
        }
    };
    let started_ms = match &resumed {
        Some(r) => r.started_ms,
        None => now,
    };
    if resumed.is_none() {
        supersede_stale_scans(&store, &canonical, &policy, &scan_id, now).await?;
    }
    store
        .update_scan_state(
            &scan_id,
            &config::scan_state_name("running", state_roots.as_deref()),
            None,
            None,
            now,
        )
        .await?;
    upsert_volumes(&store, &policy, &roots, now).await?;
    seed_root_tasks(&store, generation, &roots, now).await?;
    enqueue_status_refresh(&store, generation, run_rev, now).await?;

    let mut runner = Runner::new(&cfg.resources);
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

    let finished_ms = store::now_ms();
    let gen_state = if outcome.interrupted {
        "interrupted"
    } else if outcome.has_gaps() {
        "incomplete"
    } else {
        "complete"
    };
    store.set_generation_state(generation, gen_state).await?;
    let discovery_code = if outcome.has_gaps() { 3 } else { 0 };
    let report_id = config::report_id_for_scan(&scan_id);
    let inputs = ReportInputs {
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
        open_gaps: outcome.open_gaps,
        unresolvable: outcome.unresolvable,
        status_pending: outcome.status_pending,
    };
    // Stage first, publish second: a failed publication retains the saved
    // snapshot and can be retried without repeating discovery.
    let staged = stage_report(&store, &cfg.state_dir, &inputs).await?;
    let checksum = fnv1a_hex(&std::fs::read(&staged)?);
    store
        .save_report_snapshot(
            &report_id,
            "1.0.0",
            store.current_revision().await?,
            generation,
            "staged",
            Some(checksum.as_bytes()),
            finished_ms,
        )
        .await?;
    let published = match &report_dest {
        Some(dest) => match publish_to_dest(&staged, dest, &cfg.state_dir) {
            Ok(()) => {
                store
                    .set_snapshot_publication(&report_id, "published")
                    .await?;
                true
            }
            Err(e) => {
                eprintln!("repo-scan: report publication failed: {e}");
                store.set_snapshot_publication(&report_id, "failed").await?;
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
                println!("snapshot: {}", staged.display());
                return Ok(ExitCode::OperationalFailure);
            }
        },
        None => {
            store
                .set_snapshot_publication(&report_id, "published")
                .await?;
            print_terminal_report(&store, &inputs, &staged).await?;
            true
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
    println!("snapshot: {}", staged.display());
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
                return Ok(*id);
            }
        }
        if let Some((id, _)) = generations.first() {
            store.set_generation_state(*id, "running").await?;
            return Ok(*id);
        }
    }
    let prior = generations.first().map(|(id, _)| *id);
    store
        .create_generation(policy, "running", prior, now_ms)
        .await
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
    }
    let _ = roots;
    Ok(())
}

/// Seed one enumeration task per planned root. Tasks are idempotent
/// (`INSERT OR IGNORE`), so reseeding a reused generation is a no-op for
/// already reconciled roots and only adds genuinely new scope.
async fn seed_root_tasks(
    store: &TursoStore,
    generation: u64,
    roots: &[PlannedRoot],
    now_ms: i64,
) -> repo_scan::Result<()> {
    for root in roots {
        let scope_key = config::scope_key_for_dir(&root.path);
        let id = enum_task_id_for_path(generation, &root.path);
        let expected_rev = store.scope_rev(&scope_key).await?;
        let idempotency = format!("idem:{id}");
        store
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
    }
    Ok(())
}

/// Stable enumeration task ID from physical identity when the path stats,
/// else from the path bytes (execution then records the gap durably).
fn enum_task_id_for_path(generation: u64, path: &Path) -> String {
    match std::fs::symlink_metadata(path) {
        Ok(md) => {
            let (dev, ino) = dir_identity(&md);
            format!("enum:{generation}:d{dev}:i{ino}")
        }
        Err(_) => format!(
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
        enqueue_status_task(store, generation, run_rev, &checkout_id, now_ms).await?;
    }
    Ok(())
}

async fn enqueue_status_task(
    store: &TursoStore,
    generation: u64,
    run_rev: u64,
    checkout_id: &str,
    now_ms: i64,
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
    Ok(())
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
    db_writes: u64,
    stale_requeued: u64,
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
        if claimed.is_empty() {
            break;
        }
        let mut progressed = false;
        for item in &claimed {
            if interrupted() {
                break;
            }
            let volume = breaker_key_for_task(&item.task.scope_key);
            if let Some(breaker) = runner.breakers.get(&volume) {
                if !breaker.allow(SystemTime::now()) {
                    continue;
                }
            }
            let class = match item.task.kind.as_str() {
                KIND_ENUM | KIND_RECONCILE => OpClass::Enumerate,
                KIND_PROBE | KIND_STATUS => OpClass::GitProbe,
                _ => OpClass::Other,
            };
            let Some(permit) = runner.admission.try_acquire(class) else {
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
            runner.counters.db_writes += 1;
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
            runner.counters.db_writes += 1;
            Ok(CompletionApplied::Applied)
        }
        Err(repo_scan::Error::Scheduler(message)) if message.starts_with("stale-completion:") => {
            runner.counters.db_writes += 1;
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
    runner.counters.db_writes += 1;

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
    runner.counters.db_writes += 1;
    if completed {
        runner.counters.dirs_complete += 1;
        Ok(TaskOutcome::Complete)
    } else {
        let detail = mid_error.unwrap_or_else(|| String::from("partial enumeration"));
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
    store
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
    runner.counters.db_writes += 1;
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
            store
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
            runner.counters.db_writes += 1;
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
            runner.counters.db_writes += 1;
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
            runner.counters.db_writes += 1;
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
    runner.counters.db_writes += 1;
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
            runner.counters.db_writes += 1;
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
    runner.counters.db_writes += 1;
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
        runner.counters.db_writes += 1;
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
    runner.counters.db_writes += 1;

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
                runner.counters.db_writes += 1;
                checkout_ids.push(wt_id);
            }
            enqueue_probe_task_for_path(store, runner, generation, &wt.base, now_ms).await?;
        }
    }

    let refs = observed_refs(runner, instance, &mut evidence)?;
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
                    upstream: None,
                    state: "valid",
                },
                now_ms,
            )
            .await?;
        runner.counters.db_writes += 1;
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
        runner.counters.db_writes += 1;
    }

    // Detailed working state only for matching candidates (spec §9).
    if matches!(
        disposition,
        identity::MatchDisposition::Confirmed
            | identity::MatchDisposition::Related
            | identity::MatchDisposition::Probable
    ) {
        for checkout_id in &checkout_ids {
            enqueue_status_task(store, generation, run_rev, checkout_id, now_ms).await?;
        }
    }
    Ok(())
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
    runner.counters.db_writes += 1;
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
        runner.counters.db_writes += 1;
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
                submodules: "not_requested",
                unknown_fields: &unknown_json,
                input_fingerprint: None,
                observed_rev,
            },
            finished_ms,
        )
        .await?;
    runner.counters.db_writes += 1;
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

fn cell_opt_text(row: &turso::Row, idx: usize) -> repo_scan::Result<Option<String>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Null => Ok(None),
        turso::Value::Text(value) => Ok(Some(value)),
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

fn cell_opt_blob(row: &turso::Row, idx: usize) -> repo_scan::Result<Option<Vec<u8>>> {
    match row.get_value(idx).map_err(store_err)? {
        turso::Value::Null => Ok(None),
        turso::Value::Blob(value) => Ok(Some(value)),
        other => Err(repo_scan::Error::Store(format!(
            "column {idx} expected BLOB or NULL, got {other:?}"
        ))),
    }
}

struct VolInfo {
    id: String,
    native_identity: Option<String>,
    namespace: String,
    filesystem: Option<String>,
    kind: String,
    state: String,
    observed_at_ms: Option<i64>,
}

struct InstInfo {
    id: String,
    git_path: Vec<u8>,
    common_path: Vec<u8>,
    bare: Option<bool>,
    object_format: String,
    disposition: String,
    evidence_json: String,
    observed_at_ms: i64,
}

struct CoInfo {
    id: String,
    instance_id: String,
    root_path: Option<Vec<u8>>,
    git_path: Vec<u8>,
    relationship: String,
    availability: String,
    head_state: String,
    head_ref: Option<Vec<u8>>,
    head_oid: Option<Vec<u8>>,
    head_algo: Option<String>,
    observed_at_ms: i64,
}

struct RemInfo {
    id: String,
    instance_id: String,
    checkout_scope_id: Option<String>,
    name: Vec<u8>,
    role: String,
    url: Vec<u8>,
    canonical_url: Option<Vec<u8>>,
    observed_at_ms: i64,
}

struct RefInfo {
    id: String,
    instance_id: String,
    checkout_scope_id: Option<String>,
    kind: String,
    name: Vec<u8>,
    oid: Option<Vec<u8>>,
    algo: Option<String>,
    symbolic_target: Option<Vec<u8>>,
    upstream: Option<Vec<u8>>,
    state: String,
    observed_at_ms: i64,
}

struct StatusInfo {
    mode: String,
    state: String,
    started_ms: Option<i64>,
    finished_ms: Option<i64>,
    staged: Option<i64>,
    unstaged: Option<i64>,
    untracked: Option<i64>,
    untracked_units: String,
    submodules: String,
    unknown_fields: String,
}

struct ErrInfo {
    id: String,
    scope_key: String,
    category: String,
    detail: String,
    attempts: u64,
    first_seen_ms: i64,
    last_seen_ms: i64,
    next_retry_ms: Option<i64>,
}

async fn load_volumes(store: &TursoStore) -> repo_scan::Result<Vec<VolInfo>> {
    let mut rows = store
        .connection()
        .query(
            "SELECT id, native_identity, namespace, filesystem, kind, state, \
             observed_at_ms FROM volumes ORDER BY id ASC",
            (),
        )
        .await
        .map_err(store_err)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        out.push(VolInfo {
            id: cell_text(&row, 0)?,
            native_identity: cell_opt_text(&row, 1)?,
            namespace: cell_text(&row, 2)?,
            filesystem: cell_opt_text(&row, 3)?,
            kind: cell_text(&row, 4)?,
            state: cell_text(&row, 5)?,
            observed_at_ms: cell_opt_int(&row, 6)?,
        });
    }
    Ok(out)
}

/// Matching (non-`nonmatch`) instances: the report's subject rows. Durable
/// `nonmatch` observations stay in the catalog for other URLs.
async fn load_instances(store: &TursoStore) -> repo_scan::Result<Vec<InstInfo>> {
    let mut rows = store
        .connection()
        .query(
            "SELECT id, git_path, common_path, incarnation, format, bare, object_format, \
             disposition, evidence, observed_at_ms FROM git_instances \
             WHERE disposition != 'nonmatch' ORDER BY id ASC",
            (),
        )
        .await
        .map_err(store_err)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        out.push(InstInfo {
            id: cell_text(&row, 0)?,
            git_path: cell_blob(&row, 1)?,
            common_path: cell_blob(&row, 2)?,
            bare: cell_opt_int(&row, 5)?.map(|b| b != 0),
            object_format: cell_text(&row, 6)?,
            disposition: cell_text(&row, 7)?,
            evidence_json: cell_text(&row, 8)?,
            observed_at_ms: cell_int(&row, 9)?,
        });
    }
    Ok(out)
}

/// Checkouts for the report's instances, filtered in SQL (chunked `IN`).
async fn load_checkouts_for(
    store: &TursoStore,
    instance_ids: &[String],
) -> repo_scan::Result<Vec<CoInfo>> {
    let mut out = Vec::new();
    for chunk in instance_ids.chunks(400) {
        let placeholders: Vec<String> = (1..=chunk.len()).map(|n| format!("?{n}")).collect();
        let sql = format!(
            "SELECT id, instance_id, root_path, git_path, relationship, availability, \
             head_state, head_ref, head_oid, head_algo, observed_at_ms FROM checkouts \
             WHERE instance_id IN ({}) ORDER BY id ASC",
            placeholders.join(","),
        );
        let params: Vec<turso::Value> = chunk
            .iter()
            .map(|id| turso::Value::Text(id.clone()))
            .collect();
        let mut rows = store
            .connection()
            .query(sql.as_str(), params)
            .await
            .map_err(store_err)?;
        while let Some(row) = rows.next().await.map_err(store_err)? {
            out.push(CoInfo {
                id: cell_text(&row, 0)?,
                instance_id: cell_text(&row, 1)?,
                root_path: cell_opt_blob(&row, 2)?,
                git_path: cell_blob(&row, 3)?,
                relationship: cell_text(&row, 4)?,
                availability: cell_text(&row, 5)?,
                head_state: cell_text(&row, 6)?,
                head_ref: cell_opt_blob(&row, 7)?,
                head_oid: cell_opt_blob(&row, 8)?,
                head_algo: cell_opt_text(&row, 9)?,
                observed_at_ms: cell_int(&row, 10)?,
            });
        }
    }
    Ok(out)
}

async fn load_remotes_for(
    store: &TursoStore,
    instance_id: &str,
) -> repo_scan::Result<Vec<RemInfo>> {
    let mut out = Vec::new();
    for row in store.list_remotes(instance_id).await? {
        out.push(RemInfo {
            id: row.id,
            instance_id: row.instance_id,
            checkout_scope_id: row.checkout_scope_id,
            name: row.name,
            role: row.role,
            url: row.url,
            canonical_url: row.canonical_url,
            observed_at_ms: row.observed_at_ms,
        });
    }
    Ok(out)
}

async fn load_refs_for(store: &TursoStore, instance_id: &str) -> repo_scan::Result<Vec<RefInfo>> {
    let mut out = Vec::new();
    for row in store.list_refs(instance_id).await? {
        out.push(RefInfo {
            id: row.id,
            instance_id: row.instance_id,
            checkout_scope_id: row.checkout_scope_id,
            kind: row.kind,
            name: row.name,
            oid: row.oid,
            algo: row.algo,
            symbolic_target: row.symbolic_target,
            upstream: row.upstream,
            state: row.state,
            observed_at_ms: row.observed_at_ms,
        });
    }
    Ok(out)
}

async fn load_latest_status(
    store: &TursoStore,
    checkout_id: &str,
) -> repo_scan::Result<Option<StatusInfo>> {
    Ok(store
        .list_statuses(checkout_id)
        .await?
        .into_iter()
        .next()
        .map(|row| StatusInfo {
            mode: row.mode,
            state: row.state,
            started_ms: row.started_ms,
            finished_ms: row.finished_ms,
            staged: row.staged,
            unstaged: row.unstaged,
            untracked: row.untracked,
            untracked_units: row.untracked_units,
            submodules: row.submodules,
            unknown_fields: row.unknown_fields,
        }))
}

/// Open gaps, oldest first, bounded for report streaming (the true total
/// stays in `coverage.gaps`).
async fn load_open_errors(store: &TursoStore) -> repo_scan::Result<Vec<ErrInfo>> {
    let sql = format!(
        "SELECT id, scope_key, category, detail, attempts, first_seen_ms, last_seen_ms, \
         next_retry_ms, open FROM errors WHERE open = 1 ORDER BY id ASC LIMIT {}",
        REPORT_ERROR_CAP + 1,
    );
    let mut rows = store
        .connection()
        .query(sql.as_str(), ())
        .await
        .map_err(store_err)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(store_err)? {
        out.push(ErrInfo {
            id: cell_text(&row, 0)?,
            scope_key: cell_text(&row, 1)?,
            category: cell_text(&row, 2)?,
            detail: cell_text(&row, 3)?,
            attempts: cell_int(&row, 4)? as u64,
            first_seen_ms: cell_int(&row, 5)?,
            last_seen_ms: cell_int(&row, 6)?,
            next_retry_ms: cell_opt_int(&row, 7)?,
        });
    }
    Ok(out)
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
// Report staging, validation, publication
// ---------------------------------------------------------------------------

struct ReportInputs {
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
    open_gaps: u64,
    unresolvable: u64,
    status_pending: u64,
}

/// Deduplicating path table: exact bytes in, stable `path-N` IDs out.
struct PathTable {
    ids: HashMap<Vec<u8>, String>,
    ordered: Vec<(String, Vec<u8>)>,
}

impl PathTable {
    fn new() -> Self {
        Self {
            ids: HashMap::new(),
            ordered: Vec::new(),
        }
    }

    fn intern(&mut self, bytes: &[u8]) -> String {
        if let Some(id) = self.ids.get(bytes) {
            return id.clone();
        }
        let id = format!("path-{}", self.ordered.len() + 1);
        self.ids.insert(bytes.to_vec(), id.clone());
        self.ordered.push((id.clone(), bytes.to_vec()));
        id
    }
}

/// Reference checker: every non-null relationship ID emitted must resolve.
struct RefCheck {
    volumes: HashSet<String>,
    paths: HashSet<String>,
    repos: HashSet<String>,
    checkouts: HashSet<String>,
    errors: HashSet<String>,
    need_volume: Vec<String>,
    need_path: Vec<String>,
    need_repo: Vec<String>,
    need_checkout: Vec<String>,
    need_error: Vec<String>,
}

impl RefCheck {
    fn new() -> Self {
        Self {
            volumes: HashSet::new(),
            paths: HashSet::new(),
            repos: HashSet::new(),
            checkouts: HashSet::new(),
            errors: HashSet::new(),
            need_volume: Vec::new(),
            need_path: Vec::new(),
            need_repo: Vec::new(),
            need_checkout: Vec::new(),
            need_error: Vec::new(),
        }
    }

    fn verify(&self) -> repo_scan::Result<()> {
        for id in &self.need_volume {
            if !self.volumes.contains(id) {
                return broken_ref("volume", id);
            }
        }
        for id in &self.need_path {
            if !self.paths.contains(id) {
                return broken_ref("path", id);
            }
        }
        for id in &self.need_repo {
            if !self.repos.contains(id) {
                return broken_ref("repository", id);
            }
        }
        for id in &self.need_checkout {
            if !self.checkouts.contains(id) {
                return broken_ref("checkout", id);
            }
        }
        for id in &self.need_error {
            if !self.errors.contains(id) {
                return broken_ref("error", id);
            }
        }
        Ok(())
    }
}

fn broken_ref(kind: &str, id: &str) -> repo_scan::Result<()> {
    Err(repo_scan::Error::Report(format!(
        "report references unknown {kind} ID: {id}"
    )))
}

/// Strict enum check: stored values are writer-controlled, so anything
/// outside the schema set is catalog corruption, reported loudly.
fn one_of<'a>(value: &'a str, allowed: &[&str]) -> repo_scan::Result<&'a str> {
    if allowed.contains(&value) {
        Ok(value)
    } else {
        Err(repo_scan::Error::Report(format!(
            "invalid report enum value: {value:?}"
        )))
    }
}

fn opt_time(ms: Option<i64>) -> serde_json::Value {
    match ms {
        Some(ms) => serde_json::Value::String(ms_to_rfc3339(ms)),
        None => serde_json::Value::Null,
    }
}

fn opt_count(value: Option<i64>) -> serde_json::Value {
    match value {
        Some(v) => serde_json::json!(v.max(0) as u64),
        None => serde_json::Value::Null,
    }
}

fn parse_string_array(json: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(json).unwrap_or_default()
}

/// Stream the consistent report into controlled local staging (spec §15):
/// tmp sibling + atomic rename inside the payload snapshots directory, with
/// bounded memory (row-by-row emission, matches-bounded tables only).
async fn stage_report(
    store: &TursoStore,
    state_dir: &Path,
    inputs: &ReportInputs,
) -> repo_scan::Result<PathBuf> {
    let report_id = config::report_id_for_scan(&inputs.scan_id);
    let dest = config::snapshot_path(state_dir, &report_id)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension("json.tmp");

    let catalog_rev = store.current_revision().await?;
    let volumes = load_volumes(store).await?;
    let instances = load_instances(store).await?;
    let instance_ids: Vec<String> = instances.iter().map(|i| i.id.clone()).collect();
    let checkouts = load_checkouts_for(store, &instance_ids).await?;
    let errors = load_open_errors(store).await?;
    let errors_capped = errors.len() > REPORT_ERROR_CAP;
    let errors: Vec<ErrInfo> = errors.into_iter().take(REPORT_ERROR_CAP).collect();
    let dirs_complete = count_dirs_complete(store, inputs.generation).await?;
    let mut remotes_by_instance: HashMap<String, Vec<RemInfo>> = HashMap::new();
    let mut refs_by_instance: HashMap<String, Vec<RefInfo>> = HashMap::new();
    for id in &instance_ids {
        remotes_by_instance.insert(id.clone(), load_remotes_for(store, id).await?);
        refs_by_instance.insert(id.clone(), load_refs_for(store, id).await?);
    }
    let mut status_by_checkout: HashMap<String, StatusInfo> = HashMap::new();
    for checkout in &checkouts {
        if let Some(status) = load_latest_status(store, &checkout.id).await? {
            status_by_checkout.insert(checkout.id.clone(), status);
        }
    }

    // Phase 1: intern every path byte string the report will reference.
    let mut paths = PathTable::new();
    for instance in &instances {
        paths.intern(&instance.git_path);
        paths.intern(&instance.common_path);
    }
    for checkout in &checkouts {
        if let Some(root) = &checkout.root_path {
            paths.intern(root);
        }
        paths.intern(&checkout.git_path);
    }
    for root in &inputs.roots {
        paths.intern(&config::path_as_bytes(&root.path));
    }
    let snapshot_bytes = config::path_as_bytes(&dest);
    paths.intern(&snapshot_bytes);
    if let Some(report) = &inputs.report_dest {
        paths.intern(&config::path_as_bytes(report));
    }
    for error in &errors {
        if let Some(path) = scope_error_path(&error.scope_key) {
            paths.intern(&config::path_as_bytes(&path));
        }
    }

    // Phase 2: emit.
    let file = std::fs::File::create(&tmp)?;
    let mut out = std::io::BufWriter::new(file);
    let mut refs = RefCheck::new();
    emit_report(
        &mut out,
        &mut refs,
        &mut paths,
        store,
        inputs,
        &report_id,
        catalog_rev,
        &volumes,
        &instances,
        &checkouts,
        &remotes_by_instance,
        &refs_by_instance,
        &status_by_checkout,
        &errors,
        errors_capped,
        dirs_complete,
        &snapshot_bytes,
    )?;
    use std::io::Write;
    out.flush()?;
    refs.verify()?;
    drop(out);
    std::fs::rename(&tmp, &dest)?;
    Ok(dest)
}

fn scope_error_path(scope_key: &str) -> Option<PathBuf> {
    match config::parse_scope_key(scope_key) {
        Some(config::ScopeRef::Dir(p) | config::ScopeRef::Git(p)) => Some(p),
        _ => None,
    }
}

fn scope_operation(scope_key: &str) -> &'static str {
    if scope_key.starts_with("dir:") {
        "enumerate"
    } else if scope_key.starts_with("git:") {
        "probe"
    } else if scope_key.starts_with("status:") {
        "status"
    } else {
        "unknown"
    }
}

fn write_value(
    out: &mut std::io::BufWriter<std::fs::File>,
    value: &serde_json::Value,
) -> repo_scan::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(|e| repo_scan::Error::Report(e.to_string()))
}

fn write_raw(out: &mut std::io::BufWriter<std::fs::File>, text: &str) -> repo_scan::Result<()> {
    use std::io::Write;
    out.write_all(text.as_bytes())
        .map_err(|e| repo_scan::Error::Io(e.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn emit_report(
    out: &mut std::io::BufWriter<std::fs::File>,
    refs: &mut RefCheck,
    paths: &mut PathTable,
    store: &TursoStore,
    inputs: &ReportInputs,
    report_id: &str,
    catalog_rev: u64,
    volumes: &[VolInfo],
    instances: &[InstInfo],
    checkouts: &[CoInfo],
    remotes_by_instance: &HashMap<String, Vec<RemInfo>>,
    refs_by_instance: &HashMap<String, Vec<RefInfo>>,
    status_by_checkout: &HashMap<String, StatusInfo>,
    errors: &[ErrInfo],
    errors_capped: bool,
    dirs_complete: u64,
    snapshot_bytes: &[u8],
) -> repo_scan::Result<()> {
    let _ = store;
    let filesystem = if inputs.pending > 0 || inputs.open_gaps > 0 {
        "incomplete"
    } else {
        "complete"
    };
    let identity = if inputs.unresolvable > 0 {
        "unproven"
    } else {
        "complete_under_policy"
    };
    let status_cov = if inputs.status_mode == StatusMode::Metadata {
        "not_requested"
    } else if inputs.status_pending > 0 {
        "incomplete"
    } else {
        "complete"
    };
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
    boundaries.push(String::from(
        "Observation boundaries are traversal generations; live event-history \
         reconciliation cursors are not yet wired.",
    ));
    if errors_capped {
        boundaries.push(format!(
            "Error records capped at {REPORT_ERROR_CAP} in this report; \
             coverage.gaps holds the true total.",
        ));
    }
    write_raw(out, "{\"schema_version\":\"1.0.0\",")?;
    write_raw(out, &format!("\"report_id\":{},", json_string(report_id)))?;
    write_raw(
        out,
        &format!(
            "\"created_at\":{},",
            json_string(&ms_to_rfc3339(inputs.finished_ms))
        ),
    )?;
    write_raw(out, "\"tool\":")?;
    write_value(
        out,
        &serde_json::json!({
            "name": "repo-scan",
            "version": repo_scan::version(),
            "source_commit": null,
        }),
    )?;
    write_raw(out, ",\"scan\":")?;
    write_value(out, &scan_value(inputs, catalog_rev)?)?;
    write_raw(out, ",\"coverage\":")?;
    write_value(
        out,
        &serde_json::json!({
            "filesystem": filesystem,
            "identity": identity,
            "status": status_cov,
            "directories_complete": dirs_complete,
            "tasks_pending": inputs.pending,
            "gaps": inputs.open_gaps,
            "unresolvable_candidates": inputs.unresolvable,
            "scope_boundaries": boundaries,
        }),
    )?;
    write_raw(out, ",\"resources\":")?;
    write_value(
        out,
        &serde_json::json!({
            "profile": "conservative",
            "cpu_target_cores": 1.0,
            "rss_target_bytes": 268435456u64,
            "peak_rss_bytes": null,
            "cpu_seconds": null,
            "enumerated_entries": inputs.counters.entries,
            "db_transactions": inputs.counters.db_writes,
            "db_sync_calls": null,
        }),
    )?;

    // Volumes.
    write_raw(out, ",\"volumes\":[")?;
    let mut first = true;
    for volume in volumes {
        if !first {
            write_raw(out, ",")?;
        }
        first = false;
        refs.volumes.insert(volume.id.clone());
        write_value(
            out,
            &serde_json::json!({
                "id": &volume.id,
                "native_identity": &volume.native_identity,
                "namespace": &volume.namespace,
                "filesystem": &volume.filesystem,
                "kind": one_of(&volume.kind, &["local", "network", "virtual", "unknown"])?,
                "state": one_of(&volume.state, &["available", "inaccessible", "unavailable", "unknown"])?,
                "observed_at": opt_time(volume.observed_at_ms),
                "error_ids": Vec::<String>::new(),
            }),
        )?;
    }
    write_raw(out, "]")?;

    // Paths.
    write_raw(out, ",\"paths\":[")?;
    first = true;
    for (id, bytes) in &paths.ordered {
        if !first {
            write_raw(out, ",")?;
        }
        first = false;
        refs.paths.insert(id.clone());
        let (encoding, value) = match std::str::from_utf8(bytes) {
            Ok(text) => ("utf8", text.to_string()),
            Err(_) => ("base64", base64_encode(bytes)),
        };
        write_value(
            out,
            &serde_json::json!({
                "id": id,
                "display": escape_display(bytes),
                "encoding": encoding,
                "value": value,
                "volume_id": null,
                "object_id": null,
                "incarnation": null,
            }),
        )?;
    }
    write_raw(out, "]")?;

    // Roots. State is per-root for errors; otherwise the run boundary
    // decides (complete only when nothing remains anywhere).
    write_raw(out, ",\"roots\":[")?;
    first = true;
    for (n, root) in inputs.roots.iter().enumerate() {
        if !first {
            write_raw(out, ",")?;
        }
        first = false;
        let id = format!("root-{}", n + 1);
        let path_id = paths.intern(&config::path_as_bytes(&root.path));
        refs.need_path.push(path_id.clone());
        let root_scope = config::scope_key_for_dir(&root.path);
        let root_errors: Vec<String> = errors
            .iter()
            .filter(|e| e.scope_key == root_scope)
            .map(|e| e.id.clone())
            .collect();
        for error_id in &root_errors {
            refs.need_error.push(error_id.clone());
        }
        let state = if root_errors.is_empty() {
            if inputs.pending > 0 {
                "pending"
            } else {
                "complete"
            }
        } else {
            "error"
        };
        let volume_id = match &root.volume {
            Some(volume) if refs.volumes.contains(&volume.0) => {
                refs.need_volume.push(volume.0.clone());
                serde_json::Value::String(volume.0.clone())
            }
            _ if inputs.scope_policy == "roots" && refs.volumes.contains("explicit-roots") => {
                refs.need_volume.push(String::from("explicit-roots"));
                serde_json::Value::String(String::from("explicit-roots"))
            }
            _ => serde_json::Value::Null,
        };
        write_value(
            out,
            &serde_json::json!({
                "id": id,
                "path_id": path_id,
                "volume_id": volume_id,
                "state": state,
                "observed_at": ms_to_rfc3339(inputs.finished_ms),
                "event_history_uuid": null,
                "ingested_cursor": null,
                "reconciled_cursor": null,
                "error_ids": root_errors,
            }),
        )?;
    }
    write_raw(out, "]")?;

    // Repositories.
    write_raw(out, ",\"repositories\":[")?;
    first = true;
    for instance in instances {
        if !first {
            write_raw(out, ",")?;
        }
        first = false;
        refs.repos.insert(instance.id.clone());
        let git_path_id = paths.intern(&instance.git_path);
        let common_path_id = paths.intern(&instance.common_path);
        refs.need_path.push(git_path_id.clone());
        refs.need_path.push(common_path_id.clone());
        let prefix = format!("ref-err:{}:", instance.id);
        let error_ids: Vec<String> = errors
            .iter()
            .filter(|e| e.id.starts_with(&prefix))
            .map(|e| e.id.clone())
            .collect();
        for error_id in &error_ids {
            refs.need_error.push(error_id.clone());
        }
        write_value(
            out,
            &serde_json::json!({
                "id": &instance.id,
                "git_path_id": git_path_id,
                "common_path_id": common_path_id,
                "bare": instance.bare,
                "format": "git-files",
                "object_format": &instance.object_format,
                "match": one_of(&instance.disposition,
                    &["confirmed", "related", "probable", "nonmatch", "unresolvable_identity"])?,
                "evidence": parse_string_array(&instance.evidence_json),
                "observed_at": ms_to_rfc3339(instance.observed_at_ms),
                "tool_managed": null,
                "error_ids": error_ids,
            }),
        )?;
    }
    write_raw(out, "]")?;

    // Checkouts.
    let dispositions: HashMap<&str, &str> = instances
        .iter()
        .map(|i| (i.id.as_str(), i.disposition.as_str()))
        .collect();
    write_raw(out, ",\"checkouts\":[")?;
    first = true;
    for checkout in checkouts {
        if !first {
            write_raw(out, ",")?;
        }
        first = false;
        refs.checkouts.insert(checkout.id.clone());
        refs.need_repo.push(checkout.instance_id.clone());
        let root_path_id = match &checkout.root_path {
            Some(root) => {
                let id = paths.intern(root);
                refs.need_path.push(id.clone());
                serde_json::Value::String(id)
            }
            None => serde_json::Value::Null,
        };
        let git_path_id = paths.intern(&checkout.git_path);
        refs.need_path.push(git_path_id.clone());
        let disposition = dispositions
            .get(checkout.instance_id.as_str())
            .copied()
            .unwrap_or("nonmatch");
        let status = checkout_status_value(
            status_by_checkout.get(&checkout.id),
            disposition,
            inputs.status_mode,
        )?;
        write_value(
            out,
            &serde_json::json!({
                "id": &checkout.id,
                "repository_id": &checkout.instance_id,
                "root_path_id": root_path_id,
                "git_path_id": git_path_id,
                "kind": one_of(&checkout.relationship, &["main", "linked", "submodule", "unknown"])?,
                "availability": one_of(&checkout.availability,
                    &["present", "missing", "inaccessible", "broken", "unknown"])?,
                "head": head_value(checkout)?,
                "status": status,
                "observed_at": ms_to_rfc3339(checkout.observed_at_ms),
                "error_ids": Vec::<String>::new(),
            }),
        )?;
    }
    write_raw(out, "]")?;

    // Branches (all local + remote-tracking + other refs of the subjects).
    write_raw(out, ",\"branches\":[")?;
    first = true;
    for instance in instances {
        if let Some(list) = refs_by_instance.get(&instance.id) {
            for reference in list {
                if !first {
                    write_raw(out, ",")?;
                }
                first = false;
                refs.need_repo.push(reference.instance_id.clone());
                if let Some(scope) = &reference.checkout_scope_id {
                    refs.need_checkout.push(scope.clone());
                }
                write_value(out, &branch_value(reference)?)?;
            }
        }
    }
    write_raw(out, "]")?;

    // Remotes.
    write_raw(out, ",\"remotes\":[")?;
    first = true;
    for instance in instances {
        if let Some(list) = remotes_by_instance.get(&instance.id) {
            for remote in list {
                if !first {
                    write_raw(out, ",")?;
                }
                first = false;
                refs.need_repo.push(remote.instance_id.clone());
                if let Some(scope) = &remote.checkout_scope_id {
                    refs.need_checkout.push(scope.clone());
                }
                write_value(
                    out,
                    &serde_json::json!({
                        "id": &remote.id,
                        "repository_id": &remote.instance_id,
                        "checkout_scope_id": &remote.checkout_scope_id,
                        "name": encoded_name(&remote.name),
                        "role": one_of(&remote.role, &["fetch", "push"])?,
                        "url": String::from_utf8_lossy(&remote.url),
                        "canonical_url": remote.canonical_url.as_ref()
                            .map(|c| String::from_utf8_lossy(c).into_owned()),
                        "observed_at": ms_to_rfc3339(remote.observed_at_ms),
                    }),
                )?;
            }
        }
    }
    write_raw(out, "]")?;

    // Storage links (common-directory relationships; alternates are not
    // inspected by this lane).
    write_raw(out, ",\"storage_links\":[")?;
    first = true;
    for instance in instances {
        if instance.common_path == instance.git_path {
            continue;
        }
        if !first {
            write_raw(out, ",")?;
        }
        first = false;
        refs.need_repo.push(instance.id.clone());
        let to_path_id = paths.intern(&instance.common_path);
        refs.need_path.push(to_path_id.clone());
        write_value(
            out,
            &serde_json::json!({
                "id": format!("link:{}:common", instance.id),
                "from_repository_id": &instance.id,
                "to_path_id": to_path_id,
                "kind": "common_directory",
                "evidence": ["common directory differs from git directory"],
            }),
        )?;
    }
    write_raw(out, "]")?;

    // Aliases: the v1 schema carries no durable alias table, so none are
    // emitted; firmlink/mount aliases are not silently collapsed elsewhere.
    write_raw(out, ",\"aliases\":[]")?;

    // Candidates: unresolvable-identity subjects plus failed/unsupported
    // probes. Pure coverage gaps (permission, symlink, status) are errors,
    // not candidates.
    write_raw(out, ",\"candidates\":[")?;
    first = true;
    for instance in instances {
        if instance.disposition != "unresolvable_identity" {
            continue;
        }
        if !first {
            write_raw(out, ",")?;
        }
        first = false;
        let path_id = paths.intern(&instance.git_path);
        refs.need_path.push(path_id.clone());
        refs.need_repo.push(instance.id.clone());
        write_value(
            out,
            &serde_json::json!({
                "id": format!("cand:{}", instance.id),
                "path_id": path_id,
                "repository_id": &instance.id,
                "disposition": "unresolvable_identity",
                "reason": "identifying remotes removed or uninterpretable under \
                           the matching policy; see repository evidence",
                "retry_after": null,
                "error_ids": Vec::<String>::new(),
            }),
        )?;
    }
    for error in errors {
        let candidate_disposition = match error.category.as_str() {
            "probe-failed" => Some("probe_failed"),
            "unsupported-git-format" => Some("unsupported"),
            _ => None,
        };
        let Some(candidate_disposition) = candidate_disposition else {
            continue;
        };
        let Some(path) = scope_error_path(&error.scope_key) else {
            continue;
        };
        if !first {
            write_raw(out, ",")?;
        }
        first = false;
        let path_id = paths.intern(&config::path_as_bytes(&path));
        refs.need_path.push(path_id.clone());
        refs.need_error.push(error.id.clone());
        write_value(
            out,
            &serde_json::json!({
                "id": format!("cand-err:{}", error.id),
                "path_id": path_id,
                "repository_id": null,
                "disposition": candidate_disposition,
                "reason": truncate_str(&error.detail, 512),
                "retry_after": opt_time(error.next_retry_ms),
                "error_ids": [&error.id],
            }),
        )?;
    }
    write_raw(out, "]")?;

    // Errors.
    write_raw(out, ",\"errors\":[")?;
    first = true;
    for error in errors {
        if !first {
            write_raw(out, ",")?;
        }
        first = false;
        refs.errors.insert(error.id.clone());
        let path_id = match scope_error_path(&error.scope_key) {
            Some(path) => {
                let id = paths.intern(&config::path_as_bytes(&path));
                refs.need_path.push(id.clone());
                serde_json::Value::String(id)
            }
            None => serde_json::Value::Null,
        };
        write_value(
            out,
            &serde_json::json!({
                "id": &error.id,
                "path_id": path_id,
                "operation": scope_operation(&error.scope_key),
                "category": &error.category,
                "message": truncate_str(&error.detail, 2048),
                "retryable": !error.category.starts_with("unsupported"),
                "attempts": error.attempts,
                "first_seen": ms_to_rfc3339(error.first_seen_ms),
                "last_seen": ms_to_rfc3339(error.last_seen_ms),
                "next_retry": opt_time(error.next_retry_ms),
            }),
        )?;
    }
    write_raw(out, "]")?;

    // Generated artifacts: the retained snapshot (tool state) plus the
    // published report when a destination was requested. Working state was
    // observed before staging, hence `created_after_status: true`.
    write_raw(out, ",\"generated_artifacts\":[")?;
    let snapshot_path_id = paths.intern(snapshot_bytes);
    refs.need_path.push(snapshot_path_id.clone());
    write_value(
        out,
        &serde_json::json!({
            "path_id": snapshot_path_id,
            "kind": "tool_state",
            "created_after_status": true,
        }),
    )?;
    if let Some(report) = &inputs.report_dest {
        let report_path_id = paths.intern(&config::path_as_bytes(report));
        refs.need_path.push(report_path_id.clone());
        write_raw(out, ",")?;
        write_value(
            out,
            &serde_json::json!({
                "path_id": report_path_id,
                "kind": "report",
                "created_after_status": true,
            }),
        )?;
    }
    write_raw(out, "]}")?;
    Ok(())
}

fn scan_value(inputs: &ReportInputs, catalog_rev: u64) -> repo_scan::Result<serde_json::Value> {
    Ok(serde_json::json!({
        "id": &inputs.scan_id,
        "generation": inputs.generation,
        "epoch": inputs.epoch,
        "catalog_revision": catalog_rev,
        "target_url": &inputs.target_raw,
        "canonical_url": &inputs.canonical,
        "matching_policy": identity::MATCHING_POLICY,
        "scope": one_of(&inputs.scope_policy, &["machine", "roots"])?,
        "state": one_of(&inputs.scan_state,
            &["running", "complete", "incomplete", "interrupted", "failed", "superseded"])?,
        "started_at": ms_to_rfc3339(inputs.started_ms),
        "finished_at": ms_to_rfc3339(inputs.finished_ms),
        "superseded_by": null,
        "cached": false,
        "status_mode": status_mode_str(inputs.status_mode),
    }))
}

fn head_value(checkout: &CoInfo) -> repo_scan::Result<serde_json::Value> {
    let state = one_of(
        &checkout.head_state,
        &["branch", "detached", "unborn", "invalid", "unknown"],
    )?;
    let ref_name = match &checkout.head_ref {
        Some(name) => encoded_name(name),
        None => serde_json::Value::Null,
    };
    let oid = match (&checkout.head_oid, &checkout.head_algo) {
        (Some(hex), Some(algo)) => oid_value(algo, hex),
        _ => serde_json::Value::Null,
    };
    Ok(serde_json::json!({
        "state": state,
        "ref_name": ref_name,
        "oid": oid,
    }))
}

fn branch_value(reference: &RefInfo) -> repo_scan::Result<serde_json::Value> {
    let oid = match (&reference.oid, &reference.algo) {
        (Some(hex), Some(algo)) => oid_value(algo, hex),
        _ => serde_json::Value::Null,
    };
    let symbolic = match &reference.symbolic_target {
        Some(target) => encoded_name(target),
        None => serde_json::Value::Null,
    };
    let upstream = match &reference.upstream {
        Some(upstream) => encoded_name(upstream),
        None => serde_json::Value::Null,
    };
    Ok(serde_json::json!({
        "id": &reference.id,
        "repository_id": &reference.instance_id,
        "checkout_scope_id": &reference.checkout_scope_id,
        "kind": one_of(&reference.kind, &["local", "remote_tracking", "other"])?,
        "name": encoded_name(&reference.name),
        "oid": oid,
        "symbolic_target": symbolic,
        "upstream": upstream,
        "state": one_of(&reference.state, &["valid", "unborn", "invalid", "unsupported"])?,
        "observed_at": ms_to_rfc3339(reference.observed_at_ms),
        "error_ids": Vec::<String>::new(),
    }))
}

/// Map the latest status observation (or its principled absence) to the
/// report `Status` record, enforcing the §16 cross-field rules.
fn checkout_status_value(
    status: Option<&StatusInfo>,
    disposition: &str,
    requested: StatusMode,
) -> repo_scan::Result<serde_json::Value> {
    let Some(status) = status else {
        let matching = matches!(disposition, "confirmed" | "related" | "probable");
        let state = if matching { "pending" } else { "not_requested" };
        return Ok(serde_json::json!({
            "state": state,
            "mode": status_mode_str(requested),
            "started_at": null,
            "finished_at": null,
            "staged": null,
            "unstaged": null,
            "untracked": null,
            "untracked_units": status_units(requested),
            "submodules": "not_requested",
            "unknown_fields": Vec::<String>::new(),
            "error_ids": Vec::<String>::new(),
        }));
    };
    let mode = one_of(&status.mode, &["metadata", "summary", "full"])?;
    if mode == "metadata"
        && (status.staged.is_some() || status.unstaged.is_some() || status.untracked.is_some())
    {
        return Err(repo_scan::Error::Report(
            "metadata status observation carries counts".to_string(),
        ));
    }
    Ok(serde_json::json!({
        "state": one_of(&status.state,
            &["complete", "partial", "pending", "not_requested", "unsupported", "unstable", "error"])?,
        "mode": mode,
        "started_at": opt_time(status.started_ms),
        "finished_at": opt_time(status.finished_ms),
        "staged": opt_count(status.staged),
        "unstaged": opt_count(status.unstaged),
        "untracked": opt_count(status.untracked),
        "untracked_units": one_of(&status.untracked_units,
            &["collapsed_entries", "files", "not_requested"])?,
        "submodules": one_of(&status.submodules, &["checked", "not_requested", "unknown"])?,
        "unknown_fields": parse_string_array(&status.unknown_fields),
        "error_ids": Vec::<String>::new(),
    }))
}

fn truncate_str(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars).collect();
    out.push('…');
    out
}

/// Publish staged report bytes to the external destination (spec §15):
/// refuse Git administrative paths, the active persistence payload, and
/// existing unrelated files (only a verified previous `repo-scan` report
/// for that output may be replaced); reject symlink surprises; write via a
/// temporary sibling plus atomic replacement.
fn publish_to_dest(staged: &Path, dest: &Path, state_dir: &Path) -> repo_scan::Result<()> {
    if dest == state_dir || dest.starts_with(state_dir) {
        return Err(repo_scan::Error::Report(format!(
            "refusing to publish inside tool state dir: {}",
            dest.display()
        )));
    }
    if dest
        .components()
        .any(|c| c.as_os_str() == std::ffi::OsStr::new(".git"))
    {
        return Err(repo_scan::Error::Report(format!(
            "refusing to publish inside a .git directory: {}",
            dest.display()
        )));
    }
    if let Some(parent) = dest.parent() {
        // A bare-store top level (objects/ + HEAD) is Git administration.
        if parent.join("objects").is_dir() && parent.join("HEAD").is_file() {
            return Err(repo_scan::Error::Report(format!(
                "refusing to publish inside a Git directory: {}",
                dest.display()
            )));
        }
    }
    match std::fs::symlink_metadata(dest) {
        Ok(md) => {
            if md.file_type().is_symlink() {
                return Err(repo_scan::Error::Report(format!(
                    "refusing to publish through a symlink: {}",
                    dest.display()
                )));
            }
            if md.file_type().is_dir() {
                return Err(repo_scan::Error::Report(format!(
                    "refusing to publish over a directory: {}",
                    dest.display()
                )));
            }
            if md.len() > DEST_INSPECT_CAP {
                return Err(repo_scan::Error::Report(format!(
                    "refusing to replace an unexpected large file: {}",
                    dest.display()
                )));
            }
            if !is_prior_repo_scan_report(dest)? {
                return Err(repo_scan::Error::Report(format!(
                    "refusing to overwrite an unrelated existing file (no-clobber): {}",
                    dest.display()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(repo_scan::Error::Report(format!(
                "cannot inspect destination {}: {e}",
                dest.display()
            )));
        }
    }
    let parent = dest.parent().ok_or_else(|| {
        repo_scan::Error::Report(format!("destination has no parent: {}", dest.display()))
    })?;
    std::fs::create_dir_all(parent)?;
    let file_name = dest.file_name().ok_or_else(|| {
        repo_scan::Error::Report(format!("destination has no file name: {}", dest.display()))
    })?;
    let tmp = parent.join(format!(
        ".{}.repo-scan-{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    if std::fs::copy(staged, &tmp).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(repo_scan::Error::Report(format!(
            "cannot stage destination file: {}",
            tmp.display()
        )));
    }
    if let Ok(sync_file) = std::fs::File::open(&tmp) {
        let _ = sync_file.sync_all();
    }
    if let Err(e) = std::fs::rename(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(repo_scan::Error::Report(format!(
            "cannot publish {}: {e}",
            dest.display()
        )));
    }
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// True when `dest` is a verified previous `repo-scan` report: parseable
/// JSON naming this tool and the v1 schema. A filename extension alone is
/// never proof.
fn is_prior_repo_scan_report(dest: &Path) -> repo_scan::Result<bool> {
    let bytes = match std::fs::read(dest) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false),
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    Ok(value
        .get("tool")
        .and_then(|tool| tool.get("name"))
        .and_then(|name| name.as_str())
        == Some("repo-scan")
        && value.get("schema_version").and_then(|v| v.as_str()) == Some("1.0.0"))
}

/// Readable terminal report for scans without `--report` (stdout; progress
/// stays on stderr). The versioned snapshot is already retained in state.
async fn print_terminal_report(
    store: &TursoStore,
    inputs: &ReportInputs,
    staged: &Path,
) -> repo_scan::Result<()> {
    let instances = load_instances(store).await?;
    let mut confirmed = 0u64;
    let mut related = 0u64;
    let mut probable = 0u64;
    let mut unresolvable = 0u64;
    for instance in instances.iter() {
        match instance.disposition.as_str() {
            "confirmed" => confirmed += 1,
            "related" => related += 1,
            "probable" => probable += 1,
            "unresolvable_identity" => unresolvable += 1,
            _ => {}
        }
    }
    println!("target: {}", inputs.target_raw);
    println!("canonical: {}", inputs.canonical);
    println!("scope: {}", inputs.scope_policy);
    println!("state: {}", inputs.scan_state);
    println!("generation: {}", inputs.generation);
    println!(
        "matches: {confirmed} confirmed, {related} related, {probable} probable, \
         {unresolvable} unresolvable"
    );
    for instance in instances.iter().filter(|i| i.disposition == "confirmed") {
        println!("  confirmed: {}", escape_display(&instance.git_path));
    }
    println!(
        "coverage: {} pending tasks, {} open gaps",
        inputs.pending, inputs.open_gaps
    );
    println!("snapshot: {}", staged.display());
    Ok(())
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
    let published = match &dest {
        Some(dest) => match publish_to_dest(snapshot, dest, &cfg.state_dir) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("repo-scan: publication retry failed: {e}");
                store
                    .set_snapshot_publication(&recorded.report_id, "failed")
                    .await?;
                return Ok(ExitCode::OperationalFailure);
            }
        },
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
    run_scan_inner(
        cfg,
        &args,
        Some(ResumedRequest {
            scan_id,
            started_ms,
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
    let _ = store.close().await;
    println!(
        "invalidated {} rev={rev} generation={generation}; reconciliation scheduled \
         (rescan not complete)",
        root.display()
    );
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
    if !payload.exists() {
        println!("cache clear: no persisted state; already absent (success)");
        return Ok(());
    }
    // Coordinate first: clearing requires exclusive ownership.
    let _guard = acquire_guard(state_dir)?;
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

    // Database identity: SQLite magic or a fresh empty file is ours;
    // anything else at the engine path is foreign and stays.
    let db_path = payload.join("catalog.db");
    let db_ours = verify_db_identity(&db_path, &mut preserved)?;
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
    // Unknown payload-root entries are listed, never touched.
    if let Ok(entries) = std::fs::read_dir(&payload) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if config::KNOWN_ENGINE_FILES.contains(&name.as_str())
                || config::KNOWN_SIDECAR_FILES.contains(&name.as_str())
                || name == config::SNAPSHOTS_DIR_NAME
                || name == config::STAGING_DIR_NAME
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
fn verify_db_identity(db_path: &Path, preserved: &mut Vec<String>) -> repo_scan::Result<bool> {
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
    if magic == *b"SQLite format 3\0" {
        Ok(true)
    } else {
        preserved.push(format!(
            "{} (not a database file; preserved)",
            db_path.display()
        ));
        Ok(false)
    }
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

/// JSON string literal for trusted ASCII (IDs, enums, timestamps).
fn json_string(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| String::from("null"))
}
