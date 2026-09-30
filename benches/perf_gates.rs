//! PERF-02/03 measurement gates (spec §§17–18).
//!
//! Declared corpus: huge-flat 2000 files + deep 40 levels + 200 git repos
//! (170 normal with an `origin` remote, 10 arbitrarily named bare stores,
//! 10 detached checkouts, 10 mains each with one linked worktree), all in a
//! tempdir. The sustained phase scans that corpus through the built binary
//! for at least 30 measured seconds after warmup; the pressure phase injects
//! memory pressure through the existing admission path.
//!
//! Run: `cargo bench --bench perf_gates`. Results append to
//! `benches/results/perf_gates.jsonl` (override with `$BENCH_RESULTS`).
//! Exit 0 only when every gate verdict holds: excessive resource use or
//! missing evidence fails the gate, it never passes silently.

#[path = "support.rs"]
mod support;

use repo_scan::config::ResourceLimits;
use repo_scan::model::{Epoch, GenerationId, TaskState};
use repo_scan::report::{model::Status, validate::validate_status};
use repo_scan::scheduler::{
    Admission, DurableScheduler, MemorySchedulerStore, OpClass, Scheduler, SchedulerStore, Task,
    TaskKind, TaskOutcome,
};
use repo_scan::telemetry::{FootprintSampler, SamplerInputs};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use support::Recorder;

/// Scan target; every corpus repo carries [`REMOTE_URL`] as `origin`.
const TARGET_URL: &str = "https://github.com/OWNER/REPO";
const REMOTE_URL: &str = "https://github.com/OWNER/REPO.git";
/// Declared corpus shape (PERF-02).
const FLAT_FILES: usize = 2000;
const DEEP_LEVELS: usize = 40;
const REPOS_NORMAL: usize = 170;
const REPOS_BARE: usize = 10;
const REPOS_DETACHED: usize = 10;
const REPOS_WT_MAINS: usize = 10;
/// Linked worktrees: exactly one per worktree main.
const LINKED_WORKTREES: usize = REPOS_WT_MAINS;
/// Sustained measured window (spec §18: at least 30 measured seconds).
const MEASURED_MIN_SECS: f64 = 30.0;
/// Safety cap on sustained iterations (the window check ends first).
const MAX_ITERS: usize = 60;
/// Child RSS sampling cadence during each scan.
const RSS_CADENCE: Duration = Duration::from_millis(100);
/// Per-scan wall timeout: a hung scan fails the gate, never the harness.
const SCAN_TIMEOUT: Duration = Duration::from_secs(600);

fn main() {
    let mut recorder = Recorder::open(&support::results_dir(), "perf_gates");
    let limits = ResourceLimits::default();
    let binary = resolve_binary();
    eprintln!("perf_gates: binary: {}", binary.display());

    // --- Declared corpus (tempdir only). ---
    let holder = tempfile::TempDir::new().expect("perf scratch");
    let corpus = holder.path().join("corpus");
    std::fs::create_dir_all(&corpus).expect("corpus root");
    let start = Instant::now();
    build_corpus(&corpus, &holder.path().join("archetypes"));
    let build_ms = support::wall_ms(&start);
    let total_builds = REPOS_NORMAL + REPOS_BARE + REPOS_DETACHED + REPOS_WT_MAINS;
    recorder.record(&serde_json::json!({
        "record": "corpus",
        "flat_files": FLAT_FILES,
        "deep_levels": DEEP_LEVELS,
        "repos_normal": REPOS_NORMAL,
        "repos_bare": REPOS_BARE,
        "repos_detached": REPOS_DETACHED,
        "repos_worktree_mains": REPOS_WT_MAINS,
        "linked_worktrees": LINKED_WORKTREES,
        "total_repo_builds": total_builds,
        "total_repo_dirs": total_builds + LINKED_WORKTREES,
        "build_wall_ms": build_ms,
        "method": "one git-built archetype per layout, then filesystem copies; detach and worktree registration run in place",
    }));

    // --- Warmup scan (unmeasured), then the sustained measured window. ---
    let state_dir = holder.path().join("state");
    let reports = holder.path().join("reports");
    std::fs::create_dir_all(&reports).expect("reports dir");
    let ctx = ScanCtx {
        binary: &binary,
        state_dir: &state_dir,
        corpus: &corpus,
        workdir: holder.path(),
    };
    let warmup = run_scan(&ctx, &reports.join("warmup.json"));
    recorder.record(&serde_json::json!({
        "record": "warmup",
        "wall_ms": warmup.wall_ms,
        "exit_code": warmup.exit_code,
        "report_ok": warmup.report_ok,
        "entries": warmup.entries,
        "db_transactions": warmup.db_transactions,
        "child_peak_rss_bytes": warmup.child_peak_rss,
        "stderr_tail": warmup.stderr_tail,
    }));

    let cpu_before = children_cpu_seconds();
    let window_start = Instant::now();
    let mut iters = Vec::new();
    for iter in 0..MAX_ITERS {
        if window_start.elapsed().as_secs_f64() >= MEASURED_MIN_SECS {
            break;
        }
        let sample = run_scan(&ctx, &reports.join(format!("iter-{iter:03}.json")));
        recorder.record(&serde_json::json!({
            "record": "sustain_iter",
            "iter": iter,
            "wall_ms": sample.wall_ms,
            "exit_code": sample.exit_code,
            "timed_out": sample.timed_out,
            "report_ok": sample.report_ok,
            "scan_state": sample.scan_state,
            "entries": sample.entries,
            "db_transactions": sample.db_transactions,
            "db_sync_calls": sample.db_sync_calls,
            "dirs_complete": sample.dirs_complete,
            "tasks_pending": sample.tasks_pending,
            "gaps": sample.gaps,
            "child_peak_rss_bytes": sample.child_peak_rss,
            "rss_samples": sample.rss_samples,
            "stderr_tail": sample.stderr_tail,
        }));
        let stop = sample.timed_out;
        iters.push(sample);
        if stop {
            break;
        }
    }
    let measured_s = window_start.elapsed().as_secs_f64();
    let cpu_after = children_cpu_seconds();
    let total_entries: u64 = iters.iter().map(|s| s.entries).sum();
    let total_tx: u64 = iters.iter().map(|s| s.db_transactions).sum();
    let syncs: Vec<u64> = iters.iter().filter_map(|s| s.db_sync_calls).collect();
    let sync_known = !iters.is_empty() && syncs.len() == iters.len();
    let total_sync: u64 = syncs.iter().sum();
    let child_cpu = match (cpu_before, cpu_after) {
        (Some(before), Some(after)) => Some((after - before).max(0.0)),
        _ => None,
    };
    let mean_cores = child_cpu.map(|cpu| cpu / measured_s.max(0.001));
    let child_peak = iters.iter().filter_map(|s| s.child_peak_rss).max();
    let rss_samples: usize = iters.iter().map(|s| s.rss_samples).sum();
    let all_exit_zero = !iters.is_empty() && iters.iter().all(|s| s.exit_code == Some(0));
    let all_complete = !iters.is_empty()
        && iters
            .iter()
            .all(|s| s.report_ok && s.scan_state == "complete");
    let all_pending_zero =
        !iters.is_empty() && iters.iter().all(|s| s.report_ok && s.tasks_pending == 0);
    let rss_ok = child_peak.is_some_and(|peak| peak <= limits.rss_target_bytes);
    let cpu_ok = mean_cores.is_some_and(|cores| cores <= 1.1);
    let perf02 = measured_s >= MEASURED_MIN_SECS
        && all_exit_zero
        && all_complete
        && all_pending_zero
        && rss_ok
        && cpu_ok;
    recorder.record(&serde_json::json!({
        "record": "sustained",
        "iters": iters.len(),
        "measured_wall_s": measured_s,
        "min_required_s": MEASURED_MIN_SECS,
        "total_entries": total_entries,
        "entries_per_s": total_entries as f64 / measured_s.max(0.001),
        "total_tx": total_tx,
        "tx_per_s": total_tx as f64 / measured_s.max(0.001),
        "sync_known": sync_known,
        "total_sync": if sync_known { Some(total_sync) } else { None },
        "child_cpu_seconds": child_cpu,
        "cpu_method": "libc getrusage(RUSAGE_CHILDREN) diff across the measured window (direct children incl. RSS sampler procs; binary grandchildren not separated)",
        "mean_cores": mean_cores,
        "cpu_bound_cores": 1.1,
        "child_peak_rss_bytes": child_peak,
        "harness_peak_rss_bytes": support::peak_rss_bytes(),
        "rss_bound_bytes": limits.rss_target_bytes,
        "rss_method": "child RSS polled every 100 ms via /proc/<pid>/statm (linux) or ps rss (macos); peak is the max sample",
        "rss_cadence_ms": 100,
        "rss_samples": rss_samples,
        "all_exit_zero": all_exit_zero,
        "all_complete": all_complete,
        "all_pending_zero": all_pending_zero,
        "verdict": perf02,
    }));

    // --- Queue-bound observance: static prefetch caps plus live completion. ---
    let probe = Admission::new(ResourceLimits::default());
    let static_ok = probe.prefetch_allowed(1_023, 4 * 1024 * 1024 - 1)
        && !probe.prefetch_allowed(1_024, 0)
        && !probe.prefetch_allowed(0, 4 * 1024 * 1024)
        && probe.prefetch_task_cap() == 1_024
        && probe.prefetch_byte_cap() == 4 * 1024 * 1024;
    let pending_final = iters.last().map_or(u64::MAX, |s| s.tasks_pending);
    let pending_max = iters
        .iter()
        .map(|s| s.tasks_pending)
        .max()
        .unwrap_or(u64::MAX);
    let queue_pass = static_ok && all_complete && all_pending_zero;
    recorder.record(&serde_json::json!({
        "record": "queue_bounds",
        "prefetch_task_cap": 1_024,
        "prefetch_byte_cap": 4 * 1024 * 1024,
        "static_prefetch_ok": static_ok,
        "tasks_pending_final": pending_final,
        "tasks_pending_max": pending_max,
        "verdict": queue_pass,
    }));

    // --- PERF-03: pressure injection through the admission path. ---
    let (pressure_record, pressure_pass) =
        pressure_phase(child_peak, limits.pressure_threshold_bytes);
    recorder.record(&pressure_record);

    let pass = perf02 && queue_pass && pressure_pass;
    recorder.record(&serde_json::json!({
        "record": "verdict",
        "perf02_pass": perf02,
        "queue_pass": queue_pass,
        "perf03_pass": pressure_pass,
        "pass": pass,
        "measured_wall_s": measured_s,
        "iters": iters.len(),
        "child_peak_rss_bytes": child_peak,
        "mean_cores": mean_cores,
    }));
    println!("perf_gates: results at {}", recorder.path().display());
    if pass {
        println!(
            "perf_gates: PASS ({} iters, {measured_s:.1}s measured)",
            iters.len()
        );
    } else {
        eprintln!("perf_gates: FAIL (perf02={perf02} queue={queue_pass} perf03={pressure_pass})");
        std::process::exit(1);
    }
}

/// Locate the built binary: the `CARGO_BIN_EXE_repo-scan` environment wins,
/// then the crate target dirs, then `PATH`. Missing is a loud harness error.
fn resolve_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_repo-scan") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return candidate;
        }
    }
    let exe = format!("repo-scan{}", std::env::consts::EXE_SUFFIX);
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for profile in ["debug", "release"] {
        let candidate = manifest.join("target").join(profile).join(&exe);
        if candidate.is_file() {
            return candidate;
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(&exe);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    eprintln!("perf_gates: no repo-scan binary found (set CARGO_BIN_EXE_repo-scan)");
    std::process::exit(1);
}

/// Parse a report file; `None` on any read or parse failure.
fn read_json(path: &Path) -> Option<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Recursive directory copy for archetype replication. Loud on symlinks or
/// special files: fresh archetypes contain only dirs and files.
fn copy_dir_all(src: &Path, dst: &Path) {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((from, to)) = stack.pop() {
        std::fs::create_dir_all(&to).unwrap_or_else(|e| panic!("mkdir {}: {e}", to.display()));
        let mut entries: Vec<_> = std::fs::read_dir(&from)
            .unwrap_or_else(|e| panic!("readdir {}: {e}", from.display()))
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("readentry {}: {e}", from.display()));
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let ty = entry
                .file_type()
                .unwrap_or_else(|e| panic!("filetype {}: {e}", entry.path().display()));
            let target = to.join(entry.file_name());
            if ty.is_dir() {
                stack.push((entry.path(), target));
            } else if ty.is_file() {
                std::fs::copy(entry.path(), &target)
                    .unwrap_or_else(|e| panic!("copy {}: {e}", entry.path().display()));
            } else {
                panic!("unsupported archetype entry: {}", entry.path().display());
            }
        }
    }
}

/// Build the declared corpus: huge-flat files, a deep chain, and 200 git
/// repos across the four layouts. One git-built archetype per layout, then
/// filesystem copies; detach and worktree registration run in place because
/// they embed absolute paths and cannot be copied.
fn build_corpus(corpus: &Path, archetypes: &Path) {
    std::fs::create_dir_all(archetypes).expect("archetype dir");
    let normal = support::seed_repo(archetypes, "normal");
    support::git(&normal, &["remote", "add", "origin", REMOTE_URL]);
    support::git(archetypes, &["init", "-q", "--bare", "bare.git"]);
    let bare = archetypes.join("bare.git");
    let bare_arg = bare.to_string_lossy().into_owned();
    support::git(&normal, &["push", "-q", &bare_arg, "main:main"]);
    support::git(&bare, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    // Identifying remote: without an origin the bare copies report
    // unresolvable_identity and every scan exits 3 (incomplete).
    support::git(&bare, &["remote", "add", "origin", REMOTE_URL]);

    let flat = corpus.join("flat");
    std::fs::create_dir_all(&flat).expect("flat dir");
    for i in 0..FLAT_FILES {
        std::fs::write(flat.join(format!("f{i:04}")), b"x").expect("flat file");
    }
    let mut deep = corpus.join("deep");
    std::fs::create_dir_all(&deep).expect("deep top");
    for i in 0..DEEP_LEVELS {
        deep = deep.join(format!("d{i:02}"));
        std::fs::create_dir(&deep).expect("deep level");
    }
    std::fs::write(deep.join("bottom.txt"), b"bottom\n").expect("deep marker");

    let repos = corpus.join("repos");
    std::fs::create_dir_all(&repos).expect("repos dir");
    for i in 0..REPOS_NORMAL {
        copy_dir_all(&normal, &repos.join(format!("n-{i:03}")));
    }
    for i in 0..REPOS_BARE {
        copy_dir_all(&bare, &repos.join(format!("store-{i:02}.backup")));
    }
    for i in 0..REPOS_DETACHED {
        let dst = repos.join(format!("d-{i:02}"));
        copy_dir_all(&normal, &dst);
        support::git(&dst, &["checkout", "-q", "--detach", "HEAD"]);
    }
    for i in 0..REPOS_WT_MAINS {
        let main = repos.join(format!("wt-{i:02}")).join("main");
        copy_dir_all(&normal, &main);
        let wt = main.parent().expect("wt parent").join("wt");
        let wt_arg = wt.to_string_lossy().into_owned();
        support::git(&main, &["worktree", "add", "--detach", &wt_arg]);
    }
}

/// One sampled scan of the corpus through the built binary.
struct ScanCtx<'a> {
    binary: &'a Path,
    state_dir: &'a Path,
    corpus: &'a Path,
    workdir: &'a Path,
}

/// Observed outcome of one binary scan plus its report counters.
struct ScanSample {
    wall_ms: f64,
    exit_code: Option<i32>,
    timed_out: bool,
    report_ok: bool,
    scan_state: String,
    entries: u64,
    db_transactions: u64,
    db_sync_calls: Option<u64>,
    dirs_complete: u64,
    tasks_pending: u64,
    gaps: u64,
    child_peak_rss: Option<u64>,
    rss_samples: usize,
    stderr_tail: String,
}

/// Run one `scan --root <corpus> --force-rescan` through the built binary,
/// polling child RSS until exit. A nonzero exit or unreadable report is
/// recorded, never panicked: the verdict decides.
fn run_scan(ctx: &ScanCtx, report_path: &Path) -> ScanSample {
    let mut cmd = Command::new(ctx.binary);
    cmd.args([
        "--state-dir",
        ctx.state_dir.to_str().expect("utf8 state dir"),
        "scan",
        TARGET_URL,
        "--root",
        ctx.corpus.to_str().expect("utf8 corpus"),
        "--report",
        report_path.to_str().expect("utf8 report"),
        "--force-rescan",
    ]);
    cmd.current_dir(ctx.workdir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", ctx.binary.display()));
    // Drain pipes on threads so a chatty child can never block on full buffers.
    let out_handle = child.stdout.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let err_handle = child.stderr.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let pid = child.id();
    let start = Instant::now();
    let mut peak: Option<u64> = None;
    let mut samples = 0usize;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait().expect("poll scan child") {
            Some(status) => break status,
            None => {
                if start.elapsed() > SCAN_TIMEOUT {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait().expect("reap timed-out scan");
                }
                if let Some(rss) = sample_child_rss_bytes(pid) {
                    peak = Some(peak.unwrap_or(0).max(rss));
                }
                samples += 1;
                std::thread::sleep(RSS_CADENCE);
            }
        }
    };
    let wall_ms = support::wall_ms(&start);
    let stderr_bytes = err_handle.and_then(|h| h.join().ok()).unwrap_or_default();
    let _ = out_handle.and_then(|h| h.join().ok());
    let stderr_tail: String = String::from_utf8_lossy(&stderr_bytes)
        .chars()
        .rev()
        .take(400)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    let mut sample = ScanSample {
        wall_ms,
        exit_code: status.code(),
        timed_out,
        report_ok: false,
        scan_state: String::new(),
        entries: 0,
        db_transactions: 0,
        db_sync_calls: None,
        dirs_complete: 0,
        tasks_pending: u64::MAX,
        gaps: u64::MAX,
        child_peak_rss: peak,
        rss_samples: samples,
        stderr_tail,
    };
    if let Some(report) = read_json(report_path) {
        sample.report_ok = true;
        sample.scan_state = report["scan"]["state"].as_str().unwrap_or("").to_string();
        sample.entries = report["resources"]["enumerated_entries"]
            .as_u64()
            .unwrap_or(0);
        sample.db_transactions = report["resources"]["db_transactions"].as_u64().unwrap_or(0);
        sample.db_sync_calls = report["resources"]["db_sync_calls"].as_u64();
        sample.dirs_complete = report["coverage"]["directories_complete"]
            .as_u64()
            .unwrap_or(0);
        sample.tasks_pending = report["coverage"]["tasks_pending"]
            .as_u64()
            .unwrap_or(u64::MAX);
        sample.gaps = report["coverage"]["gaps"].as_u64().unwrap_or(u64::MAX);
    }
    sample
}

/// One child RSS sample in bytes. Linux reads `/proc/<pid>/statm` without
/// spawning; other Unix targets poll `ps` (its CPU cost stays inside the
/// measured window and is disclosed on the sustained record).
fn sample_child_rss_bytes(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
        let resident: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return None;
        }
        Some(resident.saturating_mul(page as u64))
    }
    #[cfg(not(target_os = "linux"))]
    {
        sample_child_rss_portable(pid)
    }
}

/// Child RSS via `ps` for Unix targets without `/proc` (macOS).
#[cfg(all(unix, not(target_os = "linux")))]
fn sample_child_rss_portable(pid: u32) -> Option<u64> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let kilobytes: u64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .ok()?;
    Some(kilobytes.saturating_mul(1024))
}

/// No child RSS source off Unix.
#[cfg(not(unix))]
fn sample_child_rss_portable(pid: u32) -> Option<u64> {
    let _ = pid;
    None
}

/// Cumulative reaped-children CPU seconds (user + system).
#[cfg(unix)]
fn children_cpu_seconds() -> Option<f64> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) } != 0 {
        return None;
    }
    let secs = usage.ru_utime.tv_sec as f64 + usage.ru_stime.tv_sec as f64;
    let micros = usage.ru_utime.tv_usec as f64 + usage.ru_stime.tv_usec as f64;
    Some(secs + micros / 1_000_000.0)
}

/// No children-CPU source off Unix.
#[cfg(not(unix))]
fn children_cpu_seconds() -> Option<f64> {
    None
}

/// PERF-03: inject pressure through [`Admission::set_pressure`], proving
/// admission stops scheduling, held work stays resumable, nothing becomes
/// falsely clean, and helper churn cannot reset CPU accounting. Returns the
/// JSONL record plus its verdict.
fn pressure_phase(sustained_peak: Option<u64>, threshold: u64) -> (serde_json::Value, bool) {
    let mut admission = Admission::new(ResourceLimits::default());
    let mut store = MemorySchedulerStore::new();
    for i in 0..4 {
        store.insert_task(Task {
            id: format!("perf-task-{i}"),
            epoch: Epoch(0),
            generation: GenerationId(1),
            kind: TaskKind::EnumerateDir,
            scope_key: format!("dir:/perf/scope-{i}"),
            expected_revision: 0,
            idempotency_key: format!("perf-task-{i}"),
            state: TaskState::Pending,
            not_before: None,
        });
    }
    let mut sched = DurableScheduler::new(store);
    let pre = admission
        .try_acquire(OpClass::Enumerate)
        .expect("pre-pressure permit");
    let pre_claimed = sched
        .claim(Epoch(7), 1, Duration::from_secs(60))
        .expect("pre-pressure claim");
    assert_eq!(pre_claimed.len(), 1);
    let held_lease = pre_claimed
        .into_iter()
        .next()
        .expect("pre-pressure lease")
        .1;
    let pending_before = sched.pending_count(GenerationId(1)).expect("pending count");

    admission.set_pressure(true);
    let stops_admission = admission.try_acquire(OpClass::Enumerate).is_none()
        && admission.try_acquire(OpClass::GitProbe).is_none()
        && admission.try_acquire(OpClass::Other).is_none();
    let spawn_stopped = !admission.helper_spawn_allowed();
    let prefetch_stopped = !admission.prefetch_allowed(0, 0);
    // Owner-loop gate under pressure (mirrors the binary: claim, then admit,
    // release on denial so denied work returns to pending immediately).
    let gated = sched
        .claim(Epoch(7), 8, Duration::from_secs(60))
        .expect("gated claim");
    let mut denied = 0usize;
    for (task, _) in &gated {
        if admission.try_acquire(OpClass::Enumerate).is_none() {
            sched
                .store_mut()
                .release_to_pending(&task.id)
                .expect("release denied");
            denied += 1;
        }
    }
    let leased_now = sched
        .store()
        .all_tasks()
        .iter()
        .filter(|task| task.state == TaskState::Leased)
        .count();
    let pending_now = sched.pending_count(GenerationId(1)).expect("pending count");
    let held_permits = admission.snapshot().shared_in_use;
    let pending_preserved = !gated.is_empty()
        && denied == gated.len()
        && leased_now == 1
        && pending_now == pending_before;

    // A contained probe stays explicitly pending with null counts: validation
    // accepts it, and nothing reads as zero or clean.
    let contained = Status {
        state: "pending".to_string(),
        mode: "summary".to_string(),
        started_at: None,
        finished_at: None,
        staged: None,
        unstaged: None,
        untracked: None,
        untracked_units: "collapsed_entries".to_string(),
        submodules: "unknown".to_string(),
        unknown_fields: vec![
            "staged".to_string(),
            "unstaged".to_string(),
            "untracked".to_string(),
        ],
        error_ids: Vec::new(),
    };
    let mut problems = Vec::new();
    validate_status(&contained, "contained probe", &mut problems);
    let no_false_clean = problems.is_empty()
        && contained.state != "complete"
        && contained.staged.is_none()
        && contained.unstaged.is_none()
        && contained.untracked.is_none()
        && admission.try_acquire(OpClass::GitProbe).is_none();

    // Exited-helper CPU is retained: repeated termination cannot reset it.
    let sampler = FootprintSampler::new();
    let running = sampler.sample_with(&SamplerInputs {
        helpers_cpu_seconds: 42.0,
        helpers: 1,
        ..SamplerInputs::default()
    });
    let reaped = sampler.sample_with(&SamplerInputs {
        helpers_cpu_seconds: 42.0,
        helpers: 0,
        ..SamplerInputs::default()
    });
    let cpu_retained =
        running.cpu_seconds >= 42.0 && reaped.cpu_seconds >= 42.0 && reaped.helpers == 0;

    admission.set_pressure(false);
    let mut helpers_added = 0;
    for _ in 0..4 {
        if admission.add_helper() {
            helpers_added += 1;
        }
    }
    let helper_cap_held = helpers_added == 4 && !admission.add_helper();
    let resumed_permit = admission.try_acquire(OpClass::GitProbe);
    let resumed_claim = sched
        .claim(Epoch(7), 8, Duration::from_secs(60))
        .expect("post-pressure claim");
    let completed = sched
        .complete_detailed(
            &held_lease,
            TaskOutcome::Complete {
                children: Vec::new(),
                candidates: Vec::new(),
            },
        )
        .is_ok();
    let pending_after = sched.pending_count(GenerationId(1)).expect("pending count");
    let resumable_after =
        resumed_permit.is_some() && resumed_claim.len() == 3 && completed && pending_after == 3;
    if let Some(permit) = resumed_permit {
        admission.release(&permit);
    }
    admission.release(&pre);

    let bounded = sustained_peak.is_some_and(|peak| peak <= threshold);
    let verdict = stops_admission
        && spawn_stopped
        && prefetch_stopped
        && pending_preserved
        && no_false_clean
        && cpu_retained
        && helper_cap_held
        && resumable_after
        && bounded;
    let record = serde_json::json!({
        "record": "pressure",
        "stops_admission": stops_admission,
        "prefetch_stopped": prefetch_stopped,
        "spawn_stopped": spawn_stopped,
        "pending_before": pending_before,
        "pending_under_pressure": pending_now,
        "denied_released": denied,
        "pending_preserved": pending_preserved,
        "no_false_clean": no_false_clean,
        "cpu_accounting_retained": cpu_retained,
        "helper_cap_held": helper_cap_held,
        "resumable_after": resumable_after,
        "overshoot_held_permits": held_permits,
        "overshoot_leased_tasks": leased_now,
        "pressure_threshold_bytes": threshold,
        "sustained_peak_rss_bytes": sustained_peak,
        "bounded_footprint": bounded,
        "verdict": verdict,
    });
    (record, verdict)
}
