//! Events + resource acceptance (EVENT-01/02, PERF-01/03 feasible subset).
//!
//! EVENT-01/02: incremental discovery reconciles while-stopped insertions
//! (CLI), history loss invalidates scope, kill between ingest and
//! reconcile loses no work, and an unrelated-event flood still yields a
//! finite-boundary report. Live FSEvents tests are macOS-only and
//! cfg-gated; Linux expectations are documented on each gate (the portable
//! path covers the same protocol logic through fixtures, and while-stopped
//! insertion reconciles through rescan + invalidation on every target).
//!
//! PERF-01: default hard admission and buffer bounds hold under burst
//! (static limit values + live counter agreement on a CLI scan).
//! PERF-03: injected memory pressure stops admission, work stays
//! resumable, nothing becomes falsely clean, and helper termination
//! cannot reset CPU accounting.

mod common;

use common::fixture;
use repo_scan::config::ResourceLimits;
use repo_scan::events::{
    continuity_plan, decide_open, subtree_scope_key, volume_scope_key, ContinuitySignal,
    CursorJournal, EventBatch, EventCursorId, HistoryUuid, MemoryCursorJournal, MemorySink,
    Reconciler, MAX_PENDING_INVALIDATIONS,
};
use repo_scan::scheduler::admission::{Admission, OpClass};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

const URL: &str = "https://github.com/OWNER/REPO";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Run the binary with `--state-dir <state>` from `cwd`.
fn run(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    ProcCommand::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn git_available() -> bool {
    ProcCommand::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn load_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Confirmed repository IDs in a report (match == "confirmed").
fn confirmed_repos(report: &serde_json::Value) -> Vec<String> {
    report["repositories"]
        .as_array()
        .expect("repositories")
        .iter()
        .filter(|r| r["match"].as_str() == Some("confirmed"))
        .filter_map(|r| r["id"].as_str().map(str::to_string))
        .collect()
}

fn batch(volume: &str, high_water: u64, paths: &[&str]) -> EventBatch {
    EventBatch {
        volume_key: volume.to_string(),
        high_water: EventCursorId(high_water),
        invalidations: paths.iter().copied().map(PathBuf::from).collect(),
        history_done: false,
        signals: Vec::new(),
    }
}

fn batch_with_signals(
    volume: &str,
    high_water: u64,
    paths: &[&str],
    signals: Vec<ContinuitySignal>,
) -> EventBatch {
    let mut batch = batch(volume, high_water, paths);
    batch.signals = signals;
    batch
}

// ---------------------------------------------------------------------------
// EVENT-01: while-stopped insertion, moved-in dirs, history loss
// ---------------------------------------------------------------------------

#[test]
fn event_01_while_stopped_insertion_reconciled() {
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo-a");
    let root_str = root.to_str().expect("utf8").to_string();

    // Baseline scan: one confirmed copy.
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "r1.json",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let first = load_json(&dir.path().join("r1.json"));
    assert_eq!(confirmed_repos(&first).len(), 1);

    // While stopped: insert a fresh clone and move in a repo from outside.
    fixture::normal_clone(&root, "repo-b");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).expect("mkdir");
    let moved = fixture::normal_clone(&outside, "repo-c");
    let moved_target = root.join("repo-c");
    std::fs::rename(&moved, &moved_target).expect("move in");

    // Invalidate the changed scope (the deterministic cross-platform
    // reconcile trigger; on macOS, stopped-period FSEvents feed the same
    // path) and rescan: both insertions reconcile without a force rescan.
    let out = run(
        &["cache", "invalidate", "--root", root_str.as_str()],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "r2.json",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let second = load_json(&dir.path().join("r2.json"));
    assert_eq!(confirmed_repos(&second).len(), 3, "{second}");

    // Stable afterwards: another scan reports the same three, no dupes.
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "r3.json",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let third = load_json(&dir.path().join("r3.json"));
    assert_eq!(confirmed_repos(&third).len(), 3, "{third}");
}

#[test]
fn event_01_history_loss_invalidates_scope() {
    // Ingest + fully reconcile under uuid-a, then lose history: cursors
    // are discarded, the volume scope is invalidated (never trusted), and
    // no completeness claim is possible until fresh reconciliation.
    let mut r = Reconciler::new(MemoryCursorJournal::new());
    let uuid = HistoryUuid("uuid-a".to_string());
    let decision = r.note_stream_opened("vol-a", None, Some(&uuid), 300, EventCursorId(300));
    assert!(!decision.history_invalid());
    r.begin_traversal().expect("traversal");
    for cursor in [100u64, 200, 300] {
        let outcome = r
            .ingest(&batch("vol-a", cursor, &[&format!("/repo/dir-{cursor}")]))
            .expect("ingest");
        assert!(!outcome.duplicate);
        assert!(!outcome.history_invalid);
    }
    let mut sink = MemorySink::new();
    let outcome = r.reconcile_volume("vol-a", &mut sink).expect("reconcile");
    for scope in &outcome.invalidated_scopes {
        sink.complete_scope(scope);
    }
    let advanced = r.try_advance_reconciled("vol-a", &sink).expect("advance");
    assert_eq!(advanced, Some(EventCursorId(300)));
    r.claim_volume_complete("vol-a").expect("claim at boundary");

    // History loss: cursors discarded, pending dropped, flag recorded.
    let outcome = r
        .ingest(&batch_with_signals(
            "vol-a",
            400,
            &["/repo/dir-400"],
            vec![ContinuitySignal::HistoryInvalid],
        ))
        .expect("ingest invalid");
    assert!(outcome.history_invalid);
    assert_eq!(outcome.advanced_to, None);
    assert_eq!(outcome.plans.len(), 1);
    assert_eq!(outcome.plans[0].scope_key, volume_scope_key("vol-a"));
    assert!(outcome.plans[0].recursive);
    let loaded = r.journal().load("vol-a").expect("cursor row");
    assert_eq!(loaded.uuid, None);
    assert_eq!(loaded.ingested, None);
    assert_eq!(loaded.reconciled, None);
    assert!(r.journal().pending("vol-a").is_empty());
    assert!(loaded.flags_seen.iter().any(|f| f.contains("invalidated")));

    // No completeness claim on lost history.
    assert!(r.claim_volume_complete("vol-a").is_err());

    // Same at the open rule: a changed UUID invalidates, never resumes.
    let stored = repo_scan::events::VolumeCursor {
        uuid: Some(HistoryUuid("uuid-a".to_string())),
        ingested: Some(EventCursorId(300)),
        reconciled: Some(EventCursorId(300)),
        flags_seen: Vec::new(),
    };
    assert!(decide_open(Some(&stored), Some("uuid-b"), 500).history_invalid());
    assert!(!decide_open(Some(&stored), Some("uuid-a"), 500).history_invalid());

    // Fresh baseline after loss: reopen, re-ingest, reconcile, claim.
    let mut r = Reconciler::new(MemoryCursorJournal::new());
    let uuid_b = HistoryUuid("uuid-b".to_string());
    let decision = r.note_stream_opened("vol-a", None, Some(&uuid_b), 600, EventCursorId(600));
    assert!(!decision.history_invalid());
    r.begin_traversal().expect("traversal");
    r.ingest(&batch("vol-a", 600, &["/repo/dir-600"]))
        .expect("ingest");
    let mut sink = MemorySink::new();
    let outcome = r.reconcile_volume("vol-a", &mut sink).expect("reconcile");
    for scope in &outcome.invalidated_scopes {
        sink.complete_scope(scope);
    }
    r.try_advance_reconciled("vol-a", &sink).expect("advance");
    r.claim_volume_complete("vol-a")
        .expect("claim after fresh baseline");
}

#[test]
fn event_01_moved_in_subtree_inspected_recursively() {
    // MustScanSubDirs plans name exactly the moved-in subtrees (recursive),
    // so reconciliation inspects them instead of trusting parent state.
    let plans = continuity_plan(
        "vol-a",
        &[ContinuitySignal::MustScanSubDirs],
        &[
            PathBuf::from("/root/moved-in"),
            PathBuf::from("/root/other"),
        ],
    );
    assert_eq!(plans.len(), 2);
    for plan in &plans {
        assert!(plan.recursive, "{}", plan.scope_key);
        assert!(
            plan.scope_key.starts_with("path:vol-a:"),
            "{}",
            plan.scope_key
        );
    }
    // Overflow without paths collapses to one volume-wide recursive plan.
    let plans = continuity_plan("vol-a", &[ContinuitySignal::MustScanSubDirs], &[]);
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].scope_key, volume_scope_key("vol-a"));
    assert!(plans[0].recursive);
}

// ---------------------------------------------------------------------------
// EVENT-02: cursor crash points, finite boundary under flood
// ---------------------------------------------------------------------------

#[test]
fn event_02_kill_between_ingest_and_reconcile_loses_no_work() {
    // Full protocol with a kill after durable ingest, before reconcile:
    // reopen replays the pending boundary idempotently and the boundary
    // claim still succeeds exactly once the work is satisfied.
    let journal = {
        let mut r = Reconciler::new(MemoryCursorJournal::new());
        let uuid = HistoryUuid("uuid-a".to_string());
        let decision = r.note_stream_opened("vol-a", None, Some(&uuid), 200, EventCursorId(200));
        assert!(!decision.history_invalid());
        r.begin_traversal().expect("traversal");
        let outcome = r
            .ingest(&batch("vol-a", 200, &["/repo/new-clone"]))
            .expect("ingest");
        assert!(!outcome.duplicate);
        assert_eq!(outcome.advanced_to, Some(EventCursorId(200)));
        // --- simulated kill: only the durable journal survives ---
        std::mem::replace(r.journal_mut(), MemoryCursorJournal::new())
    };

    let mut r = Reconciler::new(journal);
    let pending = r.journal().pending("vol-a");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].cursor, EventCursorId(200));
    // Restart replays the open rule against stored history: resume.
    let stored = r.journal().load("vol-a").expect("stored cursor");
    assert_eq!(stored.ingested, Some(EventCursorId(200)));
    let decision = r.note_stream_opened(
        "vol-a",
        Some(&stored),
        stored.uuid.as_ref(),
        200,
        EventCursorId(200),
    );
    assert!(!decision.history_invalid());
    r.begin_traversal().expect("traversal");
    // Duplicate replay of the killed batch is a no-op (no double work).
    let replay = r
        .ingest(&batch("vol-a", 200, &["/repo/new-clone"]))
        .expect("replay");
    assert!(replay.duplicate);
    assert_eq!(replay.advanced_to, Some(EventCursorId(200)));

    let mut sink = MemorySink::new();
    let outcome = r.reconcile_volume("vol-a", &mut sink).expect("reconcile");
    assert!(!outcome.invalidated_scopes.is_empty());
    // Claim before the work completes must fail (no premature complete).
    assert!(r.claim_volume_complete("vol-a").is_err());
    for scope in &outcome.invalidated_scopes {
        sink.complete_scope(scope);
    }
    let advanced = r.try_advance_reconciled("vol-a", &sink).expect("advance");
    assert_eq!(advanced, Some(EventCursorId(200)));
    assert!(r.journal().pending("vol-a").is_empty());
    r.claim_volume_complete("vol-a")
        .expect("claim after replay");
}

#[test]
fn event_02_kill_mid_scan_resumes_to_complete_report() {
    // Process-level crash point: SIGKILL-equivalent mid-scan, then a fresh
    // invocation resumes compatible unfinished discovery and publishes a
    // complete, conforming report (no lost acknowledged work, no dupes).
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo-a");
    fixture::normal_clone(&root, "repo-b");
    fixture::huge_flat(&root, fixture::HUGE_FLAT_CI);
    fixture::deep_path(&root, fixture::DEEP_PATH_CI);
    let root_str = root.to_str().expect("utf8").to_string();

    let mut child = ProcCommand::new(binary())
        .args([
            "--state-dir",
            state.to_str().expect("utf8"),
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "killed.json",
        ])
        .current_dir(dir.path())
        .spawn()
        .expect("spawn scan");
    std::thread::sleep(std::time::Duration::from_millis(100));
    // Either the scan was still running (killed) or it already finished;
    // both paths must converge on a complete report below.
    let _ = child.kill();
    let _ = child.wait();

    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "after.json",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = load_json(&dir.path().join("after.json"));
    assert_eq!(report["scan"]["state"].as_str(), Some("complete"));
    assert_eq!(confirmed_repos(&report).len(), 2, "{report}");
    assert_eq!(report["coverage"]["gaps"].as_u64(), Some(0));
}

#[test]
fn event_02_unrelated_flood_yields_finite_boundary_report() {
    // Boundary pinned at open (500). In-boundary batches reconcile and the
    // volume claims complete at 500 while 5,000 unrelated past-boundary
    // arrivals stay queued: finite report, nothing dropped, nothing waited
    // on forever.
    let mut r = Reconciler::new(MemoryCursorJournal::new());
    let uuid = HistoryUuid("uuid-flood".to_string());
    let decision = r.note_stream_opened("vol-f", None, Some(&uuid), 500, EventCursorId(500));
    assert!(!decision.history_invalid());
    r.begin_traversal().expect("traversal");
    for cursor in [100u64, 200, 300, 400, 500] {
        r.ingest(&batch("vol-f", cursor, &[&format!("/repo/dir-{cursor}")]))
            .expect("ingest");
    }
    for i in 1..=5_000u64 {
        r.ingest(&batch(
            "vol-f",
            500 + i,
            &[&format!("/unrelated/flood-{i}")],
        ))
        .expect("flood ingest");
    }
    let loaded = r.journal().load("vol-f").expect("cursor");
    assert_eq!(loaded.ingested, Some(EventCursorId(5_500)));

    let mut sink = MemorySink::new();
    let outcome = r.reconcile_volume("vol-f", &mut sink).expect("reconcile");
    assert!(!outcome.invalidated_scopes.is_empty());
    // Satisfy only in-boundary work (distinct subtree scopes).
    for cursor in [100u64, 200, 300, 400, 500] {
        let path = PathBuf::from(format!("/repo/dir-{cursor}"));
        sink.complete_scope(&subtree_scope_key("vol-f", &path));
        let parent = path.parent().expect("parent");
        sink.complete_scope(&subtree_scope_key("vol-f", parent));
    }
    let advanced = r.try_advance_reconciled("vol-f", &sink).expect("advance");
    assert_eq!(advanced, Some(EventCursorId(500)));
    r.claim_volume_complete("vol-f")
        .expect("finite boundary claim");
    // Flood arrivals preserved past the boundary for later reconciliation.
    let pending = r.journal().pending("vol-f");
    assert_eq!(pending.len(), 5_000);
    assert!(pending.iter().all(|b| b.cursor.0 > 500));

    // Coalescing bound: a single burst past the cap collapses to one
    // volume-wide plan instead of an unbounded queue.
    let paths: Vec<PathBuf> = (0..MAX_PENDING_INVALIDATIONS + 100)
        .map(|i| PathBuf::from(format!("/burst/dir-{i}")))
        .collect();
    let plans = continuity_plan("vol-f", &[], &paths);
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].scope_key, volume_scope_key("vol-f"));
}

#[test]
fn event_02_unrelated_file_flood_scan_still_completes() {
    // CLI twin: thousands of unrelated files do not prevent a complete,
    // bounded report over explicit roots.
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    fixture::huge_flat(&root, fixture::HUGE_FLAT_CI);
    let root_str = root.to_str().expect("utf8").to_string();

    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "flood.json",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = load_json(&dir.path().join("flood.json"));
    assert_eq!(report["scan"]["state"].as_str(), Some("complete"));
    assert_eq!(report["coverage"]["filesystem"].as_str(), Some("complete"));
    assert_eq!(confirmed_repos(&report).len(), 1);
}

/// Native macOS evidence: a real history stream opens on the temp
/// volume, a file-creation flood drains through bounded batches, ingest
/// stays monotonic, and the boundary protocol completes finitely.
///
/// Linux expectation: compiled out (no FSEvents). The portable path
/// covers the same ingest/reconcile/claim protocol through the fixture
/// tests above plus `cache invalidate` rescan reconciliation.
#[cfg(target_os = "macos")]
#[test]
fn event_02_live_stream_flood_yields_finite_boundary() {
    use repo_scan::events::native;
    use repo_scan::platform::macos::{FsEventsSource, MacOsMountTable};
    use repo_scan::platform::{EventSource, MountTable};

    let dir = tempfile::tempdir().expect("tempdir");
    let mounts = MacOsMountTable.mounts().expect("mounts");
    assert!(!mounts.is_empty());
    // Prefer the mount actually hosting the tempdir; fall back to first.
    let mount = mounts
        .iter()
        .find(|m| dir.path().starts_with(&m.mount_path))
        .or(mounts.first())
        .expect("one mount");

    let mut source = FsEventsSource;
    let (boundary, mut iter) = source.open_stream(&mount.volume, None).expect("open");
    let dev = native::device_of(&mount.mount_path).expect("dev");
    let live_uuid = native::live_history_uuid(dev);
    let mut r = Reconciler::new(MemoryCursorJournal::new());
    let decision = r.note_stream_opened(
        &mount.volume.0,
        None,
        live_uuid.as_ref(),
        boundary.0,
        boundary,
    );
    assert!(!decision.history_invalid());
    assert_eq!(r.boundary(&mount.volume.0), Some(boundary));
    r.begin_traversal().expect("traversal");

    // Flood: create files after the stream opened, then drain boundedly.
    for i in 0..200 {
        std::fs::write(dir.path().join(format!("flood-{i:04}")), b"x").expect("write");
    }
    let mut drained = 0usize;
    let mut last_high_water = 0u64;
    while drained < 128 {
        match iter.next_batch().expect("drain") {
            Some(batch) => {
                assert!(batch.high_water.0 >= last_high_water, "monotonic drain");
                last_high_water = batch.high_water.0;
                r.ingest(&batch).expect("ingest");
                drained += 1;
            }
            None => break,
        }
    }
    drop(iter);

    // Reconcile whatever arrived (possibly nothing on an idle volume) and
    // finish finitely: either the boundary claim holds or its refusal is
    // the honest below-boundary reason, never a hang or a false complete.
    let mut sink = MemorySink::new();
    let outcome = r
        .reconcile_volume(&mount.volume.0, &mut sink)
        .expect("reconcile");
    for scope in &outcome.invalidated_scopes {
        sink.complete_scope(scope);
    }
    let reconciled = r
        .try_advance_reconciled(&mount.volume.0, &sink)
        .expect("advance");
    let claim = r.claim_volume_complete(&mount.volume.0);
    if reconciled.map(|c| c.0).unwrap_or(0) >= boundary.0 {
        assert!(claim.is_ok(), "claim holds at boundary");
    } else {
        assert!(claim.is_err(), "no false complete below boundary");
    }
}

// ---------------------------------------------------------------------------
// PERF-01: admission and buffer bounds under burst
// ---------------------------------------------------------------------------

#[test]
fn perf_01_default_limits_match_spec_table() {
    // Static gate on spec §5: the conservative desktop profile values.
    let limits = ResourceLimits::default();
    assert_eq!(limits.max_enum_ops, 2);
    assert_eq!(limits.max_git_probes, 1);
    assert_eq!(limits.shared_permits, 2);
    assert_eq!(limits.max_helpers, 4);
    assert_eq!(limits.prefetch_tasks, 1_024);
    assert_eq!(limits.prefetch_bytes, 4 * 1024 * 1024);
    assert_eq!(limits.batch_entries, 256);
    assert_eq!(limits.batch_bytes, 256 * 1024);
    assert_eq!(limits.pending_batches_per_producer, 2);
    assert_eq!(limits.writer_rows, 512);
    assert_eq!(limits.writer_bytes, 512 * 1024);
    assert_eq!(limits.writer_max_age, std::time::Duration::from_millis(250));
    assert_eq!(limits.max_app_fds, 64);
    assert_eq!(limits.progress_max_hz, 2);
    assert_eq!(limits.telemetry_max_hz, 1);
    assert_eq!(limits.cpu_target_cores, 1.0);
    assert_eq!(limits.rss_target_bytes, 256 * 1024 * 1024);
    assert_eq!(limits.pressure_threshold_bytes, 512 * 1024 * 1024);
}

#[test]
fn perf_01_admission_bounds_hold_under_burst() {
    let mut admission = Admission::new(ResourceLimits::default());

    // Class caps: 2 enumeration, 1 Git probe (third/second refused).
    let e1 = admission.try_acquire(OpClass::Enumerate).expect("enum 1");
    let e2 = admission.try_acquire(OpClass::Enumerate).expect("enum 2");
    assert!(
        admission.try_acquire(OpClass::Enumerate).is_none(),
        "enum cap 2"
    );
    let snap = admission.snapshot();
    assert_eq!(snap.enum_in_use, 2);
    assert_eq!(snap.shared_in_use, 2);

    // The shared cap is not additive: with 2 shared permits held, no Git
    // probe and no Other work admits, even though their class caps are free.
    assert!(
        admission.try_acquire(OpClass::GitProbe).is_none(),
        "shared cap 2"
    );
    assert!(
        admission.try_acquire(OpClass::Other).is_none(),
        "shared cap 2"
    );
    admission.release(&e1);
    // Enum + Git together still capped at 2 shared.
    let g1 = admission.try_acquire(OpClass::GitProbe).expect("git 1");
    assert!(
        admission.try_acquire(OpClass::GitProbe).is_none(),
        "git cap 1"
    );
    assert!(
        admission.try_acquire(OpClass::Other).is_none(),
        "shared cap 2"
    );
    let snap = admission.snapshot();
    assert_eq!(
        (snap.enum_in_use, snap.git_in_use, snap.shared_in_use),
        (1, 1, 2)
    );
    admission.release(&e2);
    admission.release(&g1);
    let o1 = admission.try_acquire(OpClass::Other).expect("other 1");
    let o2 = admission.try_acquire(OpClass::Other).expect("other 2");
    assert!(
        admission.try_acquire(OpClass::Other).is_none(),
        "shared cap 2"
    );
    admission.release(&o1);
    admission.release(&o2);
    // Unknown/double release never corrupts counters.
    admission.release(&o1);
    assert_eq!(admission.snapshot().shared_in_use, 0);

    // Helper cap: 4 including still-stuck; no unlimited replacements.
    for _ in 0..4 {
        assert!(admission.add_helper());
    }
    assert!(!admission.add_helper(), "helper cap 4");
    assert!(!admission.helper_spawn_allowed());
    assert_eq!(admission.snapshot().helpers_live, 4);
    admission.remove_helper(); // only a fully reaped exit decrements
    assert!(admission.helper_spawn_allowed());

    // Descriptor budget: 64, first-byte-exact.
    assert!(admission.fd_acquire(64));
    assert!(!admission.fd_acquire(1), "fd cap 64");
    admission.fd_release(64);
    assert!(admission.fd_acquire(1));

    // Prefetch stops at 1,024 tasks or 4 MiB, first limit wins.
    assert!(admission.prefetch_allowed(1_023, 4 * 1024 * 1024 - 1));
    assert!(!admission.prefetch_allowed(1_024, 0), "task cap");
    assert!(!admission.prefetch_allowed(0, 4 * 1024 * 1024), "byte cap");
    assert_eq!(admission.prefetch_task_cap(), 1_024);
    assert_eq!(admission.prefetch_byte_cap(), 4 * 1024 * 1024);

    // Churn burst: 10k acquire/release cycles never exceed caps.
    let mut held = Vec::new();
    for i in 0..10_000usize {
        let class = match i % 3 {
            0 => OpClass::Enumerate,
            1 => OpClass::GitProbe,
            _ => OpClass::Other,
        };
        if let Some(permit) = admission.try_acquire(class) {
            held.push(permit);
        }
        let snap = admission.snapshot();
        assert!(snap.enum_in_use <= 2, "enum burst cap");
        assert!(snap.git_in_use <= 1, "git burst cap");
        assert!(snap.shared_in_use <= 2, "shared burst cap");
        if i % 2 == 0 {
            for permit in held.drain(..) {
                admission.release(&permit);
            }
        }
    }
    for permit in held.drain(..) {
        admission.release(&permit);
    }
    assert_eq!(admission.snapshot().shared_in_use, 0);
}

#[test]
fn perf_01_live_scan_counters_agree_with_work() {
    // Live counter assertions: a CLI scan over known content reports
    // counters consistent with the work actually done.
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    for name in ["a.txt", "b.txt", "c.txt"] {
        std::fs::write(root.join(name), "data\n").expect("write");
    }
    let root_str = root.to_str().expect("utf8").to_string();

    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "counters.json",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = load_json(&dir.path().join("counters.json"));
    let resources = &report["resources"];
    // Lower bounds from known content (top-level entries + git internals
    // only add more; nothing is skipped or double-counted into absurdity).
    assert!(resources["enumerated_entries"].as_u64().expect("entries") >= 4);
    assert!(resources["enumerated_entries"].as_u64().expect("entries") < 1_000_000);
    assert!(resources["db_transactions"].as_u64().expect("txns") >= 1);
    assert!(
        report["coverage"]["directories_complete"]
            .as_u64()
            .expect("dirs")
            >= 2
    );
    assert_eq!(report["coverage"]["tasks_pending"].as_u64(), Some(0));
    assert_eq!(report["tool"]["name"].as_str(), Some("repo-scan"));
}

// ---------------------------------------------------------------------------
// PERF-03: memory-pressure response (injected at the admission layer)
// ---------------------------------------------------------------------------

#[test]
fn perf_03_pressure_stops_admission_and_work_resumes() {
    // The binary exposes no pressure-injection hook, so the response path
    // is exercised at the admission layer it is built on: pressure stops
    // all admission and prefetch, held work is preserved (never silently
    // completed), and clearing pressure resumes the same counters.
    let mut admission = Admission::new(ResourceLimits::default());
    let held = admission
        .try_acquire(OpClass::Enumerate)
        .expect("pre-pressure permit");
    assert_eq!(admission.snapshot().shared_in_use, 1);

    admission.set_pressure(true);
    assert!(admission.under_pressure());
    assert!(
        admission.try_acquire(OpClass::Enumerate).is_none(),
        "stopped admission"
    );
    assert!(
        admission.try_acquire(OpClass::GitProbe).is_none(),
        "stopped admission"
    );
    assert!(
        admission.try_acquire(OpClass::Other).is_none(),
        "stopped admission"
    );
    assert!(!admission.helper_spawn_allowed(), "stopped spawn");
    assert!(!admission.prefetch_allowed(0, 0), "stopped prefetch");
    // Held work is preserved, not silently completed or dropped.
    assert_eq!(admission.snapshot().shared_in_use, 1);

    admission.set_pressure(false);
    assert!(!admission.under_pressure());
    assert_eq!(admission.snapshot().shared_in_use, 1);
    admission.release(&held);
    assert!(
        admission.try_acquire(OpClass::GitProbe).is_some(),
        "work resumable"
    );
}

#[test]
fn perf_03_no_false_clean_and_cpu_accounting_survives_respawn() {
    // Contained work stays explicitly pending: a pending status with null
    // counts validates, and the admission refusal is an explicit `None`,
    // never a silent success that could launder into "clean".
    let pending = repo_scan::report::model::Status {
        state: "pending".to_string(),
        mode: "summary".to_string(),
        started_at: None,
        finished_at: None,
        staged: None,
        unstaged: None,
        untracked: None,
        untracked_units: "collapsed_entries".to_string(),
        submodules: "unknown".to_string(),
        unknown_fields: Vec::new(),
        error_ids: Vec::new(),
    };
    let mut problems = Vec::new();
    repo_scan::report::validate::validate_status(&pending, "contained probe", &mut problems);
    assert!(problems.is_empty(), "{problems:?}");

    let mut admission = Admission::new(ResourceLimits::default());
    admission.set_pressure(true);
    let refused: Option<repo_scan::scheduler::Permit> = admission.try_acquire(OpClass::GitProbe);
    assert!(
        refused.is_none(),
        "pressure refusal is explicit, never fake success"
    );

    // Repeated helper termination cannot reset CPU accounting: exited
    // helper CPU is retained in the sampler inputs forever.
    use repo_scan::telemetry::{FootprintSampler, SamplerInputs};
    let sampler = FootprintSampler::new();
    let running = sampler.sample_with(&SamplerInputs {
        helpers_cpu_seconds: 42.0,
        helpers: 1,
        ..SamplerInputs::default()
    });
    assert!(running.cpu_seconds >= 42.0, "helper CPU folded in");
    // Helper exits and is reaped; its CPU stays in the cumulative total.
    let reaped = sampler.sample_with(&SamplerInputs {
        helpers_cpu_seconds: 42.0,
        helpers: 0,
        ..SamplerInputs::default()
    });
    assert!(
        reaped.cpu_seconds >= 42.0,
        "exited-helper CPU retained, not reset"
    );
    assert_eq!(reaped.helpers, 0);
}
