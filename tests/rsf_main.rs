//! RSF consumer-findings regression tests (one production-path test per
//! issue). Binary end-to-end tests run the built binary; run-loop tests
//! drive `src/main.rs` directly (included as a module) through its
//! `#[cfg(test)]` hooks — the same code the command paths execute.

mod common;

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

use common::fixture;
use repo_scan::model::{StatusMode, TaskState};
use repo_scan::store::{NewTask, Store, TursoStore};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

const URL_A: &str = "https://github.com/owner-a/repo-a";
const CANON_A: &str = "https://github.com/owner-a/repo-a";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn run(args: &[String], cwd: &Path, state: &Path) -> std::process::Output {
    repo_scan::privacy::private_dir_0700(state).expect("state dir");
    let mut full = vec![
        "--state-dir".to_string(),
        state.to_str().expect("utf8 state dir").to_string(),
    ];
    full.extend(args.iter().cloned());
    ProcCommand::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

fn run_str(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    run(&owned, cwd, state)
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).expect("read json");
    serde_json::from_slice(&bytes).expect("parse json")
}

fn scan(
    state: &Path,
    url: &str,
    roots: &[&Path],
    report: &Path,
    extra: &[&str],
) -> std::process::Output {
    let mut args: Vec<String> = vec![
        "scan".to_string(),
        url.to_string(),
        "--scope".to_string(),
        "roots".to_string(),
        "--report".to_string(),
        report.to_str().expect("utf8 report").to_string(),
    ];
    for r in roots {
        args.push("--root".to_string());
        args.push(r.to_str().expect("utf8 root").to_string());
    }
    for e in extra {
        args.push(e.to_string());
    }
    run(&args, state, state)
}

async fn open_store(db: &Path) -> TursoStore {
    TursoStore::open(db).await.expect("open catalog")
}

async fn seed_enum_task(store: &TursoStore, id: &str, generation: u64, path: &Path, now: i64) {
    let scope_key = repo_scan::config::scope_key_for_dir(path);
    let expected_rev = store.scope_rev(&scope_key).await.expect("scope rev");
    let idempotency = format!("idem:{id}");
    let inserted = store
        .enqueue_task(
            &NewTask {
                id,
                kind: "enumerate_dir",
                generation,
                dir_id: None,
                scope_key: &scope_key,
                expected_rev,
                idempotency_key: &idempotency,
            },
            now,
        )
        .await
        .expect("enqueue");
    assert!(inserted, "seeded task {id}");
}

/// RSF-7511725D-DC03-471A-9635-4F8173986489: production publication
/// verifies staged bytes and refuses invalid output. A deliberately
/// invalid staged report through the real publish path is refused before
/// anything is retained or shipped; a genuinely emitted report through
/// the same path publishes.
#[test]
fn rsf751_publish_refuses_invalid_staged() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let store = open_store(&db).await;
        let now = repo_scan::store::now_ms();
        let state = tmp.path().join("state");
        repo_scan::privacy::private_dir_0700(&state).unwrap();

        // Deliberately invalid staged bytes: not a report at all.
        let dest = tmp.path().join("bad-report.json");
        let err = main_under_test::test_verified_publish_bytes(
            &store,
            &state,
            "report-invalid",
            b"{ this is not a report",
            &dest,
            now,
        )
        .await
        .expect_err("invalid staged report must be refused");
        assert!(
            err.to_string().contains("refusing invalid staged report"),
            "refusal names the gate: {err}"
        );
        assert!(!dest.exists(), "destination untouched by refusal");
        let snapshots = state.join("payload").join("report-snapshots");
        let retained: Vec<_> = if snapshots.is_dir() {
            std::fs::read_dir(&snapshots)
                .unwrap()
                .filter_map(|e| e.ok())
                .collect()
        } else {
            Vec::new()
        };
        assert!(
            retained.is_empty(),
            "refused bytes are never retained: {retained:?}"
        );

        // Positive control through the same path: a genuinely emitted
        // report publishes.
        let root = tmp.path().join("root");
        repo_scan::privacy::private_dir_0700(&root).unwrap();
        fixture::normal_clone(&root, "repo");
        let estate = tmp.path().join("estate");
        let rep = tmp.path().join("rep.json");
        let out = scan(&estate, URL_A, &[&root], &rep, &["--status", "metadata"]);
        assert_eq!(out.status.code(), Some(0), "emitting scan: {out:?}");
        let emitted = std::fs::read(&rep).expect("emitted report");
        let emitted_value: serde_json::Value =
            serde_json::from_slice(&emitted).expect("parse emitted report");
        let emitted_report_id = emitted_value["report_id"]
            .as_str()
            .expect("emitted report ID");
        let dest2 = tmp.path().join("replay.json");
        let snapshot = main_under_test::test_verified_publish_bytes(
            &store,
            &state,
            emitted_report_id,
            &emitted,
            &dest2,
            now,
        )
        .await
        .expect("valid staged report publishes");
        assert!(snapshot.is_file(), "snapshot retained");
        assert!(dest2.is_file(), "destination published");
        assert_eq!(
            std::fs::read(&dest2).unwrap(),
            emitted,
            "published bytes match staged bytes"
        );
    });
}

/// RSF-3E2FDCF3-78C5-401A-84DD-A799688ED84F: the run loop claims only
/// its own generation's tasks. Two generations are seeded; a run-loop
/// resume of the first leaves the second untouched, and vice versa.
#[test]
fn rsf3e2_run_loop_claims_only_own_generation() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir1 = tmp.path().join("d1");
        let dir2 = tmp.path().join("d2");
        repo_scan::privacy::private_dir_0700(&dir1).unwrap();
        repo_scan::privacy::private_dir_0700(&dir2).unwrap();
        repo_scan::privacy::private_write_0600(&dir1.join("f.txt"), b"one").unwrap();
        repo_scan::privacy::private_write_0600(&dir2.join("f.txt"), b"two").unwrap();

        let db = tmp.path().join("catalog.db");
        let store = open_store(&db).await;
        let epoch = store.epoch();
        let now = repo_scan::store::now_ms();
        let gen1 = store
            .create_generation("roots", "running", None, now)
            .await
            .expect("gen1");
        let gen2 = store
            .create_generation("roots", "running", None, now)
            .await
            .expect("gen2");
        assert_ne!(gen1, gen2);
        seed_enum_task(&store, "task-gen1", gen1, &dir1, now).await;
        seed_enum_task(&store, "task-gen2", gen2, &dir2, now).await;

        // Run-loop resume of generation 1 only.
        let stats = main_under_test::test_run_boundary(
            &store,
            epoch,
            gen1,
            1,
            CANON_A,
            StatusMode::Metadata,
            "scan-rsf3e2",
        )
        .await
        .expect("run gen1");
        assert!(stats.dirs_complete >= 1, "gen1 work done: {stats:?}");
        let t1 = store
            .get_task("task-gen1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(t1.state, TaskState::Complete, "gen1 task complete");
        let t2 = store
            .get_task("task-gen2")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(t2.state, TaskState::Pending, "gen2 task still pending");
        assert_eq!(t2.attempts, 0, "gen2 task never claimed by the gen1 run");

        // Run-loop resume of generation 2 only.
        let stats = main_under_test::test_run_boundary(
            &store,
            epoch,
            gen2,
            1,
            CANON_A,
            StatusMode::Metadata,
            "scan-rsf3e2b",
        )
        .await
        .expect("run gen2");
        assert!(stats.dirs_complete >= 1, "gen2 work done");
        let t2 = store
            .get_task("task-gen2")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(t2.state, TaskState::Complete, "gen2 task complete");
        let t1 = store
            .get_task("task-gen1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(t1.attempts, 1, "gen1 task not reclaimed by the gen2 run");
    });
}

/// RSF-AC461500-609D-4D55-991E-09C60D382D67: scan writes use WriterBatch
/// buffering with CheckpointCoordinator cadence. A run-loop drive over
/// real directory tasks moves the batch counters (commits + ops) and
/// the WAL-probe counter.
#[test]
fn rsf_ac46_batch_and_checkpoint_cadence() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("root");
        repo_scan::privacy::private_dir_0700(&root.join("a")).unwrap();
        repo_scan::privacy::private_dir_0700(&root.join("b")).unwrap();
        repo_scan::privacy::private_write_0600(&root.join("a").join("f.txt"), b"a").unwrap();
        repo_scan::privacy::private_write_0600(&root.join("b").join("f.txt"), b"b").unwrap();

        let db = tmp.path().join("catalog.db");
        let store = open_store(&db).await;
        let epoch = store.epoch();
        let now = repo_scan::store::now_ms();
        let gen = store
            .create_generation("roots", "running", None, now)
            .await
            .expect("gen");
        seed_enum_task(&store, "task-root", gen, &root, now).await;

        // Eager policy: a probe is due after every applied op so the
        // cadence is observable in one bounded run.
        let stats = main_under_test::test_run_boundary_with_checkpoint(
            &store,
            epoch,
            gen,
            1,
            CANON_A,
            StatusMode::Metadata,
            "scan-rsfac46",
            1,
        )
        .await
        .expect("run");
        assert!(stats.dirs_complete >= 3, "root + children done: {stats:?}");
        assert!(
            stats.batch_commits >= 1,
            "writer batches committed: {stats:?}"
        );
        assert!(stats.batch_ops >= 1, "batched ops applied: {stats:?}");
        assert!(
            stats.wal_probes >= 1,
            "wal_status probed from the loop: {stats:?}"
        );
    });
}

/// RSF-02C3154D-7D7A-420E-A0C5-EA763B8B327D: `query --cached` reads
/// through `open_read_only` — it is served while the owner write lock
/// is held elsewhere and leaves catalog bytes unchanged.
#[test]
fn rsf02c3_cached_query_readonly_under_lock() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    let repo = fixture::normal_clone(&root, "repo");
    fixture::git(&repo, &["remote", "set-url", "origin", URL_A]);
    let state = tmp.path().join("state");
    let rep = tmp.path().join("rep.json");
    let out = scan(&state, URL_A, &[&root], &rep, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "scan: {out:?}");

    let db_path = state.join("payload").join("catalog.db");
    let before = std::fs::read(&db_path).expect("catalog bytes before");
    let wal_path = db_path.with_extension("db-wal");
    let wal_before = std::fs::read(&wal_path).unwrap_or_default();

    // Hold the owner write lock in this process for the whole query.
    let _guard = repo_scan::store::OwnerGuard::acquire(&state).expect("hold owner lock");
    let out = run_str(&["query", URL_A, "--cached"], &state, &state);
    assert_eq!(out.status.code(), Some(0), "cached query served: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("cached: true"), "cached marker: {stdout}");
    drop(_guard);

    let after = std::fs::read(&db_path).expect("catalog bytes after");
    assert_eq!(before, after, "catalog bytes unchanged by cached query");
    let wal_after = std::fs::read(&wal_path).unwrap_or_default();
    assert_eq!(wal_before, wal_after, "WAL bytes unchanged by cached query");
}

/// RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1: the run loop samples its
/// footprint and the report carries measured resources (never
/// None-after-run); catalog derivation scans page in bounded chunks, so
/// a large-errors fixture scans completely with a bounded peak chunk.
#[test]
fn rsf23d_measured_resources_and_bounded_loads() {
    // Measured resources end to end: no None-after-run.
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    fixture::normal_clone(&root, "repo");
    let state = tmp.path().join("state");
    let rep = tmp.path().join("rep.json");
    let out = scan(&state, URL_A, &[&root], &rep, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "scan: {out:?}");
    let report = read_json(&rep);
    let resources = &report["resources"];
    assert!(
        resources["peak_rss_bytes"].is_number(),
        "measured peak_rss_bytes: {resources}"
    );
    assert!(
        resources["cpu_seconds"].is_number(),
        "measured cpu_seconds: {resources}"
    );
    assert!(
        resources["db_sync_calls"].is_number(),
        "measured db_sync_calls: {resources}"
    );
    assert!(
        resources["db_sync_calls"].as_u64().unwrap_or(0) >= 1,
        "at least one sync call measured: {resources}"
    );

    // Bounded chunked loads over a large-errors fixture through the
    // production derivation scan.
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let store = open_store(&db).await;
        let now = repo_scan::store::now_ms();
        // Pure coverage gaps: non-candidate categories on scopes no root
        // matches, so derived output stays empty however many gaps exist.
        let seeded: usize = 1200;
        for n in 0..seeded {
            store
                .record_error(
                    &format!("gap-{n:05}"),
                    "dir:424242",
                    "stat-error",
                    "synthetic gap for bounded-load proof",
                    None,
                    now,
                )
                .await
                .expect("seed gap");
        }
        let scan = main_under_test::test_scan_error_derivations(&store, &[String::from("dir:1")])
            .await
            .expect("chunked error scan");
        assert_eq!(scan.scanned, seeded as u64, "every gap scanned");
        assert!(scan.chunks > 1, "more than one chunk: {scan:?}");
        assert!(scan.peak_chunk <= 512, "peak chunk bounded: {scan:?}");
        assert_eq!(scan.candidates, 0, "no candidates from pure gaps");

        // Run-loop telemetry is measured, not None.
        let dir = tmp.path().join("d");
        repo_scan::privacy::private_dir_0700(&dir).unwrap();
        repo_scan::privacy::private_write_0600(&dir.join("f.txt"), b"x").unwrap();
        let gen = store
            .create_generation("roots", "running", None, now)
            .await
            .expect("gen");
        seed_enum_task(&store, "task-t", gen, &dir, now).await;
        let stats = main_under_test::test_run_boundary(
            &store,
            store.epoch(),
            gen,
            1,
            CANON_A,
            StatusMode::Metadata,
            "scan-rsf23d",
        )
        .await
        .expect("run");
        // Owner RSS reads are implemented on macOS/Linux; other
        // targets report 0 by documented design.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(stats.peak_rss_bytes > 0, "peak RSS measured: {stats:?}");
        assert!(stats.cpu_seconds >= 0.0, "CPU measured: {stats:?}");
        assert!(stats.db_sync_calls >= 1, "syncs measured: {stats:?}");
        assert!(!stats.pressure, "no pressure on a tiny run: {stats:?}");
    });
}

/// RSF-AD9D4AF7-3CC3-4B37-8168-E78DD6375C5B: the watchdog distinguishes
/// blocked from advancing; a contained task never clears its containment
/// via success-after-timeout. Driven through the production run loop
/// with a zero grace so every task is evaluated for timeout.
#[test]
fn rsf_ad9d_watchdog_blocked_vs_advancing() {
    assert_eq!(
        main_under_test::test_watchdog_verdict(false, false),
        "within_grace"
    );
    assert_eq!(
        main_under_test::test_watchdog_verdict(false, true),
        "within_grace"
    );
    assert_eq!(
        main_under_test::test_watchdog_verdict(true, true),
        "advancing"
    );
    assert_eq!(
        main_under_test::test_watchdog_verdict(true, false),
        "contained"
    );

    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Flat directory: entries advance, no children, no probes.
        let dir = tmp.path().join("d");
        repo_scan::privacy::private_dir_0700(&dir).unwrap();
        repo_scan::privacy::private_write_0600(&dir.join("a.txt"), b"a").unwrap();
        repo_scan::privacy::private_write_0600(&dir.join("b.txt"), b"b").unwrap();

        let db = tmp.path().join("catalog.db");
        let store = open_store(&db).await;
        let epoch = store.epoch();
        let now = repo_scan::store::now_ms();
        let gen = store
            .create_generation("roots", "running", None, now)
            .await
            .expect("gen");
        seed_enum_task(&store, "task-advancing", gen, &dir, now).await;
        // Marker reconcile: completes with no entries (blocked-shaped).
        let scope_key = String::from("volume:rsf-ad9d");
        let expected_rev = store.scope_rev(&scope_key).await.expect("rev");
        store
            .enqueue_task(
                &NewTask {
                    id: "task-blocked",
                    kind: "reconcile",
                    generation: gen,
                    dir_id: None,
                    scope_key: &scope_key,
                    expected_rev,
                    idempotency_key: "idem:task-blocked",
                },
                now,
            )
            .await
            .expect("enqueue marker");

        let stats = main_under_test::test_run_boundary_with_grace(
            &store,
            epoch,
            gen,
            1,
            CANON_A,
            StatusMode::Metadata,
            "scan-rsfad9d",
            0,
        )
        .await
        .expect("run");
        assert_eq!(stats.claimed, 2, "both tasks ran: {stats:?}");
        assert_eq!(stats.watchdog_trips, 2, "both evaluated: {stats:?}");
        // The advancing enumeration is not contained despite the timeout.
        assert!(
            stats.breakers_open.iter().all(|b| !b.starts_with("dev:")),
            "advancing volume not contained: {stats:?}"
        );
        // The non-advancing marker is contained — and stays contained:
        // its Ok completion must not clear via success-after-timeout.
        assert!(
            stats.breakers_open.iter().any(|b| b == "status"),
            "blocked marker contained: {stats:?}"
        );
    });
}

/// RSF-CHAINARGOS-PROGRESS-001: progress emits at most 2 Hz through the
/// token-timer gate and every line carries scan position (current
/// root/volume), pending work, and elapsed time.
#[test]
fn rsf_chainargos_progress_rate_and_content() {
    // Burst through the real gate: first passes, followers coalesce.
    let verdicts = main_under_test::test_progress_burst(10);
    assert_eq!(verdicts.len(), 10);
    assert!(verdicts[0], "first tick passes");
    assert!(
        verdicts[1..].iter().all(|v| !v),
        "burst coalesced at 2 Hz: {verdicts:?}"
    );

    // Timed sample: closed inside the 500 ms interval, open past it.
    let (first, immediate, after_interval) = main_under_test::test_progress_timed();
    assert!(first, "first tick passes");
    assert!(!immediate, "immediate re-tick blocked (2 Hz ceiling)");
    assert!(after_interval, "tick reopens after the interval");

    // Content through the real formatter.
    let line = main_under_test::test_format_progress(10, 9, 100, 1, 5, 42, "dir:/tmp/x", "dev:123");
    for needle in ["pending=5", "elapsed=42s", "dir:/tmp/x", "dev:123"] {
        assert!(line.contains(needle), "progress carries {needle}: {line}");
    }

    // The binary's stderr progress carries the same context end to end.
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    fixture::normal_clone(&root, "repo");
    let state = tmp.path().join("state");
    let rep = tmp.path().join("rep.json");
    let out = scan(&state, URL_A, &[&root], &rep, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "scan: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.lines().any(|l| l.contains("pending=")
            && l.contains("elapsed=")
            && l.contains("scope=")
            && l.contains("volume=")),
        "stderr progress context: {stderr}"
    );
}
