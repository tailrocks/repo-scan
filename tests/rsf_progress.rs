//! RSF-F286/23D/RESUME-002/SPEED-003 progress-output regression tests.
//!
//! Drives the production progress formatter, ETA, totals load, 2 Hz gate
//! (`src/main.rs` included as a module, same as `tests/rsf_main.rs`) and the
//! production telemetry sampler (`src/telemetry.rs`) on bounded fixtures
//! under tempdirs only — never a machine scan.

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

use repo_scan::store::{NewTask, Store, TaskOutcome, TursoStore};
use repo_scan::telemetry::{
    live_helper_rss_bytes, rss_is_peak, FootprintSampler, SamplerInputs, Telemetry,
};
use std::path::Path;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

async fn open_store(db: &Path) -> TursoStore {
    TursoStore::open(db).await.expect("open catalog")
}

/// RSF-F2865989 + SPEED-003: progress carries a frontier denominator and a
/// defensible ETA, or an explicit unknown with reason — never a silent gap.
#[test]
fn rsf_f286_denominator_and_eta_or_explicit_unknown() {
    // Known ETA from this session's rate: 100 claimed / 10 s = 10 tasks/s,
    // 50 pending / 10 = ~5 s lower bound.
    assert_eq!(
        main_under_test::test_format_eta(100, 50, 10),
        "~5s (lower bound; denominator grows with discovery)"
    );
    assert_eq!(main_under_test::test_format_eta(10, 0, 10), "0s");
    for (claimed, pending, elapsed, reason) in [
        (10, 5, 0, "warming-up"),
        (10, 5, 1, "warming-up"),
        (0, 5, 10, "no session progress yet"),
    ] {
        let eta = main_under_test::test_format_eta(claimed, pending, elapsed);
        assert!(
            eta.starts_with("unknown (") && eta.contains(reason),
            "explicit unknown with reason: {eta}"
        );
    }

    // Full line carries denominator, pending, rate, ETA, and the scope-total
    // unknown with its reason.
    let line = main_under_test::test_format_progress_full(
        100,
        90,
        1000,
        1,
        50,
        150,
        90,
        1000,
        10,
        "dir:/tmp/x",
        "dev:123",
    );
    for needle in [
        "tasks_done=100/150",
        "pending=50",
        "rate=10.0 tasks/s",
        "eta=~5s",
        "elapsed=10s",
        "scope_total=unknown (full machine dir count unknowable until traversal completes)",
        "dir:/tmp/x",
        "dev:123",
    ] {
        assert!(line.contains(needle), "progress carries {needle}: {line}");
    }

    // Legacy entry without store totals: explicit unknowns with reasons.
    let legacy =
        main_under_test::test_format_progress(10, 9, 100, 1, 5, 42, "dir:/tmp/x", "dev:123");
    for needle in [
        "cumulative(scan total)=unknown (store totals not loaded in this context)",
        "tasks_total=unknown (frontier denominator not loaded)",
        "pending=5",
        "elapsed=42s",
        "eta=",
    ] {
        assert!(legacy.contains(needle), "legacy line: {needle}: {legacy}");
    }
}

/// RSF-CHAINARGOS-RESUME-002: session vs cumulative labels keep a resume
/// starting at 1/1/1 unambiguous.
#[test]
fn rsf_resume002_session_vs_cumulative_labels() {
    // Resumed run: this session just started (1/1/1) while the scan total
    // across resumes is already large.
    let line = main_under_test::test_format_progress_full(
        1,
        1,
        1,
        0,
        812,
        30000,
        29188,
        122631,
        513,
        "dir:/tmp/y",
        "dev:7",
    );
    for needle in [
        "session(this run): claimed=1 dirs=1 entries=1",
        "cumulative(scan total): tasks_done=29188/30000 dirs=29188 entries=122631",
        "pending=812",
    ] {
        assert!(
            line.contains(needle),
            "resume-at-1 unambiguous: {needle}: {line}"
        );
    }
    assert!(
        !line.contains("(this run): 1 claimed, 1 dirs"),
        "old ambiguous shape is gone: {line}"
    );
}

/// RSF-CHAINARGOS-SPEED-003: pending totals and cumulative denominators come
/// from the store for this generation (bounded fixture, tempdir only).
#[test]
fn rsf_speed003_store_pending_and_cumulative_totals() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let store = open_store(&db).await;
        let now = repo_scan::store::now_ms();
        let gen = store
            .create_generation("roots", "running", None, now)
            .await
            .expect("gen");
        for (id, name) in [("task-a", "a"), ("task-b", "b"), ("task-c", "c")] {
            let dir = tmp.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let scope = repo_scan::config::scope_key_for_dir(&dir);
            let rev = store.scope_rev(&scope).await.expect("rev");
            let idem = format!("idem:{id}");
            assert!(
                store
                    .enqueue_task(
                        &NewTask {
                            id,
                            kind: "enumerate_dir",
                            generation: gen,
                            dir_id: None,
                            scope_key: &scope,
                            expected_rev: rev,
                            idempotency_key: &idem,
                        },
                        now,
                    )
                    .await
                    .expect("enqueue"),
                "seeded {id}"
            );
        }
        // One task done, two pending: denominator 3.
        let claimed = store
            .claim_tasks_in_generation(gen, store.epoch(), 8, 60_000, now)
            .await
            .expect("claim");
        assert!(!claimed.is_empty());
        store
            .complete_task(
                &claimed[0].task.id,
                claimed[0].token,
                store.epoch(),
                &TaskOutcome::Complete,
                now,
            )
            .await
            .expect("complete");
        store
            .record_dir_observation(1, gen, true, 1, 10, None, now)
            .await
            .expect("obs 1");
        store
            .record_dir_observation(2, gen, true, 1, 20, None, now)
            .await
            .expect("obs 2");

        let (pending, total, cum_dirs, cum_entries) =
            main_under_test::test_load_progress_totals(&store, gen)
                .await
                .expect("totals");
        assert_eq!((pending, total, cum_dirs, cum_entries), (2, 3, 2, 30));

        let line = main_under_test::test_format_progress_full(
            5,
            4,
            40,
            0,
            pending,
            total,
            cum_dirs,
            cum_entries,
            10,
            "dir:/tmp/z",
            "dev:9",
        );
        for needle in ["tasks_done=1/3", "dirs=2", "entries=30", "pending=2"] {
            assert!(
                line.contains(needle),
                "store totals on the line: {needle}: {line}"
            );
        }
    });
}

/// RSF-23D074E0: helper CPU is measured (reaped children + retained input),
/// helper RSS is measured or an honest unknown — never a hardcoded fake zero.
/// The macOS `ru_maxrss` peak stays labeled peak.
#[test]
fn rsf_23d_helper_telemetry_honesty() {
    // Honesty helper: measured zero vs honest unknown.
    assert_eq!(live_helper_rss_bytes(0), Some(0));
    assert_eq!(live_helper_rss_bytes(3), None);

    let sampler = FootprintSampler::new();
    // No helpers: measured zero folds in; aggregate equals owner.
    let zero = sampler.sample_with(&SamplerInputs {
        helpers_rss_bytes: Some(0),
        helpers: 0,
        ..SamplerInputs::default()
    });
    assert_eq!(zero.helpers_rss_bytes, Some(0));
    assert_eq!(zero.aggregate_rss_bytes, zero.owner_rss_bytes);
    // Live helpers without instrumentation: honest unknown; aggregate is
    // explicitly owner-only, not owner-plus-fake-zero.
    let unknown = sampler.sample_with(&SamplerInputs {
        helpers_rss_bytes: None,
        helpers: 2,
        ..SamplerInputs::default()
    });
    assert_eq!(unknown.helpers_rss_bytes, None);
    assert_eq!(unknown.aggregate_rss_bytes, unknown.owner_rss_bytes);
    // Reaped-children CPU is measured on top of owner + retained input, and
    // retained helper CPU still cannot be reset by respawning.
    let retained = sampler.sample_with(&SamplerInputs {
        helpers_cpu_seconds: 42.0,
        helpers: 0,
        ..SamplerInputs::default()
    });
    assert!(retained.cpu_seconds >= 42.0, "helper CPU folded in");
    assert!(retained.children_cpu_seconds >= 0.0);
    assert!(retained.owner_cpu_seconds >= 0.0);
    assert_eq!(retained.rss_is_peak, rss_is_peak());

    let method = sampler.accounting_method();
    for needle in ["RUSAGE_CHILDREN", "None=honest unknown"] {
        assert!(
            method.contains(needle),
            "method discloses {needle}: {method}"
        );
    }
    assert!(
        method.contains("peak") || method.contains("PEAK"),
        "peak stays labeled: {method}"
    );
    #[cfg(target_os = "macos")]
    assert!(
        method.contains("PEAK") && rss_is_peak(),
        "macOS ru_maxrss peak labeled: {method}"
    );
    #[cfg(not(target_os = "macos"))]
    assert!(!rss_is_peak(), "only macOS uses the peak stand-in");
}

/// The 2 Hz progress ceiling still holds after the content changes.
#[test]
fn rsf_progress_2hz_bound_kept() {
    let verdicts = main_under_test::test_progress_burst(10);
    assert_eq!(verdicts.len(), 10);
    assert!(verdicts[0], "first tick passes");
    assert!(
        verdicts[1..].iter().all(|v| !v),
        "burst coalesced at 2 Hz: {verdicts:?}"
    );
    let (first, immediate, after_interval) = main_under_test::test_progress_timed();
    assert!(first, "first tick passes");
    assert!(!immediate, "immediate re-tick blocked (2 Hz ceiling)");
    assert!(after_interval, "tick reopens after the interval");
}
