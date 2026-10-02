//! Focused regressions for lease durability (RESOURCE-RECHECK R4): the
//! scheduler-layer renewal heartbeat keeps long probe/status operations
//! alive, lost leases report false (never touching another owner's lease),
//! and the production store never reclaims a renewed lease — valid work is
//! never reclaimed and duplicated.
//!
//! All databases live in tempdirs; timestamps are passed explicitly, so no
//! test sleeps. A current-thread Tokio runtime drives the async store paths.

use repo_scan::model::{Epoch, GenerationId, TaskState};
use repo_scan::scheduler::{
    DurableScheduler, MemorySchedulerStore, Scheduler, SchedulerStore, Task, TaskKind, TaskOutcome,
};
use repo_scan::store::{now_ms, NewTask, Store, TaskOutcome as StoreOutcome, TursoStore};
use std::time::{Duration, SystemTime};

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn db_in(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("payload").join("catalog.db")
}

fn fixture_task(id: &str, scope: &str) -> Task {
    Task {
        id: id.to_string(),
        epoch: Epoch(1),
        generation: GenerationId(1),
        kind: TaskKind::ProbeGit,
        scope_key: scope.to_string(),
        expected_revision: 0,
        idempotency_key: id.to_string(),
        state: TaskState::Pending,
        not_before: None,
    }
}

fn never_skip(_: &str) -> bool {
    false
}

fn complete_empty() -> TaskOutcome {
    TaskOutcome::Complete {
        children: vec![],
        candidates: vec![],
    }
}

/// R4: a 300 s probe/status op renewing every 20 s keeps its 60 s lease
/// alive for the whole operation, and no rival claim can take the task
/// mid-operation (never reclaimed, never duplicated). Fully deterministic:
/// every transition runs at an explicit timestamp.
#[test]
fn scheduler_heartbeat_keeps_long_op_alive() {
    let mut sched = DurableScheduler::new(MemorySchedulerStore::new());
    sched
        .store_mut()
        .insert_task(fixture_task("probe-a", "scope-a"));
    let t0 = SystemTime::now();
    let ttl = Duration::from_secs(60);
    let claimed = sched
        .store_mut()
        .claim_eligible(Epoch(1), 10, ttl, t0, &never_skip)
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    let lease = claimed[0].1.clone();
    let mut now = t0;
    for _ in 0..15 {
        now = now.checked_add(Duration::from_secs(20)).expect("step");
        assert!(
            sched
                .store_mut()
                .renew_lease(&lease, ttl, now)
                .expect("renew"),
            "heartbeat holds the lease at {now:?}"
        );
        sched.store_mut().expire_leases(now);
        let rivals = sched
            .store_mut()
            .claim_eligible(Epoch(2), 10, ttl, now, &never_skip)
            .expect("rival claim");
        assert!(rivals.is_empty(), "renewed lease never reclaimable");
    }
    // Same lease, five minutes past its original expiry: still completes.
    sched.complete(&lease, complete_empty()).expect("complete");
    let tasks = sched.store().all_tasks();
    assert_eq!(
        tasks.iter().find(|t| t.id == "probe-a").unwrap().state,
        TaskState::Complete
    );
}

/// R4: the scheduler-level renewal wrapper extends a live lease.
#[test]
fn scheduler_renew_wrapper_extends_live_lease() {
    let mut sched = DurableScheduler::new(MemorySchedulerStore::new());
    sched
        .store_mut()
        .insert_task(fixture_task("probe-b", "scope-b"));
    let claimed = sched
        .claim(Epoch(1), 1, Duration::from_secs(60))
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert!(sched
        .renew_lease(&claimed[0].1, Duration::from_secs(60))
        .expect("renew"));
    sched
        .complete(&claimed[0].1, complete_empty())
        .expect("complete");
}

/// R4: without a heartbeat the lease lapses and is reclaimed exactly once;
/// the stale lease then renews false (never touching the new owner's
/// lease) and its completion is fenced, while the new lease completes.
#[test]
fn scheduler_lost_lease_reports_false_and_fences_completion() {
    let mut sched = DurableScheduler::new(MemorySchedulerStore::new());
    sched
        .store_mut()
        .insert_task(fixture_task("probe-c", "scope-c"));
    let t0 = SystemTime::now();
    let ttl = Duration::from_secs(60);
    let claimed = sched
        .store_mut()
        .claim_eligible(Epoch(1), 10, ttl, t0, &never_skip)
        .expect("claim");
    let stale = claimed[0].1.clone();
    // No heartbeat: past the 60 s TTL the lease lapses ...
    let lapsed = t0.checked_add(Duration::from_secs(61)).expect("lapse");
    sched.store_mut().expire_leases(lapsed);
    // ... and the next claim reclaims the task exactly once, new token.
    let reclaimed = sched
        .store_mut()
        .claim_eligible(Epoch(1), 10, ttl, lapsed, &never_skip)
        .expect("reclaim");
    assert_eq!(reclaimed.len(), 1);
    assert_ne!(reclaimed[0].1.token, stale.token);
    let again = sched
        .store_mut()
        .claim_eligible(Epoch(1), 10, ttl, lapsed, &never_skip)
        .expect("reclaim again");
    assert!(again.is_empty(), "one owner at a time");
    // The stale lease renews false and its completion is fenced ...
    assert!(!sched
        .store_mut()
        .renew_lease(&stale, ttl, lapsed)
        .expect("stale renew"));
    let fenced = sched.complete(&stale, complete_empty()).unwrap_err();
    assert!(
        fenced.to_string().contains("stale or superseded"),
        "{fenced}"
    );
    // ... while the new owner's lease is intact: it survives expiry
    // processing just inside its own window, renews, and completes.
    sched
        .store_mut()
        .expire_leases(lapsed.checked_add(Duration::from_secs(59)).expect("window"));
    let tasks = sched.store().all_tasks();
    assert_eq!(
        tasks.iter().find(|t| t.id == "probe-c").unwrap().state,
        TaskState::Leased
    );
    assert!(sched
        .store_mut()
        .renew_lease(&reclaimed[0].1, ttl, lapsed)
        .expect("rival renew"));
    sched
        .complete(&reclaimed[0].1, complete_empty())
        .expect("rival complete");
}

/// R4 on the production store: heartbeats across a simulated 300 s probe
/// keep the task leased (rival claims find nothing, expiry moves nothing);
/// once the beats stop, the lease lapses and is reclaimed exactly once,
/// and the old token can no longer complete. Explicit timestamps only.
#[test]
fn store_heartbeat_prevents_reclaim_across_long_op() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = db_in(&dir);
        let store = TursoStore::open(&db).await.expect("open");
        let epoch = store.epoch();
        let t0 = now_ms();
        let ttl = 60_000i64;
        store
            .enqueue_task(
                &NewTask {
                    id: "t-probe",
                    kind: "probe_git",
                    generation: 1,
                    dir_id: None,
                    scope_key: "s",
                    expected_rev: 0,
                    idempotency_key: "idem-probe",
                },
                t0,
            )
            .await
            .expect("enqueue");
        let claimed = store.claim_tasks(epoch, 10, ttl, t0).await.expect("claim");
        assert_eq!(claimed.len(), 1);
        let token = claimed[0].token;
        // Fifteen 20 s heartbeats: the renewal extends the expiry, the
        // expiry sweep moves nothing, and no rival claim takes the task.
        let mut now = t0;
        for step in 0..15 {
            now += 20_000;
            assert!(store
                .renew_lease("t-probe", token, epoch, ttl, now)
                .await
                .expect("renew"));
            if step == 0 {
                let task = store.get_task("t-probe").await.expect("get").expect("row");
                assert_eq!(task.lease_expires_ms, Some(now + ttl));
            }
            assert_eq!(store.expire_leases(now).await.expect("expire"), 0);
            let rivals = store
                .claim_tasks(epoch, 10, ttl, now)
                .await
                .expect("rival claim");
            assert!(rivals.is_empty(), "renewed lease never reclaimable");
        }
        // Beats stop: past the last extension the lease lapses, returns to
        // pending, and is reclaimed exactly once with a fresh token.
        let lapsed = now + ttl + 1;
        assert_eq!(store.expire_leases(lapsed).await.expect("expire"), 1);
        let reclaimed = store
            .claim_tasks(epoch, 10, ttl, lapsed)
            .await
            .expect("reclaim");
        assert_eq!(reclaimed.len(), 1);
        assert_ne!(reclaimed[0].token, token);
        let fenced = store
            .complete_task("t-probe", token, epoch, &StoreOutcome::Complete, lapsed)
            .await
            .unwrap_err();
        assert!(fenced.to_string().contains("lease-mismatch"), "{fenced}");
        store
            .complete_task(
                "t-probe",
                reclaimed[0].token,
                epoch,
                &StoreOutcome::Complete,
                lapsed,
            )
            .await
            .expect("rival complete");
    });
}

/// R4: the blocking status call runs under the tighter of the remaining
/// wall budget and the freshly-renewed lease window (60 s TTL minus 15 s
/// margin); a window abandonment retries with a fresh lease, never parks.
#[test]
fn status_call_budget_bounded_by_lease_window() {
    // Fresh op: the 300 s wall budget yields to the 45 s lease window.
    assert_eq!(
        main_under_test::test_lease_call_budget(300_000),
        (45_000, true)
    );
    // Late op: the remaining wall budget is already tighter — unchanged.
    assert_eq!(
        main_under_test::test_lease_call_budget(10_000),
        (10_000, false)
    );
    // Boundary: exactly the window — the wall budget governs, no lease flag.
    assert_eq!(
        main_under_test::test_lease_call_budget(45_000),
        (45_000, false)
    );
}

/// R04: on a slow filesystem (e.g. NFS/SMB with high latency), reading few entries
/// takes longer than the 60s lease TTL. The time-aware renewal policy (renewing every
/// 20s) keeps the lease alive continuously, whereas the legacy policy (renewing only
/// every 256 entries) would have let the lease lapse and be reclaimed.
#[test]
fn r04_slow_mount_renewal_before_ttl_lapses() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = db_in(&dir);
        let store = TursoStore::open(&db).await.expect("open");
        let epoch = store.epoch();
        let t0 = now_ms();
        let ttl = 60_000i64;
        store
            .enqueue_task(
                &NewTask {
                    id: "t-slow-enum",
                    kind: "enumerate_dir",
                    generation: 1,
                    dir_id: None,
                    scope_key: "s-slow",
                    expected_rev: 0,
                    idempotency_key: "idem-slow-enum",
                },
                t0,
            )
            .await
            .expect("enqueue");
        let claimed = store.claim_tasks(epoch, 10, ttl, t0).await.expect("claim");
        assert_eq!(claimed.len(), 1);
        let token = claimed[0].token;

        // Simulate 4 steps of 20 seconds each (total 80 seconds).
        // In each step, only 2 entries are processed (total 8 entries << 256).
        // Under legacy policy (every 256 entries):
        //   lease_renewal_expiry(2, 256, ...) -> None
        //   At t0 + 61_000, lease expires and is reclaimed!
        // Under R04 time-aware policy:
        //   lease_renewal_expiry_elapsed(entries, 20s, 20s, now, 60s) -> Some(now + 60s)
        //   Lease is renewed at each 20s step, surviving 80s of slow traversal!
        let mut now = t0;
        let mut entries_seen = 0u64;
        for _step in 1..=4 {
            now += 20_000;
            entries_seen += 2;
            let expiry = repo_scan::scheduler::admission::lease_renewal_expiry_elapsed(
                entries_seen,
                Duration::from_secs(20),
                Duration::from_secs(20),
                now,
                ttl,
            )
            .expect("renewal due every 20s");
            assert_eq!(expiry, now + ttl);

            assert!(store
                .renew_lease("t-slow-enum", token, epoch, ttl, now)
                .await
                .expect("renew"));
            assert_eq!(store.expire_leases(now).await.expect("expire"), 0);
        }

        // At 80 seconds past admission, task is still validly leased to the original owner:
        let task = store
            .get_task("t-slow-enum")
            .await
            .expect("get")
            .expect("task");
        assert_eq!(task.state, TaskState::Leased);
        assert_eq!(task.lease_token, Some(token));

        store.close().await.expect("close");
    });
}
