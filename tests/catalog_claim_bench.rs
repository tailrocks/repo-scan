//! Wave5 claim microbench (Step 9): time `claim_tasks_in_generation` at
//! pending-queue depths of 1k / 100k / 1M.
//!
//! Run with timings visible:
//! `cargo test --test catalog_claim_bench -- --nocapture [--ignored]`
//!
//! The 1k case always runs (fast). The 100k/1M cases are `#[ignore]` so
//! the default suite stays fast; run them explicitly for before/after
//! evidence.

use repo_scan::store::{now_ms, NewTask, Store, TaskOutcome, TursoStore, WriterBatch};
use std::path::PathBuf;
use std::time::Instant;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn db_in(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("payload").join("catalog.db")
}

/// Seed `n` pending tasks in `generation`: mostly `enumerate_dir` (the
/// production backlog shape), with a few probe/reconcile/status rows so
/// the R06 interleave has work to do. Uses large unbatched-limit flushes
/// (seed-only; production honors the 512-row WriterBatch limits).
async fn seed(store: &TursoStore, generation: u64, n: usize, now: i64) {
    let mut batch = WriterBatch::new();
    for i in 0..n {
        let (id, kind, scope) = if i % 1000 == 0 {
            (format!("probe:{generation}:repo{i}"), "probe_git", "git:00")
        } else if i % 1000 == 1 {
            (
                format!("reconcile:{generation}:vol{i}"),
                "reconcile",
                "vol:00",
            )
        } else if i % 500 == 2 {
            (
                format!("status:repo{i}:{generation}"),
                "status",
                "status:00",
            )
        } else {
            (
                format!("enum:{generation}:d{i}:i{i}"),
                "enumerate_dir",
                "dir:00",
            )
        };
        let idem = format!("idem:{id}");
        let task = NewTask {
            id: &id,
            kind,
            generation,
            dir_id: None,
            scope_key: scope,
            expected_rev: 0,
            idempotency_key: &idem,
        };
        TursoStore::buffer_enqueue_task(&mut batch, &task, now);
        if i % 20_000 == 19_999 {
            store.flush(&mut batch).await.expect("seed flush");
        }
    }
    store.flush(&mut batch).await.expect("seed flush");
}

async fn time_claim(depth: usize) -> (u128, usize) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = TursoStore::open(&db_in(&dir)).await.expect("open");
    let epoch = store.epoch();
    let now = now_ms();
    seed(&store, 1, depth, now).await;
    // Production claim shape: CLAIM_BATCH=16, discovery kinds.
    let start = Instant::now();
    let claimed = store
        .claim_tasks_in_generation_kinds(
            1,
            epoch,
            16,
            60_000,
            now,
            &["enumerate_dir", "probe_git", "reconcile"],
        )
        .await
        .expect("claim");
    let elapsed_us = start.elapsed().as_micros();
    println!(
        "claim depth={depth} limit=16 kinds=3 -> {} tasks in {elapsed_us} us",
        claimed.len()
    );
    // Second round: queue still huge, measures steady-state rounds.
    let start = Instant::now();
    let claimed2 = store
        .claim_tasks_in_generation_kinds(
            1,
            epoch,
            16,
            60_000,
            now,
            &["enumerate_dir", "probe_git", "reconcile"],
        )
        .await
        .expect("claim2");
    let elapsed2_us = start.elapsed().as_micros();
    println!(
        "claim depth={} limit=16 kinds=3 (round 2) -> {} tasks in {elapsed2_us} us",
        depth - claimed.len(),
        claimed2.len()
    );
    store.close().await.expect("close");
    (elapsed_us, claimed.len())
}

#[test]
fn claim_bench_1k() {
    let rt = runtime();
    rt.block_on(async {
        let (us, n) = time_claim(1_000).await;
        assert_eq!(n, 16);
        println!("BENCH claim/1k = {us} us");
    });
}

#[test]
#[ignore]
fn claim_bench_100k() {
    let rt = runtime();
    rt.block_on(async {
        let (us, n) = time_claim(100_000).await;
        assert_eq!(n, 16);
        println!("BENCH claim/100k = {us} us");
    });
}

#[test]
#[ignore]
fn claim_bench_1m() {
    let rt = runtime();
    rt.block_on(async {
        let (us, n) = time_claim(1_000_000).await;
        assert_eq!(n, 16);
        println!("BENCH claim/1m = {us} us");
    });
}

// ---------------------------------------------------------------------------
// Step 9 fast-claim equivalence: the bounded indexed path must reproduce
// the window query's sequence row for row. This binary NEVER enqueues a
// skewed (kind,id) pair, so filtered claims exercise the fast path;
// skewed-pair fallback coverage lives in `catalog_claim_skew.rs`
// (separate process: the skew verdict is process-wide).
// ---------------------------------------------------------------------------

const ALL_KINDS: [&str; 5] = [
    "enumerate_dir",
    "probe_git",
    "status",
    "reconcile",
    "analyze_store",
];

/// Deterministic mixed seed with fixed timestamps: all five kinds,
/// attempts diversity (some rows claimed + lease-expired back to
/// pending), and updated_at diversity. Two stores seeded by this helper
/// hold byte-identical claim-relevant state.
async fn seed_mixed(store: &TursoStore, base: i64) {
    let epoch = store.epoch();
    let mut batch = WriterBatch::new();
    for i in 0..300 {
        let (id, kind, scope) = match i % 10 {
            0 => (format!("probe:1:repo{i}"), "probe_git", "git:00"),
            1 => (format!("reconcile:vol{i}:1"), "reconcile", "vol:00"),
            2 => (format!("status:repo{i}:1"), "status", "status:00"),
            3 => (format!("analyze:store{i}:1"), "analyze_store", "store:00"),
            _ => (format!("enum:1:d{i}:i{i}"), "enumerate_dir", "dir:00"),
        };
        let idem = format!("idem:{id}");
        let task = NewTask {
            id: &id,
            kind,
            generation: 1,
            dir_id: None,
            scope_key: scope,
            expected_rev: 0,
            idempotency_key: &idem,
        };
        // Stagger updated_at so partition order is nontrivial.
        TursoStore::buffer_enqueue_task(&mut batch, &task, base + (i as i64 % 7));
    }
    store.flush(&mut batch).await.expect("seed flush");
    // Attempts diversity: lease 40 rows, then expire them back to
    // pending (attempts=1, fresh updated_at).
    let claimed = store
        .claim_tasks_in_generation(1, epoch, 40, 60_000, base + 100)
        .await
        .expect("diversity claim");
    assert_eq!(claimed.len(), 40);
    let expired = store
        .expire_leases(base + 100 + 60_001)
        .await
        .expect("expire");
    assert_eq!(expired, 40);
}

/// Drain one store with `limit`-sized filtered claims, returning the
/// full claimed id sequence.
async fn drain_filtered(store: &TursoStore, limit: usize, now: i64) -> Vec<String> {
    let epoch = store.epoch();
    let mut ids = Vec::new();
    loop {
        let claimed = store
            .claim_tasks_in_generation_kinds(1, epoch, limit, 60_000, now, &ALL_KINDS)
            .await
            .expect("drain claim");
        if claimed.is_empty() {
            break;
        }
        ids.extend(claimed.iter().map(|c| c.task.id.clone()));
    }
    ids
}

/// Drain one store with `limit`-sized UNFILTERED (window-query) claims.
async fn drain_window(store: &TursoStore, limit: usize, now: i64) -> Vec<String> {
    let epoch = store.epoch();
    let mut ids = Vec::new();
    loop {
        let claimed = store
            .claim_tasks_in_generation(1, epoch, limit, 60_000, now)
            .await
            .expect("drain claim");
        if claimed.is_empty() {
            break;
        }
        ids.extend(claimed.iter().map(|c| c.task.id.clone()));
    }
    ids
}

#[test]
fn fast_claim_matches_window_sequence() {
    let rt = runtime();
    rt.block_on(async {
        let base = 1_700_000_000_000i64;
        // Small and large limits, plus an odd one: the interleave
        // prefix must match at every truncation.
        for limit in [1usize, 7, 16, 64, 300] {
            let dir_a = tempfile::tempdir().expect("tempdir");
            let a = TursoStore::open(&db_in(&dir_a)).await.expect("open");
            seed_mixed(&a, base).await;
            let dir_b = tempfile::tempdir().expect("tempdir");
            let b = TursoStore::open(&db_in(&dir_b)).await.expect("open");
            seed_mixed(&b, base).await;
            let seq_fast = drain_filtered(&a, limit, base + 200_000).await;
            let seq_win = drain_window(&b, limit, base + 200_000).await;
            assert_eq!(seq_fast, seq_win, "limit={limit}");
            assert_eq!(seq_fast.len(), 300, "limit={limit}");
            a.close().await.expect("close");
            b.close().await.expect("close");
        }
    });
}

#[test]
fn fast_claim_r06_fairness_filtered() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let epoch = store.epoch();
        let now = now_ms();
        for i in 100..120 {
            let id = format!("enum:1:d1:i{i}");
            let idem = format!("idem:{id}");
            store
                .enqueue_task(
                    &NewTask {
                        id: &id,
                        kind: "enumerate_dir",
                        generation: 1,
                        dir_id: None,
                        scope_key: "dir:00",
                        expected_rev: 0,
                        idempotency_key: &idem,
                    },
                    now,
                )
                .await
                .expect("enqueue enum");
        }
        for name in ["repo1", "repo2"] {
            let id = format!("probe:1:{name}");
            let idem = format!("idem:{id}");
            store
                .enqueue_task(
                    &NewTask {
                        id: &id,
                        kind: "probe_git",
                        generation: 1,
                        dir_id: None,
                        scope_key: "git:00",
                        expected_rev: 0,
                        idempotency_key: &idem,
                    },
                    now,
                )
                .await
                .expect("enqueue probe");
        }
        // Discovery-shaped filtered claim (fast path): probes first,
        // enumeration interleaved — the R06 contract.
        let claimed = store
            .claim_tasks_in_generation_kinds(
                1,
                epoch,
                8,
                60_000,
                now,
                &["enumerate_dir", "probe_git", "reconcile"],
            )
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 8);
        assert_eq!(claimed[0].task.kind, "probe_git");
        assert_eq!(claimed[0].task.id, "probe:1:repo1");
        assert_eq!(claimed[1].task.kind, "enumerate_dir");
        assert_eq!(
            claimed
                .iter()
                .filter(|c| c.task.kind == "probe_git")
                .count(),
            2
        );
        store.close().await.expect("close");
    });
}

#[test]
fn fast_claim_retry_fallback_exact() {
    let rt = runtime();
    rt.block_on(async {
        let base = 1_700_000_000_000i64;
        for use_fast in [true, false] {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = TursoStore::open(&db_in(&dir)).await.expect("open");
            let epoch = store.epoch();
            seed_mixed(&store, base).await;
            // Park one enum row in retry_wait with an ELAPSED backoff:
            // filtered claims must fall back and still order it exactly.
            let claimed = store
                .claim_tasks_in_generation_kinds(1, epoch, 1, 60_000, base + 200_000, &ALL_KINDS)
                .await
                .expect("claim one");
            assert_eq!(claimed.len(), 1);
            let victim = claimed[0].task.id.clone();
            store
                .complete_task(
                    &victim,
                    claimed[0].token,
                    epoch,
                    &TaskOutcome::Retry {
                        category: "stalled".to_string(),
                        detail: "slow".to_string(),
                        retry_after_ms: base + 200_001,
                    },
                    base + 200_000,
                )
                .await
                .expect("retry");
            let seq = if use_fast {
                drain_filtered(&store, 64, base + 300_000).await
            } else {
                drain_window(&store, 64, base + 300_000).await
            };
            assert_eq!(seq.len(), 300);
            assert!(seq.contains(&victim), "elapsed retry row must be claimable");
            store.close().await.expect("close");
        }
        // And the two paths must agree with each other, not just drain.
        let dir_a = tempfile::tempdir().expect("tempdir");
        let a = TursoStore::open(&db_in(&dir_a)).await.expect("open");
        seed_mixed(&a, base).await;
        let dir_b = tempfile::tempdir().expect("tempdir");
        let b = TursoStore::open(&db_in(&dir_b)).await.expect("open");
        seed_mixed(&b, base).await;
        for store in [&a, &b] {
            let epoch = store.epoch();
            let claimed = store
                .claim_tasks_in_generation_kinds(1, epoch, 1, 60_000, base + 200_000, &ALL_KINDS)
                .await
                .expect("claim one");
            let victim = claimed[0].task.id.clone();
            let token = claimed[0].token;
            store
                .complete_task(
                    &victim,
                    token,
                    epoch,
                    &TaskOutcome::Retry {
                        category: "stalled".to_string(),
                        detail: "slow".to_string(),
                        retry_after_ms: base + 200_001,
                    },
                    base + 200_000,
                )
                .await
                .expect("retry");
        }
        let seq_fast = drain_filtered(&a, 64, base + 300_000).await;
        let seq_win = drain_window(&b, 64, base + 300_000).await;
        assert_eq!(seq_fast, seq_win);
        a.close().await.expect("close");
        b.close().await.expect("close");
    });
}

#[test]
fn fast_claim_uses_covering_index() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let now = now_ms();
        seed(&store, 1, 50, now).await;
        let mut rows = store
            .connection()
            .query(
                "EXPLAIN QUERY PLAN SELECT id, kind, generation, dir_id, scope_key, expected_rev, \
                    state, lease_token, lease_epoch, lease_expires_ms, idempotency_key, \
                    retry_after_ms, attempts FROM frontier_tasks WHERE generation = 1 \
                    AND state = 'pending' AND kind = 'enumerate_dir' \
                    ORDER BY attempts ASC, updated_at_ms ASC, id ASC LIMIT 16",
                (),
            )
            .await
            .expect("explain");
        let mut plan = String::new();
        while let Some(row) = rows.next().await.expect("row") {
            let detail: String = match row.get_value(3) {
                Ok(turso::Value::Text(text)) => text,
                other => panic!("unexpected plan column: {other:?}"),
            };
            plan.push_str(&detail);
            plan.push('\n');
        }
        println!("plan:\n{plan}");
        assert!(
            plan.contains("idx_tasks_claim"),
            "class query must use the claim index, plan:\n{plan}"
        );
        assert!(
            !plan.to_lowercase().contains("sort"),
            "class query must not sort, plan:\n{plan}"
        );
        store.close().await.expect("close");
    });
}
