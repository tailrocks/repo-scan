//! Step 9 skewed-pair fallback: tasks whose id prefix pulls them into
//! an earlier R06 class than their kind must still claim in exact
//! window order (via the legacy fallback).
//!
//! Separate binary from `catalog_claim_bench.rs` on purpose: the skew
//! verdict is process-wide, and these tests SET it. Nothing here may
//! assume the fast path; everything asserts window-exact sequences.

use repo_scan::store::{now_ms, NewTask, Store, TursoStore};
use std::path::PathBuf;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn db_in(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("payload").join("catalog.db")
}

async fn enqueue(store: &TursoStore, id: &str, kind: &str, now: i64) {
    let idem = format!("idem:{id}");
    store
        .enqueue_task(
            &NewTask {
                id,
                kind,
                generation: 1,
                dir_id: None,
                scope_key: "s:00",
                expected_rev: 0,
                idempotency_key: &idem,
            },
            now,
        )
        .await
        .expect("enqueue");
}

#[test]
fn skewed_pairs_claim_in_window_order() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let epoch = store.epoch();
        let now = now_ms();
        // Skewed: id prefix beats kind (first-match class 1 and 3).
        enqueue(&store, "probe:1:skewed-status", "status", now).await;
        enqueue(&store, "enum:1:skewed-analyze", "analyze_store", now).await;
        // Case-fold skew: SQL LIKE folds ASCII case.
        enqueue(&store, "PROBE:1:upper-enum", "enumerate_dir", now).await;
        // Consistent controls.
        enqueue(&store, "enum:1:plain", "enumerate_dir", now).await;
        enqueue(&store, "status:plain:1", "status", now).await;

        let claimed = store
            .claim_tasks_in_generation_kinds(
                1,
                epoch,
                16,
                60_000,
                now,
                &[
                    "enumerate_dir",
                    "probe_git",
                    "status",
                    "reconcile",
                    "analyze_store",
                ],
            )
            .await
            .expect("claim");
        let ids: Vec<&str> = claimed.iter().map(|c| c.task.id.as_str()).collect();
        // Window first-match classes, `_rn`-major round-robin: the two
        // probe-pulled rows are class 1 (by id: PROBE... < probe... in
        // BINARY order), the enum-pulled analyze row joins class 3 with
        // the plain enum row, and the plain status row is class 4.
        assert_eq!(
            ids,
            vec![
                "PROBE:1:upper-enum",
                "enum:1:plain",
                "status:plain:1",
                "probe:1:skewed-status",
                "enum:1:skewed-analyze",
            ]
        );
        store.close().await.expect("close");
    });
}

#[test]
fn skewed_fallback_matches_unfiltered_window() {
    let rt = runtime();
    rt.block_on(async {
        let now = now_ms();
        let kinds = [
            "enumerate_dir",
            "probe_git",
            "status",
            "reconcile",
            "analyze_store",
        ];
        let mut seqs = Vec::new();
        for filtered in [true, false] {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = TursoStore::open(&db_in(&dir)).await.expect("open");
            let epoch = store.epoch();
            for i in 0..50 {
                let (id, kind) = match i % 7 {
                    0 => (format!("probe:1:s{i}"), "status"),
                    1 => (format!("enum:1:s{i}"), "analyze_store"),
                    2 => (format!("reconcile:1:s{i}"), "enumerate_dir"),
                    3 => (format!("status:x:{i}"), "probe_git"),
                    4 => (format!("probe:1:p{i}"), "probe_git"),
                    5 => (format!("enum:1:e{i}"), "enumerate_dir"),
                    _ => (format!("analyze:z:{i}"), "analyze_store"),
                };
                enqueue(&store, &id, kind, now).await;
            }
            let mut ids = Vec::new();
            loop {
                let claimed = if filtered {
                    store
                        .claim_tasks_in_generation_kinds(1, epoch, 9, 60_000, now, &kinds)
                        .await
                        .expect("claim")
                } else {
                    store
                        .claim_tasks_in_generation(1, epoch, 9, 60_000, now)
                        .await
                        .expect("claim")
                };
                if claimed.is_empty() {
                    break;
                }
                ids.extend(claimed.iter().map(|c| c.task.id.clone()));
            }
            assert_eq!(ids.len(), 50);
            seqs.push(ids);
            store.close().await.expect("close");
        }
        assert_eq!(seqs[0], seqs[1]);
    });
}
