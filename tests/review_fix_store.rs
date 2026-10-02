//! Review-fix regressions for store findings R2, R6, R8, R10, R11, R12
//! (`docs/REVIEW_WF4.md`): generation-scoped claims, path-based
//! invalidation mirror, mid-scan checkpoint cadence, scan-path writer
//! batching with tx/sync counters, verified parent completion, and
//! read-only cached-query opens.
//!
//! All databases live in tempdirs; timestamps are explicit, so no test
//! sleeps. A current-thread Tokio runtime drives the waker futures.

use repo_scan::model::TaskState;
use repo_scan::store::{
    now_ms, CheckpointCoordinator, CheckpointPolicy, NewGitInstance, NewRemote, NewStatus, NewTask,
    Store, TaskOutcome, TursoStore, WriterBatch,
};
use std::path::PathBuf;
use std::time::Duration;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn db_in(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("payload").join("catalog.db")
}

async fn enqueue(store: &TursoStore, id: &str, generation: u64, now: i64) {
    let idempotency = format!("idem:{id}");
    store
        .enqueue_task(
            &NewTask {
                id,
                kind: "enumerate_dir",
                generation,
                dir_id: None,
                scope_key: "dir:00",
                expected_rev: 0,
                idempotency_key: &idempotency,
            },
            now,
        )
        .await
        .expect("enqueue");
}

/// R2: a generation-scoped claim sees only its own generation (a
/// force-rescan generation never drains older work), while repeated claims
/// of the same generation share that generation's work.
#[test]
fn r2_scoped_claim_isolates_generations() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let epoch = store.epoch();
        let now = now_ms();
        enqueue(&store, "r2-a1", 1, now).await;
        enqueue(&store, "r2-a2", 1, now).await;
        enqueue(&store, "r2-b1", 2, now).await;

        // Same-generation sharing: sequential claims split gen-1 work.
        let first = store
            .claim_tasks_in_generation(1, epoch, 1, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].task.generation, 1);
        let second = store
            .claim_tasks_in_generation(1, epoch, 10, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].task.generation, 1);
        assert_ne!(first[0].task.id, second[0].task.id);

        // Gen 1 exhausted; its claims never touched gen 2.
        let empty = store
            .claim_tasks_in_generation(1, epoch, 10, 60_000, now)
            .await
            .expect("claim");
        assert!(empty.is_empty());
        let gen2 = store
            .claim_tasks_in_generation(2, epoch, 10, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(gen2.len(), 1);
        assert_eq!(gen2[0].task.id, "r2-b1");

        store.close().await.expect("close");
    });
}

/// R6: `invalidate_scope` mirrors a `dir:` scope into the directory row by
/// path lookup — even though production tasks carry `dir_id: None` and the
/// key suffix is hex, never an integer row id.
#[test]
fn r6_invalidate_mirrors_dir_row_by_path() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let now = now_ms();

        let path = PathBuf::from("/tmp/r6-mirror-dir");
        let scope = repo_scan::config::scope_key_for_dir(&path);
        let dir_id = store
            .upsert_dir(
                None,
                b"r6-mirror-dir",
                "/tmp/r6-mirror-dir",
                "dev:9",
                "ino-9",
                "inc-9",
                now,
            )
            .await
            .expect("upsert");
        // Production shape: the task for this scope carries no dir id.
        let idempotency = "idem:r6-enum".to_string();
        store
            .enqueue_task(
                &NewTask {
                    id: "r6-enum",
                    kind: "enumerate_dir",
                    generation: 1,
                    dir_id: None,
                    scope_key: &scope,
                    expected_rev: 0,
                    idempotency_key: &idempotency,
                },
                now,
            )
            .await
            .expect("enqueue");

        let rev = store
            .invalidate_scope(&scope, 1, now)
            .await
            .expect("invalidate");
        assert_eq!(rev, 1);
        let row = store.get_dir(dir_id).await.expect("get").expect("row");
        assert_eq!(row.invalidation_rev, 1);

        // Unrelated rows are untouched; non-dir scopes mirror nothing.
        let other = store
            .upsert_dir(None, b"other", "/other", "dev:9", "ino-10", "inc-9", now)
            .await
            .expect("upsert");
        let rev2 = store
            .invalidate_scope("status:co-1", 1, now)
            .await
            .expect("invalidate");
        assert_eq!(rev2, 1);
        let other_row = store.get_dir(other).await.expect("get").expect("row");
        assert_eq!(other_row.invalidation_rev, 0);

        // Malformed dir key: the revision still bumps (the stale-completion
        // guard), nothing mirrors, nothing panics.
        let rev3 = store
            .invalidate_scope("dir:zz", 1, now)
            .await
            .expect("invalidate");
        assert_eq!(rev3, 1);
        assert_eq!(store.scope_rev("dir:zz").await.expect("rev"), 1);

        store.close().await.expect("close");
    });
}

/// R8: the scan loop gets a checkpoint cadence hook (op counting plus a
/// time rate-limit) and WAL-growth counters it can call mid-scan.
#[test]
fn r8_checkpoint_cadence_probes_and_counts() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let now = now_ms();
        enqueue(&store, "r8-t1", 1, now).await;

        let mut coord = CheckpointCoordinator::new(CheckpointPolicy {
            ops_between_probes: 2,
            max_wal_frames: u64::MAX,
            min_probe_interval: Duration::ZERO,
        });
        assert!(!coord.note_ops(1));
        assert_eq!(coord.ops_since_probe(), 1);
        assert!(coord.note_ops(1));

        let status = coord
            .maybe_checkpoint(&store)
            .await
            .expect("probe")
            .expect("not rate-limited");
        assert_eq!(coord.stats().wal_probes, 1);
        assert_eq!(coord.stats().wal_frames_last, status.log_frames);
        assert_eq!(coord.stats().wal_frames_max, status.log_frames);
        assert_eq!(coord.ops_since_probe(), 0);
        assert_eq!(store.stats().wal_probes, 1);

        // Zero-frame budget forces the truncate path (or records busy).
        let mut tight = CheckpointCoordinator::new(CheckpointPolicy {
            ops_between_probes: 1,
            max_wal_frames: 0,
            min_probe_interval: Duration::ZERO,
        });
        assert!(tight.note_ops(1));
        tight.maybe_checkpoint(&store).await.expect("probe");
        let stats = tight.stats();
        assert_eq!(stats.wal_probes, 1);
        assert!(
            stats.checkpoints + stats.busy_skips == 1 || stats.wal_frames_last == 0,
            "unexpected stats: {stats:?}"
        );

        // The time rate-limit skips back-to-back probes.
        let mut gated = CheckpointCoordinator::new(CheckpointPolicy {
            ops_between_probes: 1,
            max_wal_frames: u64::MAX,
            min_probe_interval: Duration::from_secs(3600),
        });
        assert!(gated.note_ops(1));
        assert!(gated
            .maybe_checkpoint(&store)
            .await
            .expect("probe")
            .is_some());
        assert!(gated
            .maybe_checkpoint(&store)
            .await
            .expect("probe")
            .is_none());
        assert_eq!(gated.stats().wal_probes, 1);

        store.close().await.expect("close");
    });
}

/// R10: probe/enumeration/status writes buffer through `WriterBatch` and
/// commit in one transaction at the 512-row limit; tx/batch counters expose
/// the amortized rate for PERF-02.
#[test]
fn r10_buffered_scan_writes_commit_in_one_tx() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let now = now_ms();
        let dir_id = store
            .upsert_dir(None, b"bat", "/bat", "dev:1", "ino-1", "inc-1", now)
            .await
            .expect("upsert");
        let baseline = store.stats();

        let mut batch = WriterBatch::new();
        let mut first_flush_at = None;
        for i in 0..600 {
            let id = format!("r10-t{i:04}");
            let idempotency = format!("idem:{id}");
            let task = NewTask {
                id: &id,
                kind: "enumerate_dir",
                generation: 1,
                dir_id: None,
                scope_key: "dir:00",
                expected_rev: 0,
                idempotency_key: &idempotency,
            };
            if TursoStore::buffer_enqueue_task(&mut batch, &task, now) && first_flush_at.is_none() {
                first_flush_at = Some(i);
            }
        }
        assert_eq!(first_flush_at, Some(511));
        TursoStore::buffer_upsert_git_instance(
            &mut batch,
            &NewGitInstance {
                id: "r10-inst",
                git_path: b"/g",
                common_path: b"/g",
                incarnation: "",
                format: "git-files",
                bare: Some(false),
                object_format: "sha1",
                disposition: "confirmed",
                evidence_json: "[]",
            },
            now,
        );
        TursoStore::buffer_upsert_remote(
            &mut batch,
            &NewRemote {
                id: "r10-rem",
                instance_id: "r10-inst",
                checkout_scope_id: None,
                name: b"origin",
                role: "fetch",
                url: b"https://github.com/o/r",
                canonical_url: Some(b"https://github.com/o/r"),
            },
            now,
        );
        TursoStore::buffer_record_status(
            &mut batch,
            &NewStatus {
                checkout_id: "r10-co",
                mode: "summary",
                state: "complete",
                started_ms: Some(now),
                finished_ms: Some(now),
                staged: Some(0),
                unstaged: Some(0),
                untracked: Some(0),
                untracked_units: "collapsed_entries",
                submodules: "not_requested",
                unknown_fields: "[]",
                input_fingerprint: None,
                observed_rev: 1,
            },
            now,
        );
        TursoStore::buffer_record_dir_observation(&mut batch, dir_id, 1, true, 1, 7, None, now);

        let applied = store.flush(&mut batch).await.expect("flush");
        assert_eq!(applied, 604);
        assert!(batch.is_empty());
        let delta = store.stats();
        assert_eq!(delta.transactions, baseline.transactions + 1);
        assert_eq!(delta.batch_commits, baseline.batch_commits + 1);
        assert_eq!(delta.batch_ops, baseline.batch_ops + 604);

        assert!(store.get_task("r10-t0000").await.expect("get").is_some());
        assert!(store.get_task("r10-t0599").await.expect("get").is_some());
        assert!(store
            .get_git_instance("r10-inst")
            .await
            .expect("get")
            .is_some());
        assert_eq!(store.list_remotes("r10-inst").await.expect("list").len(), 1);
        assert_eq!(store.list_statuses("r10-co").await.expect("list").len(), 1);
        let obs = store
            .get_dir_observation(dir_id, 1)
            .await
            .expect("get")
            .expect("row");
        assert!(obs.completed);
        assert_eq!(obs.entries_seen, 7);

        store.close().await.expect("close");
    });
}

/// R11: verified parent completion positively checks that preserved child
/// records are durable; a missing child fails loudly and leaves the parent
/// leased instead of completing over lost work.
#[test]
fn r11_verified_completion_checks_child_records() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let epoch = store.epoch();
        let now = now_ms();
        enqueue(&store, "r11-parent", 1, now).await;
        enqueue(&store, "r11-c1", 1, now).await;
        enqueue(&store, "r11-c2", 1, now).await;

        let claimed = store
            .claim_tasks_in_generation(1, epoch, 10, 60_000, now)
            .await
            .expect("claim");
        let parent = claimed
            .iter()
            .find(|c| c.task.id == "r11-parent")
            .expect("parent claimed");
        let children = vec!["r11-c1".to_string(), "r11-c2".to_string()];
        store
            .complete_task_with_children(
                "r11-parent",
                parent.token,
                epoch,
                &TaskOutcome::Complete,
                &children,
                now,
            )
            .await
            .expect("verified complete");
        let done = store
            .get_task("r11-parent")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(done.state, TaskState::Complete);

        // A missing child record fails loudly; the parent stays leased.
        enqueue(&store, "r11-parent2", 1, now).await;
        let claimed2 = store
            .claim_tasks_in_generation(1, epoch, 10, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(claimed2.len(), 1);
        let missing = vec!["r11-ghost".to_string()];
        let err = store
            .complete_task_with_children(
                "r11-parent2",
                claimed2[0].token,
                epoch,
                &TaskOutcome::Complete,
                &missing,
                now,
            )
            .await
            .expect_err("missing child must fail");
        assert!(
            err.to_string().contains("missing-child-record"),
            "wrong error: {err}"
        );
        let held = store
            .get_task("r11-parent2")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(held.state, TaskState::Leased);

        // Non-complete outcomes claim no durable children: no check.
        store
            .complete_task_with_children(
                "r11-parent2",
                claimed2[0].token,
                epoch,
                &TaskOutcome::Retry {
                    category: "stalled".to_string(),
                    detail: "helper stuck".to_string(),
                    retry_after_ms: now + 1_000,
                },
                &missing,
                now,
            )
            .await
            .expect("retry skips child check");
        let waiting = store
            .get_task("r11-parent2")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(waiting.state, TaskState::RetryWait);

        store.close().await.expect("close");
    });
}

/// R12: cached queries open read-only — no epoch claim, no recovery
/// writes — and recovery runs only when leases actually block.
#[test]
fn r12_read_only_open_claims_nothing() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = db_in(&dir);
        let epoch0;
        {
            let store = TursoStore::open(&db).await.expect("open");
            epoch0 = store.epoch();
            let now = now_ms();
            enqueue(&store, "r12-t1", 1, now).await;
            let claimed = store
                .claim_tasks_in_generation(1, epoch0, 10, 60_000, now)
                .await
                .expect("claim");
            assert_eq!(claimed.len(), 1);
            store.close().await.expect("close");
        }

        // Absent catalog: read-only open refuses instead of creating.
        let missing = dir.path().join("nowhere").join("catalog.db");
        assert!(TursoStore::open_read_only(&missing).await.is_err());

        let cached = TursoStore::open_read_only(&db)
            .await
            .expect("read-only open");
        assert!(cached.is_read_only());
        assert_eq!(
            cached.epoch(),
            epoch0,
            "read-only open must not claim an epoch"
        );
        // No recovery writes: the live lease is untouched.
        let task = cached.get_task("r12-t1").await.expect("get").expect("row");
        assert_eq!(task.state, TaskState::Leased);
        assert_eq!(cached.pending_count(1).await.expect("count"), 1);
        // Writes are refused on the read-only handle.
        assert!(cached
            .invalidate_scope("dir:00", 1, now_ms())
            .await
            .is_err());
        // Nothing blocks yet: conditional recovery performs zero writes.
        let idle = cached.recover_if_blocked(now_ms()).await.expect("idle");
        assert_eq!(idle.requeued, 0);
        assert_eq!(idle.uncertain_dropped, 0);
        assert_eq!(
            cached.blocking_lease_count(now_ms()).await.expect("count"),
            0
        );
        // After expiry the lease blocks; a read-only handle cannot recover it.
        assert_eq!(
            cached
                .blocking_lease_count(now_ms() + 60_001)
                .await
                .expect("count"),
            1
        );
        assert!(cached.recover_if_blocked(now_ms() + 60_001).await.is_err());
        cached.close().await.expect("close");

        // The normal owner path still claims and recovers.
        let store = TursoStore::open(&db).await.expect("reopen");
        assert_eq!(store.epoch(), epoch0 + 1);
        store.close().await.expect("close");
    });
}

/// R06: Fair task claiming interleaves probe tasks ahead of large enumeration
/// backlogs so discovered Git repositories are scheduled and validated promptly
/// while directory enumeration continues in parallel or interleaved.
#[test]
fn r06_fair_scheduling_interleaves_probes_and_enumeration() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let epoch = store.epoch();
        let now = now_ms();

        // Enqueue 20 enumeration tasks: enum:1:d1:i100..i119
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

        // Enqueue 2 Git candidate probe tasks: probe:1:repo1 and probe:1:repo2
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

        // Enqueue 2 checkout status tasks: status:repo1:1 and status:repo2:1
        for name in ["repo1", "repo2"] {
            let id = format!("status:{name}:1");
            let idem = format!("idem:{id}");
            store
                .enqueue_task(
                    &NewTask {
                        id: &id,
                        kind: "status",
                        generation: 1,
                        dir_id: None,
                        scope_key: "status:00",
                        expected_rev: 0,
                        idempotency_key: &idem,
                    },
                    now,
                )
                .await
                .expect("enqueue status");
        }

        // Under old ORDER BY id ASC:
        // 'e' < 'p' < 's', so claiming 8 tasks would return ONLY enum tasks (enum:1:d1:i100..i107).
        // Zero probe tasks would be claimed, starving candidate validation.
        // Under R06 fair scheduling:
        // Probe tasks are prioritized and interleaved with enumeration and status.
        let claimed = store
            .claim_tasks_in_generation(1, epoch, 8, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 8);

        // First item must be a probe task (prompt validation of discovered candidate)
        assert_eq!(claimed[0].task.kind, "probe_git");
        assert_eq!(claimed[0].task.id, "probe:1:repo1");

        // The batch must contain BOTH probe tasks and enumeration tasks (interleaved)
        let probe_count = claimed.iter().filter(|c| c.task.kind == "probe_git").count();
        let enum_count = claimed.iter().filter(|c| c.task.kind == "enumerate_dir").count();
        let status_count = claimed.iter().filter(|c| c.task.kind == "status").count();

        assert_eq!(probe_count, 2, "both probe tasks claimed promptly in the first batch");
        assert!(enum_count > 0, "enumeration continues in the same batch");
        assert!(status_count > 0, "status tasks make progress without starving enumeration");

        store.close().await.expect("close");
    });
}

