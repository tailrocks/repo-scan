//! Store acceptance: round-trip persistence, lease expiry/renewal,
//! stale-completion guard, writer batching, and owner-lock exclusivity.
//!
//! All databases live in tempdirs. Timestamps are passed explicitly, so no
//! test sleeps. The Turso local path needs no async runtime services; a
//! current-thread Tokio runtime drives the waker futures.

use repo_scan::model::TaskState;
use repo_scan::store::{
    now_ms, NewCheckout, NewGitInstance, NewRef, NewRemote, NewScan, NewStatus, NewTask, NewVolume,
    OwnerGuard, Store, TaskOutcome, TursoStore, WriterBatch,
};
use std::path::PathBuf;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn db_in(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("payload").join("catalog.db")
}

#[test]
fn round_trip_persists_across_reopen() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = db_in(&dir);
        let store = TursoStore::open(&db).await.expect("open");
        assert_eq!(store.schema_version().expect("version"), 5);
        assert!(store.epoch() >= 1);

        let proof = store.durability_proof().await.expect("proof");
        assert_eq!(proof.synchronous, 2);
        assert_eq!(proof.data_sync_retry, 1);
        assert_eq!(proof.journal_mode.to_lowercase(), "wal");
        #[cfg(target_os = "macos")]
        assert_eq!(proof.fullfsync, Some(1));
        #[cfg(not(target_os = "macos"))]
        assert_eq!(proof.fullfsync, None);

        let now = now_ms();

        store
            .upsert_volume(
                &NewVolume {
                    id: "vol-1",
                    native_identity: Some("native-1"),
                    namespace: "ns-1",
                    filesystem: Some("apfs"),
                    kind: "local",
                    state: "available",
                },
                Some(now),
            )
            .await
            .expect("upsert volume");
        let volume = store.get_volume("vol-1").await.expect("get").expect("row");
        assert_eq!(volume.namespace, "ns-1");

        let generation = store
            .create_generation("machine", "running", None, now)
            .await
            .expect("generation");
        store
            .set_generation_state(generation, "complete")
            .await
            .expect("gen state");
        let gen = store
            .get_generation(generation)
            .await
            .expect("get")
            .expect("row");
        assert_eq!(gen.state, "complete");

        // Non-UTF8 component bytes must survive the BLOB round-trip.
        let component = vec![0xff, 0xfe, b'd', b'i', b'r'];
        let dir_id = store
            .upsert_dir(None, &component, "<ff><fe>dir", "vol-1", "obj-9", "", now)
            .await
            .expect("upsert dir");
        let same = store
            .upsert_dir(None, &component, "<ff><fe>dir", "vol-1", "obj-9", "", now)
            .await
            .expect("upsert dir again");
        assert_eq!(dir_id, same);
        let dir = store.get_dir(dir_id).await.expect("get").expect("row");
        assert_eq!(dir.component, component);
        assert_eq!(dir.invalidation_rev, 0);

        store
            .record_dir_observation(dir_id, generation, true, 7, 42, None, now)
            .await
            .expect("observation");
        let obs = store
            .get_dir_observation(dir_id, generation)
            .await
            .expect("get")
            .expect("row");
        assert!(obs.completed);
        assert_eq!(obs.entries_seen, 42);

        let git_path = vec![0x80, b'g', b'i', b't'];
        store
            .upsert_git_instance(
                &NewGitInstance {
                    id: "inst-1",
                    git_path: &git_path,
                    common_path: b"/store/common",
                    incarnation: "",
                    format: "git-files",
                    bare: Some(true),
                    object_format: "sha1",
                    disposition: "confirmed",
                    evidence_json: "[\"origin matches\"]",
                },
                now,
            )
            .await
            .expect("upsert instance");
        let inst = store
            .get_git_instance("inst-1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(inst.git_path, git_path);
        assert_eq!(inst.bare, Some(true));

        store
            .upsert_checkout(
                &NewCheckout {
                    id: "co-1",
                    instance_id: "inst-1",
                    root_path: Some(b"/work/tree"),
                    git_path: &git_path,
                    relationship: "main",
                    availability: "present",
                    head_state: "branch",
                    head_ref: Some(b"refs/heads/main"),
                    head_oid: Some(b"0123456789abcdef0123"),
                    head_algo: Some("sha1"),
                },
                now,
            )
            .await
            .expect("upsert checkout");
        let checkout = store.get_checkout("co-1").await.expect("get").expect("row");
        assert_eq!(checkout.head_state, "branch");

        store
            .upsert_remote(
                &NewRemote {
                    id: "rem-1",
                    instance_id: "inst-1",
                    checkout_scope_id: None,
                    name: b"origin",
                    role: "fetch",
                    url: b"https://github.com/owner/repo.git",
                    canonical_url: Some(b"https://github.com/owner/repo"),
                },
                now,
            )
            .await
            .expect("upsert remote");
        let remotes = store.list_remotes("inst-1").await.expect("list");
        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0].role, "fetch");

        for (id, kind) in [("ref-1", "local"), ("ref-2", "remote_tracking")] {
            store
                .upsert_ref(
                    &NewRef {
                        id,
                        instance_id: "inst-1",
                        checkout_scope_id: None,
                        kind,
                        name: b"refs/heads/main",
                        oid: Some(b"0123456789abcdef0123"),
                        algo: Some("sha1"),
                        symbolic_target: None,
                        upstream: None,
                        state: "valid",
                    },
                    now,
                )
                .await
                .expect("upsert ref");
        }
        assert_eq!(store.list_refs("inst-1").await.expect("list").len(), 2);

        let status = NewStatus {
            checkout_id: "co-1",
            mode: "summary",
            state: "complete",
            started_ms: Some(now),
            finished_ms: Some(now),
            staged: Some(1),
            unstaged: Some(2),
            untracked: Some(3),
            conflicts: Some(0),
            working_state: "dirty",
            untracked_units: "collapsed_entries",
            submodules: "not_requested",
            unknown_fields: "[]",
            input_fingerprint: None,
            observed_rev: 1,
        };
        assert!(store.record_status(&status, now).await.expect("status"));
        assert!(!store.record_status(&status, now).await.expect("status dup"));
        let statuses = store.list_statuses("co-1").await.expect("list");
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].untracked, Some(3));

        let scan = NewScan {
            id: "scan-1",
            url_raw: b"https://github.com/OWNER/REPO",
            url_canonical: Some(b"https://github.com/owner/repo"),
            scope: "machine",
            status_mode: "summary",
            report_dest: None,
            targets_json: None,
            format: None,
            all_targets: None,
            fetch: None,
            workers: None,
        };
        assert!(store.create_scan_request(&scan, now).await.expect("scan"));
        assert!(!store
            .create_scan_request(&scan, now)
            .await
            .expect("scan dup"));
        store
            .update_scan_state("scan-1", "complete", Some("ok"), None, now)
            .await
            .expect("scan state");
        let scan_row = store.get_scan("scan-1").await.expect("get").expect("row");
        assert_eq!(scan_row.state, "complete");
        assert_eq!(scan_row.workers, None);

        assert!(store
            .save_report_snapshot("rep-1", "1.0.0", 3, generation, "staged", None, now)
            .await
            .expect("snapshot"));
        assert!(!store
            .save_report_snapshot("rep-1", "1.0.0", 3, generation, "staged", None, now)
            .await
            .expect("snapshot dup"));
        store
            .set_snapshot_publication("rep-1", "published")
            .await
            .expect("publish");
        let snap = store
            .get_report_snapshot("rep-1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(snap.publication_state, "published");

        store
            .record_error("err-1", "scope-a", "denied", "no entry", None, now)
            .await
            .expect("error");
        store
            .record_error("err-1", "scope-a", "denied", "still no", None, now)
            .await
            .expect("error again");
        let error = store.get_error("err-1").await.expect("get").expect("row");
        assert_eq!(error.attempts, 2);
        assert!(error.open);
        store.resolve_error("err-1", now).await.expect("resolve");
        let resolved = store.get_error("err-1").await.expect("get").expect("row");
        assert!(!resolved.open);

        assert!(store
            .append_event("vol-1", "hist-1", "cursor-9", true, now)
            .await
            .expect("event"));
        assert!(!store
            .append_event("vol-1", "hist-1", "cursor-9", true, now)
            .await
            .expect("event dup"));
        let events = store.list_events("vol-1", "hist-1").await.expect("list");
        assert_eq!(events.len(), 1);
        assert!(events[0].ingested);
        store
            .mark_event_reconciled(events[0].id)
            .await
            .expect("reconcile");
        let events = store.list_events("vol-1", "hist-1").await.expect("list");
        assert!(events[0].reconciled);

        assert!(store
            .enqueue_task(
                &NewTask {
                    id: "task-1",
                    kind: "enumerate_dir",
                    generation,
                    dir_id: Some(dir_id),
                    scope_key: "all",
                    expected_rev: 0,
                    idempotency_key: "idem-task-1",
                },
                now,
            )
            .await
            .expect("enqueue"));
        let claimed = store
            .claim_tasks(store.epoch(), 10, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        store
            .complete_task(
                "task-1",
                claimed[0].token,
                store.epoch(),
                &TaskOutcome::Complete,
                now,
            )
            .await
            .expect("complete");
        assert_eq!(store.pending_count(generation).await.expect("count"), 0);

        assert_eq!(store.next_revision().await.expect("rev"), 1);
        assert_eq!(store.current_revision().await.expect("rev"), 1);

        let (busy, _log, _done) = store.checkpoint().await.expect("checkpoint");
        assert_eq!(busy, 0);
        let wal = store.wal_status().await.expect("wal");
        assert_eq!(wal.busy, 0);

        let reader = store.open_reader().await.expect("reader");
        let mut rows = reader
            .query("SELECT COUNT(*) FROM directories", ())
            .await
            .expect("reader query");
        let row = rows.next().await.expect("reader next").expect("row");
        assert_eq!(row.get_value(0).expect("value"), turso::Value::Integer(1));

        let first_epoch = store.epoch();
        store.close().await.expect("close");

        let reopened = TursoStore::open(&db).await.expect("reopen");
        assert!(reopened.epoch() > first_epoch);
        let dir = reopened.get_dir(dir_id).await.expect("get").expect("row");
        assert_eq!(dir.component, component);
        let task = reopened
            .get_task("task-1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(task.state, TaskState::Complete);
        let scan_row = reopened
            .get_scan("scan-1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(scan_row.outcome.as_deref(), Some("ok"));
        assert_eq!(reopened.list_statuses("co-1").await.expect("list").len(), 1);
        reopened.close().await.expect("close");
    });
}

#[test]
fn expired_leases_return_to_pending() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let epoch = store.epoch();
        let now = now_ms();

        store
            .enqueue_task(
                &NewTask {
                    id: "t-lease",
                    kind: "enumerate_dir",
                    generation: 1,
                    dir_id: None,
                    scope_key: "s",
                    expected_rev: 0,
                    idempotency_key: "idem-lease",
                },
                now,
            )
            .await
            .expect("enqueue");

        let claimed = store
            .claim_tasks(epoch, 10, 1_000, now)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        let token = claimed[0].token;

        // Wrong token must not renew.
        assert!(!store
            .renew_lease("t-lease", 999_999, epoch, 1_000, now)
            .await
            .expect("renew wrong"));
        // Right token renews.
        assert!(store
            .renew_lease("t-lease", token, epoch, 1_000, now)
            .await
            .expect("renew"));

        // Not yet expired: nothing moves.
        assert_eq!(store.expire_leases(now + 999).await.expect("expire"), 0);
        // Past expiry: returns to pending.
        assert_eq!(store.expire_leases(now + 1_001).await.expect("expire"), 1);
        let task = store.get_task("t-lease").await.expect("get").expect("row");
        assert_eq!(task.state, TaskState::Pending);
        assert_eq!(task.lease_token, None);

        // Reclaim under the same epoch; the old token can no longer complete.
        let later = now + 60_000;
        let reclaimed = store
            .claim_tasks(epoch, 10, 1_000, later)
            .await
            .expect("reclaim");
        assert_eq!(reclaimed.len(), 1);
        let stale = store
            .complete_task("t-lease", token, epoch, &TaskOutcome::Complete, later)
            .await
            .unwrap_err();
        assert!(stale.to_string().contains("lease-mismatch"), "{stale}");
        store
            .complete_task(
                "t-lease",
                reclaimed[0].token,
                epoch,
                &TaskOutcome::Complete,
                later,
            )
            .await
            .expect("complete");

        // Retry outcome parks the task with a preserved gap; it becomes
        // claimable again only after its retry time.
        store
            .enqueue_task(
                &NewTask {
                    id: "t-retry",
                    kind: "probe_git",
                    generation: 1,
                    dir_id: None,
                    scope_key: "s",
                    expected_rev: 0,
                    idempotency_key: "idem-retry",
                },
                later,
            )
            .await
            .expect("enqueue");
        let claimed = store
            .claim_tasks(epoch, 10, 1_000, later)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        store
            .complete_task(
                "t-retry",
                claimed[0].token,
                epoch,
                &TaskOutcome::Retry {
                    category: "stalled".to_string(),
                    detail: "helper stuck".to_string(),
                    retry_after_ms: later + 1_000,
                },
                later,
            )
            .await
            .expect("retry");
        let task = store.get_task("t-retry").await.expect("get").expect("row");
        assert_eq!(task.state, TaskState::RetryWait);
        assert!(store.get_error("gap:t-retry").await.expect("get").is_some());
        assert!(store
            .claim_tasks(epoch, 10, 1_000, later)
            .await
            .expect("claim early")
            .is_empty());
        let claimed = store
            .claim_tasks(epoch, 10, 1_000, later + 1_001)
            .await
            .expect("claim after retry");
        assert_eq!(claimed.len(), 1);

        // Only unavailable/unsupported are valid parked states.
        let bad = store
            .complete_task(
                "t-retry",
                claimed[0].token,
                epoch,
                &TaskOutcome::Parked {
                    state: TaskState::Complete,
                    reason: "bogus".to_string(),
                },
                later + 1_001,
            )
            .await
            .unwrap_err();
        assert!(bad.to_string().contains("invalid-parked-state"), "{bad}");
        store
            .complete_task(
                "t-retry",
                claimed[0].token,
                epoch,
                &TaskOutcome::Parked {
                    state: TaskState::Unavailable,
                    reason: "volume offline".to_string(),
                },
                later + 1_001,
            )
            .await
            .expect("park");
        let task = store.get_task("t-retry").await.expect("get").expect("row");
        assert_eq!(task.state, TaskState::Unavailable);

        store.close().await.expect("close");
    });
}

#[test]
fn stale_completion_is_rejected_and_requeued() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let epoch = store.epoch();
        let now = now_ms();

        store
            .enqueue_task(
                &NewTask {
                    id: "t-stale",
                    kind: "enumerate_dir",
                    generation: 1,
                    dir_id: None,
                    scope_key: "s1",
                    expected_rev: 0,
                    idempotency_key: "idem-stale",
                },
                now,
            )
            .await
            .expect("enqueue");
        let claimed = store
            .claim_tasks(epoch, 10, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);

        // Invalidation lands while the task is leased.
        assert_eq!(store.invalidate_scope("s1", 1, now).await.expect("inv"), 1);
        assert_eq!(store.scope_rev("s1").await.expect("rev"), 1);
        let reconcile = store
            .get_task("reconcile:s1:1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(reconcile.state, TaskState::Pending);

        // The stale completion must not erase the invalidation.
        let stale = store
            .complete_task(
                "t-stale",
                claimed[0].token,
                epoch,
                &TaskOutcome::Complete,
                now,
            )
            .await
            .unwrap_err();
        assert!(stale.to_string().contains("stale-completion"), "{stale}");
        let task = store.get_task("t-stale").await.expect("get").expect("row");
        assert_eq!(task.state, TaskState::Pending);
        assert_eq!(task.expected_rev, 1);
        assert_eq!(store.scope_rev("s1").await.expect("rev"), 1);

        // A fresh claim observes the new revision and completes cleanly.
        let claimed = store
            .claim_tasks(epoch, 10, 60_000, now)
            .await
            .expect("claim");
        assert!(claimed.iter().any(|entry| entry.task.id == "t-stale"));
        let fresh = claimed
            .into_iter()
            .find(|entry| entry.task.id == "t-stale")
            .expect("fresh claim");
        assert_eq!(fresh.task.expected_rev, 1);
        store
            .complete_task("t-stale", fresh.token, epoch, &TaskOutcome::Complete, now)
            .await
            .expect("complete");
        let task = store.get_task("t-stale").await.expect("get").expect("row");
        assert_eq!(task.state, TaskState::Complete);

        store.close().await.expect("close");
    });
}

#[test]
fn writer_batch_limits_and_idempotent_commit() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let now = now_ms();

        // Small batch: no limit reached.
        let mut batch = WriterBatch::new();
        assert!(batch.is_empty());
        let error_sql = "INSERT OR IGNORE INTO errors (id, scope_key, category, detail, attempts, \
                first_seen_ms, last_seen_ms, open) VALUES (?1, 's', 'c', 'd', 1, ?2, ?2, 1)";
        assert!(!batch.push(
            error_sql,
            vec![
                turso::Value::Text("pad-small".to_string()),
                turso::Value::Integer(now),
            ],
        ));
        assert_eq!(batch.len(), 1);
        assert!(!batch.should_flush());
        assert_eq!(store.flush(&mut batch).await.expect("flush"), 1);
        assert!(batch.is_empty());
        assert!(store.get_error("pad-small").await.expect("get").is_some());

        // Row limit: the 512th op trips should_flush; one commit applies all.
        let mut batch = WriterBatch::new();
        for index in 0..512 {
            let due = batch.push(
                error_sql,
                vec![
                    turso::Value::Text(format!("pad-{index}")),
                    turso::Value::Integer(now),
                ],
            );
            assert_eq!(due, index == 511, "pad-{index}");
        }
        assert!(batch.should_flush());
        assert_eq!(store.flush(&mut batch).await.expect("flush"), 512);
        assert!(store.get_error("pad-511").await.expect("get").is_some());

        // Byte limit: a single 512 KiB parameter trips should_flush.
        let mut batch = WriterBatch::new();
        assert!(batch.push(
            error_sql,
            vec![
                turso::Value::Blob(vec![7u8; 512 * 1024]),
                turso::Value::Integer(now),
            ],
        ));

        // Idempotent commit: a duplicate key skips the replayed batch.
        let mut first = WriterBatch::new();
        first.push(
            error_sql,
            vec![
                turso::Value::Text("batch-op-1".to_string()),
                turso::Value::Integer(now),
            ],
        );
        assert_eq!(
            store
                .commit_batch("batch-k1", &mut first, now)
                .await
                .expect("commit"),
            1
        );
        assert!(store
            .reconcile_idempotency_key("batch-k1")
            .await
            .expect("rec"));
        assert!(!store
            .reconcile_idempotency_key("batch-absent")
            .await
            .expect("rec"));
        let mut replay = WriterBatch::new();
        replay.push(
            error_sql,
            vec![
                turso::Value::Text("batch-op-1".to_string()),
                turso::Value::Integer(now),
            ],
        );
        assert_eq!(
            store
                .commit_batch("batch-k1", &mut replay, now)
                .await
                .expect("replay"),
            0
        );
        assert!(replay.is_empty());

        // Uncertain markers are reconciled on recovery.
        store
            .note_uncertain_batch("batch-lost", now)
            .await
            .expect("note");
        assert!(store
            .reconcile_idempotency_key("batch-lost")
            .await
            .expect("rec"));
        let report = store.recover_now(now).await.expect("recover");
        assert_eq!(report.uncertain_dropped, 1);
        assert!(!store
            .reconcile_idempotency_key("batch-lost")
            .await
            .expect("rec"));

        store.close().await.expect("close");
    });
}

#[test]
fn owner_lock_is_exclusive_and_epochs_fence() {
    let dir = tempfile::tempdir().expect("tempdir");

    let guard = OwnerGuard::acquire(dir.path()).expect("acquire");
    assert_eq!(guard.state_dir(), dir.path());
    assert_eq!(
        guard.db_path(),
        dir.path().join("payload").join("catalog.db")
    );
    // Second acquisition while held must fail (lock outside payload/).
    assert!(OwnerGuard::acquire(dir.path()).is_err());
    assert!(dir.path().join("instance.lock").exists());
    drop(guard);

    let rt = runtime();
    rt.block_on(async {
        let (guard, store) = TursoStore::open_owned(dir.path()).await.expect("owned");
        assert!(guard.epoch() >= 1);
        assert_eq!(guard.epoch(), store.epoch());
        assert_eq!(guard.db_path(), db_in(&dir));
        let first = guard.epoch();
        store.close().await.expect("close");
        drop(guard);

        // Next owner incarnation claims the next epoch.
        let (guard, store) = TursoStore::open_owned(dir.path()).await.expect("owned");
        assert_eq!(guard.epoch(), first + 1);
        store.close().await.expect("close");
    });
}

/// `complete_task_report_gap` reports the gap delta each outcome caused:
/// `Retry`/`Parked` open, `Complete` closes only a genuinely open row,
/// and a clean task reports nothing.
#[test]
fn completion_delta_reports_open_then_close() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = db_in(&dir);
        let store = TursoStore::open(&db).await.expect("open");
        let epoch = store.epoch();
        let base = now_ms();

        for (id, idem) in [("t-delta", "idem-delta"), ("t-park", "idem-park")] {
            assert!(store
                .enqueue_task(
                    &NewTask {
                        id,
                        kind: "probe_git",
                        generation: 1,
                        dir_id: None,
                        scope_key: "s",
                        expected_rev: 0,
                        idempotency_key: idem,
                    },
                    base,
                )
                .await
                .expect("enqueue"));
        }
        let claimed = store
            .claim_tasks(epoch, 10, 60_000, base)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 2);
        let token_for = |id: &str| {
            claimed
                .iter()
                .find(|entry| entry.task.id == id)
                .unwrap_or_else(|| panic!("claimed {id}"))
                .token
        };

        // Retry opens `gap:t-delta`; nothing closes.
        let delta = store
            .complete_task_report_gap(
                "t-delta",
                token_for("t-delta"),
                epoch,
                &TaskOutcome::Retry {
                    category: "stalled".to_string(),
                    detail: "helper stuck".to_string(),
                    retry_after_ms: base + 1_000,
                },
                base,
            )
            .await
            .expect("retry");
        let opened = delta.opened.expect("retry opens");
        assert_eq!(opened.id, "gap:t-delta");
        assert_eq!(opened.category, "stalled");
        assert!(delta.closed.is_none());
        let row = store
            .get_error("gap:t-delta")
            .await
            .expect("get")
            .expect("row");
        assert!(row.open);

        // Parked opens `gap:t-park` the same way.
        let delta = store
            .complete_task_report_gap(
                "t-park",
                token_for("t-park"),
                epoch,
                &TaskOutcome::Parked {
                    state: TaskState::Unavailable,
                    reason: "volume offline".to_string(),
                },
                base,
            )
            .await
            .expect("park");
        assert_eq!(delta.opened.expect("park opens").id, "gap:t-park");
        assert!(delta.closed.is_none());

        // Reclaim after backoff; success closes the open row.
        let claimed = store
            .claim_tasks(epoch, 10, 60_000, base + 1_001)
            .await
            .expect("reclaim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].task.id, "t-delta");
        let delta = store
            .complete_task_report_gap(
                "t-delta",
                claimed[0].token,
                epoch,
                &TaskOutcome::Complete,
                base + 1_001,
            )
            .await
            .expect("complete");
        assert!(delta.opened.is_none());
        assert_eq!(delta.closed.as_deref(), Some("gap:t-delta"));
        let row = store
            .get_error("gap:t-delta")
            .await
            .expect("get")
            .expect("row");
        assert!(!row.open);

        // A task that never failed reports no delta at all.
        assert!(store
            .enqueue_task(
                &NewTask {
                    id: "t-clean",
                    kind: "probe_git",
                    generation: 1,
                    dir_id: None,
                    scope_key: "s",
                    expected_rev: 0,
                    idempotency_key: "idem-clean",
                },
                base + 1_001,
            )
            .await
            .expect("enqueue"));
        let claimed = store
            .claim_tasks(epoch, 10, 60_000, base + 1_001)
            .await
            .expect("claim clean");
        assert_eq!(claimed.len(), 1);
        let delta = store
            .complete_task_report_gap(
                "t-clean",
                claimed[0].token,
                epoch,
                &TaskOutcome::Complete,
                base + 1_001,
            )
            .await
            .expect("complete clean");
        assert!(delta.opened.is_none());
        assert!(delta.closed.is_none());

        // Only the parked gap stays open.
        assert_eq!(
            store.list_open_error_ids().await.expect("list"),
            vec!["gap:t-park".to_string()]
        );
        store.close().await.expect("close");
    });
}

/// v4 resilience: a corrupt negative `workers` value resolves to `None`
/// (runtime default) instead of failing the scan-request read — resume
/// never breaks on a bad stored value.
#[test]
fn negative_workers_reads_as_none() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = db_in(&dir);
        let store = TursoStore::open(&db).await.expect("open");
        let now = now_ms();
        store
            .create_scan_request(
                &NewScan {
                    id: "scan-neg",
                    url_raw: b"https://github.com/OWNER/REPO",
                    url_canonical: None,
                    scope: "machine",
                    status_mode: "summary",
                    report_dest: None,
                    targets_json: None,
                    format: None,
                    all_targets: None,
                    fetch: None,
                    workers: Some(4),
                },
                now,
            )
            .await
            .expect("scan");
        store
            .connection()
            .execute(
                "UPDATE scan_requests SET workers = -1 WHERE id = 'scan-neg'",
                (),
            )
            .await
            .expect("corrupt workers");
        let row = store.get_scan("scan-neg").await.expect("get").expect("row");
        assert_eq!(row.workers, None);
        assert_eq!(repo_scan::config::restore_workers(row.workers), None);
        store.close().await.expect("close");
    });
}
