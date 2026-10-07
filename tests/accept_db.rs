//! Durability, error, and cache acceptance (DB-02/DB-03 feasible subset,
//! ERROR-01/ERROR-02, CACHE-01/CACHE-02; spec sections 10-12, 14-15).
//!
//! Every database lives in a tempdir; every CLI run uses explicit `--root`
//! and `--state-dir` (never a whole-machine scan) via
//! `env!("CARGO_BIN_EXE_repo-scan")`. Tests assert meaningful outcomes:
//! exit codes, report contents, and catalog state.
//!
//! Honestly static (no live fault-injection hook exists in this
//! implementation): ERROR-01 stall watchdogs and ERROR-02 helper
//! replacement are policy-unit tests over `Admission`, `CircuitBreaker`,
//! and `backoff_for_attempt`; the owner executes tasks sequentially inline
//! and spawns zero helper processes. Disk-full and sync-error injection
//! likewise have no hook, so DB-02 covers the feasible subset
//! (commit/rollback/cancel/read-write/migration/checkpoint/
//! durability-proof/visible-failure).

mod common;

use common::fixture;
use repo_scan::config::ResourceLimits;
use repo_scan::model::{ExitCode, TaskState};
use repo_scan::scheduler::{backoff_for_attempt, Admission, CircuitBreaker, OpClass};
use repo_scan::store::{
    now_ms, NewTask, NewVolume, Store, TaskOutcome, TursoStore, WriterBatch, CURRENT_SCHEMA_VERSION,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

const URL: &str = "https://github.com/OWNER/REPO";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Base CLI invocation with an explicit state dir and caller dir.
fn cmd(state: &Path, cwd: &Path) -> Command {
    let mut command = Command::new(binary());
    command.arg("--state-dir").arg(state).current_dir(cwd);
    command
}

/// Run the binary with static args; tempdirs plus explicit roots only.
fn run(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    cmd(state, cwd)
        .args(args)
        .output()
        .expect("spawn repo-scan")
}

fn stderr_text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout_line(out: &std::process::Output, key: &str) -> String {
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(&format!("{key}:")) {
            return value.trim().to_string();
        }
    }
    panic!("missing `{key}:` in stdout:\n{text}");
}

fn report_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("report is JSON")
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn fresh_db(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("payload").join("catalog.db")
}

/// Minimal local volume row for durability tests.
fn vol(id: &str) -> NewVolume<'_> {
    NewVolume {
        id,
        native_identity: None,
        namespace: "ns",
        filesystem: None,
        kind: "local",
        state: "available",
    }
}

/// DB-02: a committed row survives reopen; a failing transaction rolls back
/// with no partial row and the connection stays usable afterwards.
#[test]
fn db02_commit_persists_and_rollback_discards() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = fresh_db(&dir);
        let store = TursoStore::open(&db).await.expect("open");
        store
            .upsert_volume(&vol("vol-commit"), Some(now_ms()))
            .await
            .expect("upsert");
        store.close().await.expect("close");

        let store = TursoStore::open(&db).await.expect("reopen");
        assert!(store.get_volume("vol-commit").await.expect("get").is_some());

        let err = store
            .with_tx(|conn| async move {
                conn.execute(
                    "INSERT INTO volumes (id, namespace, kind, state) \
                     VALUES ('vol-tx', 'ns', 'local', 'available')",
                    (),
                )
                .await
                .map_err(|e| repo_scan::Error::Store(e.to_string()))?;
                Err::<(), repo_scan::Error>(repo_scan::Error::Store("boom".to_string()))
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("boom"), "{err}");
        assert!(store.get_volume("vol-tx").await.expect("get").is_none());
        store
            .upsert_volume(&vol("vol-after"), Some(now_ms()))
            .await
            .expect("upsert after rollback");
        assert!(store.get_volume("vol-after").await.expect("get").is_some());
        store.close().await.expect("close");
    });
}

/// DB-02: a lease abandoned by a dead owner (dropped with no completion or
/// close) returns to `pending` on the next open; nothing completes by
/// phantom and the incarnation epoch advances.
#[test]
fn db02_cancelled_lease_requeues_on_reopen() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = fresh_db(&dir);
        let store = TursoStore::open(&db).await.expect("open");
        let first_epoch = store.epoch();
        let now = now_ms();
        let task = NewTask {
            id: "t-cancel",
            kind: "enumerate_dir",
            generation: 1,
            dir_id: None,
            scope_key: "dir:cancel",
            expected_rev: 0,
            idempotency_key: "idem-cancel",
        };
        store.enqueue_task(&task, now).await.expect("enqueue");
        let claimed = store
            .claim_tasks(first_epoch, 10, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        drop(store); // Crash: no completion, no close, no checkpoint.

        let store = TursoStore::open(&db).await.expect("reopen");
        assert!(store.epoch() > first_epoch);
        let task = store.get_task("t-cancel").await.expect("get").expect("row");
        assert_eq!(task.state, TaskState::Pending);
        assert_eq!(task.lease_token, None);
        // Recovery already ran at open; nothing further moves.
        let report = store.recover_now(now_ms()).await.expect("recover");
        assert_eq!(report.requeued, 0);
        // The work itself is intact and can finish normally.
        let epoch = store.epoch();
        let claimed = store
            .claim_tasks(epoch, 10, 60_000, now_ms())
            .await
            .expect("reclaim");
        assert_eq!(claimed.len(), 1);
        store
            .complete_task(
                "t-cancel",
                claimed[0].token,
                epoch,
                &TaskOutcome::Complete,
                now_ms(),
            )
            .await
            .expect("complete");
        let task = store.get_task("t-cancel").await.expect("get").expect("row");
        assert_eq!(task.state, TaskState::Complete);
        store.close().await.expect("close");
    });
}

/// DB-02: read/write interleaving (a same-process reader observes writer
/// commits), checkpoint coordination, migration identity, and asserted
/// durability PRAGMAs (never silently downgraded).
#[test]
fn db02_reader_checkpoint_migration_durability() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = fresh_db(&dir);
        let store = TursoStore::open(&db).await.expect("open");
        assert_eq!(
            store.schema_version().expect("version"),
            CURRENT_SCHEMA_VERSION
        );
        assert_eq!(CURRENT_SCHEMA_VERSION, 6);
        let chain = repo_scan::store::migrations();
        assert_eq!(chain.len(), 6);
        assert_eq!(chain[0].version, 1);
        assert_eq!(chain[1].version, 2);
        assert_eq!(chain[2].version, 3);
        assert_eq!(chain[3].version, 4);
        assert_eq!(chain[4].version, 5);
        assert_eq!(chain[5].version, 6);

        let proof = store.durability_proof().await.expect("proof");
        assert_eq!(proof.synchronous, 2);
        assert_eq!(proof.data_sync_retry, 1);
        assert_eq!(proof.journal_mode.to_lowercase(), "wal");
        #[cfg(target_os = "macos")]
        assert_eq!(proof.fullfsync, Some(1));

        let now = now_ms();
        for id in ["vol-r1", "vol-r2"] {
            store
                .upsert_volume(&vol(id), Some(now))
                .await
                .expect("upsert");
        }
        // The reader and its rows must be fully dropped before the
        // checkpoint: an open read snapshot holds the WAL busy by design.
        {
            let reader = store.open_reader().await.expect("reader");
            let mut rows = reader
                .query("SELECT COUNT(*) FROM volumes", ())
                .await
                .expect("reader query");
            let row = rows.next().await.expect("next").expect("row");
            assert_eq!(row.get_value(0).expect("value"), turso::Value::Integer(2));
        }

        let (busy, _log, _checkpointed) = store.checkpoint_truncate().await.expect("checkpoint");
        assert_eq!(busy, 0);
        assert_eq!(store.wal_status().await.expect("wal").busy, 0);
        store.close().await.expect("close");

        let store = TursoStore::open(&db).await.expect("reopen");
        assert_eq!(store.schema_version().expect("version"), 6);
        assert!(store.get_volume("vol-r1").await.expect("get").is_some());
        assert!(store.get_volume("vol-r2").await.expect("get").is_some());
        store.close().await.expect("close");
    });
}

/// DB-02 feasible-subset boundary: a storage failure surfaces as an
/// operational error, never silent success (disk-full/sync-error injection
/// has no hook; see module docs).
#[test]
fn db02_storage_failure_is_visible() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blocker = dir.path().join("blocker");
    repo_scan::privacy::private_write_0600(&blocker, b"not a directory").expect("write");
    let rt = runtime();
    rt.block_on(async {
        let err = TursoStore::open(&blocker.join("catalog.db"))
            .await
            .err()
            .expect("expected open failure");
        assert!(!err.to_string().is_empty());
        assert_eq!(err.exit_code(), ExitCode::OperationalFailure);
    });
}

/// DB-03: crash between claim and completion (dropped with no close or
/// checkpoint): the acknowledged completion survives, the unacknowledged
/// claim is requeued rather than phantom-completed, and the committed
/// invalidation revision persists.
#[test]
fn db03_crash_boundaries_preserve_acknowledged_work() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = fresh_db(&dir);
        let store = TursoStore::open(&db).await.expect("open");
        let epoch = store.epoch();
        let now = now_ms();
        for (id, scope, idem) in [
            ("t-ack", "scope-ack", "idem-ack"),
            ("t-noack", "scope-noack", "idem-noack"),
        ] {
            let task = NewTask {
                id,
                kind: "enumerate_dir",
                generation: 1,
                dir_id: None,
                scope_key: scope,
                expected_rev: 0,
                idempotency_key: idem,
            };
            store.enqueue_task(&task, now).await.expect("enqueue");
        }
        let claimed = store
            .claim_tasks(epoch, 10, 60_000, now)
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
        store
            .complete_task(
                "t-ack",
                token_for("t-ack"),
                epoch,
                &TaskOutcome::Complete,
                now,
            )
            .await
            .expect("ack");
        assert_eq!(
            store
                .invalidate_scope("scope-noack", 1, now)
                .await
                .expect("invalidate"),
            1
        );
        drop(store); // Crash before t-noack completes.

        let store = TursoStore::open(&db).await.expect("reopen");
        let acked = store.get_task("t-ack").await.expect("get").expect("row");
        assert_eq!(
            acked.state,
            TaskState::Complete,
            "acknowledged completion survives"
        );
        let pending = store.get_task("t-noack").await.expect("get").expect("row");
        assert_eq!(
            pending.state,
            TaskState::Pending,
            "unacknowledged claim requeues"
        );
        assert_eq!(
            store.scope_rev("scope-noack").await.expect("rev"),
            1,
            "committed invalidation persists"
        );
        // The requeued task still carries its pre-crash revision, so its
        // next completion is stale and adopts the newer rev instead of
        // erasing it.
        let epoch = store.epoch();
        let later = now_ms();
        let claimed = store
            .claim_tasks(epoch, 10, 60_000, later)
            .await
            .expect("reclaim");
        // Both the requeued task and its scheduled reconciliation are
        // claimable; drive the stale completion on the requeued task.
        assert_eq!(claimed.len(), 2);
        let retry = claimed
            .iter()
            .find(|entry| entry.task.id == "t-noack")
            .expect("requeued claim");
        let stale = store
            .complete_task("t-noack", retry.token, epoch, &TaskOutcome::Complete, later)
            .await
            .unwrap_err();
        assert!(stale.to_string().contains("stale-completion"), "{stale}");
        let task = store.get_task("t-noack").await.expect("get").expect("row");
        assert_eq!((task.state, task.expected_rev), (TaskState::Pending, 1));
        let claimed = store
            .claim_tasks(epoch, 10, 60_000, later)
            .await
            .expect("reclaim");
        let fresh = claimed
            .into_iter()
            .find(|entry| entry.task.id == "t-noack")
            .expect("fresh claim");
        store
            .complete_task("t-noack", fresh.token, epoch, &TaskOutcome::Complete, later)
            .await
            .expect("complete");
        let task = store.get_task("t-noack").await.expect("get").expect("row");
        assert_eq!(task.state, TaskState::Complete);
        store.close().await.expect("close");
    });
}

/// DB-03: rows committed before the first checkpoint survive a crash
/// (dropped with no close and no checkpoint) via WAL durability.
#[test]
fn db03_writes_before_first_checkpoint_survive() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = fresh_db(&dir);
        let store = TursoStore::open(&db).await.expect("open");
        let now = now_ms();
        store
            .upsert_volume(&vol("vol-early"), Some(now))
            .await
            .expect("upsert");
        let task = NewTask {
            id: "t-early",
            kind: "enumerate_dir",
            generation: 1,
            dir_id: None,
            scope_key: "dir:early",
            expected_rev: 0,
            idempotency_key: "idem-early",
        };
        store.enqueue_task(&task, now).await.expect("enqueue");
        let generation = store
            .create_generation("roots", "running", None, now)
            .await
            .expect("generation");
        assert_eq!(store.next_revision().await.expect("rev"), 1);
        drop(store); // Crash before any checkpoint.

        let store = TursoStore::open(&db).await.expect("reopen");
        assert!(store.get_volume("vol-early").await.expect("get").is_some());
        assert!(store.get_task("t-early").await.expect("get").is_some());
        assert!(store
            .get_generation(generation)
            .await
            .expect("get")
            .is_some());
        assert_eq!(store.current_revision().await.expect("rev"), 1);
        store.close().await.expect("close");
    });
}

/// DB-03: after an explicit WAL reset, the first acknowledged commit
/// following it survives a crash.
#[test]
fn db03_commit_after_wal_reset_survives() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = fresh_db(&dir);
        let store = TursoStore::open(&db).await.expect("open");
        store
            .upsert_volume(&vol("vol-a"), Some(now_ms()))
            .await
            .expect("upsert");
        let (busy, _log, _checkpointed) = store.checkpoint_truncate().await.expect("checkpoint");
        assert_eq!(busy, 0);
        store
            .upsert_volume(&vol("vol-b"), Some(now_ms()))
            .await
            .expect("upsert after reset");
        let task = NewTask {
            id: "t-after",
            kind: "enumerate_dir",
            generation: 1,
            dir_id: None,
            scope_key: "dir:after",
            expected_rev: 0,
            idempotency_key: "idem-after",
        };
        store.enqueue_task(&task, now_ms()).await.expect("enqueue");
        drop(store); // Crash right after the post-reset commits.

        let store = TursoStore::open(&db).await.expect("reopen");
        assert!(store.get_volume("vol-a").await.expect("get").is_some());
        assert!(store.get_volume("vol-b").await.expect("get").is_some());
        let task = store.get_task("t-after").await.expect("get").expect("row");
        assert_eq!(task.state, TaskState::Pending);
        store.close().await.expect("close");
    });
}

/// DB-03: lost-acknowledgment handling. A committed batch key is never
/// re-applied (replay returns 0 applied ops); an uncertain marker
/// reconciles as committed until recovery drops it, after which the key is
/// safe to apply exactly once.
#[test]
fn db03_idempotent_replay_and_uncertain_reconcile() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&fresh_db(&dir)).await.expect("open");
        let now = now_ms();
        let error_sql = "INSERT OR IGNORE INTO errors (id, scope_key, category, \
            detail, attempts, first_seen_ms, last_seen_ms, open) \
            VALUES (?1, 's', 'c', 'd', 1, ?2, ?2, 1)";
        let mut first = WriterBatch::new();
        assert!(!first.push(
            error_sql,
            vec![
                turso::Value::Text("db03-op-1".to_string()),
                turso::Value::Integer(now),
            ],
        ));
        assert_eq!(
            store
                .commit_batch("db03-k1", &mut first, now)
                .await
                .expect("commit"),
            1
        );
        let mut replay = WriterBatch::new();
        assert!(!replay.push(
            error_sql,
            vec![
                turso::Value::Text("db03-op-1".to_string()),
                turso::Value::Integer(now),
            ],
        ));
        assert_eq!(
            store
                .commit_batch("db03-k1", &mut replay, now)
                .await
                .expect("replay"),
            0
        );
        assert!(replay.is_empty());
        assert!(store
            .reconcile_idempotency_key("db03-k1")
            .await
            .expect("reconcile"));
        assert!(!store
            .reconcile_idempotency_key("db03-absent")
            .await
            .expect("reconcile"));

        store
            .note_uncertain_batch("db03-lost", now)
            .await
            .expect("note");
        assert!(store
            .reconcile_idempotency_key("db03-lost")
            .await
            .expect("reconcile"));
        let report = store.recover_now(now).await.expect("recover");
        assert_eq!(report.uncertain_dropped, 1);
        assert!(!store
            .reconcile_idempotency_key("db03-lost")
            .await
            .expect("reconcile"));
        let mut apply = WriterBatch::new();
        assert!(!apply.push(
            error_sql,
            vec![
                turso::Value::Text("db03-op-lost".to_string()),
                turso::Value::Integer(now),
            ],
        ));
        assert_eq!(
            store
                .commit_batch("db03-lost", &mut apply, now)
                .await
                .expect("apply"),
            1
        );
        store.close().await.expect("close");
    });
}

/// DB-03: corrupt and truncated payloads fail visibly (open or read error)
/// or present an empty catalog — never phantom acknowledged work and never
/// a panic.
#[test]
fn db03_corrupt_and_truncated_payload_fail_visibly() {
    let rt = runtime();
    let garbage = tempfile::tempdir().expect("tempdir");
    let garbage_db = fresh_db(&garbage);
    repo_scan::privacy::private_dir_0700(garbage_db.parent().expect("parent")).expect("mkdir");
    repo_scan::privacy::private_write_0600(&garbage_db, &vec![0x58u8; 4096]).expect("write");
    rt.block_on(assert_no_phantom_ack(&garbage_db));

    let trunc = tempfile::tempdir().expect("tempdir");
    let trunc_db = fresh_db(&trunc);
    rt.block_on(async {
        let store = TursoStore::open(&trunc_db).await.expect("open");
        store
            .upsert_volume(&vol("vol-trunc"), Some(now_ms()))
            .await
            .expect("upsert");
        store.close().await.expect("close");
    });
    std::fs::OpenOptions::new()
        .write(true)
        .open(&trunc_db)
        .expect("open")
        .set_len(96)
        .expect("truncate");
    rt.block_on(assert_no_phantom_ack(&trunc_db));
}

/// Open a suspect payload: an error anywhere is the honest visible
/// outcome; a tolerated open must show zero acknowledged rows.
async fn assert_no_phantom_ack(db: &Path) {
    match TursoStore::open(db).await {
        Err(_) => {}
        Ok(store) => {
            match count_acknowledged(&store).await {
                Err(_) => {}
                Ok(total) => assert_eq!(total, 0, "tolerated payload must be empty"),
            }
            let _ = store.close().await;
        }
    }
}

async fn count_acknowledged(store: &TursoStore) -> Result<i64, String> {
    let mut total = 0i64;
    for table in [
        "volumes",
        "frontier_tasks",
        "generations",
        "git_instances",
        "scan_requests",
    ] {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let mut rows = store
            .connection()
            .query(sql.as_str(), ())
            .await
            .map_err(|e| e.to_string())?;
        let row = rows
            .next()
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "no count row".to_string())?;
        match row.get_value(0).map_err(|e| e.to_string())? {
            turso::Value::Integer(n) => total += n,
            other => return Err(format!("non-integer count: {other:?}")),
        }
    }
    Ok(total)
}

/// ERROR-01 (unix): a permission-denied scope is a preserved gap (exit 3)
/// while independent scope still completes; after restore plus invalidate
/// plus rescan the scope is covered. The historical gap record stays open,
/// so the run still exits 3 — conservative and honest, never a false
/// success.
#[cfg(unix)]
#[test]
fn error01_permission_denied_then_restored() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let state = tmp.path().join("state");
    let root = tmp.path().join("fixture");
    let ok = root.join("ok");
    repo_scan::privacy::private_dir_0700(&ok).expect("mkdir");
    fixture::normal_clone(&ok, "repo");
    let denied = root.join("denied");
    repo_scan::privacy::private_dir_0700(&denied).expect("mkdir");
    fixture::normal_clone(&denied, "repo");
    let report = tmp.path().join("rep.json");
    let report_s = report.to_str().expect("utf8").to_string();
    let root_s = root.to_str().expect("utf8").to_string();

    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).expect("lock out");
    let lockout_effective = std::fs::read_dir(&denied).is_err();
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_s.as_str(),
            "--report",
            report_s.as_str(),
        ],
        tmp.path(),
        &state,
    );
    if lockout_effective {
        assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
        let rep = report_json(&report);
        assert!(
            rep["coverage"]["gaps"].as_u64().unwrap_or(0) >= 1,
            "denied scope is a gap: {rep}"
        );
        assert_eq!(rep["coverage"]["filesystem"].as_str(), Some("incomplete"));
        // Independent work progressed despite the gap.
        assert_eq!(
            rep["repositories"].as_array().map(|a| a.len()),
            Some(1),
            "ok repo still found: {rep}"
        );
    } else {
        eprintln!("note: permission lockout ineffective here; gap branch skipped");
    }
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o755)).expect("restore");

    let denied_s = denied.to_str().expect("utf8").to_string();
    let out = run(
        &["cache", "invalidate", "--root", denied_s.as_str()],
        tmp.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_s.as_str(),
            "--report",
            report_s.as_str(),
        ],
        tmp.path(),
        &state,
    );
    let rep = report_json(&report);
    assert_eq!(
        rep["repositories"].as_array().map(|a| a.len()),
        Some(2),
        "restored scope covered: {rep}"
    );
    for repo in rep["repositories"].as_array().expect("repos") {
        assert_eq!(repo["match"].as_str(), Some("confirmed"), "{repo}");
    }
    if lockout_effective {
        assert_eq!(
            out.status.code(),
            Some(3),
            "historical gap record keeps exit 3: {}",
            stderr_text(&out)
        );
    } else {
        assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    }
    // The incomplete scan never deleted the older finding.
    let out = run(&["query", URL, "--cached"], tmp.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert_eq!(stdout_line(&out, "matches"), "2");
}

/// ERROR-01: a missing (offline/unavailable) root is a durable gap with
/// exit 3, not a crash; catalog state is still written.
#[test]
fn error01_missing_root_is_gap_not_crash() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = tmp.path().join("state");
    let missing = tmp.path().join("no-such-root");
    let missing_s = missing.to_str().expect("utf8").to_string();
    let report = tmp.path().join("rep.json");
    let report_s = report.to_str().expect("utf8").to_string();
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            missing_s.as_str(),
            "--report",
            report_s.as_str(),
        ],
        tmp.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let rep = report_json(&report);
    assert!(rep["coverage"]["gaps"].as_u64().unwrap_or(0) >= 1, "{rep}");
    assert_eq!(rep["coverage"]["filesystem"].as_str(), Some("incomplete"));
    assert!(state.join("payload").join("catalog.db").exists());
}

/// ERROR-01 policy units (static; live stall injection has no hook — see
/// module docs): bounded exponential backoff and breaker open/close, which
/// delay eligibility without deleting pending work.
#[test]
fn error01_backoff_breaker_policy_preserves_work() {
    assert_eq!(backoff_for_attempt(0), Duration::from_millis(1000));
    assert_eq!(backoff_for_attempt(1), Duration::from_millis(2761));
    assert!(backoff_for_attempt(1) > backoff_for_attempt(0));
    let capped = backoff_for_attempt(100);
    assert!(capped <= Duration::from_secs(300), "{capped:?}");
    assert!(capped >= Duration::from_secs(256), "{capped:?}");

    let mut breaker = CircuitBreaker::new(3, Duration::from_secs(60));
    let now = SystemTime::now();
    assert!(breaker.allow(now));
    breaker.on_failure(now);
    breaker.on_failure(now);
    assert!(breaker.allow(now), "below threshold");
    breaker.on_failure(now);
    assert!(!breaker.allow(now), "open at threshold");
    breaker.on_success();
    assert!(breaker.allow(now), "success closes");
    breaker.on_failure(now);
    breaker.on_failure(now);
    breaker.on_failure(now);
    assert!(!breaker.allow(now));
    assert!(
        breaker.allow(now + Duration::from_secs(61)),
        "cooldown re-admits the preserved scope"
    );
}

/// ERROR-02 (static; live stall injection has no hook — see module docs):
/// still-stuck helpers keep counting against the fixed cap of 4, so the
/// owner can never spawn unlimited replacements; class caps never exceed
/// the shared cap and pressure stops all admission.
#[test]
fn error02_stuck_helpers_count_against_cap() {
    let mut admission = Admission::new(ResourceLimits::default());
    let first = admission.try_acquire(OpClass::Enumerate).expect("enum 1");
    let second = admission.try_acquire(OpClass::Enumerate).expect("enum 2");
    assert!(admission.try_acquire(OpClass::Enumerate).is_none());
    assert!(
        admission.try_acquire(OpClass::GitProbe).is_none(),
        "shared permits exhausted"
    );
    admission.release(&first);
    let probe = admission.try_acquire(OpClass::GitProbe).expect("git 1");
    assert!(
        admission.try_acquire(OpClass::GitProbe).is_none(),
        "git cap is 1"
    );
    admission.release(&second);
    admission.release(&probe);

    for _ in 0..4 {
        assert!(admission.add_helper());
    }
    assert!(!admission.add_helper(), "helper cap is 4");
    assert!(!admission.helper_spawn_allowed());
    admission.remove_helper(); // One clean exit frees exactly one slot.
    assert!(admission.helper_spawn_allowed());
    assert!(admission.add_helper());
    assert!(
        !admission.add_helper(),
        "stuck helpers still count: no unlimited replacements"
    );

    assert!(admission.fd_acquire(64));
    assert!(!admission.fd_acquire(1));
    admission.fd_release(64);

    admission.set_pressure(true);
    assert!(admission.try_acquire(OpClass::Other).is_none());
    assert!(!admission.helper_spawn_allowed());
    admission.set_pressure(false);
    assert!(admission.try_acquire(OpClass::Other).is_some());
}

/// True when the payload snapshot dir still holds report JSON files.
fn snapshots_hold_json(state: &Path) -> bool {
    let dir = state.join("payload").join("report-snapshots");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    entries
        .flatten()
        .any(|entry| entry.path().extension() == Some(std::ffi::OsStr::new("json")))
}

/// CACHE-01: invalidate (same generation, reconcile the scope),
/// force-rescan (fresh generation), and clear (state gone, user exports
/// kept) have distinct, observable semantics.
#[test]
fn cache01_invalidate_force_rescan_clear_distinct() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = tmp.path().join("state");
    let root = tmp.path().join("fixture");
    let area = root.join("area");
    repo_scan::privacy::private_dir_0700(&area).expect("mkdir");
    repo_scan::privacy::private_write_0600(&area.join("note.txt"), b"note").expect("write");
    fixture::normal_clone(&root, "repo");
    let report = tmp.path().join("rep.json");
    let report_s = report.to_str().expect("utf8").to_string();
    let root_s = root.to_str().expect("utf8").to_string();

    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_s.as_str(),
            "--report",
            report_s.as_str(),
        ],
        tmp.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let first = report_json(&report);
    assert_eq!(first["scan"]["generation"].as_u64(), Some(1));
    assert!(snapshots_hold_json(&state), "scan retains a snapshot");

    // Invalidate: durable, scheduled — but explicitly not complete.
    let area_s = area.to_str().expect("utf8").to_string();
    let out = run(
        &["cache", "invalidate", "--root", area_s.as_str()],
        tmp.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("not complete"),
        "no completion claim: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    // The next scan reconciles in the SAME generation (no fresh traversal).
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_s.as_str(),
            "--report",
            report_s.as_str(),
        ],
        tmp.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let second = report_json(&report);
    assert_eq!(
        second["scan"]["generation"].as_u64(),
        Some(1),
        "invalidate reconciles; it does not mint a generation"
    );

    // Force rescan: a genuinely fresh traversal generation.
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_s.as_str(),
            "--report",
            report_s.as_str(),
            "--force-rescan",
        ],
        tmp.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("fresh generation"),
        "fresh generation path: {}",
        stderr_text(&out)
    );
    let forced = report_json(&report);
    assert_eq!(forced["scan"]["generation"].as_u64(), Some(2));
    let out = run(&["query", URL, "--cached"], tmp.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert_eq!(stdout_line(&out, "matches"), "1");

    // Clear: tool-owned payload goes, the exported report stays.
    let out = run(&["cache", "clear", "--all"], tmp.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(!state.join("payload").join("catalog.db").exists());
    assert!(!snapshots_hold_json(&state));
    assert!(report.exists(), "exported user report preserved");
    let out = run(&["query", URL, "--cached"], tmp.path(), &state);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("suitable_catalog: false"),
        "no catalog after clear: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    // A later scan starts from a fresh catalog (generation 1 again).
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_s.as_str(),
            "--report",
            report_s.as_str(),
        ],
        tmp.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let fresh = report_json(&report);
    assert_eq!(fresh["scan"]["generation"].as_u64(), Some(1));
}

/// CACHE-01 (unix): clear coordinates with a live owner instead of racing
/// it. While the lock is held, clear fails fenced (exit 1, ~5s bounded
/// wait); once released, the same clear succeeds.
#[cfg(unix)]
#[test]
fn cache01_clear_fences_live_owner() {
    use repo_scan::store::OwnerGuard;

    let tmp = tempfile::tempdir().expect("tempdir");
    let state = tmp.path().join("state");
    let guard = OwnerGuard::acquire(&state).expect("hold lock");
    let out = run(&["cache", "clear", "--all"], tmp.path(), &state);
    assert_eq!(
        out.status.code(),
        Some(1),
        "fenced refusal, not a race: {}",
        stderr_text(&out)
    );
    assert!(
        stderr_text(&out).contains("holds"),
        "names the live owner: {}",
        stderr_text(&out)
    );
    drop(guard);
    let out = run(&["cache", "clear", "--all"], tmp.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
}

/// CACHE-02 (unix): hostile `--state-dir` layouts refuse the reset instead
/// of deleting through symlinks; victim contents stay byte-identical and
/// nothing outside the state dir is touched.
#[cfg(unix)]
#[test]
fn cache02_symlink_state_dir_refuses() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let outside = tmp.path().join("outside.txt");
    repo_scan::privacy::private_write_0600(&outside, b"precious").expect("write");

    // Case A: the state dir itself is a symlink.
    let real = tmp.path().join("real");
    repo_scan::privacy::private_dir_0700(&real.join("payload")).expect("mkdir");
    repo_scan::privacy::private_write_0600(&real.join("payload").join("keep.txt"), b"precious")
        .expect("write");
    repo_scan::privacy::private_write_0600(
        &real.join("payload").join("catalog.db"),
        b"victim-bytes",
    )
    .expect("write");
    let link = tmp.path().join("link-state");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let link_s = link.to_str().expect("utf8").to_string();
    let out = Command::new(binary())
        .args(["--state-dir", link_s.as_str(), "cache", "clear", "--all"])
        .current_dir(tmp.path())
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("refusing"),
        "{}",
        stderr_text(&out)
    );
    assert_eq!(
        std::fs::read_to_string(real.join("payload").join("keep.txt")).expect("read"),
        "precious"
    );
    assert_eq!(
        std::fs::read_to_string(real.join("payload").join("catalog.db")).expect("read"),
        "victim-bytes"
    );

    // Case B: the engine file is a symlink to an outside victim.
    let state_b = tmp.path().join("state-b");
    repo_scan::privacy::private_dir_0700(&state_b.join("payload")).expect("mkdir");
    let victim = tmp.path().join("victim.txt");
    repo_scan::privacy::private_write_0600(&victim, b"precious").expect("write");
    std::os::unix::fs::symlink(&victim, state_b.join("payload").join("catalog.db"))
        .expect("symlink");
    let out = run(&["cache", "clear", "--all"], tmp.path(), &state_b);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("refusing"),
        "{}",
        stderr_text(&out)
    );
    assert_eq!(std::fs::read_to_string(&victim).expect("read"), "precious");
    assert!(
        std::fs::symlink_metadata(state_b.join("payload").join("catalog.db"))
            .expect("meta")
            .file_type()
            .is_symlink(),
        "symlink itself untouched"
    );

    // Case C: the snapshots dir is a symlink elsewhere.
    let elsewhere = tmp.path().join("elsewhere");
    repo_scan::privacy::private_dir_0700(&elsewhere).expect("mkdir");
    repo_scan::privacy::private_write_0600(&elsewhere.join("keep.txt"), b"precious")
        .expect("write");
    let state_c = tmp.path().join("state-c");
    repo_scan::privacy::private_dir_0700(&state_c.join("payload")).expect("mkdir");
    std::os::unix::fs::symlink(&elsewhere, state_c.join("payload").join("report-snapshots"))
        .expect("symlink");
    let out = run(&["cache", "clear", "--all"], tmp.path(), &state_c);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert!(
        stderr_text(&out).contains("refusing"),
        "{}",
        stderr_text(&out)
    );
    assert_eq!(
        std::fs::read_to_string(elsewhere.join("keep.txt")).expect("read"),
        "precious"
    );
    assert_eq!(std::fs::read_to_string(&outside).expect("read"), "precious");
}

/// CACHE-02: clear removes only verified tool-owned payload. Foreign files
/// anywhere in the payload, foreign content at the engine path, and the
/// coordination lock are preserved; nothing outside the state dir goes.
#[test]
fn cache02_foreign_files_preserved() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let outside = tmp.path().join("outside.txt");
    repo_scan::privacy::private_write_0600(&outside, b"precious").expect("write");
    let state = tmp.path().join("state");
    let root = tmp.path().join("fixture");
    fixture::normal_clone(&root, "repo");
    let report = tmp.path().join("rep.json");
    let report_s = report.to_str().expect("utf8").to_string();
    let root_s = root.to_str().expect("utf8").to_string();
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_s.as_str(),
            "--report",
            report_s.as_str(),
        ],
        tmp.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(snapshots_hold_json(&state));

    let payload = state.join("payload");
    repo_scan::privacy::private_write_0600(&payload.join("notes.txt"), b"mine").expect("write");
    repo_scan::privacy::private_dir_0700(&payload.join("other")).expect("mkdir");
    repo_scan::privacy::private_write_0600(&payload.join("other").join("keep"), b"mine")
        .expect("write");
    let snapshots = payload.join("report-snapshots");
    repo_scan::privacy::private_dir_0700(&snapshots.join("subdir")).expect("mkdir");
    repo_scan::privacy::private_write_0600(&snapshots.join("subdir").join("keep"), b"mine")
        .expect("write");
    #[cfg(unix)]
    std::os::unix::fs::symlink(payload.join("notes.txt"), snapshots.join("sneaky-link"))
        .expect("symlink");

    let out = run(&["cache", "clear", "--all"], tmp.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("preserved"),
        "names preserved files: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!payload.join("catalog.db").exists());
    assert!(!snapshots_hold_json(&state));
    assert_eq!(
        std::fs::read_to_string(payload.join("notes.txt")).expect("read"),
        "mine"
    );
    assert_eq!(
        std::fs::read_to_string(payload.join("other").join("keep")).expect("read"),
        "mine"
    );
    assert_eq!(
        std::fs::read_to_string(snapshots.join("subdir").join("keep")).expect("read"),
        "mine"
    );
    #[cfg(unix)]
    assert!(
        std::fs::symlink_metadata(snapshots.join("sneaky-link"))
            .expect("meta")
            .file_type()
            .is_symlink(),
        "snapshot symlink preserved, not followed"
    );
    assert!(
        state.join("instance.lock").exists(),
        "coordination retained"
    );

    // Foreign content at the engine path is preserved, with success.
    let state_foreign = tmp.path().join("state-foreign");
    let payload_foreign = state_foreign.join("payload");
    repo_scan::privacy::private_dir_0700(&payload_foreign).expect("mkdir");
    repo_scan::privacy::private_write_0600(
        &payload_foreign.join("catalog.db"),
        &vec![0x51u8; 4096],
    )
    .expect("write");
    repo_scan::privacy::private_write_0600(&payload_foreign.join("notes.txt"), b"mine")
        .expect("write");
    let out = run(&["cache", "clear", "--all"], tmp.path(), &state_foreign);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert_eq!(
        std::fs::read(payload_foreign.join("catalog.db")).expect("read"),
        vec![0x51u8; 4096]
    );
    assert!(payload_foreign.join("notes.txt").exists());
    assert_eq!(std::fs::read_to_string(&outside).expect("read"), "precious");
}
