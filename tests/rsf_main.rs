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
use repo_scan::store::{
    NewCheckout, NewGitInstance, NewScan, NewTask, Store, TaskOutcome, TursoStore, WriterBatch,
};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

const URL_A: &str = "https://github.com/owner-a/repo-a";
const CANON_A: &str = "https://github.com/owner-a/repo-a";

#[test]
fn resume_command_never_exposes_state_path() {
    let ordinary_path = "/tmp/RESUME_PATH_CANARY/repo scan state";
    let spaced = main_under_test::test_resume_cmd_for(Path::new(ordinary_path), "scan-1");
    assert!(spaced.contains("${REPO_SCAN_STATE_DIR:?set REPO_SCAN_STATE_DIR"));
    assert!(spaced.ends_with("resume 'scan-1'"));
    assert!(!spaced.contains(ordinary_path));
    assert!(!spaced.contains("RESUME_PATH_CANARY"));

    let secret = main_under_test::test_resume_cmd_for(
        Path::new("/tmp/password=RESUMECMDCANARY/state"),
        "scan-2",
    );
    assert!(
        secret.contains("${REPO_SCAN_STATE_DIR:?set REPO_SCAN_STATE_DIR to this scan's state dir}")
    );
    assert!(!secret.contains("RESUMECMDCANARY"));
    assert!(!secret.contains("<redacted>"));
    assert!(secret.ends_with("resume 'scan-2'"));
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

fn runtime() -> tokio::runtime::Runtime {
    // All drivers on: the pooled drain needs the timer (renewal ticks)
    // and the blocking pool (worker threads).
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn root_volume_selection_uses_canonical_identity_for_symlink_aliases() {
    let mounts = [PathBuf::from("/"), PathBuf::from("/private/volume")];
    let physical_root = PathBuf::from("/private/volume/worktrees/project");
    assert_eq!(
        main_under_test::test_deepest_mount_index(&physical_root, &mounts),
        Some(1),
        "the alias's resolved root selects its actual nested volume"
    );
}

#[test]
fn root_cursors_follow_canonical_mount_for_symlink_aliases() {
    let (volume_id, history_uuid) = main_under_test::test_root_cursor_alias_mapping(
        Path::new("/tmp/root-alias"),
        Path::new("/private/volume/worktrees/project"),
        Path::new("/private/volume"),
        "macos-volume-uuid-1",
        "history-alias-test",
    );
    assert_eq!(volume_id.as_deref(), Some("macos-volume-uuid-1"));
    assert_eq!(history_uuid.as_deref(), Some("history-alias-test"));
}

#[test]
fn scoped_progress_gap_count_accepts_root_event_volume_uuid() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = open_store(&tmp.path().join("catalog.db")).await;
        let now = repo_scan::store::now_ms();
        for (id, volume) in [
            ("gap-in-root-volume", "macos-volume-uuid-1"),
            ("gap-outside-volume", "macos-volume-uuid-2"),
        ] {
            store
                .record_error(
                    id,
                    &format!("volume:{volume}"),
                    "event-batch-error",
                    "synthetic event gap",
                    None,
                    now,
                )
                .await
                .expect("seed volume gap");
        }
        let roots = [PathBuf::from("/scope/root")];
        let count = main_under_test::test_count_open_errors_for_roots_with_event_volumes(
            &store,
            &roots,
            &roots,
            &[String::from("macos-volume-uuid-1")],
        )
        .await
        .expect("count scoped errors");
        assert_eq!(count, 1, "only the root's monitored volume gap counts");
        store.close().await.expect("close");
    });
}

#[test]
fn interrupted_journal_root_path_is_scrubbed_before_persistence() {
    use repo_scan::walk::roots::{PlannedRoot, RootPriority};

    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = open_store(&tmp.path().join("catalog.db")).await;
        store
            .create_scan_request(
                &NewScan {
                    id: "scan-interrupted-path-privacy",
                    url_raw: b"--all",
                    url_canonical: None,
                    scope: "roots",
                    status_mode: "summary",
                    report_dest: None,
                    targets_json: None,
                    format: Some("human"),
                    all_targets: Some(true),
                    fetch: Some(false),
                    workers: None,
                },
                repo_scan::store::now_ms(),
            )
            .await
            .expect("create scan request");
        let roots = [PlannedRoot {
            path: PathBuf::from("/tmp/password=ghp_TESTINTERRUPTCANARY00000000000000000000/root"),
            priority: RootPriority::Normal,
            namespace: String::from("test"),
            volume: None,
        }];
        main_under_test::test_append_interrupted_roots_event(
            &store,
            "scan-interrupted-path-privacy",
            &roots,
        )
        .await
        .expect("append interrupted event");
        let rows = store
            .read_scan_events("scan-interrupted-path-privacy", 0, 10)
            .await
            .expect("read event");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "scan_interrupted");
        let record = String::from_utf8_lossy(&rows[0].records);
        assert!(!record.contains("TESTINTERRUPTCANARY"));
        store.close().await.expect("close");
    });
}

#[test]
fn initial_tui_header_target_scrubs_credential_shaped_local_path() {
    let target = repo_scan::report::tui::safe_tui_target(
        "/tmp/password=ghp_TESTTUITARGETCANARY00000000000000000000/repo",
    );
    assert!(!target.contains("TESTTUITARGETCANARY"));
}

#[test]
fn resume_uses_canonical_identity_when_local_target_path_was_scrubbed() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = open_store(&tmp.path().join("catalog.db")).await;
        let raw = "/tmp/password=ghp_TESTRESUMECANARY00000000000000000000/repo";
        let canonical = "https://github.com/owner/repo";
        let targets = serde_json::json!([{"raw": raw, "canonical": canonical}]).to_string();
        store
            .create_scan_request(
                &NewScan {
                    id: "scan-resume-scrubbed-local-target",
                    url_raw: raw.as_bytes(),
                    url_canonical: Some(canonical.as_bytes()),
                    scope: "roots",
                    status_mode: "summary",
                    report_dest: None,
                    targets_json: Some(&targets),
                    format: Some("human"),
                    all_targets: Some(false),
                    fetch: Some(false),
                    workers: None,
                },
                repo_scan::store::now_ms(),
            )
            .await
            .expect("create scan row");
        let row = store
            .get_scan("scan-resume-scrubbed-local-target")
            .await
            .expect("read scan row")
            .expect("scan exists");
        assert!(!String::from_utf8_lossy(&row.url_raw).contains("TESTRESUMECANARY"));
        let targets = main_under_test::test_resume_targets_for_row(&row);
        assert_eq!(targets, [canonical]);
        store.close().await.expect("close");
    });
}

#[test]
fn resume_classifies_redacted_no_remote_local_target_without_reopening_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let secret_parent = tmp
        .path()
        .join("password=ghp_TESTNOREMOTECANARY00000000000000000000");
    repo_scan::privacy::private_dir_0700(&secret_parent).expect("make local repo parent");
    let local_repo = fixture::normal_clone(&secret_parent, "repo");
    fixture::git(&local_repo, &["remote", "remove", "origin"]);
    let raw = local_repo.to_string_lossy().into_owned();
    let (_, canonical) = main_under_test::test_resolve_target_identity(&raw)
        .expect("resolve local repository without remote");
    assert!(canonical.starts_with("file://"));

    let state = tmp.path().join("state");
    repo_scan::privacy::private_dir_0700(&state).expect("make state");
    let payload = repo_scan::store::owner::payload_dir(&state);
    repo_scan::privacy::private_dir_0700(&payload).expect("make payload");
    let catalog = repo_scan::store::owner::catalog_db_path(&state);
    let rt = runtime();
    let scan_id = rt.block_on(async {
        let store = open_store(&catalog).await;
        let id = main_under_test::test_mint_resume_target(&store, &raw, &canonical)
            .await
            .expect("persist privacy-safe target");
        let outcome = repo_scan::config::encode_outcome(
            130,
            Some(3),
            "report-redacted-local-target",
            false,
            None,
        );
        store
            .update_scan_state(
                &id,
                "interrupted",
                Some(&outcome),
                None,
                repo_scan::store::now_ms(),
            )
            .await
            .expect("mark resumable scan interrupted");
        store.close().await.expect("close catalog");
        id
    });

    // The stored target and canonical file URL both contain only the
    // redaction marker. Resume must classify them as unavailable before it
    // tries to reopen the original path, which is removed here.
    let rt = runtime();
    rt.block_on(async {
        let store = open_store(&catalog).await;
        let row = store
            .get_scan(&scan_id)
            .await
            .expect("read saved scan")
            .expect("saved scan row");
        assert!(!String::from_utf8_lossy(&row.url_raw).contains("NOREMOTECANARY"));
        assert!(
            !String::from_utf8_lossy(row.url_canonical.as_deref().unwrap())
                .contains("NOREMOTECANARY")
        );
        assert!(!row
            .targets_json
            .as_deref()
            .unwrap()
            .contains("NOREMOTECANARY"));
        let restored = main_under_test::test_resume_targets_for_row(&row);
        assert_eq!(restored, ["repo-scan:redacted-local-target"]);
        let resolved = main_under_test::test_resolve_saved_targets(&row)
            .expect_err("redacted local target is not reopened");
        assert!(resolved
            .to_string()
            .contains("saved local target path was redacted"));
        assert!(!resolved.to_string().contains("NOREMOTECANARY"));
        store.close().await.expect("close");
    });
    std::fs::remove_dir_all(&local_repo).expect("remove original target before resume");
    let out = run_str(&["resume", &scan_id], tmp.path(), &state);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("saved local target path was redacted"),
        "{stderr}"
    );
    assert!(!stderr.contains("NOREMOTECANARY"));
}

#[test]
fn completion_gap_followup_scrubs_detail_before_database_persistence() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = open_store(&tmp.path().join("catalog.db")).await;
        let now = repo_scan::store::now_ms();
        let task_id = "task-completion-gap-privacy";
        seed_enum_task(&store, task_id, 1, Path::new("/scope/completion"), now).await;
        let epoch = store.epoch();
        let claimed = store
            .claim_tasks(epoch, 1, 60_000, now)
            .await
            .expect("claim task")
            .into_iter()
            .next()
            .expect("claimed task");
        let detail = "fetch failed for \
            https://ghp_R5T1COMPLETIONCANARY00000000000000000000:completion-secret@example.invalid/repo?token=query-secret";
        store
            .complete_task_report_gap(
                task_id,
                claimed.token,
                epoch,
                &TaskOutcome::Retry {
                    category: String::from("test-completion-gap"),
                    detail: detail.to_string(),
                    retry_after_ms: now + 60_000,
                },
                now,
            )
            .await
            .expect("commit completion outcome");
        main_under_test::test_buffer_completion_gap_detail(&store, task_id, detail, now)
            .await
            .expect("buffer completion gap follow-up");

        let error = store
            .get_error(&format!("gap:{task_id}"))
            .await
            .expect("read error")
            .expect("completion error row");
        assert!(!error.detail.contains("COMPLETIONCANARY"));
        assert!(!error.detail.contains("completion-secret"));
        assert!(!error.detail.contains("query-secret"));
        assert!(error.detail.contains("fetch failed"));
        store.close().await.expect("close");
    });
}

#[test]
fn derivation_cap_marks_report_scan_and_terminal_incomplete() {
    const ERROR_COUNT: usize = 4_097;
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    repo_scan::privacy::private_dir_0700(&root).expect("make root");
    repo_scan::privacy::private_dir_0700(&state).expect("make state");
    let payload = repo_scan::store::owner::payload_dir(&state);
    repo_scan::privacy::private_dir_0700(&payload).expect("make payload");
    let catalog = repo_scan::store::owner::catalog_db_path(&state);

    let rt = runtime();
    rt.block_on(async {
        let store = open_store(&catalog).await;
        let scope_key = repo_scan::config::scope_key_for_dir(&root);
        let now = repo_scan::store::now_ms();
        let mut batch = WriterBatch::new();
        for n in 0..ERROR_COUNT {
            batch.push(
                "INSERT INTO errors (id, scope_key, category, detail, attempts, first_seen_ms, \
                    last_seen_ms, next_retry_ms, open) VALUES (?1, ?2, 'probe-failed', \
                    'synthetic probe failure', 1, ?3, ?3, NULL, 1)",
                vec![
                    turso::Value::Text(format!("probe-cap-{n:05}")),
                    turso::Value::Text(scope_key.clone()),
                    turso::Value::Integer(now),
                ],
            );
            if batch.should_flush() {
                store.flush(&mut batch).await.expect("flush errors");
            }
        }
        if !batch.is_empty() {
            store.flush(&mut batch).await.expect("flush final errors");
        }
        let scoped_count = main_under_test::test_count_open_errors_for_roots_with_event_volumes(
            &store,
            std::slice::from_ref(&root),
            std::slice::from_ref(&root),
            &[],
        )
        .await
        .expect("count seeded scoped errors");
        assert_eq!(scoped_count, ERROR_COUNT as u64);
        store.close().await.expect("close seeded catalog");
    });

    let out = run_str(
        &[
            "scan",
            "--all",
            "--root",
            root.to_str().unwrap(),
            "--format",
            "json",
        ],
        &root,
        &state,
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "scan stdout: {}; stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).expect("parse report");
    assert_eq!(report["scan"]["state"], "incomplete");
    assert!(report["coverage"]["gaps"].as_u64().unwrap_or_default() > 0);
    let scan_id = report["scan"]["id"].as_str().expect("scan id");

    let rt = runtime();
    rt.block_on(async {
        let store = open_store(&catalog).await;
        let scan = store
            .get_scan(scan_id)
            .await
            .expect("read scan")
            .expect("scan row");
        assert!(
            scan.state.starts_with("incomplete:roots:"),
            "state: {}",
            scan.state
        );
        let events = store
            .read_scan_events(scan_id, 0, 100)
            .await
            .expect("read terminal events");
        let terminal = events
            .iter()
            .find(|event| event.event_type == "scan_incomplete")
            .expect("scan_incomplete terminal event");
        let records: serde_json::Value =
            serde_json::from_slice(&terminal.records).expect("parse terminal records");
        assert!(records["counts"]["open_gaps"].as_u64().unwrap_or_default() > 0);
        store.close().await.expect("close");
    });
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
        let dest2 = tmp.path().join("replay.json");
        let snapshot = main_under_test::test_verified_publish_bytes(
            &store,
            &state,
            "report-replay",
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

/// Roots-scoped error derivation matches `status:` scopes by checkout ID,
/// while instance derivations use the separate owning repository IDs.
#[test]
fn roots_error_derivation_includes_only_in_scope_checkout_status_errors() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let store = open_store(&db).await;
        let now = repo_scan::store::now_ms();
        for (repo_id, checkout_id, root_path, git_path) in [
            (
                "repo-in",
                "checkout-in",
                b"/scope/in/repo".as_slice(),
                b"/scope/in/repo/.git".as_slice(),
            ),
            (
                "repo-out",
                "checkout-out",
                b"/scope/out/repo".as_slice(),
                b"/scope/out/repo/.git".as_slice(),
            ),
        ] {
            store
                .upsert_git_instance(
                    &NewGitInstance {
                        id: repo_id,
                        git_path,
                        common_path: git_path,
                        incarnation: repo_id,
                        format: "git-files",
                        bare: Some(false),
                        object_format: "sha1",
                        disposition: "confirmed",
                        evidence_json: "[]",
                    },
                    now,
                )
                .await
                .expect("seed git instance");
            store
                .upsert_checkout(
                    &NewCheckout {
                        id: checkout_id,
                        instance_id: repo_id,
                        root_path: Some(root_path),
                        git_path,
                        relationship: "main",
                        availability: "present",
                        head_state: "branch",
                        head_ref: None,
                        head_oid: None,
                        head_algo: None,
                    },
                    now,
                )
                .await
                .expect("seed checkout");
            store
                .record_error(
                    &format!("status-error-{checkout_id}"),
                    &repo_scan::config::scope_key_for_status(checkout_id),
                    "status-error",
                    "synthetic status error",
                    None,
                    now,
                )
                .await
                .expect("seed status error");
        }

        store
            .record_error(
                "a-probe-error",
                &repo_scan::config::scope_key_for_dir(Path::new("/scope/in")),
                "probe-failed",
                "synthetic in-scope probe failure",
                None,
                now,
            )
            .await
            .expect("seed candidate error");
        let roots = [PathBuf::from("/scope/in")];
        let root_scopes = [repo_scan::config::scope_key_for_dir(Path::new("/scope/in"))];
        let derived =
            main_under_test::test_scan_error_derivations_for_roots(&store, &root_scopes, &roots, 1)
                .await
                .expect("scan scoped errors");
        assert_eq!(
            derived.scanned, 2,
            "the in-scope candidate and checkout error are scanned"
        );
        assert_eq!(derived.candidates, 1, "the candidate cap is respected");

        let root_a = [PathBuf::from("/scope/in")];
        let root_a_gap = repo_scan::config::report_derivation_gap_id("errors", Some(&root_a));
        let root_a_gap_scope = repo_scan::config::report_derivation_gap_scope_key(Some(&root_a));
        store
            .record_error(
                &root_a_gap,
                &root_a_gap_scope,
                "report-derivation-truncated",
                "root A derivation budget reached",
                None,
                now,
            )
            .await
            .expect("seed root A derivation gap");
        let roots_b = [PathBuf::from("/scope/out")];
        let scopes_b = [repo_scan::config::scope_key_for_dir(Path::new(
            "/scope/out",
        ))];
        let later =
            main_under_test::test_scan_error_derivations_for_roots(&store, &scopes_b, &roots_b, 1)
                .await
                .expect("scan root B errors");
        assert_eq!(
            later.scanned, 1,
            "root B includes its status error but not root A's persisted derivation gap"
        );
        assert_eq!(later.candidates, 0);
        store.close().await.expect("close store");
    });
}

#[test]
fn roots_run_boundary_counts_only_in_scope_errors_and_unresolvable_repos() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = open_store(&tmp.path().join("catalog.db")).await;
        let now = repo_scan::store::now_ms();
        let generation = store
            .create_generation("roots", "running", None, now)
            .await
            .expect("generation");

        for suffix in ["a", "b"] {
            let root = format!("/scope/{suffix}");
            let git_path = format!("{root}/repo/.git");
            let repository_id = format!("unresolvable-{suffix}");
            store
                .upsert_git_instance(
                    &NewGitInstance {
                        id: &repository_id,
                        git_path: git_path.as_bytes(),
                        common_path: git_path.as_bytes(),
                        incarnation: suffix,
                        format: "git-files",
                        bare: None,
                        object_format: "sha1",
                        disposition: "unresolvable_identity",
                        evidence_json: "[]",
                    },
                    now,
                )
                .await
                .expect("seed unresolvable instance");
            store
                .record_error(
                    &format!("gap-{suffix}"),
                    &repo_scan::config::scope_key_for_dir(Path::new(&root)),
                    "permission-denied",
                    "synthetic scope error",
                    None,
                    now,
                )
                .await
                .expect("seed scope error");
        }

        let roots_b = [PathBuf::from("/scope/b")];
        let only_b = main_under_test::test_run_boundary_for_roots(
            &store,
            store.epoch(),
            generation,
            1,
            CANON_A,
            StatusMode::Metadata,
            "scan-roots-boundary",
            &roots_b,
        )
        .await
        .expect("run B boundary");
        assert_eq!(only_b.open_gaps, 1, "root B counts only its gap");
        assert_eq!(only_b.unresolvable, 1, "root B counts only its repo");

        let roots_c = [PathBuf::from("/scope/c")];
        let neither = main_under_test::test_run_boundary_for_roots(
            &store,
            store.epoch(),
            generation,
            1,
            CANON_A,
            StatusMode::Metadata,
            "scan-roots-boundary-c",
            &roots_c,
        )
        .await
        .expect("run C boundary");
        assert_eq!(neither.open_gaps, 0, "root A/B gaps do not leak into C");
        assert_eq!(neither.unresolvable, 0, "root A/B repos do not leak into C");
        store.close().await.expect("close store");
    });
}

#[test]
fn error_derivation_cap_resumes_after_last_candidate() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = open_store(&tmp.path().join("catalog.db")).await;
        let now = repo_scan::store::now_ms();
        let scope_path = Path::new("/scope/cap-errors");
        let scope_key = repo_scan::config::scope_key_for_dir(scope_path);
        for id in ["candidate-a", "candidate-b"] {
            store
                .record_error(
                    id,
                    &scope_key,
                    "probe-failed",
                    "synthetic candidate",
                    None,
                    now,
                )
                .await
                .expect("seed candidate error");
        }
        let roots = [PathBuf::from(scope_path)];
        let root_scopes = [scope_key];

        let first =
            main_under_test::test_scan_error_derivations_for_roots(&store, &root_scopes, &roots, 1)
                .await
                .expect("first capped error pass");
        assert_eq!(first.candidate_ids, ["cand-err:candidate-a"]);

        let second =
            main_under_test::test_scan_error_derivations_for_roots(&store, &root_scopes, &roots, 1)
                .await
                .expect("resumed error pass");
        assert_eq!(second.candidate_ids, ["cand-err:candidate-b"]);
        store.close().await.expect("close store");
    });
}

#[test]
fn instance_derivation_cap_resumes_after_last_repository() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = open_store(&tmp.path().join("catalog.db")).await;
        let now = repo_scan::store::now_ms();
        for (id, path) in [
            ("instance-a", b"/scope/instance-a/.git".as_slice()),
            ("instance-b", b"/scope/instance-b/.git".as_slice()),
        ] {
            store
                .upsert_git_instance(
                    &NewGitInstance {
                        id,
                        git_path: path,
                        common_path: path,
                        incarnation: id,
                        format: "git-files",
                        bare: Some(false),
                        object_format: "sha1",
                        disposition: "unresolvable_identity",
                        evidence_json: "[]",
                    },
                    now,
                )
                .await
                .expect("seed unresolvable instance");
        }

        let first = main_under_test::test_scan_instance_derivations_with_cap(&store, 1)
            .await
            .expect("first capped instance pass");
        assert_eq!(first.candidate_ids, ["cand:instance-a"]);

        let second = main_under_test::test_scan_instance_derivations_with_cap(&store, 1)
            .await
            .expect("resumed instance pass");
        assert_eq!(second.candidate_ids, ["cand:instance-b"]);
        store.close().await.expect("close store");
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

#[test]
fn buffered_error_detail_is_scrubbed_in_catalog_and_journal() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = open_store(&tmp.path().join("catalog.db")).await;
        store
            .create_scan_request(
                &NewScan {
                    id: "scan-secret-detail",
                    url_raw: b"--all",
                    url_canonical: None,
                    scope: "roots",
                    status_mode: "metadata",
                    report_dest: None,
                    targets_json: None,
                    format: Some("jsonl"),
                    all_targets: Some(true),
                    fetch: Some(false),
                    workers: None,
                },
                repo_scan::store::now_ms(),
            )
            .await
            .expect("create scan");

        let detail = "fetch failed for \
            https://ghp_R5T1JOURNALUSER:journal-secret@example.invalid/repo?token=query-secret";
        main_under_test::test_buffer_record_error(&store, "scan-secret-detail", detail)
            .await
            .expect("buffer error");

        let error = store
            .get_error("gap:test-secret-detail")
            .await
            .expect("get error")
            .expect("error row");
        let events = store
            .read_scan_events("scan-secret-detail", 0, 10)
            .await
            .expect("read events");
        let event = events
            .iter()
            .find(|row| row.event_type == "error")
            .expect("error event");
        let records: serde_json::Value =
            serde_json::from_slice(&event.records).expect("parse event records");
        let journal_detail = records["detail"].as_str().expect("detail");

        for saved in [error.detail.as_str(), journal_detail] {
            assert!(!saved.contains("ghp_R5T1JOURNALUSER"));
            assert!(!saved.contains("journal-secret"));
            assert!(!saved.contains("query-secret"));
            assert!(saved.contains("fetch failed"));
        }
        assert_eq!(error.detail, journal_detail);
    });
}
