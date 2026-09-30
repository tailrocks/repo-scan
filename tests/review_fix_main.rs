//! REVIEW_WF4 binary-path regression tests (one per fixed finding).
//!
//! R1/R3/R7/R13/R14/R15/R16 run the built binary end to end; R4/R5/R9
//! drive `src/main.rs` directly (included as a module) through its
//! `#[cfg(test)]` hooks — the same code the command paths execute.

mod common;

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

use common::fixture;
use repo_scan::store::{NewTask, Store, TursoStore};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

const URL_A: &str = "https://github.com/owner-a/repo-a";
const URL_B: &str = "https://github.com/owner-b/repo-b";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn run(args: &[String], cwd: &Path, state: &Path) -> std::process::Output {
    std::fs::create_dir_all(state).expect("state dir");
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

fn stdout_line(output: &std::process::Output, key: &str) -> String {
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(&format!("{key}:")) {
            return value.trim().to_string();
        }
    }
    panic!("missing `{key}:` line in stdout:\n{text}");
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

fn resume(state: &Path, scan_id: &str) -> std::process::Output {
    run(&["resume".to_string(), scan_id.to_string()], state, state)
}

/// R1: dispositions are per scan target at report time. Scanning B after A
/// must not leak A's matches into B's report (or vice versa).
#[test]
fn r1_per_target_disposition() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let a = fixture::normal_clone(&root, "a");
    fixture::git(&a, &["remote", "set-url", "origin", URL_A]);
    let b = fixture::normal_clone(&root, "b");
    fixture::git(&b, &["remote", "set-url", "origin", URL_B]);
    let state = tmp.path().join("state");

    let rep_a = tmp.path().join("a.json");
    let out = scan(&state, URL_A, &[&root], &rep_a, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "scan A: {out:?}");
    let report = read_json(&rep_a);
    let repos = report["repositories"].as_array().expect("repos");
    assert_eq!(repos.len(), 1, "scan A sees only A: {repos:?}");
    assert!(
        serde_json::to_string(&repos[0])
            .unwrap()
            .contains("owner-a"),
        "scan A names A: {:?}",
        repos[0]
    );

    let rep_b = tmp.path().join("b.json");
    let out = scan(&state, URL_B, &[&root], &rep_b, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "scan B: {out:?}");
    let report = read_json(&rep_b);
    let repos = report["repositories"].as_array().expect("repos");
    assert_eq!(repos.len(), 1, "scan B sees only B: {repos:?}");
    assert!(
        serde_json::to_string(&repos[0])
            .unwrap()
            .contains("owner-b"),
        "scan B names B: {:?}",
        repos[0]
    );
}

/// R3: staging + publication go through the tested lib path. A destination
/// smuggled under a symlinked parent is refused, and a prior report file
/// without a `report_id` is never clobbered.
#[test]
fn r3_lib_path_staging_publish() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    fixture::normal_clone(&root, "repo");

    // Symlinked parent smuggling into the payload namespace is refused.
    #[cfg(unix)]
    {
        let state = tmp.path().join("state");
        std::fs::create_dir_all(state.join("payload")).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(state.join("payload"), &link).unwrap();
        let smuggled = link.join("report.json");
        let out = scan(
            &state,
            URL_A,
            &[&root],
            &smuggled,
            &["--status", "metadata"],
        );
        assert_eq!(out.status.code(), Some(1), "smuggled dest refused: {out:?}");
        assert!(!smuggled.exists(), "refused dest not created");
    }

    // A prior report without a report_id is never overwritten.
    let state2 = tmp.path().join("state2");
    let prior = tmp.path().join("prior.json");
    let prior_bytes = br#"{"tool": {"name": "repo-scan"}, "note": "no report id"}"#;
    std::fs::write(&prior, prior_bytes).unwrap();
    let out = scan(&state2, URL_A, &[&root], &prior, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(1), "id-less prior refused: {out:?}");
    assert_eq!(
        std::fs::read(&prior).unwrap(),
        prior_bytes,
        "prior bytes untouched"
    );
    let snapshot = PathBuf::from(stdout_line(&out, "snapshot"));
    assert!(snapshot.is_file(), "snapshot retained for retry");
}

/// R4: a breaker/admission skip explicitly releases the lease back to
/// `pending` without an attempt penalty — a prompt resume reclaims it.
#[test]
fn r4_lease_released_on_skip() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let epoch = store.epoch();
        let now = repo_scan::store::now_ms();
        let generation = store
            .create_generation("roots", "running", None, now)
            .await
            .expect("generation");
        store
            .enqueue_task(
                &NewTask {
                    id: "task-1",
                    kind: "enumerate",
                    generation,
                    dir_id: None,
                    scope_key: "dir:abcd",
                    expected_rev: 0,
                    idempotency_key: "idem:task-1",
                },
                now,
            )
            .await
            .expect("enqueue");
        let claimed = store
            .claim_tasks(epoch, 8, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        let attempts_at_claim = claimed[0].task.attempts;

        let tx = main_under_test::test_release_claim(&store, &claimed[0], epoch)
            .await
            .expect("release");
        assert_eq!(tx, 1, "one transaction");

        let task = store.get_task("task-1").await.expect("get").expect("row");
        assert_eq!(task.state, repo_scan::model::TaskState::Pending);
        assert_eq!(task.attempts, attempts_at_claim, "no attempt penalty");
        assert_eq!(task.lease_token, None, "lease cleared");
        assert_eq!(task.lease_epoch, None, "lease epoch cleared");

        // Prompt reclaim works: no 60 s TTL wait.
        let reclaimed = store
            .claim_tasks(epoch, 8, 60_000, now)
            .await
            .expect("reclaim");
        assert_eq!(reclaimed.len(), 1, "reclaimable immediately");
    });
}

/// R5: event batches ingest durably (cursors persisted, scopes
/// invalidated), history loss invalidates the volume scope, and reconcile
/// marking lands on the journal rows.
#[test]
fn r5_events_ingest_reconcile() {
    use repo_scan::events::{ContinuitySignal, EventBatch, EventCursorId};
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let now = repo_scan::store::now_ms();
        let generation = store
            .create_generation("roots", "running", None, now)
            .await
            .expect("generation");

        // Plain batch: cursor persisted, path + parent scopes invalidated.
        let changed = tmp.path().join("sub");
        std::fs::create_dir_all(&changed).unwrap();
        let batch = EventBatch {
            volume_key: "vol-test".to_string(),
            high_water: EventCursorId(50),
            invalidations: vec![changed.clone()],
            history_done: false,
            signals: vec![],
        };
        let outcome = main_under_test::test_apply_event_batch(&store, generation, "uuid-1", &batch)
            .await
            .expect("ingest");
        assert!(!outcome.history_invalid);
        assert_eq!(outcome.batches, 1);
        assert!(outcome.scopes >= 2, "path + parent: {:?}", outcome.scopes);
        assert!(outcome.tx >= 2, "append + invalidations: {}", outcome.tx);
        let dir_scope = repo_scan::config::scope_key_for_dir(&changed);
        assert_eq!(store.scope_rev(&dir_scope).await.expect("rev"), 1);
        let mut rows = store
            .connection()
            .query(
                "SELECT cursor, ingested FROM event_journal WHERE volume_id = 'vol-test'",
                (),
            )
            .await
            .expect("query");
        let row = rows.next().await.expect("next").expect("row");
        assert!(matches!(
            row.get_value(0).expect("cursor"),
            turso::Value::Text(c) if c == "50"
        ));
        assert!(matches!(
            row.get_value(1).expect("ingested"),
            turso::Value::Integer(1)
        ));

        // History-loss batch: volume scope invalidated, flagged for a fresh gen.
        let lost = EventBatch {
            volume_key: "vol-test".to_string(),
            high_water: EventCursorId(60),
            invalidations: vec![],
            history_done: false,
            signals: vec![
                ContinuitySignal::MustScanSubDirs,
                ContinuitySignal::HistoryInvalid,
            ],
        };
        let outcome = main_under_test::test_apply_event_batch(&store, generation, "uuid-2", &lost)
            .await
            .expect("ingest loss");
        assert!(outcome.history_invalid);
        let vol_scope = repo_scan::events::volume_scope_key("vol-test");
        assert_eq!(store.scope_rev(&vol_scope).await.expect("rev"), 1);

        // Reconcile marking lands durably.
        main_under_test::test_mark_reconciled(&store, "vol-test", 50)
            .await
            .expect("mark");
        let mut rows = store
        .connection()
        .query(
            "SELECT reconciled FROM event_journal WHERE volume_id = 'vol-test' AND cursor = '50'",
            (),
        )
        .await
        .expect("query");
        let row = rows.next().await.expect("next").expect("row");
        assert!(matches!(
            row.get_value(0).expect("reconciled"),
            turso::Value::Integer(1)
        ));

        // The report carries an honest event-history boundary note.
        let root = tmp.path().join("scanroot");
        std::fs::create_dir_all(&root).unwrap();
        fixture::normal_clone(&root, "repo");
        let state = tmp.path().join("state");
        let rep = tmp.path().join("rep.json");
        let out = scan(&state, URL_A, &[&root], &rep, &["--status", "metadata"]);
        assert_eq!(out.status.code(), Some(0), "scan: {out:?}");
        let report = read_json(&rep);
        let boundaries = report["coverage"]["scope_boundaries"]
            .as_array()
            .expect("boundaries");
        let text = serde_json::to_string(boundaries).unwrap();
        #[cfg(target_os = "linux")]
        assert!(
            text.contains("Event history unavailable on this platform"),
            "honest degraded note: {text}"
        );
        #[cfg(target_os = "macos")]
        assert!(
            text.contains("Event-history reconciliation")
                || text.contains("Event-history monitoring unavailable"),
            "honest live/degraded note: {text}"
        );
    });
}

/// R7: pathname aliases are preserved as `Alias` records instead of being
/// silently dropped by identity dedupe.
#[test]
fn r7_alias_records() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let real = fixture::normal_clone(&root, "real");
    fixture::git(&real, &["remote", "set-url", "origin", URL_A]);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, root.join("alias")).unwrap();
    #[cfg(not(unix))]
    panic!("alias test needs symlinks");

    let state = tmp.path().join("state");
    let rep = tmp.path().join("rep.json");
    let out = scan(&state, URL_A, &[&root], &rep, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "scan: {out:?}");
    let report = read_json(&rep);
    let aliases = report["aliases"].as_array().expect("aliases");
    assert!(!aliases.is_empty(), "alias recorded");
    let paths = report["paths"].as_array().expect("paths");
    let by_id: std::collections::HashMap<&str, &str> = paths
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p["value"].as_str()?)))
        .collect();
    let mut found = false;
    for alias in aliases {
        let path = by_id
            .get(alias["path_id"].as_str().unwrap_or(""))
            .unwrap_or(&"");
        let target = by_id
            .get(alias["target_path_id"].as_str().unwrap_or(""))
            .unwrap_or(&"");
        if path.contains("alias") && target.contains("real") {
            found = true;
            assert_eq!(alias["kind"].as_str(), Some("symlink"));
        }
    }
    assert!(found, "link -> target alias: {aliases:?}");
}

/// R9: the per-operation no-progress watchdog trips past its bounded grace
/// and only past it.
#[test]
fn r9_watchdog_grace() {
    use std::time::Duration;
    assert!(!main_under_test::test_watchdog_exceeded(
        120,
        Duration::from_secs(0)
    ));
    assert!(!main_under_test::test_watchdog_exceeded(
        120,
        Duration::from_secs(119)
    ));
    assert!(!main_under_test::test_watchdog_exceeded(
        120,
        Duration::from_secs(120)
    ));
    assert!(main_under_test::test_watchdog_exceeded(
        120,
        Duration::from_secs(121)
    ));
    assert!(main_under_test::test_watchdog_exceeded(
        1,
        Duration::from_secs(3600)
    ));
}

/// R13: the report counts real store transactions.
#[test]
fn r13_db_transactions() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    fixture::normal_clone(&root, "repo");
    let state = tmp.path().join("state");
    let rep = tmp.path().join("rep.json");
    let out = scan(&state, URL_A, &[&root], &rep, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "scan: {out:?}");
    let report = read_json(&rep);
    let tx = report["resources"]["db_transactions"]
        .as_u64()
        .expect("db_transactions");
    assert!(tx >= 1, "real transactions counted: {tx}");

    // Even an empty scan performs (and counts) setup transactions.
    let empty = tmp.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let state2 = tmp.path().join("state2");
    let rep2 = tmp.path().join("rep2.json");
    let out = scan(&state2, URL_A, &[&empty], &rep2, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "empty scan: {out:?}");
    let tx = read_json(&rep2)["resources"]["db_transactions"]
        .as_u64()
        .expect("db_transactions");
    assert!(tx >= 1, "setup transactions counted: {tx}");
}

/// R14: the generation is persisted on the scan row and a resume honors
/// it even after an interleaving force-rescan picked a newer generation.
#[test]
fn r14_generation_binding() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let repo = fixture::normal_clone(&root, "repo");
    fixture::git(&repo, &["remote", "set-url", "origin", URL_A]);
    fixture::symlink_cycle(&root);
    let state = tmp.path().join("state");

    let rep1 = tmp.path().join("r1.json");
    let out = scan(&state, URL_A, &[&root], &rep1, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(3), "cycle gaps: {out:?}");
    let scan_id = stdout_line(&out, "scan_id");
    let gen1: u64 = stdout_line(&out, "generation").parse().expect("gen1");

    let rep2 = tmp.path().join("r2.json");
    let out = scan(
        &state,
        URL_A,
        &[&root],
        &rep2,
        &["--status", "metadata", "--force-rescan"],
    );
    assert_eq!(out.status.code(), Some(3), "forced: {out:?}");
    let gen2: u64 = stdout_line(&out, "generation").parse().expect("gen2");
    assert_ne!(gen1, gen2, "force picked a newer generation");

    // Resume restores the saved report destination (r1.json) and the
    // saved generation.
    let out = resume(&state, &scan_id);
    assert_eq!(out.status.code(), Some(3), "resume: {out:?}");
    let gen_resumed: u64 = stdout_line(&out, "generation").parse().expect("gen");
    assert_eq!(gen_resumed, gen1, "resume honors the saved generation");
    assert_eq!(
        read_json(&rep1)["scan"]["generation"].as_u64(),
        Some(gen1),
        "report generation matches"
    );
}

/// R15: a foreign SQLite database without tool ownership evidence is
/// preserved by `cache clear`; tool-owned state is still removed.
#[test]
fn r15_foreign_sqlite_preserved() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Foreign SQLite bytes at the engine path: magic but no marker and no
    // catalog schema markers.
    let state = tmp.path().join("state");
    let payload = state.join("payload");
    std::fs::create_dir_all(&payload).unwrap();
    let db = payload.join("catalog.db");
    let mut foreign = b"SQLite format 3\0".to_vec();
    foreign.resize(8192, 0);
    std::fs::write(&db, &foreign).unwrap();
    let out = run_str(&["cache", "clear", "--all"], &state, &state);
    assert_eq!(out.status.code(), Some(0), "clear: {out:?}");
    assert!(db.is_file(), "foreign database preserved");
    assert_eq!(std::fs::read(&db).unwrap(), foreign, "bytes untouched");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("preserved"), "says preserved: {stdout}");

    // Tool-owned state (marker bound by a real scan) is still removed.
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    fixture::normal_clone(&root, "repo");
    let state2 = tmp.path().join("state2");
    let rep = tmp.path().join("rep.json");
    let out = scan(&state2, URL_A, &[&root], &rep, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "scan: {out:?}");
    assert!(state2.join("payload").join("catalog.db").is_file());
    let out = run_str(&["cache", "clear", "--all"], &state2, &state2);
    assert_eq!(out.status.code(), Some(0), "clear: {out:?}");
    assert!(
        !state2.join("payload").join("catalog.db").exists(),
        "owned catalog removed"
    );
}

/// R16: refs carry upstream tracking, status carries examined submodule
/// coverage, and restaged snapshots never silently rewrite (fresh IDs).
#[test]
fn r16_refs_submodules_snapshot() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Upstream tracking from repo config.
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let repo = fixture::normal_clone(&root, "repo");
    fixture::git(&repo, &["remote", "set-url", "origin", URL_A]);
    fixture::git(&repo, &["config", "branch.main.remote", "origin"]);
    fixture::git(&repo, &["config", "branch.main.merge", "refs/heads/main"]);
    let state = tmp.path().join("state");
    let rep = tmp.path().join("rep.json");
    let out = scan(&state, URL_A, &[&root], &rep, &["--status", "summary"]);
    assert_eq!(out.status.code(), Some(0), "scan: {out:?}");
    let report = read_json(&rep);
    let branches = report["branches"].as_array().expect("branches");
    let main = branches
        .iter()
        .find(|b| b["name"]["value"].as_str() == Some("refs/heads/main"))
        .expect("main branch");
    assert_eq!(
        main["upstream"]["value"].as_str(),
        Some("origin/main"),
        "upstream tracked: {main:?}"
    );

    // Submodule coverage is examined, not hardcoded.
    let sup_root = tmp.path().join("suproot");
    std::fs::create_dir_all(&sup_root).unwrap();
    let (sup, _sub) = fixture::submodule_repo(&sup_root);
    fixture::git(&sup, &["remote", "set-url", "origin", URL_A]);
    let state2 = tmp.path().join("state2");
    let rep2 = tmp.path().join("rep2.json");
    let out = scan(
        &state2,
        URL_A,
        &[&sup_root],
        &rep2,
        &["--status", "summary"],
    );
    // Exit 3: the remote-less siblings are unresolvable identities (honest
    // gap, pre-existing semantics); the superproject itself is confirmed.
    assert_eq!(out.status.code(), Some(3), "submodule scan: {out:?}");
    let report = read_json(&rep2);
    let repos = report["repositories"].as_array().expect("repos");
    assert!(!repos.is_empty());
    let checkouts = report["checkouts"].as_array().expect("checkouts");
    assert!(!checkouts.is_empty());
    let checked = checkouts
        .iter()
        .any(|c| c["status"]["submodules"].as_str() == Some("checked"));
    assert!(checked, "submodules examined: {checkouts:?}");

    // Same-scan restage mints a fresh snapshot ID; history is kept.
    let cyc_root = tmp.path().join("cyc");
    std::fs::create_dir_all(&cyc_root).unwrap();
    let crepo = fixture::normal_clone(&cyc_root, "repo");
    fixture::git(&crepo, &["remote", "set-url", "origin", URL_A]);
    fixture::symlink_cycle(&cyc_root);
    let state3 = tmp.path().join("state3");
    let rep3 = tmp.path().join("rep3.json");
    let out = scan(
        &state3,
        URL_A,
        &[&cyc_root],
        &rep3,
        &["--status", "metadata"],
    );
    assert_eq!(out.status.code(), Some(3), "incomplete: {out:?}");
    let scan_id = stdout_line(&out, "scan_id");
    let first_report = stdout_line(&out, "report_id");
    let first_snapshot = PathBuf::from(stdout_line(&out, "snapshot"));
    assert!(first_snapshot.is_file());
    let out = resume(&state3, &scan_id);
    assert_eq!(out.status.code(), Some(3), "resume: {out:?}");
    let second_report = stdout_line(&out, "report_id");
    let second_snapshot = PathBuf::from(stdout_line(&out, "snapshot"));
    assert_ne!(first_report, second_report, "fresh snapshot ID per attempt");
    assert!(second_snapshot.is_file());
    assert!(first_snapshot.is_file(), "first snapshot kept");
}
