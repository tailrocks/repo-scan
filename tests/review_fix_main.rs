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
    // Wave6: explicit human keeps the footer lines these tests parse
    // (the redirected default is now the JSONL journal replay).
    let mut args: Vec<String> = vec![
        "scan".to_string(),
        url.to_string(),
        "--scope".to_string(),
        "roots".to_string(),
        "--report".to_string(),
        report.to_str().expect("utf8 report").to_string(),
        "--format".to_string(),
        "human".to_string(),
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
    run(
        &[
            "resume".to_string(),
            scan_id.to_string(),
            "--format".to_string(),
            "human".to_string(),
        ],
        state,
        state,
    )
}

/// R1: dispositions are per scan target at report time. Scanning B after A
/// must not leak A's matches into B's report (or vice versa).
#[test]
fn r1_per_target_disposition() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
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
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    fixture::normal_clone(&root, "repo");

    // Symlinked parent smuggling into the payload namespace is refused.
    #[cfg(unix)]
    {
        let state = tmp.path().join("state");
        repo_scan::privacy::private_dir_0700(&state.join("payload")).unwrap();
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
    repo_scan::privacy::private_write_0600(&prior, prior_bytes).unwrap();
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
        assert_eq!(
            task.attempts,
            attempts_at_claim - 1,
            "release refunds the denied claim's attempts increment"
        );
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
        repo_scan::privacy::private_dir_0700(&changed).unwrap();
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
        assert_eq!(
            outcome.tx, 1,
            "atomic ingest (RSF-F940): cursor + invalidations in one commit"
        );
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
        repo_scan::privacy::private_dir_0700(&root).unwrap();
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
    repo_scan::privacy::private_dir_0700(&root).unwrap();
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
    repo_scan::privacy::private_dir_0700(&root).unwrap();
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
    repo_scan::privacy::private_dir_0700(&empty).unwrap();
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
    repo_scan::privacy::private_dir_0700(&root).unwrap();
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
    repo_scan::privacy::private_dir_0700(&payload).unwrap();
    let db = payload.join("catalog.db");
    let mut foreign = b"SQLite format 3\0".to_vec();
    foreign.resize(8192, 0);
    repo_scan::privacy::private_write_0600(&db, &foreign).unwrap();
    let out = run_str(&["cache", "clear", "--all"], &state, &state);
    assert_eq!(out.status.code(), Some(0), "clear: {out:?}");
    assert!(db.is_file(), "foreign database preserved");
    assert_eq!(std::fs::read(&db).unwrap(), foreign, "bytes untouched");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("preserved"), "says preserved: {stdout}");

    // Tool-owned state (marker bound by a real scan) is still removed.
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
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
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    let repo = fixture::normal_clone(&root, "repo");
    fixture::git(&repo, &["remote", "set-url", "origin", URL_A]);
    fixture::git(&repo, &["config", "branch.main.remote", "origin"]);
    fixture::git(&repo, &["config", "branch.main.merge", "refs/heads/main"]);
    // Real tracking ref: without it installed git fails `@{u}` too, and
    // the scanner (correctly) stores no upstream.
    fixture::git(&repo, &["update-ref", "refs/remotes/origin/main", "main"]);
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
        Some("refs/remotes/origin/main"),
        "upstream tracked: {main:?}"
    );

    // Submodule coverage is examined, not hardcoded.
    let sup_root = tmp.path().join("suproot");
    repo_scan::privacy::private_dir_0700(&sup_root).unwrap();
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
    repo_scan::privacy::private_dir_0700(&cyc_root).unwrap();
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

/// Tool-marker snapshot bytes authorizing their own removal: the stem
/// must equal `report_id`.
#[cfg(unix)]
fn seam_marker_json(report_id: &str) -> String {
    format!(
        "{{\"schema_version\":\"{}\",\"tool\":{{\"name\":\"{}\",\"version\":\"test\"}},\"report_id\":\"{}\"}}",
        repo_scan::report::model::SCHEMA_VERSION,
        repo_scan::report::model::TOOL_NAME,
        report_id
    )
}

/// Seam fixture: `state/payload/` with engine victims, a marker-
/// authorized snapshot, and (unless `omit_staging`) an empty staging
/// dir. `catalog.db-shm` is always omitted — the raced-in case plants it.
#[cfg(unix)]
fn seam_state(tmp: &Path, name: &str, omit_staging: bool) -> PathBuf {
    let state = tmp.join(name);
    let payload = state.join("payload");
    std::fs::create_dir_all(payload.join("report-snapshots")).unwrap();
    if !omit_staging {
        std::fs::create_dir_all(payload.join("staging")).unwrap();
    }
    std::fs::write(payload.join("catalog.db"), b"seam catalog bytes").unwrap();
    std::fs::write(payload.join("catalog.db-wal"), b"seam wal bytes").unwrap();
    std::fs::write(
        payload.join("report-snapshots").join("seam-report.json"),
        seam_marker_json("seam-report"),
    )
    .unwrap();
    state
}

/// Round-2 C1/C2 deterministic preflight/removal seam regression: each
/// race plants between the REAL preflight and the REAL removal phase
/// (no thread timing). Every plant refuses LOUDLY — never false
/// success, never a followed link — while the unswapped control clears
/// through the held pins. The `removed` counts pin the honest partial-
/// on-race semantics: a race caught after earlier unlinks cannot un-
/// unlink (POSIX has no transactional multi-unlink), so it refuses
/// instead of pretending success.
#[cfg(unix)]
#[test]
fn round2_c1_preflight_removal_seam_refuses_loudly() {
    use main_under_test::{test_clear_preflight_removal_seam as seam, TestClearSeamSwap as Swap};
    let tmp = tempfile::tempdir().expect("scratch");

    // Control: no swap — full removal through the held pins.
    let state = seam_state(tmp.path(), "seam-none", false);
    let out = seam(&state, Swap::None);
    assert!(!out.refused, "control must clear: {}", out.detail);
    assert_eq!(out.removed, 3, "db + wal + snapshot: {out:?}");
    let payload = state.join("payload");
    assert!(!payload.join("catalog.db").exists());
    assert!(!payload.join("catalog.db-wal").exists());
    assert!(!payload
        .join("report-snapshots")
        .join("seam-report.json")
        .exists());

    // Replaced victim: first engine victim already swapped — zero unlinks.
    let state = seam_state(tmp.path(), "seam-replace", false);
    let out = seam(&state, Swap::ReplaceVictim);
    assert!(out.refused, "swapped victim must refuse: {out:?}");
    assert!(
        out.detail.contains("changed between preflight and unlink"),
        "{}",
        out.detail
    );
    assert_eq!(out.removed, 0, "{out:?}");
    let payload = state.join("payload");
    assert_eq!(
        std::fs::read(payload.join("catalog.db")).expect("swapped db stays"),
        b"swapped catalog bytes",
        "swapped victim unlinked instead of refused"
    );
    assert!(
        payload.join("catalog.db-wal").is_file(),
        "later victims untouched"
    );

    // Symlinked victim: the link is never followed; the outside sentinel
    // survives byte-identical. catalog.db unlinked before the race was
    // caught (loud partial, never false success).
    let state = seam_state(tmp.path(), "seam-symlink", false);
    let out = seam(&state, Swap::PlantVictimSymlink);
    assert!(out.refused, "symlinked victim must refuse: {out:?}");
    assert!(out.detail.contains("symlink"), "{}", out.detail);
    assert_eq!(out.removed, 1, "{out:?}");
    assert_eq!(
        std::fs::read(state.join("seam-sentinel")).expect("sentinel"),
        b"outside bytes",
        "outside sentinel touched"
    );
    let payload = state.join("payload");
    assert!(
        std::fs::symlink_metadata(payload.join("catalog.db-wal"))
            .expect("meta")
            .file_type()
            .is_symlink(),
        "planted link itself untouched"
    );
    assert!(
        !payload.join("catalog.db").exists(),
        "earlier unlink stands (loud partial)"
    );

    // Raced-in victim (absent at preflight): refuses, entry preserved.
    let state = seam_state(tmp.path(), "seam-racein", false);
    let out = seam(&state, Swap::RaceInVictim);
    assert!(out.refused, "raced-in victim must refuse: {out:?}");
    assert!(
        out.detail.contains("raced in after preflight"),
        "{}",
        out.detail
    );
    assert_eq!(out.removed, 2, "{out:?}");
    assert_eq!(
        std::fs::read(state.join("payload").join("catalog.db-shm")).expect("shm stays"),
        b"raced-in sidecar bytes",
        "raced-in entry unlinked instead of refused"
    );

    // Swapped snapshots dir: the held pin no longer verifies — the
    // substituted tree is never listed or cleared.
    let state = seam_state(tmp.path(), "seam-swapdir", false);
    let out = seam(&state, Swap::SwapSnapshotsDir);
    assert!(out.refused, "swapped known dir must refuse: {out:?}");
    assert_eq!(out.removed, 2, "{out:?}");
    assert!(
        state
            .join("seam-orig-snapshots")
            .join("seam-report.json")
            .is_file(),
        "pre-swap tree untouched"
    );

    // C2 raced-in dangling symlink at an absent-at-preflight known dir:
    // loud refusal, never silent success over uninspected entries.
    let state = seam_state(tmp.path(), "seam-dangling", true);
    let out = seam(&state, Swap::RaceInStagingSymlink);
    assert!(out.refused, "dangling known-dir race must refuse: {out:?}");
    assert!(out.detail.contains("raced in"), "{}", out.detail);
    assert!(
        std::fs::symlink_metadata(state.join("payload").join("staging"))
            .expect("meta")
            .file_type()
            .is_symlink(),
        "dangling link left untouched"
    );
}

/// Round-3 C1b snapshot seam: snapshot authorization is CONTENT-bound,
/// so it survives the re-open removal — a content-swapped snapshot
/// preserves WITHOUT refusal (hash mismatch, not identity mismatch),
/// while byte-identical content under a new identity still removes
/// (removal does not depend on inode stability).
#[cfg(unix)]
#[test]
fn round3_c1_snapshot_seam_content_bound() {
    use main_under_test::{test_clear_preflight_removal_seam as seam, TestClearSeamSwap as Swap};
    let tmp = tempfile::tempdir().expect("scratch");

    // Content swap: preserved, no refusal, siblings still removed.
    let state = seam_state(tmp.path(), "seam-snapswap", false);
    let out = seam(&state, Swap::ReplaceSnapshotVictim);
    assert!(
        !out.refused,
        "content swap preserves, never refuses: {out:?}"
    );
    assert_eq!(out.removed, 2, "{out:?}");
    let payload = state.join("payload");
    assert_eq!(
        std::fs::read(payload.join("report-snapshots").join("seam-report.json"))
            .expect("swapped snapshot stays"),
        b"swapped snapshot bytes",
        "unauthorized bytes unlinked instead of preserved"
    );
    assert!(
        !payload.join("catalog.db").exists(),
        "earlier engine unlinks stand"
    );
    assert!(!payload.join("catalog.db-wal").exists());

    // Identical bytes, new identity: still removed.
    let state = seam_state(tmp.path(), "seam-snapidentical", false);
    let out = seam(&state, Swap::ReplaceSnapshotIdenticalBytes);
    assert!(!out.refused, "identical bytes must clear: {out:?}");
    assert_eq!(out.removed, 3, "{out:?}");
    assert!(
        !state
            .join("payload")
            .join("report-snapshots")
            .join("seam-report.json")
            .exists(),
        "content-bound removal completed"
    );
}

/// Round-3 C1b ownership seam: the read-only store open binds to the
/// HELD victim FD — a catalog swapped in between the FD open and the
/// store open cannot authorize the held (foreign) victim or its marker.
/// Before the bind, the swap variant reported `(true, true)` (the
/// swapped file's `db_id` matched the marker); now it reports
/// `(false, false)` with the victim preserved.
#[cfg(unix)]
#[test]
fn round3_c1_db_identity_seam_binds_store_open() {
    use main_under_test::{test_verify_db_identity_seam as seam, TestDbIdentitySwap as Swap};
    use repo_scan::store::owner::OWNER_MARKER_TAG;

    // Fixture: a marker bound to a REAL tool catalog. Returns the state
    // dir and the real catalog bytes (for the staged swap plant).
    let build = |tmp: &tempfile::TempDir, name: &str| {
        let state = tmp.path().join(name);
        let payload = state.join("payload");
        repo_scan::privacy::private_dir_0700(&payload).expect("mkdir");
        let db = payload.join("catalog.db");
        let db_id = runtime()
            .block_on(async {
                let store = TursoStore::open(&db).await.expect("open");
                let id = store.catalog_db_id().await.expect("db id");
                store.close().await.expect("close");
                id
            })
            .expect("catalog carries a db_id");
        let marker = format!("{OWNER_MARKER_TAG}\ndb_id={db_id}\nwritten_ms=1\npid=1\n");
        repo_scan::privacy::private_write_0600(&payload.join("owner.marker"), marker.as_bytes())
            .expect("marker");
        let real = std::fs::read(&db).expect("read real catalog");
        (state, payload, real)
    };
    // Foreign bytes that pass the magic gate but carry no tool-ownership
    // evidence (no schema markers).
    let foreign = {
        let mut bytes = b"SQLite format 3\0".to_vec();
        bytes.extend(std::iter::repeat_n(0u8, 4096));
        bytes
    };

    // Control: the bound catalog with no swap reports `(true, true)`.
    let tmp = tempfile::tempdir().expect("scratch");
    let (state, _, _) = build(&tmp, "seam-dbbind-none");
    let out = runtime().block_on(seam(&state, Swap::None));
    assert_eq!(out.result, Ok((true, true)), "{out:?}");

    // Swap: the held victim is foreign; the staged (marker-matching)
    // catalog lands between the FD open and the store open. The store
    // opens a different file than the held FD, so the binding fails and
    // the held bytes decide: foreign, preserved.
    let (state, payload, real) = build(&tmp, "seam-dbbind-swap");
    repo_scan::privacy::private_write_0600(&payload.join("catalog.db"), &foreign)
        .expect("overwrite with foreign bytes");
    repo_scan::privacy::private_write_0600(&payload.join("staged-seam-catalog.db"), &real)
        .expect("stage real catalog");
    let out = runtime().block_on(seam(&state, Swap::SwapDbAfterFdOpen));
    assert_eq!(out.result, Ok((false, false)), "{out:?}");
    assert!(
        out.preserved
            .iter()
            .any(|p| p.contains("without tool ownership evidence")),
        "foreign victim preserved loudly: {out:?}"
    );
    // The marker stays: nothing was ever bound.
    assert!(payload.join("owner.marker").is_file());
}
