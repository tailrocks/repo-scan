//! Resume acceptance (RESUME-01/RESUME-02; spec section 12).
//!
//! Every CLI run uses a tempdir plus explicit `--root` and `--state-dir`
//! (never a whole-machine scan) via `env!("CARGO_BIN_EXE_repo-scan")`.
//! Tests assert meaningful outcomes: acknowledged work surviving SIGKILL,
//! resume finishing the same scan without re-executing reconciled scope,
//! stale completions keeping the newer revision, and incomplete scans
//! never deleting older findings.

mod common;

use common::fixture;
use repo_scan::model::TaskState;
use repo_scan::store::{now_ms, NewTask, Store, TaskOutcome, TursoStore};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

/// Parse one stderr progress line into cumulative `(tasks_done, pending)`.
/// Both counters are store-read per tick, so they describe durable state.
/// Returns `None` for non-progress lines.
fn parse_progress(line: &str) -> Option<(u64, u64)> {
    let (_, rest) = line.split_once("tasks_done=")?;
    let (done_s, rest) = rest.split_once('/')?;
    let done = done_s.parse::<u64>().ok()?;
    let (_, rest) = rest.split_once("pending=")?;
    let pending_s = rest.split(|c: char| !c.is_ascii_digit()).next()?;
    let pending = pending_s.parse::<u64>().ok()?;
    Some((done, pending))
}

/// Minimum durable acknowledgments before the RESUME-01 kill (clarified
/// floor: >=1 terminal task while pending work remains; 5 keeps margin
/// against a single-task fluke without slowing the gate).
const MIN_ACKS: u64 = 5;

/// Kill-gate predicate: durable evidence of acknowledged work while work
/// remains. Both counters are store-read per tick (never a fixed-sleep
/// proxy); `pending > 0` proves the kill lands mid-scan.
fn kill_gate_met(done: u64, pending: u64) -> bool {
    done >= MIN_ACKS && pending > 0
}

#[test]
fn resume01_kill_gate_requires_acks_with_pending_work() {
    // Production progress format (`format_progress_line_full_inner`):
    // store-read cumulative `tasks_done` plus `pending` on one line.
    let line = "repo-scan: scan abc gen 1 session(this run): claimed=7 dirs=7 entries=70 \
         stale-requeued=0 | cumulative(scan total): tasks_done=7/50 dirs=7 entries=70 \
         pending=43 | elapsed=3s rate=1.0 tasks/s eta=~1s scope=- volume=- scope_total=unknown";
    assert_eq!(parse_progress(line), Some((7, 43)));
    assert!(kill_gate_met(7, 43));
    // Drained scan: dones without pending work are never a mid-scan kill.
    assert!(!kill_gate_met(7, 0));
    // Below the acknowledgment floor: no durable evidence yet.
    assert!(!kill_gate_met(MIN_ACKS - 1, 43));
    // Non-progress lines never satisfy the gate.
    assert_eq!(parse_progress("repo-scan: starting scan"), None);
    assert_eq!(parse_progress(""), None);
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

/// Single integer result of a `SELECT COUNT(*)`-shaped query.
async fn sql_count(store: &TursoStore, sql: &str) -> i64 {
    let mut rows = store.connection().query(sql, ()).await.expect("query");
    let row = rows.next().await.expect("next").expect("row");
    match row.get_value(0).expect("value") {
        turso::Value::Integer(n) => n,
        other => panic!("expected integer count, got {other:?}"),
    }
}

/// First text column of every row.
async fn sql_text_col(store: &TursoStore, sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rows = store.connection().query(sql, ()).await.expect("query");
    while let Some(row) = rows.next().await.expect("next") {
        match row.get_value(0).expect("value") {
            turso::Value::Text(text) => out.push(text),
            other => panic!("expected text, got {other:?}"),
        }
    }
    out
}

/// First two text columns of every row.
async fn sql_text_pairs(store: &TursoStore, sql: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rows = store.connection().query(sql, ()).await.expect("query");
    while let Some(row) = rows.next().await.expect("next") {
        let first = match row.get_value(0).expect("v0") {
            turso::Value::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        };
        let second = match row.get_value(1).expect("v1") {
            turso::Value::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        };
        out.push((first, second));
    }
    out
}

/// RESUME-01: SIGKILL mid-scan, then resume. Acknowledged (`complete`) work
/// survives the crash and is never re-executed (attempt counts frozen);
/// resume finishes the same scan id in the same generation with full
/// coverage; only bounded in-flight work is redone; and the resumed
/// dir-complete count equals a fresh full traversal.
#[test]
fn resume01_kill_mid_scan_resume_completes_without_redo() {
    const MID_DIRS: usize = 25;
    const LEAVES_PER_MID: usize = 10;
    const FILES_PER_LEAF: usize = 8;
    const DEEP: usize = 48;
    const REPOS: usize = 8;

    let tmp = tempfile::tempdir().expect("tempdir");
    let state = tmp.path().join("state");
    let root = tmp.path().join("crash-tree");
    for mid in 0..MID_DIRS {
        let mid_dir = root.join(format!("mid-{mid:02}"));
        for leaf in 0..LEAVES_PER_MID {
            let leaf_dir = mid_dir.join(format!("leaf-{leaf:02}"));
            repo_scan::privacy::private_dir_0700(&leaf_dir).expect("mkdir");
            for file in 0..FILES_PER_LEAF {
                repo_scan::privacy::private_write_0600(
                    &leaf_dir.join(format!("f{file}.txt")),
                    b"x",
                )
                .expect("write");
            }
        }
    }
    fixture::deep_path(&root, DEEP);
    for repo in 0..REPOS {
        fixture::normal_clone(&root, &format!("repo-{repo}"));
    }
    let report = tmp.path().join("rep.json");
    let report_s = report.to_str().expect("utf8").to_string();
    let root_s = root.to_str().expect("utf8").to_string();

    // Spawn the scan; SIGKILL it once durable acknowledgments are
    // observable (never a blind sleep: a fixed grace races scan startup
    // and kills before the first acknowledgment on a loaded host).
    // Progress `tasks_done`/`pending` are store-read per tick, so an
    // observed `tasks_done` count is already durable at kill time.
    let mut child = cmd(&state, tmp.path())
        .args([
            "scan",
            URL,
            "--root",
            root_s.as_str(),
            "--report",
            report_s.as_str(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn scan");
    // Drain stderr on a helper thread: the kill gate reads progress
    // lines live, and no pipe back-pressure can stall the scan.
    let child_stderr = child.stderr.take().expect("piped stderr");
    let (line_tx, line_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        use std::io::BufRead as _;
        let reader = std::io::BufReader::new(child_stderr);
        for line in reader.lines().map_while(Result::ok) {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut acked = 0u64;
    let mut lines_seen = 0u64;
    let mut last_progress = String::from("<none>");
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            panic!("scan exited ({status}) before the kill window");
        }
        // Bounded on every path: the deadline is checked above the
        // receive, so a closed pipe (Disconnected) can never spin past
        // it while the child lingers.
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "no durable acknowledgment within 120s \
                 (acked={acked} lines_seen={lines_seen} last_progress={last_progress:?})"
            );
        }
        match line_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(line) => {
                lines_seen += 1;
                if let Some((done, pending)) = parse_progress(&line) {
                    acked = acked.max(done);
                    last_progress = line;
                    if kill_gate_met(done, pending) {
                        break;
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // stderr closed: the child is exiting; re-polled above.
            }
        }
    }
    // The gate broke on a tick with pending work, so the kill lands
    // mid-scan; if the run still finished first, the tree is too small
    // for this host's speed, not too big for its slowness.
    assert!(
        child.try_wait().expect("poll child").is_none(),
        "scan finished before the kill landed"
    );
    child.kill().expect("SIGKILL mid-scan");
    let status = child.wait().expect("wait");
    assert!(!status.success(), "killed scan must not report success");
    reader.join().expect("stderr reader");

    // Acknowledged work survives the crash.
    let rt = runtime();
    let killed: (String, Vec<(String, u64)>, i64) = rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        assert!(db.exists(), "catalog survives SIGKILL");
        let store = TursoStore::open(&db).await.expect("reopen after kill");
        let scans = sql_text_pairs(&store, "SELECT id, state FROM scan_requests").await;
        assert_eq!(scans.len(), 1, "one scan request row: {scans:?}");
        assert!(
            scans[0].1.starts_with("running"),
            "killed scan stays resumable: {:?}",
            scans[0]
        );
        assert_eq!(
            sql_count(&store, "SELECT COUNT(*) FROM generations").await,
            1
        );
        assert_eq!(
            sql_count(
                &store,
                "SELECT COUNT(*) FROM frontier_tasks WHERE state = 'leased'"
            )
            .await,
            0,
            "recovery requeues dead leases at open"
        );
        let complete_ids = sql_text_col(
            &store,
            "SELECT id FROM frontier_tasks WHERE state = 'complete'",
        )
        .await;
        assert!(
            !complete_ids.is_empty(),
            "kill gate observed {MIN_ACKS} durable dones yet none are complete"
        );
        let mut frozen = Vec::with_capacity(complete_ids.len());
        for id in &complete_ids {
            let task = store.get_task(id).await.expect("get").expect("row");
            frozen.push((id.clone(), task.attempts));
        }
        let total = sql_count(&store, "SELECT COUNT(*) FROM frontier_tasks").await;
        assert!(total >= 10, "durable enqueue survived: {total} tasks");
        store.close().await.expect("close");
        (scans[0].0.clone(), frozen, total)
    });
    let (scan_id, killed_complete, total_at_kill) = killed;

    // Resume the same scan id to completion.
    let out = run(&["resume", scan_id.as_str()], tmp.path(), &state);
    assert_eq!(
        out.status.code(),
        Some(0),
        "resume exits 0: {}",
        stderr_text(&out)
    );
    assert_eq!(stdout_line(&out, "scan_id"), scan_id, "resume keeps the id");
    let resumed = report_json(&report);
    assert_eq!(resumed["scan"]["state"].as_str(), Some("complete"));
    assert_eq!(
        resumed["scan"]["generation"].as_u64(),
        Some(1),
        "resume reuses the killed generation"
    );
    assert_eq!(resumed["coverage"]["filesystem"].as_str(), Some("complete"));
    assert_eq!(resumed["coverage"]["gaps"].as_u64(), Some(0));
    let dirs_resumed = resumed["coverage"]["directories_complete"]
        .as_u64()
        .expect("dir-complete count");
    assert!(dirs_resumed > 100, "full scope covered: {dirs_resumed}");

    // Reconciled scope was not redone: every task complete-at-kill is still
    // complete with a frozen attempt count (never reclaimed); only bounded
    // in-flight work (one claim batch) was re-executed.
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("reopen");
        for (id, attempts_before) in &killed_complete {
            let task = store
                .get_task(id)
                .await
                .expect("get")
                .unwrap_or_else(|| panic!("complete task {id} survives resume"));
            assert_eq!(task.state, TaskState::Complete, "{id}");
            assert_eq!(task.attempts, *attempts_before, "{id} never reclaimed");
        }
        let redone = sql_count(
            &store,
            "SELECT COUNT(*) FROM frontier_tasks \
             WHERE kind = 'enumerate_dir' AND attempts > 1",
        )
        .await;
        assert!(
            redone <= 32,
            "bounded in-flight redo only, got {redone} of {total_at_kill}"
        );
        store.close().await.expect("close");
    });

    // A fresh full traversal covers the same scope: dir-complete counts
    // agree between the resumed run and the force-rescan.
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
    let full = report_json(&report);
    assert_eq!(full["scan"]["generation"].as_u64(), Some(2));
    assert_eq!(
        full["coverage"]["directories_complete"].as_u64(),
        Some(dirs_resumed),
        "resume covered the full scope"
    );
}

/// RESUME-02 (store level): invalidations landing during enumeration
/// survive a stale completion. The completion is rejected, the task is
/// requeued at the newest revision, the revision is never erased, and a
/// reconciliation task is scheduled. Uses the CLI's dir scope-key codec
/// over a real tempdir path, with two stacked invalidations.
#[test]
fn resume02_stale_completion_keeps_newer_rev() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let watched = dir.path().join("watched");
        repo_scan::privacy::private_dir_0700(&watched).expect("mkdir");
        let scope = repo_scan::config::scope_key_for_dir(&watched);
        let db = dir.path().join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let epoch = store.epoch();
        let now = now_ms();
        let task = NewTask {
            id: "t-enum-live",
            kind: "enumerate_dir",
            generation: 1,
            dir_id: None,
            scope_key: &scope,
            expected_rev: 0,
            idempotency_key: "idem-enum-live",
        };
        store.enqueue_task(&task, now).await.expect("enqueue");
        let claimed = store
            .claim_tasks(epoch, 10, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);

        // Two invalidations land while the enumeration is leased.
        assert_eq!(
            store.invalidate_scope(&scope, 1, now).await.expect("inv"),
            1
        );
        assert_eq!(
            store.invalidate_scope(&scope, 1, now).await.expect("inv"),
            2
        );
        assert_eq!(store.scope_rev(&scope).await.expect("rev"), 2);

        let stale = store
            .complete_task(
                "t-enum-live",
                claimed[0].token,
                epoch,
                &TaskOutcome::Complete,
                now,
            )
            .await
            .unwrap_err();
        assert!(stale.to_string().contains("stale-completion"), "{stale}");
        let task = store
            .get_task("t-enum-live")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(task.state, TaskState::Pending, "stale work requeues");
        assert_eq!(task.expected_rev, 2, "newest revision adopted");
        assert_eq!(
            store.scope_rev(&scope).await.expect("rev"),
            2,
            "newer rev never erased"
        );
        let reconcile = store
            .get_task(&format!("reconcile:{scope}:2"))
            .await
            .expect("get")
            .expect("reconcile scheduled");
        assert_eq!(reconcile.state, TaskState::Pending);

        // A fresh claim observes the new revision and completes cleanly.
        let claimed = store
            .claim_tasks(epoch, 10, 60_000, now)
            .await
            .expect("reclaim");
        let fresh = claimed
            .into_iter()
            .find(|entry| entry.task.id == "t-enum-live")
            .expect("fresh claim");
        assert_eq!(fresh.task.expected_rev, 2);
        store
            .complete_task(
                "t-enum-live",
                fresh.token,
                epoch,
                &TaskOutcome::Complete,
                now,
            )
            .await
            .expect("complete");
        let task = store
            .get_task("t-enum-live")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(task.state, TaskState::Complete);
        assert_eq!(store.scope_rev(&scope).await.expect("rev"), 2);
        store.close().await.expect("close");
    });
}

/// RESUME-02: an incomplete scan (durable gap on one root) never deletes
/// older findings: the catalog still serves both repositories afterwards,
/// in the report and in cached queries.
#[test]
fn resume02_incomplete_scan_keeps_old_findings() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = tmp.path().join("state");
    let root = tmp.path().join("fixture");
    fixture::normal_clone(&root, "repo-a");
    fixture::normal_clone(&root, "repo-b");
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
    let out = run(&["query", URL, "--cached"], tmp.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert_eq!(stdout_line(&out, "matches"), "2");

    // A later scan with an extra missing root goes incomplete on that root.
    let missing = tmp.path().join("gone");
    let missing_s = missing.to_str().expect("utf8").to_string();
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_s.as_str(),
            "--root",
            missing_s.as_str(),
            "--report",
            report_s.as_str(),
        ],
        tmp.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let gapped = report_json(&report);
    assert!(
        gapped["coverage"]["gaps"].as_u64().unwrap_or(0) >= 1,
        "missing root is a gap: {gapped}"
    );
    assert_eq!(
        gapped["coverage"]["filesystem"].as_str(),
        Some("incomplete")
    );
    // D5 (Step 15 case 5): the root set {fixture, gone} differs from the
    // first scan's {fixture}, so coverage cannot be reused even with live
    // events — a fresh generation on every platform. The old findings below
    // still come from the shared catalog, not from generation reuse.
    assert_eq!(
        gapped["scan"]["generation"].as_u64(),
        Some(2),
        "fresh generation for a different root set"
    );
    assert_eq!(
        gapped["repositories"].as_array().map(|a| a.len()),
        Some(2),
        "old findings kept: {gapped}"
    );

    // The failed scope removed nothing from the catalog.
    let out = run(&["query", URL, "--cached"], tmp.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert_eq!(stdout_line(&out, "matches"), "2");
}
