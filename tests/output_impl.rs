//! Wave2b output-matrix acceptance (Steps 6 + 12, cases 15/16/17).
//!
//! One state model: the human, JSON, and JSONL lanes all read the same
//! catalog state (retained snapshot bytes or the journal committed
//! with them). Every test drives the production `scan`/`query`/`resume`
//! binaries plus read-only catalog reads — never self-comparison:
//!
//! - `w2b_formats_agree_on_ids_and_totals`: the same fixture scanned
//!   with `--format human|json|jsonl` yields identical record IDs and
//!   totals (each format parsed independently).
//! - `w2b_jsonl_replay_reconstructs_json_inventory` (case 15): folding
//!   the JSONL replay yields the final JSON inventory record by
//!   record, with the same totals.
//! - `w2b_mid_transaction_resume_and_expired_reset` (case 16):
//!   reconnecting between two events of one transaction loses nothing;
//!   an expired cursor yields an explicit-reset snapshot — both end to
//!   end through `query --follow --after`.
//! - `w2b_concurrent_readers_see_single_revisions` (case 17): every
//!   concurrent read of a live `--report` file is valid JSON from
//!   exactly one revision; revisions stay bounded (no per-discovery
//!   rebuild).
//! - `w2b_fetch_recomputes_only_affected_comparison`: `--fetch` moving
//!   one tracking ref recomputes only the branches tracking it; an
//!   excluded ref stays `stale` with its analysis-pass label.
//! - `w2b_branch_batch_matches_final_json`: `branch_batch` records
//!   carry `comparison`/`ahead`/`behind` matching the final JSON.
//! - `w2b_broken_pipe_leaves_catalog_unchanged`: a closed follow
//!   consumer ends the writer quietly; catalog records are untouched.
//! - `w2b_terminal_and_failed_payloads`: terminal events carry final
//!   counts + resume command; `scan_failed` carries last cursor +
//!   error + resume capability.
//! - `w2b_query_snapshot_lanes_match_scan`: `query --scan --format
//!   json|human` read the same retained snapshot the scan wrote.
//! - `w2b_follow_json_stays_rejected`: `--follow --format json` is
//!   rejected (JSON supplies one snapshot).

mod common;

use common::fixture;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const W2B_URL: &str = "https://github.com/OWNER/REPO";

fn w2b_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

fn w2b_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn w2b_git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn w2b_db(state: &Path) -> PathBuf {
    state.join("payload").join("catalog.db")
}

/// Temp workspace: fixture root + state dir + cwd. Scans run with
/// `--root <root>` only, never machine-wide.
struct W2bEnv {
    _dir: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
    cwd: PathBuf,
}

impl W2bEnv {
    fn new(prefix: &str) -> Self {
        let dir = fixture::scratch_root(prefix);
        let root = dir.path().join("root");
        repo_scan::privacy::private_dir_0700(&root).unwrap();
        let state = dir.path().join("state");
        let cwd = dir.path().join("cwd");
        repo_scan::privacy::private_dir_0700(&cwd).unwrap();
        Self {
            _dir: dir,
            root,
            state,
            cwd,
        }
    }

    /// Run a scan to completion with `extra` args appended to the base
    /// scan command. Returns the full output (stdout must fit memory;
    /// the fixtures here are small).
    fn run_scan(&self, target: &str, extra: &[&str]) -> std::process::Output {
        let mut args = vec![
            "--state-dir",
            self.state.to_str().expect("utf8"),
            "scan",
            target,
            "--root",
            self.root.to_str().expect("utf8"),
            "--status",
            "metadata",
        ];
        args.extend(extra.iter().copied());
        std::process::Command::new(w2b_binary())
            .args(&args)
            .current_dir(&self.cwd)
            .output()
            .expect("spawn repo-scan scan")
    }

    /// Spawn a scan with stdio captured to files (for long scans polled
    /// while running).
    fn spawn_scan(&self, target: &str, extra: &[&str]) -> std::process::Child {
        let stdout = std::fs::File::create(self.cwd.join("scan.out")).expect("scan.out");
        let stderr = std::fs::File::create(self.cwd.join("scan.err")).expect("scan.err");
        // Wave6: explicit human keeps the footer lines these tests parse
        // (the redirected default is now the JSONL journal replay).
        let mut args = vec![
            "--state-dir".to_string(),
            self.state.to_str().expect("utf8").to_string(),
            "scan".to_string(),
            target.to_string(),
            "--root".to_string(),
            self.root.to_str().expect("utf8").to_string(),
            "--status".to_string(),
            "metadata".to_string(),
            "--format".to_string(),
            "human".to_string(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        std::process::Command::new(w2b_binary())
            .args(&args)
            .current_dir(&self.cwd)
            .stdout(std::process::Stdio::from(stdout))
            .stderr(std::process::Stdio::from(stderr))
            .spawn()
            .expect("spawn repo-scan")
    }

    fn run_query(&self, args: &[&str]) -> std::process::Output {
        let mut full = vec!["--state-dir", self.state.to_str().expect("utf8")];
        full.extend(args.iter().copied());
        std::process::Command::new(w2b_binary())
            .args(&full)
            .current_dir(&self.cwd)
            .output()
            .expect("spawn repo-scan query")
    }

    fn scan_out(&self) -> (String, String) {
        (
            fixture::read_to_string(&self.cwd.join("scan.out")),
            fixture::read_to_string(&self.cwd.join("scan.err")),
        )
    }
}

fn w2b_stdout_line(stdout: &str, key: &str) -> String {
    for line in stdout.lines() {
        if let Some(value) = line.strip_prefix(&format!("{key}:")) {
            return value.trim().to_string();
        }
    }
    panic!("missing `{key}:` in stdout:\n{stdout}");
}

fn w2b_parse_jsonl(stdout: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
        .collect()
}

/// Assert machine-lane stdout purity: no ESC/BEL/CR bytes anywhere.
fn w2b_assert_machine_pure(stdout: &[u8], what: &str) {
    assert!(
        repo_scan::report::output::is_machine_pure(stdout),
        "{what} carries control bytes: {stdout:?}"
    );
}

/// IDs + totals folded from one JSON report document.
struct JsonInventory {
    repos: HashSet<String>,
    checkouts: HashSet<String>,
    branches: HashMap<String, (String, Option<u64>, Option<u64>)>,
    remotes: usize,
    candidates: usize,
    error_ids: HashSet<String>,
}

fn w2b_fold_json(doc: &serde_json::Value) -> JsonInventory {
    let ids = |key: &str| {
        doc[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key} array"))
            .iter()
            .filter_map(|r| r["id"].as_str().map(str::to_string))
            .collect::<HashSet<_>>()
    };
    let branches = doc["branches"]
        .as_array()
        .expect("branches array")
        .iter()
        .map(|b| {
            (
                b["id"].as_str().expect("branch id").to_string(),
                (
                    b["comparison"].as_str().expect("comparison").to_string(),
                    b["ahead"].as_u64(),
                    b["behind"].as_u64(),
                ),
            )
        })
        .collect();
    JsonInventory {
        repos: ids("repositories"),
        checkouts: ids("checkouts"),
        branches,
        remotes: doc["remotes"].as_array().expect("remotes").len(),
        candidates: doc["candidates"].as_array().expect("candidates").len(),
        error_ids: ids("errors"),
    }
}

/// IDs + totals parsed from explicit-human stdout: the `totals` line
/// plus the `R`/`C`/`B` detail rows (parsed independently of the JSON
/// lane — plain-text splitting only, no JSON).
struct HumanInventory {
    totals: HashMap<String, u64>,
    repos: HashSet<String>,
    checkouts: HashSet<String>,
    branches: HashSet<String>,
}

fn w2b_parse_human(stdout: &str) -> HumanInventory {
    let mut totals = HashMap::new();
    let mut repos = HashSet::new();
    let mut checkouts = HashSet::new();
    let mut branches = HashSet::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("totals ") {
            for pair in rest.split_whitespace() {
                let (k, v) = pair.split_once('=').expect("k=v totals");
                totals.insert(k.to_string(), v.parse().expect("u64 total"));
            }
        } else if let Some(rest) = line.strip_prefix("R ") {
            repos.insert(rest.split_whitespace().next().expect("R id").to_string());
        } else if let Some(rest) = line.strip_prefix("C ") {
            checkouts.insert(rest.split_whitespace().next().expect("C id").to_string());
        } else if let Some(rest) = line.strip_prefix("B ") {
            branches.insert(rest.split_whitespace().next().expect("B id").to_string());
        }
    }
    assert!(
        totals.contains_key("repositories"),
        "totals line:\n{stdout}"
    );
    HumanInventory {
        totals,
        repos,
        checkouts,
        branches,
    }
}

/// IDs folded from a JSONL event replay: `repository_found` store
/// IDs, `location_found` checkout IDs, `branch_batch` branch IDs with
/// their comparison triples, `error` record IDs.
struct ReplayInventory {
    repos: HashSet<String>,
    checkouts: HashSet<String>,
    branches: HashMap<String, (String, Option<u64>, Option<u64>)>,
    errors: HashSet<String>,
    terminal_type: String,
    terminal: serde_json::Value,
}

fn w2b_fold_replay(events: &[serde_json::Value]) -> ReplayInventory {
    let mut repos = HashSet::new();
    let mut checkouts = HashSet::new();
    let mut branches = HashMap::new();
    let mut errors = HashSet::new();
    for e in events {
        let t = e["type"].as_str().expect("type");
        let r = &e["records"];
        match t {
            "repository_found" => {
                repos.insert(r["store_id"].as_str().expect("store_id").to_string());
            }
            "location_found" => {
                checkouts.insert(r["checkout_id"].as_str().expect("checkout_id").to_string());
            }
            "branch_batch" => {
                for b in r["branches"].as_array().expect("branches") {
                    branches.insert(
                        b["id"].as_str().expect("branch id").to_string(),
                        (
                            b["comparison"].as_str().expect("comparison").to_string(),
                            b["ahead"].as_u64(),
                            b["behind"].as_u64(),
                        ),
                    );
                }
            }
            "error" => {
                errors.insert(r["id"].as_str().expect("error id").to_string());
            }
            _ => {}
        }
    }
    let last = events.last().expect("terminal event");
    ReplayInventory {
        repos,
        checkouts,
        branches,
        errors,
        terminal_type: last["type"].as_str().expect("type").to_string(),
        terminal: last["records"].clone(),
    }
}

/// Committed `scan_events` rows for one scan, oldest first (read-only).
async fn w2b_journal_rows(db: &Path, scan_id: &str) -> Vec<repo_scan::store::ScanEventRow> {
    use repo_scan::store::Store;
    let store = repo_scan::store::TursoStore::open(db).await.expect("open");
    let rows = store
        .read_scan_events(scan_id, 0, 10_000)
        .await
        .expect("read");
    store.close().await.expect("close");
    rows
}

/// Committed `scan_events` row count for one scan (read-only).
async fn w2b_journal_count(db: &Path, scan_id: &str) -> u64 {
    let store = repo_scan::store::TursoStore::open_read_only(db)
        .await
        .expect("open ro");
    let mut rows = store
        .connection()
        .query(
            "SELECT COUNT(*) FROM scan_events WHERE scan_id = ?1",
            vec![turso::Value::Text(scan_id.to_string())],
        )
        .await
        .expect("count");
    let row = rows.next().await.expect("next").expect("row");
    let turso::Value::Integer(n) = row.get_value(0).expect("val") else {
        panic!("count is integer");
    };
    store.close().await.expect("close");
    u64::try_from(n).expect("u64")
}

/// One state model: the same fixture scanned with `--format
/// human|json|jsonl` (fresh state each, same root) yields identical
/// record IDs and identical totals. Each lane is parsed independently:
/// JSON as one document, human as plain-text rows, JSONL folded from
/// envelopes. Machine lanes carry no prose/ANSI/cursor codes.
#[test]
fn w2b_formats_agree_on_ids_and_totals() {
    if !w2b_git_available() {
        eprintln!("w2b formats: git unavailable; skipping");
        return;
    }
    let dir = fixture::scratch_root("w2b-formats-");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    fixture::tracking_clone(&root, "tracked");
    fixture::normal_clone(&root, "plain");
    fixture::comparison_pair(&root, "shaped", 1, 2);

    let scan_once = |state_name: &str, format: &str| {
        let state = dir.path().join(state_name);
        let out = std::process::Command::new(w2b_binary())
            .arg("--state-dir")
            .arg(&state)
            .arg("scan")
            .arg(W2B_URL)
            .arg("--root")
            .arg(&root)
            .arg("--status")
            .arg("metadata")
            .arg("--format")
            .arg(format)
            .current_dir(dir.path())
            .output()
            .expect("spawn scan");
        assert_eq!(
            out.status.code(),
            Some(0),
            "{format} scan: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };

    // JSON: exactly one document on stdout.
    let json_out = scan_once("st-json", "json");
    w2b_assert_machine_pure(&json_out.stdout, "scan --format json");
    let json_text = String::from_utf8_lossy(&json_out.stdout);
    let doc: serde_json::Value =
        serde_json::from_str(&json_text).expect("stdout is one JSON document");
    assert_eq!(doc["schema_version"], "1.4.0");
    let json = w2b_fold_json(&doc);
    assert_eq!(json.repos.len(), 3, "three confirmed repos");
    assert!(!json.branches.is_empty(), "branches observed");

    // Human: plain-text rows parsed without JSON.
    let human_out = scan_once("st-human", "human");
    let human_text = String::from_utf8_lossy(&human_out.stdout);
    assert!(
        !human_text.as_bytes().contains(&0x1b),
        "human carries no ESC"
    );
    let human = w2b_parse_human(&human_text);
    assert_eq!(human.repos, json.repos, "repo IDs agree");
    assert_eq!(human.checkouts, json.checkouts, "checkout IDs agree");
    assert_eq!(
        human.branches,
        json.branches.keys().cloned().collect::<HashSet<_>>(),
        "branch IDs agree"
    );
    for (key, want) in [
        ("repositories", json.repos.len() as u64),
        ("checkouts", json.checkouts.len() as u64),
        ("branches", json.branches.len() as u64),
        ("remotes", json.remotes as u64),
        ("candidates", json.candidates as u64),
        ("errors", json.error_ids.len() as u64),
    ] {
        assert_eq!(
            human.totals.get(key),
            Some(&want),
            "human total {key} agrees"
        );
    }

    // JSONL: fold the scan's own event stream.
    let jsonl_out = scan_once("st-jsonl", "jsonl");
    w2b_assert_machine_pure(&jsonl_out.stdout, "scan --format jsonl");
    let events = w2b_parse_jsonl(&jsonl_out.stdout);
    assert!(events.len() > 5, "nontrivial stream");
    let replay = w2b_fold_replay(&events);
    assert_eq!(replay.repos, json.repos, "replay repo IDs agree");
    assert_eq!(replay.checkouts, json.checkouts, "checkout IDs agree");
    assert_eq!(
        replay.branches.keys().collect::<HashSet<_>>(),
        json.branches.keys().collect::<HashSet<_>>(),
        "replay branch IDs agree"
    );
    assert_eq!(replay.terminal_type, "scan_completed");
    assert!(
        replay.terminal.get("counts").is_some(),
        "terminal carries final counts"
    );
    assert!(
        replay.terminal["resume_cmd"]
            .as_str()
            .expect("resume_cmd")
            .contains("resume"),
        "terminal carries resume command"
    );
}

/// Case 15: JSONL replay reconstructs the final JSON inventory. One
/// scan serves both sides: the `--format json` document is the
/// inventory, and `query --scan --format jsonl` is the replay. Same
/// records (IDs + comparison triples), same totals, same terminal
/// counts + resume command.
#[test]
fn w2b_jsonl_replay_reconstructs_json_inventory() {
    if !w2b_git_available() {
        eprintln!("w2b case15: git unavailable; skipping");
        return;
    }
    let env = W2bEnv::new("w2b-case15-");
    fixture::tracking_clone(&env.root, "tracked");
    fixture::comparison_pair(&env.root, "shaped", 2, 1);

    let scan = env.run_scan(W2B_URL, &["--format", "json"]);
    assert_eq!(
        scan.status.code(),
        Some(0),
        "scan: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    w2b_assert_machine_pure(&scan.stdout, "scan --format json");
    let doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&scan.stdout)).expect("one JSON doc");
    let scan_id = doc["scan"]["id"].as_str().expect("scan id").to_string();
    let json = w2b_fold_json(&doc);

    let replay = env.run_query(&["query", "--scan", &scan_id, "--format", "jsonl"]);
    assert_eq!(
        replay.status.code(),
        Some(0),
        "replay: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    w2b_assert_machine_pure(&replay.stdout, "query --scan --format jsonl");
    let events = w2b_parse_jsonl(&replay.stdout);
    let folded = w2b_fold_replay(&events);

    assert_eq!(folded.repos, json.repos, "same repository records");
    assert_eq!(folded.checkouts, json.checkouts, "same checkout records");
    assert_eq!(
        folded.branches, json.branches,
        "same branch records with comparison triples"
    );
    assert_eq!(
        folded.errors, json.error_ids,
        "same error records (possibly none)"
    );
    assert_eq!(folded.terminal_type, "scan_completed");
    // Terminal counts name the same per-target matches the JSON
    // envelope reports.
    let matched = doc["scan"]["targets"].as_array().expect("targets")[0]["matched_repositories"]
        .as_u64()
        .expect("u64");
    assert_eq!(
        folded.terminal["counts"]["matched_per_target"][0]
            .as_u64()
            .expect("u64"),
        matched,
        "terminal counts match the inventory"
    );
    assert!(
        folded.terminal["resume_cmd"]
            .as_str()
            .expect("resume_cmd")
            .contains(&scan_id),
        "resume command names the scan"
    );
}

/// Case 16: reconnecting between two events of one transaction loses
/// nothing, end to end through `query --follow --after`; an expired
/// cursor yields an explicit-reset snapshot (never a silent resume,
/// never an error).
#[test]
fn w2b_mid_transaction_resume_and_expired_reset() {
    use repo_scan::scan_events::Cursor;

    if !w2b_git_available() {
        eprintln!("w2b case16: git unavailable; skipping");
        return;
    }
    let env = W2bEnv::new("w2b-case16-");
    fixture::many_repos(&env.root, "repo", 2);
    let mut child = env.spawn_scan(W2B_URL, &[]);
    let status = child.wait().expect("wait");
    let (stdout, stderr) = env.scan_out();
    assert_eq!(status.code(), Some(0), "scan: {stderr}");
    let scan_id = w2b_stdout_line(&stdout, "scan_id");

    let rt = w2b_runtime();
    let db = w2b_db(&env.state);
    let rows = rt.block_on(w2b_journal_rows(&db, &scan_id));
    // One probe's flush: consecutively journaled events sharing one
    // revision with consecutive offsets.
    let pair = rows
        .windows(2)
        .find(|w| {
            w[0].event_type == "repository_found"
                && w[1].event_type == "location_found"
                && w[1].seq == w[0].seq + 1
                && w[1].catalog_rev == w[0].catalog_rev
                && w[1].event_offset == w[0].event_offset + 1
        })
        .unwrap_or_else(|| {
            panic!(
                "no adjacent same-revision pair in: {:?}",
                rows.iter()
                    .map(|r| (r.seq, r.catalog_rev, r.event_offset, r.event_type.clone()))
                    .collect::<Vec<_>>()
            )
        });
    let cursor = Cursor {
        seq: pair[0].seq,
        catalog_rev: pair[0].catalog_rev,
        event_offset: pair[0].event_offset,
    }
    .encode();

    // Resume between the two events of the transaction: the second
    // event arrives first, then everything after it, with no reset.
    let resumed = env.run_query(&[
        "query", "--scan", &scan_id, "--follow", "--format", "jsonl", "--after", &cursor,
    ]);
    assert_eq!(
        resumed.status.code(),
        Some(0),
        "resume: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let tail = w2b_parse_jsonl(&resumed.stdout);
    let expected: Vec<u64> = ((pair[0].seq + 1)..=rows.len() as u64).collect();
    let got: Vec<u64> = tail
        .iter()
        .map(|e| e["seq"].as_u64().expect("seq u64"))
        .collect();
    assert_eq!(got, expected, "every later row exactly once");
    assert_eq!(tail[0]["type"], "location_found");
    assert!(tail.iter().all(|e| e["reset"] != true), "no reset");
    assert_eq!(tail.last().expect("last")["type"], "scan_completed");

    // Expire the prefix through seq 2, then reconnect with a cursor
    // into the pruned prefix: an explicit-reset snapshot replays the
    // retained window from its start.
    let expired = rows[1].clone();
    rt.block_on(async {
        use repo_scan::store::Store;
        let store = repo_scan::store::TursoStore::open(&db).await.expect("open");
        store
            .connection()
            .execute(
                "DELETE FROM scan_events WHERE scan_id = ?1 AND seq <= ?2",
                vec![
                    turso::Value::Text(scan_id.clone()),
                    turso::Value::Integer(2),
                ],
            )
            .await
            .expect("delete prefix");
        store.close().await.expect("close");
    });
    let after = Cursor {
        seq: expired.seq,
        catalog_rev: expired.catalog_rev,
        event_offset: expired.event_offset,
    }
    .encode();
    let resync = env.run_query(&[
        "query", "--scan", &scan_id, "--follow", "--format", "jsonl", "--after", &after,
    ]);
    assert_eq!(
        resync.status.code(),
        Some(0),
        "expired cursor is a snapshot: {}",
        String::from_utf8_lossy(&resync.stderr)
    );
    let tail = w2b_parse_jsonl(&resync.stdout);
    assert_eq!(tail[0]["seq"], 3, "retained window replays");
    assert_eq!(tail[0]["reset"], true, "explicit reset");
    assert_eq!(tail.len(), rows.len() - 2, "whole retained window");
    assert_eq!(tail.last().expect("last")["type"], "scan_completed");
}

/// Case 17: every concurrent read of a live `--report` file is valid
/// JSON from exactly one revision. Readers poll from threads while a
/// slow scan publishes; revisions stay bounded (phase boundaries +
/// throttle — never a rebuild per discovery).
#[test]
fn w2b_concurrent_readers_see_single_revisions() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    if !w2b_git_available() {
        eprintln!("w2b case17: git unavailable; skipping");
        return;
    }
    let env = W2bEnv::new("w2b-case17-");
    fixture::many_repos(&env.root, "repo", 30);
    let dest = env.cwd.join("live.json");
    let dest_arg = dest.to_str().expect("utf8").to_string();

    let mut child = env.spawn_scan(W2B_URL, &["--report", &dest_arg]);
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel::<(String, String)>();
    let (err_tx, err_rx) = std::sync::mpsc::channel::<String>();
    let mut readers = Vec::new();
    for _ in 0..4 {
        let dest = dest.clone();
        let stop = Arc::clone(&stop);
        let tx = tx.clone();
        let err_tx = err_tx.clone();
        readers.push(std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let bytes = match std::fs::read(&dest) {
                    Ok(b) => b,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => {
                        let _ = err_tx.send(format!("read error: {e}"));
                        return;
                    }
                };
                // Every read must be valid JSON from exactly one
                // revision: one schema version, one report id, one
                // scan state.
                match serde_json::from_slice::<serde_json::Value>(&bytes) {
                    Ok(doc) => {
                        let (Some(ver), Some(id), Some(state)) = (
                            doc["schema_version"].as_str(),
                            doc["report_id"].as_str(),
                            doc["scan"]["state"].as_str(),
                        ) else {
                            let _ = err_tx
                                .send(format!("revision missing keys in {} bytes", bytes.len()));
                            return;
                        };
                        assert_eq!(ver, "1.4.0");
                        let _ = tx.send((id.to_string(), state.to_string()));
                    }
                    Err(e) => {
                        let _ = err_tx.send(format!("torn read ({} bytes): {e}", bytes.len()));
                        return;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }));
    }
    drop(tx);
    drop(err_tx);
    let status = child.wait().expect("wait");
    stop.store(true, Ordering::SeqCst);
    for r in readers {
        r.join().expect("reader");
    }
    let (stdout, stderr) = env.scan_out();
    assert!(
        status.code() == Some(0) || status.code() == Some(3),
        "scan: {stderr} {stdout}"
    );

    let read_errors: Vec<String> = err_rx.try_iter().collect();
    assert!(read_errors.is_empty(), "reader failures: {read_errors:?}");
    let mut revisions: HashSet<(String, String)> = HashSet::new();
    for rev in rx.try_iter() {
        revisions.insert(rev);
    }
    assert!(
        !revisions.is_empty(),
        "readers observed the live publication"
    );
    let states: HashSet<&str> = revisions.iter().map(|(_, s)| s.as_str()).collect();
    assert!(
        states.contains("running"),
        "a live (running) revision was observed: {revisions:?}"
    );
    assert!(
        revisions.len() <= 4,
        "revisions bounded (boundaries + throttle, not per discovery): {revisions:?}"
    );
    // The final file is the terminal revision.
    let final_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&dest).expect("final")).expect("final JSON");
    assert!(
        ["complete", "incomplete"].contains(&final_doc["scan"]["state"].as_str().unwrap_or("")),
        "terminal state"
    );
}

/// `--fetch` recomputes only the affected comparison labels: the
/// tracking ref the fetch moved is observed `current` and the local
/// branch tracking it is relabeled from the post-fetch oids, while a
/// refspec-excluded tracking ref stays `stale` and its local branch
/// keeps the analysis-pass label. Fully offline: `origin` is a local
/// path remote.
#[test]
fn w2b_fetch_recomputes_only_affected_comparison() {
    if !w2b_git_available() {
        eprintln!("w2b fetch: git unavailable; skipping");
        return;
    }
    let dir = fixture::scratch_root("w2b-fetch-");
    // Upstream seed lives OUTSIDE the scanned root (it is fetched,
    // never scanned).
    let seed = fixture::normal_clone(dir.path(), "seed");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    let clone = fixture::clone_local(&seed, &root, "clone-a");
    let tip = fixture::git_str(&clone, &["rev-parse", "HEAD"]);
    // A branch tracking a ref the upstream DELETED: `origin/old`
    // exists offline at the branch tip, but the seed has no
    // `refs/heads/old`, so the fetch audit marks it deleted/stale.
    fixture::git(&clone, &["update-ref", "refs/remotes/origin/old", &tip]);
    fixture::git(&clone, &["branch", "old", &tip]);
    fixture::git(&clone, &["config", "branch.old.remote", "origin"]);
    fixture::git(&clone, &["config", "branch.old.merge", "refs/heads/old"]);
    // A second remote with a NARROWED refspec: `narrow/other` is
    // excluded from every fetch and must stay `stale`.
    let seed_arg = seed.to_str().expect("utf8").to_string();
    fixture::git(&clone, &["remote", "add", "narrow", &seed_arg]);
    fixture::git(
        &clone,
        &[
            "config",
            "remote.narrow.fetch",
            "+refs/heads/main:refs/remotes/narrow/main",
        ],
    );
    fixture::git(&clone, &["update-ref", "refs/remotes/narrow/other", &tip]);
    // Upstream advances past the clone: after `--fetch`, `main` is
    // behind by exactly 2.
    fixture::advance_main(&seed, "up", 2);

    let state = dir.path().join("state");
    let target = clone.to_str().expect("utf8").to_string();
    let out = std::process::Command::new(w2b_binary())
        .arg("--state-dir")
        .arg(&state)
        .arg("scan")
        .arg(&target)
        .arg("--root")
        .arg(&root)
        .arg("--status")
        .arg("metadata")
        .arg("--fetch")
        .arg("--format")
        .arg("json")
        .current_dir(dir.path())
        .output()
        .expect("spawn scan");
    assert_eq!(
        out.status.code(),
        Some(0),
        "fetch scan: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("one JSON doc");
    let scan_id = doc["scan"]["id"].as_str().expect("scan id").to_string();
    let by_name = |display: &str| {
        doc["branches"]
            .as_array()
            .expect("branches")
            .iter()
            .find(|b| b["name"]["display"].as_str() == Some(display))
            .unwrap_or_else(|| panic!("branch {display}"))
            .clone()
    };

    // The moved tracking ref is `current`; `main` was recomputed from
    // the post-fetch oids (behind 2, not the analysis-pass equal).
    let tracking = by_name("refs/remotes/origin/main");
    assert_eq!(tracking["freshness"], "current");
    let main = by_name("refs/heads/main");
    assert_eq!(main["comparison"], "behind", "recomputed label");
    assert_eq!(main["behind"], 2, "recomputed behind count");
    assert_eq!(main["ahead"], 0);

    // The deleted-upstream ref stays `stale` — no false `current`
    // — and the branch tracking it keeps its analysis-pass label.
    let deleted = by_name("refs/remotes/origin/old");
    assert_eq!(deleted["freshness"], "stale");
    let old = by_name("refs/heads/old");
    assert_eq!(old["comparison"], "equal");
    assert_eq!(old["ahead"], 0);
    assert_eq!(old["behind"], 0);
    // The refspec-excluded ref stays `stale` too.
    let excluded = by_name("refs/remotes/narrow/other");
    assert_eq!(excluded["freshness"], "stale");

    // The journal proves the direction of motion: analysis-time
    // `branch_batch` records show `main` as `equal` (pre-fetch oids);
    // only the fetch recompute moved it to `behind 2`.
    let replay = std::process::Command::new(w2b_binary())
        .arg("--state-dir")
        .arg(&state)
        .arg("query")
        .arg("--scan")
        .arg(&scan_id)
        .arg("--format")
        .arg("jsonl")
        .current_dir(dir.path())
        .output()
        .expect("spawn query");
    assert_eq!(replay.status.code(), Some(0));
    let events = w2b_parse_jsonl(&replay.stdout);
    let mut batch_main = None;
    let mut batch_old = None;
    for e in &events {
        if e["type"] != "branch_batch" {
            continue;
        }
        for b in e["records"]["branches"].as_array().expect("branches") {
            match b["name"].as_str() {
                Some("refs/heads/main") => batch_main = Some(b.clone()),
                Some("refs/heads/old") => batch_old = Some(b.clone()),
                _ => {}
            }
        }
    }
    let batch_main = batch_main.expect("main in branch_batch");
    assert_eq!(
        batch_main["comparison"], "equal",
        "analysis saw pre-fetch oids"
    );
    let batch_old = batch_old.expect("old in branch_batch");
    assert_eq!(
        (
            batch_old["comparison"].clone(),
            batch_old["ahead"].clone(),
            batch_old["behind"].clone()
        ),
        (
            old["comparison"].clone(),
            old["ahead"].clone(),
            old["behind"].clone()
        ),
        "stale-labeled branch untouched by the recompute"
    );
    // Both remotes refreshed successfully (fetch-phase outcome is
    // journaled per remote).
    let updated: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["type"] == "remote_updated")
        .collect();
    assert_eq!(updated.len(), 2, "one remote_updated per remote");
    assert!(updated.iter().all(|e| e["records"]["status"] == "success"));
}

/// A broken pipe on a follow stream ends the writer quietly (exit 0)
/// with committed catalog records unchanged: same journal row count,
/// same retained snapshot bytes.
#[test]
fn w2b_broken_pipe_leaves_catalog_unchanged() {
    if !w2b_git_available() {
        eprintln!("w2b pipe: git unavailable; skipping");
        return;
    }
    let env = W2bEnv::new("w2b-pipe-");
    fixture::many_repos(&env.root, "repo", 15);
    let mut child = env.spawn_scan(W2B_URL, &[]);
    let status = child.wait().expect("wait");
    let (stdout, stderr) = env.scan_out();
    assert_eq!(status.code(), Some(0), "scan: {stderr}");
    let scan_id = w2b_stdout_line(&stdout, "scan_id");
    let snapshot = w2b_stdout_line(&stdout, "snapshot");

    let rt = w2b_runtime();
    let db = w2b_db(&env.state);
    let before = rt.block_on(w2b_journal_count(&db, &scan_id));
    assert!(before > 10, "nontrivial journal");
    let snapshot_before = std::fs::read(&snapshot).expect("snapshot bytes");

    // Follow with the read end dropped almost immediately: the writer
    // either finishes into the pipe buffer or takes EPIPE — either
    // way it exits 0 without touching the catalog.
    let mut follow = std::process::Command::new(w2b_binary())
        .arg("--state-dir")
        .arg(&env.state)
        .arg("query")
        .arg("--scan")
        .arg(&scan_id)
        .arg("--follow")
        .arg("--format")
        .arg("jsonl")
        .current_dir(&env.cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn follow");
    let mut piped = follow.stdout.take().expect("piped stdout");
    {
        use std::io::Read;
        let mut buf = [0u8; 64];
        let _ = piped.read(&mut buf);
    }
    drop(piped);
    let waited = follow.wait().expect("wait");
    let mut err_bytes = Vec::new();
    if let Some(mut s) = follow.stderr.take() {
        use std::io::Read;
        let _ = s.read_to_end(&mut err_bytes);
    }
    assert_eq!(
        waited.code(),
        Some(0),
        "closed consumer ends quietly: {}",
        String::from_utf8_lossy(&err_bytes)
    );

    let after = rt.block_on(w2b_journal_count(&db, &scan_id));
    assert_eq!(after, before, "journal rows unchanged");
    assert_eq!(
        std::fs::read(&snapshot).expect("snapshot bytes"),
        snapshot_before,
        "snapshot bytes unchanged"
    );
}

/// Terminal events carry final counts + resume command where
/// applicable; `scan_failed` carries the last cursor + error + resume
/// capability. The failure side is forced with a `--report`
/// destination the publisher refuses (inside tool state).
#[test]
fn w2b_terminal_and_failed_payloads() {
    if !w2b_git_available() {
        eprintln!("w2b terminal: git unavailable; skipping");
        return;
    }
    // Completed terminal: counts + resume command.
    let env = W2bEnv::new("w2b-term-ok-");
    fixture::normal_clone(&env.root, "repo");
    let mut child = env.spawn_scan(W2B_URL, &[]);
    let status = child.wait().expect("wait");
    let (stdout, stderr) = env.scan_out();
    assert_eq!(status.code(), Some(0), "scan: {stderr}");
    let scan_id = w2b_stdout_line(&stdout, "scan_id");
    let replay = env.run_query(&["query", "--scan", &scan_id, "--format", "jsonl"]);
    assert_eq!(replay.status.code(), Some(0));
    let events = w2b_parse_jsonl(&replay.stdout);
    let last = events.last().expect("terminal");
    assert_eq!(last["type"], "scan_completed");
    for key in [
        "matched_per_target",
        "pending",
        "open_gaps",
        "unresolvable",
        "status_pending",
        "event_gaps",
    ] {
        assert!(
            last["records"]["counts"].get(key).is_some(),
            "terminal counts carry {key}"
        );
    }
    let resume_cmd = last["records"]["resume_cmd"].as_str().expect("resume_cmd");
    assert!(resume_cmd.contains(&scan_id), "resume names the scan");
    assert!(resume_cmd.contains("--state-dir"), "resume replays state");

    // Failed terminal: last cursor + error + resume capability.
    let env = W2bEnv::new("w2b-term-fail-");
    fixture::normal_clone(&env.root, "repo");
    let refused = env.state.join("rep.json");
    let refused_arg = refused.to_str().expect("utf8").to_string();
    let mut child = env.spawn_scan(W2B_URL, &["--report", &refused_arg]);
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(1), "refused destination fails the scan");
    let (stdout, _) = env.scan_out();
    let scan_id = w2b_stdout_line(&stdout, "scan_id");
    let replay = env.run_query(&["query", "--scan", &scan_id, "--format", "jsonl"]);
    assert_eq!(replay.status.code(), Some(0));
    let events = w2b_parse_jsonl(&replay.stdout);
    let last = events.last().expect("terminal");
    assert_eq!(last["type"], "scan_failed");
    assert!(
        last["records"]["cursor"].is_object() || last["records"]["cursor"].is_null(),
        "last cursor travels (null only when nothing journaled)"
    );
    assert!(
        last["records"]["error"]
            .as_str()
            .is_some_and(|e| !e.is_empty()),
        "error travels"
    );
    assert_eq!(last["records"]["resumable"], true, "resume capability");
    assert!(
        last["records"]["resume_cmd"]
            .as_str()
            .expect("resume_cmd")
            .contains(&scan_id),
        "resume command names the scan"
    );
}

/// `query --scan --format json|human` read the same retained snapshot
/// the scan wrote: the JSON bytes are identical, and the human totals
/// match the JSON lengths.
#[test]
fn w2b_query_snapshot_lanes_match_scan() {
    if !w2b_git_available() {
        eprintln!("w2b querylanes: git unavailable; skipping");
        return;
    }
    let env = W2bEnv::new("w2b-querylanes-");
    fixture::tracking_clone(&env.root, "tracked");
    fixture::normal_clone(&env.root, "plain");

    let scan = env.run_scan(W2B_URL, &["--format", "json"]);
    assert_eq!(
        scan.status.code(),
        Some(0),
        "scan: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&scan.stdout)).expect("one JSON doc");
    let scan_id = doc["scan"]["id"].as_str().expect("scan id").to_string();
    let json = w2b_fold_json(&doc);

    let query = env.run_query(&["query", "--scan", &scan_id, "--format", "json"]);
    assert_eq!(
        query.status.code(),
        Some(0),
        "query json: {}",
        String::from_utf8_lossy(&query.stderr)
    );
    w2b_assert_machine_pure(&query.stdout, "query --scan --format json");
    assert_eq!(
        query.stdout, scan.stdout,
        "query serves the retained snapshot bytes verbatim"
    );

    let human = env.run_query(&["query", "--scan", &scan_id, "--format", "human"]);
    assert_eq!(
        human.status.code(),
        Some(0),
        "query human: {}",
        String::from_utf8_lossy(&human.stderr)
    );
    let parsed = w2b_parse_human(&String::from_utf8_lossy(&human.stdout));
    assert_eq!(parsed.repos, json.repos);
    assert_eq!(parsed.checkouts, json.checkouts);
    assert_eq!(
        parsed.totals.get("branches"),
        Some(&(json.branches.len() as u64))
    );
}

/// `scan_interrupted` carries the scan id, last cursor, saved
/// scope/options, and resume command. Forced with a real SIGINT to a
/// running scan (Unix-only): the bounded save exits 130 and journals
/// the terminal event.
#[cfg(unix)]
#[test]
fn w2b_interrupted_carries_cursor_and_resume() {
    if !w2b_git_available() {
        eprintln!("w2b interrupt: git unavailable; skipping");
        return;
    }
    let env = W2bEnv::new("w2b-interrupt-");
    fixture::many_repos(&env.root, "repo", 30);
    fixture::deep_repo_chain(&env.root, 6);

    let mut child = env.spawn_scan(W2B_URL, &[]);
    let rt = w2b_runtime();
    let db = w2b_db(&env.state);
    // Wait until the scan is observably running (scan row + journaled
    // events), so the SIGINT lands mid-run, not before startup.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let scan_id = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "scan never reached a running state"
        );
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "scan finished before the interrupt window"
        );
        let probe = rt.block_on(async {
            let Ok(store) = repo_scan::store::TursoStore::open_read_only(&db).await else {
                return None;
            };
            let mut rows = store
                .connection()
                .query("SELECT id, state FROM scan_requests LIMIT 1", ())
                .await
                .ok()?;
            let row = rows.next().await.ok()??;
            let (turso::Value::Text(id), turso::Value::Text(state)) =
                (row.get_value(0).ok()?, row.get_value(1).ok()?)
            else {
                return None;
            };
            let events = store.read_scan_events(&id, 0, 10).await.ok()?;
            store.close().await.ok()?;
            Some((id, state, events.len()))
        });
        if let Some((id, state, events)) = probe {
            if state.starts_with("running") && events >= 3 {
                break id;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    // SAFETY: signaling our own spawned child by PID.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            assert_eq!(status.code(), Some(130), "interrupted exit");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "interrupted scan never exited"
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let replay = env.run_query(&["query", "--scan", &scan_id, "--format", "jsonl"]);
    assert_eq!(replay.status.code(), Some(0));
    let events = w2b_parse_jsonl(&replay.stdout);
    let last = events.last().expect("terminal");
    assert_eq!(last["type"], "scan_interrupted");
    assert_eq!(last["records"]["scan_id"], scan_id);
    assert!(
        last["records"]["cursor"].as_str().is_some(),
        "last cursor travels"
    );
    assert!(last["records"]["scope"].is_object(), "saved scope");
    assert!(last["records"]["options"].is_object(), "saved options");
    assert!(
        last["records"]["resume_cmd"]
            .as_str()
            .expect("resume_cmd")
            .contains(&scan_id),
        "resume command names the scan"
    );
}

/// Completed snapshots are retained bounded: past snapshots beyond
/// the newest 32 are pruned (files + catalog rows) while the scan's
/// own snapshot — and every outcome-referenced snapshot — survives.
#[test]
fn w2b_completed_snapshots_retained_bounded() {
    if !w2b_git_available() {
        eprintln!("w2b prune: git unavailable; skipping");
        return;
    }
    let env = W2bEnv::new("w2b-prune-");
    fixture::normal_clone(&env.root, "repo");
    let snapshots = env.state.join("payload").join("report-snapshots");
    repo_scan::privacy::private_dir_0700(&snapshots).unwrap();
    // 40 stale snapshots (content never parsed by the pruner, only
    // listed by safe name + mtime); staggered writes order them.
    for i in 0..40 {
        let path = snapshots.join(format!("w2b-fake-{i:03}.json"));
        std::fs::write(&path, b"{\"stale\":true}").expect("fake snapshot");
    }

    let mut child = env.spawn_scan(W2B_URL, &[]);
    let status = child.wait().expect("wait");
    let (stdout, stderr) = env.scan_out();
    assert_eq!(status.code(), Some(0), "scan: {stderr}");
    let report_id = w2b_stdout_line(&stdout, "report_id");

    let mut kept: Vec<String> = std::fs::read_dir(&snapshots)
        .expect("snapshots dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    kept.sort();
    assert!(
        kept.len() <= repo_scan::report::output::MAX_RETAINED_SNAPSHOTS,
        "bounded retention: {} files",
        kept.len()
    );
    assert!(
        kept.contains(&format!("{report_id}.json")),
        "own snapshot survives: {kept:?}"
    );
    // The oldest fakes went first.
    assert!(
        !kept.contains(&"w2b-fake-000.json".to_string()),
        "oldest pruned: {kept:?}"
    );
}

/// `resume --format` follows the scan lanes: json serves the retained
/// snapshot bytes verbatim, jsonl replays the journal, human renders
/// plain text plus the legacy footers.
#[test]
fn w2b_resume_format_lanes() {
    if !w2b_git_available() {
        eprintln!("w2b resume: git unavailable; skipping");
        return;
    }
    let env = W2bEnv::new("w2b-resume-");
    fixture::tracking_clone(&env.root, "tracked");
    let mut child = env.spawn_scan(W2B_URL, &[]);
    let status = child.wait().expect("wait");
    let (stdout, stderr) = env.scan_out();
    assert_eq!(status.code(), Some(0), "scan: {stderr}");
    let scan_id = w2b_stdout_line(&stdout, "scan_id");

    let query_json = env.run_query(&["query", "--scan", &scan_id, "--format", "json"]);
    assert_eq!(query_json.status.code(), Some(0));
    let resume_json = env.run_query(&["resume", &scan_id, "--format", "json"]);
    assert_eq!(
        resume_json.status.code(),
        Some(0),
        "resume json: {}",
        String::from_utf8_lossy(&resume_json.stderr)
    );
    w2b_assert_machine_pure(&resume_json.stdout, "resume --format json");
    assert_eq!(
        resume_json.stdout, query_json.stdout,
        "resume serves the same snapshot bytes"
    );

    let resume_jsonl = env.run_query(&["resume", &scan_id, "--format", "jsonl"]);
    assert_eq!(resume_jsonl.status.code(), Some(0));
    let events = w2b_parse_jsonl(&resume_jsonl.stdout);
    assert_eq!(events.last().expect("last")["type"], "scan_completed");

    let resume_human = env.run_query(&["resume", &scan_id, "--format", "human"]);
    assert_eq!(resume_human.status.code(), Some(0));
    let text = String::from_utf8_lossy(&resume_human.stdout);
    assert!(text.contains("totals repositories="), "plain render");
    assert!(text.contains(&format!("scan_id: {scan_id}")), "footers");
}

/// `--follow --format json` stays rejected: JSON supplies one
/// snapshot; followers use human or jsonl.
#[test]
fn w2b_follow_json_stays_rejected() {
    if !w2b_git_available() {
        eprintln!("w2b followjson: git unavailable; skipping");
        return;
    }
    let env = W2bEnv::new("w2b-followjson-");
    fixture::normal_clone(&env.root, "repo");
    let mut child = env.spawn_scan(W2B_URL, &[]);
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0));
    let (stdout, _) = env.scan_out();
    let scan_id = w2b_stdout_line(&stdout, "scan_id");

    let out = env.run_query(&["query", "--scan", &scan_id, "--follow", "--format", "json"]);
    assert_eq!(out.status.code(), Some(2), "rejected with exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--follow --format json is rejected"),
        "explicit rejection: {stderr}"
    );
    assert!(out.stdout.is_empty(), "no machine output on rejection");
}

/// `branch_batch` carries `comparison`/`ahead`/`behind` on every
/// record, matching the final JSON branch-for-branch — including a
/// counted `diverged` shape (never a zero default for unknown).
#[test]
fn w2b_branch_batch_matches_final_json() {
    if !w2b_git_available() {
        eprintln!("w2b branchbatch: git unavailable; skipping");
        return;
    }
    let env = W2bEnv::new("w2b-branchbatch-");
    fixture::comparison_pair(&env.root, "shaped", 1, 2);

    let scan = env.run_scan(W2B_URL, &["--format", "json"]);
    assert_eq!(
        scan.status.code(),
        Some(0),
        "scan: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&scan.stdout)).expect("one JSON doc");
    let scan_id = doc["scan"]["id"].as_str().expect("scan id").to_string();
    let json = w2b_fold_json(&doc);
    let shaped_main = json
        .branches
        .values()
        .find(|(c, a, b)| c == "diverged" && *a == Some(1) && *b == Some(2));
    assert!(
        shaped_main.is_some(),
        "diverged 1/2 in JSON: {:?}",
        json.branches.values().collect::<Vec<_>>()
    );

    let replay = env.run_query(&["query", "--scan", &scan_id, "--format", "jsonl"]);
    assert_eq!(replay.status.code(), Some(0));
    let events = w2b_parse_jsonl(&replay.stdout);
    let folded = w2b_fold_replay(&events);
    assert_eq!(
        folded.branches, json.branches,
        "branch_batch triples match the final JSON"
    );
    // Unknown counts are null, never zero.
    for e in &events {
        if e["type"] != "branch_batch" {
            continue;
        }
        for b in e["records"]["branches"].as_array().expect("branches") {
            let counted = ["equal", "ahead", "behind", "diverged"]
                .contains(&b["comparison"].as_str().expect("comparison"));
            assert_eq!(
                b["ahead"].is_null(),
                !counted,
                "ahead null iff uncounted: {b}"
            );
            assert_eq!(
                b["behind"].is_null(),
                !counted,
                "behind null iff uncounted: {b}"
            );
        }
    }
}
