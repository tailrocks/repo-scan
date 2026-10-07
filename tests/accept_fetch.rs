//! E2E `--fetch` phase acceptance (goal Step 11, cases 15.22/15.23/15.18).
//!
//! Real `git fetch` executions against local-path remotes (never network:
//! every remote is a plain filesystem path under a private scratch root).
//! The installed Git CLI is the independent oracle: tracking-oid moves,
//! local-tip immobility, kept-but-deleted refs, and worktree cleanliness
//! are all re-read with `git` after the scan, never trusted from the
//! report alone.
//!
//! Worlds are single-clone except the resume test, so `origin/*`
//! branches and the `origin` remote match uniquely in each report
//! (seed upstreams carry no remotes of their own).

mod common;

use common::fixture;
use repo_scan::store::{Store, TursoStore};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

fn cmd(state: &Path, cwd: &Path) -> Command {
    let mut command = Command::new(binary());
    command.arg("--state-dir").arg(state).current_dir(cwd);
    command
}

fn run(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    cmd(state, cwd)
        .args(args)
        .output()
        .expect("spawn repo-scan")
}

fn stderr_text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn load_json(path: &Path) -> serde_json::Value {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("report is valid JSON")
}

/// Find a branch row by kind + full ref name. Unique in single-clone
/// worlds (seed upstreams have no remotes, hence no tracking rows).
fn branch<'r>(report: &'r serde_json::Value, kind: &str, name: &str) -> &'r serde_json::Value {
    report["branches"]
        .as_array()
        .expect("branches array")
        .iter()
        .find(|b| b["kind"].as_str() == Some(kind) && b["name"]["value"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("missing {kind} branch {name}: {report}"))
}

/// Find a remote row by name + role. Unique in single-clone worlds.
fn remote(report: &serde_json::Value, name: &str, role: &str) -> serde_json::Value {
    report["remotes"]
        .as_array()
        .expect("remotes array")
        .iter()
        .find(|r| r["name"]["value"].as_str() == Some(name) && r["role"].as_str() == Some(role))
        .unwrap_or_else(|| panic!("missing {role} remote {name}: {report}"))
        .clone()
}

/// Seed upstream: a normal repo with `main` + `other` at the same oid.
/// Returns `(upstream_dir, main_oid)`. Commits land directly in the
/// upstream worktree; clones only ever fetch from it.
fn seed_upstream(parent: &Path, name: &str) -> (PathBuf, String) {
    let dir = parent.join(name);
    repo_scan::privacy::private_dir_0700(&dir).expect("mkdir");
    fixture::git(&dir, &["init", "-q"]);
    let oid = fixture::commit_file(&dir, "README.md", "# seed\n", "initial");
    fixture::git(&dir, &["branch", "-M", "main"]);
    fixture::git(&dir, &["branch", "other"]);
    (dir, oid)
}

fn clone_from(parent: &Path, src: &Path, name: &str) -> PathBuf {
    let dst = parent.join(name);
    fixture::git(
        parent,
        &[
            "clone",
            "-q",
            src.to_str().expect("utf8"),
            dst.to_str().expect("utf8"),
        ],
    );
    dst
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

async fn refresh_rows(store: &TursoStore) -> Vec<(String, String, String, i64)> {
    let mut out = Vec::new();
    let mut rows = store
        .connection()
        .query(
            "SELECT store_id, remote_name, status, observed_at_ms FROM remote_refreshes",
            (),
        )
        .await
        .expect("query refreshes");
    while let Some(row) = rows.next().await.expect("next") {
        let id = match row.get_value(0).expect("v0") {
            turso::Value::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        };
        let name = match row.get_value(1).expect("v1") {
            turso::Value::Blob(bytes) => String::from_utf8(bytes).expect("remote name utf8"),
            other => panic!("expected blob, got {other:?}"),
        };
        let status = match row.get_value(2).expect("v2") {
            turso::Value::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        };
        let observed = match row.get_value(3).expect("v3") {
            turso::Value::Integer(n) => n,
            other => panic!("expected integer, got {other:?}"),
        };
        out.push((id, name, status, observed));
    }
    out
}

/// FETCH-E2E-01: a behind tracking ref advances to the upstream tip,
/// labels `current`, and the local branch tip + worktree stay untouched.
#[test]
fn fetch01_success_advances_tracking_marks_current() {
    let tmp = fixture::scratch_root("fetch01");
    let state = tmp.path().join("state");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");

    let (upstream, c1) = seed_upstream(&root, "upstream");
    let clone = clone_from(&root, &upstream, "clone");
    // Upstream advances after the clone: the fetch must pick this up.
    let c2 = fixture::commit_file(&upstream, "advance.txt", "v2\n", "advance main");
    assert_ne!(c1, c2);

    let pre_tip = fixture::git_str(&clone, &["rev-parse", "refs/heads/main"]);
    assert_eq!(pre_tip, c1, "clone starts at the old tip");
    let pre_tracking = fixture::git_str(&clone, &["rev-parse", "refs/remotes/origin/main"]);
    assert_eq!(pre_tracking, c1, "tracking starts behind");

    let report_path = tmp.path().join("rep.json");
    let out = run(
        &[
            "scan",
            "--all",
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            report_path.to_str().expect("utf8"),
            "--fetch",
        ],
        tmp.path(),
        &state,
    );
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "usable scan result: {}",
        stderr_text(&out)
    );
    let report = load_json(&report_path);

    let refresh = remote(&report, "origin", "fetch");
    assert_eq!(refresh["refresh"]["status"].as_str(), Some("success"));
    let tracking = branch(&report, "remote_tracking", "refs/remotes/origin/main");
    assert_eq!(tracking["oid"]["hex"].as_str(), Some(c2.as_str()));
    assert_eq!(tracking["freshness"].as_str(), Some("current"));
    assert!(
        tracking["freshness_at"].as_str().is_some(),
        "current label carries a timestamp"
    );
    // Local branches are never freshness-labeled.
    let local = branch(&report, "local", "refs/heads/main");
    assert_eq!(local["oid"]["hex"].as_str(), Some(c1.as_str()));
    assert_eq!(local["freshness"].as_str(), Some("unknown"));

    // Independent oracle: git re-reads the moved tracking ref, the
    // unmoved local tip, and a still-clean worktree.
    assert_eq!(
        fixture::git_str(&clone, &["rev-parse", "refs/remotes/origin/main"]),
        c2,
        "tracking ref really advanced"
    );
    assert_eq!(
        fixture::git_str(&clone, &["rev-parse", "refs/heads/main"]),
        c1,
        "local branch tip never moved"
    );
    assert!(
        fixture::git(&clone, &["status", "--porcelain=v2"]).is_empty(),
        "worktree untouched by the fetch"
    );
}

/// FETCH-E2E-02: an already-current remote still records success with
/// zero updated refs and a `current` label (no-op fetch is honest).
#[test]
fn fetch02_up_to_date_fetch_is_success_with_zero_updates() {
    let tmp = fixture::scratch_root("fetch02");
    let state = tmp.path().join("state");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");

    let (upstream, c1) = seed_upstream(&root, "upstream");
    let clone = clone_from(&root, &upstream, "clone");

    let report_path = tmp.path().join("rep.json");
    let out = run(
        &[
            "scan",
            "--all",
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            report_path.to_str().expect("utf8"),
            "--fetch",
        ],
        tmp.path(),
        &state,
    );
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "usable scan result: {}",
        stderr_text(&out)
    );
    let report = load_json(&report_path);

    let refresh = remote(&report, "origin", "fetch");
    assert_eq!(refresh["refresh"]["status"].as_str(), Some("success"));
    assert_eq!(refresh["refresh"]["refs_updated"].as_u64(), Some(0));
    let tracking = branch(&report, "remote_tracking", "refs/remotes/origin/main");
    assert_eq!(tracking["oid"]["hex"].as_str(), Some(c1.as_str()));
    assert_eq!(tracking["freshness"].as_str(), Some("current"));

    assert_eq!(
        fixture::git_str(&clone, &["rev-parse", "refs/remotes/origin/main"]),
        c1
    );
}

/// FETCH-E2E-03 (Step 15.22): a bare `--mirror` clone reports
/// `unsupported` and its branch tips stay byte-identical: the
/// branch-tip-writing refspec is never executed.
#[test]
fn fetch03_mirror_is_unsupported_branch_tips_untouched() {
    let tmp = fixture::scratch_root("fetch03");
    let state = tmp.path().join("state");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");

    let (upstream, c1) = seed_upstream(&root, "upstream");
    let mirror = root.join("mirror");
    fixture::git(
        &root,
        &[
            "clone",
            "-q",
            "--mirror",
            upstream.to_str().expect("utf8"),
            mirror.to_str().expect("utf8"),
        ],
    );
    let c2 = fixture::commit_file(&upstream, "advance.txt", "v2\n", "advance main");
    assert_ne!(c1, c2);

    let report_path = tmp.path().join("rep.json");
    let out = run(
        &[
            "scan",
            "--all",
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            report_path.to_str().expect("utf8"),
            "--fetch",
        ],
        tmp.path(),
        &state,
    );
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "usable scan result: {}",
        stderr_text(&out)
    );
    let report = load_json(&report_path);

    let refresh = remote(&report, "origin", "fetch");
    assert_eq!(
        refresh["refresh"]["status"].as_str(),
        Some("unsupported"),
        "mirror refspec refuses to run"
    );
    // No tracking row may claim to be current without an executed fetch.
    for b in report["branches"].as_array().expect("branches") {
        assert_ne!(
            b["freshness"].as_str(),
            Some("current"),
            "unsupported refresh labels nothing current: {}",
            b["name"]["value"]
        );
    }

    // Oracle: the mirror's branch tips are exactly as cloned.
    assert_eq!(
        fixture::git_str(&mirror, &["rev-parse", "refs/heads/main"]),
        c1,
        "mirror branch tip untouched"
    );
    assert_eq!(
        fixture::git_str(&mirror, &["rev-parse", "refs/heads/other"]),
        c1,
        "mirror second branch untouched"
    );
}

/// FETCH-E2E-04 (Step 15.23): a branch deleted upstream is found, its
/// local tracking ref is KEPT (no prune) and labeled `stale`, while a
/// still-present branch labels `current`.
#[test]
fn fetch04_deleted_upstream_branch_stays_stale_tracking_kept() {
    let tmp = fixture::scratch_root("fetch04");
    let state = tmp.path().join("state");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");

    let (upstream, c1) = seed_upstream(&root, "upstream");
    fixture::git(&upstream, &["branch", "gone"]);
    let clone = clone_from(&root, &upstream, "clone");
    assert_eq!(
        fixture::git_str(&clone, &["rev-parse", "refs/remotes/origin/gone"]),
        c1,
        "clone tracks the doomed branch"
    );
    // Upstream deletes `gone` and advances `main`.
    fixture::git(&upstream, &["branch", "-D", "gone"]);
    let c2 = fixture::commit_file(&upstream, "advance.txt", "v2\n", "advance main");

    let report_path = tmp.path().join("rep.json");
    let out = run(
        &[
            "scan",
            "--all",
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            report_path.to_str().expect("utf8"),
            "--fetch",
        ],
        tmp.path(),
        &state,
    );
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "usable scan result: {}",
        stderr_text(&out)
    );
    let report = load_json(&report_path);

    let refresh = remote(&report, "origin", "fetch");
    assert_eq!(refresh["refresh"]["status"].as_str(), Some("success"));
    let main = branch(&report, "remote_tracking", "refs/remotes/origin/main");
    assert_eq!(main["oid"]["hex"].as_str(), Some(c2.as_str()));
    assert_eq!(main["freshness"].as_str(), Some("current"));
    let gone = branch(&report, "remote_tracking", "refs/remotes/origin/gone");
    assert_eq!(gone["oid"]["hex"].as_str(), Some(c1.as_str()), "kept oid");
    assert_eq!(gone["freshness"].as_str(), Some("stale"));

    // Catalog records the upstream deletion the audit found.
    let rt = runtime();
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open catalog");
        let mut rows = store
            .connection()
            .query(
                "SELECT refs_deleted_json FROM remote_refreshes WHERE status = 'success'",
                (),
            )
            .await
            .expect("query");
        let row = rows.next().await.expect("next").expect("one success row");
        let deleted = match row.get_value(0).expect("v0") {
            turso::Value::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        };
        store.close().await.expect("close");
        assert!(
            deleted.contains("refs/remotes/origin/gone"),
            "deleted branch recorded: {deleted}"
        );
    });

    // Oracle: no prune happened; the tracking ref still resolves.
    assert_eq!(
        fixture::git_str(&clone, &["rev-parse", "refs/remotes/origin/gone"]),
        c1,
        "tracking ref kept, never pruned"
    );
}

/// FETCH-E2E-05 (Step 15.23): a ref outside the effective fetch
/// refspecs is never labeled `current`, even when the fetch succeeds.
#[test]
fn fetch05_excluded_ref_never_labeled_current() {
    let tmp = fixture::scratch_root("fetch05");
    let state = tmp.path().join("state");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");

    let (upstream, c1) = seed_upstream(&root, "upstream");
    let clone = clone_from(&root, &upstream, "clone");
    // Restrict the clone to `main`-only fetching, then advance the
    // excluded branch upstream.
    fixture::git(
        &clone,
        &[
            "config",
            "remote.origin.fetch",
            "+refs/heads/main:refs/remotes/origin/main",
        ],
    );
    fixture::git(&upstream, &["checkout", "-q", "other"]);
    let c_other = fixture::commit_file(&upstream, "other.txt", "o2\n", "advance other");
    fixture::git(&upstream, &["checkout", "-q", "main"]);
    assert_ne!(c1, c_other);

    let report_path = tmp.path().join("rep.json");
    let out = run(
        &[
            "scan",
            "--all",
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            report_path.to_str().expect("utf8"),
            "--fetch",
        ],
        tmp.path(),
        &state,
    );
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "usable scan result: {}",
        stderr_text(&out)
    );
    let report = load_json(&report_path);

    let refresh = remote(&report, "origin", "fetch");
    assert_eq!(refresh["refresh"]["status"].as_str(), Some("success"));
    let main = branch(&report, "remote_tracking", "refs/remotes/origin/main");
    assert_eq!(main["freshness"].as_str(), Some("current"));
    let other = branch(&report, "remote_tracking", "refs/remotes/origin/other");
    assert_eq!(
        other["oid"]["hex"].as_str(),
        Some(c1.as_str()),
        "not fetched"
    );
    assert_eq!(other["freshness"].as_str(), Some("stale"));

    // Oracle: the excluded ref is byte-identical; only `main` is
    // current anywhere in the report.
    assert_eq!(
        fixture::git_str(&clone, &["rev-parse", "refs/remotes/origin/other"]),
        c1
    );
    for b in report["branches"].as_array().expect("branches") {
        if b["freshness"].as_str() == Some("current") {
            assert_eq!(
                b["name"]["value"].as_str(),
                Some("refs/remotes/origin/main"),
                "only the covered ref is current"
            );
        }
    }
}

/// FETCH-E2E-06: an unreachable remote records `failed`, keeps prior
/// freshness (never `current`), and the scan reports incomplete work.
#[test]
fn fetch06_failed_remote_records_failure_keeps_unknown() {
    let tmp = fixture::scratch_root("fetch06");
    let state = tmp.path().join("state");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");

    let (upstream, c1) = seed_upstream(&root, "upstream");
    let clone = clone_from(&root, &upstream, "clone");
    let missing = root.join("no-such-upstream");
    fixture::git(
        &clone,
        &[
            "remote",
            "set-url",
            "origin",
            missing.to_str().expect("utf8"),
        ],
    );

    let report_path = tmp.path().join("rep.json");
    let out = run(
        &[
            "scan",
            "--all",
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            report_path.to_str().expect("utf8"),
            "--fetch",
        ],
        tmp.path(),
        &state,
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "failed refresh is incomplete work: {}",
        stderr_text(&out)
    );
    let report = load_json(&report_path);

    let refresh = remote(&report, "origin", "fetch");
    assert_eq!(refresh["refresh"]["status"].as_str(), Some("failed"));
    assert!(
        refresh["refresh"]["observed_at"].as_str().is_some(),
        "failure carries observation time"
    );
    for b in report["branches"].as_array().expect("branches") {
        assert_ne!(
            b["freshness"].as_str(),
            Some("current"),
            "failed refresh labels nothing current: {}",
            b["name"]["value"]
        );
    }

    // Oracle: the failed fetch changed nothing on disk.
    assert_eq!(
        fixture::git_str(&clone, &["rev-parse", "refs/remotes/origin/main"]),
        c1
    );
}

/// Read a clone's `origin/main` tracking oid without subprocesses
/// (fast poll loop): loose-ref file first, then `packed-refs`, then a
/// `git rev-parse` fallback for exotic layouts.
fn tracking_oid(clone: &Path) -> Option<String> {
    fn valid_hex(s: &str) -> bool {
        s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }
    let loose = clone
        .join(".git")
        .join("refs")
        .join("remotes")
        .join("origin")
        .join("main");
    if let Ok(text) = std::fs::read_to_string(&loose) {
        let oid = text.trim().to_owned();
        if valid_hex(&oid) {
            return Some(oid);
        }
    }
    if let Ok(packed) = std::fs::read_to_string(clone.join(".git").join("packed-refs")) {
        for line in packed.lines() {
            if let Some(hex) = line.strip_suffix(" refs/remotes/origin/main") {
                if valid_hex(hex) {
                    return Some(hex.to_owned());
                }
            }
        }
    }
    std::panic::catch_unwind(|| fixture::git_str(clone, &["rev-parse", "refs/remotes/origin/main"]))
        .ok()
}

/// FETCH-E2E-07 (Step 15.18, fetch leg): SIGKILL mid-fetch, break every
/// upstream, resume. Families fetched before the kill keep `success`
/// with an UNCHANGED timestamp (completed work is never repeated);
/// families still pending are retried and record `failed` against the
/// broken remotes. Without per-family skip, every row would be failed.
#[test]
fn fetch07_kill_mid_fetch_resume_skips_completed_retries_pending() {
    const FAMILIES: usize = 16;

    let tmp = fixture::scratch_root("fetch07");
    let state = tmp.path().join("state");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");

    let mut families: Vec<(PathBuf, PathBuf, String)> = Vec::with_capacity(FAMILIES);
    for i in 0..FAMILIES {
        let (upstream, _) = seed_upstream(&root, &format!("up-{i:02}"));
        let clone = clone_from(&root, &upstream, &format!("clone-{i:02}"));
        let advanced = fixture::commit_file(&upstream, "advance.txt", "v2\n", "advance main");
        // Gate input: every clone starts behind with a readable
        // tracking ref (loose or packed).
        assert!(
            tracking_oid(&clone).is_some(),
            "fresh clone tracking ref resolves"
        );
        families.push((upstream, clone, advanced));
    }

    let report_path = tmp.path().join("rep.json");
    let report_s = report_path.to_str().expect("utf8").to_string();
    let root_s = root.to_str().expect("utf8").to_string();
    let mut child = cmd(&state, tmp.path())
        .args([
            "scan",
            "--all",
            "--root",
            root_s.as_str(),
            "--report",
            report_s.as_str(),
            "--fetch",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn scan");
    // Drain stderr so no pipe back-pressure can stall the scan; the
    // kill gate reads the clones' tracking refs, not progress lines.
    let child_stderr = child.stderr.take().expect("piped stderr");
    let reader = std::thread::spawn(move || {
        use std::io::BufRead as _;
        let reader = std::io::BufReader::new(child_stderr);
        for line in reader.lines().map_while(Result::ok) {
            std::hint::black_box(line);
        }
    });
    // Kill gate, two phases. Phase 1 (filesystem only): the first
    // updated tracking ref proves the fetch phase is mid-flight.
    // Phase 2 (read-only catalog polls): the first DURABLE success
    // row. Phase 1 alone cannot gate the kill: `git fetch` writes
    // the ref before the scanner's post-fetch audit persists the
    // row. Read-only opens are engine-enforced read-only, never
    // migrate, and WAL readers never block the writer; any
    // transient open/query failure retries.
    let deadline = Instant::now() + Duration::from_secs(180);
    let db = state.join("payload").join("catalog.db");
    let rt_gate = runtime();
    let live_successes = || -> Option<i64> {
        rt_gate.block_on(async {
            let store = TursoStore::open_read_only(&db).await.ok()?;
            let mut rows = store
                .connection()
                .query(
                    "SELECT COUNT(*) FROM remote_refreshes WHERE status = 'success'",
                    (),
                )
                .await
                .ok()?;
            let row = rows.next().await.ok()??;
            let count = match row.get_value(0).ok()? {
                turso::Value::Integer(n) => n,
                _ => return None,
            };
            store.close().await.ok()?;
            Some(count)
        })
    };
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            panic!("scan exited ({status}) before the fetch kill window");
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("no tracking ref advanced within 180s");
        }
        let advanced = families
            .iter()
            .filter(|(_, clone, want)| tracking_oid(clone).as_deref() == Some(want.as_str()))
            .count();
        if advanced >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            panic!("scan exited ({status}) before the durability gate");
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("no durable success row within 180s of the first advanced ref");
        }
        match live_successes() {
            Some(n) if n >= 1 => break,
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    assert!(
        child.try_wait().expect("poll child").is_none(),
        "scan finished before the kill landed; bump FAMILIES"
    );
    child.kill().expect("SIGKILL mid-fetch");
    let status = child.wait().expect("wait");
    assert!(!status.success(), "killed scan must not report success");
    reader.join().expect("stderr reader");

    // Pre-kill success set + scan id from the surviving catalog.
    let rt = runtime();
    let (scan_id, pre_success): (String, Vec<(String, i64)>) = rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        assert!(db.exists(), "catalog survives SIGKILL");
        let store = TursoStore::open(&db).await.expect("reopen after kill");
        let mut rows = store
            .connection()
            .query("SELECT id, state FROM scan_requests", ())
            .await
            .expect("query scans");
        let row = rows.next().await.expect("next").expect("one scan row");
        let id = match row.get_value(0).expect("v0") {
            turso::Value::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        };
        let scan_state = match row.get_value(1).expect("v1") {
            turso::Value::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        };
        assert!(
            scan_state.starts_with("running"),
            "killed scan stays resumable: {scan_state}"
        );
        let mut pre = Vec::new();
        for (store_id, name, status, observed) in refresh_rows(&store).await {
            assert_eq!(name, "origin");
            if status == "success" {
                pre.push((store_id, observed));
            }
        }
        store.close().await.expect("close");
        (id, pre)
    });
    assert!(
        !pre_success.is_empty(),
        "kill gate saw an advanced ref yet no success row is durable"
    );
    assert!(
        pre_success.len() < FAMILIES,
        "all {FAMILIES} families fetched before the kill; bump FAMILIES"
    );

    // Break EVERY upstream (including already-fetched ones): skipped
    // families never touch their remote again, so their rows survive.
    for (upstream, _, _) in &families {
        let broken = upstream.with_extension("broken");
        std::fs::rename(upstream, &broken).expect("break upstream");
    }

    // Resume restores `fetch=true` from the saved request and finishes.
    let out = run(&["resume", scan_id.as_str()], tmp.path(), &state);
    assert_eq!(
        out.status.code(),
        Some(3),
        "resumed scan reports the broken-remotes failures: {}",
        stderr_text(&out)
    );
    let report = load_json(&report_path);
    // The resume ran every phase to the end (exit 3): failed refreshes
    // are unresolved gaps, hence `incomplete`, not a crash.
    assert_eq!(report["scan"]["state"].as_str(), Some("incomplete"));

    // Post-resume: pre-kill successes kept byte-identical (skip, not
    // re-execution); pending families retried into `failed`.
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("reopen");
        let rows = refresh_rows(&store).await;
        store.close().await.expect("close");
        assert_eq!(rows.len(), FAMILIES, "exactly one row per family");
        for (store_id, observed) in &pre_success {
            let row = rows
                .iter()
                .find(|(id, _, _, _)| id == store_id)
                .unwrap_or_else(|| panic!("pre-kill family {store_id} lost its row"));
            assert_eq!(row.2, "success", "skipped family keeps success");
            assert_eq!(
                row.3, *observed,
                "skipped family row is byte-identical (no re-fetch)"
            );
        }
        let failed = rows.iter().filter(|(_, _, s, _)| s == "failed").count();
        assert_eq!(
            failed,
            FAMILIES - pre_success.len(),
            "every pending family retried into failure"
        );
    });
}

/// FETCH-E2E-08: resume-skip never leaks across scans. A second scan
/// re-executes the fetch (one row per family, overwritten in place)
/// and picks up commits that landed after the first scan.
#[test]
fn fetch08_second_scan_refetches_and_picks_up_new_commits() {
    let tmp = fixture::scratch_root("fetch08");
    let state = tmp.path().join("state");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");

    let (upstream, _) = seed_upstream(&root, "upstream");
    let clone = clone_from(&root, &upstream, "clone");
    let c2 = fixture::commit_file(&upstream, "a2.txt", "v2\n", "advance two");

    let root_s = root.to_str().expect("utf8").to_string();
    let rep_a = tmp.path().join("a.json");
    let out_a = run(
        &[
            "scan",
            "--all",
            "--root",
            root_s.as_str(),
            "--report",
            rep_a.to_str().expect("utf8"),
            "--fetch",
        ],
        tmp.path(),
        &state,
    );
    assert!(
        matches!(out_a.status.code(), Some(0) | Some(3)),
        "scan A usable: {}",
        stderr_text(&out_a)
    );
    assert_eq!(
        fixture::git_str(&clone, &["rev-parse", "refs/remotes/origin/main"]),
        c2,
        "scan A fetched"
    );

    // New commit after scan A; scan B shares the state dir (hence the
    // catalog rows) but is a new scan id: skip must not apply.
    let c3 = fixture::commit_file(&upstream, "a3.txt", "v3\n", "advance three");
    let rep_b = tmp.path().join("b.json");
    let out_b = run(
        &[
            "scan",
            "--all",
            "--root",
            root_s.as_str(),
            "--report",
            rep_b.to_str().expect("utf8"),
            "--fetch",
        ],
        tmp.path(),
        &state,
    );
    assert!(
        matches!(out_b.status.code(), Some(0) | Some(3)),
        "scan B usable: {}",
        stderr_text(&out_b)
    );
    let report_b = load_json(&rep_b);
    let refresh = remote(&report_b, "origin", "fetch");
    assert_eq!(refresh["refresh"]["status"].as_str(), Some("success"));
    let tracking = branch(&report_b, "remote_tracking", "refs/remotes/origin/main");
    assert_eq!(tracking["oid"]["hex"].as_str(), Some(c3.as_str()));
    assert_eq!(tracking["freshness"].as_str(), Some("current"));
    assert_eq!(
        fixture::git_str(&clone, &["rev-parse", "refs/remotes/origin/main"]),
        c3,
        "scan B really re-fetched"
    );

    // One row per family: scan B overwrote scan A's row in place.
    let rt = runtime();
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open catalog");
        let rows = refresh_rows(&store).await;
        store.close().await.expect("close");
        assert_eq!(rows.len(), 1, "single family keeps one row: {rows:?}");
        assert_eq!(rows[0].2, "success");
    });
}
