//! CLI acceptance (spec §17: CLI-01..03). End-to-end runs of the built
//! binary in tempdirs with explicit `--root`/`--state-dir` only — never a
//! whole-machine scan. Asserts exit codes, report contents, and catalog
//! state, not implementation details.
//!
//! CLI-01: the six exact commands parse and obey the command table + exit
//! codes. CLI-02: `query --cached` performs no live reads. CLI-03: resume
//! preserves the absolute report destination + options across cwd; completed
//! resume is idempotent; superseded resume is usable.

mod common;

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

use clap::Parser;
use common::fixture;
use repo_scan::cli::{CacheAction, Cli, Command};
use repo_scan::model::{Scope, StatusMode};
use repo_scan::store::Store;
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

const URL: &str = "https://github.com/OWNER/REPO";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Run the binary with `--state-dir <state>` from `cwd`.
fn run(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    ProcCommand::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

fn stdout_line(output: &std::process::Output, key: &str) -> String {
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(&format!("{key}:")) {
            return value.trim().to_string();
        }
    }
    panic!("missing `{key}:` in stdout:\n{text}");
}

fn stdout_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn read_report(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("report is valid JSON")
}

/// Minimal workspace: tempdir + state dir + two cwds + a fixture holding one
/// matching clone. Every scan uses `--root <fixture>`.
struct Env {
    _dir: tempfile::TempDir,
    state: PathBuf,
    cwd_a: PathBuf,
    cwd_b: PathBuf,
    fixture: PathBuf,
    fixture_str: String,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        let cwd_a = dir.path().join("cwd-a");
        let cwd_b = dir.path().join("cwd-b");
        repo_scan::privacy::private_dir_0700(&cwd_a).expect("mkdir");
        repo_scan::privacy::private_dir_0700(&cwd_b).expect("mkdir");
        let fixture = dir.path().join("fixture");
        repo_scan::privacy::private_dir_0700(&fixture).expect("mkdir");
        fixture::normal_clone(&fixture, "repo");
        let fixture_str = fixture.to_str().expect("utf8").to_string();
        Self {
            _dir: dir,
            state,
            cwd_a,
            cwd_b,
            fixture,
            fixture_str,
        }
    }

    fn scan(&self, extra: &[&str], cwd: &Path) -> std::process::Output {
        // Wave6: explicit human keeps the footer lines these tests parse
        // (the redirected default is now the JSONL journal replay).
        let mut args = vec![
            "scan",
            URL,
            "--root",
            self.fixture_str.as_str(),
            "--format",
            "human",
        ];
        args.extend(extra.iter().copied());
        run(&args, cwd, &self.state)
    }
}

// ---------------------------------------------------------------------------
// CLI-01: six exact commands parse and obey the command table + exit codes.
// ---------------------------------------------------------------------------

#[test]
fn cli01_six_exact_commands_parse() {
    // Exactly as spec §3 shows them (SCAN_ID stands in for a minted id).
    let cli = Cli::try_parse_from([
        "repo-scan",
        "scan",
        "https://github.com/OWNER/REPO",
        "--scope",
        "machine",
        "--report",
        "repository-report.json",
    ])
    .expect("scan parses");
    match cli.command {
        Command::Scan(args) => {
            assert_eq!(
                args.targets,
                vec!["https://github.com/OWNER/REPO".to_string()]
            );
            assert!(!args.all);
            assert!(matches!(args.scope, Scope::Machine));
            assert_eq!(args.report, Some(PathBuf::from("repository-report.json")));
            assert!(!args.force_rescan);
            assert!(matches!(args.status, StatusMode::Summary));
        }
        _ => panic!("expected scan"),
    }
    let cli = Cli::try_parse_from([
        "repo-scan",
        "query",
        "https://github.com/OWNER/REPO",
        "--cached",
    ])
    .expect("query parses");
    match cli.command {
        Command::Query(args) => {
            assert_eq!(
                args.target.as_deref(),
                Some("https://github.com/OWNER/REPO")
            );
            assert!(args.cached);
        }
        _ => panic!("expected query"),
    }
    let cli = Cli::try_parse_from(["repo-scan", "resume", "SCAN_ID"]).expect("resume parses");
    match cli.command {
        Command::Resume(args) => assert_eq!(args.scan_id, "SCAN_ID"),
        _ => panic!("expected resume"),
    }
    let cli = Cli::try_parse_from([
        "repo-scan",
        "scan",
        "https://github.com/OWNER/REPO",
        "--scope",
        "machine",
        "--force-rescan",
    ])
    .expect("force scan parses");
    match cli.command {
        Command::Scan(args) => assert!(args.force_rescan),
        _ => panic!("expected scan"),
    }
    let cli = Cli::try_parse_from([
        "repo-scan",
        "cache",
        "invalidate",
        "--root",
        "/private/var/folders",
    ])
    .expect("invalidate parses");
    match cli.command {
        Command::Cache(args) => match args.action {
            CacheAction::Invalidate(args) => {
                assert_eq!(args.root, PathBuf::from("/private/var/folders"));
            }
            _ => panic!("expected invalidate"),
        },
        _ => panic!("expected cache"),
    }
    let cli = Cli::try_parse_from(["repo-scan", "cache", "clear", "--all"]).expect("clear parses");
    match cli.command {
        Command::Cache(args) => match args.action {
            CacheAction::Clear(args) => assert!(args.all),
            _ => panic!("expected clear"),
        },
        _ => panic!("expected cache"),
    }
    // Default status mode is summary; the three modes parse.
    for (flag, expect) in [
        ("metadata", StatusMode::Metadata),
        ("summary", StatusMode::Summary),
        ("full", StatusMode::Full),
    ] {
        let cli = Cli::try_parse_from(["repo-scan", "scan", URL, "--status", flag])
            .expect("status parses");
        match cli.command {
            Command::Scan(args) => assert_eq!(args.status, expect),
            _ => panic!("expected scan"),
        }
    }
}

#[test]
fn cli01_command_table_end_to_end() {
    let env = Env::new();
    // scan: discovers the matching clone and publishes a report (exit 0).
    let out = env.scan(&["--report", "rep.json"], &env.cwd_a);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id = stdout_line(&out, "scan_id");
    assert!(scan_id.starts_with("scan-"), "{scan_id}");
    let report_path = env.cwd_a.join("rep.json");
    assert!(report_path.exists(), "report published");
    let report = read_report(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("1.5.0"));
    assert_eq!(report["tool"]["name"].as_str(), Some("repo-scan"));
    assert_eq!(report["scan"]["id"].as_str(), Some(scan_id.as_str()));
    assert_eq!(report["scan"]["scope"].as_str(), Some("roots"));
    assert_eq!(report["scan"]["state"].as_str(), Some("complete"));
    assert_eq!(report["scan"]["status_mode"].as_str(), Some("summary"));
    assert_eq!(report["scan"]["cached"].as_bool(), Some(false));
    assert_eq!(report["coverage"]["filesystem"].as_str(), Some("complete"));
    assert_eq!(
        report["coverage"]["identity"].as_str(),
        Some("complete_under_policy")
    );
    assert_eq!(report["coverage"]["gaps"].as_u64(), Some(0));
    let repos = report["repositories"].as_array().expect("repositories");
    assert_eq!(repos.len(), 1, "one matching clone");
    assert_eq!(repos[0]["match"].as_str(), Some("confirmed"));
    assert!(
        !report["remotes"].as_array().expect("remotes").is_empty(),
        "effective remotes recorded"
    );
    assert!(
        !report["branches"].as_array().expect("branches").is_empty(),
        "local branches recorded"
    );

    // query --cached: reads state only, says it is cached (exit 0).
    let out = run(&["query", URL, "--cached"], &env.cwd_b, &env.state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(stdout.contains("cached: true"), "{stdout}");
    assert!(stdout.contains("matches: 1"), "{stdout}");

    // resume of a completed scan: idempotent terminal replay (exit 0).
    // Wave6: explicit human keeps the footer lines (the redirected
    // default is now the JSONL journal replay).
    let out = run(
        &["resume", scan_id.as_str(), "--format", "human"],
        &env.cwd_b,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(stdout.contains("replayed"), "{stdout}");
    assert_eq!(stdout_line(&out, "scan_id"), scan_id);

    // cache invalidate: durable, with no completion claim (exit 0).
    let sub = env.fixture.join("repo").to_str().expect("utf8").to_string();
    let out = run(
        &["cache", "invalidate", "--root", sub.as_str()],
        &env.cwd_b,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        stdout_text(&out).contains("not complete"),
        "no completion claim"
    );

    // cache clear --all: removes tool-owned payload, keeps exported reports
    // and the coordination namespace (exit 0).
    let out = run(&["cache", "clear", "--all"], &env.cwd_b, &env.state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        !env.state.join("payload").join("catalog.db").exists(),
        "catalog payload removed"
    );
    assert!(report_path.exists(), "exported report preserved");
    assert!(
        env.state.join("instance.lock").exists(),
        "coordination namespace retained"
    );
    // Clearing already absent state is still success.
    let out = run(&["cache", "clear", "--all"], &env.cwd_b, &env.state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    // And the catalog is gone: the next cached query has no suitable catalog.
    let out = run(&["query", URL, "--cached"], &env.cwd_b, &env.state);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
}

#[test]
fn cli01_exit_codes() {
    let env = Env::new();
    // 0: a complete search with zero matches is still success.
    let empty = env.cwd_a.join("empty");
    repo_scan::privacy::private_dir_0700(&empty).expect("mkdir");
    repo_scan::privacy::private_write_0600(&empty.join("notes.txt"), "no repos here".as_bytes())
        .expect("write");
    let empty_str = empty.to_str().expect("utf8").to_string();
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            empty_str.as_str(),
            "--report",
            "zero.json",
        ],
        &env.cwd_a,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&env.cwd_a.join("zero.json"));
    assert_eq!(report["repositories"].as_array().expect("repos").len(), 0);
    assert_eq!(report["scan"]["state"].as_str(), Some("complete"));

    // 2: invalid arguments and configuration.
    for args in [
        vec!["query", URL],
        vec!["cache", "clear"],
        vec!["scan", "not-a-url", "--root", empty_str.as_str()],
        vec!["resume", "scan-no-such"],
        vec!["scan", URL, "--scope", "roots"],
    ] {
        let out = run(&args, &env.cwd_a, &env.state);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?} stderr: {}",
            stderr_text(&out)
        );
    }
    // 3: cached query with no suitable catalog.
    let fresh = tempfile::tempdir().expect("tempdir");
    let fresh_state = fresh.path().join("state");
    let out = run(&["query", URL, "--cached"], fresh.path(), &fresh_state);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    assert!(
        stdout_text(&out).contains("suitable_catalog: false"),
        "explicit miss"
    );
}

#[test]
fn cli01_force_rescan_mints_fresh_generation() {
    let env = Env::new();
    let out = env.scan(&["--report", "rep.json"], &env.cwd_a);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let gen1 = read_report(&env.cwd_a.join("rep.json"))["scan"]["generation"]
        .as_u64()
        .expect("generation");
    // Ordinary rescan reuses the generation on macOS when live events are active;
    // on Linux (and non-macOS platforms) without live events, it mints a fresh
    // generation so newly added copies are discovered.
    let out = env.scan(&["--report", "rep.json"], &env.cwd_a);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let gen2 = read_report(&env.cwd_a.join("rep.json"))["scan"]["generation"]
        .as_u64()
        .expect("generation");
    #[cfg(target_os = "macos")]
    assert_eq!(gen1, gen2, "catalog information reused");
    #[cfg(not(target_os = "macos"))]
    assert_ne!(gen1, gen2, "fresh generation when events unsupported");
    // Force rescan creates a fresh traversal generation.
    let out = env.scan(&["--report", "rep.json", "--force-rescan"], &env.cwd_a);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let gen3 = read_report(&env.cwd_a.join("rep.json"))["scan"]["generation"]
        .as_u64()
        .expect("generation");
    assert_ne!(gen3, gen1, "fresh generation");
    assert!(
        stderr_text(&out).contains("force rescan"),
        "provisional-findings notice"
    );
}

// ---------------------------------------------------------------------------
// CLI-02: cached query performs no live reads.
// ---------------------------------------------------------------------------

#[test]
fn cli02_query_on_absent_state_reads_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let out = run(&["query", URL, "--cached"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(stdout.contains("cached: true"), "{stdout}");
    assert!(stdout.contains("suitable_catalog: false"), "{stdout}");
    assert!(stdout.contains("no live verification"), "{stdout}");
    assert!(
        !state.join("payload").join("catalog.db").exists(),
        "read-only miss creates no catalog"
    );
}

/// Scan a fixture, then revoke all fixture access (`chmod 000`): the cached
/// query must still succeed purely from state.
#[cfg(unix)]
#[test]
fn cli02_cached_query_survives_fixture_lockdown() {
    use std::os::unix::fs::PermissionsExt;

    /// Restores fixture permissions on drop so the tempdir can be cleaned.
    struct Restore<'a> {
        path: &'a Path,
    }
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.path, std::fs::Permissions::from_mode(0o755));
        }
    }

    let env = Env::new();
    let out = env.scan(&["--report", "rep.json"], &env.cwd_a);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let before = run(&["query", URL, "--cached"], &env.cwd_b, &env.state);
    assert_eq!(
        before.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&before)
    );
    assert!(stdout_text(&before).contains("matches: 1"));

    std::fs::set_permissions(&env.fixture, std::fs::Permissions::from_mode(0o0))
        .expect("chmod 000 fixture");
    let _restore = Restore { path: &env.fixture };
    assert!(
        std::fs::read_dir(&env.fixture).is_err(),
        "fixture is really unreadable"
    );

    let after = run(&["query", URL, "--cached"], &env.cwd_b, &env.state);
    assert_eq!(
        after.status.code(),
        Some(0),
        "cached query needs no live reads; stderr: {}",
        stderr_text(&after)
    );
    let stdout = stdout_text(&after);
    assert!(stdout.contains("cached: true"), "{stdout}");
    assert!(stdout.contains("matches: 1"), "{stdout}");
    assert!(stdout.contains("no live verification"), "{stdout}");
}

// ---------------------------------------------------------------------------
// CLI-03: resume preserves absolute dest + options; idempotent/superseded.
// ---------------------------------------------------------------------------

#[test]
fn cli03_completed_resume_idempotent_across_cwd() {
    let env = Env::new();
    let out = env.scan(&["--report", "rep.json"], &env.cwd_a);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id = stdout_line(&out, "scan_id");
    let report_id = stdout_line(&out, "report_id");
    let report_bytes = std::fs::read(env.cwd_a.join("rep.json")).expect("report");
    // Resume twice from the other cwd: same terminal result, no fresh scan.
    for _ in 0..2 {
        // Wave6: explicit human keeps the footer lines (the redirected
        // default is now the JSONL journal replay).
        let out = run(
            &["resume", scan_id.as_str(), "--format", "human"],
            &env.cwd_b,
            &env.state,
        );
        assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
        let stdout = stdout_text(&out);
        assert!(stdout.contains("replayed"), "{stdout}");
        assert!(stdout.contains("no new scan"), "{stdout}");
        assert_eq!(stdout_line(&out, "scan_id"), scan_id);
        assert_eq!(stdout_line(&out, "report_id"), report_id);
    }
    assert!(
        !env.cwd_b.join("rep.json").exists(),
        "no report written relative to the resume cwd"
    );
    assert_eq!(
        std::fs::read(env.cwd_a.join("rep.json")).expect("report"),
        report_bytes,
        "original report untouched by replay"
    );
}

/// A failed report publication retries against the saved snapshot from any
/// cwd, writing to the original absolute destination without rescanning.
#[test]
fn cli03_failed_publication_retries_to_absolute_dest() {
    let env = Env::new();
    let rodir = env.cwd_a.join("rodir");
    repo_scan::privacy::private_dir_0700(&rodir).expect("mkdir");
    let dest = rodir.join("rep.json");
    let dest_str = dest.to_str().expect("utf8").to_string();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&rodir, std::fs::Permissions::from_mode(0o555))
            .expect("chmod 555");
    }
    // Probe: a privileged user can still write; without a real failure this
    // test cannot set up its precondition.
    if repo_scan::privacy::private_write_0600(&rodir.join(".probe"), b"x").is_ok() {
        let _ = std::fs::remove_file(rodir.join(".probe"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&rodir, std::fs::Permissions::from_mode(0o755))
                .expect("chmod restore");
        }
        eprintln!(
            "cli03_failed_publication: destination dir is writable (privileged user); skipping"
        );
        return;
    }
    let out = env.scan(&["--report", dest_str.as_str()], &env.cwd_a);
    assert_eq!(
        out.status.code(),
        Some(1),
        "publication failure is operational failure; stderr: {}",
        stderr_text(&out)
    );
    let scan_id = stdout_line(&out, "scan_id");
    assert!(!dest.exists(), "nothing published");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&rodir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod restore");
    }
    // Resume from the other cwd: no rescan, original absolute dest honored.
    let out = run(
        &["resume", scan_id.as_str(), "--format", "human"],
        &env.cwd_b,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(stdout.contains("publication retried"), "{stdout}");
    assert!(stdout.contains("no new scan"), "{stdout}");
    assert!(dest.exists(), "absolute destination honored");
    assert!(
        !env.cwd_b.join("rep.json").exists(),
        "resume never consults its own cwd"
    );
    let report = read_report(&dest);
    assert_eq!(report["scan"]["id"].as_str(), Some(scan_id.as_str()));
    assert_eq!(report["scan"]["state"].as_str(), Some("complete"));
}

/// A failed terminal write replays the retained snapshot on resume without
/// starting another scan, then completed resume does not render it twice.
#[test]
fn cli03_failed_terminal_delivery_retries_saved_snapshot() {
    use repo_scan::store::{Store, TursoStore};

    let env = Env::new();
    let initial = env.scan(&[], &env.cwd_a);
    assert_eq!(
        initial.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&initial)
    );
    let scan_id = stdout_line(&initial, "scan_id");
    let report_id = stdout_line(&initial, "report_id");
    // Wave6: the explicit-human lane renders the retained snapshot as
    // stable plain text (render_plain), not the legacy terminal header.
    let initial_stdout = stdout_text(&initial);
    assert!(
        initial_stdout.contains("state=complete"),
        "{initial_stdout}"
    );

    let db = env.state.join("payload").join("catalog.db");
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let store = TursoStore::open(&db).await.expect("open catalog");
        let row = store
            .get_scan(&scan_id)
            .await
            .expect("get scan")
            .expect("scan row");
        let outcome = repo_scan::config::parse_outcome(row.outcome.as_deref().expect("outcome"))
            .expect("decode outcome");
        let failed =
            repo_scan::config::encode_outcome(1, Some(0), &report_id, false, outcome.generation);
        store
            .update_scan_state(
                &scan_id,
                "failed",
                Some(&failed),
                None,
                repo_scan::store::now_ms(),
            )
            .await
            .expect("mark terminal delivery failed");
        store
            .set_snapshot_publication(&report_id, "failed")
            .await
            .expect("mark snapshot delivery failed");
        assert!(
            store
                .get_report_snapshot(&report_id)
                .await
                .expect("get retained snapshot")
                .is_some(),
            "retained snapshot remains available for resume"
        );
        store.close().await.expect("close catalog");
    });

    let resumed = run(
        &["resume", scan_id.as_str(), "--format", "human"],
        &env.cwd_b,
        &env.state,
    );
    assert_eq!(
        resumed.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&resumed)
    );
    let resumed_stdout = stdout_text(&resumed);
    assert!(
        resumed_stdout.contains("repo-scan 0.1.0 report"),
        "{resumed_stdout}"
    );
    assert!(
        resumed_stdout.contains("report retried from saved snapshot; no new scan"),
        "{resumed_stdout}"
    );
    assert_eq!(stdout_line(&resumed, "scan_id"), scan_id);
    assert_eq!(stdout_line(&resumed, "report_id"), report_id);

    let replay = run(
        &["resume", scan_id.as_str(), "--format", "human"],
        &env.cwd_b,
        &env.state,
    );
    assert_eq!(
        replay.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&replay)
    );
    let replay_stdout = stdout_text(&replay);
    assert!(replay_stdout.contains("replayed"), "{replay_stdout}");
    assert!(replay_stdout.contains("no new scan"), "{replay_stdout}");
    assert!(!replay_stdout.contains("repo-scan 0.1.0 report"));
    assert_eq!(stdout_line(&replay, "scan_id"), scan_id);
    assert_eq!(stdout_line(&replay, "report_id"), report_id);
}

/// An unfinished scan keeps its absolute destination and options: resume
/// from another cwd continues there with the saved status mode.
#[cfg(unix)]
#[test]
fn cli03_incomplete_resume_restores_dest_and_options() {
    use std::os::unix::fs::PermissionsExt;

    struct Restore<'a> {
        path: &'a Path,
    }
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.path, std::fs::Permissions::from_mode(0o755));
        }
    }

    let env = Env::new();
    let blocked = env.fixture.join("blocked");
    repo_scan::privacy::private_dir_0700(&blocked).expect("mkdir");
    repo_scan::privacy::private_write_0600(&blocked.join("secret.txt"), b"x").expect("write");
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o0)).expect("chmod 000");
    let _restore = Restore { path: &blocked };
    if std::fs::read_dir(&blocked).is_ok() {
        eprintln!("cli03_incomplete_resume: chmod 000 ineffective (privileged user); skipping");
        return;
    }
    // Relative --report from cwd-a resolves absolutely at request creation.
    let out = env.scan(&["--report", "rep.json", "--status", "full"], &env.cwd_a);
    assert_eq!(
        out.status.code(),
        Some(3),
        "permission gap is usable-but-incomplete; stderr: {}",
        stderr_text(&out)
    );
    let scan_id = stdout_line(&out, "scan_id");
    // Resume from the other cwd: continues (not replays), same id, same
    // absolute destination, same saved status mode.
    let out = run(&["resume", scan_id.as_str()], &env.cwd_b, &env.state);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let stderr = stderr_text(&out);
    assert!(stderr.contains("resuming scan"), "{stderr}");
    assert_eq!(stdout_line(&out, "scan_id"), scan_id);
    assert!(
        !env.cwd_b.join("rep.json").exists(),
        "resume never consults its own cwd"
    );
    let report = read_report(&env.cwd_a.join("rep.json"));
    assert_eq!(report["scan"]["id"].as_str(), Some(scan_id.as_str()));
    assert_eq!(report["scan"]["status_mode"].as_str(), Some("full"));
    assert_eq!(report["scan"]["state"].as_str(), Some("incomplete"));
    assert!(report["coverage"]["gaps"].as_u64().expect("gaps") > 0);
}

/// A superseded request returns a usable incomplete result naming its
/// successor, without switching targets or destinations.
#[test]
fn cli03_superseded_resume_names_successor() {
    use repo_scan::store::{NewScan, Store, TursoStore};

    let env = Env::new();
    // First scan creates the catalog.
    let out = env.scan(&["--report", "rep.json"], &env.cwd_a);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    // Plant a stale `running` row for the same canonical target + scope.
    let canonical = repo_scan::identity::normalize_github_url(URL).expect("canonical");
    let stale_id = "scan-stale-cli03";
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let store = TursoStore::open(&env.state.join("payload").join("catalog.db"))
            .await
            .expect("open catalog");
        let inserted = store
            .create_scan_request(
                &NewScan {
                    id: stale_id,
                    url_raw: URL.as_bytes(),
                    url_canonical: Some(canonical.as_bytes()),
                    scope: "roots",
                    status_mode: "summary",
                    report_dest: None,
                    targets_json: None,
                    format: None,
                    all_targets: None,
                },
                repo_scan::store::now_ms(),
            )
            .await
            .expect("insert stale scan");
        assert!(inserted);
        store.close().await.expect("close");
    });
    // A new scan for the same target supersedes the stale row.
    let out = env.scan(&["--report", "rep.json"], &env.cwd_a);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let successor = stdout_line(&out, "scan_id");
    assert_ne!(successor, stale_id);
    // Resume of the superseded request: exit 3 with a usable result.
    let out = run(
        &["resume", stale_id, "--format", "human"],
        &env.cwd_b,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(stdout.contains("superseded"), "{stdout}");
    assert!(stdout.contains(&successor), "{stdout}");
    assert!(stdout.contains(URL), "original target preserved");
    assert!(
        stdout.contains("no target or destination switch"),
        "{stdout}"
    );
}

// ---------------------------------------------------------------------------
// Step 6 execution: multi-target union, owner/name, and --all from one pass.
// ---------------------------------------------------------------------------

const URL_B: &str = "https://github.com/OTHER/REPO2";

/// Second matching clone with a different origin, beside Env's default repo.
fn add_second_clone(env: &Env) {
    let other = fixture::normal_clone(&env.fixture, "repo-b");
    fixture::git(&other, &["remote", "set-url", "origin", URL_B]);
}

fn confirmed_repos(report: &serde_json::Value) -> Vec<&serde_json::Value> {
    report["repositories"]
        .as_array()
        .expect("repositories array")
        .iter()
        .filter(|r| r["match"] == "confirmed")
        .collect()
}

#[test]
fn step6_multi_target_union_single_pass() {
    let env = Env::new();
    add_second_clone(&env);
    let out = run(
        &[
            "scan",
            URL,
            URL_B,
            "--root",
            env.fixture_str.as_str(),
            "--report",
            "rep.json",
        ],
        &env.cwd_a,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&env.cwd_a.join("rep.json"));
    assert_eq!(report["schema_version"], "1.5.0");
    // Full target set in request order with per-target match counts.
    let targets = report["scan"]["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0]["raw"], URL);
    assert_eq!(targets[0]["canonical"], "https://github.com/owner/repo");
    assert_eq!(targets[1]["raw"], URL_B);
    assert_eq!(targets[1]["canonical"], "https://github.com/other/repo2");
    assert!(targets[0]["matched_repositories"].as_u64().unwrap() >= 1);
    assert!(targets[1]["matched_repositories"].as_u64().unwrap() >= 1);
    // Legacy primary-target fields repeat the first target.
    assert_eq!(report["scan"]["target_url"], URL);
    // One report, one generation: both repos confirmed from one pass.
    assert_eq!(confirmed_repos(&report).len(), 2);
    assert_eq!(report["scan"]["state"], "complete");
}

#[test]
fn step6_owner_name_target_matches_url() {
    let env = Env::new();
    let out = run(
        &[
            "scan",
            "OWNER/REPO",
            "--root",
            env.fixture_str.as_str(),
            "--report",
            "rep.json",
        ],
        &env.cwd_a,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&env.cwd_a.join("rep.json"));
    assert_eq!(report["scan"]["target_url"], "OWNER/REPO");
    assert_eq!(
        report["scan"]["canonical_url"],
        "https://github.com/owner/repo"
    );
    let targets = report["scan"]["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["raw"], "OWNER/REPO");
    assert_eq!(targets[0]["canonical"], "https://github.com/owner/repo");
    assert_eq!(confirmed_repos(&report).len(), 1);
}

#[test]
fn step6_all_finds_without_target_filter() {
    let env = Env::new();
    add_second_clone(&env);
    let out = run(
        &[
            "scan",
            "--all",
            "--root",
            env.fixture_str.as_str(),
            "--report",
            "rep.json",
        ],
        &env.cwd_a,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&env.cwd_a.join("rep.json"));
    assert_eq!(report["scan"]["target_url"], "--all");
    assert!(report["scan"]["canonical_url"].is_null());
    assert_eq!(
        report["scan"]["targets"]
            .as_array()
            .expect("targets array")
            .len(),
        0
    );
    // No filter: every discovered store is in scope and confirmed.
    assert_eq!(confirmed_repos(&report).len(), 2);
    assert_eq!(report["scan"]["state"], "complete");
}

// ---------------------------------------------------------------------------
// Step 15 case 5: distinct explicit root sets never share a generation.
// ---------------------------------------------------------------------------

/// Distinct root sets get distinct generations with recorded scope keys;
/// re-scanning a root set lands on its own key — never a foreign one. All
/// three scans share one state dir, so any policy-name-only reuse would
/// collapse them onto generation 1.
#[test]
fn case5_distinct_root_sets_never_share_generations() {
    use repo_scan::store::{Store, TursoStore};
    use repo_scan::walk::roots::{generation_scope_key, PlannedRoot, RootPriority};

    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let r1 = dir.path().join("r1");
    let r2 = dir.path().join("r2");
    repo_scan::privacy::private_dir_0700(&r1).expect("mkdir");
    repo_scan::privacy::private_dir_0700(&r2).expect("mkdir");
    fixture::normal_clone(&r1, "repo");
    fixture::normal_clone(&r2, "repo");

    let scan = |root: &Path, rep: &str| {
        let out = run(
            &[
                "scan",
                URL,
                "--root",
                root.to_str().expect("utf8"),
                "--report",
                rep,
            ],
            &cwd,
            &state,
        );
        assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
        read_report(&cwd.join(rep))
    };
    let rep_a = scan(&r1, "a.json");
    let rep_b = scan(&r2, "b.json");
    let rep_a2 = scan(&r1, "a2.json");
    let ga = rep_a["scan"]["generation"].as_u64().expect("gen a");
    let gb = rep_b["scan"]["generation"].as_u64().expect("gen b");
    let ga2 = rep_a2["scan"]["generation"].as_u64().expect("gen a2");
    assert_ne!(ga, gb, "incompatible root sets must not share a generation");

    // Expected keys built independently through the shipped builder over
    // the same explicit-root shape production plans.
    let keyed = |root: &Path| {
        generation_scope_key(
            "roots",
            &[PlannedRoot {
                path: root.to_path_buf(),
                priority: RootPriority::Early,
                namespace: String::from("explicit"),
                volume: None,
            }],
        )
    };
    let k1 = keyed(&r1);
    let k2 = keyed(&r2);
    assert_ne!(k1, k2, "builder distinguishes the sets");

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        for (id, want) in [(ga, &k1), (gb, &k2), (ga2, &k1)] {
            let row = store.get_generation(id).await.expect("get").expect("row");
            assert_eq!(
                row.scope_key.as_deref(),
                Some(want.as_str()),
                "generation {id} carries its requesting key"
            );
        }
        store.close().await.expect("close");
    });
}

/// Goal Step 12 (D4): a completed scan journals its lifecycle —
/// `scan_started` … `inventory_ready` … exactly one terminal event — with
/// contiguous 1-based seqs and non-decreasing committed catalog revs.
#[test]
fn journal_lifecycle_events_span_started_ready_terminal() {
    use repo_scan::store::{Store, TursoStore};

    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            "rep.json",
            "--format",
            "human",
        ],
        &cwd,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id = stdout_line(&out, "scan_id");
    let generation: u64 = stdout_line(&out, "generation").parse().expect("gen u64");

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 100)
            .await
            .expect("read");
        assert!(
            rows.len() >= 3,
            "lifecycle journals >= 3 rows, got {}",
            rows.len()
        );
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row.seq, (i + 1) as u64, "seqs contiguous from 1");
            assert_eq!(row.scan_id, scan_id, "rows belong to this scan");
        }
        assert_eq!(rows[0].event_type, "scan_started");
        assert_eq!(rows[0].op, "add");
        let started: serde_json::Value =
            serde_json::from_slice(&rows[0].records).expect("started json");
        assert_eq!(
            started["scan_id"],
            serde_json::Value::String(scan_id.clone())
        );
        assert!(
            started["scope"]["scope_key"].is_string(),
            "started carries scope key"
        );
        assert_eq!(
            started["targets"][0]["raw"],
            serde_json::Value::String(URL.to_string())
        );
        assert!(
            started["resume_cmd"].is_string(),
            "started carries resume cmd"
        );

        let ready_pos = rows
            .iter()
            .position(|r| r.event_type == "inventory_ready")
            .expect("inventory_ready journaled");
        assert_eq!(rows[ready_pos].op, "add");
        let ready: serde_json::Value =
            serde_json::from_slice(&rows[ready_pos].records).expect("ready json");
        assert_eq!(ready["generation"], serde_json::Value::from(generation));
        assert_eq!(
            ready["verdict"],
            serde_json::Value::String("complete".to_string())
        );

        let terminals: Vec<&str> = rows
            .iter()
            .map(|r| r.event_type.as_str())
            .filter(|t| {
                matches!(
                    *t,
                    "scan_completed" | "scan_incomplete" | "scan_interrupted" | "scan_failed"
                )
            })
            .collect();
        assert_eq!(
            terminals,
            vec!["scan_completed"],
            "exactly one terminal event"
        );
        assert_eq!(rows.last().expect("last").event_type, "scan_completed");

        let mut prev_rev = 0u64;
        for row in &rows {
            assert!(row.catalog_rev >= prev_rev, "revs non-decreasing");
            prev_rev = row.catalog_rev;
        }
        store.close().await.expect("close");
    });
}

/// Goal Step 12 (D4): `query --scan` replays the journaled lifecycle as
/// JSONL envelopes; `--after` resumes after a cursor; unknown scans exit 2.
#[test]
fn query_scan_replays_journaled_lifecycle_as_jsonl() {
    use repo_scan::scan_events::ScanCursor as Cursor;
    use repo_scan::store::{NewScanEvent, Store, TursoStore};

    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            "rep.json",
            "--format",
            "human",
        ],
        &cwd,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id = stdout_line(&out, "scan_id");

    let replay = run(
        &["query", "--scan", &scan_id, "--format", "jsonl"],
        &cwd,
        &state,
    );
    assert_eq!(
        replay.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&replay)
    );
    let lines: Vec<serde_json::Value> = stdout_text(&replay)
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
        .collect();
    assert!(
        lines.len() >= 3,
        "replay covers the lifecycle, got {}",
        lines.len()
    );
    for (i, env) in lines.iter().enumerate() {
        assert_eq!(
            env["schema_version"],
            serde_json::Value::String("1.0.0".to_string())
        );
        assert_eq!(env["scan_id"], serde_json::Value::String(scan_id.clone()));
        assert_eq!(env["seq"], serde_json::Value::from((i + 1) as u64));
    }
    assert_eq!(
        lines[0]["type"],
        serde_json::Value::String("scan_started".to_string())
    );
    assert_eq!(lines[0]["op"], serde_json::Value::String("add".to_string()));
    assert!(
        lines.iter().any(|e| e["type"] == "inventory_ready"),
        "replay includes inventory_ready"
    );
    let last = lines.last().expect("last");
    assert_eq!(
        last["type"],
        serde_json::Value::String("scan_completed".to_string())
    );

    // A post-terminal row is outside the completed event stream. Readers
    // stop at the first terminal even if a malformed/legacy journal has a
    // later row.
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let terminal_seq = lines.last().expect("terminal")["seq"]
            .as_u64()
            .expect("terminal seq");
        let rev = store.next_revision().await.expect("revision");
        assert!(store
            .append_scan_event(&NewScanEvent {
                scan_id: &scan_id,
                seq: terminal_seq + 1,
                catalog_rev: rev,
                event_offset: 0,
                event_type: "location_updated",
                op: "replace",
                reset: false,
                records: b"{}",
            })
            .await
            .expect("append post-terminal row"));
        store.close().await.expect("close");
    });
    let after_terminal = run(
        &["query", "--scan", &scan_id, "--format", "jsonl"],
        &cwd,
        &state,
    );
    assert_eq!(after_terminal.status.code(), Some(0));
    let after_terminal_lines: Vec<serde_json::Value> = stdout_text(&after_terminal)
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
        .collect();
    assert_eq!(after_terminal_lines.len(), lines.len());
    assert_eq!(
        after_terminal_lines.last().expect("terminal")["type"],
        "scan_completed"
    );

    // `--after` resumes strictly after the cursor: from the first envelope,
    // replay restarts at seq 2 and still ends at the terminal event.
    let cursor = Cursor::for_scan(
        &scan_id,
        lines[0]["seq"].as_u64().expect("seq u64"),
        lines[0]["catalog_rev"].as_u64().expect("rev u64"),
        lines[0]["event_offset"].as_u64().expect("off u64"),
    )
    .encode();
    let resumed = run(
        &[
            "query", "--scan", &scan_id, "--follow", "--format", "jsonl", "--after", &cursor,
        ],
        &cwd,
        &state,
    );
    assert_eq!(
        resumed.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&resumed)
    );
    let tail: Vec<serde_json::Value> = stdout_text(&resumed)
        .lines()
        .map(|l| serde_json::from_str(l).expect("tail line is valid JSON"))
        .collect();
    assert_eq!(tail.len(), lines.len() - 1, "one row skipped by the cursor");
    assert_eq!(tail[0]["seq"], serde_json::Value::from(2u64));
    assert_eq!(
        tail.last().expect("tail last")["type"],
        serde_json::Value::String("scan_completed".to_string())
    );

    // A cursor on the terminal event closes replay. The malformed row we
    // appended after terminal above must never be treated as a live tail.
    let terminal = lines.last().expect("terminal");
    let terminal_cursor = Cursor::for_scan(
        &scan_id,
        terminal["seq"].as_u64().expect("terminal seq"),
        terminal["catalog_rev"].as_u64().expect("terminal rev"),
        terminal["event_offset"].as_u64().expect("terminal offset"),
    )
    .encode();
    let terminal_tail = run(
        &[
            "query",
            "--scan",
            &scan_id,
            "--follow",
            "--format",
            "jsonl",
            "--after",
            &terminal_cursor,
        ],
        &cwd,
        &state,
    );
    assert_eq!(
        terminal_tail.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&terminal_tail)
    );
    assert!(stdout_text(&terminal_tail).is_empty());

    // A validly encoded seq beyond SQLite's signed range cannot exist in
    // this journal. Treat it as an expired cursor and explicitly reset.
    let overflow = Cursor::for_scan(&scan_id, u64::MAX, u64::MAX, u64::MAX).encode();
    let reset = run(
        &[
            "query", "--scan", &scan_id, "--follow", "--format", "jsonl", "--after", &overflow,
        ],
        &cwd,
        &state,
    );
    assert_eq!(
        reset.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&reset)
    );
    let reset_lines: Vec<serde_json::Value> = stdout_text(&reset)
        .lines()
        .map(|l| serde_json::from_str(l).expect("reset line is valid JSON"))
        .collect();
    assert_eq!(reset_lines[0]["reset"], true);
    assert_eq!(reset_lines[0]["type"], "scan_started");

    // Unknown scan IDs follow the resume convention: exit 2, clear error.
    let missing = run(
        &["query", "--scan", "scan-no-such", "--format", "jsonl"],
        &cwd,
        &state,
    );
    assert_eq!(
        missing.status.code(),
        Some(2),
        "stderr: {}",
        stderr_text(&missing)
    );
}

/// `--follow` race: the scan writer commits the terminal row state and the
/// terminal journal event as two transactions (row first). A follower that
/// polls between them must keep draining for the event instead of exiting
/// at the tip. Reproduced deterministically by deleting the committed
/// terminal event (row stays `complete`) and re-inserting it while the
/// follower polls: the event must still be replayed.
#[test]
fn query_scan_follow_drains_terminal_event_committed_after_row_state() {
    use repo_scan::store::{Store, TursoStore};
    use std::io::{BufRead, BufReader, Read as _};

    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            "rep.json",
            // Wave6: explicit human keeps the footer lines (the redirected
            // default is now the JSONL journal replay).
            "--format",
            "human",
        ],
        &cwd,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id = stdout_line(&out, "scan_id");

    // Lift the committed terminal event out of the journal; the scan row
    // stays `complete`, so the follower observes the terminal state one
    // commit ahead of the terminal event — the writer's real order.
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    let terminal_row: Vec<turso::Value> = rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let mut rows = store
            .connection()
            .query(
                "SELECT seq, catalog_rev, event_offset, event_type, op, reset, records \
                 FROM scan_events WHERE scan_id = ?1 ORDER BY seq DESC LIMIT 1",
                vec![turso::Value::Text(scan_id.clone())],
            )
            .await
            .expect("query");
        let row = rows.next().await.expect("next").expect("terminal row");
        let mut values = Vec::new();
        for i in 0..7 {
            values.push(row.get_value(i).expect("column"));
        }
        let seq = match &values[0] {
            turso::Value::Integer(n) => *n,
            other => panic!("seq integer, got {other:?}"),
        };
        assert!(
            matches!(&values[3], turso::Value::Text(t) if t.as_str() == "scan_completed"),
            "last journaled event is the terminal one: {:?}",
            values[3]
        );
        store
            .connection()
            .execute(
                "DELETE FROM scan_events WHERE scan_id = ?1 AND seq = ?2",
                vec![
                    turso::Value::Text(scan_id.clone()),
                    turso::Value::Integer(seq),
                ],
            )
            .await
            .expect("delete terminal event");
        store.close().await.expect("close");
        values
    });

    // Follow with piped stdout; read until the follower passes
    // `inventory_ready`, which proves its initial replay finished and the
    // follow loop is polling.
    let mut child = ProcCommand::new(binary())
        .args([
            "--state-dir",
            state.to_str().expect("utf8"),
            "query",
            "--scan",
            scan_id.as_str(),
            "--follow",
            "--format",
            "jsonl",
        ])
        .current_dir(&cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn follower");
    let child_stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(child_stdout);
    let mut followed = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read follower line");
        assert!(n > 0, "follower exited before inventory_ready: {followed}");
        let envelope: serde_json::Value = serde_json::from_str(&line).expect("jsonl");
        let is_inventory = envelope["type"] == "inventory_ready";
        followed.push_str(&line);
        if is_inventory {
            break;
        }
    }

    // The follower is now polling a terminal scan row with the terminal
    // event missing. Commit the event mid-window; the bounded grace drain
    // must pick it up instead of stopping at the tip.
    std::thread::sleep(std::time::Duration::from_millis(500));
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("reopen");
        let mut params = vec![turso::Value::Text(scan_id.clone())];
        params.extend(terminal_row);
        store
            .connection()
            .execute(
                "INSERT INTO scan_events \
                 (scan_id, seq, catalog_rev, event_offset, event_type, op, reset, records) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params,
            )
            .await
            .expect("re-insert terminal event");
        store.close().await.expect("close");
    });

    let mut rest = String::new();
    reader.read_to_string(&mut rest).expect("read to EOF");
    followed.push_str(&rest);
    let status = child.wait().expect("wait");
    assert_eq!(
        status.code(),
        Some(0),
        "follower exits 0 at the terminal event"
    );
    let last = followed
        .lines()
        .last()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("jsonl"))
        .expect("follower emitted events");
    assert_eq!(
        last["type"],
        serde_json::Value::String("scan_completed".to_string()),
        "terminal event committed after the row state is still replayed: {followed}"
    );
}

/// Goal Step 12 (D4): a discovery scan journals one `repository_found`
/// per local store and one `location_found` per checkout — each exactly
/// once, each before `inventory_ready`, each store before its checkouts,
/// all with `analysis: "pending"`.
#[test]
fn found_events_cover_each_store_and_checkout_once() {
    use repo_scan::store::{Store, TursoStore};
    use std::collections::{HashMap, HashSet};

    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo-a");
    fixture::normal_clone(&root, "repo-b");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            "rep.json",
            "--format",
            "human",
        ],
        &cwd,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id = stdout_line(&out, "scan_id");

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 1_000)
            .await
            .expect("read");
        let records = |seq: u64| -> serde_json::Value {
            let row = rows.iter().find(|r| r.seq == seq).expect("row by seq");
            serde_json::from_slice(&row.records).expect("records json")
        };
        let repos: Vec<u64> = rows
            .iter()
            .filter(|r| r.event_type == "repository_found")
            .map(|r| r.seq)
            .collect();
        let locs: Vec<u64> = rows
            .iter()
            .filter(|r| r.event_type == "location_found")
            .map(|r| r.seq)
            .collect();
        assert_eq!(repos.len(), 2, "one repository_found per store");
        assert_eq!(locs.len(), 2, "one location_found per checkout");
        let ready = rows
            .iter()
            .find(|r| r.event_type == "inventory_ready")
            .expect("inventory_ready")
            .seq;
        for seq in repos.iter().chain(locs.iter()) {
            assert!(*seq < ready, "found events precede inventory_ready");
        }
        // Each store id exactly once; each checkout id exactly once, and
        // each store's event precedes its checkouts' events.
        let mut store_seq: HashMap<String, u64> = HashMap::new();
        for seq in &repos {
            let v = records(*seq);
            assert_eq!(
                v["analysis"],
                serde_json::Value::String("pending".to_string())
            );
            let id = v["store_id"].as_str().expect("store id").to_string();
            assert!(store_seq.insert(id, *seq).is_none(), "store emitted once");
        }
        let mut seen_checkouts: HashSet<String> = HashSet::new();
        for seq in &locs {
            let v = records(*seq);
            assert_eq!(
                v["analysis"],
                serde_json::Value::String("pending".to_string())
            );
            assert!(v["identity_state"].is_string(), "identity state explicit");
            let co = v["checkout_id"].as_str().expect("checkout id").to_string();
            let st = v["store_id"].as_str().expect("store id").to_string();
            assert!(seen_checkouts.insert(co), "checkout emitted once");
            let repo_seq = store_seq.get(&st).expect("checkout names an emitted store");
            assert!(*repo_seq < *seq, "store before its checkouts");
        }
        // Seqs stay contiguous across the interleaved stream.
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row.seq, (i + 1) as u64, "contiguous 1-based seqs");
        }
        store.close().await.expect("close");
    });
}

#[test]
fn github_groups_link_stores_to_canonical_identities() {
    use repo_scan::store::{Store, TursoStore};
    use std::collections::{HashMap, HashSet};

    // Three independent clones: scp + mixed-case spelling, plain https,
    // and https origin plus a distinct upstream (fork-style). Independent
    // reference is the installed git CLI (`git remote -v` per clone);
    // expected group ids are literal GitHub identities, never normalizer
    // output.
    const GROUP_MAIN: &str = "github.com/acme/widget";
    const GROUP_UP: &str = "github.com/other/widget";

    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let clone_a = fixture::normal_clone(&root, "clone-a");
    fixture::git(
        &clone_a,
        &[
            "remote",
            "set-url",
            "origin",
            "git@github.com:ACME/Widget.git",
        ],
    );
    let clone_b = fixture::normal_clone(&root, "clone-b");
    fixture::git(
        &clone_b,
        &[
            "remote",
            "set-url",
            "origin",
            "https://github.com/acme/widget",
        ],
    );
    let clone_c = fixture::normal_clone(&root, "clone-c");
    fixture::git(
        &clone_c,
        &[
            "remote",
            "set-url",
            "origin",
            "https://github.com/acme/widget",
        ],
    );
    fixture::git(
        &clone_c,
        &[
            "remote",
            "add",
            "upstream",
            "https://github.com/other/widget",
        ],
    );

    // (name, role) pairs straight from git per clone dir name.
    let mut git_pairs: HashMap<String, HashSet<(String, String)>> = HashMap::new();
    for (name, path) in [
        ("clone-a", &clone_a),
        ("clone-b", &clone_b),
        ("clone-c", &clone_c),
    ] {
        let mut pairs = HashSet::new();
        for line in fixture::git_str(path, &["remote", "-v"]).lines() {
            let mut cols = line.split_whitespace();
            let (Some(n), _, Some(direction)) = (cols.next(), cols.next(), cols.next()) else {
                panic!("unexpected git remote -v line: {line}");
            };
            let role = direction.trim_matches(|c| c == '(' || c == ')').to_string();
            assert!(
                role == "fetch" || role == "push",
                "git direction is fetch/push: {line}"
            );
            pairs.insert((n.to_string(), role));
        }
        assert!(!pairs.is_empty(), "{name} has remotes");
        git_pairs.insert(name.to_string(), pairs);
    }

    let out = run(
        &[
            "scan",
            "--all",
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            "rep.json",
            "--format",
            "human",
        ],
        &cwd,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id = stdout_line(&out, "scan_id");

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");

        // Exactly two groups: both spellings of one identity merge, the
        // fork-style upstream stays separate.
        let groups = store.list_github_groups().await.expect("groups");
        let ids: Vec<&str> = groups.iter().map(|g| g.id.as_str()).collect();
        assert_eq!(ids, vec![GROUP_MAIN, GROUP_UP]);
        for g in &groups {
            let (host, account, repo) = match g.id.as_str() {
                GROUP_MAIN => ("github.com", "acme", "widget"),
                GROUP_UP => ("github.com", "other", "widget"),
                other => panic!("unexpected group {other}"),
            };
            assert_eq!(g.host, host);
            assert_eq!(g.account, account);
            assert_eq!(g.repo, repo);
            assert!(g.observed_at_ms > 0, "observation time kept");
        }

        // Event IDs are opaque projections of the owner-local catalog IDs.
        // Build the expected projection from each fixture's common dir so
        // the stream can be joined without exposing path encodings.
        let event_store_id = |path: &Path| {
            let common = std::fs::canonicalize(path.join(".git")).expect("canonical .git");
            let catalog_id = format!(
                "git:{}",
                repo_scan::config::encode_hex(&repo_scan::config::path_as_bytes(&common))
            );
            main_under_test::test_event_opaque_id(&catalog_id)
        };
        let fixture_names = HashMap::from([
            (event_store_id(&clone_a), String::from("clone-a")),
            (event_store_id(&clone_b), String::from("clone-b")),
            (event_store_id(&clone_c), String::from("clone-c")),
        ]);
        let rows = store
            .read_scan_events(&scan_id, 0, 1_000)
            .await
            .expect("read");
        let mut store_clone: HashMap<String, String> = HashMap::new();
        let mut store_groups: HashMap<String, Vec<String>> = HashMap::new();
        for row in &rows {
            let v: serde_json::Value = serde_json::from_slice(&row.records).expect("json");
            if row.event_type == "location_found" {
                let store_id = v["store_id"].as_str().expect("store id").to_string();
                let name = fixture_names
                    .get(&store_id)
                    .expect("fixture store id")
                    .clone();
                store_clone.insert(store_id, name);
            } else if row.event_type == "repository_found" {
                let found: Vec<String> = v["github_groups"]
                    .as_array()
                    .expect("github_groups array")
                    .iter()
                    .map(|g| g.as_str().expect("group id").to_string())
                    .collect();
                store_groups.insert(v["store_id"].as_str().expect("store").to_string(), found);
            }
        }
        assert_eq!(store_clone.len(), 3, "three stores located");
        assert_eq!(store_groups.len(), 3, "three stores reported");

        // Per-(store, remote, role) member edges match `git remote -v`
        // exactly; each edge sits under its literal group id.
        let main_members = store.list_group_members(GROUP_MAIN).await.expect("members");
        let up_members = store.list_group_members(GROUP_UP).await.expect("members");
        let mut main_by_store: HashMap<String, HashSet<(String, String)>> = HashMap::new();
        for m in &main_members {
            assert!(m.observed_at_ms > 0, "member observation time kept");
            main_by_store
                .entry(main_under_test::test_event_opaque_id(&m.instance_id))
                .or_default()
                .insert((
                    String::from_utf8_lossy(&m.remote_name).into_owned(),
                    m.role.clone(),
                ));
        }
        assert_eq!(main_by_store.len(), 3, "three stores share one group");
        for (instance, pairs) in &main_by_store {
            let clone = store_clone.get(instance).expect("member of a known store");
            let expect: HashSet<(String, String)> = git_pairs[clone.as_str()]
                .iter()
                .filter(|(n, _)| n == "origin")
                .cloned()
                .collect();
            assert_eq!(pairs, &expect, "{clone} origin edges match git");
        }
        assert_eq!(up_members.len(), 2, "upstream edges: fetch + push");
        let up_store = up_members[0].instance_id.clone();
        let up_event_store = main_under_test::test_event_opaque_id(&up_store);
        assert_eq!(
            store_clone.get(&up_event_store).map(String::as_str),
            Some("clone-c")
        );
        assert!(up_members
            .iter()
            .all(|m| main_under_test::test_event_opaque_id(&m.instance_id) == up_event_store));
        let up_pairs: HashSet<(String, String)> = up_members
            .iter()
            .map(|m| {
                (
                    String::from_utf8_lossy(&m.remote_name).into_owned(),
                    m.role.clone(),
                )
            })
            .collect();
        let expect_up: HashSet<(String, String)> = git_pairs["clone-c"]
            .iter()
            .filter(|(n, _)| n == "upstream")
            .cloned()
            .collect();
        assert_eq!(up_pairs, expect_up, "clone-c upstream edges match git");
        assert!(
            main_by_store.contains_key(&up_event_store),
            "one store belongs to both groups"
        );
        let both = store.groups_for_instance(&up_store).await.expect("groups");
        let both_ids: HashSet<&str> = both.iter().map(|m| m.group_id.as_str()).collect();
        assert_eq!(both_ids, HashSet::from([GROUP_MAIN, GROUP_UP]));

        // `repository_found.github_groups` names the same literal ids.
        for (instance, found) in &store_groups {
            let clone = store_clone.get(instance).expect("store located");
            let mut expect = vec![GROUP_MAIN.to_string()];
            if clone == "clone-c" {
                expect.push(GROUP_UP.to_string());
                expect.sort();
            }
            assert_eq!(found, &expect, "{clone} event groups");
        }
        store.close().await.expect("close");
    });
}

#[test]
fn location_updated_marks_status_completion() {
    use repo_scan::store::{Store, TursoStore};

    // One dirty checkout (staged + unstaged + collapsed untracked, proven
    // by STATUS-01). Expected counts come from `git status --porcelain=v1`
    // parsed here, never from the scanner's own rows.
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let layout = fixture::dirty_variants(&root, "dirty");
    let (mut staged, mut unstaged, mut untracked) = (0u64, 0u64, 0u64);
    // Raw bytes, not git_str: trimming would eat the first line's leading
    // space and miscount unstaged as staged.
    let porcelain = fixture::git(&layout.repo, &["status", "--porcelain=v1"]);
    for line in String::from_utf8_lossy(&porcelain).lines() {
        let xy = line.as_bytes();
        assert!(xy.len() >= 3, "porcelain line: {line}");
        match (xy[0], xy[1]) {
            (b'?', b'?') => untracked += 1,
            (x, y) => {
                if x != b' ' {
                    staged += 1;
                }
                if y != b' ' {
                    unstaged += 1;
                }
            }
        }
    }
    assert_eq!((staged, unstaged, untracked), (1, 1, 3), "fixture is dirty");

    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root.to_str().expect("utf8"),
            "--status",
            "summary",
            "--report",
            "rep.json",
            "--format",
            "human",
        ],
        &cwd,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id = stdout_line(&out, "scan_id");

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 1_000)
            .await
            .expect("read");
        let updated: Vec<_> = rows
            .iter()
            .filter(|r| r.event_type == "location_updated")
            .collect();
        assert_eq!(updated.len(), 1, "one update per completed status");
        let row = updated[0];
        assert_eq!(row.op, "replace", "D4 op for location_updated");
        let v: serde_json::Value = serde_json::from_slice(&row.records).expect("json");
        assert_eq!(v["mode"].as_str(), Some("summary"));
        assert_eq!(v["status_state"].as_str(), Some("complete"));
        assert_eq!(v["staged"].as_u64(), Some(staged), "staged matches git");
        assert_eq!(
            v["unstaged"].as_u64(),
            Some(unstaged),
            "unstaged matches git"
        );
        assert_eq!(
            v["untracked"].as_u64(),
            Some(untracked),
            "untracked matches git"
        );
        assert!(v["rev"].as_u64().is_some(), "observation rev carried");
        // The update names the found checkout/store and lands after its
        // location_found.
        let found = rows
            .iter()
            .find(|r| r.event_type == "location_found")
            .expect("location_found");
        let f: serde_json::Value = serde_json::from_slice(&found.records).expect("json");
        assert_eq!(v["checkout_id"], f["checkout_id"]);
        assert_eq!(v["store_id"], f["store_id"]);
        assert!(row.seq > found.seq, "update follows its found event");
        store.close().await.expect("close");
    });
}

/// A completion-recorded coverage gap (chmod-000 directory) is journaled
/// as an `error` event whose payload joins back to the open `errors` row.
/// The event carries id/category/detail only; attempts and open state live
/// on the catalog row, not the event.
#[test]
fn error_events_journal_completion_gaps() {
    use repo_scan::store::{Store, TursoStore};
    use std::os::unix::fs::PermissionsExt;

    struct Restore<'a> {
        path: &'a Path,
    }
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.path, std::fs::Permissions::from_mode(0o755));
        }
    }

    let env = Env::new();
    let blocked = env.fixture.join("blocked");
    repo_scan::privacy::private_dir_0700(&blocked).expect("mkdir");
    repo_scan::privacy::private_write_0600(&blocked.join("secret.txt"), b"x").expect("write");
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o0)).expect("chmod 000");
    let _restore = Restore { path: &blocked };
    if std::fs::read_dir(&blocked).is_ok() {
        eprintln!("error_events_journal_completion_gaps: chmod 000 ineffective; skipping");
        return;
    }

    let out = env.scan(&["--report", "rep.json"], &env.cwd_a);
    assert_eq!(
        out.status.code(),
        Some(3),
        "permission gap is usable-but-incomplete; stderr: {}",
        stderr_text(&out)
    );
    let scan_id = stdout_line(&out, "scan_id");
    let report = read_report(&env.cwd_a.join("rep.json"));
    assert_eq!(report["scan"]["state"].as_str(), Some("incomplete"));
    assert!(report["coverage"]["gaps"].as_u64().expect("gaps") > 0);

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = env.state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 1_000)
            .await
            .expect("read");
        let errors: Vec<_> = rows.iter().filter(|r| r.event_type == "error").collect();
        assert!(!errors.is_empty(), "gap journaled at least one error event");
        for row in &errors {
            assert_eq!(row.op, "add", "D4 op for error");
            let v: serde_json::Value = serde_json::from_slice(&row.records).expect("json");
            let id = v["id"].as_str().expect("event id");
            assert!(id.starts_with("evt:"), "opaque gap id: {id}");
            assert!(
                v["category"].as_str().is_some_and(|c| !c.is_empty()),
                "category carried"
            );
            assert!(
                v["detail"].as_str().is_some_and(|d| !d.is_empty()),
                "detail carried"
            );
            // Join: the payload names a real open catalog row; attempts and
            // open state are read there, never from the event.
            let raw_id = store
                .list_open_error_ids()
                .await
                .expect("open gap ids")
                .into_iter()
                .find(|raw| main_under_test::test_event_opaque_id(raw).as_str() == id)
                .expect("opaque event id maps to an open catalog gap");
            let gap = store
                .get_error(&raw_id)
                .await
                .expect("get")
                .expect("gap row");
            assert!(gap.open, "gap row is open");
            assert!(gap.attempts >= 1, "recorded at least once");
            assert_eq!(gap.category, v["category"].as_str().expect("category"));
        }
        store.close().await.expect("close");
    });
}

/// Persisted refs are journaled as `branch_batch` events: one `add` batch
/// per store (chunked at 500), carrying every ref the installed `git`
/// reports with matching oids, ordered after the store's
/// `repository_found`.
#[test]
fn branch_batch_journals_persisted_refs() {
    use repo_scan::store::{Store, TursoStore};
    use std::collections::{HashMap, HashSet};

    let env = Env::new();
    let repo = env.fixture.join("repo");
    // Three local branches on distinct commits plus a tag; `git` is the
    // independent reference for the expected ref set.
    fixture::git(&repo, &["checkout", "-qb", "side-a"]);
    std::fs::write(repo.join("a.txt"), b"a\n").expect("write");
    fixture::git(&repo, &["add", "-A"]);
    fixture::git(&repo, &["commit", "-qm", "a"]);
    fixture::git(&repo, &["checkout", "-q", "main"]);
    fixture::git(&repo, &["checkout", "-qb", "side-b"]);
    std::fs::write(repo.join("b.txt"), b"b\n").expect("write");
    fixture::git(&repo, &["add", "-A"]);
    fixture::git(&repo, &["commit", "-qm", "b"]);
    fixture::git(&repo, &["checkout", "-q", "main"]);
    fixture::git(&repo, &["tag", "v1"]);
    let mut expected = HashMap::new();
    for line in fixture::git_str(
        &repo,
        &["for-each-ref", "--format=%(refname) %(objectname)"],
    )
    .lines()
    .map(str::to_string)
    {
        let (name, oid) = line.split_once(' ').expect("refname oid");
        expected.insert(name.to_string(), oid.to_string());
    }
    assert_eq!(expected.len(), 4, "main + side-a + side-b + v1");

    let out = env.scan(&["--report", "rep.json"], &env.cwd_a);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id = stdout_line(&out, "scan_id");

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = env.state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 1_000)
            .await
            .expect("read");
        let batches: Vec<_> = rows
            .iter()
            .filter(|r| r.event_type == "branch_batch")
            .collect();
        assert_eq!(batches.len(), 1, "4 refs fit one chunk");
        let row = batches[0];
        assert_eq!(row.op, "add", "first batch per store is add");
        let v: serde_json::Value = serde_json::from_slice(&row.records).expect("json");
        assert!(v["rev"].as_i64().is_some(), "observation rev carried");
        assert_eq!(v["batch_index"].as_u64(), Some(0));
        assert_eq!(v["batch_count"].as_u64(), Some(1));
        let branches = v["branches"].as_array().expect("branches array");
        assert_eq!(branches.len(), expected.len(), "every ref journaled");
        let common = std::fs::canonicalize(repo.join(".git")).expect("canonical common dir");
        let common_hex = repo_scan::config::encode_hex(&repo_scan::config::path_as_bytes(&common));
        let mut seen = HashSet::new();
        for b in branches {
            let name = b["name"].as_str().expect("name");
            let want_oid = expected
                .get(name)
                .unwrap_or_else(|| panic!("unexpected {name}"));
            assert_eq!(b["oid"].as_str(), Some(want_oid.as_str()), "oid of {name}");
            assert_eq!(
                b["name_hex"].as_str(),
                Some(hex_of(name.as_bytes()).as_str()),
                "lossless name of {name}"
            );
            let want_kind = if name.starts_with("refs/heads/") {
                "local"
            } else {
                "other"
            };
            assert_eq!(b["kind"].as_str(), Some(want_kind), "kind of {name}");
            assert!(
                b["state"].as_str().is_some_and(|s| !s.is_empty()),
                "state of {name}"
            );
            assert!(seen.insert(name.to_string()), "no duplicate {name}");
            let catalog_id = format!("ref:{common_hex}:{}", hex_of(name.as_bytes()));
            assert_eq!(
                b["id"],
                main_under_test::test_event_opaque_id(&catalog_id),
                "opaque event id for catalog ref {name}"
            );
        }
        // Ordering: the batch lands after its store's repository_found.
        let found = rows
            .iter()
            .find(|r| {
                r.event_type == "repository_found"
                    && serde_json::from_slice::<serde_json::Value>(&r.records)
                        .map(|f| f["store_id"] == v["store_id"])
                        .unwrap_or(false)
            })
            .expect("repository_found for batch store");
        assert!(row.seq > found.seq, "batch follows its found event");
        store.close().await.expect("close");
    });
}

/// Lowercase hex of raw bytes (independent of the scanner's encoder).
fn hex_of(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    out
}

/// `coverage_updated` carries gap/candidate deltas only: the chmod-000 gap
/// opens exactly once (re-records are not transitions), unconditional
/// closes of never-open rows stay silent, and a remote-less clone joins
/// as an unresolvable candidate.
#[test]
fn coverage_updated_reports_gap_deltas() {
    use repo_scan::store::{Store, TursoStore};
    use std::os::unix::fs::PermissionsExt;

    struct Restore<'a> {
        path: &'a Path,
    }
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.path, std::fs::Permissions::from_mode(0o755));
        }
    }

    let env = Env::new();
    // No remotes: `classify_remotes` with an empty set is
    // `UnresolvableIdentity`, proven by git_impl's table test.
    let noremote = fixture::normal_clone(&env.fixture, "noremote");
    fixture::git(&noremote, &["remote", "remove", "origin"]);
    assert!(
        fixture::git_str(&noremote, &["remote"]).is_empty(),
        "fixture has no remotes"
    );
    let blocked = env.fixture.join("blocked");
    repo_scan::privacy::private_dir_0700(&blocked).expect("mkdir");
    repo_scan::privacy::private_write_0600(&blocked.join("secret.txt"), b"x").expect("write");
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o0)).expect("chmod 000");
    let _restore = Restore { path: &blocked };
    if std::fs::read_dir(&blocked).is_ok() {
        eprintln!("coverage_updated_reports_gap_deltas: chmod 000 ineffective; skipping");
        return;
    }

    let out = env.scan(&["--report", "rep.json"], &env.cwd_a);
    assert_eq!(
        out.status.code(),
        Some(3),
        "permission gap is usable-but-incomplete; stderr: {}",
        stderr_text(&out)
    );
    let scan_id = stdout_line(&out, "scan_id");

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = env.state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 1_000)
            .await
            .expect("read");
        let updates: Vec<_> = rows
            .iter()
            .filter(|r| r.event_type == "coverage_updated")
            .collect();
        assert!(!updates.is_empty(), "gap transitions journal deltas");
        let mut opened = Vec::new();
        let mut closed = Vec::new();
        let mut unresolvable = Vec::new();
        for row in &updates {
            assert_eq!(row.op, "replace", "D4 op for coverage_updated");
            let v: serde_json::Value = serde_json::from_slice(&row.records).expect("json");
            for key in ["opened", "closed", "unresolvable_added"] {
                assert!(v.get(key).is_some_and(|a| a.is_array()), "{key} present");
            }
            opened.extend(
                v["opened"]
                    .as_array()
                    .expect("array")
                    .iter()
                    .map(|s| s.as_str().expect("str").to_string()),
            );
            closed.extend(
                v["closed"]
                    .as_array()
                    .expect("array")
                    .iter()
                    .map(|s| s.as_str().expect("str").to_string()),
            );
            unresolvable.extend(
                v["unresolvable_added"]
                    .as_array()
                    .expect("array")
                    .iter()
                    .map(|s| s.as_str().expect("str").to_string()),
            );
        }
        // Exactly one open transition for the enum gap, whatever the
        // retry/re-record count; every probe's unconditional close of a
        // never-open row stays silent.
        assert_eq!(opened.len(), 1, "one open transition: {opened:?}");
        assert!(
            opened[0].starts_with("evt:"),
            "opaque gap id: {}",
            opened[0]
        );
        assert!(closed.is_empty(), "no genuine closes: {closed:?}");
        let raw_gap_id = store
            .list_open_error_ids()
            .await
            .expect("open gap ids")
            .into_iter()
            .find(|raw| main_under_test::test_event_opaque_id(raw).as_str() == opened[0].as_str())
            .expect("event id maps to open catalog gap");
        let gap = store
            .get_error(&raw_gap_id)
            .await
            .expect("get")
            .expect("gap row");
        assert!(gap.open, "opened id names an open row");
        // The remote-less clone joined as an unresolvable candidate.
        assert_eq!(unresolvable.len(), 1, "{unresolvable:?}");
        let common = std::fs::canonicalize(noremote.join(".git")).expect("canonical common dir");
        let instance_id = format!(
            "git:{}",
            repo_scan::config::encode_hex(&repo_scan::config::path_as_bytes(&common))
        );
        assert_eq!(
            unresolvable[0],
            main_under_test::test_event_opaque_id(&instance_id)
        );
        let instance = store
            .get_git_instance(&instance_id)
            .await
            .expect("get")
            .expect("instance row");
        assert_eq!(instance.disposition, "unresolvable_identity");
        store.close().await.expect("close");
    });
}

// ---------------------------------------------------------------------------
// Step 15 case 12: no branch, status, or graph analysis starts before
// inventory_ready (the instrumented production proof for the Step 8 phase
// boundary: analysis journals branch_batch/location_updated/remote_updated,
// and every one must sort after the boundary event).
// ---------------------------------------------------------------------------

#[test]
fn case12_no_analysis_before_inventory_ready() {
    case12_body(&[]);
}

/// Case 12 under explicit high concurrency: analysis tasks enqueue
/// during discovery and pend while probes still run — the pooled
/// drain must still hold every analysis claim behind the boundary.
#[test]
fn case12_no_analysis_before_inventory_ready_workers8() {
    case12_body(&["--workers", "8"]);
}

fn case12_body(extra: &[&str]) {
    use repo_scan::store::{Store, TursoStore};

    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    // Two stores (a plain clone plus a main+worktree pair) so both the
    // branch leg (branch_batch) and the status leg (location_updated)
    // of analysis observably run.
    fixture::normal_clone(&root, "repo");
    fixture::linked_worktree(&root);
    let mut args = vec![
        "scan",
        URL,
        "--root",
        root.to_str().expect("utf8"),
        "--status",
        "summary",
        "--report",
        "rep.json",
        "--format",
        "human",
    ];
    args.extend(extra.iter().copied());
    let out = run(&args, &cwd, &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id = stdout_line(&out, "scan_id");

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 1_000)
            .await
            .expect("read");
        let ready: Vec<_> = rows
            .iter()
            .filter(|r| r.event_type == "inventory_ready")
            .collect();
        assert_eq!(ready.len(), 1, "exactly one boundary event");
        let boundary = ready[0].seq;
        // Discovery precedes the boundary: at least one found event lands
        // before it (non-vacuous discovery leg).
        assert!(
            rows.iter().any(|r| (r.event_type == "repository_found"
                || r.event_type == "location_found")
                && r.seq < boundary),
            "a found event precedes inventory_ready"
        );
        // Analysis follows the boundary: every branch/status/remote event
        // sorts strictly after it, and both legs observably ran.
        let mut saw_batch = false;
        let mut saw_updated = false;
        for row in &rows {
            match row.event_type.as_str() {
                "branch_batch" => saw_batch = true,
                "location_updated" => saw_updated = true,
                _ => {}
            }
            assert!(
                !matches!(
                    row.event_type.as_str(),
                    "branch_batch" | "location_updated" | "remote_updated"
                ) || row.seq > boundary,
                "analysis event {} at seq {} sorts after inventory_ready at {boundary}",
                row.event_type,
                row.seq
            );
        }
        assert!(saw_batch, "branch analysis journaled branch_batch");
        assert!(saw_updated, "status analysis journaled location_updated");
        // Read-entry order proof (D3): the terminal payload carries the
        // audited pre-boundary analysis read starts — zero, because
        // every analysis read runs behind the Analysis drain gate.
        // Journal order alone cannot prove this (reads could run early
        // and persist late).
        let terminal = rows
            .iter()
            .find(|r| {
                matches!(
                    r.event_type.as_str(),
                    "scan_completed" | "scan_incomplete" | "scan_interrupted" | "scan_failed"
                )
            })
            .expect("terminal event journaled");
        let payload: serde_json::Value =
            serde_json::from_slice(&terminal.records).expect("terminal json");
        assert_eq!(
            payload["boundary_audit"]["pre_boundary_analysis_reads"].as_u64(),
            Some(0),
            "zero analysis reads started before inventory_ready"
        );
        store.close().await.expect("close");
    });
}

/// Case 12 with `--fetch`: the remote leg (`remote_updated`) is
/// non-vacuous here — a file-remote clone really fetches — and the
/// fetch-phase events sort after the boundary with zero pre-boundary
/// analysis read starts.
#[test]
fn case12_no_analysis_before_inventory_ready_fetch() {
    use repo_scan::store::{Store, TursoStore};

    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    // File-remote world (never network): the clone's fetch really runs.
    let upstream = fixture::normal_clone(&root, "upstream");
    let clone = root.join("clone");
    fixture::git(
        &root,
        &[
            "clone",
            "-q",
            upstream.to_str().expect("utf8"),
            clone.to_str().expect("utf8"),
        ],
    );
    fixture::linked_worktree(&root);
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root.to_str().expect("utf8"),
            "--status",
            "summary",
            "--report",
            "rep.json",
            "--format",
            "human",
            "--fetch",
        ],
        &cwd,
        &state,
    );
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "usable scan result: {}",
        stderr_text(&out)
    );
    let scan_id = stdout_line(&out, "scan_id");

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 1_000)
            .await
            .expect("read");
        let ready: Vec<_> = rows
            .iter()
            .filter(|r| r.event_type == "inventory_ready")
            .collect();
        assert_eq!(ready.len(), 1, "exactly one boundary event");
        let boundary = ready[0].seq;
        let mut saw_remote = false;
        for row in &rows {
            if row.event_type == "remote_updated" {
                saw_remote = true;
            }
            assert!(
                row.event_type != "remote_updated" || row.seq > boundary,
                "remote_updated at seq {} sorts after inventory_ready at {boundary}",
                row.seq
            );
        }
        assert!(saw_remote, "fetch phase journaled remote_updated");
        let terminal = rows
            .iter()
            .find(|r| {
                matches!(
                    r.event_type.as_str(),
                    "scan_completed" | "scan_incomplete" | "scan_interrupted" | "scan_failed"
                )
            })
            .expect("terminal event journaled");
        let payload: serde_json::Value =
            serde_json::from_slice(&terminal.records).expect("terminal json");
        assert_eq!(
            payload["boundary_audit"]["pre_boundary_analysis_reads"].as_u64(),
            Some(0),
            "zero analysis reads started before inventory_ready"
        );
        store.close().await.expect("close");
    });
}

/// Actual retained report snapshots stay within the configured bound even
/// after completed scan outcomes accumulate in `scan_requests`.
#[test]
fn completed_scan_outcomes_do_not_pin_snapshots_past_retention() {
    let env = Env::new();
    let mut latest_report_id = None;
    for _ in 0..=repo_scan::report::output::MAX_RETAINED_SNAPSHOTS {
        let out = run(
            &[
                "scan",
                "--all",
                "--root",
                env.fixture_str.as_str(),
                "--force-rescan",
                "--format",
                "jsonl",
            ],
            &env.cwd_a,
            &env.state,
        );
        assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
        let events: Vec<serde_json::Value> = stdout_text(&out)
            .lines()
            .map(|line| serde_json::from_str(line).expect("event is JSON"))
            .collect();
        latest_report_id = events
            .last()
            .and_then(|event| event["records"]["report_id"].as_str())
            .map(str::to_string);
    }
    let latest_report_id = latest_report_id.expect("latest report id");
    let snapshots = env
        .state
        .join("payload")
        .join(repo_scan::config::SNAPSHOTS_DIR_NAME);
    let retained: Vec<PathBuf> = std::fs::read_dir(&snapshots)
        .expect("snapshots directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    assert_eq!(
        retained.len(),
        repo_scan::report::output::MAX_RETAINED_SNAPSHOTS,
        "only the configured newest snapshots remain"
    );
    assert!(
        snapshots.join(format!("{latest_report_id}.json")).is_file(),
        "the current report survives pruning"
    );
}

/// DB-M1: invalidating a symlinked root by either spelling schedules
/// reconciliation (the invalidate path resolves both spellings onto
/// the same object). Keys keep observed spellings; the cross-spelling
/// live-task fan-out is pinned at the store level by
/// `dbm1_cross_spelling_invalidate_hits_live_task`.
#[cfg(unix)]
#[test]
fn dbm1_symlink_root_invalidate_schedules_reconcile() {
    let env = Env::new();
    let link = env._dir.path().join("fixture-link");
    std::os::unix::fs::symlink(&env.fixture, &link).expect("symlink");
    let link_str = link.to_str().expect("utf8").to_string();
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            link_str.as_str(),
            "--format",
            "human",
        ],
        &env.cwd_a,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    // Invalidate via the physical path: durable, with no completion
    // claim (exit 0), exactly like a same-spelling invalidate.
    let out = run(
        &["cache", "invalidate", "--root", env.fixture_str.as_str()],
        &env.cwd_b,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        stdout_text(&out).contains("not complete"),
        "no completion claim"
    );
}

/// A failed publication remains retryable after more than 32 newer reports
/// are staged. Resume must publish the exact saved snapshot bytes.
#[test]
fn failed_unpublished_snapshot_survives_retention_and_resume_retries_bytes() {
    use repo_scan::store::{now_ms, NewScan, TursoStore};

    let env = Env::new();
    let seed_dest = env.cwd_a.join("seed.json");
    let seed_dest_s = seed_dest.to_str().expect("seed path");
    let seed = env.scan(&["--report", seed_dest_s], &env.cwd_a);
    assert_eq!(
        seed.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&seed)
    );
    let mut failed_report = read_report(&seed_dest);

    let scan_id = "failed-retention-retry";
    let report_id = repo_scan::config::report_id_for_scan(scan_id);
    failed_report["report_id"] = report_id.clone().into();
    failed_report["scan"]["id"] = scan_id.into();
    let saved_bytes = serde_json::to_vec(&failed_report).expect("saved report JSON");
    let snapshot =
        repo_scan::config::snapshot_path(&env.state, &report_id).expect("failed snapshot path");
    std::fs::write(&snapshot, &saved_bytes).expect("write failed snapshot");

    let destination = env.cwd_a.join("retry.json");
    let destination_bytes = repo_scan::config::path_as_bytes(&destination);
    let canonical = repo_scan::identity::normalize_github_url(URL).expect("canonical URL");
    let catalog_rev = failed_report["scan"]["catalog_revision"]
        .as_u64()
        .expect("catalog revision");
    let generation = failed_report["scan"]["generation"]
        .as_u64()
        .expect("generation");
    let schema_version = failed_report["schema_version"]
        .as_str()
        .expect("schema version")
        .to_string();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let store = TursoStore::open(&env.state.join("payload").join("catalog.db"))
            .await
            .expect("open catalog");
        assert!(store
            .create_scan_request(
                &NewScan {
                    id: scan_id,
                    url_raw: URL.as_bytes(),
                    url_canonical: Some(canonical.as_bytes()),
                    scope: "roots",
                    status_mode: "summary",
                    report_dest: Some(&destination_bytes),
                    targets_json: None,
                    format: Some("json"),
                    all_targets: Some(false),
                },
                now_ms(),
            )
            .await
            .expect("create failed scan"));
        store
            .update_scan_state(
                scan_id,
                "failed",
                Some(&repo_scan::config::encode_outcome(
                    1,
                    Some(0),
                    &report_id,
                    false,
                    Some(generation),
                )),
                None,
                now_ms(),
            )
            .await
            .expect("record failed publication");
        // Consolidation checksum binding: the catalog row carries the
        // staged bytes' checksum, which the retry verifies before publish.
        let checksum = repo_scan::report::publish::sha256_hex(&saved_bytes);
        assert!(store
            .save_report_snapshot(
                &report_id,
                &schema_version,
                catalog_rev,
                generation,
                "failed",
                Some(checksum.as_bytes()),
                now_ms(),
            )
            .await
            .expect("catalog failed snapshot"));
        store.close().await.expect("close catalog");
    });

    // Make the unpublished snapshot older than the ordinary 32-file window.
    for n in 0..=repo_scan::report::output::MAX_RETAINED_SNAPSHOTS {
        let id = format!("retry-filler-{n:03}");
        let path = repo_scan::config::snapshot_path(&env.state, &id).expect("filler path");
        std::fs::write(path, &saved_bytes).expect("write filler snapshot");
    }

    let active = env.scan(&["--force-rescan"], &env.cwd_a);
    assert_eq!(
        active.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&active)
    );
    assert!(
        snapshot.is_file(),
        "failed unpublished snapshot survives pruning"
    );

    let retry = run(
        &["resume", scan_id, "--format", "json"],
        &env.cwd_b,
        &env.state,
    );
    assert_eq!(
        retry.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&retry)
    );
    let output: serde_json::Value = serde_json::from_slice(&retry.stdout).expect("JSON output");
    assert_eq!(output["report_id"], report_id);
    assert_eq!(
        std::fs::read(&destination).expect("published bytes"),
        saved_bytes
    );
    rt.block_on(async {
        let store = TursoStore::open(&env.state.join("payload").join("catalog.db"))
            .await
            .expect("reopen catalog");
        let row = store
            .get_scan(scan_id)
            .await
            .expect("get scan")
            .expect("row");
        assert_eq!(row.state, "complete");
        assert!(row
            .outcome
            .as_deref()
            .and_then(repo_scan::config::parse_outcome)
            .is_some_and(|outcome| outcome.published));
        store.close().await.expect("close catalog");
    });
}

/// Boundary B1: a gappy no-fetch scan journals COMPLETELY and IN ORDER.
/// Lifecycle emits (`inventory_ready`, terminal) commit immediately,
/// so the writer batch must drain before each — otherwise lower-seq
/// gap events commit after the terminal event (or drop at Runner
/// drop). Asserts contiguous seqs, the terminal event last and alone,
/// every buffered event ordered before it, and every open catalog gap
/// row joined from a journaled error event (nothing dropped).
#[test]
fn gappy_scan_journal_complete_and_ordered() {
    use repo_scan::store::{Store, TursoStore};
    use std::collections::HashSet;
    use std::os::unix::fs::PermissionsExt;

    struct Restore<'a> {
        path: &'a Path,
    }
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.path, std::fs::Permissions::from_mode(0o755));
        }
    }

    let env = Env::new();
    let blocked = env.fixture.join("blocked");
    repo_scan::privacy::private_dir_0700(&blocked).expect("mkdir");
    repo_scan::privacy::private_write_0600(&blocked.join("secret.txt"), b"x").expect("write");
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o0)).expect("chmod 000");
    let _restore = Restore { path: &blocked };
    if std::fs::read_dir(&blocked).is_ok() {
        eprintln!("gappy_scan_journal_complete_and_ordered: chmod 000 ineffective; skipping");
        return;
    }

    let out = env.scan(&["--report", "rep.json"], &env.cwd_a);
    assert_eq!(
        out.status.code(),
        Some(3),
        "permission gap is usable-but-incomplete; stderr: {}",
        stderr_text(&out)
    );
    let scan_id = stdout_line(&out, "scan_id");

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = env.state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 10_000)
            .await
            .expect("read");
        assert!(!rows.is_empty(), "journal is non-empty");
        // Completeness: seqs contiguous from 1 (no dropped tail).
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row.seq, (i + 1) as u64, "seqs contiguous from 1");
        }
        // Order agreement: exactly one terminal, committed last; the
        // boundary precedes it; every gap event precedes the terminal.
        let is_terminal = |t: &str| {
            matches!(
                t,
                "scan_completed" | "scan_incomplete" | "scan_interrupted" | "scan_failed"
            )
        };
        let terminals: Vec<u64> = rows
            .iter()
            .filter(|r| is_terminal(r.event_type.as_str()))
            .map(|r| r.seq)
            .collect();
        assert_eq!(terminals.len(), 1, "exactly one terminal event");
        assert_eq!(
            rows.last().expect("last").seq,
            terminals[0],
            "terminal event committed last"
        );
        let ready = rows
            .iter()
            .find(|r| r.event_type == "inventory_ready")
            .expect("inventory_ready journaled");
        assert!(
            ready.seq < terminals[0],
            "boundary commits before the terminal"
        );
        let errors: Vec<_> = rows.iter().filter(|r| r.event_type == "error").collect();
        assert!(!errors.is_empty(), "gap journaled at least one error event");
        for row in &errors {
            assert!(
                row.seq < terminals[0],
                "gap event seq {} commits before the terminal",
                row.seq
            );
        }
        // Join the other way: every open gap row has a journaled error
        // event (no committed gap silently missing its event).
        let journaled: HashSet<String> = errors
            .iter()
            .map(|r| {
                let v: serde_json::Value = serde_json::from_slice(&r.records).expect("error json");
                v["id"].as_str().expect("event id").to_string()
            })
            .collect();
        let open_rows = store.list_open_error_ids().await.expect("open ids");
        assert!(!open_rows.is_empty(), "world holds open gaps");
        for id in &open_rows {
            assert!(
                journaled.contains(&main_under_test::test_event_opaque_id(id)),
                "open gap {id} has a journaled error event"
            );
        }
        store.close().await.expect("close");
    });
}

#[test]
fn human_footers_and_destination_errors_scrub_local_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("password=STATEPATHCANARY");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("cwd");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("root");
    fixture::normal_clone(&root, "repo");
    let report_dir = cwd.join("password=REPORTPATHCANARY");
    repo_scan::privacy::private_dir_0700(&report_dir).expect("report dir");
    let report = report_dir.join("report.json");
    let successful = run(
        &[
            "scan",
            URL,
            "--root",
            root.to_str().expect("root UTF-8"),
            "--report",
            report.to_str().expect("report UTF-8"),
            "--format",
            "human",
        ],
        &cwd,
        &state,
    );
    assert_eq!(
        successful.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&successful)
    );
    assert!(!stdout_text(&successful).contains("STATEPATHCANARY"));
    assert!(!stdout_text(&successful).contains("REPORTPATHCANARY"));

    let rejected_dest = state.join("password=ERRORPATHCANARY").join("report.json");
    let rejected = run(
        &[
            "scan",
            URL,
            "--root",
            root.to_str().expect("root UTF-8"),
            "--report",
            rejected_dest.to_str().expect("rejected path UTF-8"),
            "--format",
            "human",
        ],
        &cwd,
        &state,
    );
    assert_ne!(rejected.status.code(), Some(0));
    let diagnostic = stderr_text(&rejected);
    assert!(!diagnostic.contains("STATEPATHCANARY"));
    assert!(!diagnostic.contains("ERRORPATHCANARY"));
}

#[test]
fn local_target_credentials_are_scrubbed_from_persistence_and_report() {
    use repo_scan::store::{Store, TursoStore};

    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("cwd");
    // Synthetic credential-shaped path component, used only as a canary.
    let root = dir
        .path()
        .join("password=ghp_TESTTARGETCANARY00000000000000000000");
    repo_scan::privacy::private_dir_0700(&root).expect("root");
    let repo = fixture::normal_clone(&root, "repo");
    let target = repo.to_str().expect("UTF-8 target");
    let root_arg = root.to_str().expect("UTF-8 root");
    let output = run(
        &[
            "scan",
            target,
            "--root",
            root_arg,
            "--report",
            "report.json",
            "--format",
            "human",
        ],
        &cwd,
        &state,
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&output)
    );
    let report = read_report(&cwd.join("report.json"));
    let scan_id = report["scan"]["id"].as_str().expect("scan id");
    let scan_json = serde_json::to_string(&report["scan"]).expect("scan JSON");
    assert!(
        !scan_json.contains("TESTTARGETCANARY"),
        "report scan target fields must not retain the synthetic credential"
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open catalog");
        let saved = store
            .get_scan(scan_id)
            .await
            .expect("get scan")
            .expect("scan row");
        assert!(
            !String::from_utf8_lossy(&saved.url_raw).contains("TESTTARGETCANARY"),
            "scan url_raw must be scrubbed"
        );
        assert!(
            !saved
                .url_canonical
                .as_deref()
                .is_some_and(|bytes| String::from_utf8_lossy(bytes).contains("TESTTARGETCANARY")),
            "scan url_canonical must be scrubbed"
        );
        assert!(
            !saved
                .targets_json
                .as_deref()
                .is_some_and(|text| text.contains("TESTTARGETCANARY")),
            "targets_json must be scrubbed"
        );
        let rows = store
            .read_scan_events(scan_id, 0, 10_000)
            .await
            .expect("read scan events");
        let started = rows
            .iter()
            .find(|row| row.event_type == "scan_started")
            .expect("scan_started event");
        let records = String::from_utf8_lossy(&started.records);
        assert!(
            !records.contains("TESTTARGETCANARY"),
            "scan_started target and root fields must be scrubbed"
        );
        store.close().await.expect("close catalog");
    });
}

/// The active scan's recovery report is pinned separately from the newest
/// window. Pruning must also keep the newest earlier running scan's
/// snapshot when that snapshot falls outside the window.
#[test]
fn prior_running_scan_recovery_snapshot_survives_retention() {
    use repo_scan::store::{NewScan, Store, TursoStore};
    use std::collections::HashSet;

    let env = Env::new();
    let seed = env.scan(&["--report", "seed.json"], &env.cwd_a);
    assert_eq!(
        seed.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&seed)
    );
    let seed_scan_id = stdout_line(&seed, "scan_id");
    let seed_report_id = repo_scan::config::report_id_for_scan(&seed_scan_id);
    let seed_snapshot =
        repo_scan::config::snapshot_path(&env.state, &seed_report_id).expect("seed snapshot path");
    let mut recovery_report = read_report(&seed_snapshot);

    let crashed_scan_id = "crashed-retention-prior";
    let recovery_report_id = repo_scan::config::report_id_for_scan(crashed_scan_id);
    let crashed_url = "https://github.com/OWNER/CRASHED";
    let crashed_canonical =
        repo_scan::identity::normalize_github_url(crashed_url).expect("crashed target");
    recovery_report["report_id"] = recovery_report_id.clone().into();
    recovery_report["scan"]["id"] = crashed_scan_id.into();
    recovery_report["scan"]["target_url"] = crashed_url.into();
    recovery_report["scan"]["canonical_url"] = crashed_canonical.clone().into();
    let recovery_bytes = serde_json::to_vec(&recovery_report).expect("recovery report JSON");
    let recovery_snapshot = repo_scan::config::snapshot_path(&env.state, &recovery_report_id)
        .expect("recovery snapshot path");
    std::fs::write(&recovery_snapshot, &recovery_bytes).expect("write recovery snapshot");

    let recovery_outcome =
        repo_scan::config::encode_outcome(-1, None, &recovery_report_id, false, Some(1));
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let store = TursoStore::open(&env.state.join("payload").join("catalog.db"))
            .await
            .expect("open catalog");
        let inserted = store
            .create_scan_request(
                &NewScan {
                    id: crashed_scan_id,
                    url_raw: crashed_url.as_bytes(),
                    url_canonical: Some(crashed_canonical.as_bytes()),
                    scope: "roots",
                    status_mode: "summary",
                    report_dest: None,
                    targets_json: None,
                    format: None,
                    all_targets: None,
                },
                1,
            )
            .await
            .expect("insert crashed scan");
        assert!(inserted);
        store
            .update_scan_state(
                crashed_scan_id,
                "running:roots",
                Some(&recovery_outcome),
                None,
                1,
            )
            .await
            .expect("mark crashed scan running");
        assert!(store
            .save_report_snapshot(&recovery_report_id, "1.5.0", 1, 1, "staged", None, 1,)
            .await
            .expect("save recovery snapshot row"));
        store.close().await.expect("close catalog");
    });

    // Place 33 newer, unreferenced snapshots behind the recovery snapshot.
    // The recovery ID sorts before these if the filesystem has coarse mtime
    // resolution, and its earlier creation time sorts it first otherwise.
    for n in 0..=repo_scan::report::output::MAX_RETAINED_SNAPSHOTS {
        let id = format!("retained-{n:03}");
        let path = repo_scan::config::snapshot_path(&env.state, &id).expect("filler path");
        std::fs::write(path, &recovery_bytes).expect("write filler snapshot");
    }
    let snapshots_dir = recovery_snapshot.parent().expect("snapshot directory");
    let ordinary_victims = repo_scan::report::output::select_snapshot_victims(
        repo_scan::report::output::list_snapshot_entries(snapshots_dir),
        &HashSet::new(),
        repo_scan::report::output::MAX_RETAINED_SNAPSHOTS,
    );
    assert!(
        ordinary_victims
            .iter()
            .any(|entry| entry.id == recovery_report_id),
        "setup puts the prior recovery snapshot outside normal retention"
    );

    let active = env.scan(&["--report", "active.json"], &env.cwd_a);
    assert_eq!(
        active.status.code(),
        Some(0),
        "stderr: {}",
        stderr_text(&active)
    );
    let active_scan_id = stdout_line(&active, "scan_id");
    let active_report_id = repo_scan::config::report_id_for_scan(&active_scan_id);
    let active_snapshot = repo_scan::config::snapshot_path(&env.state, &active_report_id)
        .expect("active snapshot path");
    assert!(active_snapshot.is_file(), "current scan report is retained");
    assert!(
        recovery_snapshot.is_file(),
        "the latest prior running scan recovery report survives pruning"
    );

    let retained_files = repo_scan::report::output::list_snapshot_entries(snapshots_dir);
    assert!(
        (repo_scan::report::output::MAX_RETAINED_SNAPSHOTS + 1
            ..=repo_scan::report::output::MAX_RETAINED_SNAPSHOTS + 2)
            .contains(&retained_files.len()),
        "only the current report and prior recovery report may extend the normal window"
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let store = TursoStore::open(&env.state.join("payload").join("catalog.db"))
            .await
            .expect("open catalog");
        assert!(store
            .get_report_snapshot(&recovery_report_id)
            .await
            .expect("recovery snapshot row")
            .is_some());
        store.close().await.expect("close catalog");
    });
}

/// Sibling symlink spellings share one generation and refresh catalog rows
/// persisted through the first alias.
#[cfg(unix)]
#[test]
fn roots_symlink_alias_reuses_catalog_rows() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    let physical_lexical = dir.path().join("physical");
    let alias_a = dir.path().join("alias-a");
    let alias_c = dir.path().join("alias-c");
    for path in [&cwd, &physical_lexical] {
        repo_scan::privacy::private_dir_0700(path).expect("mkdir");
    }
    fixture::normal_clone(&physical_lexical, "repo");
    let physical = std::fs::canonicalize(&physical_lexical).expect("canonical physical root");
    symlink(&physical, &alias_a).expect("first symlink root alias");
    symlink(&physical, &alias_c).expect("second symlink root alias");

    let scan = |root: &Path, report_name: &str| {
        let out = run(
            &[
                "scan",
                "--all",
                "--root",
                root.to_str().expect("utf8 root"),
                "--report",
                report_name,
            ],
            &cwd,
            &state,
        );
        assert!(
            matches!(out.status.code(), Some(0) | Some(3)),
            "usable report: {}",
            stderr_text(&out)
        );
        read_report(&cwd.join(report_name))
    };

    let alias_a_root = alias_a.join("repo");
    let alias_c_root = alias_c.join("repo");
    let alias_a_report = scan(&alias_a_root, "alias-a.json");
    let updated_commit = fixture::commit_file(
        &physical.join("repo"),
        "README.md",
        "# fixture after alias A scan\n",
        "advance before alias C scan",
    );
    repo_scan::privacy::private_write_0600(
        &physical.join("repo/alias-refresh-untracked"),
        b"untracked after alias A scan",
    )
    .expect("write dirty status marker");
    let alias_report = scan(&alias_c_root, "alias-c.json");
    #[cfg(target_os = "macos")]
    assert_eq!(
        alias_report["scan"]["generation"], alias_a_report["scan"]["generation"],
        "sibling root spellings share the canonical generation"
    );
    #[cfg(not(target_os = "macos"))]
    assert_ne!(
        alias_report["scan"]["generation"], alias_a_report["scan"]["generation"],
        "fresh generation when events unsupported"
    );
    assert_eq!(
        alias_report["repositories"].as_array().unwrap().len(),
        1,
        "alias report must retain physical catalog rows: {alias_report}"
    );
    assert_eq!(alias_report["checkouts"].as_array().unwrap().len(), 1);
    assert!(!alias_report["branches"].as_array().unwrap().is_empty());
    assert_eq!(
        alias_report["checkouts"][0]["status"]["working_state"], "dirty",
        "status is refreshed for the prior alias-A checkout"
    );
    assert_eq!(
        alias_report["branches"][0]["oid"]["hex"], updated_commit,
        "branch analysis refreshes the prior alias-A store"
    );

    let git_path_id = alias_report["repositories"][0]["git_path_id"]
        .as_str()
        .expect("repository git path id");
    let git_path = alias_report["paths"]
        .as_array()
        .expect("paths")
        .iter()
        .find(|path| path["id"].as_str() == Some(git_path_id))
        .expect("repository git path")["value"]
        .as_str()
        .expect("UTF-8 git path");
    assert_eq!(
        git_path,
        alias_a.join("repo/.git").to_str().expect("utf8 path"),
        "alias scope retains the prior alias-A catalog spelling"
    );

    let root_gap_id = "shared-root-gap";
    let physical_repo = physical.join("repo");
    let alias_a_repo = alias_a.join("repo");
    let root_scope_key = repo_scan::config::scope_key_for_dir(&physical_repo);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = repo_scan::store::TursoStore::open(&db)
            .await
            .expect("open catalog");
        store
            .record_error(
                root_gap_id,
                &root_scope_key,
                "permission-denied",
                "synthetic shared-root gap",
                None,
                repo_scan::store::now_ms(),
            )
            .await
            .expect("seed root gap");
        store.close().await.expect("close catalog");
    });

    let both = run(
        &[
            "scan",
            "--all",
            "--root",
            physical_repo.to_str().expect("utf8 physical repo root"),
            "--root",
            alias_a_repo.to_str().expect("utf8 alias A repo root"),
            "--report",
            "both.json",
        ],
        &cwd,
        &state,
    );
    assert!(
        matches!(both.status.code(), Some(0) | Some(3)),
        "usable paired-root report: {}",
        stderr_text(&both)
    );
    let both_report = read_report(&cwd.join("both.json"));
    #[cfg(target_os = "macos")]
    assert_eq!(
        both_report["scan"]["generation"],
        alias_a_report["scan"]["generation"]
    );
    #[cfg(not(target_os = "macos"))]
    assert_ne!(
        both_report["scan"]["generation"],
        alias_a_report["scan"]["generation"]
    );
    assert_eq!(both_report["roots"].as_array().unwrap().len(), 2);
    assert_eq!(both_report["repositories"].as_array().unwrap().len(), 1);
    assert!(both_report["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error["id"].as_str() == Some(root_gap_id)));
    assert!(both_report["roots"]
        .as_array()
        .unwrap()
        .iter()
        .all(|root| root["error_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id.as_str() == Some(root_gap_id))));

    let reversed = run(
        &[
            "scan",
            "--all",
            "--root",
            alias_a_repo.to_str().expect("utf8 alias A repo root"),
            "--root",
            physical_repo.to_str().expect("utf8 physical repo root"),
            "--report",
            "both-reversed.json",
        ],
        &cwd,
        &state,
    );
    assert!(
        matches!(reversed.status.code(), Some(0) | Some(3)),
        "usable reversed paired-root report: {}",
        stderr_text(&reversed)
    );
    let reversed_report = read_report(&cwd.join("both-reversed.json"));
    assert_eq!(reversed_report["roots"].as_array().unwrap().len(), 2);
    assert_eq!(reversed_report["repositories"].as_array().unwrap().len(), 1);
    assert!(reversed_report["roots"]
        .as_array()
        .unwrap()
        .iter()
        .all(|root| root["error_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id.as_str() == Some(root_gap_id))));

    // Start with an alias-only root and a lexically keyed identity gap.
    // Both its own rows and the safety gap must survive report filtering.
    let fresh_lexical = dir.path().join("fresh-physical");
    let fresh_alias = dir.path().join("fresh-alias");
    repo_scan::privacy::private_dir_0700(&fresh_lexical).expect("mkdir fresh root");
    fixture::normal_clone(&fresh_lexical, "repo");
    let fresh_physical = std::fs::canonicalize(&fresh_lexical).expect("canonical fresh root");
    symlink(&fresh_physical, &fresh_alias).expect("fresh symlink root");
    let fresh_gap_id = "fresh-alias-identity-gap";
    let fresh_scope = repo_scan::config::scope_key_for_dir(&fresh_alias);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = repo_scan::store::TursoStore::open(&db)
            .await
            .expect("open catalog");
        store
            .record_error(
                fresh_gap_id,
                &fresh_scope,
                "fence-identity-unknown",
                "synthetic unresolved alias identity",
                None,
                repo_scan::store::now_ms(),
            )
            .await
            .expect("seed fresh alias gap");
        store.close().await.expect("close catalog");
    });
    let fresh = run(
        &[
            "scan",
            "--all",
            "--root",
            fresh_alias.to_str().expect("utf8 fresh alias"),
            "--report",
            "fresh-alias.json",
        ],
        &cwd,
        &state,
    );
    assert!(
        matches!(fresh.status.code(), Some(0) | Some(3)),
        "usable fresh alias report: {}",
        stderr_text(&fresh)
    );
    let fresh_report = read_report(&cwd.join("fresh-alias.json"));
    assert!(fresh_report["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error["id"].as_str() == Some(fresh_gap_id)));
    assert!(fresh_report["roots"][0]["error_ids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id.as_str() == Some(fresh_gap_id)));
}

/// Explicit roots are report boundaries even when the catalog already has
/// matching records from an earlier `--all` run at a different root.
#[test]
fn sequential_all_root_scans_exclude_prior_out_of_scope_records() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    let root_a = dir.path().join("root-a");
    let root_b = dir.path().join("root-b");
    for path in [&cwd, &root_a, &root_b] {
        repo_scan::privacy::private_dir_0700(path).expect("mkdir");
    }
    fixture::normal_clone(&root_a, "repo");
    fixture::normal_clone(&root_b, "repo");

    let scan = |root: &Path, report_name: &str| {
        let out = run(
            &[
                "scan",
                "--all",
                "--root",
                root.to_str().expect("utf8 root"),
                "--report",
                report_name,
                "--format",
                "human",
            ],
            &cwd,
            &state,
        );
        assert!(
            matches!(out.status.code(), Some(0) | Some(3)),
            "usable report: {}",
            stderr_text(&out)
        );
        read_report(&cwd.join(report_name))
    };

    let first = scan(&root_a, "root-a.json");
    assert_eq!(first["repositories"].as_array().unwrap().len(), 1);

    // Model a persisted root-A report-derivation gap. Root B must not
    // surface it when both scopes share the same catalog.
    let root_a_set = [root_a.clone()];
    let old_gap_id = repo_scan::config::report_derivation_gap_id("errors", Some(&root_a_set));
    let old_gap_scope = repo_scan::config::report_derivation_gap_scope_key(Some(&root_a_set));
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = repo_scan::store::TursoStore::open(&db)
            .await
            .expect("open catalog");
        store
            .record_error(
                &old_gap_id,
                &old_gap_scope,
                "report-derivation-truncated",
                "root A derivation budget reached",
                None,
                repo_scan::store::now_ms(),
            )
            .await
            .expect("seed root A gap");
        store.close().await.expect("close catalog");
    });

    let second = scan(&root_b, "root-b.json");
    assert_eq!(second["repositories"].as_array().unwrap().len(), 1);
    assert_eq!(second["checkouts"].as_array().unwrap().len(), 1);
    assert_eq!(second["repositories"][0]["match"], "confirmed");
    assert!(
        second["errors"]
            .as_array()
            .expect("errors array")
            .iter()
            .all(|error| error["id"].as_str() != Some(old_gap_id.as_str())),
        "root B report must exclude root A's persisted derivation gap: {}",
        second["errors"]
    );

    let paths = second["paths"].as_array().expect("paths array");
    for record in paths {
        let value = record["value"].as_str().unwrap_or_default();
        assert!(
            !value.contains(root_a.to_str().expect("root A UTF-8")),
            "out-of-scope path was persisted in the second report: {value}"
        );
    }
    let checkout = &second["checkouts"][0];
    let path_id = checkout["root_path_id"].as_str().expect("root path id");
    let checkout_path = paths
        .iter()
        .find(|path| path["id"] == path_id)
        .expect("checkout path record")["value"]
        .as_str()
        .expect("UTF-8 checkout path");
    assert!(
        checkout_path.starts_with(root_b.to_str().expect("root B UTF-8")),
        "second report checkout belongs to root B: {checkout_path}"
    );
}
