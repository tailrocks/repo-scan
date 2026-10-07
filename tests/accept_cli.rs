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

use clap::Parser;
use common::fixture;
use repo_scan::cli::{CacheAction, Cli, Command};
use repo_scan::model::{Scope, StatusMode};
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
            assert_eq!(args.workers, None);
        }
        _ => panic!("expected scan"),
    }
    let cli = Cli::try_parse_from(["repo-scan", "scan", "--all", "--workers", "6"])
        .expect("workers scan parses");
    match cli.command {
        Command::Scan(args) => {
            assert!(args.all);
            assert_eq!(args.workers, Some(6));
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
    assert_eq!(report["schema_version"].as_str(), Some("1.4.0"));
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
        vec!["scan", URL, "--workers", "0", "--root", empty_str.as_str()],
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
    let out = run(
        &["resume", scan_id.as_str(), "--format", "human"],
        &env.cwd_b,
        &env.state,
    );
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
                    fetch: None,
                    workers: None,
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
            "--format",
            "human",
        ],
        &env.cwd_a,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&env.cwd_a.join("rep.json"));
    assert_eq!(report["schema_version"], "1.4.0");
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
            "--format",
            "human",
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
            "--format",
            "human",
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
    use repo_scan::scan_events::Cursor;

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

    // `--after` resumes strictly after the cursor: from the first envelope,
    // replay restarts at seq 2 and still ends at the terminal event.
    let cursor = Cursor {
        seq: lines[0]["seq"].as_u64().expect("seq u64"),
        catalog_rev: lines[0]["catalog_rev"].as_u64().expect("rev u64"),
        event_offset: lines[0]["event_offset"].as_u64().expect("off u64"),
    }
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

        // Store -> clone mapping from location_found paths (lossy display
        // keeps our ASCII dir names intact).
        let rows = store
            .read_scan_events(&scan_id, 0, 1_000)
            .await
            .expect("read");
        let mut store_clone: HashMap<String, String> = HashMap::new();
        let mut store_groups: HashMap<String, Vec<String>> = HashMap::new();
        for row in &rows {
            let v: serde_json::Value = serde_json::from_slice(&row.records).expect("json");
            if row.event_type == "location_found" {
                let path = v["path"].as_str().expect("path").to_string();
                let name = ["clone-a", "clone-b", "clone-c"]
                    .into_iter()
                    .find(|n| path.contains(n))
                    .expect("fixture clone path");
                store_clone.insert(
                    v["store_id"].as_str().expect("store").to_string(),
                    name.into(),
                );
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
                .entry(m.instance_id.clone())
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
        let up_store = &up_members[0].instance_id;
        assert_eq!(
            store_clone.get(up_store).map(String::as_str),
            Some("clone-c")
        );
        assert!(up_members.iter().all(|m| &m.instance_id == up_store));
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
            main_by_store.contains_key(up_store),
            "one store belongs to both groups"
        );
        let both = store.groups_for_instance(up_store).await.expect("groups");
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
            assert!(id.starts_with("gap:"), "gap id: {id}");
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
            let gap = store.get_error(id).await.expect("get").expect("gap row");
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
            assert_eq!(
                b["id"].as_str().expect("id").split(':').count(),
                3,
                "ref id"
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
        assert!(opened[0].starts_with("gap:"), "gap id: {}", opened[0]);
        assert!(closed.is_empty(), "no genuine closes: {closed:?}");
        let gap = store
            .get_error(&opened[0])
            .await
            .expect("get")
            .expect("gap row");
        assert!(gap.open, "opened id names an open row");
        // The remote-less clone joined as an unresolvable candidate.
        assert_eq!(unresolvable.len(), 1, "{unresolvable:?}");
        let instance = store
            .get_git_instance(&unresolvable[0])
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
        store.close().await.expect("close");
    });
}
