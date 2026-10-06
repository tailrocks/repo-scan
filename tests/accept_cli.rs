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
        let mut args = vec!["scan", URL, "--root", self.fixture_str.as_str()];
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
    assert_eq!(report["schema_version"].as_str(), Some("1.1.0"));
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
    let out = run(&["resume", scan_id.as_str()], &env.cwd_b, &env.state);
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
        let out = run(&["resume", scan_id.as_str()], &env.cwd_b, &env.state);
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
    let out = run(&["resume", scan_id.as_str()], &env.cwd_b, &env.state);
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
    let out = run(&["resume", stale_id], &env.cwd_b, &env.state);
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
    assert_eq!(report["schema_version"], "1.1.0");
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
