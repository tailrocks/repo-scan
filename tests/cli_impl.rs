//! CLI acceptance (CLI-01/02/03, CACHE-02): the six exact commands parse
//! with their spec §3 meanings, exit codes map per the exit table, resume
//! restores the absolute report destination across caller directories, and
//! cache clear preserves foreign files. Library-level checks plus
//! end-to-end runs of the built binary in tempdirs.

use clap::Parser;
use repo_scan::cli::{CacheAction, Cli, Command, OutputFormat, QuerySelection, TargetSet};
use repo_scan::config;
use repo_scan::model::{ExitCode, Scope, StatusMode};
use repo_scan::store::{Store, TursoStore};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

const URL: &str = "https://github.com/OWNER/REPO";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Run the binary with `--state-dir <state>` from `cwd`, returning output.
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

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn six_commands_parse() {
    // 1. scan with machine scope and a report destination.
    let cli = Cli::try_parse_from([
        "repo-scan",
        "scan",
        URL,
        "--scope",
        "machine",
        "--report",
        "repository-report.json",
    ])
    .expect("scan parses");
    match cli.command {
        Command::Scan(args) => {
            assert_eq!(args.targets, vec![URL.to_string()]);
            assert!(!args.all);
            assert!(matches!(args.scope, Scope::Machine));
            assert_eq!(args.report, Some(PathBuf::from("repository-report.json")));
            assert!(!args.force_rescan);
            assert!(matches!(args.status, StatusMode::Summary));
            assert!(args.root.is_empty());
        }
        _ => panic!("expected scan"),
    }
    // 2. cached query.
    let cli = Cli::try_parse_from(["repo-scan", "query", URL, "--cached"]).expect("query parses");
    match cli.command {
        Command::Query(args) => {
            assert_eq!(args.target.as_deref(), Some(URL));
            assert!(args.cached);
        }
        _ => panic!("expected query"),
    }
    // 3. resume.
    let cli = Cli::try_parse_from(["repo-scan", "resume", "SCAN_ID"]).expect("resume parses");
    match cli.command {
        Command::Resume(args) => assert_eq!(args.scan_id, "SCAN_ID"),
        _ => panic!("expected resume"),
    }
    // 4. force rescan.
    let cli = Cli::try_parse_from([
        "repo-scan",
        "scan",
        URL,
        "--scope",
        "machine",
        "--force-rescan",
    ])
    .expect("force scan parses");
    match cli.command {
        Command::Scan(args) => assert!(args.force_rescan),
        _ => panic!("expected scan"),
    }
    // 5. cache invalidate.
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
    // 6. cache clear.
    let cli = Cli::try_parse_from(["repo-scan", "cache", "clear", "--all"]).expect("clear parses");
    match cli.command {
        Command::Cache(args) => match args.action {
            CacheAction::Clear(args) => assert!(args.all),
            _ => panic!("expected clear"),
        },
        _ => panic!("expected cache"),
    }
}

#[test]
fn optional_controls_parse_without_changing_commands() {
    let cli = Cli::try_parse_from([
        "repo-scan",
        "--state-dir",
        "/tmp/custom-state",
        "scan",
        URL,
        "--status",
        "full",
        "--root",
        "/tmp/a",
        "--root",
        "/tmp/b",
    ])
    .expect("optional controls parse");
    assert_eq!(cli.state_dir, Some(PathBuf::from("/tmp/custom-state")));
    match cli.command {
        Command::Scan(args) => {
            assert!(matches!(args.status, StatusMode::Full));
            assert_eq!(
                args.root,
                vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")]
            );
        }
        _ => panic!("expected scan"),
    }
    let cli = Cli::try_parse_from(["repo-scan", "scan", URL, "--status", "metadata"])
        .expect("metadata parses");
    match cli.command {
        Command::Scan(args) => assert!(matches!(args.status, StatusMode::Metadata)),
        _ => panic!("expected scan"),
    }
}

#[test]
fn exit_code_mapping() {
    use repo_scan::Error;
    for (error, expected) in [
        (Error::InvalidArgs(String::new()), ExitCode::InvalidArgs),
        (Error::Config(String::new()), ExitCode::InvalidArgs),
        (Error::UnknownScan(String::new()), ExitCode::InvalidArgs),
        (Error::Store(String::new()), ExitCode::OperationalFailure),
        (
            Error::Scheduler(String::new()),
            ExitCode::OperationalFailure,
        ),
        (Error::Git(String::new()), ExitCode::OperationalFailure),
        (Error::Events(String::new()), ExitCode::OperationalFailure),
        (Error::Report(String::new()), ExitCode::OperationalFailure),
        (Error::Platform(String::new()), ExitCode::OperationalFailure),
        (Error::Io(String::new()), ExitCode::OperationalFailure),
        (
            Error::OwnerBusy(String::new()),
            ExitCode::OperationalFailure,
        ),
        (
            Error::UnknownTask(String::new()),
            ExitCode::OperationalFailure,
        ),
        (
            Error::LeaseMismatch(String::new()),
            ExitCode::OperationalFailure,
        ),
        (
            Error::StaleCompletion(String::new()),
            ExitCode::OperationalFailure,
        ),
        (Error::Walk(String::new()), ExitCode::Incomplete),
        (
            Error::UnresolvableIdentity(String::new()),
            ExitCode::Incomplete,
        ),
        (Error::Incomplete(String::new()), ExitCode::Incomplete),
        (Error::Superseded(String::new()), ExitCode::Incomplete),
        (Error::Interrupted, ExitCode::Interrupted),
    ] {
        assert_eq!(error.exit_code(), expected, "{error:?}");
    }
    assert_eq!(ExitCode::Success.code(), 0);
    assert_eq!(ExitCode::OperationalFailure.code(), 1);
    assert_eq!(ExitCode::InvalidArgs.code(), 2);
    assert_eq!(ExitCode::Incomplete.code(), 3);
    assert_eq!(ExitCode::Interrupted.code(), 130);
}

#[test]
fn state_dir_resolution_is_absolute_once() {
    let abs = config::resolve_state_dir(None).expect("default resolves");
    assert!(abs.is_absolute());
    let cwd = std::env::current_dir().expect("cwd");
    let rel = config::resolve_state_dir(Some(PathBuf::from("rel-state"))).expect("relative");
    assert_eq!(rel, cwd.join("rel-state"));
    // Lexical cleanup without filesystem access.
    let messy = config::resolve_state_dir(Some(PathBuf::from("/tmp/a/../b/./c"))).expect("clean");
    assert_eq!(messy, PathBuf::from("/tmp/b/c"));
}

#[test]
fn tilde_expansion_uses_home() {
    let home = tempfile::tempdir().expect("tempdir");
    std::env::set_var("HOME", home.path());
    let out = config::resolve_state_dir(Some(PathBuf::from("~/x"))).expect("tilde");
    assert_eq!(out, home.path().join("x"));
}

#[test]
fn report_dest_resolution() {
    let cwd = std::env::current_dir().expect("cwd");
    let rel = config::resolve_report_dest(Path::new("rep.json")).expect("relative");
    assert_eq!(rel, cwd.join("rep.json"));
    let abs = config::resolve_report_dest(Path::new("/tmp/r.json")).expect("absolute");
    assert_eq!(abs, PathBuf::from("/tmp/r.json"));
    let err = config::resolve_report_dest(Path::new("")).expect_err("empty rejected");
    assert_eq!(err.exit_code(), ExitCode::InvalidArgs);
}

#[test]
fn outcome_roundtrip() {
    let encoded = config::encode_outcome(3, Some(3), "report-scan-1", false, Some(7));
    let decoded = config::parse_outcome(&encoded).expect("parses");
    assert_eq!(decoded.exit_code, 3);
    assert_eq!(decoded.discovery_code, Some(3));
    assert_eq!(decoded.report_id, "report-scan-1");
    assert!(!decoded.published);
    assert_eq!(decoded.generation, Some(7));
    assert!(config::parse_outcome("exit=0 report=r published=1").is_some());
    assert!(config::parse_outcome("garbage").is_none());
    assert!(config::parse_outcome("exit=0 published=1").is_none());
    assert!(config::parse_outcome("exit=bogus report=r published=1").is_none());
}

#[test]
fn scope_key_roundtrip() {
    let dir = PathBuf::from("/tmp/some dir/repo");
    let key = config::scope_key_for_dir(&dir);
    assert_eq!(
        config::parse_scope_key(&key),
        Some(config::ScopeRef::Dir(dir))
    );
    let git = PathBuf::from("/repo.git");
    let key = config::scope_key_for_git(&git);
    assert_eq!(
        config::parse_scope_key(&key),
        Some(config::ScopeRef::Git(git))
    );
    let key = config::scope_key_for_status("co:ab12");
    assert_eq!(
        config::parse_scope_key(&key),
        Some(config::ScopeRef::Status(String::from("co:ab12")))
    );
    assert_eq!(config::parse_scope_key("bogus"), None);
    assert_eq!(config::parse_scope_key("dir:zz"), None);
    assert_eq!(config::parse_scope_key("status:a/b"), None);
    assert_eq!(config::parse_scope_key("status:"), None);
}

#[cfg(unix)]
#[test]
fn scope_key_roundtrip_non_utf8() {
    use std::os::unix::ffi::OsStringExt;
    let raw = vec![0xff, 0xfe, b'/', 0x80];
    let path = PathBuf::from(std::ffi::OsString::from_vec(raw.clone()));
    let key = config::scope_key_for_dir(&path);
    assert_eq!(
        config::parse_scope_key(&key),
        Some(config::ScopeRef::Dir(path))
    );
    assert_eq!(config::decode_hex("ff"), Some(vec![0xff]));
    assert_eq!(config::decode_hex("f"), None);
}

#[test]
fn snapshot_path_rejects_traversal() {
    let state = PathBuf::from("/tmp/state");
    let ok = config::snapshot_path(&state, "report-scan-1").expect("safe id");
    assert_eq!(
        ok,
        state
            .join("payload")
            .join("report-snapshots")
            .join("report-scan-1.json")
    );
    assert!(config::snapshot_path(&state, "../evil").is_err());
    assert!(config::snapshot_path(&state, "a/b").is_err());
    assert!(config::snapshot_path(&state, "").is_err());
    assert!(config::snapshot_path(&state, "..").is_err());
}

#[test]
fn scan_state_roots_roundtrip() {
    let roots = vec![PathBuf::from("/a"), PathBuf::from("/b c")];
    let state = config::scan_state_name("running", Some(&roots));
    let (base, restored) = config::split_scan_state(&state);
    assert_eq!(base, "running");
    assert_eq!(restored, Some(roots));
    // Terminal states stay bare.
    assert_eq!(
        config::scan_state_name("complete", Some(&[PathBuf::from("/a")])),
        "complete"
    );
    let (base, restored) = config::split_scan_state("complete");
    assert_eq!((base, restored), ("complete", None));
    assert_ne!(config::new_scan_id(), config::new_scan_id());
}

#[test]
fn binary_query_without_catalog_exit_3() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let out = run(&["query", URL, "--cached"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("suitable_catalog: false"), "{stdout}");
    // Nothing was created for a read-only miss.
    assert!(!state.join("payload").join("catalog.db").exists());
}

#[test]
fn binary_resume_unknown_exit_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let out = run(&["resume", "scan-no-such"], dir.path(), &state);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr_text(&out).contains("unknown scan"),
        "stderr: {}",
        stderr_text(&out)
    );
}

#[test]
fn binary_clear_requires_all() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let out = run(&["cache", "clear"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr_text(&out));
}

#[test]
fn binary_clear_preserves_foreign_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let payload = state.join("payload");
    repo_scan::privacy::private_dir_0700(&payload.join("report-snapshots")).expect("mkdir");
    // A real catalog plus tool-owned snapshot bytes.
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let store = TursoStore::open(&payload.join("catalog.db"))
            .await
            .expect("open");
        store.close().await.expect("close");
    });
    // Tool-owned snapshot bytes: tool-marker fields bound to the filename.
    let owned_report = "{\"schema_version\":\"1.0.0\",\
        \"tool\":{\"name\":\"repo-scan\",\"version\":\"test\"},\
        \"report_id\":\"report-x\"}";
    repo_scan::privacy::private_write_0600(
        &payload.join("report-snapshots").join("report-x.json"),
        owned_report.as_bytes(),
    )
    .expect("write");
    // Foreign files that must survive.
    repo_scan::privacy::private_write_0600(&payload.join("notes.txt"), "mine".as_bytes())
        .expect("write");
    repo_scan::privacy::private_dir_0700(&payload.join("other")).expect("mkdir");
    repo_scan::privacy::private_write_0600(&payload.join("other").join("keep"), "mine".as_bytes())
        .expect("write");
    repo_scan::privacy::private_write_0600(&state.join("keep.txt"), "mine".as_bytes())
        .expect("write");

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(!payload.join("catalog.db").exists());
    assert!(!payload
        .join("report-snapshots")
        .join("report-x.json")
        .exists());
    assert!(payload.join("notes.txt").exists());
    assert!(payload.join("other").join("keep").exists());
    assert!(state.join("keep.txt").exists());
    assert!(state.join("instance.lock").exists());
}

#[test]
fn binary_scan_resume_query_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let fixture = dir.path().join("fixture");
    repo_scan::privacy::private_dir_0700(&fixture.join("a").join("b")).expect("mkdir");
    repo_scan::privacy::private_write_0600(&fixture.join("a").join("file.txt"), "hello".as_bytes())
        .expect("write");
    repo_scan::privacy::private_write_0600(&fixture.join("top.txt"), "top".as_bytes())
        .expect("write");
    let cwd_a = dir.path().join("cwd-a");
    let cwd_b = dir.path().join("cwd-b");
    repo_scan::privacy::private_dir_0700(&cwd_a).expect("mkdir");
    repo_scan::privacy::private_dir_0700(&cwd_b).expect("mkdir");
    let fixture_str = fixture.to_str().expect("utf8").to_string();

    // Scan with a relative --report from cwd-a: the destination resolves
    // absolutely at request creation.
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            fixture_str.as_str(),
            "--report",
            "rep.json",
        ],
        &cwd_a,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id = stdout_line(&out, "scan_id");
    assert!(scan_id.starts_with("scan-"), "{scan_id}");
    let report_path = cwd_a.join("rep.json");
    assert!(report_path.exists());
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).expect("read")).expect("json");
    assert_eq!(report["schema_version"].as_str(), Some("1.0.0"));
    assert_eq!(report["tool"]["name"].as_str(), Some("repo-scan"));
    assert_eq!(report["scan"]["scope"].as_str(), Some("roots"));
    assert_eq!(report["scan"]["state"].as_str(), Some("complete"));
    assert_eq!(report["coverage"]["filesystem"].as_str(), Some("complete"));
    assert_eq!(report["coverage"]["gaps"].as_u64(), Some(0));
    let generation = report["scan"]["generation"].as_u64().expect("generation");

    // A second scan reuses the generation (fast catalog reuse, same id).
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            fixture_str.as_str(),
            "--report",
            "rep.json",
        ],
        &cwd_a,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let scan_id_2 = stdout_line(&out, "scan_id");
    assert_ne!(scan_id, scan_id_2);
    let report2: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).expect("read")).expect("json");
    #[cfg(target_os = "macos")]
    assert_eq!(report2["scan"]["generation"].as_u64(), Some(generation));
    #[cfg(not(target_os = "macos"))]
    assert_ne!(report2["scan"]["generation"].as_u64(), Some(generation));

    // Force rescan mints a fresh generation.
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            fixture_str.as_str(),
            "--report",
            "rep.json",
            "--force-rescan",
        ],
        &cwd_a,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report3: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).expect("read")).expect("json");
    assert_ne!(
        report3["scan"]["generation"].as_u64().expect("generation"),
        generation
    );

    // Resume the completed first scan from a different cwd: idempotent
    // terminal replay, no rescan, absolute destination intact.
    let out = run(&["resume", scan_id.as_str()], &cwd_b, &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("replayed"), "{stdout}");
    assert_eq!(stdout_line(&out, "scan_id"), scan_id);
    assert!(report_path.exists());

    // Cached query serves state only and says so.
    let out = run(&["query", URL, "--cached"], &cwd_b, &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("cached: true"), "{stdout}");

    // Unresolvable query shape: exit 3, no probe.
    let out = run(&["query", "not-a-url", "--cached"], &cwd_b, &state);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));

    // Invalidate one area: durable, with no completion claim.
    let sub = fixture.join("a").to_str().expect("utf8").to_string();
    let out = run(
        &["cache", "invalidate", "--root", sub.as_str()],
        &cwd_b,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("not complete"), "{stdout}");

    // The next scan reconciles the invalidated scope.
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            fixture_str.as_str(),
            "--report",
            "rep.json",
        ],
        &cwd_a,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
}

#[test]
fn step6_scan_targets_parse_and_validate() {
    // Multi-target scan with roots, format, fetch, color.
    let cli = Cli::try_parse_from([
        "repo-scan",
        "scan",
        "tailrocks/repo-scan",
        "jackin-project/jackin",
        "--root",
        "/Users",
        "--root",
        "/Volumes",
        "--format",
        "jsonl",
        "--fetch",
        "--color",
        "never",
    ])
    .expect("multi-target scan parses");
    match cli.command {
        Command::Scan(args) => {
            assert_eq!(
                args.target_set().expect("valid targets"),
                TargetSet::Targets(vec![
                    "tailrocks/repo-scan".to_string(),
                    "jackin-project/jackin".to_string()
                ])
            );
            assert_eq!(args.format, Some(OutputFormat::Jsonl));
            assert!(args.fetch);
            assert_eq!(args.root.len(), 2);
        }
        _ => panic!("expected scan"),
    }
    // --all scan.
    let cli = Cli::try_parse_from(["repo-scan", "scan", "--all", "--format", "human"])
        .expect("--all scan parses");
    match cli.command {
        Command::Scan(args) => {
            assert_eq!(args.target_set().expect("valid --all"), TargetSet::All);
            assert_eq!(args.format, Some(OutputFormat::Human));
        }
        _ => panic!("expected scan"),
    }
    // Contradictory: --all with targets.
    let cli = Cli::try_parse_from(["repo-scan", "scan", "--all", "owner/repo"])
        .expect("contradictory scan parses (validation rejects)");
    match cli.command {
        Command::Scan(args) => assert!(args.target_set().is_err()),
        _ => panic!("expected scan"),
    }
    // Contradictory: neither targets nor --all.
    let cli = Cli::try_parse_from(["repo-scan", "scan"]).expect("bare scan parses");
    match cli.command {
        Command::Scan(args) => assert!(args.target_set().is_err()),
        _ => panic!("expected scan"),
    }
}

#[test]
fn step6_query_resume_parse_and_validate() {
    // query --all --cached --format json.
    let cli = Cli::try_parse_from([
        "repo-scan", "query", "--all", "--cached", "--format", "json",
    ])
    .expect("query --all parses");
    match cli.command {
        Command::Query(args) => {
            assert_eq!(args.selection().expect("valid"), QuerySelection::All);
            assert!(!args.follow);
        }
        _ => panic!("expected query"),
    }
    // query --scan with follow + cursor.
    let cli = Cli::try_parse_from([
        "repo-scan",
        "query",
        "--scan",
        "SCAN_ID",
        "--follow",
        "--format",
        "jsonl",
        "--after",
        "CURSOR",
    ])
    .expect("query --scan parses");
    match cli.command {
        Command::Query(args) => {
            assert_eq!(
                args.selection().expect("valid"),
                QuerySelection::Scan("SCAN_ID".to_string())
            );
            assert!(args.follow);
        }
        _ => panic!("expected query"),
    }
    // Rejected: --follow --format json.
    let cli = Cli::try_parse_from([
        "repo-scan",
        "query",
        "--scan",
        "SCAN_ID",
        "--follow",
        "--format",
        "json",
    ])
    .expect("follow+json parses (validation rejects)");
    match cli.command {
        Command::Query(args) => assert!(args.selection().is_err()),
        _ => panic!("expected query"),
    }
    // Rejected: --after without --follow.
    let cli = Cli::try_parse_from(["repo-scan", "query", "--all", "--after", "CURSOR"])
        .expect("after-without-follow parses (validation rejects)");
    match cli.command {
        Command::Query(args) => assert!(args.selection().is_err()),
        _ => panic!("expected query"),
    }
    // Rejected: target + --all together.
    let cli = Cli::try_parse_from(["repo-scan", "query", "owner/repo", "--all", "--cached"])
        .expect("target+all parses (validation rejects)");
    match cli.command {
        Command::Query(args) => assert!(args.selection().is_err()),
        _ => panic!("expected query"),
    }
    // resume with format.
    let cli = Cli::try_parse_from(["repo-scan", "resume", "SCAN_ID", "--format", "jsonl"])
        .expect("resume parses");
    match cli.command {
        Command::Resume(args) => {
            assert_eq!(args.scan_id, "SCAN_ID");
            assert_eq!(args.format, Some(OutputFormat::Jsonl));
        }
        _ => panic!("expected resume"),
    }
}
