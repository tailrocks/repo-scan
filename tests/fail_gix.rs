//! Fail-gix boundary regression tests: gix status must never execute
//! repo-selected clean/smudge/process filter drivers (EXACT-2 defect 1).
//! Fixtures live under `/tmp` only via `tempfile` (0700); the marker
//! helpers are tiny shell scripts (<4 KiB total custom data). No `git`
//! invocation runs after a filter is configured, so a marker file can
//! only be written by the gix status path under test.

#[cfg(unix)]
mod common;

#[cfg(unix)]
use common::fixture;
#[cfg(unix)]
use repo_scan::git::{
    filter_driver_gap, GitInspect, GixInspector, FILTER_DRIVER_GAP, UNSUPPORTED_MARKER,
};
#[cfg(unix)]
use repo_scan::model::StatusMode;
#[cfg(unix)]
use std::path::Path;

/// Mark `path` executable (0700-rooted `tempfile` fixture binaries).
#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

/// Write a marker helper: touches `marker`, then passes stdin through
/// (valid `clean` behavior). Absolute paths keep it cwd-independent.
#[cfg(unix)]
fn write_marker_helper(helper: &Path, marker: &Path) {
    let script = format!("#!/bin/sh\ntouch '{}'\ncat\n", marker.display());
    repo_scan::privacy::private_write_0600(helper, script.as_bytes()).unwrap();
    make_executable(helper);
}

/// Dirty `file` with same-byte-length content and a pinned mtime.
/// Same size matters: gix `FastEq` short-circuits size mismatches
/// without reading content, so only a same-size change reaches the
/// `convert_to_git` filter pipeline; the pinned mtime defeats the
/// stat-match early-out deterministically on any mtime granularity.
#[cfg(unix)]
fn dirty_same_size(file: &Path, contents: &str) {
    let before = std::fs::read(file).unwrap();
    assert_eq!(
        before.len(),
        contents.len(),
        "fixture must keep size to reach content comparison"
    );
    repo_scan::privacy::private_write_0600(file, contents.as_bytes()).unwrap();
    let fixed = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    std::fs::File::options()
        .write(true)
        .open(file)
        .unwrap()
        .set_modified(fixed)
        .unwrap();
}

/// EXACT-2 defect 1 (parent): a repo with `.gitattributes` selecting a
/// configured clean/smudge driver must refuse gix status with an
/// explicit gap — never execute the helper. Pre-fix this probe ran the
/// driver (marker written) and returned counts.
#[cfg(unix)]
#[test]
fn gix_status_refuses_configured_filter_drivers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let parent = tmp.path().join("repos");
    repo_scan::privacy::private_dir_0700(&parent).unwrap();
    let repo = fixture::normal_clone(&parent, "filtered");
    let marker = tmp.path().join("marker");
    let helper = tmp.path().join("helper.sh");
    write_marker_helper(&helper, &marker);

    repo_scan::privacy::private_write_0600(
        &repo.join(".gitattributes"),
        "*.md filter=marker\n".as_bytes(),
    )
    .unwrap();
    let config_path = repo.join(".git/config");
    let mut text = std::fs::read_to_string(&config_path).unwrap();
    text.push_str(&format!(
        "\n[filter \"marker\"]\n\tclean = {}\n\tsmudge = {}\n",
        helper.display(),
        helper.display()
    ));
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    // README.md is `# fixture\n` (10 bytes); keep the size, change content.
    dirty_same_size(&repo.join("README.md"), "# FIXTURE\n");
    assert!(
        !marker.exists(),
        "no git op ran after configuring the filter"
    );

    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&repo).expect("open filtered");
    let gap = filter_driver_gap(&instance).expect("gap must flag drivers");
    assert!(gap.starts_with(FILTER_DRIVER_GAP), "{gap}");

    for mode in [StatusMode::Summary, StatusMode::Full] {
        let err = inspector
            .status(&instance, mode)
            .expect_err("status must refuse drivers");
        let message = err.to_string();
        assert!(
            message.contains(UNSUPPORTED_MARKER) && message.contains(FILTER_DRIVER_GAP),
            "explicit gap refusal, got {message}"
        );
    }
    assert!(
        !marker.exists(),
        "refused probe must not execute the helper"
    );

    // Metadata mode converts no content, so it legitimately skips refusal.
    let metadata = inspector
        .status(&instance, StatusMode::Metadata)
        .expect("metadata skips content conversion");
    assert_eq!(metadata.staged, None);
    assert!(
        !marker.exists(),
        "metadata probe must not execute the helper"
    );
}

/// EXACT-2 defect 1 (submodule): parent status recurses into submodule
/// worktrees internally, so submodule-configured drivers must refuse
/// the parent probe too — never execute inside the recursion.
#[cfg(unix)]
#[test]
fn gix_status_refuses_submodule_filter_drivers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let parent = tmp.path().join("repos");
    repo_scan::privacy::private_dir_0700(&parent).unwrap();
    let (sup, sub) = fixture::submodule_repo(&parent);
    let marker = tmp.path().join("sub-marker");
    let helper = tmp.path().join("sub-helper.sh");
    write_marker_helper(&helper, &marker);

    repo_scan::privacy::private_write_0600(
        &sub.join(".gitattributes"),
        "*.md filter=submarker\n".as_bytes(),
    )
    .unwrap();
    let sub_config = sup.join(".git/modules/vendor/sub/config");
    assert!(sub_config.is_file(), "absorbed submodule config");
    let mut text = std::fs::read_to_string(&sub_config).unwrap();
    text.push_str(&format!(
        "\n[filter \"submarker\"]\n\tclean = {}\n\tprocess = {}\n",
        helper.display(),
        helper.display()
    ));
    repo_scan::privacy::private_write_0600(&sub_config, text.as_bytes()).unwrap();
    dirty_same_size(&sub.join("README.md"), "# FIXTURE\n");

    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&sup).expect("open super");
    let gap = filter_driver_gap(&instance).expect("gap must flag submodule drivers");
    assert!(gap.starts_with(FILTER_DRIVER_GAP), "{gap}");

    let err = inspector
        .status(&instance, StatusMode::Summary)
        .expect_err("parent status must refuse submodule drivers");
    let message = err.to_string();
    assert!(
        message.contains(UNSUPPORTED_MARKER) && message.contains(FILTER_DRIVER_GAP),
        "explicit gap refusal, got {message}"
    );
    assert!(
        !marker.exists(),
        "refused probe must not execute the submodule helper"
    );
}

/// Gap shapes: plain repos stay clean, `required`-only sections are
/// inert (no command keys), process-only and case-variant drivers
/// refuse, and non-filter sections never match.
#[cfg(unix)]
#[test]
fn filter_driver_gap_shapes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let parent = tmp.path().join("repos");
    repo_scan::privacy::private_dir_0700(&parent).unwrap();
    let inspector = GixInspector::new();

    let plain = fixture::normal_clone(&parent, "plain");
    let plain_instance = inspector.open_exact(&plain).expect("open plain");
    assert!(filter_driver_gap(&plain_instance).is_none());
    assert!(inspector
        .status(&plain_instance, StatusMode::Summary)
        .is_ok());

    for (name, stanza, expect_gap) in [
        (
            "required-only",
            "[filter \"x\"]\n\trequired = true\n",
            false,
        ),
        (
            "process-only",
            "[filter \"p\"]\n\tprocess = /bin/false\n",
            true,
        ),
        (
            "case-variant",
            "[FILTER \"c\"]\n\tCLEAN = /bin/false\n",
            true,
        ),
        ("non-filter", "[core]\n\tclean = true\n", false),
    ] {
        let repo = fixture::normal_clone(&parent, name);
        let config_path = repo.join(".git/config");
        let mut text = std::fs::read_to_string(&config_path).unwrap();
        text.push('\n');
        text.push_str(stanza);
        repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
        let instance = inspector.open_exact(&repo).expect("open shaped");
        let gap = filter_driver_gap(&instance);
        assert_eq!(
            gap.as_ref().map(|g| g.starts_with(FILTER_DRIVER_GAP)),
            if expect_gap { Some(true) } else { None },
            "{name}: {gap:?}"
        );
        assert_eq!(
            inspector.status(&instance, StatusMode::Summary).is_ok(),
            !expect_gap,
            "{name} refusal must match the gap"
        );
    }
}

// ---------------------------------------------------------------------------
// FIXREADY4 F (47A7E507): no configured clean helper may execute during a
// `--status full` scan, whatever scope configured it. Root cause of the
// EXACT-2 miss: the guard scanned only repo-local configs (user/system/env
// were declared "operator trust domain") and the regression fixture
// configured repo-local drivers only — but the REPOSITORY selects which
// operator helper runs via `.gitattributes`, so a global helper is
// repo-selected code execution. Each case below spawns the binary with a
// hermetic env (exactly one scope carries the driver) and asserts the
// marker helper never ran while the scan still completes honestly.
// In-process tests cannot cover these scopes (HOME/env are process-global).
// ---------------------------------------------------------------------------

/// Binary path for the spawned scans.
#[cfg(unix)]
fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Filter-execution fixture: a matched repo (origin `OWNER/REPO`, so the
/// scheduler actually runs status) with TRACKED `.gitattributes`
/// selecting `filter=marker` plus a same-size dirty `README.md` with a
/// pinned mtime (size + mtime defeat the stat short-circuits so the
/// comparison reaches content conversion). Returns `(root, helper, marker)`.
/// No git op runs after the driver exists anywhere the scanner can see.
#[cfg(unix)]
fn filter_scan_fixture(
    scratch: &Path,
    name: &str,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let root = scratch.join(name);
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    let repo = fixture::normal_clone(&root, "filtered");
    let marker = scratch.join(format!("{name}-marker"));
    let helper = scratch.join(format!("{name}-helper.sh"));
    let script = format!("#!/bin/sh\n/usr/bin/touch '{}'\ncat\n", marker.display());
    repo_scan::privacy::private_write_0600(&helper, script.as_bytes()).unwrap();
    make_executable(&helper);
    fixture::commit_file(&repo, ".gitattributes", "*.md filter=marker\n", "attrs");
    // README.md is `# fixture\n` (10 bytes); keep the size, change content.
    dirty_same_size(&repo.join("README.md"), "# FIXTURE\n");
    assert!(!marker.exists(), "no git op ran after fixture setup");
    (root, helper, marker)
}

/// Spawn `scan --status full --report rep.json` with a hermetic config
/// env: ambient `GIT_CONFIG_*`/XDG injection is stripped, HOME is always
/// the caller fixture, and `extra` carries exactly the scope under test.
#[cfg(unix)]
fn run_filtered_scan(
    cwd: &Path,
    state: &Path,
    root: &Path,
    home: &Path,
    extra: &[(&str, &std::ffi::OsStr)],
) -> std::process::Output {
    let mut cmd = std::process::Command::new(binary());
    cmd.arg("--state-dir")
        .arg(state)
        .arg("scan")
        .arg("https://github.com/OWNER/REPO")
        .arg("--root")
        .arg(root)
        .arg("--status")
        .arg("full")
        .arg("--report")
        .arg("rep.json")
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("GIT_CONFIG_SYSTEM")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("XDG_CONFIG_HOME");
    for n in 0..8 {
        cmd.env_remove(format!("GIT_CONFIG_KEY_{n}"));
        cmd.env_remove(format!("GIT_CONFIG_VALUE_{n}"));
    }
    for (key, value) in extra {
        cmd.env(key, value);
    }
    cmd.output().expect("spawn repo-scan")
}

/// Assert one scope case: the scan completes honestly (usable report,
/// exit 0, checkout status `complete` with the dirty file counted) and
/// the marker helper never executed.
#[cfg(unix)]
fn assert_scope_case(
    scratch: &Path,
    case: &str,
    home: &Path,
    extra: &[(&str, &std::ffi::OsStr)],
    root: &Path,
    marker: &Path,
) {
    let cwd = scratch.join(format!("{case}-cwd"));
    let state = scratch.join(format!("{case}-state"));
    repo_scan::privacy::private_dir_0700(&cwd).unwrap();
    let out = run_filtered_scan(&cwd, &state, root, home, extra);
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "{case}: scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report_bytes = std::fs::read(cwd.join("rep.json")).expect("read report");
    let report: serde_json::Value = serde_json::from_slice(&report_bytes).expect("report JSON");
    assert!(
        !marker.exists(),
        "{case}: configured helper EXECUTED during scan"
    );
    // Honest completion: the isolated status still counts the dirty file.
    let checkouts = report
        .get("checkouts")
        .and_then(|v| v.as_array())
        .expect("checkouts array");
    assert_eq!(checkouts.len(), 1, "{case}: one checkout");
    let status = checkouts[0].get("status").expect("checkout status");
    assert_eq!(
        status.get("state").and_then(|s| s.as_str()),
        Some("complete"),
        "{case}: {status:?}"
    );
    assert_eq!(
        status.get("unstaged").and_then(|v| v.as_u64()),
        Some(1),
        "{case}: dirty file counted: {status:?}"
    );
}

/// Global scope: the helper lives only in fixture `$HOME/.gitconfig`
/// (the EXACT consumer shape). Pre-fix this executed the helper.
#[cfg(unix)]
#[test]
fn fixready4_global_filter_helper_never_executes() {
    let scratch = fixture::scratch_root("fail-gix-fixready4f-");
    let (root, helper, marker) = filter_scan_fixture(scratch.path(), "global");
    let home = scratch.path().join("home-global");
    repo_scan::privacy::private_dir_0700(&home).unwrap();
    let config = format!(
        "[filter \"marker\"]\n\tclean = {}\n\tsmudge = {}\n",
        helper.display(),
        helper.display()
    );
    repo_scan::privacy::private_write_0600(&home.join(".gitconfig"), config.as_bytes()).unwrap();
    assert_scope_case(scratch.path(), "global", &home, &[], &root, &marker);
}

/// System scope: the helper lives only in the file
/// `GIT_CONFIG_SYSTEM` points at (the only writable stand-in for the
/// system config in a test).
#[cfg(unix)]
#[test]
fn fixready4_system_filter_helper_never_executes() {
    let scratch = fixture::scratch_root("fail-gix-fixready4f-");
    let (root, helper, marker) = filter_scan_fixture(scratch.path(), "system");
    let home = scratch.path().join("home-system");
    repo_scan::privacy::private_dir_0700(&home).unwrap();
    let sys_config = scratch.path().join("gitconfig-system");
    let config = format!(
        "[filter \"marker\"]\n\tclean = {}\n\tsmudge = {}\n",
        helper.display(),
        helper.display()
    );
    repo_scan::privacy::private_write_0600(&sys_config, config.as_bytes()).unwrap();
    assert_scope_case(
        scratch.path(),
        "system",
        &home,
        &[("GIT_CONFIG_SYSTEM", sys_config.as_os_str())],
        &root,
        &marker,
    );
}

/// Env-injected scopes: `GIT_CONFIG_COUNT`/`KEY`/`VALUE` pairs and a
/// `GIT_CONFIG_GLOBAL` file redirect. Both must stay inert.
#[cfg(unix)]
#[test]
fn fixready4_env_filter_helper_never_executes() {
    let scratch = fixture::scratch_root("fail-gix-fixready4f-");
    let (root, helper, marker) = filter_scan_fixture(scratch.path(), "env");
    let home = scratch.path().join("home-env");
    repo_scan::privacy::private_dir_0700(&home).unwrap();
    // Pure env injection: no config file anywhere.
    assert_scope_case(
        scratch.path(),
        "env-count",
        &home,
        &[
            ("GIT_CONFIG_COUNT", std::ffi::OsStr::new("1")),
            (
                "GIT_CONFIG_KEY_0",
                std::ffi::OsStr::new("filter.marker.clean"),
            ),
            ("GIT_CONFIG_VALUE_0", helper.as_os_str()),
        ],
        &root,
        &marker,
    );
    // Env-redirected global file.
    let global_config = scratch.path().join("gitconfig-env-global");
    let config = format!(
        "[filter \"marker\"]\n\tclean = {}\n\tsmudge = {}\n",
        helper.display(),
        helper.display()
    );
    repo_scan::privacy::private_write_0600(&global_config, config.as_bytes()).unwrap();
    assert_scope_case(
        scratch.path(),
        "env-global",
        &home,
        &[("GIT_CONFIG_GLOBAL", global_config.as_os_str())],
        &root,
        &marker,
    );
}

/// Repo-local scope end to end: a repo-configured driver still refuses
/// with the explicit gap (never executes), and the scan completes with
/// the refusal honestly recorded in the report.
#[cfg(unix)]
#[test]
fn fixready4_repo_local_filter_still_refuses() {
    let scratch = fixture::scratch_root("fail-gix-fixready4f-");
    let (root, helper, marker) = filter_scan_fixture(scratch.path(), "local");
    let repo = root.join("filtered");
    let config_path = repo.join(".git/config");
    let mut text = std::fs::read_to_string(&config_path).unwrap();
    text.push_str(&format!(
        "\n[filter \"marker\"]\n\tclean = {}\n\tsmudge = {}\n",
        helper.display(),
        helper.display()
    ));
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    assert!(!marker.exists(), "no git op ran after configuring");
    let home = scratch.path().join("home-local");
    repo_scan::privacy::private_dir_0700(&home).unwrap();

    let cwd = scratch.path().join("local-cwd");
    let state = scratch.path().join("local-state");
    repo_scan::privacy::private_dir_0700(&cwd).unwrap();
    let out = run_filtered_scan(&cwd, &state, &root, &home, &[]);
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "local: scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report_bytes = std::fs::read(cwd.join("rep.json")).expect("read report");
    let report: serde_json::Value = serde_json::from_slice(&report_bytes).expect("report JSON");
    assert!(
        !marker.exists(),
        "local: configured helper EXECUTED during scan"
    );
    // Honest recording: both backends refused, so the checkout status
    // state is `unsupported` (never silent, never executed).
    let states: Vec<&str> = report
        .get("checkouts")
        .and_then(|v| v.as_array())
        .expect("checkouts array")
        .iter()
        .filter_map(|c| {
            c.get("status")
                .and_then(|s| s.get("state"))
                .and_then(|s| s.as_str())
        })
        .collect();
    assert_eq!(states, vec!["unsupported"], "local: {states:?}");
}
