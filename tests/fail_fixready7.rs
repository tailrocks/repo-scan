//! FIXREADY6 retest regressions: consumer FAILs 88117623 (remote-drop),
//! 47A7E507 (submodule filter execution, both backends), 2165D21F (false
//! complete/isolated declarations) + the resume-gap recommendation.
//!
//! - F1: one gix-unparseable remote must not fail the whole remote read:
//!   per-remote fault isolation, one REDACTED_URL row pair per unparseable
//!   remote, valid siblings unaffected, zero canary bytes in every sink.
//! - F2a (FAIL-1): gix parent-status recursion must not execute
//!   global-config filter drivers: recursion refused with a declared gap,
//!   marker absent, honest status.
//! - F2b (FAIL-2): the fallback `config --list` guard must also cover
//!   absorbed + live-enumerated (incl. nested non-absorbed) submodule
//!   configs; misses fail closed.
//! - F3: complete/isolated declarations only when every executed path was
//!   proven isolated; honest top-level isolated-complete still declares.
//! - F4: resumed retries clear stale in-flight-interrupt gaps (no
//!   permanent poison); resumed data identical to a fresh scan.
//!
//! Fixtures live under `/tmp` only (0700). CLI tests run with a fixture
//! HOME and stripped `GIT_CONFIG_*`/`XDG_CONFIG_HOME` (consumer parity).
//! Marker helpers are tiny shell scripts; no `git` invocation runs after
//! a filter is configured, so a marker can only be written by the code
//! under test.

#[cfg(unix)]
mod common;

#[cfg(unix)]
use common::fixture;
#[cfg(unix)]
use repo_scan::store::Store as _;
#[cfg(unix)]
use repo_scan::store::{now_ms, NewTask, TaskOutcome, TursoStore};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Command, Output, Stdio};
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Run the CLI with fixture HOME + stripped config env (consumer parity).
#[cfg(unix)]
fn run_isolated(state: &Path, home: &Path, args: &[&str], cwd: &Path) -> Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    Command::new(binary())
        .args(&full)
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("GIT_CONFIG_SYSTEM")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .expect("spawn repo-scan")
}

#[cfg(unix)]
fn stderr_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[cfg(unix)]
fn read_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).expect("read report");
    serde_json::from_slice(&bytes).expect("parse report")
}

#[cfg(unix)]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(unix)]
fn state_files(state: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![state.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !path.is_symlink() {
                stack.push(path);
            } else if path.is_file() {
                out.push(path);
            }
        }
    }
    out
}

/// Every durable byte under `state` (catalog.db+WAL, staging, snapshots,
/// marker/lock) must be free of `canary`.
#[cfg(unix)]
fn assert_no_canary_in_state(state: &Path, canary: &str) {
    for path in state_files(state) {
        let bytes = std::fs::read(&path).expect("read state file");
        assert!(
            !contains_bytes(&bytes, canary.as_bytes()),
            "canary in {}",
            path.display()
        );
    }
}

/// Report file + terminal stdout/stderr must be free of `canary`.
#[cfg(unix)]
fn assert_no_canary_in_outputs(report: &Path, out: &Output, canary: &str) {
    let bytes = std::fs::read(report).expect("read report");
    assert!(
        !contains_bytes(&bytes, canary.as_bytes()),
        "canary in report file"
    );
    assert!(
        !contains_bytes(&out.stdout, canary.as_bytes()),
        "canary in stdout"
    );
    assert!(
        !contains_bytes(&out.stderr, canary.as_bytes()),
        "canary in stderr"
    );
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

/// Marker helper: touches `marker`, logs PPID/argv, passes stdin through
/// (valid `clean` behavior). Absolute paths keep it cwd-independent.
#[cfg(unix)]
fn write_marker_helper(helper: &Path, marker: &Path, log: &Path) {
    let script = format!(
        "#!/bin/sh\necho \"PPID=$PPID ARGV=$*\" >> '{}'\ntouch '{}'\ncat\n",
        log.display(),
        marker.display()
    );
    repo_scan::privacy::private_write_0600(helper, script.as_bytes()).unwrap();
    make_executable(helper);
}

/// Dirty `file` with same-byte-length content and a pinned mtime, forcing
/// content comparison past size/stat short-circuits.
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

/// Append a raw `[remote "name"]` section (exact bytes, no git CLI
/// validation) for gix-unparseable URL shapes.
#[cfg(unix)]
fn add_remote_direct(repo: &Path, name: &str, url: &str) {
    let config_path = repo.join(".git/config");
    let mut text = std::fs::read_to_string(&config_path).unwrap();
    text.push_str(&format!(
        "\n[remote \"{name}\"]\n\turl = {url}\n\tfetch = +refs/heads/*:refs/remotes/{name}/*\n"
    ));
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
}

#[cfg(unix)]
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

/// F1 (88117623): the exact consumer repro — valid origin + m1
/// `https://userZWQ@` — must keep the repo visible with its valid rows
/// plus one REDACTED_URL row pair for m1, and zero canary bytes in
/// report, catalog/state, snapshot, terminal stdout/stderr. Pre-fix the
/// whole remote read failed (repositories=[], remotes=[], exit 3).
#[cfg(unix)]
#[test]
fn f1_unsupported_remote_isolated_consumer_repro() {
    let tmp = fixture::scratch_root("fr7-f1-");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    let repo = fixture::normal_clone(&root, "repo");
    add_remote_direct(&repo, "m1", "https://userZWQ@");
    let canary = "userZWQ";

    let state = tmp.path().join("state");
    let home = tmp.path().join("home");
    repo_scan::privacy::private_dir_0700(&home).unwrap();
    let report = tmp.path().join("s.json");
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            root.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            "--status",
            "full",
            "--force-rescan",
        ],
        tmp.path(),
    );
    assert!(
        out.status.code() == Some(0) || out.status.code() == Some(3),
        "scan runs: {}",
        stderr_text(&out)
    );
    let parsed = read_json(&report);
    let repos = parsed["repositories"].as_array().expect("repositories");
    assert_eq!(repos.len(), 1, "repo visible: {parsed:?}");
    let remotes = parsed["remotes"].as_array().expect("remotes");
    let origin_rows: Vec<_> = remotes
        .iter()
        .filter(|r| {
            r["url"]
                .as_str()
                .unwrap_or_default()
                .contains("github.com/OWNER/REPO")
        })
        .collect();
    assert_eq!(
        origin_rows.len(),
        2,
        "valid origin fetch+push rows survive: {remotes:?}"
    );
    let redacted_rows: Vec<_> = remotes
        .iter()
        .filter(|r| r["url"].as_str() == Some(repo_scan::identity::REDACTED_URL))
        .collect();
    assert_eq!(
        redacted_rows.len(),
        2,
        "one REDACTED_URL row pair for m1: {remotes:?}"
    );
    let roles: Vec<_> = redacted_rows
        .iter()
        .map(|r| r["role"].as_str().unwrap_or_default())
        .collect();
    assert!(
        roles.contains(&"fetch") && roles.contains(&"push"),
        "{roles:?}"
    );
    assert_no_canary_in_outputs(&report, &out, canary);
    assert_no_canary_in_state(&state, canary);
}

/// F1 (88117623): all 11 gix-unparseable instance shapes — malformed
/// userinfo (d01-d03), file:/:// smuggle (d04/d05), `::ZWQ` (d07),
/// scheme validation (d09-d11), VT in https URL (d12), ext-space (d16)
/// — each alongside a valid origin: every repo stays visible with its
/// valid rows plus REDACTED_URL rows, zero per-shape canary bytes in
/// every sink. Pre-fix every shape failed the whole read (remotes=[]).
#[cfg(unix)]
#[test]
fn f1_unsupported_remote_eleven_shapes() {
    // (tag, url shape, per-shape canary planted in the shape)
    let shapes: Vec<(&str, String, &str)> = vec![
        ("d01", "https://userZWQ01@".to_string(), "userZWQ01"),
        ("d02", "https://:ZWQ02pass@".to_string(), "ZWQ02pass"),
        ("d03", "https://us erZWQ03@host/".to_string(), "ZWQ03"),
        ("d04", "file:/://ZWQ04".to_string(), "ZWQ04"),
        ("d05", "https:///ZWQ05path".to_string(), "ZWQ05path"),
        ("d07", "::ZWQ06".to_string(), "ZWQ06"),
        ("d09", "://host/ZWQ07".to_string(), "ZWQ07"),
        ("d10", "9http://host/ZWQ08".to_string(), "ZWQ08"),
        ("d11", "ht tp://host/ZWQ09".to_string(), "ZWQ09"),
        ("d12", "https://host/\x0bZWQ10".to_string(), "ZWQ10"),
        ("d16", "ext ::/tmp/ZWQ11x".to_string(), "ZWQ11x"),
    ];
    let tmp = fixture::scratch_root("fr7-f1m-");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    for (tag, url, _) in &shapes {
        let repo = fixture::normal_clone(&root, tag);
        add_remote_direct(&repo, "m1", url);
    }

    let state = tmp.path().join("state");
    let home = tmp.path().join("home");
    repo_scan::privacy::private_dir_0700(&home).unwrap();
    let report = tmp.path().join("s.json");
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            root.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            "--status",
            "full",
            "--force-rescan",
        ],
        tmp.path(),
    );
    assert!(
        out.status.code() == Some(0) || out.status.code() == Some(3),
        "scan runs: {}",
        stderr_text(&out)
    );
    let parsed = read_json(&report);
    let repos = parsed["repositories"].as_array().expect("repositories");
    assert_eq!(repos.len(), 11, "all repos visible: {parsed:?}");
    let remotes = parsed["remotes"].as_array().expect("remotes");
    for repo_row in repos {
        let repo_id = repo_row["id"].as_str().expect("repo id");
        let rows: Vec<_> = remotes
            .iter()
            .filter(|r| r["repository_id"].as_str() == Some(repo_id))
            .collect();
        assert!(
            rows.iter().any(|r| r["url"]
                .as_str()
                .unwrap_or_default()
                .contains("github.com/OWNER/REPO")),
            "valid origin row for {repo_id}: {rows:?}"
        );
        assert!(
            rows.iter()
                .any(|r| r["url"].as_str() == Some(repo_scan::identity::REDACTED_URL)),
            "REDACTED_URL row for {repo_id}: {rows:?}"
        );
    }
    for (_, _, canary) in &shapes {
        assert_no_canary_in_outputs(&report, &out, canary);
        assert_no_canary_in_state(&state, canary);
    }
}

/// FAIL-1/FAIL-2 shared layout: parent + live submodule, submodule
/// `.gitattributes` selecting `filter=marker`, same-size dirty
/// `README.md` with pinned mtime (forces content comparison). The
/// superproject origin already matches the scan target (status runs).
/// Returns `(roots, sup, sub, marker, helper, log)`. No driver is
/// configured: the caller plants it LAST, then scans without any
/// further `git` invocation, so a marker can only be written by the
/// code under test.
#[cfg(unix)]
fn marker_submodule_layout(
    tmp: &Path,
    tag: &str,
) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let roots = tmp.join(format!("roots-{tag}"));
    repo_scan::privacy::private_dir_0700(&roots).unwrap();
    let (sup, sub) = fixture::submodule_repo(&roots);
    repo_scan::privacy::private_write_0600(
        &sub.join(".gitattributes"),
        "*.md filter=marker\n".as_bytes(),
    )
    .unwrap();
    dirty_same_size(&sub.join("README.md"), "# FIXTURE\n");
    let marker = tmp.join(format!("{tag}-marker"));
    let helper = tmp.join(format!("{tag}-helper.sh"));
    let log = tmp.join(format!("{tag}-helper.log"));
    write_marker_helper(&helper, &marker, &log);
    assert!(!marker.exists(), "no git op ran after filter setup");
    (roots, sup, sub, marker, helper, log)
}

/// Find the parent checkout row by its stable `co:<hex-gitdir>` id.
#[cfg(unix)]
fn parent_checkout<'a>(parsed: &'a serde_json::Value, sup: &Path) -> &'a serde_json::Value {
    let want = format!(
        "co:{}",
        repo_scan::config::encode_hex(&repo_scan::config::path_as_bytes(&sup.join(".git")))
    );
    parsed["checkouts"]
        .as_array()
        .expect("checkouts")
        .iter()
        .find(|c| c["id"].as_str() == Some(want.as_str()))
        .unwrap_or_else(|| panic!("parent checkout {want}: {:?}", parsed["checkouts"]))
}

#[cfg(unix)]
fn status_unknown(checkout: &serde_json::Value) -> Vec<String> {
    checkout["status"]["unknown_fields"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

#[cfg(unix)]
fn declares_isolated_scope(checkout: &serde_json::Value) -> bool {
    status_unknown(checkout)
        .iter()
        .any(|f| f.contains("isolated-config-scope"))
}

/// F2a (47A7E507 FAIL-1): driver only in fixture-HOME global config,
/// live submodule, `.gitattributes filter=marker`, same-size dirty file,
/// pinned mtime — the exact consumer repro. The marker must be ABSENT
/// (gix recursion refused with a declared gap, never executing) and the
/// parent status honest: complete only via the proven-isolated fallback
/// serving after the declared recursion gap, else incomplete with no
/// isolated-scope declaration. Pre-fix the helper executed in-process
/// (PPID = repo-scan) with complete + isolated declaration.
#[cfg(unix)]
#[test]
fn f2a_fail1_global_driver_no_execution_honest_status() {
    let tmp = fixture::scratch_root("fr7-f2a-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "r1");
    // Driver ONLY in fixture-HOME global config (LAST setup step).
    let home = tmp.path().join("home-r1");
    repo_scan::privacy::private_dir_0700(&home).unwrap();
    repo_scan::privacy::private_write_0600(
        &home.join(".gitconfig"),
        format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
    )
    .unwrap();

    let state = tmp.path().join("r1-state");
    let report = tmp.path().join("r1-rep.json");
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            report.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(
        !marker.exists() && !log.exists(),
        "FAIL-1: global-config driver executed via gix recursion"
    );
    let parsed = read_json(&report);
    let parent = parent_checkout(&parsed, &sup);
    let state_name = parent["status"]["state"].as_str().unwrap_or_default();
    let fields = status_unknown(parent);
    let fallback_after_recursion_gap = fields.iter().any(|f| {
        f.contains("installed-git fallback") && f.contains(repo_scan::git::SUBMODULE_RECURSION_GAP)
    });
    if state_name == "complete" {
        assert!(
            declares_isolated_scope(parent) && fallback_after_recursion_gap,
            "complete only on the proven path (fallback after declared recursion gap): {state_name} {fields:?}"
        );
    } else {
        assert!(
            !declares_isolated_scope(parent),
            "incomplete status must not declare isolated scope: {state_name} {fields:?}"
        );
    }
    let _ = stderr_text(&out);
}

/// F2b (47A7E507 FAIL-2): driver only in the absorbed submodule config
/// (`sup/.git/modules/vendor/sub/config`), empty HOME — the exact
/// consumer repro. The marker must be ABSENT (fallback guard sees the
/// absorbed driver and refuses conversion) with no complete state and
/// no isolated-scope declaration. Pre-fix the fallback guard saw only
/// the parent effective config, executed the driver, and still
/// declared complete + isolated scope.
#[cfg(unix)]
#[test]
fn f2b_fail2_absorbed_driver_guard_refuses() {
    let tmp = fixture::scratch_root("fr7-f2b-");
    let (roots, sup, sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "r2");
    // Driver ONLY in the absorbed submodule config (LAST git op: `config`
    // never converts content, so the marker can only come from the scan).
    fixture::git(
        &sub,
        &["config", "filter.marker.clean", helper.to_str().unwrap()],
    );
    let absorbed = sup.join(".git/modules/vendor/sub/config");
    let absorbed_text = std::fs::read_to_string(&absorbed).expect("absorbed config");
    assert!(
        absorbed_text.contains("filter.marker.clean")
            || absorbed_text.contains("[filter \"marker\"]"),
        "driver placed in absorbed config: {absorbed_text}"
    );
    let home = tmp.path().join("empty-home");
    repo_scan::privacy::private_dir_0700(&home).unwrap();

    let state = tmp.path().join("r2-state");
    let report = tmp.path().join("r2-rep.json");
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            report.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(
        !marker.exists() && !log.exists(),
        "FAIL-2: absorbed-submodule driver executed via fallback"
    );
    let parsed = read_json(&report);
    let parent = parent_checkout(&parsed, &sup);
    let state_name = parent["status"]["state"].as_str().unwrap_or_default();
    assert_ne!(
        state_name,
        "complete",
        "FAIL-2: no complete state without proven isolation: {:?}",
        status_unknown(parent)
    );
    assert!(
        !declares_isolated_scope(parent),
        "FAIL-2: no isolated-scope declaration without proven isolation"
    );
    let _ = stderr_text(&out);
}

/// Run `git --git-dir=X --work-tree=Y config K V` (absolute dirs, so the
/// hermetic fixture cwd is irrelevant). Used to repair + arm de-absorbed
/// submodule gitdirs.
#[cfg(unix)]
fn git_config_in(cwd: &Path, git_dir: &Path, work_tree: &Path, key: &str, value: &str) {
    fixture::git(
        cwd,
        &[
            &format!("--git-dir={}", git_dir.display()),
            &format!("--work-tree={}", work_tree.display()),
            "config",
            key,
            value,
        ],
    );
}

/// F2b (guard depth): the same bug class beyond absorbed depth-1 —
/// non-absorbed submodule gitdirs (worktree `.git` file pointing
/// outside `modules/`) at depth 1 AND nested depth 2. Installed `git
/// status` descends recursively through the worktree `.git` files and
/// executes drivers from those external configs, so the guard must
/// live-enumerate recursively (not just scan `modules/` trees). Both
/// markers must be ABSENT with no complete/isolated declarations.
/// Pre-fix both helpers executed.
#[cfg(unix)]
#[test]
fn f2b_guard_covers_nonabsorbed_and_nested() {
    let tmp = fixture::scratch_root("fr7-f2bx-");
    let scanroot = tmp.path().join("scanroot");
    repo_scan::privacy::private_dir_0700(&scanroot).unwrap();

    // Layout A: non-absorbed depth-1 submodule with an external driver.
    let lay_a = scanroot.join("layA");
    repo_scan::privacy::private_dir_0700(&lay_a).unwrap();
    let (sup_a, sub_a) = fixture::submodule_repo(&lay_a);
    repo_scan::privacy::private_write_0600(
        &sub_a.join(".gitattributes"),
        "*.md filter=marker\n".as_bytes(),
    )
    .unwrap();
    dirty_same_size(&sub_a.join("README.md"), "# FIXTURE\n");
    let marker_a = tmp.path().join("xa-marker");
    let helper_a = tmp.path().join("xa-helper.sh");
    let log_a = tmp.path().join("xa-helper.log");
    write_marker_helper(&helper_a, &marker_a, &log_a);
    let wex_a = lay_a.join("wexA.git");
    std::fs::rename(sup_a.join(".git/modules/vendor/sub"), &wex_a).expect("de-absorb A");
    repo_scan::privacy::private_write_0600(&sub_a.join(".git"), b"gitdir: ../../../wexA.git\n")
        .unwrap();
    git_config_in(
        tmp.path(),
        &wex_a,
        &sub_a,
        "core.worktree",
        sub_a.to_str().unwrap(),
    );
    git_config_in(
        tmp.path(),
        &wex_a,
        &sub_a,
        "filter.marker.clean",
        helper_a.to_str().unwrap(),
    );
    assert!(
        std::fs::read_to_string(wex_a.join("config"))
            .unwrap()
            .contains("[filter \"marker\"]"),
        "driver placed in external gitdir A"
    );

    // Layout B: nested depth-2 submodule, inner gitdir external.
    let lay_b = scanroot.join("layB");
    repo_scan::privacy::private_dir_0700(&lay_b).unwrap();
    let inner_src = fixture::normal_clone(&lay_b, "inner-src");
    let mid = fixture::normal_clone(&lay_b, "mid");
    fixture::git(
        &mid,
        &[
            "submodule",
            "-q",
            "add",
            inner_src.to_str().unwrap(),
            "inner",
        ],
    );
    fixture::git(&mid, &["commit", "-q", "-m", "add inner"]);
    let parent_b = fixture::normal_clone(&lay_b, "parent");
    fixture::git(
        &parent_b,
        &["submodule", "-q", "add", mid.to_str().unwrap(), "mid"],
    );
    fixture::git(&parent_b, &["commit", "-q", "-m", "add mid"]);
    fixture::git(
        &parent_b,
        &["submodule", "-q", "update", "--init", "--recursive"],
    );
    let inner_wt = parent_b.join("mid/inner");
    assert!(inner_wt.join(".git").exists(), "nested checkout present");
    repo_scan::privacy::private_write_0600(
        &inner_wt.join(".gitattributes"),
        "*.md filter=marker\n".as_bytes(),
    )
    .unwrap();
    dirty_same_size(&inner_wt.join("README.md"), "# FIXTURE\n");
    let marker_b = tmp.path().join("xb-marker");
    let helper_b = tmp.path().join("xb-helper.sh");
    let log_b = tmp.path().join("xb-helper.log");
    write_marker_helper(&helper_b, &marker_b, &log_b);
    let deep_b = lay_b.join("deepB.git");
    std::fs::rename(parent_b.join(".git/modules/mid/modules/inner"), &deep_b).expect("de-absorb B");
    repo_scan::privacy::private_write_0600(&inner_wt.join(".git"), b"gitdir: ../../../deepB.git\n")
        .unwrap();
    git_config_in(
        tmp.path(),
        &deep_b,
        &inner_wt,
        "core.worktree",
        inner_wt.to_str().unwrap(),
    );
    git_config_in(
        tmp.path(),
        &deep_b,
        &inner_wt,
        "filter.marker.clean",
        helper_b.to_str().unwrap(),
    );
    assert!(
        std::fs::read_to_string(deep_b.join("config"))
            .unwrap()
            .contains("[filter \"marker\"]"),
        "driver placed in external gitdir B"
    );
    assert!(
        !marker_a.exists() && !marker_b.exists(),
        "no git op ran after arming the drivers"
    );

    let home = tmp.path().join("empty-home");
    repo_scan::privacy::private_dir_0700(&home).unwrap();
    let state = tmp.path().join("state");
    let report = tmp.path().join("rep.json");
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            scanroot.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            report.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(
        !marker_a.exists() && !log_a.exists(),
        "non-absorbed depth-1 driver executed"
    );
    assert!(
        !marker_b.exists() && !log_b.exists(),
        "nested depth-2 non-absorbed driver executed"
    );
    let parsed = read_json(&report);
    for (sup, tag) in [(&sup_a, "A"), (&parent_b, "B")] {
        let parent = parent_checkout(&parsed, sup);
        let state_name = parent["status"]["state"].as_str().unwrap_or_default();
        assert_ne!(
            state_name,
            "complete",
            "layout {tag}: no complete state without proven isolation: {:?}",
            status_unknown(parent)
        );
        assert!(
            !declares_isolated_scope(parent),
            "layout {tag}: no isolated-scope declaration without proven isolation"
        );
    }
    let _ = stderr_text(&out);
}

/// F3 (2165D21F): complete/isolated declarations are emitted only when
/// every actually-executed path was proven isolated. FAIL-1 shape:
/// complete only via the proven fallback-after-recursion-gap path, else
/// no isolated declaration. FAIL-2 shape: strictly no complete state
/// and no isolated declaration. Honest top-level case: complete WITH
/// the isolated declaration (positive pin against over-refusal).
/// Pre-fix both FAIL shapes declared complete + isolated scope
/// despite helper execution.
#[cfg(unix)]
#[test]
fn f3_declarations_withheld_unless_proven() {
    // FAIL-1 shape: global driver + live submodule.
    let tmp = fixture::scratch_root("fr7-f3-");
    let (roots1, sup1, _sub1, marker1, helper1, log1) = marker_submodule_layout(tmp.path(), "f3r1");
    let home1 = tmp.path().join("home-f3r1");
    repo_scan::privacy::private_dir_0700(&home1).unwrap();
    repo_scan::privacy::private_write_0600(
        &home1.join(".gitconfig"),
        format!("[filter \"marker\"]\n\tclean = {}\n", helper1.display()).as_bytes(),
    )
    .unwrap();
    let state1 = tmp.path().join("state1");
    let rep1 = tmp.path().join("rep1.json");
    run_isolated(
        &state1,
        &home1,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots1.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            rep1.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(!marker1.exists() && !log1.exists(), "F3/FAIL-1 executed");
    let parsed1 = read_json(&rep1);
    let parent1 = parent_checkout(&parsed1, &sup1);
    let s1 = parent1["status"]["state"].as_str().unwrap_or_default();
    let f1 = status_unknown(parent1);
    if s1 == "complete" {
        assert!(
            declares_isolated_scope(parent1)
                && f1.iter().any(|f| f.contains("installed-git fallback")
                    && f.contains(repo_scan::git::SUBMODULE_RECURSION_GAP)),
            "F3/FAIL-1: complete only on the proven path: {s1} {f1:?}"
        );
    } else {
        assert!(
            !declares_isolated_scope(parent1),
            "F3/FAIL-1: no isolated declaration when incomplete: {s1} {f1:?}"
        );
    }

    // FAIL-2 shape: absorbed driver + empty HOME.
    let (roots2, sup2, sub2, marker2, helper2, log2) = marker_submodule_layout(tmp.path(), "f3r2");
    fixture::git(
        &sub2,
        &["config", "filter.marker.clean", helper2.to_str().unwrap()],
    );
    let home2 = tmp.path().join("empty-home");
    repo_scan::privacy::private_dir_0700(&home2).unwrap();
    let state2 = tmp.path().join("state2");
    let rep2 = tmp.path().join("rep2.json");
    run_isolated(
        &state2,
        &home2,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots2.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            rep2.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(!marker2.exists() && !log2.exists(), "F3/FAIL-2 executed");
    let parsed2 = read_json(&rep2);
    let parent2 = parent_checkout(&parsed2, &sup2);
    let s2 = parent2["status"]["state"].as_str().unwrap_or_default();
    assert_ne!(
        s2,
        "complete",
        "F3/FAIL-2: no complete state: {:?}",
        status_unknown(parent2)
    );
    assert!(
        !declares_isolated_scope(parent2),
        "F3/FAIL-2: no isolated declaration"
    );

    // Honest top-level: no drivers anywhere → complete + isolated.
    let roots3 = tmp.path().join("roots-top");
    repo_scan::privacy::private_dir_0700(&roots3).unwrap();
    let top = fixture::normal_clone(&roots3, "top");
    dirty_same_size(&top.join("README.md"), "# FIXTURE\n");
    let state3 = tmp.path().join("state3");
    let rep3 = tmp.path().join("rep3.json");
    run_isolated(
        &state3,
        &home2,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots3.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            rep3.to_str().unwrap(),
        ],
        tmp.path(),
    );
    let parsed3 = read_json(&rep3);
    let checkout = parent_checkout(&parsed3, &top);
    assert_eq!(
        checkout["status"]["state"].as_str(),
        Some("complete"),
        "honest top-level stays complete: {:?}",
        status_unknown(checkout)
    );
    assert!(
        declares_isolated_scope(checkout),
        "honest top-level keeps the isolated declaration"
    );
}

/// F4 (resume-gap): a task that fails with the in-flight-interrupt gap
/// and then completes on retry must not leave a permanent open gap.
/// Two consecutive interrupt→retry→complete legs (the TWICE
/// lifecycle): after each successful retry its `gap:<task>` row is
/// closed (still auditable, `open = 0`). Pre-fix the row stayed open
/// with `attempts` stuck at 1, poisoning verdict fields forever.
#[cfg(unix)]
#[test]
fn f4_complete_closes_stale_interrupt_gap() {
    let rt = runtime();
    rt.block_on(async {
        let dir = fixture::scratch_root("fr7-f4s-");
        let db = dir.path().join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let epoch = store.epoch();
        let now = now_ms();
        let generation = store
            .create_generation("roots", "running", None, now)
            .await
            .expect("generation");
        for leg in 0..2 {
            let task_id = format!("enum:dir:seed{leg}");
            let scope_key = format!("dir:seed{leg:02}");
            let idem = format!("idem:seed{leg}");
            assert!(
                store
                    .enqueue_task(
                        &NewTask {
                            id: &task_id,
                            kind: "enumerate_dir",
                            generation,
                            dir_id: None,
                            scope_key: &scope_key,
                            expected_rev: 0,
                            idempotency_key: &idem,
                        },
                        now,
                    )
                    .await
                    .expect("enqueue"),
                "leg {leg}: enqueued"
            );
            let claimed = store
                .claim_tasks_in_generation(generation, epoch, 4, 60_000, now)
                .await
                .expect("claim");
            let first = claimed
                .iter()
                .find(|c| c.task.id == task_id)
                .expect("leg claimed");
            // In-flight interrupt completes as Retry with the stale gap.
            store
                .complete_task(
                    &first.task.id,
                    first.token,
                    epoch,
                    &TaskOutcome::Retry {
                        category: "enumerate-error".to_string(),
                        detail: "interrupted; partial enumeration".to_string(),
                        retry_after_ms: now,
                    },
                    now,
                )
                .await
                .expect("retry completion");
            let gap_id = format!("gap:{task_id}");
            let gap = store
                .get_error(&gap_id)
                .await
                .expect("get")
                .unwrap_or_else(|| panic!("leg {leg}: gap row recorded"));
            assert!(gap.open, "leg {leg}: gap open while retry pending");
            assert_eq!(gap.attempts, 1, "leg {leg}: one failure recorded");
            // Resume leg: the retry is claimed and the work completes.
            let later = now + 120_000;
            let reclaimed = store
                .claim_tasks_in_generation(generation, epoch, 4, 60_000, later)
                .await
                .expect("reclaim");
            let second = reclaimed
                .iter()
                .find(|c| c.task.id == task_id)
                .unwrap_or_else(|| panic!("leg {leg}: retry claimed on resume"));
            store
                .complete_task(
                    &second.task.id,
                    second.token,
                    epoch,
                    &TaskOutcome::Complete,
                    later,
                )
                .await
                .expect("complete");
            let gap = store
                .get_error(&gap_id)
                .await
                .expect("get")
                .unwrap_or_else(|| panic!("leg {leg}: gap row retained"));
            assert!(
                !gap.open,
                "leg {leg}: successful retry closes the stale interrupt gap"
            );
            assert_eq!(gap.attempts, 1, "leg {leg}: no phantom re-failure");
        }
        store.close().await.expect("close");
    });
}

/// Parse one stderr progress line into cumulative `(tasks_done, pending)`.
#[cfg(unix)]
fn parse_progress(line: &str) -> Option<(u64, u64)> {
    let (_, rest) = line.split_once("tasks_done=")?;
    let (done_s, rest) = rest.split_once('/')?;
    let done = done_s.parse::<u64>().ok()?;
    let (_, rest) = rest.split_once("pending=")?;
    let pending_s = rest.split(|c: char| !c.is_ascii_digit()).next()?;
    let pending = pending_s.parse::<u64>().ok()?;
    Some((done, pending))
}

/// Minimum durable acknowledgments before the mid-scan kill (mirrors
/// the RESUME-01 gate: store-read counters, never a fixed sleep).
#[cfg(unix)]
const MIN_ACKS: u64 = 5;

#[cfg(unix)]
fn kill_gate_met(done: u64, pending: u64) -> bool {
    done >= MIN_ACKS && pending > 0
}

#[cfg(unix)]
async fn sql_count(store: &TursoStore, sql: &str) -> i64 {
    let mut rows = store.connection().query(sql, ()).await.expect("query");
    let row = rows.next().await.expect("next").expect("row");
    match row.get_value(0).expect("value") {
        turso::Value::Integer(n) => n,
        other => panic!("expected integer count, got {other:?}"),
    }
}

/// Seed one in-flight-interrupt gap exactly as `exec_enumerate` +
/// `complete_task` produce it on SIGINT: the task returns to
/// `retry_wait` and `gap:<task>` opens with attempts=1.
#[cfg(unix)]
async fn seed_interrupt_gap(store: &TursoStore, task_id: &str, scope_key: &str) {
    let now = now_ms();
    let retry_after = now - 60_000;
    let matched = store
        .connection()
        .execute(
            "UPDATE frontier_tasks SET state = 'retry_wait', lease_token = NULL, \
             lease_epoch = NULL, lease_expires_ms = NULL, attempts = attempts + 1, \
             retry_after_ms = ?1, updated_at_ms = ?2 WHERE id = ?3",
            vec![
                turso::Value::Integer(retry_after),
                turso::Value::Integer(now),
                turso::Value::Text(task_id.to_string()),
            ],
        )
        .await
        .expect("seed task");
    assert_eq!(matched, 1, "seeded task {task_id} flipped to retry_wait");
    store
        .connection()
        .execute(
            "INSERT OR IGNORE INTO errors (id, scope_key, category, detail, attempts, \
             first_seen_ms, last_seen_ms, next_retry_ms, open) \
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5, ?6, 1)",
            vec![
                turso::Value::Text(format!("gap:{task_id}")),
                turso::Value::Text(scope_key.to_string()),
                turso::Value::Text("enumerate-error".to_string()),
                turso::Value::Text("interrupted; partial enumeration".to_string()),
                turso::Value::Integer(now),
                turso::Value::Integer(retry_after),
            ],
        )
        .await
        .expect("seed gap");
}

/// F4 (resume-gap) lifecycle: SIGKILL mid-scan, seed TWO
/// in-flight-interrupt gaps (two interrupted enumerations) onto
/// pending tasks, then resume. The resume must retry both gaps (no
/// permanent poison: exit 0, gaps 0, both rows closed) and report
/// data identical to a fresh full traversal. Pre-fix the resumed run
/// ended incomplete/gaps=2/exit 3 with the stale gaps permanent.
#[cfg(unix)]
#[test]
fn f4_resume_retries_interrupt_gaps_no_poison() {
    const MID_DIRS: usize = 25;
    const LEAVES_PER_MID: usize = 10;
    const FILES_PER_LEAF: usize = 8;
    const DEEP: usize = 48;
    const REPOS: usize = 8;

    let tmp = fixture::scratch_root("fr7-f4c-");
    let state = tmp.path().join("state");
    let home = tmp.path().join("home");
    repo_scan::privacy::private_dir_0700(&home).unwrap();
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
    let state_s = state.to_str().expect("utf8").to_string();

    // SIGKILL mid-scan on the durable-ack gate (never a blind sleep).
    let mut child = Command::new(binary())
        .args([
            "--state-dir",
            state_s.as_str(),
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            root_s.as_str(),
            "--report",
            report_s.as_str(),
        ])
        .current_dir(tmp.path())
        .env("HOME", &home)
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("GIT_CONFIG_SYSTEM")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("XDG_CONFIG_HOME")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn scan");
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
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            panic!("scan exited ({status}) before the kill window");
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("no durable acknowledgment within 180s");
        }
        match line_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(line) => {
                if let Some((done, pending)) = parse_progress(&line) {
                    if kill_gate_met(done, pending) {
                        break;
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
        }
    }
    assert!(
        child.try_wait().expect("poll child").is_none(),
        "scan finished before the kill landed"
    );
    child.kill().expect("SIGKILL mid-scan");
    let status = child.wait().expect("wait");
    assert!(!status.success(), "killed scan must not report success");
    reader.join().expect("stderr reader");

    // Seed two in-flight-interrupt gaps onto pending enum tasks.
    let rt = runtime();
    let scan_id = rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        assert!(db.exists(), "catalog survives SIGKILL");
        let store = TursoStore::open(&db).await.expect("reopen after kill");
        let mut rows = store
            .connection()
            .query("SELECT id, state FROM scan_requests", ())
            .await
            .expect("scans");
        let row = rows.next().await.expect("next").expect("one scan");
        let id = match row.get_value(0).expect("id") {
            turso::Value::Text(id) => id,
            other => panic!("scan id text, got {other:?}"),
        };
        let scan_state = match row.get_value(1).expect("state") {
            turso::Value::Text(state) => state,
            other => panic!("scan state text, got {other:?}"),
        };
        assert!(scan_state.starts_with("running"), "resumable: {scan_state}");
        let mut rows = store
            .connection()
            .query(
                "SELECT id, scope_key FROM frontier_tasks \
                 WHERE kind = 'enumerate_dir' AND state = 'pending' LIMIT 2",
                (),
            )
            .await
            .expect("pending enum tasks");
        let mut picked = Vec::new();
        while let Some(row) = rows.next().await.expect("next") {
            let id = match row.get_value(0).expect("id") {
                turso::Value::Text(id) => id,
                other => panic!("task id text, got {other:?}"),
            };
            let scope = match row.get_value(1).expect("scope") {
                turso::Value::Text(scope) => scope,
                other => panic!("scope text, got {other:?}"),
            };
            picked.push((id, scope));
        }
        assert_eq!(picked.len(), 2, "two pending enum tasks to interrupt");
        for (id, scope) in &picked {
            seed_interrupt_gap(&store, id, scope).await;
        }
        assert_eq!(
            sql_count(&store, "SELECT COUNT(*) FROM errors WHERE open = 1").await,
            2,
            "two seeded interrupt gaps open"
        );
        store.close().await.expect("close");
        id
    });

    // Resume retries both gaps: no permanent poison.
    let out = run_isolated(&state, &home, &["resume", scan_id.as_str()], tmp.path());
    assert_eq!(
        out.status.code(),
        Some(0),
        "resume exits 0: {}",
        stderr_text(&out)
    );
    let resumed = read_json(&report);
    assert_eq!(resumed["scan"]["state"].as_str(), Some("complete"));
    assert_eq!(resumed["coverage"]["gaps"].as_u64(), Some(0));
    assert_eq!(
        resumed["errors"].as_array().map(Vec::len),
        Some(0),
        "no stale gaps in report: {:?}",
        resumed["errors"]
    );
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("reopen");
        assert_eq!(
            sql_count(&store, "SELECT COUNT(*) FROM errors WHERE open = 1").await,
            0,
            "no open gaps left in catalog"
        );
        assert_eq!(
            sql_count(
                &store,
                "SELECT COUNT(*) FROM errors WHERE open = 0 AND detail = 'interrupted; partial enumeration'"
            )
            .await,
            2,
            "both interrupt gaps retried and closed (auditable)"
        );
        store.close().await.expect("close");
    });

    // Resumed data identical to a fresh full traversal.
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            root_s.as_str(),
            "--report",
            report_s.as_str(),
            "--force-rescan",
        ],
        tmp.path(),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "fresh stderr: {}",
        stderr_text(&out)
    );
    let fresh = read_json(&report);
    for key in ["repositories", "remotes", "checkouts", "branches"] {
        assert_eq!(
            resumed[key].as_array().map(Vec::len),
            fresh[key].as_array().map(Vec::len),
            "{key} count identical to fresh scan"
        );
    }
    assert_eq!(
        resumed["coverage"]["directories_complete"].as_u64(),
        fresh["coverage"]["directories_complete"].as_u64(),
        "dir-complete count identical to fresh scan"
    );
    let mut resumed_ids: Vec<_> = resumed["repositories"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    let mut fresh_ids: Vec<_> = fresh["repositories"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    resumed_ids.sort_unstable();
    fresh_ids.sort_unstable();
    assert_eq!(resumed_ids, fresh_ids, "same repository id set");
}

/// F2c (include-chain hole): driver ONLY behind an `[include]` chain in
/// the absorbed submodule config — the exact challenger repro: a parent
/// with absorbed submodule S; S selects `filter=marker` with a same-size
/// dirty file; `P/.git/modules/vendor/sub/config` carries no `[filter]`
/// section, only `[include] path = inc/f.inc`; `inc/f.inc` names the
/// marker driver; empty HOME. Installed `git status` loads submodule
/// configs WITH repo-local includes, so the marker must be ABSENT
/// (submodule-leg guard follows the chain and refuses conversion)
/// with no complete state and no isolated-scope declaration. Pre-fix
/// the guard read only `config`/`config.worktree` `[filter]` keys,
/// executed the driver, and declared complete + isolated scope.
#[cfg(unix)]
#[test]
fn f2c_include_chain_absorbed_driver_guard_refuses() {
    let tmp = fixture::scratch_root("fr7-f2c-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "r7");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    let target = inc_dir.join("f.inc");
    repo_scan::privacy::private_write_0600(
        &target,
        format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
    )
    .unwrap();
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(
        !text.contains("[filter"),
        "driver reachable only via the include chain: {text}"
    );
    text.push_str("\n[include]\n\tpath = inc/f.inc\n");
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    // Chain well-formed (a dangling path would refuse vacuously):
    // the resolved target exists and names the driver.
    assert!(target.is_file(), "include target resolves");
    assert!(
        std::fs::read_to_string(&target)
            .unwrap()
            .contains("[filter \"marker\"]"),
        "driver lives in the included file"
    );
    let home = tmp.path().join("empty-home");
    repo_scan::privacy::private_dir_0700(&home).unwrap();

    let state = tmp.path().join("r7-state");
    let report = tmp.path().join("r7-rep.json");
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            report.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(
        !marker.exists() && !log.exists(),
        "F2c: include-chain driver executed via fallback"
    );
    let parsed = read_json(&report);
    let parent = parent_checkout(&parsed, &sup);
    let state_name = parent["status"]["state"].as_str().unwrap_or_default();
    assert_ne!(
        state_name,
        "complete",
        "F2c: no complete state without proven isolation: {:?}",
        status_unknown(parent)
    );
    assert!(
        !declares_isolated_scope(parent),
        "F2c: no isolated-scope declaration without proven isolation"
    );
    let _ = stderr_text(&out);
}

/// F2c (nested depth): two-hop include chain — absorbed config
/// includes `inc/d1.inc`, which includes `d2.inc` (relative to its own
/// directory), which names the marker driver. Same verdict as the
/// single-hop repro: marker absent, no complete state, no isolated
/// declaration. Pre-fix both hops were invisible to the guard.
#[cfg(unix)]
#[test]
fn f2c_include_chain_nested_depth_refuses() {
    let tmp = fixture::scratch_root("fr7-f2cn-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "r7n");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("d2.inc"),
        format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
    )
    .unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("d1.inc"),
        b"[include]\n\tpath = d2.inc\n",
    )
    .unwrap();
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(!text.contains("[filter"), "no direct driver: {text}");
    text.push_str("\n[include]\n\tpath = inc/d1.inc\n");
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    assert!(
        std::fs::read_to_string(inc_dir.join("d2.inc"))
            .unwrap()
            .contains("[filter \"marker\"]"),
        "driver lives at the end of the two-hop chain"
    );
    let home = tmp.path().join("empty-home");
    repo_scan::privacy::private_dir_0700(&home).unwrap();

    let state = tmp.path().join("r7n-state");
    let report = tmp.path().join("r7n-rep.json");
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            report.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(
        !marker.exists() && !log.exists(),
        "F2c/nested: chained driver executed via fallback"
    );
    let parsed = read_json(&report);
    let parent = parent_checkout(&parsed, &sup);
    let state_name = parent["status"]["state"].as_str().unwrap_or_default();
    assert_ne!(
        state_name,
        "complete",
        "F2c/nested: no complete state: {:?}",
        status_unknown(parent)
    );
    assert!(
        !declares_isolated_scope(parent),
        "F2c/nested: no isolated-scope declaration"
    );
    let _ = stderr_text(&out);
}

/// F2c (includeIf over-approximation): the marker driver lives in a
/// file pulled in only by `[includeIf "gitdir:/nonexistent-..."]` —
/// a condition that cannot match, so git itself would NOT load the
/// driver. The guard nevertheless follows includeIf paths
/// UNCONDITIONALLY (conditions are never evaluated) and refuses:
/// marker absent, no complete state, no isolated declaration. This
/// pins the documented over-approximation (refusal when git would not
/// load = safe direction). Pre-fix the guard saw no driver and served
/// complete + isolated scope.
#[cfg(unix)]
#[test]
fn f2c_includeif_followed_unconditionally_refuses() {
    let tmp = fixture::scratch_root("fr7-f2ci-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "r7i");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    let target = inc_dir.join("cond.inc");
    repo_scan::privacy::private_write_0600(
        &target,
        format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
    )
    .unwrap();
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(!text.contains("[filter"), "no direct driver: {text}");
    text.push_str("\n[includeIf \"gitdir:/nonexistent-fr7-f2c/\"]\n\tpath = inc/cond.inc\n");
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    assert!(
        std::fs::read_to_string(&target)
            .unwrap()
            .contains("[filter \"marker\"]"),
        "driver lives in the conditionally included file"
    );
    let home = tmp.path().join("empty-home");
    repo_scan::privacy::private_dir_0700(&home).unwrap();

    let state = tmp.path().join("r7i-state");
    let report = tmp.path().join("r7i-rep.json");
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            report.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(
        !marker.exists() && !log.exists(),
        "F2c/includeIf: driver executed via fallback"
    );
    let parsed = read_json(&report);
    let parent = parent_checkout(&parsed, &sup);
    let state_name = parent["status"]["state"].as_str().unwrap_or_default();
    assert_ne!(
        state_name,
        "complete",
        "F2c/includeIf: unconditional follow refuses: {:?}",
        status_unknown(parent)
    );
    assert!(
        !declares_isolated_scope(parent),
        "F2c/includeIf: no isolated-scope declaration"
    );
    let _ = stderr_text(&out);
}

/// F2c (fail closed): the absorbed config names an include target the
/// scanner cannot read (mode 000). The guard refuses loudly (fail
/// closed) instead of skipping silently: no complete state, no
/// isolated declaration. The target carries a driver, so refusal also
/// holds where the file happens to stay readable. The include sits
/// under a FALSE `[includeIf "gitdir:/nonexistent-..."]` so git itself
/// would skip it and succeed — any refusal must come from the guard's
/// unconditional follow (an unconditional unreadable include fails
/// loudly inside git either way, which would pass without proving the
/// guard). Pre-fix the guard ignored the include and served complete
/// + isolated scope. Non-root assumption: mode 000 must deny reads.
#[cfg(unix)]
#[test]
fn f2c_unreadable_include_target_refuses() {
    let tmp = fixture::scratch_root("fr7-f2cu-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "r7u");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    let target = inc_dir.join("noperm.inc");
    repo_scan::privacy::private_write_0600(
        &target,
        format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(!text.contains("[filter"), "no direct driver: {text}");
    text.push_str("\n[includeIf \"gitdir:/nonexistent-fr7-f2c/\"]\n\tpath = inc/noperm.inc\n");
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    let home = tmp.path().join("empty-home");
    repo_scan::privacy::private_dir_0700(&home).unwrap();

    let state = tmp.path().join("r7u-state");
    let report = tmp.path().join("r7u-rep.json");
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            report.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(
        !marker.exists() && !log.exists(),
        "F2c/unreadable: driver executed via fallback"
    );
    let parsed = read_json(&report);
    let parent = parent_checkout(&parsed, &sup);
    let state_name = parent["status"]["state"].as_str().unwrap_or_default();
    assert_ne!(
        state_name,
        "complete",
        "F2c/unreadable: unreadable target refuses: {:?}",
        status_unknown(parent)
    );
    assert!(
        !declares_isolated_scope(parent),
        "F2c/unreadable: no isolated-scope declaration"
    );
    let _ = stderr_text(&out);
}

/// F2c (cycle): the absorbed config includes `inc/a.inc`, whose
/// back-edge (`../config`) closes an include cycle with NO driver
/// anywhere, so any refusal must come from cycle detection (never
/// from a driver hit, never a hang): no complete state, no isolated
/// declaration. The back-edge sits under a FALSE `[includeIf
/// "gitdir:/nonexistent-..."]` so git itself would skip it and
/// succeed — any refusal must come from the guard's unconditional
/// follow (an unconditional cycle dies loudly inside git either way,
/// which would pass without proving the guard). Pre-fix the guard
/// ignored the include and served complete + isolated scope.
#[cfg(unix)]
#[test]
fn f2c_include_cycle_refuses() {
    let tmp = fixture::scratch_root("fr7-f2cc-");
    let (roots, sup, _sub, marker, _helper, log) = marker_submodule_layout(tmp.path(), "r7c");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("a.inc"),
        b"[includeIf \"gitdir:/nonexistent-fr7-f2c/\"]\n\tpath = ../config\n",
    )
    .unwrap();
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(!text.contains("[filter"), "no direct driver: {text}");
    text.push_str("\n[include]\n\tpath = inc/a.inc\n");
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    assert!(
        std::fs::read_to_string(inc_dir.join("a.inc"))
            .unwrap()
            .contains("../config"),
        "back-edge to the absorbed config present"
    );
    let home = tmp.path().join("empty-home");
    repo_scan::privacy::private_dir_0700(&home).unwrap();

    let state = tmp.path().join("r7c-state");
    let report = tmp.path().join("r7c-rep.json");
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            report.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(
        !marker.exists() && !log.exists(),
        "F2c/cycle: unexpected execution"
    );
    let parsed = read_json(&report);
    let parent = parent_checkout(&parsed, &sup);
    let state_name = parent["status"]["state"].as_str().unwrap_or_default();
    assert_ne!(
        state_name,
        "complete",
        "F2c/cycle: cycle refuses: {:?}",
        status_unknown(parent)
    );
    assert!(
        !declares_isolated_scope(parent),
        "F2c/cycle: no isolated-scope declaration"
    );
    let _ = stderr_text(&out);
}

/// F2c (symlink): the absorbed config includes `inc/link.inc`, a
/// symlink to a benign driver-free file. Links are never followed
/// (PATH-GIT-07 posture), so the guard refuses: no complete state, no
/// isolated declaration. Refusal here is about the LINK, not missing
/// content — the link target exists and is clean. Pre-fix the guard
/// ignored the include and served complete + isolated scope.
#[cfg(unix)]
#[test]
fn f2c_include_symlink_refuses() {
    let tmp = fixture::scratch_root("fr7-f2cl-");
    let (roots, sup, _sub, marker, _helper, log) = marker_submodule_layout(tmp.path(), "r7l");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("clean.inc"),
        b"[core]\n\trepositoryformatversion = 0\n",
    )
    .unwrap();
    std::os::unix::fs::symlink("clean.inc", inc_dir.join("link.inc")).unwrap();
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(!text.contains("[filter"), "no direct driver: {text}");
    text.push_str("\n[include]\n\tpath = inc/link.inc\n");
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    assert!(
        std::fs::symlink_metadata(inc_dir.join("link.inc"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "include target is a link"
    );
    assert!(
        inc_dir.join("clean.inc").is_file(),
        "link target exists and is clean"
    );
    let home = tmp.path().join("empty-home");
    repo_scan::privacy::private_dir_0700(&home).unwrap();

    let state = tmp.path().join("r7l-state");
    let report = tmp.path().join("r7l-rep.json");
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            report.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(
        !marker.exists() && !log.exists(),
        "F2c/symlink: unexpected execution"
    );
    let parsed = read_json(&report);
    let parent = parent_checkout(&parsed, &sup);
    let state_name = parent["status"]["state"].as_str().unwrap_or_default();
    assert_ne!(
        state_name,
        "complete",
        "F2c/symlink: linked target refuses: {:?}",
        status_unknown(parent)
    );
    assert!(
        !declares_isolated_scope(parent),
        "F2c/symlink: no isolated-scope declaration"
    );
    let _ = stderr_text(&out);
}

/// Shared full-status scan for the NORM normalization-hole regressions
/// (H0/H1/H2): fixture HOME, stripped config env, caller asserts.
#[cfg(unix)]
fn norm_full_scan(tmp: &Path, tag: &str, roots: &Path) -> (Output, serde_json::Value) {
    let home = tmp.join(format!("empty-home-{tag}"));
    repo_scan::privacy::private_dir_0700(&home).unwrap();
    let state = tmp.join(format!("{tag}-state"));
    let report = tmp.join(format!("{tag}-rep.json"));
    let out = run_isolated(
        &state,
        &home,
        &[
            "scan",
            fixture::FIXTURE_REMOTE_URL,
            "--root",
            roots.to_str().unwrap(),
            "--status",
            "full",
            "--report",
            report.to_str().unwrap(),
        ],
        tmp,
    );
    let parsed = read_json(&report);
    (out, parsed)
}

/// Shared NORM verdict: marker absent, no complete state, no
/// isolated-scope declaration on the parent checkout.
#[cfg(unix)]
fn norm_assert_refused(
    tag: &str,
    parsed: &serde_json::Value,
    sup: &Path,
    marker: &Path,
    log: &Path,
) {
    assert!(
        !marker.exists() && !log.exists(),
        "{tag}: normalization-hole driver executed"
    );
    let parent = parent_checkout(parsed, sup);
    let state_name = parent["status"]["state"].as_str().unwrap_or_default();
    assert_ne!(
        state_name,
        "complete",
        "{tag}: no complete state: {:?}",
        status_unknown(parent)
    );
    assert!(
        !declares_isolated_scope(parent),
        "{tag}: no isolated-scope declaration"
    );
}

/// NORM-H0 (include): the absorbed submodule config starts with the exact
/// bytes `\xef\xbb\xbf[include]\npath = inc/evil.inc\n`, and the marker
/// driver lives in `inc/evil.inc`. git skips the BOM and loads the driver;
/// pre-fix `str::trim` left the BOM in place so both guard parsers skipped
/// the first line, served Clean, and the fallback executed the marker.
/// Post-fix the guard strips the BOM, follows the include, and refuses.
#[cfg(unix)]
#[test]
fn norm_h0_bom_include_chain_refuses() {
    let tmp = fixture::scratch_root("fr7-n0i-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "n0i");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    let target = inc_dir.join("evil.inc");
    repo_scan::privacy::private_write_0600(
        &target,
        format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
    )
    .unwrap();
    let config_path = absorbed_dir.join("config");
    let existing = std::fs::read(&config_path).expect("absorbed config");
    assert!(
        !String::from_utf8_lossy(&existing).contains("[filter"),
        "driver reachable only via the BOM'd include"
    );
    let mut bytes = b"\xef\xbb\xbf[include]\n\tpath = inc/evil.inc\n".to_vec();
    bytes.extend_from_slice(&existing);
    repo_scan::privacy::private_write_0600(&config_path, &bytes).unwrap();
    assert!(
        std::fs::read(&config_path)
            .unwrap()
            .starts_with(b"\xef\xbb\xbf[include]"),
        "exact BOM first-line bytes planted"
    );
    assert!(target.is_file(), "BOM'd include target resolves");
    assert!(
        std::fs::read_to_string(&target)
            .unwrap()
            .contains("[filter \"marker\"]"),
        "driver lives in the included file"
    );

    let (out, parsed) = norm_full_scan(tmp.path(), "n0i", &roots);
    norm_assert_refused("NORM-H0/include", &parsed, &sup, &marker, &log);
    let _ = stderr_text(&out);
}

/// NORM-H0 (direct): the absorbed submodule config starts with the exact
/// bytes `\xef\xbb\xbf[filter "marker"]\n\tclean = ...\n` — no include
/// involved. git parses the BOM'd section and loads the driver; pre-fix
/// the filter scan missed it (Clean + execution). Post-fix refuses.
#[cfg(unix)]
#[test]
fn norm_h0_bom_direct_filter_refuses() {
    let tmp = fixture::scratch_root("fr7-n0d-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "n0d");
    let config_path = sup.join(".git/modules/vendor/sub/config");
    let existing = std::fs::read(&config_path).expect("absorbed config");
    assert!(
        !String::from_utf8_lossy(&existing).contains("[filter"),
        "no filter section before the BOM'd plant"
    );
    let mut bytes = format!(
        "\u{FEFF}[filter \"marker\"]\n\tclean = {}\n",
        helper.display()
    )
    .into_bytes();
    bytes.extend_from_slice(&existing);
    repo_scan::privacy::private_write_0600(&config_path, &bytes).unwrap();
    assert!(
        std::fs::read(&config_path)
            .unwrap()
            .starts_with("\u{FEFF}[filter \"marker\"]".as_bytes()),
        "exact BOM first-line bytes planted"
    );

    let (out, parsed) = norm_full_scan(tmp.path(), "n0d", &roots);
    norm_assert_refused("NORM-H0/direct", &parsed, &sup, &marker, &log);
    let _ = stderr_text(&out);
}

/// NORM-H0 (siblings): a BOM'd `[include]` first line in a plain repo
/// config must still raise the bounded pre-scan gap
/// (`has_include_section`) and list its target in the read-only include
/// evidence (`scan_include_paths`). Pre-fix both siblings were BOM-blind
/// (no gap, no dep). Library-level: no scan, no execution surface.
#[cfg(unix)]
#[test]
fn norm_h0_bom_sibling_gap_and_deps() {
    let tmp = fixture::scratch_root("fr7-n0s-");
    let parent = tmp.path().join("repos");
    repo_scan::privacy::private_dir_0700(&parent).unwrap();
    let repo = fixture::normal_clone(&parent, "bomgap");
    let extra = parent.join("extra.conf");
    repo_scan::privacy::private_write_0600(&extra, b"[core]\n\trepositoryformatversion = 0\n")
        .unwrap();
    let config_path = repo.join(".git/config");
    let existing = std::fs::read(&config_path).unwrap();
    assert!(
        !String::from_utf8_lossy(&existing).contains("[include]"),
        "fixture has no include yet"
    );
    let mut bytes = format!("\u{FEFF}[include]\n\tpath = {}\n", extra.display()).into_bytes();
    bytes.extend_from_slice(&existing);
    repo_scan::privacy::private_write_0600(&config_path, &bytes).unwrap();

    let inspector = repo_scan::git::GixInspector::new();
    let instance =
        repo_scan::git::GitInspect::open_exact(&inspector, &repo).expect("open with BOM include");
    let gap =
        repo_scan::git::config_include_gap(&instance).expect("BOM include must raise the gap");
    assert!(gap.starts_with(repo_scan::git::CONFIG_INCLUDE_GAP), "{gap}");
    let deps = inspector.config_dependencies(&instance);
    assert!(
        deps.iter()
            .any(|d| d.via_include && d.exists && d.path == extra),
        "BOM include target listed in deps: {deps:?}"
    );
}

/// NORM-H1 (comment decoys): one absorbed config with three `path` lines
/// carrying trailing comments — `;` spaced, `;` bare, `#` — each with the
/// marker driver in the REAL file git loads (comment stripped) and a clean
/// decoy planted at the literal junk spelling the naive parser kept
/// (`inc/real.inc ; docs`, `inc/bare.inc;docs`, `inc/hash.inc # docs`).
/// Pre-fix the guard read only the decoys (Clean + execution); post-fix
/// it strips comments per git rules, reads the real files, and refuses
/// (the raw leg additionally follows each decoy — inspected, still clean).
#[cfg(unix)]
#[test]
fn norm_h1_comment_decoys_refuse() {
    let tmp = fixture::scratch_root("fr7-n1-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "n1");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    // (config line suffix after `path = `, real file git loads, literal
    // junk spelling the pre-fix parser kept)
    let variants = [
        ("inc/semi.inc ; docs about this include", "inc/semi.inc"),
        ("inc/bare.inc;docs", "inc/bare.inc"),
        ("inc/hash.inc # docs", "inc/hash.inc"),
    ];
    let mut block = String::from("\n[include]\n");
    for (spelling, real) in &variants {
        repo_scan::privacy::private_write_0600(
            &absorbed_dir.join(real),
            format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
        )
        .unwrap();
        repo_scan::privacy::private_write_0600(
            &absorbed_dir.join(spelling),
            b"[core]\n\trepositoryformatversion = 0\n",
        )
        .unwrap();
        block.push_str(&format!("\tpath = {spelling}\n"));
    }
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(!text.contains("[filter"), "no direct driver: {text}");
    text.push_str(&block);
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    for (spelling, real) in &variants {
        assert!(
            absorbed_dir.join(real).is_file(),
            "real file resolves: {real}"
        );
        assert!(
            std::fs::read_to_string(absorbed_dir.join(real))
                .unwrap()
                .contains("[filter \"marker\"]"),
            "driver lives in the real file: {real}"
        );
        assert!(
            absorbed_dir.join(spelling).is_file(),
            "decoy planted at literal junk spelling: {spelling}"
        );
        assert!(
            !std::fs::read_to_string(absorbed_dir.join(spelling))
                .unwrap()
                .contains("filter"),
            "decoy is clean: {spelling}"
        );
    }

    let (out, parsed) = norm_full_scan(tmp.path(), "n1", &roots);
    norm_assert_refused("NORM-H1/comment", &parsed, &sup, &marker, &log);
    let _ = stderr_text(&out);
}

/// NORM-H2 (quote-escape decoys): one absorbed config with five quoted
/// `path` lines exercising git's full inside-quotes escape table — `\"`,
/// `\\`, `\t`, `\n`, `\b` — each with the marker driver in the REAL file
/// git loads (unescaped) and a clean decoy at the literal backslash
/// spelling the naive `trim_matches('"')` parser kept. Pre-fix the guard
/// read only the decoys (Clean + execution); post-fix it unescapes per
/// git rules, reads the real files, and refuses (the raw leg additionally
/// follows each decoy — inspected, still clean).
#[cfg(unix)]
#[test]
fn norm_h2_quote_escape_decoys_refuse() {
    let tmp = fixture::scratch_root("fr7-n2-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "n2");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    // (config-file value bytes, real file git loads, literal junk spelling
    // the pre-fix parser kept)
    let variants = [
        ("\"inc/esc\\\"q.inc\"", "esc\"q.inc", "esc\\\"q.inc"),
        ("\"inc/bs\\\\b.inc\"", "bs\\b.inc", "bs\\\\b.inc"),
        ("\"inc/tab\\tb.inc\"", "tab\tb.inc", "tab\\tb.inc"),
        ("\"inc/nl\\nb.inc\"", "nl\nb.inc", "nl\\nb.inc"),
        ("\"inc/bel\\bb.inc\"", "bel\u{8}b.inc", "bel\\bb.inc"),
    ];
    let mut block = String::from("\n[include]\n");
    for (value, real, decoy) in &variants {
        repo_scan::privacy::private_write_0600(
            &inc_dir.join(real),
            format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
        )
        .unwrap();
        repo_scan::privacy::private_write_0600(
            &inc_dir.join(decoy),
            b"[core]\n\trepositoryformatversion = 0\n",
        )
        .unwrap();
        block.push_str(&format!("\tpath = {value}\n"));
    }
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(!text.contains("[filter"), "no direct driver: {text}");
    text.push_str(&block);
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    for (value, real, decoy) in &variants {
        assert_ne!(real, decoy, "variant must split legs: {value}");
        assert!(
            std::fs::read_to_string(inc_dir.join(real))
                .unwrap()
                .contains("[filter \"marker\"]"),
            "driver lives in the real file: {real:?}"
        );
        assert!(
            inc_dir.join(decoy).is_file(),
            "decoy planted at literal junk spelling: {decoy:?}"
        );
        assert!(
            !std::fs::read_to_string(inc_dir.join(decoy))
                .unwrap()
                .contains("filter"),
            "decoy is clean: {decoy:?}"
        );
    }

    let (out, parsed) = norm_full_scan(tmp.path(), "n2", &roots);
    norm_assert_refused("NORM-H2/escape", &parsed, &sup, &marker, &log);
    let _ = stderr_text(&out);
}

/// NORM-H3 (line continuation, exact challenger repro): the absorbed
/// submodule config ends with the exact bytes
/// `[include]\n\tpath = inc/re\\\nal.inc\n` (line 1 ends with a single
/// backslash). Installed git 2.56.0 JOINS the continuation and loads
/// `inc/real.inc`, where the marker driver lives; a clean decoy sits at
/// the literal split spelling `inc/re\` (legal unix name) that the
/// pre-fix line-based parser followed instead (line 1's normalized leg
/// dropped on the trailing backslash, line 2 has no `=` so it was
/// skipped) — Clean + execution + complete/isolated declarations.
/// Post-fix the guard joins continuations per git rules, reads the real
/// file, and refuses (the unjoined leg additionally follows the decoy —
/// inspected, still clean).
#[cfg(unix)]
#[test]
fn norm_h3_continuation_exact_repro_refuses() {
    let tmp = fixture::scratch_root("fr7-n3-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "n3");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("real.inc"),
        format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
    )
    .unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("re\\"),
        b"[core]\n\trepositoryformatversion = 0\n",
    )
    .unwrap();
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(!text.contains("[filter"), "no direct driver: {text}");
    text.push_str("\n[include]\n\tpath = inc/re\\\nal.inc\n");
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    let planted = std::fs::read(&config_path).unwrap();
    assert!(
        planted.ends_with(b"[include]\n\tpath = inc/re\\\nal.inc\n"),
        "exact repro bytes planted"
    );
    assert!(
        std::fs::read_to_string(inc_dir.join("real.inc"))
            .unwrap()
            .contains("[filter \"marker\"]"),
        "driver lives in the joined file"
    );
    assert!(
        inc_dir.join("re\\").is_file(),
        "decoy planted at literal split spelling"
    );
    assert!(
        !std::fs::read_to_string(inc_dir.join("re\\"))
            .unwrap()
            .contains("filter"),
        "decoy is clean"
    );

    let (out, parsed) = norm_full_scan(tmp.path(), "n3", &roots);
    norm_assert_refused("NORM-H3/continuation", &parsed, &sup, &marker, &log);
    let _ = stderr_text(&out);
}

/// NORM-H3 (quoted continuation): `path = "inc/re\` + newline +
/// `al.inc"` — git joins INSIDE double quotes too (probed 2.56.0:
/// `include.path=inc/real.inc`). Same layout as the exact repro: driver
/// in `inc/real.inc`, clean decoy at the literal `inc/re\` spelling the
/// pre-fix raw leg kept. Pre-fix Clean + execution; post-fix refuses.
#[cfg(unix)]
#[test]
fn norm_h3_continuation_quoted_refuses() {
    let tmp = fixture::scratch_root("fr7-n3q-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "n3q");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("real.inc"),
        format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
    )
    .unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("re\\"),
        b"[core]\n\trepositoryformatversion = 0\n",
    )
    .unwrap();
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(!text.contains("[filter"), "no direct driver: {text}");
    text.push_str("\n[include]\n\tpath = \"inc/re\\\nal.inc\"\n");
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    assert!(
        std::fs::read(&config_path)
            .unwrap()
            .ends_with(b"[include]\n\tpath = \"inc/re\\\nal.inc\"\n"),
        "exact quoted-continuation bytes planted"
    );

    let (out, parsed) = norm_full_scan(tmp.path(), "n3q", &roots);
    norm_assert_refused("NORM-H3/quoted", &parsed, &sup, &marker, &log);
    let _ = stderr_text(&out);
}

/// NORM-H3 (backslash at EOF): the absorbed config ENDS with
/// `path = inc/eof.inc\` and NO trailing newline — git drops the
/// trailing backslash (probed 2.56.0: `include.path=inc/eof.inc`).
/// Driver in `inc/eof.inc`, clean decoy at the literal `inc/eof.inc\`
/// spelling the pre-fix raw leg kept. Pre-fix Clean + execution;
/// post-fix refuses.
#[cfg(unix)]
#[test]
fn norm_h3_continuation_backslash_eof_refuses() {
    let tmp = fixture::scratch_root("fr7-n3e-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "n3e");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("eof.inc"),
        format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
    )
    .unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("eof.inc\\"),
        b"[core]\n\trepositoryformatversion = 0\n",
    )
    .unwrap();
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(!text.contains("[filter"), "no direct driver: {text}");
    text.push_str("\n[include]\n\tpath = inc/eof.inc\\");
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    let planted = std::fs::read(&config_path).unwrap();
    assert!(
        planted.ends_with(b"[include]\n\tpath = inc/eof.inc\\"),
        "exact backslash-EOF bytes planted"
    );
    assert!(!planted.ends_with(b"\n"), "no trailing newline");

    let (out, parsed) = norm_full_scan(tmp.path(), "n3e", &roots);
    norm_assert_refused("NORM-H3/backslash-eof", &parsed, &sup, &marker, &log);
    let _ = stderr_text(&out);
}

/// NORM-H3 (join-then-comment-cut): `path = inc/re\` + newline +
/// `; comment` — git joins FIRST, then cuts the comment (probed 2.56.0:
/// `include.path=inc/re`). Driver in `inc/re`, clean decoy at the
/// literal `inc/re\` spelling the pre-fix raw leg kept. Pre-fix Clean +
/// execution; post-fix refuses.
#[cfg(unix)]
#[test]
fn norm_h3_continuation_join_then_comment_refuses() {
    let tmp = fixture::scratch_root("fr7-n3c-");
    let (roots, sup, _sub, marker, helper, log) = marker_submodule_layout(tmp.path(), "n3c");
    let absorbed_dir = sup.join(".git/modules/vendor/sub");
    let inc_dir = absorbed_dir.join("inc");
    repo_scan::privacy::private_dir_0700(&inc_dir).unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("re"),
        format!("[filter \"marker\"]\n\tclean = {}\n", helper.display()).as_bytes(),
    )
    .unwrap();
    repo_scan::privacy::private_write_0600(
        &inc_dir.join("re\\"),
        b"[core]\n\trepositoryformatversion = 0\n",
    )
    .unwrap();
    let config_path = absorbed_dir.join("config");
    let mut text = std::fs::read_to_string(&config_path).expect("absorbed config");
    assert!(!text.contains("[filter"), "no direct driver: {text}");
    text.push_str("\n[include]\n\tpath = inc/re\\\n; comment\n");
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    assert!(
        std::fs::read(&config_path)
            .unwrap()
            .ends_with(b"[include]\n\tpath = inc/re\\\n; comment\n"),
        "exact join-then-comment bytes planted"
    );

    let (out, parsed) = norm_full_scan(tmp.path(), "n3c", &roots);
    norm_assert_refused("NORM-H3/join-comment", &parsed, &sup, &marker, &log);
    let _ = stderr_text(&out);
}

/// NORM-H3 (trailing backslash, last line WITH newline): a plain repo
/// config whose final line is `path = <extra>\` + newline — git drops
/// the backslash and loads the target (probed 2.56.0). Library-level
/// (no scan, no execution surface): the read-only include evidence
/// (`scan_include_paths` via `config_dependencies`) must list the
/// joined target as an existing via-include dep. Pre-fix the evidence
/// named only the literal `<extra>\` spelling (missing).
#[cfg(unix)]
#[test]
fn norm_h3_continuation_trailing_backslash_dep() {
    let tmp = fixture::scratch_root("fr7-n3t-");
    let parent = tmp.path().join("repos");
    repo_scan::privacy::private_dir_0700(&parent).unwrap();
    let repo = fixture::normal_clone(&parent, "contgap");
    let extra = parent.join("extra.conf");
    repo_scan::privacy::private_write_0600(&extra, b"[core]\n\trepositoryformatversion = 0\n")
        .unwrap();
    let config_path = repo.join(".git/config");
    let mut text = std::fs::read_to_string(&config_path).unwrap();
    assert!(!text.contains("[include]"), "fixture has no include yet");
    text.push_str(&format!("\n[include]\n\tpath = {}\\\n", extra.display()));
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();
    assert!(
        std::fs::read(&config_path).unwrap().ends_with(b"\\\n"),
        "trailing backslash + newline planted"
    );

    let inspector = repo_scan::git::GixInspector::new();
    let instance = repo_scan::git::GitInspect::open_exact(&inspector, &repo)
        .expect("open with continued include");
    let deps = inspector.config_dependencies(&instance);
    assert!(
        deps.iter()
            .any(|d| d.via_include && d.exists && d.path == extra),
        "joined include target listed in deps: {deps:?}"
    );
}
