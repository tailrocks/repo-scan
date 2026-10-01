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
