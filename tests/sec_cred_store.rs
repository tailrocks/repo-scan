//! RSF-SEC-TARGET-URL + RSF-SEC-FILE-MODE regressions: credential-bearing
//! scan targets are detectable/redactable end to end, and tool state layout
//! is owner-only with symlinked components refused. Fixtures live under
//! `/tmp` only (`tempdir_in`); no machine scans, no repo writes.

use repo_scan::identity::{has_userinfo, normalize_github_url, redact_credentials, strip_userinfo};
use repo_scan::report::model::Report;
use repo_scan::store::owner::{ensure_private_dir_all, lock_path, payload_dir, OwnerGuard};

fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp")
}

fn example_report() -> Report {
    let bytes = include_bytes!("data/example-report.json");
    serde_json::from_slice(bytes).expect("example parses")
}

// ---------------------------------------------------------------------------
// RSF-SEC-TARGET-URL: userinfo is detected, redacted, and never rendered raw
// ---------------------------------------------------------------------------

#[test]
fn rsf_sec_target_url_userinfo_detected_and_redacted() {
    // Detection table: scheme userinfo yes, plain/scp-like no.
    assert!(has_userinfo("https://user:s3cr3t@github.com/o/r.git"));
    assert!(has_userinfo("https://token123@github.com/o/r.git"));
    assert!(has_userinfo("https://user:<redacted>@github.com/o/r.git"));
    assert!(!has_userinfo("https://github.com/o/r.git"));
    assert!(!has_userinfo("git@github.com:o/r.git"));
    assert!(!has_userinfo("https://@github.com/o/r.git"));

    // Redaction removes the secret but keeps a safe, normalizable shape.
    let redacted = redact_credentials("https://user:s3cr3t@github.com/OWNER/REPO.git");
    assert!(redacted.contains("<redacted>"), "{redacted}");
    assert!(!redacted.contains("s3cr3t"), "{redacted}");
    assert_eq!(
        normalize_github_url(&redacted).as_deref(),
        Some("https://github.com/owner/repo")
    );
    let bare = redact_credentials("https://token123@github.com/OWNER/REPO.git");
    assert_eq!(bare, "https://<redacted>@github.com/OWNER/REPO.git");

    // Stripping removes userinfo entirely for internal reuse (resume of a
    // legacy row): no `@` remains and the canonical target matches.
    let stripped = strip_userinfo("https://user:s3cr3t@github.com/OWNER/REPO.git");
    assert_eq!(stripped, "https://github.com/OWNER/REPO.git");
    assert!(!has_userinfo(&stripped));
    assert_eq!(
        normalize_github_url(&stripped).as_deref(),
        Some("https://github.com/owner/repo")
    );
    assert_eq!(
        strip_userinfo("git@github.com:o/r.git"),
        "git@github.com:o/r.git"
    );

    // Terminal rendering redacts: escape_display alone is not redaction.
    let mut report = example_report();
    report.scan.target_url = "https://user:s3cr3t@github.com/OWNER/REPO".to_string();
    let mut out: Vec<u8> = Vec::new();
    repo_scan::report::render::render_terminal(&report, &mut out).expect("render");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("<redacted>"), "{text}");
    assert!(!text.contains("s3cr3t"), "{text}");
    assert!(text.contains("user:"), "{text}");
}

// ---------------------------------------------------------------------------
// RSF-SEC-FILE-MODE: 0o700 dirs / 0o600 files, symlinked state refused
// ---------------------------------------------------------------------------

#[test]
fn rsf_sec_file_mode_private_layout_and_symlink_refusal() {
    let dir = tmpdir();
    let state = dir.path().join("state");

    let guard = OwnerGuard::acquire(&state).expect("acquire");
    assert_eq!(guard.state_dir(), state.as_path());
    assert!(payload_dir(&state).is_dir());
    assert!(lock_path(&state).is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| {
            std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777
        };
        assert_eq!(mode(&state), 0o700, "state dir");
        assert_eq!(mode(&payload_dir(&state)), 0o700, "payload dir");
        assert_eq!(mode(&lock_path(&state)), 0o600, "lock file");

        // Staging/snapshot dirs created through the same helper are 0o700.
        let staging = payload_dir(&state).join("staging");
        let snapshots = payload_dir(&state).join("report-snapshots");
        ensure_private_dir_all(&staging).expect("staging");
        ensure_private_dir_all(&snapshots).expect("snapshots");
        assert_eq!(mode(&staging), 0o700);
        assert_eq!(mode(&snapshots), 0o700);

        // Pre-existing lax dirs are tightened, not left behind.
        let lax = dir.path().join("lax");
        std::fs::create_dir_all(&lax).expect("lax");
        std::fs::set_permissions(&lax, std::fs::Permissions::from_mode(0o755)).expect("chmod lax");
        ensure_private_dir_all(&lax).expect("tighten");
        assert_eq!(mode(&lax), 0o700);
    }
    #[cfg(not(unix))]
    {
        ensure_private_dir_all(&payload_dir(&state).join("staging")).expect("staging");
    }
    drop(guard);

    // Symlinked state components are refused (fail closed).
    #[cfg(unix)]
    {
        let real = dir.path().join("real-payload");
        std::fs::create_dir_all(&real).expect("real");
        let linked_state = dir.path().join("linked-state");
        std::fs::create_dir_all(&linked_state).expect("linked state");
        std::os::unix::fs::symlink(&real, payload_dir(&linked_state)).expect("symlink");
        let err = OwnerGuard::acquire(&linked_state).expect_err("payload symlink refused");
        assert!(err.to_string().contains("symlink"), "{err}");

        let target = dir.path().join("link-target");
        ensure_private_dir_all(&target).expect("target");
        let link = dir.path().join("staging-link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let err = ensure_private_dir_all(&link).expect_err("dir symlink refused");
        assert!(err.to_string().contains("symlink"), "{err}");
    }
}
