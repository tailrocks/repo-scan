//! RS-PRIV-01..12 regression (binary + lib): FD-relative clear, exact
//! marker binding, scp/redaction policy, creation primitive, query
//! budgets/scrub, tshm enumeration, CI provenance. Tempdirs only; the
//! binary tests run `CARGO_BIN_EXE_repo-scan` end to end.

use repo_scan::identity::{has_userinfo, redact_credentials, scrub_text, strip_userinfo};
use repo_scan::store::{now_ms, Store, TursoStore};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

fn run(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    ProcCommand::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

fn stdout_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt")
}

fn marker_report(report_id: &str) -> String {
    format!(
        "{{\"schema_version\":\"{}\",\
        \"tool\":{{\"name\":\"repo-scan\",\"version\":\"test\"}},\
        \"report_id\":\"{report_id}\"}}",
        repo_scan::report::model::SCHEMA_VERSION
    )
}

/// A fresh owned catalog plus `report-snapshots/` and `staging/` dirs.
/// No ownership marker: the binding tests write one explicitly.
fn owned_payload(dir: &Path) -> (PathBuf, PathBuf) {
    let state = dir.join("state");
    let payload = state.join("payload");
    repo_scan::privacy::private_dir_0700(&payload.join("report-snapshots")).expect("mkdir");
    repo_scan::privacy::private_dir_0700(&payload.join("staging")).expect("mkdir");
    runtime().block_on(async {
        let store = TursoStore::open(&payload.join("catalog.db"))
            .await
            .expect("open");
        store.close().await.expect("close");
    });
    (state, payload)
}

fn live_db_id(db: &Path) -> String {
    runtime().block_on(async {
        let store = TursoStore::open(db).await.expect("open");
        let id = store
            .catalog_db_id()
            .await
            .expect("db_id")
            .expect("db_id row");
        store.close().await.expect("close");
        id
    })
}

fn write_marker(payload: &Path, db_id: &str) {
    let text = format!(
        "{}\ndb_id={db_id}\nwritten_ms=1\npid=1\n",
        repo_scan::store::owner::OWNER_MARKER_TAG
    );
    repo_scan::privacy::private_write_0600(
        &payload.join(repo_scan::store::owner::OWNER_MARKER_NAME),
        text.as_bytes(),
    )
    .expect("marker");
}

/// RS-PRIV-01: the FD-relative clear removes verified tool files and keeps
/// foreign files plus symlinks, exit 0.
#[cfg(unix)]
#[test]
fn rspriv01_fd_clear_removes_verified_keeps_rest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let snapshots = payload.join("report-snapshots");
    let tool = snapshots.join("report-toola.json");
    let bytes = marker_report("report-toola");
    repo_scan::privacy::private_write_0600(&tool, bytes.as_bytes()).expect("write");
    let foreign = snapshots.join("evil.txt");
    repo_scan::privacy::private_write_0600(&foreign, b"not tool state").expect("write");
    let target = dir.path().join("target.txt");
    repo_scan::privacy::private_write_0600(&target, b"target").expect("write");
    std::os::unix::fs::symlink(&target, snapshots.join("link.json")).expect("symlink");

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(!tool.exists(), "verified tool file removed");
    assert!(
        !payload.join("catalog.db").exists(),
        "owned catalog removed"
    );
    assert!(foreign.is_file(), "foreign file kept");
    assert!(
        std::fs::symlink_metadata(snapshots.join("link.json"))
            .expect("meta")
            .file_type()
            .is_symlink(),
        "symlink kept"
    );
    assert_eq!(std::fs::read(&target).expect("read"), b"target");
}

/// RS-PRIV-02: the marker drops only on an exact live-`db_id` binding — a
/// forged `db_id` keeps the marker while tool-shaped bytes still authorize
/// the engine file; the exact id drops both.
#[cfg(unix)]
#[test]
fn rspriv02_marker_drops_only_on_exact_binding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    write_marker(&payload, "db-forged");
    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        !payload.join("catalog.db").exists(),
        "tool-shaped db removed"
    );
    assert!(
        payload
            .join(repo_scan::store::owner::OWNER_MARKER_NAME)
            .is_file(),
        "forged marker preserved"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let id = live_db_id(&payload.join("catalog.db"));
    write_marker(&payload, &id);
    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(!payload.join("catalog.db").exists(), "bound db removed");
    assert!(
        !payload
            .join(repo_scan::store::owner::OWNER_MARKER_NAME)
            .exists(),
        "bound marker removed"
    );
}

/// RS-PRIV-05: the privacy constructors route through the ancestor-pinned
/// primitive — a symlinked ancestor is refused, never created through.
#[cfg(unix)]
#[test]
fn rspriv05_privacy_constructors_use_pinned_primitive() {
    let t = tempfile::tempdir().unwrap();
    let real = t.path().join("real");
    repo_scan::privacy::private_dir_0700(&real).unwrap();
    let link = t.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = repo_scan::privacy::private_dir_0700(&link.join("sub"))
        .expect_err("symlinked ancestor refused");
    assert!(err.to_string().contains("symlink"), "{err}");
    assert!(!real.join("sub").exists());
    let target = t.path().join("target.txt");
    repo_scan::privacy::private_write_0600(&target, b"x").unwrap();
    let file_link = t.path().join("file-link");
    std::os::unix::fs::symlink(&target, &file_link).unwrap();
    let err = repo_scan::privacy::private_write_0600(&file_link, b"y")
        .expect_err("symlinked file refused");
    assert!(err.to_string().contains("symlink"), "{err}");
    assert_eq!(std::fs::read(&target).unwrap(), b"x");
}

/// RS-PRIV-06: a cached query against an unbound catalog (no marker)
/// reports "no suitable catalog", exit 3 — it never serves the bytes.
#[test]
fn rspriv06_query_serves_only_bound_catalogs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, _payload) = owned_payload(dir.path());
    let out = run(
        &["query", "https://github.com/owner/repo", "--cached"],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(stdout.contains("suitable_catalog: false"), "{stdout}");
}

/// RS-PRIV-09: snapshot-row resolution past the stem budget stops with an
/// explicit INCOMPLETE report, never a silent partial clear.
#[cfg(unix)]
#[test]
fn rspriv09_snapshot_budget_reports_incomplete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let snapshots = payload.join("report-snapshots");
    for n in 0..10_200u32 {
        let name = format!("r{n:05}.json");
        std::fs::write(snapshots.join(name), b"{}").expect("seed");
    }
    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(stdout.contains("INCOMPLETE"), "{stdout}");
    assert!(stdout.contains("truncated"), "{stdout}");
}

/// RS-PRIV-10: scp-like users redact on display; detection stays
/// scheme-scoped so the CLI keeps accepting `git@` targets; internal
/// strip keeps the login name; emails and bare paths are untouched.
#[test]
fn rspriv10_scp_like_user_redacts() {
    assert_eq!(
        redact_credentials("git@github.com:o/r.git"),
        "<redacted>@github.com:o/r.git"
    );
    assert_eq!(
        redact_credentials("secret-token@github.com:o/r.git"),
        "<redacted>@github.com:o/r.git"
    );
    assert!(!has_userinfo("git@github.com:o/r.git"));
    assert_eq!(
        strip_userinfo("git@github.com:o/r.git"),
        "git@github.com:o/r.git"
    );
    assert_eq!(redact_credentials("user@example.com"), "user@example.com");
    assert_eq!(redact_credentials("host:path"), "host:path");
    let scrubbed = scrub_text("clone git@github.com:o/r.git failed");
    assert!(
        scrubbed.contains("<redacted>@github.com:o/r.git"),
        "{scrubbed}"
    );
    assert!(!scrubbed.contains("git@github.com"), "{scrubbed}");
}

/// RS-PRIV-12: cached-query output scrubs secrets out of stored paths —
/// escaping alone is not redaction.
#[test]
fn rspriv12_query_output_scrubs_stored_paths() {
    use repo_scan::store::{NewGitInstance, NewRemote};
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let db = payload.join("catalog.db");
    let now = now_ms();
    runtime().block_on(async {
        let store = TursoStore::open(&db).await.expect("open");
        store
            .create_generation("roots", "complete", None, now)
            .await
            .expect("generation");
        store
            .upsert_git_instance(
                &NewGitInstance {
                    id: "repo-1",
                    git_path: b"/wk/repo?token=zzz-leak-query",
                    common_path: b"/wk/repo",
                    incarnation: "1",
                    format: "git-files",
                    bare: Some(false),
                    object_format: "sha1",
                    disposition: "confirmed",
                    evidence_json: "[]",
                },
                now,
            )
            .await
            .expect("instance");
        store
            .upsert_remote(
                &NewRemote {
                    id: "rem-1",
                    instance_id: "repo-1",
                    checkout_scope_id: None,
                    name: b"origin",
                    role: "fetch",
                    url: b"https://github.com/owner/repo",
                    canonical_url: Some(b"https://github.com/owner/repo"),
                },
                now,
            )
            .await
            .expect("remote");
        let id = store.catalog_db_id().await.expect("db_id").expect("row");
        store.close().await.expect("close");
        write_marker(&payload, &id);
    });
    let out = run(
        &["query", "https://github.com/owner/repo", "--cached"],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(stdout.contains("matches: 1"), "{stdout}");
    assert!(stdout.contains("<redacted>"), "{stdout}");
    assert!(!stdout.contains("zzz-leak-query"), "{stdout}");
}

/// RS-CI-01: the audit workflow records toolchain, binary, and runner
/// provenance with every run.
#[test]
fn rsci01_audit_provenance_recorded() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wf = std::fs::read_to_string(root.join("docs/workflows/audit.yml")).expect("audit.yml");
    for needle in [
        "rustc --version --verbose",
        "cargo-home/bin/cargo-audit",
        "cargo-home/bin/cargo-deny",
        "runner_image_os=$ImageOS",
        "runner_image_version=$ImageVersion",
        "/etc/os-release",
    ] {
        assert!(wf.contains(needle), "audit.yml must contain {needle:?}");
    }
}
