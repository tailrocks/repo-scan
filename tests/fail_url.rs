//! EXACT-2 target-URL credential regression: a target carrying userinfo,
//! any query/fragment tail (JWT/opaque/spaced/JSON values are not
//! key-identifiable), or an scp-like login must never persist verbatim into
//! the report, catalog, snapshot, mint row, terminal, or error echoes.
//! Rejectable forms exit 2 before any persistence; scp logins are
//! normalized before persist while `git@` stays accepted (RS-PRIV-10).
//! Fixture-scale only (tempdirs under /tmp, empty `--root`s, no scans).

use repo_scan::identity::{
    must_reject_target, redact_credentials, redact_target_for_display, sanitize_target_url,
    scrub_text,
};
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

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

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

/// Reject table: userinfo or any query/fragment tail fails closed, even
/// with benign-looking keys (normalization ignores tails, so nothing
/// legitimate is lost); plain shapes and scp logins stay accepted.
#[test]
fn exact2_target_reject_and_sanitize_table() {
    for url in [
        "https://user:pw@github.com/o/r",
        "https://token123@github.com/o/r",
        "https://github.com/o/r?jwt=EXACT2URLJWTCANARY01",
        "https://github.com/o/r?next=EXACT2URLOPAQUECANARY02",
        "https://github.com/o/r#jwt=EXACT2URLFRAGCANARY03",
        "https://github.com/o/r?page=2",
        "https://github.com/o/r?filter={\"password\":\"x\"}",
        "git@github.com:o/r?x=1",
        "ssh://git@github.com/o/r",
    ] {
        assert!(must_reject_target(url), "must reject {url}");
    }
    for url in [
        "https://github.com/o/r",
        "https://github.com/OWNER/REPO.git",
        "http://github.com/o/r",
        "ssh://github.com/o/r",
        "git@github.com:o/r.git",
        "EXACT2URLSCPCANARY04@github.com:o/r.git",
    ] {
        assert!(!must_reject_target(url), "must accept {url}");
    }
    // Sanitize: scp user normalizes to the conventional login, scheme
    // tails/userinfo strip, plain targets round-trip.
    assert_eq!(
        sanitize_target_url("EXACT2URLSCPCANARY04@github.com:o/r.git"),
        "git@github.com:o/r.git"
    );
    assert_eq!(
        sanitize_target_url("git@github.com:o/r.git"),
        "git@github.com:o/r.git"
    );
    assert_eq!(
        sanitize_target_url("https://github.com/o/r?jwt=x#y"),
        "https://github.com/o/r"
    );
    assert_eq!(
        sanitize_target_url("https://u:p@github.com/o/r"),
        "https://github.com/o/r"
    );
    assert_eq!(
        sanitize_target_url("https://github.com/OWNER/REPO.git"),
        "https://github.com/OWNER/REPO.git"
    );
    // The sanitized scp shape still resolves to the same canonical target.
    assert_eq!(
        repo_scan::identity::normalize_github_url(&sanitize_target_url(
            "EXACT2URLSCPCANARY04@github.com:OWNER/REPO.git"
        ))
        .as_deref(),
        Some("https://github.com/owner/repo")
    );
}

/// PUB-PRIV round: JWT/opaque values redact by key in query, fragment,
/// and spaced/JSON/CLI pairs; non-sensitive parameters still round-trip.
#[test]
fn exact2_pubpriv_round_covers_jwt_opaque() {
    assert_eq!(
        redact_credentials("https://github.com/o/r.git?jwt=SECRET"),
        "https://github.com/o/r.git?jwt=<redacted>"
    );
    assert_eq!(
        redact_credentials("https://h/o/r#jwt=SECRET"),
        "https://h/o/r#jwt=<redacted>"
    );
    assert_eq!(
        redact_credentials("https://h/o/r?opaque=SECRET"),
        "https://h/o/r?opaque=<redacted>"
    );
    assert_eq!(
        redact_credentials("https://host/o/r.git?page=2&per=50"),
        "https://host/o/r.git?page=2&per=50"
    );
    assert_eq!(scrub_text("--jwt SECRET"), "--jwt <redacted>");
    assert_eq!(
        scrub_text(r#"{"jwt": "SECRET"}"#),
        r#"{"jwt": "<redacted>"}"#
    );
    assert_eq!(scrub_text("jwt: SECRET"), "jwt: <redacted>");
    // Rejection echoes never carry secret bytes, however shaped.
    for url in [
        "https://u:p@github.com/o/r?jwt=SECRET",
        "https://github.com/o/r --token SECRET",
        "{\"password\":\"SECRET\"}",
        "EXACT2URLSCPCANARY04@github.com:o/r.git",
    ] {
        let shown = redact_target_for_display(url);
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(!shown.contains("EXACT2URLSCPCANARY04"), "{shown}");
    }
}

/// Rejectable targets exit 2 with no canary in any stream and no
/// persisted artifact (no catalog row, no report file).
#[test]
fn exact2_scan_rejects_credential_targets() {
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let root_str = root.to_str().expect("utf8").to_string();
    let vectors = [
        (
            "userinfo",
            "https://user:EXACT2URLUSERINFO10@github.com/o/r",
            "EXACT2URLUSERINFO10",
        ),
        (
            "jwt-q",
            "https://github.com/o/r?jwt=EXACT2URLJWTCANARY11",
            "EXACT2URLJWTCANARY11",
        ),
        (
            "opaque-q",
            "https://github.com/o/r?next=EXACT2URLOPAQUECANARY12",
            "EXACT2URLOPAQUECANARY12",
        ),
        (
            "jwt-f",
            "https://github.com/o/r#jwt=EXACT2URLFRAGCANARY13",
            "EXACT2URLFRAGCANARY13",
        ),
        (
            "json-q",
            "https://github.com/o/r?filter={\"password\":\"EXACT2URLJSONCANARY14\"}",
            "EXACT2URLJSONCANARY14",
        ),
    ];
    for (name, url, canary) in vectors {
        let state = dir.path().join(format!("state-{name}"));
        let cwd = dir.path().join(format!("cwd-{name}"));
        repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
        let out = run(
            &[
                "scan",
                url,
                "--root",
                root_str.as_str(),
                "--report",
                "rep.json",
            ],
            &cwd,
            &state,
        );
        assert_eq!(
            out.status.code(),
            Some(2),
            "{name}: stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !contains_bytes(&out.stdout, canary.as_bytes()),
            "{name}: canary on stdout"
        );
        assert!(
            !contains_bytes(&out.stderr, canary.as_bytes()),
            "{name}: canary on stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!cwd.join("rep.json").exists(), "{name}: no report file");
        assert!(
            !state.join("payload").join("catalog.db").exists(),
            "{name}: mint never ran"
        );
        assert_no_canary_in_state(&state, canary);
    }
    // Terminal mode (no --report) rejects the same way: exit 2, clean stdout.
    let state = dir.path().join("state-term");
    let cwd = dir.path().join("cwd-term");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let url = "https://github.com/o/r?jwt=EXACT2URLTERMCANARY15";
    let out = run(&["scan", url, "--root", root_str.as_str()], &cwd, &state);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!contains_bytes(&out.stdout, b"EXACT2URLTERMCANARY15"));
    assert!(!contains_bytes(&out.stderr, b"EXACT2URLTERMCANARY15"));
}

/// An scp-like login stays accepted, but the raw login never persists:
/// report, catalog, and snapshot bytes carry no canary in either file or
/// terminal mode.
#[test]
fn exact2_scan_scp_user_never_persists() {
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let root_str = root.to_str().expect("utf8").to_string();
    let canary = "EXACT2URLSCPCANARY16";
    let url = format!("{canary}@github.com:o/r.git");

    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let out = run(
        &[
            "scan",
            url.as_str(),
            "--root",
            root_str.as_str(),
            "--report",
            "rep.json",
        ],
        &cwd,
        &state,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report_bytes = std::fs::read(cwd.join("rep.json")).expect("read report");
    assert!(!contains_bytes(&report_bytes, canary.as_bytes()));
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("report is valid JSON");
    assert_eq!(
        report["scan"]["target_url"].as_str(),
        Some("<redacted>@github.com:o/r.git")
    );
    assert_no_canary_in_state(&state, canary);
    assert!(
        state.join("payload").join("catalog.db").is_file(),
        "catalog row was minted (sanitized)"
    );

    // Terminal mode renders no canary either.
    let state_t = dir.path().join("state-term");
    let cwd_t = dir.path().join("cwd-term");
    repo_scan::privacy::private_dir_0700(&cwd_t).expect("mkdir");
    let out = run(
        &["scan", url.as_str(), "--root", root_str.as_str()],
        &cwd_t,
        &state_t,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!contains_bytes(&out.stdout, canary.as_bytes()));
    assert!(!contains_bytes(&out.stderr, canary.as_bytes()));
    assert_no_canary_in_state(&state_t, canary);
}

/// Targets that fail shape validation echo the display-safe form: spaced
/// and JSON secrets never reach stderr verbatim.
#[test]
fn exact2_reject_echo_scrubs_spaced_pairs() {
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let root_str = root.to_str().expect("utf8").to_string();
    for (name, url, canary) in [
        (
            "spaced",
            "https://github.com/o/r --token EXACT2URLSPACEDCANARY17",
            "EXACT2URLSPACEDCANARY17",
        ),
        (
            "json",
            "{\"password\":\"EXACT2URLJSONCANARY18\"}",
            "EXACT2URLJSONCANARY18",
        ),
    ] {
        let state = dir.path().join(format!("state-{name}"));
        let cwd = dir.path().join(format!("cwd-{name}"));
        repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
        let out = run(&["scan", url, "--root", root_str.as_str()], &cwd, &state);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{name}: stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !contains_bytes(&out.stderr, canary.as_bytes()),
            "{name}: canary on stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_no_canary_in_state(&state, canary);
    }
}

/// Finding 3: cached-query + superseded-resume target echoes strip opaque
/// query/fragment tails (`next=` is not key-identifiable, so bare
/// `redact_credentials` leaks it). Canaries are synthetic, never secrets.
#[test]
fn finding3_query_resume_strip_opaque_tails() {
    use repo_scan::store::{NewScan, Store, TursoStore};
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let root_str = root.to_str().expect("utf8").to_string();
    let state = dir.path().join("state");
    let cwd = dir.path().join("cwd");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let out = run(
        &[
            "scan",
            "https://github.com/o/r",
            "--root",
            root_str.as_str(),
            "--report",
            "rep.json",
        ],
        &cwd,
        &state,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "seed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for (url, canary) in [
        (
            "https://github.com/o/r?next=FINDING3QUERYCANARY01",
            "FINDING3QUERYCANARY01",
        ),
        (
            "https://github.com/o/r#next=FINDING3FRAGCANARY02",
            "FINDING3FRAGCANARY02",
        ),
    ] {
        let out = run(&["query", url, "--cached"], &cwd, &state);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{url}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !contains_bytes(&out.stdout, canary.as_bytes()),
            "query canary on stdout: {url}"
        );
        assert!(
            !contains_bytes(&out.stderr, canary.as_bytes()),
            "query canary on stderr: {url}"
        );
    }
    let canary_u = "FINDING3UNRESOLVED03";
    let unresolved = format!("https://example.com/o/r?next={canary_u}");
    let out = run(&["query", unresolved.as_str(), "--cached"], &cwd, &state);
    assert_eq!(
        out.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!contains_bytes(&out.stdout, canary_u.as_bytes()));
    assert!(!contains_bytes(&out.stderr, canary_u.as_bytes()));
    let canary_s = "FINDING3RESUMECANARY04";
    let legacy_raw = format!("https://github.com/o/r?next={canary_s}");
    let canonical =
        repo_scan::identity::normalize_github_url("https://github.com/o/r").expect("canonical");
    let stale_id = "scan-stale-finding3";
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let store = TursoStore::open(&state.join("payload").join("catalog.db"))
            .await
            .expect("open catalog");
        let inserted = store
            .create_scan_request(
                &NewScan {
                    id: stale_id,
                    url_raw: legacy_raw.as_bytes(),
                    url_canonical: Some(canonical.as_bytes()),
                    scope: "roots",
                    status_mode: "summary",
                    report_dest: None,
                },
                repo_scan::store::now_ms(),
            )
            .await
            .expect("insert stale");
        assert!(inserted);
        store.close().await.expect("close");
    });
    let out = run(
        &[
            "scan",
            "https://github.com/o/r",
            "--root",
            root_str.as_str(),
            "--report",
            "rep2.json",
        ],
        &cwd,
        &state,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "supersede: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(&["resume", stale_id], &cwd, &state);
    assert_eq!(
        out.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !contains_bytes(&out.stdout, canary_s.as_bytes()),
        "resume canary on stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!contains_bytes(&out.stderr, canary_s.as_bytes()));
}
