//! RETEST-1..4 credential-redaction regression: no credential-shaped
//! byte may persist into, or emit from, report/terminal/catalog/snapshot
//! paths. Every listed canary form is asserted ABSENT from persisted and
//! emitted bytes (canary matrix). Fixtures live under `/tmp` only (0700
//! dirs); no machine scans, no repo writes. Canaries are synthetic.

mod common;

use common::fixture;
use repo_scan::git::{GitInspect, GixInspector};
use repo_scan::identity::{
    classify_remote, redact_credentials, redact_remote_url, redact_target_for_display,
    sanitize_target_url, scrub_text, REDACTED_URL,
};
use repo_scan::model::StatusMode;
use repo_scan::privacy::{private_dir_0700, private_write_0600};
use repo_scan::report::builder::{stream_report_from_store, ReportInputs};
use repo_scan::report::model::Report;
use repo_scan::report::render::render_terminal;
use repo_scan::store::{NewCheckout, NewGitInstance, NewRemote, NewVolume, Store, TursoStore};
use std::path::{Path, PathBuf};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn test_inputs(report_id: &str) -> ReportInputs {
    ReportInputs {
        report_id: report_id.to_string(),
        created_at_ms: 1_759_154_400_000,
        scan_id: "scan-test-1".to_string(),
        generation: 1,
        epoch: 1,
        catalog_revision: 7,
        target_url: "https://github.com/OWNER/REPO".to_string(),
        canonical_url: Some("https://github.com/owner/repo".to_string()),
        scope: "roots".to_string(),
        scan_state: "complete".to_string(),
        started_at_ms: 1_759_154_398_000,
        finished_at_ms: Some(1_759_154_400_000),
        superseded_by: None,
        cached: false,
        status_mode: StatusMode::Summary,
        directories_complete: 2,
        tasks_pending: 0,
        scope_boundaries: Vec::new(),
        profile: "conservative".to_string(),
        cpu_target_cores: 1.0,
        rss_target_bytes: 268_435_456,
        peak_rss_bytes: None,
        cpu_seconds: None,
        enumerated_entries: 8,
        db_transactions: 3,
        db_sync_calls: None,
        source_commit: None,
        include_nonmatching: false,
        coverage_filesystem: None,
        coverage_identity: None,
        coverage_status: None,
        roots: Vec::new(),
        storage_links: Vec::new(),
        aliases: Vec::new(),
        candidates: Vec::new(),
        generated_artifacts: Vec::new(),
    }
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

fn run(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    std::process::Command::new(binary())
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

/// RETEST-1: a PAT-shaped username is credential material — never emitted
/// intact by any userinfo redaction path. Plain logins still round-trip
/// (existing `user:<redacted>` contract pinned).
#[test]
fn retest1_pat_shaped_username_never_emitted_intact() {
    // PAT families, OAuth placeholders, secret-worded and marker-less
    // token-shaped usernames: the username must not survive intact.
    for user in [
        "ghp_FAILREDACTPAT01",
        "github_pat_FAILREDACT02",
        "glpat-FAILREDACT03",
        "x-access-token",
        "oauth2",
        "FAILREDACTPATCANARY04",
        "xT9qL2mZ8vB4nR7sK1wE5dFAILREDACT05",
    ] {
        let url = format!("https://{user}:x@github.com/o/r.git");
        for shown in [redact_credentials(&url), redact_remote_url(&url)] {
            assert!(!shown.contains(user), "username intact: {shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
        }
        // Percent-encoded usernames match through the encoding.
        let encoded = format!("https://{}:x@github.com/o/r.git", user.replace('A', "%41"));
        if encoded != url {
            for shown in [redact_credentials(&encoded), redact_remote_url(&encoded)] {
                assert_eq!(shown, "https://<redacted>:<redacted>@github.com/o/r.git");
            }
        }
    }
    // Conventional `user:pass` logins keep the documented shape.
    assert_eq!(
        redact_credentials("https://user:secret@github.com/o/r.git"),
        "https://user:<redacted>@github.com/o/r.git"
    );
    assert_eq!(
        redact_remote_url("https://user:secret@github.com/o/r.git"),
        "https://user:<redacted>@github.com/o/r.git"
    );
    // Bare token-as-username and scp users still fully redact.
    assert_eq!(
        redact_remote_url("https://token123@github.com/o/r.git"),
        "https://<redacted>@github.com/o/r.git"
    );
    assert_eq!(
        redact_remote_url("git@github.com:o/r.git"),
        "<redacted>@github.com:o/r.git"
    );
    // Classifier evidence (persisted to catalog + report) carries no
    // intact PAT username.
    let (_, evidence) = classify_remote(
        "https://github.com/o/r",
        "https://ghp_FAILREDACTPAT06:x@github.com/o/r.git",
        "fetch",
    );
    assert!(!evidence.is_empty());
    for line in &evidence {
        assert!(!line.contains("FAILREDACTPAT06"), "{line}");
    }
}

/// RETEST-2: opaque query/fragment tails (and scp `?`/`#` tails) drop in
/// every remote/report construction path. Strict form drops all tails;
/// key-based free-text scrub keeps non-sensitive `k=v` pairs (pinned)
/// but redacts opaque valueless segments.
#[test]
fn retest2_opaque_tails_dropped_in_remote_paths() {
    // Strict remote form: every tail shape drops entirely.
    for (url, canary) in [
        (
            "https://github.com/o/r?next=FAILREDACTOPAQUE10",
            "FAILREDACTOPAQUE10",
        ),
        (
            "https://github.com/o/r#next=FAILREDACTFRAG11",
            "FAILREDACTFRAG11",
        ),
        (
            "https://github.com/o/r?FAILREDACTBARE12",
            "FAILREDACTBARE12",
        ),
        (
            "https://github.com/o/r#FAILREDACTBARE13",
            "FAILREDACTBARE13",
        ),
        ("https://github.com/o/r.git?page=2&per=50", "page=2"),
        (
            "git@github.com:o/r.git?opaque=FAILREDACTSCP14",
            "FAILREDACTSCP14",
        ),
        ("git@github.com:o/r.git#FAILREDACTSCP15", "FAILREDACTSCP15"),
        (
            "https://user:x@github.com/o/r?next=FAILREDACTMIX16",
            "FAILREDACTMIX16",
        ),
    ] {
        let shown = redact_remote_url(url);
        assert!(!shown.contains(canary), "{url} -> {shown}");
        let (_, evidence) = classify_remote("https://github.com/o/r", url, "fetch");
        for line in &evidence {
            assert!(!line.contains(canary), "{url} evidence: {line}");
        }
    }
    assert_eq!(
        redact_remote_url("https://github.com/o/r.git?page=2&per=50"),
        "https://github.com/o/r.git"
    );
    assert_eq!(
        redact_remote_url("git@github.com:o/r.git?opaque=x"),
        "<redacted>@github.com:o/r.git"
    );
    // Plain shapes round-trip through the strict form.
    assert_eq!(
        redact_remote_url("https://github.com/o/r.git"),
        "https://github.com/o/r.git"
    );
    // Free-text key-based scrub still preserves non-sensitive `k=v`
    // pairs (existing contract pinned)...
    assert_eq!(
        redact_credentials("https://host/o/r.git?next=/x&token=abc#sig=def"),
        "https://host/o/r.git?next=/x&token=<redacted>#sig=<redacted>"
    );
    assert_eq!(
        redact_credentials("https://host/o/r.git?page=2&per=50"),
        "https://host/o/r.git?page=2&per=50"
    );
    // ...but opaque valueless segments redact even there.
    for (url, canary) in [
        ("https://h/o/r?FAILREDACTBARE17", "FAILREDACTBARE17"),
        ("https://h/o/r#FAILREDACTBARE18", "FAILREDACTBARE18"),
        ("https://h/o/r?a=1&FAILREDACTBARE19&b=2", "FAILREDACTBARE19"),
    ] {
        let shown = redact_credentials(url);
        assert!(!shown.contains(canary), "{url} -> {shown}");
    }
    // Scp tails strip in the persist-sanitize path too.
    assert_eq!(
        sanitize_target_url("git@github.com:o/r.git?x=1#y"),
        "git@github.com:o/r.git"
    );
}

/// RETEST-3: target display fails closed on malformed/unparseable input —
/// redact or refuse, never echo. Well-formed shapes keep useful echoes.
#[test]
fn retest3_display_fails_closed_on_malformed() {
    // Malformed/unparseable: refused, never echoed.
    for url in [
        "",
        "   ",
        "not-a-url",
        "not a url at all",
        "not-a-url FAILREDACTMALFORMED20",
        "https://github.com/o/r --token FAILREDACTMALFORMED21",
        "{\"password\":\"FAILREDACTMALFORMED22\"}",
        "https://user:secret/ret@github.com/o/r",
        "https://host/o/r\n?x=1",
        "owner/repo",
        "/srv/git/o/r.git",
        "C:\\repos\\o",
    ] {
        let shown = redact_target_for_display(url);
        assert_eq!(shown, REDACTED_URL, "{url:?} -> {shown:?}");
        assert!(!shown.contains("FAILREDACTMALFORMED"), "{shown}");
    }
    // Well-formed shapes keep host/path echoes (useful errors), with
    // userinfo redacted and tails stripped.
    assert_eq!(
        redact_target_for_display("https://github.com/o/r"),
        "https://github.com/o/r"
    );
    assert_eq!(
        redact_target_for_display("https://example.com/o/r"),
        "https://example.com/o/r"
    );
    assert_eq!(
        redact_target_for_display("https://u:p@github.com/o/r?jwt=x#y"),
        "https://u:<redacted>@github.com/o/r"
    );
    assert_eq!(
        redact_target_for_display("EXACT2URLSCPCANARY04@github.com:o/r.git"),
        "<<redacted>@github.com:o/r.git"
    );
}

/// RETEST-4: sensitive-key matching unescapes-then-matches — escaped keys
/// (`\u0073ecret`, `\x`, percent-double-encoded) must not evade.
#[test]
fn retest4_escaped_keys_unescape_then_match() {
    // JSON quoted keys with `\uXXXX` escapes (the reported evasion).
    for (text, canary) in [
        ("{\"\\u0073ecret\": \"FAILREDACTESC30\"}", "FAILREDACTESC30"),
        (
            "{\"\\u0074\\u006f\\u006b\\u0065\\u006e\": \"FAILREDACTESC31\"}",
            "FAILREDACTESC31",
        ),
        ("{\"\\x73ecret\": \"FAILREDACTESC32\"}", "FAILREDACTESC32"),
        (
            "{\"\\u0050assword\": \"FAILREDACTESC33\"}",
            "FAILREDACTESC33",
        ),
        // Same-token `key=value` pairs with escaped keys.
        ("\"\\u0073ecret\"=FAILREDACTESC34", "FAILREDACTESC34"),
        ("\\u0074oken:FAILREDACTESC35", "FAILREDACTESC35"),
        // Spaced and CLI shapes with escaped keys.
        ("\\u0073ecret: FAILREDACTESC36", "FAILREDACTESC36"),
        ("--\\u0070assword FAILREDACTESC37", "FAILREDACTESC37"),
    ] {
        let shown = scrub_text(text);
        assert!(!shown.contains(canary), "{text} -> {shown}");
        assert!(shown.contains("<redacted>"), "{text} -> {shown}");
    }
    // Query/fragment keys: escaped and double-encoded forms match.
    for (url, canary) in [
        (
            "https://h/o/r?\\u0073ecret=FAILREDACTESC38",
            "FAILREDACTESC38",
        ),
        (
            "https://h/o/r?%5Cu0073ecret=FAILREDACTESC39",
            "FAILREDACTESC39",
        ),
        (
            "https://h/o/r#\\u0074oken=FAILREDACTESC40",
            "FAILREDACTESC40",
        ),
    ] {
        let shown = redact_credentials(url);
        assert!(!shown.contains(canary), "{url} -> {shown}");
    }
    // Plain sensitive pairs still redact (existing contract pinned).
    assert_eq!(
        scrub_text("{\"password\": \"secret\"}"),
        "{\"password\": \"<redacted>\"}"
    );
    assert_eq!(scrub_text("token: abc"), "token: <redacted>");
    assert_eq!(
        scrub_text("ordinary prose, nothing secret"),
        "ordinary prose, nothing secret"
    );
}

/// RETEST-1/2/4 at the emission boundary: legacy catalog rows carrying a
/// PAT-shaped username, an opaque query tail, and escaped-key JSON error
/// text stream no canary bytes into the report or the terminal render.
#[test]
fn retest_emission_boundary_drops_legacy_canaries() {
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let db = dir.path().join("payload").join("catalog.db");
    let store = runtime().block_on(async { TursoStore::open(&db).await.expect("open") });
    let now = 1_759_154_400_000;
    let canaries = [
        "FAILREDACTLEGACYPAT70",
        "FAILREDACTLEGACYTAIL71",
        "FAILREDACTLEGACYESC72",
    ];
    let evidence = serde_json::to_string(&vec![
        "Effective origin fetch URL matches the target.".to_string()
    ])
    .expect("json");
    runtime().block_on(async {
        store
            .upsert_volume(
                &NewVolume {
                    id: "vol-1",
                    native_identity: Some("native-1"),
                    namespace: "ns-1",
                    filesystem: Some("apfs"),
                    kind: "local",
                    state: "available",
                },
                Some(now),
            )
            .await
            .expect("volume");
        let root = store
            .upsert_dir(None, b"/", "/", "vol-1", "obj-root", "1", now)
            .await
            .expect("root dir");
        store
            .upsert_dir(Some(root), b"repo", "/repo", "vol-1", "obj-repo", "1", now)
            .await
            .expect("child dir");
        store
            .upsert_git_instance(
                &NewGitInstance {
                    id: "repo-1",
                    git_path: b"/repo/.git",
                    common_path: b"/repo/.git",
                    incarnation: "1",
                    format: "git-files",
                    bare: Some(false),
                    object_format: "sha1",
                    disposition: "confirmed",
                    evidence_json: &evidence,
                },
                now,
            )
            .await
            .expect("instance");
        store
            .upsert_checkout(
                &NewCheckout {
                    id: "co-1",
                    instance_id: "repo-1",
                    root_path: Some(b"/repo"),
                    git_path: b"/repo/.git",
                    relationship: "main",
                    availability: "present",
                    head_state: "branch",
                    head_ref: Some(b"refs/heads/main"),
                    head_oid: Some(b"1111111111111111111111111111111111111111"),
                    head_algo: Some("sha1"),
                },
                now,
            )
            .await
            .expect("checkout");
        // Legacy remote row: PAT-shaped username plus an opaque tail.
        let legacy_url = format!(
            "https://ghp_{}@github.com/o/r.git?next={}",
            canaries[0], canaries[1]
        );
        store
            .upsert_remote(
                &NewRemote {
                    id: "rem-1",
                    instance_id: "repo-1",
                    checkout_scope_id: None,
                    name: b"origin",
                    role: "fetch",
                    url: legacy_url.as_bytes(),
                    canonical_url: Some(b"https://github.com/owner/repo"),
                },
                now,
            )
            .await
            .expect("remote");
        // Legacy error text with an escaped sensitive key.
        let message = format!(
            "{{\"\\u0073ecret\": \"{}\"}} leaked in probe output",
            canaries[2]
        );
        store
            .record_error("err-1", "probe:git", "fetch-failed", &message, None, now)
            .await
            .expect("record error");
    });
    let inputs = test_inputs("retest-emission-1");
    let (bytes, _) = runtime()
        .block_on(async { stream_report_from_store(&store, &inputs, Vec::new()).await })
        .expect("stream");
    for canary in canaries {
        assert!(
            !contains_bytes(&bytes, canary.as_bytes()),
            "canary {canary} in streamed report"
        );
    }
    let report: Report = serde_json::from_slice(&bytes).expect("report parses");
    let mut terminal: Vec<u8> = Vec::new();
    render_terminal(&report, &mut terminal).expect("render");
    for canary in canaries {
        assert!(
            !contains_bytes(&terminal, canary.as_bytes()),
            "canary {canary} in terminal render"
        );
    }
}

/// RETEST-1/2 end to end: git remotes carrying every listed canary form
/// persist and emit no canary bytes — report file, terminal stdout,
/// stderr, catalog, snapshot, and staging are all clean.
#[test]
fn retest_remote_canaries_never_persist_or_emit() {
    let scratch = fixture::scratch_root("fail-redact-");
    let root = scratch.path().join("root");
    private_dir_0700(&root).expect("mkdir");
    let vectors: &[(&str, &str, &str)] = &[
        (
            "pat-user",
            "https://ghp_FAILREDACTPAT50:x@github.com/OWNER/REPO.git",
            "FAILREDACTPAT50",
        ),
        (
            "opaque-query",
            "https://github.com/OWNER/REPO.git?next=FAILREDACTOPAQUE51",
            "FAILREDACTOPAQUE51",
        ),
        (
            "bare-frag",
            "https://github.com/OWNER/REPO.git#FAILREDACTFRAG52",
            "FAILREDACTFRAG52",
        ),
        (
            "scp-tail",
            "git@github.com:OWNER/REPO.git?opaque=FAILREDACTSCP53",
            "FAILREDACTSCP53",
        ),
        (
            "user-plus-tail",
            "https://user:pw@github.com/OWNER/REPO.git?next=FAILREDACTMIX54",
            "FAILREDACTMIX54",
        ),
    ];
    for (name, remote_url, _canary) in vectors.iter().copied() {
        let repo = fixture::normal_clone(&root, name);
        fixture::git(&repo, &["remote", "set-url", "origin", remote_url]);
    }
    let root_str = root.to_str().expect("utf8").to_string();
    let canaries: Vec<&str> = vectors.iter().map(|(_, _, c)| *c).collect();

    // File mode: report bytes plus every state file stay clean.
    let state = scratch.path().join("state");
    let cwd = scratch.path().join("cwd");
    private_dir_0700(&cwd).expect("mkdir");
    let out = run(
        &[
            "scan",
            "https://github.com/OWNER/REPO",
            "--root",
            root_str.as_str(),
            "--report",
            "rep.json",
        ],
        &cwd,
        &state,
    );
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report_bytes = std::fs::read(cwd.join("rep.json")).expect("read report");
    let _: serde_json::Value = serde_json::from_slice(&report_bytes).expect("report JSON");
    for canary in &canaries {
        assert!(
            !contains_bytes(&report_bytes, canary.as_bytes()),
            "canary {canary} in report file"
        );
        assert!(
            !contains_bytes(&out.stdout, canary.as_bytes()),
            "canary {canary} on stdout"
        );
        assert!(
            !contains_bytes(&out.stderr, canary.as_bytes()),
            "canary {canary} on stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_no_canary_in_state(&state, canary);
    }

    // Terminal mode: stdout plus the retained snapshot stay clean.
    let state_t = scratch.path().join("state-term");
    let cwd_t = scratch.path().join("cwd-term");
    private_dir_0700(&cwd_t).expect("mkdir");
    let out = run(
        &[
            "scan",
            "https://github.com/OWNER/REPO",
            "--root",
            root_str.as_str(),
        ],
        &cwd_t,
        &state_t,
    );
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "terminal scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for canary in &canaries {
        assert!(
            !contains_bytes(&out.stdout, canary.as_bytes()),
            "canary {canary} on terminal stdout"
        );
        assert!(
            !contains_bytes(&out.stderr, canary.as_bytes()),
            "canary {canary} on terminal stderr"
        );
        assert_no_canary_in_state(&state_t, canary);
    }
}

/// RETEST-1/2 on the submodule path: a tainted submodule URL (PAT-shaped
/// user plus opaque tail) is strictly redacted by the constructor, and
/// inspector observations carry no canary bytes.
#[test]
fn retest_submodule_url_strictly_redacted() {
    let scratch = fixture::scratch_root("fail-redact-sub-");
    let parent = scratch.path().join("repos");
    private_dir_0700(&parent).unwrap();
    let (sup, _sub) = fixture::submodule_repo(&parent);
    let canary_user = "FAILREDACTSUBPAT80";
    let canary_tail = "FAILREDACTSUBTAIL81";
    let tainted = format!("https://ghp_{canary_user}:x@github.com/o/r.git?next={canary_tail}");
    // The constructor transform itself drops both canaries.
    let shown = redact_remote_url(&tainted);
    assert!(!shown.contains(canary_user), "{shown}");
    assert!(!shown.contains(canary_tail), "{shown}");
    // Plant the taint where the inspector reads submodule URLs.
    let modules = std::fs::read_to_string(sup.join(".gitmodules")).expect("read modules");
    assert!(modules.contains("url = "), "{modules}");
    let tainted_modules = modules
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("url = ") || trimmed.starts_with("url=") {
                format!("url = {tainted}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    private_write_0600(&sup.join(".gitmodules"), tainted_modules.as_bytes()).unwrap();
    let on_disk = std::fs::read_to_string(sup.join(".gitmodules")).expect("reread");
    assert!(on_disk.contains(canary_tail), "taint planted");
    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&sup).expect("open super");
    let observations = inspector.submodules(&instance).expect("submodules");
    for observation in &observations {
        if let Some(url) = &observation.url {
            assert!(!url.contains(canary_user), "{url}");
            assert!(!url.contains(canary_tail), "{url}");
        }
    }
}

/// RETEST-3 end to end: malformed scan targets exit 2 with no canary on
/// either stream and nothing persisted.
#[test]
fn retest_malformed_target_scan_echo_clean() {
    let scratch = fixture::scratch_root("fail-redact-mal-");
    let root = scratch.path().join("root");
    private_dir_0700(&root).expect("mkdir");
    let root_str = root.to_str().expect("utf8").to_string();
    for (name, target, canary) in [
        (
            "prose",
            "not-a-url FAILREDACTMALFORMED60",
            "FAILREDACTMALFORMED60",
        ),
        (
            "json",
            "{\"password\":\"FAILREDACTMALFORMED61\"}",
            "FAILREDACTMALFORMED61",
        ),
        (
            "spaced",
            "https://github.com/o/r --token FAILREDACTMALFORMED62",
            "FAILREDACTMALFORMED62",
        ),
    ] {
        let state = scratch.path().join(format!("state-{name}"));
        let cwd = scratch.path().join(format!("cwd-{name}"));
        private_dir_0700(&cwd).expect("mkdir");
        let out = run(&["scan", target, "--root", root_str.as_str()], &cwd, &state);
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
        assert_no_canary_in_state(&state, canary);
    }
}

/// RETEST-1 (bare `user@host`): a credential-shaped bare username is
/// credential material even with no colon, path, or scheme — it never
/// echoes intact through any redaction path, while ordinary
/// `user@example.com` logins still echo (RS-PRIV-10 contract pinned).
/// End to end: a git remote carrying the bare canary persists and emits
/// no canary bytes — report file, terminal stdout, stderr, catalog,
/// snapshot, and staging are all clean.
#[test]
fn retest_bare_user_host_canary_never_persist_or_emit() {
    let canary = "FAILREDACTBARE90";
    let bare = format!("ghp_{canary}@github.com");
    // Unit boundary: every redaction path drops the bare canary.
    for shown in [redact_credentials(&bare), redact_remote_url(&bare)] {
        assert!(!shown.contains(canary), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }
    assert_eq!(
        redact_remote_url(&bare),
        "<redacted>@github.com",
        "bare user redacts, host preserved"
    );
    let scrubbed = scrub_text(&format!("fetch {bare} failed"));
    assert!(!scrubbed.contains(canary), "{scrubbed}");
    assert!(scrubbed.contains("<redacted>@github.com"), "{scrubbed}");
    let (_, evidence) = classify_remote("https://github.com/o/r", &bare, "fetch");
    assert!(!evidence.is_empty());
    for line in &evidence {
        assert!(!line.contains(canary), "{line}");
    }
    // Ordinary bare logins still echo (existing contract pinned).
    assert_eq!(redact_credentials("user@example.com"), "user@example.com");
    assert_eq!(redact_remote_url("user@example.com"), "user@example.com");
    assert_eq!(redact_credentials("host:path"), "host:path");
    assert_eq!(
        scrub_text("contact user@example.com for access"),
        "contact user@example.com for access"
    );

    // End to end: git remote -> scan -> report/catalog/terminal clean.
    let scratch = fixture::scratch_root("fail-redact-bare-");
    let root = scratch.path().join("root");
    private_dir_0700(&root).expect("mkdir");
    let repo = fixture::normal_clone(&root, "bare-user");
    fixture::git(&repo, &["remote", "set-url", "origin", &bare]);
    let root_str = root.to_str().expect("utf8").to_string();

    // File mode: report bytes plus every state file stay clean.
    let state = scratch.path().join("state");
    let cwd = scratch.path().join("cwd");
    private_dir_0700(&cwd).expect("mkdir");
    let out = run(
        &[
            "scan",
            "https://github.com/OWNER/REPO",
            "--root",
            root_str.as_str(),
            "--report",
            "rep.json",
        ],
        &cwd,
        &state,
    );
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report_bytes = std::fs::read(cwd.join("rep.json")).expect("read report");
    let _: serde_json::Value = serde_json::from_slice(&report_bytes).expect("report JSON");
    assert!(
        !contains_bytes(&report_bytes, canary.as_bytes()),
        "canary in report file"
    );
    assert!(
        !contains_bytes(&out.stdout, canary.as_bytes()),
        "canary on stdout"
    );
    assert!(
        !contains_bytes(&out.stderr, canary.as_bytes()),
        "canary on stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_no_canary_in_state(&state, canary);

    // Terminal mode: stdout plus the retained snapshot stay clean.
    let state_t = scratch.path().join("state-term");
    let cwd_t = scratch.path().join("cwd-term");
    private_dir_0700(&cwd_t).expect("mkdir");
    let out = run(
        &[
            "scan",
            "https://github.com/OWNER/REPO",
            "--root",
            root_str.as_str(),
        ],
        &cwd_t,
        &state_t,
    );
    assert!(
        matches!(out.status.code(), Some(0) | Some(3)),
        "terminal scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !contains_bytes(&out.stdout, canary.as_bytes()),
        "canary on terminal stdout"
    );
    assert!(
        !contains_bytes(&out.stderr, canary.as_bytes()),
        "canary on terminal stderr"
    );
    assert_no_canary_in_state(&state_t, canary);
}
