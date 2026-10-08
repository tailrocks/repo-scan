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
        targets: vec![],
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
    let observations = inspector
        .submodules(&instance, &repo_scan::identity::load_ssh_aliases())
        .expect("submodules");
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

/// FIXREADY4 R (88117623 + dbb823b0) unit boundary: `ext::`/helper
/// transports, `file:`-with-tail, and malformed token-userinfo shapes
/// collapse at the choke point — never persist or emit verbatim. The
/// collapsed row is preserved with the `unsupported` marker
/// (`unresolvable_identity`), never silently dropped.
#[test]
fn fixready4_unsupported_remote_shapes_collapse() {
    // ext:: helper remote with an Authorization Bearer canary (EXACT
    // consumer shape): the whole command line collapses — a command is
    // not redactable piece-wise.
    let ext = "ext::ssh -l u %S host --header 'Authorization: Bearer FIXREADY4RBEARER01'";
    assert_eq!(redact_remote_url(ext), REDACTED_URL);
    assert_eq!(redact_credentials(ext), REDACTED_URL);
    // Helper `name::address` transports collapse the same way.
    assert_eq!(
        redact_remote_url("my-helper::ssl:host:1234/SECRET02"),
        REDACTED_URL
    );
    // file:/ URLs (no `//`) drop the query/fragment canary but keep the
    // path evidence; `file://` spellings behave identically.
    assert_eq!(
        redact_remote_url("file:/srv/git/o/r.git?token=FIXREADY4RFILE03"),
        "file:/srv/git/o/r.git"
    );
    assert_eq!(
        redact_remote_url("file:///srv/git/o/r.git?token=FIXREADY4RFILE04#x"),
        "file:///srv/git/o/r.git"
    );
    assert!(
        !redact_remote_url("file:/srv/git/o/r.git?token=FIXREADY4RFILE03")
            .contains("FIXREADY4RFILE")
    );
    // Malformed token-shaped userinfo (known scheme without `://`)
    // collapses — it is not a parseable authority.
    assert_eq!(
        redact_remote_url("https:/ghp_FIXREADY4RMAL05@github.com/o/r.git"),
        REDACTED_URL
    );
    // ...while an scp-shaped `ssh:`-prefixed login still takes the scp
    // path (user fully redacted, host/path preserved — no leak).
    assert_eq!(
        redact_remote_url("ssh:git@github.com:o/r.git"),
        "<redacted>@github.com:o/r.git"
    );
    assert_eq!(redact_remote_url("ssh:github.com/o/r.git"), REDACTED_URL);
    assert_eq!(
        redact_remote_url("https://user:secret/ret@github.com/o/r"),
        REDACTED_URL
    );
    // Stray `@` past classification is malformed smuggled userinfo.
    assert_eq!(
        redact_remote_url("not a url user@host with spaces FIXREADY4R06"),
        REDACTED_URL
    );
    // Idempotent: the placeholder re-scrubs to itself.
    assert_eq!(redact_remote_url(REDACTED_URL), REDACTED_URL);
    assert_eq!(redact_credentials(REDACTED_URL), REDACTED_URL);
    // Established echoes are unchanged.
    assert_eq!(redact_remote_url("host:path"), "host:path");
    assert_eq!(redact_remote_url("user@example.com"), "user@example.com");
    assert_eq!(
        redact_remote_url("https://github.com/o/r.git"),
        "https://github.com/o/r.git"
    );
    assert_eq!(
        redact_remote_url("git@github.com:o/r.git"),
        "<redacted>@github.com:o/r.git"
    );
    assert_eq!(
        redact_remote_url("file:/srv/git/o/r.git"),
        "file:/srv/git/o/r.git"
    );
    // The collapsed row classifies `unresolvable_identity` (the preserved
    // `unsupported` marker) with canary-free evidence — never dropped.
    for raw in [
        ext,
        "file:/srv/git/o/r.git?token=FIXREADY4RFILE07",
        "https:/ghp_FIXREADY4RMAL08@github.com/o/r.git",
    ] {
        let (disposition, evidence) = classify_remote("https://github.com/o/r", raw, "fetch");
        assert_eq!(
            disposition,
            repo_scan::identity::MatchDisposition::UnresolvableIdentity,
            "{raw}"
        );
        assert!(!evidence.is_empty(), "row preserved: {raw}");
        for line in &evidence {
            assert!(!line.contains("FIXREADY4R"), "{raw}: {line}");
        }
    }
    let (disposition, evidence) = classify_remote("https://github.com/o/r", REDACTED_URL, "fetch");
    assert_eq!(
        disposition,
        repo_scan::identity::MatchDisposition::UnresolvableIdentity
    );
    assert!(
        evidence
            .iter()
            .any(|l| l.contains("redacted at observation")),
        "{evidence:?}"
    );
    // Free-text sinks: the Bearer token follows the scheme word, and
    // `ext::` tokens collapse whole.
    let scrubbed = scrub_text("helper failed: Authorization: Bearer FIXREADY4RBEARER09");
    assert!(!scrubbed.contains("FIXREADY4RBEARER09"), "{scrubbed}");
    let scrubbed = scrub_text("remote ext::ssh-FIXREADY4REXT10 failed");
    assert!(!scrubbed.contains("FIXREADY4REXT10"), "{scrubbed}");
    assert!(scrubbed.contains(REDACTED_URL), "{scrubbed}");
    // `ext::` matching needs a word boundary: neighboring `::` prose
    // never collapses.
    assert_eq!(
        scrub_text("text::prose, next::item, use std::fmt"),
        "text::prose, next::item, use std::fmt"
    );
    // Documented over-redaction (safe direction): any `bearer <token>`
    // shape redacts the following token, even in prose.
    assert_eq!(
        scrub_text("the bearer of bad news"),
        "the bearer <redacted> bad news"
    );
}

/// FIXREADY4 R end to end (88117623 + dbb823b0): git remotes carrying
/// the EXACT consumer shapes (ext:: + `Authorization: Bearer` canary,
/// file: URL + `?query` canary, malformed token userinfo) persist and
/// emit no canary bytes — report file, terminal stdout, stderr,
/// catalog.db raw bytes, snapshot, and staging are all clean. The
/// collapsed remote rows are still present (`<redacted-url>`, never
/// silently dropped).
#[test]
fn fixready4_exact_remote_canaries_never_persist_or_emit() {
    let scratch = fixture::scratch_root("fail-redact-fixready4r-");
    let root = scratch.path().join("root");
    private_dir_0700(&root).expect("mkdir");
    let vectors: &[(&str, &str, &str)] = &[
        (
            "ext-bearer",
            "ext::ssh -l u %S host --header 'Authorization: Bearer FIXREADY4REXT20'",
            "FIXREADY4REXT20",
        ),
        (
            "file-query",
            "file:/srv/git/o/r.git?token=FIXREADY4RFILE21",
            "FIXREADY4RFILE21",
        ),
        (
            "malformed-userinfo",
            "https:/ghp_FIXREADY4RMAL22@github.com/o/r.git",
            "FIXREADY4RMAL22",
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
    let report: serde_json::Value = serde_json::from_slice(&report_bytes).expect("report JSON");
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
    // Collapsed rows are preserved, never silently dropped: every remote
    // URL is either clean or the placeholder, and the placeholder rows
    // exist (ext + malformed collapse; file keeps its tail-stripped path).
    let remotes = report
        .get("remotes")
        .and_then(|v| v.as_array())
        .expect("remotes array");
    assert!(!remotes.is_empty(), "remote rows preserved");
    let urls: Vec<&str> = remotes
        .iter()
        .filter_map(|r| r.get("url").and_then(|u| u.as_str()))
        .collect();
    assert!(
        urls.contains(&REDACTED_URL),
        "collapsed rows present: {urls:?}"
    );
    assert!(
        urls.contains(&"file:/srv/git/o/r.git"),
        "tail-stripped file row present: {urls:?}"
    );
    for url in &urls {
        for canary in &canaries {
            assert!(!url.contains(canary), "canary in remote url: {url}");
        }
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

/// Round-2 R1 unit boundary: smuggled shapes inside `file:` collapse —
/// `@` userinfo, `scheme::` transports, and whitespace never echo
/// verbatim — while clean `file:` paths keep echoing tail-stripped.
#[test]
fn round2_r1_file_smuggled_shapes_collapse() {
    // `@` inside `file:`: malformed smuggled userinfo, collapses.
    assert_eq!(
        redact_remote_url("file:ghp_ROUND2FILE01@x/y.git"),
        REDACTED_URL
    );
    assert_eq!(
        redact_credentials("file:ghp_ROUND2FILE01@x/y.git"),
        REDACTED_URL
    );
    // `scheme::` smuggled inside `file:`, spaced or not, collapses.
    assert_eq!(
        redact_remote_url("file:ext::ssh --token=ROUND2FILE02"),
        REDACTED_URL
    );
    assert_eq!(redact_remote_url("file:ext::ssh"), REDACTED_URL);
    assert_eq!(redact_credentials("file:ext::ssh SECRET"), REDACTED_URL);
    // Whitespace inside `file:` collapses (fail closed, not prose).
    assert_eq!(
        redact_remote_url("file:/srv/git/o/r.git TOKEN"),
        REDACTED_URL
    );
    // Credential-shaped `file:`-bare user redacts like the general path.
    assert_eq!(redact_remote_url("file:token123@host"), "<redacted>@host");
    // Clean `file:` paths are unchanged (tail-stripped echo).
    assert_eq!(
        redact_remote_url("file:/srv/git/o/r.git?token=x"),
        "file:/srv/git/o/r.git"
    );
    assert_eq!(
        redact_remote_url("file:///srv/git/o/r.git"),
        "file:///srv/git/o/r.git"
    );
}

/// Round-2 R6 unit boundary: a command line smuggling `://` takes the
/// transport path (collapses), never the scheme path (verbatim echo).
#[test]
fn round2_r6_smuggled_scheme_collapses() {
    let smuggled = "ext::helper --url=https://x/ --header 'Authorization: Bearer ROUND2EXT03'";
    assert_eq!(redact_remote_url(smuggled), REDACTED_URL);
    assert_eq!(redact_credentials(smuggled), REDACTED_URL);
    assert_eq!(
        sanitize_target_url("my-helper::ssl --url=https://x/y?jwt=z"),
        REDACTED_URL
    );
    // Genuine scheme URLs still take the scheme path.
    assert_eq!(
        redact_remote_url("https://github.com/o/r.git"),
        "https://github.com/o/r.git"
    );
    assert_eq!(
        redact_remote_url("ssh://git@github.com/o/r.git"),
        "ssh://<redacted>@github.com/o/r.git"
    );
}

/// Round-2 R2 unit boundary: the free-text pass collapses generic
/// `scheme::` tokens (word-boundary-aware, constructor charset), not
/// just literal `ext::` — while lowercase prose/Rust paths echo on.
#[test]
fn round2_r2_generic_transports_collapse_in_free_text() {
    for text in [
        "failed my-helper::ROUND2R2CANARY04",
        "preext::ROUND2R2CANARY05 blew up",
        "remote 9foo::ROUND2R2CANARY06 failed",
    ] {
        let scrubbed = scrub_text(text);
        assert!(!scrubbed.contains("ROUND2R2CANARY"), "{text} -> {scrubbed}");
        assert!(scrubbed.contains(REDACTED_URL), "{scrubbed}");
    }
    // Established prose/Rust-path echo contract is unchanged.
    assert_eq!(
        scrub_text("text::prose, next::item, use std::fmt"),
        "text::prose, next::item, use std::fmt"
    );
    // Established `ext::` collapse is unchanged (even all-lowercase).
    assert_eq!(
        scrub_text("remote ext::ssh failed"),
        "remote <redacted-url> failed"
    );
    // Documented residual (forced by the prose echo contract above): an
    // all-lowercase non-ext address echoes in free text. The constructor
    // still collapses such REMOTES at observation.
    assert_eq!(
        scrub_text("failed my-helper::secret"),
        "failed my-helper::secret"
    );
    assert_eq!(redact_remote_url("my-helper::secret"), REDACTED_URL);
}

/// Round-2 R7 unit boundary: bare nospace sensitive pairs route through
/// pair redaction instead of echoing verbatim.
#[test]
fn round2_r7_bare_pairs_redact() {
    assert_eq!(redact_remote_url("token=ROUND2PAIR04"), "token=<redacted>");
    assert_eq!(
        redact_remote_url("password:ROUND2PAIR05"),
        "password:<redacted>"
    );
    assert_eq!(
        redact_credentials("api_key=ROUND2PAIR06"),
        "api_key=<redacted>"
    );
    // Non-sensitive pairs and plain shapes still echo.
    assert_eq!(redact_remote_url("host:path"), "host:path");
    assert_eq!(redact_remote_url("page=2"), "page=2");
}

/// Round-2 R5 unit boundary: digit-leading helper names are transports
/// (git helper names are not alpha-restricted).
#[test]
fn round2_r5_digit_leading_transports_collapse() {
    assert_eq!(redact_remote_url("9foo::ROUND2R5CANARY07"), REDACTED_URL);
    assert_eq!(redact_credentials("9foo::ROUND2R5CANARY07"), REDACTED_URL);
    let scrubbed = scrub_text("failed 9foo::ROUND2R5CANARY07");
    assert!(!scrubbed.contains("ROUND2R5CANARY07"), "{scrubbed}");
    // Nearby non-transports still echo.
    assert_eq!(redact_remote_url("host:path"), "host:path");
}

/// Round-2 R3 unit boundary: over-long Bearer tokens redact whole
/// (no cap tail leak) and folded `Bearer\n<token>` headers redact.
#[test]
fn round2_r3_bearer_overlong_and_folded() {
    // R3a: a 2000-byte token redacts through the end of the run.
    let long = format!("Authorization: Bearer {}", "A".repeat(2000));
    let scrubbed = scrub_text(&long);
    assert!(!scrubbed.contains("AA"), "{scrubbed}");
    assert!(scrubbed.contains("<redacted>"), "{scrubbed}");
    // R3b: folded headers (LF and CRLF) redact the token.
    for text in [
        "Authorization: Bearer\nROUND2FOLDED01",
        "Authorization: Bearer\r\nROUND2FOLDED02",
    ] {
        let scrubbed = scrub_text(text);
        assert!(
            !scrubbed.contains("ROUND2FOLDED"),
            "{text:?} -> {scrubbed:?}"
        );
    }
    // Same-line behavior is unchanged: the established prose
    // over-redaction demo plus a real-token case (scheme-word case is
    // preserved; only the token redacts).
    assert_eq!(
        scrub_text("the bearer of bad news"),
        "the bearer <redacted> bad news"
    );
    assert_eq!(
        scrub_text("the Bearer ROUND2SAME03 bad news"),
        "the Bearer <redacted> bad news"
    );
}

/// Round-2 end to end: git remotes carrying the R1/R6/R7 shapes
/// (`file:` + smuggled userinfo, spaced `file:ext::`, `://`-smuggling
/// `ext::` with a Bearer canary, bare `token=`/`password:` pairs)
/// persist and emit no canary bytes — report file, terminal stdout,
/// stderr, catalog.db raw bytes, snapshot, and staging are all clean.
#[test]
fn round2_exact_round2_canaries_never_persist_or_emit() {
    let scratch = fixture::scratch_root("fail-redact-round2-");
    let root = scratch.path().join("root");
    private_dir_0700(&root).expect("mkdir");
    let vectors: &[(&str, &str, &str)] = &[
        (
            "file-userinfo",
            "file:ghp_ROUND2EIFILE01@x/y.git",
            "ROUND2EIFILE01",
        ),
        (
            "file-ext-spaced",
            "file:ext::ssh --token=ROUND2EIFILE02",
            "ROUND2EIFILE02",
        ),
        (
            "ext-smuggled-scheme",
            "ext::helper --url=https://x/ --header 'Authorization: Bearer ROUND2EIEXT03'",
            "ROUND2EIEXT03",
        ),
        ("bare-pair-eq", "token=ROUND2EIPAIR04", "ROUND2EIPAIR04"),
        (
            "bare-pair-colon",
            "password:ROUND2EIPAIR05",
            "ROUND2EIPAIR05",
        ),
    ];
    for (name, remote_url, _canary) in vectors.iter().copied() {
        let repo = fixture::normal_clone(&root, name);
        fixture::git(&repo, &["remote", "set-url", "origin", remote_url]);
    }
    let root_str = root.to_str().expect("utf8").to_string();
    let canaries: Vec<&str> = vectors.iter().map(|(_, _, c)| *c).collect();

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
    // Terminal mode stays clean too.
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

// ---------------------------------------------------------------------------
// Round-3 R1b/R6b/R2b/R7/R3b: redaction-boundary regressions.
// ---------------------------------------------------------------------------

/// Round-3 R1b: a colon in the user is USERINFO, never a bare login —
/// `user:password@host` with a letters-only, marker-less password (and
/// the `file:` variant) never echoes verbatim anywhere.
#[test]
fn round3_r1b_colon_user_collapses() {
    for url in ["user:abcdefghijklmn@host", "a:abcdefghijklmno@host"] {
        for got in [redact_remote_url(url), redact_credentials(url)] {
            assert!(
                !got.contains("abcdefghijklmn") && !got.contains("abcdefghijklmno"),
                "{url} -> {got}"
            );
        }
        let scrubbed = scrub_text(&format!("see {url} ok"));
        assert!(
            !scrubbed.contains("abcdefghijklmn") && !scrubbed.contains("abcdefghijklmno"),
            "{url} -> {scrubbed}"
        );
    }
    assert_eq!(
        redact_remote_url("user:abcdefghijklmn@host"),
        "user:<redacted>@host"
    );
    assert_eq!(
        redact_credentials("a:abcdefghijklmno@host"),
        "a:<redacted>@host"
    );
    // `file:` variant: the prefix is not part of the user.
    assert_eq!(
        redact_remote_url("file:user:abcdefghijklmn@host"),
        "user:<redacted>@host"
    );
    assert!(!scrub_text("see file:user:abcdefghijklmn@host ok").contains("abcdefghijklmn"));
    // Credential-shaped user redacts on both sides (RETEST-1 through
    // the userinfo path).
    assert_eq!(
        redact_remote_url("ghp_R3B1U00000000000000:pass@host"),
        "<redacted>:<redacted>@host"
    );
    // Pins: the no-colon contracts are unchanged.
    assert_eq!(redact_remote_url("user@example.com"), "user@example.com");
    assert_eq!(redact_remote_url("file:token123@host"), "<redacted>@host");
    assert_eq!(
        scrub_text("contact user@example.com for access"),
        "contact user@example.com for access"
    );
    assert_eq!(
        scrub_text("see file:token123@host ok"),
        "see <redacted>@host ok"
    );
}

/// Round-3 R6b: the scheme split is validated — a `://` smuggled past
/// prose, pairs, or transports falls through to transport/pair/scrub
/// handling, never a verbatim scheme-path echo. Leading whitespace
/// trims at the sink entries.
#[test]
fn round3_r6b_invalid_scheme_falls_through() {
    // Smuggled pair + URL: the pair redacts, the clean URL survives.
    assert_eq!(
        redact_remote_url("token=R3B6HOLE01 https://example.com"),
        "token=<redacted> https://example.com"
    );
    assert_eq!(
        redact_credentials("token=R3B6HOLE01 https://example.com"),
        "token=<redacted> https://example.com"
    );
    // Smuggled transports collapse.
    assert_eq!(
        redact_remote_url("file:ext::helper --url=https://x/S"),
        REDACTED_URL
    );
    assert_eq!(
        redact_credentials("file:ext::helper --url=https://x/S"),
        REDACTED_URL
    );
    assert_eq!(
        redact_remote_url("https:/evil --url=https://x/S"),
        REDACTED_URL
    );
    // Leading-space variants: the trim exposes the transport/pair shape.
    assert_eq!(
        redact_remote_url(" ext::helper --url=https://x/S"),
        REDACTED_URL
    );
    assert_eq!(
        redact_remote_url(" token=R3B6HOLE02 https://example.com"),
        "token=<redacted> https://example.com"
    );
    // Invalid-scheme nospace input collapses (never verbatim).
    assert_eq!(redact_remote_url("9foo://token=R3B6HOLE03"), REDACTED_URL);
    assert_eq!(
        sanitize_target_url("token=R3B6HOLE04 https://example.com"),
        "token=<redacted> https://example.com"
    );
    // Genuine scheme URLs still take the scheme path.
    assert_eq!(
        redact_remote_url("https://github.com/o/r.git"),
        "https://github.com/o/r.git"
    );
    assert_eq!(
        redact_remote_url("file:///srv/git/o/r.git"),
        "file:///srv/git/o/r.git"
    );
    assert_eq!(
        redact_credentials("https://user:secret@github.com/o/r.git"),
        "https://user:<redacted>@github.com/o/r.git"
    );
}

/// Round-3 R6b catalog sink: a leading-whitespace smuggled remote
/// persists redacted through `redacted_remote_bytes` (the trim lives at
/// the choke point, so the sink is covered too).
#[test]
fn round3_r6b_catalog_sink_trims_and_redacts() {
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let db = dir.path().join("payload").join("catalog.db");
    let store = runtime().block_on(async { TursoStore::open(&db).await.expect("open") });
    let now = 1_759_154_400_000;
    let canary = "R3B6SINKCANARY04";
    let evil = format!(" token={canary} https://example.com/o/r.git");
    let evidence = serde_json::to_string(&vec!["sink probe".to_string()]).expect("json");
    runtime().block_on(async {
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
            .upsert_remote(
                &NewRemote {
                    id: "rem-1",
                    instance_id: "repo-1",
                    checkout_scope_id: None,
                    name: b"origin",
                    role: "fetch",
                    url: evil.as_bytes(),
                    canonical_url: None,
                },
                now,
            )
            .await
            .expect("remote");
        let rows = store.list_remotes("repo-1").await.expect("list");
        assert_eq!(rows.len(), 1);
        let persisted = String::from_utf8_lossy(&rows[0].url).into_owned();
        assert!(
            !persisted.contains(canary),
            "canary persisted: {persisted:?}"
        );
        assert!(
            !persisted.starts_with([' ', '\t']),
            "leading space persisted: {persisted:?}"
        );
        assert_eq!(persisted, "token=<redacted> https://example.com/o/r.git");
        store.close().await.expect("close");
    });
    let raw = std::fs::read(&db).expect("read db");
    assert!(
        !contains_bytes(&raw, canary.as_bytes()),
        "canary in catalog.db raw bytes"
    );
}

/// Round-3 R2b: after collapsing a command-transport token, subsequent
/// same-span credential-shaped tokens redact too — line-locally. Bare
/// UNMARKED trailing secrets stay the documented residual.
#[test]
fn round3_r2b_trailing_span_credentials_redact() {
    // Marked/shaped trailing secrets redact (single, multiple, quoted).
    assert_eq!(
        scrub_text("ext::ssh ghp_R3B2U00000000000000"),
        "<redacted-url> <redacted>"
    );
    assert_eq!(
        scrub_text("ext::ssh ghp_R3B2U00000000000000 glpat-R3B2V00000000000000 done"),
        "<redacted-url> <redacted> <redacted> done"
    );
    assert_eq!(
        scrub_text("ext::ssh 'ghp_R3B2U00000000000000'"),
        "<redacted-url> '<redacted>'"
    );
    // Non-`ext` collapses sweep too; the sweep skips flags/values
    // (round-4 H2: non-credential tokens no longer stop the scan).
    assert_eq!(
        scrub_text("failed my-helper::R3B2X1 ghp_R3B2U00000000000000"),
        "failed <redacted-url> <redacted>"
    );
    assert_eq!(
        scrub_text("ext::ssh --flag value"),
        "<redacted-url> --flag value"
    );
    // The sweep stops at line breaks.
    assert_eq!(
        scrub_text("ext::ssh ghp_R3B2U00000000000000\nnext ghp_R3B2V00000000000000"),
        "<redacted-url> <redacted>\nnext ghp_R3B2V00000000000000"
    );
    // The `ext` always-collapse stays line-local (no EOL extension).
    assert_eq!(scrub_text("use ext::fmt"), "use <redacted-url>");
    assert_eq!(
        scrub_text("use ext::fmt\ntail line"),
        "use <redacted-url>\ntail line"
    );
    // Binding: bare UNMARKED trailing secrets are the documented
    // free-text residual (unidentifiable by construction), not a hole.
    assert_eq!(
        scrub_text("failed mysecretpassword"),
        "failed mysecretpassword"
    );
    assert_eq!(scrub_text("x helper::passphrase"), "x helper::passphrase");
}

/// Round-3 R7-over: bare-pair redaction does not fire on path-like or
/// scp-like shapes — while true pairs still collapse.
#[test]
fn round3_r7_bare_pair_boundaries() {
    // Regression: true pairs fully collapse (full-input + free-text).
    assert_eq!(redact_remote_url("token=R3B7PAIR99"), "token=<redacted>");
    assert_eq!(
        redact_remote_url("password:R3B7HUNTER2"),
        "password:<redacted>"
    );
    assert_eq!(
        scrub_text("set token=R3B7PAIR99 ok"),
        "set token=<redacted> ok"
    );
    assert_eq!(
        scrub_text("use password:R3B7HUNTER2 ok"),
        "use password:<redacted> ok"
    );
    // Regression: scp-like and path-like FULL INPUTS survive
    // byte-identical.
    assert_eq!(redact_remote_url("auth:repo"), "auth:repo");
    assert_eq!(
        redact_remote_url("/tmp/token=R3B7BAR"),
        "/tmp/token=R3B7BAR"
    );
    // Scp-like shapes echo in free text too (no path ambiguity there).
    assert_eq!(scrub_text("clone auth:repo now"), "clone auth:repo now");
    // Split contract (reconciled with `tests/fail_termsink.rs`): the
    // `/`-key guard is full-input-only — a free-text path pair still
    // redacts on the terminal display channel.
    assert_eq!(
        scrub_text("wrote /tmp/token=R3B7BAR ok"),
        "wrote /tmp/token=<redacted> ok"
    );
    // Guards stay narrow: values may carry `/`, `=` never means scp,
    // and spaced/quoted/CLI pairs still redact.
    assert_eq!(
        redact_remote_url("password=R3B7A/R3B7B"),
        "password=<redacted>"
    );
    assert_eq!(redact_remote_url("auth=R3B7S"), "auth=<redacted>");
    assert_eq!(scrub_text("auth: R3B7S"), "auth: <redacted>");
    assert_eq!(
        scrub_text("{\"auth\": \"R3B7S\"}"),
        "{\"auth\": \"<redacted>\"}"
    );
    assert_eq!(scrub_text("--auth R3B7S"), "--auth <redacted>");
    // In-URL path pairs keep redacting through the spaced pass.
    assert_eq!(
        scrub_text("see https://h/token=R3B7S end"),
        "see https://h/token=<redacted> end"
    );
}

/// Round-3 R7-under: short key words match delimited-substring (suffix /
/// hyphen compounds redact; plurals newly redact), while `keyboard`
/// still echoes — and descriptive words keep substring matching (no
/// fail-open flip for `authorization`-family compounds).
#[test]
fn round3_r7_short_words_delimited() {
    // Per-word: bare, suffix, hyphen, and plural forms redact.
    for key in [
        "key",
        "mykey",
        "x-key",
        "api-key",
        "keys",
        "sig",
        "mysig",
        "pin",
        "mypin",
        "pins",
        "pwd",
        "mypwd",
        "pwds",
        "otp",
        "myotp",
        "pass",
        "mypass",
        "token",
        "mytoken",
        "tokens",
        "secret",
        "secrets",
        "password",
        "passwords",
        "passwd",
        "auth",
        "myauth",
    ] {
        let input = format!("{key}=R3B7UW99");
        assert_eq!(
            redact_remote_url(&input),
            format!("{key}=<redacted>"),
            "{input}"
        );
    }
    // `keyboard` echo pin (full-input + free-text + JSON).
    assert_eq!(redact_remote_url("keyboard=R3B7UW99"), "keyboard=R3B7UW99");
    assert_eq!(
        scrub_text("set keyboard=R3B7UW99 ok"),
        "set keyboard=R3B7UW99 ok"
    );
    assert_eq!(
        scrub_text("{\"keyboard\": \"R3B7UW99\"}"),
        "{\"keyboard\": \"R3B7UW99\"}"
    );
    // Free-text + JSON spot checks for the fixed compounds.
    assert_eq!(
        scrub_text("set mykey=R3B7UW99, x-key=R3B7UW98 ok"),
        "set mykey=<redacted>, x-key=<redacted> ok"
    );
    assert_eq!(
        scrub_text("{\"mykey\": \"R3B7UW99\"}"),
        "{\"mykey\": \"<redacted>\"}"
    );
    assert_eq!(
        scrub_text("set tokens=R3B7UW99, secrets=R3B7UW98 ok"),
        "set tokens=<redacted>, secrets=<redacted> ok"
    );
    // No-weakening pins: descriptive compounds keep redacting whole.
    assert_eq!(
        scrub_text("{\"authorization\": \"Basic R3B7UW99\"}"),
        "{\"authorization\": \"<redacted>\"}"
    );
    assert_eq!(
        scrub_text("see https://h/sessionid=R3B7UW99 end"),
        "see https://h/sessionid=<redacted> end"
    );
}

/// Round-3 R3b: the unified gap class — a `Bearer` token separated by
/// vertical tab or form feed redacts like spaces/tabs/newlines, and a
/// token/value split by `\v\f` absorbs whole (fail closed) instead of
/// leaking its tail.
#[test]
fn round3_r3b_bearer_vtab_ff() {
    for text in [
        "Authorization: Bearer\x0bR3B3VTOK01",
        "Authorization: Bearer\x0cR3B3VTOK02",
        "Bearer\x0bR3B3VTOK03",
        "Bearer\x0cR3B3VTOK04",
    ] {
        let scrubbed = scrub_text(text);
        assert!(!scrubbed.contains("R3B3VTOK"), "{text:?} -> {scrubbed:?}");
        assert!(scrubbed.contains("<redacted>"), "{scrubbed:?}");
    }
    // Split tokens absorb whole (fail closed, no tail leak).
    assert_eq!(scrub_text("Bearer R3B3VTOK05\x0bTAIL"), "Bearer <redacted>");
    assert_eq!(scrub_text("Bearer R3B3VTOK06\x0cTAIL"), "Bearer <redacted>");
    // Spaced-pair values separated by `\v\f` redact too (gap preserved
    // exactly like spaces).
    assert_eq!(
        scrub_text("password:\x0cR3B3VTOK07"),
        "password:\x0c<redacted>"
    );
    assert_eq!(
        scrub_text("password:\x0bR3B3VTOK08"),
        "password:\x0b<redacted>"
    );
}

/// Round-4 H1: sensitive pairs in a valid-scheme URL path scrub (the path
/// was never pair-scrubbed, so `https://h/token=SECRET` persisted
/// byte-identical), including space-separated trailing tokens on
/// full-input scheme shapes. Every sink channel agrees.
#[test]
fn round4_h1_scheme_path_pairs_scrubbed() {
    // In-path `=` pair redacts on every channel.
    assert_eq!(
        redact_remote_url("https://github.com/token=R4H1SECRET99"),
        "https://github.com/token=<redacted>"
    );
    assert_eq!(
        redact_credentials("https://github.com/token=R4H1SECRET99"),
        "https://github.com/token=<redacted>"
    );
    assert_eq!(
        sanitize_target_url("https://github.com/token=R4H1SECRET99"),
        "https://github.com/token=<redacted>"
    );
    assert_eq!(
        scrub_text("see https://github.com/token=R4H1SECRET99 end"),
        "see https://github.com/token=<redacted> end"
    );
    // Space-separated trailing pair on a full-input scheme shape redacts.
    assert_eq!(
        redact_remote_url("https://github.com/owner/repo token=R4H1SECRET98"),
        "https://github.com/owner/repo token=<redacted>"
    );
    assert_eq!(
        redact_credentials("https://github.com/owner/repo token=R4H1SECRET98"),
        "https://github.com/owner/repo token=<redacted>"
    );
    assert_eq!(
        sanitize_target_url("https://github.com/owner/repo token=R4H1SECRET98"),
        "https://github.com/owner/repo token=<redacted>"
    );
    assert_eq!(
        scrub_text("see https://github.com/owner/repo token=R4H1SECRET98 end"),
        "see https://github.com/owner/repo token=<redacted> end"
    );
    // In-path `:` pair redacts under the same rule as free text.
    assert_eq!(
        redact_remote_url("https://h/password=R4H1SECRET97"),
        "https://h/password=<redacted>"
    );
    // Legit-path pins intact: normal paths round-trip byte-identical.
    assert_eq!(
        redact_remote_url("https://github.com/owner/repo"),
        "https://github.com/owner/repo"
    );
    assert_eq!(
        redact_credentials("https://github.com/owner/repo"),
        "https://github.com/owner/repo"
    );
    assert_eq!(
        sanitize_target_url("https://github.com/owner/repo"),
        "https://github.com/owner/repo"
    );
    // Query/fragment handling preserved on every channel.
    assert_eq!(
        redact_credentials("https://host/o/r.git?page=2&per=50"),
        "https://host/o/r.git?page=2&per=50"
    );
    assert_eq!(
        redact_credentials("https://host/o/r.git?next=/x&token=abc#sig=def"),
        "https://host/o/r.git?next=/x&token=<redacted>#sig=<redacted>"
    );
    assert_eq!(
        redact_remote_url("https://github.com/o/r.git?page=2&per=50"),
        "https://github.com/o/r.git"
    );
}

/// Round-4 H2: the post-collapse span sweep skips non-credential tokens
/// instead of stopping at the first one, bounded to the rest of the line
/// — a marked secret after an innocent flag still redacts.
#[test]
fn round4_h2_sweep_skips_innocent_tokens() {
    assert_eq!(
        scrub_text("ext::ssh --flag xT9qL2mZ8vB4nR7sK1wE5dR4H2A1"),
        "<redacted-url> --flag <redacted>"
    );
    assert_eq!(
        scrub_text("ext::ssh --flag xT9qL2mZ8vB4nR7sK1wE5dR4H2A1 --other glpat-R4H2CANARY02 done"),
        "<redacted-url> --flag <redacted> --other <redacted> done"
    );
    // Line-break bound intact: the next line is never swept.
    assert_eq!(
        scrub_text("ext::ssh --flag xT9qL2mZ8vB4nR7sK1wE5dR4H2A1\nnext mW8sKx2vBn5qLz9tR4H2B3dF"),
        "<redacted-url> --flag <redacted>\nnext mW8sKx2vBn5qLz9tR4H2B3dF"
    );
    // `use ext::fmt` stays line-local (no EOL extension).
    assert_eq!(scrub_text("use ext::fmt"), "use <redacted-url>");
    // Unmarked-secret residual intact: unshaped tokens still echo.
    assert_eq!(
        scrub_text("ext::ssh --flag hunter2value"),
        "<redacted-url> --flag hunter2value"
    );
}

/// Round-4 H3: `:`-pairs are value-shape-aware — a weak (short) key with
/// a credential-shaped value redacts even though the key alone is
/// ambiguous with scp `host:path`. Both channels agree.
#[test]
fn round4_h3_weak_colon_pairs_shape_aware() {
    // Shaped-value short keys redact (full-input + free-text).
    assert_eq!(
        redact_remote_url("jwt:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        "jwt:<redacted>"
    );
    assert_eq!(
        scrub_text("use jwt:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 ok"),
        "use jwt:<redacted> ok"
    );
    assert_eq!(
        redact_remote_url("api-key:glpat-R4H3CANARY01"),
        "api-key:<redacted>"
    );
    assert_eq!(
        scrub_text("set api-key:glpat-R4H3CANARY01 ok"),
        "set api-key:<redacted> ok"
    );
    assert_eq!(
        redact_credentials("otp:glpat-R4H3CANARY02"),
        "otp:<redacted>"
    );
    // Unshaped-value pins hold: `auth:repo` still echoes, scp survives.
    assert_eq!(redact_remote_url("auth:repo"), "auth:repo");
    assert_eq!(scrub_text("clone auth:repo now"), "clone auth:repo now");
    assert_eq!(
        redact_remote_url("git@github.com:o/r.git"),
        "<redacted>@github.com:o/r.git"
    );
    assert_eq!(
        scrub_text("clone git@github.com:o/r.git now"),
        "clone <redacted>@github.com:o/r.git now"
    );
    // BINDING documented residual: `pass:hunter2`-class (short UNMARKED
    // value) still echoes — same class as the accepted bare-token
    // residual, pinned explicitly, not silently left.
    assert_eq!(redact_remote_url("pass:hunter2"), "pass:hunter2");
    assert_eq!(scrub_text("set pass:hunter2 ok"), "set pass:hunter2 ok");
}

/// Round-4 H4: short-key plural rule covers `es` (`passes` → `pass`;
/// `door_passes`, `bypasses`), without breaking naturally-s-ending
/// words or the `keyboard` echo.
#[test]
fn round4_h4_es_plurals_redact() {
    for key in ["passes", "door_passes", "bypasses"] {
        let input = format!("{key}=R4H4CANARY01");
        assert_eq!(
            redact_remote_url(&input),
            format!("{key}=<redacted>"),
            "{input}"
        );
        assert_eq!(
            scrub_text(&format!("set {input} ok")),
            format!("set {key}=<redacted> ok"),
            "{input}"
        );
    }
    // Existing pins hold: `keys` redacts, `keyboard` still echoes.
    assert_eq!(redact_remote_url("keys=R4H4CANARY02"), "keys=<redacted>");
    assert_eq!(
        redact_remote_url("keyboard=R4H4CANARY03"),
        "keyboard=R4H4CANARY03"
    );
    assert_eq!(
        scrub_text("set keyboard=R4H4CANARY03 ok"),
        "set keyboard=R4H4CANARY03 ok"
    );
}

/// Round-4 H5: a percent-encoded colon (`%3A`, either case) in a bare
/// `user@host` user is smuggled userinfo — the password collapses under
/// userinfo semantics instead of echoing via the bare path.
#[test]
fn round4_h5_encoded_colon_bare_user_is_userinfo() {
    assert_eq!(
        redact_remote_url("admin%3AP%40ssw0rd@dbhost"),
        "admin:<redacted>@dbhost"
    );
    assert_eq!(
        redact_credentials("admin%3AP%40ssw0rd@dbhost"),
        "admin:<redacted>@dbhost"
    );
    assert_eq!(
        scrub_text("login admin%3AP%40ssw0rd@dbhost ok"),
        "login admin:<redacted>@dbhost ok"
    );
    // Lowercase escape spelling matches too.
    assert_eq!(
        redact_remote_url("admin%3ap%40ssw0rd@dbhost"),
        "admin:<redacted>@dbhost"
    );
    // A credential-shaped encoded user redacts on both sides.
    assert_eq!(
        redact_remote_url("glpat-R4H5%3Asecret@dbhost"),
        "<redacted>:<redacted>@dbhost"
    );
    // Ordinary bare logins still echo (established contract).
    assert_eq!(redact_remote_url("user@example.com"), "user@example.com");
    // Scheme-URL form still fully redacts (existing behavior pin).
    assert_eq!(
        redact_remote_url("https://admin%3AP%40ssw0rd@dbhost/x"),
        "https://<redacted>@dbhost/x"
    );
}

/// Round-5 L1: a sensitive pair's scheme-path value extends through `/`
/// to the token end (base64 routinely contains `/`) — subsequent
/// segments over-redact (safe direction), legit paths stay intact.
#[test]
fn round5_l1_scheme_path_value_runs_past_slash() {
    // Base64-with-slash value fully redacted on every channel.
    assert_eq!(
        redact_remote_url("https://github.com/token=R5L1AAAA/R5L1BBBB"),
        "https://github.com/token=<redacted>"
    );
    assert_eq!(
        redact_credentials("https://github.com/token=R5L1AAAA/R5L1BBBB"),
        "https://github.com/token=<redacted>"
    );
    assert_eq!(
        sanitize_target_url("https://github.com/token=R5L1AAAA/R5L1BBBB"),
        "https://github.com/token=<redacted>"
    );
    assert_eq!(
        scrub_text("see https://github.com/token=R5L1AAAA/R5L1BBBB end"),
        "see https://github.com/token=<redacted> end"
    );
    // Mid-path pair swallows the rest (documented over-redaction).
    assert_eq!(
        redact_remote_url("https://h/a/token=R5L1CCCC/tail"),
        "https://h/a/token=<redacted>"
    );
    // Legit multi-segment paths round-trip byte-identical.
    assert_eq!(
        redact_remote_url("https://github.com/owner/repo"),
        "https://github.com/owner/repo"
    );
    assert_eq!(
        redact_remote_url("https://h/next=1/owner/repo"),
        "https://h/next=1/owner/repo"
    );
    assert_eq!(
        redact_credentials("https://github.com/owner/repo"),
        "https://github.com/owner/repo"
    );
}

/// Round-5 L2: percent-encoded pair separators (`%3D`/`%3A`, either
/// case) split like their literal forms on every channel, with the
/// original spelling preserved and `:`-semantics intact.
#[test]
fn round5_l2_encoded_pair_separators_split() {
    for sep in ["%3D", "%3d"] {
        let input = format!("token{sep}R5L2EQ99");
        assert_eq!(
            redact_remote_url(&format!("https://github.com/{input}")),
            format!("https://github.com/token{sep}<redacted>"),
            "{input}"
        );
        assert_eq!(
            redact_remote_url(&input),
            format!("token{sep}<redacted>"),
            "{input}"
        );
        assert_eq!(
            scrub_text(&format!("set {input} ok")),
            format!("set token{sep}<redacted> ok"),
            "{input}"
        );
    }
    for sep in ["%3A", "%3a"] {
        // Strong key redacts through the encoded colon.
        let input = format!("token{sep}R5L2CO99");
        assert_eq!(
            redact_remote_url(&format!("https://github.com/{input}")),
            format!("https://github.com/token{sep}<redacted>"),
            "{input}"
        );
        assert_eq!(
            scrub_text(&format!("set {input} ok")),
            format!("set token{sep}<redacted> ok"),
            "{input}"
        );
        // Weak-key colon semantics preserved: unshaped echoes, shaped redacts.
        assert_eq!(
            redact_remote_url(&format!("auth{sep}repo")),
            format!("auth{sep}repo"),
            "{sep}"
        );
        assert_eq!(
            redact_remote_url(&format!("auth{sep}glpat-R5L2SHAPED01")),
            format!("auth{sep}<redacted>"),
            "{sep}"
        );
    }
    // Drive-letter guard and empty key/value still echo.
    assert_eq!(redact_remote_url("C%3A\\path"), "C%3A\\path");
    assert_eq!(scrub_text("set C%3A\\path ok"), "set C%3A\\path ok");
    assert_eq!(redact_remote_url("%3DR5L2NOKEY"), "%3DR5L2NOKEY");
    // Encoded legit content (non-sensitive key) echoes.
    assert_eq!(
        redact_remote_url("https://github.com/owner%3Drepo"),
        "https://github.com/owner%3Drepo"
    );
    assert_eq!(scrub_text("set owner%3Drepo ok"), "set owner%3Drepo ok");
}

/// Round-5 L3: vertical-tab/form-feed are sweep gaps (skipped), not
/// stops — a marked secret past one still redacts; line breaks stop.
#[test]
fn round5_l3_sweep_skips_vtab_ff() {
    assert_eq!(
        scrub_text("ext::ssh --flag \u{0b}ghp_R5L3CANARY01"),
        "<redacted-url> --flag \u{0b}<redacted>"
    );
    assert_eq!(
        scrub_text("ext::ssh --flag \u{0c}ghp_R5L3CANARY02"),
        "<redacted-url> --flag \u{0c}<redacted>"
    );
    // Gap span preserved verbatim across consecutive gaps.
    assert_eq!(
        scrub_text("ext::ssh \u{0b}\u{0c}ghp_R5L3CANARY03"),
        "<redacted-url> \u{0b}\u{0c}<redacted>"
    );
    // Line-break bound intact (existing pins hold).
    assert_eq!(
        scrub_text("ext::ssh --flag ghp_R5L3A\nnext ghp_R5L3B"),
        "<redacted-url> --flag <redacted>\nnext ghp_R5L3B"
    );
}

/// Round-5 W1: `passphrase` (and `passkey`, same secret-bearing family)
/// are sensitive key words on every pair shape; the weak `pass:`
/// residual and the `keyboard` echo hold.
#[test]
fn round5_w1_passphrase_passkey_redact() {
    for key in ["passphrase", "passkey"] {
        for (input, want) in [
            (format!("{key}=R5W1EQ99"), format!("{key}=<redacted>")),
            (format!("{key}:R5W1CO99"), format!("{key}:<redacted>")),
        ] {
            assert_eq!(redact_remote_url(&input), want, "{input}");
            assert_eq!(
                scrub_text(&format!("set {input} ok")),
                format!("set {want} ok"),
                "{input}"
            );
        }
        // Spaced, JSON, and CLI shapes agree.
        assert_eq!(
            scrub_text(&format!("{key}: R5W1SP99")),
            format!("{key}: <redacted>")
        );
        assert_eq!(
            scrub_text(&format!("{{\"{key}\": \"R5W1JS99\"}}")),
            format!("{{\"{key}\": \"<redacted>\"}}")
        );
        assert_eq!(
            scrub_text(&format!("--{key} R5W1CLI99")),
            format!("--{key} <redacted>")
        );
    }
    // Username parity: a passphrase/passkey-carrying user is
    // credential-shaped like `password` (sibling parity).
    assert_eq!(redact_remote_url("mypassphrase1@host"), "<redacted>@host");
    assert_eq!(redact_remote_url("mypasskey1@host"), "<redacted>@host");
    // Existing pins hold: `keyboard` echoes, weak `pass:hunter2` echoes.
    assert_eq!(redact_remote_url("keyboard=R5W1KB"), "keyboard=R5W1KB");
    assert_eq!(redact_remote_url("pass:hunter2"), "pass:hunter2");
    assert_eq!(scrub_text("set pass:hunter2 ok"), "set pass:hunter2 ok");
}
