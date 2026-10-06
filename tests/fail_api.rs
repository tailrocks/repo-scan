//! RETEST-5/6 direct-API regression: public constructors uphold the
//! no-credential-bytes invariant and pin file creation to the parent FD
//! even when callers bypass CLI sanitization. Fixtures live under `/tmp`
//! only (0700 dirs); no machine scans, no repo writes, no binary spawns.

use repo_scan::model::StatusMode;
use repo_scan::report::builder::{stream_report_from_store, ReportInputs, ReportPipeline};
use repo_scan::report::model::{EncodedName, Remote, Scan, ScanTarget};
use repo_scan::store::{
    NewCheckout, NewGitInstance, NewRef, NewRemote, NewScan, NewStatus, NewVolume, Store,
    TursoStore,
};
use std::path::Path;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn state_files(state: &Path) -> Vec<std::path::PathBuf> {
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
        scope_boundaries: vec!["Only the explicit fixture root was requested.".to_string()],
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

fn seed_catalog(store: &TursoStore, now: i64) {
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
                    evidence_json: "[\"Effective origin fetch URL matches the target.\"]",
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
        store
            .upsert_ref(
                &NewRef {
                    id: "ref-1",
                    instance_id: "repo-1",
                    checkout_scope_id: None,
                    kind: "local",
                    name: b"refs/heads/main",
                    oid: Some(b"1111111111111111111111111111111111111111"),
                    algo: Some("sha1"),
                    symbolic_target: None,
                    upstream: None,
                    state: "valid",
                },
                now,
            )
            .await
            .expect("ref");
        store
            .upsert_remote(
                &NewRemote {
                    id: "rem-1",
                    instance_id: "repo-1",
                    checkout_scope_id: None,
                    name: b"origin",
                    role: "fetch",
                    url: b"https://github.com/owner/repo.git",
                    canonical_url: Some(b"https://github.com/owner/repo"),
                },
                now,
            )
            .await
            .expect("remote");
        store
            .record_status(
                &NewStatus {
                    checkout_id: "co-1",
                    mode: "summary",
                    state: "complete",
                    started_ms: Some(now - 10),
                    finished_ms: Some(now),
                    staged: Some(1),
                    unstaged: Some(2),
                    untracked: Some(3),
                    untracked_units: "collapsed_entries",
                    submodules: "checked",
                    unknown_fields: "[]",
                    input_fingerprint: None,
                    observed_rev: 1,
                },
                now,
            )
            .await
            .expect("status");
    });
}

/// RETEST-5: `create_scan_request` sanitizes inside the method, so a direct
/// API caller bypassing CLI sanitization persists no credential bytes.
/// Stored rows carry the sanitized form; catalog files carry no canary.
#[test]
fn api_store_create_scan_request_holds_no_credential_bytes() {
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let db = dir.path().join("payload").join("catalog.db");
    let vectors: &[(&str, &str, &str)] = &[
        (
            "userinfo",
            "https://user:FAILAPICANARY01@github.com/o/r",
            "FAILAPICANARY01",
        ),
        (
            "jwt-query",
            "https://github.com/o/r?jwt=FAILAPICANARY02",
            "FAILAPICANARY02",
        ),
        (
            "frag",
            "https://github.com/o/r#token=FAILAPICANARY03",
            "FAILAPICANARY03",
        ),
        (
            "scp-user",
            "FAILAPICANARY04@github.com:o/r.git",
            "FAILAPICANARY04",
        ),
    ];
    runtime().block_on(async {
        let store = TursoStore::open(&db).await.expect("open");
        let now = repo_scan::store::now_ms();
        for (i, (name, url, canary)) in vectors.iter().enumerate() {
            let id = format!("scan-failapi-{i}");
            let canonical = format!("https://github.com/o/r?next={canary}-canon");
            let inserted = store
                .create_scan_request(
                    &NewScan {
                        id: &id,
                        url_raw: url.as_bytes(),
                        url_canonical: Some(canonical.as_bytes()),
                        scope: "roots",
                        status_mode: "summary",
                        report_dest: None,
                    },
                    now,
                )
                .await
                .expect("sanitize layer accepts UTF-8 targets");
            assert!(inserted, "{name}: first insert wins");
            let row = store.get_scan(&id).await.expect("get").expect("row");
            assert!(
                !contains_bytes(&row.url_raw, canary.as_bytes()),
                "{name}: url_raw leaks"
            );
            let stored_canon = row.url_canonical.expect("canonical row");
            assert!(
                !contains_bytes(&stored_canon, canary.as_bytes()),
                "{name}: canonical leaks"
            );
            assert_eq!(
                String::from_utf8_lossy(&row.url_raw).into_owned(),
                repo_scan::identity::sanitize_target_url(url),
                "{name}: stored form is the sanitized target"
            );
            assert_eq!(
                String::from_utf8_lossy(&stored_canon).into_owned(),
                "https://github.com/o/r",
                "{name}: canonical tail stripped"
            );
        }
        // Non-UTF-8 targets are refused without echoing input bytes.
        let err = store
            .create_scan_request(
                &NewScan {
                    id: "scan-failapi-bad",
                    url_raw: b"https://github.com/o/r\xff",
                    url_canonical: None,
                    scope: "roots",
                    status_mode: "summary",
                    report_dest: None,
                },
                now,
            )
            .await
            .expect_err("non-UTF-8 target refused");
        assert!(err.to_string().contains("UTF-8"), "{err}");
        assert!(
            store
                .get_scan("scan-failapi-bad")
                .await
                .expect("get")
                .is_none(),
            "refused row never persisted"
        );
        store.close().await.expect("close");
    });
    for (_, _, canary) in vectors {
        assert_no_canary_in_state(dir.path(), canary);
    }
}

/// RETEST-5: the report-model `sanitized` constructors drop credential bytes
/// from URL fields, so direct model callers that bypass the builder still
/// serialize clean records. Idempotent on already-redacted values.
#[test]
fn api_report_model_sanitized_drops_canaries() {
    let scan = Scan {
        id: "scan-x".to_string(),
        generation: 1,
        epoch: 1,
        catalog_revision: 1,
        target_url: "https://user:FAILAPIMODELCANARY05@github.com/o/r".to_string(),
        canonical_url: Some("https://github.com/o/r?jwt=FAILAPIMODELCANARY06".to_string()),
        targets: vec![ScanTarget {
            raw: "https://user:FAILAPIMODELCANARY08@github.com/o/r".to_string(),
            canonical: Some("https://github.com/o/r?jwt=FAILAPIMODELCANARY09".to_string()),
            matched_repositories: 1,
        }],
        matching_policy: "v1".to_string(),
        scope: "roots".to_string(),
        state: "complete".to_string(),
        started_at: "2026-01-01T00:00:00Z".to_string(),
        finished_at: None,
        superseded_by: None,
        cached: false,
        status_mode: "summary".to_string(),
    }
    .sanitized();
    let bytes = serde_json::to_vec(&scan).expect("scan json");
    assert!(!contains_bytes(&bytes, b"FAILAPIMODELCANARY05"));
    assert!(!contains_bytes(&bytes, b"FAILAPIMODELCANARY06"));
    assert!(!contains_bytes(&bytes, b"FAILAPIMODELCANARY08"));
    assert!(!contains_bytes(&bytes, b"FAILAPIMODELCANARY09"));
    assert!(
        scan.target_url.contains("<redacted>"),
        "{}",
        scan.target_url
    );
    let again = scan.clone().sanitized();
    assert_eq!(serde_json::to_vec(&again).expect("json"), bytes);

    let remote = Remote {
        id: "rem-x".to_string(),
        repository_id: "repo-x".to_string(),
        checkout_scope_id: None,
        name: EncodedName {
            display: "origin".to_string(),
            encoding: "utf8".to_string(),
            value: "origin".to_string(),
        },
        role: "fetch".to_string(),
        url: "https://tok:FAILAPIREMOTECANARY07@github.com/o/r.git".to_string(),
        canonical_url: Some("https://github.com/o/r".to_string()),
        observed_at: "2026-01-01T00:00:00Z".to_string(),
    }
    .sanitized();
    let bytes = serde_json::to_vec(&remote).expect("remote json");
    assert!(!contains_bytes(&bytes, b"FAILAPIREMOTECANARY07"));
    assert!(remote.url.contains("<redacted>"), "{}", remote.url);
}

/// RETEST-5: report emission from direct-API `ReportInputs` carrying
/// canaries emits no canary bytes in the streamed report, the published
/// file, the retained snapshot, or the terminal rendering.
#[test]
fn api_report_emission_never_emits_canary() {
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let state_dir = dir.path().join("state");
    let db = state_dir.join("payload").join("catalog.db");
    let canary = "FAILAPIEMITCANARY08";
    let store = runtime().block_on(async { TursoStore::open(&db).await.expect("open") });
    let now = 1_759_154_400_000;
    seed_catalog(&store, now);

    let mut inputs = test_inputs("report-failapi-1");
    inputs.target_url = format!("https://user:{canary}@github.com/o/r");
    inputs.canonical_url = Some(format!("https://github.com/o/r?jwt={canary}"));
    let (bytes, _) = runtime()
        .block_on(async { stream_report_from_store(&store, &inputs, Vec::new()).await })
        .expect("stream");
    assert!(!contains_bytes(&bytes, canary.as_bytes()));
    let report: serde_json::Value = serde_json::from_slice(&bytes).expect("report json");
    assert_eq!(
        report["scan"]["target_url"].as_str(),
        Some("https://user:<redacted>@github.com/o/r")
    );

    let dest = dir.path().join("report.json");
    let staging = state_dir.join("payload").join("report_staging");
    let snapshots = state_dir.join("payload").join("report_snapshots");
    let mut file_inputs = test_inputs("report-failapi-2");
    file_inputs.target_url = format!("https://user:{canary}@github.com/o/r");
    file_inputs.canonical_url = Some(format!("https://github.com/o/r?jwt={canary}"));
    runtime()
        .block_on(async {
            ReportPipeline::emit_to_file(
                &store,
                &file_inputs,
                &dest,
                &state_dir,
                &staging,
                &snapshots,
                now,
            )
            .await
        })
        .expect("emit file");
    let dest_bytes = std::fs::read(&dest).expect("read dest");
    assert!(!contains_bytes(&dest_bytes, canary.as_bytes()));
    let snap_bytes = std::fs::read(snapshots.join("report-failapi-2.json")).expect("read snapshot");
    assert!(!contains_bytes(&snap_bytes, canary.as_bytes()));

    let mut term_inputs = test_inputs("report-failapi-3");
    term_inputs.target_url = format!("https://user:{canary}@github.com/o/r");
    term_inputs.canonical_url = Some(format!("https://github.com/o/r?jwt={canary}"));
    let mut terminal: Vec<u8> = Vec::new();
    runtime()
        .block_on(async {
            ReportPipeline::emit_to_terminal(
                &store,
                &term_inputs,
                &staging,
                &snapshots,
                now,
                &mut terminal,
            )
            .await
        })
        .expect("emit terminal");
    assert!(!contains_bytes(&terminal, canary.as_bytes()));
    assert_no_canary_in_state(dir.path(), canary);
    runtime().block_on(async { store.close().await.expect("close") });
}

/// RETEST-6: the file helpers keep owner-only happy-path behavior —
/// exclusive create, truncate-write, no parent creation.
#[test]
fn api_privacy_helpers_hold_modes_and_refuse_symlinks() {
    use repo_scan::privacy::{private_dir_0700, private_file_0600, private_write_0600};
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let root = dir.path().join("root");
    private_dir_0700(&root).expect("mkdir");
    let created = root.join("a.txt");
    {
        use std::io::Write as _;
        let mut handle = private_file_0600(&created).expect("create");
        handle.write_all(b"data").expect("write");
    }
    assert!(
        private_file_0600(&created).is_err(),
        "exclusive rerun fails"
    );
    private_write_0600(&root.join("b.txt"), b"hello").expect("write");
    private_write_0600(&root.join("b.txt"), b"again").expect("overwrite");
    assert_eq!(std::fs::read(root.join("b.txt")).expect("read"), b"again");
    assert!(
        private_write_0600(&root.join("missing").join("c.txt"), b"x").is_err(),
        "parents are never created"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode(&created), 0o600, "created file mode");
        assert_eq!(mode(&root.join("b.txt")), 0o600, "written file mode");
    }
}

/// RETEST-6: file creation is pinned to the parent FD — a symlinked ancestor
/// is refused (never created through) and a symlinked leaf is refused with
/// its target untouched.
#[cfg(unix)]
#[test]
fn api_privacy_file_helpers_pin_ancestors() {
    use repo_scan::privacy::{private_dir_0700, private_file_0600, private_write_0600};
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let real = dir.path().join("real");
    private_dir_0700(&real).expect("mkdir");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let err = private_file_0600(&link.join("evil.txt")).expect_err("symlinked ancestor refused");
    assert!(err.to_string().contains("symlink"), "{err}");
    assert!(!real.join("evil.txt").exists(), "no creation through link");
    let err = private_write_0600(&link.join("evil2.txt"), b"x").expect_err("ancestor refused");
    assert!(err.to_string().contains("symlink"), "{err}");
    assert!(!real.join("evil2.txt").exists(), "no write through link");

    let target = real.join("target.txt");
    private_write_0600(&target, b"orig").expect("seed");
    let leaf = real.join("leaf");
    std::os::unix::fs::symlink(&target, &leaf).expect("symlink");
    let err = private_file_0600(&leaf).expect_err("leaf symlink refused");
    assert!(err.to_string().contains("symlink"), "{err}");
    let err = private_write_0600(&leaf, b"pwn").expect_err("leaf symlink refused");
    assert!(err.to_string().contains("symlink"), "{err}");
    assert_eq!(std::fs::read(&target).expect("read"), b"orig");
}
