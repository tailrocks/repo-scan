//! Regression tests for the report/privacy security review findings
//! (RSP-001..RSP-011, XSEC-04/05/06/08): one focused test per fix.
//! Fixture-scale only (tempdirs, no machine scans).

use repo_scan::identity::{
    has_userinfo, redact_credentials, scrub_text, strip_userinfo, REDACTED_URL,
};
use repo_scan::model::StatusMode;
use repo_scan::report::builder::{
    quarantine_staging, stream_report_from_store, verify_staged_report_capped, AliasInput,
    CandidateInput, FullPathCache, ReportInputs, ReportPipeline,
};
use repo_scan::report::model::Report;
use repo_scan::report::publish::{
    check_destination, check_staged_memory_budget, publish_staged, sha256_hex, BoundStaged,
    DestinationKind,
};
#[cfg(unix)]
use repo_scan::report::publish::{publish_staged_with_options, PublishOptions};
use repo_scan::report::validate::validate_report;
use repo_scan::store::{
    NewCheckout, NewGitInstance, NewRemote, NewStatus, NewTask, NewVolume, Store, TursoStore,
};

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

fn open_store(dir: &tempfile::TempDir) -> TursoStore {
    let db = dir.path().join("payload").join("catalog.db");
    runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
}

/// Minimal valid seed: volume, two dirs, one confirmed instance +
/// checkout + remote. Status rows are added only where a test needs them.
fn seed_minimal(store: &TursoStore, now: i64, remote_url: &[u8], evidence_json: &str) {
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
                    evidence_json,
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
            .upsert_remote(
                &NewRemote {
                    id: "rem-1",
                    instance_id: "repo-1",
                    checkout_scope_id: None,
                    name: b"origin",
                    role: "fetch",
                    url: remote_url,
                    canonical_url: Some(b"https://github.com/owner/repo"),
                },
                now,
            )
            .await
            .expect("remote");
    });
}

fn seed_complete_status(store: &TursoStore, now: i64) {
    runtime().block_on(async {
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

fn stream_to_report(store: &TursoStore, inputs: &ReportInputs) -> Report {
    let (bytes, _) = runtime()
        .block_on(async { stream_report_from_store(store, inputs, Vec::new()).await })
        .expect("stream");
    serde_json::from_slice(&bytes).expect("report parses")
}

/// RSP-001: legacy catalog rows carrying credential-bearing URLs must be
/// redacted at the report emission boundary (not trusted from the writer).
#[test]
fn rsp001_legacy_credential_urls_redacted_at_emission() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    let evidence = serde_json::to_string(&vec![
        "Effective origin fetch URL matches the target.".to_string(),
        "legacy note: https://tok:sekret-token@git.internal/o/r?access_token=zzz-legacy"
            .to_string(),
    ])
    .expect("evidence json");
    seed_minimal(
        &store,
        now,
        b"https://user:s3cr3t-legacy@github.com/owner/repo.git",
        &evidence,
    );
    let report = stream_to_report(&store, &test_inputs("rsp001-1"));
    assert_eq!(report.remotes.len(), 1);
    let url = &report.remotes[0].url;
    assert!(url.contains("<redacted>"), "{url}");
    assert!(!url.contains("s3cr3t-legacy"), "{url}");
    for line in &report.repositories[0].evidence {
        assert!(!line.contains("sekret-token"), "{line}");
        assert!(!line.contains("zzz-legacy"), "{line}");
    }
    assert!(
        report.repositories[0]
            .evidence
            .iter()
            .any(|line| line.contains("<redacted>")),
        "embedded legacy URL redacted: {:?}",
        report.repositories[0].evidence
    );
    // Terminal rendering carries no secret either.
    let mut out: Vec<u8> = Vec::new();
    repo_scan::report::render::render_terminal(&report, &mut out).expect("render");
    let text = String::from_utf8(out).expect("utf8");
    assert!(!text.contains("s3cr3t-legacy"), "{text}");
    assert!(!text.contains("sekret-token"), "{text}");
    assert!(!text.contains("zzz-legacy"), "{text}");
}

/// RSP-002: redaction covers query/fragment secrets and fails closed on
/// malformed userinfo, percent-encoded keys, and control characters.
#[test]
fn rsp002_query_fragment_and_malformed_redaction() {
    // Sensitive query/fragment values are redacted, structure preserved.
    assert_eq!(
        redact_credentials("https://github.com/o/r.git?access_token=secret"),
        "https://github.com/o/r.git?access_token=<redacted>"
    );
    assert_eq!(
        redact_credentials("https://host/o/r.git?next=/x&token=abc#sig=def"),
        "https://host/o/r.git?next=/x&token=<redacted>#sig=<redacted>"
    );
    // Non-sensitive parameters round-trip byte-identical.
    assert_eq!(
        redact_credentials("https://host/o/r.git?page=2&per=50"),
        "https://host/o/r.git?page=2&per=50"
    );
    // Percent-encoded sensitive keys are still detected.
    let encoded = redact_credentials("https://host/o/r?%74oken=abc&x=1");
    assert!(!encoded.contains("abc"), "{encoded}");
    assert!(encoded.contains("%74oken=<redacted>"), "{encoded}");
    // Malformed smuggled userinfo containing `/` fails closed.
    let malformed = "https://user:secret/ret@github.com/o/r";
    assert!(has_userinfo(malformed));
    assert_eq!(redact_credentials(malformed), REDACTED_URL);
    assert_eq!(strip_userinfo(malformed), REDACTED_URL);
    // Control characters fail closed.
    assert_eq!(redact_credentials("https://host/o/r\n?x=1"), REDACTED_URL);
    // Established shapes are unchanged.
    assert_eq!(
        redact_credentials("https://user:secret@github.com/o/r.git"),
        "https://user:<redacted>@github.com/o/r.git"
    );
    assert_eq!(
        redact_credentials("https://token123@github.com/o/r.git"),
        "https://<redacted>@github.com/o/r.git"
    );
    assert_eq!(
        redact_credentials("https://github.com/o/r.git"),
        "https://github.com/o/r.git"
    );
    assert_eq!(
        redact_credentials("git@github.com:o/r.git"),
        "<redacted>@github.com:o/r.git"
    );
    assert!(!has_userinfo("https://@github.com/o/r.git"));
    // RS-PRIV-10: scp-like users redact on display but are not rejectable
    // userinfo (the CLI must keep accepting the `git@` login).
    assert!(!has_userinfo("git@github.com:o/r.git"));
    // Free-text scrubbing: embedded URLs and bare secret pairs.
    let scrubbed = scrub_text("clone failed for https://u:p@h/r?token=abc, retry later");
    assert!(!scrubbed.contains("token=abc"), "{scrubbed}");
    assert!(scrubbed.contains("<redacted>"), "{scrubbed}");
    assert_eq!(
        scrub_text("access_token=zzz leaked"),
        "access_token=<redacted> leaked"
    );
    assert_eq!(
        scrub_text("ordinary prose, nothing secret"),
        "ordinary prose, nothing secret"
    );
}

/// RS-PRIV-04: spaced, JSON, CLI-flag, and multiline pairs redact with
/// structure preserved; bare `key value` prose does not.
#[test]
fn rspriv04_spaced_json_cli_multiline_pairs_redact() {
    assert_eq!(scrub_text("password: secret"), "password: <redacted>");
    assert_eq!(scrub_text("token: abc"), "token: <redacted>");
    assert_eq!(scrub_text("password : secret"), "password : <redacted>");
    assert_eq!(
        scrub_text(r#"{"password": "secret"}"#),
        r#"{"password": "<redacted>"}"#
    );
    assert_eq!(scrub_text("--password secret"), "--password <redacted>");
    assert_eq!(scrub_text("token:\nabc123"), "token:\n<redacted>");
    // Same-token behavior is unchanged and idempotent.
    assert_eq!(
        scrub_text("access_token=zzz leaked"),
        "access_token=<redacted> leaked"
    );
    // Non-pairs survive: bare prose, drive letters, `::` paths.
    assert_eq!(
        scrub_text("ordinary prose, nothing secret"),
        "ordinary prose, nothing secret"
    );
    assert_eq!(scrub_text("C:\\path\\x"), "C:\\path\\x");
    assert_eq!(scrub_text("--password --user x"), "--password --user x");
}

fn prior_bytes(report_id: &str) -> Vec<u8> {
    serde_json::json!({
        "schema_version": repo_scan::report::model::SCHEMA_VERSION,
        "report_id": report_id,
        "tool": {"name": "repo-scan", "version": "0.1.0", "source_commit": null},
    })
    .to_string()
    .into_bytes()
}

/// RSP-003: concurrent publishers and destination swaps never produce torn
/// bytes or residue: every observed state is exactly one complete value.
/// (The expected-inode CAS + directory lock narrow the commit race to the
/// `renameat` syscall itself; this hammer locks in old-or-new atomicity
/// under contention. A deterministically timed swap into the residual
/// single-syscall window is not feasible without fault injection.)
#[test]
fn rsp003_concurrent_publish_stays_atomic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    repo_scan::privacy::private_dir_0700(&state.join("payload")).expect("payload");
    let bytes_a = prior_bytes("report-a");
    let bytes_b = prior_bytes("report-b");
    let unrelated: Vec<u8> = b"user data, not a report".to_vec();
    let staged_a = dir.path().join("staged-a.json");
    let staged_b = dir.path().join("staged-b.json");
    repo_scan::privacy::private_write_0600(&staged_a, &bytes_a).expect("staged a");
    repo_scan::privacy::private_write_0600(&staged_b, &bytes_b).expect("staged b");
    let dest = dir.path().join("report.json");
    repo_scan::privacy::private_write_0600(&dest, &bytes_a).expect("dest a");
    // Swapper inputs: renamed into place and back, so their contents roam
    // within {A, B, unrelated} but never tear.
    let swap_a = dir.path().join("swap-a.json");
    let swap_u = dir.path().join("swap-u.json");
    repo_scan::privacy::private_write_0600(&swap_a, &bytes_a).expect("swap a");
    repo_scan::privacy::private_write_0600(&swap_u, &unrelated).expect("swap u");

    std::thread::scope(|scope| {
        let (dest, state, staged_a, staged_b) = (&dest, &state, &staged_a, &staged_b);
        let (swap_a, swap_u) = (&swap_a, &swap_u);
        let dir_path = dir.path();
        scope.spawn(move || {
            for _ in 0..30 {
                let _ = publish_staged(staged_b, dest, state);
            }
        });
        scope.spawn(move || {
            for _ in 0..30 {
                let _ = publish_staged(staged_a, dest, state);
            }
        });
        scope.spawn(move || {
            for i in 0..30 {
                let src = if i % 2 == 0 { swap_a } else { swap_u };
                let hold = dir_path.join("hold.json");
                let _ = std::fs::rename(dest, &hold);
                let _ = std::fs::rename(src, dest);
                let _ = std::fs::rename(&hold, src);
            }
        });
        // Observer: every sample is one complete value or a mid-swap gap.
        for _ in 0..300 {
            if let Ok(sample) = std::fs::read(dest) {
                assert!(
                    sample == bytes_a || sample == bytes_b || sample == unrelated,
                    "torn destination bytes observed"
                );
            }
        }
    });

    // The swapper permutes files by rename; if it bowed out with the
    // destination mid-permutation, restore it (test artifact only:
    // publication itself never deletes the destination).
    let hold = dir.path().join("hold.json");
    if !dest.exists() {
        if hold.exists() {
            std::fs::rename(&hold, &dest).expect("restore dest");
        } else {
            repo_scan::privacy::private_write_0600(&dest, &bytes_a).expect("restore dest");
        }
    }

    let final_bytes = std::fs::read(&dest).expect("dest readable");
    assert!(
        final_bytes == bytes_a || final_bytes == bytes_b || final_bytes == unrelated,
        "final destination is one complete value"
    );
    let leftovers: Vec<_> = dir
        .path()
        .read_dir()
        .expect("ls")
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "no sibling left behind: {leftovers:?}"
    );
}

/// RSP-004: a symlinked parent resolving to a legitimate directory still
/// publishes (bound through the resolved FD), while any destination under
/// tool state is refused even through an alias.
#[test]
fn rsp004_symlinked_parent_bound_and_state_alias_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    repo_scan::privacy::private_dir_0700(&state.join("payload")).expect("payload");
    #[cfg(unix)]
    {
        let staged = dir.path().join("staged.bin");
        repo_scan::privacy::private_write_0600(&staged, b"abc").expect("write");
        let real = dir.path().join("real");
        repo_scan::privacy::private_dir_0700(&real).expect("real");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let dest = link.join("report.json");
        publish_staged(&staged, &dest, &state).expect("aliased legit parent publishes");
        assert_eq!(
            std::fs::read(real.join("report.json")).expect("read"),
            b"abc"
        );

        // Alias into tool state is refused, not followed.
        let state_link = dir.path().join("state-link");
        std::os::unix::fs::symlink(&state, &state_link).expect("symlink");
        let evil = state_link.join("evil.json");
        let err = check_destination(&evil, &state).expect_err("state alias refused");
        assert!(
            err.to_string().contains("tool state dir")
                || err.to_string().contains("persistence payload"),
            "{err}"
        );
    }

    // Direct state child is refused by the lib (not just the binary guard).
    let direct = state.join("evil.json");
    let err = check_destination(&direct, &state).expect_err("state child refused");
    assert!(err.to_string().contains("tool state dir"), "{err}");
}

/// RSP-005: staged/prior inputs must be regular files: devices and
/// directories are refused before any read (no hang, no drain).
#[cfg(unix)]
#[test]
fn rsp005_nonregular_staged_inputs_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = BoundStaged::open(std::path::Path::new("/dev/null")).expect_err("device refused");
    assert!(err.to_string().contains("non-regular"), "{err}");
    let err = BoundStaged::open(dir.path()).expect_err("directory refused");
    assert!(err.to_string().contains("non-regular"), "{err}");
    let err = repo_scan::report::publish::is_verified_prior_report(dir.path())
        .expect_err("prior refused");
    assert!(err.to_string().contains("non-regular"), "{err}");
}

/// RSP-006: a traversal report ID is rejected before any staging filename
/// is built, leaving no residue behind.
#[test]
fn rsp006_traversal_report_id_rejected_before_staging() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let store = {
        let db = state.join("payload").join("catalog.db");
        runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
    };
    seed_minimal(
        &store,
        1_759_154_400_000,
        b"https://github.com/owner/repo.git",
        "[]",
    );
    let staging = state.join("payload").join("report_staging");
    let snapshots = state.join("payload").join("report_snapshots");

    for bad_id in ["../../evil", "a/b", ".."] {
        let inputs = test_inputs(bad_id);
        let mut terminal: Vec<u8> = Vec::new();
        let err = runtime()
            .block_on(async {
                ReportPipeline::emit_to_terminal(
                    &store,
                    &inputs,
                    &staging,
                    &snapshots,
                    1_759_154_400_000,
                    &mut terminal,
                )
                .await
            })
            .expect_err("traversal ID refused");
        assert!(err.to_string().contains("safe snapshot name"), "{err}");
    }
    assert!(
        !dir.path().join("evil").exists(),
        "no file escaped the staging directory"
    );
    if staging.exists() {
        let strays: Vec<_> = staging.read_dir().expect("ls").flatten().collect();
        assert!(strays.is_empty(), "no staging residue: {strays:?}");
    }
    let row = runtime().block_on(async {
        store
            .get_report_snapshot("../../evil")
            .await
            .expect("lookup")
    });
    assert!(row.is_none(), "no snapshot row for a rejected ID");
}

/// RSP-007: snapshots are created owner-only (`0600`) inside `0700`
/// directories, independent of the process umask.
#[cfg(unix)]
#[test]
fn rsp007_snapshot_and_staging_modes_restrictive() {
    use std::os::unix::fs::PermissionsExt;
    let mode =
        |p: &std::path::Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let store = {
        let db = state.join("payload").join("catalog.db");
        runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
    };
    seed_minimal(
        &store,
        1_759_154_400_000,
        b"https://github.com/owner/repo.git",
        "[]",
    );
    seed_complete_status(&store, 1_759_154_400_000);
    let staging = state.join("payload").join("report_staging");
    let snapshots = state.join("payload").join("report_snapshots");
    let inputs = test_inputs("rsp007-1");
    let mut terminal: Vec<u8> = Vec::new();
    runtime()
        .block_on(async {
            ReportPipeline::emit_to_terminal(
                &store,
                &inputs,
                &staging,
                &snapshots,
                1_759_154_400_000,
                &mut terminal,
            )
            .await
        })
        .expect("emit");
    assert_eq!(mode(&snapshots.join("rsp007-1.json")), 0o600);
    assert_eq!(mode(&snapshots), 0o700);
    assert_eq!(mode(&staging), 0o700);
    // Published bytes inherit the restrictive sibling mode as well.
    let dest = dir.path().join("report.json");
    publish_staged(&snapshots.join("rsp007-1.json"), &dest, &state).expect("publish");
    assert_eq!(
        mode(&dest) & 0o077,
        0,
        "no group/other access on published bytes"
    );
}

/// RSP-008: coverage is derived from scan state; overrides that
/// contradict the derived facts are refused, and validation rejects
/// reports whose claims contradict their own records.
#[test]
fn rsp008_contradicted_coverage_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_minimal(&store, now, b"https://github.com/owner/repo.git", "[]");

    // Filesystem "complete" with pending tasks contradicts the facts.
    // Pending work lives in the catalog (RSP-008 in-txn count); the caller
    // count is ignored, so the task is seeded rather than claimed.
    runtime().block_on(async {
        store
            .enqueue_task(
                &NewTask {
                    id: "rsp008-seed",
                    kind: "e",
                    generation: 1,
                    dir_id: None,
                    scope_key: "d:00",
                    expected_rev: 0,
                    idempotency_key: "i:rsp008-seed",
                },
                now,
            )
            .await
            .expect("enqueue");
    });
    let mut inputs = test_inputs("rsp008-a");
    inputs.tasks_pending = 0;
    inputs.coverage_filesystem = Some("complete".to_string());
    let err = runtime()
        .block_on(async { stream_report_from_store(&store, &inputs, Vec::new()).await })
        .expect_err("contradicted filesystem override refused");
    assert!(err.to_string().contains("contradicts"), "{err}");

    // Status "complete" with no status row (pending default) contradicts.
    let mut inputs = test_inputs("rsp008-b");
    inputs.coverage_status = Some("complete".to_string());
    let err = runtime()
        .block_on(async { stream_report_from_store(&store, &inputs, Vec::new()).await })
        .expect_err("contradicted status override refused");
    assert!(err.to_string().contains("contradicts"), "{err}");

    // Identity "complete_under_policy" with an unresolvable candidate.
    let mut inputs = test_inputs("rsp008-c");
    inputs.candidates.push(CandidateInput {
        id: "cand-1".to_string(),
        path_bytes: b"/tmp/stray".to_vec(),
        repository_id: None,
        disposition: "unresolvable_identity".to_string(),
        reason: "identifying remotes removed".to_string(),
        retry_after_ms: None,
        error_ids: Vec::new(),
    });
    inputs.coverage_identity = Some("complete_under_policy".to_string());
    let err = runtime()
        .block_on(async { stream_report_from_store(&store, &inputs, Vec::new()).await })
        .expect_err("contradicted identity override refused");
    assert!(err.to_string().contains("contradicts"), "{err}");

    // Positive control: a truthful restatement streams fine.
    seed_complete_status(&store, now);
    let mut inputs = test_inputs("rsp008-d");
    inputs.coverage_status = Some("complete".to_string());
    let report = stream_to_report(&store, &inputs);
    assert_eq!(report.coverage.status, "complete");

    // Validation layer: claims must agree with the report's own records.
    let bytes = include_bytes!("data/example-report.json");
    let mut report: Report = serde_json::from_slice(bytes).expect("example parses");
    report.coverage.tasks_pending = 5;
    let err = validate_report(&report).expect_err("pending work contradicts complete");
    assert!(err.to_string().contains("tasks_pending"), "{err}");
}

#[test]
fn rsf_5dbc3836_validator_rejects_complete_scan_with_incomplete_status() {
    let bytes = include_bytes!("data/example-report.json");
    let mut report: Report = serde_json::from_slice(bytes).expect("example parses");
    report.scan.state = "complete".to_string();
    report.coverage.status = "incomplete".to_string();
    let err = validate_report(&report)
        .expect_err("validator must reject scan.state=complete when coverage.status=incomplete");
    assert!(
        err.to_string()
            .contains("scan.state is complete but coverage.status is incomplete"),
        "expected cross-check error, got: {err}"
    );
}

/// RSP-009: the envelope binds the revision actually observed stable
/// across the pre-pass and the stream (single-revision barrier), not the
/// caller's pinned claim.
#[test]
fn rsp009_envelope_binds_observed_revision() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_minimal(&store, now, b"https://github.com/owner/repo.git", "[]");
    seed_complete_status(&store, now);
    let observed = runtime().block_on(async {
        store.next_revision().await.expect("rev 1");
        store.next_revision().await.expect("rev 2")
    });
    assert_eq!(observed, 2);
    let mut inputs = test_inputs("rsp009-1");
    inputs.catalog_revision = 999; // Stale/lying caller pin.
    let report = stream_to_report(&store, &inputs);
    assert_eq!(report.scan.catalog_revision, 2);
    validate_report(&report).expect("consistent report validates");
}

/// RSP-010: hostile JSON arrays in catalog rows are streamed under
/// input/count/aggregate caps with explicit truncation markers.
#[test]
fn rsp010_huge_evidence_arrays_capped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    // One 300 KiB line: over the raw-input bound, content withheld.
    let huge = serde_json::to_string(&vec!["x".repeat(300 * 1024)]).expect("json");
    seed_minimal(&store, now, b"https://github.com/owner/repo.git", &huge);
    let report = stream_to_report(&store, &test_inputs("rsp010-a"));
    let evidence = &report.repositories[0].evidence;
    assert_eq!(evidence.len(), 1, "{evidence:?}");
    assert!(evidence[0].contains("exceeds"), "{}", evidence[0]);

    // 2000 small items: truncated at the item bound with a marker.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let many: Vec<String> = (0..2000).map(|i| format!("line-{i}")).collect();
    let many_json = serde_json::to_string(&many).expect("json");
    seed_minimal(
        &store,
        now,
        b"https://github.com/owner/repo.git",
        &many_json,
    );
    let report = stream_to_report(&store, &test_inputs("rsp010-b"));
    let evidence = &report.repositories[0].evidence;
    assert_eq!(evidence.len(), 1024 + 1, "items + marker");
    assert!(evidence[1024].contains("truncated"), "{}", evidence[1024]);
    assert_eq!(evidence[0], "line-0");
}

/// RSP-011: lower-layer error strings are privacy-scrubbed at emission:
/// no embedded credential URL or secret pair reaches the report.
#[test]
fn rsp011_error_text_scrubbed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_minimal(&store, now, b"https://github.com/owner/repo.git", "[]");
    runtime().block_on(async {
        store
            .record_error(
                "err-cred-1",
                "probe:git",
                "fetch-failed",
                "clone of https://deploy:s3cr3t-pw@git.internal/o/r?token=abc123 failed; access_token=zzz-top",
                None,
                now,
            )
            .await
            .expect("record error");
    });
    let report = stream_to_report(&store, &test_inputs("rsp011-1"));
    assert_eq!(report.errors.len(), 1);
    let message = &report.errors[0].message;
    assert!(!message.contains("s3cr3t-pw"), "{message}");
    assert!(!message.contains("abc123"), "{message}");
    assert!(!message.contains("zzz-top"), "{message}");
    assert!(message.contains("<redacted>"), "{message}");
    let mut out: Vec<u8> = Vec::new();
    repo_scan::report::render::render_terminal(&report, &mut out).expect("render");
    let text = String::from_utf8(out).expect("utf8");
    assert!(!text.contains("s3cr3t-pw"), "{text}");
    assert!(!text.contains("abc123"), "{text}");
}

/// XSEC-04: a planted prior report naming a retained report ID must match
/// the owner-private snapshot bytes; foreign priors without a snapshot
/// here keep field verification.
#[test]
fn xsec04_planted_prior_naming_snapshot_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let store = {
        let db = state.join("payload").join("catalog.db");
        runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
    };
    let now = 1_759_154_400_000;
    seed_minimal(&store, now, b"https://github.com/owner/repo.git", "[]");
    seed_complete_status(&store, now);
    let staging = state.join("payload").join("report_staging");
    let snapshots = state.join("payload").join("report_snapshots");
    let dest = dir.path().join("report.json");
    let inputs = test_inputs("xsec04-a");
    runtime()
        .block_on(async {
            ReportPipeline::emit_to_file(&store, &inputs, &dest, &state, &staging, &snapshots, now)
                .await
        })
        .expect("first emit");
    let retained = std::fs::read(&dest).expect("published bytes");

    // Planted plausible report reusing the retained report ID: refused.
    let planted = prior_bytes("xsec04-a");
    assert_ne!(planted, retained);
    repo_scan::privacy::private_write_0600(&dest, &planted).expect("plant");
    let err = check_destination(&dest, &state).expect_err("planted prior refused");
    assert!(err.to_string().contains("no-clobber"), "{err}");
    let staged_new = dir.path().join("staged-new.json");
    repo_scan::privacy::private_write_0600(&staged_new, &prior_bytes("xsec04-b")).expect("staged");
    let err = publish_staged(&staged_new, &dest, &state).expect_err("publish refused");
    assert!(
        err.to_string().contains("no-clobber") || err.to_string().contains("snapshot"),
        "{err}"
    );
    assert_eq!(
        std::fs::read(&dest).expect("read"),
        planted,
        "planted bytes untouched"
    );

    // Genuine prior (byte-identical to the snapshot) still replaces.
    repo_scan::privacy::private_write_0600(&dest, &retained).expect("restore");
    assert_eq!(
        check_destination(&dest, &state).expect("genuine prior ok"),
        DestinationKind::VerifiedPriorReport
    );
    publish_staged(&staged_new, &dest, &state).expect("genuine replacement works");

    // Foreign prior with no snapshot here: field verification still admits.
    let foreign = dir.path().join("foreign.json");
    repo_scan::privacy::private_write_0600(&foreign, &prior_bytes("foreign-1")).expect("foreign");
    assert_eq!(
        check_destination(&foreign, &state).expect("foreign prior ok"),
        DestinationKind::VerifiedPriorReport
    );
}

/// XSEC-05: destinations inside tool state are rejected by resolved
/// identity, including through a symlink alias (not just lexically).
#[test]
fn xsec05_state_dest_rejected_by_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    repo_scan::privacy::private_dir_0700(&state.join("payload")).expect("payload");

    let direct = state.join("report.json");
    let err = check_destination(&direct, &state).expect_err("state child refused");
    assert!(err.to_string().contains("tool state dir"), "{err}");

    let payload_dest = state.join("payload").join("evil.json");
    let err = check_destination(&payload_dest, &state).expect_err("payload refused");
    assert!(err.to_string().contains("persistence payload"), "{err}");

    #[cfg(unix)]
    {
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&state, &alias).expect("symlink");
        let evil = alias.join("payload").join("evil.json");
        let err = check_destination(&evil, &state).expect_err("aliased state refused");
        assert!(
            err.to_string().contains("tool state dir")
                || err.to_string().contains("persistence payload"),
            "{err}"
        );
        assert!(!evil.exists(), "nothing written through the alias");
    }
}

/// XSEC-06: quarantine dirs are owner-only and the move is dir-FD-bound;
/// a symlinked quarantine dir cannot redirect cleanup elsewhere.
#[test]
fn xsec06_quarantine_private_and_symlink_safe() {
    let dir = tempfile::tempdir().expect("tempdir");
    let staging = dir.path().join("staging");
    repo_scan::privacy::private_dir_0700(&staging).expect("mkdir");
    let staged = staging.join(".staging-1.json");
    repo_scan::privacy::private_write_0600(&staged, "bogus".as_bytes()).expect("write");
    quarantine_staging(&staged);
    assert!(!staged.exists(), "failed staging moved away");
    let moved = staging.join("quarantine").join(".staging-1.json");
    assert!(moved.is_file(), "preserved under quarantine/");
    assert_eq!(std::fs::read(&moved).expect("read"), b"bogus");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(staging.join("quarantine"))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "quarantine dir is owner-only");

        // A symlinked quarantine dir must not redirect the failed file
        // outside staging: the file is deleted, the target untouched.
        let staging2 = dir.path().join("staging2");
        repo_scan::privacy::private_dir_0700(&staging2).expect("mkdir");
        let outside = dir.path().join("outside");
        repo_scan::privacy::private_dir_0700(&outside).expect("mkdir");
        std::os::unix::fs::symlink(&outside, staging2.join("quarantine")).expect("symlink");
        let staged2 = staging2.join(".staging-2.json");
        repo_scan::privacy::private_write_0600(&staged2, "bogus".as_bytes()).expect("write");
        quarantine_staging(&staged2);
        assert!(!staged2.exists(), "failed staging not left in place");
        assert!(
            outside.read_dir().expect("ls").next().is_none(),
            "nothing escaped through the symlinked quarantine dir"
        );
    }
}

/// XSEC-08: path interning and full-path reconstruction are bounded:
/// hostile sizes fail loudly instead of growing memory with input.
#[test]
fn xsec08_path_interning_bounded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_minimal(&store, now, b"https://github.com/owner/repo.git", "[]");
    // One 2 MiB directory component: the reconstructed path trips the
    // per-path byte bound.
    let big_component = vec![b'a'; 2 * 1024 * 1024];
    runtime().block_on(async {
        let root = store
            .lookup_dir_id("vol-1", "obj-root", "1")
            .await
            .expect("lookup")
            .expect("root id");
        store
            .upsert_dir(
                Some(root),
                &big_component,
                "huge",
                "vol-1",
                "obj-huge",
                "1",
                now,
            )
            .await
            .expect("huge dir");
    });
    let err = runtime()
        .block_on(async {
            stream_report_from_store(&store, &test_inputs("xsec08-a"), Vec::new()).await
        })
        .expect_err("oversize path refused");
    assert!(err.to_string().contains("byte bound"), "{err}");

    // Caller-side aggregate: 40 distinct 1 MiB alias paths trip the
    // interned-bytes bound.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    seed_minimal(&store, now, b"https://github.com/owner/repo.git", "[]");
    let mut inputs = test_inputs("xsec08-b");
    for i in 0..40u8 {
        let mut path = vec![i; 1024 * 1024];
        path[0] = i;
        path[1] = 0xAA;
        let mut target = vec![0x55; 1024 * 1024];
        target[0] = i;
        inputs.aliases.push(AliasInput {
            path_bytes: path,
            target_path_bytes: target,
            kind: "symlink".to_string(),
            verified_at_ms: now,
        });
    }
    let err = runtime()
        .block_on(async { stream_report_from_store(&store, &inputs, Vec::new()).await })
        .expect_err("interned-bytes bound refused");
    assert!(err.to_string().contains("bound"), "{err}");
}

/// RESOURCE-RECHECK item 7: the directory full-path cache refuses overlong
/// values *before* retention and bounds aggregate bytes as well as entries
/// (previously count-only with the 1 MiB check running after insertion).
#[test]
fn recheck07_full_path_cache_byte_bounded() {
    const MIB: usize = 1024 * 1024;
    let mut cache = FullPathCache::new();

    // Overlong values (>1 MiB) are refused pre-insert: never retained,
    // never counted.
    for i in 0..8i64 {
        cache.insert(i, vec![i as u8; 2 * MIB]);
    }
    assert!(cache.is_empty(), "overlong values must not be retained");
    assert_eq!(cache.total_bytes(), 0, "refused values add no bytes");
    assert!(cache.get(&0).is_none(), "refused key must miss");

    // Ordinary retention still works, with exact byte accounting.
    cache.insert(1, vec![0xAA; 1024]);
    cache.insert(2, vec![0xBB; 2048]);
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.total_bytes(), 3072);
    assert_eq!(cache.get(&1).expect("hit").len(), 1024);
    // Re-inserting a key replaces without double-counting.
    cache.insert(1, vec![0xCC; 512]);
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.total_bytes(), 2560);

    // Aggregate bounded: 1 MiB values fill the 64 MiB budget, then the
    // cache clears and rebuilds — total never exceeds 64 MiB.
    let mut cache = FullPathCache::new();
    for i in 0..100i64 {
        cache.insert(1000 + i, vec![0xAA; MIB]);
        assert!(
            cache.total_bytes() <= 64 * MIB,
            "aggregate exceeds 64 MiB after insert {i}: {}",
            cache.total_bytes()
        );
        assert!(cache.len() <= 4096, "entry count exceeds 4096");
    }
    // 100 x 1 MiB through a 64 MiB cache forces at least one clear.
    assert!(
        cache.len() < 100,
        "expected clear-and-rebuild, kept {}",
        cache.len()
    );

    // Entry-count bound still holds with tiny values.
    let mut cache = FullPathCache::new();
    for i in 0..5000i64 {
        cache.insert(i, vec![b'x'; 8]);
        assert!(cache.len() <= 4096, "entry count exceeds 4096");
    }
}

/// RSP-004: staging/snapshot creation is dir-FD-relative (`openat`
/// `O_CREAT|O_EXCL|O_NOFOLLOW`): a symlinked snapshot dir is refused and
/// a symlinked snapshot leaf can neither be created through nor
/// overwritten — nothing escapes to the link target.
#[cfg(unix)]
#[test]
fn rsp004_snapshot_fd_relative_no_escape() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let store = {
        let db = state.join("payload").join("catalog.db");
        runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
    };
    let snapshots = state.join("payload").join("report_snapshots");
    repo_scan::privacy::private_dir_0700(&snapshots).expect("snapshots");
    let outside = dir.path().join("outside");
    repo_scan::privacy::private_dir_0700(&outside).expect("outside");

    // Leaf symlink at the snapshot path: retention fails, target untouched.
    let staged = dir.path().join("staged.bin");
    repo_scan::privacy::private_write_0600(&staged, b"hello").expect("staged");
    let bound = BoundStaged::open(&staged).expect("bound");
    let evil = outside.join("evil.json");
    std::os::unix::fs::symlink(&evil, snapshots.join("rsp004-leaf.json")).expect("symlink");
    let err = runtime()
        .block_on(async {
            repo_scan::report::publish::retain_bound(
                &store,
                &bound,
                &snapshots,
                "rsp004-leaf",
                1,
                1,
                1_759_154_400_000,
            )
            .await
        })
        .expect_err("symlinked leaf refused");
    assert!(
        err.to_string().contains("symlink")
            || err.to_string().contains("non-regular")
            || err.to_string().contains("refusing"),
        "{err}"
    );
    assert!(!evil.exists(), "nothing written through the symlink");

    // Symlinked snapshot dir: refused before any create.
    let link_dir = dir.path().join("snap-link");
    std::os::unix::fs::symlink(&outside, &link_dir).expect("symlink");
    let err = runtime()
        .block_on(async {
            repo_scan::report::publish::retain_bound(
                &store,
                &bound,
                &link_dir,
                "rsp004-dir",
                1,
                1,
                1_759_154_400_000,
            )
            .await
        })
        .expect_err("symlinked dir refused");
    assert!(
        err.to_string().contains("symlink") || err.to_string().contains("refusing"),
        "{err}"
    );
    assert!(
        outside.read_dir().expect("ls").next().is_none(),
        "nothing escaped into the link target"
    );
}

/// RSP-005: a FIFO staged/snapshot path is refused as non-regular without
/// hanging: `O_NONBLOCK` open + `fstat` + refuse, then `O_NONBLOCK`
/// cleared for regular files. The timeout join proves no hang (a
/// blocking open would trip the 5s deadline instead of returning).
#[cfg(unix)]
#[test]
fn rsp005_fifo_staged_refused_without_hang() {
    use std::os::unix::ffi::OsStrExt;
    use std::time::Duration;
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("staged.fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("cstr");
    // SAFETY: `mkfifo` on a tempdir path with a valid mode.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = BoundStaged::open(&fifo).map(|_| ());
        let message = match result {
            Ok(()) => "unexpected-ok".to_string(),
            Err(e) => e.to_string(),
        };
        let _ = tx.send(message);
    });
    let message = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("open returned within 5s (no FIFO hang)");
    assert!(
        message.contains("non-regular"),
        "FIFO refused as non-regular: {message}"
    );
}

/// RSP-008: `coverage.tasks_pending` and the filesystem derivation use the
/// in-transaction pending/leased count for this generation, never the
/// caller `tasks_pending` (lying callers in either direction are
/// corrected; other generations do not leak in).
#[test]
fn rsp008_tasks_pending_counted_in_txn() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_minimal(&store, now, b"https://github.com/owner/repo.git", "[]");
    let epoch = store.epoch();
    runtime().block_on(async {
        for id in ["rsp008-p1", "rsp008-p2"] {
            let key = format!("i:{id}");
            store
                .enqueue_task(
                    &NewTask {
                        id,
                        kind: "e",
                        generation: 1,
                        dir_id: None,
                        scope_key: "d:00",
                        expected_rev: 0,
                        idempotency_key: &key,
                    },
                    now,
                )
                .await
                .expect("enqueue");
        }
        // One pending, one leased: both count.
        let claimed = store
            .claim_tasks_in_generation(1, epoch, 1, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        // Another generation's work must not leak into generation 1.
        store
            .enqueue_task(
                &NewTask {
                    id: "rsp008-other",
                    kind: "e",
                    generation: 2,
                    dir_id: None,
                    scope_key: "d:00",
                    expected_rev: 0,
                    idempotency_key: "i:rsp008-other",
                },
                now,
            )
            .await
            .expect("enqueue other");
    });
    // Lying caller says no work: the DB count (1 pending + 1 leased) wins.
    let mut inputs = test_inputs("rsp008-txn-a");
    inputs.generation = 1;
    inputs.tasks_pending = 0;
    let report = stream_to_report(&store, &inputs);
    assert_eq!(report.coverage.tasks_pending, 2);
    assert_eq!(report.coverage.filesystem, "incomplete");
    // Lying caller invents work on an idle generation: corrected to zero.
    // Generation 9 has no tasks at all.
    let mut inputs = test_inputs("rsp008-txn-b");
    inputs.generation = 9;
    inputs.tasks_pending = 99;
    let report = stream_to_report(&store, &inputs);
    assert_eq!(report.coverage.tasks_pending, 0);
    assert_eq!(report.coverage.filesystem, "complete");
}

/// RSP-004 remainder (binary staging): `emit_file_report` stages through
/// the same FD-relative shape as the lib pipeline — the report ID is
/// validated before it is interpolated into the leaf, the staging dir is
/// held as an `O_NOFOLLOW|O_DIRECTORY` FD, and the file is created
/// `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` with an explicit `0600` asserted
/// after creation. The binary entry point is crate-private, so this pins
/// the shared shape through the public pipeline: malicious IDs are
/// refused with no residue, a symlinked staging dir is refused with no
/// escape into its target, and a successful emission leaves a `0600`
/// snapshot, `0700` dirs, and no staging residue.
#[cfg(unix)]
#[test]
fn rsp004_binary_staging_shape_fd_relative() {
    use std::os::unix::fs::PermissionsExt;
    let mode =
        |p: &std::path::Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let store = {
        let db = state.join("payload").join("catalog.db");
        runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
    };
    seed_minimal(
        &store,
        1_759_154_400_000,
        b"https://github.com/owner/repo.git",
        "[]",
    );
    seed_complete_status(&store, 1_759_154_400_000);
    let staging = state.join("payload").join("report_staging");
    let snapshots = state.join("payload").join("report_snapshots");

    // 1. Malicious report IDs are refused before any staging filename is
    // built (the RSP-006 shape the binary mirrors): no escape, no residue,
    // no catalog row.
    let bad_ids = [
        "../escape".to_string(),
        "a/b".to_string(),
        "..".to_string(),
        ".".to_string(),
        String::new(),
        "has space".to_string(),
        "x\0y".to_string(),
        "q".repeat(129),
    ];
    for bad_id in &bad_ids {
        let inputs = test_inputs(bad_id);
        let mut terminal: Vec<u8> = Vec::new();
        let err = runtime()
            .block_on(async {
                ReportPipeline::emit_to_terminal(
                    &store,
                    &inputs,
                    &staging,
                    &snapshots,
                    1_759_154_400_000,
                    &mut terminal,
                )
                .await
            })
            .expect_err("malicious report ID refused");
        assert!(
            err.to_string().contains("safe snapshot name")
                || err.to_string().contains("must be nonempty"),
            "{bad_id:?}: {err}"
        );
        let row =
            runtime().block_on(async { store.get_report_snapshot(bad_id).await.expect("lookup") });
        assert!(row.is_none(), "no snapshot row for {bad_id:?}");
    }
    assert!(
        !dir.path().join("escape").exists(),
        "no file escaped the staging directory"
    );
    if staging.exists() {
        let strays: Vec<_> = staging.read_dir().expect("ls").flatten().collect();
        assert!(strays.is_empty(), "no staging residue: {strays:?}");
    }

    // 2. FD-relative staging: a symlinked staging dir is refused without
    // being followed (no check-then-use by path); the link target stays
    // empty.
    let outside = dir.path().join("outside");
    repo_scan::privacy::private_dir_0700(&outside).expect("outside");
    let link_staging = dir.path().join("staging-link");
    std::os::unix::fs::symlink(&outside, &link_staging).expect("symlink");
    let inputs = test_inputs("rsp004-binstage");
    let mut terminal: Vec<u8> = Vec::new();
    let err = runtime()
        .block_on(async {
            ReportPipeline::emit_to_terminal(
                &store,
                &inputs,
                &link_staging,
                &snapshots,
                1_759_154_400_000,
                &mut terminal,
            )
            .await
        })
        .expect_err("symlinked staging dir refused");
    assert!(
        err.to_string().contains("symlink") || err.to_string().contains("refusing"),
        "{err}"
    );
    assert!(
        outside.read_dir().expect("ls").next().is_none(),
        "nothing escaped into the link target"
    );

    // 3. Mode assert: a successful emission retains a `0600` snapshot in
    // `0700` dirs and leaves no staging residue behind.
    let inputs = test_inputs("rsp004-binstage-ok");
    let mut terminal: Vec<u8> = Vec::new();
    runtime()
        .block_on(async {
            ReportPipeline::emit_to_terminal(
                &store,
                &inputs,
                &staging,
                &snapshots,
                1_759_154_400_000,
                &mut terminal,
            )
            .await
        })
        .expect("emit");
    assert_eq!(mode(&snapshots.join("rsp004-binstage-ok.json")), 0o600);
    assert_eq!(mode(&snapshots), 0o700);
    assert_eq!(mode(&staging), 0o700);
    let strays: Vec<_> = staging.read_dir().expect("ls").flatten().collect();
    assert!(strays.is_empty(), "no staging residue: {strays:?}");
}

/// PUB-01A: replacement inside an untrusted parent (world-writable
/// without the sticky bit) is refused unless explicitly overridden —
/// a hostile sibling writer could swap the destination inside the
/// residual single-`renameat` window. Fresh publishes stay allowed
/// (the atomic `install_new` path needs no trust), and trusted parents
/// need no override.
#[cfg(unix)]
#[test]
fn pub01a_untrusted_parent_replacement_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    repo_scan::privacy::private_dir_0700(&state.join("payload")).expect("payload");
    let shared = dir.path().join("shared");
    repo_scan::privacy::private_dir_0700(&shared).expect("shared");
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).expect("chmod 777");

    let staged = dir.path().join("staged-a.json");
    let bytes_a = prior_bytes("pub01a-a");
    repo_scan::privacy::private_write_0600(&staged, &bytes_a).expect("staged");
    let dest = shared.join("report.json");

    // Fresh publish into the untrusted parent: allowed.
    publish_staged(&staged, &dest, &state).expect("fresh publish allowed on untrusted parent");
    assert_eq!(std::fs::read(&dest).expect("read"), bytes_a);

    // Replacement: refused by pre-flight and by publish; bytes untouched.
    let staged_b = dir.path().join("staged-b.json");
    let bytes_b = prior_bytes("pub01a-b");
    repo_scan::privacy::private_write_0600(&staged_b, &bytes_b).expect("staged b");
    let err = check_destination(&dest, &state).expect_err("pre-flight refuses");
    assert!(err.to_string().contains("untrusted parent"), "{err}");
    let err = publish_staged(&staged_b, &dest, &state).expect_err("publish refuses");
    assert!(err.to_string().contains("untrusted parent"), "{err}");
    assert_eq!(
        std::fs::read(&dest).expect("read"),
        bytes_a,
        "refused replacement touches nothing"
    );

    // Explicit override: replacement proceeds.
    publish_staged_with_options(
        &staged_b,
        &dest,
        &state,
        PublishOptions {
            allow_untrusted_parent_replacement: true,
        },
    )
    .expect("override publishes");
    assert_eq!(std::fs::read(&dest).expect("read"), bytes_b);

    // Trusted-parent control (the 0700 tempdir itself): replacement
    // without override still works.
    let trusted = dir.path().join("report2.json");
    publish_staged(&staged, &trusted, &state).expect("fresh");
    publish_staged(&staged_b, &trusted, &state).expect("trusted replacement needs no override");
    assert_eq!(std::fs::read(&trusted).expect("read"), bytes_b);
}

/// R3 (RESOURCE-RECHECK item 3): staged-report verification cannot multiply
/// memory past the RSS target. A low-memory probe counts records, the
/// aggregate bytes-plus-typed budget is enforced before the typed build,
/// exhaustion refuses with incomplete-worded resource wording, and the
/// owned path releases the staging bytes as a single moved copy.
#[test]
fn r3_staged_aggregate_budget_and_byte_release() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_minimal(&store, now, b"https://github.com/owner/repo.git", "[]");
    seed_complete_status(&store, now);
    let inputs = test_inputs("r3-budget-1");
    let (bytes, _) = runtime()
        .block_on(async { stream_report_from_store(&store, &inputs, Vec::new()).await })
        .expect("stream");
    let staged = dir.path().join("staged.json");
    repo_scan::privacy::private_write_0600(&staged, &bytes).expect("write");

    // Generous budget: verifies and validates.
    let report = verify_staged_report_capped(&staged, 256 * 1024 * 1024).expect("verifies");
    assert_eq!(report.report_id, "r3-budget-1");

    // Exhausted budget: refused before the typed build, incomplete-worded.
    let err = verify_staged_report_capped(&staged, 1024).expect_err("budget refused");
    assert!(err.to_string().contains("incomplete"), "{err}");
    assert!(err.to_string().contains("rss_target_bytes"), "{err}");

    // Budget unit shape: byte-driven and count-driven exhaustion each
    // refuse, while a fitting footprint passes.
    check_staged_memory_budget(200 * 1024 * 1024, 0, 256 * 1024 * 1024)
        .expect_err("byte-driven exhaustion refuses");
    check_staged_memory_budget(1024, 1_048_576, 256 * 1024 * 1024)
        .expect_err("count-driven exhaustion refuses");
    check_staged_memory_budget(1024 * 1024, 1000, 256 * 1024 * 1024)
        .expect("fitting budget passes");

    // Explicit release: the bound bytes move out as the single copy.
    let expected = BoundStaged::open(&staged)
        .expect("open")
        .sha256()
        .to_string();
    let owned = BoundStaged::open(&staged).expect("open").into_bytes();
    assert_eq!(owned.len(), bytes.len());
    assert_eq!(sha256_hex(&owned), expected);
}
