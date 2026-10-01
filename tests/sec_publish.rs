//! SEC publish hardening: single-open `O_NOFOLLOW` binding, dir-FD
//! atomic no-clobber install, verify-then-retain terminal emission with
//! staging quarantine, SHA-256 + byte-count receipts, and capped reads.
//!
//! Fixture-scale only (tempdirs under `/tmp` via `tempfile`): no machine
//! scans.

use repo_scan::model::StatusMode;
use repo_scan::report::builder::{quarantine_staging, ReportInputs, ReportPipeline};
use repo_scan::report::publish::{
    checksum_hex, publish_staged, sha256_hex, BoundStaged, DestinationKind,
};
use repo_scan::store::{
    NewCheckout, NewGitInstance, NewRef, NewRemote, NewStatus, NewVolume, Store, TursoStore,
};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn no_tmp_leftovers(dir: &std::path::Path) -> bool {
    dir.read_dir()
        .expect("ls")
        .filter_map(|entry| entry.ok())
        .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp-"))
}

/// Item 9: receipts carry the SHA-256 digest and byte count of the exact
/// bytes copied, checked against the standard "abc" vector.
#[test]
fn publish_receipt_carries_sha256_and_byte_count() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    repo_scan::privacy::private_dir_0700(&state_dir.join("payload")).expect("payload");
    let staged = dir.path().join("staged.bin");
    repo_scan::privacy::private_write_0600(&staged, b"abc").expect("write");
    let dest = dir.path().join("out.bin");
    let receipt = publish_staged(&staged, &dest, &state_dir).expect("publish");
    assert_eq!(receipt.bytes, 3);
    assert_eq!(
        receipt.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(receipt.checksum, checksum_hex(b"abc"));
    assert_eq!(receipt.replaced, DestinationKind::Missing);
    assert_eq!(std::fs::read(&dest).expect("read"), b"abc");
    assert!(no_tmp_leftovers(dir.path()), "no sibling left behind");
}

/// PUBLISH-RACE: an existing unrelated file is refused, untouched, and no
/// sibling survives the refusal.
#[test]
fn publish_refuses_unrelated_file_and_leaves_no_sibling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    repo_scan::privacy::private_dir_0700(&state_dir.join("payload")).expect("payload");
    let staged = dir.path().join("staged.bin");
    repo_scan::privacy::private_write_0600(&staged, b"abc").expect("write");
    let unrelated = dir.path().join("notes.txt");
    repo_scan::privacy::private_write_0600(&unrelated, "user data".as_bytes()).expect("write");
    let err = publish_staged(&staged, &unrelated, &state_dir).expect_err("no-clobber");
    assert!(err.to_string().contains("no-clobber"), "{err}");
    assert_eq!(std::fs::read(&unrelated).expect("read"), b"user data");
    assert!(no_tmp_leftovers(dir.path()), "no sibling left behind");
}

/// RSF-SEC-REPORT-TOCTOU: a symlinked staging input is refused at open; a
/// verified prior report is still replaceable through the FD-verified path.
#[cfg(unix)]
#[test]
fn symlinked_staged_input_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    repo_scan::privacy::private_dir_0700(&state_dir.join("payload")).expect("payload");
    let target = dir.path().join("target.bin");
    repo_scan::privacy::private_write_0600(&target, b"abc").expect("write");
    let staged = dir.path().join("staged.bin");
    std::os::unix::fs::symlink(&target, &staged).expect("symlink");
    let err = BoundStaged::open(&staged).expect_err("symlink refused");
    assert!(err.to_string().contains("symlink"), "{err}");
    let dest = dir.path().join("out.bin");
    let err = publish_staged(&staged, &dest, &state_dir).expect_err("publish refused");
    assert!(err.to_string().contains("symlink"), "{err}");
    assert!(!dest.exists(), "destination untouched");
}

/// Item 9: staged reads are byte-capped.
#[test]
fn staged_reads_are_byte_capped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let staged = dir.path().join("staged.bin");
    repo_scan::privacy::private_write_0600(&staged, b"12345678").expect("write");
    let err = BoundStaged::open_capped(&staged, 4).expect_err("over cap refused");
    assert!(err.to_string().contains("cap"), "{err}");
    let bound = BoundStaged::open_capped(&staged, 8).expect("at cap ok");
    assert_eq!(bound.len(), 8);
    assert_eq!(bound.bytes(), b"12345678");
}

/// Item 8: failed staging is quarantined out of the way, never left in
/// place or silently dropped without a trace.
#[test]
fn failed_staging_is_quarantined() {
    let dir = tempfile::tempdir().expect("tempdir");
    let staging = dir.path().join("staging");
    repo_scan::privacy::private_dir_0700(&staging).expect("mkdir");
    let staged = staging.join(".staging-1.json");
    repo_scan::privacy::private_write_0600(&staged, "bogus".as_bytes()).expect("write");
    quarantine_staging(&staged);
    assert!(!staged.exists(), "failed staging moved away");
    assert!(
        staging.join("quarantine").join(".staging-1.json").is_file(),
        "failed staging preserved under quarantine/"
    );
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

/// Item 8: terminal emission verifies before retaining. Invalid staged
/// bytes are refused with nothing retained and the staging file
/// quarantined; a valid report still renders, and its catalog row matches
/// the retained file's SHA-256 (item 9 reconcile).
#[test]
fn terminal_emission_verifies_before_retain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    let store = {
        let db = state_dir.join("payload").join("catalog.db");
        runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
    };
    let now = 1_759_154_400_000;
    seed_catalog(&store, now);
    let staging = state_dir.join("payload").join("report_staging");
    let snapshots = state_dir.join("payload").join("report_snapshots");

    let mut invalid = test_inputs("report-term-bogus-1");
    invalid.coverage_status = Some("bogus".to_string());
    let mut terminal: Vec<u8> = Vec::new();
    let err = runtime()
        .block_on(async {
            ReportPipeline::emit_to_terminal(
                &store,
                &invalid,
                &staging,
                &snapshots,
                now,
                &mut terminal,
            )
            .await
        })
        .expect_err("invalid staged report must be refused");
    assert!(
        err.to_string().contains("refusing invalid staged report"),
        "refusal names the gate: {err}"
    );
    assert!(
        !snapshots.join("report-term-bogus-1.json").exists(),
        "refused bytes leave no snapshot file"
    );
    let retained = runtime().block_on(async {
        store
            .get_report_snapshot("report-term-bogus-1")
            .await
            .expect("lookup")
    });
    assert!(retained.is_none(), "refused bytes leave no snapshot row");
    let stray: Vec<_> = staging
        .read_dir()
        .expect("ls")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".staging-"))
        .collect();
    assert!(
        stray.is_empty(),
        "failed staging quarantined, not left: {stray:?}"
    );

    // Positive control through the same entry point.
    let valid = test_inputs("report-term-valid-1");
    let mut terminal: Vec<u8> = Vec::new();
    let publication = runtime()
        .block_on(async {
            ReportPipeline::emit_to_terminal(
                &store,
                &valid,
                &staging,
                &snapshots,
                now,
                &mut terminal,
            )
            .await
        })
        .expect("valid report renders");
    assert!(!publication.published);
    assert!(!terminal.is_empty(), "terminal summary rendered");
    let snapshot_bytes =
        std::fs::read(snapshots.join("report-term-valid-1.json")).expect("snapshot file");
    let row = runtime()
        .block_on(async {
            store
                .get_report_snapshot("report-term-valid-1")
                .await
                .expect("lookup")
        })
        .expect("snapshot row");
    assert_eq!(
        row.checksum,
        Some(sha256_hex(&snapshot_bytes).into_bytes()),
        "catalog row reconciles with retained file"
    );
}
