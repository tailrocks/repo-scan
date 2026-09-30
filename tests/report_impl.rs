//! Report acceptance (REPORT-01, REPORT-02): schema-structure match,
//! ID resolution, count agreement, cross-field status rules, lossless
//! encoding, streaming equivalence, inside-tree artifacts, and atomic
//! no-clobber publication.

use repo_scan::model::StatusMode;
use repo_scan::report::builder::{
    artifact_for_report, stream_report_from_store, verify_staged_report, AliasInput, ArtifactInput,
    CandidateInput, ReportInputs, ReportPipeline, RootInput, StorageLinkInput,
};
use repo_scan::report::encode::{base64_decode, base64_encode, encode_bytes, ms_to_rfc3339};
use repo_scan::report::model::{Report, Status};
use repo_scan::report::publish::{check_destination, publish_staged, DestinationKind};
use repo_scan::report::stream::write_report_value;
use repo_scan::report::validate::{validate_report, validate_status};
use repo_scan::store::{
    NewCheckout, NewGitInstance, NewRef, NewRemote, NewStatus, NewVolume, Store, TursoStore,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn example_report() -> Report {
    let bytes = include_bytes!("data/example-report.json");
    serde_json::from_slice(bytes).expect("example parses")
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

fn seed_catalog(store: &TursoStore, now: i64) -> (i64, i64) {
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
        let child = store
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
        store
            .record_error(
                "err-1",
                &format!("dir:{root}"),
                "permission-denied",
                "EACCES listing fixture dir",
                None,
                now,
            )
            .await
            .expect("error");
        (root, child)
    })
}

fn open_store(dir: &tempfile::TempDir) -> TursoStore {
    let db = dir.path().join("payload").join("catalog.db");
    runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
}

#[test]
fn example_report_matches_schema_structure() {
    let report = example_report();
    validate_report(&report).expect("example validates");

    // Every top-level record from spec §16 is present exactly once.
    let value = serde_json::to_value(&report).expect("to value");
    let top: HashSet<String> = value.as_object().expect("object").keys().cloned().collect();
    let expected: HashSet<String> = [
        "schema_version",
        "report_id",
        "created_at",
        "tool",
        "scan",
        "coverage",
        "resources",
        "volumes",
        "paths",
        "roots",
        "repositories",
        "checkouts",
        "branches",
        "remotes",
        "storage_links",
        "aliases",
        "candidates",
        "errors",
        "generated_artifacts",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(top, expected);

    // Required-fields-always-present: spot-check nested required keys,
    // including explicit nulls (never omitted).
    let scan = &value["scan"];
    for key in [
        "id",
        "generation",
        "epoch",
        "catalog_revision",
        "target_url",
        "canonical_url",
        "matching_policy",
        "scope",
        "state",
        "started_at",
        "finished_at",
        "superseded_by",
        "cached",
        "status_mode",
    ] {
        assert!(scan.get(key).is_some(), "scan.{key} present");
    }
    assert!(value["tool"].get("source_commit").is_some());
    assert!(value["resources"].get("peak_rss_bytes").is_some());
    let branch = &value["branches"][0];
    for key in [
        "id",
        "repository_id",
        "checkout_scope_id",
        "kind",
        "name",
        "oid",
        "symbolic_target",
        "upstream",
        "state",
        "observed_at",
        "error_ids",
    ] {
        assert!(branch.get(key).is_some(), "branch.{key} present");
    }
    let remote = &value["remotes"][0];
    for key in [
        "id",
        "repository_id",
        "checkout_scope_id",
        "name",
        "role",
        "url",
        "canonical_url",
        "observed_at",
    ] {
        assert!(remote.get(key).is_some(), "remote.{key} present");
    }
}

#[test]
fn dangling_reference_fails_with_location() {
    let mut report = example_report();
    report.repositories[0].git_path_id = "path-missing".to_string();
    let err = validate_report(&report).expect_err("must fail");
    let message = err.to_string();
    assert!(message.contains("path-missing"), "names the id: {message}");
    assert!(
        message.contains("git_path_id"),
        "names the field: {message}"
    );

    let mut report = example_report();
    let dup = report.volumes[0].clone();
    report.volumes.push(dup);
    let err = validate_report(&report).expect_err("dup must fail");
    assert!(err.to_string().contains("duplicate"), "dup: {err}");
}

#[test]
fn count_agreement_is_checked() {
    let mut report = example_report();
    report.coverage.gaps = 5;
    let err = validate_report(&report).expect_err("gaps must agree");
    assert!(err.to_string().contains("coverage.gaps"), "{err}");
}

#[test]
fn status_cross_field_rules() {
    let mut problems = Vec::new();
    // Metadata with counts is invalid.
    validate_status(
        &Status {
            state: "complete".to_string(),
            mode: "metadata".to_string(),
            started_at: None,
            finished_at: None,
            staged: Some(0),
            unstaged: None,
            untracked: None,
            untracked_units: "not_requested".to_string(),
            submodules: "not_requested".to_string(),
            unknown_fields: Vec::new(),
            error_ids: Vec::new(),
        },
        "probe",
        &mut problems,
    );
    assert!(
        problems.iter().any(|p| p.contains("null counts")),
        "{problems:?}"
    );

    // Summary with file units is invalid.
    problems.clear();
    validate_status(
        &Status {
            state: "complete".to_string(),
            mode: "summary".to_string(),
            started_at: None,
            finished_at: None,
            staged: None,
            unstaged: None,
            untracked: None,
            untracked_units: "files".to_string(),
            submodules: "unknown".to_string(),
            unknown_fields: Vec::new(),
            error_ids: Vec::new(),
        },
        "probe",
        &mut problems,
    );
    assert!(
        problems.iter().any(|p| p.contains("collapsed_entries")),
        "{problems:?}"
    );

    // Unknown counts stay null with known units: valid.
    problems.clear();
    validate_status(
        &Status {
            state: "pending".to_string(),
            mode: "full".to_string(),
            started_at: None,
            finished_at: None,
            staged: None,
            unstaged: None,
            untracked: None,
            untracked_units: "files".to_string(),
            submodules: "unknown".to_string(),
            unknown_fields: Vec::new(),
            error_ids: Vec::new(),
        },
        "probe",
        &mut problems,
    );
    assert!(problems.is_empty(), "{problems:?}");
}

#[test]
fn encoding_round_trip_and_display_escaping() {
    // Valid UTF-8 passes through exactly.
    let (encoding, value, display) = encode_bytes("/repo/café".as_bytes());
    assert_eq!(encoding, "utf8");
    assert_eq!(value, "/repo/café");
    assert_eq!(display, "/repo/café");

    // Invalid UTF-8 becomes standard Base64 of the original bytes.
    let raw = b"/repo/\xff\xfe";
    let (encoding, value, display) = encode_bytes(raw);
    assert_eq!(encoding, "base64");
    assert_eq!(base64_decode(&value).expect("decodes"), raw);
    assert_eq!(value, base64_encode(raw));
    assert!(!display.chars().any(|c| c.is_control()));

    // Control characters are escaped in display, never raw.
    let (_, _, display) = encode_bytes(b"a\nb\x07c");
    assert_eq!(display, "a\\nb\\u{7}c");

    assert_eq!(ms_to_rfc3339(0), "1970-01-01T00:00:00.000Z");
    // Unix billennium: 1_000_000_000 seconds is 2001-09-09T01:46:40Z.
    assert_eq!(ms_to_rfc3339(1_000_000_000_000), "2001-09-09T01:46:40.000Z");
}

#[test]
fn streaming_matches_value_serialization() {
    let report = example_report();
    let streamed = write_report_value(Vec::new(), &report).expect("stream");
    let direct = serde_json::to_vec(&report).expect("direct");
    let streamed_value: serde_json::Value = serde_json::from_slice(&streamed).expect("parse");
    let direct_value: serde_json::Value = serde_json::from_slice(&direct).expect("parse");
    assert_eq!(streamed_value, direct_value);
}

#[test]
fn stream_from_catalog_resolves_and_agrees() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    let (root_id, _child) = seed_catalog(&store, now);

    let mut inputs = test_inputs("report-stream-1");
    inputs.roots.push(RootInput {
        id: "root-1".to_string(),
        dir_id: Some(root_id),
        path_bytes: None,
        volume_id: Some("vol-1".to_string()),
        state: "complete".to_string(),
        observed_at_ms: Some(now),
        event_history_uuid: None,
        ingested_cursor: None,
        reconciled_cursor: None,
        error_ids: Vec::new(),
    });

    let (bytes, stats) = runtime()
        .block_on(async { stream_report_from_store(&store, &inputs, Vec::new()).await })
        .expect("stream");
    assert_eq!(stats.volumes, 1);
    assert_eq!(stats.paths, 2 + 2); // Two directories + /repo and /repo/.git synthetics.
    assert_eq!(stats.repositories, 1);
    assert_eq!(stats.checkouts, 1);
    assert_eq!(stats.branches, 1);
    assert_eq!(stats.remotes, 1);
    assert_eq!(stats.errors, 1);

    let staged = dir.path().join("staged.json");
    std::fs::write(&staged, &bytes).expect("write");
    let report = verify_staged_report(&staged).expect("validates");
    assert_eq!(report.coverage.gaps, 1);
    assert_eq!(report.coverage.filesystem, "incomplete"); // Open gap.
    assert_eq!(report.coverage.identity, "complete_under_policy");
    assert_eq!(report.coverage.status, "complete");
    assert_eq!(report.checkouts[0].status.staged, Some(1));
    assert_eq!(report.errors[0].path_id, Some(format!("path-{root_id}")));
    // Reconstructed full path from parent/component links.
    let child_path = report
        .paths
        .iter()
        .find(|p| p.object_id.as_deref() == Some("obj-repo"))
        .expect("child path");
    assert_eq!(child_path.value, "/repo");
    assert_eq!(child_path.encoding, "utf8");
}

#[test]
fn terminal_render_goes_to_caller_writer() {
    let report = example_report();
    let mut out: Vec<u8> = Vec::new();
    repo_scan::report::render::render_terminal(&report, &mut out).expect("render");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("report-example-1"), "{text}");
    assert!(text.contains("https://github.com/OWNER/REPO"), "{text}");
    assert!(text.contains("repositories: 1"), "{text}");
    assert!(!text.chars().any(|c| c.is_control() && c != '\n'), "{text}");
}

#[test]
fn no_clobber_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(state_dir.join("payload")).expect("payload");
    let staged = dir.path().join("staged.json");
    std::fs::write(&staged, include_bytes!("data/example-report.json")).expect("staged");

    // Missing destination is fine.
    let fresh = dir.path().join("fresh.json");
    assert_eq!(
        check_destination(&fresh, &state_dir).expect("fresh ok"),
        DestinationKind::Missing
    );

    // Unrelated existing file is refused.
    let unrelated = dir.path().join("notes.txt");
    std::fs::write(&unrelated, "user data").expect("write");
    let err = check_destination(&unrelated, &state_dir).expect_err("no-clobber");
    assert!(err.to_string().contains("no-clobber"), "{err}");
    let err = publish_staged(&staged, &unrelated, &state_dir).expect_err("publish refused");
    assert!(err.to_string().contains("no-clobber"), "{err}");
    assert_eq!(std::fs::read(&unrelated).expect("read"), b"user data");

    // Verified prior report may be replaced.
    let prior = dir.path().join("prior.json");
    std::fs::write(&prior, include_bytes!("data/example-report.json")).expect("prior");
    assert_eq!(
        check_destination(&prior, &state_dir).expect("prior ok"),
        DestinationKind::VerifiedPriorReport
    );
    let receipt = publish_staged(&staged, &prior, &state_dir).expect("replace");
    assert!(receipt.bytes > 0);
    assert!(!receipt.checksum.is_empty());
    assert!(dir.path().read_dir().expect("ls").all(|entry| {
        !entry
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")
    }));

    // Git-administrative destination is refused.
    let git_dir = dir.path().join("repo").join(".git");
    std::fs::create_dir_all(&git_dir).expect("git");
    let git_dest = git_dir.join("report.json");
    let err = check_destination(&git_dest, &state_dir).expect_err("git refused");
    assert!(err.to_string().contains("Git administrative"), "{err}");

    // Active payload destination is refused.
    let payload_dest = state_dir.join("payload").join("evil.json");
    let err = check_destination(&payload_dest, &state_dir).expect_err("payload refused");
    assert!(err.to_string().contains("persistence payload"), "{err}");

    // Relative destination is refused.
    let err = check_destination(Path::new("relative.json"), &state_dir).expect_err("rel");
    assert!(err.to_string().contains("absolute"), "{err}");
}

#[cfg(unix)]
#[test]
fn symlink_destination_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(state_dir.join("payload")).expect("payload");
    let target = dir.path().join("target.json");
    std::fs::write(&target, "{}").expect("write");
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let staged = dir.path().join("staged.json");
    std::fs::write(&staged, include_bytes!("data/example-report.json")).expect("staged");
    let err = check_destination(&link, &state_dir).expect_err("symlink refused");
    assert!(err.to_string().contains("symlink"), "{err}");
    let err = publish_staged(&staged, &link, &state_dir).expect_err("publish refused");
    assert!(err.to_string().contains("symlink"), "{err}");
}

#[test]
fn emit_to_file_with_inside_tree_artifact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    let store = {
        let db = state_dir.join("payload").join("catalog.db");
        runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
    };
    let now = 1_759_154_400_000;
    seed_catalog(&store, now);

    // The report lands inside the scanned tree: status was observed before
    // publication and the artifact is listed honestly.
    let dest: PathBuf = dir.path().join("repo").join("report.json");
    std::fs::create_dir_all(dest.parent().expect("parent")).expect("mkdir");
    let mut inputs = test_inputs("report-inside-tree-1");
    inputs.generated_artifacts.push(ArtifactInput {
        path_bytes: dest.as_os_str().as_encoded_bytes().to_vec(),
        kind: "report".to_string(),
        created_after_status: true,
    });
    // Same helper the owner lane uses for the destination artifact.
    let via_helper = artifact_for_report(&dest);
    assert!(via_helper.created_after_status);
    assert_eq!(via_helper.kind, "report");

    let staging = state_dir.join("payload").join("report_staging");
    let snapshots = state_dir.join("payload").join("report_snapshots");
    let publication = runtime()
        .block_on(async {
            ReportPipeline::emit_to_file(
                &store, &inputs, &dest, &state_dir, &staging, &snapshots, now,
            )
            .await
        })
        .expect("emit");
    assert!(publication.published);
    assert_eq!(publication.report_id, "report-inside-tree-1");

    let report = verify_staged_report(&dest).expect("dest validates");
    assert_eq!(report.generated_artifacts.len(), 1);
    assert!(report.generated_artifacts[0].created_after_status);
    assert_eq!(report.generated_artifacts[0].kind, "report");
    // The artifact path resolves and round-trips the destination bytes.
    let artifact_path = report
        .paths
        .iter()
        .find(|p| p.id == report.generated_artifacts[0].path_id)
        .expect("artifact path resolves");
    assert_eq!(artifact_path.encoding, "utf8");
    assert_eq!(artifact_path.value, dest.to_str().expect("utf8 tempdir"));
}

#[test]
fn snapshot_immutability_and_retry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    let store = {
        let db = state_dir.join("payload").join("catalog.db");
        runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
    };
    let now = 1_759_154_400_000;
    seed_catalog(&store, now);
    let inputs = test_inputs("report-immutable-1");
    let staging = state_dir.join("payload").join("report_staging");
    let snapshots = state_dir.join("payload").join("report_snapshots");

    // First publication succeeds.
    let dest = dir.path().join("report.json");
    let first = runtime()
        .block_on(async {
            ReportPipeline::emit_to_file(
                &store, &inputs, &dest, &state_dir, &staging, &snapshots, now,
            )
            .await
        })
        .expect("first emit");
    assert!(first.published);

    // The retained snapshot is immutable: retrying the same bytes works,
    // while different bytes under the same ID are refused.
    let snapshot_path = snapshots.join("report-immutable-1.json");
    assert!(snapshot_path.is_file());
    let dest2 = dir.path().join("report2.json");
    let retry = runtime()
        .block_on(async {
            ReportPipeline::retry_publication(
                &store,
                &snapshot_path,
                "report-immutable-1",
                &dest2,
                &state_dir,
            )
            .await
        })
        .expect("retry works");
    assert!(retry.published);
    assert_eq!(retry.checksum, first.checksum);

    let other_staged = dir.path().join("other.json");
    std::fs::write(&other_staged, include_bytes!("data/example-report.json")).expect("write");
    let err = runtime()
        .block_on(async {
            repo_scan::report::publish::retain_snapshot(
                &store,
                &other_staged,
                &snapshots,
                "report-immutable-1",
                7,
                1,
                now,
            )
            .await
        })
        .expect_err("different bytes refused");
    assert!(err.to_string().contains("immutable"), "{err}");

    // Terminal emission retains the snapshot without publishing a file.
    let term_inputs = test_inputs("report-terminal-1");
    let mut terminal: Vec<u8> = Vec::new();
    let publication = runtime()
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
        .expect("terminal emit");
    assert!(!publication.published);
    assert!(snapshots.join("report-terminal-1.json").is_file());
    let text = String::from_utf8(terminal).expect("utf8");
    assert!(text.contains("report-terminal-1"), "{text}");
}

#[test]
fn caller_owned_sections_stream() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_catalog(&store, now);
    let mut inputs = test_inputs("report-caller-1");
    inputs.storage_links.push(StorageLinkInput {
        id: "link-1".to_string(),
        from_repository_id: "repo-1".to_string(),
        to_path_bytes: b"/shared/objects".to_vec(),
        kind: "shared_object_store".to_string(),
        evidence: vec!["same device and inode on pack files".to_string()],
    });
    inputs.aliases.push(AliasInput {
        path_bytes: b"/repo".to_vec(),
        target_path_bytes: b"/private/repo".to_vec(),
        kind: "mount_alias".to_string(),
        verified_at_ms: now,
    });
    inputs.candidates.push(CandidateInput {
        id: "cand-1".to_string(),
        path_bytes: b"/tmp/stray".to_vec(),
        repository_id: None,
        disposition: "unresolvable_identity".to_string(),
        reason: "identifying remotes removed".to_string(),
        retry_after_ms: None,
        error_ids: vec!["err-1".to_string()],
    });
    let (bytes, stats) = runtime()
        .block_on(async { stream_report_from_store(&store, &inputs, Vec::new()).await })
        .expect("stream");
    assert_eq!(stats.storage_links, 1);
    assert_eq!(stats.aliases, 1);
    assert_eq!(stats.candidates, 1);
    let staged = dir.path().join("staged.json");
    std::fs::write(&staged, &bytes).expect("write");
    let report = verify_staged_report(&staged).expect("validates");
    assert_eq!(report.coverage.unresolvable_candidates, 1);
    assert_eq!(report.coverage.identity, "unproven");

    // Dangling caller input fails loudly before any JSON is written.
    let mut bad = test_inputs("report-bad-1");
    bad.candidates.push(CandidateInput {
        id: "cand-9".to_string(),
        path_bytes: b"/tmp/stray".to_vec(),
        repository_id: Some("repo-missing".to_string()),
        disposition: "probe_pending".to_string(),
        reason: "test".to_string(),
        retry_after_ms: None,
        error_ids: Vec::new(),
    });
    let err = runtime()
        .block_on(async { stream_report_from_store(&store, &bad, Vec::new()).await })
        .expect_err("dangling repo refused");
    assert!(err.to_string().contains("repo-missing"), "{err}");
}

// ---------------------------------------------------------------------------
// REPORT-01: real JSON-Schema validation via the `jsonschema` crate
// ---------------------------------------------------------------------------

/// Compile the shipped Draft 2020-12 schema. Local `$ref`s only, so this
/// performs no network I/O.
fn schema_validator() -> jsonschema::Validator {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/schemas/report-v1.schema.json");
    let bytes = std::fs::read(path).expect("read shipped schema");
    let schema: serde_json::Value = serde_json::from_slice(&bytes).expect("schema parses");
    jsonschema::validator_for(&schema).expect("shipped schema compiles")
}

/// Assert `value` validates; render every violation on failure.
fn assert_json_schema_valid(validator: &jsonschema::Validator, value: &serde_json::Value) {
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "schema violations:\n{}",
        errors.join("\n")
    );
}

#[test]
fn shipped_example_validates_against_real_json_schema() {
    let validator = schema_validator();
    let bytes = include_bytes!("data/example-report.json");
    let report: serde_json::Value = serde_json::from_slice(bytes).expect("example parses");
    assert_json_schema_valid(&validator, &report);
}

#[test]
fn real_json_schema_rejects_broken_reports() {
    let validator = schema_validator();
    let bytes = include_bytes!("data/example-report.json");
    let mut report: serde_json::Value = serde_json::from_slice(bytes).expect("example parses");
    // Drop a required top-level record: the validator must notice.
    report.as_object_mut().expect("object").remove("scan");
    assert!(
        !validator.is_valid(&report),
        "report missing required `scan` must fail validation"
    );
    let errors: Vec<String> = validator
        .iter_errors(&report)
        .map(|e| e.to_string())
        .collect();
    assert!(!errors.is_empty(), "violations must be reported");
}
