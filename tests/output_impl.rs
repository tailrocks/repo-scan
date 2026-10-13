//! Output-lane acceptance (contract C4/C6, Wave2b cases 15/16/17 code
//! portion): one state model across the human/JSON/JSONL lanes — the same
//! verified staged bytes are retained as the immutable snapshot and (for
//! the JSON lane) written to the machine consumer verbatim plus one
//! newline, with no prose, ANSI, or cursor codes.
//!
//! These tests drive the library pipeline (`ReportPipeline::emit_to_json`
//! / `stage_and_retain` / `publish_live`) plus the retention pruner. The
//! CLI wiring of the lanes (binary-level `--format` acceptance) is the
//! main.rs slice's; B11's binary-level output-matrix tests land with it.
//!
//! - `json_lane_bytes_equal_retained_snapshot`: stdout bytes == retained
//!   snapshot bytes + `\n`; both validate; the catalog row reads
//!   `retained`.
//! - `json_lane_broken_pipe_keeps_snapshot`: a closed consumer is a quiet
//!   stop (`Ok(false)`), never a scan failure; the snapshot stays
//!   retained.
//! - `jsonl_lane_retains_without_machine_bytes`: `stage_and_retain`
//!   verifies and retains without writing a destination.
//! - `live_publish_replaces_without_retaining`: the live `--report`
//!   destination is atomically replaced per tick and accumulates no
//!   snapshots (C4: atomic live ≠ retained snapshot ≠ published).
//! - `snapshot_pruning_*`: completed snapshots are retained bounded; the
//!   current report and any referenced snapshot survive; symlinks are
//!   never followed.

mod common;

use repo_scan::model::StatusMode;
use repo_scan::report::builder::{ReportInputs, ReportPipeline};
use repo_scan::report::output::{
    is_machine_pure, list_snapshot_entries, prune_snapshot_files, select_snapshot_victims,
    MAX_RETAINED_SNAPSHOTS,
};
use repo_scan::report::validate::validate_report;
use repo_scan::store::{
    NewCheckout, NewGitInstance, NewRef, NewRemote, NewStatus, NewVolume, Store, TursoStore,
};
use std::collections::HashSet;
use std::path::Path;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn open_store(dir: &tempfile::TempDir) -> TursoStore {
    let db = dir.path().join("payload").join("catalog.db");
    runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
}

fn test_inputs(report_id: &str) -> ReportInputs {
    ReportInputs {
        report_id: report_id.to_string(),
        created_at_ms: 1_759_154_400_000,
        scan_id: "scan-1".to_string(),
        generation: 1,
        epoch: 1,
        catalog_revision: 7,
        target_url: "https://github.com/OWNER/REPO".to_string(),
        canonical_url: Some("https://github.com/owner/repo".to_string()),
        targets: vec![],
        scope: "machine".to_string(),
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
                    evidence_json: "[]",
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

struct BrokenPipeWriter;

impl std::io::Write for BrokenPipeWriter {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn json_lane_bytes_equal_retained_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_catalog(&store, now);
    let staging = dir.path().join("report_staging");
    let snapshots = dir.path().join("report_snapshots");
    let inputs = test_inputs("report-json-lane-1");

    let mut out: Vec<u8> = Vec::new();
    let pipe_open = runtime()
        .block_on(ReportPipeline::emit_to_json(
            &store, &inputs, &staging, &snapshots, now, &mut out,
        ))
        .expect("json lane emits");
    assert!(pipe_open, "open consumer");

    let snapshot = snapshots.join("report-json-lane-1.json");
    let retained = std::fs::read(&snapshot).expect("retained snapshot");
    assert_eq!(out, {
        let mut expected = retained.clone();
        expected.push(b'\n');
        expected
    });
    assert!(
        is_machine_pure(&out),
        "machine lane: serialized data only, no prose/ANSI"
    );

    // The emitted bytes are the valid 1.5.0 report.
    let report: repo_scan::report::model::Report =
        serde_json::from_slice(&retained).expect("snapshot parses");
    validate_report(&report).expect("snapshot validates");
    assert_eq!(report.schema_version, "1.5.0");

    let row = runtime()
        .block_on(store.get_report_snapshot("report-json-lane-1"))
        .expect("snapshot row")
        .expect("snapshot row present");
    assert_eq!(row.publication_state, "retained");
    assert!(
        staging.read_dir().expect("staging dir").next().is_none(),
        "staging file is removed after retention"
    );
}

#[test]
fn json_lane_broken_pipe_keeps_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_catalog(&store, now);
    let staging = dir.path().join("report_staging");
    let snapshots = dir.path().join("report_snapshots");
    let inputs = test_inputs("report-json-pipe-1");

    let mut broken = BrokenPipeWriter;
    let pipe_open = runtime()
        .block_on(ReportPipeline::emit_to_json(
            &store,
            &inputs,
            &staging,
            &snapshots,
            now,
            &mut broken,
        ))
        .expect("broken pipe is a quiet stop, not a scan failure");
    assert!(!pipe_open, "consumer went away");
    assert!(
        snapshots.join("report-json-pipe-1.json").is_file(),
        "verified snapshot stays retained for replay"
    );
    let row = runtime()
        .block_on(store.get_report_snapshot("report-json-pipe-1"))
        .expect("snapshot row")
        .expect("snapshot row present");
    assert_eq!(row.publication_state, "retained");
}

#[test]
fn jsonl_lane_retains_without_machine_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_catalog(&store, now);
    let staging = dir.path().join("report_staging");
    let snapshots = dir.path().join("report_snapshots");
    let inputs = test_inputs("report-jsonl-lane-1");

    let snapshot_path = runtime()
        .block_on(ReportPipeline::stage_and_retain(
            &store, &inputs, &staging, &snapshots, now,
        ))
        .expect("stage and retain");
    assert_eq!(snapshot_path, snapshots.join("report-jsonl-lane-1.json"));
    let retained = std::fs::read(&snapshot_path).expect("retained snapshot");
    let report: repo_scan::report::model::Report =
        serde_json::from_slice(&retained).expect("snapshot parses");
    validate_report(&report).expect("snapshot validates");
    let row = runtime()
        .block_on(store.get_report_snapshot("report-jsonl-lane-1"))
        .expect("snapshot row")
        .expect("snapshot row present");
    assert_eq!(row.publication_state, "retained");
}

#[test]
fn live_publish_replaces_without_retaining() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_catalog(&store, now);
    let staging = dir.path().join("report_staging");
    let state_dir = dir.path().join("state");
    let dest = dir.path().join("live.json");

    // C4: the atomic live report is not the retained snapshot and not a
    // published destination: no snapshot file, no catalog row accumulates
    // per live tick.
    for tick in 0..2 {
        let inputs = test_inputs(&format!("live-tick-{tick}"));
        let receipt = runtime()
            .block_on(ReportPipeline::publish_live(
                &store, &inputs, &staging, &dest, &state_dir,
            ))
            .expect("live publish");
        let bytes = std::fs::read(&dest).expect("live destination");
        assert_eq!(
            repo_scan::report::publish::sha256_hex(&bytes),
            receipt.sha256,
            "destination bytes match the receipt digest"
        );
        let report: repo_scan::report::model::Report =
            serde_json::from_slice(&bytes).expect("live destination parses");
        validate_report(&report).expect("live destination validates");
        assert_eq!(report.report_id, format!("live-tick-{tick}"));
    }
    assert!(
        !dir.path().join("report_snapshots").exists(),
        "live ticks retain no snapshots"
    );
    assert!(
        staging.read_dir().expect("staging dir").next().is_none(),
        "staging file is removed after a live tick"
    );
}

#[test]
fn snapshot_pruning_keeps_referenced_pins_within_the_bound() {
    let dir = tempfile::tempdir().expect("tempdir");
    let snapshots = dir.path().join("snapshots");
    std::fs::create_dir(&snapshots).expect("snapshots dir");

    // MAX_RETAINED_SNAPSHOTS + 5 completed snapshots with ascending mtimes.
    let total = MAX_RETAINED_SNAPSHOTS + 5;
    for index in 0..total {
        let path = snapshots.join(format!("snapshot-{index:03}.json"));
        std::fs::write(&path, b"{}").expect("write snapshot");
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(index as u64);
        let file = std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("open");
        file.set_modified(mtime).expect("set mtime");
    }
    // Pins: the current report (newest) plus two older referenced ones
    // (a prior running recovery and a failed unpublished report).
    let referenced: HashSet<String> = ["snapshot-000", "snapshot-002"]
        .iter()
        .map(|id| id.to_string())
        .collect();
    let pruned = prune_snapshot_files(&snapshots, &referenced, MAX_RETAINED_SNAPSHOTS);
    // Oldest-first overflow is 5 (000..004), but the two referenced pins
    // are never pruned even inside the overflow window.
    assert_eq!(pruned.len(), 3, "referenced pins survive the overflow");
    assert_eq!(pruned, vec!["snapshot-001", "snapshot-003", "snapshot-004"]);
    for pinned in ["snapshot-000", "snapshot-002"] {
        assert!(
            snapshots.join(format!("{pinned}.json")).is_file(),
            "referenced snapshot {pinned} survives"
        );
    }
    let remaining = list_snapshot_entries(&snapshots);
    assert_eq!(remaining.len(), total - 3);
    // Non-json residue and unsafe stems are never listed or pruned.
    std::fs::write(snapshots.join("notes.txt"), b"x").expect("residue");
    std::fs::write(snapshots.join("..json"), b"x").expect("dot stem");
    let listed: Vec<String> = list_snapshot_entries(&snapshots)
        .iter()
        .map(|entry| entry.id.clone())
        .collect();
    assert!(!listed.iter().any(|id| id.is_empty() || id == "."));
    assert_eq!(listed.len(), total - 3);
}

#[test]
fn snapshot_victim_selection_is_oldest_first_and_pure() {
    let base = std::time::SystemTime::UNIX_EPOCH;
    let entries: Vec<repo_scan::report::output::SnapshotEntry> = (0..6)
        .map(|i| repo_scan::report::output::SnapshotEntry {
            id: format!("r{i}"),
            path: std::path::PathBuf::from(format!("/tmp/r{i}.json")),
            modified: Some(base + std::time::Duration::from_secs(i)),
        })
        .collect();
    let referenced: HashSet<String> = ["r0".to_string()].into_iter().collect();
    let victims = select_snapshot_victims(entries, &referenced, 4);
    let ids: Vec<&str> = victims.iter().map(|v| v.id.as_str()).collect();
    // Oldest-first overflow, minus referenced pins.
    assert_eq!(ids, vec!["r1"], "oldest unreferenced victim first");
}

#[cfg(unix)]
#[test]
fn live_publish_refuses_a_symlink_destination() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(&dir);
    let now = 1_759_154_400_000;
    seed_catalog(&store, now);
    let staging = dir.path().join("report_staging");
    let state_dir = dir.path().join("state");
    let precious = dir.path().join("precious.json");
    std::fs::write(&precious, b"precious user bytes").expect("precious");
    let link = dir.path().join("link.json");
    symlink(&precious, &link).expect("symlink");

    let inputs = test_inputs("live-symlink-1");
    runtime()
        .block_on(ReportPipeline::publish_live(
            &store, &inputs, &staging, &link, &state_dir,
        ))
        .expect_err("symlink destination is refused");
    assert_eq!(
        std::fs::read(&precious).expect("read precious"),
        b"precious user bytes",
        "symlink target is never overwritten"
    );
    let _ = Path::new(&precious);
}
