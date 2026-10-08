//! EXACT-2 defect 3: failed event-history completeness claims must
//! surface as explicit gaps + non-complete status everywhere (stderr,
//! catalog, report coverage/gaps, exit status) — never stderr-only.
//! Fixture-scale only (tempdirs, no machine scans).

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

use repo_scan::events::{
    plan_claim_error, volume_scope_key, EventBatch, EventCursorId, CLAIM_ERROR_CATEGORY,
};
use repo_scan::model::StatusMode;
use repo_scan::report::builder::{stream_report_from_store, ReportInputs};
use repo_scan::report::model::Report;
use repo_scan::store::{now_ms, Store, TursoStore};
use std::path::PathBuf;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn batch(volume: &str, high_water: u64, paths: &[PathBuf], history_done: bool) -> EventBatch {
    EventBatch {
        volume_key: volume.to_string(),
        high_water: EventCursorId(high_water),
        invalidations: paths.to_vec(),
        history_done,
        signals: Vec::new(),
    }
}

async fn open_generation(db: &std::path::Path) -> (TursoStore, u64) {
    let store = TursoStore::open(db).await.expect("open");
    let now = now_ms();
    let generation = store
        .create_generation("machine", "running", None, now)
        .await
        .expect("generation");
    (store, generation)
}

fn report_inputs(report_id: &str, generation: u64, scan_state: &str) -> ReportInputs {
    ReportInputs {
        report_id: report_id.to_string(),
        created_at_ms: 1_759_154_400_000,
        scan_id: "scan-claim-1".to_string(),
        generation,
        epoch: 1,
        catalog_revision: 0,
        target_url: "https://github.com/OWNER/REPO".to_string(),
        canonical_url: Some("https://github.com/owner/repo".to_string()),
        targets: vec![],
        scope: "roots".to_string(),
        scan_state: scan_state.to_string(),
        started_at_ms: 1_759_154_398_000,
        finished_at_ms: Some(1_759_154_400_000),
        superseded_by: None,
        cached: false,
        status_mode: StatusMode::Summary,
        directories_complete: 0,
        tasks_pending: 0,
        scope_boundaries: Vec::new(),
        profile: "conservative".to_string(),
        cpu_target_cores: 1.0,
        rss_target_bytes: 268_435_456,
        peak_rss_bytes: None,
        cpu_seconds: None,
        enumerated_entries: 0,
        db_transactions: 0,
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

async fn stream_to_report(store: &TursoStore, inputs: &ReportInputs) -> Report {
    let (bytes, _) = stream_report_from_store(store, inputs, Vec::new())
        .await
        .expect("stream");
    serde_json::from_slice(&bytes).expect("report parses")
}

/// The claim-gap planner is pure and stable: one id per volume, the
/// volume scope, the `event-history-incomplete` category, and detail
/// naming the volume and the claim refusal.
#[test]
fn exact2_claim_gap_action_shape() {
    let action = plan_claim_error("vol-a", "no history_done consumed");
    assert_eq!(action.volume_key, "vol-a");
    assert_eq!(action.scope_key, volume_scope_key("vol-a"));
    assert_eq!(action.gap_id, "gap:event-claim:vol-a");
    assert_eq!(CLAIM_ERROR_CATEGORY, "event-history-incomplete");
    assert!(action.detail.contains("vol-a"), "{}", action.detail);
    assert!(
        action.detail.contains("no history_done consumed"),
        "{}",
        action.detail
    );
}

/// Production reconcile without `history_done`: the claim refuses AND the
/// refusal persists as an explicit open gap that the report derives into
/// `coverage.gaps` + `coverage.filesystem = incomplete` (the pre-fix code
/// logged stderr and reported complete with no gaps).
#[test]
fn exact2_failed_claim_persists_gap_and_report_incomplete() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let sub = tmp.path().join("sub");
        repo_scan::privacy::private_dir_0700(&sub).unwrap();
        let (store, generation) = open_generation(&db).await;
        let batches = vec![
            batch("vol-a", 10, std::slice::from_ref(&sub), false),
            batch("vol-a", 20, std::slice::from_ref(&sub), false),
        ];
        let outcome = main_under_test::test_reconcile_scripted(
            &store,
            generation,
            "vol-a",
            "uuid-a",
            &[tmp.path().to_path_buf()],
            batches,
        )
        .await
        .expect("reconcile");
        assert_eq!(outcome.claims.len(), 1);
        assert!(!outcome.claims[0].complete);

        let gap = store
            .get_error("gap:event-claim:vol-a")
            .await
            .expect("get")
            .expect("claim gap row persisted");
        assert_eq!(gap.category, CLAIM_ERROR_CATEGORY);
        assert_eq!(gap.scope_key, volume_scope_key("vol-a"));
        assert!(gap.open);
        assert!(gap.detail.contains("history_done"), "{}", gap.detail);

        let report =
            stream_to_report(&store, &report_inputs("claim-a", generation, "incomplete")).await;
        assert!(report.coverage.gaps >= 1, "{}", report.coverage.gaps);
        assert_eq!(report.coverage.filesystem, "incomplete");
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.id == "gap:event-claim:vol-a"),
            "claim gap streams into report errors"
        );
    });
}

/// Positive control: with `history_done` consumed the claim holds, no gap
/// row is written, and the report stays complete.
#[test]
fn exact2_held_claim_writes_no_gap_and_report_complete() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let sub = tmp.path().join("sub");
        repo_scan::privacy::private_dir_0700(&sub).unwrap();
        let (store, generation) = open_generation(&db).await;
        let batches = vec![
            batch("vol-a", 10, std::slice::from_ref(&sub), false),
            batch("vol-a", 20, std::slice::from_ref(&sub), true),
        ];
        let outcome = main_under_test::test_reconcile_scripted(
            &store,
            generation,
            "vol-a",
            "uuid-a",
            &[tmp.path().to_path_buf()],
            batches,
        )
        .await
        .expect("reconcile");
        assert_eq!(outcome.claims.len(), 1);
        assert!(outcome.claims[0].complete, "{}", outcome.claims[0].detail);
        assert!(
            store
                .get_error("gap:event-claim:vol-a")
                .await
                .expect("get")
                .is_none(),
            "held claim writes no gap"
        );

        let report =
            stream_to_report(&store, &report_inputs("claim-b", generation, "complete")).await;
        assert_eq!(report.coverage.gaps, 0);
        assert_eq!(report.coverage.filesystem, "complete");
    });
}
