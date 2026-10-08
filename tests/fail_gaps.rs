//! RESUME-IDENTITY-CLEAR findings 1+2: event gaps must resolve on
//! bounded recovery, and coordinator identity I/O must be bounded with
//! durable unknown/gap on failure (never a silent path-derived fallback).
//! Fixture-scale only (tempdirs, no machine scans).

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

use main_under_test::TestDrainItem;
use repo_scan::events::{
    volume_scope_key, EventBatch, EventCursorId, BATCH_ERROR_CATEGORY, CLAIM_ERROR_CATEGORY,
};
use repo_scan::store::{now_ms, Store, TursoStore};
use repo_scan::walk::topology::{
    bounded_dir_identity, bounded_volume_dev, identity_io_calls, ScopeFence,
};
use std::path::PathBuf;

fn runtime() -> tokio::runtime::Runtime {
    // All drivers on: the pooled drain needs the timer (renewal ticks)
    // and the blocking pool (worker threads).
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
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

/// Finding 1: a failed batch/claim records an open gap, and a later
/// generation's bounded recovery (rescan drain / consumed `HistoryDone`)
/// resolves the matching gap transactionally — evidence retained, `open`
/// flipped — so old failures never pin later generations incomplete.
#[test]
fn gaps_failure_then_success_resolves_across_generations() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let sub = tmp.path().join("sub");
        repo_scan::privacy::private_dir_0700(&sub).unwrap();
        let (store, gen_fail) = open_generation(&db).await;

        // Batch gap opens on a failed batch read (durable rescan + retry).
        main_under_test::test_drain_scripted(
            &store,
            gen_fail,
            "vol-batch",
            "uuid-batch",
            &[tmp.path().to_path_buf()],
            vec![TestDrainItem::Fail(String::from("channel overrun"))],
        )
        .await
        .expect("fail drain");
        let gap = store
            .get_error("gap:event-batch:vol-batch")
            .await
            .expect("get")
            .expect("batch gap row");
        assert_eq!(gap.category, BATCH_ERROR_CATEGORY);
        assert_eq!(gap.scope_key, volume_scope_key("vol-batch"));
        assert!(gap.open);

        // Later generation: the stream recovers and history closes — the
        // matching batch gap resolves, its evidence row retained.
        let gen_ok = store
            .create_generation("machine", "running", None, now_ms())
            .await
            .expect("generation");
        main_under_test::test_drain_scripted(
            &store,
            gen_ok,
            "vol-batch",
            "uuid-batch",
            &[tmp.path().to_path_buf()],
            vec![TestDrainItem::Batch(batch(
                "vol-batch",
                10,
                std::slice::from_ref(&sub),
                true,
            ))],
        )
        .await
        .expect("recovery drain");
        let gap = store
            .get_error("gap:event-batch:vol-batch")
            .await
            .expect("get")
            .expect("batch gap row retained");
        assert!(!gap.open, "recovered batch gap resolves");

        // Claim gap opens when reconcile cannot claim completeness.
        let outcome = main_under_test::test_reconcile_scripted(
            &store,
            gen_fail,
            "vol-claim",
            "uuid-claim",
            &[tmp.path().to_path_buf()],
            vec![batch("vol-claim", 10, std::slice::from_ref(&sub), false)],
        )
        .await
        .expect("fail reconcile");
        assert_eq!(outcome.claims.len(), 1);
        assert!(!outcome.claims[0].complete);
        let gap = store
            .get_error("gap:event-claim:vol-claim")
            .await
            .expect("get")
            .expect("claim gap row");
        assert_eq!(gap.category, CLAIM_ERROR_CATEGORY);
        assert!(gap.open);

        // Later generation consumes HistoryDone: the claim holds and the
        // matching claim gap resolves.
        let outcome = main_under_test::test_reconcile_scripted(
            &store,
            gen_ok,
            "vol-claim",
            "uuid-claim",
            &[tmp.path().to_path_buf()],
            vec![batch("vol-claim", 20, std::slice::from_ref(&sub), true)],
        )
        .await
        .expect("recovery reconcile");
        assert_eq!(outcome.claims.len(), 1);
        assert!(outcome.claims[0].complete, "{}", outcome.claims[0].detail);
        let gap = store
            .get_error("gap:event-claim:vol-claim")
            .await
            .expect("get")
            .expect("claim gap row retained");
        assert!(!gap.open, "recovered claim gap resolves");

        // Resolver primitive: transactional close only when an open gap
        // exists; the no-gap path commits nothing.
        store
            .record_error(
                "gap:event-claim:vol-direct",
                &volume_scope_key("vol-direct"),
                CLAIM_ERROR_CATEGORY,
                "direct",
                None,
                now_ms(),
            )
            .await
            .expect("record");
        assert!(
            store
                .resolve_event_gaps_for_volume("vol-direct", now_ms())
                .await
                .expect("resolve"),
            "open gap commits a resolve transaction"
        );
        assert!(
            !store
                .get_error("gap:event-claim:vol-direct")
                .await
                .expect("get")
                .expect("row")
                .open
        );
        assert!(
            !store
                .resolve_event_gaps_for_volume("vol-direct", now_ms())
                .await
                .expect("resolve"),
            "no open gap commits nothing"
        );
    });
}

/// Finding 2: coordinator identity work is bounded; unstatable paths get
/// an explicit unknown marker plus a durable gap — never a silent
/// path-derived identity that changes meaning under failure.
#[test]
fn identity_unknown_persists_gap_without_failopen_fallback() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let sub = tmp.path().join("sub");
        repo_scan::privacy::private_dir_0700(&sub).unwrap();
        let missing = tmp.path().join("missing");
        assert!(!missing.exists());
        let (store, generation) = open_generation(&db).await;

        // Bounded stat: identity for live paths, unknown for dead ones.
        assert!(bounded_dir_identity(&sub).is_some());
        assert_eq!(bounded_dir_identity(&missing), None);
        assert!(bounded_volume_dev(&sub).is_some());
        assert_eq!(bounded_volume_dev(&missing), None);

        // M5 routing pin: coordinator stats flow through the bounded
        // identity-I/O lane (admission + timeout), never direct
        // unbounded `metadata` — every call advances the lane counter.
        let before = identity_io_calls();
        assert!(bounded_dir_identity(&sub).is_some());
        assert!(bounded_volume_dev(&sub).is_some());
        assert_eq!(
            identity_io_calls(),
            before + 2,
            "both resolve lanes are bounded"
        );

        // Per-claim breaker keying rides the same lane: live scopes key
        // by volume, unstattable scopes share `unknown` explicitly.
        let live_key =
            main_under_test::breaker_key_for_task(&repo_scan::config::scope_key_for_dir(&sub));
        assert!(
            live_key.starts_with("dev:"),
            "live scope keys by volume, got {live_key}"
        );
        assert_eq!(
            main_under_test::breaker_key_for_task(&repo_scan::config::scope_key_for_dir(&missing)),
            "unknown"
        );

        // Enum IDs: explicit unknown marker (stable, never `:path:`).
        let unknown = main_under_test::enum_task_id_for_path(generation, &missing);
        assert!(
            unknown.contains(":unknown:"),
            "unknown marker, got {unknown}"
        );
        assert!(!unknown.contains(":path:"), "no fail-open fallback");
        assert_eq!(
            unknown,
            main_under_test::enum_task_id_for_path(generation, &missing),
            "unknown IDs are stable"
        );
        #[cfg(unix)]
        assert!(
            main_under_test::enum_task_id_for_path(generation, &sub).contains(":d"),
            "live paths keep identity IDs"
        );

        // Fence: unknown roots are flagged (not silently fenced), while
        // scheduling still matches them lexically for honest execution.
        let fence = ScopeFence::build(std::slice::from_ref(&missing));
        assert_eq!(fence.unknown_roots(), vec![missing.clone()]);
        assert!(fence.allows_path(&missing));
        let fence = ScopeFence::build(std::slice::from_ref(&sub));
        assert!(fence.unknown_roots().is_empty());

        // Production drain persists one durable gap per unknown root.
        main_under_test::test_drain_scripted(
            &store,
            generation,
            "vol-fence",
            "uuid-fence",
            std::slice::from_ref(&missing),
            Vec::new(),
        )
        .await
        .expect("drain");
        let gap_id = format!(
            "gap:fence-identity:{}",
            repo_scan::config::encode_hex(&repo_scan::config::path_as_bytes(&missing))
        );
        let gap = store
            .get_error(&gap_id)
            .await
            .expect("get")
            .expect("fence gap row");
        assert_eq!(gap.category, "fence-identity-unknown");
        assert!(gap.open);
    });
}
