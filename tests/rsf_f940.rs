//! RSF-F940 production-wiring regression tests: FSEvents durability in the
//! PRODUCTION reconcile path (`src/main.rs`), not the support helpers
//! (`tests/rsf_support.rs` covers those in isolation).
//!
//! Run-loop level, never helper-only: every test drives production code
//! (the real drain `ingest_available_events`, the real
//! `reconcile_event_cursors`, the real `TursoStore` across close/reopen
//! restarts) through `#[cfg(test)]` hooks — the same code the command
//! paths execute — and asserts durable outcomes: restored resume,
//! atomic commits, scheduled retries, and history_done-gated claims.

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

use main_under_test::TestDrainItem;
use repo_scan::config::scope_key_for_dir;
use repo_scan::events::{volume_scope_key, EventBatch, EventCursorId, BATCH_ERROR_CATEGORY};
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

// ---------------------------------------------------------------------------
// RSF-F940: the production path restores durable cursors and ingests
// batches atomically (cursor row + invalidations in ONE commit)
// ---------------------------------------------------------------------------

#[test]
fn rsf_f940_production_drain_restores_and_ingests_atomically() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let now = now_ms();

        // Prior run: cursor 200 ingested, only 100 reconciled — then a kill.
        let generation: u64;
        {
            let store = TursoStore::open(&db).await.expect("open");
            generation = store
                .create_generation("machine", "running", None, now)
                .await
                .expect("generation");
            for cursor in ["100", "200"] {
                assert!(store
                    .append_event("vol-a", "uuid-a", cursor, true, now)
                    .await
                    .expect("append"));
            }
            let rows = store.list_events("vol-a", "uuid-a").await.expect("list");
            let first = rows.iter().find(|r| r.cursor == "100").expect("row 100").id;
            store.mark_event_reconciled(first).await.expect("mark");
            store.close().await.expect("close");
        }

        // --- restart on the same catalog ---
        let store = TursoStore::open(&db).await.expect("reopen");

        // Replay of the recorded boundary is a duplicate no-op: the
        // production path restored durable cursors, so the replay drops
        // with no transaction and no double-scheduled work.
        let replay = main_under_test::test_apply_event_batch(
            &store,
            generation,
            "uuid-a",
            &batch("vol-a", 200, std::slice::from_ref(&sub), false),
        )
        .await
        .expect("replay");
        assert!(!replay.history_invalid);
        assert_eq!(replay.batches, 1);
        assert_eq!(replay.scopes, 0, "duplicate replay schedules nothing");
        assert_eq!(replay.tx, 0, "duplicate replay writes nothing");

        // Fresh batch: ONE transaction commits the cursor row and its
        // scope invalidations together (atomic, never torn).
        let fresh = main_under_test::test_apply_event_batch(
            &store,
            generation,
            "uuid-a",
            &batch("vol-a", 250, std::slice::from_ref(&sub), false),
        )
        .await
        .expect("fresh");
        assert!(!fresh.history_invalid);
        assert_eq!(fresh.batches, 1);
        assert_eq!(fresh.scopes, 2, "path + parent dir scopes");
        assert_eq!(fresh.tx, 1, "atomic ingest: one commit");

        let dir_sub = scope_key_for_dir(&sub);
        let dir_tmp = scope_key_for_dir(tmp.path());
        assert_eq!(store.scope_rev(&dir_sub).await.expect("rev"), 1);
        assert_eq!(store.scope_rev(&dir_tmp).await.expect("rev"), 1);
        assert_eq!(store.pending_count(generation).await.expect("pending"), 2);
        let rows = store.list_events("vol-a", "uuid-a").await.expect("list");
        let row = rows.iter().find(|r| r.cursor == "250").expect("row 250");
        assert!(row.ingested);
        assert!(row.invalidated);

        // Dir-key plans only: no planner `path:` key is ever scheduled.
        let mut query = store
            .connection()
            .query("SELECT scope_key FROM scope_revisions", ())
            .await
            .expect("query");
        let mut keys = Vec::new();
        while let Some(row) = query.next().await.expect("next") {
            match row.get_value(0).expect("key") {
                turso::Value::Text(key) => keys.push(key),
                other => panic!("scope key not text: {other:?}"),
            }
        }
        assert!(keys.iter().all(|k| !k.starts_with("path:")), "{keys:?}");
        assert!(keys.contains(&dir_sub), "{keys:?}");
        assert!(keys.contains(&dir_tmp), "{keys:?}");
    });
}

// ---------------------------------------------------------------------------
// RSF-F940: production batch errors schedule a rescan with retry
// (never log-and-drop)
// ---------------------------------------------------------------------------

#[test]
fn rsf_f940_production_batch_error_schedules_rescan_with_retry() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let (store, generation) = open_generation(&db).await;

        let before = now_ms();
        let script = vec![
            TestDrainItem::Batch(batch("vol-a", 50, std::slice::from_ref(&sub), false)),
            TestDrainItem::Fail(String::from("channel overrun")),
        ];
        let outcome = main_under_test::test_drain_scripted(
            &store,
            generation,
            "vol-a",
            "uuid-a",
            &[tmp.path().to_path_buf()],
            script,
        )
        .await
        .expect("drain");
        assert!(!outcome.history_invalid);
        assert_eq!(outcome.batches, 1);
        assert_eq!(outcome.scopes, 3, "path + parent + volume rescan");
        assert_eq!(outcome.tx, 3, "atomic ingest + gap record + rescan");

        // Retry, not drop: stable gap row with a retry time, and the
        // volume-wide rescan scheduled as pending work.
        let gap = store
            .get_error("gap:event-batch:vol-a")
            .await
            .expect("get")
            .expect("gap row");
        assert_eq!(gap.category, BATCH_ERROR_CATEGORY);
        assert_eq!(gap.scope_key, volume_scope_key("vol-a"));
        assert!(gap.open);
        assert!(gap.detail.contains("vol-a"), "{}", gap.detail);
        assert!(gap.detail.contains("channel overrun"), "{}", gap.detail);
        let retry = gap.next_retry_ms.expect("retry scheduled");
        assert!(retry > before, "retry {retry} after {before}");
        assert_eq!(
            store
                .scope_rev(&volume_scope_key("vol-a"))
                .await
                .expect("rev"),
            1
        );
        assert_eq!(store.pending_count(generation).await.expect("pending"), 3);
    });
}

// ---------------------------------------------------------------------------
// RSF-F940: production completeness claims gate on history_done
// ---------------------------------------------------------------------------

#[test]
fn rsf_f940_production_claims_gate_on_history_done() {
    let rt = runtime();
    rt.block_on(async {
        // (a) Historical phase still replaying: reconciled reaches the
        // boundary, but the checked claim refuses — a prefix is never
        // complete.
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
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
        let cursor = outcome.cursors.get("vol-a").expect("cursor");
        assert_eq!(cursor.history_uuid.as_deref(), Some("uuid-a"));
        assert_eq!(cursor.ingested.as_deref(), Some("20"));
        assert_eq!(cursor.reconciled.as_deref(), Some("20"));
        assert_eq!(outcome.claims.len(), 1);
        assert!(!outcome.claims[0].complete);
        assert!(
            outcome.claims[0].detail.contains("history_done"),
            "{}",
            outcome.claims[0].detail
        );

        // (b) Sentinel consumed: the same work claims complete.
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
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
        let cursor = outcome.cursors.get("vol-a").expect("cursor");
        assert_eq!(cursor.reconciled.as_deref(), Some("20"));
        assert_eq!(outcome.claims.len(), 1);
        assert!(outcome.claims[0].complete, "{}", outcome.claims[0].detail);
        assert_eq!(outcome.tx, 2, "two atomic ingests");
    });
}

// ---------------------------------------------------------------------------
// RSF-F940: production dir scopes stay byte-exact for non-UTF-8 paths
// ---------------------------------------------------------------------------

#[test]
#[cfg(unix)]
fn rsf_f940_production_dir_scopes_stay_byte_exact() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let mut raw = tmp.path().as_os_str().as_bytes().to_vec();
        raw.extend_from_slice(b"/weird-\xff\xfe");
        let weird = PathBuf::from(std::ffi::OsString::from_vec(raw));
        // Fixture realism only: nothing under test reads this dir (the
        // fence falls back to the uncanonicalized path, `in_scan_scope`
        // is lexical, and every assertion below is store-level). Proceed
        // when the platform rejects the name itself (macOS/APFS refuses
        // non-UTF-8 names with EILSEQ); fail on any other setup error.
        match std::fs::create_dir_all(&weird) {
            Ok(()) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::InvalidInput
                    || e.raw_os_error() == Some(libc::EILSEQ) =>
            {
                eprintln!("note: OS rejected non-UTF-8 fixture dir name: {e}; continuing");
            }
            Err(e) => panic!("create non-UTF-8 fixture dir: {e}"),
        }
        let (store, generation) = open_generation(&db).await;

        let outcome = main_under_test::test_apply_event_batch(
            &store,
            generation,
            "uuid-a",
            &batch("vol-a", 60, std::slice::from_ref(&weird), false),
        )
        .await
        .expect("ingest");
        assert_eq!(outcome.scopes, 2, "path + parent dir scopes");

        // Exact bytes scheduled; the lossy rendering is not.
        assert_eq!(
            store
                .scope_rev(&scope_key_for_dir(&weird))
                .await
                .expect("rev"),
            1
        );
        let lossy = PathBuf::from(weird.to_string_lossy().into_owned());
        assert_ne!(weird, lossy);
        assert_eq!(
            store
                .scope_rev(&scope_key_for_dir(&lossy))
                .await
                .expect("rev"),
            0
        );
    });
}
