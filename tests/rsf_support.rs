//! RSF support-module regression tests (RSF-F940 events resume, RSF-88BA
//! git feature probe).
//!
//! Run-loop level, never helper-only: every test drives production code
//! (real `TursoStore` across close/reopen restarts, the real `Reconciler`
//! protocol, real `git` process spawns) and asserts durable outcomes —
//! persisted cursors, scheduled retries, pending work, and completeness
//! gates — not implementation trivia.

use repo_scan::events::{
    classify_try_recv, continuity_plan, dir_scope_for_subtree_key, journal_cursor_string,
    parse_subtree_scope_key, plan_batch_error, subtree_scope_key, volume_cursor_from_rows,
    volume_scope_key, BatchErrorAction, ContinuitySignal, CursorJournal, EventBatch, EventCursorId,
    HistoryUuid, MemoryCursorJournal, MemorySink, Reconciler, TryRecvAction, VolumeCursor,
    BATCH_ERROR_CATEGORY,
};
use repo_scan::store::{now_ms, Store, TaskOutcome, TursoStore};
use std::collections::HashMap;
use std::path::PathBuf;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn batch(volume: &str, high_water: u64, paths: &[&str]) -> EventBatch {
    EventBatch {
        volume_key: volume.to_string(),
        high_water: EventCursorId(high_water),
        invalidations: paths.iter().copied().map(PathBuf::from).collect(),
        history_done: false,
        signals: Vec::new(),
    }
}

fn stored_cursor(uuid: &str, ingested: u64, reconciled: u64) -> VolumeCursor {
    VolumeCursor {
        uuid: Some(HistoryUuid(uuid.to_string())),
        ingested: Some(EventCursorId(ingested)),
        reconciled: Some(EventCursorId(reconciled)),
        flags_seen: Vec::new(),
    }
}

/// Durable cursors for one volume/history from the production journal.
async fn durable_cursor(
    store: &TursoStore,
    volume: &str,
    history_uuid: &str,
) -> Option<VolumeCursor> {
    let rows = store
        .list_events(volume, history_uuid)
        .await
        .expect("list events");
    volume_cursor_from_rows(volume, &rows)
}

// ---------------------------------------------------------------------------
// RSF-F940: reconciler starts from durable cursors (never empty when they exist)
// ---------------------------------------------------------------------------

#[test]
fn rsf_f940_reconciler_starts_from_durable_cursors() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let now = now_ms();

        // First run: two boundaries ingested, only the first reconciled.
        let store = TursoStore::open(&db).await.expect("open");
        for cursor in [100u64, 200u64] {
            assert!(store
                .append_event(
                    "vol-a",
                    "uuid-a",
                    &journal_cursor_string(EventCursorId(cursor)),
                    true,
                    now
                )
                .await
                .expect("append"));
        }
        let rows = store.list_events("vol-a", "uuid-a").await.expect("list");
        let first = rows.iter().find(|r| r.cursor == "100").expect("row 100").id;
        store.mark_event_reconciled(first).await.expect("mark");
        store.close().await.expect("close");

        // --- restart: fresh process, fresh reconciler, same catalog ---
        let store = TursoStore::open(&db).await.expect("reopen");
        let cursor = durable_cursor(&store, "vol-a", "uuid-a")
            .await
            .expect("durable cursor");
        assert_eq!(cursor.ingested, Some(EventCursorId(200)));
        assert_eq!(cursor.reconciled, Some(EventCursorId(100)));

        let mut stored = HashMap::new();
        stored.insert("vol-a".to_string(), cursor);
        let mut r = Reconciler::new(MemoryCursorJournal::new());
        r.restore_durable_cursors(&stored);

        // No empty start: resume position, duplicate suppression, and the
        // unreconciled gap (200 > 100) with a volume-wide rescan pending.
        let loaded = r.journal().load("vol-a").expect("restored cursor");
        assert_eq!(loaded.uuid, Some(HistoryUuid("uuid-a".into())));
        assert_eq!(loaded.ingested, Some(EventCursorId(200)));
        assert_eq!(loaded.reconciled, Some(EventCursorId(100)));
        let pending = r.journal().pending("vol-a");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].cursor, EventCursorId(200));
        assert_eq!(pending[0].scopes, vec![volume_scope_key("vol-a")]);

        // Restart replay of the recorded boundary is a duplicate no-op.
        r.note_stream_opened(
            "vol-a",
            stored.get("vol-a"),
            stored.get("vol-a").and_then(|c| c.uuid.as_ref()),
            200,
            EventCursorId(200),
        );
        r.begin_traversal().expect("traversal");
        let replay = r
            .ingest(&batch("vol-a", 200, &["/replayed"]))
            .expect("replay");
        assert!(replay.duplicate);
        assert_eq!(replay.advanced_to, Some(EventCursorId(200)));

        // A fully reconciled volume restores with no pending work.
        let mut r2 = Reconciler::new(MemoryCursorJournal::new());
        let mut clean = HashMap::new();
        clean.insert("vol-b".to_string(), stored_cursor("uuid-b", 50, 50));
        r2.restore_durable_cursors(&clean);
        assert!(r2.journal().pending("vol-b").is_empty());
        assert_eq!(
            r2.journal().load("vol-b").expect("row").ingested,
            Some(EventCursorId(50))
        );
    });
}

// ---------------------------------------------------------------------------
// RSF-F940: cursor append + scope invalidation commit atomically
// ---------------------------------------------------------------------------

#[test]
fn rsf_f940_atomic_ingest_commits_cursor_and_scopes_together() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let now = now_ms();
        let generation = store
            .create_generation("machine", "running", None, now)
            .await
            .expect("generation");

        let scope_a = repo_scan::config::scope_key_for_dir(&PathBuf::from("/a"));
        let scope_b = repo_scan::config::scope_key_for_dir(&PathBuf::from("/b"));
        let scopes = vec![scope_a.clone(), scope_b.clone()];

        // One call commits the cursor row and both invalidations together.
        let outcome = store
            .ingest_event_batch("vol-a", "uuid-a", "300", true, &scopes, generation, now)
            .await
            .expect("atomic ingest");
        assert!(outcome.inserted);
        assert_eq!(outcome.revs, vec![1, 1]);
        assert_eq!(store.scope_rev(&scope_a).await.expect("rev"), 1);
        assert_eq!(store.scope_rev(&scope_b).await.expect("rev"), 1);
        assert_eq!(store.pending_count(generation).await.expect("pending"), 2);
        let rows = store.list_events("vol-a", "uuid-a").await.expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cursor, "300");
        assert!(rows[0].ingested);

        // Duplicate replay is an idempotent no-op: no revision bump, no
        // double-scheduled work.
        let replay = store
            .ingest_event_batch("vol-a", "uuid-a", "300", true, &scopes, generation, now)
            .await
            .expect("replay");
        assert!(!replay.inserted);
        assert!(replay.revs.is_empty());
        assert_eq!(store.scope_rev(&scope_a).await.expect("rev"), 1);
        assert_eq!(store.pending_count(generation).await.expect("pending"), 2);

        // Empty scopes still record the cursor (fenced batches advance the
        // boundary with no scheduled work).
        let fenced = store
            .ingest_event_batch("vol-a", "uuid-a", "400", false, &[], generation, now)
            .await
            .expect("fenced");
        assert!(fenced.inserted);
        assert!(fenced.revs.is_empty());
        assert_eq!(store.pending_count(generation).await.expect("pending"), 2);
    });
}

// ---------------------------------------------------------------------------
// RSF-F940: interruption between cursor append and scope invalidation
// restarts into a rescan that must complete before any completeness claim
// ---------------------------------------------------------------------------

#[test]
fn rsf_f940_torn_cursor_without_invalidation_rescans_before_completion() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let now = now_ms();

        // Pre-fix torn write, then a kill: the cursor row commits but its
        // scope invalidations never do (separate writes, crash between).
        let generation: u64;
        {
            let store = TursoStore::open(&db).await.expect("open");
            let now = now_ms();
            generation = store
                .create_generation("machine", "running", None, now)
                .await
                .expect("generation");
            assert!(store
                .append_event("vol-a", "uuid-a", "300", true, now)
                .await
                .expect("torn append"));
            // --- simulated kill here: no invalidate_scope, store dropped ---
        }

        // --- restart on the same catalog ---
        let store = TursoStore::open(&db).await.expect("reopen");
        let epoch = store.epoch();
        let cursor = durable_cursor(&store, "vol-a", "uuid-a")
            .await
            .expect("durable cursor");
        assert_eq!(cursor.ingested, Some(EventCursorId(300)));
        assert_eq!(cursor.reconciled, None);

        // The reconciler restores the torn gap as pending volume-wide
        // rescan work instead of starting empty.
        let mut stored = HashMap::new();
        stored.insert("vol-a".to_string(), cursor.clone());
        let mut r = Reconciler::new(MemoryCursorJournal::new());
        r.restore_durable_cursors(&stored);
        let pending = r.journal().pending("vol-a");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].cursor, EventCursorId(300));

        // Same open rule as the run loop: same UUID, live at the cursor.
        let decision = r.note_stream_opened(
            "vol-a",
            Some(&cursor),
            cursor.uuid.as_ref(),
            300,
            EventCursorId(300),
        );
        assert!(!decision.history_invalid());
        r.begin_traversal().expect("traversal");

        // No premature completeness: reconciled (none) is below the
        // boundary (300), and no history_done was consumed yet.
        assert!(r.claim_volume_complete("vol-a").is_err());
        assert!(r.claim_volume_complete_requiring_history("vol-a").is_err());

        // Reconcile replays the restored rescan scope; the owner mirrors
        // it into the store, where it becomes durable pending work.
        let mut sink = MemorySink::new();
        let outcome = r.reconcile_volume("vol-a", &mut sink).expect("reconcile");
        assert_eq!(outcome.invalidated_scopes, vec![volume_scope_key("vol-a")]);
        assert_eq!(outcome.reconciled_through, None);
        for scope in &outcome.invalidated_scopes {
            store
                .invalidate_scope(scope, generation, now)
                .await
                .expect("rescan invalidate");
        }
        assert_eq!(store.pending_count(generation).await.expect("pending"), 1);
        assert!(r.claim_volume_complete("vol-a").is_err());

        // The rescan work executes through the production claim/complete
        // path; only then may the reconciled cursor advance.
        let claimed = store
            .claim_tasks(epoch, 8, 60_000, now)
            .await
            .expect("claim rescan");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].task.scope_key, volume_scope_key("vol-a"));
        store
            .complete_task(
                &claimed[0].task.id,
                claimed[0].token,
                epoch,
                &TaskOutcome::Complete,
                now,
            )
            .await
            .expect("complete rescan");
        assert_eq!(store.pending_count(generation).await.expect("pending"), 0);
        for scope in sink.pending_scopes() {
            sink.complete_scope(&scope);
        }
        let advanced = r.try_advance_reconciled("vol-a", &sink).expect("advance");
        assert_eq!(advanced, Some(EventCursorId(300)));
        let rows = store.list_events("vol-a", "uuid-a").await.expect("list");
        let row = rows
            .iter()
            .find(|row| row.cursor == "300")
            .expect("row 300");
        store.mark_event_reconciled(row.id).await.expect("mark");
        let cursor = durable_cursor(&store, "vol-a", "uuid-a")
            .await
            .expect("cursor");
        assert_eq!(cursor.reconciled, Some(EventCursorId(300)));

        // Rescan satisfied: the plain claim succeeds. The checked claim
        // still waits for the replayed history_done sentinel, then
        // succeeds too — rescan-before-completion in both forms.
        r.claim_volume_complete("vol-a")
            .expect("claim after rescan");
        assert!(r.claim_volume_complete_requiring_history("vol-a").is_err());
        r.note_history_done("vol-a");
        r.claim_volume_complete_requiring_history("vol-a")
            .expect("checked claim after history_done");
    });
}

// ---------------------------------------------------------------------------
// RSF-F940: batch errors schedule retry/park (never log-and-drop)
// ---------------------------------------------------------------------------

#[test]
fn rsf_f940_batch_error_schedules_retry_not_drop() {
    // Pure plan: a failed batch covers unknown paths, so the retry is a
    // volume-wide rescan with a stable gap identity and category.
    let action: BatchErrorAction = plan_batch_error("vol-a", "channel overrun");
    assert_eq!(action.volume_key, "vol-a");
    assert_eq!(action.scope_key, volume_scope_key("vol-a"));
    assert_eq!(action.gap_id, "gap:event-batch:vol-a");
    assert!(action.detail.contains("vol-a"));
    assert!(action.detail.contains("channel overrun"));
    assert_eq!(BATCH_ERROR_CATEGORY, "event-batch-error");

    // Production application: the gap is recorded durably and the rescan
    // scope becomes pending scheduler work with a retry time.
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let now = now_ms();
        let generation = store
            .create_generation("machine", "running", None, now)
            .await
            .expect("generation");

        store
            .record_error(
                &action.gap_id,
                &action.scope_key,
                BATCH_ERROR_CATEGORY,
                &action.detail,
                Some(now + 5_000),
                now,
            )
            .await
            .expect("record gap");
        let rev = store
            .invalidate_scope(&action.scope_key, generation, now)
            .await
            .expect("invalidate");
        assert_eq!(rev, 1);

        let row = store
            .get_error(&action.gap_id)
            .await
            .expect("get")
            .expect("gap row");
        assert_eq!(row.category, BATCH_ERROR_CATEGORY);
        assert_eq!(row.scope_key, volume_scope_key("vol-a"));
        assert!(row.open);
        assert_eq!(row.next_retry_ms, Some(now + 5_000));
        // Retryable work is scheduled — nothing was dropped.
        assert_eq!(store.pending_count(generation).await.expect("pending"), 1);
        assert_eq!(store.scope_rev(&action.scope_key).await.expect("rev"), 1);
    });
}

// ---------------------------------------------------------------------------
// RSF-F940: history_done is consumed by the reconcile path
// ---------------------------------------------------------------------------

#[test]
fn rsf_f940_history_done_consumed_by_reconcile_path() {
    // Batches without the sentinel leave the reconcile path unconsumed.
    let mut r = Reconciler::new(MemoryCursorJournal::new());
    r.note_stream_opened(
        "vol-a",
        None,
        Some(&HistoryUuid("u".into())),
        20,
        EventCursorId(20),
    );
    r.begin_traversal().expect("traversal");
    let outcome = r.ingest(&batch("vol-a", 10, &["/a"])).expect("ingest");
    assert!(!outcome.history_done);
    assert!(!r.history_done("vol-a"));

    // The sentinel batch is consumed: ingest outcome, reconciler state,
    // and reconcile outcome all observe it.
    let done = EventBatch {
        volume_key: "vol-a".to_string(),
        high_water: EventCursorId(20),
        invalidations: vec![PathBuf::from("/a/b")],
        history_done: true,
        signals: Vec::new(),
    };
    let outcome = r.ingest(&done).expect("ingest done");
    assert!(outcome.history_done);
    assert!(r.history_done("vol-a"));
    let mut sink = MemorySink::new();
    let reconciled = r.reconcile_volume("vol-a", &mut sink).expect("reconcile");
    assert!(reconciled.history_done);

    // The checked claim gates on the sentinel; the plain claim does not.
    for scope in sink.pending_scopes() {
        sink.complete_scope(&scope);
    }
    r.try_advance_reconciled("vol-a", &sink).expect("advance");
    r.claim_volume_complete_requiring_history("vol-a")
        .expect("checked claim with history_done");

    let mut bare = Reconciler::new(MemoryCursorJournal::new());
    bare.note_stream_opened(
        "vol-b",
        None,
        Some(&HistoryUuid("u".into())),
        10,
        EventCursorId(10),
    );
    bare.begin_traversal().expect("traversal");
    bare.ingest(&batch("vol-b", 10, &["/b"])).expect("ingest");
    let mut sink = MemorySink::new();
    bare.reconcile_volume("vol-b", &mut sink)
        .expect("reconcile");
    for scope in sink.pending_scopes() {
        sink.complete_scope(&scope);
    }
    bare.try_advance_reconciled("vol-b", &sink)
        .expect("advance");
    bare.claim_volume_complete("vol-b").expect("plain claim");
    assert!(bare
        .claim_volume_complete_requiring_history("vol-b")
        .is_err());
    bare.note_history_done("vol-b");
    bare.claim_volume_complete_requiring_history("vol-b")
        .expect("checked claim after explicit note");

    // A sentinel on a history-invalid batch belongs to the discarded
    // baseline and must not mark the fresh one done.
    let mut lost = Reconciler::new(MemoryCursorJournal::new());
    lost.note_stream_opened(
        "vol-c",
        None,
        Some(&HistoryUuid("u".into())),
        5,
        EventCursorId(5),
    );
    let invalid = EventBatch {
        volume_key: "vol-c".to_string(),
        high_water: EventCursorId(6),
        invalidations: Vec::new(),
        history_done: true,
        signals: vec![ContinuitySignal::HistoryInvalid],
    };
    let outcome = lost.ingest(&invalid).expect("ingest invalid");
    assert!(outcome.history_invalid);
    assert!(!outcome.history_done);
    assert!(!lost.history_done("vol-c"));
}

// ---------------------------------------------------------------------------
// RSF-F940: try_recv distinguishes Empty from Disconnected
// ---------------------------------------------------------------------------

#[test]
fn rsf_f940_try_recv_empty_vs_disconnected() {
    // Pure classification: routine backpressure vs lost history.
    assert_eq!(
        classify_try_recv(std::sync::mpsc::TryRecvError::Empty),
        TryRecvAction::CaughtUp
    );
    assert_eq!(
        classify_try_recv(std::sync::mpsc::TryRecvError::Disconnected),
        TryRecvAction::StreamLost
    );

    // Production channels: an idle bounded channel reports Empty
    // (caught up, drain returns pending work or None), while a channel
    // whose sender is gone reports Disconnected (stream lost, the
    // owner must invalidate the volume scope — never silent end).
    let (tx, rx) = std::sync::mpsc::sync_channel::<u8>(512);
    assert_eq!(
        classify_try_recv(rx.try_recv().expect_err("idle channel is empty")),
        TryRecvAction::CaughtUp
    );
    drop(tx);
    assert_eq!(
        classify_try_recv(rx.try_recv().expect_err("dropped sender disconnects")),
        TryRecvAction::StreamLost
    );
}

// ---------------------------------------------------------------------------
// RSF-F940: planner path keys and scheduler dir keys agree (round-trip)
// ---------------------------------------------------------------------------

#[test]
fn rsf_f940_planner_and_scheduler_keys_agree() {
    use repo_scan::config::{
        encode_hex, parse_scope_key, path_as_bytes, scope_key_for_dir, ScopeRef,
    };

    // Planner keys keep the per-volume `path:` contract with the
    // hex-encoded path bytes embedded (never the literal path: `:`,
    // unicode, and non-UTF-8 bytes must survive planner-key parsing),
    // and every one denotes exactly the scheduler scope for its path:
    // byte-identical to what the owner invalidates.
    let paths = [
        PathBuf::from("/"),
        PathBuf::from("/private/var/folders/xy"),
        PathBuf::from("/tmp/sp ace/ünicode"),
        PathBuf::from("/tmp/with:colon"),
    ];
    for path in &paths {
        let planner = subtree_scope_key("vol-a", path);
        assert!(planner.starts_with("path:vol-a:"), "{planner}");
        assert_eq!(
            planner,
            format!("path:vol-a:{}", encode_hex(&path_as_bytes(path))),
            "{planner}"
        );
        assert_eq!(
            parse_subtree_scope_key(&planner),
            Some(("vol-a".to_string(), path.clone())),
            "{planner}"
        );
        let scheduler = dir_scope_for_subtree_key(&planner).expect("mapped scope");
        assert_eq!(scheduler, scope_key_for_dir(path), "{planner}");
        assert_eq!(
            parse_scope_key(&scheduler),
            Some(ScopeRef::Dir(path.clone())),
            "{planner}"
        );
    }

    // Non-UTF-8 paths stay lossless: the constructor never panics,
    // the key keeps the contract prefix, the path round-trips
    // byte-exactly, and the scheduler mapping stays total.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let raw = vec![b'/', b't', b'm', b'p', 0xff, 0xfe, 0x01];
        let path = PathBuf::from(std::ffi::OsString::from_vec(raw.clone()));
        let key = subtree_scope_key("vol-a", &path);
        assert!(key.starts_with("path:vol-a:"), "{key}");
        assert_eq!(
            parse_subtree_scope_key(&key),
            Some(("vol-a".to_string(), path.clone())),
            "{key}"
        );
        assert!(dir_scope_for_subtree_key(&key).is_some());
    }

    // Malformed planner keys map to nothing: the owner can never derive
    // a scheduler scope from a key no constructor emits.
    for bad in [
        "",
        "dir:2f",
        "path:",
        "path:vol-a",
        "path::/tmp/x",
        "path:vol-a:",
        "PATH:vol-a:/tmp/x",
    ] {
        assert_eq!(parse_subtree_scope_key(bad), None, "{bad}");
        assert_eq!(dir_scope_for_subtree_key(bad), None, "{bad}");
    }

    // Every continuity-plan path key parses back to the exact planned
    // path and denotes its scheduler scope — no second key universe.
    let moved_in = PathBuf::from("/root/moved-in");
    let plans = continuity_plan(
        "vol-a",
        &[ContinuitySignal::MustScanSubDirs],
        std::slice::from_ref(&moved_in),
    );
    assert_eq!(plans.len(), 1);
    assert!(plans[0].recursive);
    assert!(
        plans[0].scope_key.starts_with("path:vol-a:"),
        "{}",
        plans[0].scope_key
    );
    assert_eq!(
        parse_subtree_scope_key(&plans[0].scope_key),
        Some(("vol-a".to_string(), moved_in.clone()))
    );
    let scheduler = dir_scope_for_subtree_key(&plans[0].scope_key).expect("mapped scope");
    assert_eq!(scheduler, scope_key_for_dir(&moved_in));
    assert_eq!(parse_scope_key(&scheduler), Some(ScopeRef::Dir(moved_in)));
    let plain = continuity_plan("vol-a", &[], &[PathBuf::from("/a/new-clone")]);
    assert_eq!(plain.len(), 2);
    for plan in &plain {
        let scheduler = dir_scope_for_subtree_key(&plan.scope_key).expect("mapped scope");
        assert!(
            matches!(parse_scope_key(&scheduler), Some(ScopeRef::Dir(_))),
            "{}",
            plan.scope_key
        );
    }

    // Store level: invalidating the scheduler scope a planner key
    // denotes schedules work whose scope the scheduler codec resolves
    // to the original path.
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let now = now_ms();
        let generation = store
            .create_generation("machine", "running", None, now)
            .await
            .expect("generation");
        let path = PathBuf::from("/watched/new-clone");
        let planner = subtree_scope_key("vol-a", &path);
        let scheduler = dir_scope_for_subtree_key(&planner).expect("mapped scope");
        assert_eq!(scheduler, scope_key_for_dir(&path));
        assert_eq!(
            store
                .invalidate_scope(&scheduler, generation, now)
                .await
                .expect("inv"),
            1
        );
        assert_eq!(store.pending_count(generation).await.expect("pending"), 1);
        let claimed = store
            .claim_tasks(store.epoch(), 8, 60_000, now)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(
            parse_scope_key(&claimed[0].task.scope_key),
            Some(ScopeRef::Dir(path))
        );
    });
}

// ---------------------------------------------------------------------------
// RSF-88BA: fallback runs the feature probe, not version alone
// ---------------------------------------------------------------------------

/// Write an executable `git` wrapper fixture answering `--version` with
/// `banner` and every other invocation with `probe_body` (exit code +
/// stdout/stderr text for the feature probe).
#[cfg(unix)]
fn git_wrapper(dir: &std::path::Path, name: &str, banner: &str, probe_body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    let script = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then\n\
         echo \"{banner}\"\n\
         exit 0\n\
         fi\n\
         {probe_body}\n"
    );
    repo_scan::privacy::private_write_0600(&path, script.as_bytes()).expect("write wrapper");
    let mut perms = std::fs::metadata(&path).expect("meta").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod");
    path
}

#[cfg(unix)]
#[test]
fn rsf_88ba_feature_probe_hidden_option_is_not_capable() {
    use repo_scan::git::fallback::FallbackGit;
    // Wrapper reports a modern version but hides/rejects the required
    // option: version alone would misclassify it as capable.
    let dir = tempfile::tempdir().expect("tempdir");
    let git = git_wrapper(
        dir.path(),
        "git",
        "git version 2.47.1",
        "echo \"error: unknown option\" >&2\nexit 129",
    );
    let found = FallbackGit::probe(&git).expect("probe answers --version");
    assert!(found.capabilities().version.starts_with("git version "));
    assert_eq!(found.capabilities().version_tuple, (2, 47, 1));
    assert!(!found.capabilities().feature_probe_ok);
    assert!(
        !found.capabilities().porcelain_v2,
        "hidden option must read as incapable despite the version"
    );
}

#[cfg(unix)]
#[test]
fn rsf_88ba_feature_probe_version_backport_mismatch_is_not_capable() {
    use repo_scan::git::fallback::FallbackGit;
    // Vendor backport: newest banner, old option set rejecting v2.
    let dir = tempfile::tempdir().expect("tempdir");
    let git = git_wrapper(
        dir.path(),
        "git",
        "git version 2.50.0.vfs.1.1",
        "echo 'error: unknown option porcelain-v2' >&2\nexit 129",
    );
    let found = FallbackGit::probe(&git).expect("probe answers --version");
    assert_eq!(found.capabilities().version_tuple, (2, 50, 0));
    assert!(!found.capabilities().feature_probe_ok);
    assert!(
        !found.capabilities().porcelain_v2,
        "backport mismatch must read as incapable despite the banner"
    );
}

#[cfg(unix)]
#[test]
fn rsf_88ba_feature_probe_working_wrapper_is_capable() {
    use repo_scan::git::fallback::FallbackGit;
    // Control: version floor plus a passing probe reads as capable.
    let dir = tempfile::tempdir().expect("tempdir");
    let git = git_wrapper(
        dir.path(),
        "git",
        "git version 2.47.1",
        "echo \" --porcelain[<version>]  machine-readable output\"\nexit 0",
    );
    let found = FallbackGit::probe(&git).expect("probe answers --version");
    assert!(found.capabilities().feature_probe_ok);
    assert!(found.capabilities().porcelain_v2);
}

#[test]
fn rsf_88ba_feature_probe_real_git_is_capable() {
    use repo_scan::git::fallback::FallbackGit;
    // Production path: discover the installed git and prove the real
    // probe passes on it (no fixture standing in for the binary).
    let Some(found) = FallbackGit::discover(&[]) else {
        eprintln!("skip: no installed git");
        return;
    };
    let caps = found.capabilities();
    assert!(caps.version.starts_with("git version "), "{}", caps.version);
    assert!(
        caps.feature_probe_ok,
        "real git ({}) must pass the status --porcelain=v2 --help probe",
        caps.version
    );
    assert!(
        caps.porcelain_v2,
        "real git ({}) must read as porcelain-v2 capable",
        caps.version
    );
}
