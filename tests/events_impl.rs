//! Incremental-events acceptance (spec §13, EVENT-01/EVENT-02).
//!
//! Portable tests run on every target through fixtures: cursor crash
//! points (kill between ingest and reconcile), coalescing bounds,
//! history-loss invalidation, own-bookkeeping identity, per-volume
//! boundaries, the poll-free fallback, and while-stopped resume via
//! Turso cursor persistence.
//!
//! Linux expectations: no live FSEvents exists, so scripted
//! [`repo_scan::platform::EventSource`] replays plus the memory journal
//! cover the protocol logic; the `live_*` tests below are compiled out.
//! macOS adds `live_*` tests asserting real history-UUID round-trips and
//! stream open against the native `objc2-core-services` stack.

use repo_scan::config::scope_key_for_dir;
use repo_scan::events::{
    coalesce_invalidations, continuity_plan, decide_open, dir_scope_for_subtree_key,
    journal_cursor_string, monitor_volumes, parse_journal_cursor, portable, subtree_scope_key,
    validate_live_progress, volume_cursor_from_rows, BatchCoalescer, BookkeepingClass,
    ContinuitySignal, CursorJournal, EventBatch, EventCursorId, HistoryUuid, MemoryCursorJournal,
    MemorySink, OpenDecision, RawFlags, Reconciler, VolumeCursor, WorkChecker, MAX_BATCH_BYTES,
    MAX_BATCH_EVENTS,
};
use repo_scan::platform::{EventBatchIter, EventSource, VolumeId};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

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

/// Scripted `EventSource` replay (fixture twin of `MockLogSource`, usable
/// on every target including macOS).
struct ScriptSource {
    script: VecDeque<EventBatch>,
}

struct ScriptIter {
    script: VecDeque<EventBatch>,
}

impl EventBatchIter for ScriptIter {
    fn next_batch(&mut self) -> repo_scan::Result<Option<EventBatch>> {
        Ok(self.script.pop_front())
    }
}

impl EventSource for ScriptSource {
    fn open_stream(
        &mut self,
        _volume: &VolumeId,
        _stored: Option<VolumeCursor>,
    ) -> repo_scan::Result<(EventCursorId, Box<dyn EventBatchIter>)> {
        let high_water = self
            .script
            .iter()
            .map(|b| b.high_water.0)
            .max()
            .unwrap_or(0);
        let script = std::mem::take(&mut self.script);
        Ok((EventCursorId(high_water), Box::new(ScriptIter { script })))
    }
}

#[test]
fn open_rule_matrix() {
    let stored = stored_cursor("uuid-a", 100, 90);
    // Match + live at/above stored: resume from the stored cursor.
    assert_eq!(
        decide_open(Some(&stored), Some("uuid-a"), 100),
        OpenDecision::Resume {
            since: EventCursorId(100)
        }
    );
    assert_eq!(
        decide_open(Some(&stored), Some("uuid-a"), 500),
        OpenDecision::Resume {
            since: EventCursorId(100)
        }
    );
    // UUID mismatch: discard, invalidate.
    assert_eq!(
        decide_open(Some(&stored), Some("uuid-b"), 500),
        OpenDecision::Fresh {
            history_invalid: true,
            eventless: false
        }
    );
    // Live ID below stored: backup-restore/wrap/purge, invalid.
    assert_eq!(
        decide_open(Some(&stored), Some("uuid-a"), 50),
        OpenDecision::Fresh {
            history_invalid: true,
            eventless: false
        }
    );
    assert!(validate_live_progress(Some(EventCursorId(100)), 50).is_err());
    assert!(validate_live_progress(Some(EventCursorId(100)), 100).is_ok());
    // NULL live UUID with stored history: eventless + invalid.
    assert_eq!(
        decide_open(Some(&stored), None, 0),
        OpenDecision::Fresh {
            history_invalid: true,
            eventless: true
        }
    );
    // First run: fresh baseline, nothing to invalidate.
    assert_eq!(
        decide_open(None, Some("uuid-a"), 500),
        OpenDecision::Fresh {
            history_invalid: false,
            eventless: false
        }
    );
    // Previously eventless, history now present: fresh, not invalid.
    let eventless = VolumeCursor::default();
    assert_eq!(
        decide_open(Some(&eventless), Some("uuid-a"), 500),
        OpenDecision::Fresh {
            history_invalid: false,
            eventless: false
        }
    );
}

#[test]
fn cursor_string_round_trip() {
    assert_eq!(journal_cursor_string(EventCursorId(12345)), "12345");
    assert_eq!(parse_journal_cursor("12345"), Some(EventCursorId(12345)));
    assert_eq!(parse_journal_cursor("garbage"), None);
    assert_eq!(parse_journal_cursor(""), None);
}

#[test]
fn ingest_then_kill_before_reconcile_loses_no_work() {
    // Crash point 1: kill after durable ingest, before any reconcile.
    // Reopening must find ingested=100, reconciled unset, and the pending
    // boundary intact; reconciliation then completes normally.
    let mut journal = MemoryCursorJournal::new();
    journal.record_open("vol-a", Some(HistoryUuid("uuid-a".into())), None);
    let record = journal
        .record_ingested(
            "vol-a",
            Some(&HistoryUuid("uuid-a".into())),
            EventCursorId(100),
            &["path:vol-a:/tmp/x".to_string()],
            &[],
        )
        .expect("ingest");
    assert!(!record.duplicate);
    assert_eq!(record.advanced_to, Some(EventCursorId(100)));

    // --- simulated kill: drop everything except the durable journal ---
    let mut reopened = Reconciler::new(journal);
    let loaded = reopened.journal().load("vol-a").expect("cursor row");
    assert_eq!(loaded.ingested, Some(EventCursorId(100)));
    assert_eq!(loaded.reconciled, None);
    let pending = reopened.journal().pending("vol-a");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].cursor, EventCursorId(100));

    // Reconcile replays the recorded work idempotently.
    let mut sink = MemorySink::new();
    let outcome = reopened
        .reconcile_volume("vol-a", &mut sink)
        .expect("reconcile");
    assert_eq!(outcome.invalidated_scopes, ["path:vol-a:/tmp/x"]);
    assert_eq!(outcome.reconciled_through, None); // work still outstanding
    for scope in outcome.invalidated_scopes {
        sink.complete_scope(&scope);
    }
    let advanced = reopened
        .try_advance_reconciled("vol-a", &sink)
        .expect("advance");
    assert_eq!(advanced, Some(EventCursorId(100)));
    assert!(reopened.journal().pending("vol-a").is_empty());
}

#[test]
fn reconcile_advances_only_when_work_done() {
    // Two ingested boundaries; only the first boundary's work completes.
    // Reconciled must stop at the contiguous satisfied prefix (100, not
    // 200); no gap-skipping.
    let mut r = Reconciler::new(MemoryCursorJournal::new());
    r.note_stream_opened(
        "vol-a",
        None,
        Some(&HistoryUuid("u".into())),
        5,
        EventCursorId(200),
    );
    r.begin_traversal().expect("traverse");
    r.ingest(&batch("vol-a", 100, &["/a"])).expect("ingest 100");
    r.ingest(&batch("vol-a", 200, &["/b"])).expect("ingest 200");

    let mut sink = MemorySink::new();
    let outcome = r.reconcile_volume("vol-a", &mut sink).expect("reconcile");
    assert!(!outcome.invalidated_scopes.is_empty());

    // Complete only the scopes belonging to boundary 100.
    let first: Vec<String> = r
        .journal()
        .pending("vol-a")
        .into_iter()
        .find(|p| p.cursor == EventCursorId(100))
        .expect("boundary 100")
        .scopes;
    for scope in &first {
        sink.complete_scope(scope);
    }
    let advanced = r.try_advance_reconciled("vol-a", &sink).expect("advance");
    assert_eq!(advanced, Some(EventCursorId(100)));

    // Boundary 200 still pending: claim at boundary 200 fails.
    assert!(r.claim_volume_complete("vol-a").is_err());
    // Finish the rest: contiguous advance reaches 200, claim succeeds.
    for scope in sink.pending_scopes() {
        sink.complete_scope(&scope);
    }
    let advanced = r.try_advance_reconciled("vol-a", &sink).expect("advance");
    assert_eq!(advanced, Some(EventCursorId(200)));
    r.claim_volume_complete("vol-a").expect("claim");
}

#[test]
fn reconcile_never_runs_ahead_of_ingest() {
    let mut journal = MemoryCursorJournal::new();
    journal.record_open("vol-a", Some(HistoryUuid("u".into())), None);
    let err = journal
        .mark_reconciled_through("vol-a", EventCursorId(50))
        .expect_err("reconcile ahead of ingest must fail");
    assert!(err.to_string().contains("reconcile-ahead-of-ingest"));
}

#[test]
fn duplicate_history_replay_is_idempotent() {
    // FullHistory overlap: the first chunk contains IDs at/below sinceWhen.
    // Re-ingesting them must be a duplicate no-op, never new work.
    let mut journal = MemoryCursorJournal::new();
    journal.record_open("vol-a", Some(HistoryUuid("u".into())), None);
    let uuid = HistoryUuid("u".into());
    journal
        .record_ingested("vol-a", Some(&uuid), EventCursorId(100), &["s".into()], &[])
        .expect("first");
    let replay = journal
        .record_ingested("vol-a", Some(&uuid), EventCursorId(100), &["s".into()], &[])
        .expect("replay");
    assert!(replay.duplicate);
    let older = journal
        .record_ingested("vol-a", Some(&uuid), EventCursorId(40), &["s".into()], &[])
        .expect("older overlap");
    assert!(older.duplicate);
    assert_eq!(journal.pending("vol-a").len(), 1);
}

#[test]
fn root_changed_id_zero_never_persisted() {
    // RootChanged carries event ID 0: scopes recorded, cursor untouched.
    let mut r = Reconciler::new(MemoryCursorJournal::new());
    r.note_stream_opened(
        "vol-a",
        None,
        Some(&HistoryUuid("u".into())),
        9,
        EventCursorId(9),
    );
    let zero = EventBatch {
        volume_key: "vol-a".to_string(),
        high_water: EventCursorId(0),
        invalidations: [PathBuf::from("/watched/root")].into(),
        history_done: false,
        signals: vec![ContinuitySignal::RootChanged],
    };
    let outcome = r.ingest(&zero).expect("ingest");
    assert!(!outcome.duplicate);
    let loaded = r.journal().load("vol-a").expect("row");
    assert_eq!(loaded.ingested, None);
    assert!(loaded.flags_seen.iter().any(|f| f == "root-changed"));
    assert!(outcome.plans.iter().any(|p| p.recursive));
}

#[test]
fn coalescing_bounds() {
    // Ancestor collapse: nested paths under one ancestor become one.
    let nested: Vec<PathBuf> = [
        "/a",
        "/a/b",
        "/a/b/c",
        "/a/b/c/d.txt",
        "/other",
        "/other/deep/x",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    assert_eq!(
        coalesce_invalidations(nested),
        [PathBuf::from("/a"), PathBuf::from("/other")]
    );

    // Batch entry bound: 256 entries, then overflow coalesces to a
    // volume-wide MustScanSubDirs signal.
    let mut coal = BatchCoalescer::new("vol-a");
    for i in 1..=300u64 {
        coal.push(format!("/burst/{i}").into_bytes(), i, &RawFlags::none());
    }
    assert!(coal.overflowed());
    let done = coal.finish().expect("batch");
    assert_eq!(done.invalidations.len(), MAX_BATCH_EVENTS);
    assert_eq!(done.high_water, EventCursorId(256));
    assert!(done.signals.contains(&ContinuitySignal::MustScanSubDirs));

    // Batch byte bound: 256 KiB flushes first on huge paths.
    let mut coal = BatchCoalescer::new("vol-a");
    let huge = vec![b'x'; MAX_BATCH_BYTES + 1];
    coal.push(huge, 7, &RawFlags::none());
    coal.push(b"/after".to_vec(), 8, &RawFlags::none());
    assert!(coal.overflowed());
    let done = coal.finish().expect("batch");
    assert_eq!(done.high_water, EventCursorId(7));

    // HistoryDone sentinel: path ignored, flag set.
    let mut coal = BatchCoalescer::new("vol-a");
    coal.push(
        b"/ignored".to_vec(),
        99,
        &RawFlags {
            history_done: true,
            ..RawFlags::none()
        },
    );
    let done = coal.finish().expect("batch");
    assert!(done.history_done);
    assert!(done.invalidations.is_empty());

    // Wrap flag maps to HistoryInvalid; dropped alone is audit-only.
    let mut coal = BatchCoalescer::new("vol-a");
    coal.push(
        b"/w".to_vec(),
        3,
        &RawFlags {
            ids_wrapped: true,
            ..RawFlags::none()
        },
    );
    let done = coal.finish().expect("batch");
    assert!(done.signals.contains(&ContinuitySignal::HistoryInvalid));
    let mut coal = BatchCoalescer::new("vol-a");
    coal.push(
        b"/d".to_vec(),
        4,
        &RawFlags {
            dropped: true,
            ..RawFlags::none()
        },
    );
    let done = coal.finish().expect("batch");
    assert!(done.signals.is_empty());
    assert_eq!(done.invalidations.len(), 1);

    // Empty coalescer finishes to None (nothing observed).
    assert!(BatchCoalescer::new("vol-a").finish().is_none());
}

#[test]
fn history_loss_invalidates_scope() {
    // Signal path: HistoryInvalid discards cursors and plans a
    // volume-wide recursive rescan; per-path plans are never trusted.
    let mut r = Reconciler::new(MemoryCursorJournal::new());
    r.note_stream_opened(
        "vol-a",
        Some(&stored_cursor("uuid-a", 100, 100)),
        Some(&HistoryUuid("uuid-a".into())),
        150,
        EventCursorId(150),
    );
    let bad = EventBatch {
        volume_key: "vol-a".to_string(),
        high_water: EventCursorId(160),
        invalidations: [PathBuf::from("/some/path")].into(),
        history_done: false,
        signals: vec![ContinuitySignal::HistoryInvalid],
    };
    let outcome = r.ingest(&bad).expect("ingest");
    assert!(outcome.history_invalid);
    assert_eq!(outcome.advanced_to, None);
    assert_eq!(outcome.plans.len(), 1);
    assert!(outcome.plans[0].recursive);
    assert!(outcome.plans[0].scope_key.starts_with("volume:vol-a"));
    let loaded = r.journal().load("vol-a").expect("row");
    assert_eq!(loaded.uuid, None);
    assert_eq!(loaded.ingested, None);
    assert!(r.claim_volume_complete("vol-a").is_err());

    // Journal path: a batch UUID disagreeing with the recorded UUID is
    // rejected until the caller invalidates first.
    let mut journal = MemoryCursorJournal::new();
    journal.record_open("vol-b", Some(HistoryUuid("uuid-1".into())), None);
    let err = journal
        .record_ingested(
            "vol-b",
            Some(&HistoryUuid("uuid-2".into())),
            EventCursorId(10),
            &[],
            &[],
        )
        .expect_err("uuid disagreement must fail");
    assert!(err.to_string().contains("history-invalid"));
}

#[test]
fn subtree_invalidation_plans() {
    // MustScanSubDirs: recursive re-inspection of exactly that subtree.
    let plans = continuity_plan(
        "vol-a",
        &[ContinuitySignal::MustScanSubDirs],
        &[PathBuf::from("/moved/in")],
    );
    assert_eq!(plans.len(), 1);
    assert!(plans[0].recursive);
    // Exact planner key plus planner-to-scheduler `dir:` agreement.
    let moved_in = Path::new("/moved/in");
    assert_eq!(plans[0].scope_key, subtree_scope_key("vol-a", moved_in));
    assert_eq!(
        dir_scope_for_subtree_key(&plans[0].scope_key),
        Some(scope_key_for_dir(moved_in)),
        "{}",
        plans[0].scope_key
    );

    // Overflow form: MustScanSubDirs with no paths means the watched roots.
    let plans = continuity_plan("vol-a", &[ContinuitySignal::MustScanSubDirs], &[]);
    assert_eq!(plans.len(), 1);
    assert!(plans[0].recursive);
    assert_eq!(plans[0].scope_key, "volume:vol-a");

    // Plain change: path scope plus parent scope (created/moved-in
    // discovery by re-enumeration).
    let plans = continuity_plan("vol-a", &[], &[PathBuf::from("/a/new-clone")]);
    assert_eq!(plans.len(), 2);

    // Mount change adds a mount-table refresh scope.
    let plans = continuity_plan(
        "vol-a",
        &[ContinuitySignal::MountChanged],
        &[PathBuf::from("/mnt/x")],
    );
    assert!(plans.iter().any(|p| p.scope_key == "mounts"));

    // Pending cap overflow collapses to one volume-wide rescan.
    let many: Vec<PathBuf> = (0..5000)
        .map(|i| PathBuf::from(format!("/many/{i}")))
        .collect();
    let plans = continuity_plan("vol-a", &[], &many);
    assert_eq!(plans.len(), 1);
    assert!(plans[0].recursive);
    assert_eq!(plans[0].scope_key, "volume:vol-a");
}

#[test]
fn own_bookkeeping_exact_identity_never_parent_exclusion() {
    use repo_scan::events::OwnBookkeeping;

    let tmp = tempfile::tempdir().expect("tempdir");
    let state_file = tmp.path().join("catalog.db");
    repo_scan::privacy::private_write_0600(&state_file, b"state").unwrap();
    let sibling = tmp.path().join("other.db");
    repo_scan::privacy::private_write_0600(&sibling, b"other").unwrap();

    let mut own = OwnBookkeeping::new();
    let id = own.register(&state_file).expect("register");
    assert_eq!(own.len(), 1);

    // The exact file suppresses, with its registered path as evidence.
    assert_eq!(own.classify(&state_file), BookkeepingClass::Own(id));
    assert_eq!(own.registered_path(&id), Some(state_file.as_path()));

    // Same parent, different identity: never suppressed.
    assert_eq!(own.classify(&sibling), BookkeepingClass::Foreign);

    // Registering a directory never suppresses its children.
    let subdir = tmp.path().join("payload");
    repo_scan::privacy::private_dir_0700(&subdir).unwrap();
    let child = subdir.join("wal");
    repo_scan::privacy::private_write_0600(&child, b"wal").unwrap();
    own.register(&subdir).expect("register dir");
    assert_eq!(own.classify(&child), BookkeepingClass::Foreign);

    // Identity follows the file, not the path: a hard link to the same
    // object suppresses too.
    #[cfg(unix)]
    {
        let link = tmp.path().join("catalog-hardlink.db");
        std::fs::hard_link(&state_file, &link).unwrap();
        assert_eq!(own.classify(&link), BookkeepingClass::Own(id));
    }

    // Missing or unobservable paths reconcile normally (never suppressed).
    assert_eq!(
        own.classify(&tmp.path().join("does-not-exist")),
        BookkeepingClass::Unknown
    );
}

#[test]
fn ingest_suppresses_only_exact_own_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_file = tmp.path().join("catalog.db");
    repo_scan::privacy::private_write_0600(&state_file, b"state").unwrap();

    let mut r = Reconciler::new(MemoryCursorJournal::new());
    r.note_stream_opened(
        "vol-a",
        None,
        Some(&HistoryUuid("u".into())),
        1,
        EventCursorId(1),
    );
    r.own_bookkeeping_mut()
        .register(&state_file)
        .expect("register");
    let foreign_missing = tmp.path().join("not-observed");
    let outcome = r
        .ingest(&EventBatch {
            volume_key: "vol-a".to_string(),
            high_water: EventCursorId(10),
            invalidations: vec![state_file.clone(), foreign_missing.clone()],
            history_done: false,
            signals: Vec::new(),
        })
        .expect("ingest");
    assert_eq!(outcome.suppressed_own, 1);
    // Only the foreign path (plus its parent) produced plans.
    for plan in &outcome.plans {
        assert!(
            !plan.scope_key.contains("catalog.db"),
            "own file leaked: {}",
            plan.scope_key
        );
    }
    assert!(!outcome.plans.is_empty());
}

#[test]
fn per_volume_boundaries_are_independent() {
    // Volume A reconciles to its boundary and claims complete while
    // volume B still has outstanding work: no global-quiet wait.
    let mut r = Reconciler::new(MemoryCursorJournal::new());
    r.note_stream_opened(
        "vol-a",
        None,
        Some(&HistoryUuid("ua".into())),
        50,
        EventCursorId(50),
    );
    r.note_stream_opened(
        "vol-b",
        None,
        Some(&HistoryUuid("ub".into())),
        70,
        EventCursorId(70),
    );
    r.begin_traversal().expect("traverse");
    r.ingest(&batch("vol-a", 50, &["/a/x"])).expect("ingest a");
    r.ingest(&batch("vol-b", 60, &["/b/y"])).expect("ingest b");

    let mut sink = MemorySink::new();
    r.reconcile_volume("vol-a", &mut sink).expect("reconcile a");
    r.reconcile_volume("vol-b", &mut sink).expect("reconcile b");

    // Complete only A's scopes: A advances and claims; B cannot.
    let a_scopes: Vec<String> = r
        .journal()
        .pending("vol-a")
        .into_iter()
        .flat_map(|p| p.scopes)
        .collect();
    for scope in &a_scopes {
        sink.complete_scope(scope);
    }
    assert_eq!(
        r.try_advance_reconciled("vol-a", &sink).expect("advance a"),
        Some(EventCursorId(50))
    );
    r.claim_volume_complete("vol-a").expect("claim a");
    assert!(r.claim_volume_complete("vol-b").is_err());
}

#[test]
fn monitor_before_traverse_and_reconcile_before_claim() {
    // Traversal with nothing monitored is rejected.
    let mut r = Reconciler::new(MemoryCursorJournal::new());
    let err = r.begin_traversal().expect_err("unmonitored traverse");
    assert!(err.to_string().contains("monitor-before-traverse"));

    // Claims before traversal began are rejected even when monitored.
    r.note_stream_opened(
        "vol-a",
        None,
        Some(&HistoryUuid("u".into())),
        1,
        EventCursorId(1),
    );
    assert!(r.claim_volume_complete("vol-a").is_err());

    // Eventless volumes can never claim event completeness.
    r.begin_traversal().expect("traverse");
    r.note_stream_opened("vol-e", None, None, 0, EventCursorId(0));
    let err = r
        .claim_volume_complete("vol-e")
        .expect_err("eventless claim");
    assert!(err.to_string().contains("reconcile-before-claim"));
}

#[test]
fn portable_fallback_is_deterministic_and_poll_free() {
    // Pure mapping: same inputs, same plan; no clock, no IO, no threads.
    let a = portable::plan_unavailable_history("vol-x", "NULL UUID");
    let b = portable::plan_unavailable_history("vol-x", "NULL UUID");
    assert_eq!(a, b);
    assert_eq!(a.gap_category, portable::UNAVAILABLE_HISTORY_CATEGORY);
    assert_eq!(a.gap_category, "unavailable-history");
    assert!(a.gap_detail.contains("vol-x"));
    assert_eq!(a.reconcile_scope, "volume:vol-x");

    // Applying schedules reconciliation scope through any sink.
    let mut sink = MemorySink::new();
    a.apply(&mut sink).expect("apply");
    assert_eq!(sink.revision("volume:vol-x"), 1);
    assert_eq!(sink.pending_for_scope("volume:vol-x"), 1);
}

#[test]
fn scripted_source_end_to_end() {
    // Monitor (before traversal) -> ingest -> reconcile -> claim, driven
    // by a scripted EventSource on every target.
    let script = vec![
        batch("vol-a", 10, &["/a/new-clone"]),
        EventBatch {
            volume_key: "vol-a".to_string(),
            high_water: EventCursorId(20),
            invalidations: vec![PathBuf::from("/a/moved-in")],
            history_done: true,
            signals: vec![ContinuitySignal::MustScanSubDirs],
        },
    ];
    let mut source = ScriptSource {
        script: script.into(),
    };
    let volumes = vec![VolumeId("vol-a".to_string())];
    let monitored = monitor_volumes(&mut source, &volumes, &HashMap::new()).expect("monitor");
    assert_eq!(monitored.len(), 1);
    assert_eq!(monitored[0].boundary, EventCursorId(20));

    let mut r = Reconciler::new(MemoryCursorJournal::new());
    r.note_stream_opened(
        "vol-a",
        None,
        Some(&HistoryUuid("uuid-a".into())),
        20,
        monitored[0].boundary,
    );
    r.begin_traversal().expect("traverse");
    let mut monitored = monitored;
    while let Some(batch) = monitored[0].batches.next_batch().expect("batch") {
        r.ingest(&batch).expect("ingest");
    }
    let loaded = r.journal().load("vol-a").expect("row");
    assert_eq!(loaded.ingested, Some(EventCursorId(20)));

    let mut sink = MemorySink::new();
    let outcome = r.reconcile_volume("vol-a", &mut sink).expect("reconcile");
    // Exact planner key for the moved-in subtree, plus planner-to-scheduler
    // `dir:` agreement through the total mapping.
    let moved_in = Path::new("/a/moved-in");
    let planner_key = subtree_scope_key("vol-a", moved_in);
    assert!(
        outcome.invalidated_scopes.contains(&planner_key),
        "{:?}",
        outcome.invalidated_scopes
    );
    assert_eq!(
        dir_scope_for_subtree_key(&planner_key),
        Some(scope_key_for_dir(moved_in)),
        "{planner_key}"
    );
    for scope in sink.pending_scopes() {
        sink.complete_scope(&scope);
    }
    assert_eq!(
        r.try_advance_reconciled("vol-a", &sink).expect("advance"),
        Some(EventCursorId(20))
    );
    r.claim_volume_complete("vol-a").expect("claim");
}

#[test]
fn while_stopped_changes_resume_from_persisted_cursors() {
    // While-stopped demo at the durable layer: ingest commits survive the
    // restart, reconcile commits survive separately, and the next run
    // resumes history from the persisted ingested cursor (no rescan of
    // reconciled range, no loss of unreconciled range).
    use repo_scan::store::{now_ms, Store, TursoStore};

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("payload").join("catalog.db");
        let now = now_ms();

        // First run: ingest two boundaries, reconcile only the first.
        let store = TursoStore::open(&db).await.expect("open");
        for cursor in [100u64, 200u64] {
            let fresh = store
                .append_event(
                    "vol-a",
                    "uuid-a",
                    &journal_cursor_string(EventCursorId(cursor)),
                    true,
                    now,
                )
                .await
                .expect("append");
            assert!(fresh);
        }
        // FullHistory replay at the durable layer: duplicate is a no-op.
        let dup = store
            .append_event("vol-a", "uuid-a", "100", true, now)
            .await
            .expect("dup");
        assert!(!dup);
        let rows = store.list_events("vol-a", "uuid-a").await.expect("list");
        assert_eq!(rows.len(), 2);
        let first_id = rows.iter().find(|r| r.cursor == "100").expect("row 100").id;
        store.mark_event_reconciled(first_id).await.expect("mark");
        drop(store);

        // --- process stopped here; changes accumulate; restart resumes ---
        let store = TursoStore::open(&db).await.expect("reopen");
        let rows = store.list_events("vol-a", "uuid-a").await.expect("list");
        let cursor = volume_cursor_from_rows("vol-a", &rows).expect("cursor");
        assert_eq!(cursor.uuid, Some(HistoryUuid("uuid-a".into())));
        assert_eq!(cursor.ingested, Some(EventCursorId(200)));
        assert_eq!(cursor.reconciled, Some(EventCursorId(100)));

        // Same UUID, live ahead: resume history from ingested (200).
        assert_eq!(
            decide_open(Some(&cursor), Some("uuid-a"), 260),
            OpenDecision::Resume {
                since: EventCursorId(200)
            }
        );
        // Replaced volume (UUID changed): invalidate, never reuse.
        assert!(decide_open(Some(&cursor), Some("uuid-b"), 260).history_invalid());

        // Finish reconciliation; cursors agree.
        let second_id = rows.iter().find(|r| r.cursor == "200").expect("row 200").id;
        store.mark_event_reconciled(second_id).await.expect("mark");
        let rows = store.list_events("vol-a", "uuid-a").await.expect("list");
        let cursor = volume_cursor_from_rows("vol-a", &rows).expect("cursor");
        assert_eq!(cursor.reconciled, Some(EventCursorId(200)));
    });
}

#[test]
fn eventless_fallback_gap_is_durable_and_reportable() {
    use repo_scan::store::{now_ms, Store, TursoStore};

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let now = now_ms();

        let plan = portable::plan_unavailable_history("vol-e", "NULL UUID");
        store
            .record_error(
                "gap:volume:vol-e",
                &plan.reconcile_scope,
                plan.gap_category,
                &plan.gap_detail,
                None,
                now,
            )
            .await
            .expect("gap");
        let row = store
            .get_error("gap:volume:vol-e")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(row.category, "unavailable-history");
        assert!(row.open);
        assert_eq!(row.scope_key, "volume:vol-e");
    });
}

/// Native macOS evidence: live history UUIDs are stable across reads and
/// the current event ID never regresses. A `None` UUID documents an
/// eventless volume (unsupported filesystem), not a failure. Linux
/// expectation: compiled out; the scripted-source tests above cover the
/// protocol logic without live FSEvents.
#[cfg(target_os = "macos")]
#[test]
fn live_history_uuid_round_trip() {
    use repo_scan::events::native;
    use repo_scan::platform::macos::MacOsMountTable;
    use repo_scan::platform::MountTable;

    let mounts = MacOsMountTable.mounts().expect("mounts");
    assert!(!mounts.is_empty());
    let first = &mounts[0];
    let dev = native::device_of(&first.mount_path).expect("dev");
    assert_eq!(
        native::live_history_uuid(dev),
        native::live_history_uuid(dev)
    );
    let id1 = native::current_event_id();
    let id2 = native::current_event_id();
    assert!(id2.0 >= id1.0);
}

/// Native macOS evidence: a real per-volume history stream opens, pins a
/// boundary, and drains without error. Linux expectation: compiled out.
#[cfg(target_os = "macos")]
#[test]
fn live_stream_open_pins_boundary() {
    use repo_scan::events::native;
    use repo_scan::platform::macos::{FsEventsSource, MacOsMountTable};
    use repo_scan::platform::MountTable;

    let mounts = MacOsMountTable.mounts().expect("mounts");
    let first = mounts.into_iter().next().expect("one mount");
    let mut source = FsEventsSource;
    let (boundary, mut iter) = source.open_stream(&first.volume, None).expect("open");
    // Draining is best-effort (an idle volume yields None); the open +
    // boundary pin is the assertion.
    let _ = iter.next_batch().expect("drain");
    drop(iter);

    let dev = native::device_of(&first.mount_path).expect("dev");
    let live_uuid = native::live_history_uuid(dev);
    let mut r = Reconciler::new(MemoryCursorJournal::new());
    let decision = r.note_stream_opened(
        &first.volume.0,
        None,
        live_uuid.as_ref(),
        boundary.0,
        boundary,
    );
    assert!(!decision.history_invalid());
    assert_eq!(r.boundary(&first.volume.0), Some(boundary));
}

/// Native macOS evidence: stream teardown never races an in-flight
/// dispatch-queue callback. `FSEventStreamStop` is asynchronous with
/// respect to the queue, so teardown must barrier-drain the queue
/// before freeing the callback context; without the barrier, dropping
/// a stream while the volume delivers events is a use-after-free
/// (SIGSEGV observed under parallel-test load, faulting inside
/// `fsevents_callback`). Rapid open/poll/drop cycles against a
/// churning volume exercise that window; the test passes iff every
/// teardown survives. Linux expectation: compiled out.
#[cfg(target_os = "macos")]
#[test]
fn live_stream_teardown_under_callback_load() {
    use repo_scan::platform::macos::{FsEventsSource, MacOsMountTable};
    use repo_scan::platform::MountTable;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // Churn on the watched volume so callbacks are plausibly in flight
    // at teardown: cover the tempdir with its longest-prefix mount.
    // Best-effort cover — even an idle volume still exercises the
    // open/barrier-drop path every iteration.
    let dir = tempfile::tempdir().expect("tempdir");
    let churn_root = dir.path().canonicalize().expect("canonical churn");
    let mounts = MacOsMountTable.mounts().expect("mounts");
    let mount_idx = mounts
        .iter()
        .enumerate()
        .filter(|(_, m)| churn_root.starts_with(&m.mount_path))
        .max_by_key(|(_, m)| m.mount_path.as_os_str().len())
        .map(|(i, _)| i)
        .unwrap_or(0);
    let mount = mounts.into_iter().nth(mount_idx).expect("one mount");

    let stop = Arc::new(AtomicBool::new(false));
    let writer_stop = Arc::clone(&stop);
    let writer_dir = dir.path().to_path_buf();
    let writer = std::thread::spawn(move || {
        let mut i = 0u64;
        while !writer_stop.load(Ordering::Relaxed) {
            let p = writer_dir.join(format!("churn-{i}.tmp"));
            let _ = std::fs::write(&p, b"x");
            let _ = std::fs::remove_file(&p);
            i = i.wrapping_add(1);
        }
    });
    let mut source = FsEventsSource;
    for _ in 0..25 {
        let (_boundary, mut iter) = source.open_stream(&mount.volume, None).expect("open");
        // Poll while the writer churns so callbacks land mid-lifetime.
        for _ in 0..4 {
            let _ = iter.next_batch().expect("drain");
        }
        drop(iter);
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().expect("writer");
}
