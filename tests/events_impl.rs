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

// ---------------------------------------------------------------------------
// Wave1d Step 12 (consolidation slice 3, ported from B11 `7c864ad5`):
// scan-bound v2 cursors, fail-closed guarded replay pagination, v8 dedupe
// lifecycle, bounded journal retention, and the path-free opaque-ID
// projection (contracts C3/D4, ADJ-02/ADJ-03).
//
// B11 drove these through `main_under_test` hooks and the built binary.
// The consolidation pins them at the `scan_events` ↔ `store` seam — the
// layer slice 3 owns — so slice 5 can wire the CLI lanes (scan/query/
// resume/follow/TUI) to the same entry points without re-deriving semantics.
// Binary-level assertions that need the wired CLI (redirected JSONL scan
// output, `query --scan --follow` exit codes, TUI baselines, bounded
// WAL-torn-read retry loops) land with slice 5.
// ---------------------------------------------------------------------------

/// Current-thread runtime for the Turso local path (same pattern as
/// `tests/store_impl.rs`): no async services, just the waker.
fn wave1d_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

/// Owner store over a fresh tempdir catalog (schema v9 after open).
struct Wave1dStore {
    dir: tempfile::TempDir,
    rt: tokio::runtime::Runtime,
    store: repo_scan::store::TursoStore,
}

impl Wave1dStore {
    fn new() -> Self {
        use repo_scan::store::Store;
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("payload").join("catalog.db");
        let rt = wave1d_runtime();
        let store = rt
            .block_on(async { repo_scan::store::TursoStore::open(&db).await })
            .expect("open catalog");
        Self { dir, rt, store }
    }

    fn db_path(&self) -> PathBuf {
        self.dir.path().join("payload").join("catalog.db")
    }
}

/// Append one journal row (`catalog_rev` 1, offset `seq - 1`), asserting
/// the `(scan_id, seq)` insert is fresh.
async fn wave1d_append(
    store: &repo_scan::store::TursoStore,
    scan_id: &str,
    seq: u64,
    class: &str,
    op: &str,
    records: &[u8],
) {
    let appended = store
        .append_scan_event(&repo_scan::store::NewScanEvent {
            scan_id,
            seq,
            catalog_rev: 1,
            event_offset: seq - 1,
            event_type: class,
            op,
            reset: false,
            records,
        })
        .await
        .expect("append event");
    assert!(appended, "seq {seq} newly inserted");
}

/// Live `scan_event_dedupe` marker count for one scan (raw SQL, mirroring
/// `tests/store_migrate.rs`'s direct access).
async fn wave1d_dedupe_count(store: &repo_scan::store::TursoStore, scan_id: &str) -> i64 {
    let mut rows = store
        .connection()
        .query(
            "SELECT COUNT(*) FROM scan_event_dedupe WHERE scan_id = ?1",
            vec![turso::Value::Text(scan_id.to_string())],
        )
        .await
        .expect("count dedupe markers");
    let row = rows
        .next()
        .await
        .expect("count row")
        .expect("count row present");
    match row.get_value(0).expect("count value") {
        turso::Value::Integer(n) => n,
        other => panic!("COUNT(*) is an integer, got {other:?}"),
    }
}

/// Standard base64 (RFC 4648 §4, padded) for the reversible-encoding
/// canary sweep; the projection must not leak paths under ANY encoding.
fn wave1d_b64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Cursor resolution matrix through the production resolver (B11
/// `wave1d_cursor_resolution_matrix`): covered cursors resume after their
/// own `(rev, off)` position; missing, diverged, foreign, legacy, and
/// beyond-tip cursors reset; the coalescible gauge never diverges; an
/// exact terminal cursor stops the stream; corrupt text stays a usage
/// error (contract C3).
#[test]
fn wave1d_scan_cursor_resolution_matrix() {
    use repo_scan::scan_events::{resolve_after_cursor, ReplayPosition, ScanCursor};

    let hook = Wave1dStore::new();
    hook.rt.block_on(async {
        wave1d_append(
            &hook.store,
            "scan-cursor-1",
            1,
            "scan_started",
            "add",
            b"{}",
        )
        .await;
        wave1d_append(
            &hook.store,
            "scan-cursor-1",
            2,
            "discovery_progress",
            "replace",
            b"{}",
        )
        .await;
        wave1d_append(
            &hook.store,
            "scan-cursor-1",
            3,
            "location_found",
            "add",
            b"{}",
        )
        .await;
        wave1d_append(
            &hook.store,
            "scan-cursor-1",
            4,
            "scan_completed",
            "add",
            b"{}",
        )
        .await;
    });
    let resolve = |after: &str| {
        hook.rt
            .block_on(resolve_after_cursor(&hook.store, "scan-cursor-1", after))
    };
    let cursor = |seq: u64, rev: u64, off: u64| {
        ScanCursor::for_scan("scan-cursor-1", seq, rev, off).encode()
    };
    // Covered cursors resume after their own (rev, off) position.
    assert_eq!(
        resolve(&cursor(3, 1, 2)).expect("match"),
        ReplayPosition {
            after: Some((1, 2)),
            reset_first: false,
            terminal_seen: false,
        }
    );
    assert_eq!(
        resolve(&cursor(2, 1, 1)).expect("gauge match"),
        ReplayPosition {
            after: Some((1, 1)),
            reset_first: false,
            terminal_seen: false,
        }
    );
    // An exact terminal cursor stops the stream at the terminal row.
    assert_eq!(
        resolve(&cursor(4, 1, 3)).expect("terminal"),
        ReplayPosition {
            after: Some((1, 3)),
            reset_first: false,
            terminal_seen: true,
        }
    );
    // A cursor from another scan resets even when all position fields
    // collide with the target's gauge row.
    assert_eq!(
        resolve(&ScanCursor::for_scan("scan-cursor-foreign", 2, 1, 1).encode())
            .expect("foreign scan cursor"),
        ReplayPosition {
            after: None,
            reset_first: true,
            terminal_seen: false,
        }
    );
    // A later offset from another scan must not skip target rows after
    // its same-seq progress gauge.
    assert_eq!(
        resolve(&ScanCursor::for_scan("scan-cursor-foreign", 2, 1, 9).encode())
            .expect("foreign later offset"),
        ReplayPosition {
            after: None,
            reset_first: true,
            terminal_seen: false,
        }
    );
    // Legacy v1 has no scan binding and always requests a complete reset.
    let legacy = ScanCursor {
        scan_id: None,
        seq: 2,
        catalog_rev: 1,
        event_offset: 1,
    }
    .encode();
    assert_eq!(
        resolve(&legacy).expect("legacy unbound cursor"),
        ReplayPosition {
            after: None,
            reset_first: true,
            terminal_seen: false,
        }
    );
    // A drifted gauge position still resumes (never diverges): the reader
    // continues after its own position, losing nothing between.
    hook.rt.block_on(async {
        hook.store
            .connection()
            .execute(
                "UPDATE scan_events SET catalog_rev = 7, event_offset = 9 \
                    WHERE scan_id = ?1 AND seq = 2",
                vec![turso::Value::Text("scan-cursor-1".to_string())],
            )
            .await
            .expect("drift the gauge");
    });
    assert_eq!(
        resolve(&cursor(2, 1, 1)).expect("gauge drift"),
        ReplayPosition {
            after: Some((1, 1)),
            reset_first: false,
            terminal_seen: false,
        }
    );
    // A drifted record position diverges: resync with reset.
    assert_eq!(
        resolve(&cursor(3, 99, 2)).expect("diverged"),
        ReplayPosition {
            after: None,
            reset_first: true,
            terminal_seen: false,
        }
    );
    // Missing rows (pruned prefix, beyond tip): resync with reset.
    assert_eq!(
        resolve(&cursor(99, 1, 0)).expect("beyond tip"),
        ReplayPosition {
            after: None,
            reset_first: true,
            terminal_seen: false,
        }
    );
    // Seq 0 replays from the start without reset.
    assert_eq!(
        resolve(&cursor(0, 0, 0)).expect("seq 0"),
        ReplayPosition {
            after: None,
            reset_first: false,
            terminal_seen: false,
        }
    );
    // No cursor is the caller's default position (start, no reset).
    assert_eq!(
        ReplayPosition::default(),
        ReplayPosition {
            after: None,
            reset_first: false,
            terminal_seen: false,
        }
    );
    // Corrupt cursor text stays a usage error, never a silent reset.
    let corrupt = resolve("!!!not-a-cursor!!!");
    assert!(
        matches!(corrupt, Err(repo_scan::Error::InvalidArgs(_))),
        "corrupt cursor: {corrupt:?}"
    );
}

/// An expired cursor cannot reconstruct a pruned prefix (ADJ-02): the
/// guarded page fails closed instead of serving a retained tail as full
/// state (store-level core of B11 `wave1d_pruned_prefix_replay_fails_closed`;
/// the exit-1/empty-stdout CLI assertion lands with slice 5).
#[test]
fn wave1d_guarded_replay_pruned_prefix_fails_closed() {
    use repo_scan::scan_events::{
        prune_scan_events_through, read_guarded_scan_event_page, GuardedScanEventPage,
    };

    let hook = Wave1dStore::new();
    hook.rt.block_on(async {
        wave1d_append(
            &hook.store,
            "scan-prune-replay",
            1,
            "scan_started",
            "add",
            b"{}",
        )
        .await;
        wave1d_append(
            &hook.store,
            "scan-prune-replay",
            2,
            "discovery_progress",
            "replace",
            b"{}",
        )
        .await;
        for seq in 3..=6u64 {
            wave1d_append(
                &hook.store,
                "scan-prune-replay",
                seq,
                "location_found",
                "add",
                b"{}",
            )
            .await;
        }
    });

    // Intact prefix: the first page reads from the start.
    let page = hook
        .rt
        .block_on(read_guarded_scan_event_page(
            &hook.store,
            "scan-prune-replay",
            None,
            500,
        ))
        .expect("guarded page");
    let GuardedScanEventPage::Rows(rows) = page else {
        panic!("intact prefix must read, got Pruned");
    };
    assert_eq!(rows.len(), 6);

    // Expire the prefix through seq 2 (scan_started + the gauge row).
    hook.rt
        .block_on(prune_scan_events_through(
            &hook.store,
            "scan-prune-replay",
            2,
        ))
        .expect("prune prefix");

    // A fresh replay (no cursor) over a pruned prefix fails closed.
    let page = hook
        .rt
        .block_on(read_guarded_scan_event_page(
            &hook.store,
            "scan-prune-replay",
            None,
            500,
        ))
        .expect("guarded page after prune");
    assert!(
        matches!(page, GuardedScanEventPage::Pruned),
        "pruned prefix fails closed, no retained-tail masquerade"
    );
    // A cursor whose position predates the retained window also fails
    // closed (seq 2 sat at (rev 1, off 1)).
    let page = hook
        .rt
        .block_on(read_guarded_scan_event_page(
            &hook.store,
            "scan-prune-replay",
            Some((1, 1)),
            500,
        ))
        .expect("guarded page with expired cursor");
    assert!(
        matches!(page, GuardedScanEventPage::Pruned),
        "cursor before the retained window fails closed"
    );
    // A cursor at the retained window's edge resumes within it: the first
    // retained row (seq 3 at (1, 2)) is not before itself.
    let page = hook
        .rt
        .block_on(read_guarded_scan_event_page(
            &hook.store,
            "scan-prune-replay",
            Some((1, 2)),
            500,
        ))
        .expect("guarded page inside retained window");
    let GuardedScanEventPage::Rows(rows) = page else {
        panic!("in-window resume must read, got Pruned");
    };
    assert_eq!(
        rows.iter().map(|row| row.seq).collect::<Vec<_>>(),
        vec![4, 5, 6],
        "resume strictly after the cursor position inside the window"
    );
}

/// The prefix guard and the page read share ONE read-only transaction
/// (B11 `wave1d_replay_page_pins_prefix_guard_across_prune`): a concurrent
/// prune landing between them cannot change the verdict, and the rolled
/// back transaction is fully closed before the caller renders output.
#[test]
fn wave1d_guarded_replay_page_pins_prefix_guard_across_prune() {
    use repo_scan::scan_events::{read_guarded_scan_event_page_with_hook, GuardedScanEventPage};

    let hook = Wave1dStore::new();
    let scan_id = "scan-page-snapshot-prune";
    hook.rt.block_on(async {
        for seq in 1..=8u64 {
            wave1d_append(
                &hook.store,
                scan_id,
                seq,
                if seq == 1 {
                    "scan_started"
                } else {
                    "location_updated"
                },
                if seq == 1 { "add" } else { "replace" },
                b"{}",
            )
            .await;
        }
    });

    let db = hook.db_path();
    let reader = hook
        .rt
        .block_on(repo_scan::store::TursoStore::open_read_only(&db))
        .expect("open read-only reader");

    // The writer commits a prefix prune after the guard's first SELECT.
    // The page SELECT must still see the reader transaction's earlier view.
    let first = hook
        .rt
        .block_on(read_guarded_scan_event_page_with_hook(
            &reader,
            scan_id,
            None,
            2,
            || async {
                hook.store
                    .connection()
                    .execute(
                        "DELETE FROM scan_events WHERE scan_id = ?1 AND seq = 1",
                        vec![turso::Value::Text(scan_id.to_string())],
                    )
                    .await
                    .map_err(|error| repo_scan::Error::Store(error.to_string()))?;
                Ok(())
            },
        ))
        .expect("first guarded page");
    let GuardedScanEventPage::Rows(first) = first else {
        panic!("prefix remains readable in the pinned snapshot");
    };
    assert_eq!(
        first.iter().map(|row| row.seq).collect::<Vec<_>>(),
        vec![1, 2],
        "the first page includes rows deleted by the concurrent writer"
    );
    let after_first = first
        .last()
        .map(|row| (row.catalog_rev, row.event_offset))
        .expect("first page cursor");

    // On the next page, delete the remaining rows through seq 5 after its
    // guard. The page sees seq 3-4 from its pinned view; the following
    // page must reject because seq 5 was pruned before it could be read.
    let second = hook
        .rt
        .block_on(read_guarded_scan_event_page_with_hook(
            &reader,
            scan_id,
            Some(after_first),
            2,
            || async {
                hook.store
                    .connection()
                    .execute(
                        "DELETE FROM scan_events WHERE scan_id = ?1 AND seq <= 5",
                        vec![turso::Value::Text(scan_id.to_string())],
                    )
                    .await
                    .map_err(|error| repo_scan::Error::Store(error.to_string()))?;
                Ok(())
            },
        ))
        .expect("second guarded page");
    let GuardedScanEventPage::Rows(second) = second else {
        panic!("second page remains readable in the pinned snapshot");
    };
    assert_eq!(
        second.iter().map(|row| row.seq).collect::<Vec<_>>(),
        vec![3, 4],
        "the second page includes rows deleted by the concurrent writer"
    );
    let after_second = second
        .last()
        .map(|row| (row.catalog_rev, row.event_offset))
        .expect("second page cursor");

    // A read-only store pins its opening database snapshot. Reopen it
    // after the concurrent prune before asserting that a later page sees
    // the missing prefix.
    hook.rt
        .block_on(reader.close())
        .expect("close pinned reader");
    let reader = hook
        .rt
        .block_on(repo_scan::store::TursoStore::open_read_only(&db))
        .expect("reopen reader after prune");
    let later = hook
        .rt
        .block_on(read_guarded_scan_event_page_with_hook(
            &reader,
            scan_id,
            Some(after_second),
            2,
            || async { Ok(()) },
        ))
        .expect("later guarded page");
    assert!(
        matches!(later, GuardedScanEventPage::Pruned),
        "a cursor whose unseen continuation was pruned fails closed"
    );
    hook.rt.block_on(reader.close()).expect("close reader");
}

/// A multi-page replay projects each `discovery_progress_updated`
/// notification onto the coalesced gauge's NEWEST payload (C3: progress
/// coalescing retains cursor-advancing visibility), so a full replay never
/// shows the newest gauge followed by older tick snapshots (store-level
/// port of B11 `wave1d_progress_replay_notifications_stay_at_latest_gauge_across_pages`;
/// the emission-side in-place gauge coalescing is slice-5 main.rs wiring).
#[test]
fn wave1d_replay_projects_latest_gauge_across_pages() {
    use repo_scan::scan_events::read_guarded_scan_event_page;
    use repo_scan::scan_events::GuardedScanEventPage;

    let hook = Wave1dStore::new();
    let scan_id = "scan-progress-page-1";
    hook.rt.block_on(async {
        wave1d_append(&hook.store, scan_id, 1, "scan_started", "add", b"{}").await;
        // The coalesced gauge row: one row whose records advance in place.
        wave1d_append(
            &hook.store,
            scan_id,
            2,
            "discovery_progress",
            "replace",
            br#"{"tick":0}"#,
        )
        .await;
        // Cursor-advancing notifications carry their emission-time gauge.
        for seq in 3..=12u64 {
            let records = format!(r#"{{"tick":{}}}"#, seq - 2);
            wave1d_append(
                &hook.store,
                scan_id,
                seq,
                "discovery_progress_updated",
                "add",
                records.as_bytes(),
            )
            .await;
        }
        // Later ticks updated the gauge row in place (production
        // coalescing): its stored payload is the newest tick.
        hook.store
            .connection()
            .execute(
                "UPDATE scan_events SET records = ?1 WHERE scan_id = ?2 AND seq = 2",
                vec![
                    turso::Value::Blob(br#"{"tick":11}"#.to_vec()),
                    turso::Value::Text(scan_id.to_string()),
                ],
            )
            .await
            .expect("coalesce the gauge in place");
    });

    let mut after = None;
    let mut page_sizes = Vec::new();
    let mut notification_ticks = Vec::new();
    loop {
        let page = hook
            .rt
            .block_on(read_guarded_scan_event_page(&hook.store, scan_id, after, 5))
            .expect("read replay page");
        let GuardedScanEventPage::Rows(page) = page else {
            panic!("intact prefix must read");
        };
        if page.is_empty() {
            break;
        }
        page_sizes.push(page.len());
        for row in &page {
            if row.event_type == "discovery_progress_updated" {
                let records: serde_json::Value =
                    serde_json::from_slice(&row.records).expect("notification records");
                notification_ticks.push(records["tick"].as_u64().expect("tick"));
            }
        }
        after = page.last().map(|row| (row.catalog_rev, row.event_offset));
        if page.len() < 5 {
            break;
        }
    }
    assert!(
        page_sizes.len() >= 2,
        "replay crosses the page boundary: {page_sizes:?}"
    );
    assert_eq!(notification_ticks.len(), 10);
    assert!(
        notification_ticks.iter().all(|tick| *tick == 11),
        "all notifications project to the newest gauge, never regress: {notification_ticks:?}"
    );
}

/// Step 12 retention: position-based prefix prune keeps the newest
/// `keep_rows` seqs and the tip row always survives, so a finished scan's
/// terminal event is never pruned (B11 `wave1d_retention_prunes_prefix_keeping_tip`).
#[test]
fn wave1d_retention_prunes_prefix_keeping_tip() {
    use repo_scan::scan_events::{prune_scan_events_through, retention_cutoff, scan_event_count};

    let hook = Wave1dStore::new();
    hook.rt.block_on(async {
        for seq in 1..=10u64 {
            let class = match seq {
                1 => "scan_started",
                10 => "scan_completed",
                _ => "location_found",
            };
            wave1d_append(&hook.store, "scan-prune-1", seq, class, "add", b"{}").await;
        }
    });
    let cutoff = retention_cutoff(10, 4);
    assert_eq!(cutoff, 6);
    hook.rt
        .block_on(prune_scan_events_through(
            &hook.store,
            "scan-prune-1",
            cutoff,
        ))
        .expect("prune prefix");
    hook.rt.block_on(async {
        assert_eq!(
            scan_event_count(&hook.store, "scan-prune-1")
                .await
                .expect("count"),
            4,
            "newest window survives"
        );
        let rows = hook
            .store
            .read_scan_events("scan-prune-1", 0, 100)
            .await
            .expect("read");
        let seqs: Vec<u64> = rows.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![7, 8, 9, 10]);
        assert_eq!(rows.last().expect("tip").event_type, "scan_completed");
    });
    // Under the bound nothing prunes: a zero cutoff deletes nothing.
    hook.rt
        .block_on(prune_scan_events_through(
            &hook.store,
            "scan-prune-1",
            retention_cutoff(4, 50_000),
        ))
        .expect("under-bound prune is a no-op");
    hook.rt.block_on(async {
        assert_eq!(
            scan_event_count(&hook.store, "scan-prune-1")
                .await
                .expect("count"),
            4
        );
    });
}

/// v8 dedupe lifecycle (C3): markers are durably buffered with their
/// events, backfilled from a retained legacy prefix, survive journal
/// prefix retention for a resumable attempt, survive non-terminal
/// appends, and are released only by the atomic terminal cleanup
/// (scan-final) — the store-level core of B11
/// `wave1d_resume_found_dedupe_survives_pruned_prefix`.
#[test]
fn wave1d_dedupe_markers_survive_prefix_prune_until_terminal() {
    use repo_scan::scan_events::{
        buffer_scan_event_dedupe, event_opaque_id, load_scan_event_dedupe,
        prune_scan_events_through,
    };
    use repo_scan::store::{NewScanEvent, WriterBatch};
    use std::collections::HashSet;

    let hook = Wave1dStore::new();
    let scan_id = "scan-dedupe-retention";
    hook.rt.block_on(async {
        wave1d_append(
            &hook.store,
            scan_id,
            1,
            "repository_found",
            "add",
            br#"{"store_id":"store-1"}"#,
        )
        .await;
        // Durable marker in the same writer batch pattern as production.
        let mut batch = WriterBatch::new();
        buffer_scan_event_dedupe(&mut batch, scan_id, "repository_found", "store-1");
        hook.store.flush(&mut batch).await.expect("flush marker");
        assert_eq!(wave1d_dedupe_count(&hook.store, scan_id).await, 1);

        // Re-delivery is idempotent (INSERT OR IGNORE).
        let mut batch = WriterBatch::new();
        buffer_scan_event_dedupe(&mut batch, scan_id, "repository_found", "store-1");
        hook.store.flush(&mut batch).await.expect("flush duplicate");
        assert_eq!(wave1d_dedupe_count(&hook.store, scan_id).await, 1);

        // Hydration marks the scan v8-ready and keeps the marker set.
        let mut found: HashSet<String> = HashSet::new();
        load_scan_event_dedupe(
            &hook.store,
            scan_id,
            true,
            &mut [("repository_found", &mut found)],
        )
        .await
        .expect("load dedupe");
        assert!(found.contains(&event_opaque_id("store-1")));

        // Retention removes the journal prefix: the markers survive
        // because the side table is not subject to journal retention.
        prune_scan_events_through(&hook.store, scan_id, 1)
            .await
            .expect("prune journal prefix");
        assert!(wave1d_dedupe_count(&hook.store, scan_id).await > 0);

        // With the v8 marker durably set, hydration from a pruned prefix
        // is safe and still suppresses the replayed found event.
        let mut found_after: HashSet<String> = HashSet::new();
        load_scan_event_dedupe(
            &hook.store,
            scan_id,
            false,
            &mut [("repository_found", &mut found_after)],
        )
        .await
        .expect("load dedupe after prune");
        assert!(found_after.contains(&event_opaque_id("store-1")));

        // A non-terminal append (the attempt is still in flight /
        // resumable) must NOT release the markers.
        let appended = hook
            .store
            .append_scan_event(&NewScanEvent {
                scan_id,
                seq: 2,
                catalog_rev: 2,
                event_offset: 0,
                event_type: "location_updated",
                op: "replace",
                reset: false,
                records: b"{}",
            })
            .await
            .expect("non-terminal append");
        assert!(appended);
        assert!(
            wave1d_dedupe_count(&hook.store, scan_id).await > 0,
            "markers retained until scan-final"
        );

        // Scan-final: the terminal append releases the markers atomically.
        let appended = hook
            .store
            .append_terminal_scan_event(&NewScanEvent {
                scan_id,
                seq: 3,
                catalog_rev: 2,
                event_offset: 1,
                event_type: "scan_completed",
                op: "add",
                reset: false,
                records: b"{}",
            })
            .await
            .expect("terminal append");
        assert!(appended);
        assert_eq!(
            wave1d_dedupe_count(&hook.store, scan_id).await,
            0,
            "terminal cleanup released the markers"
        );
        // The journal itself is retained (resume records survive).
        let rows = hook
            .store
            .read_scan_events(scan_id, 0, 100)
            .await
            .expect("read journal");
        assert_eq!(
            rows.iter().map(|row| row.seq).collect::<Vec<_>>(),
            vec![2, 3],
            "journal rows survive the terminal cleanup"
        );
    });
}

/// Terminal cleanup is atomic (C3): a failing dedupe DELETE rolls back the
/// terminal insert too, so a retry can commit both later (store-level core
/// of B11 `wave1d_terminal_event_cleans_dedupe_markers_atomically`).
#[test]
fn wave1d_terminal_cleanup_rolls_back_atomically() {
    use repo_scan::scan_events::buffer_scan_event_dedupe;
    use repo_scan::store::{NewScanEvent, WriterBatch};

    let hook = Wave1dStore::new();
    let scan_id = "scan-dedupe-terminal-cleanup";
    hook.rt.block_on(async {
        wave1d_append(&hook.store, scan_id, 1, "scan_started", "add", b"{}").await;
        let mut batch = WriterBatch::new();
        buffer_scan_event_dedupe(&mut batch, scan_id, "repository_found", "store-terminal-1");
        hook.store.flush(&mut batch).await.expect("flush marker");
        assert!(wave1d_dedupe_count(&hook.store, scan_id).await > 0);

        hook.store
            .connection()
            .execute(
                "CREATE TRIGGER fail_scan_dedupe_delete BEFORE DELETE ON scan_event_dedupe \
                 BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END",
                (),
            )
            .await
            .expect("install cleanup failure trigger");
        let failed = hook
            .store
            .append_terminal_scan_event(&NewScanEvent {
                scan_id,
                seq: 2,
                catalog_rev: 1,
                event_offset: 1,
                event_type: "scan_completed",
                op: "add",
                reset: false,
                records: b"{}",
            })
            .await;
        assert!(failed.is_err(), "injected cleanup failure aborts");
        assert!(
            wave1d_dedupe_count(&hook.store, scan_id).await > 0,
            "markers survive the rolled-back terminal"
        );
        let rows = hook
            .store
            .read_scan_events(scan_id, 0, 10)
            .await
            .expect("read after failed terminal transaction");
        assert!(
            rows.iter().all(|row| row.event_type != "scan_completed"),
            "terminal insert rolled back with the cleanup"
        );

        hook.store
            .connection()
            .execute("DROP TRIGGER fail_scan_dedupe_delete", ())
            .await
            .expect("drop cleanup failure trigger");
        let appended = hook
            .store
            .append_terminal_scan_event(&NewScanEvent {
                scan_id,
                seq: 2,
                catalog_rev: 1,
                event_offset: 1,
                event_type: "scan_completed",
                op: "add",
                reset: false,
                records: b"{}",
            })
            .await
            .expect("commit terminal and cleanup");
        assert!(appended);
        assert_eq!(wave1d_dedupe_count(&hook.store, scan_id).await, 0);
    });
}

/// The terminal append validates the event class (SLICE-1 contract):
/// non-terminal classes are rejected, terminal redelivery of the same
/// `(scan_id, seq)` is replay-once idempotent.
#[test]
fn wave1d_terminal_append_validates_class_and_replay_once() {
    use repo_scan::store::NewScanEvent;

    let hook = Wave1dStore::new();
    let scan_id = "scan-terminal-validation";
    hook.rt.block_on(async {
        let rejected = hook
            .store
            .append_terminal_scan_event(&NewScanEvent {
                scan_id,
                seq: 1,
                catalog_rev: 1,
                event_offset: 0,
                event_type: "location_found",
                op: "add",
                reset: false,
                records: b"{}",
            })
            .await;
        assert!(
            matches!(rejected, Err(repo_scan::Error::InvalidArgs(_))),
            "non-terminal class rejected: {rejected:?}"
        );
        assert!(
            hook.store
                .read_scan_events(scan_id, 0, 10)
                .await
                .expect("read")
                .is_empty(),
            "rejected terminal inserts nothing"
        );

        let first = hook
            .store
            .append_terminal_scan_event(&NewScanEvent {
                scan_id,
                seq: 1,
                catalog_rev: 1,
                event_offset: 0,
                event_type: "scan_failed",
                op: "add",
                reset: false,
                records: b"{}",
            })
            .await
            .expect("terminal append");
        assert!(first);
        let redelivered = hook
            .store
            .append_terminal_scan_event(&NewScanEvent {
                scan_id,
                seq: 1,
                catalog_rev: 1,
                event_offset: 0,
                event_type: "scan_failed",
                op: "add",
                reset: false,
                records: b"{}",
            })
            .await
            .expect("terminal redelivery");
        assert!(!redelivered, "same (scan_id, seq) redelivery is idempotent");
    });
}

/// `inventory_ready` is authoritative scan state (v7 milestone column)
/// even after its journal row falls out of the retained tail, so resume
/// never emits the milestone twice (store-level port of B11
/// `inventory_ready_survives_journal_retention_and_resume`; the journal
/// reopen/`has_ready` emission guard is slice-5 main.rs wiring).
#[test]
fn wave1d_inventory_ready_milestone_survives_journal_prune() {
    use repo_scan::scan_events::prune_scan_events_through;
    use repo_scan::store::NewScan;

    let hook = Wave1dStore::new();
    let scan_id = "scan-ready-retention-1";
    hook.rt.block_on(async {
        hook.store
            .create_scan_request(
                &NewScan {
                    id: scan_id,
                    url_raw: b"--all",
                    url_canonical: None,
                    scope: "roots",
                    status_mode: "metadata",
                    report_dest: None,
                    targets_json: None,
                    format: Some("jsonl"),
                    all_targets: Some(true),
                },
                1,
            )
            .await
            .expect("create request");
        wave1d_append(&hook.store, scan_id, 1, "scan_started", "add", b"{}").await;
        wave1d_append(&hook.store, scan_id, 2, "inventory_ready", "add", b"{}").await;
        hook.store
            .mark_scan_inventory_ready(scan_id, 2)
            .await
            .expect("mark ready");
        wave1d_append(&hook.store, scan_id, 3, "location_found", "add", b"{}").await;

        // Retention prunes the milestone's journal row.
        prune_scan_events_through(&hook.store, scan_id, 2)
            .await
            .expect("prune prefix");

        let scan = hook
            .store
            .get_scan(scan_id)
            .await
            .expect("get scan")
            .expect("scan row");
        assert_eq!(
            scan.inventory_ready_seq,
            Some(2),
            "the durable milestone survives its journal row"
        );
        let retained = hook
            .store
            .read_scan_events(scan_id, 0, 10)
            .await
            .expect("read retained tail");
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].seq, 3);
        assert_eq!(retained[0].event_type, "location_found");
    });
}

/// A catalog upgraded after its prefix was already pruned cannot recover
/// the lost found IDs: hydration fails closed instead of risking duplicate
/// `add` events on resume (B11 v8 load rule). An intact legacy prefix
/// backfills into durable markers and becomes v8-ready.
#[test]
fn wave1d_load_dedupe_fails_closed_on_pruned_legacy_prefix() {
    use repo_scan::scan_events::{
        event_opaque_id, load_scan_event_dedupe, prune_scan_events_through,
    };
    use std::collections::HashSet;

    let hook = Wave1dStore::new();
    hook.rt.block_on(async {
        // Legacy journal (pre-v8): found rows, no side markers.
        wave1d_append(
            &hook.store,
            "scan-legacy-intact",
            1,
            "repository_found",
            "add",
            br#"{"store_id":"store-legacy-1"}"#,
        )
        .await;
        wave1d_append(
            &hook.store,
            "scan-legacy-pruned",
            1,
            "repository_found",
            "add",
            br#"{"store_id":"store-legacy-2"}"#,
        )
        .await;
        wave1d_append(
            &hook.store,
            "scan-legacy-pruned",
            2,
            "location_updated",
            "replace",
            b"{}",
        )
        .await;
        prune_scan_events_through(&hook.store, "scan-legacy-pruned", 1)
            .await
            .expect("prune legacy prefix");

        // Intact prefix: the caller hydrates its dedupe set from the
        // retained journal (the production journal-open path does this),
        // then hydration backfills the marker and sets v8 state.
        let mut found: HashSet<String> = HashSet::new();
        let journal = hook
            .store
            .read_scan_events("scan-legacy-intact", 0, 10)
            .await
            .expect("read legacy journal");
        for row in &journal {
            if row.event_type == "repository_found" {
                let records: serde_json::Value =
                    serde_json::from_slice(&row.records).expect("records");
                if let Some(id) = records.get("store_id").and_then(|v| v.as_str()) {
                    found.insert(repo_scan::scan_events::event_id_from_journal(id));
                }
            }
        }
        load_scan_event_dedupe(
            &hook.store,
            "scan-legacy-intact",
            true,
            &mut [("repository_found", &mut found)],
        )
        .await
        .expect("hydrate intact legacy journal");
        assert!(
            found.contains(&event_opaque_id("store-legacy-1")),
            "legacy journal ID normalized into the durable set"
        );
        assert!(
            wave1d_dedupe_count(&hook.store, "scan-legacy-intact").await >= 2,
            "backfilled marker plus the v8 state marker"
        );

        // Pruned legacy prefix without durable markers: resume is unsafe.
        let mut never = HashSet::new();
        let refused = load_scan_event_dedupe(
            &hook.store,
            "scan-legacy-pruned",
            false,
            &mut [("repository_found", &mut never)],
        )
        .await;
        assert!(
            matches!(refused, Err(repo_scan::Error::Report(_))),
            "pruned legacy prefix fails closed: {refused:?}"
        );
    });
}

/// Event records never carry local target spellings or `file:` remotes
/// (ADJ-03; port of B11 `event_records_redact_local_targets_and_file_remotes`
/// onto the owned projection entry point).
#[test]
fn wave1d_event_records_omit_local_targets_and_file_remotes() {
    use repo_scan::scan_events::{event_safe_records, EventType};

    let path = "/tmp/LOCAL_TARGET_EVENT_CANARY/repo";
    let path_hex = repo_scan::config::encode_hex(path.as_bytes());
    let target = event_safe_records(
        EventType::ScanStarted,
        serde_json::json!({
            "targets": [
                {
                    "raw": path,
                    "canonical": "https://github.com/owner/repo",
                },
                {
                    "raw": "owner/repo",
                    "canonical": "https://github.com/owner/repo",
                },
            ],
        }),
    );
    assert_eq!(
        target["targets"][0]["raw"],
        "repo-scan:redacted-target-spelling"
    );
    assert_eq!(
        target["targets"][0]["canonical"],
        "https://github.com/owner/repo"
    );
    assert_eq!(
        target["targets"][1]["raw"], "repo-scan:redacted-target-spelling",
        "a bare owner/repo spelling is ambiguous with a relative local path"
    );

    let remote = event_safe_records(
        EventType::RepositoryFound,
        serde_json::json!({
            "remotes": [
                {"url": format!("file://{path}")},
                {
                    "url": format!("FILE://{path}"),
                    "canonical_url": format!("FiLe://{path}"),
                },
            ],
        }),
    );
    assert_eq!(
        remote["remotes"][0]["url"],
        "repo-scan:redacted-local-target"
    );
    assert_eq!(
        remote["remotes"][1]["url"],
        "repo-scan:redacted-local-target"
    );
    assert_eq!(
        remote["remotes"][1]["canonical_url"],
        "repo-scan:redacted-local-target"
    );

    for records in [target, remote] {
        let text = serde_json::to_string(&records).expect("JSON");
        assert!(!text.contains(path));
        assert!(!text.contains(&path_hex));
        assert!(!text.contains(wave1d_b64_standard(path.as_bytes()).as_str()));
        assert!(!text.contains("LOCAL_TARGET_EVENT_CANARY"));
    }
}

/// Older retained journals used catalog IDs and root paths directly; the
/// projection sanitizes them at the replay boundary as well as at emit
/// time (port of B11 `replay_sanitizes_legacy_path_identifiers_and_fields`).
#[test]
fn wave1d_replay_sanitizes_legacy_path_identifiers_and_fields() {
    use repo_scan::scan_events::{event_opaque_id, event_safe_records, EventType};

    let path = "/tmp/proj-token=TERMSINKPATH04/.git";
    let path_hex = repo_scan::config::encode_hex(path.as_bytes());
    let store_id = format!("git:{path_hex}");
    let checkout_id = format!("co:{path_hex}");
    let branch_id = format!("ref:{store_id}:refs/heads/main");

    let location = event_safe_records(
        EventType::LocationFound,
        serde_json::json!({
            "checkout_id": checkout_id,
            "store_id": store_id,
            "path": path,
            "path_hex": path_hex,
            "git_path": path,
            "git_path_hex": path_hex,
        }),
    );
    assert_eq!(location["store_id"], event_opaque_id(&store_id));
    assert_eq!(location["checkout_id"], event_opaque_id(&checkout_id));
    for key in ["path", "path_hex", "git_path", "git_path_hex"] {
        assert!(location.get(key).is_none(), "legacy {key} removed");
    }

    let branch = event_safe_records(
        EventType::BranchBatch,
        serde_json::json!({
            "store_id": store_id,
            "branches": [{"id": branch_id}],
        }),
    );
    assert_eq!(branch["branches"][0]["id"], event_opaque_id(&branch_id));

    let error = event_safe_records(
        EventType::Error,
        serde_json::json!({
            "id": format!("gap:{path_hex}"),
            "scope_key": format!("dir:{path_hex}"),
            "detail": format!("cannot read {path}: permission denied"),
        }),
    );
    assert_eq!(
        error["scope_key"],
        event_opaque_id(&format!("dir:{path_hex}"))
    );
    let lifecycle = event_safe_records(
        EventType::ScanStarted,
        serde_json::json!({
            "scope": {"scope_key": format!("dir:{path_hex}"), "roots": [path]},
            "targets": [
                {"raw": path, "canonical": format!("file://{path}")},
                {"raw": "owner/repo", "canonical": "https://github.com/owner/repo"},
            ],
            "resume_cmd": format!("repo-scan --state-dir '{path}/state' resume 'scan-legacy'"),
        }),
    );
    let repository = event_safe_records(
        EventType::RepositoryFound,
        serde_json::json!({
            "remotes": [{
                "url": format!("file://{path}"),
                "canonical_url": format!("file://{path}"),
            }],
        }),
    );
    let remote_update = event_safe_records(
        EventType::RemoteUpdated,
        serde_json::json!({"detail": format!("fetch failed for {path}: denied")}),
    );
    let failed = event_safe_records(
        EventType::ScanFailed,
        serde_json::json!({
            "error": format!("cannot open {path}"),
            "resume_cmd": format!("repo-scan --state-dir '{path}/state' resume 'scan-legacy'"),
        }),
    );

    assert_eq!(
        lifecycle["targets"][0]["raw"],
        "repo-scan:redacted-target-spelling"
    );
    assert_eq!(
        lifecycle["resume_cmd"],
        "repo-scan --state-dir \"${REPO_SCAN_STATE_DIR:?set REPO_SCAN_STATE_DIR to this scan's state dir}\" resume 'scan-legacy'"
    );
    assert_eq!(error["detail"], "diagnostic details omitted for privacy");
    assert_eq!(
        remote_update["detail"],
        "diagnostic details omitted for privacy"
    );
    assert_eq!(failed["error"], "diagnostic details omitted for privacy");
    assert_eq!(
        repository["remotes"][0]["url"],
        "repo-scan:redacted-local-target"
    );

    for records in [
        location,
        branch,
        error,
        lifecycle,
        repository,
        remote_update,
        failed,
    ] {
        let text = serde_json::to_string(&records).expect("JSON");
        assert!(!text.contains(path), "raw local path omitted");
        assert!(
            !text.contains(&path_hex),
            "reversible path encoding omitted"
        );
        assert!(
            !text.contains(wave1d_b64_standard(path.as_bytes()).as_str()),
            "base64 path encoding omitted"
        );
        assert!(!text.contains("TERMSINKPATH04"), "canary omitted");
        assert!(!text.contains("file://"), "local file URL omitted");
    }
}

/// Only the exact canonical opaque encoding passes through; malformed
/// `evt:`/`root:` sentinels may still embed a path and are re-hashed (port
/// of B11 `replay_hashes_malformed_opaque_id_and_root_sentinels`).
#[test]
fn wave1d_replay_hashes_malformed_opaque_id_and_root_sentinels() {
    use repo_scan::scan_events::{event_safe_records, EventType};

    let path = "/tmp/MALFORMED_EVENT_SENTINEL_CANARY/private";
    let malformed_id = format!("evt:{path}");
    let malformed_root = format!("root:{path}");
    let valid_id = format!("evt:{}", "a".repeat(64));
    let valid_root = format!("root:{}", "b".repeat(64));

    let ids = event_safe_records(
        EventType::LocationFound,
        serde_json::json!({
            "checkout_id": valid_id,
            "store_id": malformed_id,
        }),
    );
    assert_eq!(ids["checkout_id"], format!("evt:{}", "a".repeat(64)));
    assert_eq!(
        ids["store_id"],
        repo_scan::scan_events::event_opaque_id(&malformed_id)
    );

    let roots = event_safe_records(
        EventType::ScanStarted,
        serde_json::json!({
            "scope": {"roots": [malformed_root, valid_root]},
        }),
    );
    let mut path_material = b"repo-scan-event-path-v1\0".to_vec();
    path_material.extend_from_slice(malformed_root.as_bytes());
    let expected_root = format!(
        "root:{}",
        repo_scan::report::publish::sha256_hex(&path_material)
    );
    assert_eq!(roots["scope"]["roots"][0], expected_root);
    assert_eq!(
        roots["scope"]["roots"][1],
        format!("root:{}", "b".repeat(64))
    );

    let text =
        serde_json::to_string(&serde_json::json!({"ids": ids, "roots": roots})).expect("JSON");
    assert!(!text.contains(path), "malformed sentinels must be hashed");
    assert!(text.contains(&expected_root));
}

/// The replay boundary sanitizes legacy journals end to end at the store
/// seam: a raw pre-projection journal row reads back through the guarded
/// page and `envelope_for_row` as an opaque-ID, path-free envelope, and a
/// journal row carrying an unknown class fails closed (never replayed as
/// a guessed event).
#[test]
fn wave1d_envelope_for_row_sanitizes_journal_at_replay_boundary() {
    use repo_scan::scan_events::{
        envelope_for_row, event_opaque_id, read_guarded_scan_event_page, GuardedScanEventPage,
    };

    let hook = Wave1dStore::new();
    let scan_id = "scan-legacy-boundary";
    let path = "/tmp/LEGACY-JOURNAL-CANARY/repo/.git";
    let path_hex = repo_scan::config::encode_hex(path.as_bytes());
    let store_id = format!("git:{path_hex}");
    hook.rt.block_on(async {
        let records = serde_json::json!({
            "checkout_id": format!("co:{path_hex}"),
            "store_id": store_id,
            "path": path,
            "path_hex": path_hex,
            "git_path": path,
            "git_path_hex": path_hex,
        });
        let bytes = serde_json::to_vec(&records).expect("records");
        wave1d_append(&hook.store, scan_id, 1, "location_found", "add", &bytes).await;
        // A corrupt class stays unreadable as an envelope.
        wave1d_append(&hook.store, scan_id, 2, "bogus_class", "add", b"{}").await;
    });

    let page = hook
        .rt
        .block_on(read_guarded_scan_event_page(
            &hook.store,
            scan_id,
            None,
            500,
        ))
        .expect("guarded page");
    let GuardedScanEventPage::Rows(rows) = page else {
        panic!("intact prefix must read");
    };
    assert_eq!(rows.len(), 2);

    let env = envelope_for_row(&rows[0]).expect("legacy row projects");
    let text = serde_json::to_string(&env).expect("envelope JSON");
    assert!(!text.contains(path), "raw path omitted: {text}");
    assert!(!text.contains(&path_hex), "reversible hex omitted: {text}");
    assert!(
        !text.contains(wave1d_b64_standard(path.as_bytes()).as_str()),
        "base64 path omitted: {text}"
    );
    assert!(!text.contains("LEGACY-JOURNAL-CANARY"), "canary omitted");
    assert_eq!(
        env.records["store_id"],
        serde_json::Value::String(event_opaque_id(&store_id)),
        "legacy store id normalized to the opaque projection"
    );
    assert!(
        env.records["checkout_id"]
            .as_str()
            .expect("checkout id")
            .starts_with("evt:"),
        "legacy checkout id normalized"
    );

    let corrupt = envelope_for_row(&rows[1]);
    assert!(
        matches!(corrupt, Err(repo_scan::Error::Report(_))),
        "unknown journal class fails closed: {corrupt:?}"
    );
}

/// The frozen C3 event-lifecycle transition table, executable:
///
/// - exactly four terminal classes; all four close the journal
///   (attempt-terminal `scan_interrupted`/`scan_failed` and scan-final
///   `scan_completed`/`scan_incomplete` alike), release dedupe markers
///   atomically, and retain the journal rows (resume records);
/// - non-terminal classes are rejected from the terminal path;
/// - redelivery of one `(scan_id, seq)` is idempotent;
/// - resume from an interrupted/failed attempt stays possible: the scan
///   row and its retained journal remain readable after the terminal.
#[test]
fn c3_event_lifecycle_transition_table() {
    use repo_scan::scan_events::{
        buffer_scan_event_dedupe, is_terminal_event, is_terminal_name, EventType,
    };
    use repo_scan::store::{NewScan, NewScanEvent, WriterBatch};

    const TERMINAL: [EventType; 4] = [
        EventType::ScanCompleted,
        EventType::ScanIncomplete,
        EventType::ScanInterrupted,
        EventType::ScanFailed,
    ];
    const NONTERMINAL: [EventType; 11] = [
        EventType::ScanStarted,
        EventType::DiscoveryProgress,
        EventType::DiscoveryProgressUpdated,
        EventType::LocationFound,
        EventType::RepositoryFound,
        EventType::InventoryReady,
        EventType::BranchBatch,
        EventType::LocationUpdated,
        EventType::CoverageUpdated,
        EventType::Error,
        EventType::RemoteUpdated,
    ];
    for t in TERMINAL {
        assert!(is_terminal_event(t), "{t:?}");
        assert!(is_terminal_name(t.name()), "{}", t.name());
    }
    for t in NONTERMINAL {
        assert!(!is_terminal_event(t), "{t:?}");
        assert!(!is_terminal_name(t.name()), "{}", t.name());
    }

    let hook = Wave1dStore::new();
    hook.rt.block_on(async {
        // Every terminal class: accepted, markers released, rows retained.
        for (i, t) in TERMINAL.iter().enumerate() {
            let scan_id = format!("scan-c3-terminal-{i}");
            hook.store
                .create_scan_request(
                    &NewScan {
                        id: &scan_id,
                        url_raw: b"https://example.invalid/o/r.git",
                        url_canonical: Some(b"https://example.invalid/o/r.git"),
                        scope: "roots",
                        status_mode: "summary",
                        report_dest: None,
                        targets_json: None,
                        format: Some("jsonl"),
                        all_targets: Some(false),
                    },
                    1,
                )
                .await
                .expect("create scan");
            wave1d_append(&hook.store, &scan_id, 1, "scan_started", "add", b"{}").await;
            let mut batch = WriterBatch::new();
            buffer_scan_event_dedupe(&mut batch, &scan_id, "repository_found", "store-c3");
            hook.store.flush(&mut batch).await.expect("flush marker");
            assert!(wave1d_dedupe_count(&hook.store, &scan_id).await > 0);

            let appended = hook
                .store
                .append_terminal_scan_event(&NewScanEvent {
                    scan_id: &scan_id,
                    seq: 2,
                    catalog_rev: 1,
                    event_offset: 1,
                    event_type: t.name(),
                    op: t.op().name(),
                    reset: false,
                    records: b"{}",
                })
                .await
                .expect("terminal append");
            assert!(appended, "{} accepted", t.name());
            assert_eq!(
                wave1d_dedupe_count(&hook.store, &scan_id).await,
                0,
                "{} released the markers",
                t.name()
            );
            let rows = hook
                .store
                .read_scan_events(&scan_id, 0, 100)
                .await
                .expect("read journal");
            assert_eq!(rows.len(), 2, "{} journal retained", t.name());
            assert_eq!(rows[1].event_type, t.name());
        }

        // Every non-terminal class: rejected from the terminal path.
        for (i, t) in NONTERMINAL.iter().enumerate() {
            let scan_id = format!("scan-c3-nonterminal-{i}");
            let rejected = hook
                .store
                .append_terminal_scan_event(&NewScanEvent {
                    scan_id: &scan_id,
                    seq: 1,
                    catalog_rev: 1,
                    event_offset: 0,
                    event_type: t.name(),
                    op: t.op().name(),
                    reset: false,
                    records: b"{}",
                })
                .await;
            assert!(
                matches!(rejected, Err(repo_scan::Error::InvalidArgs(_))),
                "{} rejected from the terminal path",
                t.name()
            );
        }

        // Resume from an interrupted attempt: the scan row and retained
        // journal stay readable (the CLI's resume gate reads the row
        // state; the terminal cursor payload resolves StopAtTerminal for
        // followers).
        let scan_id = "scan-c3-resumable";
        hook.store
            .create_scan_request(
                &NewScan {
                    id: scan_id,
                    url_raw: b"https://example.invalid/o/r.git",
                    url_canonical: Some(b"https://example.invalid/o/r.git"),
                    scope: "roots",
                    status_mode: "summary",
                    report_dest: None,
                    targets_json: None,
                    format: Some("jsonl"),
                    all_targets: Some(false),
                },
                1,
            )
            .await
            .expect("create resumable scan");
        wave1d_append(&hook.store, scan_id, 1, "scan_started", "add", b"{}").await;
        hook.store
            .append_terminal_scan_event(&NewScanEvent {
                scan_id,
                seq: 2,
                catalog_rev: 1,
                event_offset: 1,
                event_type: "scan_interrupted",
                op: "add",
                reset: false,
                records: b"{}",
            })
            .await
            .expect("interrupted terminal");
        let row = hook
            .store
            .get_scan(scan_id)
            .await
            .expect("get scan")
            .expect("scan row retained");
        assert_eq!(row.state, "running", "row awaits its state update");
        let journal = hook
            .store
            .read_scan_events(scan_id, 0, 100)
            .await
            .expect("journal retained");
        assert_eq!(journal.len(), 2, "resume records retained");
        let position = repo_scan::scan_events::resolve_after_cursor(
            &hook.store,
            scan_id,
            &repo_scan::scan_events::ScanCursor::for_scan(scan_id, 2, 1, 1).encode(),
        )
        .await
        .expect("resolve terminal cursor");
        assert!(
            position.terminal_seen,
            "followers stop at the attempt-terminal row"
        );
    });
}
