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
//!
//! Wave1d Step 12 (`wave1d_*` below): live discovery events + durable
//! cursors + batched completion through the production scan/query
//! commands, catalog reads, and `#[cfg(test)]` hooks.

mod common;

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

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
// Wave1d Step 12: live discovery events + durable cursors + batched
// completion. Binary+catalog tests reference the production scan/query
// commands and catalog reads; hook tests drive the production batch,
// prune, resolve, and coalesce code through `main_under_test`.
// ---------------------------------------------------------------------------

use common::fixture;
use repo_scan::model::TaskState;
use repo_scan::store::{NewTask, TaskOutcome};

const WAVE1D_URL: &str = "https://github.com/OWNER/REPO";

fn wave1d_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

fn wave1d_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn wave1d_git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn wave1d_db(state: &Path) -> PathBuf {
    state.join("payload").join("catalog.db")
}

/// Temp workspace: fixture root + state dir + cwd. Scans run with
/// `--root <root>` only, never machine-wide.
struct Wave1dEnv {
    _dir: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
    cwd: PathBuf,
}

impl Wave1dEnv {
    fn new(prefix: &str) -> Self {
        let dir = fixture::scratch_root(prefix);
        let root = dir.path().join("root");
        repo_scan::privacy::private_dir_0700(&root).unwrap();
        let state = dir.path().join("state");
        let cwd = dir.path().join("cwd");
        repo_scan::privacy::private_dir_0700(&cwd).unwrap();
        Self {
            _dir: dir,
            root,
            state,
            cwd,
        }
    }

    fn report_path(&self) -> PathBuf {
        self.cwd.join("rep.json")
    }

    /// Spawn a scan, capturing stdio to files (pipes would deadlock a
    /// multi-second scan once buffers fill).
    fn spawn_scan(&self) -> std::process::Child {
        let stdout = std::fs::File::create(self.cwd.join("scan.out")).expect("scan.out");
        let stderr = std::fs::File::create(self.cwd.join("scan.err")).expect("scan.err");
        std::process::Command::new(wave1d_binary())
            .arg("--state-dir")
            .arg(&self.state)
            .arg("scan")
            .arg(WAVE1D_URL)
            .arg("--root")
            .arg(&self.root)
            .arg("--report")
            .arg(self.report_path())
            .arg("--status")
            .arg("metadata")
            // Wave6: explicit human keeps the footer lines (the
            // redirected default is now the JSONL journal replay).
            .arg("--format")
            .arg("human")
            .current_dir(&self.cwd)
            .stdout(std::process::Stdio::from(stdout))
            .stderr(std::process::Stdio::from(stderr))
            .spawn()
            .expect("spawn repo-scan")
    }

    /// Run a scan to completion, returning (status, stdout, stderr).
    fn run_scan(&self) -> (std::process::ExitStatus, String, String) {
        let mut child = self.spawn_scan();
        let status = child.wait().expect("wait");
        (
            status,
            fixture::read_to_string(&self.cwd.join("scan.out")),
            fixture::read_to_string(&self.cwd.join("scan.err")),
        )
    }

    fn run_query(&self, args: &[&str]) -> std::process::Output {
        let mut full = vec!["--state-dir", self.state.to_str().expect("utf8")];
        full.extend(args.iter().copied());
        std::process::Command::new(wave1d_binary())
            .args(&full)
            .current_dir(&self.cwd)
            .output()
            .expect("spawn repo-scan query")
    }

    fn run_resume(&self, scan_id: &str) -> std::process::Output {
        self.run_query(&["resume", scan_id])
    }
}

fn wave1d_stdout_line(stdout: &str, key: &str) -> String {
    for line in stdout.lines() {
        if let Some(value) = line.strip_prefix(&format!("{key}:")) {
            return value.trim().to_string();
        }
    }
    panic!("missing `{key}:` in stdout:\n{stdout}");
}

fn wave1d_parse_jsonl(output: &std::process::Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
        .collect()
}

fn wave1d_report(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("report is valid JSON")
}

/// Confirmed repository IDs in a report.
fn wave1d_confirmed_repos(report: &serde_json::Value) -> Vec<String> {
    report["repositories"]
        .as_array()
        .expect("repositories")
        .iter()
        .filter(|r| r["match"].as_str() == Some("confirmed"))
        .filter_map(|r| r["id"].as_str().map(str::to_string))
        .collect()
}

/// Committed scan ids, oldest first (empty when no catalog is readable
/// yet). Read-only: servable while a scan holds the write lock.
async fn wave1d_scan_ids(db: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if !db.exists() {
        return out;
    }
    let Ok(store) = repo_scan::store::TursoStore::open_read_only(db).await else {
        return out;
    };
    let Ok(mut rows) = store
        .connection()
        .query(
            "SELECT id FROM scan_requests ORDER BY created_at_ms ASC",
            (),
        )
        .await
    else {
        return out;
    };
    while let Ok(Some(row)) = rows.next().await {
        let Ok(turso::Value::Text(id)) = row.get_value(0) else {
            break;
        };
        out.push(id);
    }
    let _ = store.close().await;
    out
}

/// Committed event-type histogram (`None` when no catalog is readable
/// yet). Each call reopens read-only: a read-only handle pins its
/// opening snapshot, so mid-scan polling must reopen per poll.
async fn wave1d_event_types(db: &Path) -> Option<HashMap<String, u64>> {
    if !db.exists() {
        return None;
    }
    let store = repo_scan::store::TursoStore::open_read_only(db)
        .await
        .ok()?;
    let mut rows = store
        .connection()
        .query(
            "SELECT event_type, COUNT(*) FROM scan_events GROUP BY event_type",
            (),
        )
        .await
        .ok()?;
    let mut out = HashMap::new();
    loop {
        let row = match rows.next().await {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(_) => return None,
        };
        let event_type = match row.get_value(0) {
            Ok(turso::Value::Text(t)) => t,
            _ => return None,
        };
        let count = match row.get_value(1) {
            Ok(turso::Value::Integer(n)) => n,
            _ => return None,
        };
        out.insert(event_type, u64::try_from(count).ok()?);
    }
    store.close().await.ok()?;
    Some(out)
}

/// Committed `complete` task count (0 when unreadable).
async fn wave1d_complete_count(db: &Path) -> u64 {
    if !db.exists() {
        return 0;
    }
    let Ok(store) = repo_scan::store::TursoStore::open_read_only(db).await else {
        return 0;
    };
    let mut rows = match store
        .connection()
        .query(
            "SELECT COUNT(*) FROM frontier_tasks WHERE state = 'complete'",
            (),
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return 0,
    };
    let count = match rows.next().await {
        Ok(Some(row)) => match row.get_value(0) {
            Ok(turso::Value::Integer(n)) => u64::try_from(n).unwrap_or(0),
            _ => 0,
        },
        _ => 0,
    };
    let _ = store.close().await;
    count
}

/// Committed non-terminal task count (pending/leased/retry_wait): zero
/// means nothing was lost or left stuck.
async fn wave1d_nonterminal_count(db: &Path) -> u64 {
    if !db.exists() {
        return 0;
    }
    let Ok(store) = repo_scan::store::TursoStore::open_read_only(db).await else {
        return 0;
    };
    let mut rows = match store
        .connection()
        .query(
            "SELECT COUNT(*) FROM frontier_tasks \
                WHERE state IN ('pending', 'leased', 'retry_wait')",
            (),
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return 0,
    };
    let count = match rows.next().await {
        Ok(Some(row)) => match row.get_value(0) {
            Ok(turso::Value::Integer(n)) => u64::try_from(n).unwrap_or(0),
            _ => 0,
        },
        _ => 0,
    };
    let _ = store.close().await;
    count
}

/// Reader sees `discovery_progress` + `location_found` while discovery
/// is still active: a 30-repo scan runs for seconds, catalog polling
/// observes both committed mid-run, and a production `query --scan`
/// serves them while the scan child is still alive.
#[test]
fn wave1d_live_reader_sees_progress_and_found_while_discovery_active() {
    if !wave1d_git_available() {
        eprintln!("wave1d live read: git unavailable; skipping");
        return;
    }
    let env = Wave1dEnv::new("wave1d-live-");
    fixture::many_repos(&env.root, "repo", 30);
    let mut child = env.spawn_scan();
    let rt = wave1d_runtime();
    let db = wave1d_db(&env.state);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "live rows never committed before the deadline"
        );
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "scan exited before live rows were observed"
        );
        let types = rt.block_on(wave1d_event_types(&db)).unwrap_or_default();
        let progress = types.get("discovery_progress").copied().unwrap_or(0);
        let found = types.get("location_found").copied().unwrap_or(0);
        if progress >= 1 && found >= 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "scan still active at the live observation"
    );
    // Production-command read while active (read-only: no owner lock).
    let scan_id = rt
        .block_on(wave1d_scan_ids(&db))
        .into_iter()
        .next()
        .expect("scan row committed mid-scan");
    let replay = env.run_query(&["query", "--scan", &scan_id, "--format", "jsonl"]);
    assert_eq!(
        replay.status.code(),
        Some(0),
        "mid-scan query: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let lines = wave1d_parse_jsonl(&replay);
    assert!(
        lines.iter().any(|e| e["type"] == "discovery_progress"),
        "mid-scan replay carries discovery_progress"
    );
    assert!(
        lines.iter().any(|e| e["type"] == "location_found"),
        "mid-scan replay carries location_found"
    );
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "scan still active after the mid-scan query"
    );
    let status = child.wait().expect("wait");
    assert!(status.success(), "scan exits 0");
    // The stderr prose line is kept.
    let stderr = fixture::read_to_string(&env.cwd.join("scan.err"));
    assert!(
        stderr.contains("session(this run)") && stderr.contains("cumulative(scan total)"),
        "progress prose line kept:\n{stderr}"
    );
}

/// Reconnect with a mid-transaction cursor loses nothing: the first
/// probe's `repository_found` + `location_found` share one flush (one
/// revision, consecutive offsets); resuming between them delivers the
/// second event first, then everything after it, with no reset.
#[test]
fn wave1d_mid_transaction_cursor_resume_loses_nothing() {
    use repo_scan::scan_events::Cursor;
    use repo_scan::store::Store;

    if !wave1d_git_available() {
        eprintln!("wave1d mid-tx resume: git unavailable; skipping");
        return;
    }
    let env = Wave1dEnv::new("wave1d-midtx-");
    fixture::many_repos(&env.root, "repo", 2);
    let (status, stdout, stderr) = env.run_scan();
    assert_eq!(status.code(), Some(0), "scan: {stderr}");
    let scan_id = wave1d_stdout_line(&stdout, "scan_id");

    let rt = wave1d_runtime();
    let db = wave1d_db(&env.state);
    let rows = rt.block_on(async {
        let store = repo_scan::store::TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 10_000)
            .await
            .expect("read");
        store.close().await.expect("close");
        rows
    });
    // The scenario pair: consecutively journaled events sharing one
    // revision with consecutive offsets (one probe's flush).
    let pair = rows.windows(2).find(|w| {
        w[0].event_type == "repository_found"
            && w[1].event_type == "location_found"
            && w[1].seq == w[0].seq + 1
            && w[1].catalog_rev == w[0].catalog_rev
            && w[1].event_offset == w[0].event_offset + 1
    });
    let pair = pair.unwrap_or_else(|| {
        panic!(
            "no adjacent same-revision (repository_found, location_found) pair in: {:?}",
            rows.iter()
                .map(|r| (r.seq, r.catalog_rev, r.event_offset, r.event_type.clone()))
                .collect::<Vec<_>>()
        )
    });
    let cursor = Cursor {
        seq: pair[0].seq,
        catalog_rev: pair[0].catalog_rev,
        event_offset: pair[0].event_offset,
    }
    .encode();

    let resumed = env.run_query(&[
        "query", "--scan", &scan_id, "--follow", "--format", "jsonl", "--after", &cursor,
    ]);
    assert_eq!(
        resumed.status.code(),
        Some(0),
        "resume: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let tail = wave1d_parse_jsonl(&resumed);
    // Nothing lost: every row after the cursor, in order, starting with
    // the second event of the pair — and no reset on a covered cursor.
    let expected: Vec<u64> = ((pair[0].seq + 1)..=rows.len() as u64).collect();
    let got: Vec<u64> = tail
        .iter()
        .map(|e| e["seq"].as_u64().expect("seq u64"))
        .collect();
    assert_eq!(
        got, expected,
        "resume delivers every later row exactly once"
    );
    assert_eq!(tail[0]["type"], "location_found");
    assert!(
        tail.iter().all(|e| e["reset"] != true),
        "covered resume carries no reset"
    );
    assert_eq!(tail.last().expect("tail last")["type"], "scan_completed");
}

/// Expired and diverged cursors yield an explicit-reset snapshot — not a
/// silent resume, not an error. The prefix is deleted through the
/// catalog (simulating retention); the production query path must flag
/// the resync with `reset:true` on the first envelope and replay the
/// retained window.
#[test]
fn wave1d_expired_cursor_yields_explicit_reset_snapshot() {
    use repo_scan::scan_events::Cursor;
    use repo_scan::store::Store;

    if !wave1d_git_available() {
        eprintln!("wave1d expired cursor: git unavailable; skipping");
        return;
    }
    let env = Wave1dEnv::new("wave1d-expired-");
    fixture::many_repos(&env.root, "repo", 2);
    let (status, stdout, stderr) = env.run_scan();
    assert_eq!(status.code(), Some(0), "scan: {stderr}");
    let scan_id = wave1d_stdout_line(&stdout, "scan_id");

    let rt = wave1d_runtime();
    let db = wave1d_db(&env.state);
    let rows = rt.block_on(async {
        let store = repo_scan::store::TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 10_000)
            .await
            .expect("read");
        store.close().await.expect("close");
        rows
    });
    assert!(rows.len() >= 5, "journal to prune: {}", rows.len());
    // Expire the prefix through seq 2 (scan_started + the gauge row).
    let expired = rows[1].clone();
    rt.block_on(async {
        let store = repo_scan::store::TursoStore::open(&db).await.expect("open");
        store
            .connection()
            .execute(
                "DELETE FROM scan_events WHERE scan_id = ?1 AND seq <= ?2",
                vec![
                    turso::Value::Text(scan_id.clone()),
                    turso::Value::Integer(2),
                ],
            )
            .await
            .expect("delete prefix");
        let retained = store
            .read_scan_events(&scan_id, 0, 10_000)
            .await
            .expect("read");
        assert_eq!(retained[0].seq, 3, "retained window starts after the cut");
        store.close().await.expect("close");
    });

    // Expired cursor: the row is gone, so this is a resync, not a resume.
    let after = Cursor {
        seq: expired.seq,
        catalog_rev: expired.catalog_rev,
        event_offset: expired.event_offset,
    }
    .encode();
    let resumed = env.run_query(&[
        "query", "--scan", &scan_id, "--follow", "--format", "jsonl", "--after", &after,
    ]);
    assert_eq!(
        resumed.status.code(),
        Some(0),
        "expired cursor is a snapshot, not an error: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let tail = wave1d_parse_jsonl(&resumed);
    assert_eq!(tail[0]["seq"], 3, "snapshot replays the retained window");
    assert_eq!(tail[0]["reset"], true, "explicit reset, never silent");
    assert_eq!(tail.len(), rows.len() - 2, "whole retained window");
    assert_eq!(tail.last().expect("tail last")["type"], "scan_completed");
    // Snapshot cursor = exact end of included changes.
    let last = tail.last().expect("tail last");
    assert_eq!(last["seq"], rows.len() as u64);

    // Diverged cursor: a retained seq with a foreign position also
    // resyncs (the position check is revision + event-offset, not seq).
    let diverged = Cursor {
        seq: 3,
        catalog_rev: 999_999,
        event_offset: 0,
    }
    .encode();
    let resync = env.run_query(&[
        "query", "--scan", &scan_id, "--follow", "--format", "jsonl", "--after", &diverged,
    ]);
    assert_eq!(
        resync.status.code(),
        Some(0),
        "diverged cursor is a snapshot, not an error: {}",
        String::from_utf8_lossy(&resync.stderr)
    );
    let tail = wave1d_parse_jsonl(&resync);
    assert_eq!(tail[0]["seq"], 3);
    assert_eq!(tail[0]["reset"], true);
    assert_eq!(tail.last().expect("tail last")["type"], "scan_completed");
}

/// Interrupted batch completion resumes without lost children or
/// double-completes: the scan is killed between batch commits (after
/// completions are observed), resumed, and must report exactly the
/// baseline's repositories with a clean terminal frontier.
#[test]
fn wave1d_interrupted_batch_completion_resumes_lossless() {
    if !wave1d_git_available() {
        eprintln!("wave1d kill-resume: git unavailable; skipping");
        return;
    }
    let env = Wave1dEnv::new("wave1d-kill-");
    fixture::many_repos(&env.root, "repo", 20);
    fixture::deep_repo_chain(&env.root, 6);
    let total_repos = 26;

    let mut child = env.spawn_scan();
    let rt = wave1d_runtime();
    let db = wave1d_db(&env.state);
    // Kill between batches: wait until committed completions exist while
    // the scan is still running, so the kill lands after batch commits.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "no completions committed before the deadline"
        );
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "scan finished before the kill window"
        );
        if rt.block_on(wave1d_complete_count(&db)) >= 3 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    child.kill().expect("kill between batches");
    let killed = child.wait().expect("wait");
    assert!(!killed.success(), "killed scan did not exit 0");

    let scan_id = rt
        .block_on(wave1d_scan_ids(&db))
        .into_iter()
        .next()
        .expect("scan row survived the kill");
    let resumed = env.run_resume(&scan_id);
    assert_eq!(
        resumed.status.code(),
        Some(0),
        "resume exits 0: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let report = wave1d_report(&env.report_path());
    let repos = wave1d_confirmed_repos(&report);
    assert_eq!(
        repos.len(),
        total_repos,
        "no lost children after kill+resume: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let mut deduped = repos.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(deduped.len(), repos.len(), "no double-completes");
    // Children-before-parent: nothing pending, leased, or stuck in
    // backoff — every task reached a terminal state.
    assert_eq!(
        rt.block_on(wave1d_nonterminal_count(&db)),
        0,
        "clean terminal frontier after resume"
    );

    // Independent baseline: the same fixture scanned fresh elsewhere
    // reports exactly the same repositories.
    let mut baseline = Wave1dEnv::new("wave1d-kill-base-");
    baseline.root = env.root.clone();
    let (status, _, stderr) = baseline.run_scan();
    assert_eq!(status.code(), Some(0), "baseline scan: {stderr}");
    let baseline_report = wave1d_report(&baseline.report_path());
    let mut baseline_repos = wave1d_confirmed_repos(&baseline_report);
    baseline_repos.sort();
    assert_eq!(deduped, baseline_repos, "kill+resume matches a fresh scan");
}

/// Progress coalescing: many ticks leave exactly the newest
/// `discovery_progress` row per scan, while record events are never
/// dropped (all found/branch rows survive; the replay carries one
/// progress envelope with contiguous seqs).
#[test]
fn wave1d_progress_coalesces_to_newest_per_scan() {
    use repo_scan::store::Store;

    if !wave1d_git_available() {
        eprintln!("wave1d coalesce: git unavailable; skipping");
        return;
    }
    let env = Wave1dEnv::new("wave1d-coalesce-");
    fixture::many_repos(&env.root, "repo", 30);
    let (status, stdout, stderr) = env.run_scan();
    assert_eq!(status.code(), Some(0), "scan: {stderr}");
    let scan_id = wave1d_stdout_line(&stdout, "scan_id");

    let rt = wave1d_runtime();
    let db = wave1d_db(&env.state);
    let rows = rt.block_on(async {
        let store = repo_scan::store::TursoStore::open(&db).await.expect("open");
        let rows = store
            .read_scan_events(&scan_id, 0, 10_000)
            .await
            .expect("read");
        store.close().await.expect("close");
        rows
    });
    let progress: Vec<_> = rows
        .iter()
        .filter(|r| r.event_type == "discovery_progress")
        .collect();
    assert_eq!(progress.len(), 1, "many ticks coalesce to one gauge row");
    assert_eq!(progress[0].op, "replace", "D4 op for progress");
    let payload: serde_json::Value =
        serde_json::from_slice(&progress[0].records).expect("progress json");
    // Newest, not first: the first tick fires on the first completion
    // with ~zero done; the survivor reflects a drained scan.
    assert!(
        payload["discovered"]["tasks_done"].as_u64().unwrap_or(0) > 50,
        "survivor is the newest tick: {payload}"
    );
    assert!(
        payload.get("pending").is_some() && payload.get("gaps").is_some(),
        "D4 payload shape (pending, gaps): {payload}"
    );
    // Record events are never dropped by coalescing.
    for (class, expected) in [
        ("repository_found", 30),
        ("location_found", 30),
        ("branch_batch", 30),
    ] {
        let count = rows.iter().filter(|r| r.event_type == class).count();
        assert_eq!(count, expected, "{class} rows survive coalescing");
    }
    // Consumer view: one progress envelope, contiguous 1-based seqs.
    let replay = env.run_query(&["query", "--scan", &scan_id, "--format", "jsonl"]);
    assert_eq!(replay.status.code(), Some(0));
    let lines = wave1d_parse_jsonl(&replay);
    assert_eq!(lines.len(), rows.len(), "replay covers the journal");
    assert_eq!(
        lines
            .iter()
            .filter(|e| e["type"] == "discovery_progress")
            .count(),
        1,
        "replay carries one progress envelope"
    );
    for (i, env) in lines.iter().enumerate() {
        assert_eq!(env["seq"], serde_json::Value::from((i + 1) as u64));
    }
}

// ---------------------------------------------------------------------------
// Wave1d hook tests: production batch/prune/resolve/coalesce edges that
// need deterministic control (stale races, foreign leases, tiny bounds,
// hand-mutated positions) through `main_under_test`.
// ---------------------------------------------------------------------------

/// Fresh read-write catalog for hook tests, with its fencing epoch.
struct Wave1dHookStore {
    _dir: tempfile::TempDir,
    rt: tokio::runtime::Runtime,
    store: repo_scan::store::TursoStore,
    epoch: u64,
}

impl Wave1dHookStore {
    fn new() -> Self {
        use repo_scan::store::Store;
        let dir = fixture::scratch_root("wave1d-hook-");
        let db = dir.path().join("payload").join("catalog.db");
        let rt = wave1d_runtime();
        let store =
            rt.block_on(async { repo_scan::store::TursoStore::open(&db).await.expect("open") });
        let epoch = store.epoch();
        Self {
            _dir: dir,
            rt,
            store,
            epoch,
        }
    }

    /// Enqueue one pending task and claim it; returns the claim.
    fn enqueue_claim(&self, id: &str, kind: &str, scope: &str) -> repo_scan::store::ClaimedTask {
        self.rt.block_on(async {
            let rev = self.store.scope_rev(scope).await.expect("rev");
            let idem = format!("idem:{id}");
            let now = repo_scan::store::now_ms();
            self.store
                .enqueue_task(
                    &NewTask {
                        id,
                        kind,
                        generation: 1,
                        dir_id: None,
                        scope_key: scope,
                        expected_rev: rev,
                        idempotency_key: &idem,
                    },
                    now,
                )
                .await
                .expect("enqueue");
            let claimed = self
                .store
                .claim_tasks(self.epoch, 16, 60_000, repo_scan::store::now_ms())
                .await
                .expect("claim");
            claimed
                .into_iter()
                .find(|c| c.task.id == id)
                .expect("claimed")
        })
    }
}

fn wave1d_item(
    task_id: &str,
    token: i64,
    outcome: TaskOutcome,
    children: Vec<main_under_test::TestChildTask>,
) -> main_under_test::TestCompletionItem {
    main_under_test::TestCompletionItem {
        task_id: task_id.to_string(),
        token,
        outcome,
        children,
    }
}

fn wave1d_child(id: &str) -> main_under_test::TestChildTask {
    main_under_test::TestChildTask {
        id: id.to_string(),
        kind: "enumerate_dir".to_string(),
        generation: 1,
        scope_key: format!("dir:{id}"),
        expected_rev: 0,
    }
}

/// Batched completion applies mixed outcomes in one flush: states land,
/// gaps record, and the `error` / `coverage_updated` gap events journal
/// afterwards.
#[test]
fn wave1d_batch_applies_mixed_outcomes_with_gap_events() {
    let hook = Wave1dHookStore::new();
    let a = hook.enqueue_claim("task:a", "enumerate_dir", "dir:a");
    let b = hook.enqueue_claim("task:b", "probe_git", "dir:b");
    let c = hook.enqueue_claim("task:c", "probe_git", "dir:c");
    let now = repo_scan::store::now_ms();
    let results = hook
        .rt
        .block_on(main_under_test::test_drive_completions(
            &hook.store,
            "scan-hook-1",
            hook.epoch,
            vec![
                wave1d_item("task:a", a.token, TaskOutcome::Complete, vec![]),
                wave1d_item(
                    "task:b",
                    b.token,
                    TaskOutcome::Retry {
                        category: "retry-cat".to_string(),
                        detail: "retry detail".to_string(),
                        retry_after_ms: now + 60_000,
                    },
                    vec![],
                ),
                wave1d_item(
                    "task:c",
                    c.token,
                    TaskOutcome::Parked {
                        state: TaskState::Unavailable,
                        reason: "parked reason".to_string(),
                    },
                    vec![],
                ),
            ],
            true,
        ))
        .expect("drive");
    assert_eq!(
        results,
        vec![
            main_under_test::TestCompletionResult {
                task_id: "task:a".to_string(),
                stale: false,
            },
            main_under_test::TestCompletionResult {
                task_id: "task:b".to_string(),
                stale: false,
            },
            main_under_test::TestCompletionResult {
                task_id: "task:c".to_string(),
                stale: false,
            },
        ]
    );
    hook.rt.block_on(async {
        for (id, expected) in [
            ("task:a", TaskState::Complete),
            ("task:b", TaskState::RetryWait),
            ("task:c", TaskState::Unavailable),
        ] {
            let row = hook.store.get_task(id).await.expect("get").expect("row");
            assert_eq!(row.state, expected, "{id}");
        }
        let gap_b = hook
            .store
            .get_error("gap:task:b")
            .await
            .expect("get")
            .expect("gap row");
        assert!(gap_b.open);
        assert_eq!(gap_b.category, "retry-cat");
        let gap_c = hook
            .store
            .get_error("gap:task:c")
            .await
            .expect("get")
            .expect("gap row");
        assert!(gap_c.open);
        assert_eq!(gap_c.category, "unavailable");
        let rows = hook
            .store
            .read_scan_events("scan-hook-1", 0, 100)
            .await
            .expect("read");
        let errors: Vec<_> = rows.iter().filter(|r| r.event_type == "error").collect();
        assert_eq!(errors.len(), 2, "one error event per recorded gap");
        let coverage: Vec<_> = rows
            .iter()
            .filter(|r| r.event_type == "coverage_updated")
            .collect();
        assert_eq!(coverage.len(), 2, "one delta per genuine open");
    });
}

/// A completion racing an invalidation requeues stale: the task returns
/// to `pending` with the fresh revision, and no gap or event records.
#[test]
fn wave1d_batch_stale_completion_requeues_without_gap() {
    let hook = Wave1dHookStore::new();
    let d = hook.enqueue_claim("task:d", "enumerate_dir", "dir:d");
    hook.rt.block_on(async {
        hook.store
            .invalidate_scope("dir:d", 1, repo_scan::store::now_ms())
            .await
            .expect("invalidate");
    });
    let results = hook
        .rt
        .block_on(main_under_test::test_drive_completions(
            &hook.store,
            "scan-hook-1",
            hook.epoch,
            vec![wave1d_item(
                "task:d",
                d.token,
                TaskOutcome::Complete,
                vec![],
            )],
            true,
        ))
        .expect("drive");
    assert_eq!(
        results,
        vec![main_under_test::TestCompletionResult {
            task_id: "task:d".to_string(),
            stale: true,
        }]
    );
    hook.rt.block_on(async {
        let row = hook
            .store
            .get_task("task:d")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(row.state, TaskState::Pending);
        assert_eq!(
            row.expected_rev,
            hook.store.scope_rev("dir:d").await.expect("rev"),
            "requeued with the fresh revision"
        );
        assert!(
            hook.store
                .get_error("gap:task:d")
                .await
                .expect("get")
                .is_none(),
            "stale completions record no gap"
        );
        let rows = hook
            .store
            .read_scan_events("scan-hook-1", 0, 100)
            .await
            .expect("read");
        assert!(
            rows.iter().all(|r| r.event_type != "error"),
            "stale completions journal no error event"
        );
    });
}

/// A completion presenting a superseded lease token aborts loudly with
/// the production lease-mismatch error.
#[test]
fn wave1d_batch_lease_mismatch_aborts_loudly() {
    let hook = Wave1dHookStore::new();
    let e = hook.enqueue_claim("task:e", "enumerate_dir", "dir:e");
    hook.rt.block_on(async {
        hook.store
            .release_claim("task:e", e.token, hook.epoch, repo_scan::store::now_ms())
            .await
            .expect("release");
        let reclaimed = hook
            .store
            .claim_tasks(hook.epoch, 16, 60_000, repo_scan::store::now_ms())
            .await
            .expect("reclaim");
        assert!(
            reclaimed
                .iter()
                .any(|c| c.task.id == "task:e" && c.token != e.token),
            "reclaim grants a fresh token"
        );
    });
    let err = hook
        .rt
        .block_on(main_under_test::test_drive_completions(
            &hook.store,
            "scan-hook-1",
            hook.epoch,
            vec![wave1d_item(
                "task:e",
                e.token,
                TaskOutcome::Complete,
                vec![],
            )],
            true,
        ))
        .expect_err("stale token must fail");
    assert!(
        err.to_string().contains("lease-mismatch"),
        "production lease-mismatch error: {err}"
    );
}

/// Completing an unknown task aborts loudly with the production
/// unknown-task error.
#[test]
fn wave1d_batch_unknown_task_aborts_loudly() {
    let hook = Wave1dHookStore::new();
    let err = hook
        .rt
        .block_on(main_under_test::test_drive_completions(
            &hook.store,
            "scan-hook-1",
            hook.epoch,
            vec![wave1d_item(
                "task:no-such",
                1,
                TaskOutcome::Complete,
                vec![],
            )],
            true,
        ))
        .expect_err("unknown task must fail");
    assert!(
        err.to_string().contains("unknown-task"),
        "production unknown-task error: {err}"
    );
}

/// A foreign epoch and an invalid parked state are refused with the
/// production errors before anything buffers.
#[test]
fn wave1d_batch_rejects_foreign_epoch_and_invalid_parked_state() {
    let hook = Wave1dHookStore::new();
    let f = hook.enqueue_claim("task:f", "enumerate_dir", "dir:f");
    let err = hook
        .rt
        .block_on(main_under_test::test_drive_completions(
            &hook.store,
            "scan-hook-1",
            hook.epoch + 1,
            vec![wave1d_item(
                "task:f",
                f.token,
                TaskOutcome::Complete,
                vec![],
            )],
            true,
        ))
        .expect_err("foreign epoch must fail");
    assert!(
        err.to_string().contains("is not this owner"),
        "production owner refusal: {err}"
    );
    let err = hook
        .rt
        .block_on(main_under_test::test_drive_completions(
            &hook.store,
            "scan-hook-1",
            hook.epoch,
            vec![wave1d_item(
                "task:f",
                f.token,
                TaskOutcome::Parked {
                    state: TaskState::Complete,
                    reason: "bad state".to_string(),
                },
                vec![],
            )],
            true,
        ))
        .expect_err("invalid parked state must fail");
    assert!(
        err.to_string().contains("invalid-parked-state"),
        "production parked-state refusal: {err}"
    );
    // Nothing buffered, nothing committed: the task is still leased.
    hook.rt.block_on(async {
        let row = hook
            .store
            .get_task("task:f")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(row.state, TaskState::Leased);
    });
}

/// A kill between buffer and flush commits nothing partial: the task
/// stays leased and the children stay absent, so redelivery after the
/// interruption redoes the work cleanly (idempotent, no doubles).
#[test]
fn wave1d_batch_interruption_commits_nothing_partial() {
    let hook = Wave1dHookStore::new();
    let g = hook.enqueue_claim("task:g", "enumerate_dir", "dir:g");
    let dropped = hook
        .rt
        .block_on(main_under_test::test_drive_completions(
            &hook.store,
            "scan-hook-1",
            hook.epoch,
            vec![wave1d_item(
                "task:g",
                g.token,
                TaskOutcome::Complete,
                vec![wave1d_child("task:g-child")],
            )],
            false,
        ))
        .expect("drop");
    assert!(dropped.is_empty(), "nothing classifies without a flush");
    hook.rt.block_on(async {
        let parent = hook
            .store
            .get_task("task:g")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(parent.state, TaskState::Leased, "parent stays leased");
        assert!(
            hook.store
                .get_task("task:g-child")
                .await
                .expect("get")
                .is_none(),
            "children stay absent"
        );
    });
    // Redelivery after the interruption: reclaim, redo, apply once.
    let reclaimed = hook.rt.block_on(async {
        hook.store
            .release_claim("task:g", g.token, hook.epoch, repo_scan::store::now_ms())
            .await
            .expect("release");
        let reclaimed = hook
            .store
            .claim_tasks(hook.epoch, 16, 60_000, repo_scan::store::now_ms())
            .await
            .expect("reclaim");
        reclaimed
            .into_iter()
            .find(|c| c.task.id == "task:g")
            .expect("reclaimed")
            .token
    });
    let results = hook
        .rt
        .block_on(main_under_test::test_drive_completions(
            &hook.store,
            "scan-hook-1",
            hook.epoch,
            vec![wave1d_item(
                "task:g",
                reclaimed,
                TaskOutcome::Complete,
                vec![wave1d_child("task:g-child")],
            )],
            true,
        ))
        .expect("redrive");
    assert_eq!(results.len(), 1);
    assert!(!results[0].stale);
    hook.rt.block_on(async {
        let parent = hook
            .store
            .get_task("task:g")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(parent.state, TaskState::Complete);
        assert!(
            hook.store
                .get_task("task:g-child")
                .await
                .expect("get")
                .is_some(),
            "children saved with the redelivered completion"
        );
    });
}

/// Children commit atomically with the parent completion: one flush
/// leaves the parent complete and every buffered child durable.
#[test]
fn wave1d_batch_children_commit_with_parent_completion() {
    let hook = Wave1dHookStore::new();
    let h = hook.enqueue_claim("task:h", "enumerate_dir", "dir:h");
    let results = hook
        .rt
        .block_on(main_under_test::test_drive_completions(
            &hook.store,
            "scan-hook-1",
            hook.epoch,
            vec![wave1d_item(
                "task:h",
                h.token,
                TaskOutcome::Complete,
                vec![
                    wave1d_child("task:h-child-1"),
                    wave1d_child("task:h-child-2"),
                ],
            )],
            true,
        ))
        .expect("drive");
    assert_eq!(results.len(), 1);
    assert!(!results[0].stale);
    hook.rt.block_on(async {
        let parent = hook
            .store
            .get_task("task:h")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(parent.state, TaskState::Complete);
        for child in ["task:h-child-1", "task:h-child-2"] {
            assert!(
                hook.store.get_task(child).await.expect("get").is_some(),
                "{child} durable with the parent completion"
            );
        }
    });
}

/// Retention prunes the oldest rows past the bound in one transaction,
/// keeps the newest window plus the tip, and leaves smaller journals
/// alone.
#[test]
fn wave1d_retention_prunes_prefix_keeping_tip() {
    use repo_scan::store::NewScanEvent;

    let hook = Wave1dHookStore::new();
    hook.rt.block_on(async {
        for seq in 1..=10u64 {
            let class = match seq {
                1 => "scan_started",
                10 => "scan_completed",
                _ => "location_found",
            };
            hook.store
                .append_scan_event(&NewScanEvent {
                    scan_id: "scan-prune-1",
                    seq,
                    catalog_rev: 1,
                    event_offset: seq - 1,
                    event_type: class,
                    op: "add",
                    reset: false,
                    records: b"{}",
                })
                .await
                .expect("append");
        }
    });
    let outcome = hook
        .rt
        .block_on(main_under_test::test_prune_scan_events(
            &hook.store,
            "scan-prune-1",
            4,
        ))
        .expect("prune");
    assert_eq!(
        outcome,
        main_under_test::TestPruneOutcome {
            retained: 4,
            cutoff: 6,
            pruned: true,
        }
    );
    hook.rt.block_on(async {
        let rows = hook
            .store
            .read_scan_events("scan-prune-1", 0, 100)
            .await
            .expect("read");
        let seqs: Vec<u64> = rows.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![7, 8, 9, 10], "newest window survives");
        assert_eq!(rows.last().expect("tip").event_type, "scan_completed");
    });
    // Under the bound: no transaction, nothing pruned.
    let outcome = hook
        .rt
        .block_on(main_under_test::test_prune_scan_events(
            &hook.store,
            "scan-prune-1",
            50,
        ))
        .expect("prune");
    assert_eq!(
        outcome,
        main_under_test::TestPruneOutcome {
            retained: 4,
            cutoff: 6,
            pruned: false,
        }
    );
}

/// Cursor resolution matrix through the production resolver: covered
/// cursors resume after their `(rev, off)` position; missing, diverged,
/// and beyond-tip cursors reset; the coalescible gauge never diverges;
/// seq 0 replays from the start; corrupt cursors stay errors.
#[test]
fn wave1d_cursor_resolution_matrix() {
    use repo_scan::scan_events::Cursor;
    use repo_scan::store::NewScanEvent;

    let hook = Wave1dHookStore::new();
    hook.rt.block_on(async {
        for (seq, class) in [
            (1u64, "scan_started"),
            (2u64, "discovery_progress"),
            (3u64, "location_found"),
        ] {
            hook.store
                .append_scan_event(&NewScanEvent {
                    scan_id: "scan-cursor-1",
                    seq,
                    catalog_rev: 5,
                    event_offset: seq - 1,
                    event_type: class,
                    op: if class == "discovery_progress" {
                        "replace"
                    } else {
                        "add"
                    },
                    reset: false,
                    records: b"{}",
                })
                .await
                .expect("append");
        }
    });
    let resolve = |after: Option<String>| {
        hook.rt.block_on(main_under_test::test_resolve_after_cursor(
            &hook.store,
            "scan-cursor-1",
            after,
        ))
    };
    let cursor = |seq: u64, rev: u64, off: u64| {
        Cursor {
            seq,
            catalog_rev: rev,
            event_offset: off,
        }
        .encode()
    };
    // Covered cursors resume after their own (rev, off) position.
    assert_eq!(
        resolve(Some(cursor(3, 5, 2))).expect("match"),
        main_under_test::TestCursorResolution {
            reset_first: false,
            after: Some((5, 2)),
        }
    );
    assert_eq!(
        resolve(Some(cursor(2, 5, 1))).expect("gauge match"),
        main_under_test::TestCursorResolution {
            reset_first: false,
            after: Some((5, 1)),
        }
    );
    // A drifted gauge position still resumes (never diverges): the
    // reader continues after its own position, losing nothing between.
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
        resolve(Some(cursor(2, 5, 1))).expect("gauge drift"),
        main_under_test::TestCursorResolution {
            reset_first: false,
            after: Some((5, 1)),
        }
    );
    // A drifted record position diverges: resync with reset.
    assert_eq!(
        resolve(Some(cursor(3, 99, 2))).expect("diverged"),
        main_under_test::TestCursorResolution {
            reset_first: true,
            after: None,
        }
    );
    // Missing rows (pruned prefix, beyond tip): resync with reset.
    assert_eq!(
        resolve(Some(cursor(99, 5, 0))).expect("beyond tip"),
        main_under_test::TestCursorResolution {
            reset_first: true,
            after: None,
        }
    );
    // Seq 0 replays from the start without reset.
    assert_eq!(
        resolve(Some(cursor(0, 0, 0))).expect("seq 0"),
        main_under_test::TestCursorResolution {
            reset_first: false,
            after: None,
        }
    );
    assert_eq!(
        resolve(None).expect("no cursor"),
        main_under_test::TestCursorResolution {
            reset_first: false,
            after: None,
        }
    );
    // Empty journal + nonzero cursor: resync with reset.
    let empty = hook
        .rt
        .block_on(main_under_test::test_resolve_after_cursor(
            &hook.store,
            "scan-no-such-journal",
            Some(cursor(5, 1, 0)),
        ))
        .expect("empty journal");
    assert_eq!(
        empty,
        main_under_test::TestCursorResolution {
            reset_first: true,
            after: None,
        }
    );
    // Corrupt cursors stay usage errors.
    let err = resolve(Some("!!!".to_string())).expect_err("corrupt must fail");
    assert!(
        err.to_string().contains("corrupt --after"),
        "production corrupt-cursor error: {err}"
    );
}

/// Progress ticks coalesce through the production journal: many ticks
/// leave exactly the newest progress row, and the interleaved record
/// event survives.
#[test]
fn wave1d_progress_ticks_coalesce_newest_survives_records_kept() {
    let hook = Wave1dHookStore::new();
    let outcome = hook
        .rt
        .block_on(main_under_test::test_journal_progress_ticks(
            &hook.store,
            "scan-progress-1",
            5,
        ))
        .expect("ticks");
    assert_eq!(outcome.progress_rows, 1, "one gauge row survives");
    assert_eq!(
        outcome.survivor_records["tick"], 4,
        "the survivor is the newest tick"
    );
    assert_eq!(outcome.error_rows, 1, "record events are never dropped");
}
