//! Incremental discovery event cursors (spec §13, docs/MACOS_QUAL.md).
//!
//! Persistent per-volume history: event-history UUID + separate ingested and
//! reconciled cursors. Ingestion advances only with the commit storing its
//! invalidations; reconciliation advances only when the boundary's work is
//! satisfied. Event IDs are increasing but never assumed consecutive.
//!
//! Layering: the native or fixture byte stream lives behind
//! [`crate::platform::EventSource`] (`platform/macos.rs` owns the
//! `objc2-core-services` FSEventStream history surface; `platform/linux.rs`
//! owns the scripted replay). This module owns everything above that seam:
//! the open rule, batch coalescing, the ingest/reconcile cursor protocol,
//! own-bookkeeping suppression, per-volume observation boundaries, and the
//! poll-free portable fallback. Durable rows live in the store event journal
//! (`TursoStore::append_event` = ingest commit,
//! `TursoStore::mark_event_reconciled` = reconcile commit); [`CursorJournal`]
//! is the sync, platform-free protocol over those rows, with
//! [`MemoryCursorJournal`] as the fixture and [`volume_cursor_from_rows`] as
//! the Turso mapping.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Bounded event batch: 256 entries (spec §5 enumeration IPC batch).
pub const MAX_BATCH_EVENTS: usize = 256;
/// Bounded event batch: 256 KiB (spec §5 enumeration IPC batch).
pub const MAX_BATCH_BYTES: usize = 256 * 1024;
/// Pending-invalidation cap per volume. Past this, per-path plans collapse
/// to one volume-wide recursive rescan (a busy volume must not create an
/// unbounded queue of identical work).
pub const MAX_PENDING_INVALIDATIONS: usize = 4096;

/// Opaque per-volume event-history identity (FSEvents UUID on macOS,
/// fixture string on Linux).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HistoryUuid(pub String);

impl std::fmt::Display for HistoryUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque event cursor (monotonic per volume; never store 0 / RootChanged).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventCursorId(pub u64);

impl std::fmt::Display for EventCursorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Persisted per-volume cursor record (spec §§11+13).
#[derive(Debug, Clone, Default)]
pub struct VolumeCursor {
    /// Stored history UUID.
    pub uuid: Option<HistoryUuid>,
    /// Highest event ID durably recorded with its invalidations.
    pub ingested: Option<EventCursorId>,
    /// Highest ID whose required work is satisfied.
    pub reconciled: Option<EventCursorId>,
    /// Wrap/drop/root-changed markers seen, for audit.
    pub flags_seen: Vec<String>,
}

impl VolumeCursor {
    /// True when the volume has no event history (NULL UUID): full
    /// traversal + periodic re-reconciliation, never event completeness.
    #[must_use]
    pub fn is_eventless(&self) -> bool {
        self.uuid.is_none()
    }
}

/// A batch of history events delivered by the platform source.
#[derive(Debug, Clone)]
pub struct EventBatch {
    /// Volume these events belong to.
    pub volume_key: String,
    /// Highest event ID covered by this batch.
    pub high_water: EventCursorId,
    /// Invalidated subtree paths (coalesced; bounded batch).
    pub invalidations: Vec<std::path::PathBuf>,
    /// True when the historical phase ended (`HistoryDone` sentinel).
    pub history_done: bool,
    /// Continuity signals requiring reconciliation, not silent reuse.
    pub signals: Vec<ContinuitySignal>,
}

/// Native continuity signals (MACOS_QUAL §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuitySignal {
    /// UUID missing/changed, live ID below stored, or counter wrap: discard
    /// cursors, invalidate volume scope, fresh traversal generation.
    HistoryInvalid,
    /// Coalescing/overrun: recursive rescan of the event path.
    MustScanSubDirs,
    /// Watched root moved/deleted: rescan hierarchy, re-resolve identity.
    RootChanged,
    /// Topology change: mount-table refresh, new volume rows.
    MountChanged,
}

/// Cursor protocol. The store persists [`VolumeCursor`]; the platform module
/// supplies the native or fixture event stream behind this trait.
pub trait EventCursor: Send {
    /// Open rule (MACOS_QUAL §2): reuse stored `(uuid, cursor)` only if the
    /// live UUID is non-NULL, equals the stored UUID, and the live ID is at
    /// or above the stored cursor. Otherwise report `HistoryInvalid`.
    fn open(
        &mut self,
        volume_key: &str,
        stored: Option<VolumeCursor>,
    ) -> crate::Result<OpenedStream>;

    /// Record the observation boundary for this scan (per-volume live ID).
    /// Completion is claimed relative to it; later arrivals stay queued.
    fn boundary(&self, volume_key: &str) -> crate::Result<EventCursorId>;
}

/// An opened per-volume history stream.
#[derive(Debug)]
pub struct OpenedStream {
    /// Volume key.
    pub volume_key: String,
    /// Live history UUID, if the volume has history (`None` = eventless
    /// volume: full traversal + periodic re-reconciliation).
    pub live_uuid: Option<HistoryUuid>,
    /// Whether stored cursors were accepted.
    pub resumed: bool,
}

// ---------------------------------------------------------------------------
// Open rule, cursor mapping, scope keys, coalescing (pure, platform-free)
// ---------------------------------------------------------------------------

/// Open-rule decision (MACOS_QUAL §2). The platform stream applies the same
/// rule natively; this pure form pins the logic for tests and drives the
/// durable side (`Reconciler::note_stream_opened`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenDecision {
    /// Stored `(uuid, cursor)` accepted; read history from `since`.
    Resume {
        /// Cursor to pass as `sinceWhen`.
        since: EventCursorId,
    },
    /// Start a fresh baseline; never reuse stored cursors.
    Fresh {
        /// Stored cursors were discarded: invalidate the volume scope.
        history_invalid: bool,
        /// Live UUID is NULL: the volume has no history at all.
        eventless: bool,
    },
}

impl OpenDecision {
    /// True when stored cursors were accepted.
    #[must_use]
    pub fn resumed(self) -> bool {
        matches!(self, OpenDecision::Resume { .. })
    }

    /// True when the volume scope must be invalidated.
    #[must_use]
    pub fn history_invalid(self) -> bool {
        matches!(
            self,
            OpenDecision::Fresh {
                history_invalid: true,
                ..
            }
        )
    }
}

/// Pure open rule: reuse stored `(uuid, cursor)` only if the live UUID is
/// non-NULL, equals the stored UUID, and the live ID is at or above the
/// stored ingested cursor. Anything else is a fresh baseline, invalidating
/// when previously stored cursors are discarded.
pub fn decide_open(
    stored: Option<&VolumeCursor>,
    live_uuid: Option<&str>,
    live_id: u64,
) -> OpenDecision {
    let Some(live) = live_uuid else {
        let had = stored.is_some_and(|s| s.uuid.is_some());
        return OpenDecision::Fresh {
            history_invalid: had,
            eventless: true,
        };
    };
    let Some(s) = stored else {
        return OpenDecision::Fresh {
            history_invalid: false,
            eventless: false,
        };
    };
    match (&s.uuid, s.ingested) {
        (Some(want), Some(cursor)) if want.0 == live && live_id >= cursor.0 => {
            OpenDecision::Resume { since: cursor }
        }
        _ => OpenDecision::Fresh {
            history_invalid: s.uuid.is_some(),
            eventless: false,
        },
    }
}

/// Reject a live ID below the stored ingested cursor (backup-restore, wrap,
/// or purge: cursors invalid, MACOS_QUAL §3). Callers invalidate the volume
/// scope on `Err`.
pub fn validate_live_progress(
    stored_ingested: Option<EventCursorId>,
    live_id: u64,
) -> crate::Result<()> {
    if let Some(cursor) = stored_ingested {
        if live_id < cursor.0 {
            return Err(crate::Error::Events(format!(
                "history-invalid: live event ID {live_id} below stored cursor {}; \
                 backup-restore/wrap/purge, volume scope must be invalidated",
                cursor.0
            )));
        }
    }
    Ok(())
}

/// Opaque cursor rendering for `event_journal.cursor` (decimal; never "0").
pub fn journal_cursor_string(cursor: EventCursorId) -> String {
    cursor.0.to_string()
}

/// Parse an `event_journal.cursor` value back. `None` on garbage.
pub fn parse_journal_cursor(raw: &str) -> Option<EventCursorId> {
    raw.parse::<u64>().ok().map(EventCursorId)
}

/// Derive a [`VolumeCursor`] from durable journal rows (Turso mapping:
/// `list_events` order, `append_event` = ingest commit,
/// `mark_event_reconciled` = reconcile commit). Ingested is the max cursor
/// with `ingested`; reconciled the max with `reconciled`; cursor 0 rows are
/// never treated as a cursor. `flags_seen` is empty: flag audit lives in
/// the errors table, not the journal rows.
pub fn volume_cursor_from_rows(
    volume: &str,
    rows: &[crate::store::EventRow],
) -> Option<VolumeCursor> {
    let mut matching: Vec<&crate::store::EventRow> =
        rows.iter().filter(|r| r.volume_id == volume).collect();
    if matching.is_empty() {
        return None;
    }
    matching.sort_by_key(|r| r.id);
    let uuid = matching.last().map(|r| HistoryUuid(r.history_uuid.clone()));
    let max_where = |flag: fn(&&crate::store::EventRow) -> bool| {
        matching
            .iter()
            .copied()
            .filter(&flag)
            .filter_map(|r| parse_journal_cursor(&r.cursor))
            .filter(|c| c.0 != 0)
            .max()
    };
    Some(VolumeCursor {
        uuid,
        ingested: max_where(|r| r.ingested),
        reconciled: max_where(|r| r.reconciled),
        flags_seen: Vec::new(),
    })
}

/// Scheduler scope key for one invalidated subtree path. `{:?}` escaping
/// keeps non-UTF-8 bytes lossless in the TEXT scope column.
pub fn subtree_scope_key(volume: &str, path: &Path) -> String {
    format!("path:{volume}:{path:?}")
}

/// Scheduler scope key for a whole volume (continuity loss, overflow).
pub fn volume_scope_key(volume: &str) -> String {
    format!("volume:{volume}")
}

/// Scheduler scope key for mount-table refresh work.
pub fn mounts_scope_key() -> &'static str {
    "mounts"
}

/// Collapse invalidations: sorted, deduplicated, and any path below an
/// already-listed ancestor removed (a busy directory must not create an
/// unbounded queue of identical work). Pure and unit-testable.
pub fn coalesce_invalidations(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.sort();
    paths.dedup();
    let mut out: Vec<PathBuf> = Vec::with_capacity(paths.len());
    for path in paths {
        let covered = out
            .last()
            .map(|a: &PathBuf| path.starts_with(a))
            .unwrap_or(false);
        if !covered {
            out.push(path);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Durable cursor journal: ingest vs reconcile separation (crash protocol)
// ---------------------------------------------------------------------------

/// One ingested-but-unreconciled boundary: work recorded durably, required
/// reconciliation not yet satisfied. A kill between ingest and reconcile
/// leaves these rows behind; reopening replays them idempotently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBoundary {
    /// Batch high-water mark.
    pub cursor: EventCursorId,
    /// Scheduler scopes invalidated by this batch.
    pub scopes: Vec<String>,
}

/// Result of one durable ingest write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestRecord {
    /// Ingested cursor after the write (unchanged on duplicates).
    pub advanced_to: Option<EventCursorId>,
    /// True when the batch was already recorded (`FullHistory` overlap or
    /// restart replay): no new work, safe to drop.
    pub duplicate: bool,
}

/// Sync, platform-free cursor-journal protocol. Production backs this with
/// the store event journal (`append_event` inside the same commit that
/// stores the batch's invalidations; `mark_event_reconciled` only when the
/// boundary's required work is satisfied). Crash points: kill after
/// `record_ingested` but before `mark_reconciled_through` loses no work —
/// the pending rows replay.
pub trait CursorJournal {
    /// Load the persisted cursor record, if any.
    fn load(&self, volume: &str) -> Option<VolumeCursor>;

    /// Record the UUID validated at stream open (resume keeps cursors;
    /// after `invalidate_history` this sets the fresh baseline).
    fn record_open(&mut self, volume: &str, uuid: Option<HistoryUuid>, flag: Option<String>);

    /// Durably record one batch and advance ingested to its high-water mark
    /// in the same atomic write. Idempotent on replay (`duplicate: true`).
    /// Never persists cursor 0. Errors when the batch UUID disagrees with
    /// the recorded one (caller must `invalidate_history` first).
    fn record_ingested(
        &mut self,
        volume: &str,
        uuid: Option<&HistoryUuid>,
        high_water: EventCursorId,
        scopes: &[String],
        signals: &[ContinuitySignal],
    ) -> crate::Result<IngestRecord>;

    /// Ingested-but-unreconciled boundaries, ascending.
    fn pending(&self, volume: &str) -> Vec<PendingBoundary>;

    /// Advance reconciled through `through` (drops covered pending rows).
    /// Errors above the ingested cursor: reconciliation can never run ahead
    /// of durable ingest.
    fn mark_reconciled_through(
        &mut self,
        volume: &str,
        through: EventCursorId,
    ) -> crate::Result<()>;

    /// Continuity loss: discard UUID + cursors + pending rows for the
    /// volume. The catalog scope is invalidated alongside; never assume the
    /// old catalog is current.
    fn invalidate_history(&mut self, volume: &str, reason: &str) -> crate::Result<()>;
}

#[derive(Debug, Clone, Default)]
struct VolumeState {
    uuid: Option<HistoryUuid>,
    ingested: Option<EventCursorId>,
    reconciled: Option<EventCursorId>,
    flags_seen: Vec<String>,
    pending: BTreeMap<u64, Vec<String>>,
}

fn note_signals(flags_seen: &mut Vec<String>, signals: &[ContinuitySignal]) {
    for signal in signals {
        let name = match signal {
            ContinuitySignal::HistoryInvalid => "history-invalid",
            ContinuitySignal::MustScanSubDirs => "must-scan-subdirs",
            ContinuitySignal::RootChanged => "root-changed",
            ContinuitySignal::MountChanged => "mount-changed",
        };
        if !flags_seen.iter().any(|f| f == name) {
            flags_seen.push(name.to_string());
        }
    }
}

/// In-memory [`CursorJournal`] for unit tests and Linux fixtures. Same
/// transition semantics as the durable journal; no crash durability
/// (restart tests use the Turso-backed journal instead).
#[derive(Debug, Clone, Default)]
pub struct MemoryCursorJournal {
    volumes: HashMap<String, VolumeState>,
}

impl MemoryCursorJournal {
    /// Empty fixture journal.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CursorJournal for MemoryCursorJournal {
    fn load(&self, volume: &str) -> Option<VolumeCursor> {
        self.volumes.get(volume).map(|s| VolumeCursor {
            uuid: s.uuid.clone(),
            ingested: s.ingested,
            reconciled: s.reconciled,
            flags_seen: s.flags_seen.clone(),
        })
    }

    fn record_open(&mut self, volume: &str, uuid: Option<HistoryUuid>, flag: Option<String>) {
        let state = self.volumes.entry(volume.to_string()).or_default();
        state.uuid = uuid;
        if let Some(flag) = flag {
            if !state.flags_seen.iter().any(|f| f == &flag) {
                state.flags_seen.push(flag);
            }
        }
    }

    fn record_ingested(
        &mut self,
        volume: &str,
        uuid: Option<&HistoryUuid>,
        high_water: EventCursorId,
        scopes: &[String],
        signals: &[ContinuitySignal],
    ) -> crate::Result<IngestRecord> {
        let state = self.volumes.entry(volume.to_string()).or_default();
        match (&state.uuid, uuid) {
            (Some(have), Some(want)) if have != want => {
                return Err(crate::Error::Events(format!(
                    "history-invalid: volume {volume} recorded UUID {have} \
                     disagrees with batch UUID {want}; invalidate first"
                )));
            }
            (None, Some(want)) => state.uuid = Some((*want).clone()),
            _ => {}
        }
        note_signals(&mut state.flags_seen, signals);
        // RootChanged carries event ID zero: record its scopes, never the
        // cursor.
        if high_water.0 == 0 {
            let entry = state.pending.entry(0).or_default();
            for scope in scopes {
                if !entry.contains(scope) {
                    entry.push(scope.clone());
                }
            }
            return Ok(IngestRecord {
                advanced_to: state.ingested,
                duplicate: false,
            });
        }
        // FullHistory overlap / restart replay: IDs at or below ingested
        // are already recorded; idempotent no-op.
        if state.ingested.is_some_and(|ing| high_water <= ing) {
            return Ok(IngestRecord {
                advanced_to: state.ingested,
                duplicate: true,
            });
        }
        let entry = state.pending.entry(high_water.0).or_default();
        for scope in scopes {
            if !entry.contains(scope) {
                entry.push(scope.clone());
            }
        }
        state.ingested = Some(high_water);
        Ok(IngestRecord {
            advanced_to: Some(high_water),
            duplicate: false,
        })
    }

    fn pending(&self, volume: &str) -> Vec<PendingBoundary> {
        self.volumes
            .get(volume)
            .map(|s| {
                s.pending
                    .iter()
                    .map(|(cursor, scopes)| PendingBoundary {
                        cursor: EventCursorId(*cursor),
                        scopes: scopes.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn mark_reconciled_through(
        &mut self,
        volume: &str,
        through: EventCursorId,
    ) -> crate::Result<()> {
        let state = self.volumes.entry(volume.to_string()).or_default();
        let ingested = state.ingested.map(|c| c.0).unwrap_or(0);
        if through.0 > ingested && !(through.0 == 0 && state.ingested.is_none()) {
            return Err(crate::Error::Events(format!(
                "reconcile-ahead-of-ingest: volume {volume} through {} \
                 exceeds ingested {ingested}",
                through.0
            )));
        }
        state.pending.retain(|cursor, _| *cursor > through.0);
        if state.reconciled.map(|c| c.0).unwrap_or(0) < through.0
            || (through.0 == 0 && state.reconciled.is_none())
        {
            state.reconciled = Some(through);
        }
        Ok(())
    }

    fn invalidate_history(&mut self, volume: &str, reason: &str) -> crate::Result<()> {
        let state = self.volumes.entry(volume.to_string()).or_default();
        state.uuid = None;
        state.ingested = None;
        state.reconciled = None;
        state.pending.clear();
        let flag = format!("invalidated:{reason}");
        if !state.flags_seen.iter().any(|f| f == &flag) {
            state.flags_seen.push(flag);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bounded batch coalescing (platform-free; mirrors the native callback path)
// ---------------------------------------------------------------------------

/// Platform-free raw event flags (one native callback triple, decoded).
#[derive(Debug, Clone, Copy, Default)]
pub struct RawFlags {
    /// Coalescing/overrun: recursive rescan of the event path.
    pub must_scan_subdirs: bool,
    /// Watched root moved/deleted (event ID is zero: never a cursor).
    pub root_changed: bool,
    /// 64-bit counter wrapped: all prior IDs invalid.
    pub ids_wrapped: bool,
    /// Mount/unmount under watch: topology refresh.
    pub mount_changed: bool,
    /// Historical-phase sentinel: path meaningless, ignored.
    pub history_done: bool,
    /// Dropped-event markers are informational only (the accompanying
    /// MustScanSubDirs drives the rescan); recorded for audit, no signal.
    pub dropped: bool,
}

impl RawFlags {
    /// No flags set.
    pub fn none() -> Self {
        Self::default()
    }
}

#[cfg(unix)]
fn bytes_to_pathbuf(bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

#[cfg(not(unix))]
fn bytes_to_pathbuf(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(&bytes).into_owned())
}

/// Builds one bounded, coalesced [`EventBatch`] from raw native triples.
/// Flush at the first limit (256 entries / 256 KiB); overflow coalesces to
/// a volume-wide `MustScanSubDirs` signal instead of growing memory — an
/// empty invalidation list plus that signal means "rescan the watched
/// roots", never "nothing changed".
#[derive(Debug)]
pub struct BatchCoalescer {
    volume_key: String,
    paths: Vec<PathBuf>,
    bytes: usize,
    high_water: u64,
    saw_history_done: bool,
    saw_dropped: bool,
    signals: Vec<ContinuitySignal>,
    overflowed: bool,
}

impl BatchCoalescer {
    /// Empty coalescer for one volume.
    pub fn new(volume_key: &str) -> Self {
        Self {
            volume_key: volume_key.to_string(),
            paths: Vec::new(),
            bytes: 0,
            high_water: 0,
            saw_history_done: false,
            saw_dropped: false,
            signals: Vec::new(),
            overflowed: false,
        }
    }

    /// Push one raw `(path bytes, event ID, flags)` triple.
    pub fn push(&mut self, path: Vec<u8>, id: u64, flags: &RawFlags) {
        if flags.history_done {
            self.saw_history_done = true;
            return;
        }
        if flags.must_scan_subdirs {
            self.signals.push(ContinuitySignal::MustScanSubDirs);
        }
        if flags.root_changed {
            self.signals.push(ContinuitySignal::RootChanged);
        }
        if flags.ids_wrapped {
            self.signals.push(ContinuitySignal::HistoryInvalid);
        }
        if flags.mount_changed {
            self.signals.push(ContinuitySignal::MountChanged);
        }
        if flags.dropped {
            self.saw_dropped = true;
        }
        if self.overflowed {
            return;
        }
        if self.paths.len() >= MAX_BATCH_EVENTS || self.bytes >= MAX_BATCH_BYTES {
            self.overflowed = true;
            return;
        }
        // Event ID zero (RootChanged) is recorded as a path, never as a
        // cursor.
        if id != 0 && id > self.high_water {
            self.high_water = id;
        }
        self.bytes += path.len();
        self.paths.push(bytes_to_pathbuf(path));
    }

    /// True when the batch hit a bound and coalesced to volume-wide.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Finish the batch. `None` only when nothing was observed at all.
    pub fn finish(mut self) -> Option<EventBatch> {
        if self.overflowed {
            self.signals.push(ContinuitySignal::MustScanSubDirs);
        }
        self.signals.sort_by_key(|s| *s as u8);
        self.signals.dedup();
        if self.paths.is_empty()
            && self.signals.is_empty()
            && !self.saw_history_done
            && !self.saw_dropped
        {
            return None;
        }
        Some(EventBatch {
            volume_key: self.volume_key,
            high_water: EventCursorId(self.high_water),
            invalidations: coalesce_invalidations(self.paths),
            history_done: self.saw_history_done,
            signals: self.signals,
        })
    }
}

// ---------------------------------------------------------------------------
// Own-bookkeeping recognition: exact file identity, never parent exclusion
// ---------------------------------------------------------------------------

/// Exact file identity of one tool-owned bookkeeping file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    /// Device number.
    pub dev: u64,
    /// Filesystem object (inode) number.
    pub ino: u64,
}

#[cfg(unix)]
fn identity_of(metadata: &std::fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn identity_of(_metadata: &std::fs::Metadata) -> Option<FileIdentity> {
    // No stable identity primitive: fail open (reconcile normally).
    None
}

/// Classification of one event path against registered tool state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookkeepingClass {
    /// The path's current identity exactly matches a registered tool file:
    /// suppress with identity + operation evidence.
    Own(FileIdentity),
    /// Not tool state: reconcile normally.
    Foreign,
    /// Identity could not be observed (race, permission, no primitive):
    /// reconcile normally. Unknown is never suppressed.
    Unknown,
}

/// Registry of the tool's own bookkeeping files (state DB, sidecars,
/// staged reports). Suppression matches the file's exact `(dev, ino)`
/// identity at classify time — registering `/state/x` never suppresses
/// `/state/x/child` (different identity) or a replaced file at the same
/// path (identity changed: the new file reconciles normally, the safe
/// direction).
#[derive(Debug, Clone, Default)]
pub struct OwnBookkeeping {
    owned: HashMap<FileIdentity, PathBuf>,
}

impl OwnBookkeeping {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one exact tool-owned file, observing its current identity.
    /// Call at open/publish time; re-register after atomic replacement
    /// (replacement changes identity by design).
    pub fn register(&mut self, path: &Path) -> std::io::Result<FileIdentity> {
        let metadata = std::fs::symlink_metadata(path)?;
        let identity = identity_of(&metadata).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no stable file-identity primitive on this platform",
            )
        })?;
        self.owned.insert(identity, path.to_path_buf());
        Ok(identity)
    }

    /// Classify one event path by its current exact identity.
    pub fn classify(&self, path: &Path) -> BookkeepingClass {
        let identity = std::fs::symlink_metadata(path)
            .ok()
            .and_then(|m| identity_of(&m));
        match identity {
            Some(id) if self.owned.contains_key(&id) => BookkeepingClass::Own(id),
            Some(_) => BookkeepingClass::Foreign,
            None => BookkeepingClass::Unknown,
        }
    }

    /// Registered path for one suppressed identity (report evidence).
    pub fn registered_path(&self, identity: &FileIdentity) -> Option<&Path> {
        self.owned.get(identity).map(PathBuf::as_path)
    }

    /// Number of registered files.
    pub fn len(&self) -> usize {
        self.owned.len()
    }

    /// True when nothing is registered.
    pub fn is_empty(&self) -> bool {
        self.owned.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Scan gate: monitor-before-traverse, reconcile-before-completeness-claim
// ---------------------------------------------------------------------------

/// Enforces the §13 ordering per volume: monitoring starts before the
/// initial traversal, and completeness is claimed only after the recorded
/// boundary's required work is reconciled. Each volume is gated alone —
/// there is no global-quiet wait.
#[derive(Debug, Clone, Default)]
pub struct ScanGate {
    monitored: HashSet<String>,
    traversal_begun: bool,
}

impl ScanGate {
    /// Closed gate: nothing monitored, traversal not begun.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that monitoring started for one volume. Call at stream open,
    /// before any traversal of that volume.
    pub fn note_monitoring(&mut self, volume: &str) {
        self.monitored.insert(volume.to_string());
    }

    /// True when monitoring started for this volume.
    pub fn is_monitored(&self, volume: &str) -> bool {
        self.monitored.contains(volume)
    }

    /// Begin traversal. Errors when no volume is monitored yet: the stream
    /// must exist before the walk so changes during the walk are recorded.
    pub fn begin_traversal(&mut self) -> crate::Result<()> {
        if self.monitored.is_empty() {
            return Err(crate::Error::Events(
                "monitor-before-traverse: traversal began with no monitored volume; \
                 start event monitoring before the initial traversal"
                    .to_string(),
            ));
        }
        self.traversal_begun = true;
        Ok(())
    }

    /// Claim completeness for ONE volume relative to its own observation
    /// boundary. Later arrivals stay queued past the boundary; other
    /// volumes' state is irrelevant. Errors on unmonitored volumes,
    /// pre-traversal claims, invalid/eventless history, or reconciled
    /// cursors below the boundary.
    pub fn claim_volume_complete(
        &self,
        volume: &str,
        reconciled: Option<EventCursorId>,
        boundary: EventCursorId,
        history_valid: bool,
    ) -> crate::Result<()> {
        if !self.monitored.contains(volume) {
            return Err(crate::Error::Events(format!(
                "monitor-before-traverse: volume {volume} was never monitored; \
                 no completeness claim without monitoring"
            )));
        }
        if !self.traversal_begun {
            return Err(crate::Error::Events(format!(
                "reconcile-before-claim: volume {volume} claim before traversal began"
            )));
        }
        if !history_valid {
            return Err(crate::Error::Events(format!(
                "reconcile-before-claim: volume {volume} history invalid or eventless; \
                 full traversal + reconciliation required, events alone prove nothing"
            )));
        }
        let at = reconciled.map(|c| c.0);
        if at.map(|at| at < boundary.0).unwrap_or(true) {
            return Err(crate::Error::Events(format!(
                "reconcile-before-claim: volume {volume} reconciled {} below boundary {}; \
                 arrivals past the boundary stay queued",
                at.map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                boundary.0
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Invalidation planning: subtrees, continuity loss, portable fallback
// ---------------------------------------------------------------------------

/// One scheduler invalidation derived from event evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubtreePlan {
    /// Scheduler scope key to invalidate.
    pub scope_key: String,
    /// Recursive re-inspection of exactly this subtree (MustScanSubDirs).
    pub recursive: bool,
    /// Human-readable reason (report evidence).
    pub reason: String,
}

/// Map one batch's signals + invalidations to scheduler invalidations:
/// - `HistoryInvalid` (UUID loss, wrap, live-below-stored): continuity is
///   unavailable, so the whole volume scope is invalidated; per-path plans
///   are subsumed, never trusted.
/// - `RootChanged`: the watched root moved or was deleted: rescan the
///   hierarchy (volume-wide) and re-resolve root identity.
/// - `MountChanged`: mount-table refresh scope plus per-path plans.
/// - `MustScanSubDirs` with paths: recursive re-inspection of exactly those
///   subtrees (newly created or moved-in directories are inspected
///   recursively; the scheduler observes each entry's kind at reconcile
///   time). Without paths (channel/burst overflow): volume-wide.
/// - Plain paths: the path scope plus its parent scope, so created or
///   moved-in entries are discovered by re-enumeration even though the
///   event names only the changed path.
///
/// Past [`MAX_PENDING_INVALIDATIONS`] plans, everything collapses to one
/// volume-wide recursive rescan.
pub fn continuity_plan(
    volume: &str,
    signals: &[ContinuitySignal],
    invalidations: &[PathBuf],
) -> Vec<SubtreePlan> {
    if signals.contains(&ContinuitySignal::HistoryInvalid) {
        return vec![SubtreePlan {
            scope_key: volume_scope_key(volume),
            recursive: true,
            reason: "history-invalid: continuity unavailable, volume scope invalidated".to_string(),
        }];
    }
    if signals.contains(&ContinuitySignal::RootChanged) {
        return vec![SubtreePlan {
            scope_key: volume_scope_key(volume),
            recursive: true,
            reason: "root-changed: watched root moved/deleted, rescan hierarchy".to_string(),
        }];
    }
    let mut plans = Vec::new();
    if signals.contains(&ContinuitySignal::MountChanged) {
        plans.push(SubtreePlan {
            scope_key: mounts_scope_key().to_string(),
            recursive: false,
            reason: "mount-changed: refresh mount table, add new volume rows".to_string(),
        });
    }
    let must_scan = signals.contains(&ContinuitySignal::MustScanSubDirs);
    if must_scan && invalidations.is_empty() {
        plans.push(SubtreePlan {
            scope_key: volume_scope_key(volume),
            recursive: true,
            reason: "must-scan-subdirs: coalesced/overflow burst, rescan watched roots".to_string(),
        });
        return plans;
    }
    for path in invalidations {
        if must_scan {
            plans.push(SubtreePlan {
                scope_key: subtree_scope_key(volume, path),
                recursive: true,
                reason: "must-scan-subdirs: recursive re-inspection of subtree".to_string(),
            });
        } else {
            plans.push(SubtreePlan {
                scope_key: subtree_scope_key(volume, path),
                recursive: false,
                reason: "changed: re-inspect path".to_string(),
            });
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    plans.push(SubtreePlan {
                        scope_key: subtree_scope_key(volume, parent),
                        recursive: false,
                        reason: "changed: re-enumerate parent, discover created/moved-in entries"
                            .to_string(),
                    });
                }
            }
        }
    }
    // Deduplicate scope keys, keeping the strongest (recursive) entry.
    let mut by_scope: BTreeMap<String, SubtreePlan> = BTreeMap::new();
    for plan in plans {
        let replace = match by_scope.get(&plan.scope_key) {
            Some(have) => plan.recursive && !have.recursive,
            None => true,
        };
        if replace {
            by_scope.insert(plan.scope_key.clone(), plan);
        }
    }
    let mut plans: Vec<SubtreePlan> = by_scope.into_values().collect();
    if plans.len() > MAX_PENDING_INVALIDATIONS {
        plans = vec![SubtreePlan {
            scope_key: volume_scope_key(volume),
            recursive: true,
            reason: "coalesced-overflow: pending invalidations past bound, volume rescan"
                .to_string(),
        }];
    }
    plans
}

/// Portable fallback for volumes without event history (Linux fixtures and
/// NULL-UUID macOS volumes). Poll-free by construction: this is a pure,
/// deterministic mapping with no threads, timers, sleeps, or polling — it
/// records an `unavailable-history` gap and schedules reconciliation scope.
/// Periodic full reconciliation stays documented scheduler policy consuming
/// that scope, not a loop here.
pub mod portable {
    /// Stable gap category for volumes without usable event history.
    pub const UNAVAILABLE_HISTORY_CATEGORY: &str = "unavailable-history";

    /// Deterministic fallback plan for one eventless volume.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FallbackPlan {
        /// Volume key.
        pub volume_key: String,
        /// Why history is unavailable (NULL UUID, unsupported FS, fixture).
        pub reason: String,
        /// Gap category for `store.record_error` (always
        /// [`UNAVAILABLE_HISTORY_CATEGORY`]).
        pub gap_category: &'static str,
        /// Human-readable gap detail (report evidence).
        pub gap_detail: String,
        /// Scheduler scope to invalidate (reconciliation work scheduled).
        pub reconcile_scope: String,
    }

    /// Build the fallback plan. Pure: same inputs always yield the same
    /// plan; no clock, no IO, no polling.
    pub fn plan_unavailable_history(volume_key: &str, reason: &str) -> FallbackPlan {
        FallbackPlan {
            volume_key: volume_key.to_string(),
            reason: reason.to_string(),
            gap_category: UNAVAILABLE_HISTORY_CATEGORY,
            gap_detail: format!(
                "volume {volume_key} has no usable event history ({reason}); \
                 full traversal + scheduled reconciliation instead of incremental events"
            ),
            reconcile_scope: super::volume_scope_key(volume_key),
        }
    }

    impl FallbackPlan {
        /// Schedule the reconciliation work through any invalidation sink.
        /// The owner additionally records
        /// (`reconcile_scope`, `gap_category`, `gap_detail`) via
        /// `store.record_error` so the gap is durable and reportable.
        pub fn apply(&self, sink: &mut dyn super::InvalidationSink) -> crate::Result<()> {
            sink.invalidate(&self.reconcile_scope)
        }
    }
}

// ---------------------------------------------------------------------------
// Reconciler: ingest batches, invalidate scopes, advance cursors in order
// ---------------------------------------------------------------------------

/// Scheduler invalidation sink. Every [`crate::scheduler::Scheduler`] is
/// one (blanket impl); fixtures use [`MemorySink`].
pub trait InvalidationSink {
    /// Bump the scope revision and schedule reconciliation. Idempotent:
    /// replays after a kill are safe.
    fn invalidate(&mut self, scope_key: &str) -> crate::Result<()>;
}

impl<T: crate::scheduler::Scheduler + ?Sized> InvalidationSink for T {
    fn invalidate(&mut self, scope_key: &str) -> crate::Result<()> {
        crate::scheduler::Scheduler::invalidate(self, scope_key)
    }
}

/// Required-work probe: reconciled cursors advance only over scopes with
/// no pending work.
pub trait WorkChecker {
    /// Pending (non-terminal) work units for one scope.
    fn pending_for_scope(&self, scope_key: &str) -> u64;
}

/// Combined reconcile IO: one object that both issues invalidations and
/// reports outstanding work (avoids dual-borrow call sites; the owner
/// wires one adapter over the scheduler + pending query).
pub trait ReconcileIo: InvalidationSink + WorkChecker {}

impl<T: InvalidationSink + WorkChecker + ?Sized> ReconcileIo for T {}

/// In-memory sink + checker for tests: invalidations bump revisions and go
/// pending until the test completes them.
#[derive(Debug, Clone, Default)]
pub struct MemorySink {
    revisions: HashMap<String, u64>,
    pending: HashSet<String>,
}

impl MemorySink {
    /// Empty fixture sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current revision of a scope (0 when never invalidated).
    pub fn revision(&self, scope_key: &str) -> u64 {
        self.revisions.get(scope_key).copied().unwrap_or(0)
    }

    /// Mark one scope's required work done.
    pub fn complete_scope(&mut self, scope_key: &str) {
        self.pending.remove(scope_key);
    }

    /// Scopes still awaiting work, sorted.
    pub fn pending_scopes(&self) -> Vec<String> {
        let mut out: Vec<String> = self.pending.iter().cloned().collect();
        out.sort();
        out
    }
}

impl InvalidationSink for MemorySink {
    fn invalidate(&mut self, scope_key: &str) -> crate::Result<()> {
        *self.revisions.entry(scope_key.to_string()).or_insert(0) += 1;
        self.pending.insert(scope_key.to_string());
        Ok(())
    }
}

impl WorkChecker for MemorySink {
    fn pending_for_scope(&self, scope_key: &str) -> u64 {
        u64::from(self.pending.contains(scope_key))
    }
}

/// Result of ingesting one batch.
#[derive(Debug, Clone)]
pub struct IngestOutcome {
    /// Volume key.
    pub volume_key: String,
    /// Ingested cursor after the write (`None` when history was discarded).
    pub advanced_to: Option<EventCursorId>,
    /// True when the batch was already recorded (safe to drop).
    pub duplicate: bool,
    /// True when the batch carried `HistoryInvalid` (cursors discarded,
    /// volume scope must be invalidated alongside).
    pub history_invalid: bool,
    /// Invalidations suppressed as own bookkeeping (exact identity).
    pub suppressed_own: usize,
    /// Scheduler invalidations derived from the batch.
    pub plans: Vec<SubtreePlan>,
}

/// Result of reconciling one volume's pending boundaries.
#[derive(Debug, Clone)]
pub struct ReconcileOutcome {
    /// Volume key.
    pub volume_key: String,
    /// Scopes invalidated this call (deduped, sorted).
    pub invalidated_scopes: Vec<String>,
    /// Reconciled cursor after the call.
    pub reconciled_through: Option<EventCursorId>,
}

/// Per-volume incremental reconciler over any [`CursorJournal`].
/// Protocol: `note_stream_opened` (monitor, before traversal) ->
/// `begin_traversal` -> `ingest` batches -> `reconcile_volume` (invalidate
/// scopes, advance only over satisfied work) -> `claim_volume_complete`.
/// A kill at any point replays from durable rows without losing work or
/// claiming unreconciled completeness.
pub struct Reconciler<J> {
    journal: J,
    boundaries: HashMap<String, EventCursorId>,
    own: OwnBookkeeping,
    gate: ScanGate,
}

impl<J: CursorJournal> Reconciler<J> {
    /// Reconciler over this journal.
    pub fn new(journal: J) -> Self {
        Self {
            journal,
            boundaries: HashMap::new(),
            own: OwnBookkeeping::new(),
            gate: ScanGate::new(),
        }
    }

    /// Borrow the journal (assertions, reopen-after-kill fixtures).
    pub fn journal(&self) -> &J {
        &self.journal
    }

    /// Mutably borrow the journal.
    pub fn journal_mut(&mut self) -> &mut J {
        &mut self.journal
    }

    /// Own-bookkeeping registry (register tool state before ingesting).
    pub fn own_bookkeeping_mut(&mut self) -> &mut OwnBookkeeping {
        &mut self.own
    }

    /// Scan gate (ordering assertions).
    pub fn gate(&self) -> &ScanGate {
        &self.gate
    }

    /// Observation boundary recorded for one volume, if any.
    pub fn boundary(&self, volume: &str) -> Option<EventCursorId> {
        self.boundaries.get(volume).copied()
    }

    /// Durable side of stream open: apply the open rule, record the
    /// validated UUID, start monitoring, and pin the per-volume observation
    /// boundary. `boundary` is the live ID observed at open, before any
    /// traversal. On `HistoryInvalid`, cursors are discarded and the caller
    /// must invalidate the volume scope (fresh traversal generation).
    pub fn note_stream_opened(
        &mut self,
        volume: &str,
        stored: Option<&VolumeCursor>,
        live_uuid: Option<&HistoryUuid>,
        live_id: u64,
        boundary: EventCursorId,
    ) -> OpenDecision {
        let decision = decide_open(stored, live_uuid.map(|u| u.0.as_str()), live_id);
        match decision {
            OpenDecision::Resume { .. } => {
                self.journal.record_open(volume, live_uuid.cloned(), None);
            }
            OpenDecision::Fresh {
                history_invalid, ..
            } => {
                if history_invalid {
                    let _ = self.journal.invalidate_history(volume, "open-rule");
                }
                self.journal.record_open(
                    volume,
                    live_uuid.cloned(),
                    history_invalid.then(|| "open-rule-invalid".to_string()),
                );
            }
        }
        self.gate.note_monitoring(volume);
        self.boundaries.insert(volume.to_string(), boundary);
        decision
    }

    /// Begin traversal (fails before any monitoring: monitor-before-traverse).
    pub fn begin_traversal(&mut self) -> crate::Result<()> {
        self.gate.begin_traversal()
    }

    /// Ingest one batch: suppress own-bookkeeping paths by exact identity,
    /// derive invalidation plans, and durably record the batch (ingested
    /// advances only with this write). `HistoryInvalid` batches discard
    /// cursors instead of recording.
    pub fn ingest(&mut self, batch: &EventBatch) -> crate::Result<IngestOutcome> {
        let volume = batch.volume_key.clone();
        if batch.signals.contains(&ContinuitySignal::HistoryInvalid) {
            let _ = self.journal.invalidate_history(&volume, "signal");
            return Ok(IngestOutcome {
                volume_key: volume.clone(),
                advanced_to: None,
                duplicate: false,
                history_invalid: true,
                suppressed_own: 0,
                plans: continuity_plan(&volume, &batch.signals, &batch.invalidations),
            });
        }
        let mut kept = Vec::with_capacity(batch.invalidations.len());
        let mut suppressed_own = 0usize;
        for path in &batch.invalidations {
            match self.own.classify(path) {
                BookkeepingClass::Own(_) => suppressed_own += 1,
                BookkeepingClass::Foreign | BookkeepingClass::Unknown => kept.push(path.clone()),
            }
        }
        let plans = continuity_plan(&volume, &batch.signals, &kept);
        let scopes: Vec<String> = {
            let mut scopes: Vec<String> = plans.iter().map(|p| p.scope_key.clone()).collect();
            scopes.sort();
            scopes.dedup();
            scopes
        };
        let loaded = self.journal.load(&volume);
        let record = self.journal.record_ingested(
            &volume,
            loaded.as_ref().and_then(|c| c.uuid.as_ref()),
            batch.high_water,
            &scopes,
            &batch.signals,
        )?;
        Ok(IngestOutcome {
            volume_key: volume,
            advanced_to: record.advanced_to,
            duplicate: record.duplicate,
            history_invalid: false,
            suppressed_own,
            plans,
        })
    }

    /// Reconcile one volume: invalidate every pending boundary's scopes
    /// (idempotent replays are safe), then advance the reconciled cursor
    /// over the contiguous prefix whose required work the checker reports
    /// satisfied. Boundaries with outstanding work stay pending.
    pub fn reconcile_volume<IO: ReconcileIo + ?Sized>(
        &mut self,
        volume: &str,
        io: &mut IO,
    ) -> crate::Result<ReconcileOutcome> {
        let pending = self.journal.pending(volume);
        let mut invalidated: Vec<String> = Vec::new();
        for boundary in &pending {
            for scope in &boundary.scopes {
                io.invalidate(scope)?;
                invalidated.push(scope.clone());
            }
        }
        invalidated.sort();
        invalidated.dedup();
        let reconciled_through = self.try_advance_reconciled(volume, &*io)?;
        Ok(ReconcileOutcome {
            volume_key: volume.to_string(),
            invalidated_scopes: invalidated,
            reconciled_through,
        })
    }

    /// Advance the reconciled cursor over the contiguous pending prefix
    /// whose required work the checker reports satisfied, without issuing
    /// new invalidations. The owner calls this as scheduler reconcile
    /// tasks complete; it is the only path that moves `reconciled`.
    pub fn try_advance_reconciled<C: WorkChecker + ?Sized>(
        &mut self,
        volume: &str,
        checker: &C,
    ) -> crate::Result<Option<EventCursorId>> {
        for boundary in self.journal.pending(volume) {
            let satisfied = boundary
                .scopes
                .iter()
                .all(|s| checker.pending_for_scope(s) == 0);
            if !satisfied {
                break;
            }
            self.journal
                .mark_reconciled_through(volume, boundary.cursor)?;
        }
        Ok(self.journal.load(volume).and_then(|c| c.reconciled))
    }

    /// Claim completeness for one volume relative to its own boundary.
    pub fn claim_volume_complete(&self, volume: &str) -> crate::Result<()> {
        let boundary = self.boundaries.get(volume).copied().ok_or_else(|| {
            crate::Error::Events(format!(
                "reconcile-before-claim: volume {volume} has no recorded boundary"
            ))
        })?;
        let loaded = self.journal.load(volume);
        let history_valid = loaded.as_ref().is_some_and(|c| !c.is_eventless());
        let reconciled = loaded.and_then(|c| c.reconciled);
        self.gate
            .claim_volume_complete(volume, reconciled, boundary, history_valid)
    }
}

// ---------------------------------------------------------------------------
// Monitor-before-traverse session + native macOS history identity
// ---------------------------------------------------------------------------

/// One monitored volume: its observation boundary plus its batch stream.
/// The boundary is pinned at open, before any traversal; completion is
/// claimed relative to it per volume.
pub struct MonitoredVolume {
    /// Volume key.
    pub volume_key: String,
    /// Per-volume observation boundary (live ID at open).
    pub boundary: EventCursorId,
    /// Bounded batch stream for this volume.
    pub batches: Box<dyn crate::platform::EventBatchIter>,
}

/// Open one history stream per volume BEFORE the initial traversal and pin
/// each volume's observation boundary. Stored cursors resume only under the
/// open rule (the stream enforces it natively); the durable side records
/// the same decision via `Reconciler::note_stream_opened`.
pub fn monitor_volumes<S: crate::platform::EventSource + ?Sized>(
    source: &mut S,
    volumes: &[crate::platform::VolumeId],
    stored: &HashMap<String, VolumeCursor>,
) -> crate::Result<Vec<MonitoredVolume>> {
    let mut out = Vec::with_capacity(volumes.len());
    for volume in volumes {
        let (boundary, batches) = source.open_stream(volume, stored.get(&volume.0).cloned())?;
        out.push(MonitoredVolume {
            volume_key: volume.0.clone(),
            boundary,
            batches,
        });
    }
    Ok(out)
}

/// Native macOS history identity: live FSEvents UUID + current event ID
/// via the `objc2-core-services` / `objc2-core-foundation` stack pinned in
/// `Cargo.toml` (MACOS_QUAL §1.1). The stream itself (`platform/macos.rs`)
/// enforces the open rule; these helpers let the durable layer persist the
/// validated UUID + cursors for while-stopped resume. `unsafe` is confined
/// to the documented FFI call sites below.
#[cfg(target_os = "macos")]
pub mod native {
    use super::{EventCursorId, HistoryUuid};
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    fn format_uuid_bytes(bytes: &[u8; 16]) -> String {
        let h = |i: usize| format!("{:02x}", bytes[i]);
        format!(
            "{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
            h(0),
            h(1),
            h(2),
            h(3),
            h(4),
            h(5),
            h(6),
            h(7),
            h(8),
            h(9),
            h(10),
            h(11),
            h(12),
            h(13),
            h(14),
            h(15)
        )
    }

    /// Device number of the filesystem containing `path` (the FSEvents key;
    /// always paired with the stored UUID).
    pub fn device_of(path: &Path) -> std::io::Result<libc::dev_t> {
        let cpath = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: cpath is NUL-terminated; st is writable for the call.
        let ret = unsafe { libc::stat(cpath.as_ptr(), &mut st) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(st.st_dev)
    }

    /// Live history UUID for one device, canonically formatted, or `None`
    /// when the volume has no history (NULL from the API: read-only or
    /// unsupported volume → eventless handling, MACOS_QUAL §3).
    pub fn live_history_uuid(dev: libc::dev_t) -> Option<HistoryUuid> {
        // SAFETY: dev comes from stat of a known mountpoint; the call has
        // no additional preconditions.
        let uuid: objc2_core_foundation::CFRetained<objc2_core_foundation::CFUUID> =
            unsafe { objc2_core_services::FSEventsCopyUUIDForDevice(dev) }?;
        let b = uuid.uuid_bytes();
        let bytes = [
            b.byte0, b.byte1, b.byte2, b.byte3, b.byte4, b.byte5, b.byte6, b.byte7, b.byte8,
            b.byte9, b.byte10, b.byte11, b.byte12, b.byte13, b.byte14, b.byte15,
        ];
        Some(HistoryUuid(format_uuid_bytes(&bytes)))
    }

    /// Current per-volume event ID (observation boundary / cursor line).
    pub fn current_event_id() -> EventCursorId {
        // SAFETY: no preconditions.
        EventCursorId(unsafe { objc2_core_services::FSEventsGetCurrentEventId() })
    }
}
