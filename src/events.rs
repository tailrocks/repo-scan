//! Incremental discovery event cursors (spec §13, docs/MACOS_QUAL.md).
//!
//! Persistent per-volume history: event-history UUID + separate ingested and
//! reconciled cursors. Ingestion advances only with the commit storing its
//! invalidations; reconciliation advances only when the boundary's work is
//! satisfied. Event IDs are increasing but never assumed consecutive.

/// Opaque per-volume event-history identity (FSEvents UUID on macOS,
/// fixture string on Linux).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HistoryUuid(pub String);

/// Opaque event cursor (monotonic per volume; never store 0 / RootChanged).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventCursorId(pub u64);

/// Persisted per-volume cursor record (spec §§11+13).
#[derive(Debug, Clone)]
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
