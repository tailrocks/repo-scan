//! Portable fixture implementations for non-macOS targets
//! (MACOS_QUAL §4). These drive EVENT-01/EVENT-02 and FS-03 fixtures on
//! Linux CI; they are not macOS evidence.

use super::{EventBatchIter, EventSource, MountPoint, MountTable, VolumeId};

/// Canned mount table: includes an APFS System/Data-style pair with shared
/// file IDs across mountpoints for firmlink/alias tests (FS-03).
#[derive(Debug, Default)]
pub struct FixtureMountTable;

impl MountTable for FixtureMountTable {
    fn mounts(&self) -> crate::Result<Vec<MountPoint>> {
        todo!("FixtureMountTable: canned statfs-shaped rows")
    }
}

/// Scripted `Vec<EventBatch>` replay incl. `HistoryDone`, dropped/coalesced
/// flags, wrap, UUID change, and NULL-UUID volumes (EVENT-01/02).
#[derive(Debug, Default)]
pub struct MockLogSource {
    /// Scripted batches to replay.
    pub script: Vec<crate::events::EventBatch>,
}

impl EventSource for MockLogSource {
    fn open_stream(
        &mut self,
        _volume: &VolumeId,
        _stored: Option<crate::events::VolumeCursor>,
    ) -> crate::Result<(crate::events::EventCursorId, Box<dyn EventBatchIter>)> {
        todo!("MockLogSource: replay scripted batches")
    }
}
