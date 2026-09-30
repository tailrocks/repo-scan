//! Portable fixture implementations for non-macOS targets
//! (MACOS_QUAL §4). These drive EVENT-01/EVENT-02 and FS-03 fixtures on
//! Linux CI; they are not macOS evidence.

use super::{EventBatchIter, EventSource, MountPoint, MountTable, VolumeId, VolumeKind};
use crate::events::{EventBatch, EventCursorId};

/// Canned mount table mirroring an APFS System/Data-style layout: two
/// volumes whose firmlink-stitched views share file IDs across mountpoints
/// (FS-03 exercises the alias recording through
/// [`crate::walk::topology::PhysicalDirId`}, whose namespace keeps the two
/// mounts distinct instead of collapsing them).
#[derive(Debug, Default)]
pub struct FixtureMountTable;

impl MountTable for FixtureMountTable {
    fn mounts(&self) -> crate::Result<Vec<MountPoint>> {
        Ok(vec![
            MountPoint {
                volume: VolumeId(String::from("fixture-volume-system")),
                mount_path: std::path::PathBuf::from("/"),
                filesystem: Some(String::from("apfs")),
                kind: VolumeKind::Local,
            },
            MountPoint {
                volume: VolumeId(String::from("fixture-volume-data")),
                mount_path: std::path::PathBuf::from("/System/Volumes/Data"),
                filesystem: Some(String::from("apfs")),
                kind: VolumeKind::Local,
            },
            MountPoint {
                volume: VolumeId(String::from("fixture-volume-tmp")),
                mount_path: std::path::PathBuf::from("/tmp"),
                filesystem: Some(String::from("tmpfs")),
                kind: VolumeKind::Local,
            },
        ])
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
        volume: &VolumeId,
        stored: Option<crate::events::VolumeCursor>,
    ) -> crate::Result<(crate::events::EventCursorId, Box<dyn EventBatchIter>)> {
        // The fixture accepts any stored cursor (cursor-validation logic is
        // tested through the macOS open rule and the cursor-store unit
        // tests); the boundary is the script's high-water mark so a
        // finite-boundary report is reachable (EVENT-02).
        let _ = (volume, stored);
        let high_water = self
            .script
            .iter()
            .map(|b| b.high_water.0)
            .max()
            .unwrap_or(0);
        let script = std::mem::take(&mut self.script);
        Ok((
            EventCursorId(high_water),
            Box::new(MockLogIter {
                script: script.into(),
            }),
        ))
    }
}

/// Replay iterator over the scripted batches.
#[derive(Debug)]
struct MockLogIter {
    script: std::collections::VecDeque<EventBatch>,
}

impl EventBatchIter for MockLogIter {
    fn next_batch(&mut self) -> crate::Result<Option<EventBatch>> {
        Ok(self.script.pop_front())
    }
}
