//! macOS native implementation (MACOS_QUAL §§1–3). Compiled only on
//! `target_os = "macos"`.
//!
//! - FSEvents history via `objc2-core-services` 0.3 (`FSEvents` + `libc` +
//!   `dispatch2`) and `objc2-core-foundation` 0.3: per-volume
//!   `FSEventStreamCreateRelativeToDevice` streams with flags
//!   `FileEvents | NoDefer | WatchRoot | FullHistory`, UUID persistence via
//!   `FSEventsCopyUUIDForDevice` + `CFUUID*`.
//! - Mounts/volume UUID/file identity via `libc`: `getfsstat` (`MNT_NOWAIT`),
//!   `getattrlist` (`ATTR_VOL_UUID`), `getattrlistbulk` (bulk file IDs).

use super::{EventBatchIter, EventSource, MountPoint, MountTable, VolumeId};

/// Native macOS mount table (`getfsstat`).
#[derive(Debug, Default)]
pub struct MacOsMountTable;

impl MountTable for MacOsMountTable {
    fn mounts(&self) -> crate::Result<Vec<MountPoint>> {
        todo!("MacOsMountTable: getfsstat + MNT_* classification + ATTR_VOL_UUID")
    }
}

/// Native macOS FSEvents history source.
#[derive(Debug, Default)]
pub struct FsEventsSource;

impl EventSource for FsEventsSource {
    fn open_stream(
        &mut self,
        _volume: &VolumeId,
        _stored: Option<crate::events::VolumeCursor>,
    ) -> crate::Result<(crate::events::EventCursorId, Box<dyn EventBatchIter>)> {
        todo!("FsEventsSource: CreateRelativeToDevice + UUID open rule + boundary")
    }
}
