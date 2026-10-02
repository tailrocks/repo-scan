//! Native platform seams (spec §§7, 13). All native calls stay behind
//! these narrow traits so Linux CI exercises the reconciler/scheduler with
//! fixtures while macOS adds native evidence (MACOS_QUAL §4).
//!
//! - Events: [`crate::events::EventCursor`] + `EventSource` below.
//! - Topology: [`MountTable`], [`VolumeId`], [`FileId`].
//! - Identity dedupe key is `(volume-UUID, fileID)`; firmlinks/mount
//!   aliases are recorded as `Alias` records, never collapsed silently.

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(any(not(target_os = "macos"), test))]
pub mod linux;

use crate::events::EventBatch;

/// Stable volume identity (volume UUID; `dev_t` is only the FSEvents key and
/// must always be paired with the stored UUID).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VolumeId(pub String);

/// Filesystem object identity within a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub u64);

/// One mounted filesystem root (spec §7).
#[derive(Debug, Clone)]
pub struct MountPoint {
    /// Stable volume identity.
    pub volume: VolumeId,
    /// Where it is mounted (raw bytes preserved by the caller).
    pub mount_path: std::path::PathBuf,
    /// Filesystem type name, if known.
    pub filesystem: Option<String>,
    /// Volume kind classification.
    pub kind: VolumeKind,
}

/// Volume kind (spec §7; report `Volume.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeKind {
    /// Local disk.
    Local,
    /// Network mount.
    Network,
    /// Virtual/synthetic filesystem.
    Virtual,
    /// Unknown.
    Unknown,
}

/// Mount-table contract: native `getfsstat` on macOS (MACOS_QUAL §1.3),
/// canned `statfs`-shaped rows on Linux fixtures.
pub trait MountTable: Send {
    /// Enumerate mounted volumes, including firmlink-stitched views.
    fn mounts(&self) -> crate::Result<Vec<MountPoint>>;
}

/// Raw history event-source contract. macOS wraps FSEvents
/// (`objc2-core-services`); Linux provides `mock_log` scripted replay
/// (MACOS_QUAL §4).
pub trait EventSource: Send {
    /// Open a per-volume stream from an optional stored cursor and return
    /// the observation boundary plus the batch iterator.
    fn open_stream(
        &mut self,
        volume: &VolumeId,
        stored: Option<crate::events::VolumeCursor>,
    ) -> crate::Result<(crate::events::EventCursorId, Box<dyn EventBatchIter>)>;
}

/// Iterator over bounded, coalesced event batches.
pub trait EventBatchIter: Send {
    /// Next batch, or `None` when caught up to the boundary.
    fn next_batch(&mut self) -> crate::Result<Option<EventBatch>>;
}

/// Shared volume-kind classifier used by every [`MountTable`]
/// implementation so fixtures and native code agree (spec §7; report
/// `Volume.kind`).
pub fn classify_volume_kind(is_local: bool, fstype: &str, mntfrom: &str) -> VolumeKind {
    if !is_local {
        return VolumeKind::Network;
    }
    let fstype = fstype.to_ascii_lowercase();
    match fstype.as_str() {
        // Synthetic or kernel-provided filesystems, never user data roots.
        // tmpfs/shm/overlay stay Local: /tmp and exposed container layers
        // hold real data and remain in scope.
        "devfs" | "autofs" | "mtmfs" | "proc" | "sysfs" | "cgroup" | "cgroup2" | "devpts"
        | "securityfs" | "debugfs" | "tracefs" | "configfs" | "fusectl" | "mqueue"
        | "hugetlbfs" => VolumeKind::Virtual,
        _ => {
            if mntfrom.starts_with("map ") {
                VolumeKind::Virtual
            } else {
                VolumeKind::Local
            }
        }
    }
}

/// Device-anchored fallback volume identity (Item 11): colon-free and
/// byte-exact. The mount path hex-encodes raw bytes instead of the lossy
/// display rendering (which could collide), and carries no `:` that would
/// corrupt planner-key parsing, which splits the volume at the first `:`.
pub fn dev_fallback_volume_id(anchor: &str, mount_path: &std::path::Path) -> VolumeId {
    VolumeId(format!(
        "dev-{anchor}-{}",
        crate::config::encode_hex(&crate::config::path_as_bytes(mount_path))
    ))
}
