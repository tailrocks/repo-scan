//! Native Linux platform implementations and portable fixtures
//! (MACOS_QUAL §4, R02).
//!
//! - Topology: [`LinuxMountTable`] parses `/proc/self/mountinfo`
//!   (with fallback to `/proc/mounts`), tracking mount IDs, parent IDs,
//!   device numbers, mount points, filesystems, and volume kinds.
//! - Fixtures: [`FixtureMountTable`] and [`MockLogSource`] drive
//!   canned APFS/tmpfs and scripted event tests without live platform calls.

use super::{
    classify_volume_kind, dev_fallback_volume_id, EventBatchIter, EventSource, MountPoint,
    MountTable, VolumeId, VolumeKind,
};
use crate::events::{EventBatch, EventCursorId};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Linux mountinfo parsing & native mount table (R02)
// ---------------------------------------------------------------------------

/// One parsed entry from `/proc/self/mountinfo` (or `/proc/[pid]/mountinfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfoEntry {
    /// Mount ID (field 1). Unique identifier of the mount.
    pub mount_id: u64,
    /// Parent mount ID (field 2).
    pub parent_id: u64,
    /// Major device number (field 3).
    pub major: u32,
    /// Minor device number (field 3).
    pub minor: u32,
    /// Root of the mount within the filesystem (field 4, unescaped).
    pub root: PathBuf,
    /// Mount point relative to the process's root (field 5, unescaped).
    pub mount_point: PathBuf,
    /// Per-mount options (field 6, e.g. "rw,noatime").
    pub mount_options: String,
    /// Zero or more optional fields (field 7: "shared:N", "master:N", etc.).
    pub optional_fields: Vec<String>,
    /// Filesystem type (field 8 after '-', unescaped, e.g. "ext4", "tmpfs").
    pub fs_type: String,
    /// Mount source (field 9 after '-', unescaped, e.g. "/dev/sda1", "none").
    pub mount_source: String,
    /// Per-superblock options (field 10 after '-', e.g. "rw,data=ordered").
    pub super_options: String,
}

impl MountInfoEntry {
    /// Calculate device identity anchor (colon-free).
    pub fn dev_anchor(&self) -> String {
        format!("{}_{}", self.major, self.minor)
    }

    /// Stable, colon-free volume identity anchored to device and mount path.
    pub fn volume_id(&self) -> VolumeId {
        let anchor = self.dev_anchor();
        dev_fallback_volume_id(&anchor, &self.mount_point)
    }

    /// Whether this filesystem is a remote / network filesystem.
    pub fn is_network(&self) -> bool {
        is_network_fs(&self.fs_type)
    }

    /// Whether this filesystem is a virtual / synthetic kernel interface.
    pub fn is_virtual(&self) -> bool {
        is_virtual_fs(&self.fs_type)
    }

    /// Classify the volume kind.
    pub fn kind(&self) -> VolumeKind {
        if self.is_network() {
            VolumeKind::Network
        } else if self.is_virtual() {
            VolumeKind::Virtual
        } else {
            classify_volume_kind(true, &self.fs_type, &self.mount_source)
        }
    }

    /// Convert to a [`MountPoint`].
    pub fn to_mount_point(&self) -> MountPoint {
        MountPoint {
            volume: self.volume_id(),
            mount_path: self.mount_point.clone(),
            filesystem: Some(self.fs_type.clone()),
            kind: self.kind(),
        }
    }
}

/// Returns true if the filesystem type indicates a network filesystem.
pub fn is_network_fs(fs_type: &str) -> bool {
    let lower = fs_type.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "nfs"
            | "nfs4"
            | "cifs"
            | "smbfs"
            | "smb3"
            | "sshfs"
            | "fuse.sshfs"
            | "afs"
            | "glusterfs"
            | "ceph"
            | "lustre"
            | "davfs"
    ) || lower.starts_with("nfs")
        || lower.starts_with("cifs")
}

/// Returns true if the filesystem type indicates a virtual kernel interface.
pub fn is_virtual_fs(fs_type: &str) -> bool {
    let lower = fs_type.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "devfs"
            | "devtmpfs"
            | "autofs"
            | "mtmfs"
            | "proc"
            | "sysfs"
            | "cgroup"
            | "cgroup2"
            | "devpts"
            | "securityfs"
            | "debugfs"
            | "tracefs"
            | "configfs"
            | "fusectl"
            | "mqueue"
            | "hugetlbfs"
            | "pstore"
            | "bpf"
            | "binfmt_misc"
            | "nsfs"
            | "efivarfs"
            | "rpc_pipefs"
            | "ramfs"
    )
}

/// Unescape octal escape sequences (`\NNN` where N is 0..7) in a string
/// as emitted by `/proc/self/mountinfo`. Returns lossless raw bytes.
pub fn unescape_octal(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let d1 = bytes[i + 1];
            let d2 = bytes[i + 2];
            let d3 = bytes[i + 3];
            if (b'0'..=b'7').contains(&d1)
                && (b'0'..=b'7').contains(&d2)
                && (b'0'..=b'7').contains(&d3)
            {
                let oct = (d1 - b'0') * 64 + (d2 - b'0') * 8 + (d3 - b'0');
                out.push(oct);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Convert unescaped raw bytes into a `PathBuf` losslessly on Unix.
pub fn bytes_to_path(bytes: Vec<u8>) -> PathBuf {
    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(OsString::from_vec(bytes))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// Parse one line from `/proc/self/mountinfo`.
pub fn parse_mountinfo_line(line: &str) -> Option<MountInfoEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 7 {
        return None;
    }
    let hyphen_idx = parts.iter().position(|&p| p == "-")?;
    if hyphen_idx < 6 || hyphen_idx + 2 >= parts.len() {
        return None;
    }
    let mount_id = parts[0].parse::<u64>().ok()?;
    let parent_id = parts[1].parse::<u64>().ok()?;
    let (maj_s, min_s) = parts[2].split_once(':')?;
    let major = maj_s.parse::<u32>().ok()?;
    let minor = min_s.parse::<u32>().ok()?;
    let root = bytes_to_path(unescape_octal(parts[3]));
    let mount_point = bytes_to_path(unescape_octal(parts[4]));
    let mount_options = parts[5].to_string();
    let optional_fields: Vec<String> = parts[6..hyphen_idx]
        .iter()
        .map(|&s| s.to_string())
        .collect();
    let fs_type = String::from_utf8_lossy(&unescape_octal(parts[hyphen_idx + 1])).into_owned();
    let mount_source = String::from_utf8_lossy(&unescape_octal(parts[hyphen_idx + 2])).into_owned();
    let super_options = if hyphen_idx + 3 < parts.len() {
        parts[hyphen_idx + 3..].join(" ")
    } else {
        String::new()
    };
    Some(MountInfoEntry {
        mount_id,
        parent_id,
        major,
        minor,
        root,
        mount_point,
        mount_options,
        optional_fields,
        fs_type,
        mount_source,
        super_options,
    })
}

/// Fallback parser for lines from `/proc/mounts` or `/etc/mtab`.
/// Format: `spec file vfstype mntops freq passno`
pub fn parse_mounts_fallback_line(line: &str) -> Option<MountInfoEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let mount_source = String::from_utf8_lossy(&unescape_octal(parts[0])).into_owned();
    let mount_point = bytes_to_path(unescape_octal(parts[1]));
    let fs_type = String::from_utf8_lossy(&unescape_octal(parts[2])).into_owned();
    let mount_options = parts[3].to_string();
    Some(MountInfoEntry {
        mount_id: 0,
        parent_id: 0,
        major: 0,
        minor: 0,
        root: PathBuf::from("/"),
        mount_point,
        mount_options,
        optional_fields: Vec::new(),
        fs_type,
        mount_source,
        super_options: String::new(),
    })
}

/// Native Linux mount table that parses `/proc/self/mountinfo`
/// (falling back to `/proc/mounts` if mountinfo is not available).
#[derive(Debug, Clone)]
pub struct LinuxMountTable {
    mountinfo_path: PathBuf,
}

impl Default for LinuxMountTable {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxMountTable {
    /// Create a mount table targeting `/proc/self/mountinfo`.
    pub fn new() -> Self {
        Self {
            mountinfo_path: PathBuf::from("/proc/self/mountinfo"),
        }
    }

    /// Create a mount table targeting a custom mountinfo path (for tests).
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            mountinfo_path: path.into(),
        }
    }

    /// Parse mount entries from a string containing `/proc/self/mountinfo` content.
    pub fn parse_mountinfo_str(content: &str) -> Vec<MountInfoEntry> {
        content.lines().filter_map(parse_mountinfo_line).collect()
    }

    /// Parse mount entries from a string containing `/proc/mounts` content.
    pub fn parse_mounts_str(content: &str) -> Vec<MountInfoEntry> {
        content
            .lines()
            .filter_map(parse_mounts_fallback_line)
            .collect()
    }

    /// Read raw mount entries from the configured path, falling back to `/proc/mounts`.
    pub fn entries(&self) -> crate::Result<Vec<MountInfoEntry>> {
        if let Ok(content) = std::fs::read_to_string(&self.mountinfo_path) {
            let entries = Self::parse_mountinfo_str(&content);
            if !entries.is_empty() {
                return Ok(entries);
            }
        }
        // Fallback to /proc/mounts if reading the default mountinfo failed
        if self.mountinfo_path == Path::new("/proc/self/mountinfo") {
            let fallback_path = Path::new("/proc/mounts");
            if let Ok(content) = std::fs::read_to_string(fallback_path) {
                let entries = Self::parse_mounts_str(&content);
                if !entries.is_empty() {
                    return Ok(entries);
                }
            }
        }
        Err(crate::Error::Platform(format!(
            "could not read Linux mount information from {}",
            self.mountinfo_path.display()
        )))
    }
}

impl MountTable for LinuxMountTable {
    fn mounts(&self) -> crate::Result<Vec<MountPoint>> {
        let entries = self.entries()?;
        // Handle root `/` and nested mounts cleanly:
        // 1. Resolve shadowed overmounts: in /proc/self/mountinfo, later entries
        //    with the identical mount point shadow earlier ones.
        //    We preserve the latest entry for each distinct mount point.
        let mut by_point: HashMap<PathBuf, MountInfoEntry> = HashMap::new();
        for entry in entries {
            by_point.insert(entry.mount_point.clone(), entry);
        }

        // 2. Separate root `/` from nested submounts and sort hierarchically:
        //    Root `/` always comes first, followed by child mounts ordered by
        //    path depth / components so traversal encounters parents before children.
        let mut mount_points: Vec<MountPoint> = Vec::with_capacity(by_point.len());
        let root_path = PathBuf::from("/");

        // Push root first if present
        if let Some(root_entry) = by_point.remove(&root_path) {
            mount_points.push(root_entry.to_mount_point());
        }

        // Collect remaining nested mounts and sort deterministically
        let mut remaining: Vec<MountInfoEntry> = by_point.into_values().collect();
        remaining.sort_by(|a, b| {
            let a_components = a.mount_point.components().count();
            let b_components = b.mount_point.components().count();
            a_components
                .cmp(&b_components)
                .then_with(|| a.mount_point.cmp(&b.mount_point))
        });

        for entry in remaining {
            mount_points.push(entry.to_mount_point());
        }

        Ok(mount_points)
    }
}

// ---------------------------------------------------------------------------
// Fixture mount table & mock log source (test support)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unescape_octal() {
        assert_eq!(unescape_octal("/normal/path"), b"/normal/path");
        assert_eq!(
            unescape_octal("/path\\040with\\040spaces"),
            b"/path with spaces"
        );
        assert_eq!(
            unescape_octal("/path\\011tab\\012newline"),
            b"/path\ttab\nnewline"
        );
        assert_eq!(unescape_octal("/path\\134backslash"), b"/path\\backslash");
    }

    #[test]
    fn test_parse_mountinfo_line_standard() {
        let line = "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue";
        let entry = parse_mountinfo_line(line).expect("parse failed");
        assert_eq!(entry.mount_id, 36);
        assert_eq!(entry.parent_id, 35);
        assert_eq!(entry.major, 98);
        assert_eq!(entry.minor, 0);
        assert_eq!(entry.root, PathBuf::from("/mnt1"));
        assert_eq!(entry.mount_point, PathBuf::from("/mnt2"));
        assert_eq!(entry.mount_options, "rw,noatime");
        assert_eq!(entry.optional_fields, vec!["master:1"]);
        assert_eq!(entry.fs_type, "ext3");
        assert_eq!(entry.mount_source, "/dev/root");
        assert_eq!(entry.super_options, "rw,errors=continue");
        assert_eq!(entry.kind(), VolumeKind::Local);
        assert_eq!(entry.dev_anchor(), "98_0");
    }

    #[test]
    fn test_parse_mountinfo_line_escaped_and_multiple_optional() {
        let line = "45 21 0:40 / /run/user/1000/my\\040drive rw,nosuid shared:1 master:2 - tmpfs tmpfs rw,mode=700";
        let entry = parse_mountinfo_line(line).expect("parse failed");
        assert_eq!(entry.mount_options, "rw,nosuid");
        assert_eq!(entry.mount_id, 45);
        assert_eq!(entry.parent_id, 21);
        assert_eq!(entry.major, 0);
        assert_eq!(entry.minor, 40);
        assert_eq!(entry.mount_point, PathBuf::from("/run/user/1000/my drive"));
        assert_eq!(entry.optional_fields, vec!["shared:1", "master:2"]);
        assert_eq!(entry.fs_type, "tmpfs");
        assert_eq!(entry.kind(), VolumeKind::Local);
    }

    #[test]
    fn test_parse_mountinfo_network_and_virtual() {
        let nfs_line = "100 21 0:50 / /mnt/nfs rw,relatime - nfs4 192.168.1.1:/export rw";
        let entry_nfs = parse_mountinfo_line(nfs_line).expect("parse nfs");
        assert_eq!(entry_nfs.kind(), VolumeKind::Network);

        let proc_line = "2 1 0:4 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw";
        let entry_proc = parse_mountinfo_line(proc_line).expect("parse proc");
        assert_eq!(entry_proc.kind(), VolumeKind::Virtual);

        let sys_line = "3 1 0:5 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw";
        let entry_sys = parse_mountinfo_line(sys_line).expect("parse sys");
        assert_eq!(entry_sys.kind(), VolumeKind::Virtual);
    }

    #[test]
    fn test_volume_id_is_colon_free() {
        let line = "21 1 8:1 / /mnt/test rw - ext4 /dev/sda1 rw";
        let entry = parse_mountinfo_line(line).unwrap();
        let vid = entry.volume_id();
        assert!(
            !vid.0.contains(':'),
            "VolumeId must be colon-free: {}",
            vid.0
        );
        assert!(vid.0.starts_with("dev-8_1-"));
    }

    #[test]
    fn test_linux_mount_table_hierarchy_and_shadowing() {
        let sample = "\
21 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw,data=ordered
22 21 8:2 / /home rw,relatime - ext4 /dev/sda2 rw,data=ordered
23 22 8:3 / /home/user/work rw,relatime - ext4 /dev/sda3 rw,data=ordered
24 21 0:30 / /tmp rw,nosuid - tmpfs tmpfs rw
25 21 0:31 / /tmp rw,nosuid - tmpfs tmpfs rw
";
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("mountinfo");
        std::fs::write(&file_path, sample).unwrap();

        let table = LinuxMountTable::with_path(&file_path);
        let mounts = table.mounts().expect("mounts");

        assert_eq!(mounts.len(), 4, "shadowed /tmp was deduplicated");
        assert_eq!(mounts[0].mount_path, PathBuf::from("/"));
        assert_eq!(mounts[1].mount_path, PathBuf::from("/home"));
        assert_eq!(mounts[2].mount_path, PathBuf::from("/tmp"));
        assert_eq!(mounts[3].mount_path, PathBuf::from("/home/user/work"));
        assert_eq!(mounts[0].filesystem.as_deref(), Some("ext4"));
        assert_eq!(mounts[0].kind, VolumeKind::Local);
    }
}
