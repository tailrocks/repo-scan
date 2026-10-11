//! Wave2b output-matrix support: machine writers, live-publication throttle,
//! and bounded completed-snapshot retention (contract D6/D12).
//!
//! One state model: the human, JSON, and JSONL lanes all read the same
//! staged/retained snapshot bytes (or the journal committed with them).
//! This module holds the shared output-side pieces:
//!
//! - [`write_machine_bytes`]: stdout discipline for machine lanes — raw
//!   bytes plus one trailing newline, no prose, no ANSI, no cursor codes.
//!   A broken pipe ends quietly (`Ok(false)`); any other IO error fails.
//! - [`LiveThrottle`]: the bounded live-publication interval. Rebuilds
//!   happen only at phase boundaries (never per discovery); the throttle
//!   additionally guarantees at most one live replacement per interval.
//! - [`prune_snapshot_files`]: completed snapshots are retained bounded
//!   ([`MAX_RETAINED_SNAPSHOTS`]); snapshots referenced by a scan
//!   outcome are never pruned. Live publications are never retained —
//!   the destination file is replaced, not accumulated.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Minimum interval between live `--report` replacements (D12). Live
/// rebuilds are already boundary-gated (never per discovery); this
/// interval bounds bursty boundaries too.
pub const LIVE_PUBLISH_MIN_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum completed snapshots retained in the snapshot directory
/// (D12). The newest [`MAX_RETAINED_SNAPSHOTS`] files survive; older
/// files are deleted unless a scan outcome references them (referenced
/// snapshots are never pruned, so `resume` and `query --scan
/// --format json|human` keep working).
pub const MAX_RETAINED_SNAPSHOTS: usize = 32;

/// Write machine-lane bytes to `out`: the bytes verbatim plus one `\n`.
/// Returns `Ok(false)` when the consumer went away (broken pipe): the
/// writer stops quietly with committed catalog records untouched. Any
/// other IO error fails loudly. Never emits prose, ANSI escapes, or
/// cursor codes — callers must pass only serialized JSON/JSONL.
pub fn write_machine_bytes<W: std::io::Write + ?Sized>(
    out: &mut W,
    bytes: &[u8],
) -> crate::Result<bool> {
    match out.write_all(bytes).and_then(|()| out.write_all(b"\n")) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(crate::Error::Io(format!(
            "cannot write machine output: {e}"
        ))),
    }
}

/// Flush a machine-lane writer. `Ok(false)` is a broken pipe (quiet
/// stop); any other error fails loudly.
pub fn flush_machine<W: std::io::Write + ?Sized>(out: &mut W) -> crate::Result<bool> {
    match out.flush() {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(crate::Error::Io(format!(
            "cannot flush machine output: {e}"
        ))),
    }
}

/// True when `bytes` carry no terminal-control escape (ESC/BEL) and no
/// carriage return: the machine-lane purity rule. Newlines are allowed
/// (JSONL framing); other control bytes inside string values are the
/// serializer's business (`serde_json` escapes them).
#[must_use]
pub fn is_machine_pure(bytes: &[u8]) -> bool {
    !bytes.contains(&0x1b) && !bytes.contains(&0x07) && !bytes.contains(&b'\r')
}

/// Bounded-interval gate for live `--report` replacement (D12).
#[derive(Debug)]
pub struct LiveThrottle {
    last: Option<Instant>,
    min_interval: Duration,
}

impl LiveThrottle {
    /// New throttle: the first publication always passes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last: None,
            min_interval: LIVE_PUBLISH_MIN_INTERVAL,
        }
    }

    /// Test/fixture constructor with an explicit interval.
    #[must_use]
    pub fn with_interval(min_interval: Duration) -> Self {
        Self {
            last: None,
            min_interval,
        }
    }

    /// True when a live publication may proceed now (first call, or at
    /// least `min_interval` since the last admitted one). Admitted
    /// calls stamp `now`; denied calls leave the stamp untouched.
    pub fn admit(&mut self) -> bool {
        let now = Instant::now();
        match self.last {
            None => {
                self.last = Some(now);
                true
            }
            Some(last) if now.duration_since(last) >= self.min_interval => {
                self.last = Some(now);
                true
            }
            Some(_) => false,
        }
    }
}

impl Default for LiveThrottle {
    fn default() -> Self {
        Self::new()
    }
}

/// One candidate snapshot file for retention pruning.
#[derive(Debug, Clone)]
pub struct SnapshotEntry {
    /// Report ID (file stem of `<id>.json`).
    pub id: String,
    /// Full path.
    pub path: PathBuf,
    /// Last-modified time; files without metadata sort oldest.
    pub modified: Option<std::time::SystemTime>,
}

/// List retained snapshot files: `<dir>/<safe-id>.json` regular files
/// only. Symlinks, subdirectories, staging/quarantine residue, and
/// unsafe stems are never candidates (never followed, never deleted).
#[must_use]
pub fn list_snapshot_entries(dir: &Path) -> Vec<SnapshotEntry> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let Some(dir_handle) = open_snapshot_directory(dir) else {
            return Vec::new();
        };
        let Some(entries) = enumerate_snapshot_entries(dir, &dir_handle) else {
            return Vec::new();
        };
        entries.into_iter().map(|entry| entry.snapshot).collect()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let mut out = Vec::new();
        let Ok(read) = std::fs::read_dir(dir) else {
            return out;
        };
        for entry in read.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_file() || meta.file_type().is_symlink() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            if is_safe_snapshot_stem(stem) {
                out.push(SnapshotEntry {
                    id: stem.to_string(),
                    path,
                    modified: meta.modified().ok(),
                });
            }
        }
        out
    }
}

/// Mirror of the snapshot-ID filename gate (lib `check_report_id` plus
/// the `.json` suffix rule): nonempty, at most 128 bytes,
/// `[A-Za-z0-9._-]`, never `.`/`..`.
fn is_safe_snapshot_stem(stem: &str) -> bool {
    !stem.is_empty()
        && stem.len() <= 128
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && stem != "."
        && stem != ".."
}

/// Select pruning victims: entries sorted oldest-first, the newest
/// `keep` survive, and every ID in `referenced` survives regardless of
/// age (a scan outcome names it, so `resume`/`query` may still need
/// it). Pure: the caller deletes.
#[must_use]
pub fn select_snapshot_victims(
    mut entries: Vec<SnapshotEntry>,
    referenced: &HashSet<String>,
    keep: usize,
) -> Vec<SnapshotEntry> {
    entries.sort_by(|a, b| a.modified.cmp(&b.modified).then_with(|| a.id.cmp(&b.id)));
    if entries.len() <= keep {
        return Vec::new();
    }
    let victim_count = entries.len() - keep;
    entries
        .into_iter()
        .take(victim_count)
        .filter(|e| !referenced.contains(&e.id))
        .collect()
}

/// Delete unreferenced completed snapshots beyond
/// [`MAX_RETAINED_SNAPSHOTS`] (oldest first). Returns the pruned report
/// IDs so the caller can delete the matching catalog rows. Best-effort
/// per file: an undeletable file is skipped, never fatal.
pub fn prune_snapshot_files(dir: &Path, referenced: &HashSet<String>, keep: usize) -> Vec<String> {
    let Some(dir_handle) = open_snapshot_directory(dir) else {
        return Vec::new();
    };
    let Some(entries) = enumerate_snapshot_entries(dir, &dir_handle) else {
        return Vec::new();
    };
    let victims = select_snapshot_victims(
        entries.iter().map(|entry| entry.snapshot.clone()).collect(),
        referenced,
        keep,
    );
    let mut pruned = Vec::new();
    for victim in victims {
        let Some(entry) = entries.iter().find(|entry| entry.snapshot.id == victim.id) else {
            continue;
        };
        if remove_snapshot_entry(&dir_handle, entry) {
            pruned.push(victim.id);
        }
    }
    pruned
}

// Keep pruning bound to the directory opened here, even if another process
// renames it and places a symlink at its old path. Linux and macOS support
// handle-relative, no-follow operations; other platforms fail closed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct PinnedSnapshotEntry {
    snapshot: SnapshotEntry,
    name: std::ffi::CString,
    device: libc::dev_t,
    inode: libc::ino_t,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_snapshot_directory(dir: &Path) -> Option<std::fs::File> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: open returned a fresh owned descriptor.
    Some(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn enumerate_snapshot_entries(
    dir: &Path,
    dir_handle: &std::fs::File,
) -> Option<Vec<PinnedSnapshotEntry>> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;

    let stream_fd = unsafe { libc::dup(dir_handle.as_raw_fd()) };
    if stream_fd < 0 {
        return None;
    }
    // fdopendir owns stream_fd when it succeeds.
    let stream = unsafe { libc::fdopendir(stream_fd) };
    if stream.is_null() {
        unsafe { libc::close(stream_fd) };
        return None;
    }
    struct DirStream(*mut libc::DIR);
    impl Drop for DirStream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirStream(stream);
    let dir_fd = dir_handle.as_raw_fd();
    let mut out = Vec::new();
    loop {
        set_errno(0);
        let raw_entry = unsafe { libc::readdir(stream.0) };
        if raw_entry.is_null() {
            if get_errno() != 0 {
                return None;
            }
            break;
        }
        // SAFETY: readdir returns an entry owned by the live DIR stream.
        let name_bytes = unsafe { CStr::from_ptr((*raw_entry).d_name.as_ptr()) }.to_bytes();
        let Ok(name) = std::str::from_utf8(name_bytes) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if !is_safe_snapshot_stem(stem) {
            continue;
        }
        let name_c = std::ffi::CString::new(name_bytes).ok()?;
        let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe {
            libc::fstatat(
                dir_fd,
                name_c.as_ptr(),
                &mut metadata,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
            || metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            continue;
        }
        out.push(PinnedSnapshotEntry {
            snapshot: SnapshotEntry {
                id: stem.to_string(),
                path: dir.join(name),
                modified: snapshot_mtime(&metadata),
            },
            name: name_c,
            device: metadata.st_dev,
            inode: metadata.st_ino,
        });
    }
    Some(out)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn remove_snapshot_entry(dir_handle: &std::fs::File, entry: &PinnedSnapshotEntry) -> bool {
    use std::os::fd::AsRawFd;

    let mut current = unsafe { std::mem::zeroed::<libc::stat>() };
    let dir_fd = dir_handle.as_raw_fd();
    // Recheck the name without following it. A replaced file, symlink, or
    // directory is left alone. unlinkat cannot be redirected by replacing
    // the directory's old pathname.
    if unsafe {
        libc::fstatat(
            dir_fd,
            entry.name.as_ptr(),
            &mut current,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        || current.st_mode & libc::S_IFMT != libc::S_IFREG
        || current.st_dev != entry.device
        || current.st_ino != entry.inode
    {
        return false;
    }
    unsafe { libc::unlinkat(dir_fd, entry.name.as_ptr(), 0) == 0 }
}

#[cfg(target_os = "linux")]
fn snapshot_mtime(metadata: &libc::stat) -> Option<std::time::SystemTime> {
    system_time_from_parts(
        metadata.st_mtim.tv_sec as i64,
        metadata.st_mtim.tv_nsec as i64,
    )
}

#[cfg(target_os = "macos")]
fn snapshot_mtime(metadata: &libc::stat) -> Option<std::time::SystemTime> {
    system_time_from_parts(metadata.st_mtime, metadata.st_mtime_nsec)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn system_time_from_parts(seconds: i64, nanoseconds: i64) -> Option<std::time::SystemTime> {
    let total = i128::from(seconds) * 1_000_000_000 + i128::from(nanoseconds);
    let magnitude = total.unsigned_abs();
    let duration = Duration::new(
        (magnitude / 1_000_000_000) as u64,
        (magnitude % 1_000_000_000) as u32,
    );
    if total < 0 {
        std::time::SystemTime::UNIX_EPOCH.checked_sub(duration)
    } else {
        std::time::SystemTime::UNIX_EPOCH.checked_add(duration)
    }
}

#[cfg(target_os = "linux")]
fn set_errno(value: i32) {
    unsafe { *libc::__errno_location() = value };
}

#[cfg(target_os = "linux")]
fn get_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn set_errno(value: i32) {
    unsafe { *libc::__error() = value };
}

#[cfg(target_os = "macos")]
fn get_errno() -> i32 {
    unsafe { *libc::__error() }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct PinnedSnapshotEntry;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_snapshot_directory(_dir: &Path) -> Option<std::fs::File> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn enumerate_snapshot_entries(
    _dir: &Path,
    _dir_handle: &std::fs::File,
) -> Option<Vec<PinnedSnapshotEntry>> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn remove_snapshot_entry(_dir_handle: &std::fs::File, _entry: &PinnedSnapshotEntry) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_writer_appends_single_newline() {
        let mut out = Vec::new();
        assert!(write_machine_bytes(&mut out, b"{\"a\":1}").unwrap());
        assert_eq!(out, b"{\"a\":1}\n");
        assert!(is_machine_pure(&out));
    }

    #[test]
    fn machine_purity_rejects_esc_bel_cr() {
        assert!(is_machine_pure(b"{\"a\":1}\n{\"b\":2}\n"));
        assert!(!is_machine_pure(b"\x1b[31m{\"a\":1}\n"));
        assert!(!is_machine_pure(b"{\"a\":1}\x07\n"));
        assert!(!is_machine_pure(b"{\"a\":1}\r\n"));
    }

    struct BrokenPipe;

    impl std::io::Write for BrokenPipe {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            ))
        }
    }

    #[test]
    fn broken_pipe_is_quiet_stop() {
        assert!(!write_machine_bytes(&mut BrokenPipe, b"x").unwrap());
        assert!(!flush_machine(&mut BrokenPipe).unwrap());
    }

    #[test]
    fn throttle_admits_first_then_interval() {
        let mut t = LiveThrottle::with_interval(Duration::from_secs(60));
        assert!(t.admit());
        assert!(!t.admit());
        let mut t = LiveThrottle::with_interval(Duration::ZERO);
        assert!(t.admit());
        assert!(t.admit());
    }

    #[test]
    fn victims_are_oldest_unreferenced_beyond_keep() {
        let base = std::time::SystemTime::UNIX_EPOCH;
        let entries: Vec<SnapshotEntry> = (0..5)
            .map(|i| SnapshotEntry {
                id: format!("r{i}"),
                path: PathBuf::from(format!("/tmp/r{i}.json")),
                modified: Some(base + Duration::from_secs(i)),
            })
            .collect();
        let mut referenced = HashSet::new();
        referenced.insert("r0".to_string());
        let victims = select_snapshot_victims(entries, &referenced, 3);
        let ids: Vec<&str> = victims.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, vec!["r1"], "oldest unreferenced beyond keep");
    }

    #[test]
    fn under_bound_prunes_nothing() {
        let entries: Vec<SnapshotEntry> = (0..3)
            .map(|i| SnapshotEntry {
                id: format!("r{i}"),
                path: PathBuf::from(format!("/tmp/r{i}.json")),
                modified: None,
            })
            .collect();
        assert!(select_snapshot_victims(entries, &HashSet::new(), 32).is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn pruning_does_not_follow_directory_or_entry_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let external = root.path().join("external");
        std::fs::create_dir(&external).unwrap();
        let external_file = external.join("outside.json");
        std::fs::write(&external_file, b"outside").unwrap();
        let linked_dir = root.path().join("snapshots-link");
        symlink(&external, &linked_dir).unwrap();

        assert!(prune_snapshot_files(&linked_dir, &HashSet::new(), 0).is_empty());
        assert!(external_file.exists());

        let snapshots = root.path().join("snapshots");
        std::fs::create_dir(&snapshots).unwrap();
        let candidate = snapshots.join("candidate.json");
        std::fs::write(&candidate, b"snapshot").unwrap();
        let linked_entry = snapshots.join("linked.json");
        symlink(&candidate, &linked_entry).unwrap();

        assert_eq!(
            prune_snapshot_files(&snapshots, &HashSet::new(), 0),
            vec!["candidate".to_string()]
        );
        assert!(std::fs::symlink_metadata(&linked_entry).is_ok());
        assert!(!candidate.exists());
    }
}
