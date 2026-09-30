//! Filesystem enumeration adapters (spec §6, docs/WALKER_QUAL.md).
//!
//! All backends implement [`OneDirAdapter`]: emit immediate children of ONE
//! already-resolved directory, never recurse, never follow symlinks, never own
//! a job universe. The durable scheduler decides what runs next (spec §4).
//!
//! Error layers (all preserved, never skipped):
//! 1. directory-open failure -> `list_dir` returns `Err`;
//! 2. mid-enumeration failure -> `Err` item ends reliable enumeration, partial
//!    children plus the gap are both recorded;
//! 3. per-entry metadata failure -> entry with `metadata: Some(Err(_))`.

use std::ffi::OsString;
use std::path::Path;

/// Immediate-child file type as observed without following symlinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildKind {
    /// Directory entry (not descended into by the adapter).
    Directory,
    /// Regular file.
    File,
    /// Symlink: reported, scheduled through the topology layer.
    Symlink,
    /// Anything else (socket, fifo, device, ...).
    Other,
}

/// One immediate child of the listed directory.
#[derive(Debug)]
pub struct ChildEntry {
    /// Raw entry name (no UTF-8 assumption).
    pub name: OsString,
    /// Observed file type.
    pub kind: ChildKind,
    /// Native identity/topology metadata when requested. `None` = cheap
    /// listing mode; `Some(Err)` = per-entry metadata failure with the name
    /// still usable (dua layer 3).
    pub metadata: Option<std::io::Result<EntryMetadata>>,
}

/// Native identity/topology metadata for one entry.
#[derive(Debug, Clone, Copy)]
pub struct EntryMetadata {
    /// Device number.
    pub dev: u64,
    /// Inode / file ID.
    pub ino: u64,
    /// Hard-link count.
    pub nlink: u64,
    /// Length in bytes.
    pub len: u64,
}

/// One item from a one-directory listing: a child or a preserved error.
pub type WalkItem = std::result::Result<ChildEntry, std::io::Error>;

/// Listing options shared by all adapters.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListOptions {
    /// When true, only names + file types are fetched (`metadata: None`).
    pub skip_metadata: bool,
}

/// The single traversal contract every backend implements.
pub trait OneDirAdapter: Send + Sync {
    /// Backend name for evidence (`dua`, `ignore`, `std-escape`).
    fn name(&self) -> &'static str;

    /// List immediate children of `dir`, which must be an already-resolved
    /// directory, never a symlink root (WALKER_QUAL §§1–2 precondition).
    /// Backend-emitted root records are filtered by the adapter, never
    /// counted as children.
    fn list_dir(
        &self,
        dir: &Path,
        options: ListOptions,
    ) -> std::io::Result<Box<dyn Iterator<Item = WalkItem> + '_>>;
}

/// Primary macOS reader: dua-core 4.1.0 one-directory iterator
/// (`read_dir(path, options)`; WALKER_QUAL §1). Never `walk`/`walk_roots`/
/// `stream_roots`. `apfs_clone_metadata` stays false.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug, Default)]
pub struct DuaAdapter;

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl OneDirAdapter for DuaAdapter {
    fn name(&self) -> &'static str {
        "dua"
    }

    fn list_dir(
        &self,
        _dir: &Path,
        _options: ListOptions,
    ) -> std::io::Result<Box<dyn Iterator<Item = WalkItem> + '_>> {
        todo!("DuaAdapter: dua_core::read_dir one-dir iterator, depth-0 handoff")
    }
}

/// Fallback/comparison backend: shallow sequential `ignore::WalkBuilder`
/// with `standard_filters(false)` + `max_depth(Some(1))`
/// (WALKER_QUAL §2). Never `build_parallel()`.
#[derive(Debug, Default)]
pub struct IgnoreAdapter;

impl OneDirAdapter for IgnoreAdapter {
    fn name(&self) -> &'static str {
        "ignore"
    }

    fn list_dir(
        &self,
        _dir: &Path,
        _options: ListOptions,
    ) -> std::io::Result<Box<dyn Iterator<Item = WalkItem> + '_>> {
        todo!("IgnoreAdapter: WalkBuilder shallow sequential, filter depth-0 root")
    }
}

/// Narrow `std::fs::read_dir` escape hatch, permitted ONLY if a pinned
/// library necessarily materializes an unbounded child list for a huge flat
/// directory (WALKER_QUAL §3). At the pinned versions the hatch is OFF;
/// re-verify on any version bump before selecting it.
#[derive(Debug, Default)]
pub struct StdEscape;

impl OneDirAdapter for StdEscape {
    fn name(&self) -> &'static str {
        "std-escape"
    }

    fn list_dir(
        &self,
        _dir: &Path,
        _options: ListOptions,
    ) -> std::io::Result<Box<dyn Iterator<Item = WalkItem> + '_>> {
        todo!("StdEscape: explicit std::fs::read_dir under adapter contract")
    }
}
