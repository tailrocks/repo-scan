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
//!
//! Submodules: [`batch`] (bounded IPC batching), [`roots`] (machine-scope
//! root plan), [`topology`] (symlink resolution, cycle detection, physical
//! identity dedupe).

pub mod batch;
pub mod roots;
pub mod topology;

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

/// Build [`EntryMetadata`] from `std::fs::Metadata` (lstat semantics when
/// the caller used `symlink_metadata`, which all adapters in this module do
/// for per-entry identity).
#[cfg(unix)]
pub(crate) fn fs_entry_metadata(md: &std::fs::Metadata) -> EntryMetadata {
    use std::os::unix::fs::MetadataExt;
    EntryMetadata {
        dev: md.dev(),
        ino: md.ino(),
        nlink: md.nlink(),
        len: md.len(),
    }
}

/// Build [`EntryMetadata`] on Windows from volume serial + file index.
#[cfg(all(not(unix), target_os = "windows"))]
pub(crate) fn fs_entry_metadata(md: &std::fs::Metadata) -> EntryMetadata {
    use std::os::windows::fs::MetadataExt;
    EntryMetadata {
        dev: u64::from(md.volume_serial_number().unwrap_or(0)),
        ino: md.file_index().unwrap_or(0),
        nlink: u64::from(md.number_of_links().unwrap_or(1)),
        len: md.len(),
    }
}

/// Fallback for non-unix, non-Windows targets: length only.
#[cfg(all(not(unix), not(target_os = "windows")))]
pub(crate) fn fs_entry_metadata(md: &std::fs::Metadata) -> EntryMetadata {
    EntryMetadata {
        dev: 0,
        ino: 0,
        nlink: 1,
        len: md.len(),
    }
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
    /// counted as children. The iterator may borrow both the adapter and
    /// `dir` (dua-core `read_dir` borrows the path it streams from).
    fn list_dir<'a>(
        &'a self,
        dir: &'a Path,
        options: ListOptions,
    ) -> std::io::Result<Box<dyn Iterator<Item = WalkItem> + 'a>>;
}

/// Primary backend for this target: `dua` where its native one-directory
/// reader exists (macOS/Windows), otherwise the `ignore` adapter under the
/// identical one-directory contract.
pub fn primary_adapter() -> Box<dyn OneDirAdapter> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    return Box::new(DuaAdapter);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    return Box::new(IgnoreAdapter);
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

    fn list_dir<'a>(
        &'a self,
        dir: &'a Path,
        options: ListOptions,
    ) -> std::io::Result<Box<dyn Iterator<Item = WalkItem> + 'a>> {
        // Default() keeps apfs_clone_metadata: false — clone identity is not
        // in the discovery contract and enabling it makes bulk reads more
        // expensive (WALKER_QUAL §1).
        let dua_options = if options.skip_metadata {
            dua_core::Options::default().skip_metadata()
        } else {
            dua_core::Options::default()
        };
        // Layer 1: directory-open failure returns here, recorded as the
        // directory's enumeration error. No threads, no per-child Vec on
        // this path: fixed 64 KiB buffer, one record per next().
        let iter = dua_core::read_dir(dir, dua_options)?;
        Ok(Box::new(iter.map(|item| {
            // Layer 2: iterator-item Err ends reliable enumeration; the
            // scheduler preserves partial children AND the gap.
            let entry = item?;
            debug_assert_eq!(entry.depth, 0, "dua read_dir must hand off at depth 0");
            Ok(ChildEntry {
                name: entry.file_name,
                kind: map_dua_file_type(entry.file_type),
                // Layer 3: per-entry metadata failure keeps the usable name.
                metadata: entry.metadata.map(|m| m.map(map_dua_metadata)),
            })
        })))
    }
}

/// Map dua-core's native file type (never follows symlinks) to [`ChildKind`].
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn map_dua_file_type(file_type: dua_core::FileType) -> ChildKind {
    if file_type.is_dir() {
        ChildKind::Directory
    } else if file_type.is_file() {
        ChildKind::File
    } else if file_type.is_symlink() {
        ChildKind::Symlink
    } else {
        ChildKind::Other
    }
}

/// Map dua-core's macOS native metadata to [`EntryMetadata`].
#[cfg(target_os = "macos")]
fn map_dua_metadata(metadata: dua_core::Metadata) -> EntryMetadata {
    EntryMetadata {
        dev: metadata.dev(),
        ino: metadata.ino(),
        nlink: metadata.nlink(),
        len: metadata.len(),
    }
}

/// Map dua-core's Windows native metadata to [`EntryMetadata`].
/// `hard_link_id` is `None` for entries without a file ID; those keep
/// `ino = 0`, which the topology layer treats as "no stable identity".
#[cfg(all(not(target_os = "macos"), target_os = "windows"))]
fn map_dua_metadata(metadata: dua_core::Metadata) -> EntryMetadata {
    let (dev, ino) = metadata.hard_link_id().unwrap_or((0, 0));
    EntryMetadata {
        dev,
        ino,
        nlink: 1,
        len: metadata.len(),
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

    fn list_dir<'a>(
        &'a self,
        dir: &'a Path,
        options: ListOptions,
    ) -> std::io::Result<Box<dyn Iterator<Item = WalkItem> + 'a>> {
        let mut builder = ignore::WalkBuilder::new(dir);
        builder
            .standard_filters(false) // keep hidden + ignored, read no ignore files
            .max_depth(Some(1)) // root (0) + immediate children (1), no descent
            .follow_links(false) // symlinks reported, resolved by topology
            .same_file_system(false) // crossings become scheduled work, not drops
            .max_filesize(None) // no size filtering
            .skip_stdout(false); // no stdout skipping
                                 // Do NOT set: sorter (would materialize the whole directory),
                                 // min_depth, overrides, types, filter_entry, custom ignore names.
                                 // build() is the sequential Walk; threads() only affects
                                 // build_parallel(), which this adapter never calls.
                                 // Layer 1 surfaces as the first iterator-item Err (walkdir opens
                                 // lazily), preserved like any layer-2 error.
        Ok(Box::new(IgnoreIter {
            inner: builder.build(),
            skip_metadata: options.skip_metadata,
            pending_error: None,
        }))
    }
}

/// Sequential shallow-walk iterator with depth-0 root filtering and both
/// ignore error channels preserved (WALKER_QUAL §2.1).
struct IgnoreIter {
    inner: ignore::Walk,
    skip_metadata: bool,
    /// Buffered attached `DirEntry::error()` from the previously yielded
    /// entry: emitted as its own `Err` item before the next child so neither
    /// the child nor the error is lost.
    pending_error: Option<std::io::Error>,
}

impl Iterator for IgnoreIter {
    type Item = WalkItem;

    fn next(&mut self) -> Option<WalkItem> {
        if let Some(err) = self.pending_error.take() {
            return Some(Err(err));
        }
        loop {
            match self.inner.next()? {
                Err(e) => return Some(Err(ignore_error_to_io(&e))),
                Ok(entry) => {
                    // The backend-emitted root always arrives exactly once at
                    // depth 0 and is never filter-skipped: filter it here,
                    // never count it as a child.
                    if entry.depth() == 0 {
                        continue;
                    }
                    if let Some(attached) = entry.error() {
                        self.pending_error = Some(ignore_error_to_io(attached));
                    }
                    let kind = match entry.file_type() {
                        // None only for stdin, which this configuration never
                        // produces; map defensively, never drop the child.
                        None => ChildKind::Other,
                        Some(ft) => {
                            if ft.is_dir() {
                                ChildKind::Directory
                            } else if ft.is_file() {
                                ChildKind::File
                            } else if ft.is_symlink() {
                                ChildKind::Symlink
                            } else {
                                ChildKind::Other
                            }
                        }
                    };
                    let metadata = if self.skip_metadata {
                        None
                    } else {
                        // Lstat semantics via symlink_metadata: the identity
                        // of the link itself, not its target. Races (entry
                        // vanishing between enumeration and inspection) land
                        // here as layer-3 errors, never as confirmed absence.
                        Some(std::fs::symlink_metadata(entry.path()).map(|m| fs_entry_metadata(&m)))
                    };
                    return Some(Ok(ChildEntry {
                        name: entry.file_name().to_os_string(),
                        kind,
                        metadata,
                    }));
                }
            }
        }
    }
}

/// Convert an `ignore::Error` to `io::Error`, preserving IO kinds and the
/// full message (which carries path/depth context from walkdir tags).
fn ignore_error_to_io(error: &ignore::Error) -> std::io::Error {
    if let Some(io) = error.io_error() {
        return std::io::Error::new(io.kind(), error.to_string());
    }
    // Non-IO traversal failures (e.g. symlink loops): no IO kind maps, so
    // InvalidData with the complete message (path/depth context included).
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

/// Narrow `std::fs::read_dir` escape hatch, permitted ONLY if a pinned
/// library necessarily materializes an unbounded child list for a huge flat
/// directory (WALKER_QUAL §3). At the pinned versions the hatch is OFF;
/// re-verify on any version bump before selecting it.
#[derive(Debug, Default)]
pub struct StdEscape;

impl StdEscape {
    /// Hatch trigger (WALKER_QUAL §3, acceptance FS-05): run the huge-flat
    /// fixture through each adapter streaming (no caller-side `collect`),
    /// sampling adapter RSS vs emitted entry count. RSS delta must stay
    /// ~flat (O(buffer)) as count grows; RSS growing O(entries) proves
    /// materialization and triggers the hatch for that backend only, selected
    /// explicitly under this same adapter contract (immediate children,
    /// per-entry errors preserved, interruption between items). Inspected
    /// evidence at the pinned versions says neither backend materializes:
    /// dua-core `read_dir` uses a fixed 64 KiB buffer with one record per
    /// `next()`; ignore `Walk` streams via `fs::ReadDir` one entry at a time
    /// (the only unbounded per-directory `Vec`s — a configured `sorter` and
    /// `DirList::close` under fd pressure — are unreachable under the §2
    /// configuration). Keep real dua-core/ignore integration for the
    /// non-triggered cases; never keep an unused dependency for compliance.
    pub const TRIGGER: &'static str = "hatch OFF at pinned versions; see WALKER_QUAL §3";
}

impl OneDirAdapter for StdEscape {
    fn name(&self) -> &'static str {
        "std-escape"
    }

    fn list_dir<'a>(
        &'a self,
        dir: &'a Path,
        options: ListOptions,
    ) -> std::io::Result<Box<dyn Iterator<Item = WalkItem> + 'a>> {
        // Layer 1: directory-open failure returns here.
        let read_dir = std::fs::read_dir(dir)?;
        let dir = dir.to_path_buf();
        let skip_metadata = options.skip_metadata;
        Ok(Box::new(read_dir.map(move |item| {
            // Layer 2: per-entry read failures surface as Err items.
            let entry = item?;
            let file_type = entry.file_type()?;
            let kind = topology::kind_of(&file_type);
            let metadata = if skip_metadata {
                None
            } else {
                // Lstat semantics; races become layer-3 errors.
                Some(
                    std::fs::symlink_metadata(dir.join(entry.file_name()))
                        .map(|m| fs_entry_metadata(&m)),
                )
            };
            Ok(ChildEntry {
                name: entry.file_name(),
                kind,
                metadata,
            })
        })))
    }
}
