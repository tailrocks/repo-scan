//! Symlink resolution and physical-directory identity (spec §7).
//!
//! The adapters never follow symlinks. Every symlink is reported as a child
//! and resolved here, in the topology layer, before the scheduler decides
//! whether the target becomes new work. Cycles are detected, volume crossings
//! become scheduled work for that volume, and physical directories dedupe by
//! `(dev, ino)` plus mount/snapshot namespace — never by string prefix
//! removal or `realpath` alone (firmlinks would collapse incorrectly).

use super::{ChildKind, EntryMetadata};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Maximum symlink hops before reporting [`ResolveError::TooDeep`].
/// Mirrors the OS `ELOOP` convention (Linux `MAXSYMLINKS` = 40).
pub const MAX_SYMLINK_HOPS: u32 = 40;

/// Physical identity of one directory: `(dev, ino)` plus the mount or
/// snapshot namespace it was observed in (spec §7). Two aliases of one
/// firmlinked object share `(dev, ino)` semantics per owning volume; the
/// namespace keeps distinct mounts from collapsing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PhysicalDirId {
    /// Device number of the owning volume.
    pub dev: u64,
    /// Inode / file ID within the volume.
    pub ino: u64,
    /// Mount or snapshot namespace (mount path or volume UUID).
    pub namespace: String,
}

/// Outcome of observing one physical directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveOutcome {
    /// First observation: schedule enumeration.
    New,
    /// Already observed in this namespace: record the alias, do not
    /// re-enumerate.
    Duplicate,
}

/// Process-local cycle/dedupe guard for in-flight traversal.
///
/// This is the cheap in-memory guard against symlink cycles and firmlink
/// double-scheduling within one owner process. Durable deduplication state
/// lives in the store (directories table keyed by physical identity); this
/// guard never replaces it and is rebuilt from durable state on restart.
#[derive(Debug, Default)]
pub struct Topology {
    seen: HashSet<PhysicalDirId>,
}

impl Topology {
    /// Empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one physical directory, reporting whether it is new.
    pub fn observe(&mut self, id: PhysicalDirId) -> ObserveOutcome {
        if self.seen.insert(id) {
            ObserveOutcome::New
        } else {
            ObserveOutcome::Duplicate
        }
    }

    /// True when this physical directory was already observed.
    pub fn contains(&self, id: &PhysicalDirId) -> bool {
        self.seen.contains(id)
    }

    /// Number of distinct physical directories observed.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True when nothing has been observed yet.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// A resolved symlink target. Resolution never descends: the returned path
/// is scheduled as new work by the durable scheduler when unseen and
/// in scope.
#[derive(Debug, Clone)]
pub struct LinkTarget {
    /// Final path after resolving every symlink hop.
    pub path: PathBuf,
    /// Kind of the final target (observed via `symlink_metadata`, so a
    /// trailing symlink is impossible here — it would be another hop).
    pub kind: ChildKind,
    /// Identity of the final target for dedupe and volume-crossing checks.
    pub metadata: EntryMetadata,
    /// Whether any hop crossed a volume boundary (`dev` changed).
    pub crossed_volume: bool,
}

/// Why symlink resolution failed. All variants preserve the scope as a
/// coverage gap or retryable task — never as a confirmed absence.
#[derive(Debug)]
pub enum ResolveError {
    /// A symlink hop repeated an already-seen link identity: a cycle.
    Cycle(PathBuf),
    /// More than [`MAX_SYMLINK_HOPS`] hops: probable cycle or hostile chain.
    TooDeep(PathBuf),
    /// Underlying IO failure (dangling target, permission, race).
    Io(std::io::Error),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Cycle(p) => write!(f, "symlink cycle at {}", p.display()),
            ResolveError::TooDeep(p) => write!(f, "symlink chain too deep at {}", p.display()),
            ResolveError::Io(e) => write!(f, "symlink resolution IO error: {e}"),
        }
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ResolveError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Map `std::fs::FileType` (never follows symlinks) to [`ChildKind`].
pub fn kind_of(file_type: &std::fs::FileType) -> ChildKind {
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

/// Resolve `path` hop by hop without ever descending into a directory.
///
/// Each hop uses `symlink_metadata` (lstat semantics) and `read_link`.
/// Cycles are detected by repeating link `(dev, ino)` identities; chains
/// longer than [`MAX_SYMLINK_HOPS`] are rejected. The final target is
/// returned unresolved-as-work: scheduling it is the caller's job.
pub fn resolve_symlink(path: &Path) -> Result<LinkTarget, ResolveError> {
    let mut current = path.to_path_buf();
    let mut seen_links: HashSet<(u64, u64)> = HashSet::new();
    let mut crossed_volume = false;
    let mut first_dev: Option<u64> = None;

    for _ in 0..=MAX_SYMLINK_HOPS {
        let md = std::fs::symlink_metadata(&current).map_err(ResolveError::Io)?;
        let meta = super::fs_entry_metadata(&md);
        first_dev.get_or_insert(meta.dev);
        if Some(meta.dev) != first_dev {
            crossed_volume = true;
        }
        if !md.file_type().is_symlink() {
            return Ok(LinkTarget {
                path: current,
                kind: kind_of(&md.file_type()),
                metadata: meta,
                crossed_volume,
            });
        }
        if !seen_links.insert((meta.dev, meta.ino)) {
            return Err(ResolveError::Cycle(current));
        }
        let target = std::fs::read_link(&current).map_err(ResolveError::Io)?;
        current = if target.is_absolute() {
            target
        } else {
            match current.parent() {
                Some(parent) => parent.join(target),
                None => target,
            }
        };
    }

    Err(ResolveError::TooDeep(current))
}
