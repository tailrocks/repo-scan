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
#[cfg(unix)]
use std::ffi::{c_char, CString, OsString};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path, PathBuf};

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

/// Schedule-time identity/provenance token (PG-01 support).
///
/// Minted when a path is scheduled, carrying the physical identity it was
/// scheduled under plus the scheduling spelling for provenance. The
/// executor re-checks [`ScheduleProvenance::matches`] against the pinned
/// identity before trusting the schedule: a path swapped between
/// scheduling and execution carries a different `(dev, ino)` and fails the
/// match. Rendered form is `rs1:<dev>:<ino>:<ns-bytes>:<namespace>:<hex-path>`
/// (namespace length-prefixed so `:` inside it cannot shift fields; the
/// path is hex so arbitrary bytes survive round-trip).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleProvenance {
    /// Namespace the path was scheduled under (mount/snapshot tag).
    pub namespace: String,
    /// Device number observed at schedule time.
    pub dev: u64,
    /// Inode / file ID observed at schedule time.
    pub ino: u64,
    /// Scheduling spelling (provenance only: aliases share identity).
    pub path: PathBuf,
}

/// Maximum namespace bytes accepted by [`ScheduleProvenance::parse`].
pub const MAX_PROVENANCE_NAMESPACE_BYTES: usize = 4096;

/// Maximum hex-path characters accepted by [`ScheduleProvenance::parse`]
/// (32 KiB of path bytes; far past `PATH_MAX`, still bounded).
pub const MAX_PROVENANCE_PATH_HEX: usize = 65_536;

impl ScheduleProvenance {
    /// Mint a token for `path` scheduled under identity `id`.
    pub fn mint(id: &PhysicalDirId, path: &Path) -> Self {
        Self {
            namespace: id.namespace.clone(),
            dev: id.dev,
            ino: id.ino,
            path: path.to_path_buf(),
        }
    }

    /// Physical identity this token was minted for.
    pub fn identity(&self) -> PhysicalDirId {
        PhysicalDirId {
            dev: self.dev,
            ino: self.ino,
            namespace: self.namespace.clone(),
        }
    }

    /// True when `id` is the identity this token was minted for
    /// (namespace + `(dev, ino)`; the path spelling is provenance, not
    /// identity, so aliases of one directory still match).
    pub fn matches(&self, id: &PhysicalDirId) -> bool {
        self.dev == id.dev && self.ino == id.ino && self.namespace == id.namespace
    }

    /// Render the token for scheduler/store transport.
    pub fn render(&self) -> String {
        format!(
            "rs1:{}:{}:{}:{}:{}",
            self.dev,
            self.ino,
            self.namespace.len(),
            self.namespace,
            crate::config::encode_hex(&crate::config::path_as_bytes(&self.path)),
        )
    }

    /// Parse [`ScheduleProvenance::render`] output; `None` on any
    /// malformed, over-cap, or miscounted input (fail closed).
    pub fn parse(token: &str) -> Option<Self> {
        let rest = token.strip_prefix("rs1:")?;
        let (dev, rest) = rest.split_once(':')?;
        let (ino, rest) = rest.split_once(':')?;
        let (ns_len, rest) = rest.split_once(':')?;
        let dev: u64 = dev.parse().ok()?;
        let ino: u64 = ino.parse().ok()?;
        let ns_len: usize = ns_len.parse().ok()?;
        if ns_len > MAX_PROVENANCE_NAMESPACE_BYTES || rest.len() < ns_len {
            return None;
        }
        let (namespace, rest) = rest.as_bytes().split_at(ns_len);
        let namespace = std::str::from_utf8(namespace).ok()?;
        let rest = std::str::from_utf8(rest).ok()?;
        let hex_path = rest.strip_prefix(':')?;
        if hex_path.len() > MAX_PROVENANCE_PATH_HEX {
            return None;
        }
        let path = crate::config::path_from_bytes(crate::config::decode_hex(hex_path)?);
        Some(Self {
            namespace: namespace.to_string(),
            dev,
            ino,
            path,
        })
    }
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

// ---------------------------------------------------------------------------
// Scan-scope fence + descriptor-relative traversal (finding 12)
// ---------------------------------------------------------------------------

/// Lexically normalize an absolute path: collapse `.`, resolve `..`
/// against the preceding components (absorbed at the filesystem root),
/// and reject non-absolute inputs. Pure string handling — no I/O, so it
/// cannot be raced; symlinks are NOT resolved here (that is the pinned
/// traversal's job).
fn normalize_absolute(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::Prefix(_) => return None,
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    Some(out)
}

/// One declared scan root: its canonical spelling (symlinks resolved),
/// the raw spelling when it differs (roots may carry an unclean spelling
/// such as `/var` vs `/private/var`), and the canonical directory's
/// `(dev, ino)` identity for root-swap detection.
#[derive(Debug, Clone)]
struct FenceRoot {
    canonical: PathBuf,
    raw: Option<PathBuf>,
    identity: Option<(u64, u64)>,
}

/// Scan-scope fence built once from the planned roots.
///
/// Scheduling-time checks ([`ScopeFence::allows_path`]) are lexical over
/// a `..`-normalized path: they close `..` escapes without filesystem
/// I/O. Execution-time checks ([`ScopeFence::open_pinned`]) resolve the
/// task path component by component through pinned directory descriptors
/// (`openat`, never following symlinks silently) and fence the resulting
/// true path plus its `fstat` identity — so a symlink swapped between
/// scheduling and execution still cannot leave the declared roots.
#[derive(Debug, Clone, Default)]
pub struct ScopeFence {
    roots: Vec<FenceRoot>,
}

impl ScopeFence {
    /// Build the fence from declared roots. Each root is canonicalized
    /// (resolving root-level symlinks such as `/var` → `/private/var`);
    /// when canonicalization fails the raw spelling is kept, mirroring
    /// the legacy fence fallback. Root identities come from the
    /// canonical spelling for root-swap detection.
    pub fn build(roots: &[PathBuf]) -> Self {
        let mut fenced = Vec::with_capacity(roots.len());
        for root in roots {
            let canonical = root.canonicalize().unwrap_or_else(|_| root.clone());
            let raw = (canonical != *root).then(|| root.clone());
            let identity = std::fs::symlink_metadata(&canonical).ok().map(|md| {
                let meta = super::fs_entry_metadata(&md);
                (meta.dev, meta.ino)
            });
            fenced.push(FenceRoot {
                canonical,
                raw,
                identity,
            });
        }
        Self { roots: fenced }
    }

    /// True when no roots were declared (deny-all: every path is refused).
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Scheduling-time membership: `..`-normalize `path` and prefix-match
    /// against every root spelling. No I/O: symlink escapes through a
    /// lexically in-scope spelling are closed at execution time by
    /// [`ScopeFence::open_pinned`], which re-verifies every task.
    pub fn allows_path(&self, path: &Path) -> bool {
        let Some(normalized) = normalize_absolute(path) else {
            return false;
        };
        self.roots.iter().any(|root| {
            normalized.starts_with(&root.canonical)
                || root
                    .raw
                    .as_ref()
                    .is_some_and(|raw| normalized.starts_with(raw))
        })
    }

    /// True when a pinned true path plus its `fstat` identity sit inside
    /// the declared roots. A true path equal to a canonical root must
    /// also match the root's recorded identity, so a swapped-in impostor
    /// directory at the root spelling is refused. Descendant paths are
    /// covered by the descent-time root check in [`ScopeFence::walk_pinned`]
    /// (PATH-GIT-02), which verifies the root prefix descriptor itself —
    /// this prefix test alone would accept a descendant under a replaced
    /// root or mount.
    fn allows_verified(&self, true_path: &Path, dev: u64, ino: u64) -> bool {
        self.roots.iter().any(|root| {
            if *true_path == root.canonical {
                root.identity
                    .is_some_and(|(root_dev, root_ino)| root_dev == dev && root_ino == ino)
            } else {
                true_path.starts_with(&root.canonical)
            }
        })
    }

    /// True when `fd` — an open descriptor for `prefix` — still matches
    /// the identity the fence recorded for the declared root at `prefix`,
    /// or when no declared root sits exactly at `prefix`. The check runs
    /// on the descriptor just opened, so there is no pathname re-stat
    /// gap for a root or mount replacement to slip through (PATH-GIT-02).
    /// Roots with no recorded identity (unstatable at build) cannot be
    /// verified and pass, preserving the legacy prefix behavior for them.
    #[cfg(unix)]
    fn root_prefix_verified(&self, prefix: &Path, fd: RawFd) -> bool {
        for root in &self.roots {
            if *prefix != root.canonical {
                continue;
            }
            match root.identity {
                None => continue,
                Some((root_dev, root_ino)) => match fstat_self(fd) {
                    Ok(st) => {
                        let meta = stat_to_entry(&st);
                        if meta.dev != root_dev || meta.ino != root_ino {
                            return false;
                        }
                    }
                    Err(_) => return false,
                },
            }
        }
        true
    }

    /// Pinned no-follow descent shared by [`ScopeFence::open_pinned`] and
    /// [`ScopeFence::open_relationship_pinned`]: resolve `path` component
    /// by component from the filesystem root through pinned directory
    /// descriptors, restarting from the root past each intermediate
    /// symlink (bounded by [`MAX_SYMLINK_HOPS`]). Every time the descent
    /// crosses a declared root prefix it verifies the open descriptor's
    /// `(dev, ino)` against the build-time identity, so a root directory
    /// or mount replaced after scheduling cannot redirect descendant
    /// lookups. No scope-membership check here: the caller applies it.
    /// The returned [`PinnedDir`] lists through its own descriptor, so a
    /// path swapped after this call cannot redirect the enumeration.
    #[cfg(unix)]
    fn walk_pinned(&self, path: &Path) -> Result<FenceOpen, FenceError> {
        use std::collections::VecDeque;
        use std::os::unix::ffi::OsStrExt;

        let normalized =
            normalize_absolute(path).ok_or_else(|| FenceError::NotAbsolute(path.to_path_buf()))?;
        let mut pending: VecDeque<OsString> = normalized
            .components()
            .filter_map(|component| match component {
                Component::Normal(part) => Some(part.to_os_string()),
                _ => None,
            })
            .collect();
        let mut stack: Vec<OsString> = Vec::new();
        let mut fd = open_root_dir().map_err(FenceError::Io)?;
        if !self.root_prefix_verified(Path::new("/"), fd.as_raw_fd()) {
            return Err(FenceError::OutOfScope(PathBuf::from("/")));
        }
        let mut hops = 0u32;
        while let Some(name) = pending.pop_front() {
            let last = pending.is_empty();
            let c_name = CString::new(name.as_os_str().as_bytes()).map_err(|_| {
                FenceError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("path component holds NUL: {}", path.display()),
                ))
            })?;
            let st = fstatat_no_follow(fd.as_raw_fd(), &c_name).map_err(FenceError::Io)?;
            let kind = kind_from_mode(st.st_mode as u32);
            if kind == ChildKind::Symlink {
                if last {
                    // The task path itself is a link: never follow it
                    // here — the caller routes it to link handling.
                    return Ok(FenceOpen::Symlink);
                }
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(FenceError::TooDeep(path.to_path_buf()));
                }
                let target = readlinkat_all(fd.as_raw_fd(), &c_name).map_err(FenceError::Io)?;
                // Restart from the root past the link: an absolute
                // target replaces the stack, a relative one extends it
                // (`PathBuf::push` semantics), and `..` inside the
                // target collapses lexically before we descend again.
                let mut rejoined = PathBuf::from("/");
                for part in &stack {
                    rejoined.push(part);
                }
                rejoined.push(&target);
                for rest in &pending {
                    rejoined.push(rest);
                }
                let renormalized = normalize_absolute(&rejoined).ok_or_else(|| {
                    FenceError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "symlink target escapes to a non-absolute path: {}",
                            path.display()
                        ),
                    ))
                })?;
                pending = renormalized
                    .components()
                    .filter_map(|component| match component {
                        Component::Normal(part) => Some(part.to_os_string()),
                        _ => None,
                    })
                    .collect();
                stack.clear();
                fd = open_root_dir().map_err(FenceError::Io)?;
                if !self.root_prefix_verified(Path::new("/"), fd.as_raw_fd()) {
                    return Err(FenceError::OutOfScope(PathBuf::from("/")));
                }
                continue;
            }
            if kind != ChildKind::Directory {
                return Err(FenceError::NotDirectory(path.to_path_buf()));
            }
            // `O_NOFOLLOW` closes the fstatat→open race: a component
            // swapped to a symlink here fails the open instead of
            // redirecting the descriptor.
            let child = openat_dir(fd.as_raw_fd(), &c_name).map_err(FenceError::Io)?;
            stack.push(name);
            fd = child;
            // Bind descendant lookups to the root descriptor (PATH-GIT-02):
            // when the descent crosses a declared root, the just-opened
            // descriptor must still carry the build-time identity.
            let mut prefix = PathBuf::from("/");
            for part in &stack {
                prefix.push(part);
            }
            if !self.root_prefix_verified(&prefix, fd.as_raw_fd()) {
                return Err(FenceError::OutOfScope(prefix));
            }
        }
        let mut true_path = PathBuf::from("/");
        for part in &stack {
            true_path.push(part);
        }
        let final_stat = fstat_self(fd.as_raw_fd()).map_err(FenceError::Io)?;
        let stat = stat_to_dir_stat(&final_stat);
        Ok(FenceOpen::Dir(PinnedDir {
            fd,
            stat,
            true_path,
        }))
    }

    /// Execution-time open of one task directory: the pinned descent
    /// plus the scope-membership check on the resulting true path and
    /// its `fstat` identity. Descent-time root verification (see
    /// [`ScopeFence::walk_pinned`]) already bound every root prefix to
    /// its build-time descriptor identity.
    #[cfg(unix)]
    pub fn open_pinned(&self, path: &Path) -> Result<FenceOpen, FenceError> {
        match self.walk_pinned(path)? {
            FenceOpen::Dir(pinned) => {
                let stat = pinned.stat();
                if !self.allows_verified(pinned.true_path(), stat.meta.dev, stat.meta.ino) {
                    let sp = pinned.true_path().to_path_buf();
                    return Err(FenceError::OutOfScope(sp));
                }
                Ok(FenceOpen::Dir(pinned))
            }
            other => Ok(other),
        }
    }

    /// Descriptor-relative open of an explicitly scheduled out-of-scope
    /// relationship path (PATH-GIT-01): the same pinned no-follow walk
    /// as [`ScopeFence::open_pinned`] but without the scope-membership
    /// check, so the caller can pin and re-verify a Git-relationship
    /// path the fence cannot cover. Untrusted worktree metadata names
    /// the spelling; the pin binds the execution. Root-prefix
    /// verification still applies to any declared root crossed. Links
    /// are reported, never followed.
    #[cfg(unix)]
    pub fn open_relationship_pinned(&self, path: &Path) -> Result<FenceOpen, FenceError> {
        self.walk_pinned(path)
    }

    /// Post-run re-verification for a relationship pin: re-resolve `path`
    /// through the unscoped descriptor walk and require the same true
    /// path plus `(dev, ino)` identity. `false` means the path was
    /// swapped mid-run: the caller must discard every observation.
    #[cfg(unix)]
    pub fn reverify_relationship(&self, path: &Path, before: &PinnedDir) -> bool {
        match self.open_relationship_pinned(path) {
            Ok(FenceOpen::Dir(after)) => {
                let before_stat = before.stat();
                let after_stat = after.stat();
                after.true_path() == before.true_path()
                    && after_stat.meta.dev == before_stat.meta.dev
                    && after_stat.meta.ino == before_stat.meta.ino
            }
            _ => false,
        }
    }

    /// Post-run re-verification for either pin kind: the scoped walk
    /// first, falling back to the relationship walk when the pin sits
    /// outside the declared roots. Either mismatch (or a link where the
    /// directory was) returns `false`; the caller must discard every
    /// observation and park.
    #[cfg(unix)]
    pub fn reverify_pinned(&self, path: &Path, before: &PinnedDir) -> bool {
        match self.open_pinned(path) {
            Ok(FenceOpen::Dir(after)) => {
                let before_stat = before.stat();
                let after_stat = after.stat();
                after.true_path() == before.true_path()
                    && after_stat.meta.dev == before_stat.meta.dev
                    && after_stat.meta.ino == before_stat.meta.ino
            }
            Err(FenceError::OutOfScope(_)) => self.reverify_relationship(path, before),
            _ => false,
        }
    }

    /// Non-unix targets cannot pin descriptors: always refuse so the
    /// caller fails closed (PATH-GIT-03) — never an unfenced run.
    #[cfg(not(unix))]
    pub fn open_pinned(&self, path: &Path) -> Result<FenceOpen, FenceError> {
        let _ = path;
        Err(FenceError::Unsupported(
            "descriptor-relative traversal requires unix".to_string(),
        ))
    }

    /// Non-unix targets cannot pin descriptors: always refuse.
    #[cfg(not(unix))]
    pub fn open_relationship_pinned(&self, path: &Path) -> Result<FenceOpen, FenceError> {
        let _ = path;
        Err(FenceError::Unsupported(
            "descriptor-relative traversal requires unix".to_string(),
        ))
    }

    /// Non-unix targets cannot re-verify pins: always fail.
    #[cfg(not(unix))]
    pub fn reverify_relationship(&self, _path: &Path, _before: &PinnedDir) -> bool {
        false
    }

    /// Non-unix targets cannot re-verify pins: always fail.
    #[cfg(not(unix))]
    pub fn reverify_pinned(&self, _path: &Path, _before: &PinnedDir) -> bool {
        false
    }
}

/// Outcome of [`ScopeFence::open_pinned`].
#[derive(Debug)]
pub enum FenceOpen {
    /// Pinned, in-scope directory: enumerate through the descriptor.
    Dir(PinnedDir),
    /// The task path itself is a symlink: the caller must route it to
    /// link handling, never follow it as a directory.
    Symlink,
}

/// Why a fenced open failed. Every variant fails closed: the caller
/// records a coverage gap or parks the task, never enumerates outside
/// the declared roots.
#[derive(Debug)]
pub enum FenceError {
    /// The pinned true path sits outside every declared root.
    OutOfScope(PathBuf),
    /// More than [`MAX_SYMLINK_HOPS`] intermediate symlinks.
    TooDeep(PathBuf),
    /// The task path is not absolute (declared roots always are).
    NotAbsolute(PathBuf),
    /// The task path resolves to a non-directory, non-symlink object.
    NotDirectory(PathBuf),
    /// Descriptor-relative traversal is unavailable on this target.
    Unsupported(String),
    /// Underlying I/O failure (dangling target, permission, race).
    Io(std::io::Error),
}

impl std::fmt::Display for FenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FenceError::OutOfScope(p) => {
                write!(f, "path is outside the scan scope: {}", p.display())
            }
            FenceError::TooDeep(p) => {
                write!(f, "symlink chain too deep at {}", p.display())
            }
            FenceError::NotAbsolute(p) => {
                write!(f, "scope path is not absolute: {}", p.display())
            }
            FenceError::NotDirectory(p) => {
                write!(f, "not a directory: {}", p.display())
            }
            FenceError::Unsupported(detail) => write!(f, "{detail}"),
            FenceError::Io(e) => write!(f, "fenced open I/O error: {e}"),
        }
    }
}

impl std::error::Error for FenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FenceError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Identity + incarnation parts for one pinned directory, from a single
/// `fstat` on the open descriptor (no pathname re-stat, no race).
#[derive(Debug, Clone, Copy)]
pub struct DirStat {
    /// Device/inode/link-count/size identity.
    pub meta: EntryMetadata,
    /// Modification time seconds (unix epoch, negative before 1970).
    pub mtime_secs: i64,
    /// Modification time sub-second nanoseconds.
    pub mtime_nanos: i64,
}

/// One pinned open directory: the descriptor, its `fstat` identity, and
/// the true path derived from the resolution (never from string reuse).
#[derive(Debug)]
pub struct PinnedDir {
    #[cfg(unix)]
    fd: OwnedFd,
    stat: DirStat,
    true_path: PathBuf,
}

impl PinnedDir {
    /// True path of the pinned directory (symlinks resolved, `..` collapsed).
    pub fn true_path(&self) -> &Path {
        &self.true_path
    }

    /// `fstat` identity + incarnation parts from the open descriptor.
    pub fn stat(&self) -> DirStat {
        self.stat
    }

    /// Stream immediate children through the pinned descriptor
    /// (`fdopendir` semantics): names plus lstat identity per child,
    /// `.`/`..` skipped, per-child failures preserved like the
    /// [`StdEscape`](super::StdEscape) adapter. Consumes the pin: the
    /// stream owns the description until exhaustion or drop.
    #[cfg(unix)]
    pub fn into_children(self, skip_metadata: bool) -> std::io::Result<PinnedChildren> {
        use std::os::unix::io::IntoRawFd;
        // `fdopendir` takes the description: on failure close it here,
        // on success the stream owns it (closed by `closedir` on drop).
        let raw = self.fd.into_raw_fd();
        let dir = unsafe { libc::fdopendir(raw) };
        if dir.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(raw);
            }
            return Err(error);
        }
        let dirfd = unsafe { libc::dirfd(dir) };
        Ok(PinnedChildren {
            dir,
            dirfd,
            skip_metadata,
            done: false,
        })
    }

    /// Non-unix targets cannot pin: [`ScopeFence::open_pinned`] already
    /// refuses there, so this is unreachable — loud, never empty.
    #[cfg(not(unix))]
    pub fn into_children(self, _skip_metadata: bool) -> std::io::Result<PinnedChildren> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "pinned traversal requires unix",
        ))
    }
}

/// Streaming children of a [`PinnedDir`]: owns the `DIR*` opened from the
/// pinned descriptor (closed on drop) and yields [`super::WalkItem`]s —
/// one [`super::ChildEntry`] per child with lstat identity, or a
/// preserved error that ends reliable enumeration.
#[cfg(unix)]
pub struct PinnedChildren {
    dir: *mut libc::DIR,
    dirfd: RawFd,
    skip_metadata: bool,
    done: bool,
}

#[cfg(unix)]
impl Drop for PinnedChildren {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.dir);
        }
    }
}

#[cfg(unix)]
impl Iterator for PinnedChildren {
    type Item = super::WalkItem;

    fn next(&mut self) -> Option<Self::Item> {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        if self.done {
            return None;
        }
        loop {
            // `readdir` signals errors only via `errno`: clear it first
            // so a stale value cannot end the stream spuriously.
            clear_errno();
            let entry = unsafe { libc::readdir(self.dir) };
            if entry.is_null() {
                self.done = true;
                let errno = last_errno();
                if errno != 0 {
                    return Some(Err(std::io::Error::from_raw_os_error(errno)));
                }
                return None;
            }
            let raw_name = dirent_name_bytes(unsafe { &*entry });
            if raw_name == b"." || raw_name == b".." {
                continue;
            }
            let name = OsString::from_vec(raw_name);
            let c_name = match CString::new(name.as_os_str().as_bytes()) {
                Ok(c) => c,
                Err(_) => {
                    // Impossible: the name came from a NUL-terminated
                    // `d_name`. End the stream loudly rather than skip.
                    self.done = true;
                    return Some(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "directory entry name holds NUL",
                    )));
                }
            };
            let dtype = unsafe { (*entry).d_type } as u32;
            let (kind, stored) = match dtype_to_kind(dtype) {
                Some(kind) if self.skip_metadata => (kind, None),
                Some(kind) => match fstatat_no_follow(self.dirfd, &c_name) {
                    Ok(st) => (kind, Some(Ok(st))),
                    Err(e) => (kind, Some(Err(e))),
                },
                None => match fstatat_no_follow(self.dirfd, &c_name) {
                    Ok(st) => {
                        let kind = kind_from_mode(st.st_mode as u32);
                        let stored = (!self.skip_metadata).then_some(Ok(st));
                        (kind, stored)
                    }
                    Err(e) => return Some(Err(e)),
                },
            };
            let metadata = stored.map(|result| result.map(|st| stat_to_entry(&st)));
            return Some(Ok(super::ChildEntry {
                name,
                kind,
                metadata,
            }));
        }
    }
}

/// Non-unix placeholder: [`PinnedDir::into_children`] already refuses
/// there, so this stream is never constructed.
#[cfg(not(unix))]
pub struct PinnedChildren {
    _private: (),
}

#[cfg(not(unix))]
impl Iterator for PinnedChildren {
    type Item = super::WalkItem;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// Map a `dirent` type to [`ChildKind`]; `None` on `DT_UNKNOWN`, which
/// needs an `fstatat` for the kind.
#[cfg(unix)]
fn dtype_to_kind(dtype: u32) -> Option<ChildKind> {
    if dtype == libc::DT_DIR as u32 {
        Some(ChildKind::Directory)
    } else if dtype == libc::DT_REG as u32 {
        Some(ChildKind::File)
    } else if dtype == libc::DT_LNK as u32 {
        Some(ChildKind::Symlink)
    } else if dtype == libc::DT_UNKNOWN as u32 {
        None
    } else {
        Some(ChildKind::Other)
    }
}

/// Map a `st_mode` file-type mask to [`ChildKind`] (never follows links:
/// the mode always comes from a no-follow stat).
#[cfg(unix)]
fn kind_from_mode(mode: u32) -> ChildKind {
    let file_type = mode & libc::S_IFMT as u32;
    if file_type == libc::S_IFDIR as u32 {
        ChildKind::Directory
    } else if file_type == libc::S_IFREG as u32 {
        ChildKind::File
    } else if file_type == libc::S_IFLNK as u32 {
        ChildKind::Symlink
    } else {
        ChildKind::Other
    }
}

/// Copy a `d_name` up to its NUL terminator.
#[cfg(unix)]
fn dirent_name_bytes(entry: &libc::dirent) -> Vec<u8> {
    entry
        .d_name
        .iter()
        .map(|c| *c as u8)
        .take_while(|byte| *byte != 0)
        .collect()
}

/// [`EntryMetadata`] from a no-follow stat result.
#[cfg(unix)]
// Field widths (`ino_t`, `dev_t`, `off_t`) vary by unix target; the `as`
// casts below keep this portable and mirror `std::os::unix::fs::MetadataExt`.
#[allow(clippy::unnecessary_cast)]
fn stat_to_entry(st: &libc::stat) -> EntryMetadata {
    // `dev_t`/`off_t` are definitionally non-negative; `as` mirrors
    // `std::os::unix::fs::MetadataExt`.
    EntryMetadata {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        nlink: st.st_nlink as u64,
        len: st.st_size as u64,
    }
}

/// [`DirStat`] from a no-follow stat result.
#[cfg(unix)]
fn stat_to_dir_stat(st: &libc::stat) -> DirStat {
    let (mtime_secs, mtime_nanos) = stat_mtime(st);
    DirStat {
        meta: stat_to_entry(st),
        mtime_secs,
        mtime_nanos,
    }
}

/// mtime from a no-follow stat result. libc 0.2 exposes split
/// `st_mtime`/`st_mtime_nsec` seconds/nanos on every unix target this crate
/// supports (macOS, Linux, BSDs); only exotic targets outside our support
/// keep a `st_mtim` timespec, so no per-OS split is needed.
#[cfg(unix)]
// `time_t`/`c_long` are 64-bit on our targets but narrower on some 32-bit
// unix; the `as` casts keep this portable.
#[allow(clippy::unnecessary_cast)]
fn stat_mtime(st: &libc::stat) -> (i64, i64) {
    (st.st_mtime as i64, st.st_mtime_nsec as i64)
}

/// Open the filesystem root for a pinned descent.
#[cfg(unix)]
fn open_root_dir() -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open one descent step: a directory, never a symlink.
#[cfg(unix)]
fn openat_dir(parent: RawFd, name: &CString) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Classify one descent step without following a trailing symlink.
#[cfg(unix)]
fn fstatat_no_follow(parent: RawFd, name: &CString) -> std::io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(parent, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st)
}

/// `fstat` the pinned descriptor itself (fd-bound: no pathname, no race).
#[cfg(unix)]
fn fstat_self(fd: RawFd) -> std::io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st)
}

/// Read one link target, growing past truncation (a full buffer may hide
/// a longer target). Absurd targets fail loudly instead of resolving
/// half a path.
#[cfg(unix)]
fn readlinkat_all(parent: RawFd, name: &CString) -> std::io::Result<OsString> {
    use std::os::unix::ffi::OsStringExt;

    let mut cap = 256usize;
    loop {
        let mut buf = vec![0u8; cap];
        let read = unsafe {
            libc::readlinkat(parent, name.as_ptr(), buf.as_mut_ptr() as *mut c_char, cap)
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let read = read as usize;
        if read < cap {
            buf.truncate(read);
            return Ok(OsString::from_vec(buf));
        }
        cap *= 2;
        if cap > 65_536 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "symlink target exceeds 64 KiB",
            ));
        }
    }
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    unsafe {
        *libc::__error() = 0;
    }
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    unsafe {
        *libc::__errno_location() = 0;
    }
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn clear_errno() {}

#[cfg(target_os = "macos")]
fn last_errno() -> i32 {
    unsafe { *libc::__error() }
}

#[cfg(target_os = "linux")]
fn last_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn last_errno() -> i32 {
    0
}
