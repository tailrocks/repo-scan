//! Owner coordination: state-directory layout, lock file, epoch fencing
//! (spec §§3-4, 12, 15).
//!
//! Layout:
//!
//! ```text
//! <state_dir>/instance.lock      stable coordination lock (never unlinked)
//! <state_dir>/payload/catalog.db database file (+ engine sidecars)
//! ```
//!
//! The lock lives outside the replaceable `payload/` namespace so cache
//! clears can verify and remove only tool-owned payload files while the
//! owner identity stays stable. One process holds the lock; it claims a
//! fresh epoch (previous epoch + 1) from the catalog on open, and every
//! lease carries that epoch. Completions from older epochs are rejected,
//! which fences workers of a replaced owner.

use crate::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};

/// Coordination lock filename at the state-directory root.
pub const LOCK_FILE_NAME: &str = "instance.lock";
/// Replaceable payload namespace holding the database and sidecars.
pub const PAYLOAD_DIR_NAME: &str = "payload";
/// Catalog database filename inside the payload namespace.
pub const CATALOG_DB_NAME: &str = "catalog.db";
/// Owner-only directory mode for state/payload/staging/snapshot dirs (unix).
#[cfg(unix)]
pub const STATE_DIR_MODE: u32 = 0o700;
/// Owner-only file mode for the lock, marker, and staged/snapshot files (unix).
#[cfg(unix)]
pub const STATE_FILE_MODE: u32 = 0o600;

/// `<state_dir>/payload`.
pub fn payload_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(PAYLOAD_DIR_NAME)
}

/// `<state_dir>/payload/catalog.db`.
pub fn catalog_db_path(state_dir: &Path) -> PathBuf {
    payload_dir(state_dir).join(CATALOG_DB_NAME)
}

/// `<state_dir>/instance.lock`.
pub fn lock_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LOCK_FILE_NAME)
}

/// Held owner lock. Dropping closes the file (releasing the lock); the
/// pathname is never unlinked while active (spec §4).
#[derive(Debug)]
pub struct OwnerGuard {
    // Held for the lock lifetime, never read by design: dropping closes the
    // file, releasing the flock.
    #[allow(dead_code)]
    file: std::fs::File,
    state_dir: PathBuf,
    epoch: u64,
}

impl OwnerGuard {
    /// Create the layout, acquire an exclusive non-blocking lock, and record
    /// an occupancy note. Fails when another owner holds the lock. State and
    /// payload dirs are owner-only (`0o700`); the lock file is `0o600`.
    /// Symlinked state components are refused (fail closed).
    pub fn acquire(state_dir: &Path) -> crate::Result<Self> {
        if is_symlink_path(state_dir)? {
            return Err(symlink_refusal("state dir is a symlink"));
        }
        ensure_private_dir_all(state_dir)?;
        let payload = payload_dir(state_dir);
        ensure_private_dir_all(&payload)?;
        let lock = lock_path(state_dir);
        if is_symlink_path(&lock)? {
            return Err(symlink_refusal("coordination lock is a symlink"));
        }
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(STATE_FILE_MODE);
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = opts.open(&lock)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(STATE_FILE_MODE))?;
        }
        lock_exclusive(&file)?;
        let note = format!(
            "pid={} time_ms={}\n",
            std::process::id(),
            crate::store::now_ms()
        );
        let _ = file.write_all(note.as_bytes());
        let _ = file.sync_all();
        Ok(Self {
            file,
            state_dir: state_dir.to_path_buf(),
            epoch: 0,
        })
    }

    /// Fencing epoch claimed from the catalog after open.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Record the epoch claimed by [`crate::store::TursoStore::open_owned`].
    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    /// State directory this guard coordinates.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Database path this owner opened.
    pub fn db_path(&self) -> PathBuf {
        catalog_db_path(&self.state_dir)
    }
}

/// flock contention settle window shared by the owner lock and the
/// report-publish directory lock. Every EWOULDBLOCK holder is transient
/// (flock releases on process death; fork-shared references clear at
/// exec/exit within milliseconds — observed ≤200ms), so a brief bounded
/// wait absorbs spurious conflicts while genuine contention (another
/// live owner/publisher) still fails fast instead of hanging.
#[cfg(unix)]
pub const FLOCK_SETTLE_POLLS: u32 = 40;
/// Interval between settle polls; with [`FLOCK_SETTLE_POLLS`] this caps
/// the contention wait at two seconds.
#[cfg(unix)]
pub const FLOCK_SETTLE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// Exclusive non-blocking lock with a bounded contention settle window;
/// contention reports the holder, other failures report the OS error.
#[cfg(unix)]
fn lock_exclusive(file: &std::fs::File) -> crate::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `flock` on an owned open fd is confined to this file and
    // changes no process-global state; the fd stays valid for the call.
    for _ in 0..FLOCK_SETTLE_POLLS {
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(());
        }
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(Error::Store(format!("owner lock failed: {errno}")));
        }
        std::thread::sleep(FLOCK_SETTLE_INTERVAL);
    }
    // Settle window exhausted: genuine contention, fail fast.
    Err(Error::Store(format!(
        "owner lock held by another process: {}",
        crate::store::owner::lock_path_hint()
    )))
}

#[cfg(unix)]
fn lock_path_hint() -> &'static str {
    "state_dir/instance.lock (another repo-scan owner is running)"
}

#[cfg(not(unix))]
fn lock_exclusive(_file: &std::fs::File) -> crate::Result<()> {
    Err(Error::Config(
        "owner lock requires a unix platform (flock)".to_string(),
    ))
}

/// True when `path` itself is a symlink (lstat semantics). Missing paths
/// report false; other inspection failures are errors (fail closed).
pub fn is_symlink_path(path: &Path) -> crate::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(md) => Ok(md.file_type().is_symlink()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io(format!("cannot inspect {}: {e}", path.display()))),
    }
}

fn symlink_refusal(detail: &str) -> Error {
    Error::Store(format!("refusing symlinked state component: {detail}"))
}

/// Create `path` (parents as needed) as an owner-only directory (`0o700` on
/// unix, applied to every component this call creates plus the target
/// itself whether newly created or pre-existing; pre-existing parents are
/// never touched). A symlinked target is refused before and after creation
/// (fail closed). After creation each tightened directory is bound through
/// an `O_NOFOLLOW|O_DIRECTORY` FD: mode is tightened with `fchmod` on the
/// FD (never the path), and the FD identity is re-verified against the
/// canonical string so a transient ancestor swap between creation and
/// binding is detected loudly instead of silently trusted
/// (RSP-004/XSEC-06/SR-STATE-06).
#[cfg(unix)]
pub fn ensure_private_dir_all(path: &Path) -> crate::Result<()> {
    if is_symlink_path(path)? {
        return Err(symlink_refusal(&format!(
            "directory is a symlink: {}",
            path.display()
        )));
    }
    // Snapshot the missing chain BEFORE creation so only components this
    // call creates are tightened; pre-existing parents keep their modes.
    // Target-first order; tightened top-down after creation.
    let mut missing: Vec<std::path::PathBuf> = Vec::new();
    {
        let mut cur = path;
        loop {
            match std::fs::symlink_metadata(cur) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(cur.to_path_buf());
                    match cur.parent() {
                        Some(parent) if !parent.as_os_str().is_empty() => cur = parent,
                        _ => break,
                    }
                }
                Err(e) => {
                    return Err(Error::Io(format!("cannot inspect {}: {e}", cur.display())));
                }
            }
        }
    }
    std::fs::create_dir_all(path)?;
    if is_symlink_path(path)? {
        return Err(symlink_refusal(&format!(
            "directory is a symlink: {}",
            path.display()
        )));
    }
    for dir in missing.iter().rev() {
        bind_and_tighten_dir(dir)?;
    }
    if missing.is_empty() {
        bind_and_tighten_dir(path)?;
    }
    Ok(())
}

/// Bind an existing directory through an `O_NOFOLLOW|O_DIRECTORY` FD,
/// tighten it to [`STATE_DIR_MODE`] with `fchmod`, and verify the mode and
/// FD identity loudly. Unix only.
#[cfg(unix)]
fn bind_and_tighten_dir(path: &Path) -> crate::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let canonical = path.canonicalize().map_err(|e| {
        Error::Store(format!(
            "cannot resolve private directory {}: {e}",
            path.display()
        ))
    })?;
    let dir = open_dir_nofollow(&canonical)?;
    dir.set_permissions(std::fs::Permissions::from_mode(STATE_DIR_MODE))?;
    let mode = dir.metadata()?.permissions().mode() & 0o777;
    if mode != STATE_DIR_MODE {
        return Err(Error::Store(format!(
            "private directory {} mode is {mode:o}, want 700",
            path.display()
        )));
    }
    // Transient-swap detector: the bound FD must still be what the
    // canonical string names. A persistent redirection means the caller's
    // path genuinely names that directory; a swap/restore across the bind
    // window is caught here.
    let (fd_dev, fd_ino) = fd_identity(&dir)?;
    let restated = std::fs::metadata(&canonical)?;
    {
        use std::os::unix::fs::MetadataExt;
        if restated.dev() != fd_dev || restated.ino() != fd_ino {
            return Err(Error::Store(format!(
                "private directory {} changed during creation; refusing",
                path.display()
            )));
        }
        if !restated.is_dir() {
            return Err(Error::Store(format!(
                "private directory {} is not a directory",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Open an existing directory without following a trailing symlink, and
/// verify by `fstat` that the open FD is a directory. A symlink (or any
/// non-directory) is refused (fail closed). Unix only.
#[cfg(unix)]
pub fn open_dir_nofollow(path: &Path) -> crate::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                Error::Store(format!("refusing symlinked directory {}", path.display()))
            } else {
                Error::Io(format!("cannot open directory {}: {e}", path.display()))
            }
        })?;
    if !file.metadata()?.is_dir() {
        return Err(Error::Store(format!("not a directory: {}", path.display())));
    }
    Ok(file)
}

/// `(dev, ino)` identity `fstat`'d from an open file or directory. Unix only.
#[cfg(unix)]
pub fn fd_identity(file: &std::fs::File) -> crate::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}

/// Ancestor `(dev, ino)` chain of an open directory FD, starting with the
/// directory itself and walking `..` up to (and including) the filesystem
/// root, where the parent identity repeats. Each step opens the parent with
/// `O_NOFOLLOW|O_DIRECTORY` relative to the child FD, so the chain
/// describes the actually-bound ancestry rather than a re-resolved string.
/// Bounded (4096 levels); a deeper chain is refused. Unix only.
#[cfg(unix)]
pub fn ancestor_identities(dir: &std::fs::File) -> crate::Result<Vec<(u64, u64)>> {
    use std::os::unix::io::AsRawFd;
    const MAX_ANCESTORS: usize = 4096;
    let mut chain = Vec::new();
    // SAFETY: `dup` confines a new FD to the same open file description;
    // ownership moves into `File` exactly once per iteration.
    let mut current = unsafe {
        let duped = libc::dup(dir.as_raw_fd());
        if duped < 0 {
            return Err(Error::Io(format!(
                "cannot duplicate directory FD: {}",
                std::io::Error::last_os_error()
            )));
        }
        std::fs::File::from_raw_fd(duped)
    };
    loop {
        if chain.len() >= MAX_ANCESTORS {
            return Err(Error::Store(
                "directory ancestor chain exceeds 4096 levels; refusing".to_string(),
            ));
        }
        let identity = fd_identity(&current)?;
        chain.push(identity);
        let parent = unsafe {
            let dotdot = b"..\0";
            let fd = libc::openat(
                current.as_raw_fd(),
                dotdot.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            );
            if fd < 0 {
                return Err(Error::Io(format!(
                    "cannot open parent directory: {}",
                    std::io::Error::last_os_error()
                )));
            }
            std::fs::File::from_raw_fd(fd)
        };
        if fd_identity(&parent)? == identity {
            return Ok(chain);
        }
        current = parent;
    }
}

/// Best-effort absolute path of an open FD, for component policy checks on
/// an already-bound directory. Linux resolves `/proc/self/fd/N`; macOS uses
/// `fcntl(F_GETPATH)`. Returns `None` where unsupported or on failure
/// (callers keep their string checks as the fallback). Unix only.
#[cfg(unix)]
pub fn fd_path(file: &std::fs::File) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let mut buf = vec![0 as libc::c_char; 1024];
        // SAFETY: `buf` is a valid 1024-byte (MAXPATHLEN) out-parameter that
        // `F_GETPATH` fills with a NUL-terminated path on success; the FD is
        // open for the call.
        let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
        if rc != 0 {
            return None;
        }
        let len = buf.iter().position(|c| *c == 0)?;
        let bytes: Vec<u8> = buf[..len].iter().map(|c| *c as u8).collect();
        Some(PathBuf::from(
            std::ffi::OsStr::from_bytes(&bytes).to_os_string(),
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file;
        None
    }
}

/// Lifetime pin for the state root (SR-STATE-06, unix): holds an
/// `O_NOFOLLOW|O_DIRECTORY` FD plus the `(dev, ino)` observed at bind.
/// `verify` re-stats both the FD and the path and fails closed on any
/// divergence (swap, replace, symlink). Held for the store lifetime;
/// verified pre/post-open and periodically (every `with_tx` and
/// `open_reader`).
#[cfg(unix)]
#[derive(Debug)]
pub struct StateRootAnchor {
    dir: std::fs::File,
    dev: u64,
    ino: u64,
    path: PathBuf,
}

#[cfg(unix)]
impl StateRootAnchor {
    /// Bind `path` (must exist, must be a directory, must not be a symlink).
    pub fn open(path: &Path) -> crate::Result<Self> {
        let dir = open_dir_nofollow(path)?;
        let (dev, ino) = fd_identity(&dir)?;
        Ok(Self {
            dir,
            dev,
            ino,
            path: path.to_path_buf(),
        })
    }

    /// Fail closed unless the held FD and the live path still name the same
    /// directory we bound.
    pub fn verify(&self) -> crate::Result<()> {
        let (fd_dev, fd_ino) = fd_identity(&self.dir)?;
        if (fd_dev, fd_ino) != (self.dev, self.ino) {
            return Err(Error::Store(format!(
                "state root {} changed under the held FD; refusing",
                self.path.display()
            )));
        }
        if is_symlink_path(&self.path)? {
            return Err(Error::Store(format!(
                "state root {} is now a symlink; refusing",
                self.path.display()
            )));
        }
        let restated = std::fs::metadata(&self.path).map_err(|e| {
            Error::Store(format!(
                "state root {} is unreachable; refusing: {e}",
                self.path.display()
            ))
        })?;
        {
            use std::os::unix::fs::MetadataExt;
            if (restated.dev(), restated.ino()) != (self.dev, self.ino) {
                return Err(Error::Store(format!(
                    "state root {} changed (dev,ino) under the held FD; refusing",
                    self.path.display()
                )));
            }
            if !restated.is_dir() {
                return Err(Error::Store(format!(
                    "state root {} is no longer a directory; refusing",
                    self.path.display()
                )));
            }
        }
        Ok(())
    }
}

/// Portable fallback: no FD pinning; `verify` only refuses a symlinked path.
#[cfg(not(unix))]
#[derive(Debug)]
pub struct StateRootAnchor {
    path: PathBuf,
}

#[cfg(not(unix))]
impl StateRootAnchor {
    pub fn open(path: &Path) -> crate::Result<Self> {
        if is_symlink_path(path)? {
            return Err(symlink_refusal("state root is a symlink"));
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    pub fn verify(&self) -> crate::Result<()> {
        if is_symlink_path(&self.path)? {
            return Err(Error::Store(format!(
                "state root {} is now a symlink; refusing",
                self.path.display()
            )));
        }
        Ok(())
    }
}

/// Portable fallback: create the directory; modes are unix-only.
#[cfg(not(unix))]
pub fn ensure_private_dir_all(path: &Path) -> crate::Result<()> {
    if is_symlink_path(path)? {
        return Err(symlink_refusal(&format!(
            "directory is a symlink: {}",
            path.display()
        )));
    }
    std::fs::create_dir_all(path)?;
    Ok(())
}
