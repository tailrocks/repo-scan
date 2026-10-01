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

/// Exclusive non-blocking lock; contention reports the holder, other
/// failures report the OS error.
#[cfg(unix)]
fn lock_exclusive(file: &std::fs::File) -> crate::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `flock` on an owned open fd is confined to this file and
    // changes no process-global state; the fd stays valid for the call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(());
    }
    let errno = std::io::Error::last_os_error();
    if errno.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Err(Error::Store(format!(
            "owner lock held by another process: {}",
            crate::store::owner::lock_path_hint()
        )));
    }
    Err(Error::Store(format!("owner lock failed: {errno}")))
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
/// unix, applied to the target itself whether newly created or pre-existing).
/// A symlinked target is refused before and after creation (fail closed).
#[cfg(unix)]
pub fn ensure_private_dir_all(path: &Path) -> crate::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if is_symlink_path(path)? {
        return Err(symlink_refusal(&format!(
            "directory is a symlink: {}",
            path.display()
        )));
    }
    std::fs::create_dir_all(path)?;
    if is_symlink_path(path)? {
        return Err(symlink_refusal(&format!(
            "directory is a symlink: {}",
            path.display()
        )));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(STATE_DIR_MODE))?;
    Ok(())
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
