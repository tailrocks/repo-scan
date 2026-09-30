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
    /// an occupancy note. Fails when another owner holds the lock.
    pub fn acquire(state_dir: &Path) -> crate::Result<Self> {
        std::fs::create_dir_all(payload_dir(state_dir))?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path(state_dir))?;
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
