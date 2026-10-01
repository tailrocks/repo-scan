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
use std::io::{Read, Write};
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
/// Tool-ownership marker filename inside the payload namespace (R15).
pub const OWNER_MARKER_NAME: &str = "owner.marker";
/// Marker format tag (first line of the marker file).
pub const OWNER_MARKER_TAG: &str = "repo-scan-owner-v1";
/// Maximum ownership-marker bytes read (RS-PRIV-02: oversize fails closed).
pub const OWNER_MARKER_MAX_BYTES: u64 = 4096;

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

/// `<state_dir>/payload/owner.marker`.
pub fn owner_marker_path(state_dir: &Path) -> PathBuf {
    payload_dir(state_dir).join(OWNER_MARKER_NAME)
}

/// Read the ownership marker through a pinned payload-dir FD (RS-PRIV-02):
/// the payload dir is bound `O_NOFOLLOW|O_DIRECTORY`, the marker is opened
/// with `openat(O_NOFOLLOW)`, and the open FD must be a regular file of at
/// most [`OWNER_MARKER_MAX_BYTES`] bytes. Missing payload/marker yields
/// `Ok(None)`; a symlink, non-regular file, oversize file, or unreadable
/// file fails closed. The caller validates the tag line and the `db_id=`
/// binding against the live catalog. Unix only pins FDs; elsewhere the
/// same kind/size checks run on the path.
pub fn read_owner_marker_text(state_dir: &Path) -> crate::Result<Option<String>> {
    #[cfg(unix)]
    {
        let payload = payload_dir(state_dir);
        let dir = match open_dir_nofollow(&payload) {
            Ok(dir) => dir,
            Err(_) => {
                // Missing payload means no marker. An un-openable dir FD
                // on an otherwise usable payload (macOS denies O_RDONLY
                // dir opens without read permission even when w+x child
                // access still works) falls back to a path-validated
                // marker read with the same kind/size checks the
                // off-unix build always runs (documented residual: path
                // re-resolution instead of FD pinning).
                if !payload.exists() {
                    return Ok(None);
                }
                return read_owner_marker_by_path(state_dir);
            }
        };
        let mut file = match open_child_file(&dir, std::ffi::OsStr::new(OWNER_MARKER_NAME)) {
            Ok(file) => file,
            Err(e) => {
                if !owner_marker_path(state_dir).exists() {
                    return Ok(None);
                }
                return Err(e);
            }
        };
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(Error::Store(format!(
                "ownership marker {} is not a regular file; refusing",
                owner_marker_path(state_dir).display()
            )));
        }
        if meta.len() > OWNER_MARKER_MAX_BYTES {
            return Err(Error::Store(format!(
                "ownership marker {} exceeds {OWNER_MARKER_MAX_BYTES} bytes; refusing",
                owner_marker_path(state_dir).display()
            )));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if bytes.len() as u64 > OWNER_MARKER_MAX_BYTES {
            return Err(Error::Store(
                "ownership marker grew past the size cap during read; refusing".to_string(),
            ));
        }
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }
    #[cfg(not(unix))]
    {
        read_owner_marker_by_path(state_dir)
    }
}

/// Path-validated ownership-marker read: the payload dir must be a
/// non-symlink directory and the marker a non-symlink regular file of at
/// most [`OWNER_MARKER_MAX_BYTES`] bytes; a missing payload/marker yields
/// `Ok(None)`. Shared by the off-unix build and the unix fallback for
/// payload dirs whose FD cannot be opened (documented residual: path
/// re-resolution, no FD pinning).
fn read_owner_marker_by_path(state_dir: &Path) -> crate::Result<Option<String>> {
    let payload = payload_dir(state_dir);
    match std::fs::symlink_metadata(&payload) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(Error::Store(format!(
                "refusing symlinked directory {}",
                payload.display()
            )));
        }
        Ok(md) if !md.is_dir() => {
            return Err(Error::Store(format!(
                "not a directory: {}",
                payload.display()
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::Io(format!(
                "cannot inspect {}: {e}",
                payload.display()
            )));
        }
    }
    let path = owner_marker_path(state_dir);
    match std::fs::symlink_metadata(&path) {
        Ok(md) => {
            if md.file_type().is_symlink() || !md.is_file() {
                return Err(symlink_refusal("ownership marker is not a regular file"));
            }
            if md.len() > OWNER_MARKER_MAX_BYTES {
                return Err(Error::Store(
                    "ownership marker exceeds the size cap".to_string(),
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::Io(format!("cannot inspect {}: {e}", path.display())));
        }
    }
    Ok(Some(
        String::from_utf8_lossy(&std::fs::read(&path)?).into_owned(),
    ))
}

/// `(dev, ino)` of `name` inside the pinned `dir` FD, opened with
/// `openat(O_NOFOLLOW)` and required to be a regular file (RS-PRIV-08
/// catalog bind). Missing files yield `Ok(None)`; symlinks and
/// non-regular files fail closed. Unix only.
#[cfg(unix)]
pub fn child_file_identity(
    dir: &std::fs::File,
    name: &std::ffi::OsStr,
) -> crate::Result<Option<(u64, u64)>> {
    let file = match open_child_file(dir, name) {
        Ok(file) => file,
        Err(e) => {
            // Missing reads as `None`; every other failure (including a
            // symlinked component, already a store error) fails closed.
            // Absence is confirmed with `faccessat` against the same
            // pinned FD so a transient error cannot masquerade as missing.
            if child_missing(dir, name) {
                return Ok(None);
            }
            return Err(e);
        }
    };
    if !file.metadata()?.is_file() {
        return Err(Error::Store(format!(
            "catalog component {name:?} is not a regular file; refusing"
        )));
    }
    Ok(Some(fd_identity(&file)?))
}

/// True when `name` is absent under the pinned `dir` FD (`faccessat`
/// `F_OK` returning `ENOENT`). Any other outcome reports false (the
/// caller fails closed on its original error). Unix only.
#[cfg(unix)]
pub fn child_missing(dir: &std::fs::File, name: &std::ffi::OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;
    let bytes = name.as_bytes();
    let Ok(cname) = std::ffi::CString::new(bytes) else {
        return false;
    };
    // SAFETY: `faccessat` with a valid dir FD and NUL-terminated name
    // inspects only that directory entry.
    let rc = unsafe { libc::faccessat(dir.as_raw_fd(), cname.as_ptr(), libc::F_OK, 0) };
    if rc == 0 {
        return false;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
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
        Self::lock_state(state_dir)
    }

    /// Acquire the coordination lock for `cache clear`: the state dir is
    /// ensured (the lock lives there) but `payload/` is deliberately left
    /// untouched — clear inspects a possibly unlistable, foreign, or
    /// absent payload itself under the held lock instead of failing (or
    /// tightening permissions) up front. The caller performs its own
    /// payload symlink/existence checks after acquiring.
    pub fn acquire_for_clear(state_dir: &Path) -> crate::Result<Self> {
        if is_symlink_path(state_dir)? {
            return Err(symlink_refusal("state dir is a symlink"));
        }
        ensure_private_dir_all(state_dir)?;
        Self::lock_state(state_dir)
    }

    /// Open (creating), owner-tighten, lock, and note the coordination
    /// lock. The state dir must already be ensured by the caller.
    fn lock_state(state_dir: &Path) -> crate::Result<Self> {
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
            // RS-PRIV-05: fchmod the open FD, never the path (a path chmod
            // can land on a swapped victim after open).
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(STATE_FILE_MODE))?;
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
/// never touched). RS-PRIV-05/07 ancestor-pinned creation: the nearest
/// existing ancestor is bound through an `O_NOFOLLOW|O_DIRECTORY` FD (a
/// symlinked ancestor is refused, not followed), then each missing
/// component is created with `mkdirat` and opened with `openat`
/// (`O_NOFOLLOW|O_DIRECTORY`) relative to the pinned parent FD, so an
/// ancestor swap or symlink plant during creation cannot redirect the
/// result. Modes are tightened with `fchmod` on the FD (never the path).
/// The nearest existing ancestor is the trust root: symlinks strictly
/// above it resolve normally (system prefixes like `/tmp`/`/var` are
/// legitimately symlinked on some platforms), exactly as with
/// [`StateRootAnchor`].
#[cfg(unix)]
pub fn ensure_private_dir_all(path: &Path) -> crate::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if path.as_os_str().is_empty() {
        return Err(Error::Store(
            "refusing empty private directory path".to_string(),
        ));
    }
    if is_symlink_path(path)? {
        return Err(symlink_refusal(&format!(
            "directory is a symlink: {}",
            path.display()
        )));
    }
    // Snapshot the missing chain BEFORE creation (target-first component
    // names) above the nearest existing ancestor.
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut base = path.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&base) {
            Ok(md) => {
                if md.file_type().is_symlink() {
                    return Err(symlink_refusal(&format!(
                        "private ancestor is a symlink: {}",
                        base.display()
                    )));
                }
                if !md.is_dir() {
                    return Err(Error::Store(format!(
                        "private ancestor {} is not a directory",
                        base.display()
                    )));
                }
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match base.file_name() {
                    Some(name) => missing.push(name.to_os_string()),
                    None => {
                        // No file name (root or prefix): pin the parent dir.
                        break;
                    }
                }
                match base.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => {
                        base = parent.to_path_buf();
                    }
                    _ => {
                        base = std::path::PathBuf::from(".");
                        break;
                    }
                }
            }
            Err(e) => {
                return Err(Error::Io(format!("cannot inspect {}: {e}", base.display())));
            }
        }
    }
    // Pin the trust root; a symlink here is refused, never followed.
    let mut dir = open_dir_nofollow(&base)?;
    if missing.is_empty() {
        // Pre-existing target: tighten it exactly as before (RS-PRIV-07:
        // no canonicalize-then-trust; the FD opened above IS the target).
        dir.set_permissions(std::fs::Permissions::from_mode(STATE_DIR_MODE))?;
        verify_dir_mode(&dir, path)?;
        verify_fd_matches_path(&dir, path)?;
        return Ok(());
    }
    for name in missing.iter().rev() {
        mkdir_at(&dir, name)?;
        let child = open_child_dir(&dir, name)?;
        child.set_permissions(std::fs::Permissions::from_mode(STATE_DIR_MODE))?;
        verify_dir_mode(&child, path)?;
        dir = child;
    }
    // The FD chain ends at the target; one loud re-check that the path
    // still names the bound directory (swap/restore across the window).
    verify_fd_matches_path(&dir, path)?;
    Ok(())
}

/// `mkdirat(dirfd, name, 0o700)`; `EEXIST` is absorbed (a racing creator
/// won) and the caller re-verifies through `openat(O_NOFOLLOW)`.
#[cfg(unix)]
fn mkdir_at(dir: &std::fs::File, name: &std::ffi::OsStr) -> crate::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.contains(&0) || bytes == b"." || bytes == b".." {
        return Err(Error::Store(format!(
            "refusing unsafe private path component {name:?}"
        )));
    }
    let cname = std::ffi::CString::new(bytes)
        .map_err(|_| Error::Store(format!("private path component {name:?} holds a NUL byte")))?;
    // SAFETY: `mkdirat` on an owned open dir FD with a valid NUL-terminated
    // name touches only that directory; the FD stays valid for the call.
    let rc = unsafe {
        libc::mkdirat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            STATE_DIR_MODE as libc::mode_t,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let errno = std::io::Error::last_os_error();
    if errno.raw_os_error() == Some(libc::EEXIST) {
        return Ok(());
    }
    Err(Error::Io(format!(
        "cannot create private directory component {name:?}: {errno}"
    )))
}

/// Open `name` relative to the pinned `dir` FD with
/// `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` and verify by `fstat` that
/// the result is a directory. Symlinks and non-directories are refused
/// (fail closed). Unix only.
#[cfg(unix)]
pub fn open_child_dir(dir: &std::fs::File, name: &std::ffi::OsStr) -> crate::Result<std::fs::File> {
    let file = open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    if !file.metadata()?.is_dir() {
        return Err(Error::Store(format!(
            "private component {name:?} is not a directory"
        )));
    }
    Ok(file)
}

/// Open `name` relative to the pinned `dir` FD with
/// `O_RDONLY|O_NOFOLLOW|O_CLOEXEC` (files; the caller `fstat`s the kind).
/// Symlinks are refused with `ELOOP` mapped to a store error. Unix only.
#[cfg(unix)]
pub fn open_child_file(
    dir: &std::fs::File,
    name: &std::ffi::OsStr,
) -> crate::Result<std::fs::File> {
    open_at(dir, name, libc::O_RDONLY)
}

/// `openat(dirfd, name, flags | O_NOFOLLOW | O_CLOEXEC)`.
#[cfg(unix)]
fn open_at(
    dir: &std::fs::File,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
) -> crate::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.contains(&0) || bytes == b"." || bytes == b".." {
        return Err(Error::Store(format!(
            "refusing unsafe private path component {name:?}"
        )));
    }
    if bytes.contains(&b'/') {
        return Err(Error::Store(format!(
            "refusing multi-component private path {name:?}"
        )));
    }
    let cname = std::ffi::CString::new(bytes)
        .map_err(|_| Error::Store(format!("private path component {name:?} holds a NUL byte")))?;
    // SAFETY: `openat` on an owned open dir FD with a valid NUL-terminated
    // single-component name; ownership of the new FD moves into `File`.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() == Some(libc::ELOOP) {
            return Err(Error::Store(format!(
                "refusing symlinked private component {name:?}"
            )));
        }
        return Err(Error::Io(format!(
            "cannot open private component {name:?}: {errno}"
        )));
    }
    // SAFETY: `fd` is a fresh owned FD from the successful `openat` above.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Fail closed unless the open dir FD carries exactly [`STATE_DIR_MODE`].
#[cfg(unix)]
fn verify_dir_mode(dir: &std::fs::File, path: &Path) -> crate::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = dir.metadata()?.permissions().mode() & 0o777;
    if mode != STATE_DIR_MODE {
        return Err(Error::Store(format!(
            "private directory {} mode is {mode:o}, want 700",
            path.display()
        )));
    }
    Ok(())
}

/// Fail closed unless the live path still names the bound FD's directory
/// (same `(dev, ino)`, still a directory, not a symlink). Unix only.
#[cfg(unix)]
fn verify_fd_matches_path(dir: &std::fs::File, path: &Path) -> crate::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let (fd_dev, fd_ino) = fd_identity(dir)?;
    if is_symlink_path(path)? {
        return Err(Error::Store(format!(
            "private directory {} is now a symlink; refusing",
            path.display()
        )));
    }
    let restated = std::fs::metadata(path)?;
    if (restated.dev(), restated.ino()) != (fd_dev, fd_ino) {
        return Err(Error::Store(format!(
            "private directory {} changed (dev,ino) during creation; refusing",
            path.display()
        )));
    }
    if !restated.is_dir() {
        return Err(Error::Store(format!(
            "private directory {} is not a directory",
            path.display()
        )));
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
