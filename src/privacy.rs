//! Owner-only output constructors (CONSUMER-SCOPE-PRIVACY-001).
//!
//! Private-output contract: every directory or file this tool (or its test
//! fixtures) creates for state, reports, logs, or scratch roots is
//! owner-only — `0o700` dirs, `0o600` files — with symlinked targets refused
//! (fail closed) and modes applied explicitly after creation so the result
//! never depends on the caller's umask. See `docs/PRIVACY_DEFAULTS.md`.

#[cfg(unix)]
use std::ffi::OsStr;
use std::fs::File;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

/// Owner-only directory mode (unix).
#[cfg(unix)]
pub const PRIVATE_DIR_MODE: u32 = 0o700;
/// Owner-only file mode (unix).
#[cfg(unix)]
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// True when `path` itself is a symlink (lstat semantics). Missing paths
/// report false; other inspection failures are errors (fail closed).
pub fn is_symlink_path(path: &Path) -> crate::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(md) => Ok(md.file_type().is_symlink()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(crate::Error::Io(format!(
            "cannot inspect {}: {e}",
            path.display()
        ))),
    }
}

fn symlink_refusal(detail: String) -> crate::Error {
    crate::Error::Store(format!("refusing symlinked private component: {detail}"))
}

/// Create `path` (parents as needed) as an owner-only directory (`0o700` on
/// unix) and return it. RS-PRIV-05/07: this routes through the single
/// ancestor-pinned creation primitive
/// ([`crate::store::owner::ensure_private_dir_all`]), so symlinked
/// ancestors are refused (fail closed) and modes are tightened with
/// `fchmod` on bound FDs, never the path — the result never depends on
/// umask and creation cannot be redirected mid-call.
pub fn private_dir_0700(path: &Path) -> crate::Result<PathBuf> {
    if is_symlink_path(path)? {
        return Err(symlink_refusal(format!(
            "directory is a symlink: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        crate::store::owner::ensure_private_dir_all(path)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)?;
        if is_symlink_path(path)? {
            return Err(symlink_refusal(format!(
                "directory is a symlink: {}",
                path.display()
            )));
        }
    }
    Ok(path.to_path_buf())
}

/// Exclusively create a regular file at `path` (`O_CREAT|O_EXCL|O_NOFOLLOW`,
/// `0o600` on unix) and return the open handle. Fails when the path already
/// exists or is a symlink (fail closed). The mode is passed at creation time
/// AND re-applied with an explicit fchmod afterwards (no umask dependence).
/// Parent directories are NOT created; build them with
/// [`private_dir_0700`] first.
///
/// RS-PRIV-05/07 (RETEST-6): on unix the parent directory is pinned through
/// an `O_NOFOLLOW|O_DIRECTORY` FD and the leaf is created with `openat`
/// relative to it — there is no leaf-only `O_NOFOLLOW` after a pathname
/// parent check. `O_NOFOLLOW` refuses only a symlink in the final
/// component, so pre-existing intermediate symlinks still resolve; the
/// trust-root model binds parents at acquire instead, via
/// [`private_dir_0700`] (which routes through
/// [`crate::store::owner::ensure_private_dir_all`]) in `0o700` trees. A
/// symlink in the final parent component or the leaf is refused, never
/// followed, and a mid-call ancestor swap is detected by `(dev, ino)`
/// revalidation (`verify_leaf_matches_path`), failing closed.
pub fn private_file_0600(path: &Path) -> crate::Result<File> {
    #[cfg(unix)]
    {
        let (parent_path, leaf) = split_parent_leaf(path)?;
        let parent = crate::store::owner::open_dir_nofollow(parent_path)?;
        open_private_leaf(
            &parent,
            leaf,
            path,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
    }
    #[cfg(not(unix))]
    {
        private_file_0600_portable(path)
    }
}

/// Write `contents` to `path`, creating or truncating it as an owner-only
/// file (`0o600` on unix, `O_NOFOLLOW`, explicit fchmod after open so the
/// mode never depends on umask). Symlinked targets are refused (fail
/// closed). Parent directories are NOT created; build them with
/// [`private_dir_0700`] first.
///
/// RS-PRIV-05/07 (RETEST-6): on unix the parent directory is pinned through
/// an `O_NOFOLLOW|O_DIRECTORY` FD and the leaf is opened with `openat`
/// relative to it — there is no leaf-only `O_NOFOLLOW` after a pathname
/// parent check. `O_NOFOLLOW` refuses only a symlink in the final
/// component, so pre-existing intermediate symlinks still resolve; the
/// trust-root model binds parents at acquire instead, via
/// [`private_dir_0700`] (which routes through
/// [`crate::store::owner::ensure_private_dir_all`]) in `0o700` trees. A
/// symlink in the final parent component or the leaf is refused, never
/// followed, and a mid-call ancestor swap is detected by `(dev, ino)`
/// revalidation (`verify_leaf_matches_path`), failing closed.
pub fn private_write_0600(path: &Path, contents: &[u8]) -> crate::Result<()> {
    #[cfg(unix)]
    {
        let (parent_path, leaf) = split_parent_leaf(path)?;
        let parent = crate::store::owner::open_dir_nofollow(parent_path)?;
        let mut file = open_private_leaf(
            &parent,
            leaf,
            path,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        )?;
        {
            use std::io::Write as _;
            file.write_all(contents)?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        private_write_0600_portable(path, contents)
    }
}

/// Split `path` into its parent directory and leaf name for FD-relative
/// creation. A bare file name resolves against `.`; paths without a usable
/// leaf (root, empty, `.`, `..`) are refused. Unix only.
#[cfg(unix)]
fn split_parent_leaf(path: &Path) -> crate::Result<(&Path, &OsStr)> {
    let leaf = path.file_name().ok_or_else(|| {
        crate::Error::Store(format!(
            "refusing private file path with no file name: {}",
            path.display()
        ))
    })?;
    if leaf == OsStr::new(".") || leaf == OsStr::new("..") {
        return Err(crate::Error::Store(format!(
            "refusing unsafe private path component {leaf:?}"
        )));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((parent, leaf))
}

/// Open `leaf` relative to the pinned `parent` FD with
/// `openat(flags | O_NOFOLLOW | O_CLOEXEC, 0o600)`. A symlinked leaf fails
/// with `ELOOP` (refused, never followed); `O_EXCL` collisions report the
/// existing file. The mode is passed at creation AND re-applied with
/// `fchmod` on the open FD (no umask dependence), the open FD must be a
/// regular file, and the pathname must still name it (ancestor swap during
/// the call fails closed). Unix only.
#[cfg(unix)]
fn open_private_leaf(
    parent: &File,
    leaf: &OsStr,
    path: &Path,
    flags: libc::c_int,
) -> crate::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let bytes = leaf.as_bytes();
    if bytes.is_empty() || bytes.contains(&0) || bytes.contains(&b'/') {
        return Err(crate::Error::Store(format!(
            "refusing unsafe private path component {leaf:?}"
        )));
    }
    let cname = std::ffi::CString::new(bytes).map_err(|_| {
        crate::Error::Store(format!("private path component {leaf:?} holds a NUL byte"))
    })?;
    // SAFETY: `openat` on an owned open dir FD with a valid NUL-terminated
    // single-component name; ownership of the new FD moves into `File`.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            cname.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            PRIVATE_FILE_MODE as libc::c_uint,
        )
    };
    if fd < 0 {
        let errno = std::io::Error::last_os_error();
        let code = errno.raw_os_error();
        if code == Some(libc::ELOOP) {
            return Err(symlink_refusal(format!(
                "file is a symlink: {}",
                path.display()
            )));
        }
        if code == Some(libc::EEXIST) {
            // O_EXCL reports EEXIST for a symlinked leaf (macOS; Linux
            // reports ELOOP via O_NOFOLLOW) — classify by lstat so the
            // refusal names the symlink. Post-failure only; still refused.
            if is_symlink_path(path).unwrap_or(false) {
                return Err(symlink_refusal(format!(
                    "file is a symlink: {}",
                    path.display()
                )));
            }
            return Err(crate::Error::Io(format!(
                "private file {} already exists",
                path.display()
            )));
        }
        return Err(crate::Error::Io(format!(
            "cannot open private file {}: {errno}",
            path.display()
        )));
    }
    // SAFETY: `fd` is a fresh owned FD from the successful `openat` above.
    let file = unsafe { File::from_raw_fd(fd) };
    // RS-PRIV-05: fchmod the open FD, never the path.
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    }
    if !file.metadata()?.is_file() {
        return Err(crate::Error::Store(format!(
            "private file {} is not a regular file; refusing",
            path.display()
        )));
    }
    verify_leaf_matches_path(&file, path)?;
    Ok(file)
}

/// Fail closed unless `path` still names the open `file` (same `(dev, ino)`,
/// not a symlink): an ancestor swap between the parent pin and the `openat`
/// is detected rather than trusted. Unix only.
#[cfg(unix)]
fn verify_leaf_matches_path(file: &File, path: &Path) -> crate::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let fmeta = file.metadata()?;
    if is_symlink_path(path)? {
        return Err(symlink_refusal(format!(
            "private file {} is now a symlink; refusing",
            path.display()
        )));
    }
    let restated = std::fs::metadata(path)?;
    if (restated.dev(), restated.ino()) != (fmeta.dev(), fmeta.ino()) {
        return Err(crate::Error::Store(format!(
            "private file {} changed (dev,ino) during creation; refusing",
            path.display()
        )));
    }
    Ok(())
}

/// Portable `private_file_0600`: `openat` pinning is unavailable off-unix,
/// so the symlinked-leaf pathname check is the enforcement (documented
/// residual, mirroring `store::owner`'s off-unix builds).
#[cfg(not(unix))]
fn private_file_0600_portable(path: &Path) -> crate::Result<File> {
    if is_symlink_path(path)? {
        return Err(symlink_refusal(format!(
            "file is a symlink: {}",
            path.display()
        )));
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    Ok(opts.open(path)?)
}

/// Portable `private_write_0600`: same residual as
/// [`private_file_0600_portable`].
#[cfg(not(unix))]
fn private_write_0600_portable(path: &Path, contents: &[u8]) -> crate::Result<()> {
    if is_symlink_path(path)? {
        return Err(symlink_refusal(format!(
            "file is a symlink: {}",
            path.display()
        )));
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    let mut file = opts.open(path)?;
    {
        use std::io::Write as _;
        file.write_all(contents)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (CONSUMER-SCOPE-PRIVACY-001): constructors yield
    /// owner-only modes, exclusive creation fails closed on rerun, and
    /// symlinked targets are refused. Scratch lives under `/tmp` only.
    #[test]
    fn private_constructors_enforce_owner_only() {
        let root = std::env::temp_dir().join(format!("repo-scan-privacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = private_dir_0700(&root.join("sub")).expect("private dir");
        assert!(dir.is_dir());
        let fpath = dir.join("out.txt");
        {
            use std::io::Write as _;
            let mut f = private_file_0600(&fpath).expect("private file");
            f.write_all(b"secret\n").expect("write");
        }
        private_write_0600(&dir.join("log.txt"), b"log\n").expect("private write");
        assert!(private_file_0600(&fpath).is_err(), "O_EXCL rerun fails");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dmode = std::fs::metadata(&dir)
                .expect("stat dir")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dmode, 0o700, "dir mode");
            let fmode = std::fs::metadata(&fpath)
                .expect("stat file")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(fmode, 0o600, "file mode");
            let link = dir.join("link");
            std::os::unix::fs::symlink(&fpath, &link).expect("symlink");
            assert!(private_dir_0700(&link).is_err(), "symlinked dir refused");
            assert!(private_file_0600(&link).is_err(), "symlinked file refused");
            assert!(
                private_write_0600(&link, b"x").is_err(),
                "symlinked write refused"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
