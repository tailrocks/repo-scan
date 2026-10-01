//! Owner-only output constructors (CONSUMER-SCOPE-PRIVACY-001).
//!
//! Private-output contract: every directory or file this tool (or its test
//! fixtures) creates for state, reports, logs, or scratch roots is
//! owner-only — `0o700` dirs, `0o600` files — with symlinked targets refused
//! (fail closed) and modes applied explicitly after creation so the result
//! never depends on the caller's umask. See `docs/PRIVACY_DEFAULTS.md`.

use std::fs::{File, OpenOptions};
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
/// AND re-applied with an explicit chmod afterwards (no umask dependence).
/// Parent directories are NOT created; build them with
/// [`private_dir_0700`] first.
pub fn private_file_0600(path: &Path) -> crate::Result<File> {
    if is_symlink_path(path)? {
        return Err(symlink_refusal(format!(
            "file is a symlink: {}",
            path.display()
        )));
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(PRIVATE_FILE_MODE);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        // RS-PRIV-05: fchmod the open FD, never the path.
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    }
    Ok(file)
}

/// Write `contents` to `path`, creating or truncating it as an owner-only
/// file (`0o600` on unix, `O_NOFOLLOW`, explicit chmod after open so the mode
/// never depends on umask). Symlinked targets are refused (fail closed).
/// Parent directories are NOT created; build them with
/// [`private_dir_0700`] first.
pub fn private_write_0600(path: &Path, contents: &[u8]) -> crate::Result<()> {
    if is_symlink_path(path)? {
        return Err(symlink_refusal(format!(
            "file is a symlink: {}",
            path.display()
        )));
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(PRIVATE_FILE_MODE);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    {
        // RS-PRIV-05: fchmod the open FD, never the path.
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    }
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
