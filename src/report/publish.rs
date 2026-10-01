//! Staging, snapshot retention, and atomic publication (spec §15).
//!
//! Order of operations: stream the consistent report into controlled local
//! staging, release database snapshot readers, retain the immutable snapshot
//! bytes in state, then publish to the external destination through a
//! temporary sibling plus atomic rename.
//!
//! Destination safety: refuse Git-administrative paths, the active
//! persistence payload, symlink/path-substitution surprises, and existing
//! unrelated files (no-clobber). A destination may only replace a verified
//! previous `repo-scan` report — a filename extension alone is not proof.

use crate::error::Error;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Bounded copy buffer for staging/publication (64 KiB).
pub const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// Counter mixed into temporary sibling names for uniqueness.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// FNV-1a 64-bit checksum rendered as 16 lowercase hex chars. An integrity
/// check over staged bytes, not a cryptographic commitment.
pub fn checksum_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// Streaming checksum over a reader with a bounded buffer. Returns
/// `(checksum_hex, byte_count)`.
pub fn checksum_reader<R: Read>(reader: &mut R) -> crate::Result<(String, u64)> {
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut count: u64 = 0;
    let mut buf = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        for byte in &buf[..n] {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    Ok((format!("{hash:016x}"), count))
}

/// Maximum staged-report size accepted for verification, retention, and
/// publication (128 MiB). Every staged read is bounded by this cap so a
/// swapped-in huge file cannot exhaust memory.
pub const MAX_STAGED_REPORT_BYTES: u64 = 128 * 1024 * 1024;

/// SHA-256 digest of `bytes` rendered as 64 lowercase hex chars.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_bytes(&hasher.finalize())
}

fn hex_bytes(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Staged report bytes bound to the file description they were read from.
///
/// Opened once with `O_NOFOLLOW` (symlinks refused), fstat'd from the open
/// FD, and read under a byte cap with a size re-check after the read. The
/// `(dev, ino, size, sha256)` identity binds verify → retain → publish to
/// one set of bytes: every stage consumes [`BoundStaged::bytes`] instead of
/// re-opening the path, so a swapped or mutated staging file cannot slip
/// different bytes between stages (RSF-SEC-REPORT-TOCTOU/PUBLISH-RACE).
#[derive(Debug, Clone)]
pub struct BoundStaged {
    bytes: Vec<u8>,
    dev: u64,
    ino: u64,
    size: u64,
    sha256: String,
    checksum: String,
}

impl BoundStaged {
    /// Open, fstat, and bounded-read `staged` under
    /// [`MAX_STAGED_REPORT_BYTES`].
    pub fn open(staged: &Path) -> crate::Result<Self> {
        Self::open_capped(staged, MAX_STAGED_REPORT_BYTES)
    }

    /// Open, fstat, and bounded-read `staged` under an explicit cap.
    /// The open FD must be a regular file (RSP-005): FIFOs, devices,
    /// sockets, and directories are refused before any read, so a swapped
    /// staging/snapshot path cannot hang or exhaust the reader.
    pub fn open_capped(staged: &Path, cap_bytes: u64) -> crate::Result<Self> {
        let mut file = open_nofollow(staged)?;
        require_regular_file(&file, staged)?;
        let (dev, ino, size) = fd_identity(&file)?;
        if size > cap_bytes {
            return Err(Error::Report(format!(
                "staged report {} is {size} bytes, over the {cap_bytes}-byte cap",
                staged.display()
            )));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(cap_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > cap_bytes {
            return Err(Error::Report(format!(
                "staged report {} exceeds the {cap_bytes}-byte cap",
                staged.display()
            )));
        }
        let (_, _, size_after) = fd_identity(&file)?;
        if size_after != bytes.len() as u64 {
            return Err(Error::Report(format!(
                "staged report {} changed during read ({} -> {size_after} bytes)",
                staged.display(),
                bytes.len(),
            )));
        }
        let sha256 = sha256_hex(&bytes);
        let checksum = checksum_hex(&bytes);
        let size = bytes.len() as u64;
        Ok(Self {
            bytes,
            dev,
            ino,
            size,
            sha256,
            checksum,
        })
    }

    /// The bound bytes. All downstream stages copy from this slice; the
    /// staging path is never re-opened.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Byte count of the bound bytes.
    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// True when no bytes were bound.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// SHA-256 hex digest of the bound bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// FNV-1a integrity checksum of the bound bytes (receipt compat).
    pub fn checksum(&self) -> &str {
        &self.checksum
    }

    /// `(dev, ino, size)` fstat'd from the open FD (zeros off-Unix, where
    /// the digest alone binds the bytes).
    pub fn identity(&self) -> (u64, u64, u64) {
        (self.dev, self.ino, self.size)
    }
}

/// Open `path` for reading without following a trailing symlink
/// (RSP-005): `O_NOFOLLOW|O_NONBLOCK`, then `fstat` must show a regular
/// file, then `O_NONBLOCK` is cleared before any read. A FIFO can
/// therefore never hang the opener; it is refused as non-regular.
fn open_nofollow(path: &Path) -> crate::Result<File> {
    #[cfg(unix)]
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    Error::Report(format!(
                        "refusing symlinked staged report {}",
                        path.display()
                    ))
                } else {
                    Error::Io(e.to_string())
                }
            })?;
        require_regular_file(&file, path)?;
        clear_nonblock(&file)?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        if std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(Error::Report(format!(
                "refusing symlinked staged report {}",
                path.display()
            )));
        }
        Ok(std::fs::File::open(path)?)
    }
}

/// `(dev, ino, size)` fstat'd from the open FD.
fn fd_identity(file: &File) -> crate::Result<(u64, u64, u64)> {
    #[cfg(unix)]
    {
        let meta = file.metadata()?;
        Ok((meta.dev(), meta.ino(), meta.size()))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok((0, 0, 0))
    }
}

/// Require the open FD to be a regular file (RSP-005). Checked with
/// `fstat` on the FD itself, so a path swapped to a FIFO, device, socket,
/// or directory after open is still refused before any read.
fn require_regular_file(file: &File, path: &Path) -> crate::Result<()> {
    if file.metadata()?.is_file() {
        return Ok(());
    }
    Err(Error::Report(format!(
        "refusing non-regular staged report {}",
        path.display()
    )))
}

/// Clear `O_NONBLOCK` on an already-verified regular-file FD (RSP-005),
/// restoring blocking reads. Unix only.
#[cfg(unix)]
fn clear_nonblock(file: &File) -> crate::Result<()> {
    // SAFETY: `fcntl` on an owned open FD changes only that FD's flags.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(Error::Io(format!(
            "cannot get file flags: {}",
            std::io::Error::last_os_error()
        )));
    }
    let cleared = flags & !libc::O_NONBLOCK;
    // SAFETY: as above.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, cleared) };
    if rc != 0 {
        return Err(Error::Io(format!(
            "cannot clear O_NONBLOCK: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Default controlled staging directory: `<state_dir>/payload/report_staging`.
pub fn default_staging_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("payload").join("report_staging")
}

/// Default retained-snapshot directory: `<state_dir>/payload/report_snapshots`.
pub fn default_snapshot_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("payload").join("report_snapshots")
}

/// Classification of a validated destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationKind {
    /// No file exists; publication will create it.
    Missing,
    /// A verified previous `repo-scan` report; replacement is allowed.
    VerifiedPriorReport,
}

/// Validate a report destination without writing anything. `dest` must be
/// absolute (resolved when the scan request was created). Refuses:
/// Git-administrative paths (any `.git` component), anything inside the
/// tool state directory (not just the active payload), the coordination
/// lock, symlinks anywhere on the resolved path, directories, and existing
/// unrelated files. On unix the parent directory is additionally bound
/// through an `O_NOFOLLOW|O_DIRECTORY` FD and the state/payload refusal is
/// re-checked by resolved ancestor identity, so a symlink/alias pointing
/// into state (or a transient ancestor swap) cannot bypass the string
/// tests (RSP-004/XSEC-05).
pub fn check_destination(dest: &Path, state_dir: &Path) -> crate::Result<DestinationKind> {
    if !dest.is_absolute() {
        return Err(Error::Report(format!(
            "report destination must be absolute: {}",
            dest.display()
        )));
    }
    let parent = dest.parent().ok_or_else(|| {
        Error::Report(format!(
            "report destination has no parent: {}",
            dest.display()
        ))
    })?;
    if !parent.is_dir() {
        return Err(Error::Report(format!(
            "report destination parent is not a directory: {}",
            parent.display()
        )));
    }
    // Canonicalize the existing parent so symlinked parents cannot smuggle
    // the report into a refused location; the leaf itself is checked below
    // without following it.
    let canonical_parent = parent.canonicalize().map_err(|e| {
        Error::Report(format!(
            "cannot resolve report destination parent {}: {e}",
            parent.display()
        ))
    })?;
    let file_name = dest.file_name().ok_or_else(|| {
        Error::Report(format!(
            "report destination has no file name: {}",
            dest.display()
        ))
    })?;
    if file_name == ".git" {
        return Err(report_refusal(
            dest,
            "refusing to overwrite a Git administrative path",
        ));
    }
    let effective = canonical_parent.join(file_name);
    if effective.components().any(|c| c.as_os_str() == ".git") {
        return Err(report_refusal(
            dest,
            "refusing to publish inside a Git administrative directory",
        ));
    }
    // Refuse the active persistence payload (lexical + canonical prefix).
    let payload = crate::store::owner::payload_dir(state_dir);
    let payload_candidates = [
        payload.clone(),
        payload.canonicalize().unwrap_or(payload.clone()),
    ];
    for candidate in &payload_candidates {
        if effective == *candidate || effective.starts_with(candidate) {
            return Err(report_refusal(
                dest,
                "refusing to publish into the active persistence payload",
            ));
        }
    }
    // Refuse the whole state directory identity (XSEC-05): the payload
    // check above leaves the state root itself and non-payload children
    // (staging, snapshots) publishable through a resolved alias.
    let state_candidates = [
        state_dir.to_path_buf(),
        state_dir.canonicalize().unwrap_or(state_dir.to_path_buf()),
    ];
    for candidate in &state_candidates {
        if effective == *candidate || effective.starts_with(candidate) {
            return Err(report_refusal(
                dest,
                "refusing to publish inside tool state dir",
            ));
        }
    }
    if effective == crate::store::owner::lock_path(state_dir) {
        return Err(report_refusal(
            dest,
            "refusing to publish over the coordination lock",
        ));
    }
    // Bind the resolved parent through a no-follow directory FD and
    // re-verify the policy by identity (unix). A symlink/alias into state
    // (or a transient ancestor swap after canonicalization) is caught
    // here even when the string tests above passed.
    #[cfg(unix)]
    {
        let bound = crate::store::owner::open_dir_nofollow(&canonical_parent)?;
        verify_bound_parent(&bound, &canonical_parent, dest, state_dir)?;
    }
    match std::fs::symlink_metadata(&effective) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DestinationKind::Missing),
        Err(e) => Err(Error::Report(format!(
            "cannot inspect report destination {}: {e}",
            dest.display()
        ))),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(report_refusal(
                    dest,
                    "refusing to follow a symlinked destination",
                ));
            }
            if meta.is_dir() {
                return Err(report_refusal(dest, "refusing to overwrite a directory"));
            }
            if is_verified_prior_report_in_state(&effective, state_dir)? {
                Ok(DestinationKind::VerifiedPriorReport)
            } else {
                Err(report_refusal(
                    dest,
                    "refusing to overwrite an existing unrelated file (no-clobber)",
                ))
            }
        }
    }
}

fn report_refusal(dest: &Path, reason: &str) -> Error {
    Error::Report(format!("{}: {}", dest.display(), reason))
}

/// `(dev, ino)` of `path` by `stat`, or `None` when it cannot be stated
/// (missing path: no identity to refuse). Unix only.
#[cfg(unix)]
fn path_identity(path: &Path) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

/// Re-verify the destination policy against an already-bound parent
/// directory FD (unix): the FD must still be what `canonical_parent`
/// names (transient-swap detector), its resolved ancestor chain must not
/// pass through the tool state directory or the active payload (XSEC-05),
/// and the bound path must not sit under a `.git` component. String checks
/// in [`check_destination`] stay as the fast path; these identity checks
/// are authoritative against symlink/alias and swap races.
#[cfg(unix)]
fn verify_bound_parent(
    bound: &File,
    canonical_parent: &Path,
    dest: &Path,
    state_dir: &Path,
) -> crate::Result<()> {
    let here = crate::store::owner::fd_identity(bound)?;
    if path_identity(canonical_parent) != Some(here) {
        return Err(report_refusal(
            dest,
            "destination parent changed during publication; refusing",
        ));
    }
    let chain = crate::store::owner::ancestor_identities(bound)?;
    let payload = crate::store::owner::payload_dir(state_dir);
    for identity in &chain {
        if Some(*identity) == path_identity(state_dir) {
            return Err(report_refusal(
                dest,
                "refusing to publish inside tool state dir",
            ));
        }
        if Some(*identity) == path_identity(&payload) {
            return Err(report_refusal(
                dest,
                "refusing to publish into the active persistence payload",
            ));
        }
    }
    if let Some(resolved) = crate::store::owner::fd_path(bound) {
        if resolved.components().any(|c| c.as_os_str() == ".git") {
            return Err(report_refusal(
                dest,
                "refusing to publish inside a Git administrative directory",
            ));
        }
    }
    Ok(())
}

/// True when the existing file parses as a `repo-scan` report: a JSON
/// object with `schema_version: "1.0.0"`, `tool.name: "repo-scan"`, a
/// nonempty tool version, and a nonempty snapshot-safe `report_id`. A
/// filename extension alone is never proof. Reads from an `O_NOFOLLOW`
/// regular-file FD under the staged-report cap so a swapped-in symlink,
/// special file, or huge file cannot slip through.
pub fn is_verified_prior_report(path: &Path) -> crate::Result<bool> {
    let mut file = open_nofollow(path)?;
    require_regular_file(&file, path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_STAGED_REPORT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STAGED_REPORT_BYTES {
        return Ok(false);
    }
    Ok(is_verified_prior_report_bytes(&bytes))
}

/// Byte-level prior-report check over bytes already read from an FD.
pub fn is_verified_prior_report_bytes(bytes: &[u8]) -> bool {
    prior_report_id(bytes).is_some()
}

/// Extract the claimed `report_id` when `bytes` carry the verified-prior
/// provenance fields (schema, tool name/version, snapshot-safe report ID).
fn prior_report_id(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let object = value.as_object()?;
    let schema_ok = object.get("schema_version").and_then(|v| v.as_str())
        == Some(crate::report::model::SCHEMA_VERSION);
    let tool = object.get("tool")?.as_object()?;
    let tool_ok =
        tool.get("name").and_then(|v| v.as_str()) == Some(crate::report::model::TOOL_NAME);
    let version_ok = tool
        .get("version")
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.is_empty());
    let id = object.get("report_id")?.as_str()?;
    if !(schema_ok && tool_ok && version_ok) || check_report_id(id).is_err() {
        return None;
    }
    Some(id.to_string())
}

/// State-bound prior-report check (XSEC-04): field verification plus, when
/// this state directory retains a snapshot for the claimed report ID,
/// byte-equality against the owner-private snapshot file. A planted
/// plausible report naming a retained report ID must match its bytes;
/// foreign/legacy priors with no snapshot here fall back to field
/// verification. (Full catalog-checksum/revision binding needs a store
/// handle, which the publication call graph does not thread through, so
/// the snapshot file — always byte-identical to what was published — is
/// the binding available at this layer. No database is opened.)
pub fn is_verified_prior_report_in_state(path: &Path, state_dir: &Path) -> crate::Result<bool> {
    let mut file = open_nofollow(path)?;
    require_regular_file(&file, path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_STAGED_REPORT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STAGED_REPORT_BYTES {
        return Ok(false);
    }
    let Some(prior_id) = prior_report_id(&bytes) else {
        return Ok(false);
    };
    let snapshot = default_snapshot_dir(state_dir).join(format!("{prior_id}.json"));
    match std::fs::symlink_metadata(&snapshot) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(_) => Ok(false),
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Ok(false);
            }
            let retained = match BoundStaged::open(&snapshot) {
                Ok(bound) => bound,
                Err(_) => return Ok(false),
            };
            Ok(retained.bytes() == bytes.as_slice())
        }
    }
}

/// Receipt for a successful publication.
#[derive(Debug, Clone)]
pub struct PublishReceipt {
    /// Bytes written to the destination.
    pub bytes: u64,
    /// FNV-1a checksum of the published bytes.
    pub checksum: String,
    /// SHA-256 hex digest of the published bytes.
    pub sha256: String,
    /// What the destination held before publication.
    pub replaced: DestinationKind,
}

/// Publish staged bytes to `dest`. The staging file is opened once
/// (`O_NOFOLLOW`, capped) and every later stage consumes those bound bytes.
pub fn publish_staged(
    staged: &Path,
    dest: &Path,
    state_dir: &Path,
) -> crate::Result<PublishReceipt> {
    let bound = BoundStaged::open(staged)?;
    publish_bound(&bound, dest, state_dir)
}

/// Publish already-bound staged bytes to `dest` via a temporary sibling
/// plus an atomic dir-FD install. The destination is validated before
/// staging the sibling and re-validated after the copy; the install itself
/// is race-free for new files (`link` fails with `EEXIST` when a file
/// appeared after the final gate) and FD-verified for replacements (the
/// destination's bytes are re-read from a fresh `O_NOFOLLOW` FD and must
/// still parse as a prior report before the rename, with an expected
/// `(dev, ino)` compare-and-swap recheck immediately before commit).
/// Receipt digests are computed over the bytes actually copied into the
/// sibling, never over a re-open of the staging path.
pub fn publish_bound(
    bound: &BoundStaged,
    dest: &Path,
    state_dir: &Path,
) -> crate::Result<PublishReceipt> {
    // Early gate; the pre-install re-check inside is authoritative.
    check_destination(dest, state_dir)?;
    let parent = dest.parent().ok_or_else(|| {
        Error::Report(format!(
            "report destination has no parent: {}",
            dest.display()
        ))
    })?;
    let canonical_parent = parent.canonicalize().map_err(|e| {
        Error::Report(format!(
            "cannot resolve report destination parent {}: {e}",
            parent.display()
        ))
    })?;
    let file_name = dest
        .file_name()
        .ok_or_else(|| Error::Report("report destination has no file name".to_string()))?;
    // Hold the destination directory FD for the whole install so every
    // sibling/destination operation is dir-relative. On unix the bind is
    // mandatory (no-follow, fail closed) and an exclusive directory lock
    // covers verification through install so cooperating publishers
    // serialize; elsewhere std path operations are used instead.
    #[cfg(unix)]
    let dir = {
        let bound_dir = crate::store::owner::open_dir_nofollow(&canonical_parent)?;
        verify_bound_parent(&bound_dir, &canonical_parent, dest, state_dir)?;
        lock_dir_exclusive(&bound_dir, dest)?;
        Some(bound_dir)
    };
    #[cfg(not(unix))]
    let dir: Option<File> = File::open(&canonical_parent).ok();
    let sibling = unique_sibling(&canonical_parent, file_name);
    let receipt = publish_bound_via_sibling(
        bound,
        dir.as_ref(),
        &canonical_parent,
        &sibling,
        dest,
        state_dir,
    );
    // The sibling must never be left behind on failure.
    if receipt.is_err() {
        remove_sibling(dir.as_ref(), &sibling);
    }
    let (bytes, checksum, sha256, replaced) = receipt?;
    Ok(PublishReceipt {
        bytes,
        checksum,
        sha256,
        replaced,
    })
}

/// Remove a staging sibling, dir-FD-relative on unix (the only path form
/// the install ever uses there), by path elsewhere. Best-effort.
fn remove_sibling(dir: Option<&File>, sibling: &Path) {
    #[cfg(not(unix))]
    let _ = dir;
    #[cfg(unix)]
    {
        if let Some(dir) = dir {
            if let Ok(name) = relative_cstring(sibling) {
                // SAFETY: dirfd is an open directory FD; the name is a
                // NUL-free leaf resolved relative to it.
                let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
                if rc == 0 {
                    return;
                }
            }
        }
    }
    let _ = std::fs::remove_file(sibling);
}

/// Exclusive non-blocking lock on the destination directory FD, held from
/// verification through install (RSP-003). Serializes cooperating
/// publishers; a contended destination fails fast instead of hanging.
#[cfg(unix)]
fn lock_dir_exclusive(dir: &File, dest: &Path) -> crate::Result<()> {
    // SAFETY: `flock` on an owned open directory FD is confined to that
    // FD and changes no process-global state.
    // Settle window before reporting contention: every EWOULDBLOCK
    // holder is transient (flock releases on process death; fork-shared
    // references clear at exec/exit within milliseconds), so a brief
    // bounded wait absorbs spurious conflicts while genuine contention
    // still fails fast instead of hanging.
    for _ in 0..crate::store::owner::FLOCK_SETTLE_POLLS {
        let rc = unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(());
        }
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(Error::Report(format!(
                "cannot lock destination directory for {}: {errno}",
                dest.display()
            )));
        }
        std::thread::sleep(crate::store::owner::FLOCK_SETTLE_INTERVAL);
    }
    // Settle window exhausted: genuine contention, fail fast.
    Err(Error::Report(format!(
        "destination {} is busy (another publication holds it)",
        dest.display()
    )))
}

fn publish_bound_via_sibling(
    bound: &BoundStaged,
    dir: Option<&File>,
    canonical_parent: &Path,
    sibling: &Path,
    dest: &Path,
    state_dir: &Path,
) -> crate::Result<(u64, String, String, DestinationKind)> {
    #[cfg(unix)]
    let mut output = open_sibling_nofollow(dir, sibling)?;
    #[cfg(not(unix))]
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(sibling)
        .map_err(|e| {
            Error::Report(format!(
                "cannot create staging sibling {}: {e}",
                sibling.display()
            ))
        })?;
    let mut fnv: u64 = 0xcbf29ce484222325;
    let mut sha = Sha256::new();
    let mut count: u64 = 0;
    for chunk in bound.bytes().chunks(COPY_BUFFER_BYTES) {
        output.write_all(chunk)?;
        count += chunk.len() as u64;
        sha.update(chunk);
        for byte in chunk {
            fnv ^= *byte as u64;
            fnv = fnv.wrapping_mul(0x100000001b3);
        }
    }
    output.sync_all()?;
    drop(output);
    let checksum = format!("{fnv:016x}");
    let sha256 = hex_bytes(&sha.finalize());
    // Final no-clobber gate: re-validate after the copy, before install.
    let replaced = check_destination(dest, state_dir)?;
    match replaced {
        DestinationKind::Missing => install_new(dir, sibling, dest)?,
        DestinationKind::VerifiedPriorReport => {
            install_replacement(dir, canonical_parent, sibling, dest, state_dir)?;
        }
    }
    // Best-effort directory fsync for install durability; never masks success.
    if let Some(dir) = dir {
        let _ = dir.sync_all();
    }
    Ok((count, checksum, sha256, replaced))
}

/// Atomically install the sibling onto a missing destination. `link` fails
/// with `EEXIST` when a file appeared after the final gate: a true
/// no-clobber install with no rename race. Then unlink the sibling.
#[cfg(unix)]
fn install_new(dir: Option<&File>, sibling: &Path, dest: &Path) -> crate::Result<()> {
    let dir = dir.ok_or_else(|| {
        Error::Report(format!(
            "cannot open destination directory for {}",
            dest.display()
        ))
    })?;
    let dirfd = dir.as_raw_fd();
    let sibling_c = relative_cstring(sibling)?;
    let dest_c = relative_cstring(dest)?;
    // SAFETY: dirfd is an open directory FD held by the caller; both names
    // are NUL-free leaf names resolved relative to it.
    let rc = unsafe { libc::linkat(dirfd, sibling_c.as_ptr(), dirfd, dest_c.as_ptr(), 0) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            return Err(report_refusal(
                dest,
                "refusing to overwrite an existing unrelated file (no-clobber)",
            ));
        }
        return Err(Error::Report(format!(
            "cannot link {} into place: {e}",
            dest.display()
        )));
    }
    let rc = unsafe { libc::unlinkat(dirfd, sibling_c.as_ptr(), 0) };
    if rc != 0 {
        return Err(Error::Report(format!(
            "cannot unlink staging sibling {}: {}",
            sibling.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_new(_dir: Option<&File>, sibling: &Path, dest: &Path) -> crate::Result<()> {
    match std::fs::hard_link(sibling, dest) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(report_refusal(
                dest,
                "refusing to overwrite an existing unrelated file (no-clobber)",
            ));
        }
        Err(e) => {
            return Err(Error::Report(format!(
                "cannot link {} into place: {e}",
                dest.display()
            )));
        }
    }
    std::fs::remove_file(sibling)?;
    Ok(())
}

/// Create the staging sibling dir-FD-relative with
/// `O_CREAT|O_EXCL|O_NOFOLLOW` and owner-only `0600` mode (unix): an atomic
/// no-clobber create that can neither follow a swapped-in symlink nor leak
/// report bytes to other local users. The mode is asserted after creation
/// so it never depends on the process umask (RSP-007). Unix only.
#[cfg(unix)]
fn open_sibling_nofollow(dir: Option<&File>, sibling: &Path) -> crate::Result<File> {
    use std::os::unix::fs::PermissionsExt;
    let dir = dir.ok_or_else(|| {
        Error::Report(format!(
            "cannot open destination directory for {}",
            sibling.display()
        ))
    })?;
    let name = relative_cstring(sibling)?;
    // SAFETY: dirfd is an open directory FD held by the caller; the name
    // is a generated NUL-free leaf resolved relative to it.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            crate::store::owner::STATE_FILE_MODE as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(Error::Report(format!(
            "cannot create staging sibling {}: {}",
            sibling.display(),
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `openat` returned a new owned FD; it moves into `File` once.
    let file = unsafe { File::from_raw_fd(fd) };
    let mode = file.metadata()?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Report(format!(
            "staging sibling {} mode is {mode:o}, want no group/other access",
            sibling.display()
        )));
    }
    Ok(file)
}

/// `(dev, ino)` of a dir-FD-relative leaf by `fstatat(NOFOLLOW)`, without
/// opening it. Unix only.
#[cfg(unix)]
fn leaf_identity(dirfd: libc::c_int, name: &std::ffi::CString) -> crate::Result<(u64, u64)> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: dirfd is an open directory FD; `stat` is a valid
    // out-parameter; the name is a NUL-free leaf.
    let rc = unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error().to_string()));
    }
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

/// Replace a verified prior report: re-verify the destination's bytes from
/// a freshly opened dir-FD-relative `O_NOFOLLOW` FD (never a bare path
/// re-read), bind the state's snapshot when one is retained for the
/// claimed report ID (XSEC-04), then rename the sibling over it through
/// the open directory FD. The verified FD's `(dev, ino)` is rechecked
/// against the live leaf immediately before commit (RSP-003
/// compare-and-swap); on mismatch the destination changed and the rename
/// is refused. POSIX offers no atomic conditional rename, so the
/// directory lock held by the caller serializes cooperating publishers
/// while the CAS recheck narrows the residual window to the `renameat`
/// syscall itself.
#[cfg(unix)]
fn install_replacement(
    dir: Option<&File>,
    _canonical_parent: &Path,
    sibling: &Path,
    dest: &Path,
    state_dir: &Path,
) -> crate::Result<()> {
    let dir = dir.ok_or_else(|| {
        Error::Report(format!(
            "cannot open destination directory for {}",
            dest.display()
        ))
    })?;
    let dirfd = dir.as_raw_fd();
    let dest_c = relative_cstring(dest)?;
    // SAFETY: dirfd is an open directory FD held by the caller; the name
    // is a NUL-free leaf resolved relative to it. `O_NONBLOCK` (RSP-005)
    // so a FIFO swapped in as the destination cannot hang the verifier;
    // cleared after the regular-file check.
    let fd = unsafe {
        libc::openat(
            dirfd,
            dest_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(Error::Report(format!(
            "destination {} changed during publication: {}",
            dest.display(),
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `openat` returned a new owned FD; it moves into `File` once.
    let mut file = unsafe { File::from_raw_fd(fd) };
    require_regular_file(&file, dest)?;
    clear_nonblock(&file)?;
    let expected = crate::store::owner::fd_identity(&file)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_STAGED_REPORT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STAGED_REPORT_BYTES || !is_verified_prior_report_bytes(&bytes) {
        return Err(report_refusal(
            dest,
            "destination changed during publication; refusing to overwrite",
        ));
    }
    if let Some(prior_id) = prior_report_id(&bytes) {
        let snapshot = default_snapshot_dir(state_dir).join(format!("{prior_id}.json"));
        if std::fs::symlink_metadata(&snapshot).is_ok() {
            let retained = BoundStaged::open(&snapshot).map_err(|_| {
                report_refusal(
                    dest,
                    "prior report snapshot is unreadable; refusing to overwrite",
                )
            })?;
            if retained.bytes() != bytes.as_slice() {
                return Err(report_refusal(
                    dest,
                    "destination does not match the retained snapshot; refusing to overwrite",
                ));
            }
            // The verified FD must still be the live leaf: recheck the
            // expected identity after the (slower) snapshot bind, then
            // commit immediately.
            if leaf_identity(dirfd, &dest_c).map_err(|_| {
                report_refusal(
                    dest,
                    "destination changed during publication; refusing to overwrite",
                )
            })? != expected
            {
                return Err(report_refusal(
                    dest,
                    "destination changed during publication; refusing to overwrite",
                ));
            }
        }
    }
    // Final CAS recheck immediately before commit.
    if leaf_identity(dirfd, &dest_c).map_err(|_| {
        report_refusal(
            dest,
            "destination changed during publication; refusing to overwrite",
        )
    })? != expected
    {
        return Err(report_refusal(
            dest,
            "destination changed during publication; refusing to overwrite",
        ));
    }
    let sibling_c = relative_cstring(sibling)?;
    // SAFETY: as in install_new.
    let rc = unsafe { libc::renameat(dirfd, sibling_c.as_ptr(), dirfd, dest_c.as_ptr()) };
    if rc != 0 {
        return Err(Error::Report(format!(
            "cannot replace {}: {}",
            dest.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_replacement(
    _dir: Option<&File>,
    canonical_parent: &Path,
    sibling: &Path,
    dest: &Path,
    state_dir: &Path,
) -> crate::Result<()> {
    let leaf = dest
        .file_name()
        .ok_or_else(|| Error::Report("report destination has no file name".to_string()))?;
    let effective = canonical_parent.join(leaf);
    let mut fd = File::open(&effective).map_err(|e| {
        Error::Report(format!(
            "destination {} changed during publication: {e}",
            dest.display()
        ))
    })?;
    require_regular_file(&fd, dest)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut fd)
        .take(MAX_STAGED_REPORT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STAGED_REPORT_BYTES || !is_verified_prior_report_bytes(&bytes) {
        return Err(report_refusal(
            dest,
            "destination changed during publication; refusing to overwrite",
        ));
    }
    if let Some(prior_id) = prior_report_id(&bytes) {
        let snapshot = default_snapshot_dir(state_dir).join(format!("{prior_id}.json"));
        if std::fs::symlink_metadata(&snapshot).is_ok() {
            let retained = BoundStaged::open(&snapshot).map_err(|_| {
                report_refusal(
                    dest,
                    "prior report snapshot is unreadable; refusing to overwrite",
                )
            })?;
            if retained.bytes() != bytes.as_slice() {
                return Err(report_refusal(
                    dest,
                    "destination does not match the retained snapshot; refusing to overwrite",
                ));
            }
        }
    }
    std::fs::rename(sibling, &effective)?;
    Ok(())
}

/// Leaf name of `path` as a NUL-free `CString` for dir-FD-relative calls.
#[cfg(unix)]
fn relative_cstring(path: &Path) -> crate::Result<std::ffi::CString> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::Report(format!("path {} has no file name", path.display())))?;
    std::ffi::CString::new(name.as_bytes())
        .map_err(|_| Error::Report(format!("refusing path with NUL byte: {}", path.display())))
}

fn unique_sibling(parent: &Path, file_name: &std::ffi::OsStr) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = crate::store::now_ms();
    let mut name = std::ffi::OsString::from(".");
    name.push(file_name);
    name.push(format!(".tmp-{}-{}-{counter}", std::process::id(), nanos));
    parent.join(name)
}

/// Snapshot-retention receipt.
#[derive(Debug, Clone)]
pub struct SnapshotReceipt {
    /// Path of the retained snapshot bytes.
    pub path: PathBuf,
    /// FNV-1a checksum of the retained bytes.
    pub checksum: String,
    /// SHA-256 hex digest of the retained bytes.
    pub sha256: String,
    /// Bytes retained.
    pub bytes: u64,
}

/// Retain staged bytes as the immutable snapshot `<snapshot_dir>/<report_id>.json`
/// and record the snapshot row. The staging file is opened once
/// (`O_NOFOLLOW`, capped) and the bound bytes flow into both the file and
/// the catalog row.
pub async fn retain_snapshot(
    store: &crate::store::TursoStore,
    staged: &Path,
    snapshot_dir: &Path,
    report_id: &str,
    catalog_revision: u64,
    generation: u64,
    now_ms: i64,
) -> crate::Result<SnapshotReceipt> {
    let bound = BoundStaged::open(staged)?;
    retain_bound(
        store,
        &bound,
        snapshot_dir,
        report_id,
        catalog_revision,
        generation,
        now_ms,
    )
    .await
}

/// Retain already-bound staged bytes as the immutable snapshot
/// `<snapshot_dir>/<report_id>.json` and record the snapshot row. Snapshot
/// contents are immutable by report ID: when the ID already exists, the
/// retained bytes must be identical or retention fails loudly instead of
/// mutating history. A new scan always uses a new report ID, even when
/// replacing the user's output filename.
///
/// The snapshot file is created with `create_new` (atomic no-clobber),
/// synced with its directory; the catalog row stores the SHA-256 digest.
/// Before success is reported, the row and the file are both reconciled
/// against the bound digest.
pub async fn retain_bound(
    store: &crate::store::TursoStore,
    bound: &BoundStaged,
    snapshot_dir: &Path,
    report_id: &str,
    catalog_revision: u64,
    generation: u64,
    now_ms: i64,
) -> crate::Result<SnapshotReceipt> {
    check_report_id(report_id)?;
    crate::store::owner::ensure_private_dir_all(snapshot_dir)?;
    let snapshot_path = snapshot_dir.join(format!("{report_id}.json"));

    match persist_bound_bytes(bound, &snapshot_path, snapshot_dir)? {
        PersistOutcome::Created => {}
        PersistOutcome::Existed => {
            let existing = BoundStaged::open(&snapshot_path)?;
            if existing.sha256() != bound.sha256() {
                return Err(Error::Report(format!(
                    "snapshot {report_id} already exists with different contents; \
                     snapshots are immutable by report ID"
                )));
            }
        }
    }

    let inserted = store
        .save_report_snapshot(
            report_id,
            crate::report::model::SCHEMA_VERSION,
            catalog_revision,
            generation,
            "staged",
            Some(bound.sha256().as_bytes()),
            now_ms,
        )
        .await?;
    if !inserted {
        let row = store.get_report_snapshot(report_id).await?.ok_or_else(|| {
            Error::Report(format!(
                "snapshot {report_id} vanished after insert conflict"
            ))
        })?;
        let stored = row
            .checksum
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        if stored.as_deref() != Some(bound.sha256()) {
            return Err(Error::Report(format!(
                "snapshot {report_id} already recorded with a different checksum; \
                 snapshots are immutable by report ID"
            )));
        }
    }
    // Catalog/file reconcile: the recorded row and the retained file must
    // both match the bound digest before success is reported.
    let row = store.get_report_snapshot(report_id).await?.ok_or_else(|| {
        Error::Report(format!(
            "snapshot {report_id} has no catalog row after retention"
        ))
    })?;
    let stored = row
        .checksum
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    if stored.as_deref() != Some(bound.sha256()) {
        return Err(Error::Report(format!(
            "snapshot {report_id} catalog row does not match retained bytes; \
             refusing to report success"
        )));
    }
    let retained = BoundStaged::open(&snapshot_path)?;
    if retained.sha256() != bound.sha256() {
        return Err(Error::Report(format!(
            "snapshot {report_id} file does not match retained bytes; \
             refusing to report success"
        )));
    }
    Ok(SnapshotReceipt {
        path: snapshot_path,
        checksum: bound.checksum().to_string(),
        sha256: bound.sha256().to_string(),
        bytes: bound.len(),
    })
}

/// Report IDs become snapshot filenames; only a conservative charset is
/// allowed so `<report_id>.json` cannot escape the snapshot directory.
/// Shared with the staging path so the public pipeline validates the ID
/// before it is ever interpolated into a filename (RSP-006).
pub(crate) fn check_report_id(report_id: &str) -> crate::Result<()> {
    if report_id.is_empty() {
        return Err(Error::Report("report_id must be nonempty".to_string()));
    }
    if report_id.len() > 128
        || !report_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || report_id == "."
        || report_id == ".."
    {
        return Err(Error::Report(format!(
            "report_id {report_id:?} is not a safe snapshot name"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistOutcome {
    Created,
    Existed,
}

/// Write bound bytes to `dest` with `create_new` semantics (atomic
/// no-clobber create), then sync the file and its directory. Returns
/// whether the file was created or already existed. Snapshots carry
/// inventory and remote metadata, so they are created owner-only (`0600`
/// on unix, asserted after creation so the mode never depends on the
/// process umask) inside a directory the caller bound with
/// `ensure_private_dir_all` (RSP-004/RSP-007). On unix the directory is
/// held as an `O_NOFOLLOW|O_DIRECTORY` FD and the file is created with
/// `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` relative to it: no
/// check-then-use by path between the directory check and the create.
fn persist_bound_bytes(
    bound: &BoundStaged,
    dest: &Path,
    dir: &Path,
) -> crate::Result<PersistOutcome> {
    #[cfg(unix)]
    {
        persist_bound_bytes_at(bound, dest, dir)
    }
    #[cfg(not(unix))]
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        let mut output = match opts.open(dest) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(PersistOutcome::Existed)
            }
            Err(e) => {
                return Err(Error::Report(format!(
                    "cannot create snapshot {}: {e}",
                    dest.display()
                )))
            }
        };
        output.write_all(bound.bytes())?;
        output.sync_all()?;
        drop(output);
        if let Ok(dir_fd) = File::open(dir) {
            let _ = dir_fd.sync_all();
        }
        Ok(PersistOutcome::Created)
    }
}

/// Unix `openat`-relative snapshot create (RSP-004). Holds the snapshot
/// directory FD for the create plus the directory fsync.
#[cfg(unix)]
fn persist_bound_bytes_at(
    bound: &BoundStaged,
    dest: &Path,
    dir: &Path,
) -> crate::Result<PersistOutcome> {
    use std::os::unix::fs::PermissionsExt;
    let dir_fd = crate::store::owner::open_dir_nofollow(dir)?;
    let name = relative_cstring(dest)?;
    // SAFETY: dirfd is an open directory FD; the name is a NUL-free leaf
    // resolved relative to it.
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            crate::store::owner::STATE_FILE_MODE as libc::c_uint,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            return Ok(PersistOutcome::Existed);
        }
        return Err(Error::Report(format!(
            "cannot create snapshot {}: {e}",
            dest.display()
        )));
    }
    // SAFETY: `openat` returned a new owned FD; it moves into `File` once.
    let mut output = unsafe { File::from_raw_fd(fd) };
    let mode = output.metadata()?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Report(format!(
            "snapshot {} mode is {mode:o}, want no group/other access",
            dest.display()
        )));
    }
    output.write_all(bound.bytes())?;
    output.sync_all()?;
    drop(output);
    let _ = dir_fd.sync_all();
    Ok(PersistOutcome::Created)
}
