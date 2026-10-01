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
use std::os::unix::io::AsRawFd;
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
    pub fn open_capped(staged: &Path, cap_bytes: u64) -> crate::Result<Self> {
        let mut file = open_nofollow(staged)?;
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

/// Open `path` for reading without following a trailing symlink.
fn open_nofollow(path: &Path) -> crate::Result<File> {
    #[cfg(unix)]
    {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
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
            })
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
/// Git-administrative paths (any `.git` component), the active persistence
/// payload, symlinks anywhere on the resolved path, directories, and
/// existing unrelated files.
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
    if effective == crate::store::owner::lock_path(state_dir) {
        return Err(report_refusal(
            dest,
            "refusing to publish over the coordination lock",
        ));
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
            if is_verified_prior_report(&effective)? {
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

/// True when the existing file parses as a `repo-scan` report: a JSON
/// object with `schema_version: "1.0.0"`, `tool.name: "repo-scan"`, and a
/// nonempty `report_id`. A filename extension alone is never proof. Reads
/// from an `O_NOFOLLOW` FD under the staged-report cap so a swapped-in
/// symlink or huge file cannot slip through.
pub fn is_verified_prior_report(path: &Path) -> crate::Result<bool> {
    let mut file = open_nofollow(path)?;
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
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    let schema_ok = object.get("schema_version").and_then(|v| v.as_str())
        == Some(crate::report::model::SCHEMA_VERSION);
    let tool_ok = object
        .get("tool")
        .and_then(|v| v.as_object())
        .and_then(|t| t.get("name"))
        .and_then(|v| v.as_str())
        == Some(crate::report::model::TOOL_NAME);
    let id_ok = object
        .get("report_id")
        .and_then(|v| v.as_str())
        .is_some_and(|id| !id.is_empty());
    schema_ok && tool_ok && id_ok
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
/// still parse as a prior report before the rename). Receipt digests are
/// computed over the bytes actually copied into the sibling, never over a
/// re-open of the staging path.
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
    // sibling/destination operation is dir-relative (Unix); best-effort
    // elsewhere, where std path operations are used instead.
    let dir = File::open(&canonical_parent).ok();
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
        let _ = std::fs::remove_file(&sibling);
    }
    let (bytes, checksum, sha256, replaced) = receipt?;
    Ok(PublishReceipt {
        bytes,
        checksum,
        sha256,
        replaced,
    })
}

fn publish_bound_via_sibling(
    bound: &BoundStaged,
    dir: Option<&File>,
    canonical_parent: &Path,
    sibling: &Path,
    dest: &Path,
    state_dir: &Path,
) -> crate::Result<(u64, String, String, DestinationKind)> {
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
            install_replacement(dir, canonical_parent, sibling, dest)?;
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

/// Replace a verified prior report: re-verify the destination's bytes from
/// a freshly opened `O_NOFOLLOW` FD (never a bare path re-read), then
/// rename the sibling over it through the open directory FD.
#[cfg(unix)]
fn install_replacement(
    dir: Option<&File>,
    canonical_parent: &Path,
    sibling: &Path,
    dest: &Path,
) -> crate::Result<()> {
    let dir = dir.ok_or_else(|| {
        Error::Report(format!(
            "cannot open destination directory for {}",
            dest.display()
        ))
    })?;
    let leaf = dest
        .file_name()
        .ok_or_else(|| Error::Report("report destination has no file name".to_string()))?;
    let effective = canonical_parent.join(leaf);
    let mut fd = open_nofollow(&effective).map_err(|e| {
        Error::Report(format!(
            "destination {} changed during publication: {e}",
            dest.display()
        ))
    })?;
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
    let dirfd = dir.as_raw_fd();
    let sibling_c = relative_cstring(sibling)?;
    let dest_c = relative_cstring(dest)?;
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
    std::fs::create_dir_all(snapshot_dir)?;
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
fn check_report_id(report_id: &str) -> crate::Result<()> {
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
/// whether the file was created or already existed.
fn persist_bound_bytes(
    bound: &BoundStaged,
    dest: &Path,
    dir: &Path,
) -> crate::Result<PersistOutcome> {
    let mut output = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
    {
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
