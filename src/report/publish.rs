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
use std::io::{Read, Write};
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
/// nonempty `report_id`. A filename extension alone is never proof.
pub fn is_verified_prior_report(path: &Path) -> crate::Result<bool> {
    let bytes = std::fs::read(path)?;
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let Some(object) = value.as_object() else {
        return Ok(false);
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
    Ok(schema_ok && tool_ok && id_ok)
}

/// Receipt for a successful publication.
#[derive(Debug, Clone)]
pub struct PublishReceipt {
    /// Bytes written to the destination.
    pub bytes: u64,
    /// Checksum of the published bytes.
    pub checksum: String,
    /// What the destination held before publication.
    pub replaced: DestinationKind,
}

/// Publish staged bytes to `dest` via a temporary sibling plus atomic
/// rename. The destination is validated before staging the sibling and
/// re-validated immediately before the rename, so a file that appeared in
/// between is still subject to the no-clobber policy (a narrow TOCTOU
/// window inherent to rename-based publication remains and is documented,
/// not silently widened: the re-check is the last step before rename).
pub fn publish_staged(
    staged: &Path,
    dest: &Path,
    state_dir: &Path,
) -> crate::Result<PublishReceipt> {
    // Early gate; the pre-rename re-check inside publish_via_sibling is authoritative.
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
    let sibling = unique_sibling(&canonical_parent, file_name);
    let receipt = publish_via_sibling(staged, &canonical_parent, &sibling, dest, state_dir);
    // The sibling must never be left behind on failure.
    if receipt.is_err() {
        let _ = std::fs::remove_file(&sibling);
    }
    let (bytes, checksum, replaced) = receipt?;
    Ok(PublishReceipt {
        bytes,
        checksum,
        replaced,
    })
}

fn publish_via_sibling(
    staged: &Path,
    canonical_parent: &Path,
    sibling: &Path,
    dest: &Path,
    state_dir: &Path,
) -> crate::Result<(u64, String, DestinationKind)> {
    let mut input = std::fs::File::open(staged)?;
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
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut count: u64 = 0;
    let mut buf = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
        count += n as u64;
        for byte in &buf[..n] {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    output.sync_all()?;
    drop(output);
    // Final no-clobber gate: re-validate after the copy, before the rename.
    let replaced = check_destination(dest, state_dir)?;
    std::fs::rename(
        sibling,
        canonical_parent.join(
            dest.file_name()
                .ok_or_else(|| Error::Report("report destination has no file name".to_string()))?,
        ),
    )?;
    // Best-effort parent fsync for rename durability; never masks success.
    if let Ok(dir) = std::fs::File::open(canonical_parent) {
        let _ = dir.sync_all();
    }
    Ok((count, format!("{hash:016x}"), replaced))
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
    /// Checksum of the retained bytes.
    pub checksum: String,
    /// Bytes retained.
    pub bytes: u64,
}

/// Retain staged bytes as the immutable snapshot `<snapshot_dir>/<report_id>.json`
/// and record the snapshot row. Snapshot contents are immutable by report ID:
/// when the ID already exists, the retained bytes must be identical or
/// retention fails loudly instead of mutating history. A new scan always
/// uses a new report ID, even when replacing the user's output filename.
pub async fn retain_snapshot(
    store: &crate::store::TursoStore,
    staged: &Path,
    snapshot_dir: &Path,
    report_id: &str,
    catalog_revision: u64,
    generation: u64,
    now_ms: i64,
) -> crate::Result<SnapshotReceipt> {
    check_report_id(report_id)?;
    std::fs::create_dir_all(snapshot_dir)?;
    let snapshot_path = snapshot_dir.join(format!("{report_id}.json"));
    let mut staged_file = std::fs::File::open(staged)?;
    let (checksum, bytes) = checksum_reader(&mut staged_file)?;
    drop(staged_file);

    match persist_new_file(staged, &snapshot_path)? {
        PersistOutcome::Created => {}
        PersistOutcome::Existed => {
            let mut existing = std::fs::File::open(&snapshot_path)?;
            let (existing_checksum, _) = checksum_reader(&mut existing)?;
            if existing_checksum != checksum {
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
            Some(checksum.as_bytes()),
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
        if stored.as_deref() != Some(checksum.as_str()) {
            return Err(Error::Report(format!(
                "snapshot {report_id} already recorded with a different checksum; \
                 snapshots are immutable by report ID"
            )));
        }
    }
    Ok(SnapshotReceipt {
        path: snapshot_path,
        checksum,
        bytes,
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

/// Copy `staged` to `dest` with `create_new` semantics (bounded buffer,
/// synced). Returns whether the file was created or already existed.
fn persist_new_file(staged: &Path, dest: &Path) -> crate::Result<PersistOutcome> {
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
    let mut input = std::fs::File::open(staged)?;
    let mut buf = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
    }
    output.sync_all()?;
    Ok(PersistOutcome::Created)
}
