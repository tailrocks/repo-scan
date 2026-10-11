//! Wave2b output-matrix support: machine writers, live-publication throttle,
//! and bounded completed-snapshot retention (contract D6/D12).
//!
//! One state model: the human, JSON, and JSONL lanes all read the same
//! staged/retained snapshot bytes (or the journal committed with them).
//! This module holds the shared output-side pieces:
//!
//! - [`write_machine_bytes`]: stdout discipline for machine lanes — raw
//!   bytes plus one trailing newline, no prose, no ANSI, no cursor codes.
//!   A broken pipe ends quietly (`Ok(false)`); any other IO error fails.
//! - [`LiveThrottle`]: the bounded live-publication interval. Rebuilds
//!   happen only at phase boundaries (never per discovery); the throttle
//!   additionally guarantees at most one live replacement per interval.
//! - [`prune_snapshot_files`]: completed snapshots are retained bounded
//!   ([`MAX_RETAINED_SNAPSHOTS`]); snapshots referenced by a scan
//!   outcome are never pruned. Live publications are never retained —
//!   the destination file is replaced, not accumulated.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Minimum interval between live `--report` replacements (D12). Live
/// rebuilds are already boundary-gated (never per discovery); this
/// interval bounds bursty boundaries too.
pub const LIVE_PUBLISH_MIN_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum completed snapshots retained in the snapshot directory
/// (D12). The newest [`MAX_RETAINED_SNAPSHOTS`] files survive; older
/// files are deleted unless a scan outcome references them (referenced
/// snapshots are never pruned, so `resume` and `query --scan
/// --format json|human` keep working).
pub const MAX_RETAINED_SNAPSHOTS: usize = 32;

/// Write machine-lane bytes to `out`: the bytes verbatim plus one `\n`.
/// Returns `Ok(false)` when the consumer went away (broken pipe): the
/// writer stops quietly with committed catalog records untouched. Any
/// other IO error fails loudly. Never emits prose, ANSI escapes, or
/// cursor codes — callers must pass only serialized JSON/JSONL.
pub fn write_machine_bytes<W: std::io::Write + ?Sized>(
    out: &mut W,
    bytes: &[u8],
) -> crate::Result<bool> {
    match out.write_all(bytes).and_then(|()| out.write_all(b"\n")) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(crate::Error::Io(format!(
            "cannot write machine output: {e}"
        ))),
    }
}

/// Flush a machine-lane writer. `Ok(false)` is a broken pipe (quiet
/// stop); any other error fails loudly.
pub fn flush_machine<W: std::io::Write + ?Sized>(out: &mut W) -> crate::Result<bool> {
    match out.flush() {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(crate::Error::Io(format!(
            "cannot flush machine output: {e}"
        ))),
    }
}

/// True when `bytes` carry no terminal-control escape (ESC/BEL) and no
/// carriage return: the machine-lane purity rule. Newlines are allowed
/// (JSONL framing); other control bytes inside string values are the
/// serializer's business (`serde_json` escapes them).
#[must_use]
pub fn is_machine_pure(bytes: &[u8]) -> bool {
    !bytes.contains(&0x1b) && !bytes.contains(&0x07) && !bytes.contains(&b'\r')
}

/// Bounded-interval gate for live `--report` replacement (D12).
#[derive(Debug)]
pub struct LiveThrottle {
    last: Option<Instant>,
    min_interval: Duration,
}

impl LiveThrottle {
    /// New throttle: the first publication always passes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last: None,
            min_interval: LIVE_PUBLISH_MIN_INTERVAL,
        }
    }

    /// Test/fixture constructor with an explicit interval.
    #[must_use]
    pub fn with_interval(min_interval: Duration) -> Self {
        Self {
            last: None,
            min_interval,
        }
    }

    /// True when a live publication may proceed now (first call, or at
    /// least `min_interval` since the last admitted one). Admitted
    /// calls stamp `now`; denied calls leave the stamp untouched.
    pub fn admit(&mut self) -> bool {
        let now = Instant::now();
        match self.last {
            None => {
                self.last = Some(now);
                true
            }
            Some(last) if now.duration_since(last) >= self.min_interval => {
                self.last = Some(now);
                true
            }
            Some(_) => false,
        }
    }
}

impl Default for LiveThrottle {
    fn default() -> Self {
        Self::new()
    }
}

/// One candidate snapshot file for retention pruning.
#[derive(Debug, Clone)]
pub struct SnapshotEntry {
    /// Report ID (file stem of `<id>.json`).
    pub id: String,
    /// Full path.
    pub path: PathBuf,
    /// Last-modified time; files without metadata sort oldest.
    pub modified: Option<std::time::SystemTime>,
}

/// List retained snapshot files: `<dir>/<safe-id>.json` regular files
/// only. Symlinks, subdirectories, staging/quarantine residue, and
/// unsafe stems are never candidates (never followed, never deleted).
#[must_use]
pub fn list_snapshot_entries(dir: &Path) -> Vec<SnapshotEntry> {
    let mut out = Vec::new();
    let Ok(read) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.file_type().is_symlink() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if !is_safe_snapshot_stem(stem) {
            continue;
        }
        out.push(SnapshotEntry {
            id: stem.to_string(),
            path,
            modified: meta.modified().ok(),
        });
    }
    out
}

/// Mirror of the snapshot-ID filename gate (lib `check_report_id` plus
/// the `.json` suffix rule): nonempty, at most 128 bytes,
/// `[A-Za-z0-9._-]`, never `.`/`..`.
fn is_safe_snapshot_stem(stem: &str) -> bool {
    !stem.is_empty()
        && stem.len() <= 128
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && stem != "."
        && stem != ".."
}

/// Select pruning victims: entries sorted oldest-first, the newest
/// `keep` survive, and every ID in `referenced` survives regardless of
/// age (a scan outcome names it, so `resume`/`query` may still need
/// it). Pure: the caller deletes.
#[must_use]
pub fn select_snapshot_victims(
    mut entries: Vec<SnapshotEntry>,
    referenced: &HashSet<String>,
    keep: usize,
) -> Vec<SnapshotEntry> {
    entries.sort_by(|a, b| a.modified.cmp(&b.modified).then_with(|| a.id.cmp(&b.id)));
    if entries.len() <= keep {
        return Vec::new();
    }
    let victim_count = entries.len() - keep;
    entries
        .into_iter()
        .take(victim_count)
        .filter(|e| !referenced.contains(&e.id))
        .collect()
}

/// Delete unreferenced completed snapshots beyond
/// [`MAX_RETAINED_SNAPSHOTS`] (oldest first). Returns the pruned report
/// IDs so the caller can delete the matching catalog rows. Best-effort
/// per file: an undeletable file is skipped, never fatal.
pub fn prune_snapshot_files(dir: &Path, referenced: &HashSet<String>, keep: usize) -> Vec<String> {
    let victims = select_snapshot_victims(list_snapshot_entries(dir), referenced, keep);
    let mut pruned = Vec::new();
    for victim in victims {
        if std::fs::remove_file(&victim.path).is_ok() {
            pruned.push(victim.id);
        }
    }
    pruned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_writer_appends_single_newline() {
        let mut out = Vec::new();
        assert!(write_machine_bytes(&mut out, b"{\"a\":1}").unwrap());
        assert_eq!(out, b"{\"a\":1}\n");
        assert!(is_machine_pure(&out));
    }

    #[test]
    fn machine_purity_rejects_esc_bel_cr() {
        assert!(is_machine_pure(b"{\"a\":1}\n{\"b\":2}\n"));
        assert!(!is_machine_pure(b"\x1b[31m{\"a\":1}\n"));
        assert!(!is_machine_pure(b"{\"a\":1}\x07\n"));
        assert!(!is_machine_pure(b"{\"a\":1}\r\n"));
    }

    struct BrokenPipe;

    impl std::io::Write for BrokenPipe {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            ))
        }
    }

    #[test]
    fn broken_pipe_is_quiet_stop() {
        assert!(!write_machine_bytes(&mut BrokenPipe, b"x").unwrap());
        assert!(!flush_machine(&mut BrokenPipe).unwrap());
    }

    #[test]
    fn throttle_admits_first_then_interval() {
        let mut t = LiveThrottle::with_interval(Duration::from_secs(60));
        assert!(t.admit());
        assert!(!t.admit());
        let mut t = LiveThrottle::with_interval(Duration::ZERO);
        assert!(t.admit());
        assert!(t.admit());
    }

    #[test]
    fn victims_are_oldest_unreferenced_beyond_keep() {
        let base = std::time::SystemTime::UNIX_EPOCH;
        let entries: Vec<SnapshotEntry> = (0..5)
            .map(|i| SnapshotEntry {
                id: format!("r{i}"),
                path: PathBuf::from(format!("/tmp/r{i}.json")),
                modified: Some(base + Duration::from_secs(i)),
            })
            .collect();
        let mut referenced = HashSet::new();
        referenced.insert("r0".to_string());
        let victims = select_snapshot_victims(entries, &referenced, 3);
        let ids: Vec<&str> = victims.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, vec!["r1"], "oldest unreferenced beyond keep");
    }

    #[test]
    fn under_bound_prunes_nothing() {
        let entries: Vec<SnapshotEntry> = (0..3)
            .map(|i| SnapshotEntry {
                id: format!("r{i}"),
                path: PathBuf::from(format!("/tmp/r{i}.json")),
                modified: None,
            })
            .collect();
        assert!(select_snapshot_victims(entries, &HashSet::new(), 32).is_empty());
    }
}
