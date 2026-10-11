//! Mid-scan checkpoint coordination (spec §11: coordinate checkpointing
//! with readers, measure WAL growth and checkpoint cost).
//!
//! The scan loop owns one [`CheckpointCoordinator`]: it reports applied
//! writer ops through [`CheckpointCoordinator::note_ops`] and calls
//! [`CheckpointCoordinator::maybe_checkpoint`] when a probe is due. Probes
//! use `PRAGMA wal_checkpoint(PASSIVE)` (never blocks readers); a truncate
//! runs only when observed WAL depth exceeds the policy budget. Every probe
//! and checkpoint updates [`CheckpointStats`] for PERF-02 evidence.

use std::time::{Duration, Instant};

/// When to probe the WAL and when to truncate it.
#[derive(Debug, Clone)]
pub struct CheckpointPolicy {
    /// Probe the WAL after this many applied writer ops (default 256).
    pub ops_between_probes: u64,
    /// Run `TRUNCATE` when observed WAL frames exceed this (default 1024).
    pub max_wal_frames: u64,
    /// Rate-limit probes to one per interval (default 5 s).
    pub min_probe_interval: Duration,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            ops_between_probes: 256,
            max_wal_frames: 1024,
            min_probe_interval: Duration::from_secs(5),
        }
    }
}

/// WAL-growth and checkpoint-cost counters for one scan loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CheckpointStats {
    /// `wal_status` probes performed.
    pub wal_probes: u64,
    /// Successful `TRUNCATE` checkpoints.
    pub checkpoints: u64,
    /// Probes/checkpoints skipped because the WAL was busy (a reader held
    /// it): expected coordination state, retried at the next cadence.
    pub busy_skips: u64,
    /// Probes/checkpoints skipped because the engine reported an active
    /// statement on the writer connection
    /// ([`is_checkpoint_contention`]): transient coordination state,
    /// retried at the next cadence like a busy WAL. A checkpoint is pure
    /// maintenance — durability never depends on it — so contention must
    /// not fail the scan.
    pub contention_skips: u64,
    /// WAL frames at the most recent probe.
    pub wal_frames_last: u64,
    /// Maximum WAL frames observed at any probe.
    pub wal_frames_max: u64,
}

/// Scan-loop checkpoint cadence: op counting plus WAL-growth counters.
#[derive(Debug)]
pub struct CheckpointCoordinator {
    policy: CheckpointPolicy,
    ops_since_probe: u64,
    last_probe: Option<Instant>,
    stats: CheckpointStats,
}

impl CheckpointCoordinator {
    /// Empty coordinator under `policy`; no probe has run yet.
    pub fn new(policy: CheckpointPolicy) -> Self {
        Self {
            policy,
            ops_since_probe: 0,
            last_probe: None,
            stats: CheckpointStats::default(),
        }
    }

    /// Active policy.
    pub fn policy(&self) -> &CheckpointPolicy {
        &self.policy
    }

    /// Current WAL-growth and checkpoint-cost counters.
    pub fn stats(&self) -> CheckpointStats {
        self.stats
    }

    /// Writer ops applied since the last probe.
    pub fn ops_since_probe(&self) -> u64 {
        self.ops_since_probe
    }

    /// Record `ops` applied writer ops (flushed batch ops, completions).
    /// Returns true when the op cadence makes a probe due; the caller then
    /// calls [`CheckpointCoordinator::maybe_checkpoint`], which still
    /// rate-limits on time.
    pub fn note_ops(&mut self, ops: u64) -> bool {
        self.ops_since_probe = self.ops_since_probe.saturating_add(ops);
        self.ops_since_probe >= self.policy.ops_between_probes.max(1)
    }

    /// Probe the WAL and truncate when over budget. Returns `Ok(None)` when
    /// the time rate-limit skips the probe (op count is kept); otherwise the
    /// observed [`crate::store::WalStatus`] with counters updated. A busy
    /// WAL is recorded as a skip, never an error: the scan loop keeps
    /// serving reads and retries at the next cadence. Statement contention
    /// ([`is_checkpoint_contention`]) skips the same way: the writer is
    /// single-owner and sequential, so any extra active statement at probe
    /// time is transient engine state, gone by the next cadence.
    pub async fn maybe_checkpoint(
        &mut self,
        store: &crate::store::TursoStore,
    ) -> crate::Result<Option<crate::store::WalStatus>> {
        if let Some(last) = self.last_probe {
            if last.elapsed() < self.policy.min_probe_interval {
                return Ok(None);
            }
        }
        self.ops_since_probe = 0;
        self.last_probe = Some(Instant::now());
        let status = match store.wal_status().await {
            Ok(status) => status,
            Err(error) if is_checkpoint_contention(&error) => {
                self.stats.contention_skips += 1;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        self.stats.wal_probes += 1;
        self.stats.wal_frames_last = status.log_frames;
        self.stats.wal_frames_max = self.stats.wal_frames_max.max(status.log_frames);
        if status.busy != 0 {
            self.stats.busy_skips += 1;
            return Ok(Some(status));
        }
        if status.log_frames > self.policy.max_wal_frames {
            match store.checkpoint_truncate().await {
                Ok((busy, _log_frames, _checkpointed)) => {
                    if busy != 0 {
                        self.stats.busy_skips += 1;
                    } else {
                        self.stats.checkpoints += 1;
                    }
                }
                Err(error) if is_checkpoint_contention(&error) => {
                    self.stats.contention_skips += 1;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Some(status))
    }
}

/// True when `error` is the engine refusing a checkpoint because another
/// statement is active on the writer connection. turso surfaces its
/// `StatementsInProgress` guard only as a message (Cargo.lock pins
/// turso 0.8.1; its text is `cannot checkpoint while another statement
/// is active`), so the classifier keys off that marker. Any other store
/// failure (IO, corruption, misuse elsewhere) is not contention and
/// keeps failing loudly.
pub fn is_checkpoint_contention(error: &crate::Error) -> bool {
    match error {
        crate::Error::Store(message) => message.contains("another statement is active"),
        _ => false,
    }
}
