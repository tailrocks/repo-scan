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
    /// serving reads and retries at the next cadence.
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
        let status = store.wal_status().await?;
        self.stats.wal_probes += 1;
        self.stats.wal_frames_last = status.log_frames;
        self.stats.wal_frames_max = self.stats.wal_frames_max.max(status.log_frames);
        if status.busy != 0 {
            self.stats.busy_skips += 1;
            return Ok(Some(status));
        }
        if status.log_frames > self.policy.max_wal_frames {
            let (busy, _log_frames, _checkpointed) = store.checkpoint_truncate().await?;
            if busy != 0 {
                self.stats.busy_skips += 1;
            } else {
                self.stats.checkpoints += 1;
            }
        }
        Ok(Some(status))
    }
}
