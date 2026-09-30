//! Cheap resource telemetry (spec §§5, 18): at most 1 Hz collection.
//! Covers the owner + all helpers, retaining exited-child CPU so respawns
//! cannot reset the measurement. Sampling method is reported, not hidden.

use std::time::SystemTime;

/// One resource sample.
#[derive(Debug, Clone)]
pub struct ResourceSample {
    /// When the sample was taken.
    pub at: SystemTime,
    /// Aggregate RSS bytes (owner + live helpers).
    pub aggregate_rss_bytes: u64,
    /// Rolling mean logical cores over the 10 s window.
    pub rolling_cores: f64,
    /// Cumulative CPU seconds incl. exited children.
    pub cpu_seconds: f64,
    /// Application-controlled descriptors in use (cap: 64).
    pub app_fds: usize,
    /// Currently admitted operations by class.
    pub admitted_enum_ops: usize,
    /// Currently admitted Git probes.
    pub admitted_git_probes: usize,
    /// Live helper processes incl. still-stuck.
    pub helpers: usize,
}

/// Telemetry sink contract. TODO(phase-2): macOS task-info + rusage
/// implementation, Linux fixture implementation, 1 Hz sampler.
pub trait Telemetry: Send {
    /// Take one cheap sample now.
    fn sample(&self) -> crate::Result<ResourceSample>;

    /// How RSS/CPU were measured (reported with results, spec §18).
    fn accounting_method(&self) -> &'static str;
}
