//! Cheap resource telemetry (spec §§5, 18): at most 1 Hz collection.
//! Covers the owner + all helpers, retaining exited-child CPU so respawns
//! cannot reset the measurement. Sampling method is reported, not hidden.
//!
//! Two pieces: [`Counters`] (monotonic owner-side event counters, cheap
//! atomic increments) and [`FootprintSampler`] (periodic RSS/CPU/descriptor
//! footprint implementing [`Telemetry`]). Reaped-subprocess CPU is measured
//! automatically via `getrusage(RUSAGE_CHILDREN)`; additional retained helper
//! CPU beyond what the kernel sees arrives through [`SamplerInputs`]. Live
//! helper RSS is `Some(n)` when measured (including `Some(0)` when no helpers
//! exist) and `None` when live helpers exist but are not instrumented — an
//! honest unknown, never a fake zero. On macOS the owner RSS reading is a
//! `ru_maxrss` peak stand-in and stays labeled peak (see
//! [`ResourceSample::rss_is_peak`] and [`Telemetry::accounting_method`]).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

/// One resource sample.
#[derive(Debug, Clone)]
pub struct ResourceSample {
    /// When the sample was taken.
    pub at: SystemTime,
    /// Aggregate RSS bytes: owner plus known live-helper RSS. When helper
    /// RSS is unknown (`helpers_rss_bytes == None`) this is owner-only and
    /// understates the family; check `helpers_rss_bytes` before treating it
    /// as a family total.
    pub aggregate_rss_bytes: u64,
    /// Owner RSS bytes alone.
    pub owner_rss_bytes: u64,
    /// Live-helper RSS bytes when known. `Some(0)` means measured zero (no
    /// helpers exist); `None` means honest unknown (live helpers exist but
    /// per-helper RSS is not instrumented) — never a fake zero.
    pub helpers_rss_bytes: Option<u64>,
    /// True when RSS readings on this target are `ru_maxrss` peak stand-ins
    /// (macOS), not current RSS. Peak stays labeled peak.
    pub rss_is_peak: bool,
    /// Rolling mean logical cores over the 10 s window.
    pub rolling_cores: f64,
    /// Cumulative CPU seconds: owner plus measured reaped-children CPU plus
    /// owner-retained helper CPU.
    pub cpu_seconds: f64,
    /// Owner CPU seconds alone (`RUSAGE_SELF`).
    pub owner_cpu_seconds: f64,
    /// Measured reaped-children CPU seconds (`RUSAGE_CHILDREN`; 0 on non-unix).
    pub children_cpu_seconds: f64,
    /// Application-controlled descriptors in use (cap: 64).
    pub app_fds: usize,
    /// Currently admitted operations by class.
    pub admitted_enum_ops: usize,
    /// Currently admitted Git probes.
    pub admitted_git_probes: usize,
    /// Live helper processes incl. still-stuck.
    pub helpers: usize,
}

/// Telemetry sink contract.
pub trait Telemetry: Send {
    /// Take one cheap sample now.
    fn sample(&self) -> crate::Result<ResourceSample>;

    /// How RSS/CPU were measured (reported with results, spec §18).
    fn accounting_method(&self) -> &'static str;
}

/// Monotonic owner-side event counters. Atomic increments keep the hot path
/// cheap; [`Counters::snapshot`] feeds report `resources` fields.
#[derive(Debug, Default)]
pub struct Counters {
    /// Immediate children enumerated across all adapters.
    pub enumerated_entries: AtomicU64,
    /// Directories fully enumerated.
    pub directories_complete: AtomicU64,
    /// Database transactions committed.
    pub db_transactions: AtomicU64,
    /// Database sync calls issued.
    pub db_sync_calls: AtomicU64,
    /// Coverage gaps preserved (never converted to success).
    pub gaps: AtomicU64,
}

/// Point-in-time copy of [`Counters`].
#[derive(Debug, Clone, Copy, Default)]
pub struct CounterSnapshot {
    /// Immediate children enumerated across all adapters.
    pub enumerated_entries: u64,
    /// Directories fully enumerated.
    pub directories_complete: u64,
    /// Database transactions committed.
    pub db_transactions: u64,
    /// Database sync calls issued.
    pub db_sync_calls: u64,
    /// Coverage gaps preserved.
    pub gaps: u64,
}

impl Counters {
    /// Add `n` enumerated entries.
    pub fn add_enumerated(&self, n: u64) {
        self.enumerated_entries.fetch_add(n, Ordering::Relaxed);
    }

    /// Record one fully enumerated directory.
    pub fn add_directory(&self) {
        self.directories_complete.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one committed database transaction.
    pub fn add_transaction(&self) {
        self.db_transactions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one database sync call.
    pub fn add_sync(&self) {
        self.db_sync_calls.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one preserved coverage gap.
    pub fn add_gap(&self) {
        self.gaps.fetch_add(1, Ordering::Relaxed);
    }

    /// Copy all counters (report `resources` fields).
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            enumerated_entries: self.enumerated_entries.load(Ordering::Relaxed),
            directories_complete: self.directories_complete.load(Ordering::Relaxed),
            db_transactions: self.db_transactions.load(Ordering::Relaxed),
            db_sync_calls: self.db_sync_calls.load(Ordering::Relaxed),
            gaps: self.gaps.load(Ordering::Relaxed),
        }
    }
}

/// Owner-supplied helper contributions folded into each sample.
/// Reaped local subprocess CPU is measured automatically via
/// `RUSAGE_CHILDREN` inside [`FootprintSampler::sample_with`]; the owner
/// passes 0.0 unless it tracks CPU the kernel cannot see (e.g. remote
/// helpers). Retained values persist forever so respawning cannot reset the
/// measurement.
#[derive(Debug, Clone)]
pub struct SamplerInputs {
    /// Live-helper RSS bytes when known: `Some(0)` when `helpers == 0`
    /// (measured zero, no helpers exist); `None` when live helpers exist
    /// but their RSS is not instrumented (honest unknown, never fake 0).
    /// Build with [`live_helper_rss_bytes`] unless the owner measures helpers.
    pub helpers_rss_bytes: Option<u64>,
    /// Additional retained helper CPU seconds beyond measured reaped-children
    /// CPU. Never negative (clamped at sampling time).
    pub helpers_cpu_seconds: f64,
    /// Application-controlled descriptors in use (cap: 64).
    pub app_fds: usize,
    /// Currently admitted enumeration operations.
    pub admitted_enum_ops: usize,
    /// Currently admitted Git probes.
    pub admitted_git_probes: usize,
    /// Live helper processes incl. still-stuck.
    pub helpers: usize,
}

impl Default for SamplerInputs {
    fn default() -> Self {
        Self {
            // No helpers tracked: measured zero, not unknown.
            helpers_rss_bytes: Some(0),
            helpers_cpu_seconds: 0.0,
            app_fds: 0,
            admitted_enum_ops: 0,
            admitted_git_probes: 0,
            helpers: 0,
        }
    }
}

/// Live-helper RSS honesty helper (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1):
/// `Some(0)` when no helpers exist (measured zero); `None` when live helpers
/// exist but per-helper RSS is not instrumented (honest unknown, never a
/// hardcoded fake zero).
pub fn live_helper_rss_bytes(helpers_live: usize) -> Option<u64> {
    if helpers_live == 0 {
        Some(0)
    } else {
        None
    }
}

/// True when RSS readings on this target are `ru_maxrss` peak stand-ins
/// (macOS), not current RSS. Peak stays labeled peak.
pub fn rss_is_peak() -> bool {
    cfg!(target_os = "macos")
}

/// Rolling CPU window: keeps (instant, cumulative CPU seconds) samples and
/// reports mean logical cores over the trailing 10 s window (spec §5).
#[derive(Debug, Default)]
struct RollingCpu {
    samples: std::collections::VecDeque<(Instant, f64)>,
}

impl RollingCpu {
    /// Record one cumulative-CPU observation, returning mean cores over the
    /// trailing 10 s window (0 when the window has no usable pair yet).
    fn observe(&mut self, now: Instant, cpu_seconds: f64) -> f64 {
        const WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
        self.samples.push_back((now, cpu_seconds));
        while let Some((t, _)) = self.samples.front() {
            if now.duration_since(*t) > WINDOW {
                self.samples.pop_front();
            } else {
                break;
            }
        }
        match (self.samples.front(), self.samples.back()) {
            (Some((t0, c0)), Some((t1, c1))) if t1 > t0 => {
                let wall = t1.duration_since(*t0).as_secs_f64();
                if wall > 0.0 {
                    (c1 - c0).max(0.0) / wall
                } else {
                    0.0
                }
            }
            _ => 0.0,
        }
    }
}

/// Current RSS of the owner process in bytes (helpers add separately).
#[cfg(target_os = "linux")]
fn owner_rss_bytes() -> u64 {
    // /proc/self/statm field 2 = resident pages; cheap single read.
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let resident: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(0) as u64;
    resident.saturating_mul(page)
}

/// Owner RSS on macOS: `ru_maxrss` peak as a conservative stand-in. A true
/// current-RSS read needs `task_info` (out of `libc`'s surface); the
/// accounting string discloses this. See unresolved note in the walk-impl
/// evidence: wiring `task_info` current RSS is follow-up work.
#[cfg(target_os = "macos")]
fn owner_rss_bytes() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: usage is writable for the call.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    // macOS ru_maxrss is in bytes (not kilobytes as on Linux).
    usage.ru_maxrss.max(0) as u64
}

/// Owner RSS fallback for other targets.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn owner_rss_bytes() -> u64 {
    0
}

/// Cumulative owner CPU seconds (user + system) via `getrusage`.
#[cfg(unix)]
fn owner_cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: usage is writable for the call.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0.0;
    }
    rusage_cpu_seconds(&usage)
}

/// Owner CPU fallback for non-unix targets.
#[cfg(not(unix))]
fn owner_cpu_seconds() -> f64 {
    0.0
}

#[cfg(unix)]
fn rusage_cpu_seconds(usage: &libc::rusage) -> f64 {
    let secs = usage.ru_utime.tv_sec as f64 + usage.ru_stime.tv_sec as f64;
    let micros = usage.ru_utime.tv_usec as f64 + usage.ru_stime.tv_usec as f64;
    secs + micros / 1_000_000.0
}

/// Measured reaped-children CPU seconds (user + system) via
/// `getrusage(RUSAGE_CHILDREN)` (RSF-23D074E0-0A9B-411C-A9D3-7CBD895650C1).
/// This captures short-lived subprocess CPU (e.g. installed-git fallback
/// probes) so respawning cannot reset the measurement. Returns 0.0 when the
/// call fails.
#[cfg(unix)]
pub fn reaped_children_cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: usage is writable for the call.
    if unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) } != 0 {
        return 0.0;
    }
    rusage_cpu_seconds(&usage).max(0.0)
}

/// Reaped-children CPU fallback for non-unix targets.
#[cfg(not(unix))]
pub fn reaped_children_cpu_seconds() -> f64 {
    0.0
}

/// How this target measures RSS/CPU (reported with results, spec §18).
/// Helper CPU is measured via `RUSAGE_CHILDREN` plus owner-retained input;
/// helper RSS is `Some(n)` when measured and `None` (honest unknown, aggregate
/// is owner-only) when live helpers exist but are not instrumented.
#[cfg(target_os = "linux")]
const ACCOUNTING_METHOD: &str =
    "linux: owner RSS (current) from /proc/self/statm resident pages; CPU = getrusage(RUSAGE_SELF) + measured getrusage(RUSAGE_CHILDREN) + owner-retained SamplerInputs.helpers_cpu_seconds; live-helper RSS is Some(n) when measured (Some(0)=measured zero, no helpers) and None=honest unknown when live helpers exist but are not instrumented (aggregate is owner-only then)";
#[cfg(target_os = "macos")]
const ACCOUNTING_METHOD: &str =
    "macos: owner RSS is getrusage ru_maxrss PEAK bytes, not current RSS (task_info current-RSS wiring pending; peak stays labeled peak); CPU = getrusage(RUSAGE_SELF) + measured getrusage(RUSAGE_CHILDREN) + owner-retained SamplerInputs.helpers_cpu_seconds; live-helper RSS is Some(n) when measured (Some(0)=measured zero, no helpers) and None=honest unknown when live helpers exist but are not instrumented (aggregate is owner-peak-only then)";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const ACCOUNTING_METHOD: &str =
    "fallback: owner RSS/CPU unsupported on this target (reported 0); reaped-children CPU unsupported (0); live-helper RSS via SamplerInputs only (Some(n)=measured, None=honest unknown)";

/// Periodic footprint sampler implementing [`Telemetry`]. Interior
/// mutability is confined to the rolling CPU window; inputs are supplied
/// per sample so the owner always reports current admission state.
#[derive(Debug, Default)]
pub struct FootprintSampler {
    rolling: std::sync::Mutex<RollingCpu>,
    last_sample: std::sync::Mutex<Option<Instant>>,
}

impl FootprintSampler {
    /// New sampler with an empty rolling window.
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one sample with these owner-supplied helper/admission inputs.
    /// Reaped-subprocess CPU (`RUSAGE_CHILDREN`) is measured automatically on
    /// top of the owner-retained input so short-lived subprocess CPU (e.g.
    /// installed-git fallback probes) cannot be reset by respawning. When
    /// helper RSS is unknown (`None`), the aggregate is owner-only.
    pub fn sample_with(&self, inputs: &SamplerInputs) -> ResourceSample {
        let now = Instant::now();
        let owner_cpu = owner_cpu_seconds();
        let children_cpu = reaped_children_cpu_seconds();
        let retained = inputs.helpers_cpu_seconds.max(0.0);
        let cpu = owner_cpu + children_cpu + retained;
        let rolling_cores = self
            .rolling
            .lock()
            .map(|mut r| r.observe(now, cpu))
            .unwrap_or(0.0);
        *self.last_sample.lock().unwrap_or_else(|e| e.into_inner()) = Some(now);
        let owner_rss = owner_rss_bytes();
        let aggregate_rss_bytes = match inputs.helpers_rss_bytes {
            Some(helper_rss) => owner_rss.saturating_add(helper_rss),
            None => owner_rss,
        };
        ResourceSample {
            at: SystemTime::now(),
            aggregate_rss_bytes,
            owner_rss_bytes: owner_rss,
            helpers_rss_bytes: inputs.helpers_rss_bytes,
            rss_is_peak: rss_is_peak(),
            rolling_cores,
            cpu_seconds: cpu,
            owner_cpu_seconds: owner_cpu,
            children_cpu_seconds: children_cpu,
            app_fds: inputs.app_fds,
            admitted_enum_ops: inputs.admitted_enum_ops,
            admitted_git_probes: inputs.admitted_git_probes,
            helpers: inputs.helpers,
        }
    }

    /// True when a sample may be taken under the at-most-1 Hz rule.
    pub fn due(&self) -> bool {
        const INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
        let now = Instant::now();
        !matches!(
            *self.last_sample.lock().unwrap_or_else(|e| e.into_inner()),
            Some(t) if now.duration_since(t) < INTERVAL
        )
    }
}

impl Telemetry for FootprintSampler {
    fn sample(&self) -> crate::Result<ResourceSample> {
        Ok(self.sample_with(&SamplerInputs::default()))
    }

    fn accounting_method(&self) -> &'static str {
        ACCOUNTING_METHOD
    }
}
