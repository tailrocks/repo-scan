//! Configuration and the spec §5 resource table defaults.
//! Hard admission limits vs buffer bounds vs measured targets are kept
//! distinct, exactly as §5 requires.

use std::path::PathBuf;
use std::time::Duration;

/// Hard admission + buffer defaults from the spec §5 resource table.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Active enumeration operations (hard max): 2.
    pub max_enum_ops: usize,
    /// Active Git probes (hard max): 1.
    pub max_git_probes: usize,
    /// Shared expensive-operation permits (hard max): 2. Enum + Git slots
    /// are NOT additive permission to exceed this.
    pub shared_permits: usize,
    /// Helper processes incl. idle and still-stuck (hard max): 4.
    pub max_helpers: usize,
    /// Scheduler prefetch task cap: 1,024.
    pub prefetch_tasks: usize,
    /// Scheduler prefetch byte cap: 4 MiB.
    pub prefetch_bytes: usize,
    /// Enumeration IPC batch entry cap: 256.
    pub batch_entries: usize,
    /// Enumeration IPC batch byte cap: 256 KiB.
    pub batch_bytes: usize,
    /// Pending producer batches per producer: 2.
    pub pending_batches_per_producer: usize,
    /// Writer batch row cap: 512.
    pub writer_rows: usize,
    /// Writer batch byte cap: 512 KiB.
    pub writer_bytes: usize,
    /// Writer maximum batch age (NOT a fixed sleep): 250 ms.
    pub writer_max_age: Duration,
    /// Application data descriptors under app control: 64.
    pub max_app_fds: usize,
    /// Progress refresh: at most 2 Hz.
    pub progress_max_hz: u32,
    /// Resource telemetry: at most 1 Hz.
    pub telemetry_max_hz: u32,
    /// CPU target: one logical core over rolling 10 s (feedback target).
    pub cpu_target_cores: f64,
    /// Aggregate RSS target incl. owner + helpers: 256 MiB.
    pub rss_target_bytes: u64,
    /// Memory-pressure response threshold: 512 MiB.
    pub pressure_threshold_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_enum_ops: 2,
            max_git_probes: 1,
            shared_permits: 2,
            max_helpers: 4,
            prefetch_tasks: 1024,
            prefetch_bytes: 4 * 1024 * 1024,
            batch_entries: 256,
            batch_bytes: 256 * 1024,
            pending_batches_per_producer: 2,
            writer_rows: 512,
            writer_bytes: 512 * 1024,
            writer_max_age: Duration::from_millis(250),
            max_app_fds: 64,
            progress_max_hz: 2,
            telemetry_max_hz: 1,
            cpu_target_cores: 1.0,
            rss_target_bytes: 256 * 1024 * 1024,
            pressure_threshold_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Effective tool configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Resolved absolute state directory.
    pub state_dir: PathBuf,
    /// Resource budgets.
    pub resources: ResourceLimits,
}

impl Config {
    /// Build from an optional `--state-dir` override. TODO(phase-2): apply
    /// config-file layer and validate budgets; invalid values are exit 2.
    pub fn load(state_dir: Option<PathBuf>) -> crate::Result<Self> {
        let dir = match state_dir {
            Some(p) => p,
            None => default_state_dir(),
        };
        Ok(Self {
            state_dir: dir,
            resources: ResourceLimits::default(),
        })
    }
}

/// Default state directory, resolved once to an absolute path (spec §3).
/// macOS: `~/Library/Application Support/repo-scan`. Never a temp dir.
pub fn default_state_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        match std::env::var("HOME") {
            Ok(home) => PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("repo-scan"),
            Err(_) => PathBuf::from("Library/Application Support/repo-scan"),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
            PathBuf::from(xdg).join("repo-scan")
        } else {
            match std::env::var("HOME") {
                Ok(home) => PathBuf::from(home).join(".local/state/repo-scan"),
                Err(_) => PathBuf::from(".local/state/repo-scan"),
            }
        }
    }
}
