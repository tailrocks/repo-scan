//! Machine-scope root planning (spec §7).
//!
//! `machine` scope inventories every mounted, addressable root and attempts
//! each fairly. Likely locations are seeded for early useful results but
//! never substitute for complete scope: `/tmp`, `/private/tmp`, the
//! effective user home, `/private/var/folders`, and configured Cargo
//! locations are priorities, and a large ordinary root must not starve the
//! temporary locations indefinitely (hence round-robin scheduling across
//! roots). Nothing is excluded by directory name (`target`, `.cargo`,
//! `.cache`, `node_modules`, `.git` are all in scope).

use crate::platform::{MountPoint, VolumeId};
use std::path::PathBuf;

/// Scheduling priority of one planned root. Priority orders first contact;
/// every root is still attempted fairly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootPriority {
    /// Seed: likely location, visited first for early results.
    Early,
    /// Ordinary scope member.
    Normal,
}

/// One root of the machine plan.
#[derive(Debug, Clone)]
pub struct PlannedRoot {
    /// Absolute path where enumeration starts.
    pub path: PathBuf,
    /// Scheduling priority.
    pub priority: RootPriority,
    /// Dedup namespace for physical-dir identity (volume UUID or mount).
    pub namespace: String,
    /// Owning volume, when known from the mount table.
    pub volume: Option<VolumeId>,
}

/// Seed likely locations for early useful results (spec §7). These are
/// priorities, not scope: the full mount table is always added by
/// [`plan_machine_roots`].
pub fn seed_roots() -> Vec<PlannedRoot> {
    let mut seeds = Vec::new();
    let mut push = |path: PathBuf| {
        seeds.push(PlannedRoot {
            path,
            priority: RootPriority::Early,
            namespace: String::from("seed"),
            volume: None,
        });
    };

    push(PathBuf::from("/tmp"));
    #[cfg(target_os = "macos")]
    push(PathBuf::from("/private/tmp"));

    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            push(PathBuf::from(&home));
        }
    }

    #[cfg(target_os = "macos")]
    push(PathBuf::from("/private/var/folders"));

    if let Ok(cargo) = std::env::var("CARGO_HOME") {
        if !cargo.is_empty() {
            push(PathBuf::from(cargo));
        }
    } else if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            push(PathBuf::from(home).join(".cargo"));
        }
    }

    seeds
}

/// Build the machine-scope plan: seeds first, then every mount-table root,
/// deduplicated by path. Unavailable or permission-denied roots stay in the
/// plan as coverage gaps; they are never silently dropped here.
pub fn plan_machine_roots(mounts: &[MountPoint]) -> Vec<PlannedRoot> {
    let mut roots = seed_roots();
    for mount in mounts {
        if roots.iter().any(|r| r.path == mount.mount_path) {
            continue;
        }
        roots.push(PlannedRoot {
            path: mount.mount_path.clone(),
            priority: RootPriority::Normal,
            namespace: mount.volume.0.clone(),
            volume: Some(mount.volume.clone()),
        });
    }
    roots
}

/// Round-robin cursor over the planned roots. The scheduler pulls roots
/// through [`RootPlan::next`] so a huge tree under one root cannot starve
/// the others — each root gets interleaved directory tasks.
#[derive(Debug)]
pub struct RootPlan {
    roots: Vec<PlannedRoot>,
    cursor: usize,
}

impl RootPlan {
    /// Plan over these roots in the given order.
    pub fn new(roots: Vec<PlannedRoot>) -> Self {
        Self { roots, cursor: 0 }
    }

    /// Next root in round-robin order, or `None` when the plan is empty.
    // Not `Iterator::next`: the borrowed item cannot be an `Item` type, and
    // the cursor cycles forever rather than terminating.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<&PlannedRoot> {
        if self.roots.is_empty() {
            return None;
        }
        let root = &self.roots[self.cursor % self.roots.len()];
        self.cursor = self.cursor.wrapping_add(1);
        Some(root)
    }

    /// Number of planned roots.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// True when the plan holds no roots.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// All planned roots in plan order.
    pub fn roots(&self) -> &[PlannedRoot] {
        &self.roots
    }
}
