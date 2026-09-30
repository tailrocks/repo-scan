//! Hard admission limits and buffer bounds (spec §5, [`ResourceLimits`]).
//!
//! Hard admission maximums (never exceeded):
//! - 2 active enumeration operations, 1 active Git probe, 2 shared
//!   expensive-operation permits (enum + Git slots are NOT additive
//!   permission to exceed the shared limit), 4 helper processes including
//!   idle and still-stuck, 64 application data descriptors.
//! - Scheduler prefetch stops at 1,024 tasks or 4 MiB, first limit wins.
//! - Progress refresh at most 2 Hz, resource telemetry at most 1 Hz.
//!
//! CPU (one logical core over a rolling 10 s window) and RSS (256 MiB) are
//! measured feedback targets, not kernel ceilings; the 512 MiB threshold
//! triggers stopped admission via [`Admission::set_pressure`].

use crate::config::ResourceLimits;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Class of an expensive operation requesting admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpClass {
    /// Directory enumeration (also needs a shared permit).
    Enumerate,
    /// Git probe (also needs a shared permit).
    GitProbe,
    /// Other inspected-scope or external-sink work (shared permit only).
    Other,
}

/// Opaque admission token. The holder must return it to
/// [`Admission::release`] when the operation finishes; permits are not
/// transferable between operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Permit {
    id: u64,
    class: OpClass,
}

/// Point-in-time admission snapshot for telemetry.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdmissionSnapshot {
    /// Currently admitted enumeration operations.
    pub enum_in_use: usize,
    /// Currently admitted Git probes.
    pub git_in_use: usize,
    /// Currently held shared expensive-operation permits.
    pub shared_in_use: usize,
    /// Live helper processes including still-stuck ones.
    pub helpers_live: usize,
    /// Application-controlled descriptors in use.
    pub app_fds: usize,
}

/// Enforces the spec §5 hard admission limits. Single-threaded by design:
/// the owner admits work on its coordinator context only.
#[derive(Debug)]
pub struct Admission {
    limits: ResourceLimits,
    next_permit: u64,
    live: HashSet<Permit>,
    enum_in_use: usize,
    git_in_use: usize,
    shared_in_use: usize,
    helpers_live: usize,
    app_fds: usize,
    pressure: bool,
    last_progress: Option<Instant>,
    last_telemetry: Option<Instant>,
}

impl Admission {
    /// Enforcer for these effective limits.
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            next_permit: 1,
            live: HashSet::new(),
            enum_in_use: 0,
            git_in_use: 0,
            shared_in_use: 0,
            helpers_live: 0,
            app_fds: 0,
            pressure: false,
            last_progress: None,
            last_telemetry: None,
        }
    }

    /// Try to admit one operation. Returns `None` (without blocking) when
    /// the class cap, the shared cap, or memory pressure forbids it.
    /// Enumeration also consumes one of the 2 shared permits; a Git probe
    /// consumes its 1 Git slot plus one shared permit.
    pub fn try_acquire(&mut self, class: OpClass) -> Option<Permit> {
        if self.pressure {
            return None;
        }
        match class {
            OpClass::Enumerate => {
                if self.enum_in_use >= self.limits.max_enum_ops
                    || self.shared_in_use >= self.limits.shared_permits
                {
                    return None;
                }
                self.enum_in_use += 1;
                self.shared_in_use += 1;
            }
            OpClass::GitProbe => {
                if self.git_in_use >= self.limits.max_git_probes
                    || self.shared_in_use >= self.limits.shared_permits
                {
                    return None;
                }
                self.git_in_use += 1;
                self.shared_in_use += 1;
            }
            OpClass::Other => {
                if self.shared_in_use >= self.limits.shared_permits {
                    return None;
                }
                self.shared_in_use += 1;
            }
        }
        let permit = Permit {
            id: self.next_permit,
            class,
        };
        self.next_permit = self.next_permit.wrapping_add(1).max(1);
        self.live.insert(permit);
        Some(permit)
    }

    /// Release a previously granted permit. Unknown or already-released
    /// permits are ignored (never panic, never corrupt counters).
    pub fn release(&mut self, permit: &Permit) {
        if !self.live.remove(permit) {
            return;
        }
        match permit.class {
            OpClass::Enumerate => {
                self.enum_in_use = self.enum_in_use.saturating_sub(1);
                self.shared_in_use = self.shared_in_use.saturating_sub(1);
            }
            OpClass::GitProbe => {
                self.git_in_use = self.git_in_use.saturating_sub(1);
                self.shared_in_use = self.shared_in_use.saturating_sub(1);
            }
            OpClass::Other => {
                self.shared_in_use = self.shared_in_use.saturating_sub(1);
            }
        }
    }

    /// True when another helper process may spawn (live count below the
    /// hard maximum of 4, including idle and still-stuck helpers).
    pub fn helper_spawn_allowed(&self) -> bool {
        !self.pressure && self.helpers_live < self.limits.max_helpers
    }

    /// Record a newly spawned helper. Returns false (and records nothing)
    /// when the hard cap forbids it.
    pub fn add_helper(&mut self) -> bool {
        if self.helpers_live >= self.limits.max_helpers {
            return false;
        }
        self.helpers_live += 1;
        true
    }

    /// Record a helper that fully exited and was reaped. Still-stuck
    /// helpers are NOT removed here: they keep counting against the cap so
    /// the owner cannot spawn unlimited replacements into a dead volume.
    pub fn remove_helper(&mut self) {
        self.helpers_live = self.helpers_live.saturating_sub(1);
    }

    /// Try to take `n` application data descriptors from the 64-descriptor
    /// budget. Returns false (taking nothing) when over budget.
    pub fn fd_acquire(&mut self, n: usize) -> bool {
        if self.app_fds + n > self.limits.max_app_fds {
            return false;
        }
        self.app_fds += n;
        true
    }

    /// Return `n` descriptors to the budget.
    pub fn fd_release(&mut self, n: usize) {
        self.app_fds = self.app_fds.saturating_sub(n);
    }

    /// True when the scheduler may prefetch more tasks: stops at 1,024
    /// tasks or 4 MiB estimated bytes, first limit wins. Remaining work
    /// stays in the database.
    pub fn prefetch_allowed(&self, tasks: usize, bytes: usize) -> bool {
        !self.pressure && tasks < self.limits.prefetch_tasks && bytes < self.limits.prefetch_bytes
    }

    /// Scheduler prefetch task cap (1,024).
    pub fn prefetch_task_cap(&self) -> usize {
        self.limits.prefetch_tasks
    }

    /// Scheduler prefetch byte cap (4 MiB).
    pub fn prefetch_byte_cap(&self) -> usize {
        self.limits.prefetch_bytes
    }

    /// At-most-2 Hz progress gate: true when a progress refresh may emit.
    /// Coalesces updates; the first call always passes.
    pub fn progress_due(&mut self) -> bool {
        rate_gate(
            &mut self.last_progress,
            Duration::from_millis(1000 / self.limits.progress_max_hz.max(1) as u64),
        )
    }

    /// At-most-1 Hz telemetry gate: true when a resource sample may be taken.
    pub fn telemetry_due(&mut self) -> bool {
        rate_gate(
            &mut self.last_telemetry,
            Duration::from_millis(1000 / self.limits.telemetry_max_hz.max(1) as u64),
        )
    }

    /// Enter or leave the memory-pressure regime (spec §5: 512 MiB
    /// threshold). While set, all admission and prefetch stop; already
    /// accepted results drain within a bounded grace period.
    pub fn set_pressure(&mut self, on: bool) {
        self.pressure = on;
    }

    /// True while memory pressure stops admission.
    pub fn under_pressure(&self) -> bool {
        self.pressure
    }

    /// Current admission counters for telemetry.
    pub fn snapshot(&self) -> AdmissionSnapshot {
        AdmissionSnapshot {
            enum_in_use: self.enum_in_use,
            git_in_use: self.git_in_use,
            shared_in_use: self.shared_in_use,
            helpers_live: self.helpers_live,
            app_fds: self.app_fds,
        }
    }
}

/// Interval gate: true (and records `now`) when `last` is empty or the
/// interval has elapsed since `last`.
fn rate_gate(last: &mut Option<Instant>, interval: Duration) -> bool {
    let now = Instant::now();
    match *last {
        Some(t) if now.duration_since(t) < interval => false,
        _ => {
            *last = Some(now);
            true
        }
    }
}
