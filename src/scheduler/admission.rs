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
//! triggers stopped admission via [`Admission::set_pressure`]. Sustained
//! rolling-core excess throttles admission via [`Admission::observe_cpu`]
//! (reduced caps plus pacing, hysteresis, no flapping).

use crate::config::ResourceLimits;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// CPU governor: consecutive over-target samples to engage throttling.
const CPU_ENTER_SAMPLES: u32 = 3;
/// CPU governor: consecutive under-target samples to release throttling.
const CPU_EXIT_SAMPLES: u32 = 3;
/// CPU governor: engage above target times this factor (1.1 matches the
/// PERF-02 gate margin at the default 1.0 target).
const CPU_ENTER_FACTOR: f64 = 1.1;
/// CPU governor: pacing pause between admissions while throttled.
const CPU_PACE_DELAY: Duration = Duration::from_millis(50);

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
    cpu_throttled: bool,
    cpu_over: u32,
    cpu_under: u32,
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
            cpu_throttled: false,
            cpu_over: 0,
            cpu_under: 0,
            last_progress: None,
            last_telemetry: None,
        }
    }

    /// Try to admit one operation. Returns `None` (without blocking) when
    /// the class cap, the shared cap, or memory pressure forbids it.
    /// Enumeration also consumes one of the 2 shared permits; a Git probe
    /// consumes its 1 Git slot plus one shared permit. While CPU-throttled
    /// the effective caps shrink (see `observe_cpu`).
    pub fn try_acquire(&mut self, class: OpClass) -> Option<Permit> {
        if self.pressure {
            return None;
        }
        let shared_cap = self.eff_shared_cap();
        match class {
            OpClass::Enumerate => {
                if self.enum_in_use >= self.eff_class_cap(self.limits.max_enum_ops)
                    || self.shared_in_use >= shared_cap
                {
                    return None;
                }
                self.enum_in_use += 1;
                self.shared_in_use += 1;
            }
            OpClass::GitProbe => {
                if self.git_in_use >= self.eff_class_cap(self.limits.max_git_probes)
                    || self.shared_in_use >= shared_cap
                {
                    return None;
                }
                self.git_in_use += 1;
                self.shared_in_use += 1;
            }
            OpClass::Other => {
                if self.shared_in_use >= shared_cap {
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
    /// hard maximum of 4, including idle and still-stuck helpers). Denied
    /// under memory pressure or CPU throttle.
    pub fn helper_spawn_allowed(&self) -> bool {
        !self.pressure && !self.cpu_throttled && self.helpers_live < self.limits.max_helpers
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
    /// stays in the database. CPU throttle halves the task cap.
    pub fn prefetch_allowed(&self, tasks: usize, bytes: usize) -> bool {
        let task_cap = if self.cpu_throttled {
            (self.limits.prefetch_tasks / 2).max(1)
        } else {
            self.limits.prefetch_tasks
        };
        !self.pressure && tasks < task_cap && bytes < self.limits.prefetch_bytes
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

    /// Feed one rolling-cores sample (trailing 10 s mean, spec §5) into the
    /// CPU governor. Sustained excess above target times `CPU_ENTER_FACTOR`
    /// for `CPU_ENTER_SAMPLES` consecutive samples engages throttling
    /// (reduced admission caps plus [`Admission::pace_delay`]); sustained
    /// relief below the target for `CPU_EXIT_SAMPLES` consecutive samples
    /// releases it. In-band samples hold the state and break both streaks,
    /// so the governor cannot flap. Non-finite or negative inputs count as
    /// zero; a non-positive target falls back to 1.0.
    pub fn observe_cpu(&mut self, rolling_cores: f64) {
        let target =
            if self.limits.cpu_target_cores.is_finite() && self.limits.cpu_target_cores > 0.0 {
                self.limits.cpu_target_cores
            } else {
                1.0
            };
        let cores = if rolling_cores.is_finite() {
            rolling_cores.max(0.0)
        } else {
            0.0
        };
        if cores > target * CPU_ENTER_FACTOR {
            self.cpu_over = self.cpu_over.saturating_add(1);
            self.cpu_under = 0;
            if self.cpu_over >= CPU_ENTER_SAMPLES {
                self.cpu_throttled = true;
            }
        } else if cores < target {
            self.cpu_under = self.cpu_under.saturating_add(1);
            self.cpu_over = 0;
            if self.cpu_under >= CPU_EXIT_SAMPLES {
                self.cpu_throttled = false;
            }
        } else {
            // Hysteresis band: hold state, break both streaks.
            self.cpu_over = 0;
            self.cpu_under = 0;
        }
    }

    /// True while sustained CPU excess throttles admission.
    pub fn cpu_throttled(&self) -> bool {
        self.cpu_throttled
    }

    /// Pacing pause to insert between admissions while CPU-throttled
    /// (zero otherwise). Bounded; the run loop sleeps it, never more.
    pub fn pace_delay(&self) -> Duration {
        if self.cpu_throttled {
            CPU_PACE_DELAY
        } else {
            Duration::ZERO
        }
    }

    /// Effective shared-permit cap (halved, minimum 1, while throttled).
    fn eff_shared_cap(&self) -> usize {
        if self.cpu_throttled {
            (self.limits.shared_permits / 2).max(1)
        } else {
            self.limits.shared_permits
        }
    }

    /// Effective per-class cap (pinned to the shared cap while throttled).
    fn eff_class_cap(&self, class_max: usize) -> usize {
        if self.cpu_throttled {
            class_max.min(self.eff_shared_cap())
        } else {
            class_max
        }
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

// ---------------------------------------------------------------------------
// Choke-point budgets and pure policy predicates (SR-STATE-01/02, SR-EVENT-01)
// ---------------------------------------------------------------------------

/// Hard cap for the process-wide helper ledger: 4 live helper children,
/// mirroring `ResourceLimits::max_helpers` (spec §5). Installed-git spawns
/// run below the owner's [`Admission`] handle, so they charge this ledger
/// at the spawn choke point instead of the unenforced owner counters.
pub const HELPER_LEDGER_CAP: usize = 4;

/// How long a spawn site waits for a ledger slot before refusing loudly.
/// Production spawns are sequential, so the wait only absorbs transient
/// contention; past it the spawn fails with an explicit ledger error.
pub const HELPER_LEDGER_WAIT: Duration = Duration::from_secs(10);

/// Aggregate native event-stream bounds (SR-STATE-02): at most 64 live
/// streams (one stream costs at least one descriptor, so this stays within
/// the `max_app_fds` class) and 16 MiB of queued callback path bytes
/// across every volume of the process.
pub const NATIVE_STREAM_CAP: usize = 64;
/// Aggregate queued callback path bytes (see [`NATIVE_STREAM_CAP`]).
pub const NATIVE_STREAM_BYTES_CAP: usize = 16 * 1024 * 1024;

/// Process-wide live-helper ledger (SR-STATE-02). Lock-free so spawn sites
/// without the owner's [`Admission`] handle can still enforce the helper
/// ceiling; releases saturate at zero and never corrupt the count.
pub struct HelperLedger {
    live: AtomicUsize,
    cap: usize,
}

impl HelperLedger {
    /// Ledger enforcing `cap` concurrent holders.
    pub const fn new(cap: usize) -> Self {
        Self {
            live: AtomicUsize::new(0),
            cap,
        }
    }

    /// Maximum concurrent holders.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Currently live holders.
    pub fn live(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// Take one holder slot. Returns false (taking nothing) at the cap.
    pub fn try_acquire(&self) -> bool {
        let mut current = self.live.load(Ordering::Relaxed);
        loop {
            if current >= self.cap {
                return false;
            }
            match self.live.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(next) => current = next,
            }
        }
    }

    /// Free one holder slot. Saturates at zero (never wraps, never panics).
    pub fn release(&self) {
        let mut current = self.live.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return;
            }
            match self.live.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(next) => current = next,
            }
        }
    }
}

impl std::fmt::Debug for HelperLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperLedger")
            .field("live", &self.live())
            .field("cap", &self.cap)
            .finish()
    }
}

/// The process-wide helper ledger every installed-git spawn charges.
pub static HELPER_LEDGER: HelperLedger = HelperLedger::new(HELPER_LEDGER_CAP);

/// Aggregate native event-stream budget (SR-STATE-02): one admission budget
/// shared by every volume stream of the process, covering live-stream count
/// plus queued callback path bytes. Streams are admitted before creation;
/// callback bytes are charged per event and released on dequeue or drop.
/// Counters saturate and never wrap.
pub struct StreamBudget {
    streams_live: AtomicUsize,
    streams_cap: usize,
    bytes_queued: AtomicUsize,
    bytes_cap: usize,
}

impl StreamBudget {
    /// Budget enforcing `streams_cap` live streams and `bytes_cap` queued
    /// callback bytes in aggregate.
    pub const fn new(streams_cap: usize, bytes_cap: usize) -> Self {
        Self {
            streams_live: AtomicUsize::new(0),
            streams_cap,
            bytes_queued: AtomicUsize::new(0),
            bytes_cap,
        }
    }

    /// Currently live streams.
    pub fn streams_live(&self) -> usize {
        self.streams_live.load(Ordering::Relaxed)
    }

    /// Currently queued callback bytes.
    pub fn bytes_queued(&self) -> usize {
        self.bytes_queued.load(Ordering::Relaxed)
    }

    /// Admit one stream. Returns false (admitting nothing) at the cap.
    pub fn try_acquire_stream(&self) -> bool {
        let mut current = self.streams_live.load(Ordering::Relaxed);
        loop {
            if current >= self.streams_cap {
                return false;
            }
            match self.streams_live.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(next) => current = next,
            }
        }
    }

    /// Release one stream slot. Saturates at zero.
    pub fn release_stream(&self) {
        let mut current = self.streams_live.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return;
            }
            match self.streams_live.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(next) => current = next,
            }
        }
    }

    /// Charge `n` queued callback bytes. Returns false (charging nothing)
    /// when the aggregate byte cap would be exceeded.
    pub fn try_charge_bytes(&self, n: usize) -> bool {
        let mut current = self.bytes_queued.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(n) else {
                return false;
            };
            if next > self.bytes_cap {
                return false;
            }
            match self.bytes_queued.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Release `n` queued callback bytes. Saturates at zero.
    pub fn release_bytes(&self, n: usize) {
        let mut current = self.bytes_queued.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(n);
            match self.bytes_queued.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}

impl std::fmt::Debug for StreamBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamBudget")
            .field("streams_live", &self.streams_live())
            .field("streams_cap", &self.streams_cap)
            .field("bytes_queued", &self.bytes_queued())
            .field("bytes_cap", &self.bytes_cap)
            .finish()
    }
}

/// The process-wide native-stream budget every volume stream charges.
pub static NATIVE_STREAM_BUDGET: StreamBudget =
    StreamBudget::new(NATIVE_STREAM_CAP, NATIVE_STREAM_BYTES_CAP);

/// Lease-renewal policy for long in-loop operations (SR-STATE-01): renew
/// the task lease every `every` observed entries (including the first check
/// at zero) so a slow-but-advancing operation never lets its lease lapse
/// mid-operation. Returns the new expiry (`now_ms + ttl_ms`, saturating)
/// when renewal is due, else `None`. Pure and unit-testable.
pub fn lease_renewal_expiry(
    entries_seen: u64,
    every: u64,
    now_ms: i64,
    ttl_ms: i64,
) -> Option<i64> {
    if every == 0 || !entries_seen.is_multiple_of(every) {
        return None;
    }
    Some(now_ms.saturating_add(ttl_ms))
}

/// R04: Time-and-progress lease renewal policy for long in-loop operations:
/// renew the task lease when `entries_seen == 0` (initial claim check) or
/// when elapsed time since the last renewal reaches or exceeds `interval`.
/// Returns the new expiry (`now_ms + ttl_ms`, saturating) when renewal is due,
/// else `None`. Pure and unit-testable.
pub fn lease_renewal_expiry_elapsed(
    entries_seen: u64,
    elapsed: Duration,
    interval: Duration,
    now_ms: i64,
    ttl_ms: i64,
) -> Option<i64> {
    if entries_seen == 0 || elapsed >= interval {
        Some(now_ms.saturating_add(ttl_ms))
    } else {
        None
    }
}

/// Native-stream rotation policy (SR-EVENT-01): a stream older than
/// `max_age_ms` must be recreated, bounding any silent native-teardown
/// window to one rotation period. Pure and unit-testable.
pub fn stream_restart_due(opened_ms: u64, now_ms: u64, max_age_ms: u64) -> bool {
    now_ms.saturating_sub(opened_ms) > max_age_ms
}

/// Native-stream stall suspicion (SR-EVENT-01): the global event clock
/// advanced (some volume saw activity) while this stream delivered no
/// callback for longer than `idle_grace_ms`. An idle filesystem (clock
/// static) is never suspicion. Pure and unit-testable.
pub fn stream_stall_suspected(
    last_callback_ms: u64,
    now_ms: u64,
    last_global: u64,
    live_global: u64,
    idle_grace_ms: u64,
) -> bool {
    live_global > last_global && now_ms.saturating_sub(last_callback_ms) > idle_grace_ms
}
