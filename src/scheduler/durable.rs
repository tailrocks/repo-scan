//! The one durable scheduler (spec §§4, 12) plus retry/backoff and
//! per-scope circuit breaking (spec §14).
//!
//! Invariants enforced here:
//! - The owner durably claims bounded work, sends it to a helper, and
//!   accepts only results matching the current epoch and lease.
//! - Discovered children and candidate records persist BEFORE the parent
//!   enumeration is marked complete (same completion path, children first).
//! - Completion requires end-of-enumeration AND revision validation: an
//!   invalidation arriving mid-enumeration bumps the scope revision, and a
//!   stale completion requeues the parent instead of erasing the
//!   invalidation.
//! - Duplicate batches after restart are safe through idempotent upserts on
//!   task idempotency keys.
//! - Expired leases return to pending; acknowledgment happens only after the
//!   commit succeeds.
//!
//! Persistence sits behind [`SchedulerStore`] so the Turso-backed store
//! (owned by the storage module) can replace [`MemorySchedulerStore`], the
//! fixture used by scheduler unit tests and Linux acceptance fixtures.

use super::{DiscoveredCandidate, DiscoveredChild, Lease, Scheduler, Task, TaskKind, TaskOutcome};
use crate::model::{Epoch, GenerationId, TaskState};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

/// Narrow persistence contract the durable scheduler needs. The production
/// implementation batches these through the owner's writer actor (spec §10);
/// every method here is one logical scheduling transition.
pub trait SchedulerStore: Send {
    /// Return expired leases to `pending` (runs before every claim).
    fn expire_leases(&mut self, now: SystemTime);

    /// Claim up to `limit` eligible tasks: `pending`, plus `retry_wait` /
    /// `unavailable` whose `not_before` has passed, skipping scopes the
    /// circuit breaker currently forbids. Grants leases of `lease_ttl`.
    fn claim_eligible(
        &mut self,
        epoch: Epoch,
        limit: usize,
        lease_ttl: Duration,
        now: SystemTime,
        skip_scope: &dyn Fn(&str) -> bool,
    ) -> crate::Result<Vec<(Task, Lease)>>;

    /// Return one leased task to `pending` (prefetch trimming).
    fn release_to_pending(&mut self, task_id: &str) -> crate::Result<()>;

    /// Load the task for a lease, rejecting unknown tasks, wrong epochs,
    /// and wrong lease tokens.
    fn verify_lease(&self, lease: &Lease) -> crate::Result<Task>;

    /// Current invalidation revision of a scope (0 when never touched).
    fn current_revision(&self, scope_key: &str) -> crate::Result<u64>;

    /// Idempotent upsert of discovered children by idempotency key.
    /// Each child is created `pending` with `expected_revision` set to the
    /// scope's current revision at insert time.
    fn upsert_children(&mut self, children: &[DiscoveredChild]) -> crate::Result<()>;

    /// Idempotent upsert of Git candidates by path key.
    fn upsert_candidates(&mut self, candidates: &[DiscoveredCandidate]) -> crate::Result<()>;

    /// Mark one leased task `complete`.
    fn mark_complete(&mut self, task_id: &str) -> crate::Result<()>;

    /// A stale completion arrived after a newer invalidation: keep the
    /// persisted children, reset the parent to `pending` at the new
    /// revision. The invalidation is never erased.
    fn requeue_stale(&mut self, task_id: &str, new_revision: u64) -> crate::Result<()>;

    /// Park a task in `retry_wait` with a preserved gap record.
    fn defer_retry(
        &mut self,
        task_id: &str,
        not_before: SystemTime,
        category: &str,
        detail: &str,
    ) -> crate::Result<()>;

    /// Park a task in `unavailable` or `unsupported` with a reason.
    fn park(&mut self, task_id: &str, state: TaskState, reason: &str) -> crate::Result<()>;

    /// Bump a scope's invalidation revision and ensure a pending
    /// reconciliation task exists for every generation already holding work
    /// on that scope. Returns the new revision.
    fn invalidate_scope(&mut self, scope_key: &str) -> crate::Result<u64>;

    /// Tasks not in a terminal state for one generation.
    fn pending_count(&self, generation: GenerationId) -> crate::Result<u64>;
}

/// How one completion was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionDisposition {
    /// Children persisted, revision current, parent marked complete.
    Applied,
    /// Children persisted, but a newer invalidation existed: the parent was
    /// requeued at the new revision instead of completing.
    StaleRequeued,
    /// Partial progress preserved; task deferred with backoff.
    Deferred,
    /// Task parked in `unavailable` / `unsupported`.
    Parked,
}

/// Per-scope circuit breaker (spec §14): consecutive failures open the
/// breaker for a cooldown; one success closes it. Pending work is
/// preserved — the breaker only delays eligibility.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    consecutive_failures: u32,
    /// Consecutive failures that open the breaker.
    pub threshold: u32,
    /// How long an open breaker forbids the scope.
    pub cooldown: Duration,
    opened_until: Option<SystemTime>,
}

impl CircuitBreaker {
    /// Breaker opening after `threshold` consecutive failures.
    pub fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            consecutive_failures: 0,
            threshold: threshold.max(1),
            cooldown,
            opened_until: None,
        }
    }

    /// True when the scope may be claimed now.
    pub fn allow(&self, now: SystemTime) -> bool {
        match self.opened_until {
            Some(until) => now >= until,
            None => true,
        }
    }

    /// Record a success: closes the breaker.
    pub fn on_success(&mut self) {
        self.consecutive_failures = 0;
        self.opened_until = None;
    }

    /// Record a failure: opens the breaker at the threshold.
    pub fn on_failure(&mut self, now: SystemTime) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= self.threshold {
            self.opened_until = now.checked_add(self.cooldown);
        }
    }
}

/// Retry backoff for attempt `n` (0-based): exponential 1s/2s/4s… capped at
/// 5 minutes, plus small deterministic jitter so independent scopes do not
/// synchronize. Deterministic (no RNG dependency) for fixture stability.
pub fn backoff_for_attempt(attempt: u32) -> Duration {
    const CAP: Duration = Duration::from_secs(300);
    let shift = attempt.min(8);
    let base = Duration::from_secs(1 << shift).min(CAP);
    let jitter_ms = (u64::from(attempt).wrapping_mul(2_654_435_761) % 1000).min(1000);
    base.saturating_add(Duration::from_millis(jitter_ms))
        .min(CAP)
}

/// Estimated prefetch bytes for one claimed task (spec §5: 1,024 tasks or
/// 4 MiB, first limit wins; remaining work stays in the database).
fn task_prefetch_bytes(task: &Task) -> usize {
    const PER_TASK_OVERHEAD: usize = 256;
    task.id.len() + task.scope_key.len() + task.idempotency_key.len() + PER_TASK_OVERHEAD
}

/// The one durable scheduler, generic over its [`SchedulerStore`].
pub struct DurableScheduler<S: SchedulerStore> {
    store: S,
    circuits: HashMap<String, CircuitBreaker>,
    attempts: HashMap<String, u32>,
    circuit_threshold: u32,
    circuit_cooldown: Duration,
    prefetch_tasks: usize,
    prefetch_bytes: usize,
}

impl<S: SchedulerStore> DurableScheduler<S> {
    /// Scheduler over this store with spec §5 prefetch bounds (1,024 tasks
    /// or 4 MiB) and a 5-failure / 60 s circuit breaker.
    pub fn new(store: S) -> Self {
        Self {
            store,
            circuits: HashMap::new(),
            attempts: HashMap::new(),
            circuit_threshold: 5,
            circuit_cooldown: Duration::from_secs(60),
            prefetch_tasks: 1024,
            prefetch_bytes: 4 * 1024 * 1024,
        }
    }

    /// Override the prefetch bounds (tests, alternative profiles).
    pub fn with_prefetch(mut self, tasks: usize, bytes: usize) -> Self {
        self.prefetch_tasks = tasks;
        self.prefetch_bytes = bytes;
        self
    }

    /// Access the backing store (fixtures, inspection).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Mutable access to the backing store.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    fn circuit_mut(&mut self, scope_key: &str) -> &mut CircuitBreaker {
        let threshold = self.circuit_threshold;
        let cooldown = self.circuit_cooldown;
        self.circuits
            .entry(scope_key.to_string())
            .or_insert_with(|| CircuitBreaker::new(threshold, cooldown))
    }

    /// Accept one completion with full disposition reporting. [`Scheduler::complete`]
    /// delegates here and reports only failures.
    pub fn complete_detailed(
        &mut self,
        lease: &Lease,
        outcome: TaskOutcome,
    ) -> crate::Result<CompletionDisposition> {
        let now = SystemTime::now();
        // Epoch + lease-token check first: results from old epochs or
        // superseded leases are rejected before touching revisions.
        let task = self.store.verify_lease(lease)?;
        let scope = task.scope_key.clone();
        let current = self.store.current_revision(&scope)?;

        match outcome {
            TaskOutcome::Complete {
                children,
                candidates,
            } => {
                // Children and candidates persist BEFORE any parent state
                // change, so a crash here leaves discoveries without a
                // false completion.
                if !candidates.is_empty() {
                    self.store.upsert_candidates(&candidates)?;
                }
                if !children.is_empty() {
                    self.store.upsert_children(&children)?;
                }
                if current > task.expected_revision {
                    // Invalidation arrived mid-execution: keep the children,
                    // requeue the parent at the new revision.
                    self.store.requeue_stale(&task.id, current)?;
                    return Ok(CompletionDisposition::StaleRequeued);
                }
                self.store.mark_complete(&task.id)?;
                self.circuit_mut(&scope).on_success();
                self.attempts.remove(&task.id);
                Ok(CompletionDisposition::Applied)
            }
            TaskOutcome::Partial {
                category,
                detail,
                retry_after,
            } => {
                let attempt = self.attempts.get(&task.id).copied().unwrap_or(0);
                let backoff = backoff_for_attempt(attempt).max(retry_after);
                let not_before = now.checked_add(backoff).unwrap_or(now);
                self.store
                    .defer_retry(&task.id, not_before, &category, &detail)?;
                self.attempts
                    .insert(task.id.clone(), attempt.saturating_add(1));
                self.circuit_mut(&scope).on_failure(now);
                Ok(CompletionDisposition::Deferred)
            }
            TaskOutcome::Parked { state, reason } => {
                debug_assert!(
                    matches!(state, TaskState::Unavailable | TaskState::Unsupported),
                    "park target must be unavailable or unsupported"
                );
                let state = match state {
                    TaskState::Unavailable | TaskState::Unsupported => state,
                    _ => TaskState::Unavailable,
                };
                self.store.park(&task.id, state, &reason)?;
                // Parking is an honest terminal-ish state, not a failure:
                // the breaker stays as-is so independent work on the scope
                // can still proceed after new evidence.
                Ok(CompletionDisposition::Parked)
            }
        }
    }
}

impl<S: SchedulerStore> Scheduler for DurableScheduler<S> {
    fn claim(
        &mut self,
        epoch: Epoch,
        limit: usize,
        lease_ttl: Duration,
    ) -> crate::Result<Vec<(Task, Lease)>> {
        let now = SystemTime::now();
        // Expired leases return to pending before any new claim.
        self.store.expire_leases(now);
        let limit = limit.min(self.prefetch_tasks);
        // Snapshot currently forbidden scopes so the claim filter does not
        // borrow the scheduler while the store is mutably borrowed.
        let blocked: Vec<String> = self
            .circuits
            .iter()
            .filter(|(_, breaker)| !breaker.allow(now))
            .map(|(scope, _)| scope.clone())
            .collect();
        let mut claimed = self
            .store
            .claim_eligible(epoch, limit, lease_ttl, now, &|scope| {
                blocked.iter().any(|b| b == scope)
            })?;
        // Prefetch byte bound: stop at the first limit; trimmed tasks go
        // straight back to pending so remaining work stays in the database.
        let mut bytes = 0usize;
        let mut kept = 0usize;
        for task in &claimed {
            let size = task_prefetch_bytes(&task.0);
            if kept > 0 && bytes + size > self.prefetch_bytes {
                break;
            }
            bytes += size;
            kept += 1;
        }
        while claimed.len() > kept {
            if let Some((task, _)) = claimed.pop() {
                self.store.release_to_pending(&task.id)?;
            }
        }
        Ok(claimed)
    }

    fn complete(&mut self, lease: &Lease, outcome: TaskOutcome) -> crate::Result<()> {
        self.complete_detailed(lease, outcome)?;
        Ok(())
    }

    fn invalidate(&mut self, scope_key: &str) -> crate::Result<()> {
        self.store.invalidate_scope(scope_key)?;
        Ok(())
    }

    fn pending_count(&self, generation: GenerationId) -> crate::Result<u64> {
        self.store.pending_count(generation)
    }
}

/// One preserved gap record (ERROR-01 evidence surface for fixtures).
#[derive(Debug, Clone)]
pub struct GapRecord {
    /// Task that produced the gap.
    pub task_id: String,
    /// Stable error category.
    pub category: String,
    /// Human-readable detail.
    pub detail: String,
    /// When the task becomes eligible again.
    pub not_before: SystemTime,
}

#[derive(Debug, Clone)]
struct TaskRecord {
    task: Task,
    lease_token: Option<u64>,
    lease_expires: Option<SystemTime>,
}

/// In-memory [`SchedulerStore`] for scheduler unit tests and Linux
/// acceptance fixtures. Same transition semantics as the durable store;
/// no crash durability (restart tests use the Turso-backed store).
#[derive(Debug, Default)]
pub struct MemorySchedulerStore {
    tasks: HashMap<String, TaskRecord>,
    revisions: HashMap<String, u64>,
    candidates: HashMap<String, DiscoveredCandidate>,
    gaps: Vec<GapRecord>,
    next_token: u64,
}

impl MemorySchedulerStore {
    /// Empty fixture store.
    pub fn new() -> Self {
        Self {
            next_token: 1,
            ..Self::default()
        }
    }

    /// Insert one task directly (fixture setup).
    pub fn insert_task(&mut self, task: Task) {
        self.tasks.insert(
            task.id.clone(),
            TaskRecord {
                task,
                lease_token: None,
                lease_expires: None,
            },
        );
    }

    /// Preserved gap records (fixture assertions).
    pub fn gaps(&self) -> &[GapRecord] {
        &self.gaps
    }

    /// All tasks (fixture assertions).
    pub fn all_tasks(&self) -> Vec<Task> {
        let mut tasks: Vec<Task> = self.tasks.values().map(|r| r.task.clone()).collect();
        tasks.sort_by(|a, b| a.id.cmp(&b.id));
        tasks
    }

    /// Candidates recorded so far.
    pub fn all_candidates(&self) -> Vec<DiscoveredCandidate> {
        let mut out: Vec<DiscoveredCandidate> = self.candidates.values().cloned().collect();
        out.sort_by(|a, b| a.path_key.cmp(&b.path_key));
        out
    }

    fn next_token(&mut self) -> u64 {
        let token = self.next_token.max(1);
        self.next_token = token.wrapping_add(1).max(1);
        token
    }
}

impl SchedulerStore for MemorySchedulerStore {
    fn expire_leases(&mut self, now: SystemTime) {
        for record in self.tasks.values_mut() {
            if record.task.state == TaskState::Leased {
                let expired = record.lease_expires.map(|t| now >= t).unwrap_or(true);
                if expired {
                    record.task.state = TaskState::Pending;
                    record.lease_token = None;
                    record.lease_expires = None;
                }
            }
        }
    }

    fn claim_eligible(
        &mut self,
        epoch: Epoch,
        limit: usize,
        lease_ttl: Duration,
        now: SystemTime,
        skip_scope: &dyn Fn(&str) -> bool,
    ) -> crate::Result<Vec<(Task, Lease)>> {
        // Deterministic order: reconciliation first (invalidations unblock
        // dependent scope), then generation, then scope key.
        let mut ids: Vec<String> = self
            .tasks
            .iter()
            .filter(|(_, r)| {
                // Pending tasks are epoch-free: the claiming epoch is
                // assigned below and fenced at completion time.
                !skip_scope(&r.task.scope_key)
                    && match r.task.state {
                        TaskState::Pending => true,
                        TaskState::RetryWait | TaskState::Unavailable => {
                            r.task.not_before.map(|t| now >= t).unwrap_or(true)
                        }
                        _ => false,
                    }
            })
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort_by(|a, b| {
            let ra = &self.tasks[a].task;
            let rb = &self.tasks[b].task;
            reconcile_first(ra.kind)
                .cmp(&reconcile_first(rb.kind))
                .then(ra.generation.cmp(&rb.generation))
                .then(ra.scope_key.cmp(&rb.scope_key))
                .then(ra.id.cmp(&rb.id))
        });
        ids.truncate(limit);

        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let token = self.next_token();
            let expires_at = now.checked_add(lease_ttl).unwrap_or(now);
            let record = self.tasks.get_mut(&id).expect("filtered id exists");
            record.task.state = TaskState::Leased;
            record.task.epoch = epoch;
            record.lease_token = Some(token);
            record.lease_expires = Some(expires_at);
            out.push((
                record.task.clone(),
                Lease {
                    task_id: id,
                    epoch,
                    token,
                    expires_at,
                },
            ));
        }
        Ok(out)
    }

    fn release_to_pending(&mut self, task_id: &str) -> crate::Result<()> {
        match self.tasks.get_mut(task_id) {
            Some(record) if record.task.state == TaskState::Leased => {
                record.task.state = TaskState::Pending;
                record.lease_token = None;
                record.lease_expires = None;
                Ok(())
            }
            _ => Err(crate::Error::Scheduler(format!(
                "release of non-leased task {task_id}"
            ))),
        }
    }

    fn verify_lease(&self, lease: &Lease) -> crate::Result<Task> {
        let record = self.tasks.get(&lease.task_id).ok_or_else(|| {
            crate::Error::Scheduler(format!("completion for unknown task {}", lease.task_id))
        })?;
        if record.task.epoch != lease.epoch {
            return Err(crate::Error::Scheduler(format!(
                "completion epoch {:?} does not match task epoch {:?}",
                lease.epoch, record.task.epoch
            )));
        }
        if record.task.state != TaskState::Leased || record.lease_token != Some(lease.token) {
            return Err(crate::Error::Scheduler(format!(
                "stale or superseded lease for task {}",
                lease.task_id
            )));
        }
        Ok(record.task.clone())
    }

    fn current_revision(&self, scope_key: &str) -> crate::Result<u64> {
        Ok(self.revisions.get(scope_key).copied().unwrap_or(0))
    }

    fn upsert_children(&mut self, children: &[DiscoveredChild]) -> crate::Result<()> {
        for child in children {
            // Idempotent on the idempotency key: duplicate batches after
            // restart upsert safely and never duplicate work.
            if self.tasks.contains_key(&child.idempotency_key) {
                continue;
            }
            let revision = self.revisions.get(&child.scope_key).copied().unwrap_or(0);
            let task = Task {
                id: child.idempotency_key.clone(),
                // Epoch-free until claimed; claim assigns the live epoch.
                epoch: Epoch(0),
                generation: child.generation,
                kind: child.kind,
                scope_key: child.scope_key.clone(),
                expected_revision: revision,
                idempotency_key: child.idempotency_key.clone(),
                state: TaskState::Pending,
                not_before: None,
            };
            self.tasks.insert(
                task.id.clone(),
                TaskRecord {
                    task,
                    lease_token: None,
                    lease_expires: None,
                },
            );
        }
        Ok(())
    }

    fn upsert_candidates(&mut self, candidates: &[DiscoveredCandidate]) -> crate::Result<()> {
        for candidate in candidates {
            self.candidates
                .entry(candidate.path_key.clone())
                .or_insert_with(|| candidate.clone());
        }
        Ok(())
    }

    fn mark_complete(&mut self, task_id: &str) -> crate::Result<()> {
        let record = self.tasks.get_mut(task_id).ok_or_else(|| {
            crate::Error::Scheduler(format!("complete of unknown task {task_id}"))
        })?;
        record.task.state = TaskState::Complete;
        record.lease_token = None;
        record.lease_expires = None;
        Ok(())
    }

    fn requeue_stale(&mut self, task_id: &str, new_revision: u64) -> crate::Result<()> {
        let record = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| crate::Error::Scheduler(format!("requeue of unknown task {task_id}")))?;
        record.task.state = TaskState::Pending;
        record.task.expected_revision = new_revision;
        record.task.not_before = None;
        record.lease_token = None;
        record.lease_expires = None;
        Ok(())
    }

    fn defer_retry(
        &mut self,
        task_id: &str,
        not_before: SystemTime,
        category: &str,
        detail: &str,
    ) -> crate::Result<()> {
        let record = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| crate::Error::Scheduler(format!("defer of unknown task {task_id}")))?;
        record.task.state = TaskState::RetryWait;
        record.task.not_before = Some(not_before);
        record.lease_token = None;
        record.lease_expires = None;
        self.gaps.push(GapRecord {
            task_id: task_id.to_string(),
            category: category.to_string(),
            detail: detail.to_string(),
            not_before,
        });
        Ok(())
    }

    fn park(&mut self, task_id: &str, state: TaskState, reason: &str) -> crate::Result<()> {
        let record = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| crate::Error::Scheduler(format!("park of unknown task {task_id}")))?;
        record.task.state = state;
        record.task.not_before = None;
        record.lease_token = None;
        record.lease_expires = None;
        self.gaps.push(GapRecord {
            task_id: task_id.to_string(),
            category: String::from("parked"),
            detail: reason.to_string(),
            not_before: SystemTime::now(),
        });
        Ok(())
    }

    fn invalidate_scope(&mut self, scope_key: &str) -> crate::Result<u64> {
        let revision = self.revisions.get(scope_key).copied().unwrap_or(0) + 1;
        self.revisions.insert(scope_key.to_string(), revision);
        // One pending reconciliation task per generation already holding
        // work on this scope; duplicates collapse on the idempotency key.
        let generations: HashSet<GenerationId> = self
            .tasks
            .values()
            .filter(|r| r.task.scope_key == scope_key)
            .map(|r| r.task.generation)
            .collect();
        for generation in generations {
            let key = format!("reconcile:{}:{}", scope_key, generation.0);
            if self.tasks.contains_key(&key) {
                // An existing reconcile task (even complete) must run again:
                // reset it to pending at the new revision unless leased.
                if let Some(record) = self.tasks.get_mut(&key) {
                    if record.task.state != TaskState::Leased {
                        record.task.state = TaskState::Pending;
                        record.task.expected_revision = revision;
                        record.task.not_before = None;
                    }
                }
                continue;
            }
            let task = Task {
                id: key.clone(),
                epoch: Epoch(0),
                generation,
                kind: TaskKind::Reconcile,
                scope_key: scope_key.to_string(),
                expected_revision: revision,
                idempotency_key: key.clone(),
                state: TaskState::Pending,
                not_before: None,
            };
            self.tasks.insert(
                key,
                TaskRecord {
                    task,
                    lease_token: None,
                    lease_expires: None,
                },
            );
        }
        Ok(revision)
    }

    fn pending_count(&self, generation: GenerationId) -> crate::Result<u64> {
        Ok(self
            .tasks
            .values()
            .filter(|r| r.task.generation == generation && !r.task.state.is_terminal())
            .count() as u64)
    }
}

/// Reconciliation tasks sort before all other kinds.
fn reconcile_first(kind: TaskKind) -> u8 {
    match kind {
        TaskKind::Reconcile => 0,
        _ => 1,
    }
}
