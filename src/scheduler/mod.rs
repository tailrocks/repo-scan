//! The one durable scheduler (spec §§4, 12). No backend owns a job
//! universe; the owner claims bounded work, sends it to helpers, and accepts
//! only results matching the current epoch and lease.
//!
//! Submodules: [`admission`] (spec §5 hard limits), [`durable`] (durable
//! claim/complete/revision/circuit-breaker semantics over a
//! [`durable::SchedulerStore`]).

pub mod admission;
pub mod durable;

pub use admission::{Admission, AdmissionSnapshot, OpClass, Permit};
pub use durable::{
    backoff_for_attempt, CircuitBreaker, CompletionDisposition, DurableScheduler, GapRecord,
    MemorySchedulerStore, SchedulerStore,
};

use crate::model::{Epoch, GenerationId, TaskState};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Operation kind carried by a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    /// Enumerate one directory's immediate children.
    EnumerateDir,
    /// Probe one Git candidate at its exact path.
    ProbeGit,
    /// Inspect working state of a relevant checkout.
    Status,
    /// Reconcile an invalidated scope.
    Reconcile,
}

/// A durable unit of work (spec §12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    /// Stable task identity.
    pub id: String,
    /// Fencing epoch; results from old epochs are rejected.
    pub epoch: Epoch,
    /// Traversal generation this task belongs to.
    pub generation: GenerationId,
    /// Operation kind.
    pub kind: TaskKind,
    /// Directory or scope this task covers (opaque key into the store).
    pub scope_key: String,
    /// Expected invalidation revision; stale completions cannot erase newer
    /// invalidations.
    pub expected_revision: u64,
    /// Idempotency key: duplicate batches after restart upsert safely.
    pub idempotency_key: String,
    /// Lifecycle state.
    pub state: TaskState,
    /// Earliest time a `retry_wait`/`unavailable` task is eligible again.
    pub not_before: Option<SystemTime>,
}

/// A bounded claim on a task: helper + expiry.
#[derive(Debug, Clone)]
pub struct Lease {
    /// Leased task ID.
    pub task_id: String,
    /// Epoch the lease was granted under.
    pub epoch: Epoch,
    /// Lease token; completions must present the current token.
    pub token: u64,
    /// When the lease expires and the task returns to pending.
    pub expires_at: SystemTime,
}

/// Scheduler contract. All persistence behind this trait goes through the
/// store's writer actor; see [`crate::store::Store`].
pub trait Scheduler: Send {
    /// Durably claim up to `limit` eligible tasks for `epoch`, granting
    /// leases of `lease_ttl`. Expired leases return to pending first.
    fn claim(
        &mut self,
        epoch: Epoch,
        limit: usize,
        lease_ttl: Duration,
    ) -> crate::Result<Vec<(Task, Lease)>>;

    /// Accept a completion only if epoch + lease token still match and the
    /// invalidation revision is current. Persists children/findings before
    /// marking the parent enumeration complete.
    fn complete(&mut self, lease: &Lease, outcome: TaskOutcome) -> crate::Result<()>;

    /// Record an invalidation: bump the scope revision and schedule
    /// reconciliation. Stale completions cannot erase it.
    fn invalidate(&mut self, scope_key: &str) -> crate::Result<()>;

    /// Number of tasks not in a terminal state (for boundary accounting).
    fn pending_count(&self, generation: GenerationId) -> crate::Result<u64>;
}

/// One directory (or scope) discovered by an enumeration task. Carried in
/// the completion so children persist before the parent completes
/// (spec §12). The store assigns `expected_revision` from the scope's
/// current revision at insert and dedupes on `idempotency_key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredChild {
    /// Scope key of the discovered child (store key, not a raw path).
    pub scope_key: String,
    /// Operation kind the child needs (usually `EnumerateDir`).
    pub kind: TaskKind,
    /// Traversal generation the child belongs to.
    pub generation: GenerationId,
    /// Idempotency key: duplicate batches upsert safely.
    pub idempotency_key: String,
}

/// One Git candidate discovered at its exact path. Carried in the
/// completion so candidates persist before the parent completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredCandidate {
    /// Store key of the candidate path.
    pub path_key: String,
    /// Why this path is a Git candidate.
    pub reason: String,
}

/// Outcome of one leased task execution.
///
/// NOTE (spec-forced change): `Complete` carries the discovered children
/// and candidates so the scheduler persists them before marking the parent
/// enumeration complete (spec §12). The stub's bare `Complete` unit variant
/// could not express that ordering.
#[derive(Debug, Clone)]
pub enum TaskOutcome {
    /// End-of-enumeration reached with revision validation. Children and
    /// candidates persist first; then the parent completes only if its
    /// expected revision is still current, else it requeues (stale).
    Complete {
        /// Discovered child scopes to persist before completing.
        children: Vec<DiscoveredChild>,
        /// Discovered Git candidates to persist before completing.
        candidates: Vec<DiscoveredCandidate>,
    },
    /// Partial progress plus a preserved gap; task returns to pending/retry.
    Partial {
        /// Stable error category for the gap record.
        category: String,
        /// Human-readable detail.
        detail: String,
        /// Retry eligibility delay.
        retry_after: Duration,
    },
    /// Scope unavailable or backend-unsupported; durable terminal-ish state.
    Parked {
        /// Target state: `unavailable` or `unsupported`.
        state: TaskState,
        /// Reason recorded on the gap.
        reason: String,
    },
}
