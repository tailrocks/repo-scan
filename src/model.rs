//! Shared domain types (spec §§3, 5, 11–12, 16). No IO here.

use serde::{Deserialize, Serialize};

/// Opaque scan-request identifier (spec §3: a scan ID identifies a request).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScanId(pub String);

impl ScanId {
    /// Create a scan ID; empty strings are rejected.
    pub fn new(id: impl Into<String>) -> Option<Self> {
        let id = id.into();
        if id.is_empty() {
            None
        } else {
            Some(Self(id))
        }
    }
}

impl std::fmt::Display for ScanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Machine-catalog traversal generation (spec §3: generations belong to the
/// catalog and can serve multiple target URLs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GenerationId(pub u64);

/// Catalog epoch: fencing token for owner coordination (spec §§4, 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Epoch(pub u64);

/// Durable task lifecycle state (spec §12). Serde names are the exact
/// persisted/report strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    /// Ready to be claimed.
    Pending,
    /// Claimed by a helper under a lease.
    Leased,
    /// Finished with end-of-enumeration and revision validation.
    Complete,
    /// Waiting for backoff before becoming eligible again.
    RetryWait,
    /// Scope currently unavailable (offline volume, access loss).
    Unavailable,
    /// Backend cannot represent this work (e.g. unsupported Git format).
    Unsupported,
    /// Cancelled by shutdown or explicit request; work preserved.
    Cancelled,
    /// Replaced by a newer generation's equivalent task.
    Superseded,
}

impl TaskState {
    /// True for terminal states that need no further scheduler action.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskState::Complete
                | TaskState::Unsupported
                | TaskState::Cancelled
                | TaskState::Superseded
        )
    }
}

/// Discovery target: raw URL plus optional normalized canonical form
/// (spec §8; normalization in [`crate::identity`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlTarget {
    /// URL exactly as supplied.
    pub raw: String,
    /// Host-aware normalized form, if the URL shape is supported.
    pub canonical: Option<String>,
}

/// Working-state inspection depth (spec §§3, 9).
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum StatusMode {
    /// Identity/HEAD/refs only; no status counts.
    Metadata,
    /// Untracked directories collapsed to one entry each.
    #[default]
    Summary,
    /// Individual untracked files enumerated.
    Full,
}

/// Scan scope (spec §§3, 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Inventory all mounted, addressable filesystem roots.
    Machine,
    /// Only explicitly supplied roots.
    Roots,
}

/// Process exit codes (spec §3, normative).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ExitCode {
    /// Requested operation succeeded (zero matches is still success).
    Success = 0,
    /// Operational failure prevented the operation or publication.
    OperationalFailure = 1,
    /// Invalid arguments or configuration.
    InvalidArgs = 2,
    /// Usable report with unresolved gaps, no suitable catalog for a cached
    /// query, or an explicitly superseded resume.
    Incomplete = 3,
    /// Interrupted by the user after bounded progress save.
    Interrupted = 130,
}

impl ExitCode {
    /// Numeric process exit status.
    #[must_use]
    pub fn code(self) -> i32 {
        self as i32
    }
}
