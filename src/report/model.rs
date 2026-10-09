//! Normative report records (spec §16).
//!
//! Every field is always serialized; unknown values use an explicitly allowed
//! `null` or state, never omission. There are no `skip_serializing_*`
//! attributes anywhere in this module. Enum domains stay as `String` so a
//! corrupt or newer value fails loudly in [`crate::report::validate`] with
//! its location instead of failing deserialization without context.

use serde::{Deserialize, Serialize};

/// Report schema version. Must equal `schemas/report-v1.schema.json`.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Tool name recorded in every envelope.
pub const TOOL_NAME: &str = "repo-scan";

/// Deserialize an explicit JSON null while still requiring the field to be
/// present. Every nullable field in the v1 report schema is required.
fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Full normative report envelope (spec §16 table, first row).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// Must be `1.0.0`.
    pub schema_version: String,
    /// Immutable snapshot/report ID.
    pub report_id: String,
    /// RFC 3339 UTC creation time.
    pub created_at: String,
    pub tool: Tool,
    pub scan: Scan,
    pub coverage: Coverage,
    pub resources: Resources,
    pub volumes: Vec<Volume>,
    pub paths: Vec<PathRecord>,
    pub roots: Vec<Root>,
    pub repositories: Vec<Repository>,
    pub checkouts: Vec<Checkout>,
    pub branches: Vec<Branch>,
    pub remotes: Vec<Remote>,
    pub storage_links: Vec<StorageLink>,
    pub aliases: Vec<Alias>,
    pub candidates: Vec<Candidate>,
    pub errors: Vec<ErrorRecord>,
    pub generated_artifacts: Vec<GeneratedArtifact>,
}

/// Tool record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    /// Must be `repo-scan`.
    pub name: String,
    /// Crate version.
    pub version: String,
    /// Build source commit, when known.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub source_commit: Option<String>,
}

/// Scan record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scan {
    /// Scan-request ID (external catalog history; exempt from ID resolution).
    pub id: String,
    pub generation: u64,
    pub epoch: u64,
    pub catalog_revision: u64,
    /// Target URL as supplied, with embedded credentials redacted (never a
    /// password or token; see `identity::redact_credentials`).
    pub target_url: String,
    /// Normalized canonical form, when the shape is supported.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub canonical_url: Option<String>,
    /// Matching-policy version.
    pub matching_policy: String,
    /// `machine` or `roots`.
    pub scope: String,
    /// `running`, `complete`, `incomplete`, `interrupted`, `failed`, `superseded`.
    pub state: String,
    pub started_at: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub finished_at: Option<String>,
    /// Successor scan ID (external history; exempt from ID resolution).
    #[serde(deserialize_with = "deserialize_required_option")]
    pub superseded_by: Option<String>,
    pub cached: bool,
    /// `metadata`, `summary`, or `full`.
    pub status_mode: String,
}

/// Coverage record. Filesystem, identity, and status are independent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    /// `complete`, `incomplete`, or `unknown`.
    pub filesystem: String,
    /// `complete_under_policy` or `unproven`.
    pub identity: String,
    /// `complete`, `incomplete`, or `not_requested`.
    pub status: String,
    /// Traversal counter (summarizes work, not emitted records).
    pub directories_complete: u64,
    /// Traversal counter (summarizes work, not emitted records).
    pub tasks_pending: u64,
    /// Must equal the number of `errors` records.
    pub gaps: u64,
    /// Must equal the number of `candidates` with
    /// `unresolvable_identity` disposition.
    pub unresolvable_candidates: u64,
    pub scope_boundaries: Vec<String>,
}

/// Resources record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub profile: String,
    /// Must be greater than 0.
    pub cpu_target_cores: f64,
    pub rss_target_bytes: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub peak_rss_bytes: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub cpu_seconds: Option<f64>,
    pub enumerated_entries: u64,
    pub db_transactions: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub db_sync_calls: Option<u64>,
}

/// Volume record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volume {
    pub id: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub native_identity: Option<String>,
    pub namespace: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub filesystem: Option<String>,
    /// `local`, `network`, `virtual`, or `unknown`.
    pub kind: String,
    /// `available`, `inaccessible`, `unavailable`, or `unknown`.
    pub state: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub observed_at: Option<String>,
    pub error_ids: Vec<String>,
}

/// Lossless path record. `value` holds the exact Unicode string when the
/// raw bytes are valid UTF-8, otherwise the standard Base64 encoding of the
/// original bytes. `display` is escaped presentation text only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRecord {
    pub id: String,
    pub display: String,
    /// `utf8` or `base64`.
    pub encoding: String,
    pub value: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub volume_id: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub object_id: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub incarnation: Option<String>,
}

/// Lossless short-name record, used uniformly for branch names, HEAD
/// references, symbolic targets, upstream references, and remote names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncodedName {
    pub display: String,
    /// `utf8` or `base64`.
    pub encoding: String,
    pub value: String,
}

/// Scan-root record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub id: String,
    pub path_id: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub volume_id: Option<String>,
    /// `complete`, `pending`, `inaccessible`, `unavailable`, or `error`.
    pub state: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub observed_at: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub event_history_uuid: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub ingested_cursor: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub reconciled_cursor: Option<String>,
    pub error_ids: Vec<String>,
}

/// Repository (common-storage instance) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub id: String,
    pub git_path_id: String,
    pub common_path_id: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub bare: Option<bool>,
    pub format: String,
    pub object_format: String,
    /// `confirmed`, `related`, `probable`, `nonmatch`, `unresolvable_identity`.
    #[serde(rename = "match")]
    pub match_disposition: String,
    pub evidence: Vec<String>,
    pub observed_at: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub tool_managed: Option<String>,
    pub error_ids: Vec<String>,
}

/// Checkout (working tree) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkout {
    pub id: String,
    pub repository_id: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub root_path_id: Option<String>,
    pub git_path_id: String,
    /// `main`, `linked`, `submodule`, or `unknown`.
    pub kind: String,
    /// `present`, `missing`, `inaccessible`, `broken`, or `unknown`.
    pub availability: String,
    pub head: Head,
    pub status: Status,
    pub observed_at: String,
    pub error_ids: Vec<String>,
}

/// HEAD observation. Kind and HEAD state are independent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    /// `branch`, `detached`, `unborn`, `invalid`, or `unknown`.
    pub state: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub ref_name: Option<EncodedName>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub oid: Option<ObjectId>,
}

/// Object ID with explicit algorithm (never assume 40 hex chars).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectId {
    pub algorithm: String,
    /// Nonempty even-length lowercase hex; known algorithms enforce length.
    pub hex: String,
}

/// Branch / reference observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Branch {
    pub id: String,
    pub repository_id: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub checkout_scope_id: Option<String>,
    /// `local`, `remote_tracking`, or `other`.
    pub kind: String,
    pub name: EncodedName,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub oid: Option<ObjectId>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub symbolic_target: Option<EncodedName>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub upstream: Option<EncodedName>,
    /// `valid`, `unborn`, `invalid`, or `unsupported`.
    pub state: String,
    pub observed_at: String,
    pub error_ids: Vec<String>,
}

/// Working-state observation. Cross-field rules: `metadata` mode has null
/// counts and `untracked_units: not_requested`; `summary` uses
/// `collapsed_entries`; `full` uses `files`. Unknown counts stay null even
/// when their requested units are known. Never report zero or clean for an
/// unknown, pending, unsupported, or failed field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// `complete`, `partial`, `pending`, `not_requested`, `unsupported`,
    /// `unstable`, or `error`.
    pub state: String,
    /// `metadata`, `summary`, or `full`.
    pub mode: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub started_at: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub finished_at: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub staged: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub unstaged: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub untracked: Option<u64>,
    /// `collapsed_entries`, `files`, or `not_requested`.
    pub untracked_units: String,
    /// `checked`, `not_requested`, or `unknown`.
    pub submodules: String,
    pub unknown_fields: Vec<String>,
    pub error_ids: Vec<String>,
}

/// Effective remote observation with role preserved. Credentials redacted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remote {
    pub id: String,
    pub repository_id: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub checkout_scope_id: Option<String>,
    pub name: EncodedName,
    /// `fetch` or `push`.
    pub role: String,
    pub url: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub canonical_url: Option<String>,
    pub observed_at: String,
}

/// Shared-storage relationship edge. A dependency edge, not a merged clone.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageLink {
    pub id: String,
    pub from_repository_id: String,
    pub to_path_id: String,
    /// `common_directory`, `alternate_objects`, `shared_object_store`,
    /// or `observed_hardlink`.
    pub kind: String,
    pub evidence: Vec<String>,
}

/// Pathname alias (symlink, firmlink, mount alias, verified same object).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alias {
    pub path_id: String,
    pub target_path_id: String,
    /// `symlink`, `firmlink`, `mount_alias`, or `same_object`.
    pub kind: String,
    pub verified_at: String,
}

/// Unresolved Git candidate that prevents strict exhaustiveness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    pub path_id: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub repository_id: Option<String>,
    /// `probe_pending`, `probe_failed`, `unsupported`, `unresolvable_identity`.
    pub disposition: String,
    pub reason: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub retry_after: Option<String>,
    pub error_ids: Vec<String>,
}

/// Error / coverage-gap record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorRecord {
    pub id: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub path_id: Option<String>,
    pub operation: String,
    pub category: String,
    pub message: String,
    pub retryable: bool,
    pub attempts: u64,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub next_retry: Option<String>,
}

/// Tool-generated artifact. A report published inside scanned scope is
/// listed here with `created_after_status: true`; requested working state
/// is observed before publication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedArtifact {
    pub path_id: String,
    /// `report` or `tool_state`.
    pub kind: String,
    pub created_after_status: bool,
}

impl Scan {
    /// Return this record with credential-bearing URL fields redacted
    /// (RETEST-5 public-API boundary): `target_url` and `canonical_url`
    /// pass through [`crate::identity::redact_remote_url`], exactly as the
    /// report builder does at emission. Direct model callers that bypass
    /// the builder must apply this before serializing or displaying a
    /// `Scan`, so the no-credential-bytes invariant holds however the
    /// record was constructed. Idempotent: already-redacted values pass
    /// through unchanged.
    #[must_use]
    pub fn sanitized(mut self) -> Self {
        self.target_url = crate::identity::redact_remote_url(&self.target_url);
        self.canonical_url = self
            .canonical_url
            .map(|url| crate::identity::redact_remote_url(&url));
        self
    }
}

impl Remote {
    /// Return this record with credential-bearing URL fields redacted
    /// (RETEST-5 public-API boundary): `url` and `canonical_url` pass
    /// through [`crate::identity::redact_remote_url`], exactly as the
    /// report builder does at emission. Direct model callers that bypass
    /// the builder must apply this before serializing or displaying a
    /// `Remote`. Idempotent: already-redacted values pass through unchanged.
    #[must_use]
    pub fn sanitized(mut self) -> Self {
        self.url = crate::identity::redact_remote_url(&self.url);
        self.canonical_url = self
            .canonical_url
            .map(|url| crate::identity::redact_remote_url(&url));
        self
    }
}
