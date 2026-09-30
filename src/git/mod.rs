//! Git discovery and inspection (spec §§8–9, docs/GIT_QUAL.md).
//!
//! Backend: `gix = "=0.88.0"`, `default-features = false`, features
//! `status, dirwalk, index, excludes, attributes, sha1, sha256`. No default
//! (parallel) features, no network features. Installed git is an optional
//! compatibility backend for reftable/SSH-alias/index gaps only — never a
//! per-directory scanner, never executing hooks/filters/fetch.

use crate::model::StatusMode;

/// Object ID with explicit algorithm (never assume 40 hex chars).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid {
    /// `sha1` or `sha256`.
    pub algorithm: String,
    /// Lowercase hex, even length, algorithm-correct length.
    pub hex: String,
}

/// How a checkout relates to its repository (spec §8 topology).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutKind {
    /// Main worktree / common checkout.
    Main,
    /// Linked worktree.
    Linked,
    /// Submodule checkout.
    Submodule,
    /// Could not be determined.
    Unknown,
}

/// Availability of a registered worktree (GIT_QUAL §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorktreeAvailability {
    /// Registered and base directory exists.
    Present,
    /// Registered but base is gone.
    Missing,
    /// Registered but base is not accessible.
    Inaccessible,
    /// Registered but admin data is unparseable/unopenable.
    Broken,
    /// Unknown.
    Unknown,
}

/// HEAD state (spec §9): kind and head are reported separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadState {
    /// Symbolic HEAD pointing at a born branch.
    Branch {
        /// Full ref name (raw bytes preserved by the caller).
        ref_name: Vec<u8>,
        /// Peeled OID, if resolvable.
        oid: Option<Oid>,
    },
    /// Detached HEAD at an OID.
    Detached {
        /// Direct target.
        target: Oid,
        /// Peeled OID.
        peeled: Option<Oid>,
    },
    /// Unborn branch (symbolic ref with no commit yet).
    Unborn {
        /// Full ref name.
        ref_name: Vec<u8>,
    },
    /// HEAD exists but is invalid.
    Invalid,
    /// HEAD state could not be determined.
    Unknown,
}

/// One observed reference (packed refs included; symbolic targets preserved).
#[derive(Debug, Clone)]
pub struct RefObservation {
    /// Full ref name (raw bytes; lossy conversion forbidden).
    pub name: Vec<u8>,
    /// Direct or symbolic target.
    pub target: RefTarget,
    /// Peeled OID when computed.
    pub peeled: Option<Oid>,
}

/// Reference target.
#[derive(Debug, Clone)]
pub enum RefTarget {
    /// Points at an object.
    Object(Oid),
    /// Points at another ref (full name, raw bytes).
    Symbolic(Vec<u8>),
}

/// Effective remote with its role preserved (spec §8).
#[derive(Debug, Clone)]
pub struct RemoteObservation {
    /// Remote name (raw bytes).
    pub name: Vec<u8>,
    /// `fetch` or `push` role.
    pub role: RemoteRole,
    /// URL with credentials redacted.
    pub url: String,
    /// Normalized canonical form, if supported.
    pub canonical_url: Option<String>,
}

/// Remote role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteRole {
    /// `remote.*.url`.
    Fetch,
    /// `pushUrl` else fetch fallback.
    Push,
}

/// Validated Git instance opened at its exact discovered path (spec §8).
#[derive(Debug, Clone)]
pub struct GitInstance {
    /// Discovered git directory.
    pub git_dir: std::path::PathBuf,
    /// Shared common directory.
    pub common_dir: std::path::PathBuf,
    /// Working-tree root, if any.
    pub work_dir: Option<std::path::PathBuf>,
    /// Bare flag honoring config (not the name heuristic).
    pub is_bare: bool,
    /// Object format (`sha1`/`sha256`).
    pub object_format: String,
}

/// Working-state observation for one checkout (spec §9).
#[derive(Debug, Clone)]
pub struct StatusObservation {
    /// Mode actually executed.
    pub mode: StatusMode,
    /// Staged (HEAD<->index) count; `None` for metadata mode / unknown.
    pub staged: Option<u64>,
    /// Unstaged (index<->worktree) count.
    pub unstaged: Option<u64>,
    /// Untracked count in the mode's units.
    pub untracked: Option<u64>,
    /// Fields the backend could not determine.
    pub unknown_fields: Vec<String>,
    /// Input fingerprints (head id, index mtime+size) for instability retry.
    pub fingerprints: Vec<String>,
}

/// Git inspection contract. Read-only: no hooks, no filters, no fetch/GC,
/// no index writes (`Outcome::write_changes` is forbidden). Status honors
/// the shared 1-Git-probe admission and the no-progress watchdog in the
/// admitted helper (GIT_QUAL §§7–10).
pub trait GitInspect: Send + Sync {
    /// Validate a candidate at its exact path (no upward discovery).
    /// Handles `.git` dirs, pointer files, external dirs, bare stores
    /// (via `open_path_as_is` semantics).
    fn open_exact(&self, path: &std::path::Path) -> crate::Result<GitInstance>;

    /// Effective fetch/push remotes with roles, rewrites safely applied,
    /// credentials redacted. SSH aliases that need ssh-config resolution
    /// surface as `unresolvable_identity`, never a connection.
    fn remotes(&self, instance: &GitInstance) -> crate::Result<Vec<RemoteObservation>>;

    /// All refs incl. packed; broken refs surface as per-item errors.
    /// Reftable stores route to the installed-git fallback or `unsupported`.
    fn refs(&self, instance: &GitInstance) -> crate::Result<Vec<RefObservation>>;

    /// HEAD state: symbolic/unborn/detached reported separately from kind.
    fn head(&self, instance: &GitInstance) -> crate::Result<HeadState>;

    /// Registered worktrees (linked only; main never listed) with
    /// availability; missing-`gitdir` entries reported as broken.
    fn worktrees(&self, instance: &GitInstance) -> crate::Result<Vec<WorktreeObservation>>;

    /// Working-state probe at `mode` (`metadata` skips status entirely;
    /// `summary` = collapsed untracked; `full` = per-file untracked).
    fn status(&self, instance: &GitInstance, mode: StatusMode) -> crate::Result<StatusObservation>;
}

/// One registered worktree with availability evidence.
#[derive(Debug, Clone)]
pub struct WorktreeObservation {
    /// Worktree id (dir name under `worktrees/`).
    pub id: String,
    /// Checkout path; may not exist.
    pub base: std::path::PathBuf,
    /// Availability classification.
    pub availability: WorktreeAvailability,
    /// Lock reason, if locked.
    pub lock_reason: Option<String>,
}
