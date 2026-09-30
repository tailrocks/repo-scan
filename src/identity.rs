//! Repository identity and URL matching (spec §8).
//!
//! Supported shapes: GitHub HTTPS, SSH, and scp-like syntax, with
//! host-aware rules and optional `.git` suffix handling. Effective fetch and
//! push remotes are inspected with roles preserved; safely interpretable
//! rewrites/includes/SSH aliases are accounted for without executing
//! configured helpers. Credentials are never published.

use serde::{Deserialize, Serialize};

/// How a discovered repository relates to the requested target URL.
/// Serde names are the exact report strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchDisposition {
    /// Effective remote evidence proves this is the requested repository.
    Confirmed,
    /// Shares provenance (fork/rename evidence) but is not an exact match.
    Related,
    /// Likely match; evidence is suggestive but incomplete.
    Probable,
    /// Proven not to match the target.
    Nonmatch,
    /// No further permitted probe can resolve the ambiguity (terminal
    /// incomplete, not a retry loop; GIT-04).
    UnresolvableIdentity,
}

/// Normalize a GitHub remote URL to canonical `https://github.com/owner/repo`
/// form. Returns `None` for unsupported shapes (caller records
/// `unresolvable_identity` with the reason).
///
/// TODO(phase-3): host-aware rules, scp-like + `ssh://` + `https://` parsing
/// via `gix-url`, `.git` suffix handling, `insteadOf` rewrites, SSH-alias
/// policy, credential redaction proof.
pub fn normalize_github_url(url: &str) -> Option<String> {
    let _ = url;
    todo!("normalize_github_url: host-aware GitHub normalization")
}

/// Compare a canonical target against one effective remote observation.
/// Returns the disposition plus human-readable evidence lines.
pub fn classify_remote(
    _canonical_target: &str,
    _remote_url: &str,
    _role: &str,
) -> (MatchDisposition, Vec<String>) {
    todo!("classify_remote: identity policy + evidence lines")
}
