//! Repository identity and URL matching (spec §8).
//!
//! Supported shapes: GitHub HTTPS, SSH, and scp-like syntax, with
//! host-aware rules and optional `.git` suffix handling. Effective fetch and
//! push remotes are inspected with roles preserved; safely interpretable
//! rewrites/includes/SSH aliases are accounted for without executing
//! configured helpers. Credentials are never published.
//!
//! Matching policy [`MATCHING_POLICY`] dispositions: an effective remote that
//! normalizes to the canonical target is `confirmed`; the same repository
//! name under a different owner is `related` (possible fork, not exact);
//! a GitHub URL whose path extends beyond owner/repo is `probable`; any
//! other decisive mismatch is `nonmatch`; shapes that cannot be interpreted
//! without executing something (helpers, `ext`, unresolvable SSH aliases,
//! local paths, unparseable input) or a repository with no effective remotes
//! at all is `unresolvable_identity` (terminal incomplete, GIT-04).

use gix::bstr::ByteSlice;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Matching-policy version recorded in reports (spec §§8, 16).
pub const MATCHING_POLICY: &str = "github-effective-remotes-v1";

/// Canonical GitHub host matched by the policy (case-insensitive).
pub const GITHUB_HOST: &str = "github.com";

/// Placeholder substituted for embedded credentials.
pub const REDACTED: &str = "<redacted>";

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
/// Accepted: `https://`/`http://` (usernames lowercased, credentials and
/// query/fragment ignored), `ssh://` with default port, and scp-like
/// `[user@]github.com:owner/repo[.git]`. A single trailing `.git` segment
/// suffix and one trailing slash are stripped. SSH aliases resolving to
/// github.com via `~/.ssh/config` are honored read-only (no execution).
/// `git://`, `file:`, local paths, `ext::`, helper transports, non-default
/// ports, and non-GitHub hosts yield `None`.
pub fn normalize_github_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let parsed = gix::url::parse(url).ok()?;
    match parsed.scheme {
        gix::url::Scheme::Https | gix::url::Scheme::Http | gix::url::Scheme::Ssh => {}
        _ => return None,
    }
    let host = parsed.host.as_deref()?;
    if !is_github_host(host) {
        return None;
    }
    if let Some(port) = parsed.port {
        if Some(port) != parsed.scheme.default_port() {
            return None;
        }
    }
    let path = std::str::from_utf8(parsed.path.as_bytes()).ok()?;
    let (owner, repo) = split_owner_repo_path(path, true)?;
    Some(format!(
        "https://{}/{}",
        GITHUB_HOST,
        format!("{owner}/{repo}").to_lowercase()
    ))
}

/// Compare a canonical target against one effective remote observation.
/// Returns the disposition plus human-readable evidence lines.
///
/// `canonical_target` is the `https://github.com/owner/repo` form (see
/// [`normalize_github_url`]); `remote_url` is the raw effective URL;
/// `role` is `fetch` or `push` and is repeated in the evidence.
pub fn classify_remote(
    canonical_target: &str,
    remote_url: &str,
    role: &str,
) -> (MatchDisposition, Vec<String>) {
    let redacted = redact_credentials(remote_url.trim());
    if remote_url.trim().is_empty() {
        return (
            MatchDisposition::UnresolvableIdentity,
            vec![format!(
                "Effective {role} remote URL is empty; identity cannot be determined."
            )],
        );
    }
    if let Some(normalized) = normalize_github_url(remote_url) {
        if normalized == canonical_target {
            return (
                MatchDisposition::Confirmed,
                vec![format!(
                    "Effective {role} remote `{redacted}` matches the target ({normalized})."
                )],
            );
        }
        let here = split_canonical(&normalized);
        let want = split_canonical(canonical_target);
        match (here, want) {
            (Some((h_owner, h_repo)), Some((w_owner, w_repo)))
                if h_repo == w_repo && h_owner != w_owner =>
            {
                return (
                    MatchDisposition::Related,
                    vec![format!(
                        "Effective {role} remote `{redacted}` is repository `{h_repo}` under a different owner (`{h_owner}` vs `{w_owner}`); possible fork, not an exact match."
                    )],
                );
            }
            _ => {
                return (
                    MatchDisposition::Nonmatch,
                    vec![format!(
                        "Effective {role} remote `{redacted}` points at {normalized}, not the target."
                    )],
                );
            }
        }
    }
    lenient_noncanonical_verdict(canonical_target, remote_url, role, &redacted)
}

/// Aggregate per-remote verdicts into one repository disposition.
///
/// Precedence: any `confirmed` wins, then `related`, then `probable`;
/// a lone decisive mismatch is `nonmatch` only when no remote is merely
/// ambiguous (nonmatch means proven); otherwise `unresolvable_identity`,
/// including the no-remotes case (identifying remotes may have been
/// removed, spec §8). Each item is `(raw_effective_url, role)`.
pub fn classify_remotes<'a>(
    canonical_target: &str,
    remotes: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> (MatchDisposition, Vec<String>) {
    let mut evidence = Vec::new();
    let mut seen = 0u32;
    let mut ranks: Vec<MatchDisposition> = Vec::new();
    for (url, role) in remotes {
        seen += 1;
        let (disposition, mut lines) = classify_remote(canonical_target, url, role);
        evidence.append(&mut lines);
        ranks.push(disposition);
    }
    if seen == 0 {
        evidence.push(
            "No effective remotes; identifying remotes may have been removed. Identity is ambiguous."
                .to_string(),
        );
        return (MatchDisposition::UnresolvableIdentity, evidence);
    }
    let has = |d: MatchDisposition| ranks.contains(&d);
    let verdict = if has(MatchDisposition::Confirmed) {
        MatchDisposition::Confirmed
    } else if has(MatchDisposition::Related) {
        MatchDisposition::Related
    } else if has(MatchDisposition::Probable) {
        MatchDisposition::Probable
    } else if has(MatchDisposition::UnresolvableIdentity) {
        MatchDisposition::UnresolvableIdentity
    } else {
        MatchDisposition::Nonmatch
    };
    (verdict, evidence)
}

/// Strip embedded credentials from a remote URL for reports and logs.
///
/// URL-form userinfo `user:pass@` becomes `user:<redacted>@`; a bare
/// `token@` (no colon, the common token-as-username shape) becomes
/// `<redacted>@`. Scp-like `user@host:path` carries no password field and
/// is returned unchanged.
pub fn redact_credentials(url: &str) -> String {
    let scheme_end = match url.find("://") {
        Some(i) => i + 3,
        None => return url.to_string(),
    };
    let (scheme, rest) = url.split_at(scheme_end);
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let Some(at) = authority.rfind('@') else {
        return url.to_string();
    };
    let (userinfo, host) = authority.split_at(at + 1);
    let userinfo = &userinfo[..userinfo.len() - 1];
    if userinfo.is_empty() {
        return url.to_string();
    }
    let redacted_user = match userinfo.find(':') {
        Some(i) => format!("{}:{REDACTED}", &userinfo[..i]),
        None => REDACTED.to_string(),
    };
    format!("{scheme}{redacted_user}@{host}{tail}")
}

/// True when `host` is github.com directly or via an SSH alias.
///
/// Alias resolution is read-only (`~/.ssh/config`, `Host`/`HostName` only;
/// no `ProxyCommand` or any other directive is honored or executed).
pub fn is_github_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case(GITHUB_HOST) {
        return true;
    }
    resolve_ssh_alias(host).is_some_and(|real| real.eq_ignore_ascii_case(GITHUB_HOST))
}

/// Resolve an SSH alias to its configured `HostName` (lowercased), if any.
pub fn resolve_ssh_alias(host: &str) -> Option<String> {
    load_ssh_aliases().get(&host.to_lowercase()).cloned()
}

/// Load `Host` -> `HostName` mappings from the user's SSH config.
///
/// Best-effort: missing or unreadable files yield an empty map. Only
/// simple (wildcard-free) aliases are recorded; matching is case-insensitive
/// and the first `HostName` per alias wins, per ssh_config semantics.
pub fn load_ssh_aliases() -> HashMap<String, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        return HashMap::new();
    }
    let path = std::path::Path::new(&home).join(".ssh").join("config");
    let text = std::fs::read_to_string(path).unwrap_or_default();
    if text.is_empty() {
        return HashMap::new();
    }
    parse_ssh_config(&text)
}

/// Narrow ssh_config parser: `Host` patterns plus first `HostName` each.
///
/// Pure function over file text so callers and tests need no filesystem.
/// Comments, blank lines, `=` separators, and case-insensitive keywords are
/// handled; wildcard patterns and all other directives are ignored.
pub fn parse_ssh_config(text: &str) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    let mut current: Vec<String> = Vec::new();
    for raw_line in text.lines() {
        let line = match raw_line.find('#') {
            Some(i) => &raw_line[..i],
            None => raw_line,
        };
        let mut words = line.split_whitespace();
        let Some(keyword) = words.next() else {
            continue;
        };
        if keyword.eq_ignore_ascii_case("host") {
            current = words
                .flat_map(|w| w.split('=').filter(|s| !s.is_empty()))
                .filter(|w| !w.contains(['*', '?', '!']))
                .map(|w| w.to_lowercase())
                .collect();
        } else if keyword.eq_ignore_ascii_case("hostname") {
            let Some(mut value) = words.next() else {
                continue;
            };
            value = value.trim_start_matches('=');
            if value.is_empty() {
                value = words.next().unwrap_or_default();
            }
            let value = value.to_lowercase();
            if value.is_empty() {
                continue;
            }
            for alias in &current {
                aliases
                    .entry(alias.clone())
                    .or_insert_with(|| value.clone());
            }
        }
    }
    aliases
}

/// Split a canonical `https://github.com/owner/repo` URL into `(owner, repo)`.
fn split_canonical(canonical: &str) -> Option<(String, String)> {
    let path = canonical
        .strip_prefix("https://")
        .and_then(|s| s.strip_prefix(GITHUB_HOST))?;
    split_owner_repo_path(path, false)
}

/// Split a URL path into `(owner, repo)`.
///
/// When `web_shapes` is true, query/fragment are stripped first (HTTP
/// parsers fold them into the path). Exactly two non-empty segments must
/// remain; one trailing `.git` suffix and slashes are trimmed. GitHub
/// owner rules (alnum/hyphen, 1–39 chars, no leading/trailing hyphen) and
/// conservative repo-name rules are enforced.
fn split_owner_repo_path(path: &str, web_shapes: bool) -> Option<(String, String)> {
    let mut path = path;
    if web_shapes {
        path = path.split(['?', '#']).next().unwrap_or(path);
    }
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let path = path.trim_matches('/');
    let (owner, repo) = path.split_once('/')?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return None;
    }
    if !is_valid_owner(owner) || !is_valid_repo(repo) {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

/// GitHub account-name rules (conservative, host-aware).
fn is_valid_owner(owner: &str) -> bool {
    if owner.len() > 39 {
        return false;
    }
    let bytes = owner.as_bytes();
    if bytes.first().is_some_and(|b| !b.is_ascii_alphanumeric())
        || bytes.last().is_some_and(|b| !b.is_ascii_alphanumeric())
    {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// Conservative repository-name rules.
fn is_valid_repo(repo: &str) -> bool {
    if repo.is_empty() || repo.len() > 100 || repo == "." || repo == ".." {
        return false;
    }
    repo.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Verdict for remotes that fail strict normalization, with evidence.
fn lenient_noncanonical_verdict(
    canonical_target: &str,
    remote_url: &str,
    role: &str,
    redacted: &str,
) -> (MatchDisposition, Vec<String>) {
    let parsed = match gix::url::parse(remote_url.trim()) {
        Ok(parsed) => parsed,
        Err(_) => {
            return (
                MatchDisposition::UnresolvableIdentity,
                vec![format!(
                    "Effective {role} remote `{redacted}` could not be parsed as a Git URL; identity cannot be determined."
                )],
            );
        }
    };
    match parsed.scheme {
        gix::url::Scheme::File => {
            return (
                MatchDisposition::UnresolvableIdentity,
                vec![format!(
                    "Effective {role} remote `{redacted}` is a local path; identity cannot be determined under the policy without following it."
                )],
            );
        }
        gix::url::Scheme::Ext | gix::url::Scheme::Helper(_) | gix::url::Scheme::HelperUrl(_) => {
            return (
                MatchDisposition::UnresolvableIdentity,
                vec![format!(
                    "Effective {role} remote `{redacted}` uses a helper/ext transport that cannot be interpreted without executing it."
                )],
            );
        }
        _ => {}
    }
    let host = parsed.host.as_deref().unwrap_or_default();
    if host.is_empty() {
        return (
            MatchDisposition::UnresolvableIdentity,
            vec![format!(
                "Effective {role} remote `{redacted}` has no host; identity cannot be determined."
            )],
        );
    }
    if !is_github_host(host) {
        if !host.contains('.') && !host.eq_ignore_ascii_case("localhost") {
            return (
                MatchDisposition::UnresolvableIdentity,
                vec![format!(
                    "Effective {role} remote `{redacted}` uses single-label host `{host}` with no matching SSH alias; identity cannot be determined."
                )],
            );
        }
        return (
            MatchDisposition::Nonmatch,
            vec![format!(
                "Effective {role} remote `{redacted}` points at host `{host}`, not {GITHUB_HOST}."
            )],
        );
    }
    // GitHub host but the path is not exactly owner/repo.
    let path = std::str::from_utf8(parsed.path.as_bytes()).unwrap_or_default();
    let trimmed = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path)
        .trim_matches('/');
    if let Some((w_owner, w_repo)) = split_canonical(canonical_target) {
        let mut segments = trimmed.split('/').filter(|s| !s.is_empty());
        let owner = segments.next().unwrap_or_default();
        let repo_raw = segments.next().unwrap_or_default();
        let repo = repo_raw.strip_suffix(".git").unwrap_or(repo_raw);
        let rest = segments.next().is_some();
        if !repo_raw.is_empty()
            && owner.eq_ignore_ascii_case(&w_owner)
            && repo.eq_ignore_ascii_case(&w_repo)
            && rest
        {
            return (
                MatchDisposition::Probable,
                vec![format!(
                    "Effective {role} remote `{redacted}` names the target repository with extra path beyond owner/repo; likely the same repository."
                )],
            );
        }
    }
    (
        MatchDisposition::Nonmatch,
        vec![format!(
            "Effective {role} remote `{redacted}` path does not identify the target repository."
        )],
    )
}
