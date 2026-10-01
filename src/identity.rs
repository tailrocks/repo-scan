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

/// Fixed placeholder emitted when a URL cannot be represented without
/// secret-spill risk (control characters, malformed authority smuggling).
/// It carries no `://`, so it never re-enters URL handling as a credential
/// shape and normalizes to `None` (fail closed).
pub const REDACTED_URL: &str = "<redacted-url>";

/// Split `scheme://rest`. Returns `(scheme_prefix, rest)`.
fn split_scheme(url: &str) -> Option<(&str, &str)> {
    let end = url.find("://")? + 3;
    Some(url.split_at(end))
}

/// Length of the authority component of `rest` (the part after `://`):
/// up to the first `/`, `?`, or `#`, whichever comes first.
fn authority_len(rest: &str) -> usize {
    rest.find(['/', '?', '#']).unwrap_or(rest.len())
}

/// True when `key` names secret-bearing material. Matching is over the
/// lowercased (percent-decoded by callers where needed) key: exact match
/// for short names, substring match for descriptive names. Over-matching
/// only over-redacts a value, which is the safe direction.
fn is_sensitive_key(lower_key: &str) -> bool {
    const EXACT: &[&str] = &["key", "sig", "pin", "pwd", "otp", "pass"];
    if EXACT.contains(&lower_key) {
        return true;
    }
    const SUBSTR: &[&str] = &[
        "token",
        "secret",
        "password",
        "passwd",
        "auth",
        "credential",
        "private",
        "signature",
        "session",
        "bearer",
        "jwt",
        "opaque",
        "apikey",
        "api_key",
        "access_key",
        "secret_key",
        "client_secret",
        "passcode",
    ];
    SUBSTR.iter().any(|s| lower_key.contains(s))
}

/// Percent-decode `text` for detection purposes only (matching keys through
/// `%XX` encoding). Malformed escapes are passed through literally.
/// Byte-oriented so multibyte input can never panic slicing.
fn percent_decode_for_match(text: &str) -> String {
    fn hex_val(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi * 16 + lo) as char);
                i += 3;
                continue;
            }
        }
        // ASCII passes through exactly; non-ASCII bytes decode to the
        // matching space lossy (they can never match an ASCII sensitive
        // key, which is the only use of this output).
        if bytes[i].is_ascii() {
            out.push(bytes[i] as char);
        } else {
            out.push('\u{FFFD}');
        }
        i += 1;
    }
    out
}

/// Value-redact sensitive `key=value` pairs inside one query/fragment
/// section (`&`/`;` separated). Non-sensitive pairs pass through
/// untouched; a sensitive key's value becomes [`REDACTED`].
fn scrub_pairs(section: &str) -> String {
    let mut out = String::with_capacity(section.len());
    let mut rest = section;
    // Split manually so the original separators are preserved byte for byte
    // (a section with no sensitive keys round-trips unchanged).
    loop {
        let split = rest.find(['&', ';']);
        let (pair, separator) = match split {
            Some(i) => (&rest[..i], Some(rest.as_bytes()[i] as char)),
            None => (rest, None),
        };
        match pair.split_once('=') {
            Some((key, _)) => {
                let match_key = percent_decode_for_match(key).to_lowercase();
                if is_sensitive_key(&match_key) {
                    out.push_str(key);
                    out.push('=');
                    out.push_str(REDACTED);
                } else {
                    out.push_str(pair);
                }
            }
            None => out.push_str(pair),
        }
        match separator {
            Some(sep) => {
                out.push(sep);
                rest = &rest[pair.len() + 1..];
            }
            None => return out,
        }
    }
}

/// Scrub the query/fragment of a URL tail (the part after the authority).
/// Sensitive parameter values become [`REDACTED`]; path, structure, and
/// non-sensitive parameters are preserved.
fn scrub_query_fragment(tail: &str) -> String {
    // Split off the fragment first (`#` may legally follow `?`).
    let (before_frag, fragment) = match tail.split_once('#') {
        Some((head, frag)) => (head, Some(frag)),
        None => (tail, None),
    };
    let (path, query) = match before_frag.split_once('?') {
        Some((head, query)) => (head, Some(query)),
        None => (before_frag, None),
    };
    let mut out = String::with_capacity(tail.len());
    out.push_str(path);
    if let Some(query) = query {
        out.push('?');
        out.push_str(&scrub_pairs(query));
    }
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(&scrub_pairs(fragment));
    }
    out
}

/// Strip embedded credentials from a remote URL for reports and logs.
///
/// URL-form userinfo `user:pass@` becomes `user:<redacted>@`; a bare
/// `token@` (no colon, the common token-as-username shape) becomes
/// `<redacted>@`. Sensitive query/fragment parameter values become
/// `<redacted>` while structure is preserved. Scp-like `user@host:path`
/// has its user component redacted (`<redacted>@host:path`): a
/// token-as-username (`secret@github.com:o/r`) is indistinguishable from
/// the conventional `git` login without an allowlist, so every scp-like
/// user redacts (RS-PRIV-10). Inputs that cannot be represented safely
/// (control characters, or an `@` past the authority that signals
/// malformed smuggled userinfo such as
/// `https://user:secret/ret@host/...`) collapse to [`REDACTED_URL`].
pub fn redact_credentials(url: &str) -> String {
    let Some((scheme, rest)) = split_scheme(url) else {
        return redact_scp_like(url).unwrap_or_else(|| url.to_string());
    };
    if url.chars().any(|c| c.is_control()) {
        return REDACTED_URL.to_string();
    }
    let end = authority_len(rest);
    let (authority, tail) = rest.split_at(end);
    // An `@` past the authority boundary is not a legal path character in
    // practice; it signals malformed smuggled userinfo containing `/`.
    // Fail closed rather than emit a half-parsed secret.
    let path_part = tail.split(['?', '#']).next().unwrap_or(tail);
    if path_part.contains('@') {
        return REDACTED_URL.to_string();
    }
    let scrubbed_tail = scrub_query_fragment(tail);
    let Some(at) = authority.rfind('@') else {
        return format!("{scheme}{authority}{scrubbed_tail}");
    };
    let userinfo = &authority[..at];
    let host = &authority[at + 1..];
    if userinfo.is_empty() {
        return format!("{scheme}{authority}{scrubbed_tail}");
    }
    let redacted_user = match userinfo.find(':') {
        Some(i) => format!("{}:{REDACTED}", &userinfo[..i]),
        None => REDACTED.to_string(),
    };
    format!("{scheme}{redacted_user}@{host}{scrubbed_tail}")
}

/// Redact the user component of a scp-like `user@host:path` shape, if
/// `url` is one. Returns `None` for anything else (emails, bare
/// `user@host`, paths, prose): the shape requires a non-empty single-token
/// user, a non-empty host with no `/`, and a `host:path` remainder.
/// Control characters fail closed to [`REDACTED_URL`], mirroring scheme
/// URLs. Used by [`redact_credentials`] and the free-text scp pass of
/// [`scrub_text`] (RS-PRIV-10).
fn redact_scp_like(url: &str) -> Option<String> {
    let rest = scp_host_path(url)?;
    if rest.chars().any(|c| c.is_control()) {
        return Some(REDACTED_URL.to_string());
    }
    Some(format!("{REDACTED}@{rest}"))
}

/// Split an scp-like `user@host:path` shape into its `host:path` remainder,
/// if `url` is one. Shape rules are exactly those of [`redact_scp_like`]:
/// no `://`, a non-empty single-token user, a non-empty whitespace-free
/// host with no `/`, and a `host:path` remainder. Shared by redaction and
/// by [`sanitize_target_url`] (EXACT-2), which normalizes the user instead
/// of redacting it so the persisted shape still resolves.
fn scp_host_path(url: &str) -> Option<&str> {
    if url.contains("://") {
        return None;
    }
    let at = url.find('@')?;
    let (user, rest) = url.split_at(at);
    let rest = &rest[1..];
    if user.is_empty()
        || user
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '/')
    {
        return None;
    }
    let colon = rest.find(':')?;
    let (host, path) = rest.split_at(colon);
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '/')
        || path.len() < 2
    {
        return None;
    }
    Some(rest)
}

/// True when a scheme URL carries a non-empty `userinfo@` authority prefix
/// or a malformed smuggled-userinfo shape (an `@` past the authority
/// boundary, which [`redact_credentials`] collapses). Scp-like
/// `user@host:path` carries no password field, so it reports false even
/// though [`redact_credentials`] redacts its user component: the reject
/// boundary (CLI target validation) must keep accepting the conventional
/// `git@` login, while display paths redact because a token-as-username
/// is indistinguishable from it (RS-PRIV-10).
pub fn has_userinfo(url: &str) -> bool {
    let Some((_, rest)) = split_scheme(url) else {
        return false;
    };
    let end = authority_len(rest);
    let (authority, tail) = rest.split_at(end);
    if let Some(at) = authority.rfind('@') {
        if !authority[..at].is_empty() {
            return true;
        }
    }
    let path_part = tail.split(['?', '#']).next().unwrap_or(tail);
    path_part.contains('@')
}

/// Strip `userinfo@` from a scheme URL entirely, for internal reuse of a
/// legacy stored target (resume of a row persisted before the CLI boundary
/// rejected credentials). Unlike [`redact_credentials`] the result carries
/// no `@` at all, so it re-enters normalization without tripping the
/// userinfo reject while resolving to the same canonical target. Scp-like
/// input is returned unchanged; malformed smuggled-userinfo shapes collapse
/// to [`REDACTED_URL`] (fail closed: unresolvable, never raw).
pub fn strip_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = split_scheme(url) else {
        return url.to_string();
    };
    let end = authority_len(rest);
    let (authority, tail) = rest.split_at(end);
    let path_part = tail.split(['?', '#']).next().unwrap_or(tail);
    if path_part.contains('@') {
        return REDACTED_URL.to_string();
    }
    match authority.rfind('@') {
        Some(at) if !authority[..at].is_empty() => {
            format!("{scheme}{}{tail}", &authority[at + 1..])
        }
        _ => url.to_string(),
    }
}

/// True when a CLI scan target carries a rejectable credential form and
/// must be refused before any persistence (EXACT-2): scheme userinfo
/// (including malformed smuggled `@`, see [`has_userinfo`]) or any
/// query/fragment tail. A canonical target names `owner/repo` only, so a
/// tail can only carry non-target material — JWT/opaque/spaced/JSON values
/// that are not key-identifiable — and fails closed. Scp-like
/// `user@host:path` is NOT rejectable (the CLI must keep accepting the
/// `git@` login, RS-PRIV-10); its user is normalized before persist by
/// [`sanitize_target_url`].
pub fn must_reject_target(url: &str) -> bool {
    if has_userinfo(url) {
        return true;
    }
    let trimmed = url.trim();
    if let Some((_, rest)) = split_scheme(trimmed) {
        let tail = &rest[authority_len(rest)..];
        return tail.find(['?', '#']).is_some();
    }
    // Scp-like or bare input: a `?`/`#` tail is meaningless for a target
    // (repository names cannot contain them), so fail closed here rather
    // than persisting an opaque value normalization would ignore.
    trimmed.find(['?', '#']).is_some()
}

/// Persist-safe form of an accepted CLI scan target (EXACT-2): the only
/// value mint/report/catalog/snapshot/terminal may observe. Scp-like
/// `user@host:path` has its user normalized to the conventional `git`
/// login (normalization ignores the user and display redacts it, RS-PRIV-10,
/// so a token-as-username never persists while the shape still resolves);
/// scheme URLs are stripped of userinfo plus any query/fragment tail
/// (defense-in-depth behind [`must_reject_target`]); inputs that cannot be
/// represented safely collapse to [`REDACTED_URL`]. Plain targets
/// round-trip unchanged (modulo surrounding whitespace).
pub fn sanitize_target_url(url: &str) -> String {
    let trimmed = url.trim();
    if let Some(rest) = scp_host_path(trimmed) {
        if rest.chars().any(|c| c.is_control()) {
            return REDACTED_URL.to_string();
        }
        return format!("git@{rest}");
    }
    let Some((scheme, rest)) = split_scheme(trimmed) else {
        return trimmed.to_string();
    };
    if trimmed.chars().any(|c| c.is_control()) {
        return REDACTED_URL.to_string();
    }
    let end = authority_len(rest);
    let (authority, tail) = rest.split_at(end);
    let path = tail.split(['?', '#']).next().unwrap_or(tail);
    if path.contains('@') {
        return REDACTED_URL.to_string();
    }
    match authority.rfind('@') {
        Some(at) => format!("{scheme}{}{path}", &authority[at + 1..]),
        None => format!("{scheme}{authority}{path}"),
    }
}

/// Display form of a (possibly rejected) scan target for errors and
/// diagnostics (EXACT-2): userinfo redacted, query/fragment stripped
/// entirely (opaque values are not key-identifiable, so key-based redaction
/// cannot make them safe to echo), spaced/JSON/CLI pairs scrubbed. Never
/// carries secret bytes; host/path structure is preserved for the user.
pub fn redact_target_for_display(url: &str) -> String {
    let head = url.split(['?', '#']).next().unwrap_or(url);
    scrub_text(&redact_credentials(head))
}

/// Scrub free text (evidence lines, error strings, reasons) for report
/// emission: every embedded `scheme://...` token and every scp-like
/// `user@host:path` token is passed through [`redact_credentials`], and
/// sensitive pairs — same-token `key=value`/`key:value` plus spaced, JSON,
/// CLI-flag, and multiline shapes — have their values replaced with
/// [`REDACTED`]. Ordinary prose passes through unchanged.
pub fn scrub_text(text: &str) -> String {
    let scrubbed_urls = scrub_embedded_urls(text);
    let scrubbed_scp = scrub_embedded_scp(&scrubbed_urls);
    let scrubbed_pairs = scrub_secret_pairs(&scrubbed_scp);
    scrub_spaced_pairs(&scrubbed_pairs)
}

/// Redact embedded scp-like `user@host:path` tokens inside free text
/// (RS-PRIV-10). Tokens are whitespace-delimited; surrounding quotes and
/// trailing sentence punctuation are preserved, the user component is
/// redacted. Scheme URLs were handled by the earlier pass and are
/// skipped here.
fn scrub_embedded_scp(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token_start: Option<usize> = None;
    let flush = |out: &mut String, token: &str| {
        if token.contains("://") {
            out.push_str(token);
            return;
        }
        // Preserve surrounding punctuation; redact the core shape only.
        let core = token.trim_start_matches(['\'', '"', '`', '(', '[', '<']);
        let stripped =
            core.trim_end_matches(['\'', '"', '`', '.', ',', ';', ':', '!', '?', ')', ']', '>']);
        if stripped.is_empty() {
            out.push_str(token);
            return;
        }
        match redact_scp_like(stripped) {
            Some(redacted) => {
                let lead = token.len()
                    - token
                        .trim_start_matches(['\'', '"', '`', '(', '[', '<'])
                        .len();
                out.push_str(&token[..lead]);
                out.push_str(&redacted);
                // `stripped` borrows from `core`, which starts `lead`
                // bytes into `token`, so the tail reattaches here.
                out.push_str(&token[lead + stripped.len()..]);
            }
            None => out.push_str(token),
        }
    };
    for (index, ch) in text.char_indices() {
        if ch.is_whitespace() {
            if let Some(start) = token_start.take() {
                flush(&mut out, &text[start..index]);
            }
            out.push(ch);
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }
    if let Some(start) = token_start.take() {
        flush(&mut out, &text[start..]);
    }
    out
}

/// Redact embedded URL tokens inside free text.
fn scrub_embedded_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let Some(offset) = rest.find("://") else {
            out.push_str(rest);
            return out;
        };
        // Walk the scheme start backwards over scheme characters.
        let mut start = offset;
        while start > 0 {
            let byte = rest.as_bytes()[start - 1];
            if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.') {
                start -= 1;
            } else {
                break;
            }
        }
        // Walk the token end forwards to a delimiter.
        let bytes = rest.as_bytes();
        let mut end = offset + 3;
        while end < bytes.len() {
            let byte = bytes[end];
            if byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b'<' | b'>' | b'`') {
                break;
            }
            end += 1;
        }
        // No scheme name (e.g. `://foo`) is not a URL; keep scanning past it.
        if start == offset {
            out.push_str(&rest[..end]);
            rest = &rest[end..];
            continue;
        }
        out.push_str(&rest[..start]);
        out.push_str(&redact_credentials(&rest[start..end]));
        rest = &rest[end..];
    }
}

/// Value-redact bare sensitive pairs (`key=value`, `key: value`) in text
/// outside URLs. Tokens are whitespace/comma/semicolon separated; only the
/// value of a sensitive key is replaced.
fn scrub_secret_pairs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token_start: Option<usize> = None;
    let chars = text.char_indices();
    let flush = |out: &mut String, token: &str| {
        if let Some(scrubbed) = scrub_pair_token(token) {
            out.push_str(&scrubbed);
        } else {
            out.push_str(token);
        }
    };
    for (index, ch) in chars {
        let is_delim = ch.is_whitespace() || ch == ',' || ch == ';';
        if is_delim {
            if let Some(start) = token_start.take() {
                flush(&mut out, &text[start..index]);
            }
            out.push(ch);
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }
    if let Some(start) = token_start.take() {
        flush(&mut out, &text[start..]);
    }
    out
}

/// Redact one whitespace-delimited token when it is a sensitive pair.
fn scrub_pair_token(token: &str) -> Option<String> {
    // Skip anything already URL-shaped (handled by the URL pass) and
    // anything too long to be a `key=value` pair.
    if token.contains("://") || token.len() > 1024 {
        return None;
    }
    let (key, separator, _) = split_pair(token)?;
    let clean_key: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .collect();
    let match_key = percent_decode_for_match(&clean_key).to_lowercase();
    if match_key.is_empty() || !is_sensitive_key(&match_key) {
        return None;
    }
    Some(format!("{key}{separator}{REDACTED}"))
}

/// Split a `key=value` or `key: value` token. A bare `C:\...`-style drive
/// prefix is not a pair (single-letter key with no `=`).
fn split_pair(token: &str) -> Option<(&str, &str, &str)> {
    if let Some((key, value)) = token.split_once('=') {
        if !key.is_empty() && !value.is_empty() {
            return Some((key, "=", value));
        }
        return None;
    }
    if let Some((key, value)) = token.split_once(':') {
        if key.len() > 1 && !value.is_empty() {
            return Some((key, ":", value));
        }
    }
    None
}

/// Value-redact sensitive pairs whose key and value are NOT in one token
/// (RS-PRIV-04): spaced `password: secret` / `password : secret`, JSON
/// `{"password": "secret"}`, CLI `--password secret`, and multiline values
/// (`key:` then the value on a later line). Structure (key, separator,
/// gaps, quotes) is preserved; only the value span becomes [`REDACTED`].
/// Runs after [`scrub_secret_pairs`]; same-token pairs are already
/// redacted and re-match idempotently.
fn scrub_spaced_pairs(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let Some((key_end, clean_len, cli_flag)) = match_key_at(text, i) else {
            // No sensitive key here: emit one char, keep scanning.
            let width = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&text[i..i + width]);
            i += width;
            continue;
        };
        // Gap between key and separator: spaces/tabs only (a newline
        // before the separator is not a pair shape we claim).
        let mut j = key_end;
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
            j += 1;
        }
        let has_sep = j < bytes.len() && matches!(bytes[j], b'=' | b':');
        if has_sep {
            // Drive-letter guard mirrors `split_pair` (`C:\...`); a `::`
            // Rust path / IPv6 run is not a pair either.
            if bytes[j] == b':' && (clean_len <= 1 || bytes.get(j + 1) == Some(&b':')) {
                let width = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
                out.push_str(&text[i..i + width]);
                i += width;
                continue;
            }
            j += 1;
        } else if !cli_flag {
            // Bare `key value` with no separator redacts only for `--flag`
            // shapes; anything else would mangle ordinary prose.
            let width = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&text[i..i + width]);
            i += width;
            continue;
        }
        // Gap between separator (or flag) and value: whitespace including
        // newlines, so multiline values redact.
        let mut k = j;
        while k < bytes.len() && matches!(bytes[k], b' ' | b'\t' | b'\r' | b'\n') {
            k += 1;
        }
        // A CLI flag followed by another flag/option or nothing has no value.
        if cli_flag && !has_sep && (k >= bytes.len() || bytes[k] == b'-') {
            let width = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&text[i..i + width]);
            i += width;
            continue;
        }
        let Some((val_start, val_end, quote)) = value_span(text, k) else {
            let width = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&text[i..i + width]);
            i += width;
            continue;
        };
        // `text[i..val_start]` already ends with the opening quote for
        // quoted values; only the inner span is replaced.
        out.push_str(&text[i..val_start]);
        out.push_str(REDACTED);
        match quote {
            Some(q) => {
                out.push(q);
                i = val_end + 1;
            }
            None => {
                i = val_end;
            }
        }
    }
    out
}

/// Match a sensitive key starting at byte `i`: bare (`password`), quoted
/// (`"password"`), or CLI-flag (`--password`) form. Returns the byte end
/// of the key, the cleaned-key length (for the drive-letter guard), and
/// whether the key is a `--flag`. The match must start at a key boundary
/// (start of text or a non-key character before `i`) and the raw key is
/// capped at 128 bytes.
fn match_key_at(text: &str, i: usize) -> Option<(usize, usize, bool)> {
    let bytes = text.as_bytes();
    if i > 0 {
        let prev = bytes[i - 1];
        if prev.is_ascii_alphanumeric() || matches!(prev, b'_' | b'-' | b'.') {
            return None;
        }
    }
    let first = *bytes.get(i)?;
    let (raw, key_end) = if first == b'"' || first == b'\'' {
        let mut j = i + 1;
        while j < bytes.len() && bytes[j] != first && j - i <= 128 {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != first {
            return None;
        }
        (&text[i + 1..j], j + 1)
    } else if first.is_ascii_alphabetic() || first == b'_' || first == b'-' {
        let mut j = i;
        while j < bytes.len()
            && (bytes[j].is_ascii_alphanumeric() || matches!(bytes[j], b'_' | b'-' | b'.'))
            && j - i <= 128
        {
            j += 1;
        }
        (&text[i..j], j)
    } else {
        return None;
    };
    if raw.is_empty() || raw.len() > 128 {
        return None;
    }
    let clean_key: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .collect();
    let match_key = percent_decode_for_match(&clean_key).to_lowercase();
    if match_key.is_empty() || !is_sensitive_key(&match_key) {
        return None;
    }
    Some((key_end, match_key.len(), raw.starts_with("--")))
}

/// Value span starting at byte `k`: a quoted span (quote-aware, `\`
/// escapes honored, closing quote required within 1024 bytes) or a bare
/// run to the next delimiter (whitespace, `,;`, quotes, or `}]`).
/// Returns `(span_start, span_end, quote_char)`; empty values are `None`.
fn value_span(text: &str, k: usize) -> Option<(usize, usize, Option<char>)> {
    let bytes = text.as_bytes();
    if k >= bytes.len() {
        return None;
    }
    if bytes[k] == b'"' || bytes[k] == b'\'' {
        let quote = bytes[k] as char;
        let mut j = k + 1;
        while j < bytes.len() && j - k <= 1024 {
            if bytes[j] == b'\\' {
                j += 2;
                continue;
            }
            if bytes[j] == bytes[k] {
                return Some((k + 1, j, Some(quote)));
            }
            j += 1;
        }
        return None;
    }
    let mut j = k;
    while j < bytes.len()
        && !bytes[j].is_ascii_whitespace()
        && !matches!(bytes[j], b',' | b';' | b'"' | b'\'' | b'}' | b']')
        && j - k <= 1024
    {
        j += 1;
    }
    if j == k {
        return None;
    }
    Some((k, j, None))
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

/// Maximum bytes read from an SSH config file (SR-STATE-05). Past the
/// cap the file reads as absent (empty map), never truncated content.
pub const MAX_SSH_CONFIG_BYTES: u64 = 64 * 1024;

/// Maximum aliases retained from one SSH config (SR-STATE-05). Past the
/// cap further `Host` names are ignored; first-wins order is preserved.
pub const MAX_SSH_CONFIG_ALIASES: usize = 1024;

/// Load `Host` -> `HostName` mappings from the user's SSH config.
///
/// Best-effort: missing or unreadable files yield an empty map. Only
/// simple (wildcard-free) aliases are recorded; matching is case-insensitive
/// and the first `HostName` per alias wins, per ssh_config semantics.
/// The read is bounded (SR-STATE-05): regular-file-only, no symlink
/// following (so FIFO/device swaps cannot hang it), byte-capped at
/// [`MAX_SSH_CONFIG_BYTES`].
pub fn load_ssh_aliases() -> HashMap<String, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        return HashMap::new();
    }
    load_ssh_aliases_from(&std::path::Path::new(&home).join(".ssh").join("config"))
}

/// Load `Host` -> `HostName` mappings from one explicit SSH config path.
///
/// Same bounded read as [`load_ssh_aliases`]; split out so tests can
/// prove the guards without mutating `HOME`.
pub fn load_ssh_aliases_from(path: &std::path::Path) -> HashMap<String, String> {
    let Some(bytes) = crate::git::read_bounded_bytes(path, MAX_SSH_CONFIG_BYTES) else {
        return HashMap::new();
    };
    if bytes.is_empty() {
        return HashMap::new();
    }
    parse_ssh_config(&String::from_utf8_lossy(&bytes))
}

/// Narrow ssh_config parser: `Host` patterns plus first `HostName` each.
///
/// Pure function over file text so callers and tests need no filesystem.
/// Comments, blank lines, `=` separators, and case-insensitive keywords are
/// handled; wildcard patterns and all other directives are ignored.
/// At most [`MAX_SSH_CONFIG_ALIASES`] aliases are retained (SR-STATE-05).
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
                .take(MAX_SSH_CONFIG_ALIASES)
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
                if aliases.len() >= MAX_SSH_CONFIG_ALIASES && !aliases.contains_key(alias) {
                    continue;
                }
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
