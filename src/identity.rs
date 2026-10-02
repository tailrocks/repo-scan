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

/// True when `target` is a local filesystem repository target (starts with `file://` or `/`).
pub fn is_local_target(target: &str) -> bool {
    target.starts_with("file://") || target.starts_with('/')
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
    // Evidence lines persist into the catalog and the report, so they
    // use the strict remote form: opaque query/fragment tails drop
    // entirely rather than leaking through key-based scrubbing (RETEST-2).
    let redacted = redact_remote_url(remote_url.trim());
    if remote_url.trim().is_empty() {
        return (
            MatchDisposition::UnresolvableIdentity,
            vec![format!(
                "Effective {role} remote URL is empty; identity cannot be determined."
            )],
        );
    }
    if is_local_target(canonical_target) {
        return classify_local_target_remote(canonical_target, remote_url, role, &redacted);
    }
    if redacted == REDACTED_URL {
        // Already-collapsed observation (FIXREADY4 R): the constructor
        // redacted an unsupported or sensitive remote form. The row is
        // preserved (never silently dropped) with the `unsupported`
        // marker (`unresolvable_identity`), never verbatim bytes.
        return (
            MatchDisposition::UnresolvableIdentity,
            vec![format!(
                "Effective {role} remote `{redacted}` uses an unsupported or sensitive form that was redacted at observation; identity cannot be determined."
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

/// Compare a local repository target against one effective remote observation.
fn classify_local_target_remote(
    canonical_target: &str,
    remote_url: &str,
    role: &str,
    redacted: &str,
) -> (MatchDisposition, Vec<String>) {
    let target_path_str = canonical_target
        .strip_prefix("file://")
        .unwrap_or(canonical_target);
    let target_path = std::path::Path::new(target_path_str);
    let target_canon =
        std::fs::canonicalize(target_path).unwrap_or_else(|_| target_path.to_path_buf());

    let trimmed = remote_url.trim();
    let remote_path_opt: Option<std::path::PathBuf> =
        if let Some(stripped) = trimmed.strip_prefix("file://") {
            Some(std::path::PathBuf::from(stripped))
        } else if trimmed.starts_with('/') || trimmed.starts_with('.') {
            Some(std::path::PathBuf::from(trimmed))
        } else if let Ok(parsed) = gix::url::parse(trimmed) {
            if parsed.scheme == gix::url::Scheme::File {
                std::str::from_utf8(parsed.path.as_bytes())
                    .ok()
                    .map(std::path::PathBuf::from)
            } else {
                None
            }
        } else {
            None
        };

    if let Some(rpath) = remote_path_opt {
        let r_canon = std::fs::canonicalize(&rpath).unwrap_or(rpath);
        if r_canon == target_canon {
            return (
                MatchDisposition::Confirmed,
                vec![format!(
                    "Effective {role} remote `{redacted}` matches the local target repository ({canonical_target})."
                )],
            );
        } else {
            return (
                MatchDisposition::Nonmatch,
                vec![format!(
                    "Effective {role} remote `{redacted}` points to a different local repository ({}), not the target.",
                    r_canon.display()
                )],
            );
        }
    }
    (
        MatchDisposition::Nonmatch,
        vec![format!(
            "Effective {role} remote `{redacted}` is not a local path matching {canonical_target}."
        )],
    )
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

/// Split `scheme://rest` with scheme validation (R6b): the first `://`
/// opens a scheme URL only when the prefix is a non-empty RFC-3986
/// scheme token (ASCII alphabetic first, then ASCII
/// alphanumerics/`+`/`-`/`.` — no whitespace, no `=`/`:`/`@`, starting
/// at offset 0 of the already-trimmed input). A `://` smuggled past
/// prose, pairs, or transports (`token=... https://...`,
/// `file:ext::... --url=https://...`, `https:/evil --url=https://...`)
/// yields `None`, so callers fall through to transport/pair/scrub
/// handling instead of echoing the whole input verbatim through the
/// scheme path.
fn split_valid_scheme(url: &str) -> Option<(&str, &str)> {
    let off = url.find("://")?;
    let scheme = &url[..off];
    if !scheme
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
    {
        return None;
    }
    if !scheme
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    Some(url.split_at(off + 3))
}

/// Length of the authority component of `rest` (the part after `://`):
/// up to the first `/`, `?`, or `#`, whichever comes first.
fn authority_len(rest: &str) -> usize {
    rest.find(['/', '?', '#']).unwrap_or(rest.len())
}

/// True when `key` names secret-bearing material. Matching is over the
/// lowercased (percent-decoded by callers where needed) key. Short key
/// words use delimited-substring semantics (R7-under): a short word
/// matches at any occurrence whose RIGHT edge is a boundary — end of
/// key, a non-alpha byte, or a plural `s`/`es` followed by one of those —
/// while the left edge is unconstrained. So `mykey`, `mypwd`,
/// `api-key`, and `x-key` redact (short words were previously
/// exact-only and echoed as compounds), `keys`/`pins` newly redact
/// (plural `s` does not break the boundary; safe direction), `passes`/
/// `door_passes`/`bypasses` redact (plural `es`; round-4 H4), and
/// `keyboard` still echoes (`key` followed by `b`). Descriptive
/// words keep plain substring matching (safe-direction
/// over-redaction): narrowing them
/// would flip secret-bearing compounds (`authorization`,
/// `authentication`, `sessionid`) to echo — a fail-open leak (a
/// JSON-quoted `{"authorization": "Basic xyz"}` redacts whole today).
/// Over-matching only over-redacts a value, which is the safe
/// direction.
fn is_sensitive_key(lower_key: &str) -> bool {
    const SHORT: &[&str] = &["key", "sig", "pin", "pwd", "otp", "pass"];
    if SHORT.iter().any(|w| short_word_matches(lower_key, w)) {
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
        // Round-5 W1: `pass` (SHORT) fails on alpha continuation, so
        // `passphrase` echoed; `passkey` listed explicitly (same
        // secret-bearing family) rather than relying on the `key` suffix.
        "passphrase",
        "passkey",
    ];
    SUBSTR.iter().any(|s| lower_key.contains(s))
}

/// True when `key` carries a LONG (unambiguous) descriptive word (R7-over):
/// [`is_sensitive_key`]'s substring set restricted to words of at least 5
/// bytes. Bare `key:value` full inputs are syntactically identical to scp
/// `host:path`, so the `:`-pair path collapses only on words too specific
/// to be a host label (`password`, `token`, `secret`, ...) while short
/// ambiguous words (`auth`, `key`, `jwt`, `pass`, ...) echo as host-like.
/// `=` pairs never take this path (`=` cannot be scp syntax).
fn is_strong_sensitive_key(lower_key: &str) -> bool {
    const LONG: &[&str] = &[
        "token",
        "secret",
        "password",
        "passwd",
        "credential",
        "private",
        "signature",
        "session",
        "bearer",
        "opaque",
        "apikey",
        "api_key",
        "access_key",
        "secret_key",
        "client_secret",
        "passcode",
        // Round-5 W1: keep `:`-pair parity with `password` (strong words
        // redact regardless of value shape).
        "passphrase",
        "passkey",
    ];
    LONG.iter().any(|s| lower_key.contains(s))
}

/// True when a `:`-pair value is itself credential-shaped (round-4 H3):
/// the same shape class as [`is_credential_username`] (known
/// PAT/secret markers, or a long mixed random-looking string). A
/// credential-shaped value disambiguates an otherwise scp-ambiguous
/// weak `key:value` pair toward redaction (`jwt:eyJ...`), while
/// unshaped values (`auth:repo`, `pass:hunter2`) still echo.
fn is_credential_shaped_value(value: &str) -> bool {
    is_credential_username(value)
}

/// True when a `key`/`separator`/`value` triple redacts its value
/// (round-4 H3, shared by the full-input, same-token, and scheme-path
/// pair passes so all channels agree; the spaced pass inlines the same
/// core rule with extra separation conditions — any gap, quote, `=`
/// separator, CLI flag, or escape disambiguates toward redaction — so
/// it does not call this): `=` pairs redact on a sensitive key alone
/// (`=` cannot be scp syntax); `:` pairs redact on a STRONG key, or on
/// a weak sensitive key with a credential-shaped value
/// ([`is_credential_shaped_value`]). A weak key with an unshaped value
/// (`auth:repo`) echoes as scp-like, and a non-sensitive key never
/// redacts whatever the value shape. An encoded colon separator
/// (`%3A`, either case — round-5 L2) counts as `:`; anything else
/// counts as `=`.
fn sensitive_pair_redacts(key: &str, separator: &str, value: &str) -> bool {
    let match_key = normalize_key_for_match(key);
    if match_key.is_empty() {
        return false;
    }
    if separator != ":" && !separator.eq_ignore_ascii_case("%3A") {
        return is_sensitive_key(&match_key);
    }
    is_strong_sensitive_key(&match_key)
        || (is_sensitive_key(&match_key) && is_credential_shaped_value(value))
}

/// Delimited-substring match of one SHORT key word (R7-under helper for
/// [`is_sensitive_key`]): any occurrence whose right edge is end of key,
/// a non-alpha byte, a plural `s` plus one of those, or a plural `es`
/// plus one of those (round-4 H4: `passes` → `pass`, so `door_passes`
/// and `bypasses` redact). The `es` arm requires the literal `s` after
/// the `e`, so naturally-s-ending words and non-plural `e` continuations
/// (`keyboard`) are unaffected. `lower_key` is already normalized (ASCII
/// alphanumerics plus `_`/`-`/`.`, lowercased), so byte indexing is safe.
fn short_word_matches(lower_key: &str, word: &str) -> bool {
    let bytes = lower_key.as_bytes();
    let needle = word.as_bytes();
    bytes
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .any(|(start, _)| {
            let after = &bytes[start + needle.len()..];
            match after.first() {
                None => true,
                Some(b) if !b.is_ascii_alphabetic() => true,
                Some(b's') => after.get(1).is_none_or(|b| !b.is_ascii_alphabetic()),
                Some(b'e') => {
                    after.get(1) == Some(&b's')
                        && after.get(2).is_none_or(|b| !b.is_ascii_alphabetic())
                }
                Some(_) => false,
            }
        })
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

/// Backslash-unescape `text` for detection purposes only (matching keys
/// through JSON-style `\uXXXX` / `\xXX` / single-character escapes such
/// as `"\u0073ecret"`). Unknown escapes drop the backslash and keep the
/// character; truncated escapes pass through literally. Output feeds
/// key matching only, never emission.
fn unescape_key_for_match(text: &str) -> String {
    if !text.contains('\\') {
        return text.to_string();
    }
    fn hex_val(byte: u8) -> Option<u32> {
        match byte {
            b'0'..=b'9' => Some((byte - b'0') as u32),
            b'a'..=b'f' => Some((byte - b'a' + 10) as u32),
            b'A'..=b'F' => Some((byte - b'A' + 10) as u32),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next == b'u' && i + 5 < bytes.len() {
                let mut value = 0u32;
                let mut ok = true;
                for k in 0..4 {
                    match hex_val(bytes[i + 2 + k]) {
                        Some(digit) => value = value * 16 + digit,
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    out.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
                    i += 6;
                    continue;
                }
            }
            if next == b'x' && i + 3 < bytes.len() {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                    out.push(char::from_u32(hi * 16 + lo).unwrap_or('\u{FFFD}'));
                    i += 4;
                    continue;
                }
            }
            match next {
                b'n' => out.push('\n'),
                b't' => out.push('\t'),
                b'r' => out.push('\r'),
                b'b' => out.push('\u{0008}'),
                b'f' => out.push('\u{000C}'),
                b'v' => out.push('\u{000B}'),
                b'\\' => out.push('\\'),
                b'"' => out.push('"'),
                b'\'' => out.push('\''),
                b'/' => out.push('/'),
                _ => {
                    if next.is_ascii() {
                        out.push(next as char);
                    } else {
                        out.push('\u{FFFD}');
                    }
                }
            }
            i += 2;
            continue;
        }
        if bytes[i].is_ascii() {
            out.push(bytes[i] as char);
        } else {
            out.push('\u{FFFD}');
        }
        i += 1;
    }
    out
}

/// Normalize a raw key for sensitivity matching (RETEST-4): unescape
/// then match. Percent-decoding and backslash-unescaping run in both
/// orders (a second pass catches `%5Cu...` and `\u0025...` alike), then
/// only match-significant characters survive, lowercased. Shared by the
/// query/fragment, same-token, and spaced/JSON/CLI pair passes so an
/// escaped key cannot evade one shape while another catches it.
fn normalize_key_for_match(raw_key: &str) -> String {
    let once = unescape_key_for_match(&percent_decode_for_match(raw_key));
    let twice = unescape_key_for_match(&percent_decode_for_match(&once));
    twice
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .collect::<String>()
        .to_lowercase()
}

/// Value-redact sensitive `key=value` pairs inside one query/fragment
/// section (`&`/`;` separated). Non-sensitive pairs pass through
/// untouched; a sensitive key's value becomes [`REDACTED`]. Valueless
/// (opaque, non-`key=value`) segments cannot be key-identified and
/// become [`REDACTED`] as well (RETEST-2); empty segments from `&&`/`;;`
/// runs pass through to preserve structure.
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
                let match_key = normalize_key_for_match(key);
                if is_sensitive_key(&match_key) {
                    out.push_str(key);
                    out.push('=');
                    out.push_str(REDACTED);
                } else {
                    out.push_str(pair);
                }
            }
            None => {
                if pair.is_empty() {
                    out.push_str(pair);
                } else {
                    out.push_str(REDACTED);
                }
            }
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

/// Scrub sensitive pairs from a scheme-URL path tail (round-4 H1):
/// every `/`-separated segment of every whitespace-separated token is
/// pair-checked under the shared [`sensitive_pair_redacts`] rule, so an
/// in-path pair (`/token=SECRET`) or a space-separated trailing pair
/// (`/owner/repo token=SECRET` on a full-input scheme shape) redacts
/// its value. Once a sensitive key matches, its value extends through
/// `/` to the end of the whitespace-delimited token (round-5 L1:
/// base64 values routinely contain `/`, and per-segment splitting
/// leaked the tail as a fresh segment) — subsequent segments
/// over-redact (safe direction), like the query pass. Normal path
/// segments carry no pair and round-trip byte-identical, as does every
/// whitespace gap. Callers strip `?`/`#` tails first (or route them to
/// [`scrub_query_fragment`]), so this sees the path only.
fn scrub_scheme_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut token_start: Option<usize> = None;
    let flush = |out: &mut String, token: &str| {
        let mut swallowed = false;
        for (index, segment) in token.split('/').enumerate() {
            if swallowed {
                continue;
            }
            if index > 0 {
                out.push('/');
            }
            match split_pair(segment) {
                Some((key, separator, value)) if sensitive_pair_redacts(key, separator, value) => {
                    out.push_str(key);
                    out.push_str(separator);
                    out.push_str(REDACTED);
                    swallowed = true;
                }
                _ => out.push_str(segment),
            }
        }
    };
    for (index, ch) in path.char_indices() {
        if ch.is_whitespace() {
            if let Some(start) = token_start.take() {
                flush(&mut out, &path[start..index]);
            }
            out.push(ch);
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }
    if let Some(start) = token_start.take() {
        flush(&mut out, &path[start..]);
    }
    out
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
    out.push_str(&scrub_scheme_path(path));
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
/// URL-form userinfo `user:pass@` becomes `user:<redacted>@`, except a
/// PAT-shaped username is itself credential material and becomes
/// `<redacted>:<redacted>@` (RETEST-1); a bare `token@` (no colon, the
/// common token-as-username shape) becomes `<redacted>@`. Sensitive
/// query/fragment parameter values become `<redacted>` while structure
/// is preserved; valueless (opaque, non-`key=value`) query/fragment
/// segments cannot be key-identified and become `<redacted>` as well.
/// In-path and space-separated trailing pairs scrub under the same
/// pair rule (round-4 H1); normal paths round-trip byte-identical.
/// Scp-like `user@host:path` has its user component redacted
/// (`<redacted>@host:path`): a token-as-username
/// (`secret@github.com:o/r`) is indistinguishable from the conventional
/// `git` login without an allowlist, so every scp-like user redacts
/// (RS-PRIV-10); scp syntax has no query semantics, so any `?`/`#` tail
/// on the path is opaque and stripped. A bare `user@host` (no colon,
/// no path) redacts its user exactly when it is credential-shaped
/// (RETEST-1); ordinary `user@example.com` logins still echo. Inputs
/// that cannot be represented safely (control characters, or an `@`
/// past the authority that signals malformed smuggled userinfo such as
/// `https://user:secret/ret@host/...`) collapse to [`REDACTED_URL`].
///
/// Remote, submodule, and catalog report fields must use
/// [`redact_remote_url`] instead: it additionally drops every
/// query/fragment tail (opaque `?next=...` values are not
/// key-identifiable), while this key-based scrub is for free text.
pub fn redact_credentials(url: &str) -> String {
    // R6b: leading whitespace trims at the sink entry, so a smuggled
    // `://` cannot hide behind it (` ext::... --url=https://...` takes
    // the transport path below, never the scheme path).
    let url = url.trim_start();
    // R6: the command-transport check runs BEFORE `split_valid_scheme` —
    // a command line can smuggle `://` (`ext::helper
    // --url=https://x/...`), and the scheme path would then echo it
    // verbatim. Scheme URLs never carry a `::` prefix, so this guard
    // only ever catches transports.
    if has_command_transport_prefix(url) {
        return REDACTED_URL.to_string();
    }
    let Some((scheme, rest)) = split_valid_scheme(url) else {
        return redact_scp_like(url)
            .or_else(|| redact_bare_user_host(url))
            .or_else(|| redact_colon_user_host(url))
            .unwrap_or_else(|| redact_unclassified_shape(url));
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
    let redacted_user = redact_userinfo(userinfo);
    format!("{scheme}{redacted_user}@{host}{scrubbed_tail}")
}

/// Strict fallback for remote/free-text URL shapes without `://`
/// (FIXREADY4 R: `ext::`/unknown-scheme/malformed must fail closed, never
/// echo verbatim). Shared by [`redact_remote_url`] (the persist choke
/// point: remote observations, catalog rows, report/snapshot/terminal
/// fields) and [`redact_credentials`] (free-text scrub), so both agree on
/// every shape:
///
/// - the [`REDACTED_URL`] placeholder echoes (idempotent re-scrub);
/// - control characters collapse (never emitted);
/// - `file:` URLs (any slash spelling) keep the path but drop every
///   `?`/`#` tail — file syntax has no query semantics, so tails are
///   opaque credential-shaped material; a `file:` head carrying `@`
///   (non-bare userinfo), a `scheme::` command transport, or
///   whitespace is malformed-as-URL and collapses exactly like the
///   general fallback (R1), never echoing verbatim;
/// - `scheme::command` transports (`ext::`, helpers) collapse: an
///   arbitrary command line is not redactable;
/// - a known URL scheme written without `://` (`https:/...`, `ssh:...`)
///   is malformed and collapses;
/// - a surviving `@` signals malformed smuggled userinfo and collapses,
///   except a bare `user@host` with a non-credential user (established
///   `user@example.com` echo contract);
/// - whitespace signals prose, not a URL: the input routes to the prose
///   scrubber ([`scrub_text`], pair redaction) instead of collapsing, so
///   `token=...` pairs still redact on prose-bearing lines (termsink
///   contract) — bare key-less tokens are unidentifiable there, the same
///   residual as all free text;
/// - anything else (plain `host:path`, local paths, `user@host`
///   non-credential logins handled by the caller) echoes with any `?`/`#`
///   tail stripped — opaque tails never persist, even on paths — except
///   a bare sensitive pair (`token=...`, `password:...`), which routes
///   through pair redaction instead of echoing (R7).
///
/// Scp-like and bare `user@host` shapes are classified by the caller
/// first; this sees only the remainder.
fn redact_unclassified_shape(url: &str) -> String {
    if url == REDACTED_URL {
        return REDACTED_URL.to_string();
    }
    if url.chars().any(|c| c.is_control()) {
        return REDACTED_URL.to_string();
    }
    let lower = url.to_ascii_lowercase();
    if lower == "file:" || lower.starts_with("file:") {
        let head = url.split(['?', '#']).next().unwrap_or(url);
        if head.len() <= "file:".len() {
            return REDACTED_URL.to_string();
        }
        // R1: a `file:` URL has no userinfo, command-transport, or
        // whitespace syntax — those shapes collapse exactly like the
        // general fallback below (the `@` promise in the doc comment
        // above covers this branch too), never echo verbatim. The
        // bare-`user@host` echo contract is preserved through the same
        // credential-aware check the caller applies. R1b: the `file:`
        // prefix is not part of the user — the user-shape analysis runs
        // on the remainder after it, so `file:token123@host` still
        // redacts like the general path while `file:user:pass@host`
        // userinfo-collapses instead of echoing verbatim.
        if head.contains('@') {
            let inner = &head["file:".len()..];
            if let Some(redacted) =
                redact_bare_user_host(inner).or_else(|| redact_colon_user_host(inner))
            {
                return redacted;
            }
            if bare_user_host(inner).is_some() {
                return head.to_string();
            }
            return REDACTED_URL.to_string();
        }
        if has_command_transport_prefix(&head["file:".len()..]) {
            return REDACTED_URL.to_string();
        }
        if head.chars().any(|c| c.is_whitespace()) {
            return REDACTED_URL.to_string();
        }
        return head.to_string();
    }
    if has_command_transport_prefix(url) {
        return REDACTED_URL.to_string();
    }
    if has_malformed_known_scheme_prefix(&lower) {
        return REDACTED_URL.to_string();
    }
    if url.contains('@') {
        // A bare `user@host` with a non-credential user echoes
        // (established `user@example.com` contract — the caller only
        // reaches here for exactly that remainder); anything else
        // carrying `@` is malformed smuggled userinfo and collapses.
        let head = url.split(['?', '#']).next().unwrap_or(url);
        if bare_user_host(head).is_some() {
            return head.to_string();
        }
        return REDACTED_URL.to_string();
    }
    if url.chars().any(|c| c.is_whitespace()) {
        return scrub_text(url);
    }
    // R6b: every caller excluded valid `scheme://` URLs before reaching
    // here, so a surviving `://` in a nospace input is an INVALID scheme
    // smuggled past the validated split (`9foo://token=SECRET`) — it
    // cannot be pair-scrubbed (the key check below would misread it),
    // so malformed input collapses, never echoes verbatim. Inputs WITH
    // whitespace took the scrub branch above instead.
    if url.contains("://") {
        return REDACTED_URL.to_string();
    }
    let head = url.split(['?', '#']).next().unwrap_or(url);
    if head.is_empty() {
        return REDACTED_URL.to_string();
    }
    // R7: a bare nospace sensitive pair (`token=...`, `password:...`)
    // routes through pair redaction — it never reaches the whitespace
    // prose branch above, so without this it would echo verbatim. No
    // length cap here (unlike the free-text token pass): a remote is
    // one value, and fail-closed has no size threshold.
    //
    // R7-over: bare-pair redaction does not fire on path-like or
    // scp-like shapes — a `/` in the key is path-like
    // (`/tmp/token=bar` survives; the value may still carry `/`, so
    // `token=a/b` keeps collapsing), and a `:`-separated pair collapses
    // only on a LONG (unambiguous) key word or a credential-shaped
    // value (round-4 H3: `auth:repo` is a valid user-less scp
    // `host:path` and survives, while `password:hunter2` still
    // collapses and `jwt:eyJ...` newly collapses). The `/`-key guard
    // is full-input-only: free-text pairs with `/` still redact (the
    // terminal path-display contract in `tests/fail_termsink.rs`
    // requires it).
    if let Some((key, separator, value)) = split_pair(head) {
        if !key.contains('/') && sensitive_pair_redacts(key, separator, value) {
            return format!("{key}{separator}{REDACTED}");
        }
    }
    head.to_string()
}

/// True when `url` starts with a `scheme::` command-transport prefix
/// (`ext::`, helper `name::address`): `scheme` is ASCII alphanumeric
/// followed by ASCII alphanumerics/`+`/`-`/`.`, then a literal `::`.
/// The first character is deliberately NOT alpha-restricted (R5): git
/// helper names (`git-remote-<name>`) are not alpha-restricted, so
/// `9foo::...` is a transport, not a path. Single-colon shapes
/// (`host:path`, scp-like) never match; neither do bracketed (`[::1]`)
/// or leading-colon inputs.
fn has_command_transport_prefix(url: &str) -> bool {
    let bytes = url.as_bytes();
    let mut i = 0;
    if bytes.first().is_none_or(|b| !b.is_ascii_alphanumeric()) {
        return false;
    }
    i += 1;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'+' | b'-' | b'.'))
    {
        i += 1;
    }
    bytes.len() >= i + 2 && bytes[i] == b':' && bytes[i + 1] == b':'
}

/// True when the lowercased `url` starts with a known URL scheme name
/// followed by a single `:` but the URL carries no `://` (the caller only
/// reaches the fallback when `://` is absent): `https:/...`, `ssh:...`,
/// `git:...`, `ftp:...`, `sftp:...`, `ftps:...`, `ext:...`, `helper:...`.
/// Unknown prefixes (`host:path`, drive letters, prose) are not schemes
/// and keep echoing under the tail-stripping rule.
fn has_malformed_known_scheme_prefix(lower_url: &str) -> bool {
    const SCHEMES: &[&str] = &[
        "https:", "http:", "ssh:", "git:", "ftp:", "ftps:", "sftp:", "ext:", "helper:",
    ];
    SCHEMES.iter().any(|s| lower_url.starts_with(s))
}

/// Redact one `userinfo` authority component: `user:pass@` becomes
/// `user:<redacted>@`, except a PAT-shaped username is itself
/// credential material and yields `<redacted>:<redacted>@` (RETEST-1);
/// a bare `token@` (no colon) becomes `<redacted>@`. Shared by
/// [`redact_credentials`] and [`redact_remote_url`] so every
/// remote/submodule/catalog report path treats usernames identically.
fn redact_userinfo(userinfo: &str) -> String {
    match userinfo.find(':') {
        Some(i) => {
            let user = &userinfo[..i];
            if is_credential_username(user) {
                format!("{REDACTED}:{REDACTED}")
            } else {
                format!("{user}:{REDACTED}")
            }
        }
        None => REDACTED.to_string(),
    }
}

/// True when a URL username is itself credential-shaped (RETEST-1) and
/// must never be emitted intact: known PAT/OAuth/secret markers, or a
/// long mixed random-looking string (a marker-less token-as-username).
/// Matching runs over the percent-decoded lowercase form; over-matching
/// only over-redacts a display string, which is the safe direction.
fn is_credential_username(user: &str) -> bool {
    let decoded = percent_decode_for_match(user);
    if decoded.is_empty() {
        return false;
    }
    let lower = decoded.to_lowercase();
    const MARKERS: &[&str] = &[
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "glpat-",
        "gldt-",
        "xoxa-",
        "xoxb-",
        "xoxp-",
        "xoxs-",
        "xoxo-",
        "x-access-token",
        "oauth",
        "token",
        "secret",
        "passwd",
        "password",
        "passcode",
        // Round-5 W1: sibling parity — a username carrying a
        // passphrase/passkey word is credential-shaped like `password`.
        "passphrase",
        "passkey",
        "bearer",
        "jwt",
        "pat_",
        "pat-",
        "pat",
        "private",
        "credential",
        "auth",
        "apikey",
        "api_key",
        "api-key",
        "access_key",
        "secret_key",
        "client_secret",
        "session",
        "signature",
        "akia",
        "sk-live",
        "sk-test",
        "sk_live_",
        "rk_live_",
    ];
    if MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    // Marker-less fallback: conventional logins are short and rarely mix
    // letters with digits at length; a long mixed (or very long)
    // username is token-shaped.
    let has_letter = lower.bytes().any(|b| b.is_ascii_alphabetic());
    let has_digit = lower.bytes().any(|b| b.is_ascii_digit());
    if decoded.len() >= 16 && has_letter && has_digit {
        return true;
    }
    decoded.len() >= 32
}

/// Display/persist-safe form of a repository URL for remote, submodule,
/// and catalog report construction paths (RETEST-2): userinfo redacts
/// exactly as in [`redact_credentials`] (PAT-shaped usernames included),
/// and any query/fragment tail is dropped entirely — opaque values such
/// as `?next=...` are not key-identifiable, so key-based scrubbing
/// cannot make them safe to persist. In-path and space-separated
/// trailing pairs scrub under the shared pair rule (round-4 H1) instead
/// of persisting verbatim. Scp-like `user@host:path` likewise
/// loses any `?`/`#` tail, as does a bare `user@host` (whose user
/// redacts exactly when credential-shaped, RETEST-1). `ext::`/helper
/// transports, unknown-scheme spellings, and malformed input collapse to
/// [`REDACTED_URL`] (FIXREADY4 R: fail closed, never verbatim); `file:`
/// URLs keep the path with tails stripped.
pub fn redact_remote_url(url: &str) -> String {
    // R6b: leading whitespace trims at the sink entry (this is the
    // persist/catalog choke point, so the trim covers
    // `redacted_remote_bytes` too): a smuggled `://` cannot hide behind
    // it, and a validated scheme always starts at offset 0.
    let url = url.trim_start();
    // R6: same ordering as [`redact_credentials`] — a `://`-smuggling
    // command line collapses here, never through the scheme path.
    if has_command_transport_prefix(url) {
        return REDACTED_URL.to_string();
    }
    let Some((scheme, rest)) = split_valid_scheme(url) else {
        return redact_scp_like(url)
            .or_else(|| redact_bare_user_host(url))
            .or_else(|| redact_colon_user_host(url))
            .unwrap_or_else(|| redact_unclassified_shape(url));
    };
    if url.chars().any(|c| c.is_control()) {
        return REDACTED_URL.to_string();
    }
    let end = authority_len(rest);
    let (authority, tail) = rest.split_at(end);
    let path = tail.split(['?', '#']).next().unwrap_or(tail);
    if path.contains('@') {
        return REDACTED_URL.to_string();
    }
    // Round-4 H1: the scheme path is pair-scrubbed (in-path and
    // space-separated trailing pairs), never echoed verbatim.
    let path = scrub_scheme_path(path);
    let Some(at) = authority.rfind('@') else {
        return format!("{scheme}{authority}{path}");
    };
    let userinfo = &authority[..at];
    let host = &authority[at + 1..];
    if userinfo.is_empty() {
        return format!("{scheme}{authority}{path}");
    }
    let redacted_user = redact_userinfo(userinfo);
    format!("{scheme}{redacted_user}@{host}{path}")
}

/// Redact the user component of a scp-like `user@host:path` shape, if
/// `url` is one. Returns `None` for anything else (emails, bare
/// `user@host`, paths, prose): the shape requires a non-empty single-token
/// user, a non-empty host with no `/`, and a `host:path` remainder.
/// Control characters fail closed to [`REDACTED_URL`], mirroring scheme
/// URLs. Scp syntax has no query semantics, so any `?`/`#` tail on the
/// path is opaque and stripped (RETEST-2). Used by
/// [`redact_credentials`], [`redact_remote_url`], and the free-text scp
/// pass of [`scrub_text`] (RS-PRIV-10).
fn redact_scp_like(url: &str) -> Option<String> {
    let rest = scp_host_path(url)?;
    if rest.chars().any(|c| c.is_control()) {
        return Some(REDACTED_URL.to_string());
    }
    let head = rest.split(['?', '#']).next().unwrap_or(rest);
    Some(format!("{REDACTED}@{head}"))
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

/// Split a bare `user@host` shape (no scheme, no colon, no path) into
/// `(user, host)`, if `text` is one. User rules mirror
/// [`scp_host_path`] (non-empty single token, no `/`); the host is
/// non-empty and free of whitespace, controls, `/`, `:`, `@`, `?`, and
/// `#` (a colon makes it scp-like, handled by [`redact_scp_like`]
/// first; tails are stripped by the caller before this check). Shared
/// by [`redact_credentials`], [`redact_remote_url`], and the free-text
/// scp pass of [`scrub_text`] so a credential-shaped bare username
/// (RETEST-1) never echoes intact, while ordinary `user@host` logins
/// (emails) still echo.
fn bare_user_host(text: &str) -> Option<(&str, &str)> {
    if text.contains("://") {
        return None;
    }
    let at = text.find('@')?;
    let (user, rest) = text.split_at(at);
    let host = &rest[1..];
    // R1b: a colon in the user is USERINFO (`user:pass@`), never a bare
    // login — the doc comment always promised no-colon; the check now
    // enforces it. Colon shapes route to [`redact_colon_user_host`].
    if user.is_empty()
        || user
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '/' || c == ':')
    {
        return None;
    }
    if host.is_empty()
        || host.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '/' | ':' | '@' | '?' | '#')
        })
    {
        return None;
    }
    Some((user, host))
}

/// Byte offset of the first percent-encoded colon (`%3A`, either
/// case) in a bare `user@host` user, if any (round-4 H5). `%` is ASCII,
/// so the offset is a char boundary.
fn encoded_colon_pos(user: &str) -> Option<usize> {
    user.as_bytes()
        .windows(3)
        .position(|w| w[0] == b'%' && w[1] == b'3' && matches!(w[2], b'a' | b'A'))
}

/// Redact a bare `user@host` shape, if `text` is one. Returns `None`
/// for anything else (emails stay callers' echo), and for a bare login
/// whose user is NOT credential-shaped (the `user@example.com`
/// contract). A credential-shaped user (RETEST-1) yields
/// `<redacted>@host`; any `?`/`#` tail is opaque (bare syntax has no
/// query semantics) and stripped exactly like the scp pass, even for
/// non-credential users. A leading `file:` prefix is not part of the
/// user (R1b): analysis runs on the remainder after it, so
/// `file:token123@host` still yields `<redacted>@host`. An encoded
/// colon in the user (round-4 H5) is smuggled userinfo, not a bare
/// login — the password collapses under userinfo semantics
/// (`user:<redacted>@host`, both sides redacted when the user is
/// credential-shaped), mirroring [`redact_colon_user_host`]. Used by
/// [`redact_credentials`], [`redact_remote_url`], and the free-text scp
/// pass of [`scrub_text`].
fn redact_bare_user_host(text: &str) -> Option<String> {
    let untailed = text.split(['?', '#']).next().unwrap_or(text);
    let head = match untailed.get(.."file:".len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case("file:") => &untailed["file:".len()..],
        _ => untailed,
    };
    let (user, host) = bare_user_host(head)?;
    // Round-4 H5: an encoded colon is USERINFO (`user%3Apass@`), never
    // a bare login — the password collapses regardless of shape, and
    // the raw (still-encoded) user prefix emits, so decoded bytes never
    // enter the output. `bare_user_host` already validated the user as
    // a single token, so the raw prefix is safe to emit.
    if let Some(colon) = encoded_colon_pos(user) {
        let raw_user = &user[..colon];
        let redacted = if is_credential_username(raw_user) {
            format!("{REDACTED}:{REDACTED}")
        } else {
            format!("{raw_user}:{REDACTED}")
        };
        return Some(format!("{redacted}@{host}"));
    }
    if !is_credential_username(user) {
        return if untailed.len() != text.len() {
            Some(untailed.to_string())
        } else {
            None
        };
    }
    Some(format!("{REDACTED}@{host}"))
}

/// Redact a bare `user:pass@host` shape (R1b: a colon in the user means
/// USERINFO, not a bare login), if `text` is one. The password redacts
/// regardless of credential-shapedness (`user:<redacted>@host`); a
/// credential-shaped user yields `<redacted>:<redacted>@host`
/// (RETEST-1) via the shared [`redact_userinfo`]. Any `?`/`#` tail
/// strips exactly like the bare pass (bare syntax has no query
/// semantics), and a leading `file:` prefix is not part of the user —
/// analysis runs on the remainder after it, so `file:user:pass@host`
/// yields `user:<redacted>@host` (the general chain reaches here
/// before the `file:` branch). Returns `None` for anything else.
/// Chained after [`redact_bare_user_host`] by the redact pair and the
/// free-text scp pass, so `user:password@host` never echoes verbatim
/// anywhere.
fn redact_colon_user_host(text: &str) -> Option<String> {
    let head = text.split(['?', '#']).next().unwrap_or(text);
    if head.contains("://") {
        return None;
    }
    let head = match head.get(.."file:".len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case("file:") => &head["file:".len()..],
        _ => head,
    };
    let at = head.find('@')?;
    let (userinfo, rest) = head.split_at(at);
    let host = &rest[1..];
    if userinfo.is_empty()
        || !userinfo.contains(':')
        || userinfo
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '/')
    {
        return None;
    }
    if host.is_empty()
        || host.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '/' | ':' | '@' | '?' | '#')
        })
    {
        return None;
    }
    Some(format!("{}@{host}", redact_userinfo(userinfo)))
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
/// (defense-in-depth behind [`must_reject_target`]); anything else fails
/// closed through the shared strict fallback (`ext::`/helper transports,
/// malformed schemes, smuggled userinfo, whitespace, and tails collapse
/// to [`REDACTED_URL`], FIXREADY4 R). Plain targets round-trip unchanged
/// (modulo surrounding whitespace).
pub fn sanitize_target_url(url: &str) -> String {
    let trimmed = url.trim();
    if let Some(rest) = scp_host_path(trimmed) {
        if rest.chars().any(|c| c.is_control()) {
            return REDACTED_URL.to_string();
        }
        // Defense-in-depth behind [`must_reject_target`]: scp-like tails
        // strip exactly like scheme tails, so a direct call can never
        // persist an opaque `host:path?...` value.
        let head = rest.split(['?', '#']).next().unwrap_or(rest);
        return format!("git@{head}");
    }
    // R6 (same ordering bug as the redact pair): a `://`-smuggling
    // command-line target collapses, never through the scheme path.
    // R6b: the scheme split is validated, like the redact pair.
    if has_command_transport_prefix(trimmed) {
        return REDACTED_URL.to_string();
    }
    let Some((scheme, rest)) = split_valid_scheme(trimmed) else {
        return redact_unclassified_shape(trimmed);
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
    // Round-4 H1: the scheme path is pair-scrubbed (in-path and
    // space-separated trailing pairs), never echoed verbatim.
    let path = scrub_scheme_path(path);
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
///
/// Fails closed (RETEST-3): malformed or unparseable input — empty,
/// whitespace/control-bearing, or neither `scheme://` nor scp-like
/// shaped — collapses to [`REDACTED_URL`] instead of echoing. Redact or
/// refuse; never echo.
pub fn redact_target_for_display(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return REDACTED_URL.to_string();
    }
    let shaped = split_scheme(trimmed).is_some() || scp_host_path(trimmed).is_some();
    if !shaped {
        return REDACTED_URL.to_string();
    }
    let head = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    let redacted = redact_credentials(head);
    // `redact_credentials` echoes non-URL input unchanged by design; only
    // URL-shaped output (or the fail-closed placeholder) may pass, and it
    // must carry no smuggled whitespace.
    if redacted
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        return REDACTED_URL.to_string();
    }
    let out_shaped = redacted == REDACTED_URL
        || split_scheme(&redacted).is_some()
        || scp_host_path(&redacted).is_some();
    if !out_shaped {
        return REDACTED_URL.to_string();
    }
    scrub_text(&redacted)
}

/// Scrub free text (evidence lines, error strings, reasons) for report
/// emission: `Authorization: Bearer <token>` credentials redact first
/// (the token follows the scheme word, not the key), then every embedded
/// `scheme://...` token, every `scheme::` command-transport token, every
/// scp-like `user@host:path` token, and every bare `user@host` token with
/// a credential-shaped user is passed through [`redact_credentials`], and
/// sensitive pairs — same-token `key=value`/`key:value` plus spaced, JSON,
/// CLI-flag, and multiline shapes — have their values replaced with
/// [`REDACTED`]. Ordinary prose passes through unchanged.
pub fn scrub_text(text: &str) -> String {
    let scrubbed_bearer = scrub_bearer_tokens(text);
    let scrubbed_urls = scrub_embedded_urls(&scrubbed_bearer);
    let scrubbed_ext = scrub_embedded_command_transports(&scrubbed_urls);
    let scrubbed_scp = scrub_embedded_scp(&scrubbed_ext);
    let scrubbed_pairs = scrub_secret_pairs(&scrubbed_scp);
    scrub_spaced_pairs(&scrubbed_pairs)
}

/// True for the unified scrub gap class (round-3 R3b): C-`isspace`
/// semantics — ASCII whitespace PLUS vertical tab. Rust's
/// `is_ascii_whitespace` excludes `\x0b` (unlike C), so ad-hoc gap sets
/// kept disagreeing: the `Bearer` gap missed `\v\f` while the token
/// scan stopped at `\f` but ran through `\v`. This class covers the
/// `Bearer` inter-token gap and the spaced-pair value gap; run ends use
/// [`is_scrub_blank_byte`], and the remaining scans keep their own
/// classes (ASCII-whitespace URL token ends, Unicode-whitespace scp and
/// pair splits, space/tab-only key-separator gaps; sweep gaps add
/// vertical-tab/form-feed — only a line break stops the sweep).
fn is_scrub_gap_byte(byte: u8) -> bool {
    byte.is_ascii_whitespace() || byte == b'\x0b'
}

/// True for the blank bytes that END a scrubbed token/value run
/// (round-3 R3b): space, tab, CR, LF. Vertical-tab and form-feed do
/// NOT end runs (fail closed: a token split by vertical-tab redacts
/// whole instead of leaking its tail); they only separate as gap bytes (see
/// [`is_scrub_gap_byte`], which the gap skips consume first).
fn is_scrub_blank_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// Value-redact `Bearer <token>` credentials in free text (FIXREADY4 R):
/// the `Authorization: Bearer <token>` header shape carries the secret
/// one token AFTER the key, so key-based pair scrubbing would redact only
/// the `Bearer` scheme word and orphan the token. A case-insensitive
/// `bearer` word (ASCII word-boundary delimited) followed by blank space
/// (spaces, tabs, newlines, vertical tabs, and form feeds — round-2
/// R3b plus round-3 R3b, so a folded `Bearer\n<token>` header cannot
/// orphan the token) has its next token replaced with [`REDACTED`].
/// The redaction runs through the END of the token run no matter its
/// length (R3a: no cap, so an over-long token cannot leak a tail). Runs
/// before every other pass so
/// later key scrubbing still redacts the scheme word itself
/// (`Authorization: <redacted> <redacted>`). Already-redacted (`<...>`)
/// and missing values pass through (idempotent). Documented
/// over-redaction (safe direction): a prose `bearer` at a line end
/// redacts the next line's first token.
fn scrub_bearer_tokens(text: &str) -> String {
    const WORD: &[u8] = b"bearer";
    fn is_word_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
    }
    fn is_token_byte(byte: u8) -> bool {
        !is_scrub_blank_byte(byte)
            && !matches!(
                byte,
                b',' | b';' | b'"' | b'\'' | b'(' | b')' | b'[' | b']' | b'{' | b'}' | b'<' | b'>'
            )
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let head = &bytes[i..];
        let is_match = head.len() > WORD.len()
            && head[..WORD.len()].eq_ignore_ascii_case(WORD)
            && (i == 0 || !is_word_byte(bytes[i - 1]))
            && is_scrub_gap_byte(head[WORD.len()]);
        if !is_match {
            let width = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&text[i..i + width]);
            i += width;
            continue;
        }
        let mut j = i + WORD.len();
        while j < bytes.len() && is_scrub_gap_byte(bytes[j]) {
            j += 1;
        }
        let mut k = j;
        // R3a: no length cap — the run extends through the end of the
        // token, so an over-long token redacts whole instead of leaking
        // a tail. The scan is linear and allocation-free.
        while k < bytes.len() && is_token_byte(bytes[k]) {
            k += 1;
        }
        while k > j && !text.is_char_boundary(k) {
            k -= 1;
        }
        if k == j {
            out.push_str(&text[i..j]);
            i = j;
            continue;
        }
        out.push_str(&text[i..j]);
        out.push_str(REDACTED);
        i = k;
    }
    out
}

/// Redact embedded `scheme::` command-transport tokens inside free text
/// (FIXREADY4 R sink-side re-validation, generalized by R2): a command
/// line is not redactable piece-wise, so the whole whitespace-delimited
/// token collapses to [`REDACTED_URL`], mirroring the constructor choke
/// point. Matching is word-boundary-aware with the constructor charset
/// ([`has_command_transport_prefix`], R5-relaxed): a boundary-delimited
/// run of scheme characters followed by a literal `::` — so helper
/// `my-helper::...` and `preext::...` tokens collapse, not just `ext::`.
///
/// The `ext` scheme itself always collapses (established contract); any
/// OTHER scheme collapses only when its post-`::` run carries
/// command/secret-shaped material (an ASCII uppercase letter or digit),
/// so lowercase prose and Rust paths (`text::prose`, `next::item`,
/// `use std::fmt`) keep echoing per the established pin. Residual (R2):
/// an all-lowercase helper address (`my-helper::secret`) echoes — the
/// prose echo contract forces the asymmetry, and the constructor still
/// collapses such remotes at observation. Token ends mirror
/// [`scrub_embedded_urls`] delimiters.
///
/// After a collapse, the same-span remainder of the line is swept for
/// credential-shaped tokens (R2b): each following token that matches
/// [`is_credential_username`] (a marked/shaped secret such as
/// `ext::ssh ghp_XXXX`) redacts too, SKIPPING past non-credential
/// tokens (round-4 H2: stopping at the first innocent flag leaked a
/// marked secret behind it) out to the line end. Only
/// credential-SHAPED tokens redact, so the longer reach stays in the
/// safe direction. The sweep is strictly line-local (gaps are
/// spaces/tabs/vertical-tab/form-feed — only a line break ends the
/// span), so the `ext` always-collapse
/// (`use ext::fmt`) never extends past its own token, and bare
/// UNMARKED trailing secrets stay the documented free-text residual
/// (unidentifiable by construction).
fn scrub_embedded_command_transports(text: &str) -> String {
    fn is_word_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
    }
    fn is_scheme_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
    }
    fn token_end(bytes: &[u8], mut k: usize) -> usize {
        while k < bytes.len() {
            let byte = bytes[k];
            // Round-3 R3b: blanks end the token; vertical-tab/form-feed
            // absorb into it (fail closed: a collapsed command line
            // cannot leak a split tail).
            if is_scrub_blank_byte(byte)
                || matches!(byte, b'"' | b'\'' | b'<' | b'>' | b'`' | b'(' | b')')
            {
                break;
            }
            k += 1;
        }
        k
    }
    /// Sweep the same-span remainder of the line after a collapse at
    /// `end` (R2b): scan every following gap-separated token (spaces,
    /// tabs, vertical-tab, form-feed) out to the line break; each
    /// credential-shaped one emits the gap span
    /// plus [`REDACTED`] (preserving surrounding punctuation, mirroring
    /// [`scrub_embedded_scp`]), while non-credential tokens are SKIPPED
    /// (round-4 H2) — the scan cursor advances past them but the emit
    /// frontier `end` stays, so skipped text re-emits verbatim either
    /// inside the next redaction's gap span or, at the line break, by
    /// the main loop continuing from the returned `end`. Only the line
    /// break and text end stop the sweep. All stops are ASCII, so every
    /// slice is a char boundary.
    fn sweep_span_credentials(text: &str, bytes: &[u8], out: &mut String, mut end: usize) -> usize {
        let mut scan = end;
        loop {
            let mut j = scan;
            // Round-5 L3: vertical-tab/form-feed are gaps (skipped),
            // like the gap class and token-scan absorption — only a
            // line break or text end stops the sweep.
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\x0b' | b'\x0c') {
                j += 1;
            }
            if j >= bytes.len() || matches!(bytes[j], b'\r' | b'\n') {
                return end;
            }
            // Whitespace-only token end (unlike the transport
            // `token_end` above, quotes stay INSIDE the token so
            // `'ghp_XXX'` still redacts through the punct trim below;
            // vertical-tab/form-feed absorb, fail closed).
            let mut k = j;
            while k < bytes.len() && !is_scrub_blank_byte(bytes[k]) {
                k += 1;
            }
            if k == j {
                return end;
            }
            let token = &text[j..k];
            let core = token.trim_start_matches(['\'', '"', '`', '(', '[', '<']);
            let stripped = core
                .trim_end_matches(['\'', '"', '`', '.', ',', ';', ':', '!', '?', ')', ']', '>']);
            if stripped.is_empty() || !is_credential_username(stripped) {
                scan = k;
                continue;
            }
            let lead = token.len()
                - token
                    .trim_start_matches(['\'', '"', '`', '(', '[', '<'])
                    .len();
            out.push_str(&text[end..j]);
            out.push_str(&token[..lead]);
            out.push_str(REDACTED);
            out.push_str(&token[lead + stripped.len()..]);
            end = k;
            scan = k;
        }
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let at_candidate =
            bytes[i].is_ascii_alphanumeric() && (i == 0 || !is_word_byte(bytes[i - 1]));
        let mut j = i + 1;
        while at_candidate && j < bytes.len() && is_scheme_byte(bytes[j]) {
            j += 1;
        }
        let is_match =
            at_candidate && j + 1 < bytes.len() && bytes[j] == b':' && bytes[j + 1] == b':';
        if !is_match {
            let width = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&text[i..i + width]);
            i += width;
            continue;
        }
        let end = token_end(bytes, j + 2);
        let scheme = &text[i..j];
        // `end` only ever stops at ASCII delimiters, so both slices are
        // char boundaries.
        let rest = &text[j + 2..end];
        let command_shaped = rest
            .bytes()
            .any(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
        if scheme.eq_ignore_ascii_case("ext") || command_shaped {
            out.push_str(REDACTED_URL);
            i = sweep_span_credentials(text, bytes, &mut out, end);
        } else {
            let width = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&text[i..i + width]);
            i += width;
        }
    }
    out
}

/// Redact embedded scp-like `user@host:path` tokens inside free text
/// (RS-PRIV-10), plus bare `user@host` tokens whose user is
/// credential-shaped (RETEST-1), plus bare `user:pass@host` userinfo
/// tokens (R1b: the password always redacts). Tokens are
/// whitespace-delimited; surrounding quotes and trailing sentence
/// punctuation are preserved, the user component is redacted. Scheme
/// URLs were handled by the earlier pass and are skipped here.
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
        match redact_scp_like(stripped)
            .or_else(|| redact_bare_user_host(stripped))
            .or_else(|| redact_colon_user_host(stripped))
        {
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
/// R7-over, like the full-input path: a `:`-separated pair needs a LONG
/// (unambiguous) key word or a credential-shaped value (round-4 H3) —
/// `auth:repo` echoes as scp-like while `password:hunter2` still
/// collapses and `jwt:eyJ...` newly collapses. Pairs with `/` in the
/// key still redact here (the terminal path-display contract in
/// `tests/fail_termsink.rs` requires it); only the full-input path
/// treats a `/`-key as path-like.
fn scrub_pair_token(token: &str) -> Option<String> {
    // Skip anything already URL-shaped (handled by the URL pass) and
    // anything too long to be a `key=value` pair.
    if token.contains("://") || token.len() > 1024 {
        return None;
    }
    let (key, separator, value) = split_pair(token)?;
    if !sensitive_pair_redacts(key, separator, value) {
        return None;
    }
    Some(format!("{key}{separator}{REDACTED}"))
}

/// Split a `key=value` or `key: value` token. A bare `C:\...`-style drive
/// prefix is not a pair (single-letter key with no `=`). Round-5 L2:
/// percent-encoded separators (`%3D`/`%3A`, either case) split like
/// their literal forms — keys already match through `%XX`, so an
/// encoded separator must not smuggle a pair past the split. The
/// `=`-family keeps precedence over the `:`-family (as before); within
/// a family the earliest occurrence wins, and the returned separator
/// preserves the original spelling for byte-identical re-emission.
fn split_pair(token: &str) -> Option<(&str, &str, &str)> {
    fn find_family(token: &str, literal: u8, encoded: u8) -> Option<(usize, usize)> {
        let bytes = token.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == literal {
                return Some((i, 1));
            }
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && bytes[i + 1] == b'3'
                && bytes[i + 2].eq_ignore_ascii_case(&encoded)
            {
                return Some((i, 3));
            }
            i += 1;
        }
        None
    }
    if let Some((pos, len)) = find_family(token, b'=', b'D') {
        let key = &token[..pos];
        let value = &token[pos + len..];
        if !key.is_empty() && !value.is_empty() {
            return Some((key, &token[pos..pos + len], value));
        }
        return None;
    }
    if let Some((pos, len)) = find_family(token, b':', b'A') {
        let key = &token[..pos];
        let value = &token[pos + len..];
        if key.len() > 1 && !value.is_empty() {
            return Some((key, &token[pos..pos + len], value));
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
        let Some((key_end, clean_len, cli_flag, strong)) = match_key_at(text, i) else {
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
        // Gap between separator (or flag) and value: the unified gap
        // class (whitespace including newlines, so multiline values
        // redact — round-3 R3b).
        let mut k = j;
        while k < bytes.len() && is_scrub_gap_byte(bytes[k]) {
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
        // R7-over: an ADJACENT weak `key:value` (`auth:repo`) is scp
        // `host:path`, not a pair — echo it exactly like the
        // same-token path. Any gap, quote, `=` separator, CLI flag,
        // backslash escape, strong key word, or credential-shaped
        // value (round-4 H3: `jwt:eyJ...`) disambiguates toward a
        // pair and still redacts.
        let first = bytes[i];
        if !strong
            && !cli_flag
            && has_sep
            && bytes[j - 1] == b':'
            && j == key_end + 1
            && k == j
            && quote.is_none()
            && !matches!(first, b'"' | b'\'' | b'\\')
            && !is_credential_shaped_value(&text[val_start..val_end])
        {
            let width = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&text[i..i + width]);
            i += width;
            continue;
        }
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

/// Match a sensitive key starting at byte `i`: bare (`password`),
/// quoted (`"password"`), CLI-flag (`--password`), or backslash-escaped
/// (`\u0073ecret`) form. Returns the byte end of the key, the
/// normalized-key length (for the drive-letter guard), whether the
/// key is a `--flag`, and whether the key is STRONG (R7-over: a long
/// unambiguous word — adjacent weak `key:value` echoes as scp-like).
/// The match must start at a key boundary (start of text or a non-key
/// character before `i`) and the raw key is capped at 128 bytes.
fn match_key_at(text: &str, i: usize) -> Option<(usize, usize, bool, bool)> {
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
    } else if first.is_ascii_alphabetic() || first == b'_' || first == b'-' || first == b'\\' {
        let mut j = i;
        // Backslashes scan as key characters so `\uXXXX`-escaped key
        // starts unescape-then-match instead of evading (RETEST-4);
        // normalization resolves them before the sensitivity check.
        while j < bytes.len()
            && (bytes[j].is_ascii_alphanumeric() || matches!(bytes[j], b'_' | b'-' | b'.' | b'\\'))
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
    let match_key = normalize_key_for_match(raw);
    if match_key.is_empty() || !is_sensitive_key(&match_key) {
        return None;
    }
    let strong = is_strong_sensitive_key(&match_key);
    Some((key_end, match_key.len(), raw.starts_with("--"), strong))
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
    // Round-3 R3b: the run absorbs vertical-tab/form-feed (fail closed:
    // a split value redacts whole instead of leaking its tail) and
    // breaks only on blanks and structural delimiters.
    while j < bytes.len()
        && !is_scrub_blank_byte(bytes[j])
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
