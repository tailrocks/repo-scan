//! Fetch-refspec safety inspection (goal Step 11).
//!
//! Before `--fetch` runs `git fetch` for a remote, the remote's
//! effective fetch refspecs are examined: any mapping that can write to
//! local branch tips (`refs/heads/*`) makes the refresh `unsupported`
//! instead of executed. Pure functions over refspec text; the fetch
//! phase reads the effective values through `git config` and applies
//! [`inspect_remote_fetch`].
//!
//! Fail closed: `mirror = true`, unparseable values, and degenerate
//! forms are all `unsupported`, never executed. Refspec text carries
//! ref patterns only (never URLs or credentials), so verdict reasons
//! may echo the offending value.

/// Local branch-tip namespace a fetch must never write.
const HEADS_PREFIX: &str = "refs/heads/";

/// One parsed `remote.<name>.fetch` value: `[+][^]<src>[:<dst>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRefspec {
    /// `+` force-update flag.
    pub force: bool,
    /// `^` negative (exclusion) flag. Negative refspecs never write.
    pub negative: bool,
    /// Source pattern (remote side).
    pub src: String,
    /// Destination pattern (local side); `None` fetches into
    /// `FETCH_HEAD` only and writes no ref.
    pub dst: Option<String>,
}

impl FetchRefspec {
    /// True when this mapping can write a local branch tip. Negative
    /// and destination-less mappings never write. A literal destination
    /// is unsafe under `refs/heads/` (exact `refs/heads` counts as
    /// unsafe: degenerate, fail closed). A wildcard destination
    /// `pre*post` is unsafe exactly when some expansion lands under
    /// `refs/heads/`, i.e. when `pre` is prefix-comparable with
    /// `refs/heads/` in either direction.
    #[must_use]
    pub fn can_write_branch_tips(&self) -> bool {
        if self.negative {
            return false;
        }
        let Some(dst) = self.dst.as_deref() else {
            return false;
        };
        match dst.split_once('*') {
            None => dst == "refs/heads" || dst.starts_with(HEADS_PREFIX),
            Some((pre, _post)) => HEADS_PREFIX.starts_with(pre) || pre.starts_with(HEADS_PREFIX),
        }
    }
}

/// Parse one `remote.<name>.fetch` value. `None` means unparseable
/// (fail closed at the verdict layer). Git wildcard rules apply: at
/// most one `*` per side, and a `*` in `src` requires exactly one in
/// `dst`.
#[must_use]
pub fn parse_fetch_refspec(value: &str) -> Option<FetchRefspec> {
    let (force, rest) = match value.strip_prefix('+') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    let (negative, rest) = match rest.strip_prefix('^') {
        Some(rest) => (true, rest),
        None => (false, rest),
    };
    // `+` and `^` do not combine or repeat; a second flag byte or a
    // second colon is malformed (fail closed).
    if force && negative {
        return None;
    }
    if rest.is_empty() || rest.starts_with(['+', '^']) {
        return None;
    }
    let (src, dst) = match rest.split_once(':') {
        Some((src, dst)) => {
            if negative || src.is_empty() || dst.is_empty() || dst.contains(':') {
                return None;
            }
            (src, Some(dst))
        }
        None => (rest, None),
    };
    if src.matches('*').count() > 1 {
        return None;
    }
    if let Some(dst) = dst {
        let dst_stars = dst.matches('*').count();
        if dst_stars > 1 {
            return None;
        }
        if src.contains('*') && dst_stars != 1 {
            return None;
        }
        if !src.contains('*') && dst_stars == 1 {
            return None;
        }
    }
    Some(FetchRefspec {
        force,
        negative,
        src: src.to_string(),
        dst: dst.map(str::to_string),
    })
}

/// Verdict for one remote's effective fetch configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchVerdict {
    /// Every mapping is confined away from local branch tips: `git
    /// fetch <remote>` with its configured refspecs is safe to run.
    Safe,
    /// Do not run the fetch; `reason` is a short detail (no URLs —
    /// refspec text carries ref patterns only).
    Unsupported {
        /// Short scrubbed reason for the catalog row and event.
        reason: String,
    },
}

impl FetchVerdict {
    /// True for [`FetchVerdict::Safe`].
    #[must_use]
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Safe)
    }
}

/// Match `value` against a single-wildcard `pattern` (exact bytes);
/// returns the middle capture, or `None` for no match (patterns
/// without a wildcard never match here — see
/// [`match_pattern_or_literal`]). Ref names are matched byte-exact so
/// non-UTF-8 names classify correctly.
fn match_pattern(pattern: &[u8], value: &[u8]) -> Option<Vec<u8>> {
    let star = pattern.iter().position(|b| *b == b'*')?;
    let (pre, post) = (&pattern[..star], &pattern[star + 1..]);
    value
        .strip_prefix(pre)?
        .strip_suffix(post)
        .map(<[u8]>::to_vec)
}

/// Match `value` against a literal-or-wildcard `pattern` (exact
/// bytes). Literal patterns match by equality.
fn match_pattern_or_literal(pattern: &[u8], value: &[u8]) -> Option<Vec<u8>> {
    if pattern.contains(&b'*') {
        match_pattern(pattern, value)
    } else {
        (value == pattern).then(Vec::new)
    }
}

/// True when at least one kept (non-negative) mapping's destination
/// covers `tracking` — i.e. this remote's fetch may have written this
/// tracking ref. Destination-less mappings fetch into `FETCH_HEAD`
/// only and cover nothing. Attribution, not freshness: the fetch
/// phase labels only covered refs and leaves every other remote's
/// refs (and leftovers from narrower configs) to their own verdicts.
/// Byte-exact, through the actual destination patterns (never a
/// `refs/remotes/<name>/` prefix, which misses custom destinations
/// and trips on `origin`/`origin2` boundaries). Like git, `*` crosses
/// `/`: overlapping destinations genuinely overlap, and both remotes
/// may claim the ref — last fetch wins, exactly git's own behavior.
#[must_use]
pub fn covered_by_positive(positive: &[FetchRefspec], tracking: &[u8]) -> bool {
    positive
        .iter()
        .filter(|s| !s.negative)
        .filter_map(|s| s.dst.as_deref())
        .any(|dst| match_pattern_or_literal(dst.as_bytes(), tracking).is_some())
}

/// Git boolean-true test over raw config bytes, matching
/// `git config --type=bool` exactly (every edge below probed against
/// installed git 2.56.0; see `config_bool_matches_git`): exact
/// case-insensitive word match (`yes`/`on`/`true`, NO whitespace
/// tolerance), else a C `strtol`-base-0 integer with an optional
/// single `k`/`m`/`g` suffix (case-insensitive, ×1024^1/2/3 with a
/// per-step pre-multiply int32-range check). Plain values must fit
/// int32; anything else is fatal in git ("bad boolean config
/// value"), reported here as false: the fetch then fails honestly on
/// git's own error instead of fetching blind. The true-set matches
/// git exactly — a missed `true` on `remote.*.mirror` would fetch a
/// mirror into branch tips. (Notably: `2` is true; `"  on"`, `"1 "`,
/// and `08` are fatal; `0x10` is true; `1g` is true but `7g` is
/// fatal; `1048576k` is true but `2048m` is fatal; `2147483648` is
/// fatal.)
#[must_use]
pub fn config_bool_is_true(value: &[u8]) -> bool {
    if value.eq_ignore_ascii_case(b"yes")
        || value.eq_ignore_ascii_case(b"on")
        || value.eq_ignore_ascii_case(b"true")
    {
        return true;
    }
    // Numeric: skip leading C-locale whitespace (git uses isspace,
    // which includes vertical tab — `trim_ascii` omits it).
    let mut rest = value;
    while let Some((&b, tail)) = rest.split_first() {
        if matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
            rest = tail;
        } else {
            break;
        }
    }
    let negative = rest.first() == Some(&b'-');
    if negative || rest.first() == Some(&b'+') {
        rest = &rest[1..];
    }
    // Optional single size suffix; trailing junk of any other shape
    // is fatal in git.
    let mut steps: u32 = 0;
    if let Some((&last, head)) = rest.split_last() {
        if matches!(last, b'k' | b'K' | b'm' | b'M' | b'g' | b'G') {
            steps = match last {
                b'k' | b'K' => 1,
                b'm' | b'M' => 2,
                _ => 3,
            };
            rest = head;
        }
    }
    // Base-0 magnitude (saturating: only int32-range values can
    // return true, so saturation never flips an outcome).
    let magnitude: i128 = if let Some(hex) = rest
        .strip_prefix(b"0x")
        .or_else(|| rest.strip_prefix(b"0X"))
    {
        if hex.is_empty() || !hex.iter().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        hex.iter().fold(0i128, |acc, b| {
            acc.saturating_mul(16)
                .saturating_add((*b as char).to_digit(16).unwrap_or(0) as i128)
        })
    } else if rest.len() > 1 && rest.starts_with(b"0") {
        // Octal (`08` is fatal in git).
        if !rest.iter().all(|b| matches!(b, b'0'..=b'7')) {
            return false;
        }
        rest.iter().fold(0i128, |acc, b| {
            acc.saturating_mul(8).saturating_add((b - b'0') as i128)
        })
    } else {
        if rest.is_empty() || !rest.iter().all(|b| b.is_ascii_digit()) {
            return false;
        }
        rest.iter().fold(0i128, |acc, b| {
            acc.saturating_mul(10).saturating_add((b - b'0') as i128)
        })
    };
    let mut v: i128 = if negative { -magnitude } else { magnitude };
    if steps == 0 {
        // Plain values must fit int32.
        return v >= i128::from(i32::MIN) && v <= i128::from(i32::MAX) && v != 0;
    }
    // Per-step pre-multiply bounds (`i32::MIN / 1024`,
    // `i32::MAX / 1024` floored); no post-multiply check — `1048576k`
    // (2^31) is true in git.
    for _ in 0..steps {
        if !(-2097152..=2097151).contains(&v) {
            return false;
        }
        v *= 1024;
    }
    v != 0
}

/// True when any negative refspec excludes this upstream ref (exact
/// bytes). Only entries flagged `negative` apply; anything else in
/// the slice is ignored.
#[must_use]
pub fn excluded_by_negative(negatives: &[FetchRefspec], upstream: &[u8]) -> bool {
    negatives
        .iter()
        .filter(|n| n.negative)
        .any(|n| match_pattern_or_literal(n.src.as_bytes(), upstream).is_some())
}

/// Freshness verdict for one local tracking ref after a fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackingVerdict {
    /// A kept mapping resolves to an upstream ref that still exists:
    /// label `current`.
    Current,
    /// A kept mapping resolves to an upstream ref that is gone: label
    /// `stale` and record the name as deleted upstream (the local
    /// tracking ref itself is kept, never pruned).
    DeletedUpstream,
    /// No mapping covers the ref, or every mapping is excluded: label
    /// `stale` (outside this fetch's coverage).
    Excluded,
}

/// Classify one local tracking ref against the upstream ref set
/// observed by `ls-remote --heads --tags` (all exact bytes).
/// `positive`/`negatives` are the remote's parsed fetch refspecs; a
/// ref is current when any kept mapping resolves to a live upstream
/// ref, deleted when a kept mapping resolves to a vanished one, and
/// excluded otherwise.
#[must_use]
pub fn classify_tracking_ref(
    positive: &[FetchRefspec],
    negatives: &[FetchRefspec],
    tracking: &[u8],
    upstream_refs: &std::collections::HashSet<Vec<u8>>,
) -> TrackingVerdict {
    let mut kept_missing = false;
    for spec in positive.iter().filter(|s| !s.negative) {
        let Some(dst) = spec.dst.as_deref() else {
            continue;
        };
        let Some(middle) = match_pattern_or_literal(dst.as_bytes(), tracking) else {
            continue;
        };
        let upstream = match spec.src.split_once('*') {
            None => spec.src.as_bytes().to_vec(),
            Some((pre, post)) => {
                let mut out = Vec::with_capacity(pre.len() + middle.len() + post.len());
                out.extend_from_slice(pre.as_bytes());
                out.extend_from_slice(&middle);
                out.extend_from_slice(post.as_bytes());
                out
            }
        };
        if excluded_by_negative(negatives, &upstream) {
            continue;
        }
        if upstream_refs.contains(&upstream) {
            return TrackingVerdict::Current;
        }
        kept_missing = true;
    }
    if kept_missing {
        TrackingVerdict::DeletedUpstream
    } else {
        TrackingVerdict::Excluded
    }
}

/// Parse `git ls-remote` stdout into upstream ref names (exact bytes).
/// Each row is `<hex-oid>\t<ref>`; peeled `^{}` rows and malformed
/// rows (short/non-hex oid, missing tab, empty or tab-bearing name)
/// are skipped, never fabricated.
#[must_use]
pub fn parse_ls_remote_refs(out: &[u8]) -> Vec<Vec<u8>> {
    let mut names = Vec::new();
    for line in out.split(|b| *b == b'\n') {
        let mut parts = line.splitn(2, |b| *b == b'\t');
        let (Some(oid), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        if oid.len() < 40 || !oid.iter().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if name.is_empty() || name.contains(&b'\t') {
            continue;
        }
        if name.ends_with(b"^{}") {
            continue;
        }
        names.push(name.to_vec());
    }
    names
}

/// Inspect one remote's effective fetch configuration: `refspecs` are
/// the `remote.<name>.fetch` values in config order, `mirror` is
/// `remote.<name>.mirror`. A remote with no fetch values is safe (git
/// fetches the remote HEAD into `FETCH_HEAD` only, writing no ref).
#[must_use]
pub fn inspect_remote_fetch(refspecs: &[&str], mirror: bool) -> FetchVerdict {
    if mirror {
        return FetchVerdict::Unsupported {
            reason: "remote mirror enabled: refspecs write to local branches".to_string(),
        };
    }
    for value in refspecs {
        let Some(parsed) = parse_fetch_refspec(value) else {
            return FetchVerdict::Unsupported {
                reason: format!("unparseable fetch refspec: {value}"),
            };
        };
        if parsed.can_write_branch_tips() {
            return FetchVerdict::Unsupported {
                reason: format!("fetch refspec can write to local branch tips: {value}"),
            };
        }
    }
    FetchVerdict::Safe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_clone_refspec_is_safe() {
        let verdict = inspect_remote_fetch(&["+refs/heads/*:refs/remotes/origin/*"], false);
        assert_eq!(verdict, FetchVerdict::Safe);
    }

    #[test]
    fn single_branch_refspec_is_safe() {
        let verdict = inspect_remote_fetch(&["+refs/heads/main:refs/remotes/origin/main"], false);
        assert_eq!(verdict, FetchVerdict::Safe);
    }

    #[test]
    fn tag_only_refspec_is_safe() {
        let verdict = inspect_remote_fetch(&["+refs/tags/*:refs/tags/*"], false);
        assert_eq!(verdict, FetchVerdict::Safe);
    }

    #[test]
    fn negative_refspec_is_safe() {
        let verdict = inspect_remote_fetch(
            &["+refs/heads/*:refs/remotes/origin/*", "^refs/heads/secret"],
            false,
        );
        assert_eq!(verdict, FetchVerdict::Safe);
    }

    #[test]
    fn destination_less_refspec_is_safe() {
        // Fetches into FETCH_HEAD only; writes no ref.
        let verdict = inspect_remote_fetch(&["main"], false);
        assert_eq!(verdict, FetchVerdict::Safe);
    }

    #[test]
    fn empty_refspec_list_is_safe() {
        // No fetch lines: git fetches remote HEAD into FETCH_HEAD only.
        let verdict = inspect_remote_fetch(&[], false);
        assert_eq!(verdict, FetchVerdict::Safe);
    }

    fn parsed(specs: &[&str]) -> Vec<FetchRefspec> {
        specs
            .iter()
            .map(|s| parse_fetch_refspec(s).expect("test refspec parses"))
            .collect()
    }

    #[test]
    fn config_bool_matches_git() {
        // Every case probed against `git config --type=bool` (git
        // 2.56.0); the true-set must match exactly — a missed `true`
        // on `remote.*.mirror` would fetch a mirror into branch tips.
        for truthy in [
            "1",
            "2",
            "10",
            "007",
            "01",
            "-1",
            "+1",
            " 1",
            "\t1",
            "\u{b}1",
            "True",
            "On",
            "YES",
            "Yes",
            "yes",
            "TRUE",
            "true",
            "ON",
            "on",
            "0x10",
            "0X1",
            "-0x10",
            " 0x10",
            "-0X1",
            "010",
            "2147483647",
            "0x7FFFFFFF",
            "-2147483648",
            "-0x80000000",
            "1k",
            "1K",
            "1m",
            "1M",
            "1g",
            "1G",
            "3m",
            "0x10k",
            "2047m",
            "1048575k",
            "1048576k",
            "1048577k",
            "2097151k",
            "-2097152k",
            "1g",
            "0x1g",
            " 0x1g",
            "0X1G",
            "+0x1g",
        ] {
            assert!(
                config_bool_is_true(truthy.as_bytes()),
                "{truthy:?} must be true"
            );
        }
        for falsy in [
            "0",
            "00",
            "000",
            "-0",
            "+0",
            "0x0",
            "no",
            "NO",
            "No",
            "off",
            "OFF",
            "Off",
            "false",
            "FALSE",
            "False",
            "",
            "   ",
            "  on",
            "on ",
            "  on  ",
            "1 ",
            " 1 ",
            " 0",
            "onion",
            "trueish",
            "yes please",
            "1.0",
            "08",
            "-08",
            "0b1",
            "+ 1",
            "- 0",
            "0x",
            "0X",
            "0x1 ",
            "7g",
            "9g",
            "2g",
            "3g",
            "2G",
            "2048m",
            "-2049m",
            "2097152k",
            "-2097153k",
            "-3000000k",
            "-3000000m",
            "-5g",
            "2147483648",
            "-2147483649",
            "9223372036854775807",
            "9223372036854775808",
            "-9223372036854775808",
            "-9223372036854775809",
            "99999999999999999999999",
            "0x7FFFFFFFFFFFFFFF",
            "0x80000000",
            "0x8000000000000000",
            "0xFFFFFFFFFFFFFFFFFFFFFFFF",
            "-0x80000001",
            "1t",
            "1kk",
            "k",
            "m",
            "g",
            "+",
            "-",
            "1x",
            "12g34",
            "0xg",
            "0xg1",
            "0xx",
            "0d1",
            "  12ab",
            "1_0",
            "1,0",
            "xg",
            "mixedCase",
        ] {
            assert!(
                !config_bool_is_true(falsy.as_bytes()),
                "{falsy:?} must be false"
            );
        }
        // Non-UTF-8 bytes (config values are byte-exact; git errors
        // on these): never true.
        for raw in [
            b"tru\xff".as_slice(),
            b"\xff".as_slice(),
            b"\xfe\xfe".as_slice(),
        ] {
            assert!(!config_bool_is_true(raw), "{raw:?} must be false");
        }
    }

    #[test]
    fn coverage_follows_destination_patterns() {
        let specs = parsed(&["+refs/heads/*:refs/remotes/origin/*"]);
        assert!(covered_by_positive(&specs, b"refs/remotes/origin/main"));
        // Another remote's ref: not this fetch's statement.
        assert!(!covered_by_positive(&specs, b"refs/remotes/upstream/main"));
        // Local branches are never covered (and never labeled).
        assert!(!covered_by_positive(&specs, b"refs/heads/main"));
    }

    #[test]
    fn coverage_rejects_prefix_collision() {
        // A slash-less `refs/remotes/origin` prefix test would claim
        // remote `origin2`'s refs; destination patterns do not.
        let specs = parsed(&["+refs/heads/*:refs/remotes/origin/*"]);
        assert!(covered_by_positive(&specs, b"refs/remotes/origin/main"));
        assert!(!covered_by_positive(&specs, b"refs/remotes/origin2/main"));
        // Custom destinations attribute through the pattern, not the
        // remote name.
        let custom = parsed(&["+refs/heads/*:refs/custom/o/*"]);
        assert!(covered_by_positive(&custom, b"refs/custom/o/main"));
        assert!(!covered_by_positive(&custom, b"refs/remotes/o/main"));
    }

    #[test]
    fn coverage_star_crosses_slashes_like_git() {
        // `*` matches `/`: remote `o` with dst `refs/remotes/o/*`
        // genuinely writes `refs/remotes/o/x/main` when upstream has
        // branch `x/main` — both remotes may claim it, last fetch
        // wins, exactly git's own behavior.
        let specs = parsed(&["+refs/heads/*:refs/remotes/o/*"]);
        assert!(covered_by_positive(&specs, b"refs/remotes/o/x/main"));
    }

    #[test]
    fn coverage_ignores_negatives_and_dst_less() {
        let specs = parsed(&[
            "+refs/heads/*:refs/remotes/origin/*",
            "^refs/heads/secret",
            "main",
        ]);
        // The negative and the FETCH_HEAD-only mapping cover nothing,
        // but the kept mapping still covers its destination.
        assert!(covered_by_positive(&specs, b"refs/remotes/origin/main"));
        let only_negative = parsed(&["^refs/heads/secret"]);
        assert!(!covered_by_positive(
            &only_negative,
            b"refs/remotes/origin/secret"
        ));
        let only_dst_less = parsed(&["main"]);
        assert!(!covered_by_positive(
            &only_dst_less,
            b"refs/remotes/origin/main"
        ));
        // Non-UTF-8 tracking names match byte-exact.
        assert!(covered_by_positive(&specs, b"refs/remotes/origin/f\xf6o"));
    }

    #[test]
    fn mirror_clone_is_unsupported() {
        let verdict = inspect_remote_fetch(&["+refs/*:refs/*"], false);
        assert!(matches!(verdict, FetchVerdict::Unsupported { .. }));
        match inspect_remote_fetch(&[], true) {
            FetchVerdict::Unsupported { reason } => {
                assert!(reason.contains("mirror"), "{reason}");
            }
            FetchVerdict::Safe => panic!("mirror flag must be unsupported"),
        }
    }

    #[test]
    fn heads_to_heads_is_unsupported() {
        for value in [
            "+refs/heads/*:refs/heads/*",
            "refs/heads/main:refs/heads/main",
            "+refs/heads:refs/heads",
        ] {
            let verdict = inspect_remote_fetch(&[value], false);
            assert!(
                matches!(verdict, FetchVerdict::Unsupported { .. }),
                "{value} must be unsupported"
            );
        }
    }

    #[test]
    fn wildcard_destination_verdicts() {
        // Each (refspec, can_write) pair: wildcard destinations whose
        // static prefix overlaps refs/heads/ are unsafe; confined ones
        // are safe even with a broad source.
        for (value, can_write) in [
            ("+refs/*:refs/*", true),
            ("+*:*", true),
            ("+refs/heads/*:refs/heads/*", true),
            ("refs/*:refs/remotes/o/*", false),
            ("+refs/heads/*:refs/remotes/origin/*", false),
            ("+refs/tags/*:refs/tags/*", false),
            // Shares a string prefix with refs/heads/ but lives
            // outside the namespace: safe.
            ("+refs/heads-foo/*:refs/heads-foo/*", false),
            ("+refs/heads:refs/heads", true),
        ] {
            let parsed = parse_fetch_refspec(value).expect("parses");
            assert_eq!(parsed.can_write_branch_tips(), can_write, "{value}");
            assert_eq!(
                inspect_remote_fetch(&[value], false).is_safe(),
                !can_write,
                "{value}"
            );
        }
    }

    #[test]
    fn garbage_fails_closed() {
        for value in [
            "", "+", ":", "+:", "a:b:c", "*:refs/x", "x:*", "++a:b", "^+a", "+^a", "^^a",
        ] {
            let verdict = inspect_remote_fetch(&[value], false);
            assert!(
                matches!(verdict, FetchVerdict::Unsupported { .. }),
                "{value:?} must fail closed"
            );
        }
    }

    #[test]
    fn classify_current_deleted_excluded() {
        use std::collections::HashSet;
        let positive =
            [parse_fetch_refspec("+refs/heads/*:refs/remotes/origin/*").expect("parses")];
        let negatives: [FetchRefspec; 0] = [];
        let upstream: HashSet<Vec<u8>> =
            [b"refs/heads/main".to_vec(), b"refs/heads/feature".to_vec()]
                .into_iter()
                .collect();
        assert_eq!(
            classify_tracking_ref(
                &positive,
                &negatives,
                b"refs/remotes/origin/main",
                &upstream
            ),
            TrackingVerdict::Current
        );
        assert_eq!(
            classify_tracking_ref(
                &positive,
                &negatives,
                b"refs/remotes/origin/gone",
                &upstream
            ),
            TrackingVerdict::DeletedUpstream
        );
        // Another remote's namespace: no mapping covers it.
        assert_eq!(
            classify_tracking_ref(
                &positive,
                &negatives,
                b"refs/remotes/upstream/main",
                &upstream
            ),
            TrackingVerdict::Excluded
        );
    }

    #[test]
    fn classify_honors_negative_exclusions() {
        use std::collections::HashSet;
        let positive =
            [parse_fetch_refspec("+refs/heads/*:refs/remotes/origin/*").expect("parses")];
        let negatives = [parse_fetch_refspec("^refs/heads/secret").expect("parses")];
        let upstream: HashSet<Vec<u8>> = [b"refs/heads/secret".to_vec()].into_iter().collect();
        assert_eq!(
            classify_tracking_ref(
                &positive,
                &negatives,
                b"refs/remotes/origin/secret",
                &upstream
            ),
            TrackingVerdict::Excluded
        );
    }

    #[test]
    fn classify_single_branch_leftover_is_excluded() {
        use std::collections::HashSet;
        let positive =
            [parse_fetch_refspec("+refs/heads/main:refs/remotes/origin/main").expect("parses")];
        let negatives: [FetchRefspec; 0] = [];
        let upstream: HashSet<Vec<u8>> =
            [b"refs/heads/main".to_vec(), b"refs/heads/other".to_vec()]
                .into_iter()
                .collect();
        assert_eq!(
            classify_tracking_ref(
                &positive,
                &negatives,
                b"refs/remotes/origin/main",
                &upstream
            ),
            TrackingVerdict::Current
        );
        // A leftover from an older, broader config: outside this
        // fetch's coverage, never current.
        assert_eq!(
            classify_tracking_ref(
                &positive,
                &negatives,
                b"refs/remotes/origin/other",
                &upstream
            ),
            TrackingVerdict::Excluded
        );
    }

    #[test]
    fn classify_is_byte_exact_for_non_utf8_names() {
        use std::collections::HashSet;
        let positive =
            [parse_fetch_refspec("+refs/heads/*:refs/remotes/origin/*").expect("parses")];
        let negatives: [FetchRefspec; 0] = [];
        let upstream: HashSet<Vec<u8>> = [b"refs/heads/\xff".to_vec()].into_iter().collect();
        assert_eq!(
            classify_tracking_ref(
                &positive,
                &negatives,
                b"refs/remotes/origin/\xff",
                &upstream
            ),
            TrackingVerdict::Current
        );
    }

    #[test]
    fn ls_remote_parse_skips_peeled_and_malformed() {
        let out = b"0123456789abcdef0123456789abcdef01234567\trefs/heads/main\n\
            0123456789abcdef0123456789abcdef01234567\trefs/tags/v1\n\
            0123456789abcdef0123456789abcdef01234567\trefs/tags/v1^{}\n\
            short\trefs/heads/bad-oid\n\
            zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\trefs/heads/nonhex\n\
            no-tab-here\n\
            0123456789abcdef0123456789abcdef01234567\t\n";
        let names = parse_ls_remote_refs(out);
        let strs: Vec<String> = names
            .iter()
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .collect();
        assert_eq!(strs, vec!["refs/heads/main", "refs/tags/v1"]);
    }

    #[test]
    fn excluded_by_negative_matches_wildcards() {
        let negatives = [parse_fetch_refspec("^refs/heads/draft/*").expect("parses")];
        assert!(excluded_by_negative(&negatives, b"refs/heads/draft/a"));
        assert!(!excluded_by_negative(&negatives, b"refs/heads/main"));
    }

    #[test]
    fn one_unsafe_mapping_taints_the_remote() {
        let verdict = inspect_remote_fetch(
            &[
                "+refs/heads/*:refs/remotes/origin/*",
                "+refs/heads/*:refs/heads/*",
            ],
            false,
        );
        assert!(matches!(verdict, FetchVerdict::Unsupported { .. }));
    }
}
