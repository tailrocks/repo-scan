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
