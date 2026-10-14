//! Branch ahead/behind comparison tests (goal Step 10, Step 15 case 9).
//!
//! Every counted expectation is cross-checked against the installed
//! `git` binary (`rev-list --left-right --count`, `merge-base`,
//! `rev-parse`), never against our own walker. Git-dependent tests
//! skip quietly when no git binary is discoverable; the pure
//! state-derivation tables always run.
//!
//! Slice-2 note: the catalog/report-coupled tail of B11's graph_impl.rs
//! (comparison persistence round-trip, v5->v6 migration, builder
//! pending/label emission, shipped-schema acceptance, scan-level e2e)
//! is deferred to slice 5: it needs `store` comparison columns and
//! `report` branch comparison fields that do not exist on main yet.
//! The deferred test names are listed in the slice-2 handoff.

mod common;

use common::fixture;
use repo_scan::git::fallback::{FallbackGit, WaitCancel};
use repo_scan::git::graph::{
    compare_branch, compare_oids, grafts_present, shallow_present, BranchTips, CompareContext,
    Comparison, ComparisonCache, COMPARISON_STATES,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Locate an installed git with offline graph-read support or skip the
/// calling test.
fn git_or_skip() -> Option<FallbackGit> {
    FallbackGit::discover(&[]).filter(FallbackGit::supports_no_lazy_fetch)
}

/// Parse installed-git's `rev-list --left-right --count A...B`
/// reference output (`"<ahead>\t<behind>"`).
fn git_counts(dir: &Path, a: &str, b: &str) -> (u64, u64) {
    let spec = format!("{a}...{b}");
    let out = fixture::git_str(dir, &["rev-list", "--left-right", "--count", &spec]);
    let mut parts = out.split_whitespace();
    let ahead: u64 = parts.next().expect("ahead").parse().expect("ahead num");
    let behind: u64 = parts.next().expect("behind").parse().expect("behind num");
    assert!(parts.next().is_none(), "two counts only: {out:?}");
    (ahead, behind)
}

/// Compare `local` vs `upstream` OID in `repo` (worktree root)
/// with an explicit store key, cache, and fallback.
fn compare_in(
    repo: &Path,
    store_id: &str,
    cache: Option<&ComparisonCache>,
    fallback: Option<&FallbackGit>,
    local: &str,
    upstream: &str,
) -> Comparison {
    let git_dir = repo.join(".git");
    let ctx = CompareContext {
        git_dir: &git_dir,
        common_dir: &git_dir,
        store_id,
        use_replace_refs: None,
        replace_ref_base: None,
        work_tree: Some(repo),
        cache,
        fallback,
        cancel: None,
    };
    compare_oids(&ctx, local, upstream, "sha1")
}

/// Byte-exact `rev-parse` (no lossy round-trip): hostile refnames
/// keep their bytes end to end.
fn rev_parse_exact(dir: &Path, refname: &[u8]) -> String {
    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let out = fixture::git_os(dir, &[OsStr::new("rev-parse"), OsStr::from_bytes(refname)]);
        String::from_utf8(out)
            .expect("oid is utf8")
            .trim()
            .to_string()
    }
    #[cfg(not(unix))]
    {
        fixture::git_str(dir, &["rev-parse", &String::from_utf8_lossy(refname)])
    }
}

/// Compare one branch (full refname bytes) against its resolved
/// upstream (full refname bytes or `None`) inside `repo`, resolving
/// tip OIDs with installed git. `upstream_present=false` simulates
/// a resolved-but-absent upstream ref.
#[allow(clippy::too_many_arguments)]
fn compare_branch_in(
    repo: &Path,
    store_id: &str,
    cache: Option<&ComparisonCache>,
    fallback: Option<&FallbackGit>,
    branch: &[u8],
    upstream: Option<&[u8]>,
    upstream_present: bool,
) -> Comparison {
    let git_dir = repo.join(".git");
    let ctx = CompareContext {
        git_dir: &git_dir,
        common_dir: &git_dir,
        store_id,
        use_replace_refs: None,
        replace_ref_base: None,
        work_tree: Some(repo),
        cache,
        fallback,
        cancel: None,
    };
    let local_hex = rev_parse_exact(repo, branch);
    let (upstream_hex, upstream_known) = match upstream {
        None => (None, false),
        Some(name) => {
            if !upstream_present {
                (None, false)
            } else {
                (Some(rev_parse_exact(repo, name)), true)
            }
        }
    };
    // Keep owned strings alive for the borrowed tips.
    let tips = BranchTips {
        local_hex: Some(&local_hex),
        local_algo: Some("sha1"),
        upstream,
        upstream_hex: upstream_hex.as_deref(),
        upstream_algo: upstream_hex.as_ref().map(|_| "sha1"),
        upstream_known,
    };
    compare_branch(&ctx, &tips)
}

// ---------------------------------------------------------------------------
// Pure state derivation (no git needed)
// ---------------------------------------------------------------------------

#[test]
fn state_vocabulary_is_nine() {
    assert_eq!(
        COMPARISON_STATES,
        &[
            "equal",
            "ahead",
            "behind",
            "diverged",
            "no_upstream",
            "upstream_missing",
            "pending",
            "incomplete_history",
            "error",
        ]
    );
}

#[test]
fn from_counts_derives_four_states() {
    assert_eq!(
        Comparison::from_counts(0, 0),
        Comparison {
            state: "equal",
            ahead: Some(0),
            behind: Some(0),
        }
    );
    assert_eq!(Comparison::from_counts(2, 0).state, "ahead");
    assert_eq!(Comparison::from_counts(0, 3).state, "behind");
    assert_eq!(Comparison::from_counts(2, 3).state, "diverged");
    // Counts ride along exactly.
    assert_eq!(Comparison::from_counts(2, 3).ahead, Some(2));
    assert_eq!(Comparison::from_counts(2, 3).behind, Some(3));
}

#[test]
fn uncounted_states_carry_nulls() {
    for comparison in [
        Comparison::no_upstream(),
        Comparison::upstream_missing(),
        Comparison::pending(),
        Comparison::incomplete_history(),
        Comparison::error(),
    ] {
        assert!(comparison.ahead.is_none(), "{comparison:?}");
        assert!(comparison.behind.is_none(), "{comparison:?}");
        assert!(
            COMPARISON_STATES.contains(&comparison.state),
            "{comparison:?}"
        );
    }
}

#[test]
fn malformed_oid_is_error_without_walk() {
    let cache = ComparisonCache::new();
    let git_dir = PathBuf::from("/nonexistent-graph-fixture/.git");
    let ctx = CompareContext {
        git_dir: &git_dir,
        common_dir: &git_dir,
        store_id: "test-store",
        use_replace_refs: None,
        replace_ref_base: None,
        work_tree: None,
        cache: Some(&cache),
        fallback: None,
        cancel: None,
    };
    for (local, upstream) in [
        ("zzz", "1111111111111111111111111111111111111111"),
        ("1111111111111111111111111111111111111111", "not-hex"),
        (
            "111111111111111111111111111111111111111",
            "1111111111111111111111111111111111111111",
        ),
    ] {
        let comparison = compare_oids(&ctx, local, upstream, "sha1");
        assert_eq!(comparison.state, "error", "{local} vs {upstream}");
        assert_eq!(comparison.ahead, None);
        assert_eq!(comparison.behind, None);
    }
    // Nothing walked, nothing cached.
    assert_eq!(cache.walks(), 0);
    assert!(cache.is_empty());
    // Unknown algorithm is error too.
    let comparison = compare_oids(
        &ctx,
        "1111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222",
        "md5",
    );
    assert_eq!(comparison.state, "error");
}

#[test]
fn equal_oid_fast_path_touches_nothing() {
    // Nonexistent store: the fast path must not open, walk, or
    // cache — equality needs no object read.
    let cache = ComparisonCache::new();
    let git_dir = PathBuf::from("/nonexistent-graph-fixture/.git");
    let ctx = CompareContext {
        git_dir: &git_dir,
        common_dir: &git_dir,
        store_id: "test-store",
        use_replace_refs: None,
        replace_ref_base: None,
        work_tree: None,
        cache: Some(&cache),
        fallback: None,
        cancel: None,
    };
    let oid = "1111111111111111111111111111111111111111";
    let comparison = compare_oids(&ctx, oid, oid, "sha1");
    assert_eq!(comparison.state, "equal");
    assert_eq!(comparison.ahead, Some(0));
    assert_eq!(comparison.behind, Some(0));
    assert_eq!(cache.walks(), 0);
    assert_eq!(cache.hits(), 0);
    assert!(cache.is_empty());
}

#[test]
fn branch_state_assignment_without_reads() {
    // No-upstream short-circuits before any OID check.
    let git_dir = PathBuf::from("/nonexistent-graph-fixture/.git");
    let ctx = CompareContext {
        git_dir: &git_dir,
        common_dir: &git_dir,
        store_id: "test-store",
        use_replace_refs: None,
        replace_ref_base: None,
        work_tree: None,
        cache: None,
        fallback: None,
        cancel: None,
    };
    let none = compare_branch(
        &ctx,
        &BranchTips {
            local_hex: None,
            local_algo: None,
            upstream: None,
            upstream_hex: None,
            upstream_algo: None,
            upstream_known: false,
        },
    );
    assert_eq!(none.state, "no_upstream");
    // Absent upstream ref is upstream_missing, never no_upstream.
    let missing = compare_branch(
        &ctx,
        &BranchTips {
            local_hex: Some("1111111111111111111111111111111111111111"),
            local_algo: Some("sha1"),
            upstream: Some(b"refs/remotes/origin/ghost"),
            upstream_hex: None,
            upstream_algo: None,
            upstream_known: false,
        },
    );
    assert_eq!(missing.state, "upstream_missing");
    // Missing local OID (unborn/dangling) is error, never equal.
    let unborn = compare_branch(
        &ctx,
        &BranchTips {
            local_hex: None,
            local_algo: None,
            upstream: Some(b"refs/remotes/origin/main"),
            upstream_hex: Some("1111111111111111111111111111111111111111"),
            upstream_algo: Some("sha1"),
            upstream_known: true,
        },
    );
    assert_eq!(unborn.state, "error");
    // Algorithm mismatch is error.
    let mixed = compare_branch(
        &ctx,
        &BranchTips {
            local_hex: Some("1111111111111111111111111111111111111111"),
            local_algo: Some("sha1"),
            upstream: Some(b"refs/remotes/origin/main"),
            upstream_hex: Some("2222222222222222222222222222222222222222222222222222222222222222"),
            upstream_algo: Some("sha256"),
            upstream_known: true,
        },
    );
    assert_eq!(mixed.state, "error");
}

// ---------------------------------------------------------------------------
// Counted states vs installed-git reference
// ---------------------------------------------------------------------------

#[test]
fn counted_states_match_git_rev_list() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-counts");
    for (ahead, behind, want) in [
        (0u32, 0u32, "equal"),
        (2, 0, "ahead"),
        (0, 3, "behind"),
        (2, 3, "diverged"),
    ] {
        let name = format!("pair-{ahead}-{behind}");
        let repo = fixture::comparison_pair(root.path(), &name, ahead, behind);
        let local = fixture::git_str(&repo, &["rev-parse", "refs/heads/main"]);
        let upstream = fixture::git_str(&repo, &["rev-parse", "refs/remotes/origin/main"]);
        // Installed-git reference first.
        let (git_ahead, git_behind) = git_counts(&repo, &local, &upstream);
        assert_eq!(
            (git_ahead, git_behind),
            (u64::from(ahead), u64::from(behind))
        );
        // Merge-base sanity per shape: equal pairs share the tip;
        // ahead parks the base on the upstream tip; behind parks it
        // on the local tip; diverged sits strictly below both.
        let base = fixture::git_str(&repo, &["merge-base", &local, &upstream]);
        match want {
            "equal" => assert_eq!(local, upstream),
            "ahead" => assert_eq!(base, upstream),
            "behind" => assert_eq!(base, local),
            _ => {
                assert_ne!(base, local);
                assert_ne!(base, upstream);
            }
        }
        // Our comparison, branch-level and OID-level.
        let comparison = compare_branch_in(
            &repo,
            &format!("store-{name}"),
            None,
            Some(&fallback),
            b"refs/heads/main",
            Some(b"refs/remotes/origin/main"),
            true,
        );
        assert_eq!(comparison.state, want, "{name}");
        assert_eq!(comparison.ahead, Some(u64::from(ahead)), "{name}");
        assert_eq!(comparison.behind, Some(u64::from(behind)), "{name}");
        let direct = compare_in(
            &repo,
            "store-direct",
            None,
            Some(&fallback),
            &local,
            &upstream,
        );
        assert_eq!(direct, comparison, "{name}");
    }
}

#[test]
fn cache_reuses_saved_result_without_rewalk() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-cache");
    let repo = fixture::comparison_pair(root.path(), "pair", 2, 3);
    let local = fixture::git_str(&repo, &["rev-parse", "refs/heads/main"]);
    let upstream = fixture::git_str(&repo, &["rev-parse", "refs/remotes/origin/main"]);
    let cache = ComparisonCache::new();
    // First comparison walks.
    let first = compare_in(
        &repo,
        "store-a",
        Some(&cache),
        Some(&fallback),
        &local,
        &upstream,
    );
    assert_eq!(first.state, "diverged");
    assert_eq!(cache.walks(), 1);
    assert_eq!(cache.hits(), 0);
    assert_eq!(cache.len(), 1);
    // Second comparison with the same key reuses the saved result.
    let second = compare_in(
        &repo,
        "store-a",
        Some(&cache),
        Some(&fallback),
        &local,
        &upstream,
    );
    assert_eq!(second, first);
    assert_eq!(cache.walks(), 1, "no second walk");
    assert_eq!(cache.hits(), 1);
    // Direction matters: swapped tips are a different key (and
    // swapped counts).
    let swapped = compare_in(
        &repo,
        "store-a",
        Some(&cache),
        Some(&fallback),
        &upstream,
        &local,
    );
    assert_eq!(swapped.ahead, first.behind);
    assert_eq!(swapped.behind, first.ahead);
    assert_eq!(cache.walks(), 2);
    // Store identity matters: the same OID pair under another
    // store id is another object database — no reuse.
    let other = compare_in(
        &repo,
        "store-b",
        Some(&cache),
        Some(&fallback),
        &local,
        &upstream,
    );
    assert_eq!(other, first);
    assert_eq!(cache.walks(), 3);
    assert_eq!(cache.hits(), 1);
}

#[test]
fn no_upstream_never_compares_to_main() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-no-upstream");
    let repo = fixture::normal_clone(root.path(), "plain");
    // Reference: git itself has no upstream for this branch.
    let output = fixture::git_output(&repo, &["rev-parse", "--symbolic-full-name", "@{u}"]);
    assert!(!output.status.success(), "@{{u}} must not resolve");
    let comparison = compare_branch_in(
        &repo,
        "store-plain",
        None,
        Some(&fallback),
        b"refs/heads/main",
        None,
        false,
    );
    assert_eq!(comparison.state, "no_upstream");
    assert_eq!(comparison.ahead, None);
    assert_eq!(comparison.behind, None);
}

#[test]
fn upstream_missing_when_ref_absent_but_configured() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-upstream-missing");
    let repo = fixture::comparison_pair(root.path(), "pair", 1, 0);
    // Delete the tracking ref after resolution: config still names
    // it (resolvable), but the ref is absent.
    fixture::git(&repo, &["update-ref", "-d", "refs/remotes/origin/main"]);
    // Reference: config present, ref gone.
    let merge = fixture::git_str(&repo, &["config", "branch.main.merge"]);
    assert_eq!(merge, "refs/heads/main");
    let verify = fixture::git_output(
        &repo,
        &["rev-parse", "--verify", "refs/remotes/origin/main"],
    );
    assert!(!verify.status.success(), "tracking ref must be absent");
    let comparison = compare_branch_in(
        &repo,
        "store-missing",
        None,
        Some(&fallback),
        b"refs/heads/main",
        Some(b"refs/remotes/origin/main"),
        false,
    );
    assert_eq!(comparison.state, "upstream_missing");
    assert_eq!(comparison.ahead, None);
    assert_eq!(comparison.behind, None);
}

#[test]
fn custom_refspec_upstream_compares_custom_dest() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-custom");
    let repo = fixture::custom_fetch_clone(root.path(), "custom");
    // Reference: the custom dest exists; the default dest does not.
    let custom = fixture::git_str(&repo, &["rev-parse", "refs/custom/main"]);
    let missing = fixture::git_output(
        &repo,
        &["rev-parse", "--verify", "refs/remotes/origin/main"],
    );
    assert!(!missing.status.success(), "default dest must be absent");
    let local = fixture::git_str(&repo, &["rev-parse", "refs/heads/main"]);
    assert_eq!(local, custom, "fixture starts equal");
    let comparison = compare_branch_in(
        &repo,
        "store-custom",
        None,
        Some(&fallback),
        b"refs/heads/main",
        Some(b"refs/custom/main"),
        true,
    );
    assert_eq!(comparison.state, "equal");
    // Two local commits: ahead of the CUSTOM dest.
    fixture::commit_file(&repo, "a.txt", "a\n", "a");
    fixture::commit_file(&repo, "b.txt", "b\n", "b");
    let (git_ahead, git_behind) = git_counts(&repo, "refs/heads/main", "refs/custom/main");
    assert_eq!((git_ahead, git_behind), (2, 0));
    let comparison = compare_branch_in(
        &repo,
        "store-custom",
        None,
        Some(&fallback),
        b"refs/heads/main",
        Some(b"refs/custom/main"),
        true,
    );
    assert_eq!(comparison.state, "ahead");
    assert_eq!(comparison.ahead, Some(2));
    assert_eq!(comparison.behind, Some(0));
}

// ---------------------------------------------------------------------------
// Shallow, grafted, and damaged stores
// ---------------------------------------------------------------------------

#[test]
fn shallow_clone_reports_counts_above_cut() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-shallow");
    let repo = fixture::shallow_clone(root.path(), "shallow", 4, 1);
    // Reference: git agrees this is a shallow clone.
    assert_eq!(
        fixture::git_str(&repo, &["rev-parse", "--is-shallow-repository"]),
        "true"
    );
    assert!(shallow_present(&repo.join(".git"), &repo.join(".git")));
    // Equal tips: the fast path holds even in shallow stores.
    let local = fixture::git_str(&repo, &["rev-parse", "refs/heads/main"]);
    let upstream = fixture::git_str(&repo, &["rev-parse", "refs/remotes/origin/main"]);
    assert_eq!(local, upstream);
    let comparison = compare_in(
        &repo,
        "store-shallow",
        None,
        Some(&fallback),
        &local,
        &upstream,
    );
    assert_eq!(comparison.state, "equal");
    // Two local commits above the cut: the walk provably stays
    // above it (no boundary commit yielded), so counts are exact.
    fixture::commit_file(&repo, "a.txt", "a\n", "a");
    fixture::commit_file(&repo, "b.txt", "b\n", "b");
    let local = fixture::git_str(&repo, &["rev-parse", "refs/heads/main"]);
    let (git_ahead, git_behind) = git_counts(&repo, &local, &upstream);
    assert_eq!((git_ahead, git_behind), (2, 0));
    let comparison = compare_in(
        &repo,
        "store-shallow",
        None,
        Some(&fallback),
        &local,
        &upstream,
    );
    assert_eq!(comparison.state, "ahead");
    assert_eq!(comparison.ahead, Some(2));
    assert_eq!(comparison.behind, Some(0));
}

#[test]
fn shallow_cut_crossed_is_incomplete_history() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-cut");
    // Six linear commits C0..C5; forge a shallow boundary at C2 by
    // writing the `shallow` file by hand (same file `clone --depth`
    // writes). Branch `old` stays at C1; upstream `origin/main`
    // points at C4: the C4-side walk must yield C2 (boundary) to
    // prove its count — the cut is crossed.
    let (repo, oids) = fixture::commit_chain(root.path(), "chain", 6);
    fixture::git(&repo, &["update-ref", "refs/heads/old", &oids[1]]);
    fixture::git(&repo, &["update-ref", "refs/remotes/origin/main", &oids[4]]);
    repo_scan::privacy::private_write_0600(
        &repo.join(".git/shallow"),
        format!("{}\n", oids[2]).as_bytes(),
    )
    .expect("write shallow file");
    // Reference: git treats the store as shallow now.
    assert_eq!(
        fixture::git_str(&repo, &["rev-parse", "--is-shallow-repository"]),
        "true"
    );
    let comparison = compare_branch_in(
        &repo,
        "store-cut",
        None,
        Some(&fallback),
        b"refs/heads/old",
        Some(b"refs/remotes/origin/main"),
        true,
    );
    assert_eq!(comparison.state, "incomplete_history");
    assert_eq!(comparison.ahead, None);
    assert_eq!(comparison.behind, None);
    // Installed git still prints (cut) numbers — we refuse to claim
    // them. The refusal is the honest behavior under test.
    let output = fixture::git_output(
        &repo,
        &[
            "rev-list",
            "--left-right",
            "--count",
            &format!("{}...{}", oids[1], oids[4]),
        ],
    );
    assert!(
        output.status.success(),
        "git prints cut counts where we refuse"
    );
}

#[test]
fn grafted_store_is_incomplete_history() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-graft");
    let (repo, oids) = fixture::commit_chain(root.path(), "chain", 4);
    // Graft C3 onto C0 (skipping C1..C2): gix cannot see it.
    repo_scan::privacy::private_write_0600(
        &repo.join(".git/info/grafts"),
        format!("{} {}\n", oids[3], oids[0]).as_bytes(),
    )
    .expect("write grafts file");
    assert!(grafts_present(&repo.join(".git"), &repo.join(".git")));
    let comparison = compare_in(
        &repo,
        "store-graft",
        None,
        Some(&fallback),
        &oids[3],
        &oids[0],
    );
    assert_eq!(comparison.state, "incomplete_history");
    assert_eq!(comparison.ahead, None);
    assert_eq!(comparison.behind, None);
}

#[test]
fn missing_object_is_error_in_full_store() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-damaged");
    let (repo, oids) = fixture::commit_chain(root.path(), "chain", 5);
    // Delete C3's commit object: the C4-side walk (excluding
    // reach(C2)) must read through C3 and fail. Documented
    // behavior: missing objects in a NON-shallow store are `error`
    // (same store shallow would be `incomplete_history`, since the
    // object may sit below the cut).
    let (fan, rest) = oids[3].split_at(2);
    let object_path = repo.join(".git/objects").join(fan).join(rest);
    assert!(object_path.is_file(), "C3 object is loose");
    std::fs::remove_file(&object_path).expect("delete C3 object");
    // Reference: installed git fails the same walk.
    let output = fixture::git_output(
        &repo,
        &[
            "rev-list",
            "--left-right",
            "--count",
            &format!("{}...{}", oids[2], oids[4]),
        ],
    );
    assert!(!output.status.success(), "git fails on missing C3");
    // With the fallback available: gix fails, rev-list fails too.
    let comparison = compare_in(
        &repo,
        "store-damaged",
        None,
        Some(&fallback),
        &oids[2],
        &oids[4],
    );
    assert_eq!(comparison.state, "error");
    assert_eq!(comparison.ahead, None);
    assert_eq!(comparison.behind, None);
    // Without any fallback: still error, never a partial count.
    let comparison = compare_in(&repo, "store-damaged", None, None, &oids[2], &oids[4]);
    assert_eq!(comparison.state, "error");
}

#[test]
fn unborn_branch_stays_explicit_error() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-unborn");
    let repo = fixture::unborn_branch(root.path(), "unborn");
    // Reference: HEAD is symbolic to an unborn branch.
    let head = fixture::git_str(&repo, &["symbolic-ref", "HEAD"]);
    assert_eq!(head, "refs/heads/main");
    let verify = fixture::git_output(&repo, &["rev-parse", "--verify", "refs/heads/main"]);
    assert!(!verify.status.success(), "main must be unborn");
    // An unborn branch has no OID: compare_branch with a resolved
    // upstream but no local OID is error, never equal.
    let git_dir = repo.join(".git");
    let ctx = CompareContext {
        git_dir: &git_dir,
        common_dir: &git_dir,
        store_id: "store-unborn",
        use_replace_refs: None,
        replace_ref_base: None,
        work_tree: Some(&repo),
        cache: None,
        fallback: Some(&fallback),
        cancel: None,
    };
    let comparison = compare_branch(
        &ctx,
        &BranchTips {
            local_hex: None,
            local_algo: None,
            upstream: Some(b"refs/remotes/origin/main"),
            upstream_hex: Some("1111111111111111111111111111111111111111"),
            upstream_algo: Some("sha1"),
            upstream_known: true,
        },
    );
    assert_eq!(comparison.state, "error");
    assert_eq!(comparison.ahead, None);
}

#[test]
fn rev_list_fallback_matches_gix_counts() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-fallback");
    let repo = fixture::comparison_pair(root.path(), "pair", 2, 3);
    let local = fixture::git_str(&repo, &["rev-parse", "refs/heads/main"]);
    let upstream = fixture::git_str(&repo, &["rev-parse", "refs/remotes/origin/main"]);
    let git_dir = repo.join(".git");
    let (ahead, behind) = fallback
        .rev_list_count(&git_dir, Some(repo.as_path()), &local, &upstream)
        .expect("rev-list fallback");
    assert_eq!((ahead, behind), (2, 3));
    // Empty tips are refused, never spawned.
    assert!(fallback
        .rev_list_count(&git_dir, Some(repo.as_path()), "", &upstream)
        .is_err());
}

#[test]
fn rev_list_fallback_does_not_fetch_missing_promisor_commits() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-promisor-offline");
    let source = fixture::normal_clone(root.path(), "source");
    let ancestor = fixture::git_str(&source, &["rev-parse", "HEAD"]);
    let tip = fixture::commit_file(&source, "promised.txt", "promised\n", "promised tip");

    let create_promisor = |name: &str| {
        let repo = root.path().join(name);
        std::fs::create_dir(&repo).expect("promisor repo dir");
        fixture::git(&repo, &["init"]);
        let source_url = source.to_string_lossy().into_owned();
        fixture::git(&repo, &["config", "remote.origin.url", &source_url]);
        fixture::git(&repo, &["config", "remote.origin.promisor", "true"]);
        fixture::git(&repo, &["config", "extensions.partialClone", "origin"]);
        repo
    };

    let repo = create_promisor("scan");
    let git_dir = repo.join(".git");
    let error = fallback
        .rev_list_count(&git_dir, Some(&repo), &ancestor, &tip)
        .expect_err("missing promised commits cannot be fetched during graph reads");
    assert!(error.to_string().contains("rev-list"), "{error}");
    assert_no_promisor_objects(&git_dir, [&ancestor, &tip]);

    // Prove this fixture would trigger Git's normal lazy-fetch behavior.
    // The remote is a repository created under this test's private scratch
    // root, so this control stays local and never accesses the network.
    let control = create_promisor("control");
    assert_eq!(git_counts(&control, &ancestor, &tip), (0, 1));
    assert_promisor_objects_present(&control.join(".git"), [&ancestor, &tip]);
}

fn assert_no_promisor_objects<'a>(git_dir: &Path, oids: impl IntoIterator<Item = &'a String>) {
    for oid in oids {
        let loose = git_dir.join("objects").join(&oid[..2]).join(&oid[2..]);
        assert!(
            !loose.exists(),
            "unexpected loose promisor object: {loose:?}"
        );
    }
    let pack_dir = git_dir.join("objects/pack");
    let has_pack = std::fs::read_dir(&pack_dir)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    assert!(!has_pack, "promisor read unexpectedly fetched a pack");
}

fn assert_promisor_objects_present<'a>(git_dir: &Path, oids: impl IntoIterator<Item = &'a String>) {
    let loose = oids.into_iter().any(|oid| {
        git_dir
            .join("objects")
            .join(&oid[..2])
            .join(&oid[2..])
            .exists()
    });
    let pack_dir = git_dir.join("objects/pack");
    let has_pack = std::fs::read_dir(&pack_dir)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    assert!(
        loose || has_pack,
        "control did not materialize promised objects"
    );
}

#[test]
fn rev_list_fallback_observes_expired_deadline() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-fallback-cancel");
    let repo = fixture::comparison_pair(root.path(), "pair", 100, 100);
    let local = fixture::git_str(&repo, &["rev-parse", "refs/heads/main"]);
    let upstream = fixture::git_str(&repo, &["rev-parse", "refs/remotes/origin/main"]);
    let git_dir = repo.join(".git");
    let cancel = WaitCancel::new(
        || false,
        Some(std::time::Instant::now() - std::time::Duration::from_millis(1)),
    );

    assert!(fallback
        .rev_list_count_cancel(&git_dir, Some(&repo), &local, &upstream, &cancel)
        .is_err());
}

#[test]
fn linked_worktree_replace_ref_contexts_do_not_share_cached_counts() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-worktree-replace");
    let main = fixture::normal_clone(root.path(), "main");
    let ancestor = fixture::git_str(&main, &["rev-parse", "HEAD"]);
    let parent = fixture::commit_file(&main, "README.md", "parent\n", "parent");
    let local = fixture::commit_file(&main, "README.md", "local\n", "local");
    let tree = fixture::git_str(&main, &["rev-parse", &format!("{parent}^{{tree}}")]);
    let replacement = fixture::git_str(&main, &["commit-tree", &tree, "-m", "replacement root"]);

    fixture::git(&main, &["config", "extensions.worktreeConfig", "true"]);
    fixture::git(&main, &["branch", "-f", "upstream", &ancestor]);
    fixture::git(&main, &["replace", &parent, &replacement]);
    let linked = root.path().join("linked");
    let linked_arg = linked.to_string_lossy().into_owned();
    fixture::git(
        &main,
        &["worktree", "add", "-q", "-b", "linked", &linked_arg, &local],
    );
    fixture::git(
        &main,
        &["config", "--worktree", "core.useReplaceRefs", "true"],
    );
    fixture::git(
        &linked,
        &["config", "--worktree", "core.useReplaceRefs", "false"],
    );

    // The upstream is the original root: replacing `parent` makes the
    // enabled worktree's local history diverge from it.
    let expected_enabled = fixture::git_str(
        &main,
        &[
            "rev-list",
            "--left-right",
            "--count",
            &format!("{local}...{ancestor}"),
        ],
    );
    let expected_disabled = fixture::git_str(
        &linked,
        &[
            "rev-list",
            "--left-right",
            "--count",
            &format!("{local}...{ancestor}"),
        ],
    );
    assert_eq!(expected_enabled, "2\t1");
    assert_eq!(expected_disabled, "2\t0");

    let main_git_dir = PathBuf::from(fixture::git_str(
        &main,
        &["rev-parse", "--absolute-git-dir"],
    ));
    let linked_git_dir = PathBuf::from(fixture::git_str(
        &linked,
        &["rev-parse", "--absolute-git-dir"],
    ));
    let common_dir = main.join(fixture::git_str(&main, &["rev-parse", "--git-common-dir"]));
    let store_id = common_dir.to_string_lossy().into_owned();
    let cache = ComparisonCache::new();
    assert_eq!(
        fallback
            .rev_list_count_with_replace_refs(
                &linked_git_dir,
                Some(&linked),
                &local,
                &ancestor,
                true,
            )
            .expect("explicit replacement policy"),
        (2, 1),
        "explicit policy overrides the linked checkout's local false setting"
    );
    let main_context = CompareContext {
        git_dir: &main_git_dir,
        common_dir: &common_dir,
        store_id: &store_id,
        use_replace_refs: Some(true),
        replace_ref_base: Some("refs/replace/"),
        work_tree: Some(&main),
        cache: Some(&cache),
        fallback: Some(&fallback),
        cancel: None,
    };
    let linked_context = CompareContext {
        git_dir: &linked_git_dir,
        common_dir: &common_dir,
        store_id: &store_id,
        use_replace_refs: Some(false),
        replace_ref_base: Some("refs/replace/"),
        work_tree: Some(&linked),
        cache: Some(&cache),
        fallback: Some(&fallback),
        cancel: None,
    };

    assert_eq!(
        compare_oids(&main_context, &local, &ancestor, "sha1"),
        Comparison::from_counts(2, 1),
        "enabled worktree follows the replacement commit ancestry"
    );
    assert_eq!(
        compare_oids(&linked_context, &local, &ancestor, "sha1"),
        Comparison::from_counts(2, 0),
        "disabled linked worktree follows the original commit ancestry"
    );
    assert_eq!(
        cache.walks(),
        2,
        "different effective contexts must walk separately"
    );
    assert_eq!(
        cache.hits(),
        0,
        "one worktree must not reuse the other's counts"
    );

    let custom_ref = format!("refs/custom/{parent}");
    fixture::git(&main, &["update-ref", &custom_ref, &replacement]);
    let custom_context = CompareContext {
        git_dir: &main_git_dir,
        common_dir: &common_dir,
        store_id: &store_id,
        use_replace_refs: Some(true),
        replace_ref_base: Some("refs/custom/"),
        work_tree: Some(&main),
        cache: None,
        fallback: Some(&fallback),
        cancel: None,
    };
    assert_eq!(
        compare_oids(&custom_context, &local, &ancestor, "sha1"),
        Comparison::pending(),
        "Git rev-list cannot safely represent a custom gix replacement namespace"
    );
}

#[test]
fn reftable_replacement_refs_use_git_fallback() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-reftable-replace");
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo).expect("create reftable repo directory");
    let init = fixture::git_output(&repo, &["init", "-q", "--ref-format=reftable"]);
    if !init.status.success() {
        // Older installed Git versions do not support reftable.
        return;
    }

    let ancestor = fixture::commit_file(&repo, "README.md", "root\n", "root");
    let parent = fixture::commit_file(&repo, "README.md", "parent\n", "parent");
    let local = fixture::commit_file(&repo, "README.md", "local\n", "local");
    let tree = fixture::git_str(&repo, &["rev-parse", &format!("{parent}^{{tree}}")]);
    let replacement = fixture::git_str(&repo, &["commit-tree", &tree, "-m", "replacement root"]);
    fixture::git(&repo, &["replace", &parent, &replacement]);

    let git_dir = PathBuf::from(fixture::git_str(
        &repo,
        &["rev-parse", "--absolute-git-dir"],
    ));
    let common_dir = PathBuf::from(fixture::git_str(
        &repo,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    ));
    assert!(
        common_dir.join("reftable/tables.list").is_file(),
        "replacement refs are stored in the reftable database"
    );
    assert!(
        !common_dir.join("refs/replace").exists(),
        "the fixture must not expose its replacement ref as a loose ref"
    );
    assert!(
        !common_dir.join("packed-refs").exists(),
        "the fixture must not expose its replacement ref in packed-refs"
    );

    let context_without_fallback = CompareContext {
        git_dir: &git_dir,
        common_dir: &common_dir,
        store_id: "reftable-replacement-refs",
        use_replace_refs: Some(true),
        replace_ref_base: Some("refs/replace/"),
        work_tree: Some(&repo),
        cache: None,
        fallback: None,
        cancel: None,
    };
    assert_eq!(
        compare_oids(&context_without_fallback, &local, &ancestor, "sha1"),
        Comparison::pending(),
        "an opaque reftable store must not be walked under an unverified policy"
    );

    let expected = git_counts(&repo, &local, &ancestor);
    assert_eq!(expected, (2, 1));
    let context_with_fallback = CompareContext {
        fallback: Some(&fallback),
        ..context_without_fallback
    };
    assert_eq!(
        compare_oids(&context_with_fallback, &local, &ancestor, "sha1"),
        Comparison::from_counts(expected.0, expected.1),
        "Git rev-list must provide counts with its reftable replacement semantics"
    );
}

#[test]
fn empty_custom_replace_base_does_not_fallback_through_standard_replace_refs() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-custom-empty-replace-base");
    let repo = fixture::normal_clone(root.path(), "repo");
    let ancestor = fixture::git_str(&repo, &["rev-parse", "HEAD"]);
    let parent = fixture::commit_file(&repo, "README.md", "parent\n", "parent");
    let local = fixture::commit_file(&repo, "README.md", "local\n", "local");
    let tree = fixture::git_str(&repo, &["rev-parse", &format!("{parent}^{{tree}}")]);
    let replacement = fixture::git_str(&repo, &["commit-tree", &tree, "-m", "replacement root"]);
    fixture::git(
        &repo,
        &[
            "update-ref",
            &format!("refs/replace/{parent}"),
            &replacement,
        ],
    );

    let git_dir = PathBuf::from(fixture::git_str(
        &repo,
        &["rev-parse", "--absolute-git-dir"],
    ));
    let common_dir = git_dir.clone();
    let objects_dir = PathBuf::from(fixture::git_str(
        &repo,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
        ],
    ));
    let parent_object = objects_dir.join(&parent[..2]).join(&parent[2..]);
    assert!(parent_object.is_file(), "fixture parent is a loose object");
    std::fs::remove_file(&parent_object).expect("remove parent to force the gix fallback path");

    // Keep the configured custom namespace present but empty, while a
    // standard replacement ref remains available to Git's fallback.
    let custom_refs = common_dir.join("refs/custom");
    std::fs::create_dir_all(&custom_refs).expect("create empty custom namespace");
    assert_eq!(std::fs::read_dir(&custom_refs).unwrap().count(), 0);
    assert_eq!(
        fallback
            .rev_list_count_with_replace_refs(&git_dir, Some(&repo), &local, &ancestor, true)
            .expect("standard Git replacement ref is usable"),
        (2, 1),
        "the standard namespace would produce counts that differ from the empty custom namespace"
    );

    let context = CompareContext {
        git_dir: &git_dir,
        common_dir: &common_dir,
        store_id: "custom-empty-replace-base",
        use_replace_refs: Some(true),
        replace_ref_base: Some("refs/custom/"),
        work_tree: Some(&repo),
        cache: None,
        fallback: Some(&fallback),
        cancel: None,
    };
    assert_eq!(
        compare_oids(&context, &local, &ancestor, "sha1"),
        Comparison::pending(),
        "Git's standard replacement refs must not stand in for an empty custom namespace"
    );
}

#[test]
fn canceled_graph_walk_stops_before_visiting_the_history() {
    if git_or_skip().is_none() {
        return;
    }
    let root = fixture::scratch_root("graph-cancel");
    let repo = fixture::normal_clone(root.path(), "linear");
    let first = fixture::git_str(&repo, &["rev-parse", "HEAD"]);
    for i in 0..64 {
        fixture::commit_file(
            &repo,
            "README.md",
            &format!("commit {i}\n"),
            &format!("commit {i}"),
        );
    }
    let last = fixture::git_str(&repo, &["rev-parse", "HEAD"]);
    let checks = Arc::new(AtomicUsize::new(0));
    let check_counter = Arc::clone(&checks);
    let cancel = WaitCancel::new(
        move || check_counter.fetch_add(1, Ordering::Relaxed) >= 8,
        None,
    );
    let git_dir = repo.join(".git");
    let ctx = CompareContext {
        git_dir: &git_dir,
        common_dir: &git_dir,
        store_id: "cancelled-walk",
        use_replace_refs: None,
        replace_ref_base: None,
        work_tree: Some(&repo),
        cache: None,
        fallback: None,
        cancel: Some(&cancel),
    };

    let comparison = compare_oids(&ctx, &last, &first, "sha1");
    assert_eq!(comparison.state, "error");
    assert!(
        checks.load(Ordering::Relaxed) <= 10,
        "walk did not stop early"
    );
}

#[test]
fn graph_control_files_fail_closed_when_unreadable_or_malformed() {
    let root = fixture::scratch_root("graph-control-files");
    let git_dir = root.path().join(".git");
    std::fs::create_dir_all(git_dir.join("info")).expect("info dir");

    // Missing and empty control files do not make a repository
    // shallow or grafted.
    assert!(!shallow_present(&git_dir, &git_dir));
    assert!(!grafts_present(&git_dir, &git_dir));
    std::fs::write(git_dir.join("shallow"), b" \n\t").expect("empty shallow");
    std::fs::write(git_dir.join("info/grafts"), b"# comment\n\n").expect("empty grafts");
    assert!(!shallow_present(&git_dir, &git_dir));
    assert!(!grafts_present(&git_dir, &git_dir));

    // Invalid UTF-8 in a comment must not hide a later live graft line.
    std::fs::write(
        git_dir.join("info/grafts"),
        b"# invalid utf8: \xff\n1111111111111111111111111111111111111111\n",
    )
    .expect("malformed grafts");
    assert!(grafts_present(&git_dir, &git_dir));

    // An oversized file is unknown evidence, never silently treated as
    // an empty file.
    let oversized = vec![b' '; (repo_scan::git::MAX_GIT_CONTROL_BYTES + 1) as usize];
    std::fs::write(git_dir.join("shallow"), &oversized).expect("oversized shallow");
    std::fs::write(git_dir.join("info/grafts"), &oversized).expect("oversized grafts");
    assert!(shallow_present(&git_dir, &git_dir));
    assert!(grafts_present(&git_dir, &git_dir));
}

#[cfg(unix)]
#[test]
fn graph_control_file_probes_do_not_follow_symlinks() {
    use std::os::unix::fs::symlink;

    let root = fixture::scratch_root("graph-control-symlink");
    let git_dir = root.path().join(".git");
    std::fs::create_dir_all(git_dir.join("info")).expect("info dir");
    symlink("/dev/zero", git_dir.join("shallow")).expect("shallow symlink");
    symlink("/dev/zero", git_dir.join("info/grafts")).expect("grafts symlink");

    assert!(shallow_present(&git_dir, &git_dir));
    assert!(grafts_present(&git_dir, &git_dir));
}

// ---------------------------------------------------------------------------
// Non-UTF-8 branch names (unix-only fixture)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn non_utf8_branch_comparison_keeps_exact_bytes() {
    let Some(fallback) = git_or_skip() else {
        return;
    };
    let root = fixture::scratch_root("graph-nonutf8");
    let (repo, refname) = fixture::non_utf8_tracking_repo(root.path(), "hostile");
    assert!(
        std::str::from_utf8(&refname).is_err(),
        "fixture refname is hostile"
    );
    // Branch and upstream both sit at HEAD: equal, resolved with
    // byte-exact refnames (no lossy conversion anywhere).
    let comparison = compare_branch_in(
        &repo,
        "store-hostile",
        None,
        Some(&fallback),
        &refname,
        Some(b"refs/remotes/origin/main"),
        true,
    );
    assert_eq!(comparison.state, "equal");
    assert_eq!(comparison.ahead, Some(0));
    // Reference: installed git resolves the same hostile bytes.
    let head = fixture::git_str(&repo, &["rev-parse", "HEAD"]);
    assert_eq!(rev_parse_exact(&repo, &refname), head);
}
