//! Branch ahead/behind comparison tests (goal Step 10, Step 15 case 9).
//!
//! Every counted expectation is cross-checked against the installed
//! `git` binary (`rev-list --left-right --count`, `merge-base`,
//! `rev-parse`), never against our own walker. Git-dependent tests
//! skip quietly when no git binary is discoverable; the pure
//! state-derivation tables always run.

mod common;

use common::fixture;
use repo_scan::git::fallback::{FallbackGit, WaitCancel};
use repo_scan::git::graph::{
    compare_branch, compare_oids, grafts_present, shallow_present, BranchTips, CompareContext,
    Comparison, ComparisonCache, COMPARISON_STATES,
};
use repo_scan::model::StatusMode;
use repo_scan::report::builder::{stream_report_from_store, ReportInputs};
use repo_scan::report::model::Report;
use repo_scan::report::validate::validate_report;
use repo_scan::store::{
    NewCheckout, NewGitInstance, NewRef, NewRemote, NewStatus, NewVolume, Store, TursoStore,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Locate an installed git or skip the calling test.
fn git_or_skip() -> Option<FallbackGit> {
    FallbackGit::discover(&[])
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
        work_tree: Some(repo),
        cache,
        fallback,
        cancel: None,
    };
    compare_oids(&ctx, local, upstream, "sha1")
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
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
    // Catalog round-trip: hostile name + comparison coexist with
    // exact bytes (fresh opens are v6; the catalog lives under
    // TMPDIR, not the symlinked /tmp scratch root, because the
    // store refuses symlinked path components).
    runtime().block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        assert!(store.supports_ref_comparison().await.expect("gate"));
        let now = repo_scan::store::now_ms();
        store
            .upsert_ref(
                &NewRef {
                    id: "ref-hostile",
                    instance_id: "repo-1",
                    checkout_scope_id: None,
                    kind: "local",
                    name: &refname,
                    oid: Some(head.as_bytes()),
                    algo: Some("sha1"),
                    symbolic_target: None,
                    upstream: Some(b"refs/remotes/origin/main"),
                    state: "valid",
                },
                now,
            )
            .await
            .expect("upsert");
        assert!(store
            .update_ref_comparison("ref-hostile", "equal", Some(0), Some(0))
            .await
            .expect("label"));
        let rows = store.list_refs("repo-1").await.expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, refname, "name bytes exact");
        assert_eq!(rows[0].comparison_state.as_deref(), Some("equal"));
        assert_eq!(rows[0].ahead, Some(0));
        assert_eq!(rows[0].behind, Some(0));
    });
}

// ---------------------------------------------------------------------------
// Catalog migration v6 (additive, legacy-NULL)
// ---------------------------------------------------------------------------

/// Build a genuine v5 catalog through a direct connection: shipped
/// v1..v5 SQL, a `schema_version = 5` marker, and one legacy ref row.
/// `TursoStore::open` then migrates it to v6 (mirrors
/// `tests/store_migrate.rs`, which covers v1).
async fn build_v5_catalog(db: &std::path::Path) {
    let path_str = db.to_str().expect("utf8 db path");
    let conn = turso::Builder::new_local(path_str)
        .build()
        .await
        .expect("turso build")
        .connect()
        .expect("turso connect");
    let chain = repo_scan::store::migrations();
    assert!(chain.len() >= 6, "v6 chain wired");
    for migration in chain.iter().take(5) {
        conn.execute_batch(migration.sql).await.expect("v1..v5 sql");
    }
    conn.execute(
        "INSERT INTO meta (name, value) VALUES ('schema_version', '5')",
        (),
    )
    .await
    .expect("v5 marker");
    conn.execute(
        "INSERT INTO refs (id, instance_id, checkout_scope_id, kind, name, \
            oid, algo, symbolic_target, upstream, state, observed_at_ms) \
            VALUES ('ref-legacy', 'repo-1', NULL, 'local', \
            ?1, ?2, 'sha1', NULL, ?3, 'valid', 100)",
        vec![
            turso::Value::Blob(b"refs/heads/main".to_vec()),
            turso::Value::Blob(b"1111111111111111111111111111111111111111".to_vec()),
            turso::Value::Blob(b"refs/remotes/origin/main".to_vec()),
        ],
    )
    .await
    .expect("v5 ref row");
}

#[test]
fn v6_migration_is_additive_with_legacy_null() {
    runtime().block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        build_v5_catalog(&db).await;
        // Open migrates v5 -> v6; the legacy ref row reads NULL
        // (pending) and new labels persist and round-trip.
        let store = TursoStore::open(&db).await.expect("open upgrades");
        assert_eq!(store.schema_version().expect("version"), 6);
        assert!(store.supports_ref_comparison().await.expect("gate"));
        let rows = store.list_refs("repo-1").await.expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].comparison_state, None, "legacy NULL");
        assert_eq!(rows[0].ahead, None);
        assert_eq!(rows[0].behind, None);
        assert!(store
            .update_ref_comparison("ref-legacy", "ahead", Some(1), Some(0))
            .await
            .expect("label"));
        let rows = store.list_refs("repo-1").await.expect("list");
        assert_eq!(rows[0].comparison_state.as_deref(), Some("ahead"));
        assert_eq!(rows[0].ahead, Some(1));
        assert_eq!(rows[0].behind, Some(0));
        // D1 record IDs stable: the ref id survives the migration.
        assert_eq!(rows[0].id, "ref-legacy");
    });
}

// ---------------------------------------------------------------------------
// Report 1.4.0 plumbing: builder + validator + shipped schema
// ---------------------------------------------------------------------------

fn test_inputs(report_id: &str) -> ReportInputs {
    ReportInputs {
        report_id: report_id.to_string(),
        created_at_ms: 1_759_154_400_000,
        scan_id: "scan-test-1".to_string(),
        generation: 1,
        epoch: 1,
        catalog_revision: 7,
        target_url: "https://github.com/OWNER/REPO".to_string(),
        canonical_url: Some("https://github.com/owner/repo".to_string()),
        targets: vec![],
        scope: "roots".to_string(),
        scan_state: "complete".to_string(),
        started_at_ms: 1_759_154_398_000,
        finished_at_ms: Some(1_759_154_400_000),
        superseded_by: None,
        cached: false,
        status_mode: StatusMode::Summary,
        directories_complete: 2,
        tasks_pending: 0,
        scope_boundaries: vec!["Only the explicit fixture root was requested.".to_string()],
        profile: "conservative".to_string(),
        cpu_target_cores: 1.0,
        rss_target_bytes: 268_435_456,
        peak_rss_bytes: None,
        cpu_seconds: None,
        enumerated_entries: 8,
        db_transactions: 3,
        db_sync_calls: None,
        source_commit: None,
        include_nonmatching: false,
        coverage_filesystem: None,
        coverage_identity: None,
        coverage_status: None,
        roots: Vec::new(),
        storage_links: Vec::new(),
        aliases: Vec::new(),
        candidates: Vec::new(),
        generated_artifacts: Vec::new(),
    }
}

/// Seed one confirmed repo + checkout + remote + status (mirrors the
/// report-harness seed); refs are added per-test.
async fn seed_base(store: &TursoStore, now: i64) {
    store
        .upsert_volume(
            &NewVolume {
                id: "vol-1",
                native_identity: Some("native-1"),
                namespace: "ns-1",
                filesystem: Some("apfs"),
                kind: "local",
                state: "available",
            },
            Some(now),
        )
        .await
        .expect("volume");
    let root = store
        .upsert_dir(None, b"/", "/", "vol-1", "obj-root", "1", now)
        .await
        .expect("root dir");
    store
        .upsert_dir(Some(root), b"repo", "/repo", "vol-1", "obj-repo", "1", now)
        .await
        .expect("child dir");
    store
        .upsert_git_instance(
            &NewGitInstance {
                id: "repo-1",
                git_path: b"/repo/.git",
                common_path: b"/repo/.git",
                incarnation: "1",
                format: "git-files",
                bare: Some(false),
                object_format: "sha1",
                disposition: "confirmed",
                evidence_json: "[\"Effective origin fetch URL matches the target.\"]",
            },
            now,
        )
        .await
        .expect("instance");
    store
        .upsert_checkout(
            &NewCheckout {
                id: "co-1",
                instance_id: "repo-1",
                root_path: Some(b"/repo"),
                git_path: b"/repo/.git",
                relationship: "main",
                availability: "present",
                head_state: "branch",
                head_ref: Some(b"refs/heads/main"),
                head_oid: Some(b"1111111111111111111111111111111111111111"),
                head_algo: Some("sha1"),
            },
            now,
        )
        .await
        .expect("checkout");
    store
        .upsert_remote(
            &NewRemote {
                id: "rem-1",
                instance_id: "repo-1",
                checkout_scope_id: None,
                name: b"origin",
                role: "fetch",
                url: b"https://github.com/owner/repo.git",
                canonical_url: Some(b"https://github.com/owner/repo"),
            },
            now,
        )
        .await
        .expect("remote");
    store
        .record_status(
            &NewStatus {
                checkout_id: "co-1",
                mode: "summary",
                state: "complete",
                started_ms: Some(now - 10),
                finished_ms: Some(now),
                staged: Some(1),
                unstaged: Some(2),
                untracked: Some(3),
                conflicts: Some(0),
                working_state: "dirty",
                untracked_units: "collapsed_entries",
                submodules: "checked",
                unknown_fields: "[]",
                input_fingerprint: None,
                observed_rev: 1,
            },
            now,
        )
        .await
        .expect("status");
}

async fn seed_ref(store: &TursoStore, now: i64, id: &str, name: &[u8], upstream: Option<&[u8]>) {
    store
        .upsert_ref(
            &NewRef {
                id,
                instance_id: "repo-1",
                checkout_scope_id: None,
                kind: "local",
                name,
                oid: Some(b"1111111111111111111111111111111111111111"),
                algo: Some("sha1"),
                symbolic_target: None,
                upstream,
                state: "valid",
            },
            now,
        )
        .await
        .expect("ref");
}

async fn stream_value(store: &TursoStore, report_id: &str) -> serde_json::Value {
    let inputs = test_inputs(report_id);
    let (bytes, _) = stream_report_from_store(store, &inputs, Vec::new())
        .await
        .expect("stream");
    serde_json::from_slice(&bytes).expect("report is JSON")
}

#[test]
fn builder_emits_pending_on_unlabeled_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("catalog.db");
    runtime().block_on(async {
        // Fresh opens are v6; unlabeled rows (legacy NULL) read pending.
        // The v5-upgrade path is covered by
        // v6_migration_is_additive_with_legacy_null.
        let store = TursoStore::open(&db).await.expect("open");
        assert!(store.supports_ref_comparison().await.expect("gate"));
        let now = repo_scan::store::now_ms();
        seed_base(&store, now).await;
        seed_ref(&store, now, "ref-1", b"refs/heads/main", None).await;
        let value = stream_value(&store, "rep-unlabeled").await;
        assert_eq!(value["schema_version"], "1.5.0");
        let branches = value["branches"].as_array().expect("branches");
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0]["comparison"], "pending");
        assert!(branches[0]["ahead"].is_null());
        assert!(branches[0]["behind"].is_null());
        // The 1.4.0 report with pending comparisons validates.
        let report: Report = serde_json::from_value(value).expect("model");
        validate_report(&report).expect("validates");
    });
}

#[test]
fn builder_emits_labels_on_v6_catalog() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("catalog.db");
    runtime().block_on(async {
        let store = TursoStore::open(&db).await.expect("open");
        assert!(store.supports_ref_comparison().await.expect("gate"));
        let now = repo_scan::store::now_ms();
        seed_base(&store, now).await;
        seed_ref(
            &store,
            now,
            "ref-ahead",
            b"refs/heads/main",
            Some(b"refs/remotes/origin/main"),
        )
        .await;
        seed_ref(&store, now, "ref-unlabeled", b"refs/heads/other", None).await;
        assert!(store
            .update_ref_comparison("ref-ahead", "ahead", Some(2), Some(0))
            .await
            .expect("label"));
        let value = stream_value(&store, "rep-v6").await;
        let branches = value["branches"].as_array().expect("branches");
        assert_eq!(branches.len(), 2);
        let main = branches
            .iter()
            .find(|b| b["id"] == "ref-ahead")
            .expect("main");
        assert_eq!(main["comparison"], "ahead");
        assert_eq!(main["ahead"], 2);
        assert_eq!(main["behind"], 0);
        // Unlabeled v6 rows read pending (legacy-NULL rule).
        let other = branches
            .iter()
            .find(|b| b["id"] == "ref-unlabeled")
            .expect("other");
        assert_eq!(other["comparison"], "pending");
        assert!(other["ahead"].is_null());
        let report: Report = serde_json::from_value(value).expect("model");
        validate_report(&report).expect("validates");
    });
}

#[test]
fn shipped_v14_schema_accepts_compared_report() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("catalog.db");
    runtime().block_on(async {
        let store = TursoStore::open(&db).await.expect("open");
        assert!(store.supports_ref_comparison().await.expect("gate"));
        let now = repo_scan::store::now_ms();
        seed_base(&store, now).await;
        seed_ref(
            &store,
            now,
            "ref-div",
            b"refs/heads/main",
            Some(b"refs/remotes/origin/main"),
        )
        .await;
        assert!(store
            .update_ref_comparison("ref-div", "diverged", Some(2), Some(3))
            .await
            .expect("label"));
        let value = stream_value(&store, "rep-schema").await;
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/report-v1.5.schema.json"
        );
        let bytes = std::fs::read(path).expect("read shipped schema");
        let schema: serde_json::Value = serde_json::from_slice(&bytes).expect("schema parses");
        let validator = jsonschema::validator_for(&schema).expect("schema compiles");
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "schema violations: {errors:?}");
    });
}

#[test]
fn validator_accepts_13_and_enforces_count_shape() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("catalog.db");
    runtime().block_on(async {
        let store = TursoStore::open(&db).await.expect("open");
        let now = repo_scan::store::now_ms();
        seed_base(&store, now).await;
        seed_ref(&store, now, "ref-1", b"refs/heads/main", None).await;
        let mut value = stream_value(&store, "rep-version").await;
        // A 1.3.0 snapshot (old version, no comparison fields)
        // deserializes with pending defaults and validates.
        value["schema_version"] = serde_json::Value::String("1.3.0".to_string());
        for branch in value["branches"].as_array_mut().expect("branches") {
            let object = branch.as_object_mut().expect("branch");
            object.remove("comparison");
            object.remove("ahead");
            object.remove("behind");
        }
        let report: Report = serde_json::from_value(value.clone()).expect("model");
        assert_eq!(report.branches[0].comparison, "pending");
        validate_report(&report).expect("1.3.0 validates");
        // Bad count shape: `equal` with nonzero ahead fails.
        let mut bad = value.clone();
        bad["schema_version"] = serde_json::Value::String("1.4.0".to_string());
        bad["branches"][0]["comparison"] = serde_json::Value::String("equal".to_string());
        bad["branches"][0]["ahead"] = serde_json::Value::from(1);
        bad["branches"][0]["behind"] = serde_json::Value::from(0);
        let report: Report = serde_json::from_value(bad).expect("model");
        assert!(validate_report(&report).is_err(), "bad shape must fail");
        // Unknown state fails.
        let mut bad = value;
        bad["schema_version"] = serde_json::Value::String("1.4.0".to_string());
        bad["branches"][0]["comparison"] = serde_json::Value::String("synced".to_string());
        let report: Report = serde_json::from_value(bad).expect("model");
        assert!(validate_report(&report).is_err(), "bad state must fail");
    });
}

// ---------------------------------------------------------------------------
// Scan-level: the analysis pass computes without breaking the report
// ---------------------------------------------------------------------------

/// Scan target matching [`fixture::FIXTURE_REMOTE_URL`] (same shape as
/// the git acceptance suite).
const TARGET: &str = "https://github.com/OWNER/REPO";

#[test]
fn scan_emits_valid_branch_comparison() {
    if git_or_skip().is_none() {
        return;
    }
    let root = fixture::scratch_root("graph-scan");
    let work = root.path().join("work");
    std::fs::create_dir_all(&work).expect("work dir");
    let repo = fixture::comparison_pair(&work, "pair", 1, 0);
    let state = root.path().join("state");
    let report_path = root.path().join("report.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_repo-scan"))
        .args([
            "--state-dir",
            state.to_str().expect("utf8"),
            "scan",
            TARGET,
            "--root",
            work.to_str().expect("utf8"),
            "--report",
            report_path.to_str().expect("utf8"),
        ])
        .current_dir(&work)
        .output()
        .expect("spawn repo-scan");
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(&report_path).expect("read report");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("report is JSON");
    assert_eq!(value["schema_version"], "1.5.0");
    // The scanned branch carries a well-formed comparison: any of
    // the nine states (pre-v6 wiring the catalog cannot persist
    // labels, so analysis reads back `pending`; post-wiring this
    // becomes `ahead` — the test holds across the wiring step).
    let branches = value["branches"].as_array().expect("branches");
    let main = branches
        .iter()
        .find(|b| b["name"]["value"] == "refs/heads/main")
        .expect("main branch");
    let comparison = main["comparison"].as_str().expect("comparison");
    assert!(
        COMPARISON_STATES.contains(&comparison),
        "state {comparison:?} in vocabulary (repo {})",
        repo.display()
    );
    let report: Report = serde_json::from_value(value).expect("model");
    validate_report(&report).expect("scan report validates");
}
