//! Goal exact-count acceptance (GOAL_CONTRACTS.md D1).
//!
//! One main checkout + 3 linked worktrees sharing store A, plus an
//! independent clone B of the same origin: the report must list EXACTLY 2
//! `repositories` rows and EXACTLY 5 `checkouts` rows, with per-store branch
//! rows matching the installed `git` CLI (the independent reference — no
//! self-comparison against scanner helpers).

mod common;

use common::fixture;
use repo_scan::privacy::private_dir_0700;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

const URL: &str = "https://github.com/goal-owner/goal-repo";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Run the binary with global `--state-dir <state>` from `cwd`.
fn run(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    ProcCommand::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

fn read_report(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("report is valid JSON")
}

/// Independent local-branch count from the installed git CLI.
fn git_branch_count(dir: &Path) -> usize {
    fixture::git_str(dir, &["branch", "--list"])
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
}

fn path_value(paths: &HashMap<String, String>, id: &serde_json::Value) -> String {
    id.as_str()
        .and_then(|k| paths.get(k))
        .cloned()
        .unwrap_or_default()
}

/// Repository id of the checkout whose root (or git dir) is `dir`.
fn repo_of_checkout(
    paths: &HashMap<String, String>,
    checkouts: &[serde_json::Value],
    dir: &Path,
) -> String {
    let needle = dir.to_string_lossy().into_owned();
    for co in checkouts {
        let root_p = path_value(paths, &co["root_path_id"]);
        let git_p = path_value(paths, &co["git_path_id"]);
        if root_p == needle || git_p.starts_with(&needle) {
            return co["repository_id"]
                .as_str()
                .expect("checkout.repository_id")
                .to_owned();
        }
    }
    panic!("no checkout row for {}", needle)
}

#[test]
fn goal_exact_counts_main_plus_worktrees_plus_clone() {
    let tmp = fixture::scratch_root("goal-counts");
    let base = tmp.path().to_path_buf();

    // Origin (outside the scan root so it is never counted): 2 branches.
    let origin = base.join("seed-origin");
    private_dir_0700(&origin).unwrap();
    fixture::git(&origin, &["init", "-q"]);
    fixture::commit_file(&origin, "README.md", "# goal\n", "initial");
    fixture::git(&origin, &["branch", "-M", "main"]);
    fixture::git(&origin, &["branch", "feature"]);
    assert_eq!(
        git_branch_count(&origin),
        2,
        "origin has 2 branches (git CLI)"
    );
    let origin_arg = origin.to_string_lossy().into_owned();

    // Scan root: clone A + 3 linked worktrees + independent clone B.
    let root = base.join("root");
    private_dir_0700(&root).unwrap();
    fixture::git(&root, &["clone", "-q", &origin_arg, "clone-a"]);
    let clone_a = root.join("clone-a");
    fixture::git(&clone_a, &["remote", "set-url", "origin", URL]);
    fixture::git(&clone_a, &["branch", "feature"]);
    let expect_local_a = git_branch_count(&clone_a);
    assert_eq!(expect_local_a, 2, "clone A has 2 local branches (git CLI)");

    for i in 1..=3 {
        let wt = root.join(format!("wt-{i}"));
        let wt_arg = wt.to_string_lossy().into_owned();
        fixture::git(&clone_a, &["worktree", "add", "--detach", &wt_arg]);
    }
    let wt_list = fixture::git_str(&clone_a, &["worktree", "list"]);
    assert_eq!(
        wt_list.lines().filter(|l| !l.trim().is_empty()).count(),
        4,
        "main + 3 linked worktrees (git CLI)"
    );

    fixture::git(&root, &["clone", "-q", &origin_arg, "clone-b"]);
    let clone_b = root.join("clone-b");
    fixture::git(&clone_b, &["remote", "set-url", "origin", URL]);
    assert_eq!(
        git_branch_count(&clone_b),
        1,
        "clone B has 1 local branch (git CLI)"
    );

    fixture::assert_is_repo(&clone_a);
    fixture::assert_is_repo(&clone_b);
    assert_eq!(
        fixture::git_str(&clone_a, &["remote", "get-url", "origin"]),
        URL
    );
    assert_eq!(
        fixture::git_str(&clone_b, &["remote", "get-url", "origin"]),
        URL
    );

    // Scan with a fresh state dir; report outside the root.
    let state = base.join("state");
    let rep = base.join("rep.json");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root.to_str().expect("utf8"),
            "--report",
            rep.to_str().expect("utf8"),
        ],
        &base,
        &state,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let report = read_report(&rep);

    // EXACT store/checkout counts.
    let repos = report["repositories"].as_array().expect("repositories[]");
    assert_eq!(repos.len(), 2, "exactly two local stores, got {repos:?}");
    let checkouts = report["checkouts"].as_array().expect("checkouts[]");
    assert_eq!(
        checkouts.len(),
        5,
        "main + 3 linked + clone B, got {}",
        checkouts.len()
    );
    for co in checkouts {
        assert_eq!(
            co["availability"].as_str(),
            Some("present"),
            "checkout {} present",
            co["id"]
        );
    }
    for r in repos {
        let m = r["match"].as_str().expect("repository.match");
        assert!(
            m == "confirmed" || m == "related",
            "repository {} match={m}",
            r["id"]
        );
    }

    // Resolve checkouts -> stores via paths[].
    let mut paths = HashMap::new();
    for p in report["paths"].as_array().expect("paths[]") {
        paths.insert(
            p["id"].as_str().expect("path.id").to_owned(),
            p["value"].as_str().unwrap_or("").to_owned(),
        );
    }
    let repo_a = repo_of_checkout(&paths, checkouts, &clone_a);
    let repo_b = repo_of_checkout(&paths, checkouts, &clone_b);
    assert_ne!(
        repo_a, repo_b,
        "independent clone is a separate row despite equal URLs"
    );

    // Both stores observe the same origin URL (contains: normalization-proof).
    let remotes = report["remotes"].as_array().expect("remotes[]");
    for rid in [&repo_a, &repo_b] {
        assert!(
            remotes
                .iter()
                .any(|r| r["repository_id"].as_str() == Some(rid.as_str())
                    && r["url"]
                        .as_str()
                        .is_some_and(|u| u.contains("goal-owner/goal-repo"))),
            "store {rid} observes the goal URL"
        );
    }

    // Shared store lists each local branch ONCE (git CLI count, no per-checkout dup).
    let branches = report["branches"].as_array().expect("branches[]");
    let local_a: Vec<_> = branches
        .iter()
        .filter(|b| {
            b["repository_id"].as_str() == Some(repo_a.as_str())
                && b["kind"].as_str() == Some("local")
        })
        .collect();
    assert_eq!(
        local_a.len(),
        expect_local_a,
        "no branch duplication across 4 checkouts (git CLI: {expect_local_a})"
    );
    let mut names = HashSet::new();
    for b in &local_a {
        let n = b["name"]["value"]
            .as_str()
            .or_else(|| b["name"]["display"].as_str())
            .unwrap_or("")
            .to_owned();
        assert!(names.insert(n.clone()), "duplicate branch row for {n}");
    }

    // TODO(report 1.1.0, D1): assert groups[] has one entry for goal-owner/goal-repo — not implemented yet.
    // TODO(report 1.1.0, D1): assert totals { stores: 2, present checkouts: 5, linked worktrees: 3 } — not implemented yet.
}
