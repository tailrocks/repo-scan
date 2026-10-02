//! Local-repository target support and truthful matching acceptance tests (R08).

mod common;

use common::fixture;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

fn run(args: &[&str], cwd: &Path, state: &Path) -> Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    Command::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

fn scan(target: &str, root: &Path, state: &Path, report: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "scan",
        target,
        "--root",
        root.to_str().expect("utf8 root"),
        "--report",
        report.to_str().expect("utf8 report"),
    ];
    args.extend(extra.iter().copied());
    run(&args, root, state)
}

fn read_report(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("report is JSON")
}

fn stderr_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// 1. Local path target that has a GitHub remote origin resolves to canonical GitHub URL.
#[test]
fn local_target_with_github_remote_matches_clones() {
    let dir = fixture::scratch_root("r08-gh");
    let ws = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&ws).expect("mkdir");
    let clone_a = fixture::normal_clone(&ws, "clone-a");
    let _clone_b = fixture::normal_clone(&ws, "clone-b");
    let unrelated = fixture::normal_clone(&ws, "unrelated");
    fixture::git(
        &unrelated,
        &["remote", "set-url", "origin", "https://github.com/other/unrelated.git"],
    );

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(
        clone_a.to_str().unwrap(),
        &ws,
        &state,
        &report_path,
        &["--status", "metadata"],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    assert_eq!(
        report["scan"]["canonical_url"].as_str(),
        Some("https://github.com/owner/repo")
    );
    let repos = report["repositories"].as_array().expect("repositories");
    assert_eq!(repos.len(), 2, "clone-a and clone-b confirmed");
    for repo in repos {
        assert_eq!(repo["match"].as_str(), Some("confirmed"));
    }
}

/// 2. Local-only repository target without remotes matches itself and downstream clone.
#[test]
fn local_only_target_without_remotes() {
    let dir = fixture::scratch_root("r08-local");
    let ws = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&ws).expect("mkdir");
    let local_target = fixture::unborn_branch(&ws, "target-repo");
    fixture::commit_file(&local_target, "file.txt", "content\n", "init");

    let clone_repo = ws.join("clone-repo");
    fixture::git(
        &ws,
        &["clone", "-q", local_target.to_str().unwrap(), clone_repo.to_str().unwrap()],
    );
    let other_repo = fixture::unborn_branch(&ws, "other-repo");
    fixture::commit_file(&other_repo, "other.txt", "other\n", "init");
    fixture::git(
        &other_repo,
        &["remote", "add", "origin", "https://github.com/someone/other.git"],
    );

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(
        local_target.to_str().unwrap(),
        &ws,
        &state,
        &report_path,
        &["--status", "metadata"],
    );
    let rep_str = std::fs::read_to_string(&report_path).unwrap_or_default();
    assert_eq!(out.status.code(), Some(0), "stderr: {}\nreport: {}", stderr_text(&out), rep_str);
    let report = read_report(&report_path);
    assert!(
        report["scan"]["canonical_url"]
            .as_str()
            .unwrap()
            .starts_with("file://")
    );
    let repos = report["repositories"].as_array().expect("repositories");
    assert_eq!(repos.len(), 2, "target-repo and clone-repo confirmed");
    for repo in repos {
        assert_eq!(repo["match"].as_str(), Some("confirmed"));
    }
}

/// 3. Linked worktree target (.git pointer file).
#[test]
fn linked_worktree_target() {
    let dir = fixture::scratch_root("r08-wt");
    let ws = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&ws).expect("mkdir");
    let (_main, wt) = fixture::linked_worktree(&ws);

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(
        wt.to_str().unwrap(),
        &ws,
        &state,
        &report_path,
        &["--status", "metadata"],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    assert_eq!(
        report["scan"]["canonical_url"].as_str(),
        Some("https://github.com/owner/repo")
    );
}

/// 4. Bare repository target.
#[test]
fn bare_repository_target() {
    let dir = fixture::scratch_root("r08-bare");
    let ws = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&ws).expect("mkdir");
    let bare = fixture::bare_store(&ws, "bare.git");

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(
        bare.to_str().unwrap(),
        &ws,
        &state,
        &report_path,
        &["--status", "metadata"],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    assert!(report["scan"]["canonical_url"].is_string());
}

/// 5. Non-git directory target exits 2.
#[test]
fn non_git_directory_target_exits_2() {
    let dir = fixture::scratch_root("r08-nongit");
    let plain = dir.path().join("plain-folder");
    repo_scan::privacy::private_dir_0700(&plain).expect("mkdir");

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(
        plain.to_str().unwrap(),
        dir.path(),
        &state,
        &report_path,
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr_text(&out).contains("target path is not a git repository"));
}

/// 6. Non-existent path target exits 2.
#[test]
fn non_existent_path_target_exits_2() {
    let dir = fixture::scratch_root("r08-nonexist");
    let nonexist = dir.path().join("no-such-path");

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(
        nonexist.to_str().unwrap(),
        dir.path(),
        &state,
        &report_path,
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr_text(&out).contains("target path does not exist"));
}

/// 7. Local-only target reclassification on rescan preserves confirmed disposition.
#[test]
fn local_target_reclassify_on_rescan_preserves_confirmed() {
    let dir = fixture::scratch_root("r08-rescan");
    let ws = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&ws).expect("mkdir");
    let local_target = fixture::unborn_branch(&ws, "target-repo");
    fixture::commit_file(&local_target, "file.txt", "content\n", "init");

    let clone_repo = ws.join("clone-repo");
    fixture::git(
        &ws,
        &["clone", "-q", local_target.to_str().unwrap(), clone_repo.to_str().unwrap()],
    );

    let state = dir.path().join("state");
    let report_1 = dir.path().join("rep1.json");
    let out1 = scan(
        local_target.to_str().unwrap(),
        &ws,
        &state,
        &report_1,
        &["--status", "metadata"],
    );
    assert_eq!(out1.status.code(), Some(0), "stderr: {}", stderr_text(&out1));

    // Rescan with same state-dir triggers reclassify_for_target
    let report_2 = dir.path().join("rep2.json");
    let out2 = scan(
        local_target.to_str().unwrap(),
        &ws,
        &state,
        &report_2,
        &["--status", "metadata"],
    );
    assert_eq!(out2.status.code(), Some(0), "stderr: {}", stderr_text(&out2));
    let rep2 = read_report(&report_2);
    let repos = rep2["repositories"].as_array().expect("repositories");
    assert_eq!(repos.len(), 2, "both repos preserved on rescan");
    for repo in repos {
        assert_eq!(repo["match"].as_str(), Some("confirmed"), "must remain confirmed after reclassification");
    }
}

/// 8. Credential-bearing or query-bearing targets rejected without leakage.
#[test]
fn credential_bearing_local_target_rejected_without_leakage() {
    let dir = fixture::scratch_root("r08-cred");
    let state = dir.path().join("state");
    let rep = dir.path().join("rep.json");

    let out1 = scan("file://user:supersecretpass@localhost/tmp/repo", dir.path(), &state, &rep, &[]);
    assert_eq!(out1.status.code(), Some(2));
    let err1 = stderr_text(&out1);
    assert!(!err1.contains("supersecretpass"), "credentials must be redacted");
    assert!(err1.contains("target URL must not embed credentials"));

    let out2 = scan("/tmp/repo?jwt=verysecrettoken", dir.path(), &state, &rep, &[]);
    assert_eq!(out2.status.code(), Some(2));
    let err2 = stderr_text(&out2);
    assert!(!err2.contains("verysecrettoken"), "query token must be redacted");
    assert!(err2.contains("target URL must not embed credentials or a query/fragment tail"));
}

/// 9. Relative dot target (.) resolves to current repository.
#[test]
fn dot_target_resolves_and_matches() {
    let dir = fixture::scratch_root("r08-dot");
    let repo_dir = dir.path().join("my-repo");
    repo_scan::privacy::private_dir_0700(&repo_dir).expect("mkdir");
    fixture::git(&repo_dir, &["init", "-q", "-b", "main"]);
    fixture::commit_file(&repo_dir, "hello.txt", "hi\n", "init");

    let state = dir.path().join("state");
    let rep = dir.path().join("rep.json");
    let out = scan(".", &repo_dir, &state, &rep, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&rep);
    let repos = report["repositories"].as_array().expect("repositories");
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0]["match"].as_str(), Some("confirmed"));
}
