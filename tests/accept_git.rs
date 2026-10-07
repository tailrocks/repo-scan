//! Git + status + read-only acceptance (GIT-01..04, STATUS-01, READ-01).
//!
//! End-to-end CLI tests: deterministic tempdir fixtures (via
//! `common::fixture`), explicit `--root`/`--state-dir` only (never
//! whole-machine scans), CLI invoked via `env!("CARGO_BIN_EXE_repo-scan")`.
//! Assertions target meaningful outcomes: exit codes, report contents, and
//! catalog-driven re-probe behavior — not implementation details.

mod common;

use common::fixture;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Scan target; canonicalizes to `https://github.com/owner/repo` and matches
/// [`fixture::FIXTURE_REMOTE_URL`] under `github-effective-remotes-v1`.
const TARGET: &str = "https://github.com/OWNER/REPO";
const CANONICAL: &str = "https://github.com/owner/repo";
const POLICY: &str = "github-effective-remotes-v1";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Run the CLI with an explicit state dir from `cwd`.
fn run(args: &[&str], cwd: &Path, state: &Path) -> Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    Command::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

/// Scan exactly `root` into `report`, with extra scan flags appended.
fn scan(root: &Path, state: &Path, report: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "scan",
        TARGET,
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

/// Map report path id -> path value (fixtures use UTF-8 paths).
fn path_map(report: &Value) -> HashMap<String, String> {
    report["paths"]
        .as_array()
        .expect("paths array")
        .iter()
        .map(|p| {
            (
                p["id"].as_str().expect("path id").to_string(),
                p["value"].as_str().expect("path value").to_string(),
            )
        })
        .collect()
}

fn path_of<'a>(paths: &'a HashMap<String, String>, id: &Value) -> &'a str {
    paths
        .get(id.as_str().expect("path id ref"))
        .map(String::as_str)
        .expect("path id resolves")
}

/// The repository row whose git dir path contains `needle`.
fn repo_by_path<'a>(report: &'a Value, paths: &HashMap<String, String>, needle: &str) -> &'a Value {
    report["repositories"]
        .as_array()
        .expect("repositories array")
        .iter()
        .find(|r| path_of(paths, &r["git_path_id"]).contains(needle))
        .unwrap_or_else(|| panic!("no repository with path containing {needle}"))
}

fn branches_of<'a>(report: &'a Value, repo_id: &str) -> Vec<&'a Value> {
    report["branches"]
        .as_array()
        .expect("branches array")
        .iter()
        .filter(|b| b["repository_id"].as_str() == Some(repo_id))
        .collect()
}

fn checkout_for<'a>(report: &'a Value, repo_id: &str) -> &'a Value {
    report["checkouts"]
        .as_array()
        .expect("checkouts array")
        .iter()
        .find(|c| c["repository_id"].as_str() == Some(repo_id))
        .unwrap_or_else(|| panic!("no checkout for repository {repo_id}"))
}

fn repo_id(repo: &Value) -> &str {
    repo["id"].as_str().expect("repository id")
}

/// Same branch name in independent clones points at different work (GIT-01):
/// both stay confirmed, each `refs/heads/main` keeps its own oid.
#[test]
fn git01_same_branch_different_oids() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let (a, b) = fixture::diverged_clones(&root);
    for repo in [&a, &b] {
        fixture::git(
            repo,
            &["remote", "add", "origin", fixture::FIXTURE_REMOTE_URL],
        );
    }
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    // Metadata mode isolates branch/HEAD identity from status probing.
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    assert_eq!(report["scan"]["matching_policy"].as_str(), Some(POLICY));
    let paths = path_map(&report);
    let repo_a = repo_by_path(&report, &paths, "clone-a");
    let repo_b = repo_by_path(&report, &paths, "clone-b");
    assert_ne!(
        repo_id(repo_a),
        repo_id(repo_b),
        "independent clones stay distinct"
    );
    assert_eq!(repo_a["match"].as_str(), Some("confirmed"));
    assert_eq!(repo_b["match"].as_str(), Some("confirmed"));
    let main_oid = |repo: &Value| {
        branches_of(&report, repo_id(repo))
            .into_iter()
            .find(|br| br["name"]["value"].as_str() == Some("refs/heads/main"))
            .unwrap_or_else(|| panic!("refs/heads/main for {}", repo_id(repo)))["oid"]["hex"]
            .as_str()
            .expect("oid hex")
            .to_string()
    };
    let oid_a = main_oid(repo_a);
    let oid_b = main_oid(repo_b);
    assert_eq!(oid_a.len(), 40, "sha1 hex: {oid_a}");
    assert_eq!(oid_b.len(), 40, "sha1 hex: {oid_b}");
    assert_ne!(oid_a, oid_b, "same branch name, different work");
}

/// Unborn, detached, and packed-ref layouts stay distinguishable (GIT-01).
#[test]
fn git01_head_states_and_packed_refs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let detached = fixture::detached_head(&root, "detached");
    let unborn = fixture::unborn_branch(&root, "unborn");
    fixture::git(
        &unborn,
        &["remote", "add", "origin", fixture::FIXTURE_REMOTE_URL],
    );
    let packed = fixture::packed_refs_repo(&root, "packed");
    assert!(packed.join(".git/packed-refs").is_file());
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);

    // Detached checkout: HEAD state is detached with a concrete oid, and the
    // checkout kind still describes topology (main), not HEAD state.
    let det_repo = repo_by_path(&report, &paths, "detached");
    assert_eq!(det_repo["match"].as_str(), Some("confirmed"));
    let det_co = checkout_for(&report, repo_id(det_repo));
    assert_eq!(det_co["kind"].as_str(), Some("main"));
    assert_eq!(det_co["head"]["state"].as_str(), Some("detached"));
    let det_oid = det_co["head"]["oid"]["hex"].as_str().expect("detached oid");
    assert_eq!(det_oid.len(), 40);
    assert_eq!(
        det_oid,
        fixture::git_str(&detached, &["rev-parse", "HEAD"]),
        "detached oid matches the checkout"
    );

    // Unborn checkout: HEAD names the branch with no oid.
    let unb_repo = repo_by_path(&report, &paths, "unborn");
    assert_eq!(unb_repo["match"].as_str(), Some("confirmed"));
    let unb_co = checkout_for(&report, repo_id(unb_repo));
    assert_eq!(unb_co["head"]["state"].as_str(), Some("unborn"));
    assert_eq!(
        unb_co["head"]["ref_name"]["value"].as_str(),
        Some("refs/heads/main")
    );
    assert!(unb_co["head"]["oid"].is_null());

    // Packed refs: every branch is observed from packed storage, not just
    // loose ref files.
    let packed_repo = repo_by_path(&report, &paths, "packed");
    let mut names: Vec<String> = branches_of(&report, repo_id(packed_repo))
        .iter()
        .map(|br| {
            assert_eq!(br["state"].as_str(), Some("valid"));
            assert!(br["oid"]["hex"].as_str().is_some_and(|h| h.len() == 40));
            br["name"]["value"]
                .as_str()
                .expect("branch name")
                .to_string()
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "refs/heads/feature-a",
            "refs/heads/feature-b",
            "refs/heads/main"
        ]
    );
}

/// A garbage `.git` marker is preserved as its own candidate entry instead of
/// being dropped or merged into a neighboring repository (GIT-01).
#[test]
fn git01_unsupported_marker_preserved_distinct() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "good");
    let broken = root.join("broken");
    repo_scan::privacy::private_dir_0700(&broken.join(".git")).expect("mkdir");
    repo_scan::privacy::private_write_0600(
        &broken.join(".git/HEAD"),
        "garbage-not-a-ref\n".as_bytes(),
    )
    .expect("write");
    repo_scan::privacy::private_write_0600(&broken.join(".git/config"), "\x00not-ini\n".as_bytes())
        .expect("write");
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    // The valid clone is still reported exactly.
    let good = repo_by_path(&report, &paths, "good");
    assert_eq!(good["match"].as_str(), Some("confirmed"));
    assert!(branches_of(&report, repo_id(good))
        .iter()
        .any(|br| br["name"]["value"].as_str() == Some("refs/heads/main")));
    // The broken marker survives as a distinct candidate at its own path.
    let candidates = report["candidates"].as_array().expect("candidates array");
    let broken_cand = candidates
        .iter()
        .find(|c| path_of(&paths, &c["path_id"]).contains("broken"))
        .expect("broken marker preserved as a candidate");
    assert!(
        matches!(
            broken_cand["disposition"].as_str(),
            Some("probe_failed") | Some("unsupported")
        ),
        "unexpected disposition: {}",
        broken_cand["disposition"]
    );
    assert!(!broken_cand["reason"].as_str().expect("reason").is_empty());
}

/// Alternates-linked and hard-linked clones are independent repositories:
/// shared object storage never collapses their rows (GIT-02).
#[test]
fn git02_shared_storage_keeps_clones_independent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let src = fixture::normal_clone(&root, "src");
    // Alternates-linked clone.
    let shared = fixture::shared_clone(&src, &root.join("via-alternates"));
    fixture::git(
        &shared,
        &["remote", "set-url", "origin", fixture::FIXTURE_REMOTE_URL],
    );
    assert!(
        shared.join(".git/objects/info/alternates").is_file(),
        "shared clone still borrows the source object store"
    );
    // Local clone (hard-linked objects).
    let hardlink = root.join("via-hardlink");
    let (src_arg, dst_arg) = (
        src.to_string_lossy().into_owned(),
        hardlink.to_string_lossy().into_owned(),
    );
    fixture::git(&root, &["clone", "-q", "--local", &src_arg, &dst_arg]);
    fixture::git(
        &hardlink,
        &["remote", "set-url", "origin", fixture::FIXTURE_REMOTE_URL],
    );
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    let repos = ["src", "via-alternates", "via-hardlink"]
        .into_iter()
        .map(|n| repo_by_path(&report, &paths, n))
        .collect::<Vec<_>>();
    let ids: Vec<&str> = repos.iter().map(|r| repo_id(r)).collect();
    assert_eq!(ids.len(), 3);
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[0], ids[2]);
    assert_ne!(ids[1], ids[2]);
    for repo in &repos {
        assert_eq!(repo["match"].as_str(), Some("confirmed"));
        // Each independent clone owns its own checkout row.
        checkout_for(&report, repo_id(repo));
    }
    // Same work (identical main oid), still three independent rows.
    let main_oid = |repo: &Value| {
        branches_of(&report, repo_id(repo))
            .into_iter()
            .find(|br| br["name"]["value"].as_str() == Some("refs/heads/main"))
            .expect("main branch")["oid"]["hex"]
            .as_str()
            .expect("oid")
            .to_string()
    };
    assert_eq!(main_oid(repos[0]), main_oid(repos[1]));
    assert_eq!(main_oid(repos[0]), main_oid(repos[2]));
}

/// URL variants, insteadOf rewrites, forks, credential redaction, and
/// removed remotes all follow `github-effective-remotes-v1` (GIT-03).
#[test]
fn git03_identity_policy_variants() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "via-https");
    let scp = fixture::normal_clone(&root, "via-scp");
    fixture::git(
        &scp,
        &[
            "remote",
            "set-url",
            "origin",
            "git@github.com:OWNER/REPO.git",
        ],
    );
    let ssh = fixture::normal_clone(&root, "via-ssh");
    fixture::git(
        &ssh,
        &[
            "remote",
            "set-url",
            "origin",
            "ssh://git@github.com/owner/repo.git",
        ],
    );
    let rewrite = fixture::normal_clone(&root, "via-rewrite");
    fixture::git(
        &rewrite,
        &["remote", "set-url", "origin", "gh:OWNER/REPO.git"],
    );
    fixture::git(
        &rewrite,
        &["config", "url.https://github.com/.insteadOf", "gh:"],
    );
    let creds = fixture::normal_clone(&root, "via-creds");
    fixture::git(
        &creds,
        &[
            "remote",
            "set-url",
            "origin",
            "https://user:s3cret-token@github.com/OWNER/REPO.git",
        ],
    );
    let fork = fixture::normal_clone(&root, "fork");
    fixture::git(
        &fork,
        &[
            "remote",
            "set-url",
            "origin",
            "https://github.com/someone-else/REPO.git",
        ],
    );
    let unrelated = fixture::normal_clone(&root, "unrelated");
    fixture::git(
        &unrelated,
        &[
            "remote",
            "set-url",
            "origin",
            "https://github.com/other/project.git",
        ],
    );
    let removed = fixture::normal_clone(&root, "removed-remote");
    fixture::git(&removed, &["remote", "remove", "origin"]);

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &[]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "removed remote leaves identity unproven: {}",
        stderr_text(&out)
    );
    let raw = std::fs::read(&report_path).expect("read report");
    assert!(
        !String::from_utf8_lossy(&raw).contains("s3cret-token"),
        "embedded credentials must never reach the report"
    );
    let report: Value = serde_json::from_slice(&raw).expect("report is JSON");
    assert_eq!(report["scan"]["matching_policy"].as_str(), Some(POLICY));
    assert_eq!(report["scan"]["canonical_url"].as_str(), Some(CANONICAL));
    assert_eq!(report["coverage"]["identity"].as_str(), Some("unproven"));
    let paths = path_map(&report);

    // Every supported URL shape confirms against the canonical target.
    for name in [
        "via-https",
        "via-scp",
        "via-ssh",
        "via-rewrite",
        "via-creds",
    ] {
        let repo = repo_by_path(&report, &paths, name);
        assert_eq!(repo["match"].as_str(), Some("confirmed"), "{name}");
        let id = repo_id(repo);
        let remotes: Vec<&Value> = report["remotes"]
            .as_array()
            .expect("remotes array")
            .iter()
            .filter(|r| r["repository_id"].as_str() == Some(id))
            .collect();
        assert!(!remotes.is_empty(), "{name} emits its remotes");
        for remote in &remotes {
            assert_eq!(remote["canonical_url"].as_str(), Some(CANONICAL), "{name}");
        }
    }
    // Fetch and push roles are preserved as separate observations.
    let https_id = repo_id(repo_by_path(&report, &paths, "via-https"));
    let mut roles: Vec<&str> = report["remotes"]
        .as_array()
        .expect("remotes array")
        .iter()
        .filter(|r| r["repository_id"].as_str() == Some(https_id))
        .map(|r| r["role"].as_str().expect("role"))
        .collect();
    roles.sort();
    assert_eq!(roles, vec!["fetch", "push"]);

    // Same repo name under a different owner is related (possible fork).
    let fork_repo = repo_by_path(&report, &paths, "fork");
    assert_eq!(fork_repo["match"].as_str(), Some("related"));

    // Decisive mismatch is not emitted in a target report.
    assert!(
        !report["repositories"]
            .as_array()
            .expect("repositories array")
            .iter()
            .any(|r| path_of(&paths, &r["git_path_id"]).contains("unrelated")),
        "nonmatch stays out of the target report"
    );

    // Removed identifying remotes: permanently ambiguous, terminal incomplete.
    let gone = repo_by_path(&report, &paths, "removed-remote");
    assert_eq!(gone["match"].as_str(), Some("unresolvable_identity"));
    let gone_cand = report["candidates"]
        .as_array()
        .expect("candidates array")
        .iter()
        .find(|c| c["repository_id"].as_str() == Some(repo_id(gone)))
        .expect("unresolvable candidate entry");
    assert_eq!(
        gone_cand["disposition"].as_str(),
        Some("unresolvable_identity")
    );
    assert!(
        gone_cand["retry_after"].is_null(),
        "no futile retry scheduled"
    );
    assert!(
        report["coverage"]["unresolvable_candidates"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );
}

/// Ambiguous identity is terminal incomplete (exit 3) without retries, and
/// becomes eligible again after metadata invalidation (GIT-04).
#[test]
fn git04_ambiguous_identity_terminal_then_reeligible() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let repo = fixture::normal_clone(&root, "ambiguous");
    fixture::git(&repo, &["remote", "remove", "origin"]);
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");

    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    assert_eq!(report["coverage"]["identity"].as_str(), Some("unproven"));
    for cand in report["candidates"].as_array().expect("candidates array") {
        assert!(
            cand["retry_after"].is_null(),
            "terminal: no retry scheduled"
        );
    }

    // A repeat scan without changes reaches the same terminal state instead
    // of spinning on retries.
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let again = read_report(&report_path);
    assert_eq!(again["coverage"]["identity"].as_str(), Some("unproven"));

    // After the identifying remote returns and the scope is invalidated, the
    // repository is re-probed and confirmed.
    fixture::git(
        &repo,
        &["remote", "add", "origin", fixture::FIXTURE_REMOTE_URL],
    );
    let out = run(
        &[
            "cache",
            "invalidate",
            "--root",
            repo.to_str().expect("utf8"),
        ],
        &root,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    assert_eq!(
        report["coverage"]["identity"].as_str(),
        Some("complete_under_policy")
    );
    assert_eq!(
        report["coverage"]["unresolvable_candidates"].as_u64(),
        Some(0)
    );
    let paths = path_map(&report);
    let confirmed = repo_by_path(&report, &paths, "ambiguous");
    assert_eq!(confirmed["match"].as_str(), Some("confirmed"));
}

/// Summary status counts staged/unstaged/collapsed-untracked entries with Git
/// ignore semantics, and nonmatching repos receive no status probe
/// (STATUS-01). (`unstable` needs a mid-probe mutation race, so it cannot be
/// forced deterministically through the CLI; unknown/not-requested shape is
/// covered by the metadata-mode scan below.)
#[test]
fn status01_dirty_counts_and_nonmatch_unprobed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let layout = fixture::dirty_variants(&root, "dirty");
    assert!(layout.staged.is_file() && layout.ignored.is_file());
    let other = fixture::normal_clone(&root, "other");
    fixture::git(
        &other,
        &[
            "remote",
            "set-url",
            "origin",
            "https://github.com/other/project.git",
        ],
    );

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "summary"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    assert_eq!(report["scan"]["status_mode"].as_str(), Some("summary"));
    assert_eq!(report["coverage"]["status"].as_str(), Some("complete"));
    let paths = path_map(&report);

    // Dirty working state: 1 staged, 1 unstaged, 3 collapsed untracked
    // (file + dir + .gitignore); the ignored file is never counted.
    let dirty = repo_by_path(&report, &paths, "dirty");
    assert_eq!(dirty["match"].as_str(), Some("confirmed"));
    let status = &checkout_for(&report, repo_id(dirty))["status"];
    assert_eq!(status["state"].as_str(), Some("complete"));
    assert_eq!(status["mode"].as_str(), Some("summary"));
    assert_eq!(status["staged"].as_u64(), Some(1));
    assert_eq!(status["unstaged"].as_u64(), Some(1));
    assert_eq!(status["untracked"].as_u64(), Some(3));
    assert_eq!(
        status["untracked_units"].as_str(),
        Some("collapsed_entries")
    );

    // The nonmatching repo gets no status probe: no repository row, no
    // checkout row, and no completed/partial status outside the match.
    let repos = report["repositories"]
        .as_array()
        .expect("repositories array");
    assert!(repos
        .iter()
        .all(|r| r["match"].as_str() != Some("nonmatch")));
    let checkouts = report["checkouts"].as_array().expect("checkouts array");
    assert_eq!(checkouts.len(), 1, "only the matching checkout is emitted");
    for co in checkouts {
        let owner = repos
            .iter()
            .find(|r| r["id"].as_str() == co["repository_id"].as_str())
            .expect("checkout owner resolves");
        assert_eq!(owner["match"].as_str(), Some("confirmed"));
    }

    // Metadata mode performs no working-state probe: counts stay null with
    // explicit not-requested units (fresh state, so no older observations
    // leak into the report).
    let meta_state = dir.path().join("state-meta");
    let meta_report = dir.path().join("rep-meta.json");
    let out = scan(&root, &meta_state, &meta_report, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let meta = read_report(&meta_report);
    assert_eq!(meta["coverage"]["status"].as_str(), Some("not_requested"));
    let meta_paths = path_map(&meta);
    let meta_dirty = repo_by_path(&meta, &meta_paths, "dirty");
    let meta_status = &checkout_for(&meta, repo_id(meta_dirty))["status"];
    assert_eq!(meta_status["state"].as_str(), Some("not_requested"));
    assert!(meta_status["staged"].is_null());
    assert!(meta_status["unstaged"].is_null());
    assert!(meta_status["untracked"].is_null());
    assert_eq!(
        meta_status["untracked_units"].as_str(),
        Some("not_requested")
    );
}

/// Inspection leaves git metadata, package-manager locks, and the object
/// store byte-identical, and never touches the network (READ-01). The report
/// is written outside the scanned root so no explicit artifact lands in it.
#[test]
fn read01_scan_leaves_repos_and_locks_untouched() {
    use std::time::SystemTime;
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let repo = fixture::normal_clone(&root, "proj");
    fixture::commit_file(
        &repo,
        "Cargo.lock",
        "# fake lock for READ-01\nversion = 3\n",
        "add lockfile",
    );
    assert!(!repo.join(".git/FETCH_HEAD").exists());

    // Snapshot git metadata + lockfile bytes, mtimes, and the .git inventory.
    let watched = [
        ".git/HEAD",
        ".git/index",
        ".git/config",
        ".git/refs/heads/main",
        "Cargo.lock",
    ];
    let mut before_bytes = HashMap::new();
    let mut before_mtime: HashMap<String, SystemTime> = HashMap::new();
    for rel in watched {
        let path = repo.join(rel);
        before_bytes.insert(rel.to_string(), std::fs::read(&path).expect("read before"));
        before_mtime.insert(
            rel.to_string(),
            std::fs::metadata(&path)
                .expect("stat before")
                .modified()
                .expect("mtime"),
        );
    }
    fn inventory(dir: &Path, out: &mut Vec<String>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                inventory(&path, out);
            } else {
                out.push(path.to_string_lossy().into_owned());
            }
        }
    }
    let mut before_files = Vec::new();
    inventory(&repo.join(".git"), &mut before_files);

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &[]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    assert_eq!(
        repo_by_path(&report, &paths, "proj")["match"].as_str(),
        Some("confirmed"),
        "the scanned repo was actually inspected"
    );

    // Every watched byte and mtime is unchanged.
    for rel in watched {
        let path = repo.join(rel);
        assert_eq!(
            std::fs::read(&path).expect("read after"),
            before_bytes[rel],
            "{rel} bytes changed"
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("stat after")
                .modified()
                .expect("mtime"),
            before_mtime[rel],
            "{rel} mtime changed"
        );
    }
    // No new, removed, or rewritten files anywhere under .git …
    let mut after_files = Vec::new();
    inventory(&repo.join(".git"), &mut after_files);
    assert_eq!(before_files, after_files, ".git inventory changed");
    // … and nothing was fetched: no FETCH_HEAD may appear.
    assert!(
        !repo.join(".git/FETCH_HEAD").exists(),
        "scan must never fetch"
    );
}

/// Find one branch row by full ref name within a repository.
fn branch_named<'a>(report: &'a Value, repo_id: &str, name: &str) -> &'a Value {
    branches_of(report, repo_id)
        .into_iter()
        .find(|b| b["name"]["value"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("branch {name} for {repo_id}"))
}

/// A rewritten (non-default) fetch refspec resolves to the non-default
/// full comparison ref, exactly as installed git spells it (Step 10).
#[test]
fn upstream10_custom_fetch_refspec_resolves_full_ref() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let repo = fixture::custom_fetch_clone(&root, "custom");
    // Independent reference: installed git's own upstream spelling.
    let expected = fixture::git_str(
        &repo,
        &["rev-parse", "--symbolic-full-name", "main@{upstream}"],
    );
    assert_eq!(expected, "refs/custom/main");
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    let repo_row = repo_by_path(&report, &paths, "custom");
    assert_eq!(repo_row["match"].as_str(), Some("confirmed"));
    let main = branch_named(&report, repo_id(repo_row), "refs/heads/main");
    assert_eq!(main["upstream"]["encoding"].as_str(), Some("utf8"));
    assert_eq!(
        main["upstream"]["value"].as_str(),
        Some(expected.as_str()),
        "custom fetch destination, not a remote/leaf guess"
    );
}

/// GIT-m2: garbage-first and negative-first fetch refspecs SKIP to the
/// later valid refspec — pinned against installed git, which resolves
/// past them (probed: `rev-parse --symbolic-full-name` succeeds).
#[test]
fn upstream10_garbage_first_refspec_skips_to_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let repo = fixture::normal_clone(&root, "garbage");
    let head = fixture::git_str(&repo, &["rev-parse", "HEAD"]);
    fixture::git(&repo, &["update-ref", "refs/remotes/origin/main", &head]);
    fixture::git(&repo, &["config", "--unset-all", "remote.origin.fetch"]);
    fixture::git(
        &repo,
        &["config", "--add", "remote.origin.fetch", "garbage!!!"],
    );
    fixture::git(
        &repo,
        &[
            "config",
            "--add",
            "remote.origin.fetch",
            "^refs/heads/secret",
        ],
    );
    fixture::git(
        &repo,
        &[
            "config",
            "--add",
            "remote.origin.fetch",
            "+refs/heads/*:refs/remotes/origin/*",
        ],
    );
    fixture::git(&repo, &["config", "branch.main.remote", "origin"]);
    fixture::git(&repo, &["config", "branch.main.merge", "refs/heads/main"]);
    // Independent oracle: installed git skips both junk lines.
    let expected = fixture::git_str(
        &repo,
        &["rev-parse", "--symbolic-full-name", "main@{upstream}"],
    );
    assert_eq!(expected, "refs/remotes/origin/main");
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    let repo_row = repo_by_path(&report, &paths, "garbage");
    assert_eq!(repo_row["match"].as_str(), Some("confirmed"));
    let main = branch_named(&report, repo_id(repo_row), "refs/heads/main");
    assert_eq!(
        main["upstream"]["value"].as_str(),
        Some("refs/remotes/origin/main")
    );
}

/// A local upstream (`remote = .`) resolves to the local merge ref itself
/// (Step 10).
#[test]
fn upstream10_local_dot_resolves_merge_ref() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let repo = fixture::local_upstream_clone(&root, "local");
    let expected = fixture::git_str(
        &repo,
        &["rev-parse", "--symbolic-full-name", "main@{upstream}"],
    );
    assert_eq!(expected, "refs/heads/other");
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    let repo_row = repo_by_path(&report, &paths, "local");
    assert_eq!(repo_row["match"].as_str(), Some("confirmed"));
    let main = branch_named(&report, repo_id(repo_row), "refs/heads/main");
    assert_eq!(main["upstream"]["value"].as_str(), Some(expected.as_str()));
}

/// GIT-m1: an upstream that EXISTS but carries no OID (an unpeeled
/// symbolic tracking ref) compares as `error` — never
/// `upstream_missing`, which is reserved for truly absent refs.
/// `refs/remotes/origin/HEAD` exists and resolves, but gix returns it
/// without a peel, so no OID comparison is possible.
#[test]
fn upstream10_oid_less_present_upstream_compares_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let repo = fixture::normal_clone(&root, "symref");
    let head = fixture::git_str(&repo, &["rev-parse", "HEAD"]);
    fixture::git(&repo, &["update-ref", "refs/remotes/origin/main", &head]);
    fixture::git(
        &repo,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
        ],
    );
    fixture::git(&repo, &["config", "branch.main.remote", "origin"]);
    fixture::git(&repo, &["config", "branch.main.merge", "refs/heads/HEAD"]);
    // The upstream ref exists and resolves (installed-git oracle).
    assert_eq!(
        fixture::git_str(&repo, &["rev-parse", "refs/remotes/origin/HEAD"]),
        head
    );
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    let repo_row = repo_by_path(&report, &paths, "symref");
    assert_eq!(repo_row["match"].as_str(), Some("confirmed"));
    let main = branch_named(&report, repo_id(repo_row), "refs/heads/main");
    assert_eq!(
        main["upstream"]["value"].as_str(),
        Some("refs/remotes/origin/HEAD")
    );
    assert_eq!(
        main["comparison"].as_str(),
        Some("error"),
        "present-but-OID-less upstream is error, not upstream_missing"
    );
}

/// Branch stanzas living in an `include.path` file resolve (Step 10).
#[test]
fn upstream10_include_file_stanzas_resolve() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let repo = fixture::include_upstream_clone(&root, "included");
    let expected = fixture::git_str(
        &repo,
        &["rev-parse", "--symbolic-full-name", "main@{upstream}"],
    );
    assert_eq!(expected, "refs/remotes/origin/main");
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    let repo_row = repo_by_path(&report, &paths, "included");
    assert_eq!(repo_row["match"].as_str(), Some("confirmed"));
    let main = branch_named(&report, repo_id(repo_row), "refs/heads/main");
    assert_eq!(main["upstream"]["value"].as_str(), Some(expected.as_str()));
}

/// Worktree-level branch config (the linked worktree's own
/// `config.worktree`) resolves for that checkout's branch, while the
/// main checkout's untracked branch stays null (Step 10).
#[test]
fn upstream10_worktree_config_resolves_for_checkout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let (_main_repo, wt) = fixture::tracking_worktree(&root);
    // Reference from the linked checkout's own perspective.
    let expected = fixture::git_str(
        &wt,
        &["rev-parse", "--symbolic-full-name", "wtbranch@{upstream}"],
    );
    assert_eq!(expected, "refs/remotes/origin/main");
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    let repo_row = repo_by_path(&report, &paths, "wtmain");
    assert_eq!(repo_row["match"].as_str(), Some("confirmed"));
    let wt_branch = branch_named(&report, repo_id(repo_row), "refs/heads/wtbranch");
    assert_eq!(
        wt_branch["upstream"]["value"].as_str(),
        Some(expected.as_str())
    );
    let main_branch = branch_named(&report, repo_id(repo_row), "refs/heads/main");
    assert!(
        main_branch["upstream"].is_null(),
        "untracked main stays null: {}",
        main_branch["upstream"]
    );
}

/// A non-UTF-8 branch with tracking resolves byte-exact: the only
/// base64-encoded branch row carries the installed-git upstream (Step 10).
/// Unix-only (raw-byte refnames via packed-refs).
#[cfg(unix)]
#[test]
fn upstream10_non_utf8_branch_resolves_byte_exact() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStringExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let (repo, refname) = fixture::non_utf8_tracking_repo(&root, "bytes");
    assert!(
        refname.contains(&0xe9) && refname.contains(&0xff),
        "fixture must carry raw hostile bytes: {refname:?}"
    );
    // Reference: installed git resolves the hostile branch's upstream
    // (byte-exact argv; no UTF-8 anywhere).
    let short = refname
        .strip_prefix(b"refs/heads/")
        .expect("hostile branch under refs/heads")
        .to_vec();
    let mut upstream_arg = short;
    upstream_arg.extend_from_slice(b"@{upstream}");
    let upstream_os = std::ffi::OsString::from_vec(upstream_arg);
    let raw = fixture::git_os(
        &repo,
        &[
            OsStr::new("rev-parse"),
            OsStr::new("--symbolic-full-name"),
            upstream_os.as_os_str(),
        ],
    );
    assert_eq!(raw.trim_ascii(), b"refs/remotes/origin/main");
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    let repo_row = repo_by_path(&report, &paths, "bytes");
    assert_eq!(repo_row["match"].as_str(), Some("confirmed"));
    let hostile: Vec<&Value> = branches_of(&report, repo_id(repo_row))
        .into_iter()
        .filter(|b| b["name"]["encoding"].as_str() == Some("base64"))
        .collect();
    assert_eq!(hostile.len(), 1, "exactly the hostile branch is base64");
    assert_eq!(
        hostile[0]["upstream"]["value"].as_str(),
        Some("refs/remotes/origin/main")
    );
}

/// Unresolvable upstreams yield null, never a guess: a missing remote, a
/// fetch refspec that maps nothing (destination-less: fetches into
/// `FETCH_HEAD` only), and a merge target with no tracking ref (Step 10).
/// Installed git fails all three as well. (A syntactically unparseable
/// fetch value would also poison remote identity parsing — a separate
/// lane — so the refspec case uses the valid-but-unmappable shape.)
#[test]
fn upstream10_unresolvable_yields_null() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let missing = fixture::tracking_clone(&root, "missing-remote");
    fixture::git(&missing, &["config", "branch.main.remote", "nonexistent"]);
    let bad = fixture::tracking_clone(&root, "bad-refspec");
    fixture::git(&bad, &["config", "remote.origin.fetch", "+refs/heads/main"]);
    let gone = fixture::tracking_clone(&root, "absent-target");
    fixture::git(&gone, &["config", "branch.main.merge", "refs/heads/gone"]);
    // Reference: installed git resolves none of these either.
    for repo in [&missing, &bad, &gone] {
        assert!(
            !fixture::git_succeeds(
                repo,
                &["rev-parse", "--symbolic-full-name", "main@{upstream}"]
            ),
            "installed git must also fail in {}",
            repo.display()
        );
    }
    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "metadata"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    for needle in ["missing-remote", "bad-refspec", "absent-target"] {
        let repo_row = repo_by_path(&report, &paths, needle);
        assert_eq!(repo_row["match"].as_str(), Some("confirmed"), "{needle}");
        let main = branch_named(&report, repo_id(repo_row), "refs/heads/main");
        assert!(
            main["upstream"].is_null(),
            "{needle}: unresolvable must be null, got {}",
            main["upstream"]
        );
    }
}

/// GIT-M1: an unreadable worktree registry is a probe READ failure
/// (retry, then park with a gap) — never silent "no worktrees".
/// Swallowing would drop linked checkouts from inventory without a
/// trace; the gap detail names the registry.
#[test]
fn worktree_registry_unreadable_parks_with_gap() {
    use repo_scan::store::{Store, TursoStore};
    use std::os::unix::fs::PermissionsExt;

    struct Restore<'a> {
        path: &'a Path,
    }
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.path, std::fs::Permissions::from_mode(0o755));
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let (main, _wt) = fixture::linked_worktree(&root);
    let registry = main.join(".git").join("worktrees");
    assert!(registry.is_dir(), "linked worktree registers");
    std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o0)).expect("chmod 000");
    let _restore = Restore { path: &registry };
    if std::fs::read_dir(&registry).is_ok() {
        eprintln!("worktree_registry_unreadable_parks_with_gap: chmod 000 ineffective; skipping");
        return;
    }

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &[]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "unreadable registry parks with gaps, never silent success; stderr: {}",
        stderr_text(&out)
    );
    let report = read_report(&report_path);
    assert_eq!(report["scan"]["state"].as_str(), Some("incomplete"));
    assert!(report["coverage"]["gaps"].as_u64().expect("gaps") > 0);

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let db = state.join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let mut rows = store
            .connection()
            .query("SELECT detail FROM errors WHERE open = 1", ())
            .await
            .expect("query gaps");
        let mut saw_worktree = false;
        while let Some(row) = rows.next().await.expect("next") {
            if let turso::Value::Text(detail) = row.get_value(0).expect("v0") {
                saw_worktree |= detail.contains("worktree");
            }
        }
        store.close().await.expect("close");
        assert!(saw_worktree, "a gap names the unreadable worktree registry");
    });
}

/// GIT-M2: sparse checkouts declare their coverage scope AND keep
/// git-exact counts. The excluded-path staged change is the parity pin:
/// installed `git status` is the independent oracle (porcelain `M `
/// row), and the scan's staged count must agree — while
/// `unknown_fields` carries the `sparse-checkout` declaration (counts
/// cover the materialized worktree only). A non-sparse control repo in
/// the same world carries no such note.
#[test]
fn status11_sparse_checkout_declares_scope_with_git_parity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let sparse = fixture::normal_clone(&root, "sparse");
    fixture::commit_file(&sparse, "keep/a.txt", "a\n", "keep file");
    fixture::commit_file(&sparse, "skip/b.txt", "b\n", "skip file");
    fixture::git(&sparse, &["sparse-checkout", "init", "--cone"]);
    fixture::git(&sparse, &["sparse-checkout", "set", "keep"]);
    assert!(
        !sparse.join("skip").exists(),
        "excluded path is not materialized"
    );
    // Stage a change inside the EXCLUDED path (disable, edit, stage,
    // re-sparsify): the index is not sparse, so both git and the scan
    // must count it staged.
    fixture::git(&sparse, &["sparse-checkout", "disable"]);
    fixture::commit_file(&sparse, "skip/b.txt", "b\nmodified\n", "modify excluded");
    fixture::git(&sparse, &["reset", "--quiet", "HEAD~1"]);
    fixture::git(&sparse, &["add", "--", "skip/b.txt"]);
    fixture::git(&sparse, &["sparse-checkout", "set", "keep"]);
    // Independent oracle: installed git sees exactly one staged path.
    assert_eq!(
        fixture::git_str(&sparse, &["status", "--porcelain"]),
        "M  skip/b.txt",
        "oracle: one staged excluded-path change"
    );
    let plain = fixture::normal_clone(&root, "plain");

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "summary"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);

    let repo = repo_by_path(&report, &paths, "sparse");
    assert_eq!(repo["match"].as_str(), Some("confirmed"));
    let status = &checkout_for(&report, repo_id(repo))["status"];
    assert_eq!(status["state"].as_str(), Some("complete"));
    assert_eq!(status["staged"].as_u64(), Some(1), "parity with git status");
    assert_eq!(status["unstaged"].as_u64(), Some(0));
    assert_eq!(status["untracked"].as_u64(), Some(0));
    assert_eq!(status["conflicts"].as_u64(), Some(0));
    let unknown = status["unknown_fields"]
        .as_array()
        .expect("unknown_fields array");
    assert!(
        unknown
            .iter()
            .any(|f| f.as_str().is_some_and(|s| s.contains("sparse-checkout"))),
        "sparse coverage declared: {unknown:?}"
    );

    let control = repo_by_path(&report, &paths, "plain");
    assert!(plain.is_dir());
    let control_unknown = checkout_for(&report, repo_id(control))["status"]["unknown_fields"]
        .as_array()
        .expect("control unknown_fields array");
    assert!(
        !control_unknown
            .iter()
            .any(|f| f.as_str().is_some_and(|s| s.contains("sparse-checkout"))),
        "non-sparse repo carries no sparse note: {control_unknown:?}"
    );
}

/// Conflict-only checkout reports `conflicted` with a separate conflict
/// count (Step 10 case 10): the two unmerged paths never read as staged,
/// unstaged, dirty, or clean.
#[test]
fn status10_conflict_only_reports_conflicted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::conflict_clone(&root, "conflicted");

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = scan(&root, &state, &report_path, &["--status", "summary"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    let paths = path_map(&report);
    let repo = repo_by_path(&report, &paths, "conflicted");
    assert_eq!(repo["match"].as_str(), Some("confirmed"));
    let status = &checkout_for(&report, repo_id(repo))["status"];
    assert_eq!(status["state"].as_str(), Some("complete"));
    assert_eq!(status["staged"].as_u64(), Some(0));
    assert_eq!(status["unstaged"].as_u64(), Some(0));
    assert_eq!(status["untracked"].as_u64(), Some(0));
    assert_eq!(status["conflicts"].as_u64(), Some(2));
    assert_eq!(status["working_state"].as_str(), Some("conflicted"));
}

/// Checkout rows by kind for submodule assertions.
fn checkouts_by_kind(report: &Value) -> HashMap<&str, &Value> {
    report["checkouts"]
        .as_array()
        .expect("checkouts array")
        .iter()
        .map(|c| (c["kind"].as_str().expect("kind"), c))
        .collect()
}

/// BOUNDARY-M8 parity leg: a healthy submodule is traversal-covered —
/// the worktree `.git` file probes a `kind=submodule` checkout row, the
/// parent manifest reconciles clean, and the scan reports `complete`
/// with `submodules: checked` and zero gaps (no false gap).
#[test]
fn submodule_healthy_traversal_covered_reports_complete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let (parent, _) = fixture::submodule_repo(&root);

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = run(
        &[
            "scan",
            "--all",
            "--root",
            parent.to_str().expect("utf8"),
            "--report",
            report_path.to_str().expect("utf8"),
            "--format",
            "human",
        ],
        &root,
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    assert_eq!(report["scan"]["state"].as_str(), Some("complete"));
    assert_eq!(report["coverage"]["gaps"].as_u64(), Some(0));
    assert!(
        report["errors"].as_array().expect("errors").is_empty(),
        "no gaps: {}",
        report["errors"]
    );
    let kinds = checkouts_by_kind(&report);
    let sub = kinds.get("submodule").expect("submodule checkout row");
    assert_eq!(sub["status"]["state"].as_str(), Some("complete"));
    assert_eq!(sub["status"]["submodules"].as_str(), Some("checked"));
    let main = kinds.get("main").expect("parent checkout row");
    assert_eq!(main["status"]["state"].as_str(), Some("complete"));
    assert_eq!(main["status"]["submodules"].as_str(), Some("checked"));
}

/// BOUNDARY-M8 false-negative leg: a manifested submodule with no local
/// git data (worktree `.git` removed, modules store destroyed) was never
/// inspected — the scan must report `incomplete` with a loud
/// `submodule-uninspected` gap naming it, never silent `complete`.
#[test]
fn submodule_manifested_absent_gaps_loudly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let (parent, sub) = fixture::submodule_repo(&root);
    // Destroy all local git data for the submodule; the manifest still
    // names it. Modules store mirrors the worktree rel path.
    std::fs::remove_file(sub.join(".git")).expect("remove gitfile");
    let rel = sub.strip_prefix(&parent).expect("sub under parent");
    std::fs::remove_dir_all(parent.join(".git").join("modules").join(rel))
        .expect("remove modules store");

    let state = dir.path().join("state");
    let report_path = dir.path().join("rep.json");
    let out = run(
        &[
            "scan",
            "--all",
            "--root",
            parent.to_str().expect("utf8"),
            "--report",
            report_path.to_str().expect("utf8"),
            "--format",
            "human",
        ],
        &root,
        &state,
    );
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let report = read_report(&report_path);
    assert_eq!(report["scan"]["state"].as_str(), Some("incomplete"));
    assert!(
        report["coverage"]["gaps"].as_u64().unwrap_or(0) >= 1,
        "gap counted: {}",
        report["coverage"]
    );
    let errors = report["errors"].as_array().expect("errors");
    let gap = errors
        .iter()
        .find(|e| e["category"].as_str() == Some("submodule-uninspected"))
        .expect("submodule-uninspected gap");
    assert!(
        gap["message"]
            .as_str()
            .unwrap_or_default()
            .contains("vendor/sub"),
        "gap names the submodule: {gap}"
    );
    // The parent itself was inspected (status complete); the gap — not a
    // status failure — carries the uninspected scope.
    let kinds = checkouts_by_kind(&report);
    let main = kinds.get("main").expect("parent checkout row");
    assert_eq!(main["status"]["state"].as_str(), Some("complete"));
    assert!(!kinds.contains_key("submodule"), "no phantom submodule row");
}
