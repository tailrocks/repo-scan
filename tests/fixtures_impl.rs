//! Fixture acceptance: every builder in `common::fixture` produces the layout
//! it claims (spec §17 traceability input for FS/GIT/STATUS rows).
//!
//! Markers asserted are the same signals production discovery relies on:
//! `.git` dir-vs-pointer shape, `HEAD`/`packed-refs`/`config` contents,
//! `worktree list` registration, submodule bookkeeping, ref oids, and
//! non-UTF-8 byte round-trips.

mod common;

use common::fixture;
use std::fs;
use tempfile::TempDir;

fn tmp() -> TempDir {
    TempDir::new().expect("scratch tempdir")
}

#[test]
fn normal_clone_has_commit_branch_and_remote() {
    let tmp = tmp();
    let repo = fixture::normal_clone(tmp.path(), "repo");
    fixture::assert_is_repo(&repo);
    assert!(repo.join(".git").is_dir());
    assert_eq!(
        fixture::git_str(&repo, &["branch", "--show-current"]),
        "main"
    );
    assert_eq!(
        fixture::git_str(&repo, &["remote", "get-url", "origin"]),
        fixture::FIXTURE_REMOTE_URL
    );
    let oid = fixture::git_str(&repo, &["rev-parse", "HEAD"]);
    assert_eq!(oid.len(), 40, "full sha1 oid");
    assert!(repo.join("README.md").is_file());
}

#[test]
fn bare_store_arbitrary_name_has_main_ref() {
    let tmp = tmp();
    let bare = fixture::bare_store(tmp.path(), "store.backup");
    assert!(bare.is_dir());
    assert_eq!(bare.file_name().unwrap(), "store.backup");
    assert!(bare.join("objects").is_dir());
    assert!(bare.join("HEAD").is_file());
    assert_eq!(
        fixture::git_str(&bare, &["config", "--bool", "core.bare"]),
        "true"
    );
    let oid = fixture::git_str(&bare, &["rev-parse", "refs/heads/main"]);
    assert_eq!(oid.len(), 40);
}

#[test]
fn linked_worktree_registers_pointer_checkout() {
    let tmp = tmp();
    let (main, wt) = fixture::linked_worktree(tmp.path());
    assert!(wt.join(".git").is_file(), "linked .git is a pointer file");
    let list = fixture::git_str(&main, &["worktree", "list"]);
    assert!(list.contains(&wt.to_string_lossy().into_owned()), "{list}");
    assert!(
        list.contains(&main.to_string_lossy().into_owned()),
        "{list}"
    );
    let gitdir = fixture::git_str(&wt, &["rev-parse", "--git-dir"]);
    assert!(gitdir.contains("worktrees"), "{gitdir}");
}

#[test]
fn detached_head_points_at_oid_not_branch() {
    let tmp = tmp();
    let repo = fixture::detached_head(tmp.path(), "repo");
    let head = fixture::read_to_string(&repo.join(".git/HEAD"));
    assert!(!head.starts_with("ref:"), "detached HEAD content: {head}");
    assert_eq!(head.trim().len(), 40);
    assert!(
        fixture::git_str(&repo, &["branch", "--show-current"]).is_empty(),
        "detached HEAD is on no branch"
    );
}

#[test]
fn submodule_registers_gitmodules_and_pointer() {
    let tmp = tmp();
    let (sup, sub) = fixture::submodule_repo(tmp.path());
    assert!(sup.join(".gitmodules").is_file());
    let modules = fixture::read_to_string(&sup.join(".gitmodules"));
    assert!(modules.contains("[submodule"), "{modules}");
    assert!(sub.join(".git").is_file(), "submodule .git is pointer file");
    let status = fixture::git_str(&sup, &["submodule", "status"]);
    assert!(status.contains("vendor/sub"), "{status}");
}

#[test]
fn nested_repo_is_unregistered_inner_clone() {
    let tmp = tmp();
    let (outer, inner) = fixture::nested_repo(tmp.path());
    fixture::assert_is_repo(&outer);
    fixture::assert_is_repo(&inner);
    assert!(inner.join(".git").is_dir(), "inner keeps its own git dir");
    assert!(
        !outer.join(".gitmodules").exists(),
        "no submodule registration"
    );
}

#[test]
fn packed_refs_collapses_branch_refs() {
    let tmp = tmp();
    let repo = fixture::packed_refs_repo(tmp.path(), "repo");
    let packed = repo.join(".git/packed-refs");
    assert!(packed.is_file());
    let body = fixture::read_to_string(&packed);
    for name in [
        "refs/heads/main",
        "refs/heads/feature-a",
        "refs/heads/feature-b",
    ] {
        assert!(body.contains(name), "packed-refs has {name}:\n{body}");
    }
    assert!(!repo.join(".git/refs/heads/feature-a").exists());
}

#[test]
fn unborn_branch_has_no_commits() {
    let tmp = tmp();
    let repo = fixture::unborn_branch(tmp.path(), "repo");
    fixture::assert_is_repo(&repo);
    let head = fixture::read_to_string(&repo.join(".git/HEAD"));
    assert!(head.starts_with("ref: refs/heads/"), "unborn HEAD: {head}");
    let probe = std::process::Command::new("git")
        .current_dir(&repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("spawn git rev-parse");
    assert!(!probe.status.success(), "unborn HEAD has no oid");
}

#[test]
fn external_git_dir_links_worktree_to_common_store() {
    let tmp = tmp();
    let (work, gitdir) = fixture::external_git_dir(tmp.path());
    assert!(work.join(".git").is_file(), "external .git is pointer file");
    let pointer = fixture::read_to_string(&work.join(".git"));
    assert!(pointer.starts_with("gitdir:"), "{pointer}");
    assert!(gitdir.join("HEAD").is_file());
    assert_eq!(
        fixture::git_str(&work, &["branch", "--show-current"]),
        "main"
    );
}

#[test]
fn diverged_clones_share_branch_name_with_distinct_oids() {
    let tmp = tmp();
    let (a, b) = fixture::diverged_clones(tmp.path());
    let oid_a = fixture::git_str(&a, &["rev-parse", "refs/heads/main"]);
    let oid_b = fixture::git_str(&b, &["rev-parse", "refs/heads/main"]);
    assert_ne!(oid_a, oid_b);
    assert_eq!(oid_a.len(), 40);
    assert_eq!(oid_b.len(), 40);
}

#[test]
fn shared_clone_records_alternates() {
    let tmp = tmp();
    let src = fixture::normal_clone(tmp.path(), "src");
    let dst = tmp.path().join("shared");
    fixture::shared_clone(&src, &dst);
    assert!(dst.join(".git/objects/info/alternates").is_file());
    let oid = fixture::git_str(&dst, &["rev-parse", "refs/heads/main"]);
    assert_eq!(
        oid,
        fixture::git_str(&src, &["rev-parse", "refs/heads/main"])
    );
}

#[test]
fn scope_layouts_cover_hidden_tmp_cache_and_recovery() {
    let tmp = tmp();
    let repos = fixture::scope_layouts(tmp.path());
    assert!(repos.len() >= 8, "all layouts built");
    for repo in &repos {
        fixture::assert_is_repo(repo);
    }
    let root = tmp.path();
    for rel in [
        ".hidden/repo",
        "tmp/scratch/repo",
        ".cache/tool/repo",
        "target/debug/repo",
        "node_modules/pkg/repo",
        "outer",
        "outer/inner",
        "outer/.git/recovery/salvaged",
    ] {
        assert!(
            root.join(rel).join(".git").exists(),
            "layout present: {rel}"
        );
    }
}

#[test]
#[cfg(unix)]
fn symlink_cycle_links_are_cycles() {
    let tmp = tmp();
    let dir = fixture::symlink_cycle(tmp.path());
    assert!(fs::symlink_metadata(dir.join("a")).unwrap().is_symlink());
    assert!(fs::read_link(dir.join("a")).unwrap().as_os_str() == "b");
    assert!(fs::read_link(dir.join("b")).unwrap().as_os_str() == "a");
    assert!(dir.join("self-loop").is_symlink());
}

#[test]
#[cfg(unix)]
fn non_utf8_names_round_trip_bytes() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let tmp = tmp();
    // macOS APFS rejects invalid-UTF-8 names (EILSEQ): probe first and skip
    // gracefully where the filesystem cannot represent them. Linux ext4/tmpfs
    // exercises the full byte round-trip below.
    let probe = tmp
        .path()
        .join(std::ffi::OsString::from_vec(b"probe-\xff".to_vec()));
    if repo_scan::privacy::private_dir_0700(&probe).is_err() {
        eprintln!("skipping: filesystem rejects invalid-UTF-8 names");
        return;
    }
    let _ = fs::remove_dir_all(&probe);
    let (dir, file) = fixture::non_utf8_names(tmp.path());
    assert!(dir.is_dir());
    assert!(file.is_file());
    let name = file.file_name().unwrap();
    assert!(name.to_str().is_none(), "name is not valid UTF-8");
    assert_eq!(name.as_bytes(), b"ctrl-\xfe-\xff.txt");
    let mut seen = false;
    for entry in fs::read_dir(tmp.path()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().as_bytes() == b"bad-\xff-dir" {
            seen = true;
        }
    }
    assert!(seen, "non-UTF-8 dir visible via read_dir");
}

#[test]
fn huge_flat_and_deep_path_hit_claimed_sizes() {
    let tmp = tmp();
    let flat = fixture::huge_flat(tmp.path(), fixture::HUGE_FLAT_CI);
    assert_eq!(fs::read_dir(&flat).unwrap().count(), fixture::HUGE_FLAT_CI);
    let (top, bottom) = fixture::deep_path(tmp.path(), fixture::DEEP_PATH_CI);
    assert!(bottom.is_file());
    let depth = bottom
        .strip_prefix(&top)
        .unwrap()
        .components()
        .count()
        .saturating_sub(1);
    assert_eq!(depth, fixture::DEEP_PATH_CI);
}

#[test]
fn dirty_variants_expose_all_status_inputs() {
    let tmp = tmp();
    let dirty = fixture::dirty_variants(tmp.path(), "repo");
    assert!(dirty.staged.is_file());
    assert!(dirty.modified.is_file());
    assert!(dirty.untracked_file.is_file());
    assert!(dirty.untracked_dir.is_dir());
    assert!(dirty.ignored.is_file());
    let porcelain = fixture::git_str(&dirty.repo, &["status", "--porcelain=v1"]);
    assert!(porcelain.contains("staged-new.txt"), "{porcelain}");
    assert!(porcelain.contains("README.md"), "{porcelain}");
    assert!(porcelain.contains("untracked.txt"), "{porcelain}");
    assert!(porcelain.contains("untracked-dir/"), "{porcelain}");
    assert!(!porcelain.contains("ignored.txt"), "{porcelain}");
    // Asserts exit success: the file is ignored.
    fixture::git(&dirty.repo, &["check-ignore", "-q", "ignored.txt"]);
}
