//! Deterministic git-layout fixture builders (spec §17, FS/GIT/STATUS rows).
//!
//! Hermetic: every `git` invocation runs with `GIT_CONFIG_GLOBAL` and
//! `GIT_CONFIG_SYSTEM` pointed at the null device, a fixed author identity,
//! `init.defaultBranch=main`, no GPG signing, background maintenance off
//! (`maintenance.auto=false`: commits fork no async job that transiently
//! creates `.git/objects/maintenance.lock` and races `.git` inventory
//! snapshots), foreground-only gc (`gc.autoDetach=false`), and
//! `protocol.file.allow=always` (local `file://` submodule/file transports
//! only — no network).
//!
//! Private-output contract (CONSUMER-SCOPE-PRIVACY-001): every directory and
//! file created below goes through `repo_scan::privacy` (`0o700` dirs,
//! `0o600` files, symlink refusal, no umask dependence). Scratch roots must
//! come from [`scratch_root`] (`/tmp`, `0o700`); never a machine-wide path.

use repo_scan::privacy::{private_dir_0700, private_write_0600};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Remote URL used by seeded fixtures. Never fetched or pushed over the
/// network; the bare-store seeding below pushes to local paths only.
pub const FIXTURE_REMOTE_URL: &str = "https://github.com/OWNER/REPO.git";

/// CI-bounded huge-flat size (FS-05): big enough to prove streaming, small
/// enough for a sub-two-minute CI path.
pub const HUGE_FLAT_CI: usize = 2_000;
/// CI-bounded deep-path depth (FS-05). Well under `PATH_MAX` (each level is
/// 4 bytes + separator ≈ 320 bytes total).
pub const DEEP_PATH_CI: usize = 64;

/// Null device for hermetic git config isolation.
#[cfg(unix)]
fn null_device() -> &'static str {
    "/dev/null"
}
/// Null device for hermetic git config isolation.
#[cfg(not(unix))]
fn null_device() -> &'static str {
    "NUL"
}

/// Run `git` in `dir` with the hermetic environment. Returns stdout; panics
/// with command + status + stderr on failure.
pub fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_CONFIG_SYSTEM", null_device())
        .env("GIT_AUTHOR_NAME", "repo-scan-fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "repo-scan-fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-c")
        .arg("user.name=repo-scan-fixture")
        .arg("-c")
        .arg("user.email=fixture@example.invalid")
        .arg("-c")
        .arg("init.defaultBranch=main")
        .arg("-c")
        .arg("commit.gpgsign=false")
        .arg("-c")
        .arg("maintenance.auto=false")
        .arg("-c")
        .arg("gc.autoDetach=false")
        .arg("-c")
        .arg("protocol.file.allow=always")
        .args(args);
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("spawn git {args:?} in {}: {e}", dir.display()));
    assert!(
        output.status.success(),
        "git {args:?} in {} failed ({}): {}",
        dir.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Run `git` and return trimmed stdout as a string.
pub fn git_str(dir: &Path, args: &[&str]) -> String {
    String::from_utf8_lossy(&git(dir, args)).trim().to_owned()
}

/// Private scratch root for fixture/state/report/log trees: a fresh
/// owner-only (`0o700`) tempdir pinned under `/tmp`. All fixture builders
/// take their `parent` from the returned dir; never pass a machine-wide path.
pub fn scratch_root(prefix: &str) -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/tmp")
        .expect("scratch tempdir under /tmp");
    private_dir_0700(dir.path()).expect("scratch root is 0700");
    dir
}

/// Write `name` under `dir`, stage it, and commit. Returns the new HEAD oid.
pub fn commit_file(dir: &Path, name: &str, contents: &str, message: &str) -> String {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        private_dir_0700(parent).unwrap();
    }
    private_write_0600(&path, contents.as_bytes()).unwrap();
    git(dir, &["add", "--", name]);
    git(dir, &["commit", "-q", "-m", message]);
    git_str(dir, &["rev-parse", "HEAD"])
}

/// `git init` + one commit + `main` branch + fixture `origin` remote.
/// Returns the repo root.
pub fn normal_clone(parent: &Path, name: &str) -> PathBuf {
    let dir = parent.join(name);
    private_dir_0700(&dir).unwrap();
    git(&dir, &["init", "-q"]);
    commit_file(&dir, "README.md", "# fixture\n", "initial");
    git(&dir, &["branch", "-M", "main"]);
    git(&dir, &["remote", "add", "origin", FIXTURE_REMOTE_URL]);
    dir
}

/// Bare store under an arbitrary (non-`.git`) name, seeded with one `main`
/// ref pushed from a scratch repo over a local path. Returns the bare dir.
pub fn bare_store(parent: &Path, name: &str) -> PathBuf {
    let bare = parent.join(name);
    private_dir_0700(parent).unwrap();
    git(parent, &["init", "-q", "--bare", name]);
    let scratch = parent.join(format!(".seed-{name}"));
    private_dir_0700(&scratch).unwrap();
    git(&scratch, &["init", "-q"]);
    commit_file(&scratch, "seed.txt", "seed\n", "seed");
    git(&scratch, &["branch", "-M", "main"]);
    let bare_arg = bare.to_string_lossy().into_owned();
    git(&scratch, &["push", "-q", &bare_arg, "main:main"]);
    git(&bare, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    fs::remove_dir_all(&scratch).unwrap();
    bare
}

/// Main repo plus one linked worktree created with `git worktree add`.
/// Returns `(main_repo, worktree)`.
pub fn linked_worktree(parent: &Path) -> (PathBuf, PathBuf) {
    let main = normal_clone(parent, "main");
    let wt = parent.join("wt-feature");
    let wt_arg = wt.to_string_lossy().into_owned();
    git(&main, &["worktree", "add", "--detach", &wt_arg]);
    (main, wt)
}

/// Repo whose HEAD is detached at its single commit. Returns the repo root.
pub fn detached_head(parent: &Path, name: &str) -> PathBuf {
    let dir = normal_clone(parent, name);
    git(&dir, &["checkout", "-q", "--detach", "HEAD"]);
    dir
}

/// Super-project with one committed submodule. Returns `(super_repo, submodule_path)`.
pub fn submodule_repo(parent: &Path) -> (PathBuf, PathBuf) {
    let src = normal_clone(parent, "sub-src");
    let sup = normal_clone(parent, "super");
    let src_arg = src.to_string_lossy().into_owned();
    git(&sup, &["submodule", "-q", "add", &src_arg, "vendor/sub"]);
    git(&sup, &["commit", "-q", "-m", "add submodule"]);
    let sub = sup.join("vendor/sub");
    (sup, sub)
}

/// Plain nested repo: inner `git init` inside an outer repo with NO
/// submodule registration. Returns `(outer, inner)`.
pub fn nested_repo(parent: &Path) -> (PathBuf, PathBuf) {
    let outer = normal_clone(parent, "outer");
    let inner = outer.join("nested/inner");
    private_dir_0700(&inner).unwrap();
    git(&inner, &["init", "-q"]);
    commit_file(&inner, "inner.txt", "inner\n", "inner initial");
    git(&inner, &["branch", "-M", "main"]);
    (outer, inner)
}

/// Repo with several branches collapsed into `.git/packed-refs`.
/// Returns the repo root.
pub fn packed_refs_repo(parent: &Path, name: &str) -> PathBuf {
    let dir = normal_clone(parent, name);
    commit_file(&dir, "second.txt", "two\n", "second");
    git(&dir, &["branch", "feature-a"]);
    git(&dir, &["branch", "feature-b"]);
    git(&dir, &["pack-refs", "--all", "--prune"]);
    dir
}

/// Fresh `git init` with no commits: HEAD is unborn. Returns the repo root.
pub fn unborn_branch(parent: &Path, name: &str) -> PathBuf {
    let dir = parent.join(name);
    private_dir_0700(&dir).unwrap();
    git(&dir, &["init", "-q"]);
    dir
}

/// Repo using an external git directory (`work/.git` is a pointer file).
/// Returns `(worktree, git_dir)`.
pub fn external_git_dir(parent: &Path) -> (PathBuf, PathBuf) {
    let work = parent.join("work");
    let gitdir = parent.join("elsewhere/common.git");
    private_dir_0700(parent).unwrap();
    if let Some(gitdir_parent) = gitdir.parent() {
        private_dir_0700(gitdir_parent).unwrap();
    }
    let gitdir_arg = gitdir.to_string_lossy().into_owned();
    let work_arg = work.to_string_lossy().into_owned();
    git(
        parent,
        &["init", "-q", "--separate-git-dir", &gitdir_arg, &work_arg],
    );
    commit_file(&work, "file.txt", "work\n", "initial");
    git(&work, &["branch", "-M", "main"]);
    (work, gitdir)
}

/// Two independent repos whose `main` branches point at different oids
/// (GIT-01: same branch name, different work). Returns `(a, b)`.
pub fn diverged_clones(parent: &Path) -> (PathBuf, PathBuf) {
    let a = parent.join("clone-a");
    private_dir_0700(&a).unwrap();
    git(&a, &["init", "-q"]);
    commit_file(&a, "work.txt", "contents-a\n", "work a");
    git(&a, &["branch", "-M", "main"]);

    let b = parent.join("clone-b");
    private_dir_0700(&b).unwrap();
    git(&b, &["init", "-q"]);
    commit_file(&b, "work.txt", "contents-b\n", "work b");
    git(&b, &["branch", "-M", "main"]);
    (a, b)
}

/// Clone sharing its source's object store via alternates (GIT-02).
/// Returns the clone root.
pub fn shared_clone(src: &Path, dst: &Path) -> PathBuf {
    if let Some(parent) = dst.parent() {
        private_dir_0700(parent).unwrap();
    }
    let src_arg = src.to_string_lossy().into_owned();
    let dst_arg = dst.to_string_lossy().into_owned();
    let scratch = dst
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    git(&scratch, &["clone", "-q", "--shared", &src_arg, &dst_arg]);
    dst.to_path_buf()
}

/// Scope layouts that must never be silently excluded (FS-01/FS-02):
/// hidden dirs, tmp, package/tool caches, nested repos, and a clone inside
/// another repo's `.git/recovery`. Returns every repo root created.
pub fn scope_layouts(root: &Path) -> Vec<PathBuf> {
    let mut repos = Vec::new();
    for rel in [
        ".hidden/repo",
        "tmp/scratch/repo",
        ".cache/tool/repo",
        "target/debug/repo",
        "node_modules/pkg/repo",
    ] {
        let dir = root.join(rel);
        private_dir_0700(dir.parent().unwrap()).unwrap();
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        repos.push(normal_clone(dir.parent().unwrap(), &name));
    }
    // Nested repository (plain, unregistered).
    let outer = normal_clone(root, "outer");
    repos.push(normal_clone(&outer, "inner"));
    // Clone inside another repo's administrative recovery area.
    let recovery = outer.join(".git/recovery");
    private_dir_0700(&recovery).unwrap();
    repos.push(normal_clone(&recovery, "salvaged"));
    repos.push(outer);
    repos
}

/// Native symlink cycle `a <-> b` plus a self-loop (FS-03 topology input).
/// Unix-only; returns the directory holding the links.
#[cfg(unix)]
pub fn symlink_cycle(root: &Path) -> PathBuf {
    let dir = root.join("cycle");
    private_dir_0700(&dir).unwrap();
    std::os::unix::fs::symlink("b", dir.join("a")).unwrap();
    std::os::unix::fs::symlink("a", dir.join("b")).unwrap();
    std::os::unix::fs::symlink("self-loop", dir.join("self-loop")).unwrap();
    dir
}

/// Directory plus file whose names are invalid UTF-8 (FS-04). Unix-only;
/// returns `(dir_path, file_path)` as raw `OsString` joins.
#[cfg(unix)]
pub fn non_utf8_names(root: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::ffi::OsStringExt;
    let dir_name = OsString::from_vec(b"bad-\xff-dir".to_vec());
    let file_name = OsString::from_vec(b"ctrl-\xfe-\xff.txt".to_vec());
    let dir = root.join(&dir_name);
    private_dir_0700(&dir).unwrap();
    let file = dir.join(&file_name);
    private_write_0600(&file, b"bytes\n").unwrap();
    (dir, file)
}

/// One directory holding `count` regular files (FS-05 huge-flat input).
/// Returns the directory.
pub fn huge_flat(root: &Path, count: usize) -> PathBuf {
    let dir = root.join("flat");
    private_dir_0700(&dir).unwrap();
    for i in 0..count {
        private_write_0600(&dir.join(format!("f{i:06}")), b"x").unwrap();
    }
    dir
}

/// Single chain of `depth` nested directories with a marker file at the
/// bottom (FS-05 deep-path input). Returns `(top, bottom_file)`.
pub fn deep_path(root: &Path, depth: usize) -> (PathBuf, PathBuf) {
    let mut dir = root.join("deep");
    private_dir_0700(&dir).unwrap();
    let top = dir.clone();
    for i in 0..depth {
        dir = dir.join(format!("d{i:03}"));
        private_dir_0700(&dir).unwrap();
    }
    let marker = dir.join("bottom.txt");
    private_write_0600(&marker, b"bottom\n").unwrap();
    (top, marker)
}

/// Dirty/untracked working-state variants (STATUS-01) on one committed repo.
pub struct DirtyLayout {
    /// Repo root.
    pub repo: PathBuf,
    /// New file staged in the index.
    pub staged: PathBuf,
    /// Tracked file with unstaged modification.
    pub modified: PathBuf,
    /// Untracked file at top level.
    pub untracked_file: PathBuf,
    /// Untracked directory holding files (one collapsed status entry).
    pub untracked_dir: PathBuf,
    /// Ignored file (must never be counted by status).
    pub ignored: PathBuf,
}

/// Build the [`DirtyLayout`]: staged + unstaged + untracked file/dir +
/// ignored file, each independently addressable.
pub fn dirty_variants(parent: &Path, name: &str) -> DirtyLayout {
    let repo = normal_clone(parent, name);
    let staged = repo.join("staged-new.txt");
    private_write_0600(&staged, b"staged\n").unwrap();
    git(&repo, &["add", "--", "staged-new.txt"]);
    let modified = repo.join("README.md");
    private_write_0600(&modified, b"# fixture\nmodified\n").unwrap();
    let untracked_file = repo.join("untracked.txt");
    private_write_0600(&untracked_file, b"untracked\n").unwrap();
    let untracked_dir = repo.join("untracked-dir");
    private_dir_0700(&untracked_dir).unwrap();
    private_write_0600(&untracked_dir.join("a.txt"), b"a\n").unwrap();
    private_write_0600(&untracked_dir.join("b.txt"), b"b\n").unwrap();
    private_write_0600(&repo.join(".gitignore"), b"ignored.txt\n").unwrap();
    let ignored = repo.join("ignored.txt");
    private_write_0600(&ignored, b"ignored\n").unwrap();
    DirtyLayout {
        repo,
        staged,
        modified,
        untracked_file,
        untracked_dir,
        ignored,
    }
}

/// Clone with an unresolved two-file merge conflict (Step 10 case 10):
/// `file.txt` and `file2.txt` both conflict between `main` and `side`,
/// so the independent reference (`git ls-files -u`) lists 6 stage
/// entries collapsing to 2 conflicted paths. Returns the workdir.
pub fn conflict_clone(parent: &Path, name: &str) -> PathBuf {
    let dir = normal_clone(parent, name);
    commit_file(&dir, "file.txt", "base\n", "base file");
    commit_file(&dir, "file2.txt", "base2\n", "base file2");
    git(&dir, &["checkout", "-q", "-b", "side"]);
    commit_file(&dir, "file.txt", "side\n", "side file");
    commit_file(&dir, "file2.txt", "side2\n", "side file2");
    git(&dir, &["checkout", "-q", "main"]);
    commit_file(&dir, "file.txt", "main\n", "main file");
    commit_file(&dir, "file2.txt", "main2\n", "main file2");
    // The merge MUST fail with conflicts; `git()` asserts success, so
    // this one spawn carries the same hermetic env but allows the
    // conflict exit status.
    let output = Command::new("git")
        .current_dir(&dir)
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_CONFIG_SYSTEM", null_device())
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-c")
        .arg("user.name=repo-scan-fixture")
        .arg("-c")
        .arg("user.email=fixture@example.invalid")
        .arg("-c")
        .arg("commit.gpgsign=false")
        .arg("merge")
        .arg("side")
        .output()
        .unwrap_or_else(|e| panic!("spawn git merge in {}: {e}", dir.display()));
    assert!(
        !output.status.success(),
        "merge must conflict in {}",
        dir.display()
    );
    let unmerged = git_str(&dir, &["ls-files", "-u"]);
    assert_eq!(
        unmerged.lines().count(),
        6,
        "3 stages x 2 files expected: {unmerged}"
    );
    assert!(unmerged.contains("file.txt") && unmerged.contains("file2.txt"));
    dir
}

/// Read a file to string; panics with the path on failure.
pub fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Assert `path` is a directory containing `.git` (dir or pointer file).
pub fn assert_is_repo(path: &Path) {
    assert!(path.is_dir(), "repo root is dir: {}", path.display());
    assert!(
        path.join(".git").exists(),
        "repo has .git: {}",
        path.display()
    );
}
