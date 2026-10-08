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

/// Base `git` command with the hermetic environment (no subcommand yet).
fn git_cmd(dir: &Path) -> Command {
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
        .arg("protocol.file.allow=always");
    cmd
}

/// Run `git` in `dir` with the hermetic environment. Returns stdout; panics
/// with command + status + stderr on failure.
pub fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let output = git_output(dir, args);
    assert!(
        output.status.success(),
        "git {args:?} in {} failed ({}): {}",
        dir.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Run `git` in `dir` with the hermetic environment; return raw output
/// without asserting success. Reference oracle for negative cases
/// (installed git must fail there too).
pub fn git_output(dir: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = git_cmd(dir);
    cmd.args(args);
    cmd.output()
        .unwrap_or_else(|e| panic!("spawn git {args:?} in {}: {e}", dir.display()))
}

/// True when installed git runs `args` in `dir` successfully (same
/// hermetic environment as [`git`]).
pub fn git_succeeds(dir: &Path, args: &[&str]) -> bool {
    git_output(dir, args).status.success()
}

/// Run `git` and return trimmed stdout as a string.
pub fn git_str(dir: &Path, args: &[&str]) -> String {
    String::from_utf8_lossy(&git(dir, args)).trim().to_owned()
}

/// Run `git` with byte-exact args (non-UTF-8 refnames/paths). Same
/// hermetic env as [`git`]; returns raw stdout. Unix-only.
#[cfg(unix)]
pub fn git_os(dir: &Path, args: &[&std::ffi::OsStr]) -> Vec<u8> {
    let mut cmd = git_cmd(dir);
    for arg in args {
        cmd.arg(arg);
    }
    let output = cmd.output().unwrap_or_else(|e| {
        panic!(
            "spawn git {} in {}: {e}",
            args.iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" "),
            dir.display()
        )
    });
    assert!(
        output.status.success(),
        "git {} in {} failed ({}): {}",
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" "),
        dir.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Repo with a non-UTF-8 branch (`refs/heads/byte-\xE9-\xFF`, legal
/// refname bytes) with HEAD pointing at it. The ref lives in
/// `.git/packed-refs` (raw bytes, no filename involved), so this works
/// even where the filesystem rejects non-UTF-8 names (macOS EILSEQ).
/// Returns `(repo, full_refname_bytes)`. Unix-only.
#[cfg(unix)]
pub fn non_utf8_branch_repo(parent: &Path, name: &str) -> (PathBuf, Vec<u8>) {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStringExt;
    let dir = normal_clone(parent, name);
    let head = git_str(&dir, &["rev-parse", "HEAD"]);
    let refname = b"refs/heads/byte-\xe9-\xff".to_vec();
    let packed = dir.join(".git/packed-refs");
    let mut contents = std::fs::read(&packed).unwrap_or_default();
    contents.extend_from_slice(head.as_bytes());
    contents.push(b' ');
    contents.extend_from_slice(&refname);
    contents.push(b'\n');
    private_write_0600(&packed, &contents).unwrap();
    let ref_arg = OsString::from_vec(refname.clone());
    git_os(
        &dir,
        &[
            OsStr::new("symbolic-ref"),
            OsStr::new("HEAD"),
            ref_arg.as_os_str(),
        ],
    );
    (dir, refname)
}

/// Repo with hostile worktree paths: a staged quote/backslash-hostile
/// file (non-UTF-8 `bad-\xFF-staged.txt` where the filesystem allows;
/// ASCII `quo"ted\\staged.txt` where it rejects, e.g. macOS EILSEQ),
/// an untracked newline name, an untracked control-char name, plus one
/// unstaged ASCII modification. Returns `(repo, staged_raw_name)`.
/// Unix-only.
#[cfg(unix)]
pub fn hostile_status_repo(parent: &Path, name: &str) -> (PathBuf, Vec<u8>) {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStringExt;
    let dir = normal_clone(parent, name);
    let mut staged_raw = b"bad-\xff-staged.txt".to_vec();
    let staged_name = OsString::from_vec(staged_raw.clone());
    if private_write_0600(&dir.join(&staged_name), b"staged\n").is_err() {
        // Filesystem rejects non-UTF-8 names (macOS): fall back to a
        // C-quote-hostile ASCII name (still raw under `-z`).
        staged_raw = b"quo\"ted\\staged.txt".to_vec();
        let staged_name = OsString::from_vec(staged_raw.clone());
        private_write_0600(&dir.join(&staged_name), b"staged\n").unwrap();
    }
    let staged_name = OsString::from_vec(staged_raw.clone());
    git_os(
        &dir,
        &[OsStr::new("add"), OsStr::new("--"), staged_name.as_os_str()],
    );
    for raw in [
        b"new\nline.txt".as_slice(),
        b"ctrl-\x01-char.txt".as_slice(),
    ] {
        let name = OsString::from_vec(raw.to_vec());
        private_write_0600(&dir.join(&name), b"hostile\n").unwrap();
    }
    private_write_0600(&dir.join("README.md"), b"# fixture\nmodified\n").unwrap();
    (dir, staged_raw)
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

/// Clone whose `main` tracks `origin/main` through the default fetch
/// refspec: the tracking ref is created offline (`update-ref`, no fetch)
/// and the `branch.main` stanza is written explicitly. Returns the repo
/// root. (Step 10 upstream tests.)
pub fn tracking_clone(parent: &Path, name: &str) -> PathBuf {
    let dir = normal_clone(parent, name);
    let head = git_str(&dir, &["rev-parse", "HEAD"]);
    git(&dir, &["update-ref", "refs/remotes/origin/main", &head]);
    git(&dir, &["config", "branch.main.remote", "origin"]);
    git(&dir, &["config", "branch.main.merge", "refs/heads/main"]);
    dir
}

/// Clone whose `main` tracks through a rewritten (non-default) fetch
/// refspec `+refs/heads/*:refs/custom/*`, with the tracking ref created
/// offline at the custom location. Returns the repo root.
pub fn custom_fetch_clone(parent: &Path, name: &str) -> PathBuf {
    let dir = normal_clone(parent, name);
    let head = git_str(&dir, &["rev-parse", "HEAD"]);
    git(
        &dir,
        &[
            "config",
            "remote.origin.fetch",
            "+refs/heads/*:refs/custom/*",
        ],
    );
    git(&dir, &["update-ref", "refs/custom/main", &head]);
    git(&dir, &["config", "branch.main.remote", "origin"]);
    git(&dir, &["config", "branch.main.merge", "refs/heads/main"]);
    dir
}

/// Clone whose `main` tracks a local branch (`remote = .`). Returns the
/// repo root.
pub fn local_upstream_clone(parent: &Path, name: &str) -> PathBuf {
    let dir = normal_clone(parent, name);
    git(&dir, &["branch", "other"]);
    git(&dir, &["config", "branch.main.remote", "."]);
    git(&dir, &["config", "branch.main.merge", "refs/heads/other"]);
    dir
}

/// Clone whose `branch.main` stanza lives in an included file
/// (`.git/extra.inc`, via `[include] path`), with the tracking ref
/// created offline. Returns the repo root.
pub fn include_upstream_clone(parent: &Path, name: &str) -> PathBuf {
    let dir = normal_clone(parent, name);
    let head = git_str(&dir, &["rev-parse", "HEAD"]);
    git(&dir, &["update-ref", "refs/remotes/origin/main", &head]);
    private_write_0600(
        &dir.join(".git/extra.inc"),
        b"[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
    )
    .unwrap();
    git(&dir, &["config", "include.path", "extra.inc"]);
    dir
}

/// Main repo plus one linked worktree on branch `wtbranch`, whose
/// tracking stanza lives ONLY in the linked worktree's own
/// `config.worktree` (gated by `extensions.worktreeConfig` in the common
/// config), with the tracking ref created offline. Returns
/// `(main_repo, worktree)`.
pub fn tracking_worktree(parent: &Path) -> (PathBuf, PathBuf) {
    let main = normal_clone(parent, "wtmain");
    let wt = parent.join("wtlink");
    let wt_arg = wt.to_string_lossy().into_owned();
    git(&main, &["worktree", "add", "-b", "wtbranch", &wt_arg]);
    let head = git_str(&main, &["rev-parse", "HEAD"]);
    git(&main, &["update-ref", "refs/remotes/origin/main", &head]);
    git(&main, &["config", "extensions.worktreeConfig", "true"]);
    let wt_gitdir = PathBuf::from(git_str(&wt, &["rev-parse", "--absolute-git-dir"]));
    private_write_0600(
        &wt_gitdir.join("config.worktree"),
        b"[branch \"wtbranch\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
    )
    .unwrap();
    (main, wt)
}

/// [`non_utf8_branch_repo`] plus tracking: `branch.<hostile>` tracks
/// `origin/main` (stanza written with byte-exact args, tracking ref
/// created offline). Returns `(repo, full_refname_bytes)`. Unix-only.
#[cfg(unix)]
pub fn non_utf8_tracking_repo(parent: &Path, name: &str) -> (PathBuf, Vec<u8>) {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStringExt;
    let (dir, refname) = non_utf8_branch_repo(parent, name);
    let head = git_str(&dir, &["rev-parse", "HEAD"]);
    git(&dir, &["update-ref", "refs/remotes/origin/main", &head]);
    let short = refname
        .strip_prefix(b"refs/heads/")
        .expect("hostile branch under refs/heads")
        .to_vec();
    for (suffix, value) in [
        (b".remote".as_slice(), "origin"),
        (b".merge".as_slice(), "refs/heads/main"),
    ] {
        let mut key = b"branch.".to_vec();
        key.extend_from_slice(&short);
        key.extend_from_slice(suffix);
        let key = std::ffi::OsString::from_vec(key);
        git_os(
            &dir,
            &[OsStr::new("config"), key.as_os_str(), OsStr::new(value)],
        );
    }
    (dir, refname)
}

/// `n` normal clones side by side (`{prefix}-000`, …) for slow-scan
/// timing windows (live discovery reads, progress coalescing). Returns
/// every repo root created.
pub fn many_repos(parent: &Path, prefix: &str, n: usize) -> Vec<PathBuf> {
    (0..n)
        .map(|i| normal_clone(parent, &format!("{prefix}-{i:03}")))
        .collect()
}

/// Chain of `depth` nested repos: each level holds a repo plus the next
/// level's directory, so parent/child enumeration tasks form a deep
/// completion chain (interrupted-batch resumption must lose no child).
/// Returns every repo root created, outermost first.
pub fn deep_repo_chain(parent: &Path, depth: usize) -> Vec<PathBuf> {
    let mut repos = Vec::with_capacity(depth);
    let mut level = parent.join("chain");
    private_dir_0700(&level).unwrap();
    for i in 0..depth {
        let repo = normal_clone(&level, &format!("repo-{i:02}"));
        repos.push(repo);
        level = level.join(format!("repo-{i:02}")).join("nested");
        if i + 1 < depth {
            private_dir_0700(&level).unwrap();
        }
    }
    repos
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

/// Local `main` vs `origin/main` with an exact ahead/behind shape
/// (Step 10 comparison tests): `behind` commits land on
/// `refs/remotes/origin/main` past the base, `ahead` commits land on
/// `main` past the base, and `branch.main` tracks `origin/main`
/// through the default fetch refspec. Returns the repo root.
/// `git rev-list --left-right --count main...origin/main` prints
/// `"{ahead}\t{behind}"`.
pub fn comparison_pair(parent: &Path, name: &str, ahead: u32, behind: u32) -> PathBuf {
    let dir = normal_clone(parent, name);
    let base = git_str(&dir, &["rev-parse", "HEAD"]);
    if behind > 0 {
        git(&dir, &["checkout", "-q", "-b", "tmp-upstream"]);
        for i in 0..behind {
            commit_file(
                &dir,
                &format!("up{i}.txt"),
                "upstream\n",
                &format!("upstream {i}"),
            );
        }
        let tip = git_str(&dir, &["rev-parse", "HEAD"]);
        git(&dir, &["checkout", "-q", "main"]);
        git(&dir, &["branch", "-q", "-D", "tmp-upstream"]);
        git(&dir, &["update-ref", "refs/remotes/origin/main", &tip]);
    } else {
        git(&dir, &["update-ref", "refs/remotes/origin/main", &base]);
    }
    for i in 0..ahead {
        commit_file(
            &dir,
            &format!("local{i}.txt"),
            "local\n",
            &format!("local {i}"),
        );
    }
    git(&dir, &["config", "branch.main.remote", "origin"]);
    git(&dir, &["config", "branch.main.merge", "refs/heads/main"]);
    dir
}

/// Shallow clone (`--depth`) of a seed with `1 + extra_commits`
/// linear commits on `main`. The seed is removed after cloning, so
/// the returned clone is self-contained. Returns the clone root.
pub fn shallow_clone(parent: &Path, name: &str, extra_commits: u32, depth: u32) -> PathBuf {
    let seed = normal_clone(parent, &format!(".seed-{name}"));
    for i in 0..extra_commits {
        commit_file(&seed, &format!("s{i}.txt"), "seed\n", &format!("seed {i}"));
    }
    private_dir_0700(parent).unwrap();
    // `file://` (not a plain path): plain-path clones ignore
    // `--depth` and copy everything; the hermetic env already sets
    // `protocol.file.allow=always` for local file transports.
    let seed_arg = format!("file://{}", seed.to_string_lossy());
    let depth_arg = depth.to_string();
    git(
        parent,
        &["clone", "-q", "--depth", &depth_arg, &seed_arg, name],
    );
    fs::remove_dir_all(&seed).unwrap();
    parent.join(name)
}

/// Local-path clone of `src` into `dst_parent/name` (Wave2b fetch
/// tests): `origin` points at the absolute source path, so `git fetch`
/// / `ls-remote` work fully offline with no network and no URL
/// rewriting. Returns the clone root.
pub fn clone_local(src: &Path, dst_parent: &Path, name: &str) -> PathBuf {
    private_dir_0700(dst_parent).unwrap();
    let src_arg = src.to_string_lossy().into_owned();
    git(dst_parent, &["clone", "-q", &src_arg, name]);
    dst_parent.join(name)
}

/// Append `n` linear commits to the current branch of `dir` (Wave2b
/// fetch tests: advance an upstream past a clone, or a clone past its
/// tracking ref). Returns the new tip OID.
pub fn advance_main(dir: &Path, prefix: &str, n: u32) -> String {
    let mut tip = String::new();
    for i in 0..n {
        tip = commit_file(
            dir,
            &format!("{prefix}{i}.txt"),
            &format!("{prefix} {i}\n"),
            &format!("{prefix} {i}"),
        );
    }
    tip
}

/// Repo with `n` linear commits on `main` (`n >= 1`). Returns the
/// repo root plus tip OIDs oldest-first (index 0 is the initial
/// commit). Missing-object tests delete one OID's object file.
pub fn commit_chain(parent: &Path, name: &str, n: u32) -> (PathBuf, Vec<String>) {
    assert!(n >= 1, "commit_chain needs n >= 1");
    let dir = normal_clone(parent, name);
    let mut oids = vec![git_str(&dir, &["rev-parse", "HEAD"])];
    for i in 1..n {
        oids.push(commit_file(
            &dir,
            &format!("c{i}.txt"),
            "data\n",
            &format!("commit {i}"),
        ));
    }
    (dir, oids)
}

// ---------------------------------------------------------------------------
// Wave3 TUI fixtures (Step 13, cases 24/25): hand-built `Report` values
// for the TUI view-state + renderer tests (no git binary, no scans).
// ---------------------------------------------------------------------------

use repo_scan::report::model::{
    Branch as TuiReportBranch, Checkout as TuiReportCheckout, Coverage as TuiReportCoverage,
    EncodedName as TuiReportName, Head as TuiReportHead, PathRecord as TuiReportPath,
    Remote as TuiReportRemote, Repository as TuiReportRepository, Resources as TuiReportResources,
    Scan as TuiReportScan, Status as TuiReportStatus, Tool as TuiReportTool,
};

/// Minimal path record with identical display/value text.
pub fn tui_path(id: &str, display: &str) -> TuiReportPath {
    TuiReportPath {
        id: id.to_string(),
        display: display.to_string(),
        encoding: "utf8".to_string(),
        value: display.to_string(),
        volume_id: None,
        object_id: None,
        incarnation: None,
    }
}

/// Minimal encoded name with identical display/value text.
pub fn tui_name(display: &str) -> TuiReportName {
    TuiReportName {
        display: display.to_string(),
        encoding: "utf8".to_string(),
        value: display.to_string(),
    }
}

/// Minimal status observation.
pub fn tui_status(state: &str, working_state: &str) -> TuiReportStatus {
    TuiReportStatus {
        state: state.to_string(),
        mode: "summary".to_string(),
        started_at: None,
        finished_at: None,
        staged: None,
        unstaged: None,
        untracked: None,
        conflicts: None,
        working_state: working_state.to_string(),
        untracked_units: "collapsed_entries".to_string(),
        submodules: "unknown".to_string(),
        unknown_fields: vec![],
        error_ids: vec![],
    }
}

/// Empty deterministic report shell (scan `scan-tui-1`, running).
pub fn tui_empty_report() -> repo_scan::report::model::Report {
    repo_scan::report::model::Report {
        schema_version: "1.4.0".to_string(),
        report_id: "report-tui-1".to_string(),
        created_at: "2026-10-07T00:00:00Z".to_string(),
        tool: TuiReportTool {
            name: "repo-scan".to_string(),
            version: "0.1.0".to_string(),
            source_commit: None,
        },
        scan: TuiReportScan {
            id: "scan-tui-1".to_string(),
            generation: 1,
            epoch: 1,
            catalog_revision: 1,
            target_url: "https://github.com/acme/widgets".to_string(),
            canonical_url: Some("https://github.com/acme/widgets".to_string()),
            targets: vec![],
            matching_policy: "v1".to_string(),
            scope: "roots".to_string(),
            state: "running".to_string(),
            started_at: "2026-10-07T00:00:00Z".to_string(),
            finished_at: None,
            superseded_by: None,
            cached: false,
            status_mode: "summary".to_string(),
        },
        coverage: TuiReportCoverage {
            filesystem: "incomplete".to_string(),
            identity: "unproven".to_string(),
            status: "incomplete".to_string(),
            directories_complete: 0,
            tasks_pending: 2,
            gaps: 0,
            unresolvable_candidates: 0,
            scope_boundaries: vec![],
        },
        resources: TuiReportResources {
            profile: "default".to_string(),
            cpu_target_cores: 1.0,
            rss_target_bytes: 1,
            peak_rss_bytes: None,
            cpu_seconds: None,
            enumerated_entries: 0,
            db_transactions: 0,
            db_sync_calls: None,
        },
        volumes: vec![],
        paths: vec![],
        roots: vec![],
        groups: vec![],
        repositories: vec![],
        checkouts: vec![],
        branches: vec![],
        remotes: vec![],
        storage_links: vec![],
        aliases: vec![],
        candidates: vec![],
        errors: vec![],
        generated_artifacts: vec![],
        totals: Default::default(),
    }
}

/// Sample report with two groups (`acme/widgets` with two stores,
/// `acme/gadgets` with one bare store) plus one ungrouped store,
/// four checkouts (clean, dirty, conflicted, pending), and branches
/// covering every comparison state the filters need.
pub fn tui_sample_report() -> repo_scan::report::model::Report {
    let mut report = tui_empty_report();
    report.paths = vec![
        tui_path("p-w1", "/srv/git/widgets"),
        tui_path("p-w1c", "/home/u/work/widgets"),
        tui_path("p-w2", "/srv/git/widgets-mirror"),
        tui_path("p-w2c", "/home/u/work/widgets-mirror"),
        tui_path("p-g1", "/srv/git/gadgets.git"),
        tui_path("p-u1", "/srv/git/scratch"),
        tui_path("p-u1c", "/home/u/work/scratch"),
    ];
    report.repositories = vec![
        TuiReportRepository {
            id: "repo-w1".to_string(),
            git_path_id: "p-w1".to_string(),
            common_path_id: "p-w1".to_string(),
            bare: Some(false),
            format: "common".to_string(),
            object_format: "sha1".to_string(),
            match_disposition: "confirmed".to_string(),
            evidence: vec![],
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            tool_managed: None,
            error_ids: vec![],
        },
        TuiReportRepository {
            id: "repo-w2".to_string(),
            git_path_id: "p-w2".to_string(),
            common_path_id: "p-w2".to_string(),
            bare: Some(false),
            format: "common".to_string(),
            object_format: "sha1".to_string(),
            match_disposition: "related".to_string(),
            evidence: vec![],
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            tool_managed: None,
            error_ids: vec![],
        },
        TuiReportRepository {
            id: "repo-g1".to_string(),
            git_path_id: "p-g1".to_string(),
            common_path_id: "p-g1".to_string(),
            bare: Some(true),
            format: "common".to_string(),
            object_format: "sha1".to_string(),
            match_disposition: "confirmed".to_string(),
            evidence: vec![],
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            tool_managed: None,
            error_ids: vec![],
        },
        TuiReportRepository {
            id: "repo-u1".to_string(),
            git_path_id: "p-u1".to_string(),
            common_path_id: "p-u1".to_string(),
            bare: Some(false),
            format: "common".to_string(),
            object_format: "sha1".to_string(),
            match_disposition: "nonmatch".to_string(),
            evidence: vec![],
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            tool_managed: None,
            error_ids: vec![],
        },
    ];
    report.remotes = vec![
        TuiReportRemote {
            id: "rem-w1".to_string(),
            repository_id: "repo-w1".to_string(),
            checkout_scope_id: None,
            name: tui_name("origin"),
            role: "fetch".to_string(),
            url: "https://github.com/acme/widgets.git".to_string(),
            canonical_url: Some("https://github.com/acme/widgets".to_string()),
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            refresh: None,
        },
        TuiReportRemote {
            id: "rem-w2".to_string(),
            repository_id: "repo-w2".to_string(),
            checkout_scope_id: None,
            name: tui_name("origin"),
            role: "fetch".to_string(),
            url: "https://github.com/acme/widgets.git".to_string(),
            canonical_url: Some("https://github.com/acme/widgets".to_string()),
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            refresh: None,
        },
        TuiReportRemote {
            id: "rem-g1".to_string(),
            repository_id: "repo-g1".to_string(),
            checkout_scope_id: None,
            name: tui_name("origin"),
            role: "fetch".to_string(),
            url: "https://github.com/acme/gadgets.git".to_string(),
            canonical_url: Some("https://github.com/acme/gadgets".to_string()),
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            refresh: None,
        },
    ];
    let head = |state: &str| TuiReportHead {
        state: state.to_string(),
        ref_name: None,
        oid: None,
    };
    report.checkouts = vec![
        TuiReportCheckout {
            id: "co-w1".to_string(),
            repository_id: "repo-w1".to_string(),
            root_path_id: Some("p-w1c".to_string()),
            git_path_id: "p-w1".to_string(),
            kind: "main".to_string(),
            availability: "present".to_string(),
            head: head("branch"),
            status: tui_status("complete", "clean"),
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            error_ids: vec![],
        },
        TuiReportCheckout {
            id: "co-w2".to_string(),
            repository_id: "repo-w2".to_string(),
            root_path_id: Some("p-w2c".to_string()),
            git_path_id: "p-w2".to_string(),
            kind: "main".to_string(),
            availability: "present".to_string(),
            head: head("branch"),
            status: tui_status("complete", "dirty"),
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            error_ids: vec![],
        },
        TuiReportCheckout {
            id: "co-g1".to_string(),
            repository_id: "repo-g1".to_string(),
            root_path_id: None,
            git_path_id: "p-g1".to_string(),
            kind: "main".to_string(),
            availability: "present".to_string(),
            head: head("branch"),
            status: tui_status("complete", "conflicted"),
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            error_ids: vec![],
        },
        TuiReportCheckout {
            id: "co-u1".to_string(),
            repository_id: "repo-u1".to_string(),
            root_path_id: Some("p-u1c".to_string()),
            git_path_id: "p-u1".to_string(),
            kind: "linked".to_string(),
            availability: "present".to_string(),
            head: head("unknown"),
            status: tui_status("pending", "pending"),
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            error_ids: vec![],
        },
    ];
    let branch = |id: &str, repo: &str, name: &str, comparison: &str| TuiReportBranch {
        id: id.to_string(),
        repository_id: repo.to_string(),
        checkout_scope_id: None,
        kind: "local".to_string(),
        name: tui_name(name),
        oid: None,
        symbolic_target: None,
        upstream: None,
        state: "valid".to_string(),
        observed_at: "2026-10-07T00:00:00Z".to_string(),
        error_ids: vec![],
        freshness: "unknown".to_string(),
        freshness_at: None,
        comparison: comparison.to_string(),
        ahead: None,
        behind: None,
    };
    report.branches = vec![
        branch("br-w1-main", "repo-w1", "main", "equal"),
        branch("br-w2-main", "repo-w2", "main", "ahead"),
        branch("br-w2-feat", "repo-w2", "feature", "diverged"),
        branch("br-g1-main", "repo-g1", "main", "behind"),
        branch("br-u1-main", "repo-u1", "main", "pending"),
    ];
    // Counted states carry counts (unknown is never zero).
    report.branches[1].ahead = Some(3);
    report.branches[2].ahead = Some(2);
    report.branches[2].behind = Some(1);
    report.branches[3].behind = Some(4);
    report
}
