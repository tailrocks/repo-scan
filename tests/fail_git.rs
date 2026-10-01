//! Fail-git boundary regression tests: one focused test per PATH-GIT/XSEC
//! fix. Fixtures live under `/tmp` only via `tempfile` (0700); run-loop
//! cases drive `src/main.rs` through its `#[cfg(test)]` hooks — the same
//! code production executes. All custom fixture data stays tiny (well
//! under 4 KiB); unbounded inputs are `/dev/zero`/FIFOs, never big files.

#[cfg(unix)]
mod common;

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

#[cfg(unix)]
use common::fixture;
#[cfg(unix)]
use repo_scan::config;
#[cfg(unix)]
use repo_scan::git::fallback::FallbackGit;
#[cfg(unix)]
use repo_scan::git::{self, config_include_gap, GitInspect, GixInspector, CONFIG_INCLUDE_GAP};
#[cfg(unix)]
use repo_scan::identity::{load_ssh_aliases_from, parse_ssh_config, MAX_SSH_CONFIG_ALIASES};
#[cfg(unix)]
use repo_scan::store::{now_ms, Store, TaskOutcome, TursoStore};
#[cfg(unix)]
use repo_scan::walk::topology::{
    FenceError, FenceOpen, PhysicalDirId, ScheduleProvenance, ScopeFence,
};
#[cfg(unix)]
use std::path::{Path, PathBuf};

/// Mark `path` executable (0700-rooted `tempfile` fixture binaries).
#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

/// Write an executable `git` fixture: `--version` prints `banner`, every
/// other argv runs `body`.
#[cfg(unix)]
fn write_git_fixture(path: &Path, banner: &str, body: &str) {
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\necho \"{banner}\"\nexit 0\nfi\n{body}\n"
    );
    repo_scan::privacy::private_write_0600(path, script.as_bytes()).unwrap();
    make_executable(path);
}

/// PATH-GIT-01: an out-of-scope relationship path pins through the
/// unscoped descriptor walk and re-verifies identity; a swapped-in link
/// or a replaced directory fails re-verification.
#[cfg(unix)]
#[test]
fn relationship_paths_pin_and_reverify_identity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    let foreign = tmp.path().join("foreign");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    repo_scan::privacy::private_dir_0700(&foreign).unwrap();
    let fence = ScopeFence::build(std::slice::from_ref(&root));
    // Out of scope, but pinnable as an explicit relationship.
    assert!(!fence.allows_path(&foreign));
    let pinned = match fence.open_relationship_pinned(&foreign).expect("pin") {
        FenceOpen::Dir(pinned) => pinned,
        FenceOpen::Symlink => panic!("foreign is not a link"),
    };
    assert!(fence.reverify_relationship(&foreign, &pinned));
    assert!(fence.reverify_pinned(&foreign, &pinned));
    // Swap the directory for a link: the pin must not verify, and a
    // fresh pin must report the link instead of following it.
    std::fs::remove_dir(&foreign).unwrap();
    std::os::unix::fs::symlink(&root, &foreign).unwrap();
    assert!(!fence.reverify_relationship(&foreign, &pinned));
    assert!(!fence.reverify_pinned(&foreign, &pinned));
    assert!(matches!(
        fence.open_relationship_pinned(&foreign).expect("re-pin"),
        FenceOpen::Symlink
    ));
    // Swap for a different directory: identity mismatch fails too.
    std::fs::remove_file(&foreign).unwrap();
    repo_scan::privacy::private_dir_0700(&foreign).unwrap();
    assert!(!fence.reverify_relationship(&foreign, &pinned));
    assert!(!fence.reverify_pinned(&foreign, &pinned));
}

/// PATH-GIT-02: a root directory replaced between scheduling and a
/// descendant lookup must fail the descendant open — the prefix text
/// still matches, but the root descriptor identity does not.
#[cfg(unix)]
#[test]
fn descendant_open_rejects_root_replacement() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    let child = root.join("child");
    repo_scan::privacy::private_dir_0700(&child).unwrap();
    let fence = ScopeFence::build(std::slice::from_ref(&root));
    let pinned = match fence.open_pinned(&child).expect("baseline pin") {
        FenceOpen::Dir(pinned) => pinned,
        FenceOpen::Symlink => panic!("not a link"),
    };
    // Replace the root directory at the same spelling with a fresh one.
    let stash = tmp.path().join("root-orig");
    std::fs::rename(&root, &stash).unwrap();
    repo_scan::privacy::private_dir_0700(&child).unwrap();
    let err = fence
        .open_pinned(&child)
        .expect_err("replaced root must fail");
    assert!(matches!(err, FenceError::OutOfScope(_)), "got {err:?}");
    assert!(!fence.reverify_pinned(&child, &pinned));
}

/// PATH-GIT-03 (unix): descriptor pinning is always available, so the
/// fail-closed refusal arm is unreachable — pins succeed, never
/// `Unsupported`, and no probe/status path degrades to unfenced.
#[cfg(unix)]
#[test]
fn unix_pin_never_reports_unsupported() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    let fence = ScopeFence::build(std::slice::from_ref(&root));
    for opened in [
        fence.open_pinned(&root),
        fence.open_relationship_pinned(&root),
    ] {
        match opened {
            Ok(_) => {}
            Err(FenceError::Unsupported(detail)) => {
                panic!("unix must pin, never Unsupported: {detail}")
            }
            Err(e) => panic!("unexpected fence error: {e:?}"),
        }
    }
}

/// PATH-GIT-03 (non-unix): descriptor pinning is unavailable, so every
/// fenced open refuses and the run-loop probe parks `Unsupported`
/// instead of running unfenced.
#[cfg(not(unix))]
#[test]
fn unsupported_pin_fails_closed() {
    use repo_scan::model::TaskState;
    use repo_scan::store::{now_ms, Store, TaskOutcome, TursoStore};
    use repo_scan::walk::topology::{FenceError, ScopeFence};

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    let fence = ScopeFence::build(std::slice::from_ref(&root));
    assert!(matches!(
        fence.open_pinned(&root),
        Err(FenceError::Unsupported(_))
    ));
    assert!(matches!(
        fence.open_relationship_pinned(&root),
        Err(FenceError::Unsupported(_))
    ));
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let db = tmp.path().join("probe.db");
        let store = TursoStore::open(&db).await.expect("open");
        let generation = store
            .create_generation("roots", "running", None, now_ms())
            .await
            .expect("generation");
        let run_rev = store.current_revision().await.expect("revision");
        let outcome = main_under_test::test_probe_fenced_outcome(
            &store,
            std::slice::from_ref(&root),
            generation,
            run_rev,
            "https://github.com/owner/repo",
            &root,
            None,
        )
        .await
        .expect("probe");
        match outcome {
            TaskOutcome::Parked { state, reason } => {
                assert!(matches!(state, TaskState::Unsupported), "{state:?}");
                assert!(reason.contains("refusing unfenced"), "{reason}");
            }
            other => panic!("unsupported pin must park, got {other:?}"),
        }
    });
}

/// PATH-GIT-05: the capability probe runs `init` and `status --help`
/// inside a probe-owned tempdir (never the ambient CWD), with an empty
/// probe-owned template and hooks/fsmonitor neutralized.
#[cfg(unix)]
#[test]
fn probe_runs_in_owned_tempdir_with_isolated_template() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let log = tmp.path().join("probe.log");
    let git = tmp.path().join("git");
    let script = format!(
        "#!/bin/sh\necho \"CWD=$PWD ARGV=$*\" >> \"{}\"\nif [ \"$1\" = \"--version\" ]; then\necho \"git version 2.47.1\"\nexit 0\nfi\necho \" --porcelain[<version>]  machine-readable output\"\nexit 0\n",
        log.display()
    );
    repo_scan::privacy::private_write_0600(&git, script.as_bytes()).unwrap();
    make_executable(&git);

    let found = FallbackGit::probe(&git).expect("capable fixture must probe");
    assert!(found.capabilities().feature_probe_ok);

    let logged = std::fs::read_to_string(&log).expect("log");
    let ambient = std::env::current_dir().expect("cwd");
    let mut saw_init = false;
    let mut saw_status = false;
    for line in logged.lines() {
        if line.contains(" ARGV=--version") {
            continue; // identity spawn inherits CWD by design (no repo)
        }
        let cwd = line
            .strip_prefix("CWD=")
            .and_then(|rest| rest.split_once(" ARGV="))
            .map(|(cwd, _)| cwd)
            .expect("log shape");
        assert_ne!(
            Path::new(cwd),
            ambient.as_path(),
            "probe must not run in ambient CWD: {line}"
        );
        if line.contains(" init -q") {
            saw_init = true;
            assert!(
                line.contains("--template="),
                "init isolates templates: {line}"
            );
            assert!(
                line.contains("core.hooksPath=/dev/null"),
                "init neutralizes hooks: {line}"
            );
            assert!(
                line.contains("core.fsmonitor=false"),
                "init neutralizes fsmonitor: {line}"
            );
            let template = line
                .split("--template=")
                .nth(1)
                .expect("template")
                .split_whitespace()
                .next()
                .expect("template value");
            // The shell logs the physical CWD (`/private/var/...`) while
            // the `--template` argv carries the logical TMPDIR spelling
            // (`/var/...`): same directory, different prefix. Normalize
            // both through the (live) temp root, since the probe-owned
            // dir is already deleted and cannot be canonicalized itself.
            let tmp_base = std::env::temp_dir();
            let tmp_canon = std::fs::canonicalize(&tmp_base).unwrap_or_else(|_| tmp_base.clone());
            let normalize = |path: &str| {
                let path = Path::new(path);
                path.strip_prefix(&tmp_base)
                    .map(|rest| tmp_canon.join(rest))
                    .unwrap_or_else(|_| path.to_path_buf())
            };
            assert!(
                normalize(template).starts_with(normalize(cwd)),
                "template must be probe-owned: {line}"
            );
        }
        if line.contains(" status --porcelain=v2 --help") {
            saw_status = true;
            assert!(
                line.contains("core.hooksPath=/dev/null"),
                "probe neutralizes hooks: {line}"
            );
            assert!(
                line.contains("core.fsmonitor=false"),
                "probe neutralizes fsmonitor: {line}"
            );
        }
    }
    assert!(saw_init && saw_status, "both spawns logged:\n{logged}");
}

/// PATH-GIT-06: empty, relative, directory, and non-executable binary
/// paths are refused; only absolute regular executables probe.
#[cfg(unix)]
#[test]
fn probe_rejects_empty_relative_and_nonregular_binaries() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let git = tmp.path().join("git");
    write_git_fixture(
        &git,
        "git version 2.47.1",
        "echo \" --porcelain[<version>]  machine-readable output\"\nexit 0",
    );
    assert!(
        FallbackGit::probe(&git).is_some(),
        "absolute executable probes"
    );

    assert!(FallbackGit::probe(Path::new("")).is_none(), "empty refused");
    assert!(
        FallbackGit::probe(Path::new("git")).is_none(),
        "bare name refused"
    );

    // CWD-relative spelling of the same valid binary: still refused.
    let cwd = std::env::current_dir().expect("cwd");
    let mut rel = PathBuf::new();
    for _ in 0..cwd.components().count() {
        rel.push("..");
    }
    rel.push(git.strip_prefix("/").expect("absolute fixture"));
    assert!(!rel.is_absolute());
    assert!(
        FallbackGit::probe(&rel).is_none(),
        "relative refused: {}",
        rel.display()
    );

    assert!(
        FallbackGit::probe(tmp.path()).is_none(),
        "directory refused"
    );
    let plain = tmp.path().join("plain.sh");
    repo_scan::privacy::private_write_0600(&plain, "#!/bin/sh\necho hi\n".as_bytes()).unwrap();
    let mut perms = std::fs::metadata(&plain).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&plain, perms).unwrap();
    assert!(
        FallbackGit::probe(&plain).is_none(),
        "non-executable refused"
    );
}

/// PATH-GIT-07: Git control reads are byte-capped and regular-file-only —
/// over-cap content, symlinks, and FIFOs refuse without blocking, a
/// `/dev/zero` include cannot hang config collection, and symlinked
/// includes are recorded absent instead of followed.
#[cfg(unix)]
#[test]
fn git_control_reads_are_byte_capped() {
    // Tiny cap, tiny file: same code path as the production cap.
    let tmp = tempfile::tempdir().expect("tempdir");
    let small = tmp.path().join("small");
    repo_scan::privacy::private_write_0600(&small, b"0123456789abcdef").unwrap();
    assert_eq!(git::read_bounded_bytes(&small, 16).unwrap().len(), 16);
    assert!(
        git::read_bounded_bytes(&small, 15).is_none(),
        "over-cap closed"
    );
    assert!(git::read_bounded_bytes(&tmp.path().join("missing"), 16).is_none());

    // Symlinks are never followed.
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&small, &link).unwrap();
    assert!(
        git::read_bounded_bytes(&link, 1024).is_none(),
        "link refused"
    );

    // FIFOs refuse without blocking (a plain open+read would wedge here).
    let fifo = tmp.path().join("fifo");
    {
        use std::os::unix::ffi::OsStrExt;
        let c_fifo = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
    }
    assert!(
        git::read_bounded_bytes(&fifo, 1024).is_none(),
        "fifo refused"
    );

    // A `/dev/zero` include returns promptly instead of hanging.
    let parent = tmp.path().join("repos");
    repo_scan::privacy::private_dir_0700(&parent).unwrap();
    let repo = fixture::normal_clone(&parent, "zero");
    let config_path = repo.join(".git/config");
    let mut config_text = std::fs::read_to_string(&config_path).unwrap();
    config_text.push_str("\n[include]\npath = /dev/zero\n");
    repo_scan::privacy::private_write_0600(&config_path, config_text.as_bytes()).unwrap();
    // Direct instance: `config_dependencies` only joins `git_dir` /
    // `common_dir` — gix never opens the poisoned config.
    let instance = git::GitInstance {
        git_dir: repo.join(".git"),
        common_dir: repo.join(".git"),
        work_dir: Some(repo.clone()),
        is_bare: false,
        object_format: String::from("sha1"),
    };
    let inspector = GixInspector::new();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let deps = inspector.config_dependencies(&instance);
        let _ = tx.send(deps);
    });
    let deps = rx
        .recv_timeout(std::time::Duration::from_secs(15))
        .expect("config scan must not hang on /dev/zero");
    assert!(deps
        .iter()
        .any(|d| d.path.ends_with("config") && !d.via_include));
    let zero = deps
        .iter()
        .find(|d| d.path.as_path() == Path::new("/dev/zero"))
        .expect("zero dep recorded");
    assert!(!zero.exists, "/dev/zero is not a regular config file");

    // Symlinked includes are recorded absent, never followed.
    let target = tmp.path().join("target.conf");
    repo_scan::privacy::private_write_0600(
        &target,
        "[include]\npath = /tmp/nested-from-link\n".as_bytes(),
    )
    .unwrap();
    let linkconf = parent.join("link.conf");
    std::os::unix::fs::symlink(&target, &linkconf).unwrap();
    let repo2 = fixture::normal_clone(&parent, "linked");
    let config2 = repo2.join(".git/config");
    let mut text2 = std::fs::read_to_string(&config2).unwrap();
    text2.push_str(&format!("\n[include]\npath = {}\n", linkconf.display()));
    repo_scan::privacy::private_write_0600(&config2, text2.as_bytes()).unwrap();
    let instance2 = git::GitInstance {
        git_dir: repo2.join(".git"),
        common_dir: repo2.join(".git"),
        work_dir: Some(repo2.clone()),
        is_bare: false,
        object_format: String::from("sha1"),
    };
    let deps2 = GixInspector::new().config_dependencies(&instance2);
    let linked = deps2
        .iter()
        .find(|d| d.path == linkconf)
        .expect("link dep recorded");
    assert!(!linked.exists, "symlinked include reads as absent");
    assert!(
        !deps2
            .iter()
            .any(|d| d.path.as_path() == Path::new("/tmp/nested-from-link")),
        "nothing is followed through a symlinked include"
    );
}

/// XSEC-01: relationship inspection runs inside the pinned envelope —
/// a probe scheduled through a symlink parent completes and persists
/// under the scheduling spelling (spelling-stable rows), while the
/// pre-run pin and post-run re-verification bind the execution.
/// Mid-run swap detection itself is covered by
/// `relationship_paths_pin_and_reverify_identity`.
#[cfg(unix)]
#[test]
fn relationship_probe_runs_inside_pinned_envelope() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("root");
        let outside = tmp.path().join("outside");
        repo_scan::privacy::private_dir_0700(&root).unwrap();
        let real_parent = outside.join("real");
        repo_scan::privacy::private_dir_0700(&real_parent).unwrap();
        fixture::normal_clone(&real_parent, "repo");
        std::os::unix::fs::symlink(&real_parent, outside.join("link")).unwrap();
        let scheduled = outside.join("link").join("repo");
        let fence = ScopeFence::build(std::slice::from_ref(&root));
        assert!(!fence.allows_path(&scheduled));
        // The envelope engages: the spelling pins through the middle link.
        assert!(matches!(
            fence.open_relationship_pinned(&scheduled).expect("pin"),
            FenceOpen::Dir(_)
        ));

        let db = tmp.path().join("probe.db");
        let store = TursoStore::open(&db).await.expect("open");
        let generation = store
            .create_generation("roots", "running", None, now_ms())
            .await
            .expect("generation");
        let run_rev = store.current_revision().await.expect("revision");
        let outcome = main_under_test::test_probe_fenced_outcome(
            &store,
            std::slice::from_ref(&root),
            generation,
            run_rev,
            "https://github.com/owner/repo",
            &scheduled,
            None,
        )
        .await
        .expect("probe");
        assert!(
            matches!(outcome, TaskOutcome::Complete),
            "relationship probe must complete, got {outcome:?}"
        );
        let id = format!(
            "git:{}",
            config::encode_hex(&config::path_as_bytes(&scheduled.join(".git")))
        );
        assert!(
            store.get_git_instance(&id).await.expect("read").is_some(),
            "instance persists under the scheduling spelling"
        );
    });
}

/// XSEC-02: the fallback refuses to spawn when the probed binary is
/// replaced or re-permissioned — identity is bound at probe time, and a
/// fresh probe re-binds the new binary.
#[cfg(unix)]
#[test]
fn fallback_refuses_swapped_binary() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let git = tmp.path().join("git");
    write_git_fixture(
        &git,
        "git version 2.47.1",
        "echo \"v1-output --porcelain\"\nexit 0",
    );
    let parent = tmp.path().join("repos");
    repo_scan::privacy::private_dir_0700(&parent).unwrap();
    let repo = fixture::normal_clone(&parent, "r");
    let git_dir = repo.join(".git");

    let h1 = FallbackGit::probe(&git).expect("probe v1");
    assert!(
        h1.refs(&git_dir, Some(&repo)).is_ok(),
        "baseline spawn works"
    );

    // Replace the binary (new inode, same spelling).
    std::fs::remove_file(&git).unwrap();
    write_git_fixture(
        &git,
        "git version 9.9.9",
        "echo \"v2-output --porcelain\"\nexit 0",
    );
    let err = h1
        .refs(&git_dir, Some(&repo))
        .expect_err("swapped binary must be refused");
    assert!(err.to_string().contains("identity changed"), "{err}");

    // A fresh probe binds the new binary and works again.
    let h2 = FallbackGit::probe(&git).expect("probe v2");
    assert!(h2.refs(&git_dir, Some(&repo)).is_ok());

    // Re-permissioning the binary also breaks the binding.
    let mut perms = std::fs::metadata(&git).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&git, perms).unwrap();
    let err = h2
        .refs(&git_dir, Some(&repo))
        .expect_err("de-executable binary must be refused");
    assert!(err.to_string().contains("identity changed"), "{err}");
}

/// XSEC-03: installed-git spawns carry only allowlisted `GIT_*`
/// variables — ambient helper overrides never reach the child, while
/// caller-set safe values still flow.
#[cfg(unix)]
#[test]
fn git_spawns_strip_nonallowlisted_env() {
    struct EnvGuard {
        saved: Vec<(String, Option<std::ffi::OsString>)>,
    }
    impl EnvGuard {
        fn set(vars: &[(&str, &str)]) -> Self {
            let mut saved = Vec::new();
            for (key, value) in vars {
                saved.push((key.to_string(), std::env::var_os(key)));
                std::env::set_var(key, value);
            }
            Self { saved }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..) {
                match value {
                    Some(value) => std::env::set_var(&key, value),
                    None => std::env::remove_var(&key),
                }
            }
        }
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let log = tmp.path().join("env.log");
    let git = tmp.path().join("git");
    let script = format!(
        "#!/bin/sh\nenv >> \"{}\"\necho \"---\" >> \"{}\"\nif [ \"$1\" = \"--version\" ]; then\necho \"git version 2.47.1\"\nexit 0\nfi\necho \" --porcelain[<version>]  machine-readable output\"\nexit 0\n",
        log.display(),
        log.display()
    );
    repo_scan::privacy::private_write_0600(&git, script.as_bytes()).unwrap();
    make_executable(&git);

    // Inert for every other test's fixture flows (no ssh/editor/diff).
    let guard = EnvGuard::set(&[
        ("GIT_SSH_COMMAND", "evil-ssh-command"),
        ("GIT_EDITOR", "evil-editor"),
        ("GIT_EXTERNAL_DIFF", "evil-diff"),
        ("GIT_SEQUENCE_EDITOR", "evil-seq-editor"),
    ]);
    let found = FallbackGit::probe(&git).expect("probe");
    assert!(found.capabilities().feature_probe_ok);
    drop(guard);

    let logged = std::fs::read_to_string(&log).expect("log");
    for evil in [
        "evil-ssh-command",
        "evil-editor",
        "evil-diff",
        "evil-seq-editor",
    ] {
        assert!(!logged.contains(evil), "ambient {evil} must not reach git");
    }
    assert!(
        logged.contains("LC_ALL=C"),
        "caller-set LC_ALL flows:\n{logged}"
    );
    assert!(
        logged.contains("GIT_PAGER=cat"),
        "allowlisted GIT_PAGER flows:\n{logged}"
    );
}

/// PG-01: probe tasks carry the schedule-time `(dev, ino)` + provenance
/// token in the task id; execution compares the pre-run pin against the
/// carried identity instead of inferring the relationship from the
/// spelling. A directory replaced at the same spelling between scheduling
/// and execution parks with a schedule-identity refusal and persists
/// nothing.
#[cfg(unix)]
#[test]
fn pg01_probe_carries_schedule_identity() {
    use repo_scan::model::TaskState;

    // Suffix shape: identity + provenance parse; legacy/other ids do not.
    let rel =
        main_under_test::parse_probe_schedule("probe:7:ab12:s5x6:rel").expect("rel suffix parses");
    assert_eq!(rel.identity, Some((5, 6)));
    assert_eq!(
        rel.provenance,
        main_under_test::ProbeProvenance::Relationship
    );
    let with_rev = main_under_test::parse_probe_schedule("probe:7:ab12:r3:s1x2:enum")
        .expect("reconcile suffix still parses");
    assert_eq!(with_rev.identity, Some((1, 2)));
    assert_eq!(with_rev.provenance, main_under_test::ProbeProvenance::Enum);
    assert!(
        main_under_test::parse_probe_schedule("probe:7:ab12:s0x0:rel")
            .expect("unknown identity parses")
            .identity
            .is_none(),
        "(0, 0) decodes to unknown identity"
    );
    for legacy in [
        "probe:7:ab12",
        "probe:7:ab12:r3",
        "status:co:ab12:3",
        "enum:7:path:ab12",
        "probe:7:ab12:s5x6:bogus",
    ] {
        assert!(
            main_under_test::parse_probe_schedule(legacy).is_none(),
            "legacy id must not parse a schedule: {legacy}"
        );
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let victim = fixture::normal_clone(&root, "victim");
        let db = tmp.path().join("probe.db");
        let store = TursoStore::open(&db).await.expect("open");
        let generation = store
            .create_generation("roots", "running", None, now_ms())
            .await
            .expect("generation");
        let run_rev = store.current_revision().await.expect("revision");
        // Replace the scheduled directory with a FRESH directory at the
        // same spelling (new inode; the original is only renamed aside, so
        // the inode cannot alias): the pre-run pin no longer matches the
        // schedule-time identity.
        let swap_victim = victim.clone();
        let stash = tmp.path().join("victim-orig");
        let outcome = main_under_test::test_probe_fenced_outcome(
            &store,
            std::slice::from_ref(&root),
            generation,
            run_rev,
            "https://github.com/owner/repo",
            &victim,
            Some(Box::new(move || {
                std::fs::rename(&swap_victim, &stash).unwrap();
                std::fs::create_dir(&swap_victim).unwrap();
            })),
        )
        .await
        .expect("probe");
        match outcome {
            TaskOutcome::Parked { state, reason } => {
                assert!(matches!(state, TaskState::Unavailable), "{state:?}");
                assert!(reason.contains("schedule-time identity"), "{reason}");
            }
            other => panic!("swapped probe must park, got {other:?}"),
        }
        // Nothing persisted under the scheduling spelling.
        let id = format!(
            "git:{}",
            config::encode_hex(&config::path_as_bytes(&victim.join(".git")))
        );
        assert!(
            store.get_git_instance(&id).await.expect("read").is_none(),
            "swapped probe must persist nothing"
        );
    });
}

/// PG-03: enumeration fails CLOSED where descriptors cannot pin — the
/// fence-error mapping refuses `Unsupported` as `Unsupported` (never the
/// legacy unfenced pathname open), and off-unix the run-loop enum parks
/// `Unsupported` instead of listing.
#[test]
fn pg03_enum_unsupported_fails_closed() {
    assert!(
        main_under_test::test_enum_unsupported_is_refused(),
        "Unsupported must map to a Refused/Unsupported enum outcome"
    );
    #[cfg(not(unix))]
    {
        use repo_scan::model::TaskState;
        use repo_scan::store::{now_ms, Store, TaskOutcome, TursoStore};

        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let db = tmp.path().join("enum.db");
            let store = TursoStore::open(&db).await.expect("open");
            let generation = store
                .create_generation("roots", "running", None, now_ms())
                .await
                .expect("generation");
            let outcome = main_under_test::test_enum_fenced_outcome(
                &store,
                std::slice::from_ref(&root),
                generation,
                &root,
            )
            .await
            .expect("enum");
            match outcome {
                TaskOutcome::Parked { state, reason } => {
                    assert!(matches!(state, TaskState::Unsupported), "{state:?}");
                    assert!(reason.contains("refusing unfenced"), "{reason}");
                }
                other => panic!("unsupported enum must park, got {other:?}"),
            }
        });
    }
}

/// XSEC-01: identity is re-verified DURING Git inspection — a directory
/// swapped for a different valid repo between read stages discards every
/// observation (reads precede all writes) and parks instead of persisting
/// the swapped-in identity's rows.
#[cfg(unix)]
#[test]
fn xsec01_mid_inspection_swap_discards() {
    use repo_scan::model::TaskState;

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let scheduled = fixture::normal_clone(&root, "scheduled");
        let donor = fixture::normal_clone(&root, "donor");
        let db = tmp.path().join("probe.db");
        let store = TursoStore::open(&db).await.expect("open");
        let generation = store
            .create_generation("roots", "running", None, now_ms())
            .await
            .expect("generation");
        let run_rev = store.current_revision().await.expect("revision");
        // Mid-inspection swap, consumed between Git read stages: same
        // spelling, different valid repo (both survive, so the inode
        // cannot alias and every post-swap read would succeed).
        let swap_scheduled = scheduled.clone();
        let swap_donor = donor.clone();
        let swap_stash = tmp.path().join("scheduled-orig");
        main_under_test::test_set_mid_inspection_hook(move || {
            std::fs::rename(&swap_scheduled, &swap_stash).unwrap();
            std::fs::rename(&swap_donor, &swap_scheduled).unwrap();
        });
        let outcome = main_under_test::test_probe_fenced_outcome(
            &store,
            std::slice::from_ref(&root),
            generation,
            run_rev,
            "https://github.com/owner/repo",
            &scheduled,
            None,
        )
        .await
        .expect("probe");
        match outcome {
            TaskOutcome::Parked { state, reason } => {
                assert!(matches!(state, TaskState::Unavailable), "{state:?}");
                assert!(reason.contains("changed during inspection"), "{reason}");
            }
            other => panic!("mid-inspection swap must park, got {other:?}"),
        }
        // Two-phase discard: neither the original's nor the swapped-in
        // repo's observations reached the catalog under this spelling.
        let id = format!(
            "git:{}",
            config::encode_hex(&config::path_as_bytes(&scheduled.join(".git")))
        );
        assert!(
            store.get_git_instance(&id).await.expect("read").is_none(),
            "mid-inspection swap must persist nothing"
        );
    });
}

/// SR-STATE-05 (includes): gix opens with include following disabled, so
/// a remote defined only in an included file is invisible — and the
/// include-bearing repo is flagged by the bounded pre-scan gap instead of
/// silently observed unexpanded.
#[cfg(unix)]
#[test]
fn includes_disabled_with_explicit_gap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let parent = tmp.path().join("repos");
    repo_scan::privacy::private_dir_0700(&parent).unwrap();
    let repo = fixture::normal_clone(&parent, "incl");
    let extra = parent.join("extra.conf");
    repo_scan::privacy::private_write_0600(
        &extra,
        "[remote \"smuggled\"]\n\turl = https://github.com/evil/smuggled\n".as_bytes(),
    )
    .unwrap();
    let config_path = repo.join(".git/config");
    let mut text = std::fs::read_to_string(&config_path).unwrap();
    text.push_str(&format!("\n[include]\n\tpath = {}\n", extra.display()));
    repo_scan::privacy::private_write_0600(&config_path, text.as_bytes()).unwrap();

    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&repo).expect("open with include");
    let remotes = inspector.remotes(&instance).expect("remotes");
    assert!(
        remotes.iter().all(|r| r.name != b"smuggled"),
        "included remote must not leak: {remotes:?}"
    );
    assert!(
        remotes.iter().any(|r| r.name == b"origin"),
        "local remote still seen: {remotes:?}"
    );
    let gap = config_include_gap(&instance).expect("gap must flag includes");
    assert!(gap.starts_with(CONFIG_INCLUDE_GAP), "{gap}");

    let plain = fixture::normal_clone(&parent, "plain");
    let plain_instance = inspector.open_exact(&plain).expect("open plain");
    assert!(config_include_gap(&plain_instance).is_none());
}

/// SR-STATE-05 (ssh): the SSH-alias read is regular-only, no-follow, and
/// entry-capped — symlinks, FIFOs, and device files yield an empty map
/// without hanging, and alias retention stops at the cap.
#[cfg(unix)]
#[test]
fn ssh_config_read_is_bounded() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let good = tmp.path().join("config");
    repo_scan::privacy::private_write_0600(&good, "Host gh\n  HostName github.com\n".as_bytes())
        .unwrap();
    assert_eq!(
        load_ssh_aliases_from(&good).get("gh").map(String::as_str),
        Some("github.com")
    );
    assert!(load_ssh_aliases_from(&tmp.path().join("missing")).is_empty());

    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&good, &link).unwrap();
    assert!(load_ssh_aliases_from(&link).is_empty(), "symlink refused");

    let fifo = tmp.path().join("fifo");
    {
        use std::os::unix::ffi::OsStrExt;
        let c_fifo = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
    }
    assert!(
        load_ssh_aliases_from(&fifo).is_empty(),
        "fifo refused without blocking"
    );
    assert!(
        load_ssh_aliases_from(Path::new("/dev/zero")).is_empty(),
        "device refused without hanging"
    );

    // Entry cap, built programmatically (no big fixture on disk).
    let mut text = String::new();
    for i in 0..(MAX_SSH_CONFIG_ALIASES + 25) {
        text.push_str(&format!("Host a{i}\n  HostName h{i}.test\n"));
    }
    let map = parse_ssh_config(&text);
    assert_eq!(map.len(), MAX_SSH_CONFIG_ALIASES);
    assert!(map.contains_key("a0"), "first-wins order kept");
    assert!(
        !map.contains_key(&format!("a{}", MAX_SSH_CONFIG_ALIASES + 24)),
        "past-cap aliases ignored"
    );
}

/// PG-01: the schedule-time provenance token round-trips identity plus
/// the scheduling spelling, fails matches on swapped identity, and
/// rejects malformed tokens.
#[cfg(unix)]
#[test]
fn schedule_provenance_token_roundtrip() {
    let id = PhysicalDirId {
        dev: 7,
        ino: 42,
        namespace: "mnt:x".to_string(),
    };
    let path = Path::new("/tmp/roots/a b/repo");
    let tok = ScheduleProvenance::mint(&id, path);
    assert!(tok.matches(&id));
    assert!(!tok.matches(&PhysicalDirId {
        dev: 7,
        ino: 43,
        namespace: "mnt:x".to_string(),
    }));
    assert_eq!(tok.identity(), id);

    let rendered = tok.render();
    let back = ScheduleProvenance::parse(&rendered).expect("roundtrip");
    assert_eq!(back, tok);
    assert_eq!(back.path, path);

    // Tampered identity still parses but no longer matches the schedule.
    let tampered = rendered.replacen("rs1:7:42:", "rs1:7:43:", 1);
    let parsed = ScheduleProvenance::parse(&tampered).expect("shape valid");
    assert!(!parsed.matches(&id));

    for bad in [
        "",
        "rs1:",
        "rs1:7:42",
        "xx:7:42:5:mnt:x:",
        "rs1:x:42:5:mnt:x:",
        "rs1:7:42:99:mnt:x:",
        "rs1:7:42:5:mnt:x:zz",
    ] {
        assert!(ScheduleProvenance::parse(bad).is_none(), "{bad:?}");
    }
}
