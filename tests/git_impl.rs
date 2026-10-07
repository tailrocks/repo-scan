//! Git inspection + URL identity acceptance tests (spec §§8–9, GIT-01..04).
//!
//! Fixtures are built with the installed git binary (via `tempfile`
//! scratch dirs, hermetic `HOME`/config env). Git-dependent tests skip
//! quietly when no git binary is discoverable; the identity tables are
//! pure and always run.

use repo_scan::git::fallback::FallbackGit;
use repo_scan::git::{
    working_state_of, CandidateKind, CheckoutKind, GitInspect, GixInspector, HeadState,
    StatusObservation, WorktreeAvailability,
};
use repo_scan::identity::{
    classify_remote, classify_remotes, github_host_matches, is_github_host, normalize_github_url,
    parse_ssh_config, redact_credentials, MatchDisposition,
};
use repo_scan::model::StatusMode;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate an installed git or skip the calling test.
fn git_or_skip() -> Option<PathBuf> {
    FallbackGit::discover(&[]).map(|found| found.path().to_path_buf())
}

/// Run git with a hermetic environment (scratch HOME, no system/global config).
fn git(git_bin: &Path, home: &Path, workdir: &Path, args: &[&str]) {
    let status = Command::new(git_bin)
        .args(args)
        .current_dir(workdir)
        .env("HOME", home)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .status()
        .expect("spawn git");
    assert!(
        status.success(),
        "git {args:?} failed in {}",
        workdir.display()
    );
}

/// Identity flags shared by every repo-creating command.
const ID: &[&str] = &[
    "-c",
    "user.name=test",
    "-c",
    "user.email=test@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "init.defaultBranch=main",
];

/// `git init` + one commit; returns the workdir path.
fn init_with_commit(git_bin: &Path, dir: &Path) -> PathBuf {
    let home = dir.join("home");
    repo_scan::privacy::private_dir_0700(&home).expect("home");
    let work = dir.join("work");
    repo_scan::privacy::private_dir_0700(&work).expect("work");
    let mut args = ID.to_vec();
    args.push("init");
    git(git_bin, &home, &work, &args);
    repo_scan::privacy::private_write_0600(&work.join("file.txt"), "hello\n".as_bytes())
        .expect("seed file");
    let mut args = ID.to_vec();
    args.extend(["add", "file.txt"]);
    git(git_bin, &home, &work, &args);
    let mut args = ID.to_vec();
    args.extend(["commit", "-m", "initial"]);
    git(git_bin, &home, &work, &args);
    work
}

#[test]
fn normal_checkout_opens_with_branch_head() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let work = init_with_commit(&git_bin, scratch.path());
    let inspector = GixInspector::new();

    let validated = inspector.validate(&work).expect("validate checkout");
    assert_eq!(validated.kind, CandidateKind::WorktreeCheckout);
    assert!(validated.continue_below_boundary);
    assert!(!validated.instance.is_bare);
    assert_eq!(validated.instance.object_format, "sha1");
    assert!(validated.instance.work_dir.is_some());

    match inspector.head(&validated.instance).expect("head") {
        HeadState::Branch { ref_name, oid } => {
            assert_eq!(ref_name, b"refs/heads/main");
            let oid = oid.expect("born branch has oid");
            assert_eq!(oid.algorithm, "sha1");
            assert_eq!(oid.hex.len(), 40);
        }
        other => panic!("expected branch head, got {other:?}"),
    }
    let refs = inspector.refs(&validated.instance).expect("refs");
    assert!(refs.iter().any(|r| r.name == b"refs/heads/main"));
    assert!(inspector.reference_errors(&validated.instance).is_empty());
    // One-pass twin agrees with the split pair on a healthy store.
    let (refs2, errors2) = inspector
        .refs_with_errors(&validated.instance)
        .expect("refs_with_errors");
    assert_eq!(refs.len(), refs2.len());
    assert!(errors2.is_empty());
    assert_eq!(
        inspector.checkout_kind(&validated.instance).expect("kind"),
        CheckoutKind::Main
    );
    assert!(inspector
        .worktrees(&validated.instance)
        .expect("worktrees")
        .is_empty());
}

/// GIT-m3: a garbage loose ref is preserved as a per-item error while
/// its valid siblings still observe — and the one-pass
/// `refs_with_errors` agrees exactly with the `refs` /
/// `reference_errors` pair (single traversal, no skew between them).
#[test]
fn broken_loose_ref_preserved_as_error_with_valid_siblings() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let work = init_with_commit(&git_bin, scratch.path());
    repo_scan::privacy::private_write_0600(
        &work.join(".git").join("refs").join("heads").join("broken"),
        b"not-an-oid\n",
    )
    .expect("plant broken ref");
    let inspector = GixInspector::new();
    let validated = inspector.validate(&work).expect("validate checkout");

    let (refs, errors) = inspector
        .refs_with_errors(&validated.instance)
        .expect("refs_with_errors");
    assert!(
        refs.iter().any(|r| r.name == b"refs/heads/main"),
        "valid siblings still observe"
    );
    assert!(
        !errors.is_empty(),
        "broken ref preserved as an error, never skipped silently"
    );
    assert!(
        errors.iter().all(|e| e.contains("invalid ref")),
        "error channel shape: {errors:?}"
    );
    // Split-pair agreement: identical observations, identical errors.
    let split_refs = inspector.refs(&validated.instance).expect("refs");
    assert_eq!(split_refs.len(), refs.len());
    assert_eq!(inspector.reference_errors(&validated.instance), errors);
}

#[test]
fn bare_store_with_arbitrary_name_opens() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let home = scratch.path().join("home");
    repo_scan::privacy::private_dir_0700(&home).expect("home");
    let store = scratch.path().join("odd-store-name");
    repo_scan::privacy::private_dir_0700(&store).expect("store");
    let mut args = ID.to_vec();
    args.extend(["init", "--bare"]);
    git(&git_bin, &home, &store, &args);

    let inspector = GixInspector::new();
    let validated = inspector.validate(&store).expect("validate bare");
    assert_eq!(validated.kind, CandidateKind::BareStore);
    assert!(validated.instance.is_bare);
    assert!(validated.instance.work_dir.is_none());

    let meta = inspector
        .status(&validated.instance, StatusMode::Metadata)
        .expect("metadata status");
    assert_eq!(meta.staged, None);
    assert_eq!(meta.unstaged, None);
    assert_eq!(meta.untracked, None);

    let summary = inspector
        .status(&validated.instance, StatusMode::Summary)
        .expect("summary status");
    assert_eq!(summary.staged, None, "bare status stays unknown, not zero");
    assert!(summary
        .unknown_fields
        .iter()
        .any(|f| f.contains("no-worktree")));
}

#[test]
fn linked_worktree_is_followed_with_availability() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let home = scratch.path().join("home");
    let work = init_with_commit(&git_bin, scratch.path());
    let linked = scratch.path().join("linked");
    let path_str = linked.to_string_lossy().into_owned();
    let mut owned: Vec<String> = ID.iter().map(|s| s.to_string()).collect();
    owned.extend(
        ["worktree", "add", "-b", "wt-branch"]
            .iter()
            .map(|s| s.to_string()),
    );
    owned.push(path_str);
    let arg_refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    git(&git_bin, &home, &work, &arg_refs);

    let inspector = GixInspector::new();
    let main = inspector.validate(&work).expect("validate main");
    assert!(main
        .evidence
        .iter()
        .any(|e| e.contains("registered linked worktrees: 1")));

    let trees = inspector.worktrees(&main.instance).expect("worktrees");
    assert_eq!(trees.len(), 1);
    assert_eq!(trees[0].availability, WorktreeAvailability::Present);
    // git records the physical path (macOS: /var -> /private/var), so compare
    // canonical forms; both exist (the worktree was just created).
    assert_eq!(
        trees[0].base.canonicalize().expect("base exists"),
        linked.canonicalize().expect("linked exists")
    );

    let linked_validated = inspector.validate(&linked).expect("validate linked");
    assert_eq!(linked_validated.kind, CandidateKind::LinkedWorktree);
    assert_eq!(
        inspector
            .checkout_kind(&linked_validated.instance)
            .expect("kind"),
        CheckoutKind::Linked
    );
}

#[test]
fn detached_head_observed() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let home = scratch.path().join("home");
    let work = init_with_commit(&git_bin, scratch.path());
    let mut args = ID.to_vec();
    args.extend(["checkout", "--detach", "HEAD"]);
    git(&git_bin, &home, &work, &args);

    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&work).expect("open detached");
    match inspector.head(&instance).expect("head") {
        HeadState::Detached { target, .. } => {
            assert_eq!(target.algorithm, "sha1");
            assert_eq!(target.hex.len(), 40);
        }
        other => panic!("expected detached head, got {other:?}"),
    }
}

#[test]
fn unborn_head_observed() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let home = scratch.path().join("home");
    repo_scan::privacy::private_dir_0700(&home).expect("home");
    let work = scratch.path().join("empty");
    repo_scan::privacy::private_dir_0700(&work).expect("work");
    let mut args = ID.to_vec();
    args.push("init");
    git(&git_bin, &home, &work, &args);

    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&work).expect("open unborn");
    match inspector.head(&instance).expect("head") {
        HeadState::Unborn { ref_name } => assert_eq!(ref_name, b"refs/heads/main"),
        other => panic!("expected unborn head, got {other:?}"),
    }
}

#[test]
fn packed_refs_are_enumerated() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let home = scratch.path().join("home");
    let work = init_with_commit(&git_bin, scratch.path());
    let mut args = ID.to_vec();
    args.extend(["branch", "second"]);
    git(&git_bin, &home, &work, &args);
    git(&git_bin, &home, &work, &["pack-refs", "--all"]);
    // Force packed-only storage so loose-file assumptions would fail.
    for entry in std::fs::read_dir(work.join(".git").join("refs").join("heads"))
        .expect("heads dir")
        .flatten()
    {
        if entry.path().is_file() {
            std::fs::remove_file(entry.path()).expect("prune loose ref");
        }
    }
    assert!(work.join(".git").join("packed-refs").is_file());

    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&work).expect("open packed");
    let refs = inspector.refs(&instance).expect("refs");
    assert!(refs.iter().any(|r| r.name == b"refs/heads/main"));
    assert!(refs.iter().any(|r| r.name == b"refs/heads/second"));
}

#[test]
fn status_counts_match_git_semantics() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let home = scratch.path().join("home");
    let work = init_with_commit(&git_bin, scratch.path());
    // One unstaged modification, one staged addition, one untracked dir
    // holding two files (collapsed to one entry in summary mode).
    repo_scan::privacy::private_write_0600(&work.join("file.txt"), "changed\n".as_bytes())
        .expect("modify");
    repo_scan::privacy::private_write_0600(&work.join("staged.txt"), "new\n".as_bytes())
        .expect("staged");
    let mut args = ID.to_vec();
    args.extend(["add", "staged.txt"]);
    git(&git_bin, &home, &work, &args);
    let newdir = work.join("newdir");
    repo_scan::privacy::private_dir_0700(&newdir).expect("newdir");
    repo_scan::privacy::private_write_0600(&newdir.join("a.txt"), "a\n".as_bytes()).expect("a");
    repo_scan::privacy::private_write_0600(&newdir.join("b.txt"), "b\n".as_bytes()).expect("b");
    // Ignored files are never counted (summary) nor listed (full).
    repo_scan::privacy::private_write_0600(&work.join(".gitignore"), "ignored.txt\n".as_bytes())
        .expect("gitignore");
    repo_scan::privacy::private_write_0600(&work.join("ignored.txt"), "x\n".as_bytes())
        .expect("ignored");

    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&work).expect("open");
    let summary = inspector
        .status(&instance, StatusMode::Summary)
        .expect("summary");
    assert_eq!(summary.staged, Some(1));
    assert_eq!(summary.unstaged, Some(1));
    assert_eq!(
        summary.untracked,
        Some(2),
        "newdir + .gitignore, ignored.txt excluded"
    );
    assert!(!summary.fingerprints.is_empty());

    let full = inspector.status(&instance, StatusMode::Full).expect("full");
    assert_eq!(full.staged, Some(1));
    assert_eq!(full.unstaged, Some(1));
    assert_eq!(
        full.untracked,
        Some(3),
        "a.txt + b.txt + .gitignore, ignored.txt excluded"
    );
}

/// One working-state expectation: staged/unstaged/untracked/conflicts
/// counts, unknown-field markers, and the expected state word.
type WorkingStateCase<'a> = (
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    &'a [&'a str],
    &'a str,
);

#[test]
fn working_state_vocabulary_table() {
    let cases: &[WorkingStateCase<'_>] = &[
        (Some(0), Some(0), Some(0), Some(0), &[], "clean"),
        (Some(1), Some(0), Some(0), Some(0), &[], "dirty"),
        (Some(0), Some(2), Some(0), Some(0), &[], "dirty"),
        (Some(0), Some(0), Some(3), Some(0), &[], "dirty"),
        // Conflict-only: conflicts never read as dirty or clean.
        (Some(0), Some(0), Some(0), Some(1), &[], "conflicted"),
        (Some(1), Some(1), Some(1), Some(2), &[], "conflicted"),
        // Metadata mode (all null) is unknown, never clean.
        (None, None, None, None, &[], "unknown"),
        (Some(0), Some(0), Some(0), None, &[], "unknown"),
        // Observation markers beat counts (except definite conflicts).
        (
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            &["unstable: HEAD/index changed during the probe"],
            "unstable",
        ),
        (
            Some(1),
            Some(0),
            Some(0),
            Some(0),
            &["unstable: HEAD/index changed during the probe"],
            "unstable",
        ),
        (
            None,
            None,
            None,
            None,
            &["no-worktree: bare or worktree-less repository; status not applicable"],
            "not_applicable",
        ),
        (
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            &["truncated: item cap reached; counts are partial"],
            "partial",
        ),
        // Definite conflicts win even over markers.
        (
            Some(0),
            Some(0),
            Some(0),
            Some(1),
            &["unstable: HEAD/index changed during the probe"],
            "conflicted",
        ),
    ];
    for (staged, unstaged, untracked, conflicts, markers, expected) in cases {
        let obs = StatusObservation {
            mode: StatusMode::Summary,
            staged: *staged,
            unstaged: *unstaged,
            untracked: *untracked,
            conflicts: *conflicts,
            unknown_fields: markers.iter().map(|s| s.to_string()).collect(),
            fingerprints: Vec::new(),
        };
        assert_eq!(
            working_state_of(&obs),
            *expected,
            "staged={staged:?} unstaged={unstaged:?} untracked={untracked:?} \
             conflicts={conflicts:?} markers={markers:?}"
        );
    }
}

#[test]
fn conflict_counts_match_git_reference() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let home = scratch.path().join("home");
    let work = init_with_commit(&git_bin, scratch.path());
    // Clean baseline first: zero conflicts on both backends.
    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&work).expect("open");
    let baseline = inspector
        .status(&instance, StatusMode::Summary)
        .expect("baseline");
    assert_eq!(baseline.conflicts, Some(0));
    assert_eq!(working_state_of(&baseline), "clean");

    // Two files conflict between main and side (3 index stages each).
    for name in ["file.txt", "file2.txt"] {
        repo_scan::privacy::private_write_0600(&work.join(name), "base\n".as_bytes())
            .expect("base");
    }
    let mut args = ID.to_vec();
    args.extend(["add", "file.txt", "file2.txt"]);
    git(&git_bin, &home, &work, &args);
    let mut args = ID.to_vec();
    args.extend(["commit", "-m", "base files"]);
    git(&git_bin, &home, &work, &args);
    let mut args = ID.to_vec();
    args.extend(["checkout", "-b", "side"]);
    git(&git_bin, &home, &work, &args);
    for name in ["file.txt", "file2.txt"] {
        repo_scan::privacy::private_write_0600(&work.join(name), "side\n".as_bytes())
            .expect("side");
    }
    let mut args = ID.to_vec();
    args.extend(["commit", "-am", "side files"]);
    git(&git_bin, &home, &work, &args);
    let mut args = ID.to_vec();
    args.extend(["checkout", "main"]);
    git(&git_bin, &home, &work, &args);
    for name in ["file.txt", "file2.txt"] {
        repo_scan::privacy::private_write_0600(&work.join(name), "main\n".as_bytes())
            .expect("main");
    }
    let mut args = ID.to_vec();
    args.extend(["commit", "-am", "main files"]);
    git(&git_bin, &home, &work, &args);
    // The merge MUST fail with conflicts; the `git()` helper asserts
    // success, so this one spawn repeats its hermetic env inline.
    let mut cmd = Command::new(&git_bin);
    cmd.args(ID)
        .args(["merge", "side"])
        .current_dir(&work)
        .env("HOME", &home)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
    let merge = cmd.output().expect("spawn git merge");
    assert!(!merge.status.success(), "merge must conflict");

    // Independent reference: installed git sees 6 unmerged stage
    // entries (3 stages x 2 files) and two porcelain-v2 `u` lines.
    let mut args = ID.to_vec();
    args.extend(["ls-files", "-u"]);
    let unmerged = Command::new(&git_bin)
        .args(&args)
        .current_dir(&work)
        .env("HOME", &home)
        .output()
        .expect("ls-files")
        .stdout;
    assert_eq!(String::from_utf8_lossy(&unmerged).lines().count(), 6);

    // gix backend: 6 stage entries collapse to 2 conflicted paths,
    // excluded from staged/unstaged tallies (count separation).
    let instance = inspector.open_exact(&work).expect("reopen");
    let summary = inspector
        .status(&instance, StatusMode::Summary)
        .expect("summary");
    assert_eq!(summary.staged, Some(0));
    assert_eq!(summary.unstaged, Some(0));
    assert_eq!(summary.untracked, Some(0));
    assert_eq!(summary.conflicts, Some(2));
    assert_eq!(working_state_of(&summary), "conflicted");

    // Installed-git backend: the two `u` lines count as conflicts
    // only — never staged/unstaged.
    let fallback = FallbackGit::probe(&git_bin).expect("probe explicit git");
    let (staged, unstaged, untracked, conflicts) = fallback
        .status_counts(&work.join(".git"), Some(&work), true)
        .expect("fallback status");
    assert_eq!((staged, unstaged, untracked, conflicts), (0, 0, 0, 2));
    let obs = StatusObservation {
        mode: StatusMode::Summary,
        staged: Some(staged),
        unstaged: Some(unstaged),
        untracked: Some(untracked),
        conflicts: Some(conflicts),
        unknown_fields: Vec::new(),
        fingerprints: Vec::new(),
    };
    assert_eq!(working_state_of(&obs), "conflicted");
}

#[test]
fn invalid_candidate_rejected() {
    let scratch = tempfile::tempdir().expect("scratch");
    let inspector = GixInspector::new();
    assert!(inspector.open_exact(scratch.path()).is_err());
}

#[test]
fn remotes_observed_with_roles_and_canonical_urls() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let home = scratch.path().join("home");
    let work = init_with_commit(&git_bin, scratch.path());
    git(
        &git_bin,
        &home,
        &work,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/OWNER/REPO.git",
        ],
    );

    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&work).expect("open");
    let remotes = inspector
        .remotes(&instance, &repo_scan::identity::load_ssh_aliases())
        .expect("remotes");
    assert_eq!(remotes.len(), 2, "fetch + push roles");
    for remote in &remotes {
        assert_eq!(remote.name, b"origin");
        assert_eq!(remote.url, "https://github.com/OWNER/REPO.git");
        assert_eq!(
            remote.canonical_url.as_deref(),
            Some("https://github.com/owner/repo")
        );
    }
    let pairs: Vec<(&str, &str)> = remotes
        .iter()
        .map(|r| {
            (
                r.url.as_str(),
                match r.role {
                    repo_scan::git::RemoteRole::Fetch => "fetch",
                    repo_scan::git::RemoteRole::Push => "push",
                },
            )
        })
        .collect();
    let (disposition, _) = classify_remotes("https://github.com/owner/repo", pairs);
    assert_eq!(disposition, MatchDisposition::Confirmed);

    let deps = inspector.config_dependencies(&instance);
    assert!(deps.iter().any(|d| d.exists && !d.via_include));
}

#[test]
fn insteadof_rewrite_applied_without_helpers() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let home = scratch.path().join("home");
    let work = init_with_commit(&git_bin, scratch.path());
    git(
        &git_bin,
        &home,
        &work,
        &["config", "url.https://github.com/.insteadOf", "gh:"],
    );
    git(
        &git_bin,
        &home,
        &work,
        &["remote", "add", "origin", "gh:OWNER/REPO.git"],
    );

    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&work).expect("open");
    let remotes = inspector
        .remotes(&instance, &repo_scan::identity::load_ssh_aliases())
        .expect("remotes");
    assert!(
        remotes
            .iter()
            .any(|r| r.canonical_url.as_deref() == Some("https://github.com/owner/repo")),
        "insteadOf rewrite must produce the effective GitHub URL: {remotes:?}"
    );
}

#[test]
fn fallback_probes_and_reads_refs() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let work = init_with_commit(&git_bin, scratch.path());
    let fallback = FallbackGit::probe(&git_bin).expect("probe explicit git");
    assert!(fallback.capabilities().version.starts_with("git version "));

    let git_dir = work.join(".git");
    let refs = fallback.refs(&git_dir, Some(&work)).expect("fallback refs");
    assert!(refs.iter().any(|r| r.name == b"refs/heads/main"));
    match fallback.head(&git_dir, Some(&work)).expect("fallback head") {
        HeadState::Branch { ref_name, .. } => assert_eq!(ref_name, b"refs/heads/main"),
        other => panic!("expected branch, got {other:?}"),
    }
    let (staged, unstaged, untracked, conflicts) = fallback
        .status_counts(&git_dir, Some(&work), true)
        .expect("fallback status");
    assert_eq!((staged, unstaged, untracked, conflicts), (0, 0, 0, 0));
}

#[test]
fn identity_url_variant_table() {
    const TARGET: &str = "https://github.com/owner/repo";
    // (raw remote, role, expected disposition, expected canonical or None)
    let cases: &[(&str, &str, MatchDisposition, Option<&str>)] = &[
        (
            "https://github.com/owner/repo",
            "fetch",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        (
            "https://github.com/OWNER/REPO.git",
            "fetch",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        (
            "https://github.com/owner/repo/",
            "push",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        (
            "https://user:secret@github.com/owner/repo.git",
            "fetch",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        (
            "https://token-only@github.com/owner/repo",
            "fetch",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        (
            "http://github.com/owner/repo",
            "fetch",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        (
            "git@github.com:owner/repo.git",
            "fetch",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        (
            "git@github.com:OWNER/REPO",
            "push",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        (
            "ssh://git@github.com/owner/repo.git",
            "fetch",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        (
            "ssh://git@github.com:22/owner/repo",
            "fetch",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        // Documented ssh.github.com:443 endpoint (Step 10).
        (
            "ssh://git@ssh.github.com:443/owner/repo.git",
            "fetch",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        (
            "ssh://git@ssh.github.com:443/OWNER/REPO",
            "push",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        // ssh.github.com any other way: no port, wrong scheme, wrong port.
        (
            "ssh://git@ssh.github.com/owner/repo",
            "fetch",
            MatchDisposition::Nonmatch,
            None,
        ),
        (
            "https://ssh.github.com:443/owner/repo",
            "fetch",
            MatchDisposition::Nonmatch,
            None,
        ),
        (
            "ssh://git@github.com:443/owner/repo",
            "fetch",
            MatchDisposition::Nonmatch,
            None,
        ),
        // HTTPS host with an alias-shaped name: aliases never apply to
        // http(s), so this is unresolvable, not a match (Step 10 case 8).
        (
            "https://gh-alias/owner/repo",
            "fetch",
            MatchDisposition::UnresolvableIdentity,
            None,
        ),
        (
            "https://GITHUB.COM/Owner/Repo",
            "fetch",
            MatchDisposition::Confirmed,
            Some(TARGET),
        ),
        (
            "https://github.com/other/repo",
            "fetch",
            MatchDisposition::Related,
            Some("https://github.com/other/repo"),
        ),
        (
            "git@github.com:fork/repo.git",
            "fetch",
            MatchDisposition::Related,
            Some("https://github.com/fork/repo"),
        ),
        (
            "https://github.com/owner/other",
            "fetch",
            MatchDisposition::Nonmatch,
            Some("https://github.com/owner/other"),
        ),
        (
            "https://github.com/owner/repo/tree/main",
            "fetch",
            MatchDisposition::Probable,
            None,
        ),
        (
            "https://gitlab.com/owner/repo.git",
            "fetch",
            MatchDisposition::Nonmatch,
            None,
        ),
        (
            "git@gitlab.com:owner/repo.git",
            "push",
            MatchDisposition::Nonmatch,
            None,
        ),
        (
            "https://github.com:8443/owner/repo",
            "fetch",
            MatchDisposition::Nonmatch,
            None,
        ),
        (
            "git://github.com/owner/repo.git",
            "fetch",
            MatchDisposition::Nonmatch,
            None,
        ),
        (
            "/srv/git/owner/repo.git",
            "fetch",
            MatchDisposition::UnresolvableIdentity,
            None,
        ),
        (
            "file:///srv/git/owner/repo.git",
            "fetch",
            MatchDisposition::UnresolvableIdentity,
            None,
        ),
        (
            "ext::ssh -i key git@github.com owner/repo",
            "fetch",
            MatchDisposition::UnresolvableIdentity,
            None,
        ),
        (
            "gh-alias:owner/repo.git",
            "fetch",
            MatchDisposition::UnresolvableIdentity,
            None,
        ),
        ("", "fetch", MatchDisposition::UnresolvableIdentity, None),
        (
            "not a url at all",
            "fetch",
            MatchDisposition::UnresolvableIdentity,
            None,
        ),
    ];
    for (raw, role, expected, canonical) in cases {
        assert_eq!(
            normalize_github_url(raw).as_deref(),
            *canonical,
            "canonical mismatch for {raw:?}"
        );
        let (disposition, evidence) = classify_remote(TARGET, raw, role);
        assert_eq!(disposition, *expected, "verdict mismatch for {raw:?}");
        assert!(!evidence.is_empty(), "evidence required for {raw:?}");
        for line in &evidence {
            assert!(
                !line.contains("secret") && !line.contains("token-only"),
                "credential leak in evidence: {line:?}"
            );
        }
    }
    // Aggregation: positive signals win; ambiguity beats lone mismatch.
    let (all_empty, _) = classify_remotes(TARGET, []);
    assert_eq!(all_empty, MatchDisposition::UnresolvableIdentity);
    let (mixed, _) = classify_remotes(
        TARGET,
        [
            ("https://gitlab.com/owner/repo.git", "fetch"),
            ("/srv/local.git", "push"),
        ],
    );
    assert_eq!(mixed, MatchDisposition::UnresolvableIdentity);
    let (all_bad, _) = classify_remotes(
        TARGET,
        [
            ("https://gitlab.com/owner/repo.git", "fetch"),
            ("git@gitlab.com:owner/repo.git", "push"),
        ],
    );
    assert_eq!(all_bad, MatchDisposition::Nonmatch);
}

#[test]
fn ssh_alias_scheme_gate() {
    // Literal matching is transport-independent and never reads config.
    assert!(is_github_host("github.com"));
    assert!(is_github_host("GITHUB.COM"));
    assert!(!is_github_host("gh-alias"));
    assert!(github_host_matches("github.com", false));
    assert!(github_host_matches("github.com", true));
    // Non-SSH transports never consult aliases: hermetic for ANY config.
    assert!(!github_host_matches("gh-alias", false));
    assert!(!github_host_matches("gitlab.com", false));
    // The single-label evidence message must not claim an alias lookup
    // ran on transports where aliases do not apply (Step 10 case 8).
    let (_, https_evidence) = classify_remote(
        "https://github.com/owner/repo",
        "https://gh-alias/owner/repo",
        "fetch",
    );
    assert!(!https_evidence.iter().any(|l| l.contains("SSH alias")));
    let (_, ssh_evidence) = classify_remote(
        "https://github.com/owner/repo",
        "gh-alias:owner/repo.git",
        "fetch",
    );
    assert!(ssh_evidence.iter().any(|l| l.contains("SSH alias")));
}

#[test]
fn credential_redaction_table() {
    assert_eq!(
        redact_credentials("https://user:secret@github.com/o/r.git"),
        "https://user:<redacted>@github.com/o/r.git"
    );
    assert_eq!(
        redact_credentials("https://token123@github.com/o/r.git"),
        "https://<redacted>@github.com/o/r.git"
    );
    assert_eq!(
        redact_credentials("https://github.com/o/r.git"),
        "https://github.com/o/r.git"
    );
    assert_eq!(
        redact_credentials("git@github.com:o/r.git"),
        "<redacted>@github.com:o/r.git",
        "RS-PRIV-10: scp-like user redacts (token-as-username is indistinguishable)"
    );
}

/// GIT-m5: the threaded alias map decides SSH identity — the `_with`
/// chain honors a caller-supplied map without touching `HOME`, an
/// empty map resolves nothing, and the legacy entry points delegate
/// (threaded fresh-load equals the direct call).
#[test]
fn ssh_alias_threaded_map_decides_without_file_read() {
    use repo_scan::identity::{
        classify_remote_with, github_host_matches_with, normalize_github_url_with,
        resolve_ssh_alias, resolve_ssh_alias_with,
    };
    let aliases = parse_ssh_config("Host gh\n  HostName github.com\n");
    // Threaded map: alias resolves to GitHub on SSH transports.
    assert_eq!(
        resolve_ssh_alias_with("gh", &aliases).as_deref(),
        Some("github.com")
    );
    assert!(github_host_matches_with("gh", true, &aliases));
    assert!(!github_host_matches_with("gh", false, &aliases));
    assert_eq!(
        normalize_github_url_with("gh:owner/repo.git", &aliases).as_deref(),
        Some("https://github.com/owner/repo")
    );
    let (disposition, _) = classify_remote_with(
        "https://github.com/owner/repo",
        "gh:owner/repo.git",
        "fetch",
        &aliases,
    );
    assert_eq!(disposition, MatchDisposition::Confirmed);
    // Empty map: the same inputs resolve nothing (no file consulted).
    let empty = parse_ssh_config("# nothing\n");
    assert_eq!(resolve_ssh_alias_with("gh", &empty), None);
    assert!(!github_host_matches_with("gh", true, &empty));
    assert_eq!(normalize_github_url_with("gh:owner/repo.git", &empty), None);
    // Legacy entry points delegate to the threaded chain.
    let fresh = repo_scan::identity::load_ssh_aliases();
    assert_eq!(
        resolve_ssh_alias("github.com"),
        resolve_ssh_alias_with("github.com", &fresh)
    );
}

#[test]
fn ssh_alias_config_parses_narrowly() {
    let map = parse_ssh_config(
        "# comment\nHost gh work\n  HostName github.com\nHost *.example.com\n  HostName evil.test\nHost second\n  # no hostname here\n",
    );
    assert_eq!(map.get("gh").map(String::as_str), Some("github.com"));
    assert_eq!(map.get("work").map(String::as_str), Some("github.com"));
    assert!(!map.contains_key("*.example.com"), "wildcards ignored");
    assert!(!map.contains_key("second"), "missing hostname ignored");
}

/// A non-UTF-8 `include.path` spelling reaches `config_dependencies`
/// byte-exact (no lossy `U+FFFD` mangling), recorded as a missing
/// include target — installed git tolerates the same config (missing
/// includes are silently skipped). Unix-only (raw-byte paths).
#[cfg(unix)]
#[test]
fn config_deps_record_non_utf8_include_bytes() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let home = scratch.path().join("home");
    let work = init_with_commit(&git_bin, scratch.path());
    let config_path = work.join(".git").join("config");
    let mut config = std::fs::read(&config_path).expect("read config");
    config.extend_from_slice(b"[include]\n\tpath = bad-\xff.inc\n");
    repo_scan::privacy::private_write_0600(&config_path, &config).expect("append include");
    // Reference: installed git still opens the repo (missing include
    // targets are silently skipped, never fatal).
    git(&git_bin, &home, &work, &["rev-parse", "HEAD"]);

    let inspector = GixInspector::new();
    let instance = inspector.open_exact(&work).expect("open");
    let deps = inspector.config_dependencies(&instance);
    let expected = work
        .join(".git")
        .join(std::ffi::OsString::from_vec(b"bad-\xff.inc".to_vec()));
    let found = deps
        .iter()
        .find(|d| d.path == expected)
        .unwrap_or_else(|| panic!("byte-exact include dep missing: {deps:?}"));
    assert!(!found.exists, "target is genuinely missing");
    assert!(found.via_include);
    // No lossy twin: the replacement-character spelling must not appear.
    assert!(
        !deps.iter().any(|d| d
            .path
            .as_os_str()
            .as_bytes()
            .windows("�".len())
            .any(|w| w == "�".as_bytes())),
        "lossy U+FFFD spelling leaked into deps: {deps:?}"
    );
}

/// A `.git` pointer file's ASCII `gitdir:` target keeps its exact
/// evidence spelling after the byte-exact conversion.
#[test]
fn gitdir_pointer_evidence_ascii_stable() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let work = init_with_commit(&git_bin, scratch.path());
    let elsewhere = scratch.path().join("elsewhere.git");
    std::fs::rename(work.join(".git"), &elsewhere).expect("move gitdir");
    repo_scan::privacy::private_write_0600(
        &work.join(".git"),
        format!("gitdir: {}\n", elsewhere.display()).as_bytes(),
    )
    .expect("pointer");
    let inspector = GixInspector::new();
    let validated = inspector.validate(&work).expect("validate pointer");
    assert!(
        validated
            .evidence
            .iter()
            .any(|e| e == &format!("gitdir pointer: {}", elsewhere.display())),
        "ASCII pointer evidence unchanged: {:?}",
        validated.evidence
    );
}

/// Round-2 F-note1: every status observation declares the isolated
/// config scope it was inspected under (spec "declare what was
/// inspected"), so readers never mistake the counts for operator-`git
/// status` output, which honors global scope.
#[test]
fn status_observations_declare_isolated_scope() {
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let work = init_with_commit(&git_bin, scratch.path());
    let inspector = GixInspector::new();
    let validated = inspector.validate(&work).expect("validate workdir");
    for mode in [StatusMode::Metadata, StatusMode::Summary, StatusMode::Full] {
        let obs = inspector
            .status(&validated.instance, mode)
            .expect("status reads");
        assert!(
            obs.unknown_fields
                .iter()
                .any(|f| f.contains("isolated-config-scope")),
            "{mode:?} must declare its inspected scope: {:?}",
            obs.unknown_fields
        );
    }
}
