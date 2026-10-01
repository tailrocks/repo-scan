//! RSF-FALLBACK-HELPER-SECURITY regression tests: one focused test per
//! fix. Fixtures live under `/tmp` only via `tempfile` (0700); all custom
//! fixture data stays tiny (well under 4 KiB); unbounded inputs are
//! `/bin/sh` loops, never big files.

#[cfg(unix)]
mod common;

#[cfg(unix)]
use common::fixture;
#[cfg(unix)]
use repo_scan::git::{self, fallback::FallbackGit};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::time::Duration;

/// Serializes every test in this binary: fallback spawns share the
/// process-wide helper ledger, and the telemetry tests need it stable.
#[cfg(unix)]
static SPAWN_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(unix)]
fn spawn_serial() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_SERIAL
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Installed git, or `None` when the machine has none (skip, loudly).
#[cfg(unix)]
fn git_or_skip() -> Option<PathBuf> {
    FallbackGit::discover(&[]).map(|found| found.path().to_path_buf())
}

/// Write an executable `git` fixture: `--version` prints `banner`, every
/// other argv runs `body`.
#[cfg(unix)]
fn write_git_fixture(path: &Path, banner: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\necho \"{banner}\"\nexit 0\nfi\n{body}\n"
    );
    repo_scan::privacy::private_write_0600(path, script.as_bytes()).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

/// Append `snippet` to a repo's `.git/config` (0700-rooted fixture).
#[cfg(unix)]
fn append_repo_config(repo: &Path, snippet: &str) {
    let path = repo.join(".git/config");
    let mut config = std::fs::read_to_string(&path).expect("read .git/config");
    config.push_str(snippet);
    repo_scan::privacy::private_write_0600(&path, config.as_bytes()).unwrap();
}

/// RSF-FALLBACK-HELPER-SECURITY(1): repo-selected code never executes.
/// A repo defining executable filter drivers refuses `status_counts`
/// with `unsupported` (marker files prove the drivers never ran), while
/// non-content reads (`head`, `refs`) still serve without executing;
/// a repo arming fsmonitor through an `include.path` chain serves
/// status with the hook neutralized by `-c` precedence (marker absent).
#[cfg(unix)]
#[test]
fn fallback01_repo_selected_code_never_executes() {
    let _serial = spawn_serial();
    let Some(git_bin) = git_or_skip() else {
        eprintln!("skip: no installed git");
        return;
    };
    let scratch = fixture::scratch_root("rsf-fb1-");
    let fallback = FallbackGit::probe(&git_bin).expect("probe explicit git");

    // Repo A: executable filter drivers -> content reads refuse.
    let repo_a = fixture::normal_clone(scratch.path(), "repo-a");
    let marker_clean = repo_a.join("marker-clean");
    let marker_smudge = repo_a.join("marker-smudge");
    repo_scan::privacy::private_write_0600(
        &repo_a.join(".gitattributes"),
        b"* filter=rsf-fallback-evil\n",
    )
    .unwrap();
    append_repo_config(
        &repo_a,
        &format!(
            "[filter \"rsf-fallback-evil\"]\n\tclean = touch \"{}\"\n\tsmudge = touch \"{}\"\n",
            marker_clean.display(),
            marker_smudge.display()
        ),
    );
    let git_dir_a = repo_a.join(".git");
    let err = fallback
        .status_counts(&git_dir_a, Some(&repo_a), true)
        .expect_err("filtered status must refuse, never execute");
    assert!(err.to_string().contains("filter"), "{err}");
    assert!(git::is_unsupported_error(&err), "{err}");
    assert!(
        !marker_clean.exists() && !marker_smudge.exists(),
        "filter drivers must never run"
    );
    fallback
        .head(&git_dir_a, Some(&repo_a))
        .expect("head serves without filters");
    fallback
        .refs(&git_dir_a, Some(&repo_a))
        .expect("refs serve without filters");
    assert!(
        !marker_clean.exists() && !marker_smudge.exists(),
        "non-content reads must not execute filters either"
    );

    // Repo B: fsmonitor armed through an include chain -> status serves,
    // hook neutralized (`-c core.fsmonitor=false` wins by precedence).
    let repo_b = fixture::normal_clone(scratch.path(), "repo-b");
    let marker_fs = repo_b.join("marker-fs");
    repo_scan::privacy::private_write_0600(
        &repo_b.join(".git/inc.conf"),
        format!("[core]\n\tfsmonitor = touch \"{}\"\n", marker_fs.display()).as_bytes(),
    )
    .unwrap();
    append_repo_config(&repo_b, "[include]\n\tpath = inc.conf\n");
    let git_dir_b = repo_b.join(".git");
    let counts = fallback
        .status_counts(&git_dir_b, Some(&repo_b), true)
        .expect("unfiltered status serves");
    assert_eq!(counts, (0, 0, 0));
    assert!(
        !marker_fs.exists(),
        "fsmonitor hook must be neutralized, including via includes"
    );
}

/// RSF-FALLBACK-HELPER-SECURITY(2): the child exits at once while a
/// grandchild in the same group holds the stdout pipe open. The post-exit
/// drain must fail as an explicit incomplete gap once the drain budget
/// elapses — never hang. The group kill is skipped: the child was already
/// reaped by `try_wait`, so its pgid may be reused by an unrelated group
/// (PGID-reuse friendly-fire) — the surviving holder detaches loudly past
/// the grace with the charge kept and stuck recorded.
#[cfg(unix)]
#[test]
fn fallback02_post_exit_drain_is_bounded() {
    use repo_scan::git::fallback::{helper_telemetry, spawn_enveloped, POST_EXIT_DRAIN_TIMEOUT};
    use repo_scan::scheduler::admission::HELPER_LEDGER;

    let _serial = spawn_serial();
    let live_before = HELPER_LEDGER.live();
    let stuck_before = helper_telemetry().stuck;
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c").arg("sleep 30 >&1 & echo hello; exit 0");
    let start = std::time::Instant::now();
    let err = spawn_enveloped(&mut cmd, false, Duration::from_secs(60), 1024 * 1024)
        .expect_err("a descendant-held pipe must fail, never hang");
    let elapsed = start.elapsed();
    assert!(err.contains("incomplete"), "{err}");
    assert!(err.contains("drain"), "{err}");
    assert!(err.contains("skipped"), "{err}");
    assert!(err.contains("already reaped"), "{err}");
    assert!(!err.contains("group killed"), "{err}");
    assert!(err.contains("STUCK"), "{err}");
    assert!(
        elapsed >= POST_EXIT_DRAIN_TIMEOUT,
        "must wait out the drain budget: {elapsed:?}"
    );
    assert!(
        elapsed < POST_EXIT_DRAIN_TIMEOUT + Duration::from_secs(30),
        "bounded, never a hang: {elapsed:?}"
    );
    assert_eq!(
        HELPER_LEDGER.live(),
        live_before + 1,
        "an unproven drain keeps its charge (surviving holder)"
    );
    assert_eq!(
        helper_telemetry().stuck,
        stuck_before + 1,
        "the surviving holder must record stuck"
    );
}

/// PGID-reuse friendly-fire (drain-cancel arm): a token fired during the
/// post-exit drain cancels loudly while still skipping the group kill —
/// the child is already reaped, so its pgid may be reused. The surviving
/// holder detaches loudly with the charge kept and stuck recorded.
#[cfg(unix)]
#[test]
fn fallback02b_drain_cancel_skips_reaped_group_kill() {
    use repo_scan::git::fallback::{
        helper_telemetry, spawn_enveloped, with_wait_cancel, WaitCancel,
    };
    use repo_scan::scheduler::admission::HELPER_LEDGER;
    use std::sync::atomic::{AtomicBool, Ordering};

    let _serial = spawn_serial();
    let live_before = HELPER_LEDGER.live();
    let stuck_before = helper_telemetry().stuck;
    // The child exits in milliseconds; fire mid-drain (well inside the 5s
    // budget) so the drain-cancel arm — not the wait-cancel arm — trips.
    let flag = Arc::new(AtomicBool::new(false));
    let setter = Arc::clone(&flag);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(1));
        setter.store(true, Ordering::SeqCst);
    });
    let token = WaitCancel::new(move || flag.load(Ordering::SeqCst), None);
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c").arg("sleep 30 >&1 & echo hello; exit 0");
    let start = std::time::Instant::now();
    let err = with_wait_cancel(&token, || {
        spawn_enveloped(&mut cmd, false, Duration::from_secs(60), 1024 * 1024)
    })
    .expect_err("a token fired mid-drain must cancel");
    assert!(err.contains("cancelled during post-exit drain"), "{err}");
    assert!(err.contains("skipped"), "{err}");
    assert!(!err.contains("group killed"), "{err}");
    assert!(err.contains("STUCK"), "{err}");
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "cancel must end the drain promptly: {:?}",
        start.elapsed()
    );
    assert_eq!(
        HELPER_LEDGER.live(),
        live_before + 1,
        "an unproven drain keeps its charge (surviving holder)"
    );
    assert_eq!(
        helper_telemetry().stuck,
        stuck_before + 1,
        "the surviving holder must record stuck"
    );
}

/// RSF-FALLBACK-HELPER-SECURITY(3): the over-cap path group-kills (a lone
/// `child.kill` would orphan the grandchild), grace-joins, and releases
/// the proven charge. The child ignores SIGPIPE and floods forever, so
/// the cap path (not the exit path) always triggers.
#[cfg(unix)]
#[test]
fn fallback03_cap_path_group_kills_and_accounts() {
    use repo_scan::git::fallback::spawn_enveloped;
    use repo_scan::scheduler::admission::HELPER_LEDGER;

    let _serial = spawn_serial();
    let live_before = HELPER_LEDGER.live();
    let dir = tempfile::tempdir().expect("tempdir");
    let pidfile = dir.path().join("grandchild.pid");
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c").arg(format!(
        "sleep 30 & echo $! > \"{}\"; trap \"\" PIPE; while true; do echo flood; done",
        pidfile.display()
    ));
    spawn_enveloped(&mut cmd, false, Duration::from_secs(30), 4096)
        .expect("the cap path must return, not hang");
    let pid: i32 = std::fs::read_to_string(&pidfile)
        .expect("pidfile")
        .trim()
        .parse()
        .expect("pid");
    let mut gone = false;
    for _ in 0..40 {
        // SAFETY: signal 0 performs no delivery; it only probes existence.
        if unsafe { libc::kill(pid, 0) } != 0 {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(gone, "cap-path grandchild {pid} must be group-killed");
    assert_eq!(
        HELPER_LEDGER.live(),
        live_before,
        "cap path releases the proven charge"
    );
}

/// RSF-FALLBACK-HELPER-SECURITY(4): a timed-out spawn kills the whole
/// process group, reaps, joins readers, and reports every stage loudly —
/// with no false stuck/unknown evidence and the proven charge released.
/// (The true-unknown branch — a failed `killpg` — is covered by the
/// `classify_killpg_error` unit test; it cannot be triggered
/// deterministically from a test.)
#[cfg(unix)]
#[test]
fn fallback04_timeout_is_loud_and_accounted() {
    use repo_scan::git::fallback::{helper_telemetry, spawn_enveloped};
    use repo_scan::scheduler::admission::HELPER_LEDGER;

    let _serial = spawn_serial();
    let live_before = HELPER_LEDGER.live();
    let tally_before = helper_telemetry();
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c").arg("sleep 30 & exec sleep 30");
    let err = spawn_enveloped(&mut cmd, false, Duration::from_millis(200), 1024)
        .expect_err("a 30s sleeper must exceed a 200ms budget");
    assert!(err.contains("timed out"), "{err}");
    assert!(err.contains("group killed"), "{err}");
    assert!(err.contains("reaped"), "{err}");
    assert!(err.contains("stdout joined"), "{err}");
    assert!(!err.contains("FAILED"), "{err}");
    assert!(!err.contains("STUCK"), "{err}");
    assert!(!err.contains("UNKNOWN"), "{err}");
    assert_eq!(
        HELPER_LEDGER.live(),
        live_before,
        "proven cleanup releases the charge"
    );
    let tally_after = helper_telemetry();
    assert_eq!(
        tally_after.unknown, tally_before.unknown,
        "a clean group kill must not record unknown"
    );
    assert_eq!(
        tally_after.stuck, tally_before.stuck,
        "joined readers must not record stuck"
    );
}

/// RSF-FALLBACK-HELPER-SECURITY(5): a task cancellation token ends stuck
/// waits — both a flag fired mid-wait (SIGINT shape) and an already
/// expired deadline — with the proven charges released.
#[cfg(unix)]
#[test]
fn fallback05_cancel_token_ends_stuck_waits() {
    use repo_scan::git::fallback::{spawn_enveloped, with_wait_cancel, WaitCancel};
    use repo_scan::scheduler::admission::HELPER_LEDGER;
    use std::sync::atomic::{AtomicBool, Ordering};

    let _serial = spawn_serial();
    let live_before = HELPER_LEDGER.live();
    // A flag fired mid-wait ends a stuck child wait promptly.
    let flag = Arc::new(AtomicBool::new(false));
    let setter = Arc::clone(&flag);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        setter.store(true, Ordering::SeqCst);
    });
    let token = WaitCancel::new(move || flag.load(Ordering::SeqCst), None);
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c").arg("exec sleep 30");
    let start = std::time::Instant::now();
    let err = with_wait_cancel(&token, || {
        spawn_enveloped(&mut cmd, false, Duration::from_secs(60), 1024)
    })
    .expect_err("a fired token must cancel the wait");
    assert!(err.contains("cancelled"), "{err}");
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "cancel must end the wait promptly"
    );
    // An already-expired deadline cancels without running the budget out.
    let expired = WaitCancel::new(|| false, Some(std::time::Instant::now()));
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c").arg("exec sleep 30");
    let err = with_wait_cancel(&expired, || {
        spawn_enveloped(&mut cmd, false, Duration::from_secs(60), 1024)
    })
    .expect_err("an expired deadline must cancel");
    assert!(err.contains("cancelled"), "{err}");
    assert_eq!(
        HELPER_LEDGER.live(),
        live_before,
        "cancel paths release proven charges"
    );
}

/// RSF-FALLBACK-HELPER-SECURITY(5b, FALLBACK-5): SIGINT/deadline during a
/// refs/head fallback cancels promptly. The probe path wraps `head`/`refs`
/// in `with_wait_cancel` (mirroring the status path); a hanging installed
/// git must therefore fail fast under a fired token instead of burning the
/// 30s-per-spawn budget (`head` fans out to sequential spawns).
#[cfg(unix)]
#[test]
fn fallback05b_head_refs_honor_cancel_token() {
    use repo_scan::git::fallback::{with_wait_cancel, WaitCancel};
    use repo_scan::scheduler::admission::HELPER_LEDGER;
    use std::sync::atomic::{AtomicBool, Ordering};

    let _serial = spawn_serial();
    let live_before = HELPER_LEDGER.live();
    let dir = tempfile::tempdir().expect("tempdir");
    // Every read argv hangs; probe argv (`init`, `status --porcelain=v2
    // --help`) answer fast so discovery still succeeds.
    let git = dir.path().join("git");
    write_git_fixture(
        &git,
        "git version 9.9.9-hang",
        concat!(
            "case \" $* \" in *\" for-each-ref \"*|*\" symbolic-ref \"*",
            "|*\" rev-parse \"*|*\" config \"*) exec sleep 30;;",
            " *) echo \" --porcelain[<version>]  machine-readable output\";",
            " exit 0;; esac",
        ),
    );
    let fallback = FallbackGit::probe(&git).expect("probe hanging git");
    // Never touched: the fixture hangs before reading any repo.
    let git_dir = dir.path().join("repo.git");

    // SIGINT shape: the flag fires mid-wait during the refs fallback.
    let flag = Arc::new(AtomicBool::new(false));
    let setter = Arc::clone(&flag);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        setter.store(true, Ordering::SeqCst);
    });
    let token = WaitCancel::new(move || flag.load(Ordering::SeqCst), None);
    let start = std::time::Instant::now();
    let err = with_wait_cancel(&token, || fallback.refs(&git_dir, None))
        .expect_err("a fired token must cancel the refs fallback");
    assert!(err.to_string().contains("cancelled"), "{err}");
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "cancel must end the refs fallback promptly"
    );

    // An already-expired deadline cancels the head fallback without
    // running the budget out. (`head` maps spawn errors to Unknown, so
    // promptness — not the error — is the verdict: unfired, its
    // sequential spawns would burn 30s each.)
    let expired = WaitCancel::new(|| false, Some(std::time::Instant::now()));
    let start = std::time::Instant::now();
    let head =
        with_wait_cancel(&expired, || fallback.head(&git_dir, None)).expect("head serves Unknown");
    assert!(
        matches!(head, git::HeadState::Unknown),
        "cancelled head reads as Unknown, got {head:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "cancel must end the head fallback promptly"
    );
    assert_eq!(
        HELPER_LEDGER.live(),
        live_before,
        "cancel paths release proven charges"
    );
}

/// RSF-FALLBACK-HELPER-SECURITY(6): helper telemetry reads the
/// process-wide ledger as its source of truth, with stuck/unknown
/// explicit — a held ledger slot surfaces in `live` immediately.
#[cfg(unix)]
#[test]
fn fallback06_helper_telemetry_unifies_ledger() {
    use repo_scan::git::fallback::helper_telemetry;
    use repo_scan::scheduler::admission::{HELPER_LEDGER, HELPER_LEDGER_CAP};

    let _serial = spawn_serial();
    let baseline = helper_telemetry();
    assert_eq!(
        baseline.live,
        HELPER_LEDGER.live(),
        "telemetry live must read the ledger"
    );
    assert_eq!(baseline.cap, HELPER_LEDGER_CAP);
    assert!(HELPER_LEDGER.try_acquire());
    assert_eq!(
        helper_telemetry().live,
        baseline.live + 1,
        "a ledger charge must surface in telemetry"
    );
    HELPER_LEDGER.release();
    let after = helper_telemetry();
    assert_eq!(after.live, baseline.live);
    assert_eq!(after.stuck, baseline.stuck, "stuck stays explicit");
    assert_eq!(after.unknown, baseline.unknown, "unknown stays explicit");
}

/// RSF-FALLBACK-HELPER-SECURITY(7): group/other-writable `$PATH` entries
/// are refused before probing (never executed); trusted entries still
/// discover with their source recorded; explicit paths stay
/// operator-trusted even under a writable directory.
#[cfg(unix)]
#[test]
fn fallback07_writable_path_entries_rejected() {
    use repo_scan::git::fallback::{BinarySource, FallbackGit};
    use std::os::unix::fs::PermissionsExt;

    let _serial = spawn_serial();
    let scratch = fixture::scratch_root("rsf-fb7-");
    let writable = scratch.path().join("writable");
    repo_scan::privacy::private_dir_0700(&writable).unwrap();
    write_git_fixture(
        &writable.join("git"),
        "git version 9.9.9-writable",
        "echo hi\nexit 0\n",
    );
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        FallbackGit::discover_from(&[], &[], Some(writable.to_string_lossy().into_owned()))
            .is_none(),
        "a 0777 PATH entry must be refused before probing"
    );
    let trusted = scratch.path().join("trusted");
    repo_scan::privacy::private_dir_0700(&trusted).unwrap();
    write_git_fixture(
        &trusted.join("git"),
        "git version 9.9.9-trusted",
        "echo hi\nexit 0\n",
    );
    std::fs::set_permissions(&trusted, std::fs::Permissions::from_mode(0o755)).unwrap();
    let found = FallbackGit::discover_from(&[], &[], Some(trusted.to_string_lossy().into_owned()))
        .expect("a 0755 PATH entry stays trusted");
    assert_eq!(found.source(), BinarySource::Path);
    assert!(found.capabilities().version.contains("trusted"));
    let mixed = format!("{}:{}", writable.display(), trusted.display());
    let found =
        FallbackGit::discover_from(&[], &[], Some(mixed)).expect("mixed PATH skips writable");
    assert_eq!(found.source(), BinarySource::Path);
    assert!(
        found.path().starts_with(&trusted),
        "must select the trusted entry: {}",
        found.path().display()
    );
    let explicit = FallbackGit::discover_from(&[writable.join("git")], &[], None)
        .expect("explicit paths stay operator-trusted");
    assert_eq!(explicit.source(), BinarySource::Explicit);
}
