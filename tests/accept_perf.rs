//! PERF-02/03 acceptance (spec §17): build the `perf_gates` harness, run it
//! once into a tempdir, and assert exit 0 plus the JSONL verdict records and
//! numeric bounds. Bounds are re-checked here from the raw numbers, never
//! taken on the harness's word alone.
//!
//! RSF-PERF-BLOCKED-TEST-001: every wait is bounded and every timeout FAILS
//! (never skips); full harness output is tee'd to a durable directory with
//! a SHA-256-hashed JSONL copy plus TEST_EXIT and source/build fingerprints,
//! all captured BEFORE the fixture tempdir is cleaned.

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

use repo_scan::report::publish::sha256_hex;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

/// Declared corpus shape (must match the harness record).
const FLAT_FILES: u64 = 2000;
const DEEP_LEVELS: u64 = 40;
const TOTAL_REPO_BUILDS: u64 = 200;
const LINKED_WORKTREES: u64 = 10;
/// Spec §5/§18 bounds, re-checked from raw samples.
const RSS_TARGET_BYTES: u64 = 256 * 1024 * 1024;
const CPU_BOUND_CORES: f64 = 1.1;
const MIN_MEASURED_S: f64 = 30.0;
/// Bounded waits (RSF-PERF-BLOCKED-TEST-001): overruns panic (FAIL),
/// never skip. The harness self-bounds below [`HARNESS_TIMEOUT`]; the
/// test backstop only fires if the harness itself hangs.
const BUILD_TIMEOUT: Duration = Duration::from_secs(900);
const HARNESS_TIMEOUT: Duration = Duration::from_secs(3000);
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const TIMEOUT_TEST_TIMEOUT: Duration = Duration::from_secs(300);

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn target_dir() -> PathBuf {
    std::env::var("CARGO_BUILD_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir().join("target"))
}

fn harness_bin() -> PathBuf {
    target_dir()
        .join("debug")
        .join(format!("perf_gates{}", std::env::consts::EXE_SUFFIX))
}

/// Primary locator: parse the `compiler-artifact` executable path out of
/// `cargo build --message-format=json` stdout. `cargo build --bench` leaves
/// the hashed binary under `debug/deps/`, never at `debug/perf_gates`.
fn harness_bin_from_message(build_stdout: &str) -> Option<PathBuf> {
    for line in build_stdout.lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if msg["reason"].as_str() != Some("compiler-artifact") {
            continue;
        }
        if msg["target"]["name"].as_str() != Some("perf_gates") {
            continue;
        }
        if let Some(exe) = msg["executable"].as_str() {
            return Some(PathBuf::from(exe));
        }
    }
    None
}

/// Fallback locator: newest executable `perf_gates-*` entry in `debug/deps/`.
fn harness_bin_from_deps() -> Option<PathBuf> {
    let deps = target_dir().join("debug").join("deps");
    let mut best: Option<(SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(&deps).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("perf_gates-") {
            continue;
        }
        if name.ends_with(".d")
            || name.ends_with(".rlib")
            || name.ends_with(".rmeta")
            || name.ends_with(".o")
        {
            continue;
        }
        let path = entry.path();
        let meta = std::fs::metadata(&path).ok()?;
        if !meta.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        let mtime = meta.modified().ok()?;
        let newer = best.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true);
        if newer {
            best = Some((mtime, path));
        }
    }
    best.map(|(_, p)| p)
}

/// Last `n` chars of a long log for failure messages (bounded).
fn tail(text: &str, n: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    chars[chars.len().saturating_sub(n)..].iter().collect()
}

fn load_jsonl(path: &Path) -> Vec<serde_json::Value> {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("jsonl line parses"))
        .collect()
}

fn find<'a>(records: &'a [serde_json::Value], name: &str) -> Vec<&'a serde_json::Value> {
    records
        .iter()
        .filter(|v| v["record"].as_str() == Some(name))
        .collect()
}

fn one<'a>(records: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
    let hits = find(records, name);
    assert_eq!(hits.len(), 1, "exactly one `{name}` record");
    hits[0]
}

/// Run `cmd` to completion within `timeout`, capturing output to temp
/// files. `Ok` carries the output whatever the exit status (callers assert
/// it); `Err` carries a bounded timeout report. Callers panic on `Err`:
/// a timeout FAILS the test, never skips it.
///
/// Output goes to files, never OS pipes: a piped child that emits more
/// than the pipe buffer (~64 KiB, e.g. `cargo build
/// --message-format=json`) blocks on write while the parent polls
/// `try_wait`, deadlocking until the timeout fires. Files have no such
/// bound, however large the output.
fn run_with_timeout(mut cmd: Command, timeout: Duration, label: &str) -> Result<Output, String> {
    let capture = tempfile::tempdir().unwrap_or_else(|e| panic!("capture tempdir: {e}"));
    let stdout_path = capture.path().join("stdout.log");
    let stderr_path = capture.path().join("stderr.log");
    let stdout_file =
        std::fs::File::create(&stdout_path).unwrap_or_else(|e| panic!("capture stdout: {e}"));
    let stderr_file =
        std::fs::File::create(&stderr_path).unwrap_or_else(|e| panic!("capture stderr: {e}"));
    cmd.stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {label}: {e}"));
    let start = Instant::now();
    let timed_out = loop {
        let done = child
            .try_wait()
            .unwrap_or_else(|e| panic!("poll {label}: {e}"));
        if done.is_some() {
            break false;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            break true;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let status = child.wait().unwrap_or_else(|e| panic!("reap {label}: {e}"));
    let stdout =
        std::fs::read(&stdout_path).unwrap_or_else(|e| panic!("read captured stdout: {e}"));
    let stderr =
        std::fs::read(&stderr_path).unwrap_or_else(|e| panic!("read captured stderr: {e}"));
    if timed_out {
        return Err(format!(
            "{label} exceeded {}s timeout\nstdout tail: {}\nstderr tail: {}",
            timeout.as_secs(),
            tail(&String::from_utf8_lossy(&stdout), 2000),
            tail(&String::from_utf8_lossy(&stderr), 2000),
        ));
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Build the harness bench (bounded wait that FAILS on timeout) and
/// locate the harness plus repo-scan binaries. Returns
/// `(harness, repo_scan, build_exit)`.
fn build_harness() -> (PathBuf, PathBuf, Option<i32>) {
    let manifest = manifest_dir();
    let mut cmd = Command::new(cargo_bin());
    cmd.args(["build", "--bench", "perf_gates", "--message-format=json"])
        .current_dir(&manifest);
    let build = run_with_timeout(cmd, BUILD_TIMEOUT, "cargo build --bench perf_gates")
        .unwrap_or_else(|e| panic!("harness build timed out (failing, never skipping):\n{e}"));
    assert!(
        build.status.success(),
        "cargo build --bench perf_gates failed (Cargo.toml needs [[bench]] name = \"perf_gates\", harness = false):\n{}",
        String::from_utf8_lossy(&build.stderr),
    );
    let build_stdout = String::from_utf8_lossy(&build.stdout).into_owned();
    let harness = harness_bin_from_message(&build_stdout)
        .or_else(harness_bin_from_deps)
        .unwrap_or_else(harness_bin);
    assert!(
        harness.is_file(),
        "harness binary missing at {}",
        harness.display()
    );
    let repo_scan = PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"));
    assert!(
        repo_scan.is_file(),
        "repo-scan binary missing at {}",
        repo_scan.display()
    );
    (harness, repo_scan, build.status.code())
}

/// Durable evidence directory under `target/perf_evidence/` (never
/// auto-cleaned): `<label>-<pid>-<epoch_ms>/`.
fn evidence_dir(label: &str) -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let dir = target_dir()
        .join("perf_evidence")
        .join(format!("{label}-{}-{millis}", std::process::id()));
    repo_scan::privacy::private_dir_0700(&dir)
        .unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    dir
}

/// One read-only probe (git/toolchain): trimmed stdout, or an explicit
/// unknown-with-reason. Bounded; never panics.
fn probe(label: &str, cmd: &str, args: &[&str]) -> String {
    let mut command = Command::new(cmd);
    command.args(args).current_dir(manifest_dir());
    match run_with_timeout(command, PROBE_TIMEOUT, label) {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Ok(out) => format!("unknown (exit {})", out.status.code().unwrap_or(-1)),
        Err(_) => String::from("unknown (probe timeout)"),
    }
}

fn git_head() -> String {
    let head = probe("git rev-parse", "git", &["rev-parse", "HEAD"]);
    if head.len() == 40 && head.chars().all(|c| c.is_ascii_hexdigit()) {
        head
    } else {
        format!("unknown (unexpected rev-parse output: {head:?})")
    }
}

/// SHA-256 over the tracked-diff bytes (a clean tree hashes the empty
/// input — still a known fingerprint, never a skip).
fn git_diff_sha256() -> String {
    let mut command = Command::new("git");
    command
        .args(["diff", "--no-ext-diff", "HEAD"])
        .current_dir(manifest_dir());
    match run_with_timeout(command, PROBE_TIMEOUT, "git diff") {
        Ok(out) if out.status.success() => sha256_hex(&out.stdout),
        Ok(out) => format!("unknown (exit {})", out.status.code().unwrap_or(-1)),
        Err(_) => String::from("unknown (probe timeout)"),
    }
}

/// Tee harness output, hash the JSONL, and copy it to the durable dir
/// BEFORE the fixture tempdir drops, with TEST_EXIT plus source/build
/// fingerprints. Panics (fails) on any IO error: evidence gaps are
/// loud, never silent. Returns the evidence object.
#[allow(clippy::too_many_arguments)]
fn write_evidence(
    dir: &Path,
    test: &str,
    build_exit: Option<i32>,
    harness_exit: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    jsonl_src: &Path,
) -> serde_json::Value {
    repo_scan::privacy::private_write_0600(&dir.join("harness_stdout.log"), stdout)
        .unwrap_or_else(|e| panic!("tee stdout: {e}"));
    repo_scan::privacy::private_write_0600(&dir.join("harness_stderr.log"), stderr)
        .unwrap_or_else(|e| panic!("tee stderr: {e}"));
    let jsonl_bytes =
        std::fs::read(jsonl_src).unwrap_or_else(|e| panic!("read {}: {e}", jsonl_src.display()));
    repo_scan::privacy::private_write_0600(&dir.join("perf_gates.jsonl"), &jsonl_bytes)
        .unwrap_or_else(|e| panic!("copy jsonl: {e}"));
    let evidence = serde_json::json!({
        "test": test,
        "TEST_EXIT": harness_exit,
        "build_exit": build_exit,
        "git_head": git_head(),
        "git_diff_sha256": git_diff_sha256(),
        "rustc": probe("rustc --version", "rustc", &["--version"]),
        "cargo": probe("cargo --version", &cargo_bin(), &["--version"]),
        "jsonl_sha256": sha256_hex(&jsonl_bytes),
        "jsonl_bytes": jsonl_bytes.len(),
        "jsonl_lines": jsonl_bytes.iter().filter(|b| **b == b'\n').count(),
        "harness_stdout_bytes": stdout.len(),
        "harness_stderr_bytes": stderr.len(),
    });
    repo_scan::privacy::private_write_0600(
        &dir.join("evidence.json"),
        serde_json::to_string_pretty(&evidence)
            .expect("serialize evidence")
            .as_bytes(),
    )
    .unwrap_or_else(|e| panic!("write evidence.json: {e}"));
    eprintln!("perf gates: durable evidence at {}", dir.display());
    evidence
}

/// Parse the harness's post-record `EVIDENCE jsonl_sha256=.. jsonl_bytes=..`
/// line from its stdout: `(sha256, bytes)`.
fn parse_evidence_line(stdout: &str) -> (String, usize) {
    let line = stdout
        .lines()
        .find(|line| line.starts_with("EVIDENCE jsonl_sha256="))
        .expect("harness printed EVIDENCE jsonl line");
    let sha = line
        .split_whitespace()
        .find_map(|word| word.strip_prefix("jsonl_sha256="))
        .expect("sha field")
        .to_string();
    let len: usize = line
        .split_whitespace()
        .find_map(|word| word.strip_prefix("jsonl_bytes="))
        .expect("len field")
        .parse()
        .expect("len parses");
    (sha, len)
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.chars().all(|c| c.is_ascii_hexdigit())
}

#[test]
fn perf_02_03_gates_hold() {
    if !git_available() {
        panic!(
            "perf gates: git is missing; cannot build the declared corpus — failing, never skipping"
        );
    }
    let (harness, repo_scan, build_exit) = build_harness();

    let results = tempfile::tempdir().expect("tempdir");
    let mut cmd = Command::new(&harness);
    cmd.env("BENCH_RESULTS", results.path())
        .env("CARGO_BIN_EXE_repo-scan", &repo_scan)
        .current_dir(manifest_dir());
    let run = run_with_timeout(cmd, HARNESS_TIMEOUT, "perf_gates")
        .unwrap_or_else(|e| panic!("perf_gates harness timed out (failing, never skipping):\n{e}"));
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&run.stderr).into_owned();

    // Durable evidence BEFORE any assertion can panic: tee, hash, copy.
    let dir = evidence_dir("perf-02-03");
    let evidence = write_evidence(
        &dir,
        "perf_02_03_gates_hold",
        build_exit,
        run.status.code(),
        &run.stdout,
        &run.stderr,
        &results.path().join("perf_gates.jsonl"),
    );

    assert_eq!(
        run.status.code(),
        Some(0),
        "perf_gates failed\nstdout tail: {}\nstderr tail: {}",
        tail(&stdout, 2000),
        tail(&stderr, 2000),
    );

    // Evidence protocol: exit + fingerprints are known, never unknowns.
    assert_eq!(evidence["TEST_EXIT"].as_i64(), Some(0));
    assert_eq!(evidence["build_exit"].as_i64(), Some(0));
    let head = evidence["git_head"].as_str().expect("git_head");
    assert!(is_hex(head, 40), "test git_head is 40-hex: {head}");
    let diff = evidence["git_diff_sha256"].as_str().expect("diff fp");
    assert!(is_hex(diff, 64), "test diff fp is 64-hex: {diff}");
    for key in ["rustc", "cargo"] {
        let tool = evidence[key].as_str().expect("toolchain");
        assert!(!tool.starts_with("unknown"), "test {key} known: {tool}");
    }

    // Provenance comes from the durable copy (the tempdir original is
    // cleaned when this scope ends).
    let copied = dir.join("perf_gates.jsonl");
    let records = load_jsonl(&copied);
    assert!(!records.is_empty(), "harness wrote records");
    assert!(
        find(&records, "phase_timeout").is_empty(),
        "no phase timed out on the pass path"
    );
    let env = one(&records, "env");
    assert_eq!(env["bench"].as_str(), Some("perf_gates"));

    // Harness-side build fingerprint agrees with the test-side one (same
    // source) and is fully known.
    let build_ev = one(&records, "build_evidence");
    assert_eq!(build_ev["git_head"].as_str(), Some(head));
    let harness_diff = build_ev["git_diff_sha256"].as_str().expect("harness diff");
    assert!(is_hex(harness_diff, 64), "harness diff fp: {harness_diff}");
    for key in ["rustc", "cargo"] {
        let tool = build_ev[key].as_str().expect("harness toolchain");
        assert!(!tool.starts_with("unknown"), "harness {key} known: {tool}");
    }

    // Durable-evidence anchor: recompute both hashes from the copied bytes.
    let copied_bytes = std::fs::read(&copied).expect("reread durable jsonl");
    let (printed_sha, printed_len) = parse_evidence_line(&stdout);
    assert_eq!(sha256_hex(&copied_bytes), printed_sha, "post hash matches");
    assert_eq!(copied_bytes.len(), printed_len, "post length matches");
    let text = String::from_utf8(copied_bytes.clone()).expect("jsonl is utf8");
    let mut offset = 0usize;
    let mut pre_end: Option<usize> = None;
    for line in text.split_inclusive('\n') {
        if line.contains("\"record\":\"evidence\"") {
            pre_end = Some(offset);
            break;
        }
        offset += line.len();
    }
    let anchor = one(&records, "evidence");
    let pre_end = pre_end.expect("evidence line present in bytes");
    assert_eq!(
        sha256_hex(&copied_bytes[..pre_end]),
        anchor["jsonl_sha256_pre"].as_str().expect("pre hash"),
        "pre hash matches bytes before the evidence record",
    );
    assert_eq!(
        pre_end as u64,
        anchor["jsonl_bytes_pre"].as_u64().expect("pre len"),
        "pre length matches",
    );

    // Declared corpus (PERF-02 fixture contract).
    let corpus = one(&records, "corpus");
    assert_eq!(corpus["flat_files"].as_u64(), Some(FLAT_FILES));
    assert_eq!(corpus["deep_levels"].as_u64(), Some(DEEP_LEVELS));
    let mut builds = 0u64;
    for key in [
        "repos_normal",
        "repos_bare",
        "repos_detached",
        "repos_worktree_mains",
    ] {
        builds += corpus[key]
            .as_u64()
            .unwrap_or_else(|| panic!("{key} count"));
    }
    assert_eq!(builds, TOTAL_REPO_BUILDS);
    assert_eq!(corpus["linked_worktrees"].as_u64(), Some(LINKED_WORKTREES));
    assert!(corpus["repos_bare"].as_u64().expect("bare") > 0);
    assert!(corpus["repos_detached"].as_u64().expect("detached") > 0);
    assert!(corpus["repos_worktree_mains"].as_u64().expect("worktree") > 0);

    // Every sustained iteration exited clean with a complete scan.
    let iters = find(&records, "sustain_iter");
    assert!(!iters.is_empty(), "at least one measured iteration");
    for iter in &iters {
        assert_eq!(iter["exit_code"].as_i64(), Some(0), "{iter}");
        assert_eq!(iter["timed_out"].as_bool(), Some(false), "{iter}");
        assert_eq!(iter["report_ok"].as_bool(), Some(true), "{iter}");
        assert_eq!(iter["scan_state"].as_str(), Some("complete"), "{iter}");
        assert_eq!(iter["tasks_pending"].as_u64(), Some(0), "{iter}");
    }

    // Evidence anchor covers warmup plus one report per iteration.
    let reports = anchor["reports"].as_array().expect("reports list");
    assert_eq!(
        reports.len(),
        iters.len() + 1,
        "warmup + one report per iter"
    );
    assert!(reports
        .iter()
        .any(|r| r["name"].as_str() == Some("warmup.json")));
    for report in reports {
        let sha = report["sha256"].as_str().expect("report sha");
        assert!(is_hex(sha, 64), "report sha: {sha}");
        assert!(report["bytes"].as_u64().expect("report len") > 0);
    }

    // Sustained window: >= 30 measured seconds, RSS + CPU bounds re-checked.
    let sustained = one(&records, "sustained");
    let measured = sustained["measured_wall_s"]
        .as_f64()
        .expect("measured wall");
    assert!(measured >= MIN_MEASURED_S, "measured {measured}s >= 30s");
    assert_eq!(sustained["iters"].as_u64(), Some(iters.len() as u64));
    let peak = sustained["child_peak_rss_bytes"]
        .as_u64()
        .expect("child peak RSS measured");
    assert!(peak <= RSS_TARGET_BYTES, "peak RSS {peak} <= 256 MiB");
    assert!(peak > 0, "peak RSS is a real sample");
    let cores = sustained["mean_cores"]
        .as_f64()
        .expect("mean cores measured");
    assert!(cores <= CPU_BOUND_CORES, "mean {cores} cores <= 1.1");
    assert!(cores >= 0.0, "mean cores non-negative");
    assert!(sustained["total_entries"].as_u64().expect("entries") > 0);
    assert!(sustained["total_tx"].as_u64().expect("tx") > 0);
    assert_eq!(sustained["verdict"].as_bool(), Some(true));

    // Queue bounds held across the window.
    let queue = one(&records, "queue_bounds");
    assert_eq!(queue["static_prefetch_ok"].as_bool(), Some(true));
    assert_eq!(queue["tasks_pending_final"].as_u64(), Some(0));
    assert_eq!(queue["tasks_pending_max"].as_u64(), Some(0));
    assert_eq!(queue["verdict"].as_bool(), Some(true));

    // Pressure injection (PERF-03): every sub-proof true.
    let pressure = one(&records, "pressure");
    for flag in [
        "stops_admission",
        "prefetch_stopped",
        "spawn_stopped",
        "pending_preserved",
        "no_false_clean",
        "cpu_accounting_retained",
        "helper_cap_held",
        "resumable_after",
        "bounded_footprint",
    ] {
        assert_eq!(pressure[flag].as_bool(), Some(true), "{flag}");
    }
    assert_eq!(pressure["verdict"].as_bool(), Some(true));

    // Top-level verdict agrees with the re-checked bounds.
    let verdict = one(&records, "verdict");
    assert_eq!(verdict["perf02_pass"].as_bool(), Some(true));
    assert_eq!(verdict["queue_pass"].as_bool(), Some(true));
    assert_eq!(verdict["perf03_pass"].as_bool(), Some(true));
    assert_eq!(verdict["pass"].as_bool(), Some(true));
    assert_eq!(verdict["timeout"].as_bool(), Some(false));
}

/// RSF-PERF-BLOCKED-TEST-001: a zero corpus budget must FAIL the gate
/// fast (exit 1 with a `phase_timeout` record + hashed evidence), never
/// hang and never skip. Behavioral regression test for harness timeouts.
#[test]
fn perf_gates_corpus_timeout_fails() {
    if !git_available() {
        panic!("timeout test needs git (harness corpus); failing, never skipping");
    }
    let (harness, repo_scan, _) = build_harness();
    let results = tempfile::tempdir().expect("tempdir");
    let mut cmd = Command::new(&harness);
    cmd.env("BENCH_RESULTS", results.path())
        .env("CARGO_BIN_EXE_repo-scan", &repo_scan)
        .env("PERF_GATES_CORPUS_BUDGET_S", "0")
        .current_dir(manifest_dir());
    let run = run_with_timeout(cmd, TIMEOUT_TEST_TIMEOUT, "perf_gates timeout probe")
        .unwrap_or_else(|e| panic!("timeout probe itself hung:\n{e}"));
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    let dir = evidence_dir("perf-timeout");
    let evidence = write_evidence(
        &dir,
        "perf_gates_corpus_timeout_fails",
        Some(0),
        run.status.code(),
        &run.stdout,
        &run.stderr,
        &results.path().join("perf_gates.jsonl"),
    );
    assert_eq!(
        run.status.code(),
        Some(1),
        "timeout exits 1, stdout: {stdout}"
    );
    assert_eq!(evidence["TEST_EXIT"].as_i64(), Some(1));
    assert!(
        stdout.contains("TEST_EXIT=1"),
        "tee'd stdout carries TEST_EXIT=1: {stdout}"
    );
    let records = load_jsonl(&dir.join("perf_gates.jsonl"));
    let timeout = one(&records, "phase_timeout");
    assert_eq!(timeout["phase"].as_str(), Some("corpus"));
    assert_eq!(timeout["timeout"].as_bool(), Some(true));
    assert_eq!(timeout["verdict"].as_bool(), Some(false));
    let verdict = one(&records, "verdict");
    assert_eq!(verdict["pass"].as_bool(), Some(false));
    assert_eq!(verdict["timeout"].as_bool(), Some(true));
    assert_eq!(verdict["timeout_phase"].as_str(), Some("corpus"));
    let anchor = one(&records, "evidence");
    let pre = anchor["jsonl_sha256_pre"].as_str().expect("pre hash");
    assert!(
        is_hex(pre, 64),
        "evidence pre hash present on timeout: {pre}"
    );
    // Build fingerprint is recorded even on the timeout path.
    assert_eq!(
        one(&records, "build_evidence")["record"].as_str(),
        Some("build_evidence")
    );
}

/// RSF-CHAINARGOS-PROGRESS-002: while the frontier denominator grows the
/// production ETA is an explicit unknown naming the growth — never a
/// `~Ns` estimate over a moving denominator. A stable denominator keeps
/// the lower-bound estimate; `pending == 0` keeps `0s`.
#[test]
fn progress_eta_unknown_while_denominator_grows() {
    let growing = main_under_test::test_format_eta_growth(100, 50, 10, true, 37);
    assert!(
        growing.starts_with("unknown (frontier denominator still growing")
            && growing.contains("+37 tasks since last tick")
            && growing.contains("no stable total until discovery completes"),
        "explicit unknown with growth reason: {growing}"
    );
    assert!(
        !growing.contains("~5s"),
        "no estimate over a moving denominator: {growing}"
    );
    let stable = main_under_test::test_format_eta_growth(100, 50, 10, false, 0);
    assert_eq!(
        stable,
        main_under_test::test_format_eta(100, 50, 10),
        "stable denominator delegates to the lower-bound estimate",
    );
    assert_eq!(
        stable, "~5s (lower bound; denominator grows with discovery)",
        "stable estimate keeps its contract: {stable}",
    );
    assert_eq!(
        main_under_test::test_format_eta_growth(100, 0, 10, true, 37),
        "0s",
        "nothing pending still reports 0s",
    );

    let line = main_under_test::test_format_progress_full_growth(
        100,
        90,
        1000,
        1,
        50,
        150,
        90,
        1000,
        10,
        "dir:/tmp/x",
        "dev:123",
        true,
        37,
    );
    for needle in [
        "tasks_done=100/150",
        "pending=50",
        "eta=unknown (frontier denominator still growing",
        "denominator=growing(+37 since last tick)",
    ] {
        assert!(
            line.contains(needle),
            "growing line carries {needle}: {line}"
        );
    }
    let calm = main_under_test::test_format_progress_full_growth(
        100,
        90,
        1000,
        1,
        50,
        150,
        90,
        1000,
        10,
        "dir:/tmp/x",
        "dev:123",
        false,
        0,
    );
    for needle in ["eta=~5s", "denominator=stable(since last tick)"] {
        assert!(
            calm.contains(needle),
            "stable line carries {needle}: {calm}"
        );
    }
}

#[cfg(unix)]
fn echo_cmd() -> Command {
    let mut cmd = Command::new("echo");
    cmd.arg("evidence-plumbing");
    cmd
}

#[cfg(unix)]
fn sleep_cmd(secs: &str) -> Command {
    let mut cmd = Command::new("sleep");
    cmd.arg(secs);
    cmd
}

#[cfg(windows)]
fn echo_cmd() -> Command {
    let mut cmd = Command::new("cmd");
    cmd.args(["/c", "echo", "evidence-plumbing"]);
    cmd
}

#[cfg(windows)]
fn sleep_cmd(secs: &str) -> Command {
    let mut cmd = Command::new("ping");
    cmd.args(["-n", secs, "127.0.0.1"]);
    cmd
}

/// Evidence plumbing: a fast command succeeds with captured output, a
/// slow command reports a timeout (the caller fails), and file hashing
/// matches the direct digest (known SHA-256 vector included).
#[cfg(any(unix, windows))]
#[test]
fn evidence_helpers_timeout_and_hash() {
    let ok = run_with_timeout(echo_cmd(), Duration::from_secs(30), "echo")
        .expect("fast command succeeds");
    assert!(ok.status.success());
    assert!(
        String::from_utf8_lossy(&ok.stdout).contains("evidence-plumbing"),
        "output captured"
    );
    let err = run_with_timeout(sleep_cmd("30"), Duration::from_secs(2), "sleep-probe")
        .expect_err("slow command must report a timeout");
    assert!(err.contains("exceeded 2s timeout"), "timeout report: {err}");

    // Pipe-buffer flood: output far beyond 64 KiB must be captured
    // completely, never deadlock the wait loop.
    #[cfg(unix)]
    {
        let mut flood = Command::new("seq");
        flood.args(["1", "100000"]);
        let out = run_with_timeout(flood, Duration::from_secs(30), "flood")
            .expect("large output must not deadlock");
        assert!(out.status.success());
        assert!(
            out.stdout.len() > 256 * 1024,
            "flood size: {}",
            out.stdout.len()
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).ends_with("100000\n"),
            "flood captured to the last line"
        );
    }

    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-256 known vector",
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = tmp.path().join("sample.jsonl");
    repo_scan::privacy::private_write_0600(&file, b"{\"record\":\"env\"}\n").expect("write sample");
    let bytes = std::fs::read(&file).expect("read sample");
    assert_eq!(sha256_hex(&bytes), sha256_hex(b"{\"record\":\"env\"}\n"));
}
