//! PERF-02/03 acceptance (spec §17): build the `perf_gates` harness, run it
//! once into a tempdir, and assert exit 0 plus the JSONL verdict records and
//! numeric bounds. Bounds are re-checked here from the raw numbers, never
//! taken on the harness's word alone.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// Declared corpus shape (must match the harness record).
const FLAT_FILES: u64 = 2000;
const DEEP_LEVELS: u64 = 40;
const TOTAL_REPO_BUILDS: u64 = 200;
const LINKED_WORKTREES: u64 = 10;
/// Spec §5/§18 bounds, re-asserted from raw samples.
const RSS_TARGET_BYTES: u64 = 256 * 1024 * 1024;
const CPU_BOUND_CORES: f64 = 1.1;
const MIN_MEASURED_S: f64 = 30.0;

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

#[test]
fn perf_02_03_gates_hold() {
    if !git_available() {
        eprintln!("perf gates: git is missing; skipping");
        return;
    }
    let manifest = manifest_dir();
    let build = Command::new(cargo_bin())
        .args(["build", "--bench", "perf_gates", "--message-format=json"])
        .current_dir(&manifest)
        .output()
        .expect("spawn cargo build");
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

    let results = tempfile::tempdir().expect("tempdir");
    let run = Command::new(&harness)
        .env("BENCH_RESULTS", results.path())
        .env("CARGO_BIN_EXE_repo-scan", &repo_scan)
        .current_dir(&manifest)
        .output()
        .expect("spawn perf_gates");
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
    assert_eq!(
        run.status.code(),
        Some(0),
        "perf_gates failed\nstdout tail: {}\nstderr tail: {}",
        tail(&stdout, 2000),
        tail(&stderr, 2000),
    );

    let records = load_jsonl(&results.path().join("perf_gates.jsonl"));
    assert!(!records.is_empty(), "harness wrote records");
    let env = one(&records, "env");
    assert_eq!(env["bench"].as_str(), Some("perf_gates"));

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
}
