//! Shared benchmark harness support (spec §18).
//!
//! Plain `fn main` harnesses (no criterion dependency): every measurement is
//! appended as one JSON object per line to `benches/results/<bench>.jsonl`,
//! recorded on run — never invented. Each file starts with an `env` record
//! carrying hardware, OS, build, and dependency versions, then one record per
//! measurement.
//!
//! The git runner here is a minimal copy of `tests/common/fixture.rs` (bench
//! targets cannot import integration-test helpers).
//!
//! Each bench binary includes this file separately and uses only a subset;
//! per-binary unused warnings would be noise, so dead code is allowed here
//! by design.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// Append-only JSONL recorder. The results directory is created on open.
pub struct Recorder {
    out: BufWriter<File>,
    path: PathBuf,
}

impl Recorder {
    /// Open (creating parents) and immediately write the `env` record so
    /// every results file is self-describing even if a phase aborts.
    pub fn open(results_dir: &Path, bench: &str) -> Self {
        fs::create_dir_all(results_dir).expect("create results dir");
        let path = results_dir.join(format!("{bench}.jsonl"));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
        let mut recorder = Self {
            out: BufWriter::new(file),
            path,
        };
        recorder.record(&env_record(bench));
        recorder
    }

    /// Append one JSON object line and flush (a killed bench keeps its prefix).
    pub fn record(&mut self, value: &serde_json::Value) {
        serde_json::to_writer(&mut self.out, value).expect("serialize record");
        self.out.write_all(b"\n").expect("write record");
        self.out.flush().expect("flush record");
    }

    /// Results file path, for the final human-readable summary line.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Self-describing run header: recorded versions only, no claims.
pub fn env_record(bench: &str) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("record".into(), "env".into());
    map.insert("bench".into(), bench.into());
    map.insert(
        "repo_scan_version".into(),
        repo_scan::version().to_string().into(),
    );
    map.insert("os".into(), std::env::consts::OS.into());
    map.insert("arch".into(), std::env::consts::ARCH.into());
    map.insert("dua_core".into(), "4.1.0".into());
    map.insert("turso".into(), "0.8.1".into());
    #[cfg(debug_assertions)]
    map.insert("profile".into(), "debug".into());
    #[cfg(not(debug_assertions))]
    map.insert("profile".into(), "release".into());
    serde_json::Value::Object(map)
}

/// Wall-clock helper returning elapsed milliseconds as f64.
pub fn wall_ms(start: &Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

/// Peak RSS of this process in bytes via `getrusage` (Unix only).
/// macOS reports bytes, Linux kilobytes — normalized here.
#[cfg(unix)]
pub fn peak_rss_bytes() -> Option<u64> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return None;
    }
    #[cfg(target_os = "macos")]
    let bytes = usage.ru_maxrss as u64;
    #[cfg(target_os = "linux")]
    let bytes = usage.ru_maxrss as u64 * 1024;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let bytes = usage.ru_maxrss as u64;
    Some(bytes)
}

/// Peak RSS is unavailable off Unix.
#[cfg(not(unix))]
pub fn peak_rss_bytes() -> Option<u64> {
    None
}

/// Results directory: `$BENCH_RESULTS` or `benches/results` under the crate root.
pub fn results_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("BENCH_RESULTS") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("results")
}

/// Run `git` in `dir` with the hermetic fixture environment. Panics loudly
/// with command + stderr on failure.
pub fn git(dir: &Path, args: &[&str]) {
    let null = if cfg!(unix) { "/dev/null" } else { "NUL" };
    let output = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", null)
        .env("GIT_CONFIG_SYSTEM", null)
        .env("GIT_AUTHOR_NAME", "repo-scan-bench")
        .env("GIT_AUTHOR_EMAIL", "bench@example.invalid")
        .env("GIT_COMMITTER_NAME", "repo-scan-bench")
        .env("GIT_COMMITTER_EMAIL", "bench@example.invalid")
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-c")
        .arg("user.name=repo-scan-bench")
        .arg("-c")
        .arg("user.email=bench@example.invalid")
        .arg("-c")
        .arg("init.defaultBranch=main")
        .arg("-c")
        .arg("commit.gpgsign=false")
        .arg("-c")
        .arg("protocol.file.allow=always")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn git {args:?}: {e}"));
    assert!(
        output.status.success(),
        "git {args:?} in {} failed: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Seed one committed repo with `main` branch at `parent/name`.
pub fn seed_repo(parent: &Path, name: &str) -> PathBuf {
    let dir = parent.join(name);
    fs::create_dir_all(&dir).expect("seed repo dir");
    git(&dir, &["init", "-q"]);
    fs::write(dir.join("file.txt"), b"bench\n").expect("seed file");
    git(&dir, &["add", "--", "file.txt"]);
    git(&dir, &["commit", "-q", "-m", "seed"]);
    git(&dir, &["branch", "-M", "main"]);
    dir
}

/// Outcome of one full-scope traversal pass.
#[derive(Debug, Default)]
pub struct TraversalOutcome {
    /// Directories successfully opened.
    pub dirs: u64,
    /// Child entries observed (all backends, all kinds).
    pub entries: u64,
    /// Directory-open failures plus mid-enumeration errors.
    pub errors: u64,
    /// Per-directory sorted child-name multiset, for cross-backend equivalence.
    pub digests: BTreeMap<PathBuf, Vec<String>>,
}

/// Breadth-first traversal of `root` through one adapter: immediate children
/// only per call, subdirectories queued by the harness (never backend
/// recursion), symlinks never followed. Bounded by `entry_cap`.
pub fn traverse(
    adapter: &dyn repo_scan::walk::OneDirAdapter,
    root: &Path,
    entry_cap: u64,
) -> TraversalOutcome {
    use repo_scan::walk::{ChildKind, ListOptions};
    let mut outcome = TraversalOutcome::default();
    let mut queue = std::collections::VecDeque::from([root.to_path_buf()]);
    while let Some(dir) = queue.pop_front() {
        let items = match adapter.list_dir(&dir, ListOptions::default()) {
            Ok(items) => items,
            Err(_) => {
                outcome.errors += 1;
                continue;
            }
        };
        outcome.dirs += 1;
        let mut names = Vec::new();
        for item in items {
            if outcome.entries >= entry_cap {
                return outcome;
            }
            match item {
                Ok(child) => {
                    outcome.entries += 1;
                    names.push(format!("{:?}:{}", child.kind, child.name.to_string_lossy()));
                    if child.kind == ChildKind::Directory {
                        queue.push_back(dir.join(&child.name));
                    }
                }
                Err(_) => outcome.errors += 1,
            }
        }
        names.sort();
        outcome.digests.insert(dir, names);
    }
    outcome
}
