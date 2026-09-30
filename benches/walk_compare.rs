//! Adapter comparison benchmark (spec §18): `dua` vs `ignore` vs `std-escape`
//! over one identical scope. Records wall time, entries, and errors per
//! backend plus a cross-backend equivalence verdict. A backend that skips
//! hidden paths or nested repos fails the comparison regardless of speed.
//!
//! Run: `cargo bench --bench walk_compare`. Results append to
//! `benches/results/walk_compare.jsonl` (override with `$BENCH_RESULTS`).

#[path = "support.rs"]
mod support;

use std::fs;
use std::time::Instant;
use support::Recorder;

/// Build the shared comparison scope: hidden/tmp/cache repos, a bare store
/// with an arbitrary name, a linked worktree, a nested repo, a flat
/// directory, a deep chain, and (Unix) a non-UTF-8 name.
fn build_scope(holder: &tempfile::TempDir) -> std::path::PathBuf {
    let scope = holder.path().join("scope");
    fs::create_dir_all(&scope).expect("scope root");
    for rel in [".hidden", "tmp/scratch", ".cache/tool", "target/debug"] {
        let parent = scope.join(rel);
        fs::create_dir_all(&parent).expect("scope parent");
        support::seed_repo(&parent, "repo");
    }
    support::seed_repo(&scope, "outer");
    let outer = scope.join("outer");
    support::seed_repo(&outer, "inner");
    let recovery = outer.join(".git/recovery");
    fs::create_dir_all(&recovery).expect("recovery dir");
    support::seed_repo(&recovery, "salvaged");

    let bare = scope.join("store.backup");
    support::git(&scope, &["init", "-q", "--bare", "store.backup"]);
    let seed = scope.join("seed-src");
    support::seed_repo(&scope, "seed-src");
    let bare_arg = bare.to_string_lossy().into_owned();
    support::git(&seed, &["push", "-q", &bare_arg, "main:main"]);
    fs::remove_dir_all(&seed).expect("remove seed scratch");

    support::git(&outer, &["worktree", "add", "--detach", "../wt-feature"]);

    let flat = scope.join("flat");
    fs::create_dir_all(&flat).expect("flat dir");
    for i in 0..500 {
        fs::write(flat.join(format!("f{i:04}")), b"x").expect("flat file");
    }
    let mut deep = scope.join("deep");
    fs::create_dir_all(&deep).expect("deep top");
    for i in 0..32 {
        deep = deep.join(format!("d{i:02}"));
        fs::create_dir(&deep).expect("deep level");
    }
    fs::write(deep.join("bottom.txt"), b"bottom\n").expect("deep marker");

    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        // APFS rejects invalid-UTF-8 names (EILSEQ): probe first and skip
        // loudly where the filesystem cannot represent them, mirroring the
        // acceptance tests.
        let weird = scope.join(OsString::from_vec(b"bad-\xff-dir".to_vec()));
        if fs::create_dir(&weird).is_err() {
            eprintln!("walk_compare: filesystem rejects non-UTF-8 names; skipping");
        } else {
            fs::write(
                weird.join(OsString::from_vec(b"ctrl-\x01.txt".to_vec())),
                b"x",
            )
            .expect("non-utf8 file");
        }
    }
    scope
}

fn main() {
    let mut recorder = Recorder::open(&support::results_dir(), "walk_compare");
    let holder = tempfile::TempDir::new().expect("bench scratch");
    let root = build_scope(&holder);
    const ENTRY_CAP: u64 = 500_000;

    let mut adapters: Vec<Box<dyn repo_scan::walk::OneDirAdapter>> = vec![
        Box::new(repo_scan::walk::IgnoreAdapter),
        Box::new(repo_scan::walk::StdEscape),
    ];
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    adapters.push(Box::new(repo_scan::walk::DuaAdapter));

    let mut baseline: Option<support::TraversalOutcome> = None;
    let mut all_equivalent = true;
    for adapter in &adapters {
        let start = Instant::now();
        let outcome = support::traverse(adapter.as_ref(), &root, ENTRY_CAP);
        let elapsed = support::wall_ms(&start);
        let equivalent = match &baseline {
            None => true,
            Some(first) => {
                first.dirs == outcome.dirs
                    && first.entries == outcome.entries
                    && first.errors == outcome.errors
                    && first.digests == outcome.digests
            }
        };
        all_equivalent &= equivalent;
        if baseline.is_none() {
            baseline = Some(outcome);
            let first = baseline.as_ref().expect("just stored");
            recorder.record(&serde_json::json!({
                "record": "adapter",
                "adapter": adapter.name(),
                "wall_ms": elapsed,
                "dirs": first.dirs,
                "entries": first.entries,
                "errors": first.errors,
                "equivalent_to_baseline": true,
                "peak_rss_bytes": support::peak_rss_bytes(),
            }));
        } else {
            recorder.record(&serde_json::json!({
                "record": "adapter",
                "adapter": adapter.name(),
                "wall_ms": elapsed,
                "dirs": outcome.dirs,
                "entries": outcome.entries,
                "errors": outcome.errors,
                "equivalent_to_baseline": equivalent,
                "peak_rss_bytes": support::peak_rss_bytes(),
            }));
        }
    }
    let first = baseline.as_ref().expect("at least one adapter ran");
    recorder.record(&serde_json::json!({
        "record": "verdict",
        "adapters": adapters.iter().map(|a| a.name()).collect::<Vec<_>>(),
        "equivalent": all_equivalent,
        "baseline_dirs": first.dirs,
        "baseline_entries": first.entries,
        "baseline_errors": first.errors,
    }));
    println!("walk_compare: results at {}", recorder.path().display());
    if !all_equivalent {
        eprintln!("walk_compare: BACKEND MISMATCH — see verdict record");
        std::process::exit(1);
    }
}
