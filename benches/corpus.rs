//! Step 16 measurement corpus builder: a developer-machine-like tree with
//! at least 100,000 directories, 1,000,000 files, and 200 Git stores,
//! plus deep/wide shapes, linked worktrees, a submodule, bare stores,
//! and nested/hidden/cache/node_modules placements. Deterministic layout;
//! every expected store path lands in `manifest.json`.
//!
//! Run: `CORPUS_DIR=/path/to/corpus cargo bench --bench corpus`.
//! Refuses to run into an existing `ws/` dir (no double-counts).

#[path = "support.rs"]
mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Full-shape wide tree: 400 x 250 leaves x 10 files = 1M files;
/// every 500th leaf a store = 200 stores. `CORPUS_SMALL=1` shrinks all
/// of these for a fast builder smoke run (minimums scale with it).
struct Shape {
    groups: usize,
    leaves_per_group: usize,
    files_per_leaf: usize,
    repo_every: usize,
    deep_levels: usize,
    wide_single_files: usize,
    min_dirs: u64,
    min_files: u64,
    min_stores: usize,
}

fn shape() -> Shape {
    if std::env::var("CORPUS_SMALL").as_deref() == Ok("1") {
        Shape {
            groups: 2,
            leaves_per_group: 6,
            files_per_leaf: 4,
            repo_every: 6,
            deep_levels: 5,
            wide_single_files: 50,
            min_dirs: 20,
            min_files: 100,
            min_stores: 15,
        }
    } else {
        Shape {
            groups: 400,
            leaves_per_group: 250,
            files_per_leaf: 10,
            repo_every: 500,
            deep_levels: 300,
            wide_single_files: 30_000,
            min_dirs: 100_000,
            min_files: 1_000_000,
            min_stores: 200,
        }
    }
}

/// File-creation parallelism (git seeding rides along inline).
const FILE_THREADS: usize = 32;

struct Counts {
    dirs: AtomicU64,
    files: AtomicU64,
}

fn write_file(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// Seed a repo with one commit on main and a distinct bench remote.
fn seed_remote_repo(dir: &Path, owner: &str, repo: &str) {
    support::seed_repo(
        dir.parent().expect("parent"),
        dir.file_name().expect("name").to_str().expect("utf8"),
    );
    let url = format!("https://github.com/{owner}/{repo}.git");
    support::git(dir, &["remote", "add", "origin", &url]);
}

fn main() {
    let corpus = std::env::var("CORPUS_DIR").expect("CORPUS_DIR must point at the corpus root");
    let corpus = PathBuf::from(corpus);
    let ws = corpus.join("ws");
    assert!(
        !ws.exists(),
        "refusing to build into existing {} (wipe it first)",
        ws.display()
    );
    fs::create_dir_all(&ws).expect("ws root");
    let sh = shape();
    let counts = Arc::new(Counts {
        dirs: AtomicU64::new(1),
        files: AtomicU64::new(0),
    });

    // --- Wide tree: groups of leaves; every Nth leaf is a repo. ---
    let wide = ws.join("wide");
    fs::create_dir_all(&wide).expect("wide root");
    counts.dirs.fetch_add(1, Ordering::Relaxed);
    // Create groups serially (cheap), leaves+files in parallel by group.
    let mut group_names = Vec::with_capacity(sh.groups);
    for g in 0..sh.groups {
        let name = format!("g{g:04}");
        fs::create_dir_all(wide.join(&name)).expect("group dir");
        group_names.push(name);
    }
    counts.dirs.fetch_add(sh.groups as u64, Ordering::Relaxed);
    let chunk = sh.groups.div_ceil(FILE_THREADS).max(1);
    std::thread::scope(|s| {
        for (t, names) in group_names.chunks(chunk).enumerate() {
            let wide = &wide;
            let counts = Arc::clone(&counts);
            s.spawn(move || {
                let mut repo_paths = Vec::new();
                for name in names {
                    let g: usize = name[1..].parse().expect("group num");
                    for l in 0..sh.leaves_per_group {
                        let leaf = wide.join(name).join(format!("l{l:04}"));
                        fs::create_dir_all(&leaf).expect("leaf dir");
                        let global = g * sh.leaves_per_group + l;
                        if global % sh.repo_every == 0 {
                            repo_paths.push((global, leaf));
                        } else {
                            for f in 0..sh.files_per_leaf {
                                write_file(&leaf.join(format!("f{f:02}.txt")), b"bench-data\n");
                            }
                            counts
                                .files
                                .fetch_add(sh.files_per_leaf as u64, Ordering::Relaxed);
                        }
                    }
                    counts
                        .dirs
                        .fetch_add(sh.leaves_per_group as u64, Ordering::Relaxed);
                }
                // Seed this thread's repos (git CLI, hermetic env).
                for (global, leaf) in &repo_paths {
                    let owner = format!("bench-o{:03}", global % 100);
                    let repo = format!("bench-r{global:06}");
                    // Replace the plain leaf with a repo of the same name.
                    fs::remove_dir(leaf).expect("drop placeholder leaf");
                    seed_remote_repo(leaf, &owner, &repo);
                    for f in 0..sh.files_per_leaf {
                        write_file(&leaf.join(format!("f{f:02}.txt")), b"bench-data\n");
                    }
                    counts
                        .files
                        .fetch_add(sh.files_per_leaf as u64 + 1, Ordering::Relaxed);
                }
                eprintln!("corpus: file thread {t} done ({} repos)", repo_paths.len());
            });
        }
    });

    // --- Deep chain, wide-single dir. ---
    let mut deep = ws.join("deep");
    fs::create_dir_all(&deep).expect("deep root");
    counts.dirs.fetch_add(1, Ordering::Relaxed);
    for d in 0..sh.deep_levels {
        deep = deep.join(format!("c{d:03}"));
        fs::create_dir_all(&deep).expect("deep level");
        write_file(&deep.join("level.txt"), b"deep\n");
    }
    counts
        .dirs
        .fetch_add(sh.deep_levels as u64, Ordering::Relaxed);
    counts
        .files
        .fetch_add(sh.deep_levels as u64, Ordering::Relaxed);
    let wide_single = ws.join("wide_single");
    fs::create_dir_all(&wide_single).expect("wide_single");
    counts.dirs.fetch_add(1, Ordering::Relaxed);
    std::thread::scope(|s| {
        let chunk = sh.wide_single_files.div_ceil(FILE_THREADS);
        for t in 0..FILE_THREADS {
            let wide_single = &wide_single;
            let counts = Arc::clone(&counts);
            s.spawn(move || {
                let start = (t * chunk).min(sh.wide_single_files);
                let end = (start + chunk).min(sh.wide_single_files);
                for i in start..end {
                    write_file(&wide_single.join(format!("w{i:05}.dat")), b"wide\n");
                }
                counts
                    .files
                    .fetch_add((end - start) as u64, Ordering::Relaxed);
            });
        }
    });

    // --- Special placements (serial; git ops dominate, few of them). ---
    let special = ws.join("special");
    fs::create_dir_all(&special).expect("special");
    counts.dirs.fetch_add(1, Ordering::Relaxed);
    let mut expected: Vec<String> = Vec::new();
    // Wide-tree repos (deterministic names).
    for global in (0..sh.groups * sh.leaves_per_group).step_by(sh.repo_every) {
        let g = global / sh.leaves_per_group;
        let l = global % sh.leaves_per_group;
        expected.push(format!("ws/wide/g{g:04}/l{l:04}"));
    }
    let rel = |p: &Path| {
        p.strip_prefix(&corpus)
            .expect("under corpus")
            .to_str()
            .expect("utf8")
            .to_string()
    };
    // Nested pair.
    let outer = special.join("nested_outer");
    seed_remote_repo(&outer, "bench-special", "nested-outer");
    let inner = outer.join("vendor").join("inner_repo");
    fs::create_dir_all(inner.parent().expect("vendor")).expect("vendor");
    counts.dirs.fetch_add(1, Ordering::Relaxed);
    seed_remote_repo(&inner, "bench-special", "nested-inner");
    expected.push(rel(&outer));
    expected.push(rel(&inner));
    // Bare stores under arbitrary names.
    for (name, repo) in [("bare_one.store", "bare-one"), ("bare_two", "bare-two")] {
        let bare = special.join(name);
        support::git(&special, &["init", "-q", "--bare", name]);
        let seed = special.join(format!(".seed-{repo}"));
        fs::create_dir_all(&seed).expect("seed");
        support::git(&seed, &["init", "-q"]);
        write_file(&seed.join("seed.txt"), b"seed\n");
        support::git(&seed, &["add", "--", "seed.txt"]);
        support::git(&seed, &["commit", "-q", "-m", "seed"]);
        support::git(&seed, &["branch", "-M", "main"]);
        support::git(
            &seed,
            &["push", "-q", bare.to_str().expect("utf8"), "main:main"],
        );
        support::git(&bare, &["symbolic-ref", "HEAD", "refs/heads/main"]);
        fs::remove_dir_all(&seed).expect("drop seed");
        expected.push(rel(&bare));
    }
    // Worktree family: main + 3 linked.
    let family = special.join("family");
    seed_remote_repo(&family, "bench-special", "family");
    for w in 0..3 {
        support::git(&family, &["branch", &format!("wt{w}")]);
        support::git(
            &family,
            &[
                "worktree",
                "add",
                family
                    .join(format!("../family-wt{w}"))
                    .to_str()
                    .expect("utf8"),
                &format!("wt{w}"),
            ],
        );
    }
    expected.push(rel(&family));
    // Submodule pair.
    let sub_src = special.join("sub_src");
    seed_remote_repo(&sub_src, "bench-special", "sub-src");
    let super_repo = special.join("super");
    seed_remote_repo(&super_repo, "bench-special", "super");
    support::git(
        &super_repo,
        &[
            "submodule",
            "add",
            "-q",
            sub_src.to_str().expect("utf8"),
            "sub",
        ],
    );
    support::git(&super_repo, &["commit", "-q", "-m", "add sub"]);
    expected.push(rel(&sub_src));
    expected.push(rel(&super_repo));
    // node_modules / hidden / cache / tmp placements.
    let nm = special.join("node_modules").join("pkg").join("deep_repo");
    fs::create_dir_all(nm.parent().expect("pkg")).expect("nm parents");
    counts.dirs.fetch_add(2, Ordering::Relaxed);
    seed_remote_repo(&nm, "bench-special", "nm-deep");
    expected.push(rel(&nm));
    for (name, repo) in [
        (".hidden_repo", "hidden"),
        ("cache_like", "cache-like"),
        ("tmp_like", "tmp-like"),
    ] {
        let dir = special.join(name);
        seed_remote_repo(&dir, "bench-special", repo);
        expected.push(rel(&dir));
    }
    // Branchy (5 x 4 branches) + dirty + unborn.
    for b in 0..5 {
        let dir = special.join(format!("branchy_{b}"));
        seed_remote_repo(&dir, "bench-special", &format!("branchy-{b}"));
        for br in 0..3 {
            support::git(&dir, &["branch", &format!("feat-{br}")]);
        }
        expected.push(rel(&dir));
    }
    let dirty = special.join("dirty_repo");
    seed_remote_repo(&dirty, "bench-special", "dirty");
    write_file(&dirty.join("dirty.txt"), b"uncommitted\n");
    expected.push(rel(&dirty));
    let unborn = special.join("unborn_repo");
    fs::create_dir_all(&unborn).expect("unborn");
    support::git(&unborn, &["init", "-q"]);
    expected.push(rel(&unborn));

    // --- Manifest + minimums. ---
    let dirs = counts.dirs.load(Ordering::Relaxed);
    let files = counts.files.load(Ordering::Relaxed);
    // NOTE: .git internals add uncounted dirs/files; the tracked counts
    // below are the corpus shape itself, hence a lower bound on reality.
    assert!(dirs >= sh.min_dirs, "dirs {dirs} < {}", sh.min_dirs);
    assert!(files >= sh.min_files, "files {files} < {}", sh.min_files);
    assert!(
        expected.len() >= sh.min_stores,
        "stores {} < {}",
        expected.len(),
        sh.min_stores
    );
    let manifest = serde_json::json!({
        "version": 1,
        "root": ws.to_str().expect("utf8"),
        "tracked_dirs": dirs,
        "tracked_files": files,
        "expected_stores": expected.len(),
        "expected_stores_paths": expected,
        "notes": [
            "wide/: 400x250 leaves, 10 files each, every 500th leaf a git store",
            "deep/: 300-level chain; wide_single/: 30000 files in one dir",
            "special/: nested pair, 2 bare, worktree family (main+3), submodule pair, node_modules/hidden/cache/tmp, 5 branchy, dirty, unborn",
            "recall: scans find one more store than listed (the embedded submodule clone at super/sub)",
            ".git internals are NOT in tracked counts; find(1) totals will exceed them",
        ],
    });
    let manifest_path = corpus.join("manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("json"),
    )
    .expect("manifest");
    println!(
        "corpus ready: {} tracked dirs, {} tracked files, {} expected stores\nmanifest: {}",
        dirs,
        files,
        expected.len(),
        manifest_path.display()
    );
}
