//! Filesystem acceptance (spec §17: FS-01..05). End-to-end runs of the
//! built binary in tempdirs with explicit `--root`/`--state-dir` only —
//! never a whole-machine scan — plus library-adapter equivalence for the
//! traversal backends (the CLI exposes no `--traversal` flag, so FS-05
//! exercises the adapters directly).
//!
//! FS-01: hidden/tmp/cache/nested/`.git`-recovery layouts found. FS-02:
//! arbitrary-name bare stores, `.git` pointer files, external common dirs,
//! detached checkouts, outside-root worktrees. FS-03: symlink cycles, path
//! replacement, no duplicate instances. FS-04: non-UTF-8 + control chars
//! round-trip JSON with safe terminal output. FS-05: huge-flat + deep
//! fixtures stay bounded with equivalent backends.

mod common;

use common::fixture;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

const URL: &str = "https://github.com/OWNER/REPO";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Run the binary with `--state-dir <state>` from `cwd`.
fn run(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    ProcCommand::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

/// Scan exactly `root` into `report_name` under `cwd`. Returns the output.
fn scan_root(root: &Path, report_name: &str, cwd: &Path, state: &Path) -> std::process::Output {
    let root_str = root.to_str().expect("utf8 root").to_string();
    run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            report_name,
        ],
        cwd,
        state,
    )
}

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn read_report(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("report is valid JSON")
}

/// Decode one standard-Base64 value (spec §16 path encoding).
fn base64_decode(text: &str) -> Vec<u8> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => None,
            _ => panic!("bad base64 byte: {byte}"),
        }
    }
    let bytes = text.as_bytes();
    assert_eq!(bytes.len() % 4, 0, "base64 length");
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().rev().take_while(|b| **b == b'=').count();
        let mut n = 0u32;
        for (i, byte) in chunk.iter().enumerate() {
            if *byte != b'=' {
                n |= u32::from(value(*byte).expect("base64 alphabet")) << (18 - 6 * i);
            }
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    out
}

/// Exact bytes behind one spec §16 path/`EncodedName` value object.
fn decoded_value(entry: &serde_json::Value) -> Vec<u8> {
    let encoding = entry["encoding"].as_str().expect("encoding");
    let value = entry["value"].as_str().expect("value");
    match encoding {
        "utf8" => value.as_bytes().to_vec(),
        "base64" => base64_decode(value),
        other => panic!("unknown encoding: {other}"),
    }
}

/// Report `path id -> exact bytes` table.
fn path_table(report: &serde_json::Value) -> HashMap<String, Vec<u8>> {
    let mut table = HashMap::new();
    for entry in report["paths"].as_array().expect("paths") {
        let id = entry["id"].as_str().expect("path id").to_string();
        table.insert(id, decoded_value(entry));
    }
    table
}

/// Lossless expected-path bytes for comparison with report path entries.
#[cfg(unix)]
fn expected_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

/// Lossless expected-path bytes (non-unix fallback).
#[cfg(not(unix))]
fn expected_bytes(path: &Path) -> Vec<u8> {
    repo_scan::config::path_as_bytes(path)
}

struct RepoView {
    git: Vec<u8>,
    common: Vec<u8>,
    disposition: String,
}

fn repositories(report: &serde_json::Value) -> Vec<RepoView> {
    let paths = path_table(report);
    report["repositories"]
        .as_array()
        .expect("repositories")
        .iter()
        .map(|r| {
            let git_id = r["git_path_id"].as_str().expect("git_path_id");
            let common_id = r["common_path_id"].as_str().expect("common_path_id");
            RepoView {
                git: paths
                    .get(git_id)
                    .unwrap_or_else(|| panic!("path {git_id}"))
                    .clone(),
                common: paths
                    .get(common_id)
                    .unwrap_or_else(|| panic!("path {common_id}"))
                    .clone(),
                disposition: r["match"].as_str().expect("match").to_string(),
            }
        })
        .collect()
}

struct CheckoutView {
    root: Option<Vec<u8>>,
    kind: String,
    head_state: String,
}

fn checkouts(report: &serde_json::Value) -> Vec<CheckoutView> {
    let paths = path_table(report);
    report["checkouts"]
        .as_array()
        .expect("checkouts")
        .iter()
        .map(|c| CheckoutView {
            root: c["root_path_id"]
                .as_str()
                .map(|id| paths.get(id).unwrap_or_else(|| panic!("path {id}")).clone()),
            kind: c["kind"].as_str().expect("kind").to_string(),
            head_state: c["head"]["state"].as_str().expect("head.state").to_string(),
        })
        .collect()
}

/// Fresh tempdir + state dir + root fixture dir. Every scan uses explicit
/// `--root`; nothing ever scans the whole machine.
struct Env {
    _dir: tempfile::TempDir,
    state: PathBuf,
    cwd: PathBuf,
    root: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        let cwd = dir.path().join("cwd");
        repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
        let root = dir.path().join("root");
        repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
        Self {
            _dir: dir,
            state,
            cwd,
            root,
        }
    }

    fn scan(&self, root: &Path, report: &str) -> std::process::Output {
        scan_root(root, report, &self.cwd, &self.state)
    }
}

// ---------------------------------------------------------------------------
// FS-01: scope layouts found without exclusions.
// ---------------------------------------------------------------------------

#[test]
fn fs01_scope_layouts_found_without_exclusions() {
    let env = Env::new();
    let repos = fixture::scope_layouts(&env.root);
    assert_eq!(
        repos.len(),
        8,
        "hidden/tmp/cache/target/node/nested/recovery/outer"
    );
    let out = env.scan(&env.root, "rep.json");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&env.cwd.join("rep.json"));
    assert_eq!(report["scan"]["state"].as_str(), Some("complete"));
    assert_eq!(report["coverage"]["gaps"].as_u64(), Some(0));
    let found = repositories(&report);
    assert_eq!(found.len(), repos.len(), "every layout found exactly once");
    for repo in &repos {
        let git = expected_bytes(&repo.join(".git"));
        let hits: Vec<&RepoView> = found.iter().filter(|r| r.git == git).collect();
        assert_eq!(hits.len(), 1, "found once: {}", repo.display());
        assert_eq!(hits[0].disposition, "confirmed", "{}", repo.display());
    }
    // No silent exclusion by directory name: the cache-build-vendored clones
    // are all confirmed matches.
    for rel in [
        ".hidden/repo",
        "tmp/scratch/repo",
        ".cache/tool/repo",
        "target/debug/repo",
        "node_modules/pkg/repo",
    ] {
        let git = expected_bytes(&env.root.join(rel).join(".git"));
        assert!(
            found
                .iter()
                .any(|r| r.git == git && r.disposition == "confirmed"),
            "no exclusion for {rel}"
        );
    }
}

// ---------------------------------------------------------------------------
// FS-02: Git layout variants represented.
// ---------------------------------------------------------------------------

#[test]
fn fs02_arbitrary_bare_store_represented() {
    let env = Env::new();
    let bare = fixture::bare_store(&env.root, "archive-store");
    assert!(bare.join("HEAD").is_file(), "bare store is a git dir");
    let out = env.scan(&env.root, "rep.json");
    // No identifying remotes: terminal incomplete, not a retry loop.
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let report = read_report(&env.cwd.join("rep.json"));
    assert_eq!(report["coverage"]["identity"].as_str(), Some("unproven"));
    assert_eq!(
        report["coverage"]["unresolvable_candidates"].as_u64(),
        Some(1)
    );
    let found = repositories(&report);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].git, expected_bytes(&bare));
    assert_eq!(found[0].common, expected_bytes(&bare));
    assert_eq!(found[0].disposition, "unresolvable_identity");
    assert_eq!(report["repositories"][0]["bare"].as_bool(), Some(true));
    // Branches survive packed/loose storage without assuming file layout.
    let branches = report["branches"].as_array().expect("branches");
    assert!(
        branches.iter().any(|b| b["name"]["value"]
            .as_str()
            .is_some_and(|n| n == "refs/heads/main")),
        "main branch observed in bare store"
    );
}

#[test]
fn fs02_pointer_external_and_detached_layouts() {
    let env = Env::new();
    let (work, gitdir) = fixture::external_git_dir(&env.root);
    assert!(work.join(".git").is_file(), ".git is a pointer file");
    fixture::git(
        &work,
        &["remote", "add", "origin", fixture::FIXTURE_REMOTE_URL],
    );
    let detached = fixture::detached_head(&env.root, "detached");

    // Git canonicalizes the absolute paths it writes into `.git` pointer
    // files, while the tempdir root may carry an unclean spelling
    // (`/var` -> `/private/var` on macOS). Scan and compare in canonical
    // space so both discovery angles key the same instance spelling.
    let root = env.root.canonicalize().expect("canonical root");
    let gitdir = gitdir.canonicalize().expect("canonical gitdir");
    let work_canon = work.canonicalize().expect("canonical work");
    let detached_canon = detached.canonicalize().expect("canonical detached");
    let out = env.scan(&root, "rep.json");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&env.cwd.join("rep.json"));
    let found = repositories(&report);
    assert_eq!(found.len(), 2);
    // External git directory: instance keyed at the outside common dir.
    let ext: Vec<&RepoView> = found
        .iter()
        .filter(|r| r.git == expected_bytes(&gitdir))
        .collect();
    assert_eq!(ext.len(), 1, "external git dir is one instance");
    assert_eq!(ext[0].disposition, "confirmed");
    assert_eq!(ext[0].common, expected_bytes(&gitdir));
    // Detached checkout keeps its topology with a detached HEAD.
    let det: Vec<&RepoView> = found
        .iter()
        .filter(|r| r.git == expected_bytes(&detached_canon.join(".git")))
        .collect();
    assert_eq!(det.len(), 1);
    assert_eq!(det[0].disposition, "confirmed");
    let cos = checkouts(&report);
    let work_root = expected_bytes(&work_canon);
    assert!(
        cos.iter().any(|c| c.root.as_ref() == Some(&work_root)),
        "pointer-file checkout has its worktree root"
    );
    let det_root = expected_bytes(&detached_canon);
    let det_co: Vec<&CheckoutView> = cos
        .iter()
        .filter(|c| c.root.as_ref() == Some(&det_root))
        .collect();
    assert_eq!(det_co.len(), 1);
    assert_eq!(det_co[0].head_state, "detached");
}

#[test]
fn fs02_outside_root_registered_worktree_followed() {
    let env = Env::new();
    let (main, wt) = fixture::linked_worktree(&env.root);
    // Scan ONLY the main checkout: the registered worktree lives outside the
    // requested root but must still be followed via Git relationships.
    let out = env.scan(&main, "rep.json");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&env.cwd.join("rep.json"));
    let cos = checkouts(&report);
    // Git canonicalizes the worktree base it records in the registry
    // `gitdir` file, and that registry entry is the scanner's only view of
    // the outside-root path, so compare in canonical space.
    let wt_root = expected_bytes(&wt.canonicalize().expect("canonical wt"));
    let linked: Vec<&CheckoutView> = cos
        .iter()
        .filter(|c| c.root.as_ref() == Some(&wt_root))
        .collect();
    assert_eq!(linked.len(), 1, "outside-root worktree has a checkout");
    assert_eq!(linked[0].kind, "linked");
    let main_root = expected_bytes(&main);
    assert!(
        cos.iter().any(|c| c.root.as_ref() == Some(&main_root)),
        "main checkout present alongside the linked one"
    );
}

// ---------------------------------------------------------------------------
// FS-03: cycles, replacement, no duplicates.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn fs03_symlink_cycle_terminates_without_duplicates() {
    let env = Env::new();
    let cycle = fixture::symlink_cycle(&env.root);
    assert!(cycle.join("a").is_symlink());
    let repo = fixture::normal_clone(&env.root, "repo");
    let out = env.scan(&env.root, "rep.json");
    let code = out.status.code();
    assert!(
        matches!(code, Some(0) | Some(3)),
        "cycle is complete or an honest gap, never a hang/failure; stderr: {}",
        stderr_text(&out)
    );
    let report = read_report(&env.cwd.join("rep.json"));
    let found = repositories(&report);
    assert_eq!(found.len(), 1, "one instance despite the cycle");
    assert_eq!(found[0].git, expected_bytes(&repo.join(".git")));
    assert_eq!(found[0].disposition, "confirmed");
}

#[test]
fn fs03_path_replacement_reconciles_without_duplicates() {
    let env = Env::new();
    let victim_parent = env.root.join("v");
    repo_scan::privacy::private_dir_0700(&victim_parent).expect("mkdir");
    fixture::normal_clone(&victim_parent, "victim");
    let victim = victim_parent.join("victim");
    let out = env.scan(&env.root, "rep1.json");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let first = read_report(&env.cwd.join("rep1.json"));
    let first_oid = first["branches"]
        .as_array()
        .expect("branches")
        .iter()
        .find(|b| {
            b["name"]["value"]
                .as_str()
                .is_some_and(|n| n == "refs/heads/main")
        })
        .expect("main branch")["oid"]["hex"]
        .as_str()
        .expect("oid")
        .to_string();

    // Replace the directory with a fresh, different repo at the same path.
    std::fs::remove_dir_all(&victim).expect("remove");
    fixture::normal_clone(&victim_parent, "victim");
    fixture::commit_file(&victim, "extra.txt", "replacement\n", "replacement commit");
    let victim_str = victim.to_str().expect("utf8").to_string();
    let out = run(
        &["cache", "invalidate", "--root", victim_str.as_str()],
        &env.cwd,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let out = env.scan(&env.root, "rep2.json");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let second = read_report(&env.cwd.join("rep2.json"));
    let found = repositories(&second);
    assert_eq!(
        found.len(),
        1,
        "replacement does not duplicate the instance"
    );
    assert_eq!(found[0].git, expected_bytes(&victim.join(".git")));
    let second_oid = second["branches"]
        .as_array()
        .expect("branches")
        .iter()
        .find(|b| {
            b["name"]["value"]
                .as_str()
                .is_some_and(|n| n == "refs/heads/main")
        })
        .expect("main branch")["oid"]["hex"]
        .as_str()
        .expect("oid");
    assert_ne!(
        second_oid, first_oid,
        "replacement re-observed, not inherited"
    );
}

// ---------------------------------------------------------------------------
// FS-04: non-UTF-8 + control characters.
// ---------------------------------------------------------------------------

/// Raw terminal bytes must carry no control characters (escape_display
/// replaces them); newlines are output separators.
fn assert_no_terminal_controls(text: &str, what: &str) {
    for ch in text.chars() {
        assert!(
            !ch.is_control() || ch == '\n',
            "{what} leaks control char {ch:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn fs04_non_utf8_and_controls_round_trip() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let env = Env::new();
    // Invalid-UTF-8 directory: some filesystems (APFS) reject these names,
    // so a failed creation skips loudly instead of failing.
    let bad_dir = env.root.join(OsString::from_vec(b"bad-\xff-dir".to_vec()));
    if repo_scan::privacy::private_dir_0700(&bad_dir).is_err() {
        eprintln!("fs04: filesystem rejects non-UTF-8 names; skipping");
        return;
    }
    let repo = fixture::normal_clone(&bad_dir, "repo");
    // Valid UTF-8 name carrying control characters.
    let ctrl = fixture::normal_clone(&env.root, "ctrl-\u{1}\u{7}-repo");

    let out = env.scan(&env.root, "rep.json");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    // JSON round-trip: parses, and the exact non-UTF-8 bytes survive via
    // base64 with byte-identical decode.
    let report = read_report(&env.cwd.join("rep.json"));
    let found = repositories(&report);
    assert_eq!(found.len(), 2);
    assert!(
        found
            .iter()
            .any(|r| r.git == expected_bytes(&repo.join(".git"))),
        "non-UTF-8 repo path round-trips exactly"
    );
    assert!(
        found
            .iter()
            .any(|r| r.git == expected_bytes(&ctrl.join(".git"))),
        "control-char repo path round-trips exactly"
    );
    let mut saw_base64 = false;
    for entry in report["paths"].as_array().expect("paths") {
        let display = entry["display"].as_str().expect("display");
        for ch in display.chars() {
            assert!(!ch.is_control(), "display escapes controls: {display:?}");
        }
        if entry["encoding"].as_str() == Some("base64") {
            saw_base64 = true;
            let raw = decoded_value(entry);
            assert!(
                raw.contains(&0xff),
                "base64 entry decodes to the original bytes"
            );
        }
    }
    assert!(saw_base64, "non-UTF-8 bytes use base64 encoding");
    // Safe terminal rendering: terminal report + cached query output carry
    // no raw control bytes.
    let root_str = env.root.to_str().expect("utf8").to_string();
    let out = run(
        &["scan", URL, "--root", root_str.as_str()],
        &env.cwd,
        &env.state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert_no_terminal_controls(&String::from_utf8_lossy(&out.stdout), "terminal report");
    let out = run(&["query", URL, "--cached"], &env.cwd, &env.state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert_no_terminal_controls(&String::from_utf8_lossy(&out.stdout), "cached query");
}

// ---------------------------------------------------------------------------
// FS-05: huge-flat + deep fixtures stay bounded; backends equivalent.
// ---------------------------------------------------------------------------

fn all_adapters() -> Vec<Box<dyn repo_scan::walk::OneDirAdapter>> {
    let mut adapters: Vec<Box<dyn repo_scan::walk::OneDirAdapter>> = vec![
        Box::new(repo_scan::walk::IgnoreAdapter),
        Box::new(repo_scan::walk::StdEscape),
    ];
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    adapters.push(Box::new(repo_scan::walk::DuaAdapter));
    adapters
}

/// Stream one directory through an adapter without retaining entries:
/// returns (count, name-length checksum, error count). Bounded callers never
/// `collect` the child list.
fn stream_dir(adapter: &dyn repo_scan::walk::OneDirAdapter, dir: &Path) -> (usize, u64, usize) {
    let mut count = 0usize;
    let mut checksum = 0u64;
    let mut errors = 0usize;
    let iter = adapter
        .list_dir(
            dir,
            repo_scan::walk::ListOptions {
                skip_metadata: true,
            },
        )
        .expect("open dir");
    for item in iter {
        match item {
            Ok(entry) => {
                count += 1;
                checksum = checksum.wrapping_add(entry.name.len() as u64);
            }
            Err(_) => errors += 1,
        }
    }
    (count, checksum, errors)
}

#[test]
fn fs05_huge_flat_bounded_and_backends_equivalent() {
    let env = Env::new();
    let flat = fixture::huge_flat(&env.root, fixture::HUGE_FLAT_CI);
    // Every backend streams the same children with the same names and no
    // errors; streaming (not collecting) keeps caller memory O(1).
    let mut baseline: Option<(usize, u64)> = None;
    for adapter in all_adapters() {
        let (count, checksum, errors) = stream_dir(adapter.as_ref(), &flat);
        assert_eq!(errors, 0, "{} errors", adapter.name());
        assert_eq!(count, fixture::HUGE_FLAT_CI, "{} count", adapter.name());
        match baseline {
            None => baseline = Some((count, checksum)),
            Some((bcount, bsum)) => {
                assert_eq!((count, checksum), (bcount, bsum), "backend equivalence");
            }
        }
    }
    // The full scan stays bounded too: complete coverage, no gaps.
    let out = env.scan(&env.root, "rep.json");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&env.cwd.join("rep.json"));
    assert_eq!(report["coverage"]["filesystem"].as_str(), Some("complete"));
    assert_eq!(report["coverage"]["gaps"].as_u64(), Some(0));
    assert!(
        report["coverage"]["directories_complete"]
            .as_u64()
            .expect("directories_complete")
            > 0
    );
}

#[test]
fn fs05_deep_path_bounded_and_backends_equivalent() {
    let env = Env::new();
    let (top, bottom) = fixture::deep_path(&env.root, fixture::DEEP_PATH_CI);
    assert!(bottom.is_file());
    // Backend equivalence at depth: same single-child chain everywhere.
    let mut dir = top.clone();
    for _ in 0..fixture::DEEP_PATH_CI {
        let mut baseline: Option<HashSet<String>> = None;
        for adapter in all_adapters() {
            let iter = adapter
                .list_dir(
                    dir.as_path(),
                    repo_scan::walk::ListOptions {
                        skip_metadata: true,
                    },
                )
                .expect("open dir");
            let mut names = HashSet::new();
            for item in iter {
                let entry = item.expect("no per-entry error");
                names.insert(entry.name.to_string_lossy().into_owned());
            }
            match &baseline {
                None => baseline = Some(names),
                Some(first) => assert_eq!(&names, first, "backend equivalence at depth"),
            }
        }
        let names = baseline.expect("baseline");
        assert_eq!(names.len(), 1, "single-child chain");
        let next: Vec<String> = names.into_iter().collect();
        dir = dir.join(&next[0]);
    }
    // The full scan reaches the bottom without recursion or buffering blowup.
    let out = env.scan(&env.root, "rep.json");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = read_report(&env.cwd.join("rep.json"));
    assert_eq!(report["coverage"]["filesystem"].as_str(), Some("complete"));
    assert_eq!(report["coverage"]["gaps"].as_u64(), Some(0));
    assert!(
        report["coverage"]["directories_complete"]
            .as_u64()
            .expect("directories_complete")
            >= fixture::DEEP_PATH_CI as u64
    );
}
