//! Integration tests for the deterministic benchmark corpus generator
//! (goal §7.1 datasets; GOV-04 datasets portion; TDD-04 truth independence).
//!
//! The generator lives in `benches/corpus.rs` (a bench binary); it is compiled
//! into this test binary via `#[path]` so the tests exercise the exact code
//! the benchmark custodian runs.
//!
//! Covered:
//! - determinism: same recipe+seed+tier in two fresh roots → identical
//!   root-independent tree hash and identical manifests modulo the root path;
//! - manifest truth: every manifest repository/worktree/ref/HEAD claim is
//!   re-derived independently through `tests/common/fixture.rs` git helpers
//!   (a separate git-runner implementation from the generator's own);
//! - containment: generation never writes outside the requested output root;
//! - refusal: a non-empty output root is rejected;
//! - special entries: non-UTF-8 names and permission-denied dirs are recorded
//!   explicitly (created or capability-unavailable, never silent).

mod common;

#[path = "../benches/corpus.rs"]
mod corpus;

use serde_json::Value;
use std::path::{Path, PathBuf};

fn generate(id: &str, out: &Path, tier: &str) -> corpus::GenReport {
    corpus::generate(id, out, tier).unwrap_or_else(|e| panic!("generate {id}/{tier}: {e}"))
}

/// Manifest serialized with the absolute tree root replaced by a token, so
/// manifests from two different roots are comparable.
fn normalized_manifest(report: &corpus::GenReport) -> String {
    let root = report.manifest["root"].as_str().expect("root string");
    serde_json::to_string(&report.manifest)
        .expect("serialize manifest")
        .replace(root, "<ROOT>")
}

fn assert_deterministic(id: &str) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = generate(id, &tmp.path().join("a"), "smoke");
    let b = generate(id, &tmp.path().join("b"), "smoke");
    assert_eq!(
        a.manifest["tree_sha256"], b.manifest["tree_sha256"],
        "{id}: tree hash must be identical across roots"
    );
    assert_eq!(
        normalized_manifest(&a),
        normalized_manifest(&b),
        "{id}: manifests must be identical modulo the root path"
    );
    // Scratch area must not survive into the deliverable root.
    let canon = std::fs::canonicalize(tmp.path().join("a")).expect("canonicalize");
    assert!(
        !canon.join("stage").exists(),
        "{id}: stage/ must be removed"
    );
}

#[test]
fn determinism_shape_families_smoke() {
    for id in ["wide-file-heavy", "dir-heavy", "deep-tree"] {
        assert_deterministic(id);
    }
}

#[test]
fn determinism_git_families_smoke() {
    for id in ["huge-git-object-store", "many-tiny-repos", "many-refs"] {
        assert_deterministic(id);
    }
}

#[test]
fn determinism_topology_families_smoke() {
    for id in [
        "many-linked-worktrees",
        "independent-clones",
        "ignored-hidden-nested",
    ] {
        assert_deterministic(id);
    }
}

/// Re-derive one manifest repository entry with the independent test git
/// runner and assert every claim matches.
fn assert_repo_truth(root: &Path, entry: &Value) {
    let rel = entry["path"].as_str().expect("utf8 repo path");
    let abs = root.join(rel);
    let git_dir = root.join(entry["git_dir"].as_str().expect("git_dir"));
    let common_dir = root.join(entry["common_dir"].as_str().expect("common_dir"));

    let actual_git_dir = common::fixture::git_str(&abs, &["rev-parse", "--absolute-git-dir"]);
    assert_eq!(
        PathBuf::from(&actual_git_dir),
        git_dir,
        "{rel}: git_dir must match rev-parse --absolute-git-dir"
    );
    // commondir resolution: gitdir/commondir file relative to the gitdir,
    // else the gitdir itself — same rule as git(7) documents.
    let actual_common = match std::fs::read_to_string(git_dir.join("commondir")) {
        Ok(text) => {
            let rel_c = Path::new(text.trim());
            if rel_c.is_absolute() {
                rel_c.to_path_buf()
            } else {
                let mut n = git_dir.clone();
                for c in rel_c.components() {
                    match c {
                        std::path::Component::ParentDir => {
                            n.pop();
                        }
                        std::path::Component::CurDir => {}
                        other => n.push(other.as_os_str()),
                    }
                }
                n
            }
        }
        Err(_) => git_dir.clone(),
    };
    assert_eq!(actual_common, common_dir, "{rel}: common_dir");

    let bare = common::fixture::git_str(&abs, &["rev-parse", "--is-bare-repository"]);
    assert_eq!(
        bare == "true",
        entry["is_bare"].as_bool().unwrap(),
        "{rel}: is_bare"
    );

    // HEAD state, independently derived.
    let symref =
        common::fixture::git_succeeds(&abs, &["symbolic-ref", "-q", "--no-recurse", "HEAD"]).then(
            || common::fixture::git_str(&abs, &["symbolic-ref", "-q", "--no-recurse", "HEAD"]),
        );
    let oid = common::fixture::git_succeeds(&abs, &["rev-parse", "--verify", "-q", "HEAD"])
        .then(|| common::fixture::git_str(&abs, &["rev-parse", "--verify", "-q", "HEAD"]));
    let state = match (&symref, &oid) {
        (Some(_), Some(_)) => "branch",
        (Some(_), None) => "unborn",
        (None, Some(_)) => "detached",
        (None, None) => "broken",
    };
    assert_eq!(
        entry["head"]["state"].as_str().unwrap(),
        state,
        "{rel}: head.state"
    );
    assert_eq!(
        entry["head"]["ref"].as_str().map(str::to_string),
        symref,
        "{rel}: head.ref"
    );
    assert_eq!(
        entry["head"]["oid"].as_str().map(str::to_string),
        oid,
        "{rel}: head.oid"
    );

    // Full ref set, independently enumerated.
    let raw = common::fixture::git(
        &abs,
        &["for-each-ref", "--format=%(refname)%09%(objectname)"],
    );
    let refs: Vec<(String, String)> = String::from_utf8_lossy(&raw)
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(n, o)| (n.to_string(), o.to_string()))
        .collect();
    let manifest_refs: Vec<(String, String)> = entry["refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_string(),
                r["oid"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(manifest_refs, refs, "{rel}: refs must match for-each-ref");

    // Remotes.
    let remote_names = common::fixture::git_str(&abs, &["remote"]);
    let mut remotes: Vec<(String, String)> = Vec::new();
    for name in remote_names.lines() {
        let url = common::fixture::git_str(&abs, &["remote", "get-url", name]);
        remotes.push((name.to_string(), url));
    }
    let manifest_remotes: Vec<(String, String)> = entry["remotes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_string(),
                r["url"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(manifest_remotes, remotes, "{rel}: remotes");

    // Worktree registry for this store.
    let porcelain = common::fixture::git(&abs, &["worktree", "list", "--porcelain"]);
    let wt_paths: Vec<PathBuf> = String::from_utf8_lossy(&porcelain)
        .lines()
        .filter_map(|l| l.strip_prefix("worktree ").map(PathBuf::from))
        .collect();
    let manifest_wts: Vec<PathBuf> = entry["worktrees"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| root.join(w["path"].as_str().unwrap()))
        .collect();
    assert_eq!(manifest_wts, wt_paths, "{rel}: worktree list");
}

#[test]
fn manifest_matches_independent_git_inspection() {
    let tmp = tempfile::tempdir().expect("tempdir");
    for (id, expect_repos) in [
        ("many-linked-worktrees", 3usize),
        ("independent-clones", 3),
        ("many-refs", 4),
    ] {
        let report = generate(id, &tmp.path().join(id), "smoke");
        let root = PathBuf::from(report.manifest["root"].as_str().unwrap());
        let repos = report.manifest["repositories"].as_array().unwrap();
        assert_eq!(
            repos.len(),
            expect_repos,
            "{id}: repository count in manifest"
        );
        for entry in repos {
            assert_repo_truth(&root, entry);
        }
    }
}

#[test]
fn linked_worktree_graph_truth() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let report = generate("many-linked-worktrees", &tmp.path().join("wt"), "smoke");
    let m = &report.manifest;
    assert_eq!(m["counts"]["repos"].as_u64().unwrap(), 3);
    assert_eq!(m["counts"]["common_stores"].as_u64().unwrap(), 1);
    assert_eq!(m["counts"]["worktrees"].as_u64().unwrap(), 3);
    let kinds: Vec<&str> = m["repositories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["checkout", "linked_worktree", "linked_worktree"]);
    // Linked worktrees share the main checkout's common store.
    let common: Vec<&str> = m["repositories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["common_dir"].as_str().unwrap())
        .collect();
    assert!(common.iter().all(|c| *c == common[0]));
}

#[test]
fn independent_clones_share_one_remote_url() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let report = generate("independent-clones", &tmp.path().join("cl"), "smoke");
    let m = &report.manifest;
    let root = PathBuf::from(m["root"].as_str().unwrap());
    let repos = m["repositories"].as_array().unwrap();
    let clones: Vec<&Value> = repos.iter().filter(|r| r["kind"] == "checkout").collect();
    assert_eq!(clones.len(), 2);
    let expected_url = format!("{}", root.join("upstream").join("up00.git").display());
    for c in &clones {
        assert_eq!(c["remotes"][0]["name"].as_str().unwrap(), "origin");
        assert_eq!(c["remotes"][0]["url"].as_str().unwrap(), expected_url);
    }
    // One bare upstream, distinct from the clones.
    let bare: Vec<&Value> = repos.iter().filter(|r| r["kind"] == "bare").collect();
    assert_eq!(bare.len(), 1);
    assert!(bare[0]["is_bare"].as_bool().unwrap());
}

#[test]
fn generator_never_writes_outside_out_root() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Deeply nested, initially nonexistent output roots.
    let base = tmp.path().join("a").join("b").join("c");
    generate("many-linked-worktrees", &base.join("wt"), "smoke");
    generate("ignored-hidden-nested", &base.join("nested"), "smoke");
    let top: Vec<_> = std::fs::read_dir(tmp.path())
        .expect("read tmp")
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        top,
        vec![std::ffi::OsString::from("a")],
        "the output root's parent chain must be the only thing created"
    );
}

#[test]
fn refuses_non_empty_out() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("sentinel"), b"x").unwrap();
    let err = corpus::generate("many-tiny-repos", &out, "smoke")
        .err()
        .expect("must refuse a non-empty out dir");
    assert!(err.contains("non-empty"), "unexpected error: {err}");
    // And the sentinel survives untouched.
    assert_eq!(std::fs::read(out.join("sentinel")).unwrap(), b"x");
}

#[cfg(unix)]
#[test]
fn special_entries_non_utf8_and_permission_denied() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let wide = generate("wide-file-heavy", &tmp.path().join("wide"), "smoke");
    let entries = wide.manifest["special_entries"]["non_utf8"]
        .as_array()
        .unwrap();
    assert_eq!(entries.len(), 1, "smoke recipe plans one non-UTF-8 entry");
    let entry = &entries[0];
    assert!(entry["path"].is_null());
    assert!(entry["path_b64"].as_str().is_some());
    let root = PathBuf::from(wide.manifest["root"].as_str().unwrap());
    if entry["created"].as_bool().unwrap() {
        // Host accepts non-UTF-8 names (Linux-style): the entry must exist
        // on disk under wide/nonutf8 with a genuinely invalid UTF-8 name.
        let dir = std::fs::read_dir(root.join("wide").join("nonutf8")).unwrap();
        let mut found = false;
        for e in dir {
            let name = e.unwrap().file_name();
            if std::str::from_utf8(name.as_bytes()).is_err() {
                found = true;
            }
        }
        assert!(found, "created non-UTF-8 entry must exist on disk");
    } else {
        // Host rejects non-UTF-8 names (macOS/APFS): explicit unavailability.
        assert_eq!(
            wide.manifest["special_entries"]["non_utf8_supported"],
            Value::Bool(false)
        );
    }

    let dir = generate("dir-heavy", &tmp.path().join("dir"), "smoke");
    let denied = dir.manifest["special_entries"]["permission_denied"]
        .as_array()
        .unwrap();
    assert_eq!(denied.len(), 1);
    let droot = PathBuf::from(dir.manifest["root"].as_str().unwrap());
    let denied_path = droot.join(denied[0]["path"].as_str().unwrap());
    let mode = std::fs::metadata(&denied_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o000, "denied dir must be chmod 000");
    assert_eq!(
        dir.manifest["counts"]["inaccessible_dirs"]
            .as_u64()
            .unwrap(),
        1
    );
}

#[test]
fn pilot_tier_many_tiny_repos() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let report = generate("many-tiny-repos", &tmp.path().join("pilot"), "pilot");
    let m = &report.manifest;
    assert_eq!(m["counts"]["repos"].as_u64().unwrap(), 40);
    assert_eq!(m["counts"]["refs"].as_u64().unwrap(), 40);
    for r in m["repositories"].as_array().unwrap() {
        assert_eq!(r["remotes"][0]["name"].as_str().unwrap(), "origin");
        assert!(r["remotes"][0]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://example.invalid/tiny/"));
        assert_eq!(r["head"]["state"].as_str().unwrap(), "branch");
    }
}
