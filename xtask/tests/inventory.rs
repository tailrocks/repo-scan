//! Black-box tests for `proof inventory` (goal sections 3.3, step 1 exit
//! gate): a deliberately omitted head must be rejected.

mod common;

use common::{code, make_lock, run, setup_repo, stdout, write_json};

#[test]
fn inventory_passes_on_matching_repo() {
    let repo = setup_repo();
    let lock = make_lock(repo.dir.path(), &repo.head_a, &repo.head_b, false);
    let lock_path = repo.dir.path().join("sources.lock.json");
    write_json(&lock_path, &lock);
    let out = run(&[
        "proof",
        "inventory",
        "--repo",
        repo.dir.path().to_str().unwrap(),
        "--sources",
        lock_path.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("\"PASS\""));
}

#[test]
fn inventory_rejects_deliberately_omitted_head() {
    let repo = setup_repo();
    // Lock omits beta while the repository still carries its frozen ref.
    let lock = make_lock(repo.dir.path(), &repo.head_a, &repo.head_b, true);
    let lock_path = repo.dir.path().join("sources.lock.json");
    write_json(&lock_path, &lock);
    let out = run(&[
        "proof",
        "inventory",
        "--repo",
        repo.dir.path().to_str().unwrap(),
        "--sources",
        lock_path.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("refs/goal/sources/beta"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn inventory_rejects_ref_missing_from_repo() {
    let repo = setup_repo();
    let mut lock = make_lock(repo.dir.path(), &repo.head_a, &repo.head_b, false);
    // Lock claims a gamma source that the repo does not carry.
    lock["sources"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": "S03",
            "ref": "gamma",
            "frozen_ref": "refs/goal/sources/gamma",
            "head": repo.head_b,
            "tree": common::git(repo.dir.path(), &["rev-parse", "HEAD^{tree}"]),
            "parents": [repo.head_a],
            "object_type": "commit",
        }));
    let lock_path = repo.dir.path().join("sources.lock.json");
    write_json(&lock_path, &lock);
    let out = run(&[
        "proof",
        "inventory",
        "--repo",
        repo.dir.path().to_str().unwrap(),
        "--sources",
        lock_path.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("gamma"), "stdout: {}", stdout(&out));
}

#[test]
fn inventory_rejects_sha_mismatch() {
    let repo = setup_repo();
    let mut lock = make_lock(repo.dir.path(), &repo.head_a, &repo.head_b, false);
    lock["sources"][1]["head"] = serde_json::json!(repo.head_a);
    let lock_path = repo.dir.path().join("sources.lock.json");
    write_json(&lock_path, &lock);
    let out = run(&[
        "proof",
        "inventory",
        "--repo",
        repo.dir.path().to_str().unwrap(),
        "--sources",
        lock_path.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
}

#[test]
fn inventory_rejects_tree_mismatch() {
    let repo = setup_repo();
    let mut lock = make_lock(repo.dir.path(), &repo.head_a, &repo.head_b, false);
    lock["sources"][1]["tree"] = serde_json::json!(common::git(
        repo.dir.path(),
        &["rev-parse", "main~1^{tree}"]
    ));
    let lock_path = repo.dir.path().join("sources.lock.json");
    write_json(&lock_path, &lock);
    let out = run(&[
        "proof",
        "inventory",
        "--repo",
        repo.dir.path().to_str().unwrap(),
        "--sources",
        lock_path.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("tree mismatch"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn inventory_rejects_parent_mismatch() {
    let repo = setup_repo();
    let mut lock = make_lock(repo.dir.path(), &repo.head_a, &repo.head_b, false);
    lock["sources"][1]["parents"] = serde_json::json!([]);
    let lock_path = repo.dir.path().join("sources.lock.json");
    write_json(&lock_path, &lock);
    let out = run(&[
        "proof",
        "inventory",
        "--repo",
        repo.dir.path().to_str().unwrap(),
        "--sources",
        lock_path.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("parents mismatch"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn inventory_rejects_malformed_lock() {
    let repo = setup_repo();
    let lock_path = repo.dir.path().join("sources.lock.json");
    std::fs::write(&lock_path, b"{not json").unwrap();
    let out = run(&[
        "proof",
        "inventory",
        "--repo",
        repo.dir.path().to_str().unwrap(),
        "--sources",
        lock_path.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
}

#[test]
fn inventory_blocked_on_non_repo() {
    let dir = tempfile::TempDir::new().unwrap();
    let lock_path = dir.path().join("sources.lock.json");
    write_json(
        &lock_path,
        &serde_json::json!({"schema": "x", "sources": []}),
    );
    let out = run(&[
        "proof",
        "inventory",
        "--repo",
        dir.path().to_str().unwrap(),
        "--sources",
        lock_path.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 3, "stdout: {}", stdout(&out));
}
