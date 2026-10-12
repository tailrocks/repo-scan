//! Black-box tests for `proof red`: pending-state listing and schema
//! validation of the requirements manifest.

mod common;

use common::{code, run, stdout, workspace_root, write_json};
use serde_json::json;

#[test]
fn red_lists_all_pending_frozen_requirements() {
    let path = workspace_root().join("proof/requirements.json");
    let out = run(&["proof", "red", "--requirements", path.to_str().unwrap()]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("GOV-01"), "stdout: {text}");
    assert!(text.contains("LAND-04"), "stdout: {text}");
    assert!(text.contains("\"pending_count\": 100"), "stdout: {text}");
}

#[test]
fn red_passes_when_every_required_item_has_green_evidence() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("requirements.json");
    let doc = common::make_requirements(
        vec![json!({"path": "/tmp/x", "sha256": "0".repeat(64)})],
        "implementer-a",
        "verifier-b",
    );
    write_json(&path, &doc);
    let out = run(&["proof", "red", "--requirements", path.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));
}

#[test]
fn red_rejects_manifest_with_missing_required_field() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("requirements.json");
    let mut doc = common::make_requirements(vec![], "a", "b");
    doc["requirements"][0]
        .as_object_mut()
        .unwrap()
        .remove("oracle");
    write_json(&path, &doc);
    let out = run(&["proof", "red", "--requirements", path.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("oracle"), "stdout: {}", stdout(&out));
}

#[test]
fn red_rejects_malformed_json() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("requirements.json");
    std::fs::write(&path, b"[broken").unwrap();
    let out = run(&["proof", "red", "--requirements", path.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
}
