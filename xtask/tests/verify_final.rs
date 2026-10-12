//! Black-box tests for `proof verify-final`: PASS only when every mandatory
//! requirement has hashed green evidence, verifier != implementer, every
//! experiment carries a valid evidenced disposition (goal section 3.2), the
//! commit exists, and source coverage is complete.

mod common;

use common::{code, make_lock, make_requirements, run, setup_repo, stdout, write_json};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Output;

struct Fixture {
    repo: common::TestRepo,
    artifact: PathBuf,
    requirements_path: PathBuf,
    lock_path: PathBuf,
    experiments_path: PathBuf,
}

fn evidence_for(artifact: &Path) -> Vec<Value> {
    vec![json!({
        "path": artifact.display().to_string(),
        "sha256": common::sha256_file(artifact),
        "recorded_at": "2026-01-01T00:00:00Z",
        "agent": "verifier-b",
    })]
}

fn fixture(green: Vec<Value>, implementer: &str, verifier: &str, omit_beta: bool) -> Fixture {
    let repo = setup_repo();
    let lock = make_lock(repo.dir.path(), &repo.head_a, &repo.head_b, omit_beta);
    let lock_path = repo.dir.path().join("sources.lock.json");
    write_json(&lock_path, &lock);
    let artifact = repo.dir.path().join("verdict.json");
    std::fs::write(&artifact, b"{\"verdict\":\"PASS\"}\n").unwrap();
    let requirements = make_requirements(green, implementer, verifier);
    let requirements_path = repo.dir.path().join("requirements.json");
    write_json(&requirements_path, &requirements);
    // Default: one experiment with a valid disposition.
    let experiments_path = repo.dir.path().join("experiments.json");
    write_json(&experiments_path, &common::make_experiments(&artifact));
    Fixture {
        repo,
        artifact,
        requirements_path,
        lock_path,
        experiments_path,
    }
}

impl Fixture {
    fn run_verify(&self, commit: &str) -> Output {
        run(&[
            "proof",
            "verify-final",
            "--commit",
            commit,
            "--requirements",
            self.requirements_path.to_str().unwrap(),
            "--sources",
            self.lock_path.to_str().unwrap(),
            "--experiments",
            self.experiments_path.to_str().unwrap(),
            "--repo",
            self.repo.dir.path().to_str().unwrap(),
        ])
    }

    fn rewrite_experiments(&self, experiments: Value) {
        write_json(&self.experiments_path, &experiments);
    }

    fn rewrite_requirements(&self, green: Vec<Value>, implementer: &str, verifier: &str) {
        write_json(
            &self.requirements_path,
            &make_requirements(green, implementer, verifier),
        );
    }
}

#[test]
fn verify_final_passes_on_complete_evidence() {
    let f = fixture(Vec::new(), "implementer-a", "verifier-b", false);
    let green = evidence_for(&f.artifact);
    f.rewrite_requirements(green, "implementer-a", "verifier-b");
    let head_b = f.repo.head_b.clone();
    let out = f.run_verify(&head_b);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("\"PASS\""),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn verify_final_rejects_self_certification() {
    let f = fixture(Vec::new(), "implementer-a", "verifier-b", false);
    let green = evidence_for(&f.artifact);
    f.rewrite_requirements(green, "same-agent", "same-agent");
    let head_b = f.repo.head_b.clone();
    let out = f.run_verify(&head_b);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("self-certification"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn verify_final_rejects_missing_green_evidence() {
    let f = fixture(Vec::new(), "implementer-a", "verifier-b", false);
    let head_b = f.repo.head_b.clone();
    let out = f.run_verify(&head_b);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("no green evidence"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn verify_final_rejects_missing_evidence_file() {
    let f = fixture(
        vec![json!({
            "path": "/nonexistent/proof-out/never/verdict.json",
            "sha256": "0".repeat(64),
        })],
        "implementer-a",
        "verifier-b",
        false,
    );
    let head_b = f.repo.head_b.clone();
    let out = f.run_verify(&head_b);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
}

#[test]
fn verify_final_rejects_tampered_evidence_hash() {
    let f = fixture(Vec::new(), "implementer-a", "verifier-b", false);
    let mut ev = evidence_for(&f.artifact);
    // Flip the recorded hash after the artifact was written.
    ev[0]["sha256"] = json!("1".repeat(64));
    f.rewrite_requirements(ev, "implementer-a", "verifier-b");
    let head_b = f.repo.head_b.clone();
    let out = f.run_verify(&head_b);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("hash mismatch"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn verify_final_blocked_on_unknown_commit() {
    let f = fixture(Vec::new(), "implementer-a", "verifier-b", false);
    let bogus = "f".repeat(40);
    let out = f.run_verify(&bogus);
    assert_eq!(code(&out), 3, "stdout: {}", stdout(&out));
}

#[test]
fn verify_final_rejects_omitted_source() {
    // Lock omits beta while the repo still carries its frozen ref.
    let f = fixture(Vec::new(), "implementer-a", "verifier-b", true);
    let green = evidence_for(&f.artifact);
    f.rewrite_requirements(green, "implementer-a", "verifier-b");
    let head_b = f.repo.head_b.clone();
    let out = f.run_verify(&head_b);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("source coverage"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn verify_final_rejects_missing_experiment_disposition() {
    let f = fixture(Vec::new(), "implementer-a", "verifier-b", false);
    let green = evidence_for(&f.artifact);
    f.rewrite_requirements(green, "implementer-a", "verifier-b");
    f.rewrite_experiments(json!({
        "schema": "repo-scan/experiments/1",
        "experiments": [{
            "id": "EXP-X",
            "status": "pending"
        }],
    }));
    let head_b = f.repo.head_b.clone();
    let out = f.run_verify(&head_b);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("no disposition"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn verify_final_rejects_not_triggered_without_executed_trigger() {
    let f = fixture(Vec::new(), "implementer-a", "verifier-b", false);
    let green = evidence_for(&f.artifact);
    f.rewrite_requirements(green, "implementer-a", "verifier-b");
    f.rewrite_experiments(json!({
        "schema": "repo-scan/experiments/1",
        "experiments": [{
            "id": "EXP-COND-X",
            "disposition": "not_triggered"
        }],
    }));
    let head_b = f.repo.head_b.clone();
    let out = f.run_verify(&head_b);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("trigger evidence"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn verify_final_rejects_experiment_evidence_hash_mismatch() {
    let f = fixture(Vec::new(), "implementer-a", "verifier-b", false);
    let green = evidence_for(&f.artifact);
    f.rewrite_requirements(green, "implementer-a", "verifier-b");
    f.rewrite_experiments(json!({
        "schema": "repo-scan/experiments/1",
        "experiments": [{
            "id": "EXP-X",
            "disposition": "qualified_enabled",
            "evidence": [{
                "path": f.artifact.display().to_string(),
                "sha256": "2".repeat(64),
            }],
        }],
    }));
    let head_b = f.repo.head_b.clone();
    let out = f.run_verify(&head_b);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
}
