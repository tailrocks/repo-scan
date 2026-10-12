//! Shared helpers for xtask black-box integration tests (goal section 3.3).
//!
//! Everything runs through the built `xtask` binary; fixtures live in
//! tempdirs so the source tree stays clean.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub fn xtask() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_xtask"))
}

pub fn run(args: &[&str]) -> Output {
    Command::new(xtask())
        .args(args)
        .output()
        .expect("spawn xtask")
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn code(o: &Output) -> i32 {
    o.status.code().expect("exit code")
}

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

pub fn policy_path() -> PathBuf {
    workspace_root().join("proof/policy.json")
}

pub fn policy_self_hash() -> String {
    let v = read_json(&policy_path());
    v.get("sha256")
        .and_then(Value::as_str)
        .expect("policy sha256")
        .to_string()
}

pub fn primary_scenario() -> String {
    let v = read_json(&policy_path());
    v.pointer("/gates/0/scenario")
        .and_then(Value::as_str)
        .expect("primary scenario")
        .to_string()
}

pub fn sha256_file(path: &Path) -> String {
    let data = fs::read(path).expect("read for sha256");
    let mut h = Sha256::new();
    h.update(&data);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

pub fn write_json(path: &Path, v: &Value) {
    fs::write(path, serde_json::to_string_pretty(v).unwrap() + "\n").expect("write json");
}

pub fn read_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("read json")).expect("parse json")
}

/// git with a fixed identity and dates for deterministic commits.
pub fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_AUTHOR_NAME", "proof-test")
        .env("GIT_AUTHOR_EMAIL", "proof@test.invalid")
        .env("GIT_COMMITTER_NAME", "proof-test")
        .env("GIT_COMMITTER_EMAIL", "proof@test.invalid")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed in {}: {}",
        args,
        repo.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

pub struct TestRepo {
    pub dir: tempfile::TempDir,
    pub head_a: String,
    pub head_b: String,
}

/// A repo with two commits on main and two frozen source refs:
/// refs/goal/sources/alpha -> A, refs/goal/sources/beta -> B (child of A).
pub fn setup_repo() -> TestRepo {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let repo = dir.path();
    git(repo, &["init", "-q", "-b", "main", "."]);
    fs::write(repo.join("a.txt"), b"a\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "a"]);
    let head_a = git(repo, &["rev-parse", "HEAD"]);
    fs::write(repo.join("b.txt"), b"b\n").unwrap();
    git(repo, &["add", "b.txt"]);
    git(repo, &["commit", "-q", "-m", "b"]);
    let head_b = git(repo, &["rev-parse", "HEAD"]);
    git(repo, &["update-ref", "refs/goal/sources/alpha", &head_a]);
    git(repo, &["update-ref", "refs/goal/sources/beta", &head_b]);
    TestRepo {
        dir,
        head_a,
        head_b,
    }
}

/// sources.lock.json value covering alpha -> head_a, beta -> head_b.
/// `omit_beta` drops the beta entry while the repo still carries the ref.
pub fn make_lock(repo: &Path, head_a: &str, head_b: &str, omit_beta: bool) -> Value {
    let commit_info = |head: &str| -> (String, Vec<String>) {
        let raw = git(repo, &["cat-file", "commit", head]);
        let mut tree = String::new();
        let mut parents = Vec::new();
        for line in raw.lines() {
            if line.is_empty() {
                break;
            }
            if let Some(t) = line.strip_prefix("tree ") {
                tree = t.to_string();
            }
            if let Some(p) = line.strip_prefix("parent ") {
                parents.push(p.to_string());
            }
        }
        (tree, parents)
    };
    let mut sources = Vec::new();
    for (id, refname, head) in [
        ("S01", "alpha", head_a.to_string()),
        ("S02", "beta", head_b.to_string()),
    ] {
        if omit_beta && id == "S02" {
            continue;
        }
        let (tree, parents) = commit_info(&head);
        sources.push(json!({
            "id": id,
            "ref": refname,
            "frozen_ref": format!("refs/goal/sources/{refname}"),
            "head": head,
            "tree": tree,
            "parents": parents,
            "object_type": "commit",
        }));
    }
    json!({
        "schema": "repo-scan/sources-lock/1",
        "frozen_at": "2026-01-01T00:00:00Z",
        "sources": sources,
    })
}

/// A minimal valid benchmark run bundle: `blocks` paired blocks at a
/// constant candidate/baseline ratio, real frozen policy, sealed checksums.
pub fn make_benchmark_bundle(root: &Path, ratio: f64, blocks: usize) -> PathBuf {
    let run = root.join("run-1");
    fs::create_dir_all(&run).expect("run dir");
    let scenario = primary_scenario();
    let mut samples = String::new();
    for b in 0..blocks {
        let base = 1_000_000u64;
        let cand = (base as f64 * ratio) as u64;
        for (role, elapsed) in [("baseline", base), ("candidate", cand)] {
            samples.push_str(
                &json!({
                    "block": b,
                    "order": "baseline_first",
                    "role": role,
                    "scenario": scenario,
                    "elapsed_ns": elapsed,
                    "exit_code": 0,
                })
                .to_string(),
            );
            samples.push('\n');
        }
    }
    fs::write(run.join("samples.jsonl"), samples).expect("samples");
    let manifest = json!({
        "schema": "repo-scan/run-manifest/1",
        "run_id": "run-1",
        "kind": "benchmark",
        "created_at": "2026-01-01T00:00:00Z",
        "policy": {
            "path": policy_path().display().to_string(),
            "sha256": policy_self_hash(),
        },
        "build": {"rustc": "test", "xtask_version": "0"},
        "host": {"os": "test", "arch": "test", "family": "test"},
        "binaries": {
            "baseline": {"path": "baseline-bin", "sha256": "00"},
            "candidate": {"path": "candidate-bin", "sha256": "11"},
        },
        "command": {"baseline_argv": [], "candidate_argv": []},
        "scenario": scenario,
        "gates_evaluated": ["PERF-PRIMARY"],
        "protocol": {"blocks": blocks, "rng_seed": 761031364449u64},
        "timing": {"started_at": "2026-01-01T00:00:00Z", "ended_at": "2026-01-01T00:00:01Z"},
    });
    write_json(&run.join("run-manifest.json"), &manifest);
    rewrite_checksums(&run);
    run
}

/// Recompute checksums.json over the current files in `dir` (flat bundles).
pub fn rewrite_checksums(dir: &Path) {
    let mut files = serde_json::Map::new();
    for entry in fs::read_dir(dir).expect("read run dir") {
        let p = entry.expect("entry").path();
        if p.is_file() && p.file_name().unwrap() != "checksums.json" {
            files.insert(
                p.file_name().unwrap().to_string_lossy().into_owned(),
                json!(sha256_file(&p)),
            );
        }
    }
    write_json(
        &dir.join("checksums.json"),
        &json!({"schema": "repo-scan/run-checksums/1", "files": files}),
    );
}

/// A requirements document with a single required item.
pub fn make_requirements(green_evidence: Vec<Value>, implementer: &str, verifier: &str) -> Value {
    json!({
        "schema": "repo-scan/requirements/1",
        "requirements": [{
            "id": "GOV-01",
            "rfc_sections": ["goal section 1.2"],
            "kind": "required",
            "claim": "synthetic test requirement",
            "platforms": ["macos"],
            "tests": ["governance::gov_01_contract_tbd"],
            "oracle": "test-oracle",
            "red_evidence": [],
            "green_evidence": green_evidence,
            "negative_controls": [],
            "performance_gate_ids": [],
            "implementer": implementer,
            "verifier": verifier,
            "status": "green",
        }],
    })
}

/// An experiments registry with one experiment in a valid disposition, its
/// evidence pointing at `artifact` (goal section 3.2 dispositions).
pub fn make_experiments(artifact: &Path) -> Value {
    json!({
        "schema": "repo-scan/experiments/1",
        "experiments": [{
            "id": "EXP-X",
            "class": "required",
            "hypothesis": "h",
            "trigger": "t",
            "controlled_variable": "c",
            "expected_benefit": "b",
            "acceptance_rule": "a",
            "rejection_rule": "r",
            "default_enablement": "off",
            "status": "complete",
            "disposition": "evaluated_not_enabled",
            "evidence": [{
                "path": artifact.display().to_string(),
                "sha256": sha256_file(artifact),
            }],
        }],
    })
}
