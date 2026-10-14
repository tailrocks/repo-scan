//! Black-box corrupt-bundle tests for `proof evaluate` and the
//! `proof benchmark` collection path (goal section 3.3).
//!
//! Exit-code contract: 0 PASS, 1 FAIL, 2 INVALID_EVIDENCE.

mod common;

use common::{code, make_benchmark_bundle, rewrite_checksums, run, stdout, write_json};

const BLOCKS: usize = 24;

#[test]
fn evaluate_accepts_minimal_valid_bundle() {
    let dir = tempfile::TempDir::new().unwrap();
    let run_dir = make_benchmark_bundle(dir.path(), 0.70, BLOCKS);
    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("\"PASS\""),
        "stdout: {}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("PERF-PRIMARY"));
}

#[test]
fn evaluate_fails_baseline_vs_baseline_on_material_improvement_gate() {
    let dir = tempfile::TempDir::new().unwrap();
    // Identical binaries: ratio 1.0 cannot satisfy U95(R) <= 0.75.
    let run_dir = make_benchmark_bundle(dir.path(), 1.0, BLOCKS);
    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("\"FAIL\""), "stdout: {text}");
    assert!(text.contains("\"status\": \"fail\""), "stdout: {text}");
}

#[test]
fn evaluate_fails_slower_candidate_on_perf_primary() {
    let dir = tempfile::TempDir::new().unwrap();
    let run_dir = make_benchmark_bundle(dir.path(), 1.25, BLOCKS);
    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("PERF-PRIMARY"));
}

#[test]
fn evaluate_rejects_malformed_run_manifest() {
    let dir = tempfile::TempDir::new().unwrap();
    let run_dir = make_benchmark_bundle(dir.path(), 0.70, BLOCKS);
    std::fs::write(run_dir.join("run-manifest.json"), b"{not json").unwrap();
    rewrite_checksums(&run_dir);
    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
}

#[test]
fn evaluate_rejects_empty_timing_samples() {
    let dir = tempfile::TempDir::new().unwrap();
    let run_dir = make_benchmark_bundle(dir.path(), 0.70, BLOCKS);
    std::fs::write(run_dir.join("samples.jsonl"), b"").unwrap();
    rewrite_checksums(&run_dir);
    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
}

#[test]
fn evaluate_rejects_fabricated_raw_sample_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let run_dir = make_benchmark_bundle(dir.path(), 0.70, BLOCKS);
    // Fabricate a faster candidate without updating the checksum seal.
    let mut samples = String::new();
    for b in 0..BLOCKS {
        for (role, elapsed) in [("baseline", 1_000_000u64), ("candidate", 100_000u64)] {
            samples.push_str(
                &serde_json::json!({
                    "block": b, "order": "baseline_first", "role": role,
                    "scenario": common::primary_scenario(),
                    "elapsed_ns": elapsed, "exit_code": 0,
                })
                .to_string(),
            );
            samples.push('\n');
        }
    }
    std::fs::write(run_dir.join("samples.jsonl"), samples).unwrap();
    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("checksum mismatch"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn evaluate_rejects_missing_raw_sample_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let run_dir = make_benchmark_bundle(dir.path(), 0.70, BLOCKS);
    std::fs::remove_file(run_dir.join("samples.jsonl")).unwrap();
    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("missing"), "stdout: {}", stdout(&out));
}

#[test]
fn evaluate_rejects_changed_policy_hash() {
    let dir = tempfile::TempDir::new().unwrap();
    // Tamper with a threshold after freezing: the self-hash no longer matches.
    let mut policy = common::read_json(&common::policy_path());
    policy["gates"][0]["threshold"] = serde_json::json!(0.99);
    let tampered = dir.path().join("policy-tampered.json");
    write_json(&tampered, &policy);

    let run_dir = make_benchmark_bundle(dir.path(), 0.70, BLOCKS);
    let mut manifest = common::read_json(&run_dir.join("run-manifest.json"));
    manifest["policy"]["path"] = serde_json::json!(tampered.display().to_string());
    write_json(&run_dir.join("run-manifest.json"), &manifest);
    rewrite_checksums(&run_dir);

    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("self-hash mismatch"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn evaluate_rejects_missing_run_dir() {
    let dir = tempfile::TempDir::new().unwrap();
    let missing = dir.path().join("no-such-run");
    let out = run(&["proof", "evaluate", "--run-dir", missing.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
}

#[test]
fn evaluate_rejects_too_few_blocks() {
    let dir = tempfile::TempDir::new().unwrap();
    // 4 blocks is below the frozen minimum of 20 paired blocks.
    let run_dir = make_benchmark_bundle(dir.path(), 0.70, 4);
    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
}

/// End-to-end: `proof benchmark` collecting baseline-vs-baseline samples,
/// then `proof evaluate` failing the material-improvement gate.
#[cfg(unix)]
#[test]
fn benchmark_then_evaluate_identical_binaries_fails_improvement() {
    let dir = tempfile::TempDir::new().unwrap();
    let out_root = dir.path().join("proof-out");
    let policy = common::policy_path();
    let scenario = common::primary_scenario();
    let out = run(&[
        "proof",
        "benchmark",
        "--policy",
        policy.to_str().unwrap(),
        "--baseline-bin",
        "/usr/bin/true",
        "--candidate-bin",
        "/usr/bin/true",
        "--scenario",
        &scenario,
        "--blocks",
        "20",
        "--out-root",
        out_root.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));
    let collected: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("collection json");
    let run_dir = collected["run_dir"].as_str().expect("run_dir").to_string();

    let out = run(&["proof", "evaluate", "--run-dir", &run_dir]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("\"FAIL\""),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn evaluate_rejects_manifest_seed_different_from_policy() {
    let dir = tempfile::TempDir::new().unwrap();
    let run_dir = make_benchmark_bundle(dir.path(), 0.70, BLOCKS);
    let mut manifest = common::read_json(&run_dir.join("run-manifest.json"));
    manifest["protocol"]["rng_seed"] = serde_json::json!(42u64);
    write_json(&run_dir.join("run-manifest.json"), &manifest);
    rewrite_checksums(&run_dir);
    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("rng_seed"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn evaluate_rejects_primary_run_missing_mandatory_primary_gate() {
    let dir = tempfile::TempDir::new().unwrap();
    // Ratio 0.9 would satisfy PERF-NOREGRESS (<= 1.05) but must never skip
    // the mandatory PERF-PRIMARY gate on a primary-scenario run.
    let run_dir = make_benchmark_bundle(dir.path(), 0.90, BLOCKS);
    let mut manifest = common::read_json(&run_dir.join("run-manifest.json"));
    manifest["gates_evaluated"] = serde_json::json!(["PERF-NOREGRESS"]);
    write_json(&run_dir.join("run-manifest.json"), &manifest);
    rewrite_checksums(&run_dir);
    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    let text = stdout(&out);
    assert_ne!(code(&out), 0, "stdout: {text}");
    assert_eq!(code(&out), 2, "stdout: {text}");
    assert!(text.contains("PERF-PRIMARY"), "stdout: {text}");
    assert!(text.contains("mandatory"), "stdout: {text}");
}

#[test]
fn evaluate_rejects_noregress_gate_without_noregress_scenarios() {
    let dir = tempfile::TempDir::new().unwrap();
    // Declaring PERF-NOREGRESS while covering only the primary scenario is
    // invalid even when the mandatory primary gate is also declared and the
    // primary gate itself passes.
    let run_dir = make_benchmark_bundle(dir.path(), 0.70, BLOCKS);
    let mut manifest = common::read_json(&run_dir.join("run-manifest.json"));
    manifest["gates_evaluated"] = serde_json::json!(["PERF-PRIMARY", "PERF-NOREGRESS"]);
    write_json(&run_dir.join("run-manifest.json"), &manifest);
    rewrite_checksums(&run_dir);
    let out = run(&["proof", "evaluate", "--run-dir", run_dir.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
}

/// `proof benchmark` refuses a --seed that differs from the frozen policy.
#[cfg(unix)]
#[test]
fn benchmark_rejects_seed_override() {
    let dir = tempfile::TempDir::new().unwrap();
    let policy = common::policy_path();
    let scenario = common::primary_scenario();
    let out = run(&[
        "proof",
        "benchmark",
        "--policy",
        policy.to_str().unwrap(),
        "--baseline-bin",
        "/usr/bin/true",
        "--candidate-bin",
        "/usr/bin/true",
        "--scenario",
        &scenario,
        "--blocks",
        "20",
        "--seed",
        "1",
        "--out-root",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
}

#[cfg(unix)]
#[test]
fn benchmark_collects_multiple_scenarios() {
    let dir = tempfile::TempDir::new().unwrap();
    let policy = common::policy_path();
    let s1 = common::primary_scenario();
    let s2 = "wide-file-heavy-warm-fs-identity";
    let multi_scenario = format!("{s1},{s2}");
    let out = run(&[
        "proof",
        "benchmark",
        "--policy",
        policy.to_str().unwrap(),
        "--baseline-bin",
        "/usr/bin/true",
        "--candidate-bin",
        "/usr/bin/true",
        "--scenario",
        &multi_scenario,
        "--blocks",
        "20",
        "--out-root",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));
    let collected: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("collection json");
    let run_dir = std::path::PathBuf::from(collected["run_dir"].as_str().unwrap());
    let samples_content = std::fs::read_to_string(run_dir.join("samples.jsonl")).unwrap();
    assert!(samples_content.contains(&s1));
    assert!(samples_content.contains(s2));
}
