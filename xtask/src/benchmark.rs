//! `proof benchmark`: paired-block benchmark between two binaries.
//!
//! Blocks alternate in randomized balanced order driven by a seeded
//! SplitMix64 (goal section 7.3): within each pair of blocks one runs
//! baseline-first and one candidate-first, assigned by the seeded RNG. Raw
//! samples are appended as JSONL and sealed with checksums; evaluation is a
//! separate `proof evaluate` step.

use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

const LOG_CAP_BYTES: usize = 1 << 20;

#[allow(clippy::too_many_arguments)]
pub fn cmd_benchmark(
    policy_path: &Path,
    baseline_bin: &Path,
    candidate_bin: &Path,
    scenario: &str,
    blocks: Option<usize>,
    seed: Option<u64>,
    gates: Option<String>,
    out_root: &Path,
    args: &[String],
) -> i32 {
    let policy = match crate::policy::load(policy_path) {
        Ok(p) => p,
        Err(e) => crate::invalid(e),
    };
    let blocks = blocks.unwrap_or(policy.min_paired_blocks);
    if blocks < policy.min_paired_blocks {
        crate::invalid(format!(
            "blocks {blocks} is below the frozen policy minimum of {} paired blocks",
            policy.min_paired_blocks
        ));
    }
    for (role, b) in [("baseline", baseline_bin), ("candidate", candidate_bin)] {
        if !b.is_file() {
            crate::blocked(format!("{role} binary {} not found", b.display()));
        }
    }
    let baseline_sha = match crate::canon::sha256_file(baseline_bin) {
        Ok(s) => s,
        Err(e) => crate::blocked(format!("cannot hash baseline binary: {e}")),
    };
    let candidate_sha = match crate::canon::sha256_file(candidate_bin) {
        Ok(s) => s,
        Err(e) => crate::blocked(format!("cannot hash candidate binary: {e}")),
    };

    let gate_ids: Vec<String> = match gates {
        Some(g) => g
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        None => {
            if scenario == policy.primary_scenario {
                vec!["PERF-PRIMARY".to_string()]
            } else {
                vec!["PERF-NOREGRESS".to_string()]
            }
        }
    };
    if gate_ids.is_empty() {
        crate::invalid("no gates selected for evaluation");
    }
    for id in &gate_ids {
        if policy.gate(id).is_none() {
            crate::invalid(format!("gate '{id}' is not defined in the frozen policy"));
        }
    }
    let seed = seed.unwrap_or(policy.rng_seed);

    let run = match crate::runs::create(out_root) {
        Ok(r) => r,
        Err(e) => crate::blocked(format!("cannot create run dir: {e}")),
    };
    let started = crate::runs::now_rfc3339();
    let samples_path = run.path.join(crate::runs::SAMPLES_FILE);
    let mut samples_file = match fs::File::create(&samples_path) {
        Ok(f) => f,
        Err(e) => crate::blocked(format!("cannot create samples file: {e}")),
    };

    // Balanced randomized order: each pair of blocks contains one
    // baseline-first and one candidate-first block, assigned by the RNG.
    let mut rng = crate::stats::SplitMix64::new(seed);
    let mut baseline_first = Vec::with_capacity(blocks);
    let mut i = 0;
    while i + 1 < blocks {
        let first = rng.coin();
        baseline_first.push(first);
        baseline_first.push(!first);
        i += 2;
    }
    if i < blocks {
        baseline_first.push(rng.coin());
    }

    for (block, &bf) in baseline_first.iter().enumerate() {
        let order: [(&str, &Path); 2] = if bf {
            [("baseline", baseline_bin), ("candidate", candidate_bin)]
        } else {
            [("candidate", candidate_bin), ("baseline", baseline_bin)]
        };
        for (role, bin) in order {
            let start = Instant::now();
            let out = match Command::new(bin).args(args).output() {
                Ok(o) => o,
                Err(e) => crate::blocked(format!("cannot spawn {}: {e}", bin.display())),
            };
            let elapsed_ns = start.elapsed().as_nanos() as u64;
            let code = out.status.code().unwrap_or(-1);
            let stdout_log = format!("block-{block:04}-{role}.stdout.log");
            let stderr_log = format!("block-{block:04}-{role}.stderr.log");
            let truncated = out.stdout.len() > LOG_CAP_BYTES || out.stderr.len() > LOG_CAP_BYTES;
            let _ = fs::write(
                run.path.join(&stdout_log),
                &out.stdout[..out.stdout.len().min(LOG_CAP_BYTES)],
            );
            let _ = fs::write(
                run.path.join(&stderr_log),
                &out.stderr[..out.stderr.len().min(LOG_CAP_BYTES)],
            );
            let line = json!({
                "block": block,
                "order": if bf { "baseline_first" } else { "candidate_first" },
                "role": role,
                "scenario": scenario,
                "elapsed_ns": elapsed_ns,
                "exit_code": code,
                "stdout_log": stdout_log,
                "stderr_log": stderr_log,
                "truncated": truncated,
            });
            writeln!(samples_file, "{line}").expect("write sample");
        }
    }
    drop(samples_file);
    let ended = crate::runs::now_rfc3339();

    let baseline_argv: Vec<String> = std::iter::once(baseline_bin.display().to_string())
        .chain(args.iter().cloned())
        .collect();
    let candidate_argv: Vec<String> = std::iter::once(candidate_bin.display().to_string())
        .chain(args.iter().cloned())
        .collect();
    let manifest = json!({
        "schema": "repo-scan/run-manifest/1",
        "run_id": run.id,
        "kind": "benchmark",
        "created_at": started,
        "policy": {
            "path": policy_path.display().to_string(),
            "sha256": policy.self_hash,
        },
        "build": crate::runs::build_metadata(),
        "host": crate::runs::host_metadata(),
        "binaries": {
            "baseline": {"path": baseline_bin.display().to_string(), "sha256": baseline_sha},
            "candidate": {"path": candidate_bin.display().to_string(), "sha256": candidate_sha},
        },
        "command": {
            "baseline_argv": baseline_argv,
            "candidate_argv": candidate_argv,
        },
        "dataset": null,
        "scenario": scenario,
        "gates_evaluated": gate_ids,
        "protocol": {
            "blocks": blocks,
            "rng_seed": seed,
            "order": "randomized balanced baseline/candidate within paired blocks",
        },
        "timing": {"started_at": started, "ended_at": ended},
    });
    if let Err(e) = crate::canon::write_json(&run.path.join(crate::runs::MANIFEST_FILE), &manifest)
    {
        crate::blocked(format!("cannot write manifest: {e}"));
    }
    if let Err(e) = crate::runs::write_checksums(&run.path) {
        crate::blocked(format!("cannot write checksums: {e}"));
    }
    crate::emit_exit(
        crate::EXIT_PASS,
        "COLLECTED",
        json!({
            "run_dir": run.path.display().to_string(),
            "blocks": blocks,
            "note": "raw samples collected; verdicts come from proof evaluate",
        }),
    );
}
