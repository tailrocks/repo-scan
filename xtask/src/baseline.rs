//! `proof baseline`: run a named binary against a frozen dataset recipe and
//! capture timing samples plus counters into `proof-out/<run-id>/`.
//!
//! Timing is process start to exit; if the binary prints stage marker lines
//! of the form `STAGE <name> <milliseconds>` they are parsed into the sample
//! record. Runs are deterministic (fixed recipe identity, fixed command) and
//! never touch the network.

use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const LOG_CAP_BYTES: usize = 1 << 20;

/// Parse `STAGE <name> <ms>` marker lines from captured stdout, if present.
fn parse_stage_markers(stdout: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    let mut stages = serde_json::Map::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        let Some(rest) = line.strip_prefix("STAGE ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let (Some(name), Some(ms), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if let Ok(ms) = ms.parse::<f64>() {
            stages.insert(name.to_string(), json!(ms));
        }
    }
    stages
}

fn resolve_recipe(dataset: &str) -> Result<PathBuf, String> {
    let as_path = Path::new(dataset);
    if as_path.is_file() {
        return Ok(as_path.to_path_buf());
    }
    let candidate = Path::new("proof/datasets").join(format!("{dataset}.json"));
    if candidate.is_file() {
        return Ok(candidate);
    }
    Err(format!(
        "dataset '{dataset}' is neither a file nor a recipe id under proof/datasets/"
    ))
}

pub fn cmd_baseline(
    policy_path: &Path,
    bin: &Path,
    dataset: &str,
    samples: Option<usize>,
    out_root: &Path,
    args: &[String],
) -> i32 {
    let policy = match crate::policy::load(policy_path) {
        Ok(p) => p,
        Err(e) => crate::invalid(e),
    };
    if !bin.is_file() {
        crate::blocked(format!("binary {} not found", bin.display()));
    }
    let recipe_path = match resolve_recipe(dataset) {
        Ok(p) => p,
        Err(e) => crate::invalid(e),
    };
    let recipe = match crate::canon::read_json(&recipe_path) {
        Ok(r) => r,
        Err(e) => crate::invalid(e),
    };
    let dataset_id = match recipe.get("id").and_then(serde_json::Value::as_str) {
        Some(s) => s.to_string(),
        None => crate::invalid(format!("{}: recipe lacks 'id'", recipe_path.display())),
    };
    let dataset_seed = match recipe.get("seed").and_then(serde_json::Value::as_u64) {
        Some(s) => s,
        None => crate::invalid(format!("{}: recipe lacks 'seed'", recipe_path.display())),
    };
    let recipe_sha = match crate::canon::sha256_file(&recipe_path) {
        Ok(s) => s,
        Err(e) => crate::invalid(format!("cannot hash recipe: {e}")),
    };
    let bin_sha = match crate::canon::sha256_file(bin) {
        Ok(s) => s,
        Err(e) => crate::blocked(format!("cannot hash {}: {e}", bin.display())),
    };

    let run = match crate::runs::create(out_root) {
        Ok(r) => r,
        Err(e) => crate::blocked(format!(
            "cannot create run dir under {}: {e}",
            out_root.display()
        )),
    };
    let reps = samples.unwrap_or(5);
    let started = crate::runs::now_rfc3339();
    let samples_path = run.path.join(crate::runs::SAMPLES_FILE);
    let mut samples_file = match fs::File::create(&samples_path) {
        Ok(f) => f,
        Err(e) => crate::blocked(format!("cannot create samples file: {e}")),
    };

    let mut exits = Vec::new();
    for i in 0..reps {
        let start = Instant::now();
        let out = match Command::new(bin).args(args).output() {
            Ok(o) => o,
            Err(e) => crate::blocked(format!("cannot spawn {}: {e}", bin.display())),
        };
        let elapsed_ns = start.elapsed().as_nanos() as u64;
        let code = out.status.code().unwrap_or(-1);
        exits.push(code);

        let stdout_log = format!("sample-{i}.stdout.log");
        let stderr_log = format!("sample-{i}.stderr.log");
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
            "sample": i,
            "role": "baseline",
            "elapsed_ns": elapsed_ns,
            "exit_code": code,
            "stages": parse_stage_markers(&out.stdout),
            "stdout_log": stdout_log,
            "stderr_log": stderr_log,
            "truncated": truncated,
        });
        writeln!(samples_file, "{line}").expect("write sample");
    }
    drop(samples_file);
    let ended = crate::runs::now_rfc3339();

    let argv: Vec<String> = std::iter::once(bin.display().to_string())
        .chain(args.iter().cloned())
        .collect();
    let manifest = json!({
        "schema": "repo-scan/run-manifest/1",
        "run_id": run.id,
        "kind": "baseline",
        "created_at": started,
        "policy": {
            "path": policy_path.display().to_string(),
            "sha256": policy.self_hash,
        },
        "build": crate::runs::build_metadata(),
        "host": crate::runs::host_metadata(),
        "binaries": {
            "baseline": {"path": bin.display().to_string(), "sha256": bin_sha},
        },
        "command": {
            "argv": argv,
            "exits": exits,
        },
        "dataset": {
            "id": dataset_id,
            "seed": dataset_seed,
            "recipe_path": recipe_path.display().to_string(),
            "recipe_sha256": recipe_sha,
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
            "samples": reps,
            "note": "baseline samples collected; verdicts come from proof evaluate",
        }),
    );
}
