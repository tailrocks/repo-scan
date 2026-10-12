//! `proof integration`: run the integration test matrix, capture the full
//! log, classify per-file pass/fail, and fail on any failure or on a
//! mandatory test that was skipped/ignored/absent (goal sections 3.2, 3.3).
//!
//! The matrix is validated before any test command runs: an unrecognized
//! platform is INVALID_EVIDENCE (2), never silently accepted.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_CMD: &str = "cargo test --locked --test '*'";

#[derive(Default)]
struct FileResults {
    passed: Vec<String>,
    failed: Vec<String>,
    ignored: Vec<String>,
}

/// Validate the platform matrix; returns (mandatory_tests, errors).
fn validate_matrix(matrix: &Value) -> (Vec<String>, Vec<String>) {
    let mut errors = Vec::new();
    if matrix.get("schema").and_then(Value::as_str).is_none() {
        errors.push("matrix lacks 'schema'".to_string());
    }
    let known: Vec<String> = matrix
        .get("known_platforms")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_else(|| {
            crate::requirements::KNOWN_PLATFORMS
                .iter()
                .map(|s| s.to_string())
                .collect()
        });
    match matrix
        .get("mandatory_native_jobs")
        .and_then(Value::as_array)
    {
        Some(jobs) => {
            for (i, job) in jobs.iter().enumerate() {
                let ctx = format!("mandatory_native_jobs[{i}]");
                let Some(obj) = job.as_object() else {
                    errors.push(format!("{ctx}: not an object"));
                    continue;
                };
                match obj.get("platform").and_then(Value::as_str) {
                    Some(p) if known.iter().any(|k| k == p) => {}
                    Some(p) => errors.push(format!(
                        "{ctx}: unrecognized platform '{p}' (known: {})",
                        known.join(", ")
                    )),
                    None => errors.push(format!("{ctx}: missing 'platform'")),
                }
                if obj.get("id").and_then(Value::as_str).is_none() {
                    errors.push(format!("{ctx}: missing 'id'"));
                }
            }
        }
        None => errors.push("matrix lacks 'mandatory_native_jobs' array".to_string()),
    }
    let mandatory = match matrix.get("mandatory_tests").and_then(Value::as_array) {
        Some(arr) => {
            let mut out = Vec::new();
            for (i, t) in arr.iter().enumerate() {
                match t.as_str().filter(|s| !s.is_empty()) {
                    Some(s) => out.push(s.to_string()),
                    None => errors.push(format!("mandatory_tests[{i}] is not a non-empty string")),
                }
            }
            out
        }
        None => {
            errors.push("matrix lacks 'mandatory_tests' array".to_string());
            Vec::new()
        }
    };
    (mandatory, errors)
}

/// Parse cargo test output into per-file results.
fn parse_cargo_log(log: &str) -> BTreeMap<String, FileResults> {
    let mut files: BTreeMap<String, FileResults> = BTreeMap::new();
    let mut current = "unknown".to_string();
    for line in log.lines() {
        let t = line.trim_start();
        if t.starts_with("Running ") || t.starts_with("Doc-tests ") {
            // e.g. "Running tests/accept_fs.rs (target/debug/deps/…-abcd)"
            current = t
                .split_whitespace()
                .skip(1)
                .take_while(|tok| !tok.starts_with('('))
                .collect::<Vec<_>>()
                .join(" ");
            if current.is_empty() {
                current = "unknown".to_string();
            }
            files.entry(current.clone()).or_default();
            continue;
        }
        let Some(rest) = t.strip_prefix("test ") else {
            continue;
        };
        let Some(idx) = rest.find(" ... ") else {
            continue;
        };
        let name = rest[..idx].to_string();
        let status = rest[idx + 5..].trim();
        let entry = files.entry(current.clone()).or_default();
        if status == "ok" {
            entry.passed.push(name);
        } else if status == "FAILED" {
            entry.failed.push(name);
        } else if status.starts_with("ignored") {
            entry.ignored.push(name);
        }
    }
    files
}

pub fn cmd_integration(
    matrix_path: &Path,
    repo: Option<PathBuf>,
    cmd: Option<String>,
    out_root: &Path,
) -> i32 {
    let matrix = match crate::canon::read_json(matrix_path) {
        Ok(m) => m,
        Err(e) => crate::invalid(e),
    };
    let (mandatory, matrix_errors) = validate_matrix(&matrix);
    if !matrix_errors.is_empty() {
        crate::emit_exit(
            crate::EXIT_INVALID,
            "INVALID_EVIDENCE",
            json!({"errors": matrix_errors}),
        );
    }
    let matrix_sha = match crate::canon::sha256_file(matrix_path) {
        Ok(s) => s,
        Err(e) => crate::invalid(format!("cannot hash matrix: {e}")),
    };
    let repo = repo.unwrap_or_else(|| PathBuf::from("."));
    let cmd = cmd.unwrap_or_else(|| DEFAULT_CMD.to_string());

    let run = match crate::runs::create(out_root) {
        Ok(r) => r,
        Err(e) => crate::blocked(format!("cannot create run dir: {e}")),
    };
    let started = crate::runs::now_rfc3339();
    let output = match Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .current_dir(&repo)
        .output()
    {
        Ok(o) => o,
        Err(e) => crate::blocked(format!("cannot spawn test command shell: {e}")),
    };
    let ended = crate::runs::now_rfc3339();
    let exit_code = output.status.code().unwrap_or(-1);

    let mut log = String::new();
    log.push_str(&String::from_utf8_lossy(&output.stdout));
    log.push_str(&String::from_utf8_lossy(&output.stderr));
    if let Err(e) = fs::write(run.path.join("integration-log.txt"), &log) {
        crate::blocked(format!("cannot write log: {e}"));
    }

    let results = parse_cargo_log(&log);
    let mut problems: Vec<String> = Vec::new();
    if exit_code != 0 {
        problems.push(format!("test command exited {exit_code}"));
    }
    let mut seen_tests: BTreeMap<String, (&str, &str)> = BTreeMap::new();
    for (file, res) in &results {
        for name in &res.failed {
            problems.push(format!("test FAILED: {name} ({file})"));
            seen_tests.insert(name.clone(), (file, "failed"));
        }
        for name in &res.passed {
            seen_tests.insert(name.clone(), (file, "ok"));
        }
        for name in &res.ignored {
            seen_tests.insert(name.clone(), (file, "ignored"));
        }
    }
    for name in &mandatory {
        match seen_tests.get(name) {
            Some((file, "ignored")) => {
                problems.push(format!("mandatory test skipped/ignored: {name} ({file})"))
            }
            Some((_, "ok")) => {}
            Some((file, other)) => {
                problems.push(format!("mandatory test {name} has status {other} ({file})"))
            }
            None => problems.push(format!("mandatory test absent from executed log: {name}")),
        }
    }

    let results_json: BTreeMap<String, Value> = results
        .iter()
        .map(|(file, res)| {
            (
                file.clone(),
                json!({
                    "passed": res.passed,
                    "failed": res.failed,
                    "ignored": res.ignored,
                }),
            )
        })
        .collect();
    let results_doc = json!({
        "schema": "repo-scan/integration-results/1",
        "command": cmd,
        "exit_code": exit_code,
        "files": results_json,
        "problems": problems,
    });
    if let Err(e) =
        crate::canon::write_json(&run.path.join("integration-results.json"), &results_doc)
    {
        crate::blocked(format!("cannot write results: {e}"));
    }
    let manifest = json!({
        "schema": "repo-scan/run-manifest/1",
        "run_id": run.id,
        "kind": "integration",
        "created_at": started,
        "matrix": {"path": matrix_path.display().to_string(), "sha256": matrix_sha},
        "build": crate::runs::build_metadata(),
        "host": crate::runs::host_metadata(),
        "command": {"shell": cmd, "exit": exit_code},
        "timing": {"started_at": started, "ended_at": ended},
    });
    if let Err(e) = crate::canon::write_json(&run.path.join(crate::runs::MANIFEST_FILE), &manifest)
    {
        crate::blocked(format!("cannot write manifest: {e}"));
    }
    if let Err(e) = crate::runs::write_checksums(&run.path) {
        crate::blocked(format!("cannot write checksums: {e}"));
    }

    if problems.is_empty() {
        crate::emit_exit(
            crate::EXIT_PASS,
            "PASS",
            json!({
                "run_dir": run.path.display().to_string(),
                "files": results.len(),
            }),
        );
    }
    crate::emit_exit(
        crate::EXIT_FAIL,
        "FAIL",
        json!({
            "run_dir": run.path.display().to_string(),
            "problems": problems,
        }),
    );
}
