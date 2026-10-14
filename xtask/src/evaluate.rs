//! `proof evaluate`: validate a run directory and compute the verdict.
//!
//! Pipeline: checksums integrity -> manifest parse -> policy self-hash and
//! recorded-hash match -> sample parse/validation -> paired-block ratios ->
//! seeded bootstrap one-sided 95% upper bounds -> frozen gate comparison.
//!
//! Verdicts (goal section 3.2): PASS (0), FAIL (1), INVALID_EVIDENCE (2),
//! BLOCKED (3). Missing samples, malformed JSON, or empty timing arrays are
//! INVALID_EVIDENCE — never zero.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::policy::Policy;

struct Sample {
    block: u64,
    role: String,
    scenario: String,
    elapsed_ns: f64,
    exit_code: i64,
}

fn invalid_errors(errors: Vec<String>) -> ! {
    crate::emit_exit(
        crate::EXIT_INVALID,
        "INVALID_EVIDENCE",
        json!({"errors": errors}),
    );
}

/// Per-scenario paired ratios keyed by block order of first appearance.
fn paired_ratios(samples: &[Sample]) -> Result<BTreeMap<String, Vec<f64>>, Vec<String>> {
    let mut blocks: BTreeMap<(String, u64), BTreeMap<String, f64>> = BTreeMap::new();
    let mut errors = Vec::new();
    for (i, s) in samples.iter().enumerate() {
        let line = i + 1;
        if s.exit_code != 0 {
            errors.push(format!(
                "samples.jsonl line {line}: exit_code {} is nonzero; failing samples \
                 invalidate the run (exclusions must be frozen policy, not edits)",
                s.exit_code
            ));
            continue;
        }
        if !(s.elapsed_ns.is_finite() && s.elapsed_ns > 0.0) {
            errors.push(format!(
                "samples.jsonl line {line}: elapsed_ns {} is zero/invalid",
                s.elapsed_ns
            ));
            continue;
        }
        let entry = blocks.entry((s.scenario.clone(), s.block)).or_default();
        if entry.insert(s.role.clone(), s.elapsed_ns).is_some() {
            errors.push(format!(
                "samples.jsonl line {line}: duplicate role '{}' in scenario '{}' block {}",
                s.role, s.scenario, s.block
            ));
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    let mut by_scenario: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for ((scenario, block), roles) in blocks {
        let (base, cand) = match (roles.get("baseline"), roles.get("candidate")) {
            (Some(b), Some(c)) => (*b, *c),
            _ => {
                errors.push(format!(
                    "scenario '{scenario}' block {block} lacks a baseline/candidate pair"
                ));
                continue;
            }
        };
        by_scenario.entry(scenario).or_default().push(cand / base);
    }
    if errors.is_empty() {
        Ok(by_scenario)
    } else {
        Err(errors)
    }
}

fn load_samples(path: &Path) -> Result<Vec<Sample>, Vec<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return Err(vec![format!("cannot read {}: {e}", path.display())]),
    };
    let mut samples = Vec::new();
    let mut errors = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let ln = i + 1;
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("samples.jsonl line {ln}: malformed JSON: {e}"));
                continue;
            }
        };
        let block = v.get("block").and_then(Value::as_u64);
        let role = v.get("role").and_then(Value::as_str);
        let scenario = v.get("scenario").and_then(Value::as_str);
        let elapsed = v.get("elapsed_ns").and_then(Value::as_f64);
        let exit_code = v.get("exit_code").and_then(Value::as_i64);
        match (block, role, scenario, elapsed, exit_code) {
            (Some(block), Some(role), Some(scenario), Some(elapsed_ns), Some(exit_code))
                if role == "baseline" || role == "candidate" =>
            {
                samples.push(Sample {
                    block,
                    role: role.to_string(),
                    scenario: scenario.to_string(),
                    elapsed_ns,
                    exit_code,
                });
            }
            _ => errors.push(format!(
                "samples.jsonl line {ln}: requires block (u64), role (baseline|candidate), \
                 scenario (string), elapsed_ns (number), exit_code (integer)"
            )),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    if samples.is_empty() {
        return Err(vec![format!(
            "{}: empty timing samples; an absent sample is never a pass",
            path.display()
        )]);
    }
    Ok(samples)
}

struct GateOutcome {
    id: String,
    status: &'static str, // "pass" | "fail" | "invalid" | "blocked"
    detail: Value,
}

fn eval_timing_gate(
    gate_id: &str,
    scenario: &str,
    ratios_map: &BTreeMap<String, Vec<f64>>,
    threshold: f64,
    policy: &Policy,
    seed: u64,
) -> GateOutcome {
    let fail_detail = |e: String| GateOutcome {
        id: gate_id.to_string(),
        status: "invalid",
        detail: json!({"error": e}),
    };
    let Some(ratios) = ratios_map.get(scenario) else {
        return fail_detail(format!(
            "scenario '{scenario}' required by {gate_id} has no samples"
        ));
    };
    if ratios.len() < policy.min_paired_blocks {
        return fail_detail(format!(
            "scenario '{scenario}' has {} paired blocks, policy minimum is {}",
            ratios.len(),
            policy.min_paired_blocks
        ));
    }
    let mean = crate::stats::mean(ratios);
    let u95 = crate::stats::bootstrap_mean_u95(
        ratios,
        policy.bootstrap_resamples,
        policy.confidence,
        seed,
    );
    GateOutcome {
        id: gate_id.to_string(),
        status: if u95 <= threshold { "pass" } else { "fail" },
        detail: json!({
            "scenario": scenario,
            "blocks": ratios.len(),
            "mean_ratio": mean,
            "u95": u95,
            "threshold": threshold,
        }),
    }
}

pub fn cmd_evaluate(run_dir: &Path) -> i32 {
    if !run_dir.is_dir() {
        crate::invalid(format!(
            "run directory {} does not exist",
            run_dir.display()
        ));
    }
    if let Err(problems) = crate::runs::verify_checksums(run_dir) {
        invalid_errors(problems);
    }

    let manifest_path = run_dir.join(crate::runs::MANIFEST_FILE);
    let manifest = match crate::canon::read_json(&manifest_path) {
        Ok(m) => m,
        Err(e) => crate::invalid(e),
    };
    match manifest.get("kind").and_then(Value::as_str) {
        Some("benchmark") => {}
        other => crate::invalid(format!(
            "run manifest kind is {other:?}; evaluate requires a 'benchmark' run"
        )),
    }
    let policy_path = manifest
        .pointer("/policy/path")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let recorded_policy_sha = manifest
        .pointer("/policy/sha256")
        .and_then(Value::as_str)
        .map(str::to_string);
    let (Some(policy_path), Some(recorded_policy_sha)) = (policy_path, recorded_policy_sha) else {
        crate::invalid("run manifest lacks policy.path / policy.sha256");
    };
    let policy = match crate::policy::load(&policy_path) {
        Ok(p) => p,
        Err(e) => crate::invalid(e),
    };
    if policy.self_hash != recorded_policy_sha {
        crate::invalid(format!(
            "policy hash mismatch: manifest recorded {recorded_policy_sha}, current policy \
             self-hash is {}",
            policy.self_hash
        ));
    }
    let gate_ids: Vec<String> = match manifest.get("gates_evaluated").and_then(Value::as_array) {
        Some(arr) if !arr.is_empty() => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => crate::invalid("run manifest lacks a non-empty gates_evaluated array"),
    };
    // The analysis seed is frozen in the policy; a manifest carrying any
    // other seed means the run does not implement the frozen procedure.
    let seed = match manifest
        .pointer("/protocol/rng_seed")
        .and_then(Value::as_u64)
    {
        Some(s) if s == policy.rng_seed => s,
        Some(s) => crate::invalid(format!(
            "manifest protocol.rng_seed {s} does not match the frozen policy seed {}",
            policy.rng_seed
        )),
        None => crate::invalid("run manifest lacks protocol.rng_seed"),
    };

    let samples = match load_samples(&run_dir.join(crate::runs::SAMPLES_FILE)) {
        Ok(s) => s,
        Err(errors) => invalid_errors(errors),
    };
    let ratios = match paired_ratios(&samples) {
        Ok(r) => r,
        Err(errors) => invalid_errors(errors),
    };

    // A run covering a scenario must declare every gate the frozen policy
    // binds to that scenario; a suite-complete run must declare PERF-SUITE.
    // Run-declared gate subsets cannot skip a mandatory gate.
    let present: BTreeSet<&str> = ratios.keys().map(String::as_str).collect();
    let mut mandatory: BTreeSet<&str> = BTreeSet::new();
    for scenario in &present {
        if let Some(gates) = policy.scenario_mandatory_gates.get(*scenario) {
            for g in gates {
                mandatory.insert(g.as_str());
            }
        }
    }
    if policy
        .suite_scenarios
        .iter()
        .all(|s| present.contains(s.as_str()))
    {
        mandatory.insert("PERF-SUITE");
    }
    for m in &mandatory {
        if !gate_ids.iter().any(|g| g == m) {
            crate::invalid(format!(
                "run covers samples requiring mandatory gate '{m}', but gates_evaluated \
                 does not declare it; a subset evaluation cannot skip mandatory gates"
            ));
        }
    }

    let mut outcomes: Vec<GateOutcome> = Vec::new();
    for id in &gate_ids {
        let Some(gate) = policy.gate(id) else {
            crate::invalid(format!("gates_evaluated names unknown gate '{id}'"));
        };
        match gate.kind.as_str() {
            "timing" => {
                let threshold = gate.threshold.unwrap_or(f64::NAN);
                if let Some(scenario) = &gate.scenario {
                    outcomes.push(eval_timing_gate(
                        id, scenario, &ratios, threshold, &policy, seed,
                    ));
                } else if !gate.scenarios.is_empty() {
                    // Multi-scenario gate (PERF-NOREGRESS): evaluate every
                    // listed scenario the run covers using joint bootstrap over the family.
                    let covered_scenarios: Vec<&str> = gate
                        .scenarios
                        .iter()
                        .map(String::as_str)
                        .filter(|s| ratios.contains_key(*s))
                        .collect();
                    if covered_scenarios.is_empty() {
                        outcomes.push(GateOutcome {
                            id: id.clone(),
                            status: "invalid",
                            detail: json!({
                                "error": format!(
                                    "gate '{id}' declares scenarios {:?} but the run covers none of them",
                                    gate.scenarios
                                )
                            }),
                        });
                    } else {
                        let mut too_few = None;
                        for s in &covered_scenarios {
                            let len = ratios[*s].len();
                            if len < policy.min_paired_blocks {
                                too_few = Some((*s, len));
                                break;
                            }
                        }
                        if let Some((s, len)) = too_few {
                            outcomes.push(GateOutcome {
                                id: id.clone(),
                                status: "invalid",
                                detail: json!({
                                    "error": format!(
                                        "scenario '{s}' has {len} paired blocks, policy minimum is {}",
                                        policy.min_paired_blocks
                                    )
                                }),
                            });
                        } else {
                            let family_slices: Vec<&[f64]> = covered_scenarios
                                .iter()
                                .map(|s| ratios[*s].as_slice())
                                .collect();
                            let bounds = crate::stats::bootstrap_joint_family_u95(
                                &family_slices,
                                policy.bootstrap_resamples,
                                policy.confidence,
                                seed,
                            );
                            let mut per_scenario = Vec::new();
                            let mut all_pass = true;
                            for (idx, &s) in covered_scenarios.iter().enumerate() {
                                let r = &ratios[s];
                                let mean = crate::stats::mean(r);
                                let u95 = bounds[idx];
                                let pass = u95 <= threshold;
                                if !pass {
                                    all_pass = false;
                                }
                                per_scenario.push(json!({
                                    "scenario": s,
                                    "status": if pass { "pass" } else { "fail" },
                                    "detail": {
                                        "scenario": s,
                                        "blocks": r.len(),
                                        "mean_ratio": mean,
                                        "u95": u95,
                                        "simultaneous": true,
                                        "threshold": threshold,
                                    }
                                }));
                            }
                            outcomes.push(GateOutcome {
                                id: id.clone(),
                                status: if all_pass { "pass" } else { "fail" },
                                detail: json!({
                                    "threshold": threshold,
                                    "scenarios": per_scenario,
                                }),
                            });
                        }
                    }
                } else {
                    // Gates without a frozen scenario (PERF-NATIVE-PROMOTION)
                    // evaluate the scenario named by the run manifest.
                    let scenario = manifest
                        .get("scenario")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if scenario.is_empty() {
                        crate::invalid(format!("gate '{id}' has no scenario to evaluate"));
                    }
                    outcomes.push(eval_timing_gate(
                        id, &scenario, &ratios, threshold, &policy, seed,
                    ));
                }
            }
            "timing_aggregate" => {
                let mut groups = Vec::new();
                let mut missing = Vec::new();
                for s in &gate.scenarios {
                    match ratios.get(s) {
                        Some(r) if r.len() >= policy.min_paired_blocks => groups.push(r.clone()),
                        Some(r) => missing.push(format!(
                            "scenario '{s}' has {} paired blocks, policy minimum is {}",
                            r.len(),
                            policy.min_paired_blocks
                        )),
                        None => missing.push(format!("scenario '{s}' has no samples")),
                    }
                }
                if !missing.is_empty() {
                    outcomes.push(GateOutcome {
                        id: id.clone(),
                        status: "invalid",
                        detail: json!({"errors": missing}),
                    });
                    continue;
                }
                let geomean = crate::stats::geomean(
                    &groups
                        .iter()
                        .map(|g| crate::stats::mean(g))
                        .collect::<Vec<_>>(),
                );
                let u95 = crate::stats::bootstrap_geomean_u95(
                    &groups,
                    policy.bootstrap_resamples,
                    policy.confidence,
                    seed,
                );
                let threshold = gate.threshold.unwrap_or(f64::NAN);
                outcomes.push(GateOutcome {
                    id: id.clone(),
                    status: if u95 <= threshold { "pass" } else { "fail" },
                    detail: json!({
                        "scenarios": gate.scenarios,
                        "geomean_ratio": geomean,
                        "u95": u95,
                        "threshold": threshold,
                    }),
                });
            }
            _ => outcomes.push(GateOutcome {
                id: id.clone(),
                status: "blocked",
                detail: json!({
                    "error": format!(
                        "gate '{id}' (kind '{}') is not evaluable from timing samples; \
                         it needs external structural/resource evidence",
                        gate.kind
                    )
                }),
            }),
        }
    }

    let mut saw_invalid = false;
    let mut saw_fail = false;
    let mut saw_blocked = false;
    let mut gate_json = Vec::new();
    for o in &outcomes {
        match o.status {
            "pass" => {}
            "fail" => saw_fail = true,
            "invalid" => saw_invalid = true,
            _ => saw_blocked = true,
        }
        let mut g = serde_json::Map::new();
        g.insert("id".to_string(), json!(o.id));
        g.insert("status".to_string(), json!(o.status));
        if let Value::Object(d) = &o.detail {
            g.extend(d.clone());
        }
        gate_json.push(Value::Object(g));
    }

    let (code, verdict) = if saw_invalid {
        (crate::EXIT_INVALID, "INVALID_EVIDENCE")
    } else if saw_fail {
        (crate::EXIT_FAIL, "FAIL")
    } else if saw_blocked {
        (crate::EXIT_BLOCKED, "BLOCKED")
    } else {
        (crate::EXIT_PASS, "PASS")
    };
    crate::emit_exit(
        code,
        verdict,
        json!({
            "run_dir": run_dir.display().to_string(),
            "policy_sha256": policy.self_hash,
            "gates": gate_json,
        }),
    );
}
