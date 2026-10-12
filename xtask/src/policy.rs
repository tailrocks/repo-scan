//! Frozen performance policy loading and integrity verification.
//!
//! proof/policy.json carries a `sha256` self-hash over the canonical JSON of
//! the document excluding the hash field. Every consumer recomputes it on
//! load; a changed threshold without a matching recorded hash is rejected as
//! invalid evidence (goal section 3.3 "changed threshold hash").

use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Gate {
    pub id: String,
    pub kind: String,
    pub threshold: Option<f64>,
    pub scenario: Option<String>,
    pub scenarios: Vec<String>,
}

/// Frozen policy. All fields are validated on load; some are retained for
/// downstream consumers rather than read by this crate.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Policy {
    pub path: PathBuf,
    pub self_hash: String,
    pub min_paired_blocks: usize,
    pub bootstrap_resamples: usize,
    pub confidence: f64,
    pub rng_seed: u64,
    pub primary_scenario: String,
    pub suite_scenarios: Vec<String>,
    pub noregress_scenarios: Vec<String>,
    pub gates: Vec<Gate>,
}

impl Policy {
    pub fn gate(&self, id: &str) -> Option<&Gate> {
        self.gates.iter().find(|g| g.id == id)
    }
}

fn req_str<'a>(obj: &'a Value, key: &str, ctx: &str) -> Result<&'a str, String> {
    obj.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{ctx}: missing or empty string field '{key}'"))
}

fn req_str_list(obj: &Value, key: &str, ctx: &str) -> Result<Vec<String>, String> {
    let arr = obj
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{ctx}: missing array field '{key}'"))?;
    let mut out = Vec::new();
    for (i, v) in arr.iter().enumerate() {
        match v.as_str().filter(|s| !s.is_empty()) {
            Some(s) => out.push(s.to_string()),
            None => return Err(format!("{ctx}: '{key}[{i}]' is not a non-empty string")),
        }
    }
    Ok(out)
}

pub fn load(path: &Path) -> Result<Policy, String> {
    let raw = crate::canon::read_json(path)?;
    let recorded = raw
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{}: missing 'sha256' self-hash field", path.display()))?
        .to_string();
    let computed = crate::canon::self_hash(&raw)?;
    if recorded != computed {
        return Err(format!(
            "{}: policy self-hash mismatch (recorded {recorded}, computed {computed}); \
             the frozen policy was modified after freezing",
            path.display()
        ));
    }

    let proto = raw
        .get("repeated_run_protocol")
        .ok_or_else(|| format!("{}: missing repeated_run_protocol", path.display()))?;
    let min_paired_blocks = proto
        .get("min_paired_blocks")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{}: missing min_paired_blocks", path.display()))?
        as usize;
    let bootstrap_resamples = proto
        .get("bootstrap_resamples")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{}: missing bootstrap_resamples", path.display()))?
        as usize;
    let confidence = proto
        .get("confidence")
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("{}: missing confidence", path.display()))?;
    let rng_seed = proto
        .get("rng_seed")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{}: missing rng_seed", path.display()))?;

    let gates_raw = raw
        .get("gates")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{}: missing gates array", path.display()))?;
    let mut gates = Vec::new();
    for (i, g) in gates_raw.iter().enumerate() {
        let ctx = format!("{}: gates[{i}]", path.display());
        let id = req_str(g, "id", &ctx)?.to_string();
        let kind = req_str(g, "kind", &ctx)?.to_string();
        let threshold = g.get("threshold").and_then(Value::as_f64);
        let scenario = g
            .get("scenario")
            .and_then(Value::as_str)
            .map(str::to_string);
        let scenarios = match g.get("scenarios") {
            Some(Value::Array(_)) => req_str_list(g, "scenarios", &ctx)?,
            _ => Vec::new(),
        };
        gates.push(Gate {
            id,
            kind,
            threshold,
            scenario,
            scenarios,
        });
    }

    let primary_scenario = gates
        .iter()
        .find(|g| g.id == "PERF-PRIMARY")
        .and_then(|g| g.scenario.clone())
        .ok_or_else(|| format!("{}: PERF-PRIMARY gate needs a scenario", path.display()))?;
    let suite_scenarios = gates
        .iter()
        .find(|g| g.id == "PERF-SUITE")
        .map(|g| g.scenarios.clone())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{}: PERF-SUITE gate needs scenarios", path.display()))?;
    let noregress_scenarios = gates
        .iter()
        .find(|g| g.id == "PERF-NOREGRESS")
        .map(|g| g.scenarios.clone())
        .ok_or_else(|| format!("{}: PERF-NOREGRESS gate missing", path.display()))?;

    Ok(Policy {
        path: path.to_path_buf(),
        self_hash: computed,
        min_paired_blocks,
        bootstrap_resamples,
        confidence,
        rng_seed,
        primary_scenario,
        suite_scenarios,
        noregress_scenarios,
        gates,
    })
}
