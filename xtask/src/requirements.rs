//! Requirements manifest loading and validation (goal section 3.1 schema).
//!
//! Every requirement record must carry all schema fields; missing required
//! values fail validation (exit 2 INVALID_EVIDENCE). The `red` subcommand
//! lists required items whose green_evidence is empty and exits 1 while any
//! remain — the executable "pending state" of the goal.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

pub const KNOWN_PLATFORMS: [&str; 3] = ["linux", "macos", "windows"];
pub const KNOWN_STATUSES: [&str; 4] = ["pending", "red", "green", "blocked"];

#[derive(Debug)]
pub struct Evidence {
    pub path: String,
    pub sha256: String,
}

/// One §3.1 requirement record. All schema fields are validated on load and
/// retained for downstream consumers even when this crate reads only some.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Requirement {
    pub id: String,
    pub rfc_sections: Vec<String>,
    pub kind: String,
    pub claim: String,
    pub platforms: Vec<String>,
    pub tests: Vec<String>,
    pub oracle: String,
    pub red_evidence: Vec<Evidence>,
    pub green_evidence: Vec<Evidence>,
    pub negative_controls: Vec<Evidence>,
    pub performance_gate_ids: Vec<String>,
    pub implementer: Option<String>,
    pub verifier: Option<String>,
    pub status: String,
}

pub(crate) fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn get_str_list(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    ctx: &str,
    allow_empty: bool,
    errors: &mut Vec<String>,
) -> Vec<String> {
    match obj.get(key) {
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for (i, v) in items.iter().enumerate() {
                match v.as_str().filter(|s| !s.is_empty()) {
                    Some(s) => out.push(s.to_string()),
                    None => errors.push(format!("{ctx}: '{key}[{i}]' is not a non-empty string")),
                }
            }
            if !allow_empty && out.is_empty() {
                errors.push(format!("{ctx}: '{key}' must not be empty"));
            }
            out
        }
        _ => {
            errors.push(format!("{ctx}: missing array field '{key}'"));
            Vec::new()
        }
    }
}

fn get_str(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    ctx: &str,
    errors: &mut Vec<String>,
) -> String {
    match obj
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        Some(s) => s.to_string(),
        None => {
            errors.push(format!("{ctx}: missing or empty string field '{key}'"));
            String::new()
        }
    }
}

fn get_opt_str(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    ctx: &str,
    errors: &mut Vec<String>,
) -> Option<String> {
    match obj.get(key) {
        Some(Value::Null) => None,
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => {
            errors.push(format!(
                "{ctx}: field '{key}' must be null or a non-empty string"
            ));
            None
        }
    }
}

pub(crate) fn parse_evidence_array(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    ctx: &str,
    errors: &mut Vec<String>,
) -> Vec<Evidence> {
    match obj.get(key) {
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for (i, v) in items.iter().enumerate() {
                let ectx = format!("{ctx}: '{key}[{i}]'");
                let Some(eobj) = v.as_object() else {
                    errors.push(format!("{ectx}: evidence entry is not an object"));
                    continue;
                };
                let path = get_str(eobj, "path", &ectx, errors);
                let sha = get_str(eobj, "sha256", &ectx, errors);
                if !sha.is_empty() && !is_hex64(&sha) {
                    errors.push(format!("{ectx}: 'sha256' is not 64 hex characters"));
                }
                out.push(Evidence { path, sha256: sha });
            }
            out
        }
        _ => {
            errors.push(format!("{ctx}: missing array field '{key}'"));
            Vec::new()
        }
    }
}

/// Load and validate proof/requirements.json. Returns all validation errors.
pub fn load(path: &Path) -> Result<Vec<Requirement>, Vec<String>> {
    let raw = match crate::canon::read_json(path) {
        Ok(v) => v,
        Err(e) => return Err(vec![e]),
    };
    let mut errors = Vec::new();
    let items = match raw.get("requirements").and_then(Value::as_array) {
        Some(a) if !a.is_empty() => a.clone(),
        _ => {
            return Err(vec![format!(
                "{}: 'requirements' must be a non-empty array",
                path.display()
            )])
        }
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let Some(obj) = item.as_object() else {
            errors.push(format!("requirements[{i}]: not an object"));
            continue;
        };
        let ctx = format!(
            "requirements[{i} (id={})]",
            obj.get("id").and_then(Value::as_str).unwrap_or("?")
        );
        let id = get_str(obj, "id", &ctx, &mut errors);
        if !id.is_empty() && !seen.insert(id.clone()) {
            errors.push(format!("{ctx}: duplicate requirement id"));
        }
        let rfc_sections = get_str_list(obj, "rfc_sections", &ctx, false, &mut errors);
        let kind = get_str(obj, "kind", &ctx, &mut errors);
        let claim = get_str(obj, "claim", &ctx, &mut errors);
        let platforms = get_str_list(obj, "platforms", &ctx, false, &mut errors);
        for p in &platforms {
            if !KNOWN_PLATFORMS.contains(&p.as_str()) {
                errors.push(format!("{ctx}: unrecognized platform '{p}'"));
            }
        }
        let tests = get_str_list(obj, "tests", &ctx, true, &mut errors);
        let oracle = get_str(obj, "oracle", &ctx, &mut errors);
        let red_evidence = parse_evidence_array(obj, "red_evidence", &ctx, &mut errors);
        let green_evidence = parse_evidence_array(obj, "green_evidence", &ctx, &mut errors);
        let negative_controls = parse_evidence_array(obj, "negative_controls", &ctx, &mut errors);
        let performance_gate_ids =
            get_str_list(obj, "performance_gate_ids", &ctx, true, &mut errors);
        let implementer = get_opt_str(obj, "implementer", &ctx, &mut errors);
        let verifier = get_opt_str(obj, "verifier", &ctx, &mut errors);
        let status = get_str(obj, "status", &ctx, &mut errors);
        if !status.is_empty() && !KNOWN_STATUSES.contains(&status.as_str()) {
            errors.push(format!("{ctx}: unknown status '{status}'"));
        }
        out.push(Requirement {
            id,
            rfc_sections,
            kind,
            claim,
            platforms,
            tests,
            oracle,
            red_evidence,
            green_evidence,
            negative_controls,
            performance_gate_ids,
            implementer,
            verifier,
            status,
        });
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// `proof red`: list required requirements with empty green evidence.
pub fn cmd_red(path: &Path) -> i32 {
    let reqs = match load(path) {
        Ok(r) => r,
        Err(errors) => crate::invalid(format!(
            "requirements validation failed: {}",
            errors.join("; ")
        )),
    };
    let pending: Vec<&Requirement> = reqs
        .iter()
        .filter(|r| r.kind == "required" && r.green_evidence.is_empty())
        .collect();
    let ids: Vec<&str> = pending.iter().map(|r| r.id.as_str()).collect();
    if pending.is_empty() {
        crate::emit_exit(
            crate::EXIT_PASS,
            "PASS",
            serde_json::json!({
                "requirements": reqs.len(),
                "pending": [],
                "note": "every required item carries green evidence",
            }),
        );
    }
    crate::emit_exit(
        crate::EXIT_FAIL,
        "FAIL",
        serde_json::json!({
            "requirements": reqs.len(),
            "pending": ids,
            "pending_count": pending.len(),
            "note": "required requirements without green evidence",
        }),
    );
}
