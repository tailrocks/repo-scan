//! Experiment registry loading (goal section 3.1, step 19).
//!
//! Structural validation only; disposition completeness is judged by
//! `proof verify-final` (goal section 3.2): every experiment needs a
//! disposition of `qualified_enabled` or `evaluated_not_enabled` with
//! evidence, or `not_triggered` with executed-trigger evidence.

use serde_json::Value;
use std::path::Path;

use crate::requirements::Evidence;

#[derive(Debug)]
pub struct Experiment {
    pub id: String,
    pub disposition: Option<String>,
    pub evidence: Vec<Evidence>,
    pub trigger_evidence: Vec<Evidence>,
}

pub fn load(path: &Path) -> Result<Vec<Experiment>, Vec<String>> {
    let raw = match crate::canon::read_json(path) {
        Ok(v) => v,
        Err(e) => return Err(vec![e]),
    };
    let items = match raw.get("experiments").and_then(Value::as_array) {
        Some(a) if !a.is_empty() => a.clone(),
        _ => {
            return Err(vec![format!(
                "{}: 'experiments' must be a non-empty array",
                path.display()
            )])
        }
    };
    let mut errors = Vec::new();
    let mut out = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let ctx = format!("experiments[{i}]");
        let Some(obj) = item.as_object() else {
            errors.push(format!("{ctx}: not an object"));
            continue;
        };
        let id = obj
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if id.is_none() {
            errors.push(format!("{ctx}: missing or empty 'id'"));
        }
        let disposition = match obj.get("disposition") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => {
                errors.push(format!(
                    "{}: 'disposition' must be absent, null, or a non-empty string",
                    id.as_deref().unwrap_or(&ctx)
                ));
                None
            }
        };
        let evidence = parse_evidence_array(obj, "evidence", &id, &ctx, &mut errors);
        let trigger_evidence =
            parse_evidence_array(obj, "trigger_evidence", &id, &ctx, &mut errors);
        out.push(Experiment {
            id: id.unwrap_or_else(|| ctx.clone()),
            disposition,
            evidence,
            trigger_evidence,
        });
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// Parse an optional evidence array; absent means empty.
fn parse_evidence_array(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    id: &Option<String>,
    ctx: &str,
    errors: &mut Vec<String>,
) -> Vec<Evidence> {
    match obj.get(key) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(_)) => {
            let ectx = format!("{} (experiment {})", ctx, id.as_deref().unwrap_or("?"));
            crate::requirements::parse_evidence_array(obj, key, &ectx, errors)
        }
        _ => {
            errors.push(format!("{ctx}: '{key}' must be an array when present"));
            Vec::new()
        }
    }
}
