//! `proof verify-final`: reconcile the final machine verdict (goal section 9).
//!
//! PASS requires, for the named commit:
//! - the commit exists in the repository (else BLOCKED),
//! - every mandatory requirement has non-empty green evidence with
//!   implementer != verifier (both set),
//! - every green-evidence artifact exists and matches its recorded SHA-256
//!   (else INVALID_EVIDENCE),
//! - the frozen sources lock exactly covers the repository's
//!   refs/goal/sources/ refs with matching heads/trees/parents.
//! No handwritten PASS, agent summary, or copied badge is accepted.

use serde_json::json;
use std::path::{Path, PathBuf};

pub fn cmd_verify_final(
    commit: &str,
    requirements_path: &Path,
    sources_path: &Path,
    repo: Option<PathBuf>,
) -> i32 {
    let repo = repo.unwrap_or_else(|| PathBuf::from("."));

    // Prerequisite: the named commit must be available.
    match crate::sources::git(&repo, &["cat-file", "-t", commit]) {
        Ok(t) if t == "commit" => {}
        Ok(t) => crate::invalid(format!("commit {commit} is a {t}, not a commit")),
        Err(e) => crate::blocked(format!(
            "commit {commit} is not available in {}: {e}",
            repo.display()
        )),
    }

    let reqs = match crate::requirements::load(requirements_path) {
        Ok(r) => r,
        Err(errors) => crate::invalid(format!(
            "requirements validation failed: {}",
            errors.join("; ")
        )),
    };

    let mut failures: Vec<String> = Vec::new();
    let mut evidence_problems: Vec<String> = Vec::new();

    for req in &reqs {
        if req.kind != "required" {
            continue;
        }
        if req.green_evidence.is_empty() {
            failures.push(format!("{}: no green evidence", req.id));
        }
        match (&req.implementer, &req.verifier) {
            (Some(i), Some(v)) if i != v => {}
            (Some(_), Some(_)) => {
                failures.push(format!(
                    "{}: verifier must differ from implementer (no self-certification)",
                    req.id
                ));
            }
            _ => failures.push(format!(
                "{}: implementer and verifier must both be recorded",
                req.id
            )),
        }
        for ev in &req.green_evidence {
            let path = {
                let p = PathBuf::from(&ev.path);
                if p.is_absolute() {
                    p
                } else {
                    repo.join(p)
                }
            };
            if !path.is_file() {
                evidence_problems.push(format!(
                    "{}: evidence artifact missing: {}",
                    req.id,
                    path.display()
                ));
                continue;
            }
            match crate::canon::sha256_file(&path) {
                Ok(actual) if actual == ev.sha256 => {}
                Ok(actual) => evidence_problems.push(format!(
                    "{}: evidence hash mismatch for {} (recorded {}, actual {})",
                    req.id,
                    path.display(),
                    ev.sha256,
                    actual
                )),
                Err(e) => evidence_problems.push(format!(
                    "{}: cannot hash evidence {}: {e}",
                    req.id,
                    path.display()
                )),
            }
        }
    }

    let lock = match crate::sources::load(sources_path) {
        Ok(l) => l,
        Err(e) => crate::invalid(e),
    };
    let report = match crate::sources::inventory(&repo, &lock) {
        Ok(r) => r,
        Err(e) => crate::blocked(e),
    };
    for p in &report.problems {
        failures.push(format!("source coverage: {p}"));
    }

    if !evidence_problems.is_empty() {
        crate::emit_exit(
            crate::EXIT_INVALID,
            "INVALID_EVIDENCE",
            json!({
                "commit": commit,
                "evidence_problems": evidence_problems,
                "failures": failures,
            }),
        );
    }
    if !failures.is_empty() {
        crate::emit_exit(
            crate::EXIT_FAIL,
            "FAIL",
            json!({
                "commit": commit,
                "failures": failures,
            }),
        );
    }
    crate::emit_exit(
        crate::EXIT_PASS,
        "PASS",
        json!({
            "commit": commit,
            "requirements": reqs.len(),
            "sources_checked": report.sources_checked,
        }),
    );
}
