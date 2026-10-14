//! `proof verify-final`: reconcile the final machine verdict (goal section 9).
//!
//! PASS requires, for the named commit:
//! - the commit exists in the repository (else BLOCKED),
//! - every mandatory requirement has non-empty green evidence with
//!   implementer != verifier (both set),
//! - every green-evidence artifact exists and matches its recorded SHA-256
//!   (else INVALID_EVIDENCE),
//! - every experiment/conditional has a valid disposition with evidence
//!   (goal section 3.2): `qualified_enabled` or `evaluated_not_enabled`
//!   with evidence, or `not_triggered` with executed-trigger evidence,
//! - the frozen sources lock exactly covers the repository's
//!   refs/goal/sources/ refs with matching heads/trees/parents.
//!
//! No handwritten PASS, agent summary, or copied badge is accepted.

use serde_json::json;
use std::path::{Path, PathBuf};

use crate::requirements::Evidence;

fn check_evidence_artifact(repo: &Path, what: &str, ev: &Evidence, problems: &mut Vec<String>) {
    let path = {
        let p = PathBuf::from(&ev.path);
        if p.is_absolute() {
            p
        } else {
            repo.join(p)
        }
    };
    if !path.is_file() {
        problems.push(format!(
            "{what}: evidence artifact missing: {}",
            path.display()
        ));
        return;
    }
    match crate::canon::sha256_file(&path) {
        Ok(actual) if actual == ev.sha256 => {}
        Ok(actual) => problems.push(format!(
            "{what}: evidence hash mismatch for {} (recorded {}, actual {})",
            path.display(),
            ev.sha256,
            actual
        )),
        Err(e) => problems.push(format!(
            "{what}: cannot hash evidence {}: {e}",
            path.display()
        )),
    }
}

pub fn cmd_verify_final(
    commit: &str,
    requirements_path: &Path,
    sources_path: &Path,
    experiments_path: &Path,
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

    let head_sha = match crate::sources::git(&repo, &["rev-parse", "HEAD"]) {
        Ok(h) => h.trim().to_string(),
        Err(e) => crate::blocked(format!("cannot resolve HEAD in {}: {e}", repo.display())),
    };
    let target_sha = match crate::sources::git(&repo, &["rev-parse", commit]) {
        Ok(h) => h.trim().to_string(),
        Err(e) => crate::blocked(format!(
            "cannot resolve {commit} in {}: {e}",
            repo.display()
        )),
    };
    if head_sha != target_sha {
        crate::blocked(format!(
            "working tree HEAD ({head_sha}) does not match requested commit {commit} ({target_sha}); \
             evidence reconciliation requires a checkout matching the verified commit"
        ));
    }
    let diff_status =
        crate::sources::git(&repo, &["status", "--porcelain", "--untracked-files=no"]);
    if let Ok(ref s) = diff_status {
        if !s.trim().is_empty() {
            crate::blocked(format!(
                "working tree in {} has uncommitted changes to tracked files; \
                 evidence reconciliation requires a clean checkout",
                repo.display()
            ));
        }
    }

    let reqs = match crate::requirements::load(requirements_path) {
        Ok(r) => r,
        Err(errors) => crate::invalid(format!(
            "requirements validation failed: {}",
            errors.join("; ")
        )),
    };
    let experiments = match crate::experiments::load(experiments_path) {
        Ok(e) => e,
        Err(errors) => crate::invalid(format!(
            "experiments validation failed: {}",
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
            check_evidence_artifact(&repo, &req.id, ev, &mut evidence_problems);
        }
    }

    for exp in &experiments {
        match exp.disposition.as_deref() {
            Some("qualified_enabled") | Some("evaluated_not_enabled") => {
                if exp.evidence.is_empty() {
                    failures.push(format!(
                        "experiment {}: disposition requires evidence",
                        exp.id
                    ));
                }
                for ev in &exp.evidence {
                    check_evidence_artifact(
                        &repo,
                        &format!("experiment {}", exp.id),
                        ev,
                        &mut evidence_problems,
                    );
                }
            }
            Some("not_triggered") => {
                // A conditional may be not_triggered only when its frozen
                // trigger test was executed and false (goal section 3.2).
                if exp.trigger_evidence.is_empty() {
                    failures.push(format!(
                        "experiment {}: not_triggered requires executed trigger evidence",
                        exp.id
                    ));
                }
                for ev in &exp.trigger_evidence {
                    check_evidence_artifact(
                        &repo,
                        &format!("experiment {} trigger", exp.id),
                        ev,
                        &mut evidence_problems,
                    );
                }
            }
            Some(other) => failures.push(format!(
                "experiment {}: unknown disposition '{other}'",
                exp.id
            )),
            None => failures.push(format!("experiment {}: no disposition recorded", exp.id)),
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
            "experiments": experiments.len(),
            "sources_checked": report.sources_checked,
        }),
    );
}
