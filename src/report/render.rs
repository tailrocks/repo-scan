//! Readable terminal rendering (spec §3: without `--report`, produce a
//! readable terminal report and retain a versioned snapshot in state).
//!
//! The caller supplies the output writer — normally stdout. Progress and
//! diagnostics stay on stderr by construction: this module never touches
//! stderr, so machine-readable output is never polluted by progress text.

use crate::identity::scrub_text;
use crate::report::encode::escape_display;
use crate::report::model::Report;

/// Scrub privacy-bearing prose (embedded credential URLs, secret pairs)
/// before display escaping. Reports built by the pipeline are already
/// scrubbed at emission; this boundary keeps terminal output safe for any
/// report handed to the renderer (RSP-001/RSP-011 defense in depth).
fn show_prose(text: &str) -> String {
    escape_display(&scrub_text(text))
}

/// Render a readable summary of `report` to `out` (normally stdout).
/// Bounded detail: repositories, checkouts, candidates, errors, and
/// artifacts render one line each; branches render per-repository counts
/// plus individual lines only when the total is small.
pub fn render_terminal(report: &Report, out: &mut dyn std::io::Write) -> crate::Result<()> {
    let mut w = |text: &str| -> crate::Result<()> {
        out.write_all(text.as_bytes()).map_err(crate::Error::from)
    };
    w(&format!(
        "repo-scan {} report {}\n",
        escape_display(&report.tool.version),
        escape_display(&report.report_id)
    ))?;
    w(&format!(
        "target {} ({})\n",
        escape_display(&crate::identity::redact_remote_url(&report.scan.target_url)),
        escape_display(&report.scan.state)
    ))?;
    w(&format!(
        "scan {} generation {} revision {} cached={} status_mode={}\n",
        escape_display(&report.scan.id),
        report.scan.generation,
        report.scan.catalog_revision,
        report.scan.cached,
        escape_display(&report.scan.status_mode)
    ))?;
    w(&format!(
        "coverage filesystem={} identity={} status={} dirs={} pending={} gaps={} unresolvable={}\n",
        report.coverage.filesystem,
        report.coverage.identity,
        report.coverage.status,
        report.coverage.directories_complete,
        report.coverage.tasks_pending,
        report.coverage.gaps,
        report.coverage.unresolvable_candidates
    ))?;
    for boundary in &report.coverage.scope_boundaries {
        w(&format!("boundary: {}\n", show_prose(boundary)))?;
    }

    let paths: std::collections::HashMap<&str, &str> = report
        .paths
        .iter()
        .map(|p| (p.id.as_str(), p.display.as_str()))
        .collect();
    // RETEST-7: path bytes are lower-layer filesystem/git material and can
    // carry credential-shaped components (`token=...`, embedded URLs); the
    // display channel scrubs them like the cached-query path display does
    // (lossless bytes stay in the report `value` channel and the catalog).
    let show_path = |id: &str| -> String {
        paths
            .get(id)
            .map(|d| show_prose(d))
            .unwrap_or_else(|| format!("<missing path {id}>"))
    };

    w(&format!("repositories: {}\n", report.repositories.len()))?;
    for repo in &report.repositories {
        w(&format!(
            "  [{}] {} common={} bare={} {}\n",
            escape_display(&repo.match_disposition),
            show_path(&repo.git_path_id),
            show_path(&repo.common_path_id),
            repo.bare
                .map(|b| b.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            escape_display(&repo.object_format)
        ))?;
        for line in &repo.evidence {
            w(&format!("    evidence: {}\n", show_prose(line)))?;
        }
    }

    w(&format!("checkouts: {}\n", report.checkouts.len()))?;
    for checkout in &report.checkouts {
        let root = checkout
            .root_path_id
            .as_deref()
            .map(&show_path)
            .unwrap_or_else(|| "(bare)".to_string());
        let status = &checkout.status;
        let counts = match (status.staged, status.unstaged, status.untracked) {
            (Some(s), Some(u), Some(t)) => {
                format!(
                    "staged={s} unstaged={u} untracked={t} {}",
                    status.untracked_units
                )
            }
            _ => format!("counts unknown ({})", status.state),
        };
        w(&format!(
            "  [{}] {} head={} status={} {}\n",
            escape_display(&checkout.availability),
            root,
            escape_display(&checkout.head.state),
            escape_display(&status.state),
            counts
        ))?;
    }

    if report.branches.len() <= 100 {
        w(&format!("branches: {}\n", report.branches.len()))?;
        for branch in &report.branches {
            let oid = branch
                .oid
                .as_ref()
                .map(|o| o.hex.as_str())
                .unwrap_or("no-oid");
            w(&format!(
                "  [{}] {} {}\n",
                escape_display(&branch.kind),
                show_prose(&branch.name.display),
                oid
            ))?;
        }
    } else {
        let mut per_repo: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for branch in &report.branches {
            *per_repo.entry(branch.repository_id.as_str()).or_default() += 1;
        }
        w(&format!(
            "branches: {} ({} repositories)\n",
            report.branches.len(),
            per_repo.len()
        ))?;
        for (repo, count) in per_repo {
            w(&format!("  {repo}: {count}\n"))?;
        }
    }

    w(&format!("candidates: {}\n", report.candidates.len()))?;
    for candidate in &report.candidates {
        w(&format!(
            "  [{}] {} {}\n",
            escape_display(&candidate.disposition),
            show_path(&candidate.path_id),
            show_prose(&candidate.reason)
        ))?;
    }

    w(&format!("errors: {}\n", report.errors.len()))?;
    for error in &report.errors {
        let at = error.path_id.as_deref().map(&show_path).unwrap_or_default();
        w(&format!(
            "  [{}] {} {} attempts={} retryable={}\n",
            escape_display(&error.category),
            escape_display(&error.operation),
            show_prose(&error.message),
            error.attempts,
            error.retryable
        ))?;
        if !at.is_empty() {
            w(&format!("    at {at}\n"))?;
        }
    }

    if !report.generated_artifacts.is_empty() {
        w(&format!(
            "generated artifacts: {}\n",
            report.generated_artifacts.len()
        ))?;
        for artifact in &report.generated_artifacts {
            w(&format!(
                "  [{}] {} after_status={}\n",
                escape_display(&artifact.kind),
                show_path(&artifact.path_id),
                artifact.created_after_status
            ))?;
        }
    }
    out.flush()?;
    Ok(())
}
