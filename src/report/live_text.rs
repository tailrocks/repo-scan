//! Plain-text live renderer (D6/D4 human lane).
//!
//! [`render_plain`] snapshots a [`Report`] as stable, deterministic plain
//! text: no ANSI codes, no cursor commands, one `\n`-terminated line per
//! row. Progress consumers (live `--follow` human output, Step 13) call it
//! on each new snapshot; identical reports render byte-identical text.
//!
//! Layout: header line, coverage line, totals line, then detail rows
//! (repositories, checkouts, candidates, errors) capped at
//! [`MAX_DETAIL_ROWS`] with a `... (N more)` overflow line.

use crate::report::model::Report;
use std::collections::HashMap;

/// Maximum detail rows (repositories + checkouts + candidates + errors)
/// emitted before the `... (N more)` overflow line.
pub const MAX_DETAIL_ROWS: usize = 200;

/// Replacement character for control characters in display text.
const CONTROL_REPLACEMENT: char = '\u{FFFD}';

/// Replace every control character with U+FFFD so one field can never
/// inject newlines, ESC bytes, or other terminal control sequences.
/// Local copy of the main display-sanitizing rule; std only.
fn sanitize(text: &str) -> String {
    if !text.chars().any(|c| c.is_control()) {
        return text.to_string();
    }
    text.chars()
        .map(|c| {
            if c.is_control() {
                CONTROL_REPLACEMENT
            } else {
                c
            }
        })
        .collect()
}

/// Render `report` as deterministic plain text (no ANSI, no cursor codes).
///
/// Header carries scan id, state, scope, and target; coverage carries
/// filesystem/identity/status plus gaps and pending tasks (never a
/// percentage of an unknown total); totals count `repositories`,
/// `checkouts`, `branches`, `remotes`, `candidates`, and `errors` vec
/// lengths. Detail rows follow in vec order:
/// `R <id> <format> match=<m> <common display>`,
/// `C <id> kind=<k> avail=<a> head=<state> status=<state>`,
/// `? <id> <disposition> <reason>`,
/// `! <id> <operation> <category> <message>`.
/// At most [`MAX_DETAIL_ROWS`] detail rows are emitted; the remainder
/// collapses into one `... (N more)` line.
pub fn render_plain(report: &Report) -> String {
    let mut out = String::new();

    // Header: scan id, state, scope, target.
    out.push_str(&format!(
        "scan {} state={} scope={} target={}\n",
        sanitize(&report.scan.id),
        sanitize(&report.scan.state),
        sanitize(&report.scan.scope),
        sanitize(&report.scan.target_url),
    ));

    // Coverage: three independent coverages + gaps + pending tasks.
    // Never a percentage: the total is unknown mid-scan.
    out.push_str(&format!(
        "coverage filesystem={} identity={} status={} gaps={} pending={}\n",
        sanitize(&report.coverage.filesystem),
        sanitize(&report.coverage.identity),
        sanitize(&report.coverage.status),
        report.coverage.gaps,
        report.coverage.tasks_pending,
    ));

    // Totals: raw vec lengths, in D1 record order.
    out.push_str(&format!(
        "totals repositories={} checkouts={} branches={} remotes={} candidates={} errors={}\n",
        report.repositories.len(),
        report.checkouts.len(),
        report.branches.len(),
        report.remotes.len(),
        report.candidates.len(),
        report.errors.len(),
    ));

    let paths: HashMap<&str, &str> = report
        .paths
        .iter()
        .map(|p| (p.id.as_str(), p.display.as_str()))
        .collect();
    let show_path = |id: &str| -> String {
        paths
            .get(id)
            .map(|d| sanitize(d))
            .unwrap_or_else(|| format!("<missing path {}>", sanitize(id)))
    };

    let mut rows: Vec<String> = Vec::new();
    for repo in &report.repositories {
        rows.push(format!(
            "R {} {} match={} {}",
            sanitize(&repo.id),
            sanitize(&repo.format),
            sanitize(&repo.match_disposition),
            show_path(&repo.common_path_id),
        ));
    }
    for checkout in &report.checkouts {
        rows.push(format!(
            "C {} kind={} avail={} head={} status={}",
            sanitize(&checkout.id),
            sanitize(&checkout.kind),
            sanitize(&checkout.availability),
            sanitize(&checkout.head.state),
            sanitize(&checkout.status.state),
        ));
    }
    for candidate in &report.candidates {
        rows.push(format!(
            "? {} {} {}",
            sanitize(&candidate.id),
            sanitize(&candidate.disposition),
            sanitize(&candidate.reason),
        ));
    }
    for error in &report.errors {
        rows.push(format!(
            "! {} {} {} {}",
            sanitize(&error.id),
            sanitize(&error.operation),
            sanitize(&error.category),
            sanitize(&error.message),
        ));
    }

    if rows.len() > MAX_DETAIL_ROWS {
        let hidden = rows.len() - MAX_DETAIL_ROWS;
        for row in rows.iter().take(MAX_DETAIL_ROWS) {
            out.push_str(row);
            out.push('\n');
        }
        out.push_str(&format!("... ({hidden} more)\n"));
    } else {
        for row in &rows {
            out.push_str(row);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::model::{
        Candidate, Checkout, Coverage, ErrorRecord, Head, Repository, Resources, Scan, Status, Tool,
    };

    fn empty_report() -> Report {
        Report {
            schema_version: "1.0.0".to_string(),
            report_id: "r1".to_string(),
            created_at: "2026-10-07T00:00:00Z".to_string(),
            tool: Tool {
                name: "repo-scan".to_string(),
                version: "0.0.0".to_string(),
                source_commit: None,
            },
            scan: Scan {
                id: "scan-1".to_string(),
                generation: 1,
                epoch: 1,
                catalog_revision: 1,
                target_url: "https://github.com/o/r".to_string(),
                canonical_url: None,
                targets: vec![],
                matching_policy: "v1".to_string(),
                scope: "machine".to_string(),
                state: "running".to_string(),
                started_at: "2026-10-07T00:00:00Z".to_string(),
                finished_at: None,
                superseded_by: None,
                cached: false,
                status_mode: "summary".to_string(),
            },
            coverage: Coverage {
                filesystem: "incomplete".to_string(),
                identity: "unproven".to_string(),
                status: "incomplete".to_string(),
                directories_complete: 0,
                tasks_pending: 3,
                gaps: 0,
                unresolvable_candidates: 0,
                scope_boundaries: vec![],
            },
            resources: Resources {
                profile: "default".to_string(),
                cpu_target_cores: 1.0,
                rss_target_bytes: 1,
                peak_rss_bytes: None,
                cpu_seconds: None,
                enumerated_entries: 0,
                db_transactions: 0,
                db_sync_calls: None,
            },
            volumes: vec![],
            paths: vec![],
            roots: vec![],
            repositories: vec![],
            checkouts: vec![],
            branches: vec![],
            remotes: vec![],
            storage_links: vec![],
            aliases: vec![],
            candidates: vec![],
            errors: vec![],
            generated_artifacts: vec![],
        }
    }

    fn repo(id: &str) -> Repository {
        Repository {
            id: id.to_string(),
            git_path_id: "p1".to_string(),
            common_path_id: "p1".to_string(),
            bare: None,
            format: "common".to_string(),
            object_format: "sha1".to_string(),
            match_disposition: "confirmed".to_string(),
            evidence: vec![],
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            tool_managed: None,
            error_ids: vec![],
        }
    }

    fn checkout(id: &str) -> Checkout {
        Checkout {
            id: id.to_string(),
            repository_id: "repo-1".to_string(),
            root_path_id: None,
            git_path_id: "p1".to_string(),
            kind: "main".to_string(),
            availability: "present".to_string(),
            head: Head {
                state: "branch".to_string(),
                ref_name: None,
                oid: None,
            },
            status: Status {
                state: "pending".to_string(),
                mode: "summary".to_string(),
                started_at: None,
                finished_at: None,
                staged: None,
                unstaged: None,
                untracked: None,
                conflicts: None,
                working_state: "pending".to_string(),
                untracked_units: "collapsed_entries".to_string(),
                submodules: "unknown".to_string(),
                unknown_fields: vec![],
                error_ids: vec![],
            },
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            error_ids: vec![],
        }
    }

    #[test]
    fn empty_report_renders_header_coverage_totals() {
        let text = render_plain(&empty_report());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "unexpected lines: {text}");
        assert!(lines[0].contains("scan-1"), "header: {text}");
        assert!(lines[0].contains("state=running"), "header: {text}");
        assert!(lines[0].contains("scope=machine"), "header: {text}");
        assert!(
            lines[1].starts_with("coverage filesystem=incomplete"),
            "coverage: {text}"
        );
        assert!(lines[1].contains("pending=3"), "coverage: {text}");
        assert!(
            lines[2].starts_with("totals repositories=0 checkouts=0"),
            "totals: {text}"
        );
        assert!(!text.contains('%'), "no percentages: {text}");
    }

    #[test]
    fn detail_rows_cap_at_max_with_overflow_line() {
        let mut report = empty_report();
        for i in 0..(MAX_DETAIL_ROWS + 50) {
            report.repositories.push(repo(&format!("repo-{i}")));
        }
        let text = render_plain(&report);
        let detail: Vec<&str> = text.lines().skip(3).collect();
        assert_eq!(detail.len(), MAX_DETAIL_ROWS + 1);
        assert_eq!(detail[MAX_DETAIL_ROWS], "... (50 more)");
    }

    #[test]
    fn control_characters_escaped() {
        let mut report = empty_report();
        report.candidates.push(Candidate {
            id: "cand-1".to_string(),
            path_id: "p1".to_string(),
            repository_id: None,
            disposition: "probe_pending".to_string(),
            reason: "line1\nline2\x1besc\tend".to_string(),
            retry_after: None,
            error_ids: vec![],
        });
        report.errors.push(ErrorRecord {
            id: "err-1".to_string(),
            path_id: None,
            operation: "read".to_string(),
            category: "io".to_string(),
            message: "bad\r\nmsg".to_string(),
            retryable: false,
            attempts: 1,
            first_seen: "2026-10-07T00:00:00Z".to_string(),
            last_seen: "2026-10-07T00:00:00Z".to_string(),
            next_retry: None,
        });
        let text = render_plain(&report);
        assert_eq!(text.lines().count(), 5, "one line per row: {text:?}");
        assert!(text.contains("line1�line2�esc�end"), "escaped: {text:?}");
        assert!(text.contains("bad��msg"), "escaped: {text:?}");
        assert!(!text.contains('\x1b'), "no ESC byte");
        assert!(!text.contains('\r'), "no raw CR");
    }

    #[test]
    fn output_contains_no_esc_byte() {
        let mut report = empty_report();
        report.repositories.push(repo("repo-\x1b[31m"));
        report.checkouts.push(checkout("co-\x07"));
        let text = render_plain(&report);
        assert!(!text.as_bytes().contains(&0x1b), "ESC found: {text:?}");
        assert!(!text.as_bytes().contains(&0x07), "BEL found: {text:?}");
    }
}
