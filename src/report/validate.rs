//! Report validation: schema-domain membership, ID resolution, count
//! agreement, and cross-field rules (spec §16, REPORT-01).
//!
//! Non-null relationship IDs must resolve within the report, except the
//! envelope/scan/successor IDs (external catalog history) and native
//! identities / event cursors (opaque strings, not foreign keys).
//! Relationship counts must agree with emitted records; traversal counters
//! (`directories_complete`, `tasks_pending`) summarize work including
//! nonmatching scope and are therefore exempt from agreement.

use crate::error::Error;
use crate::report::encode::{base64_decode, is_rfc3339_shape, object_id_error};
use crate::report::model::{EncodedName, Report, Status};
use std::collections::{HashMap, HashSet};

/// Validate a report. Returns `Ok` only when every check passes; otherwise
/// returns all violations joined into one [`Error::Report`].
pub fn validate_report(report: &Report) -> crate::Result<()> {
    let mut problems = Vec::new();
    check_envelope(report, &mut problems);
    check_ids(report, &mut problems);
    check_counts(report, &mut problems);
    check_coverage(report, &mut problems);
    check_statuses(report, &mut problems);
    check_encodings(report, &mut problems);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Error::Report(format!(
            "report {} invalid: {}",
            report.report_id,
            problems.join("; ")
        )))
    }
}

fn check_envelope(report: &Report, problems: &mut Vec<String>) {
    if report.schema_version != crate::report::model::SCHEMA_VERSION {
        problems.push(format!(
            "schema_version is {:?}, want {:?}",
            report.schema_version,
            crate::report::model::SCHEMA_VERSION
        ));
    }
    if report.report_id.is_empty() {
        problems.push("report_id must be nonempty".to_string());
    }
    if !is_rfc3339_shape(&report.created_at) {
        problems.push(format!(
            "created_at {:?} is not RFC 3339",
            report.created_at
        ));
    }
    if report.tool.name != crate::report::model::TOOL_NAME {
        problems.push(format!(
            "tool.name is {:?}, want \"repo-scan\"",
            report.tool.name
        ));
    }
    check_enum(
        "scan.scope",
        &report.scan.scope,
        &["machine", "roots"],
        problems,
    );
    check_enum(
        "scan.state",
        &report.scan.state,
        &[
            "running",
            "complete",
            "incomplete",
            "interrupted",
            "failed",
            "superseded",
        ],
        problems,
    );
    check_enum(
        "scan.status_mode",
        &report.scan.status_mode,
        &["metadata", "summary", "full"],
        problems,
    );
    if report.scan.id.is_empty() {
        problems.push("scan.id must be nonempty".to_string());
    }
    if !is_rfc3339_shape(&report.scan.started_at) {
        problems.push(format!(
            "scan.started_at {:?} is not RFC 3339",
            report.scan.started_at
        ));
    }
    check_opt_time("scan.finished_at", &report.scan.finished_at, problems);
    if let Some(successor) = &report.scan.superseded_by {
        if successor.is_empty() {
            problems.push("scan.superseded_by must be nonempty when present".to_string());
        }
    }
    check_enum(
        "coverage.filesystem",
        &report.coverage.filesystem,
        &["complete", "incomplete", "unknown"],
        problems,
    );
    check_enum(
        "coverage.identity",
        &report.coverage.identity,
        &["complete_under_policy", "unproven"],
        problems,
    );
    check_enum(
        "coverage.status",
        &report.coverage.status,
        &["complete", "incomplete", "not_requested"],
        problems,
    );
    if report.resources.cpu_target_cores <= 0.0 {
        problems.push(format!(
            "resources.cpu_target_cores must be > 0, got {}",
            report.resources.cpu_target_cores
        ));
    }
    if let Some(seconds) = report.resources.cpu_seconds {
        if seconds < 0.0 {
            problems.push(format!("resources.cpu_seconds must be >= 0, got {seconds}"));
        }
    }
    for volume in &report.volumes {
        check_enum(
            &format!("volume {} kind", volume.id),
            &volume.kind,
            &["local", "network", "virtual", "unknown"],
            problems,
        );
        check_enum(
            &format!("volume {} state", volume.id),
            &volume.state,
            &["available", "inaccessible", "unavailable", "unknown"],
            problems,
        );
        check_opt_time(
            &format!("volume {} observed_at", volume.id),
            &volume.observed_at,
            problems,
        );
    }
    for root in &report.roots {
        check_enum(
            &format!("root {} state", root.id),
            &root.state,
            &[
                "complete",
                "pending",
                "inaccessible",
                "unavailable",
                "error",
            ],
            problems,
        );
        check_opt_time(
            &format!("root {} observed_at", root.id),
            &root.observed_at,
            problems,
        );
    }
    for repo in &report.repositories {
        check_enum(
            &format!("repository {} match", repo.id),
            &repo.match_disposition,
            &[
                "confirmed",
                "related",
                "probable",
                "nonmatch",
                "unresolvable_identity",
            ],
            problems,
        );
        if !is_rfc3339_shape(&repo.observed_at) {
            problems.push(format!(
                "repository {} observed_at {:?} is not RFC 3339",
                repo.id, repo.observed_at
            ));
        }
    }
    for checkout in &report.checkouts {
        check_enum(
            &format!("checkout {} kind", checkout.id),
            &checkout.kind,
            &["main", "linked", "submodule", "unknown"],
            problems,
        );
        check_enum(
            &format!("checkout {} availability", checkout.id),
            &checkout.availability,
            &["present", "missing", "inaccessible", "broken", "unknown"],
            problems,
        );
        check_enum(
            &format!("checkout {} head.state", checkout.id),
            &checkout.head.state,
            &["branch", "detached", "unborn", "invalid", "unknown"],
            problems,
        );
        if let Some(oid) = &checkout.head.oid {
            if let Some(reason) = object_id_error(oid) {
                problems.push(format!("checkout {} head.oid: {reason}", checkout.id));
            }
        }
        if !is_rfc3339_shape(&checkout.observed_at) {
            problems.push(format!(
                "checkout {} observed_at {:?} is not RFC 3339",
                checkout.id, checkout.observed_at
            ));
        }
    }
    for branch in &report.branches {
        check_enum(
            &format!("branch {} kind", branch.id),
            &branch.kind,
            &["local", "remote_tracking", "other"],
            problems,
        );
        check_enum(
            &format!("branch {} state", branch.id),
            &branch.state,
            &["valid", "unborn", "invalid", "unsupported"],
            problems,
        );
        if let Some(oid) = &branch.oid {
            if let Some(reason) = object_id_error(oid) {
                problems.push(format!("branch {} oid: {reason}", branch.id));
            }
        }
        if !is_rfc3339_shape(&branch.observed_at) {
            problems.push(format!(
                "branch {} observed_at {:?} is not RFC 3339",
                branch.id, branch.observed_at
            ));
        }
    }
    for remote in &report.remotes {
        check_enum(
            &format!("remote {} role", remote.id),
            &remote.role,
            &["fetch", "push"],
            problems,
        );
        if !is_rfc3339_shape(&remote.observed_at) {
            problems.push(format!(
                "remote {} observed_at {:?} is not RFC 3339",
                remote.id, remote.observed_at
            ));
        }
    }
    for link in &report.storage_links {
        check_enum(
            &format!("storage_link {} kind", link.id),
            &link.kind,
            &[
                "common_directory",
                "alternate_objects",
                "shared_object_store",
                "observed_hardlink",
            ],
            problems,
        );
    }
    for (i, alias) in report.aliases.iter().enumerate() {
        check_enum(
            &format!("alias {i} kind"),
            &alias.kind,
            &["symlink", "firmlink", "mount_alias", "same_object"],
            problems,
        );
        if !is_rfc3339_shape(&alias.verified_at) {
            problems.push(format!(
                "alias {i} verified_at {:?} is not RFC 3339",
                alias.verified_at
            ));
        }
    }
    for candidate in &report.candidates {
        check_enum(
            &format!("candidate {} disposition", candidate.id),
            &candidate.disposition,
            &[
                "probe_pending",
                "probe_failed",
                "unsupported",
                "unresolvable_identity",
            ],
            problems,
        );
        check_opt_time(
            &format!("candidate {} retry_after", candidate.id),
            &candidate.retry_after,
            problems,
        );
    }
    for error in &report.errors {
        if !is_rfc3339_shape(&error.first_seen) {
            problems.push(format!(
                "error {} first_seen {:?} is not RFC 3339",
                error.id, error.first_seen
            ));
        }
        if !is_rfc3339_shape(&error.last_seen) {
            problems.push(format!(
                "error {} last_seen {:?} is not RFC 3339",
                error.id, error.last_seen
            ));
        }
        check_opt_time(
            &format!("error {} next_retry", error.id),
            &error.next_retry,
            problems,
        );
    }
    for (i, artifact) in report.generated_artifacts.iter().enumerate() {
        check_enum(
            &format!("generated_artifact {i} kind"),
            &artifact.kind,
            &["report", "tool_state"],
            problems,
        );
    }
}

fn check_enum(context: &str, value: &str, allowed: &[&str], problems: &mut Vec<String>) {
    if !allowed.contains(&value) {
        problems.push(format!("{context} is {value:?}, want one of {allowed:?}"));
    }
}

fn check_opt_time(context: &str, value: &Option<String>, problems: &mut Vec<String>) {
    if let Some(time) = value {
        if !is_rfc3339_shape(time) {
            problems.push(format!("{context} {time:?} is not RFC 3339"));
        }
    }
}

fn collect_id<'a>(
    seen: &mut HashMap<&'a str, HashSet<&'a str>>,
    section: &'static str,
    id: &'a str,
    problems: &mut Vec<String>,
) {
    if id.is_empty() {
        problems.push(format!("{section} has an empty id"));
    }
    if !seen.entry(section).or_default().insert(id) {
        problems.push(format!("duplicate {section} id {id:?}"));
    }
}

/// ID resolution: every non-null relationship ID must resolve to an emitted
/// record. Envelope/scan/successor IDs and native identities / event cursors
/// are explicitly exempt (external history and opaque strings).
fn check_ids(report: &Report, problems: &mut Vec<String>) {
    let mut volumes = HashSet::new();
    let mut paths = HashSet::new();
    let mut repositories = HashSet::new();
    let mut checkouts = HashSet::new();
    let mut errors = HashSet::new();
    let mut seen: HashMap<&str, HashSet<&str>> = HashMap::new();
    for volume in &report.volumes {
        collect_id(&mut seen, "volume", &volume.id, problems);
        volumes.insert(volume.id.as_str());
    }
    for path in &report.paths {
        collect_id(&mut seen, "path", &path.id, problems);
        paths.insert(path.id.as_str());
    }
    for root in &report.roots {
        collect_id(&mut seen, "root", &root.id, problems);
    }
    for repo in &report.repositories {
        collect_id(&mut seen, "repository", &repo.id, problems);
        repositories.insert(repo.id.as_str());
    }
    for checkout in &report.checkouts {
        collect_id(&mut seen, "checkout", &checkout.id, problems);
        checkouts.insert(checkout.id.as_str());
    }
    for branch in &report.branches {
        collect_id(&mut seen, "branch", &branch.id, problems);
    }
    for remote in &report.remotes {
        collect_id(&mut seen, "remote", &remote.id, problems);
    }
    for link in &report.storage_links {
        collect_id(&mut seen, "storage_link", &link.id, problems);
    }
    for candidate in &report.candidates {
        collect_id(&mut seen, "candidate", &candidate.id, problems);
    }
    for error in &report.errors {
        collect_id(&mut seen, "error", &error.id, problems);
        errors.insert(error.id.as_str());
    }

    let resolve = |context: String, id: &str, table: &HashSet<&str>, problems: &mut Vec<String>| {
        if id.is_empty() {
            problems.push(format!("{context} is an empty id"));
        } else if !table.contains(id) {
            problems.push(format!("{context} references missing id {id:?}"));
        }
    };
    let resolve_opt = |context: String,
                       id: &Option<String>,
                       table: &HashSet<&str>,
                       problems: &mut Vec<String>| {
        if let Some(id) = id {
            resolve(context, id, table, problems);
        }
    };
    let resolve_error_ids = |context: String, ids: &[String], problems: &mut Vec<String>| {
        for id in ids {
            resolve(format!("{context} error reference"), id, &errors, problems);
        }
    };

    for path in &report.paths {
        resolve_opt(
            format!("path {} volume_id", path.id),
            &path.volume_id,
            &volumes,
            problems,
        );
    }
    for volume in &report.volumes {
        resolve_error_ids(format!("volume {}", volume.id), &volume.error_ids, problems);
    }
    for root in &report.roots {
        resolve(
            format!("root {} path_id", root.id),
            &root.path_id,
            &paths,
            problems,
        );
        resolve_opt(
            format!("root {} volume_id", root.id),
            &root.volume_id,
            &volumes,
            problems,
        );
        resolve_error_ids(format!("root {}", root.id), &root.error_ids, problems);
    }
    for repo in &report.repositories {
        resolve(
            format!("repository {} git_path_id", repo.id),
            &repo.git_path_id,
            &paths,
            problems,
        );
        resolve(
            format!("repository {} common_path_id", repo.id),
            &repo.common_path_id,
            &paths,
            problems,
        );
        resolve_error_ids(format!("repository {}", repo.id), &repo.error_ids, problems);
    }
    for checkout in &report.checkouts {
        resolve(
            format!("checkout {} repository_id", checkout.id),
            &checkout.repository_id,
            &repositories,
            problems,
        );
        resolve_opt(
            format!("checkout {} root_path_id", checkout.id),
            &checkout.root_path_id,
            &paths,
            problems,
        );
        resolve(
            format!("checkout {} git_path_id", checkout.id),
            &checkout.git_path_id,
            &paths,
            problems,
        );
        resolve_error_ids(
            format!("checkout {} status", checkout.id),
            &checkout.status.error_ids,
            problems,
        );
        resolve_error_ids(
            format!("checkout {}", checkout.id),
            &checkout.error_ids,
            problems,
        );
    }
    for branch in &report.branches {
        resolve(
            format!("branch {} repository_id", branch.id),
            &branch.repository_id,
            &repositories,
            problems,
        );
        resolve_opt(
            format!("branch {} checkout_scope_id", branch.id),
            &branch.checkout_scope_id,
            &checkouts,
            problems,
        );
        resolve_error_ids(format!("branch {}", branch.id), &branch.error_ids, problems);
    }
    for remote in &report.remotes {
        resolve(
            format!("remote {} repository_id", remote.id),
            &remote.repository_id,
            &repositories,
            problems,
        );
        resolve_opt(
            format!("remote {} checkout_scope_id", remote.id),
            &remote.checkout_scope_id,
            &checkouts,
            problems,
        );
    }
    for link in &report.storage_links {
        resolve(
            format!("storage_link {} from_repository_id", link.id),
            &link.from_repository_id,
            &repositories,
            problems,
        );
        resolve(
            format!("storage_link {} to_path_id", link.id),
            &link.to_path_id,
            &paths,
            problems,
        );
    }
    for (i, alias) in report.aliases.iter().enumerate() {
        resolve(
            format!("alias {i} path_id"),
            &alias.path_id,
            &paths,
            problems,
        );
        resolve(
            format!("alias {i} target_path_id"),
            &alias.target_path_id,
            &paths,
            problems,
        );
    }
    for candidate in &report.candidates {
        resolve(
            format!("candidate {} path_id", candidate.id),
            &candidate.path_id,
            &paths,
            problems,
        );
        resolve_opt(
            format!("candidate {} repository_id", candidate.id),
            &candidate.repository_id,
            &repositories,
            problems,
        );
        resolve_error_ids(
            format!("candidate {}", candidate.id),
            &candidate.error_ids,
            problems,
        );
    }
    for error in &report.errors {
        resolve_opt(
            format!("error {} path_id", error.id),
            &error.path_id,
            &paths,
            problems,
        );
    }
    for (i, artifact) in report.generated_artifacts.iter().enumerate() {
        resolve(
            format!("generated_artifact {i} path_id"),
            &artifact.path_id,
            &paths,
            problems,
        );
    }
}

/// Count agreement: `gaps` equals the emitted error records and
/// `unresolvable_candidates` equals the emitted candidates with the
/// `unresolvable_identity` disposition.
fn check_counts(report: &Report, problems: &mut Vec<String>) {
    let gaps = report.errors.len() as u64;
    if report.coverage.gaps != gaps {
        problems.push(format!(
            "coverage.gaps is {}, but {} error records were emitted",
            report.coverage.gaps, gaps
        ));
    }
    let unresolvable = report
        .candidates
        .iter()
        .filter(|candidate| candidate.disposition == "unresolvable_identity")
        .count() as u64;
    if report.coverage.unresolvable_candidates != unresolvable {
        problems.push(format!(
            "coverage.unresolvable_candidates is {}, but {unresolvable} \
             unresolvable candidates were emitted",
            report.coverage.unresolvable_candidates
        ));
    }
}

/// Coverage honesty: completeness claims must agree with the emitted
/// scan state (RSP-008). The builder derives these values; validation
/// rejects any report — including a hand-crafted one — whose claims
/// contradict its own records.
fn check_coverage(report: &Report, problems: &mut Vec<String>) {
    if report.coverage.filesystem == "complete" {
        if report.coverage.tasks_pending != 0 {
            problems.push(format!(
                "coverage.filesystem is complete but tasks_pending is {}",
                report.coverage.tasks_pending
            ));
        }
        if report.coverage.gaps != 0 {
            problems.push(format!(
                "coverage.filesystem is complete but gaps is {}",
                report.coverage.gaps
            ));
        }
    }
    if report.coverage.status == "complete" {
        for checkout in &report.checkouts {
            if checkout.status.state != "complete" {
                problems.push(format!(
                    "coverage.status is complete but checkout {} status is {:?}",
                    checkout.id, checkout.status.state
                ));
            }
        }
    }
    if report.coverage.status == "not_requested" && report.scan.status_mode != "metadata" {
        problems.push(format!(
            "coverage.status is not_requested but scan.status_mode is {:?}",
            report.scan.status_mode
        ));
    }
    if report.coverage.identity == "complete_under_policy" {
        if report.coverage.unresolvable_candidates != 0 {
            problems.push(format!(
                "coverage.identity is complete_under_policy but unresolvable_candidates is {}",
                report.coverage.unresolvable_candidates
            ));
        }
        for repo in &report.repositories {
            if repo.match_disposition == "unresolvable_identity" {
                problems.push(format!(
                    "coverage.identity is complete_under_policy but repository {} is unresolvable_identity",
                    repo.id
                ));
            }
        }
    }
}

/// Cross-field status rules for every checkout status.
fn check_statuses(report: &Report, problems: &mut Vec<String>) {
    for checkout in &report.checkouts {
        validate_status(
            &checkout.status,
            &format!("checkout {} status", checkout.id),
            problems,
        );
    }
}

/// Validate one [`Status`] against the cross-field rules. Public so the
/// scheduler/git lanes can check observations before persisting them.
pub fn validate_status(status: &Status, context: &str, problems: &mut Vec<String>) {
    check_enum(
        &format!("{context} state"),
        &status.state,
        &[
            "complete",
            "partial",
            "pending",
            "not_requested",
            "unsupported",
            "unstable",
            "error",
        ],
        problems,
    );
    check_enum(
        &format!("{context} mode"),
        &status.mode,
        &["metadata", "summary", "full"],
        problems,
    );
    check_enum(
        &format!("{context} untracked_units"),
        &status.untracked_units,
        &["collapsed_entries", "files", "not_requested"],
        problems,
    );
    check_enum(
        &format!("{context} submodules"),
        &status.submodules,
        &["checked", "not_requested", "unknown"],
        problems,
    );
    check_opt_time(
        &format!("{context} started_at"),
        &status.started_at,
        problems,
    );
    check_opt_time(
        &format!("{context} finished_at"),
        &status.finished_at,
        problems,
    );
    match status.mode.as_str() {
        "metadata" => {
            if status.staged.is_some() || status.unstaged.is_some() || status.untracked.is_some() {
                problems.push(format!("{context}: metadata mode must have null counts"));
            }
            if status.untracked_units != "not_requested" {
                problems.push(format!(
                    "{context}: metadata mode requires untracked_units not_requested"
                ));
            }
        }
        "summary" => {
            if status.untracked_units != "collapsed_entries" {
                problems.push(format!(
                    "{context}: summary mode requires untracked_units collapsed_entries"
                ));
            }
        }
        "full" if status.untracked_units != "files" => {
            problems.push(format!(
                "{context}: full mode requires untracked_units files"
            ));
        }
        _ => {}
    }
}

/// Encoding rules: `utf8`/`base64` membership, Base64 well-formedness, and
/// `display` free of raw control characters (it must be escaped).
fn check_encodings(report: &Report, problems: &mut Vec<String>) {
    for path in &report.paths {
        check_encoding(
            &format!("path {} encoding", path.id),
            &path.encoding,
            &path.value,
            &path.display,
            problems,
        );
    }
    for checkout in &report.checkouts {
        if let Some(name) = checkout.head.ref_name.as_ref() {
            check_name(
                &format!("checkout {} head.ref_name", checkout.id),
                name,
                problems,
            );
        }
    }
    for branch in &report.branches {
        check_name(
            &format!("branch {} name", branch.id),
            &branch.name,
            problems,
        );
        if let Some(target) = branch.symbolic_target.as_ref() {
            check_name(
                &format!("branch {} symbolic_target", branch.id),
                target,
                problems,
            );
        }
        if let Some(upstream) = branch.upstream.as_ref() {
            check_name(
                &format!("branch {} upstream", branch.id),
                upstream,
                problems,
            );
        }
    }
    for remote in &report.remotes {
        check_name(
            &format!("remote {} name", remote.id),
            &remote.name,
            problems,
        );
    }
}

fn check_name(context: &str, name: &EncodedName, problems: &mut Vec<String>) {
    check_encoding(
        context,
        &name.encoding,
        &name.value,
        &name.display,
        problems,
    );
}

fn check_encoding(
    context: &str,
    encoding: &str,
    value: &str,
    display: &str,
    problems: &mut Vec<String>,
) {
    if encoding != "utf8" && encoding != "base64" {
        problems.push(format!("{context} is {encoding:?}, want utf8 or base64"));
        return;
    }
    if encoding == "base64" && base64_decode(value).is_none() {
        problems.push(format!("{context}: base64 value is malformed"));
    }
    if display.chars().any(|c| c.is_control()) {
        problems.push(format!("{context}: display carries raw control characters"));
    }
}
