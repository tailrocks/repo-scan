//! Bounded-memory validation for staged reports that need only a pass/fail
//! result. Records are decoded one at a time; the first pass retains only
//! borrowed IDs, and the second checks each record against those exact IDs.

use crate::report::encode::{is_rfc3339_shape, object_id_error};
use crate::report::model::{
    Alias, Branch, Candidate, Checkout, Coverage, ErrorRecord, GeneratedArtifact, PathRecord,
    Remote, Repository, Resources, Root, Scan, StorageLink, Tool, Volume,
};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::marker::PhantomData;

const MAX_PROBLEMS: usize = 256;
const ROOT_FIELDS: u32 = (1 << 19) - 1;

#[derive(Copy, Clone, Eq, PartialEq)]
enum Pass {
    CollectIds,
    Validate,
}

#[derive(Copy, Clone)]
enum IdKind {
    Volume,
    Path,
    Root,
    Repository,
    Checkout,
    Branch,
    Remote,
    StorageLink,
    Candidate,
    Error,
}

#[derive(Default)]
struct IdSets<'a> {
    volumes: HashSet<Cow<'a, str>>,
    paths: HashSet<Cow<'a, str>>,
    roots: HashSet<Cow<'a, str>>,
    repositories: HashSet<Cow<'a, str>>,
    checkouts: HashSet<Cow<'a, str>>,
    branches: HashSet<Cow<'a, str>>,
    remotes: HashSet<Cow<'a, str>>,
    storage_links: HashSet<Cow<'a, str>>,
    candidates: HashSet<Cow<'a, str>>,
    errors: HashSet<Cow<'a, str>>,
}

impl<'a> IdSets<'a> {
    fn contains(&self, kind: IdKind, id: &str) -> bool {
        match kind {
            IdKind::Volume => self.volumes.contains(id),
            IdKind::Path => self.paths.contains(id),
            IdKind::Root => self.roots.contains(id),
            IdKind::Repository => self.repositories.contains(id),
            IdKind::Checkout => self.checkouts.contains(id),
            IdKind::Branch => self.branches.contains(id),
            IdKind::Remote => self.remotes.contains(id),
            IdKind::StorageLink => self.storage_links.contains(id),
            IdKind::Candidate => self.candidates.contains(id),
            IdKind::Error => self.errors.contains(id),
        }
    }

    fn insert(&mut self, kind: IdKind, id: Cow<'a, str>) -> bool {
        match kind {
            IdKind::Volume => self.volumes.insert(id),
            IdKind::Path => self.paths.insert(id),
            IdKind::Root => self.roots.insert(id),
            IdKind::Repository => self.repositories.insert(id),
            IdKind::Checkout => self.checkouts.insert(id),
            IdKind::Branch => self.branches.insert(id),
            IdKind::Remote => self.remotes.insert(id),
            IdKind::StorageLink => self.storage_links.insert(id),
            IdKind::Candidate => self.candidates.insert(id),
            IdKind::Error => self.errors.insert(id),
        }
    }
}

#[derive(Deserialize)]
struct IdOnly<'a> {
    #[serde(borrow)]
    id: Cow<'a, str>,
}

#[derive(Default)]
struct StreamState<'a> {
    ids: IdSets<'a>,
    problems: Vec<String>,
    report_id: String,
    scan_complete: bool,
    scan_status_mode: String,
    scan_status_mode_metadata: bool,
    coverage_filesystem_complete: bool,
    coverage_identity_complete: bool,
    coverage_status_complete: bool,
    coverage_status_incomplete: bool,
    coverage_status_not_requested: bool,
    coverage_tasks_pending: u64,
    coverage_gaps: u64,
    coverage_unresolvable_candidates: u64,
    errors_seen: u64,
    unresolvable_candidates_seen: u64,
    aliases_seen: usize,
    artifacts_seen: usize,
    checkout_status_gap: Option<(String, u64)>,
    unresolvable_repository: Option<(String, u64)>,
}

impl<'a> StreamState<'a> {
    fn add_schema_version(&mut self, value: String) {
        if value != crate::report::model::SCHEMA_VERSION {
            self.problem(format!(
                "schema_version is {:?}, want {:?}",
                short_id(&value),
                crate::report::model::SCHEMA_VERSION
            ));
        }
    }

    fn add_report_id(&mut self, value: String) {
        if value.is_empty() {
            self.problem("report_id must be nonempty");
        }
        self.report_id = value;
    }

    fn add_created_at(&mut self, value: String) {
        if !is_rfc3339_shape(&value) {
            self.problem(format!("created_at {:?} is not RFC 3339", short_id(&value)));
        }
    }

    fn add_tool(&mut self, value: Tool) {
        if value.name != crate::report::model::TOOL_NAME {
            self.problem(format!(
                "tool.name is {:?}, want \"repo-scan\"",
                short_id(&value.name)
            ));
        }
    }

    fn add_scan(&mut self, value: Scan) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            "scan.scope",
            &value.scope,
            &["machine", "roots"],
            &mut problems,
        );
        crate::report::validate::check_enum(
            "scan.state",
            &value.state,
            &[
                "running",
                "complete",
                "incomplete",
                "interrupted",
                "failed",
                "superseded",
            ],
            &mut problems,
        );
        crate::report::validate::check_enum(
            "scan.status_mode",
            &value.status_mode,
            &["metadata", "summary", "full"],
            &mut problems,
        );
        if value.id.is_empty() {
            problems.push("scan.id must be nonempty".to_string());
        }
        if !is_rfc3339_shape(&value.started_at) {
            problems.push(format!(
                "scan.started_at {:?} is not RFC 3339",
                short_id(&value.started_at)
            ));
        }
        crate::report::validate::check_opt_time(
            "scan.finished_at",
            &value.finished_at,
            &mut problems,
        );
        if value.superseded_by.as_deref() == Some("") {
            problems.push("scan.superseded_by must be nonempty when present".to_string());
        }
        self.extend_problems(problems);
        self.scan_complete = value.state == "complete";
        self.scan_status_mode_metadata = value.status_mode == "metadata";
        self.scan_status_mode = short_id(&value.status_mode).to_string();
    }

    fn add_coverage(&mut self, value: Coverage) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            "coverage.filesystem",
            &value.filesystem,
            &["complete", "incomplete", "unknown"],
            &mut problems,
        );
        crate::report::validate::check_enum(
            "coverage.identity",
            &value.identity,
            &["complete_under_policy", "unproven"],
            &mut problems,
        );
        crate::report::validate::check_enum(
            "coverage.status",
            &value.status,
            &["complete", "incomplete", "not_requested"],
            &mut problems,
        );
        self.extend_problems(problems);
        self.coverage_filesystem_complete = value.filesystem == "complete";
        self.coverage_identity_complete = value.identity == "complete_under_policy";
        self.coverage_status_complete = value.status == "complete";
        self.coverage_status_incomplete = value.status == "incomplete";
        self.coverage_status_not_requested = value.status == "not_requested";
        self.coverage_tasks_pending = value.tasks_pending;
        self.coverage_gaps = value.gaps;
        self.coverage_unresolvable_candidates = value.unresolvable_candidates;
    }

    fn add_resources(&mut self, value: Resources) {
        if value.cpu_target_cores <= 0.0 {
            self.problem(format!(
                "resources.cpu_target_cores must be > 0, got {}",
                value.cpu_target_cores
            ));
        }
        if let Some(seconds) = value.cpu_seconds {
            if seconds < 0.0 {
                self.problem(format!("resources.cpu_seconds must be >= 0, got {seconds}"));
            }
        }
    }

    fn problem(&mut self, problem: impl Into<String>) {
        if self.problems.len() < MAX_PROBLEMS {
            self.problems.push(problem.into());
        }
    }

    fn extend_problems(&mut self, problems: Vec<String>) {
        for problem in problems {
            self.problem(problem);
            if self.problems.len() == MAX_PROBLEMS {
                break;
            }
        }
    }

    fn add_id(&mut self, kind: IdKind, id: Cow<'a, str>, label: &str) {
        if id.is_empty() {
            self.problem(format!("{label} has an empty id"));
        }
        if !self.ids.insert(kind, id) {
            self.problem(format!("duplicate {label} id"));
        }
    }

    fn resolve(&mut self, context: String, id: &str, kind: IdKind) {
        if id.is_empty() {
            self.problem(format!("{context} is an empty id"));
        } else if !self.ids.contains(kind, id) {
            self.problem(format!(
                "{context} references missing id {:?}",
                short_id(id)
            ));
        }
    }

    fn resolve_opt(&mut self, context: String, id: &Option<String>, kind: IdKind) {
        if let Some(id) = id {
            self.resolve(context, id, kind);
        }
    }

    fn resolve_errors(&mut self, context: String, ids: &[String]) {
        for id in ids {
            self.resolve(format!("{context} error reference"), id, IdKind::Error);
        }
    }

    fn add_volume(&mut self, row: Volume) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            &format!("volume {} kind", short_id(&row.id)),
            &row.kind,
            &["local", "network", "virtual", "unknown"],
            &mut problems,
        );
        crate::report::validate::check_enum(
            &format!("volume {} state", short_id(&row.id)),
            &row.state,
            &["available", "inaccessible", "unavailable", "unknown"],
            &mut problems,
        );
        crate::report::validate::check_opt_time(
            &format!("volume {} observed_at", short_id(&row.id)),
            &row.observed_at,
            &mut problems,
        );
        self.extend_problems(problems);
        self.resolve_errors(format!("volume {}", short_id(&row.id)), &row.error_ids);
    }

    fn add_path(&mut self, row: PathRecord) {
        let mut problems = Vec::new();
        crate::report::validate::check_encoding(
            &format!("path {} encoding", short_id(&row.id)),
            &row.encoding,
            &row.value,
            &row.display,
            &mut problems,
        );
        self.extend_problems(problems);
        self.resolve_opt(
            format!("path {} volume_id", short_id(&row.id)),
            &row.volume_id,
            IdKind::Volume,
        );
    }

    fn add_root(&mut self, row: Root) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            &format!("root {} state", short_id(&row.id)),
            &row.state,
            &[
                "complete",
                "pending",
                "inaccessible",
                "unavailable",
                "error",
            ],
            &mut problems,
        );
        crate::report::validate::check_opt_time(
            &format!("root {} observed_at", short_id(&row.id)),
            &row.observed_at,
            &mut problems,
        );
        self.extend_problems(problems);
        self.resolve(
            format!("root {} path_id", short_id(&row.id)),
            &row.path_id,
            IdKind::Path,
        );
        self.resolve_opt(
            format!("root {} volume_id", short_id(&row.id)),
            &row.volume_id,
            IdKind::Volume,
        );
        self.resolve_errors(format!("root {}", short_id(&row.id)), &row.error_ids);
    }

    fn add_repository(&mut self, row: Repository) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            &format!("repository {} match", short_id(&row.id)),
            &row.match_disposition,
            &[
                "confirmed",
                "related",
                "probable",
                "nonmatch",
                "unresolvable_identity",
            ],
            &mut problems,
        );
        if !is_rfc3339_shape(&row.observed_at) {
            problems.push(format!(
                "repository {} observed_at {:?} is not RFC 3339",
                short_id(&row.id),
                short_id(&row.observed_at)
            ));
        }
        self.extend_problems(problems);
        self.resolve(
            format!("repository {} git_path_id", short_id(&row.id)),
            &row.git_path_id,
            IdKind::Path,
        );
        self.resolve(
            format!("repository {} common_path_id", short_id(&row.id)),
            &row.common_path_id,
            IdKind::Path,
        );
        self.resolve_errors(format!("repository {}", short_id(&row.id)), &row.error_ids);
        if row.match_disposition == "unresolvable_identity" {
            remember_first(
                &mut self.unresolvable_repository,
                short_id(&row.id).to_string(),
            );
        }
    }

    fn add_checkout(&mut self, row: Checkout) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            &format!("checkout {} kind", short_id(&row.id)),
            &row.kind,
            &["main", "linked", "submodule", "unknown"],
            &mut problems,
        );
        crate::report::validate::check_enum(
            &format!("checkout {} availability", short_id(&row.id)),
            &row.availability,
            &["present", "missing", "inaccessible", "broken", "unknown"],
            &mut problems,
        );
        crate::report::validate::check_enum(
            &format!("checkout {} head.state", short_id(&row.id)),
            &row.head.state,
            &["branch", "detached", "unborn", "invalid", "unknown"],
            &mut problems,
        );
        if let Some(oid) = &row.head.oid {
            if let Some(reason) = object_id_error(oid) {
                problems.push(format!("checkout {} head.oid: {reason}", short_id(&row.id)));
            }
        }
        if !is_rfc3339_shape(&row.observed_at) {
            problems.push(format!(
                "checkout {} observed_at {:?} is not RFC 3339",
                short_id(&row.id),
                short_id(&row.observed_at)
            ));
        }
        crate::report::validate::validate_status(
            &row.status,
            &format!("checkout {} status", short_id(&row.id)),
            &mut problems,
        );
        if let Some(name) = &row.head.ref_name {
            crate::report::validate::check_encoding(
                &format!("checkout {} head.ref_name", short_id(&row.id)),
                &name.encoding,
                &name.value,
                &name.display,
                &mut problems,
            );
        }
        self.extend_problems(problems);
        self.resolve(
            format!("checkout {} repository_id", short_id(&row.id)),
            &row.repository_id,
            IdKind::Repository,
        );
        self.resolve_opt(
            format!("checkout {} root_path_id", short_id(&row.id)),
            &row.root_path_id,
            IdKind::Path,
        );
        self.resolve(
            format!("checkout {} git_path_id", short_id(&row.id)),
            &row.git_path_id,
            IdKind::Path,
        );
        self.resolve_errors(
            format!("checkout {} status", short_id(&row.id)),
            &row.status.error_ids,
        );
        self.resolve_errors(format!("checkout {}", short_id(&row.id)), &row.error_ids);
        if row.status.state != "complete" {
            remember_first(&mut self.checkout_status_gap, short_id(&row.id).to_string());
        }
    }

    fn add_branch(&mut self, row: Branch) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            &format!("branch {} kind", short_id(&row.id)),
            &row.kind,
            &["local", "remote_tracking", "other"],
            &mut problems,
        );
        crate::report::validate::check_enum(
            &format!("branch {} state", short_id(&row.id)),
            &row.state,
            &["valid", "unborn", "invalid", "unsupported"],
            &mut problems,
        );
        if let Some(oid) = &row.oid {
            if let Some(reason) = object_id_error(oid) {
                problems.push(format!("branch {} oid: {reason}", short_id(&row.id)));
            }
        }
        if !is_rfc3339_shape(&row.observed_at) {
            problems.push(format!(
                "branch {} observed_at {:?} is not RFC 3339",
                short_id(&row.id),
                short_id(&row.observed_at)
            ));
        }
        check_name(
            &format!("branch {} name", short_id(&row.id)),
            &row.name,
            &mut problems,
        );
        if let Some(name) = &row.symbolic_target {
            check_name(
                &format!("branch {} symbolic_target", short_id(&row.id)),
                name,
                &mut problems,
            );
        }
        if let Some(name) = &row.upstream {
            check_name(
                &format!("branch {} upstream", short_id(&row.id)),
                name,
                &mut problems,
            );
        }
        self.extend_problems(problems);
        self.resolve(
            format!("branch {} repository_id", short_id(&row.id)),
            &row.repository_id,
            IdKind::Repository,
        );
        self.resolve_opt(
            format!("branch {} checkout_scope_id", short_id(&row.id)),
            &row.checkout_scope_id,
            IdKind::Checkout,
        );
        self.resolve_errors(format!("branch {}", short_id(&row.id)), &row.error_ids);
    }

    fn add_remote(&mut self, row: Remote) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            &format!("remote {} role", short_id(&row.id)),
            &row.role,
            &["fetch", "push"],
            &mut problems,
        );
        if !is_rfc3339_shape(&row.observed_at) {
            problems.push(format!(
                "remote {} observed_at {:?} is not RFC 3339",
                short_id(&row.id),
                short_id(&row.observed_at)
            ));
        }
        check_name(
            &format!("remote {} name", short_id(&row.id)),
            &row.name,
            &mut problems,
        );
        self.extend_problems(problems);
        self.resolve(
            format!("remote {} repository_id", short_id(&row.id)),
            &row.repository_id,
            IdKind::Repository,
        );
        self.resolve_opt(
            format!("remote {} checkout_scope_id", short_id(&row.id)),
            &row.checkout_scope_id,
            IdKind::Checkout,
        );
    }

    fn add_storage_link(&mut self, row: StorageLink) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            &format!("storage_link {} kind", short_id(&row.id)),
            &row.kind,
            &[
                "common_directory",
                "alternate_objects",
                "shared_object_store",
                "observed_hardlink",
            ],
            &mut problems,
        );
        self.extend_problems(problems);
        self.resolve(
            format!("storage_link {} from_repository_id", short_id(&row.id)),
            &row.from_repository_id,
            IdKind::Repository,
        );
        self.resolve(
            format!("storage_link {} to_path_id", short_id(&row.id)),
            &row.to_path_id,
            IdKind::Path,
        );
    }

    fn add_alias(&mut self, index: usize, row: Alias) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            &format!("alias {index} kind"),
            &row.kind,
            &["symlink", "firmlink", "mount_alias", "same_object"],
            &mut problems,
        );
        if !is_rfc3339_shape(&row.verified_at) {
            problems.push(format!(
                "alias {index} verified_at {:?} is not RFC 3339",
                short_id(&row.verified_at)
            ));
        }
        self.extend_problems(problems);
        self.resolve(format!("alias {index} path_id"), &row.path_id, IdKind::Path);
        self.resolve(
            format!("alias {index} target_path_id"),
            &row.target_path_id,
            IdKind::Path,
        );
    }

    fn add_candidate(&mut self, row: Candidate) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            &format!("candidate {} disposition", short_id(&row.id)),
            &row.disposition,
            &[
                "probe_pending",
                "probe_failed",
                "unsupported",
                "unresolvable_identity",
            ],
            &mut problems,
        );
        crate::report::validate::check_opt_time(
            &format!("candidate {} retry_after", short_id(&row.id)),
            &row.retry_after,
            &mut problems,
        );
        self.extend_problems(problems);
        self.resolve(
            format!("candidate {} path_id", short_id(&row.id)),
            &row.path_id,
            IdKind::Path,
        );
        self.resolve_opt(
            format!("candidate {} repository_id", short_id(&row.id)),
            &row.repository_id,
            IdKind::Repository,
        );
        self.resolve_errors(format!("candidate {}", short_id(&row.id)), &row.error_ids);
        if row.disposition == "unresolvable_identity" {
            self.unresolvable_candidates_seen += 1;
        }
    }

    fn add_error(&mut self, row: ErrorRecord) {
        self.errors_seen += 1;
        let mut problems = Vec::new();
        if !is_rfc3339_shape(&row.first_seen) {
            problems.push(format!(
                "error {} first_seen {:?} is not RFC 3339",
                short_id(&row.id),
                short_id(&row.first_seen)
            ));
        }
        if !is_rfc3339_shape(&row.last_seen) {
            problems.push(format!(
                "error {} last_seen {:?} is not RFC 3339",
                short_id(&row.id),
                short_id(&row.last_seen)
            ));
        }
        crate::report::validate::check_opt_time(
            &format!("error {} next_retry", short_id(&row.id)),
            &row.next_retry,
            &mut problems,
        );
        self.extend_problems(problems);
        self.resolve_opt(
            format!("error {} path_id", short_id(&row.id)),
            &row.path_id,
            IdKind::Path,
        );
    }

    fn add_artifact(&mut self, index: usize, row: GeneratedArtifact) {
        let mut problems = Vec::new();
        crate::report::validate::check_enum(
            &format!("generated_artifact {index} kind"),
            &row.kind,
            &["report", "tool_state"],
            &mut problems,
        );
        self.extend_problems(problems);
        self.resolve(
            format!("generated_artifact {index} path_id"),
            &row.path_id,
            IdKind::Path,
        );
    }

    fn finish(mut self) -> crate::Result<String> {
        if self.coverage_gaps != self.errors_seen {
            self.problem(format!(
                "coverage.gaps is {}, but {} error records were emitted",
                self.coverage_gaps, self.errors_seen
            ));
        }
        if self.coverage_unresolvable_candidates != self.unresolvable_candidates_seen {
            self.problem(format!(
                "coverage.unresolvable_candidates is {}, but {} unresolvable candidates were emitted",
                self.coverage_unresolvable_candidates, self.unresolvable_candidates_seen
            ));
        }
        if self.coverage_filesystem_complete {
            if self.coverage_tasks_pending != 0 {
                self.problem(format!(
                    "coverage.filesystem is complete but tasks_pending is {}",
                    self.coverage_tasks_pending
                ));
            }
            if self.coverage_gaps != 0 {
                self.problem(format!(
                    "coverage.filesystem is complete but gaps is {}",
                    self.coverage_gaps
                ));
            }
        }
        if self.coverage_status_complete {
            if let Some((id, count)) = &self.checkout_status_gap {
                self.problem(format!(
                    "coverage.status is complete but checkout {id} status is not complete ({count} checkout(s))"
                ));
            }
        }
        if self.coverage_identity_complete {
            if self.coverage_unresolvable_candidates != 0 {
                self.problem(format!(
                    "coverage.identity is complete_under_policy but unresolvable_candidates is {}",
                    self.coverage_unresolvable_candidates
                ));
            }
            if let Some((id, count)) = &self.unresolvable_repository {
                self.problem(format!(
                    "coverage.identity is complete_under_policy but repository {id} is unresolvable_identity ({count} repository(s))"
                ));
            }
        }
        if self.scan_complete && self.coverage_status_incomplete {
            self.problem(format!(
                "scan.state is complete but coverage.status is incomplete (status was requested with mode {:?})",
                self.scan_status_mode
            ));
        }
        if self.coverage_status_not_requested && !self.scan_status_mode_metadata {
            self.problem(format!(
                "coverage.status is not_requested but scan.status_mode is {:?}",
                self.scan_status_mode
            ));
        }

        if self.problems.is_empty() {
            Ok(self.report_id)
        } else {
            if self.problems.len() == MAX_PROBLEMS {
                self.problems
                    .push("additional validation errors omitted".to_string());
            }
            Err(crate::Error::Report(format!(
                "report invalid: {}",
                self.problems.join("; ")
            )))
        }
    }
}

fn check_name(context: &str, name: &crate::report::model::EncodedName, problems: &mut Vec<String>) {
    crate::report::validate::check_encoding(
        context,
        &name.encoding,
        &name.value,
        &name.display,
        problems,
    );
}

fn short_id(value: &str) -> &str {
    const MAX_BYTES: usize = 128;
    let mut end = value.len().min(MAX_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

struct ValidationSeed<'a, 'de> {
    state: &'a mut StreamState<'de>,
    pass: Pass,
}

impl<'de> DeserializeSeed<'de> for ValidationSeed<'_, 'de> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ValidationVisitor {
            state: self.state,
            pass: self.pass,
        })
    }
}

struct ValidationVisitor<'a, 'de> {
    state: &'a mut StreamState<'de>,
    pass: Pass,
}

impl<'de> Visitor<'de> for ValidationVisitor<'_, 'de> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a repo-scan report object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = 0u32;
        macro_rules! rows {
            ($row:ty, $callback:expr) => {{
                let mut callback = $callback;
                visit_rows::<$row, _, _>(&mut map, &mut callback)?;
            }};
        }
        macro_rules! ids {
            ($kind:expr, $label:literal) => {{
                let state = &mut *self.state;
                rows!(IdOnly<'de>, |row: IdOnly<'de>| state
                    .add_id($kind, row.id, $label));
            }};
        }
        while let Some(key) = map.next_key_seed(RootFieldSeed)? {
            if let Some(index) = key.index() {
                let mask = 1u32 << index;
                if seen & mask != 0 {
                    return Err(de::Error::duplicate_field(ROOT_FIELD_NAMES[index]));
                }
                seen |= mask;
            }
            match key {
                RootField::SchemaVersion if self.pass == Pass::Validate => {
                    let value: String = map.next_value()?;
                    self.state.add_schema_version(value);
                }
                RootField::ReportId if self.pass == Pass::Validate => {
                    let value: String = map.next_value()?;
                    self.state.add_report_id(value);
                }
                RootField::CreatedAt if self.pass == Pass::Validate => {
                    let value: String = map.next_value()?;
                    self.state.add_created_at(value);
                }
                RootField::Tool if self.pass == Pass::Validate => {
                    let value: Tool = map.next_value()?;
                    self.state.add_tool(value);
                }
                RootField::Scan if self.pass == Pass::Validate => {
                    let value: Scan = map.next_value()?;
                    self.state.add_scan(value);
                }
                RootField::Coverage if self.pass == Pass::Validate => {
                    let value: Coverage = map.next_value()?;
                    self.state.add_coverage(value);
                }
                RootField::Resources if self.pass == Pass::Validate => {
                    let value: Resources = map.next_value()?;
                    self.state.add_resources(value);
                }
                RootField::Volumes => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Volume, "volume"),
                    Pass::Validate => {
                        let state = &mut *self.state;
                        rows!(Volume, |row| state.add_volume(row));
                    }
                },
                RootField::Paths => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Path, "path"),
                    Pass::Validate => {
                        let state = &mut *self.state;
                        rows!(PathRecord, |row| state.add_path(row));
                    }
                },
                RootField::Roots => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Root, "root"),
                    Pass::Validate => {
                        let state = &mut *self.state;
                        rows!(Root, |row| state.add_root(row));
                    }
                },
                RootField::Repositories => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Repository, "repository"),
                    Pass::Validate => {
                        let state = &mut *self.state;
                        rows!(Repository, |row| state.add_repository(row));
                    }
                },
                RootField::Checkouts => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Checkout, "checkout"),
                    Pass::Validate => {
                        let state = &mut *self.state;
                        rows!(Checkout, |row| state.add_checkout(row));
                    }
                },
                RootField::Branches => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Branch, "branch"),
                    Pass::Validate => {
                        let state = &mut *self.state;
                        rows!(Branch, |row| state.add_branch(row));
                    }
                },
                RootField::Remotes => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Remote, "remote"),
                    Pass::Validate => {
                        let state = &mut *self.state;
                        rows!(Remote, |row| state.add_remote(row));
                    }
                },
                RootField::StorageLinks => match self.pass {
                    Pass::CollectIds => ids!(IdKind::StorageLink, "storage_link"),
                    Pass::Validate => {
                        let state = &mut *self.state;
                        rows!(StorageLink, |row| state.add_storage_link(row));
                    }
                },
                RootField::Aliases if self.pass == Pass::Validate => {
                    let state = &mut *self.state;
                    let mut index = state.aliases_seen;
                    rows!(Alias, |row| {
                        state.add_alias(index, row);
                        index += 1;
                    });
                    state.aliases_seen = index;
                }
                RootField::Aliases => rows!(IgnoredAny, |_| {}),
                RootField::Candidates => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Candidate, "candidate"),
                    Pass::Validate => {
                        let state = &mut *self.state;
                        rows!(Candidate, |row| state.add_candidate(row));
                    }
                },
                RootField::Errors => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Error, "error"),
                    Pass::Validate => {
                        let state = &mut *self.state;
                        rows!(ErrorRecord, |row| state.add_error(row));
                    }
                },
                RootField::GeneratedArtifacts if self.pass == Pass::Validate => {
                    let state = &mut *self.state;
                    let mut index = state.artifacts_seen;
                    rows!(GeneratedArtifact, |row| {
                        state.add_artifact(index, row);
                        index += 1;
                    });
                    state.artifacts_seen = index;
                }
                RootField::GeneratedArtifacts => rows!(IgnoredAny, |_| {}),
                RootField::SchemaVersion
                | RootField::ReportId
                | RootField::CreatedAt
                | RootField::Tool
                | RootField::Scan
                | RootField::Coverage
                | RootField::Resources => {
                    let _: IgnoredAny = map.next_value()?;
                }
                RootField::Unknown => {
                    return Err(de::Error::custom("unknown report field"));
                }
            }
        }
        if seen != ROOT_FIELDS {
            for (index, field) in ROOT_FIELD_NAMES.iter().enumerate() {
                if seen & (1u32 << index) == 0 {
                    return Err(de::Error::missing_field(field));
                }
            }
        }
        Ok(())
    }
}

fn visit_rows<'de, T, A, F>(map: &mut A, on_row: &mut F) -> Result<(), A::Error>
where
    T: Deserialize<'de>,
    A: MapAccess<'de>,
    F: FnMut(T),
{
    map.next_value_seed(RowsSeed::<T, F> {
        on_row,
        marker: PhantomData,
    })
}

fn remember_first(slot: &mut Option<(String, u64)>, id: String) {
    if let Some((_, count)) = slot {
        *count += 1;
    } else {
        *slot = Some((id, 1));
    }
}

struct RowsSeed<'a, T, F> {
    on_row: &'a mut F,
    marker: PhantomData<T>,
}

impl<'a, 'de, T, F> DeserializeSeed<'de> for RowsSeed<'a, T, F>
where
    T: Deserialize<'de>,
    F: FnMut(T),
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(RowsVisitor::<T, F> {
            on_row: self.on_row,
            marker: PhantomData,
        })
    }
}

struct RowsVisitor<'a, T, F> {
    on_row: &'a mut F,
    marker: PhantomData<T>,
}

impl<'de, T, F> Visitor<'de> for RowsVisitor<'_, T, F>
where
    T: Deserialize<'de>,
    F: FnMut(T),
{
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of report records")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(row) = seq.next_element::<T>()? {
            (self.on_row)(row);
        }
        Ok(())
    }
}

const ROOT_FIELD_NAMES: &[&str] = &[
    "schema_version",
    "report_id",
    "created_at",
    "tool",
    "scan",
    "coverage",
    "resources",
    "volumes",
    "paths",
    "roots",
    "repositories",
    "checkouts",
    "branches",
    "remotes",
    "storage_links",
    "aliases",
    "candidates",
    "errors",
    "generated_artifacts",
];

#[derive(Copy, Clone)]
enum RootField {
    SchemaVersion,
    ReportId,
    CreatedAt,
    Tool,
    Scan,
    Coverage,
    Resources,
    Volumes,
    Paths,
    Roots,
    Repositories,
    Checkouts,
    Branches,
    Remotes,
    StorageLinks,
    Aliases,
    Candidates,
    Errors,
    GeneratedArtifacts,
    Unknown,
}

impl RootField {
    fn from_name(name: &str) -> Self {
        match name {
            "schema_version" => Self::SchemaVersion,
            "report_id" => Self::ReportId,
            "created_at" => Self::CreatedAt,
            "tool" => Self::Tool,
            "scan" => Self::Scan,
            "coverage" => Self::Coverage,
            "resources" => Self::Resources,
            "volumes" => Self::Volumes,
            "paths" => Self::Paths,
            "roots" => Self::Roots,
            "repositories" => Self::Repositories,
            "checkouts" => Self::Checkouts,
            "branches" => Self::Branches,
            "remotes" => Self::Remotes,
            "storage_links" => Self::StorageLinks,
            "aliases" => Self::Aliases,
            "candidates" => Self::Candidates,
            "errors" => Self::Errors,
            "generated_artifacts" => Self::GeneratedArtifacts,
            _ => Self::Unknown,
        }
    }

    fn index(self) -> Option<usize> {
        match self {
            Self::SchemaVersion => Some(0),
            Self::ReportId => Some(1),
            Self::CreatedAt => Some(2),
            Self::Tool => Some(3),
            Self::Scan => Some(4),
            Self::Coverage => Some(5),
            Self::Resources => Some(6),
            Self::Volumes => Some(7),
            Self::Paths => Some(8),
            Self::Roots => Some(9),
            Self::Repositories => Some(10),
            Self::Checkouts => Some(11),
            Self::Branches => Some(12),
            Self::Remotes => Some(13),
            Self::StorageLinks => Some(14),
            Self::Aliases => Some(15),
            Self::Candidates => Some(16),
            Self::Errors => Some(17),
            Self::GeneratedArtifacts => Some(18),
            Self::Unknown => None,
        }
    }
}

struct RootFieldSeed;

impl<'de> DeserializeSeed<'de> for RootFieldSeed {
    type Value = RootField;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(RootFieldVisitor)
    }
}

struct RootFieldVisitor;

impl<'de> Visitor<'de> for RootFieldVisitor {
    type Value = RootField;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a repo-scan report field name")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(RootField::from_name(value))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(RootField::from_name(value))
    }
}

/// Validate staged report bytes without building a whole [`Report`]. The
/// caller applies the memory gate before invoking this two-pass parser.
pub(super) fn measure_report_streamed(bytes: &[u8]) -> crate::Result<(u64, u64, u64, u64)> {
    let mut metrics = StreamMetrics::default();
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    MeasureSeed {
        metrics: &mut metrics,
        capture_id: false,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| staged_json_error(&error))?;
    deserializer
        .end()
        .map_err(|error| staged_json_error(&error))?;
    Ok((
        metrics.array_items,
        metrics.owned_id_bytes,
        metrics.max_string_bytes,
        metrics.max_debug_string_bytes,
    ))
}

/// Validate staged report bytes without building a whole [`Report`]. The
/// caller applies the memory gate before invoking this two-pass parser.
pub(super) fn validate_report_streamed(bytes: &[u8]) -> crate::Result<String> {
    let mut state = StreamState::default();
    let mut ids_pass = serde_json::Deserializer::from_slice(bytes);
    ValidationSeed {
        state: &mut state,
        pass: Pass::CollectIds,
    }
    .deserialize(&mut ids_pass)
    .map_err(|error| staged_json_error(&error))?;
    ids_pass.end().map_err(|error| staged_json_error(&error))?;
    drop(ids_pass);

    let mut validate_pass = serde_json::Deserializer::from_slice(bytes);
    ValidationSeed {
        state: &mut state,
        pass: Pass::Validate,
    }
    .deserialize(&mut validate_pass)
    .map_err(|error| staged_json_error(&error))?;
    validate_pass
        .end()
        .map_err(|error| staged_json_error(&error))?;
    state.finish()
}

/// Return bounded parser context without formatting serde's potentially
/// input-sized diagnostic string. Category and location are sufficient to
/// locate malformed or schema-mismatched staged data without echoing it.
pub(super) fn staged_json_error(error: &serde_json::Error) -> crate::Error {
    let category = match error.classify() {
        serde_json::error::Category::Io => "input",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "schema",
        serde_json::error::Category::Eof => "unexpected end",
    };
    crate::Error::Report(format!(
        "staged report JSON {category} error at line {}, column {}",
        error.line(),
        error.column()
    ))
}

#[cfg(test)]
mod tests {
    use super::measure_report_streamed;

    #[test]
    fn memory_probe_counts_nested_arrays_and_escaped_ids() {
        let bytes = br#"{"volumes":[{"id":"path\u002d1","error_ids":["err-1",["nested"]]}],"key\u002dlongest":"value\u002dlonger"}"#;
        let metrics = measure_report_streamed(bytes).expect("metrics");
        assert_eq!((metrics.0, metrics.1, metrics.2), (4, 6, 12));
    }

    #[test]
    fn memory_probe_counts_debug_escaped_string_length() {
        let bytes = br#"{"value":"\u202e"}"#;
        let metrics = measure_report_streamed(bytes).expect("metrics");
        assert_eq!(metrics.3, format!("{:?}", "\u{202e}").len() as u64);
    }
}

#[derive(Default)]
struct StreamMetrics {
    array_items: u64,
    owned_id_bytes: u64,
    max_string_bytes: u64,
    max_debug_string_bytes: u64,
}

#[derive(Default)]
struct FormatLength {
    bytes: u64,
}

impl fmt::Write for FormatLength {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.bytes = self.bytes.saturating_add(value.len() as u64);
        Ok(())
    }
}

fn record_string_metrics(metrics: &mut StreamMetrics, value: &str) {
    metrics.max_string_bytes = metrics.max_string_bytes.max(value.len() as u64);
    let mut debug_len = FormatLength::default();
    let _ = fmt::Write::write_fmt(&mut debug_len, format_args!("{value:?}"));
    metrics.max_debug_string_bytes = metrics.max_debug_string_bytes.max(debug_len.bytes);
}

struct MeasureSeed<'a> {
    metrics: &'a mut StreamMetrics,
    capture_id: bool,
}

struct MeasureKeySeed<'a> {
    metrics: &'a mut StreamMetrics,
}

impl<'de> DeserializeSeed<'de> for MeasureKeySeed<'_> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(MeasureKeyVisitor {
            metrics: self.metrics,
        })
    }
}

struct MeasureKeyVisitor<'a> {
    metrics: &'a mut StreamMetrics,
}

impl<'de> Visitor<'de> for MeasureKeyVisitor<'_> {
    type Value = bool;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object key")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        record_string_metrics(self.metrics, value);
        Ok(value == "id")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        record_string_metrics(self.metrics, value);
        Ok(value == "id")
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        record_string_metrics(self.metrics, &value);
        Ok(value == "id")
    }
}

impl<'de> DeserializeSeed<'de> for MeasureSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(MeasureVisitor {
            metrics: self.metrics,
            capture_id: self.capture_id,
        })
    }
}

struct MeasureVisitor<'a> {
    metrics: &'a mut StreamMetrics,
    capture_id: bool,
}

impl<'de> Visitor<'de> for MeasureVisitor<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        record_string_metrics(self.metrics, value);
        if self.capture_id {
            self.metrics.owned_id_bytes = self
                .metrics
                .owned_id_bytes
                .saturating_add(value.len() as u64);
        }
        Ok(())
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        record_string_metrics(self.metrics, value);
        Ok(())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        record_string_metrics(self.metrics, &value);
        if self.capture_id {
            self.metrics.owned_id_bytes = self
                .metrics
                .owned_id_bytes
                .saturating_add(value.len() as u64);
        }
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq
            .next_element_seed(MeasureSeed {
                metrics: &mut *self.metrics,
                capture_id: false,
            })?
            .is_some()
        {
            self.metrics.array_items = self.metrics.array_items.saturating_add(1);
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(capture_id) = map.next_key_seed(MeasureKeySeed {
            metrics: &mut *self.metrics,
        })? {
            map.next_value_seed(MeasureSeed {
                metrics: &mut *self.metrics,
                capture_id,
            })?;
        }
        Ok(())
    }
}
