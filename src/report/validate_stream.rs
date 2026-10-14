//! Bounded-memory validation for staged reports that need only a pass/fail
//! result. Records are decoded one at a time; the first pass retains only
//! borrowed IDs, and the second checks each record against those exact IDs.
//!
//! Multi-version acceptance (contract C4): envelopes 1.0.0–1.5.0
//! ([`crate::report::model::SUPPORTED_PRIOR_SCHEMA_VERSIONS`]) validate;
//! fields added after a report's version carry serde defaults that read
//! honestly (`unknown`/`pending`/null). Report 1.5.0 is version-gated:
//! `groups`/`totals` must be present, branch freshness/comparison fields,
//! `remote.refresh`, and `checkout.status` `conflicts`/`working_state` are
//! required keys, and the declared totals are recomputed from the emitted
//! records. Per-field byte caps (envelope scalars, the 4 MiB header, 1 MiB
//! per record) and the 24 MiB fail-closed ID/account-key bounds keep a
//! hostile staged file inside the caller's RSS budget. Diagnostics never
//! echo raw report bytes: values are truncated to 128 bytes
//! ([`short_id`]) and the problem list is capped at [`MAX_PROBLEMS`].

use crate::report::encode::{is_rfc3339_shape, object_id_error};
use crate::report::model::{
    Alias, AnalysisTotals, Branch, Candidate, Checkout, Coverage, ErrorRecord, GeneratedArtifact,
    Group, PathRecord, Remote, Repository, Resources, Root, Scan, StorageLink, Tool, Totals,
    Volume,
};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::marker::PhantomData;

const MAX_PROBLEMS: usize = 256;
/// Base root fields required of every accepted envelope version.
const BASE_ROOT_FIELDS: u32 = (1 << 19) - 1;
/// Full 1.5.0 root-field mask: the base fields plus `groups` + `totals`.
const ROOT_FIELDS: u32 = (1 << 21) - 1;
/// Field index of `groups` (version-gated: required at 1.5.0 only).
const GROUPS_FIELD: u32 = 1 << 19;
/// Field index of `totals` (version-gated: required at 1.5.0 only).
const TOTALS_FIELD: u32 = 1 << 20;

/// Maximum decoded bytes in any one streamed record. Report writers cap
/// path/evidence fields below this limit; this guard keeps a hostile single
/// record from becoming a large transient allocation during validation.
const MAX_STREAMED_RECORD_BYTES: usize = 1024 * 1024;
/// Maximum copied bytes retained in record-ID indexes during streaming
/// (fail-closed: the report is refused once aggregate ID bytes pass it).
const MAX_STREAMED_ID_BYTES: usize = 24 * 1024 * 1024;
/// Maximum copied bytes retained for unique `(host, account)` keys.
const MAX_STREAMED_ACCOUNT_KEY_BYTES: usize = 24 * 1024 * 1024;
/// Maximum aggregate JSON bytes across the report envelope metadata
/// (`tool`, `scan`, `coverage`, `resources`).
const MAX_STREAMED_HEADER_BYTES: usize = 4 * 1024 * 1024;
/// Per-field byte caps for the envelope scalars.
const MAX_REPORT_ID_BYTES: usize = 4096;
const MAX_SCHEMA_VERSION_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 128;

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
    Group,
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
    groups: HashSet<Cow<'a, str>>,
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
            IdKind::Group => self.groups.contains(id),
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
            IdKind::Group => self.groups.insert(id),
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
    /// Raw schema_version captured during the ID pass; drives the
    /// version-gated checks of the validate pass.
    schema_version: String,
    report_id: String,
    /// Aggregate bytes of the `tool`/`scan`/`coverage`/`resources`
    /// envelope metadata seen in the validate pass.
    header_bytes: usize,
    /// Aggregate retained ID bytes (fail-closed at [`MAX_STREAMED_ID_BYTES`]).
    id_bytes: usize,
    ids_overflow: bool,
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
    // Totals recomputation (report 1.5.0): every counter is derived from
    // the emitted records in the validate pass and compared against the
    // declared `totals` block at finish.
    declared_totals: Option<Totals>,
    groups_seen: u64,
    account_keys: HashSet<(String, String)>,
    account_key_bytes: usize,
    account_keys_overflow: bool,
    stores_seen: u64,
    bare_stores: Option<u64>,
    present_checkouts: u64,
    linked_worktrees: u64,
    paths_seen: u64,
    local_branches: u64,
    remote_tracking_refs: u64,
    analysis: AnalysisTotals,
}

impl<'a> StreamState<'a> {
    /// True when the envelope claims report 1.5.0 exactly; the 1.5.0
    /// required-field and totals rules apply only then.
    fn version_is_15(&self) -> bool {
        self.schema_version == crate::report::model::SCHEMA_VERSION
    }

    /// Root fields required for this envelope version: the base set, plus
    /// `groups`/`totals` at 1.5.0.
    fn required_root_fields(&self) -> u32 {
        if self.version_is_15() {
            ROOT_FIELDS
        } else {
            BASE_ROOT_FIELDS
        }
    }

    fn add_schema_version(&mut self, value: String, validate: bool) {
        self.schema_version = value;
        if validate {
            if self.schema_version.len() > MAX_SCHEMA_VERSION_BYTES {
                self.problem(format!(
                    "schema_version exceeds the {MAX_SCHEMA_VERSION_BYTES}-byte streaming limit"
                ));
            }
            if !crate::report::model::SUPPORTED_PRIOR_SCHEMA_VERSIONS
                .contains(&self.schema_version.as_str())
            {
                self.problem(format!(
                    "schema_version is {:?}, want one of {:?}",
                    short_id(&self.schema_version),
                    crate::report::model::SUPPORTED_PRIOR_SCHEMA_VERSIONS
                ));
            }
        }
    }

    fn add_report_id(&mut self, value: String) {
        if value.is_empty() {
            self.problem("report_id must be nonempty");
        }
        if value.len() > MAX_REPORT_ID_BYTES {
            // ADJ-05: state the cap, never the value.
            self.problem(format!(
                "report_id exceeds the {MAX_REPORT_ID_BYTES}-byte streaming limit"
            ));
        }
        self.report_id = value;
    }

    fn add_created_at(&mut self, value: String) {
        if value.len() > MAX_TIMESTAMP_BYTES {
            self.problem(format!(
                "created_at exceeds the {MAX_TIMESTAMP_BYTES}-byte streaming limit"
            ));
        }
        if !is_rfc3339_shape(&value) {
            self.problem(format!("created_at {:?} is not RFC 3339", short_id(&value)));
        }
    }

    /// Decode one envelope metadata field from its raw JSON with the
    /// aggregate 4 MiB header cap, then run the semantic check. Parse
    /// failures are bounded problems (line/column only, no input echo).
    fn add_header<T, F>(&mut self, raw: &RawValue, what: &'static str, check: F)
    where
        T: serde::de::DeserializeOwned,
        F: FnOnce(&mut Self, T),
    {
        self.header_bytes = self.header_bytes.saturating_add(raw.get().len());
        if self.header_bytes > MAX_STREAMED_HEADER_BYTES {
            self.problem(format!(
                "report envelope metadata exceeds the {MAX_STREAMED_HEADER_BYTES}-byte streaming limit"
            ));
            return;
        }
        match serde_json::from_str::<T>(raw.get()) {
            Ok(value) => check(self, value),
            Err(error) => self.problem(format!(
                "report {what} is invalid: {}",
                json_error_location(&error)
            )),
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

    fn add_totals(&mut self, value: Totals) {
        self.declared_totals = Some(value);
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
        // 24 MiB fail-closed ID bound: refuse to retain more ID bytes
        // rather than letting a hostile staged file grow the index
        // without limit. The report fails validation either way.
        let next = self.id_bytes.saturating_add(id.len());
        if next > MAX_STREAMED_ID_BYTES {
            if !self.ids_overflow {
                self.ids_overflow = true;
                self.problem(format!(
                    "streamed report ID bytes exceed the {MAX_STREAMED_ID_BYTES}-byte bound"
                ));
            }
            return;
        }
        self.id_bytes = next;
        if !self.ids.insert(kind, id) {
            self.problem(format!("duplicate {label} id"));
        }
    }

    fn register_account(&mut self, host: &str, account: &str) {
        let key = (host.to_string(), account.to_string());
        if self.account_keys.contains(&key) {
            return;
        }
        let next = self
            .account_key_bytes
            .saturating_add(host.len())
            .saturating_add(account.len());
        if next > MAX_STREAMED_ACCOUNT_KEY_BYTES {
            if !self.account_keys_overflow {
                self.account_keys_overflow = true;
                self.problem(format!(
                    "streamed report account-key bytes exceed the {MAX_STREAMED_ACCOUNT_KEY_BYTES}-byte bound"
                ));
            }
            return;
        }
        self.account_key_bytes = next;
        self.account_keys.insert(key);
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
        self.paths_seen = self.paths_seen.saturating_add(1);
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

    fn add_group(&mut self, row: Group) {
        let mut problems = Vec::new();
        crate::report::validate::check_group(&row, &mut problems);
        self.extend_problems(problems);
        self.register_account(&row.host, &row.account);
        self.groups_seen = self.groups_seen.saturating_add(1);
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
        self.stores_seen = self.stores_seen.saturating_add(1);
        match row.bare {
            Some(true) => {
                if let Some(count) = self.bare_stores.as_mut() {
                    *count += 1;
                }
            }
            Some(false) => {}
            None => self.bare_stores = None,
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
        if row.availability == "present" {
            self.present_checkouts += 1;
            if row.kind == "linked" {
                self.linked_worktrees += 1;
            }
        }
        match row.status.state.as_str() {
            "complete" => self.analysis.completed += 1,
            "pending" | "not_requested" => self.analysis.pending += 1,
            "unsupported" => self.analysis.unavailable += 1,
            "partial" | "unstable" | "error" => self.analysis.failed += 1,
            _ => self.analysis.pending += 1,
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
        crate::report::validate::check_branch_freshness_comparison(&row, &mut problems);
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
        match row.kind.as_str() {
            "local" => self.local_branches += 1,
            "remote_tracking" => self.remote_tracking_refs += 1,
            _ => {}
        }
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
        crate::report::validate::check_remote_refresh(&row, &mut problems);
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

    /// The totals recomputed from the records seen in the validate pass.
    fn recomputed_totals(&self) -> Totals {
        Totals {
            accounts: self.account_keys.len() as u64,
            groups: self.groups_seen,
            stores: self.stores_seen,
            bare_stores: self.bare_stores,
            present_checkouts: self.present_checkouts,
            linked_worktrees: self.linked_worktrees,
            observed_paths: self.paths_seen,
            aliases: self.aliases_seen as u64,
            local_branches: self.local_branches,
            remote_tracking_refs: self.remote_tracking_refs,
            analysis: self.analysis.clone(),
            unresolved_candidates: self.unresolvable_candidates_seen,
            gaps: self.errors_seen,
        }
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
        if self.version_is_15() {
            // Totals recomputation (report 1.5.0): the declared block must
            // equal the counts derived from the emitted records.
            let recomputed = self.recomputed_totals();
            if self.declared_totals.as_ref() != Some(&recomputed) {
                self.problem("totals do not agree with report records".to_string());
            }
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

/// Bounded parse-failure location: line/column only, never serde's
/// potentially input-sized diagnostic text.
fn json_error_location(error: &serde_json::Error) -> String {
    format!(
        "invalid JSON at line {}, column {}",
        error.line(),
        error.column()
    )
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

/// Required-key check over one raw record without building a value tree
/// (report 1.5.0 version gate): values are skipped as `IgnoredAny`, except
/// an explicitly selected nested object (`checkout.status`), which is
/// checked in place. Keeps the shape check within the one-record bound.
fn check_required_object_fields(
    json: &str,
    context: &'static str,
    required: &'static [&'static str],
) -> Result<(), String> {
    check_required_object_fields_nested(json, context, required, None)
}

fn check_required_object_fields_nested(
    json: &str,
    context: &'static str,
    required: &'static [&'static str],
    nested: Option<(&'static str, &'static str, &'static [&'static str])>,
) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    RequiredFieldsSeed {
        context,
        required,
        nested,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| format!("{context} has invalid required-field shape: {error}"))?;
    deserializer.end().map_err(|error| {
        format!(
            "{context} has trailing JSON data: {}",
            json_error_location(&error)
        )
    })
}

struct RequiredFieldsSeed {
    context: &'static str,
    required: &'static [&'static str],
    nested: Option<(&'static str, &'static str, &'static [&'static str])>,
}

impl<'de> DeserializeSeed<'de> for RequiredFieldsSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(RequiredFieldsVisitor {
            context: self.context,
            required: self.required,
            nested: self.nested,
        })
    }
}

struct RequiredFieldsVisitor {
    context: &'static str,
    required: &'static [&'static str],
    nested: Option<(&'static str, &'static str, &'static [&'static str])>,
}

impl<'de> Visitor<'de> for RequiredFieldsVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object with required report fields")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.required.len() > u64::BITS as usize {
            return Err(de::Error::custom(
                "required-field checker supports at most 64 fields",
            ));
        }

        let mut found = 0u64;
        while let Some(key) = map.next_key::<&str>()? {
            if let Some(index) = self.required.iter().position(|required| *required == key) {
                found |= 1u64 << index;
            }
            if let Some((parent_key, nested_context, nested_required)) = self.nested {
                if key == parent_key {
                    let nested: &'de RawValue = map.next_value()?;
                    check_required_object_fields(nested.get(), nested_context, nested_required)
                        .map_err(de::Error::custom)?;
                    continue;
                }
            }
            let _: IgnoredAny = map.next_value()?;
        }

        for (index, required) in self.required.iter().enumerate() {
            if found & (1u64 << index) == 0 {
                return Err(de::Error::custom(format!(
                    "{} is missing required field {:?}",
                    self.context, required
                )));
            }
        }
        Ok(())
    }
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
        /// Validate-pass row decoding through the raw record text: the
        /// 1 MiB per-record cap is enforced before the typed decode, the
        /// 1.5.0 required-key gate runs on the raw keys, and typed parse
        /// failures become bounded problems instead of aborting the pass.
        /// The callback receives the state explicitly so it never captures
        /// the visitor's state reference.
        macro_rules! raw_rows {
            ($row:ty, $required:expr, $callback:expr) => {{
                #[allow(unused_mut)]
                let mut callback = $callback;
                let required: Option<RawRequired> = $required;
                let gated = self.state.version_is_15();
                let visitor_state = &mut *self.state;
                visit_raw_rows(&mut map, &mut |raw: &RawValue| {
                    if raw.get().len() > MAX_STREAMED_RECORD_BYTES {
                        visitor_state.problem(format!(
                            "record is {} bytes, over the {MAX_STREAMED_RECORD_BYTES}-byte streaming limit",
                            raw.get().len()
                        ));
                        return;
                    }
                    if gated {
                        if let Some(required) = required {
                            if let Err(problem) = (required.check)(raw.get()) {
                                visitor_state.problem(problem);
                            }
                        }
                    }
                    match serde_json::from_str::<$row>(raw.get()) {
                        Ok(row) => callback(&mut *visitor_state, row),
                        Err(error) => visitor_state.problem(format!(
                            "report record is invalid: {}",
                            json_error_location(&error)
                        )),
                    }
                })?;
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
                RootField::SchemaVersion => {
                    let value: String = map.next_value()?;
                    self.state
                        .add_schema_version(value, self.pass == Pass::Validate);
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
                    let raw: &RawValue = map.next_value()?;
                    self.state.add_header(raw, "tool", StreamState::add_tool);
                }
                RootField::Scan if self.pass == Pass::Validate => {
                    let raw: &RawValue = map.next_value()?;
                    self.state.add_header(raw, "scan", StreamState::add_scan);
                }
                RootField::Coverage if self.pass == Pass::Validate => {
                    let raw: &RawValue = map.next_value()?;
                    self.state
                        .add_header(raw, "coverage", StreamState::add_coverage);
                }
                RootField::Resources if self.pass == Pass::Validate => {
                    let raw: &RawValue = map.next_value()?;
                    self.state
                        .add_header(raw, "resources", StreamState::add_resources);
                }
                RootField::Volumes => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Volume, "volume"),
                    Pass::Validate => {
                        raw_rows!(Volume, None, |state: &mut StreamState<'_>, row| state
                            .add_volume(row));
                    }
                },
                RootField::Paths => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Path, "path"),
                    Pass::Validate => {
                        raw_rows!(PathRecord, None, |state: &mut StreamState<'_>, row| state
                            .add_path(row));
                    }
                },
                RootField::Roots => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Root, "root"),
                    Pass::Validate => {
                        raw_rows!(Root, None, |state: &mut StreamState<'_>, row| state
                            .add_root(row));
                    }
                },
                RootField::Groups => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Group, "group"),
                    Pass::Validate => {
                        raw_rows!(Group, None, |state: &mut StreamState<'_>, row| state
                            .add_group(row));
                    }
                },
                RootField::Repositories => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Repository, "repository"),
                    Pass::Validate => {
                        raw_rows!(Repository, None, |state: &mut StreamState<'_>, row| state
                            .add_repository(row));
                    }
                },
                RootField::Checkouts => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Checkout, "checkout"),
                    Pass::Validate => {
                        raw_rows!(
                            Checkout,
                            Some(RawRequired {
                                check: |json| {
                                    check_required_object_fields_nested(
                                        json,
                                        "checkout",
                                        &[],
                                        Some((
                                            "status",
                                            "checkout.status",
                                            &["conflicts", "working_state"],
                                        )),
                                    )
                                }
                            }),
                            |state: &mut StreamState<'_>, row| state.add_checkout(row)
                        );
                    }
                },
                RootField::Branches => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Branch, "branch"),
                    Pass::Validate => {
                        raw_rows!(
                            Branch,
                            Some(RawRequired {
                                check: |json| {
                                    check_required_object_fields(
                                        json,
                                        "branch",
                                        &[
                                            "freshness",
                                            "freshness_at",
                                            "comparison",
                                            "ahead",
                                            "behind",
                                        ],
                                    )
                                }
                            }),
                            |state: &mut StreamState<'_>, row| state.add_branch(row)
                        );
                    }
                },
                RootField::Remotes => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Remote, "remote"),
                    Pass::Validate => {
                        raw_rows!(
                            Remote,
                            Some(RawRequired {
                                check: |json| {
                                    check_required_object_fields(json, "remote", &["refresh"])
                                }
                            }),
                            |state: &mut StreamState<'_>, row| state.add_remote(row)
                        );
                    }
                },
                RootField::StorageLinks => match self.pass {
                    Pass::CollectIds => ids!(IdKind::StorageLink, "storage_link"),
                    Pass::Validate => {
                        raw_rows!(StorageLink, None, |state: &mut StreamState<'_>, row| state
                            .add_storage_link(row));
                    }
                },
                RootField::Aliases if self.pass == Pass::Validate => {
                    let mut index = self.state.aliases_seen;
                    raw_rows!(Alias, None, |state: &mut StreamState<'_>, row| {
                        state.add_alias(index, row);
                        index += 1;
                    });
                    self.state.aliases_seen = index;
                }
                RootField::Aliases => rows!(IgnoredAny, |_| {}),
                RootField::Candidates => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Candidate, "candidate"),
                    Pass::Validate => {
                        raw_rows!(Candidate, None, |state: &mut StreamState<'_>, row| state
                            .add_candidate(row));
                    }
                },
                RootField::Errors => match self.pass {
                    Pass::CollectIds => ids!(IdKind::Error, "error"),
                    Pass::Validate => {
                        raw_rows!(ErrorRecord, None, |state: &mut StreamState<'_>, row| state
                            .add_error(row));
                    }
                },
                RootField::GeneratedArtifacts if self.pass == Pass::Validate => {
                    let mut index = self.state.artifacts_seen;
                    raw_rows!(
                        GeneratedArtifact,
                        None,
                        |state: &mut StreamState<'_>, row| {
                            state.add_artifact(index, row);
                            index += 1;
                        }
                    );
                    self.state.artifacts_seen = index;
                }
                RootField::GeneratedArtifacts => rows!(IgnoredAny, |_| {}),
                RootField::Totals if self.pass == Pass::Validate => {
                    let raw: &RawValue = map.next_value()?;
                    if raw.get().len() > MAX_STREAMED_RECORD_BYTES {
                        self.state.problem(format!(
                            "totals is {} bytes, over the {MAX_STREAMED_RECORD_BYTES}-byte streaming limit",
                            raw.get().len()
                        ));
                    } else {
                        match serde_json::from_str::<Totals>(raw.get()) {
                            Ok(totals) => self.state.add_totals(totals),
                            Err(error) => self.state.problem(format!(
                                "report totals is invalid: {}",
                                json_error_location(&error)
                            )),
                        }
                    }
                }
                RootField::ReportId | RootField::CreatedAt => {
                    let _: IgnoredAny = map.next_value()?;
                }
                RootField::Tool
                | RootField::Scan
                | RootField::Coverage
                | RootField::Resources
                | RootField::Totals => {
                    let _: IgnoredAny = map.next_value()?;
                }
                RootField::Unknown => {
                    return Err(de::Error::custom("unknown report field"));
                }
            }
        }
        // Base root fields are always required (missing = malformed
        // envelope). The version-gated 1.5.0 additions are bounded
        // problems instead: their messages name the missing field without
        // aborting the pass, and they are recorded once (validate pass).
        if self.pass == Pass::Validate {
            let required = self.state.required_root_fields();
            let missing_gated = required & !seen & !BASE_ROOT_FIELDS;
            if missing_gated & GROUPS_FIELD != 0 {
                self.state.problem("groups is missing in report 1.5.0");
            }
            if missing_gated & TOTALS_FIELD != 0 {
                self.state.problem("totals is missing in report 1.5.0");
            }
        }
        if seen & BASE_ROOT_FIELDS != BASE_ROOT_FIELDS {
            for (index, field) in ROOT_FIELD_NAMES.iter().enumerate() {
                if (1u32 << index) & BASE_ROOT_FIELDS != 0 && seen & (1u32 << index) == 0 {
                    return Err(de::Error::missing_field(field));
                }
            }
        }
        Ok(())
    }
}

/// A version-gated required-key check over one raw record.
#[derive(Copy, Clone)]
struct RawRequired {
    check: fn(&str) -> Result<(), String>,
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

fn visit_raw_rows<'de, A, F>(map: &mut A, on_row: &mut F) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
    F: FnMut(&RawValue),
{
    map.next_value_seed(RawRowsSeed::<F> { on_row })
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

struct RawRowsSeed<'a, F> {
    on_row: &'a mut F,
}

impl<'de, F> DeserializeSeed<'de> for RawRowsSeed<'_, F>
where
    F: FnMut(&RawValue),
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(RawRowsVisitor {
            on_row: self.on_row,
        })
    }
}

struct RawRowsVisitor<'a, F> {
    on_row: &'a mut F,
}

impl<'de, F> Visitor<'de> for RawRowsVisitor<'_, F>
where
    F: FnMut(&RawValue),
{
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of report records")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(raw) = seq.next_element::<&RawValue>()? {
            (self.on_row)(raw);
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
    "groups",
    "totals",
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
    Groups,
    Totals,
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
            "groups" => Self::Groups,
            "totals" => Self::Totals,
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
            Self::Groups => Some(19),
            Self::Totals => Some(20),
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
    // `Some(0)`: bare stores are counted until the first unknown-bare
    // repository flips the total to `None` (unknown is never zero).
    let mut state = StreamState {
        bare_stores: Some(0),
        ..StreamState::default()
    };
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
            metrics: &mut *self.metrics,
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

// ---------------------------------------------------------------------------
// Report 1.5 streaming-validator rules (ported from B21 `validate.rs`
// `streaming_tests`, adapted to the non-echoing two-pass validator that is
// the single streaming truth here; the budget probes use the publication
// layer's gates, which callers apply before this parser runs).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod streaming_15_tests {
    use super::{measure_report_streamed, validate_report_streamed};
    use serde_json::Value;
    use std::io::Write;

    const FULL_REPORT_RECORDS: usize = 350_520;
    const VALIDATOR_BUDGET: u64 = 256 * 1024 * 1024;

    fn example_value() -> Value {
        serde_json::from_str(include_str!("../../tests/data/example-report.json"))
            .expect("example report")
    }

    fn streaming_error(value: &Value) -> String {
        let bytes = serde_json::to_vec(value).expect("serialize report");
        validate_report_streamed(&bytes)
            .expect_err("malformed report must be rejected")
            .to_string()
    }

    fn report_with_metadata_checkout() -> Value {
        let mut value = example_value();
        value["scan"]["status_mode"] = Value::String("metadata".to_string());
        value["coverage"]["status"] = Value::String("not_requested".to_string());
        value["totals"]["analysis"]["pending"] = Value::from(1u64);
        value["checkouts"]
            .as_array_mut()
            .expect("checkouts")
            .push(serde_json::json!({
                "id": "checkout-extra",
                "repository_id": "repo-fixture",
                "root_path_id": null,
                "git_path_id": "path-bare",
                "kind": "unknown",
                "availability": "unknown",
                "head": { "state": "unknown", "ref_name": null, "oid": null },
                "status": {
                    "state": "not_requested",
                    "mode": "metadata",
                    "started_at": null,
                    "finished_at": null,
                    "staged": null,
                    "unstaged": null,
                    "untracked": null,
                    "conflicts": null,
                    "working_state": "unknown",
                    "untracked_units": "not_requested",
                    "submodules": "not_requested",
                    "unknown_fields": [],
                    "error_ids": []
                },
                "observed_at": "2026-09-30T11:59:59Z",
                "error_ids": []
            }));
        value
    }

    #[test]
    fn v15_rejects_missing_serde_defaulted_required_fields() {
        let base = example_value();
        for field in ["freshness", "freshness_at", "comparison", "ahead", "behind"] {
            let mut value = base.clone();
            value["branches"][0]
                .as_object_mut()
                .expect("branch object")
                .remove(field);
            let error = streaming_error(&value);
            assert!(error.contains(field), "missing branch.{field}: {error}");
        }

        let mut value = base.clone();
        value["remotes"][0]
            .as_object_mut()
            .expect("remote object")
            .remove("refresh");
        let error = streaming_error(&value);
        assert!(error.contains("refresh"), "missing remote.refresh: {error}");

        let baseline = report_with_metadata_checkout();
        let bytes = serde_json::to_vec(&baseline).expect("serialize status report");
        validate_report_streamed(&bytes)
            .expect("metadata checkout fixture validates before field removal");

        for field in ["conflicts", "working_state"] {
            let mut value = report_with_metadata_checkout();
            value["checkouts"][0]["status"]
                .as_object_mut()
                .expect("status object")
                .remove(field);
            let error = streaming_error(&value);
            assert!(
                error.contains(field),
                "missing checkout.status.{field}: {error}"
            );
        }

        for field in ["groups", "totals"] {
            let mut value = base.clone();
            value.as_object_mut().expect("report object").remove(field);
            let error = streaming_error(&value);
            assert!(error.contains(field), "missing {field}: {error}");
        }
    }

    #[test]
    fn v15_rejects_unknown_nested_properties() {
        let mut value = example_value();
        value["totals"]["unexpected"] = Value::Bool(true);
        let _ = streaming_error(&value);

        let mut value = example_value();
        value["totals"]["analysis"]["unexpected"] = Value::Bool(true);
        let _ = streaming_error(&value);

        for section in ["tool", "scan", "coverage", "resources"] {
            let mut value = example_value();
            value[section]["unexpected"] = Value::Bool(true);
            let error = streaming_error(&value);
            assert!(error.contains(section), "{section} property: {error}");
        }

        let mut value = example_value();
        value["branches"][0]["name"]["unexpected"] = Value::Bool(true);
        let _ = streaming_error(&value);
    }

    #[test]
    fn v15_rejects_totals_that_disagree_with_records() {
        let mut value = example_value();
        value["totals"]["stores"] = Value::from(99u64);
        let error = streaming_error(&value);
        assert!(
            error.contains("totals do not agree"),
            "totals recomputation: {error}"
        );
    }

    #[test]
    fn legacy_13_reports_keep_defaulted_fields_compatible() {
        let mut value = example_value();
        value["schema_version"] = Value::String("1.3.0".to_string());
        let object = value.as_object_mut().expect("report object");
        object.remove("groups");
        object.remove("totals");
        for field in ["comparison", "ahead", "behind"] {
            value["branches"][0]
                .as_object_mut()
                .expect("branch object")
                .remove(field);
        }

        let bytes = serde_json::to_vec(&value).expect("serialize legacy report");
        validate_report_streamed(&bytes)
            .expect("supported 1.3 report may omit fields added in later schemas");
    }

    #[test]
    fn oldest_supported_envelope_validates() {
        let mut value = example_value();
        value["schema_version"] = Value::String("1.0.0".to_string());
        let object = value.as_object_mut().expect("report object");
        object.remove("groups");
        object.remove("totals");
        let scan = value["scan"].as_object_mut().expect("scan object");
        scan.remove("targets");
        for field in ["comparison", "ahead", "behind", "freshness", "freshness_at"] {
            value["branches"][0]
                .as_object_mut()
                .expect("branch object")
                .remove(field);
        }
        value["remotes"][0]
            .as_object_mut()
            .expect("remote object")
            .remove("refresh");
        for checkout in value["checkouts"]
            .as_array_mut()
            .expect("checkouts")
            .iter_mut()
        {
            let status = checkout["status"].as_object_mut().expect("status object");
            status.remove("conflicts");
            status.remove("working_state");
        }

        let bytes = serde_json::to_vec(&value).expect("serialize 1.0 report");
        validate_report_streamed(&bytes).expect("supported 1.0 report validates");
    }

    #[test]
    fn unsupported_envelope_version_is_rejected_without_echo() {
        let mut value = example_value();
        value["schema_version"] = Value::String("9.9.9".to_string());
        let error = streaming_error(&value);
        assert!(
            error.contains("schema_version"),
            "version is rejected: {error}"
        );
        // The rejected version may be named (128-byte short_id bound), but
        // the diagnostic stays bounded and never carries report content.
        assert!(error.len() < 4096, "diagnostic is bounded: {}", error.len());
    }

    #[test]
    fn streaming_validator_accepts_350k_records_under_the_fixed_budget() {
        let mut value = example_value();
        value["groups"] = Value::Array(Vec::new());
        let groups = FULL_REPORT_RECORDS - 12; // fixture's non-group record count
        value["totals"]["groups"] = Value::from(groups as u64);
        value["totals"]["accounts"] = Value::from(1u64);

        let base = serde_json::to_vec(&value).expect("serialize base report");
        let marker = b"\"groups\":[]";
        let start = base
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("empty groups marker");
        let array_start = start + marker.len() - 2;
        let array_end = array_start + 2;
        let mut bytes = Vec::with_capacity(base.len() + groups * 104);
        bytes.extend_from_slice(&base[..array_start]);
        bytes.push(b'[');
        for index in 0..groups {
            if index != 0 {
                bytes.push(b',');
            }
            write!(
                &mut bytes,
                "{{\"id\":\"github.com/owner/synthetic-{index:06}\",\
                 \"host\":\"github.com\",\"account\":\"owner\",\
                 \"repo\":\"synthetic-{index:06}\"}}"
            )
            .expect("write synthetic group");
        }
        bytes.push(b']');
        bytes.extend_from_slice(&base[array_end..]);

        assert!(bytes.len() as u64 <= 128 * 1024 * 1024);
        // The publication-layer gates the caller applies before this parser:
        // streaming preflight, then the measured streaming estimate.
        crate::report::publish::check_streaming_measurement_memory_budget(
            bytes.len() as u64,
            VALIDATOR_BUDGET,
        )
        .expect("measurement preflight fits the budget");
        let (array_items, owned_id_bytes, max_string_bytes, max_debug_string_bytes) =
            measure_report_streamed(&bytes).expect("measure 350k-record report");
        crate::report::publish::check_streaming_staged_memory_budget(
            bytes.len() as u64,
            array_items,
            owned_id_bytes,
            max_string_bytes,
            max_debug_string_bytes,
            VALIDATOR_BUDGET,
        )
        .expect("worst-case staged size and ID indexes fit 256 MiB");
        assert_eq!(
            validate_report_streamed(&bytes).expect("350k-record report validates"),
            value["report_id"].as_str().expect("report ID")
        );
    }

    #[test]
    fn streaming_diagnostics_truncate_repeated_large_ids() {
        let long_id = "x".repeat(512 * 1024);
        let mut duplicate = example_value();
        let path = serde_json::json!({
            "id": long_id,
            "display": "/synthetic",
            "encoding": "utf8",
            "value": "/synthetic",
            "volume_id": null,
            "object_id": null,
            "incarnation": null
        });
        let paths = duplicate["paths"].as_array_mut().expect("paths");
        paths.push(path.clone());
        paths.push(path);
        duplicate["totals"]["observed_paths"] = Value::from(paths.len() as u64);
        let bytes = serde_json::to_vec(&duplicate).expect("serialize duplicate report");
        let error = validate_report_streamed(&bytes).expect_err("duplicate IDs are rejected");
        assert!(error.to_string().contains("duplicate path id"));
        assert!(error.to_string().len() < 4096, "diagnostic is bounded");

        let mut missing = example_value();
        missing["repositories"][0]["git_path_id"] = Value::String("m".repeat(512 * 1024));
        let bytes = serde_json::to_vec(&missing).expect("serialize missing-reference report");
        let error = validate_report_streamed(&bytes).expect_err("missing references are rejected");
        assert!(error.to_string().contains("git_path_id"));
        assert!(error.to_string().len() < 4096, "diagnostic is bounded");
    }

    /// ADJ-05 regression net: a semantic validation failure never carries
    /// the raw `report_id` (or any large report content) in its diagnostic.
    #[test]
    fn semantic_failures_never_echo_the_report_id() {
        let mut invalid = example_value();
        let report_id = format!("report-{}", "r".repeat(2048));
        invalid["report_id"] = Value::String(report_id.clone());
        invalid["coverage"]["gaps"] = Value::from(99u64);
        let error = streaming_error(&invalid);
        assert!(
            !error.contains(&report_id),
            "report ID is never echoed: {}",
            &error[..error.len().min(256)]
        );
        assert!(error.len() < 4096, "diagnostic is bounded: {}", error.len());
    }
}
