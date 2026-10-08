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
use crate::report::model::{
    Alias, Branch, Candidate, Checkout, Coverage, EncodedName, ErrorRecord, GeneratedArtifact,
    Group, PathRecord, Remote, Report, Repository, Resources, Root, Scan, Status, StorageLink,
    Tool, Totals, Volume,
};
use serde::de::{DeserializeOwned, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

/// Maximum decoded bytes in any one streamed record. Report writers cap
/// path/evidence fields below this limit; this guard keeps a hostile single
/// record from becoming a large transient allocation during validation.
pub const MAX_STREAMED_RECORD_BYTES: usize = 1024 * 1024;
/// Maximum copied bytes retained in record-ID indexes during streaming.
pub const MAX_STREAMED_ID_BYTES: usize = 24 * 1024 * 1024;
/// Maximum copied bytes retained for unique `(host, account)` keys.
pub const MAX_STREAMED_ACCOUNT_KEY_BYTES: usize = 24 * 1024 * 1024;
/// Maximum aggregate metadata JSON retained while decoding the report
/// envelope (`tool`, `scan`, `coverage`, and `resources`).
pub const MAX_STREAMED_HEADER_BYTES: usize = 4 * 1024 * 1024;
/// Conservative hash-table/string headers per emitted record, exclusive of
/// the separately capped ID bytes.
pub const STREAMED_INDEX_BYTES_PER_RECORD: u64 = 128;
const STREAMED_VALIDATOR_FIXED_BYTES: u64 = 32 * 1024 * 1024;
const MAX_STREAMED_PROBLEM_BYTES: usize = 512;
const MAX_STREAMED_DIAGNOSTIC_BYTES: usize = 4096;
const MAX_STREAMED_SCHEMA_VERSION_BYTES: usize = 128;
const MAX_STREAMED_TIMESTAMP_BYTES: usize = 128;

/// Bound the streaming validator's peak against the caller's existing RSS
/// budget. The estimate covers the staged bytes, copied ID/account indexes,
/// per-record hash/set overhead, one decoded record, and fixed parser state.
pub fn check_streaming_memory_budget(
    staged_len: u64,
    record_count: u64,
    rss_target_bytes: u64,
) -> crate::Result<()> {
    let estimate = staged_len
        .saturating_add((MAX_STREAMED_ID_BYTES + MAX_STREAMED_ACCOUNT_KEY_BYTES) as u64)
        .saturating_add(record_count.saturating_mul(STREAMED_INDEX_BYTES_PER_RECORD))
        .saturating_add(MAX_STREAMED_RECORD_BYTES as u64)
        .saturating_add(STREAMED_VALIDATOR_FIXED_BYTES);
    if estimate > rss_target_bytes {
        return Err(Error::Report(format!(
            "streaming staged-report validation needs an estimated {estimate} bytes, over the \
             rss_target_bytes {rss_target_bytes} budget; coverage is incomplete (resource \
             exhaustion), refusing validation"
        )));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReport<'a> {
    schema_version: &'a str,
    report_id: &'a str,
    created_at: &'a str,
    #[serde(borrow)]
    tool: &'a RawValue,
    #[serde(borrow)]
    scan: &'a RawValue,
    #[serde(borrow)]
    coverage: &'a RawValue,
    #[serde(borrow)]
    resources: &'a RawValue,
    #[serde(borrow)]
    volumes: &'a RawValue,
    #[serde(borrow)]
    paths: &'a RawValue,
    #[serde(borrow)]
    roots: &'a RawValue,
    #[serde(default, borrow)]
    groups: Option<&'a RawValue>,
    #[serde(borrow)]
    repositories: &'a RawValue,
    #[serde(borrow)]
    checkouts: &'a RawValue,
    #[serde(borrow)]
    branches: &'a RawValue,
    #[serde(borrow)]
    remotes: &'a RawValue,
    #[serde(borrow)]
    storage_links: &'a RawValue,
    #[serde(borrow)]
    aliases: &'a RawValue,
    #[serde(borrow)]
    candidates: &'a RawValue,
    #[serde(borrow)]
    errors: &'a RawValue,
    #[serde(borrow)]
    generated_artifacts: &'a RawValue,
    #[serde(default)]
    totals: Option<Totals>,
}

impl RawReport<'_> {
    fn shell(&self) -> crate::Result<Report> {
        let header_bytes = self.tool.get().len()
            + self.scan.get().len()
            + self.coverage.get().len()
            + self.resources.get().len();
        if header_bytes > MAX_STREAMED_HEADER_BYTES {
            return Err(Error::Report(format!(
                "report envelope metadata is {header_bytes} bytes, over the {}-byte streaming limit",
                MAX_STREAMED_HEADER_BYTES
            )));
        }
        if self.report_id.len() > 4096 {
            return Err(Error::Report(
                "report_id exceeds the 4096-byte streaming limit".to_string(),
            ));
        }
        if self.schema_version.len() > MAX_STREAMED_SCHEMA_VERSION_BYTES {
            return Err(Error::Report(format!(
                "schema_version exceeds the {MAX_STREAMED_SCHEMA_VERSION_BYTES}-byte streaming limit"
            )));
        }
        if self.created_at.len() > MAX_STREAMED_TIMESTAMP_BYTES {
            return Err(Error::Report(format!(
                "created_at exceeds the {MAX_STREAMED_TIMESTAMP_BYTES}-byte streaming limit"
            )));
        }
        let tool: Tool = serde_json::from_str(self.tool.get()).map_err(|error| {
            Error::Report(format!(
                "report tool is invalid: {}",
                json_error_location(&error)
            ))
        })?;
        let mut scan: Scan = serde_json::from_str(self.scan.get()).map_err(|error| {
            Error::Report(format!(
                "report scan is invalid: {}",
                json_error_location(&error)
            ))
        })?;
        let mut coverage: Coverage =
            serde_json::from_str(self.coverage.get()).map_err(|error| {
                Error::Report(format!(
                    "report coverage is invalid: {}",
                    json_error_location(&error)
                ))
            })?;
        let resources: Resources = serde_json::from_str(self.resources.get()).map_err(|error| {
            Error::Report(format!(
                "report resources is invalid: {}",
                json_error_location(&error)
            ))
        })?;
        // These fields are not inspected by validation. Replace their vectors
        // so a large but bounded header cannot leave retained capacity in the
        // per-record validation shell.
        scan.targets = Vec::new();
        coverage.scope_boundaries = Vec::new();
        Ok(Report {
            schema_version: self.schema_version.to_string(),
            report_id: self.report_id.to_string(),
            created_at: self.created_at.to_string(),
            tool,
            scan,
            coverage,
            resources,
            volumes: Vec::new(),
            paths: Vec::new(),
            roots: Vec::new(),
            groups: Vec::new(),
            repositories: Vec::new(),
            checkouts: Vec::new(),
            branches: Vec::new(),
            remotes: Vec::new(),
            storage_links: Vec::new(),
            aliases: Vec::new(),
            candidates: Vec::new(),
            errors: Vec::new(),
            generated_artifacts: Vec::new(),
            totals: self.totals.clone().unwrap_or_default(),
        })
    }
}

fn json_error_location(error: &serde_json::Error) -> String {
    format!(
        "invalid JSON at line {}, column {}",
        error.line(),
        error.column()
    )
}

struct RawArraySeed<'a, T, F, C> {
    visit: &'a mut F,
    check: &'a mut C,
    marker: PhantomData<T>,
}

impl<'de, T, F, C> DeserializeSeed<'de> for RawArraySeed<'_, T, F, C>
where
    T: DeserializeOwned,
    F: FnMut(T) -> crate::Result<()>,
    C: FnMut(&str) -> crate::Result<()>,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ArrayVisitor<'a, T, F, C> {
            visit: &'a mut F,
            check: &'a mut C,
            marker: PhantomData<T>,
        }

        impl<'de, T, F, C> Visitor<'de> for ArrayVisitor<'_, T, F, C>
        where
            T: DeserializeOwned,
            F: FnMut(T) -> crate::Result<()>,
            C: FnMut(&str) -> crate::Result<()>,
        {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an array of report records")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
            where
                A: SeqAccess<'de>,
            {
                while let Some(raw) = seq.next_element::<&'de RawValue>()? {
                    if raw.get().len() > MAX_STREAMED_RECORD_BYTES {
                        return Err(serde::de::Error::custom(format!(
                            "record is {} bytes, over the {}-byte streaming limit",
                            raw.get().len(),
                            MAX_STREAMED_RECORD_BYTES
                        )));
                    }
                    (self.check)(raw.get()).map_err(serde::de::Error::custom)?;
                    let item: T = serde_json::from_str(raw.get())
                        .map_err(|error| serde::de::Error::custom(json_error_location(&error)))?;
                    (self.visit)(item).map_err(serde::de::Error::custom)?;
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(ArrayVisitor {
            visit: self.visit,
            check: self.check,
            marker: PhantomData,
        })
    }
}

fn visit_raw_array<T, F>(raw: &RawValue, visit: F) -> crate::Result<()>
where
    T: DeserializeOwned,
    F: FnMut(T) -> crate::Result<()>,
{
    visit_raw_array_checked(raw, |_| Ok(()), visit)
}

fn visit_raw_array_checked<T, F, C>(raw: &RawValue, mut check: C, mut visit: F) -> crate::Result<()>
where
    T: DeserializeOwned,
    F: FnMut(T) -> crate::Result<()>,
    C: FnMut(&str) -> crate::Result<()>,
{
    let mut deserializer = serde_json::Deserializer::from_str(raw.get());
    RawArraySeed::<T, F, C> {
        visit: &mut visit,
        check: &mut check,
        marker: PhantomData,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| Error::Report(format!("streamed report array is invalid: {error}")))?;
    deserializer.end().map_err(|error| {
        Error::Report(format!(
            "streamed report array has trailing data: {}",
            json_error_location(&error)
        ))
    })
}

struct RequiredFieldsSeed {
    context: &'static str,
    required: &'static [&'static str],
    nested: Option<(&'static str, &'static str, &'static [&'static str])>,
}

impl<'de> DeserializeSeed<'de> for RequiredFieldsSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
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

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an object with required report fields")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.required.len() > u64::BITS as usize {
            return Err(serde::de::Error::custom(
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
                        .map_err(serde::de::Error::custom)?;
                    continue;
                }
            }
            let _: IgnoredAny = map.next_value()?;
        }

        for (index, required) in self.required.iter().enumerate() {
            if found & (1u64 << index) == 0 {
                return Err(serde::de::Error::custom(format!(
                    "{} is missing required field {:?}",
                    self.context, required
                )));
            }
        }
        Ok(())
    }
}

/// Check required keys without building a JSON value tree. Values are skipped
/// as `IgnoredAny`, except an explicitly selected nested object is checked in
/// place. This keeps the v1.5 shape check within the existing one-record bound.
fn check_required_object_fields(
    json: &str,
    context: &'static str,
    required: &'static [&'static str],
) -> crate::Result<()> {
    check_required_object_fields_nested(json, context, required, None)
}

fn check_required_object_fields_nested(
    json: &str,
    context: &'static str,
    required: &'static [&'static str],
    nested: Option<(&'static str, &'static str, &'static [&'static str])>,
) -> crate::Result<()> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    RequiredFieldsSeed {
        context,
        required,
        nested,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| {
        Error::Report(format!(
            "{context} has invalid required-field shape: {error}"
        ))
    })?;
    deserializer.end().map_err(|error| {
        Error::Report(format!(
            "{context} has trailing JSON data: {}",
            json_error_location(&error)
        ))
    })
}

/// Validate staged report bytes without retaining the report's record
/// vectors. Pass one validates each record and builds bounded ID indexes;
/// pass two resolves cross-section references against those indexes.
///
/// `record_count` must be the exact count from the low-memory staged-report
/// preprobe for these same bytes. The function is crate-private so the count
/// cannot be supplied by an external caller and used to understate the index
/// memory estimate.
pub(crate) fn validate_report_streaming(
    bytes: &[u8],
    record_count: u64,
    rss_target_bytes: u64,
) -> crate::Result<String> {
    check_streaming_memory_budget(bytes.len() as u64, record_count, rss_target_bytes)?;
    let raw: RawReport<'_> = serde_json::from_slice(bytes).map_err(|error| {
        Error::Report(format!(
            "staged report bytes are not valid JSON: {}",
            json_error_location(&error)
        ))
    })?;
    validate_raw_report(&raw).map_err(|error| Error::Report(bounded_diagnostic(error.to_string())))
}

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

const MAX_STREAM_VALIDATION_PROBLEMS: usize = 64;

fn append_stream_problems(target: &mut Vec<String>, source: Vec<String>) {
    for problem in source {
        if target.len() == MAX_STREAM_VALIDATION_PROBLEMS {
            break;
        }
        target.push(bounded_problem(problem));
    }
}

fn stream_problem(problems: &mut Vec<String>, problem: impl Into<String>) {
    if problems.len() < MAX_STREAM_VALIDATION_PROBLEMS {
        problems.push(bounded_problem(problem.into()));
    }
}

fn bounded_problem(mut problem: String) -> String {
    if problem.len() <= MAX_STREAMED_PROBLEM_BYTES {
        return problem;
    }
    let mut end = MAX_STREAMED_PROBLEM_BYTES - 3;
    while !problem.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = String::with_capacity(MAX_STREAMED_PROBLEM_BYTES);
    bounded.push_str(&problem[..end]);
    bounded.push_str("...");
    // Do not retain an attacker-sized capacity in the diagnostic vector.
    problem.clear();
    bounded
}

fn bounded_diagnostic(mut diagnostic: String) -> String {
    if diagnostic.len() <= MAX_STREAMED_DIAGNOSTIC_BYTES {
        return diagnostic;
    }
    let mut end = MAX_STREAMED_DIAGNOSTIC_BYTES - 3;
    while !diagnostic.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = String::with_capacity(MAX_STREAMED_DIAGNOSTIC_BYTES);
    bounded.push_str(&diagnostic[..end]);
    bounded.push_str("...");
    // Drop any attacker-sized allocation before returning the diagnostic.
    diagnostic.clear();
    bounded
}

fn check_one_record<T>(
    base: &Report,
    record: T,
    install: impl FnOnce(&mut Report, T),
    problems: &mut Vec<String>,
) {
    let mut report = base.clone();
    install(&mut report, record);
    let mut local = Vec::new();
    check_envelope(&report, &mut local);
    check_encodings(&report, &mut local);
    check_statuses(&report, &mut local);
    append_stream_problems(problems, local);
}

#[derive(Default)]
struct StreamIdIndex {
    sections: HashMap<&'static str, HashSet<String>>,
    id_bytes: usize,
    account_keys: HashSet<(String, String)>,
    account_key_bytes: usize,
}

impl StreamIdIndex {
    fn register(
        &mut self,
        section: &'static str,
        id: &str,
        problems: &mut Vec<String>,
    ) -> crate::Result<()> {
        if id.is_empty() {
            stream_problem(problems, format!("{section} has an empty id"));
            return Ok(());
        }
        let ids = self.sections.entry(section).or_default();
        if ids.contains(id) {
            stream_problem(problems, format!("duplicate {section} id {id:?}"));
            return Ok(());
        }
        let next = self.id_bytes.saturating_add(id.len());
        if next > MAX_STREAMED_ID_BYTES {
            return Err(Error::Report(format!(
                "streamed report ID bytes exceed the {}-byte bound",
                MAX_STREAMED_ID_BYTES
            )));
        }
        self.id_bytes = next;
        ids.insert(id.to_string());
        Ok(())
    }

    fn register_account(&mut self, host: &str, account: &str) -> crate::Result<()> {
        let key = (host.to_string(), account.to_string());
        if self.account_keys.contains(&key) {
            return Ok(());
        }
        let next = self
            .account_key_bytes
            .saturating_add(host.len())
            .saturating_add(account.len());
        if next > MAX_STREAMED_ACCOUNT_KEY_BYTES {
            return Err(Error::Report(format!(
                "streamed report account-key bytes exceed the {}-byte bound",
                MAX_STREAMED_ACCOUNT_KEY_BYTES
            )));
        }
        self.account_key_bytes = next;
        self.account_keys.insert(key);
        Ok(())
    }

    fn table(&self, section: &'static str) -> &HashSet<String> {
        static EMPTY: std::sync::OnceLock<HashSet<String>> = std::sync::OnceLock::new();
        self.sections
            .get(section)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }
}

fn validate_raw_report(raw: &RawReport<'_>) -> crate::Result<String> {
    let mut problems = Vec::new();
    let base = raw.shell()?;
    check_envelope(&base, &mut problems);
    if raw.schema_version == crate::report::model::SCHEMA_VERSION {
        if raw.groups.is_none() {
            stream_problem(&mut problems, "groups is missing in report 1.5.0");
        }
        if raw.totals.is_none() {
            stream_problem(&mut problems, "totals is missing in report 1.5.0");
        }
    }
    let mut ids = StreamIdIndex::default();
    let mut totals = Totals {
        bare_stores: Some(0),
        ..Totals::default()
    };
    let mut error_count = 0u64;
    let mut unresolvable_candidates = 0u64;
    let mut has_unresolvable_repo = false;
    let mut has_incomplete_status = false;

    visit_raw_array::<Volume, _>(raw.volumes, |record| {
        ids.register("volume", &record.id, &mut problems)?;
        check_one_record(&base, record, |r, v| r.volumes.push(v), &mut problems);
        Ok(())
    })?;
    visit_raw_array::<PathRecord, _>(raw.paths, |record| {
        ids.register("path", &record.id, &mut problems)?;
        check_one_record(&base, record, |r, v| r.paths.push(v), &mut problems);
        totals.observed_paths += 1;
        Ok(())
    })?;
    visit_raw_array::<Root, _>(raw.roots, |record| {
        ids.register("root", &record.id, &mut problems)?;
        check_one_record(&base, record, |r, v| r.roots.push(v), &mut problems);
        Ok(())
    })?;
    if let Some(groups) = raw.groups {
        visit_raw_array::<Group, _>(groups, |record| {
            ids.register("group", &record.id, &mut problems)?;
            let expected = format!(
                "{}/{}/{}",
                record.host.to_ascii_lowercase(),
                record.account.to_ascii_lowercase(),
                record.repo.to_ascii_lowercase()
            );
            if record.id != expected {
                stream_problem(
                    &mut problems,
                    format!("group {} id does not match {:?}", record.id, expected),
                );
            }
            if record.host.is_empty() || record.account.is_empty() || record.repo.is_empty() {
                stream_problem(
                    &mut problems,
                    format!("group {} host/account/repo must be nonempty", record.id),
                );
            }
            ids.register_account(&record.host, &record.account)?;
            check_one_record(&base, record, |r, v| r.groups.push(v), &mut problems);
            totals.groups += 1;
            Ok(())
        })?;
    }
    visit_raw_array::<Repository, _>(raw.repositories, |record| {
        ids.register("repository", &record.id, &mut problems)?;
        if record.match_disposition == "unresolvable_identity" {
            has_unresolvable_repo = true;
        }
        match record.bare {
            Some(true) => {
                if let Some(count) = totals.bare_stores.as_mut() {
                    *count += 1;
                }
            }
            Some(false) => {}
            None => totals.bare_stores = None,
        }
        check_one_record(&base, record, |r, v| r.repositories.push(v), &mut problems);
        totals.stores += 1;
        Ok(())
    })?;
    visit_raw_array_checked::<Checkout, _, _>(
        raw.checkouts,
        |json| {
            if raw.schema_version == crate::report::model::SCHEMA_VERSION {
                check_required_object_fields_nested(
                    json,
                    "checkout",
                    &[],
                    Some(("status", "checkout.status", &["conflicts", "working_state"])),
                )
            } else {
                Ok(())
            }
        },
        |record| {
            ids.register("checkout", &record.id, &mut problems)?;
            if record.availability == "present" {
                totals.present_checkouts += 1;
                if record.kind == "linked" {
                    totals.linked_worktrees += 1;
                }
            }
            if record.status.state != "complete" {
                has_incomplete_status = true;
            }
            match record.status.state.as_str() {
                "complete" => totals.analysis.completed += 1,
                "pending" | "not_requested" => totals.analysis.pending += 1,
                "unsupported" => totals.analysis.unavailable += 1,
                "partial" | "unstable" | "error" => totals.analysis.failed += 1,
                _ => totals.analysis.pending += 1,
            }
            check_one_record(&base, record, |r, v| r.checkouts.push(v), &mut problems);
            Ok(())
        },
    )?;
    visit_raw_array_checked::<Branch, _, _>(
        raw.branches,
        |json| {
            if raw.schema_version == crate::report::model::SCHEMA_VERSION {
                check_required_object_fields(
                    json,
                    "branch",
                    &["freshness", "freshness_at", "comparison", "ahead", "behind"],
                )
            } else {
                Ok(())
            }
        },
        |record| {
            ids.register("branch", &record.id, &mut problems)?;
            match record.kind.as_str() {
                "local" => totals.local_branches += 1,
                "remote_tracking" => totals.remote_tracking_refs += 1,
                _ => {}
            }
            check_one_record(&base, record, |r, v| r.branches.push(v), &mut problems);
            Ok(())
        },
    )?;
    visit_raw_array_checked::<Remote, _, _>(
        raw.remotes,
        |json| {
            if raw.schema_version == crate::report::model::SCHEMA_VERSION {
                check_required_object_fields(json, "remote", &["refresh"])
            } else {
                Ok(())
            }
        },
        |record| {
            ids.register("remote", &record.id, &mut problems)?;
            check_one_record(&base, record, |r, v| r.remotes.push(v), &mut problems);
            Ok(())
        },
    )?;
    visit_raw_array::<StorageLink, _>(raw.storage_links, |record| {
        ids.register("storage_link", &record.id, &mut problems)?;
        check_one_record(&base, record, |r, v| r.storage_links.push(v), &mut problems);
        Ok(())
    })?;
    visit_raw_array::<Alias, _>(raw.aliases, |record| {
        check_one_record(&base, record, |r, v| r.aliases.push(v), &mut problems);
        totals.aliases += 1;
        Ok(())
    })?;
    visit_raw_array::<Candidate, _>(raw.candidates, |record| {
        ids.register("candidate", &record.id, &mut problems)?;
        if record.disposition == "unresolvable_identity" {
            unresolvable_candidates += 1;
        }
        check_one_record(&base, record, |r, v| r.candidates.push(v), &mut problems);
        Ok(())
    })?;
    visit_raw_array::<ErrorRecord, _>(raw.errors, |record| {
        ids.register("error", &record.id, &mut problems)?;
        error_count += 1;
        check_one_record(&base, record, |r, v| r.errors.push(v), &mut problems);
        Ok(())
    })?;
    visit_raw_array::<GeneratedArtifact, _>(raw.generated_artifacts, |record| {
        check_one_record(
            &base,
            record,
            |r, v| r.generated_artifacts.push(v),
            &mut problems,
        );
        Ok(())
    })?;

    totals.accounts = ids.account_keys.len() as u64;
    totals.unresolved_candidates = unresolvable_candidates;
    totals.gaps = error_count;
    if raw.schema_version == crate::report::model::SCHEMA_VERSION
        && raw.totals.as_ref() != Some(&totals)
    {
        stream_problem(
            &mut problems,
            format!(
                "totals do not agree with records: got {:?}, want {totals:?}",
                raw.totals
            ),
        );
    }
    if base.coverage.gaps != error_count {
        stream_problem(
            &mut problems,
            format!(
                "coverage.gaps is {}, but {error_count} error records were emitted",
                base.coverage.gaps
            ),
        );
    }
    if base.coverage.unresolvable_candidates != unresolvable_candidates {
        stream_problem(
            &mut problems,
            format!("coverage.unresolvable_candidates is {}, but {unresolvable_candidates} unresolved candidates were emitted", base.coverage.unresolvable_candidates),
        );
    }
    if base.coverage.status == "complete" && has_incomplete_status {
        stream_problem(
            &mut problems,
            "coverage.status is complete but a checkout status is incomplete",
        );
    }
    if base.coverage.identity == "complete_under_policy"
        && (unresolvable_candidates != 0 || has_unresolvable_repo)
    {
        stream_problem(
            &mut problems,
            "coverage.identity is complete_under_policy but unresolved identities are present",
        );
    }
    check_coverage(&base, &mut problems);

    validate_raw_references(raw, &ids, &mut problems)?;
    if problems.is_empty() {
        Ok(raw.report_id.to_string())
    } else {
        Err(Error::Report(format!(
            "report {} invalid: {}",
            raw.report_id,
            problems.join("; ")
        )))
    }
}

fn stream_resolve(
    problems: &mut Vec<String>,
    context: impl Into<String>,
    id: &str,
    table: &HashSet<String>,
) {
    let context = context.into();
    if id.is_empty() {
        stream_problem(problems, format!("{context} is an empty id"));
    } else if !table.contains(id) {
        stream_problem(problems, format!("{context} references missing id {id:?}"));
    }
}

fn stream_resolve_opt(
    problems: &mut Vec<String>,
    context: impl Into<String>,
    id: Option<&str>,
    table: &HashSet<String>,
) {
    if let Some(id) = id {
        stream_resolve(problems, context, id, table);
    }
}

fn stream_resolve_list(
    problems: &mut Vec<String>,
    context: &str,
    ids: &[String],
    table: &HashSet<String>,
) {
    for id in ids {
        stream_resolve(problems, format!("{context} error reference"), id, table);
    }
}

fn validate_raw_references(
    raw: &RawReport<'_>,
    ids: &StreamIdIndex,
    problems: &mut Vec<String>,
) -> crate::Result<()> {
    visit_raw_array::<PathRecord, _>(raw.paths, |record| {
        stream_resolve_opt(
            problems,
            format!("path {} volume_id", record.id),
            record.volume_id.as_deref(),
            ids.table("volume"),
        );
        Ok(())
    })?;
    visit_raw_array::<Volume, _>(raw.volumes, |record| {
        stream_resolve_list(
            problems,
            &format!("volume {}", record.id),
            &record.error_ids,
            ids.table("error"),
        );
        Ok(())
    })?;
    visit_raw_array::<Root, _>(raw.roots, |record| {
        stream_resolve(
            problems,
            format!("root {} path_id", record.id),
            &record.path_id,
            ids.table("path"),
        );
        stream_resolve_opt(
            problems,
            format!("root {} volume_id", record.id),
            record.volume_id.as_deref(),
            ids.table("volume"),
        );
        stream_resolve_list(
            problems,
            &format!("root {}", record.id),
            &record.error_ids,
            ids.table("error"),
        );
        Ok(())
    })?;
    visit_raw_array::<Repository, _>(raw.repositories, |record| {
        stream_resolve(
            problems,
            format!("repository {} git_path_id", record.id),
            &record.git_path_id,
            ids.table("path"),
        );
        stream_resolve(
            problems,
            format!("repository {} common_path_id", record.id),
            &record.common_path_id,
            ids.table("path"),
        );
        stream_resolve_list(
            problems,
            &format!("repository {}", record.id),
            &record.error_ids,
            ids.table("error"),
        );
        Ok(())
    })?;
    visit_raw_array::<Checkout, _>(raw.checkouts, |record| {
        stream_resolve(
            problems,
            format!("checkout {} repository_id", record.id),
            &record.repository_id,
            ids.table("repository"),
        );
        stream_resolve_opt(
            problems,
            format!("checkout {} root_path_id", record.id),
            record.root_path_id.as_deref(),
            ids.table("path"),
        );
        stream_resolve(
            problems,
            format!("checkout {} git_path_id", record.id),
            &record.git_path_id,
            ids.table("path"),
        );
        stream_resolve_list(
            problems,
            &format!("checkout {} status", record.id),
            &record.status.error_ids,
            ids.table("error"),
        );
        stream_resolve_list(
            problems,
            &format!("checkout {}", record.id),
            &record.error_ids,
            ids.table("error"),
        );
        Ok(())
    })?;
    visit_raw_array::<Branch, _>(raw.branches, |record| {
        stream_resolve(
            problems,
            format!("branch {} repository_id", record.id),
            &record.repository_id,
            ids.table("repository"),
        );
        stream_resolve_opt(
            problems,
            format!("branch {} checkout_scope_id", record.id),
            record.checkout_scope_id.as_deref(),
            ids.table("checkout"),
        );
        stream_resolve_list(
            problems,
            &format!("branch {}", record.id),
            &record.error_ids,
            ids.table("error"),
        );
        Ok(())
    })?;
    visit_raw_array::<Remote, _>(raw.remotes, |record| {
        stream_resolve(
            problems,
            format!("remote {} repository_id", record.id),
            &record.repository_id,
            ids.table("repository"),
        );
        stream_resolve_opt(
            problems,
            format!("remote {} checkout_scope_id", record.id),
            record.checkout_scope_id.as_deref(),
            ids.table("checkout"),
        );
        Ok(())
    })?;
    visit_raw_array::<StorageLink, _>(raw.storage_links, |record| {
        stream_resolve(
            problems,
            format!("storage_link {} from_repository_id", record.id),
            &record.from_repository_id,
            ids.table("repository"),
        );
        stream_resolve(
            problems,
            format!("storage_link {} to_path_id", record.id),
            &record.to_path_id,
            ids.table("path"),
        );
        Ok(())
    })?;
    visit_raw_array::<Alias, _>(raw.aliases, |record| {
        stream_resolve(
            problems,
            "alias path_id",
            &record.path_id,
            ids.table("path"),
        );
        stream_resolve(
            problems,
            "alias target_path_id",
            &record.target_path_id,
            ids.table("path"),
        );
        Ok(())
    })?;
    visit_raw_array::<Candidate, _>(raw.candidates, |record| {
        stream_resolve(
            problems,
            format!("candidate {} path_id", record.id),
            &record.path_id,
            ids.table("path"),
        );
        stream_resolve_opt(
            problems,
            format!("candidate {} repository_id", record.id),
            record.repository_id.as_deref(),
            ids.table("repository"),
        );
        stream_resolve_list(
            problems,
            &format!("candidate {}", record.id),
            &record.error_ids,
            ids.table("error"),
        );
        Ok(())
    })?;
    visit_raw_array::<ErrorRecord, _>(raw.errors, |record| {
        stream_resolve_opt(
            problems,
            format!("error {} path_id", record.id),
            record.path_id.as_deref(),
            ids.table("path"),
        );
        Ok(())
    })?;
    visit_raw_array::<GeneratedArtifact, _>(raw.generated_artifacts, |record| {
        stream_resolve(
            problems,
            "generated_artifact path_id",
            &record.path_id,
            ids.table("path"),
        );
        Ok(())
    })?;
    Ok(())
}

fn check_envelope(report: &Report, problems: &mut Vec<String>) {
    // Report 1.4.0 is additive over 1.3.0 (comparison fields default
    // to `pending`/null), so both versions validate.
    if !matches!(
        report.schema_version.as_str(),
        "1.3.0" | "1.4.0" | crate::report::model::SCHEMA_VERSION
    ) {
        problems.push(format!(
            "schema_version is {:?}, want 1.3.0, 1.4.0, or {:?}",
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
        // Report 1.2.0: remote freshness (pre-1.2 snapshots
        // deserialize missing `freshness` as `unknown`).
        check_enum(
            &format!("branch {} freshness", branch.id),
            &branch.freshness,
            &["current", "stale", "unknown"],
            problems,
        );
        if branch.freshness == "unknown" && branch.freshness_at.is_some() {
            problems.push(format!(
                "branch {} freshness is unknown but freshness_at is set",
                branch.id
            ));
        }
        if branch.freshness != "unknown" && branch.freshness_at.is_none() {
            problems.push(format!(
                "branch {} freshness is {:?} but freshness_at is missing",
                branch.id, branch.freshness
            ));
        }
        if branch.kind != "remote_tracking"
            && (branch.freshness != "unknown" || branch.freshness_at.is_some())
        {
            problems.push(format!(
                "branch {} kind {:?} must have unknown freshness and null freshness_at",
                branch.id, branch.kind
            ));
        }
        check_opt_time(
            &format!("branch {} freshness_at", branch.id),
            &branch.freshness_at,
            problems,
        );
        // Report 1.4.0: branch comparison (pre-1.4 snapshots
        // deserialize missing fields as `pending`/null, which
        // validates). Counts are Some only for the four counted
        // states, with the exact zero/nonzero shape each state
        // derives from; every other state carries null counts —
        // unknown is never zero.
        check_enum(
            &format!("branch {} comparison", branch.id),
            &branch.comparison,
            &[
                "equal",
                "ahead",
                "behind",
                "diverged",
                "no_upstream",
                "upstream_missing",
                "pending",
                "incomplete_history",
                "error",
            ],
            problems,
        );
        let counts_ok = match branch.comparison.as_str() {
            "equal" => branch.ahead == Some(0) && branch.behind == Some(0),
            "ahead" => branch.ahead.is_some_and(|n| n > 0) && branch.behind == Some(0),
            "behind" => branch.ahead == Some(0) && branch.behind.is_some_and(|n| n > 0),
            "diverged" => {
                branch.ahead.is_some_and(|n| n > 0) && branch.behind.is_some_and(|n| n > 0)
            }
            _ => branch.ahead.is_none() && branch.behind.is_none(),
        };
        if !counts_ok {
            problems.push(format!(
                "branch {} comparison {:?} carries ahead={:?} behind={:?}: \
                 counted states need exact counts, other states need nulls",
                branch.id, branch.comparison, branch.ahead, branch.behind
            ));
        }
        if branch.kind != "local"
            && (branch.comparison != "pending" || branch.ahead.is_some() || branch.behind.is_some())
        {
            problems.push(format!(
                "branch {} kind {:?} must have pending comparison and null counts",
                branch.id, branch.kind
            ));
        }
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
        // Report 1.2.0: latest `--fetch` attempt summary.
        if let Some(refresh) = &remote.refresh {
            check_enum(
                &format!("remote {} refresh status", remote.id),
                &refresh.status,
                &["success", "failed", "unsupported"],
                problems,
            );
            if !is_rfc3339_shape(&refresh.observed_at) {
                problems.push(format!(
                    "remote {} refresh observed_at {:?} is not RFC 3339",
                    remote.id, refresh.observed_at
                ));
            }
            if refresh.duration_ms.is_some_and(|v| v < 0) {
                problems.push(format!(
                    "remote {} refresh duration_ms is negative",
                    remote.id
                ));
            }
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
    for group in &report.groups {
        collect_id(&mut seen, "group", &group.id, problems);
        let expected = format!(
            "{}/{}/{}",
            group.host.to_ascii_lowercase(),
            group.account.to_ascii_lowercase(),
            group.repo.to_ascii_lowercase()
        );
        if group.id != expected {
            problems.push(format!(
                "group {} id does not match lower(host)/lower(account)/lower(repo) {:?}",
                group.id, expected
            ));
        }
        if group.host.is_empty() || group.account.is_empty() || group.repo.is_empty() {
            problems.push(format!(
                "group {} host/account/repo must be nonempty",
                group.id
            ));
        }
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
    if report.schema_version == crate::report::model::SCHEMA_VERSION {
        check_totals(report, problems);
    }
}

fn check_totals(report: &Report, problems: &mut Vec<String>) {
    let total = &report.totals;
    let accounts: HashSet<(&str, &str)> = report
        .groups
        .iter()
        .map(|group| (group.host.as_str(), group.account.as_str()))
        .collect();
    let bare_unknown = report.repositories.iter().any(|repo| repo.bare.is_none());
    let bare_stores = if bare_unknown {
        None
    } else {
        Some(
            report
                .repositories
                .iter()
                .filter(|repo| repo.bare == Some(true))
                .count() as u64,
        )
    };
    let mut analysis = crate::report::model::AnalysisTotals::default();
    for checkout in &report.checkouts {
        match checkout.status.state.as_str() {
            "complete" => analysis.completed += 1,
            "pending" | "not_requested" => analysis.pending += 1,
            "unsupported" => analysis.unavailable += 1,
            "partial" | "unstable" | "error" => analysis.failed += 1,
            _ => analysis.pending += 1,
        }
    }
    let expected = crate::report::model::Totals {
        accounts: accounts.len() as u64,
        groups: report.groups.len() as u64,
        stores: report.repositories.len() as u64,
        bare_stores,
        present_checkouts: report
            .checkouts
            .iter()
            .filter(|checkout| checkout.availability == "present")
            .count() as u64,
        linked_worktrees: report
            .checkouts
            .iter()
            .filter(|checkout| checkout.availability == "present" && checkout.kind == "linked")
            .count() as u64,
        observed_paths: report.paths.len() as u64,
        aliases: report.aliases.len() as u64,
        local_branches: report
            .branches
            .iter()
            .filter(|branch| branch.kind == "local")
            .count() as u64,
        remote_tracking_refs: report
            .branches
            .iter()
            .filter(|branch| branch.kind == "remote_tracking")
            .count() as u64,
        analysis,
        unresolved_candidates: unresolvable_candidate_count(report),
        gaps: report.errors.len() as u64,
    };
    if total.accounts != expected.accounts
        || total.groups != expected.groups
        || total.stores != expected.stores
        || total.bare_stores != expected.bare_stores
        || total.present_checkouts != expected.present_checkouts
        || total.linked_worktrees != expected.linked_worktrees
        || total.observed_paths != expected.observed_paths
        || total.aliases != expected.aliases
        || total.local_branches != expected.local_branches
        || total.remote_tracking_refs != expected.remote_tracking_refs
        || total.analysis.completed != expected.analysis.completed
        || total.analysis.pending != expected.analysis.pending
        || total.analysis.failed != expected.analysis.failed
        || total.analysis.unavailable != expected.analysis.unavailable
        || total.unresolved_candidates != expected.unresolved_candidates
        || total.gaps != expected.gaps
    {
        problems.push(format!(
            "totals do not agree with report records: got {total:?}, want {expected:?}"
        ));
    }
}

fn unresolvable_candidate_count(report: &Report) -> u64 {
    report
        .candidates
        .iter()
        .filter(|candidate| candidate.disposition == "unresolvable_identity")
        .count() as u64
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
    if report.scan.state == "complete" && report.coverage.status == "incomplete" {
        problems.push(format!(
            "scan.state is complete but coverage.status is incomplete (status was requested with mode {:?})",
            report.scan.status_mode
        ));
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
    // Report 1.3.0 Step 10 vocabulary. Pre-1.3 snapshots deserialize
    // `working_state` as `unknown` (model default), which validates.
    check_enum(
        &format!("{context} working_state"),
        &status.working_state,
        &[
            "clean",
            "dirty",
            "conflicted",
            "pending",
            "partial",
            "unstable",
            "unknown",
            "error",
            "not_applicable",
        ],
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
            if status.staged.is_some()
                || status.unstaged.is_some()
                || status.untracked.is_some()
                || status.conflicts.is_some()
            {
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
    if status.working_state == "clean" && (status.mode == "metadata" || status.state != "complete")
    {
        problems.push(format!(
            "{context}: working_state clean requires complete status in summary or full mode"
        ));
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

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use serde_json::Value;
    use std::io::Write;

    const FULL_REPORT_RECORDS: usize = 350_520;
    const VALIDATOR_BUDGET: u64 = 256 * 1024 * 1024;

    fn example_value() -> Value {
        serde_json::from_str(include_str!("../../tests/data/example-report.json"))
            .expect("example report")
    }

    fn record_count(value: &Value) -> usize {
        [
            "volumes",
            "paths",
            "roots",
            "groups",
            "repositories",
            "checkouts",
            "branches",
            "remotes",
            "storage_links",
            "aliases",
            "candidates",
            "errors",
            "generated_artifacts",
        ]
        .iter()
        .map(|key| value[*key].as_array().map_or(0, Vec::len))
        .sum()
    }

    fn streaming_error(value: &Value) -> String {
        let bytes = serde_json::to_vec(value).expect("serialize report");
        validate_report_streaming(&bytes, record_count(value) as u64, VALIDATOR_BUDGET)
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
        validate_report_streaming(&bytes, record_count(&baseline) as u64, VALIDATOR_BUDGET)
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
        validate_report_streaming(&bytes, record_count(&value) as u64, VALIDATOR_BUDGET)
            .expect("supported 1.3 report may omit fields added in later schemas");
    }

    #[test]
    fn streaming_validator_accepts_350k_records_under_the_fixed_budget() {
        let mut value = example_value();
        value["groups"] = Value::Array(Vec::new());
        let base_records = record_count(&value);
        let groups = FULL_REPORT_RECORDS - base_records;
        value["groups"] = Value::Array(Vec::new());
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

        assert_eq!(record_count(&value) + groups, FULL_REPORT_RECORDS);
        assert!(bytes.len() as u64 <= 128 * 1024 * 1024);
        check_streaming_memory_budget(
            128 * 1024 * 1024,
            FULL_REPORT_RECORDS as u64,
            VALIDATOR_BUDGET,
        )
        .expect("worst-case staged size and ID indexes fit 256 MiB");
        assert_eq!(
            validate_report_streaming(&bytes, FULL_REPORT_RECORDS as u64, VALIDATOR_BUDGET,)
                .expect("350k-record report validates"),
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
        let count = record_count(&duplicate) as u64;
        let error = validate_report_streaming(&bytes, count, VALIDATOR_BUDGET)
            .expect_err("duplicate IDs are rejected");
        assert!(error.to_string().contains("duplicate path id"));
        assert!(error.to_string().len() < 4096, "diagnostic is bounded");

        let mut missing = example_value();
        missing["repositories"][0]["git_path_id"] = Value::String("m".repeat(512 * 1024));
        let bytes = serde_json::to_vec(&missing).expect("serialize missing-reference report");
        let count = record_count(&missing) as u64;
        let error = validate_report_streaming(&bytes, count, VALIDATOR_BUDGET)
            .expect_err("missing references are rejected");
        assert!(error.to_string().contains("git_path_id"));
        assert!(error.to_string().len() < 4096, "diagnostic is bounded");
    }
}
