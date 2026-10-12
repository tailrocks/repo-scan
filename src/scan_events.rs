//! Scan-event stream envelope, classes, ops, and cursor (contract D4/C3).
//!
//! Implements `docs/GOAL_CONTRACTS.md` §D4: one JSONL envelope per event,
//! per-class [`Op`] mapping, and the opaque replay cursor.
//!
//! IDs referenced by event payloads may be stable opaque projections of
//! owner-local catalog IDs; they are join keys for the event stream, not
//! catalog IDs. `scan_id` is the [`crate::model::ScanId`] request identifier
//! rendered as a string.
//!
//! Consolidation slice 3 (port of B11 `7c864ad5`): the scan-bound v2
//! cursor ([`ScanCursor`]), cursor classification ([`classify_cursor`]),
//! bounded retention ([`retention_cutoff`]), the fail-closed guarded
//! replay pagination ([`read_guarded_scan_event_page`]), the path-free
//! opaque-ID projection ([`event_opaque_id`]/[`event_opaque_path`],
//! [`event_safe_records`]), legacy-journal normalization
//! ([`event_id_from_journal`]/[`event_path_from_journal`]), and the v8
//! dedupe-marker helpers ([`buffer_scan_event_dedupe`],
//! [`load_scan_event_dedupe`]). B11 carried the store-coupled helpers in
//! its `main.rs`; here they are library APIs so the CLI wiring (slice 5)
//! shares one implementation with these tests.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

use crate::store::{ScanEventRow, TursoStore, WriterBatch};
use crate::{config, identity, Error};

/// Scan-event stream schema version (contract D2: first supported stream is `1.0.0`).
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Merge operation for an event (contract D4: `add` | `replace` | `remove`).
///
/// `Remove` has no producer in the D4 class table yet; it is part of the
/// wire enum so consumers handle all three ops from day one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Add,
    Replace,
    Remove,
}

impl Op {
    /// Journal/wire name (`add` | `replace` | `remove`).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Op::Add => "add",
            Op::Replace => "replace",
            Op::Remove => "remove",
        }
    }
}

/// Event class (contract D4 `type` column).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ScanStarted,
    DiscoveryProgress,
    DiscoveryProgressUpdated,
    LocationFound,
    RepositoryFound,
    InventoryReady,
    BranchBatch,
    LocationUpdated,
    CoverageUpdated,
    Error,
    RemoteUpdated,
    ScanCompleted,
    ScanIncomplete,
    ScanInterrupted,
    ScanFailed,
}

impl EventType {
    /// Default [`Op`] for this class per the D4 table.
    ///
    /// `BranchBatch` returns [`Op::Add`]: [`Op::Replace`] is used only when
    /// resending a batch carrying the same per-record `rev`s (D4
    /// `add/replace` cell); callers that resend must override [`Envelope::op`]
    /// explicitly after [`Envelope::new`].
    #[must_use]
    pub fn op(&self) -> Op {
        match self {
            EventType::DiscoveryProgress
            | EventType::LocationUpdated
            | EventType::CoverageUpdated
            | EventType::RemoteUpdated => Op::Replace,
            EventType::ScanStarted
            | EventType::DiscoveryProgressUpdated
            | EventType::LocationFound
            | EventType::RepositoryFound
            | EventType::InventoryReady
            | EventType::BranchBatch
            | EventType::Error
            | EventType::ScanCompleted
            | EventType::ScanIncomplete
            | EventType::ScanInterrupted
            | EventType::ScanFailed => Op::Add,
        }
    }

    /// Journal/wire name (snake_case, matches the serde spelling).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            EventType::ScanStarted => "scan_started",
            EventType::DiscoveryProgress => "discovery_progress",
            EventType::DiscoveryProgressUpdated => "discovery_progress_updated",
            EventType::LocationFound => "location_found",
            EventType::RepositoryFound => "repository_found",
            EventType::InventoryReady => "inventory_ready",
            EventType::BranchBatch => "branch_batch",
            EventType::LocationUpdated => "location_updated",
            EventType::CoverageUpdated => "coverage_updated",
            EventType::Error => "error",
            EventType::RemoteUpdated => "remote_updated",
            EventType::ScanCompleted => "scan_completed",
            EventType::ScanIncomplete => "scan_incomplete",
            EventType::ScanInterrupted => "scan_interrupted",
            EventType::ScanFailed => "scan_failed",
        }
    }
}

/// True only for the coalesced [`EventType::DiscoveryProgress`] gauge.
/// [`EventType::DiscoveryProgressUpdated`] notifications are append-only
/// cursor advances and are not coalesced.
#[must_use]
pub fn is_progress_coalescible(t: EventType) -> bool {
    matches!(t, EventType::DiscoveryProgress)
}

/// True for the four terminal classes (contract D4): a follower stops after
/// the first one; exactly one is journaled per scan.
#[must_use]
pub fn is_terminal_event(t: EventType) -> bool {
    matches!(
        t,
        EventType::ScanCompleted
            | EventType::ScanIncomplete
            | EventType::ScanInterrupted
            | EventType::ScanFailed
    )
}

/// Name-string form of [`is_terminal_event`] for journal-prefix replay
/// (stored rows carry the event name, not the typed enum).
///
/// Consolidation: this is the canonical helper the store slice's local
/// `is_terminal_event_name` shim in `catalog.rs` mirrors; slice 5 swaps the
/// shim's call site to this function.
#[must_use]
pub fn is_terminal_name(name: &str) -> bool {
    [
        EventType::ScanCompleted,
        EventType::ScanIncomplete,
        EventType::ScanInterrupted,
        EventType::ScanFailed,
    ]
    .iter()
    .any(|t| t.name() == name)
}

/// One scan-event envelope (contract D4).
///
/// Wire shape is `{schema_version, scan_id, seq, catalog_rev, type, op,
/// records}` plus `event_offset` (journal offset inside `catalog_rev`) and
/// `reset` (true when the consumer must drop buffered state before applying
/// a complete replay). `event_type` serializes as `type`
/// per D4. Events are sent only after their Catalog transaction commits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub schema_version: String,
    pub scan_id: String,
    pub seq: u64,
    pub catalog_rev: u64,
    pub event_offset: u64,
    #[serde(rename = "type")]
    pub event_type: EventType,
    pub op: Op,
    pub reset: bool,
    pub records: serde_json::Value,
}

impl Envelope {
    /// Build an envelope, setting `schema_version` to [`SCHEMA_VERSION`] and
    /// `op` from [`EventType::op`].
    #[must_use]
    pub fn new(
        scan_id: String,
        seq: u64,
        catalog_rev: u64,
        event_offset: u64,
        event_type: EventType,
        reset: bool,
        records: serde_json::Value,
    ) -> Self {
        let op = event_type.op();
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            scan_id,
            seq,
            catalog_rev,
            event_offset,
            event_type,
            op,
            reset,
            records,
        }
    }
}

/// Legacy opaque replay cursor (contract D4, v1): scan `seq` +
/// `(catalog_rev, event offset)`.
///
/// COMPAT (consolidation slice 3): this unbound v1 shape is retained
/// unchanged so the current CLI (`main.rs`) and `tests/accept_cli.rs`
/// keep compiling and behaving exactly as before. New code uses the
/// scan-bound [`ScanCursor`]; slice 5 migrates the remaining callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub seq: u64,
    pub catalog_rev: u64,
    pub event_offset: u64,
}

impl Cursor {
    /// Encode as opaque base64url (no padding) of `v1:{seq}:{rev}:{off}`.
    #[must_use]
    pub fn encode(&self) -> String {
        let raw = format!("v1:{}:{}:{}", self.seq, self.catalog_rev, self.event_offset);
        b64url_encode(raw.as_bytes())
    }

    /// Decode a cursor produced by [`Cursor::encode`]; corrupt input yields
    /// `None` (callers then fall back to fresh snapshot + `reset:true`).
    #[must_use]
    pub fn decode(s: &str) -> Option<Self> {
        let bytes = b64url_decode(s)?;
        let raw = std::str::from_utf8(&bytes).ok()?;
        let mut parts = raw.split(':');
        match (parts.next()?, parts.next()?, parts.next()?, parts.next()?) {
            ("v1", seq, rev, off) if parts.next().is_none() => Some(Self {
                seq: seq.parse().ok()?,
                catalog_rev: rev.parse().ok()?,
                event_offset: off.parse().ok()?,
            }),
            _ => None,
        }
    }
}

/// Opaque replay cursor (contract D4/C3, v2): scan ID + `seq` +
/// `(catalog_rev, event offset)`.
///
/// Replay rules (D4/C3): a snapshot cursor is the exact end of the included
/// changes; a cursor outside retention requests a reset, which the CLI can
/// serve only when the full event prefix remains available (expired or
/// pruned prefixes fail closed, ADJ-02); duplicate delivery of the same
/// `seq` is idempotent and consumers dedupe by `seq`.
///
/// This is B11's `Cursor` ported under a distinct name so the legacy
/// unbound [`Cursor`] can keep serving the pre-consolidation CLI until
/// slice 5 migrates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanCursor {
    /// Scan that issued this cursor. `None` identifies a decoded legacy v1
    /// cursor, which is never trusted to resume a scan.
    pub scan_id: Option<String>,
    pub seq: u64,
    pub catalog_rev: u64,
    pub event_offset: u64,
}

impl ScanCursor {
    /// Create a cursor bound to one scan.
    #[must_use]
    pub fn for_scan(
        scan_id: impl Into<String>,
        seq: u64,
        catalog_rev: u64,
        event_offset: u64,
    ) -> Self {
        Self {
            scan_id: Some(scan_id.into()),
            seq,
            catalog_rev,
            event_offset,
        }
    }

    /// Encode a bound cursor as v2, or an unbound legacy cursor as v1.
    /// Both formats use opaque base64url with no padding.
    #[must_use]
    pub fn encode(&self) -> String {
        let raw = match &self.scan_id {
            Some(scan_id) => format!(
                "v2:{}:{}:{}:{}",
                b64url_encode(scan_id.as_bytes()),
                self.seq,
                self.catalog_rev,
                self.event_offset,
            ),
            None => format!("v1:{}:{}:{}", self.seq, self.catalog_rev, self.event_offset),
        };
        b64url_encode(raw.as_bytes())
    }

    /// Decode a cursor produced by [`ScanCursor::encode`]. Legacy v1 cursors
    /// remain readable but are unbound and must request a full reset.
    /// Corrupt input yields `None` so callers can report a usage error.
    #[must_use]
    pub fn decode(s: &str) -> Option<Self> {
        let bytes = b64url_decode(s)?;
        let raw = std::str::from_utf8(&bytes).ok()?;
        let mut parts = raw.split(':');
        match (
            parts.next()?,
            parts.next()?,
            parts.next()?,
            parts.next()?,
            parts.next(),
        ) {
            ("v1", seq, rev, off, None) => Some(Self {
                scan_id: None,
                seq: seq.parse().ok()?,
                catalog_rev: rev.parse().ok()?,
                event_offset: off.parse().ok()?,
            }),
            ("v2", encoded_scan_id, seq, rev, Some(off)) if parts.next().is_none() => {
                let scan_id = String::from_utf8(b64url_decode(encoded_scan_id)?).ok()?;
                if scan_id.is_empty() {
                    return None;
                }
                Some(Self {
                    scan_id: Some(scan_id),
                    seq: seq.parse().ok()?,
                    catalog_rev: rev.parse().ok()?,
                    event_offset: off.parse().ok()?,
                })
            }
            _ => None,
        }
    }
}

/// Bounded Step 12 retention: per-scan journal cap (contract D4,
/// `scan_events.rs` owns retention per D8).
///
/// The writer keeps the newest [`MAX_RETAINED_SCAN_EVENTS`] rows per scan
/// (position-based prefix prune; the tip row always survives, so a
/// finished scan's terminal event is never pruned). A cursor the retained
/// window no longer covers requests a reset. Replay fails closed when prefix
/// retention removed events needed to rebuild the full state
/// ([`classify_cursor`]).
pub const MAX_RETAINED_SCAN_EVENTS: u64 = 50_000;

/// Prune cutoff for [`MAX_RETAINED_SCAN_EVENTS`]: delete retained rows
/// with `seq <= cutoff`. Pure so the writer and tests share the rule;
/// keeps the newest `keep_rows` seqs. Callers pass `keep_rows >= 1`, so
/// the tip row always survives (a finished scan's terminal event is the
/// tip and is never pruned).
#[must_use]
pub fn retention_cutoff(tip_seq: u64, keep_rows: u64) -> u64 {
    tip_seq.saturating_sub(keep_rows.max(1))
}

/// Resume decision for an `--after` [`ScanCursor`] (contract D4, Step 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeAction {
    /// Resume strictly after the cursor's `(catalog_rev, event_offset)`
    /// position; the first delivered envelope keeps its stored flags.
    ResumeAfterCursor,
    /// The cursor points at a terminal event; the stream must stop there.
    /// A terminal cursor is never a valid point from which to resume rows.
    StopAtTerminal,
    /// Retained events no longer cover the cursor: the caller must reset
    /// from a complete state source. The CLI fails closed when prefix
    /// retention means the remaining event rows cannot rebuild that state.
    ResetSnapshot,
}

/// Classify one `--after` [`ScanCursor`] against its target scan and the
/// journaled row at its `seq` (`None` when no row carries that seq).
///
/// - An unbound legacy v1 cursor or a cursor bound to another scan →
///   [`ResumeAction::ResetSnapshot`].
/// - No row (pruned prefix, beyond-tip cursor, or empty journal) →
///   [`ResumeAction::ResetSnapshot`]: request a resync, never silently skip.
/// - Row found in the bound scan and [`is_progress_coalescible`] → `ResumeAfterCursor`: a
///   coalescible row is a gauge, never divergence — the caller resumes
///   after the *cursor's* position, so records journaled around it are
///   still delivered. (Production gauge positions are immutable, so the
///   fuzzy arm only fires on hand-mutated journals; routine ticks never
///   resync followers either way.)
/// - Row found, record class, `(rev, off)` matches → `ResumeAfterCursor`,
///   except an exact terminal row gives [`ResumeAction::StopAtTerminal`].
/// - Row found, record class, `(rev, off)` differs (same-scan corruption) →
///   `ResetSnapshot`.
#[must_use]
pub fn classify_cursor(
    cursor: &ScanCursor,
    scan_id: &str,
    found: Option<(EventType, u64, u64)>,
) -> ResumeAction {
    if cursor.scan_id.as_deref() != Some(scan_id) {
        return ResumeAction::ResetSnapshot;
    }
    match found {
        None => ResumeAction::ResetSnapshot,
        Some((event_type, _rev, _off)) if is_progress_coalescible(event_type) => {
            ResumeAction::ResumeAfterCursor
        }
        Some((event_type, rev, off))
            if is_terminal_event(event_type)
                && rev == cursor.catalog_rev
                && off == cursor.event_offset =>
        {
            ResumeAction::StopAtTerminal
        }
        Some((_event_type, rev, off))
            if rev == cursor.catalog_rev && off == cursor.event_offset =>
        {
            ResumeAction::ResumeAfterCursor
        }
        Some(_) => ResumeAction::ResetSnapshot,
    }
}

// ---------------------------------------------------------------------------
// Path-free opaque-ID projection (contract C3 privacy, ADJ-03).
// Ported from B11 `main.rs` so the emit and replay paths share one
// implementation; the JSONL event stream carries only these opaque join
// keys, never owner-local paths or catalog IDs.
// ---------------------------------------------------------------------------

/// Redacted replacement for a local target URL in event records.
pub const EVENT_REDACTED_LOCAL_TARGET: &str = "repo-scan:redacted-local-target";
/// Redacted replacement for a local target spelling in event records.
pub const EVENT_REDACTED_TARGET_SPELLING: &str = "repo-scan:redacted-target-spelling";
/// Redacted replacement for free-form diagnostic text in event records.
pub const EVENT_REDACTED_PATH_DETAIL: &str = "diagnostic details omitted for privacy";
/// Path-free `REPO_SCAN_STATE_DIR` placeholder rebuilt into `resume_cmd`.
pub const EVENT_RESUME_STATE_ARGUMENT: &str =
    "\"${REPO_SCAN_STATE_DIR:?set REPO_SCAN_STATE_DIR to this scan's state dir}\"";

/// Project path-derived catalog identifiers into stable, opaque IDs before
/// they enter the JSONL journal. Catalog/report IDs remain unchanged and
/// owner-local; event consumers treat these values as opaque join keys.
#[must_use]
pub fn event_opaque_id(value: &str) -> String {
    let mut material = b"repo-scan-event-id-v1\0".to_vec();
    material.extend_from_slice(value.as_bytes());
    format!("evt:{}", crate::report::publish::sha256_hex(&material))
}

/// Project one owner-local root path into a stable, opaque `root:` ID.
#[must_use]
pub fn event_opaque_path(path: &Path) -> String {
    let mut material = b"repo-scan-event-path-v1\0".to_vec();
    material.extend_from_slice(&config::path_as_bytes(path));
    format!("root:{}", crate::report::publish::sha256_hex(&material))
}

/// Normalize an ID read from a (possibly legacy) journal row: canonical
/// opaque IDs pass through; raw catalog IDs and malformed prefixed values
/// are hashed. Only the exact opaque-ID encoding is accepted — a malformed
/// prefixed value may still contain the original path.
#[must_use]
pub fn event_id_from_journal(value: &str) -> String {
    if has_canonical_event_hash(value, "evt:") {
        value.to_string()
    } else {
        // Old journals stored catalog IDs directly. Normalize those for
        // resume deduplication. Only accept the exact opaque-ID encoding;
        // malformed prefixed values may still contain the original path.
        event_opaque_id(value)
    }
}

/// Normalize a root path read from a (possibly legacy) journal row, same
/// rule as [`event_id_from_journal`] under the `root:` domain.
#[must_use]
pub fn event_path_from_journal(value: &str) -> String {
    if has_canonical_event_hash(value, "root:") {
        value.to_string()
    } else {
        let mut material = b"repo-scan-event-path-v1\0".to_vec();
        material.extend_from_slice(value.as_bytes());
        format!("root:{}", crate::report::publish::sha256_hex(&material))
    }
}

/// True only for the exact canonical encoding: prefix + 64 lowercase hex.
#[must_use]
pub fn has_canonical_event_hash(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// True for local-path target spellings (`file://`, absolute, relative,
/// `~`, or an existing path).
fn is_local_path_target(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.starts_with("file://") {
        return true;
    }
    if trimmed == "."
        || trimmed == ".."
        || trimmed == "~"
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with('/')
        || trimmed.starts_with("~/")
    {
        return true;
    }
    Path::new(trimmed).exists()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// A target pair may include a local checkout path even when its Git remote
/// supplies a public canonical identity. Keep that identity, but never put
/// the local spelling into the event stream.
fn event_target_spelling_needs_redaction(raw: &str, canonical: &str) -> bool {
    identity::is_local_target(raw)
        || is_local_path_target(raw)
        || identity::is_local_target(canonical)
        || is_local_path_target(canonical)
        || identity::normalize_target_input(raw).as_deref() != Some(canonical)
        // A bare `owner/repo` target is ambiguous with a relative local path
        // after its original working directory disappears. The canonical URL
        // carries the remote identity, so omit this spelling on the wire.
        || !raw.contains("://") && identity::normalize_github_url(raw).is_none()
}

fn event_safe_remote_url(value: &str) -> String {
    let value = value.trim();
    if value == EVENT_REDACTED_LOCAL_TARGET {
        value.to_string()
    } else if value
        .get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("file:"))
        || is_local_path_target(value)
    {
        EVENT_REDACTED_LOCAL_TARGET.to_string()
    } else {
        identity::redact_remote_url(value)
    }
}

/// Free-form diagnostics can contain absolute, relative, or embedded paths
/// that cannot be distinguished safely from ordinary text. Keep the event
/// contract path-free; structured category/status fields remain available.
fn event_safe_detail(_value: &str) -> String {
    EVENT_REDACTED_PATH_DETAIL.to_string()
}

/// Legacy lifecycle rows carried shell-quoted state paths in `resume_cmd`.
/// Retain a validated scan id and rebuild the command around the environment
/// variable so replay does not expose the old state directory.
fn event_safe_resume_cmd(value: &str) -> String {
    let Some((_, scan_arg)) = value.rsplit_once(" resume ") else {
        return format!(
            "repo-scan --state-dir {EVENT_RESUME_STATE_ARGUMENT} resume '<scan-id unavailable>'"
        );
    };
    let scan_id = scan_arg.trim().trim_matches('\'');
    if scan_id.is_empty()
        || !scan_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return format!(
            "repo-scan --state-dir {EVENT_RESUME_STATE_ARGUMENT} resume '<scan-id unavailable>'"
        );
    }
    format!(
        "repo-scan --state-dir {EVENT_RESUME_STATE_ARGUMENT} resume {}",
        shell_quote(scan_id)
    )
}

fn event_safe_fields(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                event_safe_fields(value);
            }
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                match key.as_str() {
                    "detail" | "error" => {
                        if let Some(text) = value.as_str() {
                            *value = serde_json::Value::String(event_safe_detail(text));
                        }
                    }
                    "resume_cmd" => {
                        if let Some(text) = value.as_str() {
                            *value = serde_json::Value::String(event_safe_resume_cmd(text));
                        }
                    }
                    "url" | "canonical_url" => {
                        if let Some(text) = value.as_str() {
                            *value = serde_json::Value::String(event_safe_remote_url(text));
                        }
                    }
                    _ => event_safe_fields(value),
                }
            }
        }
        _ => {}
    }
}

fn event_safe_targets(records: &mut serde_json::Value) {
    let Some(targets) = records
        .get_mut("targets")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for target in targets {
        let Some(object) = target.as_object_mut() else {
            continue;
        };
        let raw = object
            .get("raw")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let canonical = object
            .get("canonical")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        if event_target_spelling_needs_redaction(&raw, &canonical) {
            object.insert(
                "raw".to_string(),
                serde_json::Value::String(EVENT_REDACTED_TARGET_SPELLING.to_string()),
            );
        } else {
            object.insert(
                "raw".to_string(),
                serde_json::Value::String(identity::sanitize_target_url(&raw)),
            );
        }
        object.insert(
            "canonical".to_string(),
            serde_json::Value::String(event_safe_remote_url(&canonical)),
        );
    }
}

fn opaque_event_id_field(records: &mut serde_json::Value, key: &str) {
    if let Some(value) = records.get(key).and_then(serde_json::Value::as_str) {
        records[key] = serde_json::Value::String(event_id_from_journal(value));
    }
}

fn opaque_event_id_array(records: &mut serde_json::Value, key: &str) {
    if let Some(values) = records
        .get_mut(key)
        .and_then(serde_json::Value::as_array_mut)
    {
        for value in values {
            if let Some(id) = value.as_str() {
                *value = serde_json::Value::String(event_id_from_journal(id));
            }
        }
    }
}

/// Project one event record payload into its path-free JSONL form (C3
/// privacy, ADJ-03): catalog IDs become opaque `evt:`/`root:` join keys,
/// local paths and their reversible encodings are omitted, free-form
/// diagnostics are dropped, and local targets/`file:` remotes are
/// redacted.
///
/// Older retained journals used catalog IDs and root paths directly.
/// Sanitize at the replay boundary as well as at emit time so upgrading
/// the binary does not re-expose path encodings from existing state.
#[must_use]
pub fn event_safe_records(
    event_type: EventType,
    mut records: serde_json::Value,
) -> serde_json::Value {
    match event_type {
        EventType::RepositoryFound | EventType::BranchBatch | EventType::RemoteUpdated => {
            opaque_event_id_field(&mut records, "store_id");
            if event_type == EventType::BranchBatch {
                if let Some(branches) = records
                    .get_mut("branches")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for branch in branches {
                        opaque_event_id_field(branch, "id");
                    }
                }
            }
        }
        EventType::LocationFound | EventType::LocationUpdated => {
            opaque_event_id_field(&mut records, "checkout_id");
            opaque_event_id_field(&mut records, "store_id");
            if event_type == EventType::LocationFound {
                if let Some(object) = records.as_object_mut() {
                    for key in ["path", "path_hex", "git_path", "git_path_hex"] {
                        object.remove(key);
                    }
                }
            }
        }
        EventType::Error => {
            opaque_event_id_field(&mut records, "id");
            opaque_event_id_field(&mut records, "scope_key");
        }
        EventType::CoverageUpdated => {
            opaque_event_id_array(&mut records, "opened");
            opaque_event_id_array(&mut records, "closed");
            opaque_event_id_array(&mut records, "unresolvable_added");
        }
        EventType::ScanStarted | EventType::ScanInterrupted => {
            event_safe_targets(&mut records);
            if let Some(scope) = records.get_mut("scope") {
                opaque_event_id_field(scope, "scope_key");
                if let Some(roots) = scope
                    .get_mut("roots")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for root in roots {
                        if let Some(path) = root.as_str() {
                            *root = serde_json::Value::String(event_path_from_journal(path));
                        }
                    }
                }
            }
        }
        _ => {}
    }
    event_safe_fields(&mut records);
    records
}

// ---------------------------------------------------------------------------
// Replay machinery (contract C3: fail-closed guarded pagination, one short
// read transaction per page, closed before output). Ported from B11
// `main.rs`; slice 5 wires the CLI lanes (`query --scan`, `scan`/`resume
// --format jsonl`, follow, TUI baseline) to these entry points.
// ---------------------------------------------------------------------------

/// Build the replay envelope for one journaled row: the stored class and
/// op must parse (a corrupt journal fails closed), and the records pass
/// through the path-free projection so even legacy rows replay safely.
pub fn envelope_for_row(row: &ScanEventRow) -> crate::Result<Envelope> {
    let event_type: EventType =
        serde_json::from_value(serde_json::Value::String(row.event_type.clone())).map_err(|e| {
            Error::Report(format!(
                "scan_events row seq {} carries unknown class {:?}: {e}",
                row.seq, row.event_type,
            ))
        })?;
    let op: Op =
        serde_json::from_value(serde_json::Value::String(row.op.clone())).map_err(|e| {
            Error::Report(format!(
                "scan_events row seq {} carries unknown op {:?}: {e}",
                row.seq, row.op,
            ))
        })?;
    let records: serde_json::Value = serde_json::from_slice(&row.records).map_err(|e| {
        Error::Report(format!(
            "scan_events row seq {} carries corrupt records: {e}",
            row.seq,
        ))
    })?;
    let mut env = Envelope::new(
        row.scan_id.clone(),
        row.seq,
        row.catalog_rev,
        row.event_offset,
        event_type,
        row.reset,
        event_safe_records(event_type, records),
    );
    env.op = op;
    Ok(env)
}

/// True while the scan row can still journal more events: only the
/// `running` state (with or without the `:roots:` suffix) keeps a
/// follower waiting. Any other state — complete, incomplete,
/// interrupted, failed, superseded — ends the follow at the journal tip,
/// which also covers pre-journal scans that will never emit.
#[must_use]
pub fn scan_still_running(state: &str) -> bool {
    state == "running" || state.starts_with("running:")
}

/// Where a scan replay starts (Step 12): an optional strictly-after
/// `(catalog_rev, event_offset)` position plus whether the first
/// delivered envelope must carry `reset:true`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReplayPosition {
    pub after: Option<(u64, u64)>,
    pub reset_first: bool,
    pub terminal_seen: bool,
}

/// Resolve an `--after` cursor to its replay position (Step 12): seq 0
/// replays from the start; otherwise the row at the cursor's seq
/// classifies via [`classify_cursor`] — same-scan covered cursors resume
/// strictly after the cursor's `(rev, off)` position. Foreign and unbound
/// legacy cursors request a reset from the beginning; the replay loop
/// then fails closed if retention removed any prefix, since the retained
/// rows cannot restore a full inventory. Corrupt (undecodable) cursors
/// stay a usage error.
pub async fn resolve_after_cursor(
    store: &TursoStore,
    scan_id: &str,
    after: &str,
) -> crate::Result<ReplayPosition> {
    let Some(cursor) = ScanCursor::decode(after) else {
        return Err(Error::InvalidArgs(format!(
            "corrupt --after cursor for scan {scan_id}; replay from the start instead"
        )));
    };
    if cursor.scan_id.as_deref() != Some(scan_id) {
        return Ok(ReplayPosition {
            after: None,
            reset_first: true,
            terminal_seen: false,
        });
    }
    if cursor.seq == 0 {
        return Ok(ReplayPosition {
            after: None,
            reset_first: false,
            terminal_seen: false,
        });
    }
    let Ok(seq_i64) = i64::try_from(cursor.seq) else {
        return Ok(ReplayPosition {
            after: None,
            reset_first: true,
            terminal_seen: false,
        });
    };
    let mut rows = store
        .connection()
        .query(
            "SELECT event_type, catalog_rev, event_offset FROM scan_events \
                WHERE scan_id = ?1 AND seq = ?2",
            vec![
                turso::Value::Text(scan_id.to_string()),
                turso::Value::Integer(seq_i64),
            ],
        )
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    let found = match rows.next().await.map_err(|e| Error::Store(e.to_string()))? {
        None => None,
        Some(row) => {
            let event_type: EventType = serde_json::from_value(serde_json::Value::String(
                cell_text(&row, 0)?,
            ))
            .map_err(|e| {
                Error::Report(format!(
                    "scan_events row seq {} carries unknown class: {e}",
                    cursor.seq,
                ))
            })?;
            let rev = cell_int(&row, 1)?;
            let off = cell_int(&row, 2)?;
            Some((
                event_type,
                u64::try_from(rev).map_err(|_| {
                    Error::Store(format!(
                        "event catalog_rev {rev} in catalog is not a valid u64"
                    ))
                })?,
                u64::try_from(off).map_err(|_| {
                    Error::Store(format!("event offset {off} in catalog is not a valid u64"))
                })?,
            ))
        }
    };
    match classify_cursor(&cursor, scan_id, found) {
        ResumeAction::ResumeAfterCursor => Ok(ReplayPosition {
            after: Some((cursor.catalog_rev, cursor.event_offset)),
            reset_first: false,
            terminal_seen: false,
        }),
        ResumeAction::StopAtTerminal => Ok(ReplayPosition {
            after: Some((cursor.catalog_rev, cursor.event_offset)),
            reset_first: false,
            terminal_seen: true,
        }),
        ResumeAction::ResetSnapshot => Ok(ReplayPosition {
            after: None,
            reset_first: true,
            terminal_seen: false,
        }),
    }
}

/// Whether a scan's retained event window starts after the first sequence.
pub async fn scan_event_prefix_pruned_before(
    store: &TursoStore,
    scan_id: &str,
    after: Option<(u64, u64)>,
) -> crate::Result<bool> {
    let rows = store.read_scan_events(scan_id, 0, 1).await?;
    let Some(first) = rows.first() else {
        return Ok(false);
    };
    if first.seq <= 1 {
        return Ok(false);
    }
    Ok(after.is_none_or(|position| position < (first.catalog_rev, first.event_offset)))
}

/// One guarded replay page: either the retained rows, or the fail-closed
/// verdict that prefix retention removed rows the reader needs (ADJ-02).
#[derive(Debug)]
pub enum GuardedScanEventPage {
    Pruned,
    Rows(Vec<ScanEventRow>),
}

/// Read one event page with its retention check in a single read-only
/// transaction. The transaction is rolled back before returning, including
/// when either query fails; callers can then render, write, or wait without
/// retaining a database snapshot.
pub async fn read_guarded_scan_event_page(
    store: &TursoStore,
    scan_id: &str,
    after: Option<(u64, u64)>,
    limit: u64,
) -> crate::Result<GuardedScanEventPage> {
    read_guarded_scan_event_page_with_hook(store, scan_id, after, limit, || async { Ok(()) }).await
}

/// [`read_guarded_scan_event_page`] with a hook that runs inside the
/// pinned read transaction between the prefix guard and the page read —
/// the test seam proving the guard and the read share one snapshot.
pub async fn read_guarded_scan_event_page_with_hook<F, Fut>(
    store: &TursoStore,
    scan_id: &str,
    after: Option<(u64, u64)>,
    limit: u64,
    after_guard: F,
) -> crate::Result<GuardedScanEventPage>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = crate::Result<()>>,
{
    let connection = store.connection();
    connection
        .execute("BEGIN", ())
        .await
        .map_err(|error| Error::Store(error.to_string()))?;

    let result = async {
        if scan_event_prefix_pruned_before(store, scan_id, after).await? {
            return Ok(GuardedScanEventPage::Pruned);
        }
        after_guard().await?;
        let rows = read_scan_events_after_position(store, scan_id, after, limit).await?;
        Ok(GuardedScanEventPage::Rows(rows))
    }
    .await;

    let rollback = connection.execute("ROLLBACK", ()).await;
    match (result, rollback) {
        (Ok(page), Ok(_)) => {
            if !connection
                .is_autocommit()
                .map_err(|error| Error::Store(error.to_string()))?
            {
                return Err(Error::Store(
                    "read-only event page left its connection inside a transaction".to_string(),
                ));
            }
            Ok(page)
        }
        (Err(error), Ok(_)) => {
            if !connection
                .is_autocommit()
                .map_err(|rollback_error| Error::Store(rollback_error.to_string()))?
            {
                return Err(Error::Store(format!(
                    "{error}; read-only event page rollback left its connection inside a transaction"
                )));
            }
            Err(error)
        }
        (result, Err(rollback_error)) => {
            let rollback_error = rollback_error.to_string();
            match result {
                Ok(_) => Err(Error::Store(format!(
                    "cannot roll back read-only event page transaction: {rollback_error}"
                ))),
                Err(error) => Err(Error::Store(format!(
                    "{error}; cannot roll back read-only event page transaction: {rollback_error}"
                ))),
            }
        }
    }
}

/// Parse one `scan_events` row (same column order and range checks as
/// the store reader: negative seq/rev/off are catalog corruption).
fn scan_event_row_from_cells(row: &turso::Row) -> crate::Result<ScanEventRow> {
    let seq = cell_int(row, 1)?;
    let rev = cell_int(row, 2)?;
    let off = cell_int(row, 3)?;
    Ok(ScanEventRow {
        scan_id: cell_text(row, 0)?,
        seq: u64::try_from(seq)
            .map_err(|_| Error::Store(format!("event seq {seq} in catalog is not a valid u64")))?,
        catalog_rev: u64::try_from(rev).map_err(|_| {
            Error::Store(format!(
                "event catalog_rev {rev} in catalog is not a valid u64"
            ))
        })?,
        event_offset: u64::try_from(off).map_err(|_| {
            Error::Store(format!("event offset {off} in catalog is not a valid u64"))
        })?,
        event_type: cell_text(row, 4)?,
        op: cell_text(row, 5)?,
        reset: cell_int(row, 6)? != 0,
        records: cell_blob(row, 7)?,
    })
}

/// Replay journal rows for a scan in `(catalog_rev, event_offset)` order
/// (served by `idx_scan_events_cursor`), optionally strictly after one
/// position, oldest first, capped at `limit` rows (clamped to
/// `[1, 10_000]`, mirroring `TursoStore::read_scan_events`).
pub async fn read_scan_events_after_position(
    store: &TursoStore,
    scan_id: &str,
    after: Option<(u64, u64)>,
    limit: u64,
) -> crate::Result<Vec<ScanEventRow>> {
    // The coalesced gauge sits at its first cursor while its stored payload
    // advances in place. Project that current payload onto every later
    // notification during replay so a full replay cannot show the newest
    // gauge followed by older tick snapshots.
    const COLUMNS: &str = "e.scan_id, e.seq, e.catalog_rev, e.event_offset, e.event_type, \
        e.op, e.reset, CASE WHEN e.event_type = 'discovery_progress_updated' THEN \
        COALESCE((SELECT g.records FROM scan_events AS g WHERE g.scan_id = e.scan_id \
            AND g.event_type = 'discovery_progress' ORDER BY g.seq DESC LIMIT 1), e.records) \
        ELSE e.records END AS records";
    let limit_i64 = i64::try_from(limit.clamp(1, 10_000))
        .map_err(|_| Error::Store(format!("event limit {limit} exceeds i64 range")))?;
    let (sql, params) = match after {
        None => (
            format!(
                "SELECT {COLUMNS} FROM scan_events AS e WHERE e.scan_id = ?1 \
                ORDER BY e.catalog_rev ASC, e.event_offset ASC LIMIT ?2"
            ),
            vec![
                turso::Value::Text(scan_id.to_string()),
                turso::Value::Integer(limit_i64),
            ],
        ),
        Some((rev, off)) => {
            let rev_i64 = i64::try_from(rev)
                .map_err(|_| Error::Store(format!("event catalog_rev {rev} exceeds i64 range")))?;
            let off_i64 = i64::try_from(off)
                .map_err(|_| Error::Store(format!("event offset {off} exceeds i64 range")))?;
            (
                format!(
                    "SELECT {COLUMNS} FROM scan_events AS e WHERE e.scan_id = ?1 \
                    AND (e.catalog_rev > ?2 OR (e.catalog_rev = ?2 AND e.event_offset > ?3)) \
                    ORDER BY e.catalog_rev ASC, e.event_offset ASC LIMIT ?4"
                ),
                vec![
                    turso::Value::Text(scan_id.to_string()),
                    turso::Value::Integer(rev_i64),
                    turso::Value::Integer(off_i64),
                    turso::Value::Integer(limit_i64),
                ],
            )
        }
    };
    let mut rows = store
        .connection()
        .query(sql.as_str(), params)
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(|e| Error::Store(e.to_string()))? {
        out.push(scan_event_row_from_cells(&row)?);
    }
    Ok(out)
}

/// Retained rows for one scan (Step 12 retention confirm).
pub async fn scan_event_count(store: &TursoStore, scan_id: &str) -> crate::Result<u64> {
    let mut rows = store
        .connection()
        .query(
            "SELECT COUNT(*) FROM scan_events WHERE scan_id = ?1",
            vec![turso::Value::Text(scan_id.to_string())],
        )
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    let Some(row) = rows.next().await.map_err(|e| Error::Store(e.to_string()))? else {
        return Err(Error::Store("COUNT(*) returned no row".to_string()));
    };
    let count = cell_int(&row, 0)?;
    u64::try_from(count)
        .map_err(|_| Error::Store(format!("event count {count} is not a valid u64")))
}

/// Delete one scan's journal prefix through `cutoff` (inclusive) in one
/// transaction. Position-based: everything at or below the cutoff goes,
/// so the retained window stays a contiguous `[cutoff+1..=tip]` and the
/// tip (a finished scan's terminal event) always survives.
pub async fn prune_scan_events_through(
    store: &TursoStore,
    scan_id: &str,
    cutoff: u64,
) -> crate::Result<()> {
    let cutoff_i64 = i64::try_from(cutoff)
        .map_err(|_| Error::Store(format!("prune cutoff {cutoff} exceeds i64 range")))?;
    store
        .connection()
        .execute(
            "DELETE FROM scan_events WHERE scan_id = ?1 AND seq <= ?2",
            vec![
                turso::Value::Text(scan_id.to_string()),
                turso::Value::Integer(cutoff_i64),
            ],
        )
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// v8 durable dedupe markers (contract C3): per-record event identities
// persist outside the journal so retention pruning cannot erase them;
// they are released only by the atomic terminal cleanup in
// `TursoStore::append_terminal_scan_event` (scan-final) or by
// supersession.
// ---------------------------------------------------------------------------

/// Persist an event-identity marker in the same writer transaction as its
/// event row. The marker table is not subject to journal prefix retention.
/// Returns [`WriterBatch::should_flush`].
pub fn buffer_scan_event_dedupe(
    batch: &mut WriterBatch,
    scan_id: &str,
    kind: &str,
    id: &str,
) -> bool {
    batch.push(
        "INSERT OR IGNORE INTO scan_event_dedupe (scan_id, dedupe_kind, event_id) \
            VALUES (?1, ?2, ?3)",
        vec![
            turso::Value::Text(scan_id.to_string()),
            turso::Value::Text(kind.to_string()),
            turso::Value::Text(event_id_from_journal(id)),
        ],
    )
}

/// Read persistent dedupe keys and backfill keys still present in retained
/// legacy rows before a later prune can remove those rows.
///
/// A catalog upgraded after its prefix was already pruned has no way to
/// recover the lost found IDs: hydration fails closed rather than resuming
/// into duplicate `add` events. New v8 journals and legacy journals with an
/// intact prefix are safe to mark ready after backfill.
pub async fn load_scan_event_dedupe(
    store: &TursoStore,
    scan_id: &str,
    full_prefix_available: bool,
    sets: &mut [(&str, &mut HashSet<String>)],
) -> crate::Result<()> {
    let mut persisted = HashSet::new();
    let mut ready = false;
    let mut rows = store
        .connection()
        .query(
            "SELECT dedupe_kind, event_id FROM scan_event_dedupe WHERE scan_id = ?1",
            vec![turso::Value::Text(scan_id.to_string())],
        )
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    while let Some(row) = rows.next().await.map_err(|e| Error::Store(e.to_string()))? {
        let kind = cell_text(&row, 0)?;
        let raw_id = cell_text(&row, 1)?;
        if kind == "state" && raw_id == "v8" {
            ready = true;
            continue;
        }
        let id = event_id_from_journal(&raw_id);
        persisted.insert((kind.clone(), id.clone()));
        if let Some((_, set)) = sets.iter_mut().find(|(known, _)| *known == kind.as_str()) {
            set.insert(id);
        }
    }
    drop(rows);

    if !ready && !full_prefix_available {
        return Err(Error::Report(format!(
            "scan {scan_id} predates durable event dedupe and already has a pruned prefix; resume is unsafe"
        )));
    }

    // Rows from catalogs upgraded to v8 may have no side markers yet. Seed
    // the retained keys before the next prefix prune can erase their source.
    for (kind, set) in sets {
        for id in set.iter() {
            if persisted.contains(&((*kind).to_string(), id.clone())) {
                continue;
            }
            store
                .connection()
                .execute(
                    "INSERT OR IGNORE INTO scan_event_dedupe \
                        (scan_id, dedupe_kind, event_id) VALUES (?1, ?2, ?3)",
                    vec![
                        turso::Value::Text(scan_id.to_string()),
                        turso::Value::Text((*kind).to_string()),
                        turso::Value::Text(id.clone()),
                    ],
                )
                .await
                .map_err(|e| Error::Store(e.to_string()))?;
        }
    }
    if !ready {
        store
            .connection()
            .execute(
                "INSERT OR IGNORE INTO scan_event_dedupe \
                    (scan_id, dedupe_kind, event_id) VALUES (?1, 'state', 'v8')",
                vec![turso::Value::Text(scan_id.to_string())],
            )
            .await
            .map_err(|e| Error::Store(e.to_string()))?;
    }
    Ok(())
}

fn cell_text(row: &turso::Row, idx: usize) -> crate::Result<String> {
    match row
        .get_value(idx)
        .map_err(|e| Error::Store(e.to_string()))?
    {
        turso::Value::Text(value) => Ok(value),
        other => Err(Error::Store(format!(
            "column {idx} expected TEXT, got {other:?}"
        ))),
    }
}

fn cell_int(row: &turso::Row, idx: usize) -> crate::Result<i64> {
    match row
        .get_value(idx)
        .map_err(|e| Error::Store(e.to_string()))?
    {
        turso::Value::Integer(value) => Ok(value),
        other => Err(Error::Store(format!(
            "column {idx} expected INTEGER, got {other:?}"
        ))),
    }
}

fn cell_blob(row: &turso::Row, idx: usize) -> crate::Result<Vec<u8>> {
    match row
        .get_value(idx)
        .map_err(|e| Error::Store(e.to_string()))?
    {
        turso::Value::Blob(value) => Ok(value),
        other => Err(Error::Store(format!(
            "column {idx} expected BLOB, got {other:?}"
        ))),
    }
}

const B64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Minimal base64url encoder (RFC 4648 §5), no padding, no new deps.
fn b64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL_ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(B64URL_ALPHABET[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL_ALPHABET[(n >> 6 & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL_ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

/// Minimal base64url decoder; accepts unpadded input (and padded input by
/// stripping `=`). Returns `None` on any corrupt character or length.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('=');
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16 & 0xff) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8 & 0xff) as u8);
        }
        if chunk.len() > 3 {
            out.push((n & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_TYPES: [(EventType, Op, &str); 15] = [
        (EventType::ScanStarted, Op::Add, "scan_started"),
        (
            EventType::DiscoveryProgress,
            Op::Replace,
            "discovery_progress",
        ),
        (
            EventType::DiscoveryProgressUpdated,
            Op::Add,
            "discovery_progress_updated",
        ),
        (EventType::LocationFound, Op::Add, "location_found"),
        (EventType::RepositoryFound, Op::Add, "repository_found"),
        (EventType::InventoryReady, Op::Add, "inventory_ready"),
        (EventType::BranchBatch, Op::Add, "branch_batch"),
        (EventType::LocationUpdated, Op::Replace, "location_updated"),
        (EventType::CoverageUpdated, Op::Replace, "coverage_updated"),
        (EventType::Error, Op::Add, "error"),
        (EventType::RemoteUpdated, Op::Replace, "remote_updated"),
        (EventType::ScanCompleted, Op::Add, "scan_completed"),
        (EventType::ScanIncomplete, Op::Add, "scan_incomplete"),
        (EventType::ScanInterrupted, Op::Add, "scan_interrupted"),
        (EventType::ScanFailed, Op::Add, "scan_failed"),
    ];

    #[test]
    fn op_mapping_matches_d4_table() {
        for (t, expected_op, _) in ALL_TYPES {
            assert_eq!(t.op(), expected_op, "op for {t:?}");
        }
    }

    #[test]
    fn event_type_serde_names_are_snake_case() {
        for (t, _, name) in ALL_TYPES {
            let v = serde_json::to_value(t).unwrap();
            assert_eq!(v, serde_json::Value::String(name.to_string()), "{t:?}");
            assert_eq!(t.name(), name, "journal name for {t:?}");
            let back: EventType = serde_json::from_value(v).unwrap();
            assert_eq!(back, t);
        }
        assert_eq!(Op::Add.name(), "add");
        assert_eq!(Op::Replace.name(), "replace");
        assert_eq!(Op::Remove.name(), "remove");
    }

    #[test]
    fn envelope_round_trip_per_variant() {
        for (t, expected_op, _) in ALL_TYPES {
            let env = Envelope::new(
                "scan-1".to_string(),
                7,
                42,
                3,
                t,
                false,
                serde_json::json!([{"id": "r1"}]),
            );
            assert_eq!(env.schema_version, SCHEMA_VERSION);
            assert_eq!(env.op, expected_op);
            let json = serde_json::to_value(&env).unwrap();
            assert_eq!(json["type"], serde_json::to_value(t).unwrap());
            assert_eq!(json["schema_version"], "1.0.0");
            let back: Envelope = serde_json::from_value(json).unwrap();
            assert_eq!(back.event_type, t);
            assert_eq!(back.op, expected_op);
            assert_eq!(back.seq, 7);
            assert_eq!(back.catalog_rev, 42);
            assert_eq!(back.event_offset, 3);
        }
    }

    #[test]
    fn envelope_reset_flag_round_trips() {
        let env = Envelope::new(
            "s".to_string(),
            0,
            0,
            0,
            EventType::ScanStarted,
            true,
            serde_json::Value::Null,
        );
        assert!(env.reset);
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&env).unwrap()).unwrap();
        assert!(back.reset);
    }

    #[test]
    fn coalescible_only_discovery_progress() {
        for (t, _, _) in ALL_TYPES {
            assert_eq!(
                is_progress_coalescible(t),
                t == EventType::DiscoveryProgress,
                "{t:?}"
            );
        }
    }

    #[test]
    fn terminal_only_four_completed_variants() {
        for (t, _, name) in ALL_TYPES {
            let terminal = matches!(
                t,
                EventType::ScanCompleted
                    | EventType::ScanIncomplete
                    | EventType::ScanInterrupted
                    | EventType::ScanFailed
            );
            assert_eq!(is_terminal_event(t), terminal, "{t:?}");
            assert_eq!(is_terminal_name(name), terminal, "{name}");
        }
    }

    #[test]
    fn legacy_cursor_encode_decode_round_trip() {
        for c in [
            Cursor {
                seq: 0,
                catalog_rev: 0,
                event_offset: 0,
            },
            Cursor {
                seq: 1,
                catalog_rev: 2,
                event_offset: 3,
            },
            Cursor {
                seq: u64::MAX,
                catalog_rev: u64::MAX,
                event_offset: u64::MAX,
            },
        ] {
            let s = c.encode();
            assert_eq!(Cursor::decode(&s), Some(c), "{s}");
        }
    }

    #[test]
    fn legacy_cursor_corrupt_input_is_none() {
        for bad in [
            "",
            "!!!",
            "v1:1:2:3",                                     // raw, not base64url
            &b64url_encode(b"v2:1:2:3"),                    // wrong version tag
            &b64url_encode(b"v1:1:2"),                      // missing field
            &b64url_encode(b"v1:1:2:3:4"),                  // extra field
            &b64url_encode(b"v1:x:2:3"),                    // non-numeric
            &b64url_encode(b"v1:1:2:18446744073709551616"), // u64 overflow
        ] {
            assert_eq!(Cursor::decode(bad), None, "{bad}");
        }
        // Truncated / bad-length base64url.
        let mut s = Cursor {
            seq: 9,
            catalog_rev: 9,
            event_offset: 9,
        }
        .encode();
        s.pop();
        if s.len() % 4 != 1 {
            s.pop();
        }
        assert!(s.len() % 4 == 1 || Cursor::decode(&s).is_none());
        let bad_len = "abcde"; // len % 4 == 1 is unrepresentable
        assert_eq!(Cursor::decode(bad_len), None);
    }

    #[test]
    fn scan_cursor_encode_decode_round_trip() {
        for c in [
            ScanCursor::for_scan("scan-1", 0, 0, 0),
            ScanCursor::for_scan("scan-1", 1, 2, 3),
            ScanCursor::for_scan("scan-1", u64::MAX, u64::MAX, u64::MAX),
        ] {
            let s = c.encode();
            assert_eq!(ScanCursor::decode(&s), Some(c), "{s}");
        }

        let legacy = ScanCursor {
            scan_id: None,
            seq: 7,
            catalog_rev: 3,
            event_offset: 4,
        };
        let encoded = legacy.encode();
        assert_eq!(ScanCursor::decode(&encoded), Some(legacy));
        assert!(ScanCursor::decode(&encoded)
            .expect("legacy v1 cursor")
            .scan_id
            .is_none());
    }

    #[test]
    fn scan_cursor_corrupt_input_is_none() {
        for bad in [
            "",
            "!!!",
            "v1:1:2:3",                                     // raw, not base64url
            &b64url_encode(b"v3:1:2:3"),                    // wrong version tag
            &b64url_encode(b"v1:1:2"),                      // missing field
            &b64url_encode(b"v1:1:2:3:4"),                  // extra field
            &b64url_encode(b"v1:x:2:3"),                    // non-numeric
            &b64url_encode(b"v1:1:2:18446744073709551616"), // u64 overflow
            &b64url_encode(b"v2::1:2:3"),                   // empty scan ID
            &b64url_encode(b"v2:!:1:2:3"),                  // bad scan ID encoding
            &b64url_encode(b"v2:c2Nhbi0x:x:2:3"),           // non-numeric
        ] {
            assert_eq!(ScanCursor::decode(bad), None, "{bad}");
        }
        // Truncated / bad-length base64url.
        let mut s = ScanCursor::for_scan("scan-1", 9, 9, 9).encode();
        s.pop();
        if s.len() % 4 != 1 {
            s.pop();
        }
        assert!(s.len() % 4 == 1 || ScanCursor::decode(&s).is_none());
        let bad_len = "abcde"; // len % 4 == 1 is unrepresentable
        assert_eq!(ScanCursor::decode(bad_len), None);
    }

    #[test]
    fn retention_cutoff_keeps_newest_and_tip() {
        assert_eq!(retention_cutoff(100, 20), 80);
        assert_eq!(retention_cutoff(20, 20), 0);
        // Under the bound nothing prunes; keep clamps to >= 1 so the
        // tip always survives even a degenerate bound.
        assert_eq!(retention_cutoff(5, 50_000), 0);
        assert_eq!(retention_cutoff(100, 0), 99);
        const {
            assert!(MAX_RETAINED_SCAN_EVENTS > 0);
        }
    }

    #[test]
    fn classify_cursor_matrix() {
        let cursor = ScanCursor::for_scan("scan-1", 7, 3, 4);
        // Missing row (pruned prefix, beyond tip, empty journal): reset.
        assert_eq!(
            classify_cursor(&cursor, "scan-1", None),
            ResumeAction::ResetSnapshot
        );
        // Record row, position matches: resume.
        assert_eq!(
            classify_cursor(&cursor, "scan-1", Some((EventType::LocationFound, 3, 4))),
            ResumeAction::ResumeAfterCursor
        );
        // Record row, position differs (foreign cursor/corruption): reset.
        assert_eq!(
            classify_cursor(&cursor, "scan-1", Some((EventType::LocationFound, 3, 5))),
            ResumeAction::ResetSnapshot
        );
        assert_eq!(
            classify_cursor(&cursor, "scan-1", Some((EventType::LocationFound, 9, 4))),
            ResumeAction::ResetSnapshot
        );
        // Coalescible gauge: resume even when its position drifted
        // (seq-reuse coalescing moves it); the caller resumes after the
        // cursor's own position so nothing between is skipped.
        assert_eq!(
            classify_cursor(
                &cursor,
                "scan-1",
                Some((EventType::DiscoveryProgress, 3, 4))
            ),
            ResumeAction::ResumeAfterCursor
        );
        assert_eq!(
            classify_cursor(
                &cursor,
                "scan-1",
                Some((EventType::DiscoveryProgress, 9, 9))
            ),
            ResumeAction::ResumeAfterCursor
        );
        assert_eq!(
            classify_cursor(&cursor, "scan-1", Some((EventType::ScanCompleted, 3, 4))),
            ResumeAction::StopAtTerminal
        );
        assert_eq!(
            classify_cursor(&cursor, "scan-1", Some((EventType::ScanCompleted, 3, 5))),
            ResumeAction::ResetSnapshot
        );
        assert_eq!(
            classify_cursor(&cursor, "scan-1", Some((EventType::ScanCompleted, 9, 4))),
            ResumeAction::ResetSnapshot
        );

        let foreign = ScanCursor::for_scan("scan-foreign", 7, 3, 4);
        assert_eq!(
            classify_cursor(
                &foreign,
                "scan-1",
                Some((EventType::DiscoveryProgress, 3, 4))
            ),
            ResumeAction::ResetSnapshot,
            "scan binding applies even when every position field collides"
        );
        let legacy = ScanCursor {
            scan_id: None,
            seq: cursor.seq,
            catalog_rev: cursor.catalog_rev,
            event_offset: cursor.event_offset,
        };
        assert_eq!(
            classify_cursor(
                &legacy,
                "scan-1",
                Some((EventType::DiscoveryProgress, 3, 4))
            ),
            ResumeAction::ResetSnapshot,
            "v1 cursors lack a trustworthy scan binding"
        );
    }

    #[test]
    fn opaque_projection_is_domain_separated_and_stable() {
        let id = event_opaque_id("store:hex");
        assert!(id.starts_with("evt:"), "{id}");
        assert!(has_canonical_event_hash(&id, "evt:"), "{id}");
        assert_eq!(id, event_opaque_id("store:hex"), "stable");
        assert_ne!(id, event_opaque_id("store:heY"));
        // Same input under the path domain differs (domain separation).
        let path = Path::new("/nonexistent-slice3-probe");
        let root = event_opaque_path(path);
        assert!(root.starts_with("root:"), "{root}");
        assert!(has_canonical_event_hash(&root, "root:"), "{root}");
        assert_ne!(id, root);
        // Journal normalization: canonical passes through; raw and
        // malformed-prefixed values are hashed.
        assert_eq!(event_id_from_journal(&id), id);
        assert_eq!(event_path_from_journal(&root), root);
        assert_eq!(event_id_from_journal("store:hex"), id);
        let malformed = format!("evt:{id}");
        assert_eq!(
            event_id_from_journal(&malformed),
            event_opaque_id(&malformed)
        );
        assert!(!has_canonical_event_hash("evt:ABC", "evt:"));
        assert!(!has_canonical_event_hash(&id[1..], "evt:"));
    }

    #[test]
    fn base64url_vectors() {
        // RFC 4648 §10 vectors (identical in the url alphabet).
        let vectors = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ];
        for (raw, enc) in vectors {
            assert_eq!(b64url_encode(raw.as_bytes()), enc, "{raw:?}");
            assert_eq!(b64url_decode(enc).unwrap(), raw.as_bytes(), "{enc}");
        }
        // URL alphabet differs from std in the last two chars: 0xfb 0xff
        // is "+/==" in std, "-w==" → unpadded "-w" here.
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url_decode("-_8").unwrap(), vec![0xfb, 0xff]);
        // Padded input tolerated.
        assert_eq!(b64url_decode("Zg==").unwrap(), b"f");
        // Corrupt alphabet rejected.
        assert_eq!(b64url_decode("Zg+/"), None);
        assert_eq!(b64url_decode("a"), None);
    }
}
