//! Scan-event stream envelope, classes, ops, and cursor (contract D4).
//!
//! Implements `docs/GOAL_CONTRACTS.md` §D4: one JSONL envelope per event,
//! per-class [`Op`] mapping, and the opaque replay [`Cursor`].
//!
//! Record IDs referenced by event payloads follow D1
//! ([`crate::report::model`]); `scan_id` is the [`crate::model::ScanId`]
//! request identifier rendered as a string.

use serde::{Deserialize, Serialize};

/// Scan-event stream schema version (contract D2: NEW stream is `1.0.0`).
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

/// True only for [`EventType::DiscoveryProgress`] (contract D4: progress
/// events coalesce to newest per scan; record/error events are never
/// silently dropped).
#[must_use]
pub fn is_progress_coalescible(t: EventType) -> bool {
    matches!(t, EventType::DiscoveryProgress)
}

/// One scan-event envelope (contract D4).
///
/// Wire shape is `{schema_version, scan_id, seq, catalog_rev, type, op,
/// records}` plus `event_offset` (journal offset inside `catalog_rev`) and
/// `reset` (true when the consumer must drop buffered state, e.g. cursor
/// outside retention → fresh snapshot). `event_type` serializes as `type`
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

/// Opaque replay cursor (contract D4): scan `seq` + `(catalog_rev,
/// event offset)`.
///
/// Replay rules (D4): a snapshot cursor is the exact end of the included
/// changes; a cursor outside retention yields a fresh snapshot with
/// `reset:true`; duplicate delivery of the same `seq` is idempotent and
/// consumers dedupe by `seq`.
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

    const ALL_TYPES: [(EventType, Op, &str); 14] = [
        (EventType::ScanStarted, Op::Add, "scan_started"),
        (
            EventType::DiscoveryProgress,
            Op::Replace,
            "discovery_progress",
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
    fn cursor_encode_decode_round_trip() {
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
    fn cursor_corrupt_input_is_none() {
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
