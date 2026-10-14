//! Catalog migration v8: preserve scan-event dedupe keys outside the
//! prefix-pruned event journal.

/// Schema version 8 SQL: dedupe markers survive event retention.
pub const V8_SQL: &str = "
CREATE TABLE IF NOT EXISTS scan_event_dedupe (
    scan_id TEXT NOT NULL,
    dedupe_kind TEXT NOT NULL,
    event_id TEXT NOT NULL,
    PRIMARY KEY (scan_id, dedupe_kind, event_id)
);
";

/// Version marker for migration v8.
pub struct V8Marker;

impl V8Marker {
    /// 1-based schema version this migration produces.
    pub const VERSION: u32 = 8;
    /// Human-readable description, mirroring the append-only chain.
    pub const DESCRIPTION: &str = "v8: durable scan-event dedupe keys across retention";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_scan_event_dedupe_table() {
        assert!(V8_SQL.contains("CREATE TABLE IF NOT EXISTS scan_event_dedupe"));
        assert!(V8_SQL.contains("PRIMARY KEY (scan_id, dedupe_kind, event_id)"));
        assert_eq!(V8Marker::VERSION, 8);
    }
}
