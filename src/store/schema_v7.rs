//! Catalog migration v7: preserve the `inventory_ready` lifecycle milestone
//! across bounded scan-event journal retention.

/// Schema version 7 SQL: the committed sequence is durable scan metadata,
/// separate from the prunable event prefix.
pub const V7_SQL: &str = "
ALTER TABLE scan_requests ADD COLUMN inventory_ready_seq INTEGER;
";

/// Version marker for migration v7.
pub struct V7Marker;

impl V7Marker {
    /// 1-based schema version this migration produces.
    pub const VERSION: u32 = 7;
    /// Human-readable description.
    pub const DESCRIPTION: &str = "v7: durable scan_requests.inventory_ready_seq";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_nullable_ready_sequence() {
        assert_eq!(
            V7_SQL
                .matches("ADD COLUMN inventory_ready_seq INTEGER")
                .count(),
            1
        );
        assert_eq!(V7Marker::VERSION, 7);
        assert!(V7Marker::DESCRIPTION.starts_with("v7:"));
    }
}
