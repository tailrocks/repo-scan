//! Catalog migration v4: saved `--workers` (goal Step 8).
//!
//! `scan_requests.workers` persists the explicit worker request (`NULL` =
//! legacy row or flag absent: the effective count resolves at runtime via
//! [`crate::config::effective_workers`]); resume restores it.
//!
//! v1 storage rules (see `schema.rs`) apply unchanged: plain rowid tables
//! (no `WITHOUT ROWID`), no recursive CTEs, no FTS, every raw
//! path/component/ref-name/URL in a `BLOB` column, and no index key
//! contains a `BLOB` column.
//!
//! Wiring (a `Migration` chain entry plus the `CURRENT_SCHEMA_VERSION`
//! bump) belongs to the coordinator: [`V4Marker::VERSION`] and
//! [`V4Marker::DESCRIPTION`] carry the values.

/// Schema version 4 SQL: additive Step 8 column.
///
/// * `scan_requests.workers` is nullable; `NULL` = legacy row or flag
///   absent, resolved at runtime.
pub const V4_SQL: &str = "
ALTER TABLE scan_requests ADD COLUMN workers INTEGER;
";

/// Version marker for migration v4; the coordinator wires these into
/// the append-only [`crate::store::Migration`] chain.
pub struct V4Marker;

impl V4Marker {
    /// 1-based schema version this migration produces.
    pub const VERSION: u32 = 4;
    /// Human-readable description, mirroring the v1 `MIGRATIONS` style.
    pub const DESCRIPTION: &str = "v4: saved scan_requests.workers";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_nullable_workers_column() {
        assert_eq!(
            V4_SQL.matches("ADD COLUMN workers INTEGER").count(),
            1,
            "{V4_SQL}"
        );
    }

    #[test]
    fn plain_rowid_tables_only() {
        assert!(
            !V4_SQL.to_ascii_uppercase().contains("WITHOUT ROWID"),
            "v1 rule: plain rowid tables only"
        );
    }

    #[test]
    fn no_index_key_contains_blob() {
        for stmt in V4_SQL.split(';') {
            let upper = stmt.to_ascii_uppercase();
            if !upper.contains("CREATE") || !upper.contains("INDEX") {
                continue;
            }
            if upper.contains("PRIMARY KEY") {
                continue;
            }
            panic!("v4 adds no indexes: {stmt}");
        }
    }

    #[test]
    fn marker_matches_v4() {
        assert_eq!(V4Marker::VERSION, 4);
        assert!(V4Marker::DESCRIPTION.starts_with("v4:"));
    }
}
