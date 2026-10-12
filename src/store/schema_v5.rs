//! Catalog migration v5: conflict counts + working-state vocabulary (goal Step 10).
//!
//! `status_observations.conflicts` counts distinct unmerged paths (`NULL` =
//! backend could not determine, e.g. metadata mode); `working_state` is the
//! Step 10 working-state vocabulary (`clean`, `dirty`, `conflicted`,
//! `pending`, `partial`, `unstable`, `unknown`, `error`, `not_applicable`;
//! `NULL` = legacy row written before v5). The existing `state` column keeps
//! its observation-completeness meaning untouched.
//!
//! v1 storage rules (see `schema.rs`) apply unchanged: plain rowid tables
//! (no `WITHOUT ROWID`), no recursive CTEs, no FTS, every raw
//! path/component/ref-name/URL in a `BLOB` column, and no index key
//! contains a `BLOB` column.
//!
//! Wiring (a `Migration` chain entry plus the `CURRENT_SCHEMA_VERSION`
//! bump) belongs to the coordinator: [`V5Marker::VERSION`] and
//! [`V5Marker::DESCRIPTION`] carry the values.

/// Schema version 5 SQL: additive Step 10 columns, both nullable so
/// legacy rows read back as unknown/undetermined.
pub const V5_SQL: &str = "
ALTER TABLE status_observations ADD COLUMN conflicts INTEGER;
ALTER TABLE status_observations ADD COLUMN working_state TEXT;
";

/// Version marker for migration v5; the coordinator wires these into
/// the append-only [`crate::store::Migration`] chain.
pub struct V5Marker;

impl V5Marker {
    /// 1-based schema version this migration produces.
    pub const VERSION: u32 = 5;
    /// Human-readable description, mirroring the v1 `MIGRATIONS` style.
    pub const DESCRIPTION: &str = "v5: status_observations.conflicts + working_state";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_nullable_conflict_columns() {
        assert_eq!(
            V5_SQL.matches("ADD COLUMN conflicts INTEGER").count(),
            1,
            "{V5_SQL}"
        );
        assert_eq!(
            V5_SQL.matches("ADD COLUMN working_state TEXT").count(),
            1,
            "{V5_SQL}"
        );
    }

    #[test]
    fn plain_rowid_tables_only() {
        assert!(
            !V5_SQL.to_ascii_uppercase().contains("WITHOUT ROWID"),
            "v1 rule: plain rowid tables only"
        );
    }

    #[test]
    fn no_index_key_contains_blob() {
        for stmt in V5_SQL.split(';') {
            let upper = stmt.to_ascii_uppercase();
            if !upper.contains("CREATE") || !upper.contains("INDEX") {
                continue;
            }
            if upper.contains("PRIMARY KEY") {
                continue;
            }
            panic!("v5 adds no indexes: {stmt}");
        }
    }

    #[test]
    fn marker_matches_v5() {
        assert_eq!(V5Marker::VERSION, 5);
        assert!(V5Marker::DESCRIPTION.starts_with("v5:"));
    }
}
