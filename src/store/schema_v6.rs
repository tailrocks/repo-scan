//! Catalog migration v6: branch comparison storage (goal Step 10).
//!
//! `refs.comparison_state` is the D7 comparison vocabulary (`equal`,
//! `ahead`, `behind`, `diverged`, `no_upstream`, `upstream_missing`,
//! `pending`, `incomplete_history`, `error`; `NULL` = legacy row
//! written before v6, read as `pending`). `refs.ahead` /
//! `refs.behind` are the ahead/behind commit counts (`NULL` = unknown;
//! only the four counted states carry numbers, unknown is never zero).
//! The existing `state` column keeps its ref-validity meaning untouched.
//!
//! v1 storage rules (see `schema.rs`) apply unchanged: plain rowid tables
//! (no `WITHOUT ROWID`), no recursive CTEs, no FTS, every raw
//! path/component/ref-name/URL in a `BLOB` column, and no index key
//! contains a `BLOB` column.
//!
//! Wiring (a `Migration` chain entry plus the `CURRENT_SCHEMA_VERSION`
//! bump) belongs to the coordinator: [`V6Marker::VERSION`] and
//! [`V6Marker::DESCRIPTION`] carry the values. Until wired, readers
//! and writers in [`crate::store::catalog`] gate on the physical
//! columns (see `refs_has_comparison`): v5 catalogs read `pending` /
//! null counts and skip comparison writes instead of failing.

/// Schema version 6 SQL: additive Step 10 columns, all nullable so
/// legacy rows read back as pending/unknown.
pub const V6_SQL: &str = "
ALTER TABLE refs ADD COLUMN comparison_state TEXT;
ALTER TABLE refs ADD COLUMN ahead INTEGER;
ALTER TABLE refs ADD COLUMN behind INTEGER;
";

/// Version marker for migration v6; the coordinator wires these into
/// the append-only [`crate::store::Migration`] chain.
pub struct V6Marker;

impl V6Marker {
    /// 1-based schema version this migration produces.
    pub const VERSION: u32 = 6;
    /// Human-readable description, mirroring the v1 `MIGRATIONS` style.
    pub const DESCRIPTION: &str = "v6: refs.comparison_state + ahead + behind";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_nullable_comparison_columns() {
        assert_eq!(
            V6_SQL.matches("ADD COLUMN comparison_state TEXT").count(),
            1,
            "{V6_SQL}"
        );
        assert_eq!(
            V6_SQL.matches("ADD COLUMN ahead INTEGER").count(),
            1,
            "{V6_SQL}"
        );
        assert_eq!(
            V6_SQL.matches("ADD COLUMN behind INTEGER").count(),
            1,
            "{V6_SQL}"
        );
    }

    #[test]
    fn plain_rowid_tables_only() {
        assert!(
            !V6_SQL.to_ascii_uppercase().contains("WITHOUT ROWID"),
            "v1 rule: plain rowid tables only"
        );
    }

    #[test]
    fn no_index_key_contains_blob() {
        for stmt in V6_SQL.split(';') {
            let upper = stmt.to_ascii_uppercase();
            if !upper.contains("CREATE") || !upper.contains("INDEX") {
                continue;
            }
            if upper.contains("PRIMARY KEY") {
                continue;
            }
            panic!("v6 adds no indexes: {stmt}");
        }
    }

    #[test]
    fn marker_matches_v6() {
        assert_eq!(V6Marker::VERSION, 6);
        assert!(V6Marker::DESCRIPTION.starts_with("v6:"));
    }
}
