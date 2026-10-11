//! Catalog migration v3: remote-refresh records, per-ref freshness,
//! saved `--fetch` (goal Step 11).
//!
//! `remote_refreshes` records one row per (store, remote name) per fetch
//! phase run (`INSERT OR REPLACE`): status (`success`|`failed`
//! |`unsupported`), observation time and duration, count of tracking refs
//! the fetch updated, the JSON names observed current, the JSON names
//! found deleted upstream (local tracking refs are KEPT, never pruned),
//! and a scrubbed detail. Only the remote NAME is stored — never the URL
//! (canonical URLs already live in `remotes`; raw URLs may carry
//! credentials).
//!
//! `refs.freshness` labels remote-tracking rows `current` (observed by
//! this scan's fetch), `stale` (fetch ran but did not cover this ref, or
//! an older observation), or `unknown` (no successful fetch covered it).
//! `NULL` = legacy/unlabeled, read as `unknown`. Only
//! `kind = 'remote_tracking'` rows are ever labeled; local branches stay
//! `NULL`. `refs.freshness_at_ms` stamps the label assignment. The ref
//! upsert preserves these columns across re-observation
//! (`INSERT OR IGNORE` + `UPDATE` of the observed columns only).
//!
//! `scan_requests.fetch` persists the `--fetch` request (`NULL` = legacy
//! row, no fetch); resume restores it.
//!
//! v1 storage rules (see `schema.rs`) apply unchanged: plain rowid tables
//! (no `WITHOUT ROWID`), no recursive CTEs, no FTS, every raw
//! path/component/ref-name/URL in a `BLOB` column, and no index key
//! contains a `BLOB` column. One noted tension: the `remote_refreshes`
//! composite `PRIMARY KEY` includes `remote_name BLOB` (required edge
//! identity, same as v2 `group_members`), which SQLite materializes as a
//! unique autoindex; every explicit `CREATE INDEX` key below is
//! `TEXT`/`INTEGER`-only, enforced by unit test
//! (`no_index_key_contains_blob`).
//!
//! Wiring (a `Migration` chain entry plus the `CURRENT_SCHEMA_VERSION`
//! bump) belongs to the coordinator: [`V3Marker::VERSION`] and
//! [`V3Marker::DESCRIPTION`] carry the values.

/// Schema version 3 SQL: additive Step 11 tables and columns.
///
/// * `remote_refreshes` is keyed `(store_id, remote_name)` (Step 11:
///   one record per store + effective remote configuration);
///   `remote_name` is `BLOB` like `remotes.name` because remote names
///   are raw bytes.
/// * `refs.freshness` / `refs.freshness_at_ms` are nullable; `NULL` =
///   legacy unlabeled row, read as `unknown`.
/// * `scan_requests.fetch` is nullable; `NULL` = legacy row, no fetch.
pub const V3_SQL: &str = "
CREATE TABLE IF NOT EXISTS remote_refreshes (
    store_id TEXT NOT NULL,
    remote_name BLOB NOT NULL,
    status TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    duration_ms INTEGER,
    refs_updated INTEGER NOT NULL DEFAULT 0,
    refs_current_json TEXT,
    refs_deleted_json TEXT,
    detail TEXT,
    PRIMARY KEY (store_id, remote_name)
);
CREATE INDEX IF NOT EXISTS idx_remote_refreshes_store
    ON remote_refreshes(store_id);
ALTER TABLE refs ADD COLUMN freshness TEXT;
ALTER TABLE refs ADD COLUMN freshness_at_ms INTEGER;
ALTER TABLE scan_requests ADD COLUMN fetch INTEGER;
";

/// Version marker for migration v3 (Step 11); the coordinator wires these
/// into the append-only [`crate::store::Migration`] chain.
pub struct V3Marker;

impl V3Marker {
    /// 1-based schema version this migration produces.
    pub const VERSION: u32 = 3;
    /// Human-readable description, mirroring the v1 `MIGRATIONS` style.
    pub const DESCRIPTION: &str = "v3: remote_refreshes, refs freshness, \
        scan_requests fetch";
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLES: [&str; 1] = ["remote_refreshes"];
    const INDEXES: [&str; 1] = ["idx_remote_refreshes_store"];

    #[test]
    fn each_table_created_once() {
        for table in TABLES {
            let stmt = format!("CREATE TABLE IF NOT EXISTS {table}");
            assert_eq!(V3_SQL.matches(&stmt).count(), 1, "{table}");
        }
    }

    #[test]
    fn each_index_created_once() {
        for index in INDEXES {
            assert_eq!(V3_SQL.matches(index).count(), 1, "{index}");
        }
    }

    #[test]
    fn plain_rowid_tables_only() {
        assert!(
            !V3_SQL.to_ascii_uppercase().contains("WITHOUT ROWID"),
            "v1 rule: plain rowid tables only"
        );
    }

    #[test]
    fn no_index_key_contains_blob() {
        let mut index_stmts = 0;
        for stmt in V3_SQL.split(';') {
            let upper = stmt.to_ascii_uppercase();
            if !upper.contains("CREATE") || !upper.contains("INDEX") {
                continue;
            }
            if upper.contains("PRIMARY KEY") {
                continue;
            }
            index_stmts += 1;
            assert!(
                !upper.contains("BLOB"),
                "v1 rule: no BLOB in an index key: {stmt}"
            );
        }
        assert_eq!(index_stmts, INDEXES.len(), "index coverage");
    }

    #[test]
    fn marker_matches_v3() {
        assert_eq!(V3Marker::VERSION, 3);
        assert!(V3Marker::DESCRIPTION.starts_with("v3:"));
    }
}
