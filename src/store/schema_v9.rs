//! Catalog migration v9: remove raw remote-name BLOBs from primary keys.
//!
//! The v2/v3 schemas used `remote_name BLOB` directly in composite primary
//! keys. This migration rebuilds those tables with a lossless hexadecimal
//! TEXT key while retaining the original name bytes in an unindexed BLOB
//! column. `hex()` is injective over byte strings, including invalid UTF-8
//! and embedded NUL bytes.

/// Schema version 9 SQL: rebuild remote-name keyed tables without BLOB keys.
pub const V9_SQL: &str = "
CREATE TABLE group_members_v9 (
    group_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    remote_name BLOB NOT NULL,
    remote_name_key TEXT NOT NULL,
    role TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (group_id, instance_id, remote_name_key, role)
);
INSERT INTO group_members_v9 (group_id, instance_id, remote_name, remote_name_key, role, observed_at_ms) \
    SELECT group_id, instance_id, remote_name, hex(remote_name), role, observed_at_ms FROM group_members;
DROP TABLE group_members;
ALTER TABLE group_members_v9 RENAME TO group_members;
CREATE INDEX idx_group_members_instance ON group_members(instance_id);

CREATE TABLE remote_refreshes_v9 (
    store_id TEXT NOT NULL,
    remote_name BLOB NOT NULL,
    remote_name_key TEXT NOT NULL,
    status TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    duration_ms INTEGER,
    refs_updated INTEGER NOT NULL DEFAULT 0,
    refs_current_json TEXT,
    refs_deleted_json TEXT,
    detail TEXT,
    PRIMARY KEY (store_id, remote_name_key)
);
INSERT INTO remote_refreshes_v9 (store_id, remote_name, remote_name_key, status, observed_at_ms, duration_ms, refs_updated, refs_current_json, refs_deleted_json, detail) \
    SELECT store_id, remote_name, hex(remote_name), status, observed_at_ms, duration_ms, refs_updated, refs_current_json, refs_deleted_json, detail FROM remote_refreshes;
DROP TABLE remote_refreshes;
ALTER TABLE remote_refreshes_v9 RENAME TO remote_refreshes;
CREATE INDEX idx_remote_refreshes_store ON remote_refreshes(store_id);
";

/// Version marker for migration v9.
pub struct V9Marker;

impl V9Marker {
    /// 1-based schema version this migration produces.
    pub const VERSION: u32 = 9;
    /// Human-readable description.
    pub const DESCRIPTION: &str = "v9: lossless TEXT keys for raw remote-name tables";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuilds_tables_with_text_keys_and_preserves_raw_names() {
        assert!(V9_SQL.contains("remote_name BLOB NOT NULL"));
        assert!(V9_SQL.contains("remote_name_key TEXT NOT NULL"));
        assert!(V9_SQL.contains("PRIMARY KEY (group_id, instance_id, remote_name_key, role)"));
        assert!(V9_SQL.contains("PRIMARY KEY (store_id, remote_name_key)"));
        assert!(V9_SQL.contains("hex(remote_name)"));
        assert!(!V9_SQL.contains("PRIMARY KEY (group_id, instance_id, remote_name, role)"));
        assert!(!V9_SQL.contains("PRIMARY KEY (store_id, remote_name)"));
        assert_eq!(V9Marker::VERSION, 9);
        assert!(V9Marker::DESCRIPTION.starts_with("v9:"));
    }

    #[test]
    fn creates_only_blob_free_explicit_index_keys() {
        for stmt in V9_SQL.split(';') {
            let upper = stmt.to_ascii_uppercase();
            if !upper.contains("CREATE") || !upper.contains("INDEX") {
                continue;
            }
            assert!(!upper.contains("BLOB"), "BLOB in index key: {stmt}");
        }
    }

    #[test]
    fn plain_rowid_tables_only() {
        assert!(!V9_SQL.to_ascii_uppercase().contains("WITHOUT ROWID"));
    }
}
