//! Catalog migration v2: GitHub groups, scan-event journal, multi-target
//! scans, full scope keys (`docs/GOAL_CONTRACTS.md` D1/D2/D4/D5).
//!
//! D1: NEW `github_groups` record (`groups[]` in report `1.1.0`) with ID
//! `lower(host)/lower(account)/lower(repo)`; exact match for targets.
//! `group_members` edges one store to a group via the observing remote's
//! `(name, role)` — fork/upstream never merged.
//!
//! D2: additive migration over v1. New tables start empty; every added
//! column is nullable, so v1 rows migrate untouched.
//!
//! D4: `scan_events` journals [`crate::scan_events::Envelope`] fields
//! (`scan_id`, `seq`, `catalog_rev`, `event_offset`, `event_type`, `op`,
//! `reset`, `records`). `schema_version` is a stream constant stamped by
//! the reader, not journaled. Indexes serve per-scan replay (`scan_id,
//! seq`) and cursor resume (`scan_id, catalog_rev, event_offset`);
//! redelivery stays idempotent by `seq`.
//!
//! D5: `generations.scope_key` carries the full key (roots + volume
//! identities + exclusions + traversal policy); `NULL` means a v1 row
//! still keyed by the legacy policy name in `scope_policy`. Targets stay
//! OUT of the key: `scan_requests.targets_json` records the multi-target
//! request served by one filesystem pass.
//!
//! v1 storage rules (see `schema.rs`) apply unchanged: plain rowid tables
//! (no `WITHOUT ROWID`), no recursive CTEs, no FTS, every raw
//! path/component/ref-name/URL in a `BLOB` column, and no index key
//! contains a `BLOB` column. One noted tension: the `group_members`
//! composite `PRIMARY KEY` includes `remote_name BLOB` (required D1 edge
//! identity), which SQLite materializes as a unique autoindex; every
//! explicit `CREATE INDEX` key below is `TEXT`/`INTEGER`-only, enforced
//! by unit test (`no_index_key_contains_blob`).
//!
//! Wiring (a `Migration` chain entry plus the `CURRENT_SCHEMA_VERSION`
//! bump) belongs to the coordinator: [`V2Marker::VERSION`] and
//! [`V2Marker::DESCRIPTION`] carry the values.

/// Schema version 2 SQL: additive D1/D2/D4/D5 tables and columns.
///
/// * `github_groups.id` is writer-computed
///   `lower(host)/lower(account)/lower(repo)` (D1); the `UNIQUE (host,
///   account, repo)` index is the normalized-identity lookup.
/// * `group_members` is keyed `(group_id, instance_id, remote_name,
///   role)` (D1: keep name + role per store); `remote_name` is `BLOB`
///   like `remotes.name` because remote names are raw bytes.
/// * `scan_events.seq` is the scan-scoped sequence assigned by the writer
///   (D4); `records` holds JSON bytes stored byte-exact.
/// * `scan_requests.targets_json` is a JSON array of `{raw, canonical}`;
///   `NULL` means a legacy single-target row addressed via `url_raw`.
///   `format` is the D6 output format (`human|json|jsonl`); `all_targets`
///   (`NULL` = legacy) marks a `--all` filesystem-discovery scan.
/// * `generations.scope_key` is the full D5 key; `NULL` = legacy
///   policy-name key in `scope_policy`.
pub const V2_SQL: &str = "
CREATE TABLE IF NOT EXISTS github_groups (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    account TEXT NOT NULL,
    repo TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_github_groups_identity
    ON github_groups(host, account, repo);
CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    remote_name BLOB NOT NULL,
    role TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (group_id, instance_id, remote_name, role)
);
CREATE INDEX IF NOT EXISTS idx_group_members_instance
    ON group_members(instance_id);
CREATE TABLE IF NOT EXISTS scan_events (
    seq INTEGER PRIMARY KEY,
    scan_id TEXT NOT NULL,
    catalog_rev INTEGER NOT NULL,
    event_offset INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    op TEXT NOT NULL,
    reset INTEGER NOT NULL DEFAULT 0,
    records BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_events_scan_seq
    ON scan_events(scan_id, seq);
CREATE INDEX IF NOT EXISTS idx_scan_events_cursor
    ON scan_events(scan_id, catalog_rev, event_offset);
ALTER TABLE scan_requests ADD COLUMN targets_json TEXT;
ALTER TABLE scan_requests ADD COLUMN format TEXT;
ALTER TABLE scan_requests ADD COLUMN all_targets INTEGER;
ALTER TABLE generations ADD COLUMN scope_key TEXT;
";

/// Version marker for migration v2 (D2); the coordinator wires these into
/// the append-only [`crate::store::Migration`] chain.
pub struct V2Marker;

impl V2Marker {
    /// 1-based schema version this migration produces.
    pub const VERSION: u32 = 2;
    /// Human-readable description, mirroring the v1 `MIGRATIONS` style.
    pub const DESCRIPTION: &str = "v2: github_groups + group_members, scan_events journal, \
        multi-target scan_requests, generations scope key";
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLES: [&str; 3] = ["github_groups", "group_members", "scan_events"];
    const INDEXES: [&str; 4] = [
        "idx_github_groups_identity",
        "idx_group_members_instance",
        "idx_scan_events_scan_seq",
        "idx_scan_events_cursor",
    ];

    #[test]
    fn each_table_created_once() {
        for table in TABLES {
            let stmt = format!("CREATE TABLE IF NOT EXISTS {table}");
            assert_eq!(V2_SQL.matches(&stmt).count(), 1, "{table}");
        }
    }

    #[test]
    fn each_index_created_once() {
        for index in INDEXES {
            assert_eq!(V2_SQL.matches(index).count(), 1, "{index}");
        }
    }

    #[test]
    fn plain_rowid_tables_only() {
        assert!(
            !V2_SQL.to_ascii_uppercase().contains("WITHOUT ROWID"),
            "v1 rule: plain rowid tables only"
        );
    }

    #[test]
    fn no_index_key_contains_blob() {
        let mut index_stmts = 0;
        for stmt in V2_SQL.split(';') {
            let trimmed = stmt.trim();
            let upper = trimmed.to_ascii_uppercase();
            if !(upper.starts_with("CREATE ") && upper.contains("INDEX")) {
                continue;
            }
            index_stmts += 1;
            let open = trimmed.find('(').expect("index column list");
            let close = trimmed.rfind(')').expect("index column list end");
            let cols = &trimmed[open..=close];
            assert!(
                !cols.to_ascii_uppercase().contains("BLOB"),
                "BLOB in index key: {trimmed}"
            );
        }
        assert_eq!(index_stmts, INDEXES.len(), "index statement count");
    }

    #[test]
    fn alters_target_existing_v1_tables() {
        // Full v1 table inventory from `schema.rs` V1_SQL.
        const V1_TABLES: [&str; 17] = [
            "meta",
            "scan_requests",
            "generations",
            "volumes",
            "directories",
            "scope_revisions",
            "frontier_tasks",
            "dir_observations",
            "git_instances",
            "checkouts",
            "remotes",
            "refs",
            "status_observations",
            "event_journal",
            "errors",
            "report_snapshots",
            "batches",
        ];
        const EXPECTED: [(&str, &str); 4] = [
            ("scan_requests", "targets_json"),
            ("scan_requests", "format"),
            ("scan_requests", "all_targets"),
            ("generations", "scope_key"),
        ];
        let mut seen = 0;
        for stmt in V2_SQL.split(';') {
            let trimmed = stmt.trim();
            if !trimmed.to_ascii_uppercase().starts_with("ALTER TABLE ") {
                continue;
            }
            seen += 1;
            let rest = &trimmed["ALTER TABLE ".len()..];
            let table = rest.split_whitespace().next().expect("table name");
            assert!(V1_TABLES.contains(&table), "unknown v1 table: {table}");
            assert!(
                trimmed.to_ascii_uppercase().contains("ADD COLUMN"),
                "expected ADD COLUMN: {trimmed}"
            );
        }
        assert_eq!(seen, EXPECTED.len(), "ALTER statement count");
        for (table, column) in EXPECTED {
            let needle = format!("ALTER TABLE {table} ADD COLUMN {column}");
            assert!(V2_SQL.contains(&needle), "{needle}");
        }
    }

    #[test]
    fn marker_carries_v2_identity() {
        assert_eq!(V2Marker::VERSION, 2);
        assert!(V2Marker::DESCRIPTION.starts_with("v2:"));
    }
}
