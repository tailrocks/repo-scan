//! Schema migrations for the Turso catalog (spec §11).
//!
//! Rules: plain rowid tables only (no `WITHOUT ROWID`, experimental in the
//! pinned engine), no recursive CTEs, no FTS5 (not compiled in), every raw
//! path/component/ref-name/URL in a `BLOB` column (engine TEXT is UTF-8).
//! `BLOB` columns are indexed by byte equality only where unavoidable; to
//! keep the qualified SQL surface minimal, no index key contains a `BLOB`
//! column — BLOB lookups filter on a TEXT/INTEGER key first.

use crate::store::Migration;

/// Engine qualification marker stored in `meta.engine_qual`.
pub const ENGINE_QUAL: &str = "turso 0.8.1 default-features=false; WAL + synchronous=FULL + \
    data_sync_retry=ON (+ fullfsync on macOS); see docs/TURSO_QUAL.md";

/// Schema version 1: every spec §11 entity with its required lookup index.
pub const V1_SQL: &str = "
CREATE TABLE IF NOT EXISTS meta (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_requests (
    id TEXT PRIMARY KEY,
    url_raw BLOB NOT NULL,
    url_canonical BLOB,
    scope TEXT NOT NULL,
    status_mode TEXT NOT NULL,
    report_dest BLOB,
    state TEXT NOT NULL,
    outcome TEXT,
    successor_id TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_requests_state ON scan_requests(state);
CREATE TABLE IF NOT EXISTS generations (
    id INTEGER PRIMARY KEY,
    scope_policy TEXT NOT NULL,
    state TEXT NOT NULL,
    prior_generation INTEGER,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS volumes (
    id TEXT PRIMARY KEY,
    native_identity TEXT,
    namespace TEXT NOT NULL,
    filesystem TEXT,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    observed_at_ms INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_volumes_identity
    ON volumes(namespace, native_identity);
CREATE TABLE IF NOT EXISTS directories (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER,
    component BLOB NOT NULL,
    display TEXT NOT NULL,
    volume_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    incarnation TEXT NOT NULL DEFAULT '',
    last_observed_ms INTEGER,
    invalidation_rev INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_directories_identity
    ON directories(volume_id, object_id, incarnation);
CREATE INDEX IF NOT EXISTS idx_directories_parent ON directories(parent_id);
CREATE TABLE IF NOT EXISTS scope_revisions (
    scope_key TEXT PRIMARY KEY,
    rev INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS frontier_tasks (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    generation INTEGER NOT NULL,
    dir_id INTEGER,
    scope_key TEXT NOT NULL,
    expected_rev INTEGER NOT NULL,
    state TEXT NOT NULL,
    lease_token INTEGER,
    lease_epoch INTEGER,
    lease_expires_ms INTEGER,
    idempotency_key TEXT NOT NULL UNIQUE,
    retry_after_ms INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_sched
    ON frontier_tasks(state, retry_after_ms, generation);
CREATE INDEX IF NOT EXISTS idx_tasks_scope ON frontier_tasks(scope_key, state);
CREATE INDEX IF NOT EXISTS idx_tasks_lease
    ON frontier_tasks(state, lease_expires_ms);
CREATE TABLE IF NOT EXISTS dir_observations (
    dir_id INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0,
    entry_generation INTEGER NOT NULL DEFAULT 0,
    entries_seen INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    observed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (dir_id, generation)
);
CREATE TABLE IF NOT EXISTS git_instances (
    id TEXT PRIMARY KEY,
    git_path BLOB NOT NULL,
    common_path BLOB NOT NULL,
    incarnation TEXT NOT NULL DEFAULT '',
    format TEXT NOT NULL,
    bare INTEGER,
    object_format TEXT NOT NULL,
    disposition TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '[]',
    observed_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_git_incarnation ON git_instances(incarnation);
CREATE TABLE IF NOT EXISTS checkouts (
    id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    root_path BLOB,
    git_path BLOB NOT NULL,
    relationship TEXT NOT NULL,
    availability TEXT NOT NULL,
    head_state TEXT NOT NULL,
    head_ref BLOB,
    head_oid BLOB,
    head_algo TEXT,
    observed_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_checkouts_instance ON checkouts(instance_id);
CREATE TABLE IF NOT EXISTS remotes (
    id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    checkout_scope_id TEXT,
    name BLOB NOT NULL,
    role TEXT NOT NULL,
    url BLOB NOT NULL,
    canonical_url BLOB,
    observed_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remotes_instance ON remotes(instance_id, role);
CREATE TABLE IF NOT EXISTS refs (
    id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    checkout_scope_id TEXT,
    kind TEXT NOT NULL,
    name BLOB NOT NULL,
    oid BLOB,
    algo TEXT,
    symbolic_target BLOB,
    upstream BLOB,
    state TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refs_instance ON refs(instance_id, kind);
CREATE TABLE IF NOT EXISTS status_observations (
    id INTEGER PRIMARY KEY,
    checkout_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    state TEXT NOT NULL,
    started_ms INTEGER,
    finished_ms INTEGER,
    staged INTEGER,
    unstaged INTEGER,
    untracked INTEGER,
    untracked_units TEXT NOT NULL,
    submodules TEXT NOT NULL,
    unknown_fields TEXT NOT NULL DEFAULT '[]',
    input_fingerprint BLOB,
    observed_rev INTEGER NOT NULL,
    observed_at_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_status_rev
    ON status_observations(checkout_id, observed_rev);
CREATE TABLE IF NOT EXISTS event_journal (
    id INTEGER PRIMARY KEY,
    volume_id TEXT NOT NULL,
    history_uuid TEXT NOT NULL,
    cursor TEXT NOT NULL,
    received_ms INTEGER NOT NULL,
    invalidated INTEGER NOT NULL DEFAULT 0,
    ingested INTEGER NOT NULL DEFAULT 0,
    reconciled INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_cursor
    ON event_journal(volume_id, history_uuid, cursor);
CREATE TABLE IF NOT EXISTS errors (
    id TEXT PRIMARY KEY,
    scope_key TEXT NOT NULL,
    category TEXT NOT NULL,
    detail TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 1,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    next_retry_ms INTEGER,
    open INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_errors_scope
    ON errors(scope_key, category, open);
CREATE TABLE IF NOT EXISTS report_snapshots (
    id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    catalog_rev INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    publication_state TEXT NOT NULL,
    checksum BLOB,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS batches (
    idempotency_key TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
";

/// Ordered migration chain (append-only; referenced by [`crate::store::migrations`]).
pub static MIGRATIONS: [Migration; 3] = [
    Migration {
        version: 1,
        description: "v1: spec section 11 entities with required lookup indexes",
        sql: V1_SQL,
    },
    Migration {
        version: crate::store::schema_v2::V2Marker::VERSION,
        description: crate::store::schema_v2::V2Marker::DESCRIPTION,
        sql: crate::store::schema_v2::V2_SQL,
    },
    Migration {
        version: crate::store::schema_v3::V3Marker::VERSION,
        description: crate::store::schema_v3::V3Marker::DESCRIPTION,
        sql: crate::store::schema_v3::V3_SQL,
    },
];
