//! Catalog migration acceptance (goal Step 5/9/11, contracts D1/D2/D4/D5):
//! the append-only chain upgrades v1 catalogs without touching v1 rows,
//! and the new journal/group/scope/refresh APIs round-trip.
//!
//! The v1 catalog under test is built by executing the shipped v1
//! migration SQL through a direct connection — the same bytes production
//! applied — then reopened through [`TursoStore::open`].
//!
//! Slice-1 additions (contract C2): fail-closed proof for a newer-than-
//! binary catalog, a read-only open that never migrates, and an unknown
//! physical layout whose marker claims a known version — all three must
//! refuse with data preserved.

use repo_scan::store::{
    now_ms, NewRef, NewRemoteRefresh, NewScan, NewScanEvent, Store, TursoStore, WriterBatch,
    CURRENT_SCHEMA_VERSION,
};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

/// Build a genuine v1 catalog: v1 migration SQL + `schema_version = 1`
/// marker + representative v1 rows, written through a direct connection.
async fn build_v1_catalog(db: &std::path::Path) {
    let path_str = db.to_str().expect("utf8 db path");
    let conn = turso::Builder::new_local(path_str)
        .build()
        .await
        .expect("turso build")
        .connect()
        .expect("turso connect");
    let chain = repo_scan::store::migrations();
    assert!(chain.len() >= 9, "v9 chain wired");
    assert_eq!(chain[0].version, 1);
    conn.execute_batch(chain[0].sql).await.expect("v1 sql");
    conn.execute(
        "INSERT INTO meta (name, value) VALUES ('schema_version', '1')",
        (),
    )
    .await
    .expect("v1 marker");
    conn.execute(
        "INSERT INTO scan_requests (id, url_raw, url_canonical, scope, status_mode, \
            report_dest, state, created_at_ms, updated_at_ms) \
            VALUES ('scan-v1', ?1, ?2, 'roots', 'summary', NULL, 'complete', 100, 200)",
        vec![
            turso::Value::Blob(b"https://github.com/o/r".to_vec()),
            turso::Value::Blob(b"https://github.com/o/r".to_vec()),
        ],
    )
    .await
    .expect("v1 scan row");
    conn.execute(
        "INSERT INTO generations (scope_policy, state, prior_generation, created_at_ms) \
            VALUES ('roots', 'complete', NULL, 150)",
        (),
    )
    .await
    .expect("v1 generation row");
    conn.execute(
        "INSERT INTO status_observations (checkout_id, mode, state, started_ms, \
            finished_ms, staged, unstaged, untracked, untracked_units, submodules, \
            unknown_fields, input_fingerprint, observed_rev, observed_at_ms) \
            VALUES ('co-v1', 'summary', 'complete', 100, 200, 0, 0, 0, \
            'collapsed_entries', 'checked', '[]', NULL, 1, 200)",
        (),
    )
    .await
    .expect("v1 status row");
}

/// Build a genuine v8 catalog with non-UTF-8 remote names so v9's table
/// rebuild proves byte preservation, not only UTF-8 compatibility.
async fn build_v8_catalog(db: &std::path::Path) {
    let path_str = db.to_str().expect("utf8 db path");
    let conn = turso::Builder::new_local(path_str)
        .build()
        .await
        .expect("turso build")
        .connect()
        .expect("turso connect");
    let group_remote = vec![b'o', 0x80, 0];
    let refresh_remote = vec![0xff, b'u', 0x00];
    let chain = repo_scan::store::migrations();
    for migration in chain.iter().take(8) {
        conn.execute_batch(migration.sql)
            .await
            .expect("apply historical migration");
        conn.execute(
            "INSERT OR REPLACE INTO meta (name, value) VALUES ('schema_version', ?1)",
            vec![turso::Value::Text(migration.version.to_string())],
        )
        .await
        .expect("schema marker");
        if migration.version == 3 {
            conn.execute(
                "INSERT INTO group_members (group_id, instance_id, remote_name, role, observed_at_ms) \
                    VALUES ('github.com/legacy/repo', 'git:legacy', ?1, 'fetch', 100)",
                vec![turso::Value::Blob(group_remote.clone())],
            )
            .await
            .expect("legacy group member");
            conn.execute(
                "INSERT INTO remote_refreshes (store_id, remote_name, status, observed_at_ms, \
                    duration_ms, refs_updated, refs_current_json, refs_deleted_json, detail) \
                    VALUES ('git:legacy', ?1, 'success', 200, 25, 2, '[]', NULL, NULL)",
                vec![turso::Value::Blob(refresh_remote.clone())],
            )
            .await
            .expect("legacy remote refresh");
        }
    }
    assert_eq!(chain[7].version, 8);
}

#[test]
fn fresh_open_is_v9_with_working_tables() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        assert_eq!(CURRENT_SCHEMA_VERSION, 9);
        assert_eq!(store.schema_version().expect("version"), 9);

        // v2 request columns persist through the extended insert; the v3
        // `fetch` and v4 `workers` columns go through the full write path
        // (slice-1 compat: `NewScan` keeps main's v2 field set so
        // unmodified callers compile; see store/catalog.rs COMPAT notes).
        let now = now_ms();
        let inserted = store
            .create_scan_request_full(
                &NewScan {
                    id: "scan-v2",
                    url_raw: b"https://github.com/o/r",
                    url_canonical: Some(b"https://github.com/o/r"),
                    scope: "roots",
                    status_mode: "summary",
                    report_dest: None,
                    targets_json: Some(r#"[{"raw":"o/r","canonical":"https://github.com/o/r"}]"#),
                    format: Some("jsonl"),
                    all_targets: Some(false),
                },
                Some(true),
                Some(6),
                now,
            )
            .await
            .expect("create");
        assert!(inserted);
        let row = store.get_scan("scan-v2").await.expect("get").expect("row");
        assert_eq!(
            row.targets_json.as_deref(),
            Some(r#"[{"raw":"o/r","canonical":"https://github.com/o/r"}]"#)
        );
        assert_eq!(row.format.as_deref(), Some("jsonl"));
        assert_eq!(row.all_targets, Some(false));
        assert_eq!(row.fetch, Some(true));
        assert_eq!(row.workers, Some(6));

        // v2 event journal accepts writes immediately.
        let appended = store
            .append_scan_event(&NewScanEvent {
                scan_id: "scan-v2",
                seq: 1,
                catalog_rev: 1,
                event_offset: 0,
                event_type: "scan_started",
                op: "add",
                reset: false,
                records: br#"{"scan_id":"scan-v2"}"#,
            })
            .await
            .expect("append");
        assert!(appended);
        store
            .connection()
            .execute(
                "INSERT INTO scan_event_dedupe (scan_id, dedupe_kind, event_id) \
                    VALUES (?1, ?2, ?3)",
                vec![
                    turso::Value::Text("scan-v2".to_string()),
                    turso::Value::Text("repository_found".to_string()),
                    turso::Value::Text("evt:marker".to_string()),
                ],
            )
            .await
            .expect("v8 dedupe marker table");
        store.close().await.expect("close");
    });
}

#[test]
fn v1_catalog_upgrades_preserving_v1_rows() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        build_v1_catalog(&db).await;

        let store = TursoStore::open(&db).await.expect("open upgrades");
        assert_eq!(store.schema_version().expect("version"), 9);

        // v1 rows survive byte-identical; v2..v7 columns read NULL (legacy).
        let scan = store.get_scan("scan-v1").await.expect("get").expect("row");
        assert_eq!(scan.url_raw, b"https://github.com/o/r");
        assert_eq!(scan.state, "complete");
        assert_eq!(scan.targets_json, None);
        assert_eq!(scan.format, None);
        assert_eq!(scan.all_targets, None);
        assert_eq!(scan.fetch, None);
        assert_eq!(scan.workers, None);
        assert_eq!(scan.inventory_ready_seq, None);
        let generation = store.get_generation(1).await.expect("get").expect("gen");
        assert_eq!(generation.scope_policy, "roots");
        assert_eq!(generation.scope_key, None);
        // v1 status row survives; v5 columns read NULL (legacy unknown).
        let statuses = store.list_statuses("co-v1").await.expect("statuses");
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].staged, Some(0));
        assert_eq!(statuses[0].conflicts, None);
        assert_eq!(statuses[0].working_state, None);

        // v2 tables are present and writable after upgrade.
        assert!(store
            .upsert_github_group("github.com/o/r", "github.com", "o", "r", now_ms())
            .await
            .expect("group"));
        assert!(store
            .append_scan_event(&NewScanEvent {
                scan_id: "scan-v1",
                seq: 1,
                catalog_rev: 2,
                event_offset: 0,
                event_type: "inventory_ready",
                op: "add",
                reset: false,
                records: b"{}",
            })
            .await
            .expect("append"));
        store.close().await.expect("close");

        // Reopen is idempotent: still v9, rows intact.
        let store = TursoStore::open(&db).await.expect("reopen");
        assert_eq!(store.schema_version().expect("version"), 9);
        assert!(store.get_scan("scan-v1").await.expect("get").is_some());
        assert_eq!(store.last_event_seq("scan-v1").await.expect("seq"), Some(1));
        store.close().await.expect("close");
    });
}

#[test]
fn v8_remote_name_keys_migrate_losslessly_to_text() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let group_remote = vec![b'o', 0x80, 0];
        let refresh_remote = vec![0xff, b'u', 0x00];
        build_v8_catalog(&db).await;

        let store = TursoStore::open(&db).await.expect("upgrade to v9");
        assert_eq!(store.schema_version().expect("version"), 9);

        let members = store
            .list_group_members("github.com/legacy/repo")
            .await
            .expect("members");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].remote_name, group_remote);
        assert!(!store
            .add_group_member(
                "github.com/legacy/repo",
                "git:legacy",
                &members[0].remote_name,
                "fetch",
                300,
            )
            .await
            .expect("existing edge remains unique"));

        let new_group_remote = b"origin\0\xff";
        let mut batch = WriterBatch::new();
        TursoStore::buffer_add_group_member(
            &mut batch,
            "github.com/legacy/repo",
            "git:legacy",
            new_group_remote,
            "fetch",
            400,
        );
        TursoStore::buffer_record_remote_refresh(
            &mut batch,
            &NewRemoteRefresh {
                store_id: "git:legacy",
                remote_name: &refresh_remote,
                status: "failed",
                observed_at_ms: 500,
                duration_ms: Some(10),
                refs_updated: 0,
                refs_current_json: None,
                refs_deleted_json: None,
                detail: Some("resume"),
            },
        );
        store.flush(&mut batch).await.expect("flush v9 key writes");

        let members = store
            .list_group_members("github.com/legacy/repo")
            .await
            .expect("members after buffered insert");
        assert_eq!(members.len(), 2);
        assert!(members
            .iter()
            .any(|member| member.remote_name == new_group_remote));

        let refresh = store
            .get_remote_refresh("git:legacy", &refresh_remote)
            .await
            .expect("get migrated refresh")
            .expect("refresh row");
        assert_eq!(refresh.remote_name, refresh_remote);
        assert_eq!(refresh.status, "failed");
        assert_eq!(refresh.refs_updated, 0);
        assert_eq!(refresh.detail.as_deref(), Some("resume"));

        // The derived keys are TEXT encodings; raw bytes remain available
        // from the unindexed BLOB fields and are never decoded as UTF-8.
        let mut rows = store
            .connection()
            .query(
                "SELECT remote_name_key FROM group_members WHERE group_id = ?1 AND remote_name = ?2",
                vec![
                    turso::Value::Text("github.com/legacy/repo".to_string()),
                    turso::Value::Blob(group_remote.clone()),
                ],
            )
            .await
            .expect("group key query");
        let row = rows.next().await.expect("next").expect("key row");
        assert_eq!(
            row.get_value(0).expect("key"),
            turso::Value::Text("6F8000".into())
        );
        drop(rows);

        let mut rows = store
            .connection()
            .query(
                "SELECT remote_name_key FROM remote_refreshes WHERE store_id = ?1",
                vec![turso::Value::Text("git:legacy".to_string())],
            )
            .await
            .expect("refresh key query");
        let row = rows.next().await.expect("next").expect("key row");
        assert_eq!(
            row.get_value(0).expect("key"),
            turso::Value::Text("FF7500".into())
        );
        drop(rows);
        store.close().await.expect("close");
    });
}

#[test]
fn scan_event_journal_replays_and_dedupes() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        assert_eq!(store.last_event_seq("scan-a").await.expect("seq"), None);

        for seq in 1..=3u64 {
            let records = format!(r#"{{"n":{seq}}}"#);
            assert!(store
                .append_scan_event(&NewScanEvent {
                    scan_id: "scan-a",
                    seq,
                    catalog_rev: seq,
                    event_offset: 0,
                    event_type: "location_found",
                    op: "add",
                    reset: false,
                    records: records.as_bytes(),
                })
                .await
                .expect("append"));
        }
        // Same seq redelivered: idempotent, first bytes win.
        assert!(!store
            .append_scan_event(&NewScanEvent {
                scan_id: "scan-a",
                seq: 2,
                catalog_rev: 99,
                event_offset: 9,
                event_type: "location_found",
                op: "add",
                reset: true,
                records: b"{}",
            })
            .await
            .expect("redeliver"));
        // Same seq under another scan: independent (composite key).
        assert!(store
            .append_scan_event(&NewScanEvent {
                scan_id: "scan-b",
                seq: 1,
                catalog_rev: 1,
                event_offset: 0,
                event_type: "scan_started",
                op: "add",
                reset: false,
                records: b"{}",
            })
            .await
            .expect("other scan"));

        assert_eq!(store.last_event_seq("scan-a").await.expect("seq"), Some(3));
        let all = store
            .read_scan_events("scan-a", 0, 100)
            .await
            .expect("read");
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].seq, 1);
        assert_eq!(all[1].records, b"{\"n\":2}");
        assert!(!all[1].reset);
        let tail = store
            .read_scan_events("scan-a", 2, 100)
            .await
            .expect("read");
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].seq, 3);
        let capped = store.read_scan_events("scan-a", 0, 2).await.expect("read");
        assert_eq!(capped.len(), 2);
        store.close().await.expect("close");
    });
}

#[test]
fn github_groups_keep_fork_edges_separate() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let now = now_ms();

        assert!(store
            .upsert_github_group(
                "github.com/upstream/repo",
                "github.com",
                "upstream",
                "repo",
                now
            )
            .await
            .expect("group"));
        assert!(!store
            .upsert_github_group(
                "github.com/upstream/repo",
                "github.com",
                "upstream",
                "repo",
                now
            )
            .await
            .expect("group again"));
        assert!(store
            .upsert_github_group("github.com/fork/repo", "github.com", "fork", "repo", now)
            .await
            .expect("fork group"));

        // One store, two remotes: fork remote + upstream remote stay distinct.
        assert!(store
            .add_group_member("github.com/fork/repo", "git:aaa", b"origin", "fetch", now)
            .await
            .expect("member"));
        assert!(store
            .add_group_member(
                "github.com/upstream/repo",
                "git:aaa",
                b"upstream",
                "fetch",
                now
            )
            .await
            .expect("member"));
        assert!(!store
            .add_group_member("github.com/fork/repo", "git:aaa", b"origin", "fetch", now)
            .await
            .expect("member again"));

        let group = store
            .get_github_group("github.com/fork/repo")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(group.account, "fork");
        let members = store
            .list_group_members("github.com/fork/repo")
            .await
            .expect("list");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].remote_name, b"origin");
        let groups = store.groups_for_instance("git:aaa").await.expect("groups");
        assert_eq!(groups.len(), 2);
        store.close().await.expect("close");
    });
}

#[test]
fn generation_scope_key_defaults_legacy_then_sets() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let id = store
            .create_generation("roots", "running", None, now_ms())
            .await
            .expect("generation");
        let row = store.get_generation(id).await.expect("get").expect("row");
        assert_eq!(row.scope_key, None);

        store
            .set_generation_scope_key(id, "v2:roots:/a,/b:exclusions::policy:default")
            .await
            .expect("set");
        let row = store.get_generation(id).await.expect("get").expect("row");
        assert_eq!(
            row.scope_key.as_deref(),
            Some("v2:roots:/a,/b:exclusions::policy:default")
        );
        store.close().await.expect("close");
    });
}

#[test]
fn v3_remote_refresh_latest_attempt_wins() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        // Never attempted: explicit None, not a fabricated row.
        assert!(store
            .get_remote_refresh("git:aaa", b"origin")
            .await
            .expect("get")
            .is_none());

        store
            .record_remote_refresh(&NewRemoteRefresh {
                store_id: "git:aaa",
                remote_name: b"origin",
                status: "success",
                observed_at_ms: 200,
                duration_ms: Some(100),
                refs_updated: 3,
                refs_current_json: Some(r#"["refs/remotes/origin/main"]"#),
                refs_deleted_json: None,
                detail: None,
            })
            .await
            .expect("record");
        let row = store
            .get_remote_refresh("git:aaa", b"origin")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(row.status, "success");
        assert_eq!(row.observed_at_ms, 200);
        assert_eq!(row.duration_ms, Some(100));
        assert_eq!(row.refs_updated, 3);
        assert_eq!(
            row.refs_current_json.as_deref(),
            Some(r#"["refs/remotes/origin/main"]"#)
        );
        assert_eq!(row.refs_deleted_json, None);
        assert_eq!(row.detail, None);
        assert_eq!(row.remote_name, b"origin");

        // A later attempt replaces: the row always reflects the latest.
        store
            .record_remote_refresh(&NewRemoteRefresh {
                store_id: "git:aaa",
                remote_name: b"origin",
                status: "failed",
                observed_at_ms: 310,
                duration_ms: Some(10),
                refs_updated: 0,
                refs_current_json: None,
                refs_deleted_json: None,
                detail: Some("timeout after 30s"),
            })
            .await
            .expect("record failed");
        let row = store
            .get_remote_refresh("git:aaa", b"origin")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(row.status, "failed");
        assert_eq!(row.detail.as_deref(), Some("timeout after 30s"));

        // A second remote lists alongside, ordered by name; an
        // untouched store still reads empty.
        store
            .record_remote_refresh(&NewRemoteRefresh {
                store_id: "git:aaa",
                remote_name: b"upstream",
                status: "unsupported",
                observed_at_ms: 300,
                duration_ms: None,
                refs_updated: 0,
                refs_current_json: None,
                refs_deleted_json: None,
                detail: Some("refspec writes to local branches"),
            })
            .await
            .expect("record upstream");
        let listed = store.list_remote_refreshes("git:aaa").await.expect("list");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].remote_name, b"origin");
        assert_eq!(listed[1].remote_name, b"upstream");
        assert!(store
            .list_remote_refreshes("git:zzz")
            .await
            .expect("list")
            .is_empty());
        store.close().await.expect("close");
    });
}

#[test]
fn v3_ref_freshness_labels_and_upsert_preserves() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let reference = NewRef {
            id: "ref:aaa:rt:main",
            instance_id: "git:aaa",
            checkout_scope_id: None,
            kind: "remote_tracking",
            name: b"refs/remotes/origin/main",
            oid: Some(b"0123456789abcdef0123456789abcdef01234567".as_slice()),
            algo: Some("sha1"),
            symbolic_target: None,
            upstream: None,
            state: "valid",
        };
        store.upsert_ref(&reference, 100).await.expect("upsert");
        let refs = store.list_refs("git:aaa").await.expect("list");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].freshness, None);
        assert_eq!(refs[0].freshness_at_ms, None);

        assert!(store
            .label_ref_freshness("ref:aaa:rt:main", "current", 200)
            .await
            .expect("label"));
        assert!(!store
            .label_ref_freshness("ref:missing", "current", 200)
            .await
            .expect("label missing"));
        let refs = store.list_refs("git:aaa").await.expect("list");
        assert_eq!(refs[0].freshness.as_deref(), Some("current"));
        assert_eq!(refs[0].freshness_at_ms, Some(200));

        // Re-observation updates the observed columns but preserves
        // the freshness label (ON CONFLICT, not REPLACE).
        store
            .upsert_ref(&reference, 300)
            .await
            .expect("upsert again");
        let refs = store.list_refs("git:aaa").await.expect("list");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].observed_at_ms, 300);
        assert_eq!(refs[0].freshness.as_deref(), Some("current"));
        assert_eq!(refs[0].freshness_at_ms, Some(200));
        store.close().await.expect("close");
    });
}

#[test]
fn v3_ref_oid_reobservation_updates_oid_only() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let reference = NewRef {
            id: "ref:aaa:rt:main",
            instance_id: "git:aaa",
            checkout_scope_id: None,
            kind: "remote_tracking",
            name: b"refs/remotes/origin/main",
            oid: Some(b"0123456789abcdef0123456789abcdef01234567".as_slice()),
            algo: Some("sha1"),
            symbolic_target: None,
            upstream: None,
            state: "valid",
        };
        store.upsert_ref(&reference, 100).await.expect("upsert");
        store
            .label_ref_freshness("ref:aaa:rt:main", "current", 200)
            .await
            .expect("label");

        // Hit: oid + observed time move, everything else stays.
        assert!(store
            .update_ref_oid(
                "ref:aaa:rt:main",
                b"ffffffffffffffffffffffffffffffffffffffff",
                400
            )
            .await
            .expect("update"));
        // Miss: no row, no write.
        assert!(!store
            .update_ref_oid("ref:missing", b"abcd", 400)
            .await
            .expect("update missing"));
        let refs = store.list_refs("git:aaa").await.expect("list");
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0].oid.as_deref(),
            Some(b"ffffffffffffffffffffffffffffffffffffffff".as_slice())
        );
        assert_eq!(refs[0].observed_at_ms, 400);
        assert_eq!(refs[0].freshness.as_deref(), Some("current"));
        assert_eq!(refs[0].freshness_at_ms, Some(200));
        assert_eq!(refs[0].algo.as_deref(), Some("sha1"));
        assert_eq!(refs[0].state, "valid");
        store.close().await.expect("close");
    });
}

/// Contract C2 fail-closed: a catalog marked NEWER than this binary is
/// refused by the owner open, and the refusal happens before any write —
/// the marker and the rows survive byte-identical.
#[test]
fn newer_catalog_refused_with_data_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        store
            .create_scan_request(
                &NewScan {
                    id: "scan-keep",
                    url_raw: b"https://github.com/o/r",
                    url_canonical: None,
                    scope: "roots",
                    status_mode: "summary",
                    report_dest: None,
                    targets_json: None,
                    format: None,
                    all_targets: None,
                },
                now_ms(),
            )
            .await
            .expect("seed row");
        store.close().await.expect("close");

        // A future binary's marker: one past the last chain entry.
        let future = CURRENT_SCHEMA_VERSION + 1;
        let path_str = db.to_str().expect("utf8 db path");
        let conn = turso::Builder::new_local(path_str)
            .build()
            .await
            .expect("turso build")
            .connect()
            .expect("turso connect");
        conn.execute(
            "UPDATE meta SET value = ?1 WHERE name = 'schema_version'",
            vec![turso::Value::Text(future.to_string())],
        )
        .await
        .expect("forge future marker");
        drop(conn);

        let err = match TursoStore::open(&db).await {
            Ok(_) => panic!("newer catalog must be refused"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("newer than this binary"),
            "unexpected error: {err}"
        );

        // Data preserved: marker and row untouched by the refused open.
        let conn = turso::Builder::new_local(path_str)
            .build()
            .await
            .expect("turso build")
            .connect()
            .expect("turso connect");
        let mut rows = conn
            .query("SELECT value FROM meta WHERE name = 'schema_version'", ())
            .await
            .expect("read marker");
        let row = rows.next().await.expect("next").expect("marker row");
        assert_eq!(
            row.get_value(0).expect("value"),
            turso::Value::Text(future.to_string()),
            "refused open must not touch the version marker"
        );
        drop(rows);
        let mut rows = conn
            .query("SELECT state FROM scan_requests WHERE id = 'scan-keep'", ())
            .await
            .expect("read scan");
        let row = rows.next().await.expect("next").expect("scan row");
        assert_eq!(
            row.get_value(0).expect("state"),
            turso::Value::Text("running".to_string()),
            "refused open must preserve existing rows"
        );
        drop(rows);
        drop(conn);
    });
}

/// Contract C2: read-only opens never migrate. A legacy (v1) catalog is
/// refused by `open_read_only` with its marker untouched; only an owner
/// open upgrades it, after which read-only open succeeds.
#[test]
fn read_only_open_never_migrates() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        build_v1_catalog(&db).await;

        let err = match TursoStore::open_read_only(&db).await {
            Ok(_) => panic!("stale catalog must be refused read-only"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("refusing read-only open"),
            "unexpected error: {err}"
        );

        // The refusal performed no hidden upgrade: marker still v1.
        let path_str = db.to_str().expect("utf8 db path");
        let conn = turso::Builder::new_local(path_str)
            .build()
            .await
            .expect("turso build")
            .connect()
            .expect("turso connect");
        let mut rows = conn
            .query("SELECT value FROM meta WHERE name = 'schema_version'", ())
            .await
            .expect("read marker");
        let row = rows.next().await.expect("next").expect("marker row");
        assert_eq!(
            row.get_value(0).expect("value"),
            turso::Value::Text("1".to_string()),
            "read-only open must never migrate"
        );
        drop(rows);
        drop(conn);

        // Owner open upgrades; read-only open then serves the catalog.
        let store = TursoStore::open(&db).await.expect("owner open upgrades");
        assert_eq!(store.schema_version().expect("version"), 9);
        store.close().await.expect("close");
        let reader = TursoStore::open_read_only(&db)
            .await
            .expect("read-only open of current catalog");
        assert_eq!(reader.schema_version().expect("version"), 9);
        assert!(reader.get_scan("scan-v1").await.expect("get").is_some());
        reader.close().await.expect("close reader");
    });
}

/// Contract C2 unknown-shape fail-closed: a catalog whose marker claims
/// v2 but whose physical layout does not match the shipped v2 producer
/// (here: `group_members` absent) must abort the v9 rebuild inside its
/// migration transaction — the open fails loudly, no partial rebuild
/// survives, and pre-existing rows are preserved.
#[test]
fn unknown_layout_fails_closed_with_data_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let path_str = db.to_str().expect("utf8 db path");
        let conn = turso::Builder::new_local(path_str)
            .build()
            .await
            .expect("turso build")
            .connect()
            .expect("turso connect");
        // Genuine v1 + v2 migrations, then an unknown divergence: the
        // group_members table is dropped while the marker keeps claiming
        // v2. The v9 rebuild (INSERT ... SELECT FROM group_members) must
        // fail closed against this shape.
        let chain = repo_scan::store::migrations();
        conn.execute_batch(chain[0].sql).await.expect("v1 sql");
        conn.execute_batch(chain[1].sql).await.expect("v2 sql");
        conn.execute_batch("DROP TABLE group_members;")
            .await
            .expect("diverge layout");
        conn.execute(
            "INSERT INTO meta (name, value) VALUES ('schema_version', '2')",
            (),
        )
        .await
        .expect("v2 marker");
        conn.execute(
            "INSERT INTO scan_requests (id, url_raw, url_canonical, scope, status_mode, \
                report_dest, state, created_at_ms, updated_at_ms) \
                VALUES ('scan-survives', ?1, NULL, 'roots', 'summary', NULL, 'complete', 1, 2)",
            vec![turso::Value::Blob(b"https://github.com/o/r".to_vec())],
        )
        .await
        .expect("seed v1-era row");
        drop(conn);

        let err = match TursoStore::open(&db).await {
            Ok(_) => panic!("unknown layout must fail closed"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("group_members"),
            "error should name the missing table: {err}"
        );

        // Data preserved: the pre-existing row survived, the marker never
        // reached v9, and no partial v9 rebuild table leaked.
        let conn = turso::Builder::new_local(path_str)
            .build()
            .await
            .expect("turso build")
            .connect()
            .expect("turso connect");
        let mut rows = conn
            .query("SELECT value FROM meta WHERE name = 'schema_version'", ())
            .await
            .expect("read marker");
        let row = rows.next().await.expect("next").expect("marker row");
        let marker = match row.get_value(0).expect("value") {
            turso::Value::Text(value) => value,
            other => panic!("marker must stay TEXT: {other:?}"),
        };
        assert_ne!(
            marker, "9",
            "failed migration must not stamp the final version (got {marker})"
        );
        drop(rows);
        let mut rows = conn
            .query(
                "SELECT state FROM scan_requests WHERE id = 'scan-survives'",
                (),
            )
            .await
            .expect("read scan");
        let row = rows.next().await.expect("next").expect("scan row");
        assert_eq!(
            row.get_value(0).expect("state"),
            turso::Value::Text("complete".to_string()),
            "unknown-layout refusal must preserve existing rows"
        );
        drop(rows);
        let mut rows = conn
            .query(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                    AND name = 'group_members_v9'",
                (),
            )
            .await
            .expect("check partial rebuild");
        assert!(
            rows.next().await.expect("next").is_none(),
            "partial v9 rebuild table must roll back"
        );
        drop(rows);
        drop(conn);
    });
}
