//! Catalog migration acceptance (goal Step 5/9/11, contracts D1/D2/D4/D5):
//! the append-only chain upgrades v1 catalogs without touching v1 rows,
//! and the new journal/group/scope/refresh APIs round-trip.
//!
//! The v1 catalog under test is built by executing the shipped v1
//! migration SQL through a direct connection — the same bytes production
//! applied — then reopened through [`TursoStore::open`].

use repo_scan::store::{
    now_ms, NewRef, NewRemoteRefresh, NewScan, NewScanEvent, Store, TursoStore,
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
    assert!(chain.len() >= 4, "v4 chain wired");
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
}

#[test]
fn fresh_open_is_v4_with_working_tables() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        assert_eq!(CURRENT_SCHEMA_VERSION, 4);
        assert_eq!(store.schema_version().expect("version"), 4);

        // v2 request columns persist through the extended insert.
        let now = now_ms();
        let inserted = store
            .create_scan_request(
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
                    fetch: Some(true),
                    workers: Some(6),
                },
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
        assert_eq!(store.schema_version().expect("version"), 4);

        // v1 rows survive byte-identical; v2/v3/v4 columns read NULL (legacy).
        let scan = store.get_scan("scan-v1").await.expect("get").expect("row");
        assert_eq!(scan.url_raw, b"https://github.com/o/r");
        assert_eq!(scan.state, "complete");
        assert_eq!(scan.targets_json, None);
        assert_eq!(scan.format, None);
        assert_eq!(scan.all_targets, None);
        assert_eq!(scan.fetch, None);
        assert_eq!(scan.workers, None);
        let generation = store.get_generation(1).await.expect("get").expect("gen");
        assert_eq!(generation.scope_policy, "roots");
        assert_eq!(generation.scope_key, None);

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

        // Reopen is idempotent: still v4, rows intact.
        let store = TursoStore::open(&db).await.expect("reopen");
        assert_eq!(store.schema_version().expect("version"), 4);
        assert!(store.get_scan("scan-v1").await.expect("get").is_some());
        assert_eq!(store.last_event_seq("scan-v1").await.expect("seq"), Some(1));
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
