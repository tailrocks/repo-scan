//! Catalog migration v2 acceptance (goal Step 5/9, contracts D1/D2/D4/D5):
//! the append-only chain upgrades v1 catalogs without touching v1 rows,
//! and the new journal/group/scope APIs round-trip.
//!
//! The v1 catalog under test is built by executing the shipped v1
//! migration SQL through a direct connection — the same bytes production
//! applied — then reopened through [`TursoStore::open`].

use repo_scan::store::{now_ms, NewScan, NewScanEvent, Store, TursoStore, CURRENT_SCHEMA_VERSION};

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
    assert!(chain.len() >= 2, "v2 chain wired");
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
fn fresh_open_is_v2_with_working_tables() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        assert_eq!(CURRENT_SCHEMA_VERSION, 2);
        assert_eq!(store.schema_version().expect("version"), 2);

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
        assert_eq!(store.schema_version().expect("version"), 2);

        // v1 rows survive byte-identical; v2 columns read NULL (legacy).
        let scan = store.get_scan("scan-v1").await.expect("get").expect("row");
        assert_eq!(scan.url_raw, b"https://github.com/o/r");
        assert_eq!(scan.state, "complete");
        assert_eq!(scan.targets_json, None);
        assert_eq!(scan.format, None);
        assert_eq!(scan.all_targets, None);
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

        // Reopen is idempotent: still v2, rows intact.
        let store = TursoStore::open(&db).await.expect("reopen");
        assert_eq!(store.schema_version().expect("version"), 2);
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
