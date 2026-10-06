//! RSF-751/AC46/F06D production-report-path regression tests: the
//! lib file-emission gate, batched directory observations, and bounded
//! volume/event/candidate/alias scans with REPORT-01 completeness.
//!
//! Fixture-scale only (tempdirs under `/tmp` via `tempfile`): no machine
//! scans. Run-loop tests drive `src/main.rs` directly (included as a
//! module) through its `#[cfg(test)]` hooks — the same code the command
//! paths execute.

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

use repo_scan::config;
use repo_scan::events::{volume_cursor_from_rows, MAX_PENDING_INVALIDATIONS};
use repo_scan::model::StatusMode;
use repo_scan::report::builder::{verify_staged_report, ReportInputs, ReportPipeline};
use repo_scan::store::{
    NewCheckout, NewGitInstance, NewRef, NewRemote, NewStatus, NewVolume, Store, TursoStore,
    WriterBatch,
};
use std::path::PathBuf;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn test_inputs(report_id: &str) -> ReportInputs {
    ReportInputs {
        report_id: report_id.to_string(),
        created_at_ms: 1_759_154_400_000,
        scan_id: "scan-test-1".to_string(),
        generation: 1,
        epoch: 1,
        catalog_revision: 7,
        target_url: "https://github.com/OWNER/REPO".to_string(),
        canonical_url: Some("https://github.com/owner/repo".to_string()),
        targets: vec![],
        scope: "roots".to_string(),
        scan_state: "complete".to_string(),
        started_at_ms: 1_759_154_398_000,
        finished_at_ms: Some(1_759_154_400_000),
        superseded_by: None,
        cached: false,
        status_mode: StatusMode::Summary,
        directories_complete: 2,
        tasks_pending: 0,
        scope_boundaries: vec!["Only the explicit fixture root was requested.".to_string()],
        profile: "conservative".to_string(),
        cpu_target_cores: 1.0,
        rss_target_bytes: 268_435_456,
        peak_rss_bytes: None,
        cpu_seconds: None,
        enumerated_entries: 8,
        db_transactions: 3,
        db_sync_calls: None,
        source_commit: None,
        include_nonmatching: false,
        coverage_filesystem: None,
        coverage_identity: None,
        coverage_status: None,
        roots: Vec::new(),
        storage_links: Vec::new(),
        aliases: Vec::new(),
        candidates: Vec::new(),
        generated_artifacts: Vec::new(),
    }
}

fn seed_catalog(store: &TursoStore, now: i64) {
    runtime().block_on(async {
        store
            .upsert_volume(
                &NewVolume {
                    id: "vol-1",
                    native_identity: Some("native-1"),
                    namespace: "ns-1",
                    filesystem: Some("apfs"),
                    kind: "local",
                    state: "available",
                },
                Some(now),
            )
            .await
            .expect("volume");
        let root = store
            .upsert_dir(None, b"/", "/", "vol-1", "obj-root", "1", now)
            .await
            .expect("root dir");
        store
            .upsert_dir(Some(root), b"repo", "/repo", "vol-1", "obj-repo", "1", now)
            .await
            .expect("child dir");
        store
            .upsert_git_instance(
                &NewGitInstance {
                    id: "repo-1",
                    git_path: b"/repo/.git",
                    common_path: b"/repo/.git",
                    incarnation: "1",
                    format: "git-files",
                    bare: Some(false),
                    object_format: "sha1",
                    disposition: "confirmed",
                    evidence_json: "[\"Effective origin fetch URL matches the target.\"]",
                },
                now,
            )
            .await
            .expect("instance");
        store
            .upsert_checkout(
                &NewCheckout {
                    id: "co-1",
                    instance_id: "repo-1",
                    root_path: Some(b"/repo"),
                    git_path: b"/repo/.git",
                    relationship: "main",
                    availability: "present",
                    head_state: "branch",
                    head_ref: Some(b"refs/heads/main"),
                    head_oid: Some(b"1111111111111111111111111111111111111111"),
                    head_algo: Some("sha1"),
                },
                now,
            )
            .await
            .expect("checkout");
        store
            .upsert_ref(
                &NewRef {
                    id: "ref-1",
                    instance_id: "repo-1",
                    checkout_scope_id: None,
                    kind: "local",
                    name: b"refs/heads/main",
                    oid: Some(b"1111111111111111111111111111111111111111"),
                    algo: Some("sha1"),
                    symbolic_target: None,
                    upstream: None,
                    state: "valid",
                },
                now,
            )
            .await
            .expect("ref");
        store
            .upsert_remote(
                &NewRemote {
                    id: "rem-1",
                    instance_id: "repo-1",
                    checkout_scope_id: None,
                    name: b"origin",
                    role: "fetch",
                    url: b"https://github.com/owner/repo.git",
                    canonical_url: Some(b"https://github.com/owner/repo"),
                },
                now,
            )
            .await
            .expect("remote");
        store
            .record_status(
                &NewStatus {
                    checkout_id: "co-1",
                    mode: "summary",
                    state: "complete",
                    started_ms: Some(now - 10),
                    finished_ms: Some(now),
                    staged: Some(1),
                    unstaged: Some(2),
                    untracked: Some(3),
                    untracked_units: "collapsed_entries",
                    submodules: "checked",
                    unknown_fields: "[]",
                    input_fingerprint: None,
                    observed_rev: 1,
                },
                now,
            )
            .await
            .expect("status");
    });
}

/// AC46/F06D: the lib file-emission entry point verifies staged bytes
/// before retaining or shipping them, like production's
/// `verified_retain_and_publish`. A staged report that fails REPORT-01
/// (here via an off-enum coverage override) is refused with nothing
/// retained and the destination untouched; a valid report still emits.
#[test]
fn emit_to_file_verifies_before_retain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    let store = {
        let db = state_dir.join("payload").join("catalog.db");
        runtime().block_on(async { TursoStore::open(&db).await.expect("open") })
    };
    let now = 1_759_154_400_000;
    seed_catalog(&store, now);
    let staging = state_dir.join("payload").join("report_staging");
    let snapshots = state_dir.join("payload").join("report_snapshots");

    let mut invalid = test_inputs("report-bogus-1");
    invalid.coverage_status = Some("bogus".to_string());
    let bad_dest: PathBuf = dir.path().join("repo").join("bad.json");
    repo_scan::privacy::private_dir_0700(bad_dest.parent().expect("parent")).expect("mkdir");
    let err = runtime()
        .block_on(async {
            ReportPipeline::emit_to_file(
                &store, &invalid, &bad_dest, &state_dir, &staging, &snapshots, now,
            )
            .await
        })
        .expect_err("invalid staged report must be refused");
    assert!(
        err.to_string().contains("refusing invalid staged report"),
        "refusal names the gate: {err}"
    );
    assert!(!bad_dest.exists(), "destination untouched by refusal");
    assert!(
        !snapshots.join("report-bogus-1.json").exists(),
        "refused bytes leave no snapshot file"
    );
    let retained = runtime().block_on(async {
        store
            .get_report_snapshot("report-bogus-1")
            .await
            .expect("lookup")
    });
    assert!(retained.is_none(), "refused bytes leave no snapshot row");

    // Positive control through the same entry point.
    let valid = test_inputs("report-valid-1");
    let dest: PathBuf = dir.path().join("repo").join("report.json");
    let publication = runtime()
        .block_on(async {
            ReportPipeline::emit_to_file(
                &store, &valid, &dest, &state_dir, &staging, &snapshots, now,
            )
            .await
        })
        .expect("valid report emits");
    assert!(publication.published);
    verify_staged_report(&dest).expect("dest validates");
}

/// AC46/F06D: buffered directory observations count attempts in SQL, so
/// the run loop never flushes just to read the current generation back.
/// First observation seeds generation 1; repeats bump without any read,
/// including twice within one batch.
#[test]
fn dir_observation_bump_counts_without_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("catalog.db");
    let store = runtime().block_on(async { TursoStore::open(&db).await.expect("open") });
    let now = 1_700_000_000_000;
    let dir_id = runtime().block_on(async {
        store
            .upsert_dir(None, b"w", "/w", "dev:7", "ino-7", "inc-7", now)
            .await
            .expect("dir")
    });

    let mut batch = WriterBatch::new();
    TursoStore::buffer_record_dir_observation_bumped(&mut batch, dir_id, 1, true, 4, None, now);
    let applied = runtime().block_on(async { store.flush(&mut batch).await.expect("flush") });
    assert_eq!(applied, 2, "update plus seed insert");
    let first = runtime()
        .block_on(async { store.get_dir_observation(dir_id, 1).await.expect("read") })
        .expect("observation row");
    assert_eq!(
        (first.entry_generation, first.completed, first.entries_seen),
        (1, true, 4)
    );

    // No read between buffers: the generation still advances.
    let mut batch = WriterBatch::new();
    TursoStore::buffer_record_dir_observation_bumped(&mut batch, dir_id, 1, true, 9, None, now + 1);
    TursoStore::buffer_record_dir_observation_bumped(
        &mut batch,
        dir_id,
        1,
        false,
        11,
        Some("partial"),
        now + 2,
    );
    runtime().block_on(async { store.flush(&mut batch).await.expect("flush") });
    let third = runtime()
        .block_on(async { store.get_dir_observation(dir_id, 1).await.expect("read") })
        .expect("observation row");
    assert_eq!(
        (
            third.entry_generation,
            third.completed,
            third.entries_seen,
            third.error.as_deref()
        ),
        (3, false, 11, Some("partial"))
    );
}

/// Seed one volume's journal across two histories: `old` rows under
/// `uuid-old`, then `new` rows under `uuid-new`, cursors ascending from
/// 1. Returns the row ids of the new-history rows (ascending).
fn seed_journal(store: &TursoStore, volume: &str, old: u64, new: u64, now: i64) -> Vec<i64> {
    runtime().block_on(async {
        for cursor in 1..=old {
            let rendered = cursor.to_string();
            store
                .append_event(volume, "uuid-old", &rendered, true, now)
                .await
                .expect("append old");
        }
        for cursor in old + 1..=old + new {
            let rendered = cursor.to_string();
            store
                .append_event(volume, "uuid-new", &rendered, true, now)
                .await
                .expect("append new");
        }
        store
            .list_events(volume, "uuid-new")
            .await
            .expect("list new")
            .iter()
            .map(|row| row.id)
            .collect()
    })
}

/// AC46/F06D: stored cursors derive from bounded pages yet equal the
/// whole-history derivation. 536 rows force two pages; the paged cursor
/// matches `volume_cursor_from_rows` over every row.
#[test]
fn stored_cursors_page_equivalence() {
    let chunk = main_under_test::test_load_chunk_rows();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("catalog.db");
    let store = runtime().block_on(async { TursoStore::open(&db).await.expect("open") });
    let now = 1_700_000_000_000;
    let new_ids = seed_journal(&store, "vol-page", 16, 520, now);
    // Reconcile the first 100 new-history rows (cursors 17..=116).
    runtime().block_on(async {
        for id in new_ids.iter().take(100) {
            store.mark_event_reconciled(*id).await.expect("mark");
        }
    });

    let scan = runtime().block_on(async {
        main_under_test::test_stored_cursors(&store)
            .await
            .expect("scan")
    });
    assert_eq!(scan.pages, 2, "536 rows page as 512 + 24");
    assert_eq!(scan.peak_page, chunk as usize, "one full page in flight");
    let cursor = scan.cursors.get("vol-page").expect("volume cursor").clone();

    let (old_rows, new_rows) = runtime().block_on(async {
        (
            store
                .list_events("vol-page", "uuid-old")
                .await
                .expect("old"),
            store
                .list_events("vol-page", "uuid-new")
                .await
                .expect("new"),
        )
    });
    let mut all = old_rows;
    all.extend(new_rows);
    let oracle = volume_cursor_from_rows("vol-page", &all).expect("oracle");
    assert_eq!(cursor.uuid, oracle.uuid.map(|u| u.0));
    assert_eq!(cursor.ingested, oracle.ingested.map(|c| c.0));
    assert_eq!(cursor.reconciled, oracle.reconciled.map(|c| c.0));
    assert_eq!(
        cursor,
        main_under_test::TestVolumeCursor {
            uuid: Some("uuid-new".to_string()),
            ingested: Some(536),
            reconciled: Some(116),
        }
    );
}

/// AC46/F06D: report cursors cover the current history only, streaming
/// it in bounded pages. 520 current-history rows force two pages with
/// full maxima; the older history contributes nothing.
#[test]
fn report_cursors_current_uuid_pages() {
    let chunk = main_under_test::test_load_chunk_rows();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("catalog.db");
    let store = runtime().block_on(async { TursoStore::open(&db).await.expect("open") });
    let now = 1_700_000_000_000;
    let new_ids = seed_journal(&store, "vol-report", 16, 520, now);
    runtime().block_on(async {
        for id in new_ids.iter().take(100) {
            store.mark_event_reconciled(*id).await.expect("mark");
        }
    });

    let scan = runtime().block_on(async {
        main_under_test::test_report_cursors(&store)
            .await
            .expect("scan")
    });
    assert_eq!(scan.pages, 2, "520 current rows page as 512 + 8");
    assert_eq!(scan.peak_page, chunk as usize, "one full page in flight");
    assert_eq!(
        scan.cursors.get("vol-report").expect("volume cursors"),
        &main_under_test::TestRootCursors {
            history_uuid: Some("uuid-new".to_string()),
            ingested: Some("536".to_string()),
            reconciled: Some("116".to_string()),
        }
    );
}

/// AC46/F06D: error derivations page the gap table (520 gaps, two
/// pages) while deriving every candidate — REPORT-01 completeness with
/// one page outstanding.
#[test]
fn error_derivations_multichunk_complete() {
    let chunk = main_under_test::test_load_chunk_rows();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("catalog.db");
    let store = runtime().block_on(async { TursoStore::open(&db).await.expect("open") });
    let now = 1_700_000_000_000;
    let total = (chunk + 8) as usize;
    runtime().block_on(async {
        for n in 0..total {
            let scope = config::scope_key_for_dir(&dir.path().join(format!("d{n}")));
            let id = format!("gap-{n:04}");
            store
                .record_error(
                    &id,
                    &scope,
                    "probe-failed",
                    "fixture probe failure",
                    None,
                    now,
                )
                .await
                .expect("gap");
        }
    });

    let scan = runtime().block_on(async {
        main_under_test::test_scan_error_derivations(&store, &[])
            .await
            .expect("derivations")
    });
    assert_eq!(scan.scanned, total as u64);
    assert_eq!(scan.chunks, 2, "gaps page across two chunks");
    assert_eq!(scan.peak_chunk, chunk as usize, "one full page in flight");
    assert_eq!(scan.candidates, total, "every gap derives its candidate");
}

/// AC46/F06D: instance derivations page the instance table (520
/// instances, two pages) while deriving every candidate and storage
/// edge — REPORT-01 completeness with one page outstanding.
#[test]
fn instance_derivations_multichunk_complete() {
    let chunk = main_under_test::test_load_chunk_rows();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("catalog.db");
    let store = runtime().block_on(async { TursoStore::open(&db).await.expect("open") });
    let now = 1_700_000_000_000;
    let total = (chunk + 8) as usize;
    runtime().block_on(async {
        for n in 0..total {
            // Distinct, nonexistent git/common paths: no filesystem-derived
            // edges, so each instance contributes exactly its
            // common-directory edge plus its unresolvable candidate.
            let git = dir.path().join(format!("g{n}"));
            let common = dir.path().join(format!("c{n}"));
            let git_bytes = config::path_as_bytes(&git);
            let common_bytes = config::path_as_bytes(&common);
            let id = format!("inst-{n:04}");
            store
                .upsert_git_instance(
                    &NewGitInstance {
                        id: &id,
                        git_path: &git_bytes,
                        common_path: &common_bytes,
                        incarnation: "1",
                        format: "git-files",
                        bare: Some(false),
                        object_format: "sha1",
                        disposition: "unresolvable_identity",
                        evidence_json: "[]",
                    },
                    now,
                )
                .await
                .expect("instance");
        }
    });

    let scan = runtime().block_on(async {
        main_under_test::test_scan_instance_derivations(&store)
            .await
            .expect("derivations")
    });
    assert_eq!(scan.scanned, total as u64);
    assert_eq!(scan.chunks, 2, "instances page across two chunks");
    assert_eq!(scan.peak_chunk, chunk as usize, "one full page in flight");
    assert_eq!(
        scan.candidates, total,
        "every instance derives its candidate"
    );
    assert_eq!(
        scan.storage_links, total,
        "every instance derives its common-directory edge"
    );
}

/// AC46/F06D: repeat alias observations collapse at insert (distinct
/// triples only), and applied invalidation scopes cap per volume with
/// an overflow flag instead of growing without bound.
#[test]
fn alias_dedupe_and_scope_cap() {
    assert_eq!(
        main_under_test::test_alias_dedupe(),
        (2, 2),
        "one triple twice plus a distinct triple records two"
    );
    let (recorded, overflowed) = main_under_test::test_applied_scopes_cap();
    assert_eq!(
        recorded, MAX_PENDING_INVALIDATIONS,
        "applied scopes cap per volume"
    );
    assert!(overflowed, "overflow is flagged for the reconciler");
}
