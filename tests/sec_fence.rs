//! Finding-12/6/10 regression tests: one focused test per fix (finding 12
//! takes two: scheduling-time membership on all targets, plus unix
//! descriptor-relative traversal). Fixtures live under `/tmp` only via
//! `tempfile`; run-loop cases drive `src/main.rs` through its `#[cfg(test)]`
//! hooks — the same code production executes.

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

#[cfg(unix)]
use repo_scan::model::TaskState;
use repo_scan::report::encode::{cap_report_field, MAX_REPORT_FIELD_BYTES};
#[cfg(unix)]
use repo_scan::store::TaskOutcome;
use repo_scan::store::{now_ms, NewStatus, NewTask, Store, TursoStore, WriterBatch};
use repo_scan::walk::topology::ScopeFence;
#[cfg(unix)]
use repo_scan::walk::topology::{FenceError, FenceOpen};
use std::path::{Path, PathBuf};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

async fn open_generation(db: &Path) -> (TursoStore, u64) {
    let store = TursoStore::open(db).await.expect("open");
    let generation = store
        .create_generation("roots", "running", None, now_ms())
        .await
        .expect("generation");
    (store, generation)
}

/// Finding 12 (scheduling): `..` escapes and outside paths are refused
/// lexically; in-scope spellings pass. Pure string handling, no I/O.
#[test]
fn fence_refuses_dotdot_and_outside_paths() {
    let fence = ScopeFence::build(&[PathBuf::from("/root")]);
    assert!(fence.allows_path(Path::new("/root")));
    assert!(fence.allows_path(Path::new("/root/sub/deep")));
    assert!(!fence.allows_path(Path::new("/root/../etc")));
    assert!(!fence.allows_path(Path::new("/root/sub/../../etc")));
    assert!(!fence.allows_path(Path::new("/other")));
    assert!(!fence.allows_path(Path::new("relative/path")));
    assert!(!ScopeFence::default().allows_path(Path::new("/root")));
}

/// Finding 12 (execution, unix): pinned traversal opens the real
/// directory, refuses `..`/symlink escapes, and never follows a final
/// link; the production enum path completes in-scope work, parks
/// escapes, and schedules nothing for out-of-scope link targets.
#[cfg(unix)]
#[test]
fn fence_pins_execution_and_parks_escapes() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("root");
        let sub = root.join("sub");
        let outside = tmp.path().join("outside");
        repo_scan::privacy::private_dir_0700(&sub).unwrap();
        repo_scan::privacy::private_dir_0700(&outside).unwrap();
        repo_scan::privacy::private_write_0600(&sub.join("f.txt"), b"hi").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link_out")).unwrap();
        std::os::unix::fs::symlink("sub", root.join("link_in")).unwrap();

        let fence = ScopeFence::build(std::slice::from_ref(&root));

        // In-scope dir pins to its true path and streams children.
        let pinned = match fence.open_pinned(&sub).expect("pin sub") {
            FenceOpen::Dir(pinned) => pinned,
            FenceOpen::Symlink => panic!("sub is not a link"),
        };
        assert!(pinned.true_path().is_absolute());
        assert_eq!(pinned.true_path().file_name(), sub.file_name());
        let mut names: Vec<String> = Vec::new();
        for item in pinned.into_children(false).expect("children") {
            let child = item.expect("child");
            names.push(child.name.to_string_lossy().into_owned());
        }
        assert_eq!(names, vec![String::from("f.txt")]);

        // The root itself pins (identity matches the fence record).
        assert!(matches!(fence.open_pinned(&root), Ok(FenceOpen::Dir(_))));

        // `..` escape refuses even though the target exists.
        let escape = root.join("..").join("outside");
        assert!(matches!(
            fence.open_pinned(&escape),
            Err(FenceError::OutOfScope(_))
        ));

        // A final link is reported, never followed ...
        assert!(matches!(
            fence.open_pinned(&root.join("link_out")),
            Ok(FenceOpen::Symlink)
        ));
        // ... and its resolved target schedules nothing (out of scope).
        assert!(!fence.allows_path(&outside));

        // Production wiring: in-scope enum completes through the pin.
        {
            let db = tmp.path().join("in.db");
            let (store, generation) = open_generation(&db).await;
            let outcome = main_under_test::test_enum_fenced_outcome(
                &store,
                std::slice::from_ref(&root),
                generation,
                &sub,
            )
            .await
            .expect("enum");
            assert!(matches!(outcome, TaskOutcome::Complete), "{outcome:?}");
        }
        // Production wiring: `..` escape parks as an out-of-scope gap.
        {
            let db = tmp.path().join("escape.db");
            let (store, generation) = open_generation(&db).await;
            let outcome = main_under_test::test_enum_fenced_outcome(
                &store,
                std::slice::from_ref(&root),
                generation,
                &escape,
            )
            .await
            .expect("enum");
            match outcome {
                TaskOutcome::Parked { state, reason } => {
                    assert!(matches!(state, TaskState::Unavailable));
                    assert!(reason.contains("outside the scan scope"), "{reason}");
                }
                other => panic!("escape must park, got {other:?}"),
            }
        }
        // Production wiring: a task path that IS a link resolves through
        // link handling; its out-of-scope target schedules no work (the
        // only non-terminal task left is the hook's own leased one).
        {
            let db = tmp.path().join("link.db");
            let (store, generation) = open_generation(&db).await;
            let outcome = main_under_test::test_enum_fenced_outcome(
                &store,
                std::slice::from_ref(&root),
                generation,
                &root.join("link_out"),
            )
            .await
            .expect("enum");
            assert!(matches!(outcome, TaskOutcome::Complete), "{outcome:?}");
            assert_eq!(
                store.pending_count(generation).await.expect("pending"),
                1,
                "no escape work may be scheduled"
            );
        }
    });
}

/// Finding 6: one huge report field caps with a visible marker; short
/// fields pass through byte-identical.
#[test]
fn report_field_cap_marks_huge_fields() {
    assert_eq!(cap_report_field(""), "");
    assert_eq!(cap_report_field("short"), "short");
    let exact = "x".repeat(MAX_REPORT_FIELD_BYTES);
    assert_eq!(cap_report_field(&exact), exact);
    let huge = "y".repeat(MAX_REPORT_FIELD_BYTES + 1000);
    let capped = cap_report_field(&huge);
    assert!(capped.as_bytes()[..MAX_REPORT_FIELD_BYTES]
        .iter()
        .all(|byte| *byte == b'y'));
    assert!(
        capped.ends_with("…[+1000 bytes truncated]"),
        "len={}",
        capped.len()
    );
    assert_eq!(
        capped.len(),
        MAX_REPORT_FIELD_BYTES + "…[+1000 bytes truncated]".len()
    );
    // Multibyte cut lands on a char boundary (no panic, valid UTF-8).
    let wide = "é".repeat(MAX_REPORT_FIELD_BYTES / 2 + 10);
    let capped_wide = cap_report_field(&wide);
    assert!(capped_wide.contains("bytes truncated]"));
    assert!(capped_wide.starts_with('é'));
    assert!(capped_wide.len() <= MAX_REPORT_FIELD_BYTES + 64);
}

/// Finding 6 (remote URLs): huge catalog `url`/`canonical_url` blobs are
/// capped with a visible marker at the report boundary — never streamed
/// unbounded, never cut silently. Short URLs pass through byte-identical.
#[test]
fn report_remote_urls_cap_huge_fields() {
    use repo_scan::model::StatusMode;
    use repo_scan::report::builder::{stream_report_from_store, ReportInputs};
    use repo_scan::store::{NewGitInstance, NewRemote};

    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let now = now_ms();
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
                    evidence_json: "[]",
                },
                now,
            )
            .await
            .expect("instance");
        let huge_url = format!("https://example.com/{}", "a".repeat(MAX_REPORT_FIELD_BYTES));
        let huge_canonical = format!("https://example.com/{}", "b".repeat(MAX_REPORT_FIELD_BYTES));
        store
            .upsert_remote(
                &NewRemote {
                    id: "rem-1",
                    instance_id: "repo-1",
                    checkout_scope_id: None,
                    name: b"origin",
                    role: "fetch",
                    url: huge_url.as_bytes(),
                    canonical_url: Some(huge_canonical.as_bytes()),
                },
                now,
            )
            .await
            .expect("remote");
        let short_url = "https://example.com/owner/repo.git";
        let short_canonical = "https://example.com/owner/repo";
        store
            .upsert_remote(
                &NewRemote {
                    id: "rem-2",
                    instance_id: "repo-1",
                    checkout_scope_id: None,
                    name: b"upstream",
                    role: "fetch",
                    url: short_url.as_bytes(),
                    canonical_url: Some(short_canonical.as_bytes()),
                },
                now,
            )
            .await
            .expect("remote");

        let inputs = ReportInputs {
            report_id: "report-url-cap-1".to_string(),
            created_at_ms: now,
            scan_id: "scan-test-1".to_string(),
            generation: 1,
            epoch: 1,
            catalog_revision: 7,
            target_url: "https://example.com/OWNER/REPO".to_string(),
            canonical_url: Some("https://example.com/owner/repo".to_string()),
            scope: "roots".to_string(),
            scan_state: "complete".to_string(),
            started_at_ms: now,
            finished_at_ms: Some(now),
            superseded_by: None,
            cached: false,
            status_mode: StatusMode::Summary,
            directories_complete: 0,
            tasks_pending: 0,
            scope_boundaries: Vec::new(),
            profile: "conservative".to_string(),
            cpu_target_cores: 1.0,
            rss_target_bytes: 268_435_456,
            peak_rss_bytes: None,
            cpu_seconds: None,
            enumerated_entries: 0,
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
        };
        let (bytes, stats) = stream_report_from_store(&store, &inputs, Vec::new())
            .await
            .expect("stream");
        assert_eq!(stats.remotes, 2);
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse");
        let huge = &value["remotes"][0];
        for (label, original, emitted) in [
            ("url", huge_url.as_str(), huge["url"].as_str().expect("url")),
            (
                "canonical_url",
                huge_canonical.as_str(),
                huge["canonical_url"].as_str().expect("canonical"),
            ),
        ] {
            let dropped = original.len() - MAX_REPORT_FIELD_BYTES;
            assert_eq!(
                &emitted[..MAX_REPORT_FIELD_BYTES],
                &original[..MAX_REPORT_FIELD_BYTES],
                "{label} keeps its head"
            );
            assert!(
                emitted.ends_with(&format!("…[+{dropped} bytes truncated]")),
                "{label} carries the marker: len={}",
                emitted.len()
            );
            assert!(
                emitted.len() <= MAX_REPORT_FIELD_BYTES + 64,
                "{label} bounded"
            );
        }
        let short = &value["remotes"][1];
        assert_eq!(short["url"].as_str(), Some(short_url));
        assert_eq!(short["canonical_url"].as_str(), Some(short_canonical));
    });
}

/// Fix 10: out-of-range task/lease/generation values fail loudly at the
/// store boundary; valid values round-trip unchanged.
#[test]
fn store_rejects_out_of_range_task_values() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let (store, generation) = open_generation(&db).await;
        let now = now_ms();

        // Happy path first: valid values round-trip unchanged.
        assert!(store
            .enqueue_task(
                &NewTask {
                    id: "task-ok",
                    kind: "enumerate_dir",
                    generation,
                    dir_id: None,
                    scope_key: "dir:1",
                    expected_rev: 0,
                    idempotency_key: "idem:task-ok",
                },
                now,
            )
            .await
            .expect("enqueue"));
        let fetched = store
            .get_task("task-ok")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(fetched.generation, generation);
        assert_eq!(fetched.attempts, 0);

        // Writes past `i64::MAX` fail instead of wrapping.
        for (id, task) in [
            (
                "task-bad-gen",
                NewTask {
                    id: "task-bad-gen",
                    kind: "enumerate_dir",
                    generation: u64::MAX,
                    dir_id: None,
                    scope_key: "dir:2",
                    expected_rev: 0,
                    idempotency_key: "idem:task-bad-gen",
                },
            ),
            (
                "task-bad-rev",
                NewTask {
                    id: "task-bad-rev",
                    kind: "enumerate_dir",
                    generation,
                    dir_id: None,
                    scope_key: "dir:3",
                    expected_rev: u64::MAX,
                    idempotency_key: "idem:task-bad-rev",
                },
            ),
        ] {
            let err = store
                .enqueue_task(&task, now)
                .await
                .expect_err("out-of-range enqueue must fail");
            assert!(
                matches!(err, repo_scan::Error::Store(ref message) if message.contains("exceeds i64 range")),
                "{id}: {err:?}"
            );
        }
        let err = store
            .claim_tasks(u64::MAX, 16, 60_000, now)
            .await
            .expect_err("claim with epoch past i64::MAX must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("exceeds i64 range")),
            "{err:?}"
        );
        let err = store
            .renew_lease("task-ok", 1, u64::MAX, 60_000, now)
            .await
            .expect_err("renew with epoch past i64::MAX must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("exceeds i64 range")),
            "{err:?}"
        );
        let err = store
            .create_generation("roots", "running", Some(u64::MAX), now)
            .await
            .expect_err("prior generation past i64::MAX must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("exceeds i64 range")),
            "{err:?}"
        );
        let err = store
            .set_generation_state(u64::MAX, "running")
            .await
            .expect_err("generation id past i64::MAX must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("exceeds i64 range")),
            "{err:?}"
        );
        let err = store
            .get_generation(u64::MAX)
            .await
            .expect_err("generation lookup past i64::MAX must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("exceeds i64 range")),
            "{err:?}"
        );

        // Negative stored values fail loudly on read instead of wrapping.
        store
            .connection()
            .execute(
                "INSERT INTO frontier_tasks (id, kind, generation, scope_key, expected_rev, \
                    state, idempotency_key, attempts, updated_at_ms) VALUES ('task-neg', \
                    'enumerate_dir', -5, 'dir:9', 0, 'pending', 'idem:task-neg', 0, 0)",
                (),
            )
            .await
            .expect("inject negative generation");
        let err = store
            .get_task("task-neg")
            .await
            .expect_err("negative generation must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("not a valid u64")),
            "{err:?}"
        );

        // New write entry points reject out-of-range values (fix10 remainder).
        let err = store
            .record_dir_observation(1, u64::MAX, true, 0, 0, None, now)
            .await
            .expect_err("dir observation generation past i64::MAX must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("exceeds i64 range")),
            "{err:?}"
        );
        let err = store
            .record_dir_observation(1, generation, true, u64::MAX, 0, None, now)
            .await
            .expect_err("dir entry_generation past i64::MAX must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("exceeds i64 range")),
            "{err:?}"
        );
        let err = store
            .get_dir_observation(1, u64::MAX)
            .await
            .expect_err("dir observation lookup past i64::MAX must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("exceeds i64 range")),
            "{err:?}"
        );
        let bad_status = NewStatus {
            checkout_id: "co-bad",
            mode: "full",
            state: "complete",
            started_ms: None,
            finished_ms: None,
            staged: None,
            unstaged: None,
            untracked: None,
            untracked_units: "entries",
            submodules: "none",
            unknown_fields: "[]",
            input_fingerprint: None,
            observed_rev: u64::MAX,
        };
        let err = store
            .record_status(&bad_status, now)
            .await
            .expect_err("status observed_rev past i64::MAX must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("exceeds i64 range")),
            "{err:?}"
        );
        let err = store
            .save_report_snapshot("snap-bad", "v1", u64::MAX, generation, "draft", None, now)
            .await
            .expect_err("snapshot catalog_rev past i64::MAX must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("exceeds i64 range")),
            "{err:?}"
        );

        // New read entry points reject negative stored values.
        store
            .connection()
            .execute(
                "INSERT INTO dir_observations (dir_id, generation, completed, \
                    entry_generation, entries_seen, error, observed_at_ms) \
                    VALUES (1, 1, 1, 0, -3, NULL, 0)",
                (),
            )
            .await
            .expect("inject negative entries_seen");
        let err = store
            .get_dir_observation(1, 1)
            .await
            .expect_err("negative entries_seen must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("not a valid u64")),
            "{err:?}"
        );
        store
            .connection()
            .execute(
                "INSERT INTO status_observations (checkout_id, mode, state, untracked_units, \
                    submodules, observed_rev, observed_at_ms) \
                    VALUES ('co-neg', 'full', 'complete', 'entries', 'none', -2, 0)",
                (),
            )
            .await
            .expect("inject negative observed_rev");
        let err = store
            .list_statuses("co-neg")
            .await
            .expect_err("negative observed_rev must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("not a valid u64")),
            "{err:?}"
        );
        store
            .connection()
            .execute(
                "INSERT INTO report_snapshots (id, schema_version, catalog_rev, generation, \
                    publication_state, created_at_ms) \
                    VALUES ('snap-neg', 'v1', -1, 1, 'draft', 0)",
                (),
            )
            .await
            .expect("inject negative catalog_rev");
        let err = store
            .get_report_snapshot("snap-neg")
            .await
            .expect_err("negative catalog_rev must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("not a valid u64")),
            "{err:?}"
        );
        store
            .connection()
            .execute(
                "INSERT INTO errors (id, scope_key, category, detail, attempts, first_seen_ms, \
                    last_seen_ms, open) \
                    VALUES ('err-neg', 'scope', 'cat', 'detail', -4, 0, 0, 1)",
                (),
            )
            .await
            .expect("inject negative attempts");
        let err = store
            .get_error("err-neg")
            .await
            .expect_err("negative error attempts must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("not a valid u64")),
            "{err:?}"
        );

        // The `buffer_*` family returns a flush flag instead of `Result`,
        // so out-of-range input panics loudly rather than wrapping.
        let bad_task = NewTask {
            id: "task-buf-bad",
            kind: "enumerate_dir",
            generation: u64::MAX,
            dir_id: None,
            scope_key: "dir:buf",
            expected_rev: 0,
            idempotency_key: "idem:task-buf-bad",
        };
        for (label, caught) in [
            (
                "buffer_enqueue_task",
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut batch = WriterBatch::new();
                    TursoStore::buffer_enqueue_task(&mut batch, &bad_task, now)
                })),
            ),
            (
                "buffer_record_dir_observation",
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut batch = WriterBatch::new();
                    TursoStore::buffer_record_dir_observation(
                        &mut batch,
                        1,
                        generation,
                        true,
                        0,
                        u64::MAX,
                        None,
                        now,
                    )
                })),
            ),
            (
                "buffer_record_dir_observation_bumped",
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut batch = WriterBatch::new();
                    TursoStore::buffer_record_dir_observation_bumped(
                        &mut batch,
                        1,
                        u64::MAX,
                        true,
                        0,
                        None,
                        now,
                    )
                })),
            ),
            (
                "buffer_record_status",
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut batch = WriterBatch::new();
                    TursoStore::buffer_record_status(&mut batch, &bad_status, now)
                })),
            ),
        ] {
            assert!(
                caught.is_err(),
                "{label} must panic on out-of-range input"
            );
        }

        // Lease-expiry arithmetic overflows loudly instead of wrapping.
        // Fresh store: the negative-injection rows above would fail reads
        // before the claim loop reaches its expiry computation.
        let tmp2 = tempfile::tempdir().expect("tempdir");
        let db2 = tmp2.path().join("catalog2.db");
        let (store2, generation2) = open_generation(&db2).await;
        assert!(
            store2
                .enqueue_task(
                    &NewTask {
                        id: "task-overflow",
                        kind: "enumerate_dir",
                        generation: generation2,
                        dir_id: None,
                        scope_key: "dir:1",
                        expected_rev: 0,
                        idempotency_key: "idem:task-overflow",
                    },
                    now,
                )
                .await
                .expect("enqueue")
        );
        let err = store2
            .claim_tasks(0, 16, 1, i64::MAX)
            .await
            .expect_err("claim with overflowing expiry must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("overflows i64")),
            "{err:?}"
        );
        let err = store2
            .claim_tasks_in_generation(generation2, 0, 16, 1, i64::MAX)
            .await
            .expect_err("generation claim with overflowing expiry must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("overflows i64")),
            "{err:?}"
        );
        let err = store
            .renew_lease("task-ok", 1, 0, 1, i64::MAX)
            .await
            .expect_err("renew with overflowing expiry must fail");
        assert!(
            matches!(err, repo_scan::Error::Store(ref message) if message.contains("overflows i64")),
            "{err:?}"
        );
    });
}
