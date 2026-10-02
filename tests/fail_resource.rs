//! Focused regressions for the state-resources security fixes
//! (SR-STATE-01/02/03, SR-EVENT-01, PATH-GIT-04/XSEC-07): lease-renewal
//! policy, choke-point helper/stream budgets, bounded report derivations
//! with gap evidence, stream-health predicates, and process-group spawn
//! cleanup with loud failures.
//!
//! All databases and fixtures live in tempdirs (0700); no machine scan.
//! A current-thread Tokio runtime drives the async store paths.

use repo_scan::config;
use repo_scan::scheduler::admission::{
    lease_renewal_expiry, lease_renewal_expiry_elapsed, stream_restart_due, stream_stall_suspected,
    StreamBudget,
};
use repo_scan::store::{now_ms, NewGitInstance, Store, TursoStore};
use std::time::Duration;

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn db_in(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("payload").join("catalog.db")
}

/// `open` flag of one error row (1 = gap preserved for a later pass).
async fn error_open_flag(store: &TursoStore, id: &str) -> Option<i64> {
    let sql = format!("SELECT open FROM errors WHERE id = '{id}'");
    let mut rows = store
        .connection()
        .query(sql.as_str(), ())
        .await
        .expect("query");
    let row = rows.next().await.expect("next")?;
    match row.get_value(0).expect("value") {
        turso::Value::Integer(open) => Some(open),
        other => panic!("expected integer open flag, got {other:?}"),
    }
}

/// SR-STATE-01: lease renewal is due every N observed entries (including
/// the first check at zero) and yields `now + ttl`, saturating.
#[test]
fn state01_lease_renewal_policy() {
    assert_eq!(lease_renewal_expiry(0, 256, 1_000, 60_000), Some(61_000));
    assert_eq!(lease_renewal_expiry(256, 256, 1_000, 60_000), Some(61_000));
    assert_eq!(lease_renewal_expiry(512, 256, 1_000, 60_000), Some(61_000));
    assert_eq!(lease_renewal_expiry(1, 256, 1_000, 60_000), None);
    assert_eq!(lease_renewal_expiry(255, 256, 1_000, 60_000), None);
    assert_eq!(lease_renewal_expiry(257, 256, 1_000, 60_000), None);
    assert_eq!(lease_renewal_expiry(10, 0, 1_000, 60_000), None);
    assert_eq!(
        lease_renewal_expiry(0, 256, i64::MAX, 60_000),
        Some(i64::MAX)
    );
}

/// R04: Time-aware lease renewal is due at entry zero or when elapsed time reaches or exceeds the interval.
#[test]
fn r04_lease_renewal_elapsed_policy() {
    let interval = Duration::from_secs(20);
    // Initial check (entries_seen == 0) always renews:
    assert_eq!(
        lease_renewal_expiry_elapsed(0, Duration::ZERO, interval, 1_000, 60_000),
        Some(61_000)
    );
    // Advancing entries, but within the 20s interval: no renewal (prevents DB write spam)
    assert_eq!(
        lease_renewal_expiry_elapsed(100, Duration::from_secs(5), interval, 1_000, 60_000),
        None
    );
    // Interval reached (20s): renews before the 60s lease can lapse
    assert_eq!(
        lease_renewal_expiry_elapsed(10, Duration::from_secs(20), interval, 1_000, 60_000),
        Some(61_000)
    );
    // Interval exceeded (slow filesystem): renews
    assert_eq!(
        lease_renewal_expiry_elapsed(5, Duration::from_secs(25), interval, 1_000, 60_000),
        Some(61_000)
    );
    // Saturating add:
    assert_eq!(
        lease_renewal_expiry_elapsed(0, Duration::ZERO, interval, i64::MAX, 60_000),
        Some(i64::MAX)
    );
}

/// SR-STATE-02: the helper ledger refuses past its cap, reopens on
/// release, and saturates instead of wrapping.
#[test]
fn state02_helper_ledger_enforces_cap() {
    use repo_scan::scheduler::admission::HelperLedger;
    let ledger = HelperLedger::new(2);
    assert_eq!(ledger.live(), 0);
    assert!(ledger.try_acquire());
    assert!(ledger.try_acquire());
    assert!(!ledger.try_acquire(), "past-cap acquire must refuse");
    assert_eq!(ledger.live(), 2);
    ledger.release();
    assert!(ledger.try_acquire(), "a release reopens one slot");
    ledger.release();
    ledger.release();
    assert_eq!(ledger.live(), 0);
    ledger.release();
    assert_eq!(ledger.live(), 0, "release saturates at zero");
}

/// SR-STATE-02: the stream budget refuses streams and callback bytes past
/// its caps and releases saturate.
#[test]
fn state02_stream_budget_enforces_caps() {
    let budget = StreamBudget::new(1, 10);
    assert!(budget.try_acquire_stream());
    assert!(
        !budget.try_acquire_stream(),
        "second stream past cap refuses"
    );
    assert!(budget.try_charge_bytes(10));
    assert!(!budget.try_charge_bytes(1), "bytes past cap refuse");
    assert_eq!(budget.bytes_queued(), 10);
    budget.release_bytes(4);
    assert_eq!(budget.bytes_queued(), 6);
    assert!(budget.try_charge_bytes(4));
    budget.release_bytes(100);
    assert_eq!(budget.bytes_queued(), 0, "byte release saturates");
    budget.release_stream();
    budget.release_stream();
    assert_eq!(budget.streams_live(), 0, "stream release saturates");
    assert!(
        !budget.try_charge_bytes(usize::MAX),
        "overflow charge refuses"
    );
}

/// Serializes the two tests that spawn through the process-wide helper
/// ledger: the refusal proof needs the ledger full and stable, which only
/// holds when no sibling spawns concurrently.
#[cfg(unix)]
static SPAWN_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(unix)]
fn spawn_serial() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_SERIAL
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// SR-STATE-02: a spawn past the process-wide helper cap fails loudly
/// with a ledger error instead of queueing without bound.
#[cfg(unix)]
#[test]
fn state02_spawn_refused_past_ledger_cap() {
    use repo_scan::git::fallback::spawn_enveloped;
    use repo_scan::scheduler::admission::{HELPER_LEDGER, HELPER_LEDGER_CAP};
    let _serial = spawn_serial();
    struct LedgerSlots(usize);
    impl Drop for LedgerSlots {
        fn drop(&mut self) {
            for _ in 0..self.0 {
                HELPER_LEDGER.release();
            }
        }
    }
    for _ in 0..HELPER_LEDGER_CAP {
        assert!(HELPER_LEDGER.try_acquire());
    }
    let _slots = LedgerSlots(HELPER_LEDGER_CAP);
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c").arg("exit 0");
    let err = spawn_enveloped(&mut cmd, false, Duration::from_secs(5), 1024)
        .expect_err("spawn past a full ledger must refuse");
    assert!(err.contains("helper ledger"), "{err}");
    assert!(err.contains("spawn refused"), "{err}");
}

/// PATH-GIT-04/XSEC-07: a timed-out spawn kills the whole process group
/// (child plus a grandchild holding the pipe), reaps, joins readers, and
/// reports every stage loudly.
#[cfg(unix)]
#[test]
fn git04_timeout_kills_group_and_joins_readers() {
    use repo_scan::git::fallback::spawn_enveloped;
    let _serial = spawn_serial();
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c").arg("sleep 30 & exec sleep 30");
    let err = spawn_enveloped(&mut cmd, false, Duration::from_millis(200), 1024)
        .expect_err("a 30s sleeper must exceed a 200ms budget");
    assert!(err.contains("timed out"), "{err}");
    assert!(err.contains("group killed"), "{err}");
    assert!(err.contains("reaped"), "{err}");
    assert!(err.contains("stdout joined"), "{err}");
    assert!(!err.contains("FAILED"), "{err}");
    assert!(!err.contains("STUCK"), "{err}");
}

/// SR-STATE-03: error derivations stop at the aggregate cap, keep the
/// remainder open in the catalog, and record one stable open gap row.
#[test]
fn state03_error_derivations_cap_and_gap() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let scope = config::scope_key_for_dir(&dir.path().join("root"));
        let now = now_ms();
        for n in 0..10 {
            store
                .record_error(
                    &format!("deriv-err-{n:02}"),
                    &scope,
                    "probe-failed",
                    "boom",
                    None,
                    now,
                )
                .await
                .expect("record");
        }
        let tiny = main_under_test::DerivationCaps {
            max_error_candidates: 3,
            max_root_error_ids: 100,
            max_instance_candidates: 100,
            max_storage_links: 100,
            max_first_common: 100,
        };
        let first =
            main_under_test::scan_error_derivations(&store, std::slice::from_ref(&scope), &tiny)
                .await
                .expect("scan");
        assert!(
            first.truncated,
            "10 rows past a 3-candidate cap must truncate"
        );
        assert!(
            first.candidates.len() <= 3,
            "got {}",
            first.candidates.len()
        );
        assert_eq!(first.root_error_ids.len(), 1);
        assert_eq!(
            error_open_flag(&store, "gap:report-derivation:errors").await,
            Some(1),
            "truncation must record an open gap row"
        );
        // The gap row itself is not a probe candidate, so generous caps
        // still derive exactly the ten fixtures with no truncation.
        let wide = main_under_test::DerivationCaps::default_caps();
        let second = main_under_test::scan_error_derivations(&store, &[scope], &wide)
            .await
            .expect("scan");
        assert!(!second.truncated);
        assert_eq!(second.candidates.len(), 10);
        assert_eq!(second.scanned, 11, "ten fixtures plus the gap row");
    });
}

/// SR-STATE-03: instance derivations stop at the aggregate cap with the
/// same gap-and-preserve contract.
#[test]
fn state03_instance_derivations_cap_and_gap() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let now = now_ms();
        for n in 0..10 {
            let id = format!("deriv-inst-{n:02}");
            let git = format!("/nonexistent-{n:02}/.git");
            let common = format!("/nonexistent-{n:02}/.git-common");
            store
                .upsert_git_instance(
                    &NewGitInstance {
                        id: &id,
                        git_path: git.as_bytes(),
                        common_path: common.as_bytes(),
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
        let tiny = main_under_test::DerivationCaps {
            max_error_candidates: 100,
            max_root_error_ids: 100,
            max_instance_candidates: 3,
            max_storage_links: 100,
            max_first_common: 100,
        };
        let first = main_under_test::scan_instance_derivations(&store, &tiny)
            .await
            .expect("scan");
        assert!(
            first.truncated,
            "10 rows past a 3-candidate cap must truncate"
        );
        assert!(
            first.candidates.len() <= 3,
            "got {}",
            first.candidates.len()
        );
        assert_eq!(
            error_open_flag(&store, "gap:report-derivation:instances").await,
            Some(1),
            "truncation must record an open gap row"
        );
        let wide = main_under_test::DerivationCaps::default_caps();
        let second = main_under_test::scan_instance_derivations(&store, &wide)
            .await
            .expect("scan");
        assert!(!second.truncated);
        assert_eq!(second.candidates.len(), 10);
        assert_eq!(second.storage_links.len(), 10, "one common-dir edge each");
    });
}

/// SR-EVENT-01: rotation fires past the max stream age; stall suspicion
/// needs BOTH a stale heartbeat and an advanced global clock.
#[test]
fn event01_stream_health_predicates() {
    assert!(!stream_restart_due(1_000, 2_000, 60_000));
    assert!(stream_restart_due(1_000, 62_000, 60_000));
    assert!(
        !stream_restart_due(5_000, 1_000, 60_000),
        "clock skew never due"
    );
    assert!(
        stream_stall_suspected(1_000, 70_000, 100, 101, 60_000),
        "advanced clock plus stale heartbeat is suspicion"
    );
    assert!(
        !stream_stall_suspected(1_000, 70_000, 100, 100, 60_000),
        "idle filesystem (static clock) is never suspicion"
    );
    assert!(
        !stream_stall_suspected(69_000, 70_000, 100, 101, 60_000),
        "fresh heartbeat is never suspicion"
    );
    assert!(
        !stream_stall_suspected(70_000, 1_000, 100, 101, 60_000),
        "clock skew never suspects"
    );
}

/// SR-STATE-02 + SR-EVENT-01 (macOS): past the aggregate stream cap a new
/// volume stream is refused (the volume degrades honestly); after release
/// an open succeeds and dropping the iterator frees the slot again. The
/// stream is opened and dropped without reading any events: no scan.
#[cfg(target_os = "macos")]
#[test]
fn event01_stream_budget_refuses_open_past_cap() {
    use repo_scan::platform::macos::{FsEventsSource, MacOsMountTable};
    use repo_scan::platform::{EventSource, MountTable};
    use repo_scan::scheduler::admission::{NATIVE_STREAM_BUDGET, NATIVE_STREAM_CAP};
    struct StreamSlots(usize);
    impl Drop for StreamSlots {
        fn drop(&mut self) {
            for _ in 0..self.0 {
                NATIVE_STREAM_BUDGET.release_stream();
            }
        }
    }
    for _ in 0..NATIVE_STREAM_CAP {
        assert!(NATIVE_STREAM_BUDGET.try_acquire_stream());
    }
    let slots = StreamSlots(NATIVE_STREAM_CAP);
    let mounts = MacOsMountTable.mounts().expect("mounts");
    assert!(!mounts.is_empty(), "need one real mount for the open proof");
    let mut source = FsEventsSource;
    // `expect_err` needs `T: Debug`; the iterator side is not `Debug`.
    let err = match source.open_stream(&mounts[0].volume, None) {
        Ok(_) => panic!("past-cap open must refuse"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("refused"), "{err}");
    drop(slots);
    let before = NATIVE_STREAM_BUDGET.streams_live();
    {
        let (_boundary, iter) = source
            .open_stream(&mounts[0].volume, None)
            .expect("open after release");
        assert_eq!(NATIVE_STREAM_BUDGET.streams_live(), before + 1);
        drop(iter);
    }
    assert_eq!(
        NATIVE_STREAM_BUDGET.streams_live(),
        before,
        "dropping the iterator frees the slot"
    );
}

/// SR-STATE-01: an expired wall budget abandons the op before any work —
/// the scope parks `Unavailable` with a loud `timeout-abandoned` reason,
/// and completing that outcome through the lease guards records the
/// durable open gap row. The deadline hook drives the production probe
/// path; a zero budget exercises abandonment deterministically.
#[cfg(unix)]
#[test]
fn state01_timeout_abandons_parks_loud() {
    use repo_scan::model::TaskState;
    use repo_scan::store::TaskOutcome;

    // Pure deadline semantics: a live budget is unexpired, zero is spent.
    assert!(!main_under_test::OpDeadline::new(Duration::from_secs(60)).expired());
    assert!(main_under_test::OpDeadline::new(Duration::ZERO).expired());

    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let victim = root.join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let generation = store
            .create_generation("roots", "running", None, now_ms())
            .await
            .expect("generation");
        let run_rev = store.current_revision().await.expect("revision");
        // Zero budget: the probe abandons before the first Git read.
        let outcome = main_under_test::test_probe_deadline_outcome(
            &store,
            std::slice::from_ref(&root),
            generation,
            run_rev,
            "https://github.com/owner/repo",
            &victim,
            Duration::ZERO,
        )
        .await
        .expect("probe");
        match &outcome {
            TaskOutcome::Parked { state, reason } => {
                assert!(matches!(state, TaskState::Unavailable), "{state:?}");
                assert!(reason.contains("timeout-abandoned"), "{reason}");
            }
            other => panic!("expired probe must park, got {other:?}"),
        }
        // Production completes the outcome through the lease guards: the
        // park lands a loud open gap row for the scope.
        let mut rows = store
            .connection()
            .query(
                "SELECT id, lease_token FROM frontier_tasks WHERE kind = 'probe_git'",
                (),
            )
            .await
            .expect("query");
        let row = rows.next().await.expect("next").expect("one probe task");
        let task_id = match row.get_value(0).expect("id") {
            turso::Value::Text(id) => id,
            other => panic!("expected text id, got {other:?}"),
        };
        let token = match row.get_value(1).expect("token") {
            turso::Value::Integer(token) => token,
            other => panic!("expected integer token, got {other:?}"),
        };
        store
            .complete_task(&task_id, token, store.epoch(), &outcome, now_ms())
            .await
            .expect("complete");
        assert_eq!(
            error_open_flag(&store, &format!("gap:{task_id}")).await,
            Some(1),
            "timeout park must record an open gap row"
        );
    });
}

/// SR-STATE-04: borrowed object-store edges cap at 64 entries per
/// instance — 70 alternates lines plus comments/blanks derive exactly
/// 64 `alternate_objects` edges in file order — and an oversized
/// alternates file (past the byte cap) derives none instead of
/// driving unbounded allocation.
#[test]
fn state04_alternates_capped_at_64_entries() {
    use repo_scan::privacy::{private_dir_0700, private_file_0600, private_write_0600};
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::Builder::new()
            .prefix("rsf-state04-")
            .tempdir_in("/tmp")
            .expect("tempdir");
        private_dir_0700(dir.path()).expect("0700");
        // 70-entry alternates file (~1 KiB custom data) with a comment
        // and a blank line that must never become edges.
        let git = dir.path().join("repo.git");
        let info = git.join("objects").join("info");
        private_dir_0700(&info).expect("info");
        let mut text = String::from("# borrowed stores\n\n");
        for n in 0..70 {
            text.push_str(&format!("/alt/store-{n:02}\n"));
        }
        private_write_0600(&info.join("alternates"), text.as_bytes()).expect("alternates");
        // Oversized alternates: sparse 300 KiB (no custom bytes on disk),
        // past the 256 KiB control-file cap.
        let big = dir.path().join("big.git");
        let big_info = big.join("objects").join("info");
        private_dir_0700(&big_info).expect("big info");
        private_file_0600(&big_info.join("alternates"))
            .expect("big alternates")
            .set_len(300 * 1024)
            .expect("sparse");
        let store = TursoStore::open(&db_in(&dir)).await.expect("open");
        let now = now_ms();
        let git_bytes = config::path_as_bytes(&git);
        store
            .upsert_git_instance(
                &NewGitInstance {
                    id: "state04-alt",
                    git_path: &git_bytes,
                    common_path: &git_bytes,
                    incarnation: "1",
                    format: "git-files",
                    bare: Some(true),
                    object_format: "sha1",
                    disposition: "unresolvable_identity",
                    evidence_json: "[]",
                },
                now,
            )
            .await
            .expect("instance");
        let big_bytes = config::path_as_bytes(&big);
        store
            .upsert_git_instance(
                &NewGitInstance {
                    id: "state04-big",
                    git_path: &big_bytes,
                    common_path: &big_bytes,
                    incarnation: "1",
                    format: "git-files",
                    bare: Some(true),
                    object_format: "sha1",
                    disposition: "unresolvable_identity",
                    evidence_json: "[]",
                },
                now,
            )
            .await
            .expect("big instance");
        let derived = main_under_test::scan_instance_derivations(
            &store,
            &main_under_test::DerivationCaps::default_caps(),
        )
        .await
        .expect("scan");
        assert!(!derived.truncated);
        assert_eq!(derived.scanned, 2);
        let alts: Vec<_> = derived
            .storage_links
            .iter()
            .filter(|l| l.kind == "alternate_objects")
            .collect();
        assert_eq!(alts.len(), 64, "70 entries cap at 64 edges");
        assert_eq!(
            derived.storage_links.len(),
            64,
            "common == git and no hardlinks, so no other edges"
        );
        assert_eq!(alts[0].to_path_bytes, b"/alt/store-00".to_vec());
        assert_eq!(alts[63].to_path_bytes, b"/alt/store-63".to_vec());
        assert!(
            alts.iter().all(|l| l.from_repository_id == "state04-alt"),
            "the oversized alternates file derives no edges"
        );
        assert!(
            alts[0].id.starts_with("link:state04-alt:alt:"),
            "edge id carries the instance: {}",
            alts[0].id
        );
    });
}
