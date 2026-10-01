//! Probe-fence regression test: one focused test proving a path swapped
//! between scheduling and execution cannot leak out-of-scope Git
//! observations into the catalog. The run-loop case drives `src/main.rs`
//! through its `#[cfg(test)]` hook — the same code production executes.

#[cfg(unix)]
mod common;

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

#[cfg(unix)]
use common::fixture;
#[cfg(unix)]
use repo_scan::config;
#[cfg(unix)]
use repo_scan::model::TaskState;
#[cfg(unix)]
use repo_scan::store::{now_ms, Store, TaskOutcome, TursoStore};
#[cfg(unix)]
use repo_scan::walk::topology::{FenceOpen, ScopeFence};
#[cfg(unix)]
use std::path::PathBuf;

/// Swapped probe path: scheduled in-scope, replaced by a symlink to an
/// out-of-scope repo before execution. Production `exec_probe` must park
/// the scope and persist zero probe rows (no instance, no checkout under
/// either spelling); the shared re-verify gate must also refuse the
/// swapped identity while still accepting the unswapped one. The flip
/// side: an out-of-scope path the scheduler placed explicitly (a
/// registered worktree base, spec §8) still probes instead of parking.
#[cfg(unix)]
#[test]
fn swapped_probe_path_parks_and_persists_nothing() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("root");
        let outside = tmp.path().join("outside");
        repo_scan::privacy::private_dir_0700(&root).unwrap();
        repo_scan::privacy::private_dir_0700(&outside).unwrap();
        // Out-of-scope repo with real observations to leak: without the
        // fence this read would persist instance + checkout + ref rows.
        let foreign = fixture::normal_clone(&outside, "foreign");
        // In-scope scheduled path: a plain directory at schedule time.
        let victim = root.join("victim");
        repo_scan::privacy::private_dir_0700(&victim).unwrap();

        let db = tmp.path().join("probe.db");
        let store = TursoStore::open(&db).await.expect("open");
        let generation = store
            .create_generation("roots", "running", None, now_ms())
            .await
            .expect("generation");
        let run_rev = store.current_revision().await.expect("revision");
        let canonical = "https://github.com/owner/repo";

        // Swap between scheduling (inside the hook) and execution: the
        // in-scope directory becomes a link to the out-of-scope repo.
        let victim_swap = victim.clone();
        let foreign_swap = foreign.clone();
        let outcome = main_under_test::test_probe_fenced_outcome(
            &store,
            std::slice::from_ref(&root),
            generation,
            run_rev,
            canonical,
            &victim,
            Some(Box::new(move || {
                std::fs::remove_dir(&victim_swap).unwrap();
                std::os::unix::fs::symlink(&foreign_swap, &victim_swap).unwrap();
            })),
        )
        .await
        .expect("probe");
        match outcome {
            TaskOutcome::Parked { state, reason } => {
                assert!(matches!(state, TaskState::Unavailable), "{state:?}");
                assert!(
                    reason.contains("symlink") || reason.contains("scope"),
                    "{reason}"
                );
            }
            other => panic!("swapped probe must park, got {other:?}"),
        }
        // Nothing persisted under either spelling: the leaked read would
        // have landed on the victim spelling (path-joined `.git`).
        for git_dir in [victim.join(".git"), foreign.join(".git")] {
            let id = format!(
                "git:{}",
                config::encode_hex(&config::path_as_bytes(&git_dir))
            );
            assert!(
                store
                    .get_git_instance(&id)
                    .await
                    .expect("read instance")
                    .is_none(),
                "no instance row for {}",
                git_dir.display()
            );
            let checkout_id = format!(
                "co:{}",
                config::encode_hex(&config::path_as_bytes(&git_dir))
            );
            assert!(
                store
                    .get_checkout(&checkout_id)
                    .await
                    .expect("read checkout")
                    .is_none(),
                "no checkout row for {}",
                git_dir.display()
            );
        }

        // Re-verify arm (the gate `exec_status` shares): pin an in-scope
        // directory, confirm the pin verifies, swap it, confirm refusal.
        let fence = ScopeFence::build(std::slice::from_ref(&root));
        let guarded: PathBuf = root.join("guarded");
        repo_scan::privacy::private_dir_0700(&guarded).unwrap();
        let pinned = match fence.open_pinned(&guarded).expect("pin") {
            FenceOpen::Dir(pinned) => pinned,
            FenceOpen::Symlink => panic!("guarded is not a link"),
        };
        assert!(
            main_under_test::reverify_probe_path(Some(&fence), &guarded, &pinned),
            "unswapped identity must verify"
        );
        std::fs::remove_dir(&guarded).unwrap();
        std::os::unix::fs::symlink(&foreign, &guarded).unwrap();
        assert!(
            !main_under_test::reverify_probe_path(Some(&fence), &guarded, &pinned),
            "swapped identity must fail re-verification"
        );

        // Relationship arm (spec §8): an out-of-scope path the scheduler
        // placed explicitly — a registered worktree base — still probes.
        let rel_db = tmp.path().join("rel.db");
        let rel_store = TursoStore::open(&rel_db).await.expect("open");
        let rel_generation = rel_store
            .create_generation("roots", "running", None, now_ms())
            .await
            .expect("generation");
        let rel_rev = rel_store.current_revision().await.expect("revision");
        let rel_outcome = main_under_test::test_probe_fenced_outcome(
            &rel_store,
            std::slice::from_ref(&root),
            rel_generation,
            rel_rev,
            canonical,
            &foreign,
            None,
        )
        .await
        .expect("probe");
        assert!(
            matches!(rel_outcome, TaskOutcome::Complete),
            "relationship probe must complete, got {rel_outcome:?}"
        );
        let rel_id = format!(
            "git:{}",
            config::encode_hex(&config::path_as_bytes(&foreign.join(".git")))
        );
        assert!(
            rel_store
                .get_git_instance(&rel_id)
                .await
                .expect("read instance")
                .is_some(),
            "relationship probe must persist its instance"
        );
    });
}
