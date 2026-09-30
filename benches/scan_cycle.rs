//! Scan-cycle benchmark (spec §18): cold-vs-warm traversal, cached query
//! latency (indexed store reads, no filesystem walk), invalidate-one-subtree
//! cost, and resume cost (lease recovery + claim). Same JSONL discipline as
//! `walk_compare`: every number is recorded on run.
//!
//! Run: `cargo bench --bench scan_cycle`. Results append to
//! `benches/results/scan_cycle.jsonl` (override with `$BENCH_RESULTS`).

#[path = "support.rs"]
mod support;

use repo_scan::store::{NewGitInstance, NewRef, NewRemote, NewScan, NewTask, TursoStore};
use std::fs;
use std::time::Instant;
use support::Recorder;

/// Number of seeded catalog instances (each with 1 remote + 3 refs).
const INSTANCES: usize = 200;
/// Cached-query repetitions for a stable mean.
const QUERY_REPS: usize = 50;
/// Frontier tasks enqueued for the resume measurement.
const RESUME_TASKS: usize = 500;

fn build_scope(holder: &tempfile::TempDir) -> std::path::PathBuf {
    let scope = holder.path().join("scope");
    fs::create_dir_all(&scope).expect("scope root");
    for name in ["repo-a", "repo-b", ".hidden-repo"] {
        support::seed_repo(&scope, name);
    }
    let flat = scope.join("flat");
    fs::create_dir_all(&flat).expect("flat dir");
    for i in 0..500 {
        fs::write(flat.join(format!("f{i:04}")), b"x").expect("flat file");
    }
    scope
}

fn main() {
    let mut recorder = Recorder::open(&support::results_dir(), "scan_cycle");

    // --- Cold-vs-warm traversal over a fresh scope. ---
    {
        let holder = tempfile::TempDir::new().expect("bench scratch");
        let root = build_scope(&holder);
        let adapter = repo_scan::walk::primary_adapter();
        let start = Instant::now();
        let cold = support::traverse(adapter.as_ref(), &root, 500_000);
        let cold_ms = support::wall_ms(&start);
        let start = Instant::now();
        let warm = support::traverse(adapter.as_ref(), &root, 500_000);
        let warm_ms = support::wall_ms(&start);
        assert_eq!(cold.entries, warm.entries, "cold/warm entry count");
        recorder.record(&serde_json::json!({
            "record": "traversal",
            "adapter": adapter.name(),
            "cold_wall_ms": cold_ms,
            "warm_wall_ms": warm_ms,
            "dirs": cold.dirs,
            "entries": cold.entries,
            "errors": cold.errors,
            "peak_rss_bytes": support::peak_rss_bytes(),
        }));
    }

    // --- Store phases on a scratch state dir (no filesystem walk). ---
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let holder = tempfile::TempDir::new().expect("state scratch");
        let state_dir = holder.path().join("state");
        fs::create_dir_all(&state_dir).expect("state dir");
        let (_guard, store) = TursoStore::open_owned(&state_dir)
            .await
            .expect("open catalog");
        let now = repo_scan::store::now_ms();
        seed_catalog(&store, now).await;

        // Cached query latency: indexed reads only (get_scan + list_remotes
        // + list_refs), repeated for a mean. No walk, no Git probe.
        let mut total_ms = 0.0;
        for _ in 0..QUERY_REPS {
            let start = Instant::now();
            let scan = store.get_scan("scan-bench").await.expect("get scan");
            assert!(scan.is_some());
            let remotes = store.list_remotes("inst-000").await.expect("remotes");
            assert_eq!(remotes.len(), 1);
            let refs = store.list_refs("inst-000").await.expect("refs");
            assert_eq!(refs.len(), 3);
            total_ms += support::wall_ms(&start);
        }
        recorder.record(&serde_json::json!({
            "record": "cached_query",
            "reps": QUERY_REPS,
            "mean_wall_ms": total_ms / QUERY_REPS as f64,
            "total_wall_ms": total_ms,
        }));

        // Invalidate-one-subtree cost.
        let start = Instant::now();
        let rev = store
            .invalidate_scope("scope:/bench/subtree", 1, now)
            .await
            .expect("invalidate");
        let pending = store.pending_count(1).await.expect("pending count");
        let invalidate_ms = support::wall_ms(&start);
        recorder.record(&serde_json::json!({
            "record": "invalidate",
            "wall_ms": invalidate_ms,
            "new_revision": rev,
            "pending_after": pending,
        }));

        // Resume cost: enqueue a frontier, then recover + claim it back.
        let start = Instant::now();
        for i in 0..RESUME_TASKS {
            let id = format!("resume-task-{i:04}");
            let idem = format!("idem-{i:04}");
            store
                .enqueue_task(
                    &NewTask {
                        id: &id,
                        kind: "enumerate",
                        generation: 1,
                        dir_id: None,
                        scope_key: "scope:/bench/subtree",
                        expected_rev: rev,
                        idempotency_key: &idem,
                    },
                    now,
                )
                .await
                .expect("enqueue");
        }
        let enqueue_ms = support::wall_ms(&start);
        let start = Instant::now();
        let report = store.recover_now(now).await.expect("recover");
        let mut claimed = 0usize;
        loop {
            let batch = store.claim_tasks(1, 128, 60_000, now).await.expect("claim");
            if batch.is_empty() {
                break;
            }
            claimed += batch.len();
        }
        let resume_ms = support::wall_ms(&start);
        recorder.record(&serde_json::json!({
            "record": "resume",
            "enqueued": RESUME_TASKS,
            "enqueue_wall_ms": enqueue_ms,
            "recover_claim_wall_ms": resume_ms,
            "claimed": claimed,
            "recovered_to_pending": report.requeued,
        }));
        recorder.record(&serde_json::json!({
            "record": "footprint",
            "peak_rss_bytes": support::peak_rss_bytes(),
        }));
    });

    println!("scan_cycle: results at {}", recorder.path().display());
}

/// Seed instances, remotes, refs, and one scan request.
async fn seed_catalog(store: &TursoStore, now: i64) {
    for i in 0..INSTANCES {
        let id = format!("inst-{i:03}");
        let git_path = format!("/bench/repos/{i:03}/.git").into_bytes();
        store
            .upsert_git_instance(
                &NewGitInstance {
                    id: &id,
                    git_path: &git_path,
                    common_path: &git_path,
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
            .expect("upsert instance");
        let remote_id = format!("remote-{i:03}");
        let url = b"https://github.com/owner/repo".as_slice();
        store
            .upsert_remote(
                &NewRemote {
                    id: &remote_id,
                    instance_id: &id,
                    checkout_scope_id: None,
                    name: b"origin",
                    role: "fetch",
                    url,
                    canonical_url: Some(url),
                },
                now,
            )
            .await
            .expect("upsert remote");
        for (branch, oid) in [
            ("refs/heads/main", "1".repeat(40)),
            ("refs/heads/feature", "2".repeat(40)),
            ("refs/remotes/origin/main", "1".repeat(40)),
        ] {
            let ref_id = format!("ref-{i:03}-{branch}");
            let kind = if branch.starts_with("refs/remotes/") {
                "remote_tracking"
            } else {
                "local"
            };
            let oid_bytes = oid.into_bytes();
            store
                .upsert_ref(
                    &NewRef {
                        id: &ref_id,
                        instance_id: &id,
                        checkout_scope_id: None,
                        kind,
                        name: branch.as_bytes(),
                        oid: Some(&oid_bytes),
                        algo: Some("sha1"),
                        symbolic_target: None,
                        upstream: None,
                        state: "valid",
                    },
                    now,
                )
                .await
                .expect("upsert ref");
        }
    }
    store
        .create_scan_request(
            &NewScan {
                id: "scan-bench",
                url_raw: b"https://github.com/OWNER/REPO",
                url_canonical: Some(b"https://github.com/owner/repo"),
                scope: "roots",
                status_mode: "summary",
                report_dest: None,
            },
            now,
        )
        .await
        .expect("create scan");
}
