//! Adapter-equivalence and walk/scheduler contract tests (spec §§5–7, 12).
//!
//! Every [`OneDirAdapter`] backend must emit equivalent immediate-child
//! semantics over the same tree: hidden entries included, symlinks reported
//! (never followed), root records filtered, errors preserved. Scheduler
//! tests pin the children-before-complete, stale-requeue, lease, backoff,
//! circuit-breaker, and admission invariants.

use repo_scan::model::{Epoch, GenerationId, TaskState};
use repo_scan::scheduler::{
    backoff_for_attempt, Admission, CircuitBreaker, DiscoveredCandidate, DiscoveredChild,
    DurableScheduler, MemorySchedulerStore, OpClass, Scheduler, Task, TaskKind, TaskOutcome,
};
use repo_scan::telemetry::{Counters, FootprintSampler, Telemetry};
use repo_scan::walk::topology::{self, ObserveOutcome, PhysicalDirId};
use repo_scan::walk::{ChildKind, ListOptions, OneDirAdapter};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn all_adapters() -> Vec<Box<dyn OneDirAdapter>> {
    vec![
        Box::new(repo_scan::walk::IgnoreAdapter),
        Box::new(repo_scan::walk::StdEscape),
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        Box::new(repo_scan::walk::DuaAdapter),
    ]
}

fn adapter_names() -> Vec<&'static str> {
    all_adapters().iter().map(|a| a.name()).collect()
}

/// List a directory through one adapter, splitting children from preserved
/// error items (layer-1 open failures land in `errors` too).
fn list_all(
    adapter: &dyn OneDirAdapter,
    dir: &Path,
    options: ListOptions,
) -> (Vec<(OsString, ChildKind, bool)>, Vec<String>) {
    let mut children = Vec::new();
    let mut errors = Vec::new();
    match adapter.list_dir(dir, options) {
        Err(e) => errors.push(e.to_string()),
        Ok(iter) => {
            for item in iter {
                match item {
                    Ok(entry) => {
                        let has_meta = matches!(entry.metadata, Some(Ok(_)));
                        if let Some(Err(e)) = &entry.metadata {
                            errors.push(format!("meta: {e}"));
                        }
                        children.push((entry.name, entry.kind, has_meta));
                    }
                    Err(e) => errors.push(e.to_string()),
                }
            }
        }
    }
    children.sort_by(|a, b| a.0.cmp(&b.0));
    (children, errors)
}

/// Synthetic tree: visible + hidden files, hidden dir, subdir, symlinks.
/// Returns the tempdir (kept alive by the caller) and the root path.
fn build_tree() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("tree");
    repo_scan::privacy::private_dir_0700(&root).unwrap();
    repo_scan::privacy::private_write_0600(&root.join("visible.txt"), b"v").unwrap();
    repo_scan::privacy::private_write_0600(&root.join(".hidden"), b"h").unwrap();
    repo_scan::privacy::private_dir_0700(&root.join(".hdir")).unwrap();
    repo_scan::privacy::private_write_0600(&root.join(".hdir").join("inner.txt"), b"i").unwrap();
    repo_scan::privacy::private_dir_0700(&root.join("sub")).unwrap();
    repo_scan::privacy::private_write_0600(&root.join("sub").join("deep.txt"), b"d").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        std::os::unix::fs::symlink("sub", root.join("link_to_sub")).unwrap();
        std::os::unix::fs::symlink("cycle_b", root.join("cycle_a")).unwrap();
        std::os::unix::fs::symlink("cycle_a", root.join("cycle_b")).unwrap();
        std::os::unix::fs::symlink("no-such-target", root.join("dangling")).unwrap();
        let raw = std::ffi::OsString::from_vec(b"bad\xffname".to_vec());
        // Best-effort: APFS rejects non-UTF-8 names (EILSEQ). Tests that
        // need this fixture check for its presence and skip without it.
        let _ = repo_scan::privacy::private_write_0600(&root.join(raw), b"x");
    }
    (tmp, root)
}

#[test]
fn adapters_agree_on_synthetic_tree() {
    let (_tmp, root) = build_tree();
    let options = ListOptions {
        skip_metadata: false,
    };
    let mut first: Option<Vec<(OsString, ChildKind, bool)>> = None;
    for adapter in all_adapters() {
        let (children, errors) = list_all(adapter.as_ref(), &root, options);
        assert!(errors.is_empty(), "{} errors: {errors:?}", adapter.name());
        assert!(!children.is_empty(), "{} listed nothing", adapter.name());

        // Hidden entries are included by every backend (ignore runs with
        // standard_filters(false)).
        let names: BTreeSet<&OsString> = children.iter().map(|(n, _, _)| n).collect();
        for want in ["visible.txt", ".hidden", ".hdir", "sub"] {
            assert!(
                names.contains(&OsString::from(want)),
                "{} missing {want}",
                adapter.name()
            );
        }
        // Backend-emitted root record is filtered, never counted as a child.
        let root_own_name: OsString = root.file_name().unwrap().to_os_string();
        assert!(
            !names.contains(&root_own_name),
            "{} leaked its root record",
            adapter.name()
        );
        // Identity metadata present in full mode.
        assert!(
            children.iter().all(|(_, _, m)| *m),
            "{} missing metadata",
            adapter.name()
        );

        match &first {
            None => first = Some(children),
            Some(expected) => assert_eq!(
                &children,
                expected,
                "adapter {} disagrees with {}",
                adapter.name(),
                adapter_names()[0]
            ),
        }
    }
}

#[test]
fn adapters_agree_in_cheap_mode_and_subdir() {
    let (_tmp, root) = build_tree();
    let options = ListOptions {
        skip_metadata: true,
    };
    let mut first: Option<Vec<(OsString, ChildKind, bool)>> = None;
    for adapter in all_adapters() {
        for dir in [&root, &root.join("sub"), &root.join(".hdir")] {
            let (children, errors) = list_all(adapter.as_ref(), dir, options);
            assert!(
                errors.is_empty(),
                "{} errors on {dir:?}: {errors:?}",
                adapter.name()
            );
            assert!(
                children.iter().all(|(_, _, m)| !m),
                "{} fetched metadata in cheap mode",
                adapter.name()
            );
            if dir.ends_with("sub") {
                assert_eq!(children.len(), 1, "{} subdir listing", adapter.name());
                assert_eq!(children[0].0, OsString::from("deep.txt"));
                assert_eq!(children[0].1, ChildKind::File);
            }
        }
        let (children, _) = list_all(adapter.as_ref(), &root, options);
        match &first {
            None => first = Some(children),
            Some(expected) => assert_eq!(&children, expected, "cheap-mode disagreement"),
        }
    }
}

#[test]
fn adapters_preserve_open_errors() {
    let missing = PathBuf::from("definitely-not-here-repo-scan-fixture");
    assert!(!missing.exists());
    for adapter in all_adapters() {
        let (children, errors) = list_all(
            adapter.as_ref(),
            &missing,
            ListOptions {
                skip_metadata: false,
            },
        );
        assert!(
            children.is_empty(),
            "{} listed a missing dir",
            adapter.name()
        );
        assert!(
            !errors.is_empty(),
            "{} swallowed the open error",
            adapter.name()
        );
    }
}

#[test]
#[cfg(unix)]
fn symlinks_reported_never_followed() {
    let (_tmp, root) = build_tree();
    for adapter in all_adapters() {
        let (children, errors) = list_all(
            adapter.as_ref(),
            &root,
            ListOptions {
                skip_metadata: false,
            },
        );
        assert!(errors.is_empty(), "{}", adapter.name());
        let kind_of = |want: &str| {
            children
                .iter()
                .find(|(n, _, _)| n == want)
                .map(|(_, k, _)| *k)
        };
        // Links are reported as links; the adapter never descends through
        // link_to_sub (which would duplicate deep.txt at top level).
        assert_eq!(
            kind_of("link_to_sub"),
            Some(ChildKind::Symlink),
            "{}",
            adapter.name()
        );
        assert_eq!(
            kind_of("cycle_a"),
            Some(ChildKind::Symlink),
            "{}",
            adapter.name()
        );
        assert_eq!(
            kind_of("dangling"),
            Some(ChildKind::Symlink),
            "{}",
            adapter.name()
        );
        assert_eq!(
            kind_of("sub"),
            Some(ChildKind::Directory),
            "{}",
            adapter.name()
        );
        assert!(
            kind_of("deep.txt").is_none(),
            "{} descended a symlink",
            adapter.name()
        );
    }
    // Topology layer: the cycle is detected, the good link resolves to a
    // directory, the dangling link keeps its IO error.
    let target = topology::resolve_symlink(&root.join("link_to_sub")).expect("resolves");
    assert_eq!(target.kind, ChildKind::Directory);
    assert!(matches!(
        topology::resolve_symlink(&root.join("cycle_a")),
        Err(topology::ResolveError::Cycle(_)) | Err(topology::ResolveError::TooDeep(_))
    ));
    assert!(matches!(
        topology::resolve_symlink(&root.join("dangling")),
        Err(topology::ResolveError::Io(_))
    ));
}

#[test]
#[cfg(unix)]
fn non_utf8_name_round_trips_losslessly() {
    use std::os::unix::ffi::OsStringExt;
    let (_tmp, root) = build_tree();
    let raw = OsString::from_vec(b"bad\xffname".to_vec());
    if !root.join(&raw).exists() {
        eprintln!("skip: filesystem rejects non-UTF-8 names (APFS)");
        return;
    }
    let mut first: Option<Vec<u8>> = None;
    for adapter in all_adapters() {
        let (children, errors) = list_all(
            adapter.as_ref(),
            &root,
            ListOptions {
                skip_metadata: false,
            },
        );
        assert!(errors.is_empty(), "{}", adapter.name());
        let found = children
            .iter()
            .find(|(n, _, _)| n == &raw)
            .expect("non-UTF8 child");
        assert_eq!(found.1, ChildKind::File);
        let bytes = found.0.clone().into_vec();
        assert_eq!(bytes, b"bad\xffname", "{} mangled the name", adapter.name());
        match &first {
            None => first = Some(bytes),
            Some(expected) => assert_eq!(&bytes, expected, "byte disagreement"),
        }
    }
}

#[test]
#[cfg(unix)]
fn physical_dedupe_keys_on_dev_ino_plus_namespace() {
    use std::os::unix::fs::MetadataExt;
    let (_tmp, root) = build_tree();
    let md = std::fs::symlink_metadata(&root).unwrap();
    let id = PhysicalDirId {
        dev: md.dev(),
        ino: md.ino(),
        namespace: String::from("vol-a"),
    };
    let mut topo = topology::Topology::new();
    assert_eq!(topo.observe(id.clone()), ObserveOutcome::New);
    assert_eq!(topo.observe(id.clone()), ObserveOutcome::Duplicate);
    // Same object under another namespace (firmlink alias) is distinct.
    let aliased = PhysicalDirId {
        namespace: String::from("vol-b"),
        ..id
    };
    assert_eq!(topo.observe(aliased), ObserveOutcome::New);
    assert_eq!(topo.len(), 2);
}

#[test]
fn enumeration_batches_flush_at_first_limit() {
    use repo_scan::walk::batch::{BatchLimits, EntryBatch};
    use repo_scan::walk::ChildEntry;
    let limits = BatchLimits {
        max_entries: 4,
        max_bytes: 10 * 1024 * 1024,
    };
    let mut batch = EntryBatch::with_limits(limits);
    for i in 0..4 {
        let entry = ChildEntry {
            name: OsString::from(format!("f{i}")),
            kind: ChildKind::File,
            metadata: None,
        };
        assert!(batch.try_push(entry).is_none(), "push {i} should fit");
    }
    assert!(batch.is_full());
    let extra = ChildEntry {
        name: OsString::from("overflow"),
        kind: ChildKind::File,
        metadata: None,
    };
    assert!(batch.try_push(extra).is_some(), "full batch must refuse");
    assert_eq!(batch.drain().len(), 4);
    assert!(batch.is_empty());
    // Spec defaults are 256 entries / 256 KiB.
    let spec = BatchLimits::spec_default();
    assert_eq!((spec.max_entries, spec.max_bytes), (256, 256 * 1024));
}

#[test]
fn machine_root_plan_seeds_and_fair_schedules() {
    use repo_scan::walk::roots::{plan_machine_roots, seed_roots, RootPlan, RootPriority};
    let seeds = seed_roots();
    assert!(seeds.iter().any(|r| r.path.as_path() == Path::new("/tmp")));
    assert!(seeds.iter().all(|r| r.priority == RootPriority::Early));
    let planned = plan_machine_roots(&[]);
    assert!(planned.len() >= seeds.len());
    // Round-robin: a large root cannot starve the others.
    let mut plan = RootPlan::new(planned);
    let n = plan.len();
    assert!(n > 1);
    let mut seen = BTreeSet::new();
    for _ in 0..n {
        seen.insert(plan.next().unwrap().path.clone());
    }
    assert_eq!(seen.len(), n, "every root visited once per cycle");
}

fn fixture_task(id: &str, scope: &str) -> Task {
    Task {
        id: id.to_string(),
        epoch: Epoch(1),
        generation: GenerationId(1),
        kind: TaskKind::EnumerateDir,
        scope_key: scope.to_string(),
        expected_revision: 0,
        idempotency_key: id.to_string(),
        state: TaskState::Pending,
        not_before: None,
    }
}

#[test]
fn scheduler_persists_children_before_parent_complete() {
    let mut store = MemorySchedulerStore::new();
    store.insert_task(fixture_task("enum-a", "a"));
    let mut sched = DurableScheduler::new(store);
    let claimed = sched.claim(Epoch(1), 10, Duration::from_secs(60)).unwrap();
    assert_eq!(claimed.len(), 1);
    let lease = claimed[0].1.clone();
    sched
        .complete(
            &lease,
            TaskOutcome::Complete {
                children: vec![DiscoveredChild {
                    scope_key: String::from("b"),
                    kind: TaskKind::EnumerateDir,
                    generation: GenerationId(1),
                    idempotency_key: String::from("enum-b"),
                }],
                candidates: vec![DiscoveredCandidate {
                    path_key: String::from("c"),
                    reason: String::from("exact-path probe"),
                }],
            },
        )
        .unwrap();
    // Parent complete, child pending, candidate recorded.
    let tasks = sched.store().all_tasks();
    assert_eq!(
        tasks.iter().find(|t| t.id == "enum-a").unwrap().state,
        TaskState::Complete
    );
    assert_eq!(
        tasks.iter().find(|t| t.id == "enum-b").unwrap().state,
        TaskState::Pending
    );
    assert_eq!(sched.store().all_candidates().len(), 1);
    assert_eq!(sched.pending_count(GenerationId(1)).unwrap(), 1);
}

#[test]
fn stale_completion_requeues_instead_of_erasing_invalidation() {
    let mut store = MemorySchedulerStore::new();
    store.insert_task(fixture_task("enum-c", "c"));
    let mut sched = DurableScheduler::new(store);
    let claimed = sched.claim(Epoch(1), 10, Duration::from_secs(60)).unwrap();
    let lease = claimed[0].1.clone();
    // Invalidation arrives mid-enumeration.
    sched.invalidate("c").unwrap();
    let disposition = sched
        .complete_detailed(
            &lease,
            TaskOutcome::Complete {
                children: vec![],
                candidates: vec![],
            },
        )
        .unwrap();
    assert_eq!(
        disposition,
        repo_scan::scheduler::CompletionDisposition::StaleRequeued
    );
    let task = sched
        .store()
        .all_tasks()
        .into_iter()
        .find(|t| t.id == "enum-c")
        .unwrap();
    assert_eq!(task.state, TaskState::Pending);
    assert_eq!(task.expected_revision, 1);
}

#[test]
fn expired_leases_and_wrong_tokens_rejected() {
    let mut store = MemorySchedulerStore::new();
    store.insert_task(fixture_task("enum-d", "d"));
    let mut sched = DurableScheduler::new(store);
    // Zero TTL: the lease is already expired when the next claim runs.
    let claimed = sched.claim(Epoch(1), 10, Duration::from_secs(0)).unwrap();
    assert_eq!(claimed.len(), 1);
    let reclaimed = sched.claim(Epoch(1), 10, Duration::from_secs(60)).unwrap();
    assert_eq!(reclaimed.len(), 1, "expired lease must return to pending");
    assert_ne!(claimed[0].1.token, reclaimed[0].1.token);
    // The old token is stale now.
    let stale = sched.complete(
        &claimed[0].1,
        TaskOutcome::Complete {
            children: vec![],
            candidates: vec![],
        },
    );
    assert!(stale.is_err(), "stale lease token must be rejected");
}

#[test]
fn backoff_and_circuit_breaker_shape() {
    assert!(backoff_for_attempt(0) <= backoff_for_attempt(1));
    assert!(backoff_for_attempt(1) <= backoff_for_attempt(2));
    assert!(backoff_for_attempt(100) <= Duration::from_secs(300));
    let mut breaker = CircuitBreaker::new(3, Duration::from_secs(60));
    let now = std::time::SystemTime::now();
    assert!(breaker.allow(now));
    breaker.on_failure(now);
    breaker.on_failure(now);
    assert!(breaker.allow(now));
    breaker.on_failure(now);
    assert!(!breaker.allow(now), "breaker must open at threshold");
    breaker.on_success();
    assert!(breaker.allow(now), "success must close the breaker");
}

#[test]
fn admission_enforces_hard_non_additive_limits() {
    use repo_scan::config::ResourceLimits;
    let mut admission = Admission::new(ResourceLimits::default());
    let e1 = admission.try_acquire(OpClass::Enumerate).expect("enum 1");
    let e2 = admission.try_acquire(OpClass::Enumerate).expect("enum 2");
    assert!(
        admission.try_acquire(OpClass::Enumerate).is_none(),
        "enum cap is 2"
    );
    // Shared permits exhausted too: a Git probe cannot sneak past.
    assert!(
        admission.try_acquire(OpClass::GitProbe).is_none(),
        "shared cap is 2"
    );
    admission.release(&e1);
    admission.release(&e2);
    let g = admission.try_acquire(OpClass::GitProbe).expect("git 1");
    assert!(
        admission.try_acquire(OpClass::GitProbe).is_none(),
        "git cap is 1"
    );
    // One shared permit remains: one enum fits alongside the Git probe.
    let e = admission
        .try_acquire(OpClass::Enumerate)
        .expect("enum alongside git");
    assert!(
        admission.try_acquire(OpClass::Other).is_none(),
        "shared cap still 2"
    );
    admission.release(&g);
    admission.release(&e);
    // Helpers: 4 max including still-stuck.
    for _ in 0..4 {
        assert!(admission.add_helper());
    }
    assert!(!admission.add_helper());
    assert!(!admission.helper_spawn_allowed());
    // Descriptors: 64 budget.
    assert!(admission.fd_acquire(64));
    assert!(!admission.fd_acquire(1));
    admission.fd_release(64);
    // Pressure stops everything.
    admission.set_pressure(true);
    assert!(admission.try_acquire(OpClass::Enumerate).is_none());
    assert!(!admission.prefetch_allowed(0, 0));
}

#[test]
fn telemetry_counters_and_sampler() {
    let counters = Counters::default();
    counters.add_enumerated(7);
    counters.add_directory();
    counters.add_transaction();
    counters.add_gap();
    let snap = counters.snapshot();
    assert_eq!((snap.enumerated_entries, snap.directories_complete), (7, 1));
    assert_eq!((snap.db_transactions, snap.gaps), (1, 1));
    let sampler = FootprintSampler::new();
    assert!(!sampler.accounting_method().is_empty());
    let sample = Telemetry::sample(&sampler).expect("sample");
    assert!(sample.cpu_seconds >= 0.0);
    assert!(sampler.due() || !sampler.due(), "due() is total");
}
