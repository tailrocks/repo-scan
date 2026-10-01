//! SR-STATE-06..09: ancestor symlinks, batch idempotency+restore,
//! gen-scoped expiry+owner epoch, bounded fanout. Tempdirs only.
use repo_scan::model::TaskState;
use repo_scan::store::{now_ms, NewTask, Store, TaskOutcome, TursoStore, WriterBatch};
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}
async fn enq(s: &TursoStore, id: &str, g: u64, now: i64) {
    let k = format!("i:{id}");
    s.enqueue_task(
        &NewTask {
            id,
            kind: "e",
            generation: g,
            dir_id: None,
            scope_key: "d:00",
            expected_rev: 0,
            idempotency_key: &k,
        },
        now,
    )
    .await
    .unwrap();
}
#[cfg(unix)]
#[test]
fn sr06_links_refused() {
    rt().block_on(async {
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("r");
        repo_scan::privacy::private_dir_0700(&r).unwrap();
        let l = t.path().join("l");
        std::os::unix::fs::symlink(&r, &l).unwrap();
        let db = l.join("p").join("c.db");
        // `TursoStore` is not `Debug`, so `expect_err` cannot be used.
        let errs = [
            match TursoStore::open(&db).await {
                Ok(_) => panic!("symlinked ancestors must be refused (link)"),
                Err(e) => e,
            },
            match TursoStore::open_read_only(&db).await {
                Ok(_) => panic!("symlinked ancestors must be refused (ro)"),
                Err(e) => e,
            },
        ];
        for e in errs {
            assert!(e.to_string().contains("symlink"), "{e}");
        }
        assert!(!r.join("p").exists());
        let ok = t.path().join("o.db");
        TursoStore::open(&ok).await.unwrap().close().await.unwrap();
        let sy = t.path().join("s.db");
        std::os::unix::fs::symlink(&ok, &sy).unwrap();
        let err = match TursoStore::open(&sy).await {
            Ok(_) => panic!("symlinked db file must be refused"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("symlink"), "{err}");
    });
}
#[test]
fn sr07_dup_skips_fail_restores() {
    rt().block_on(async {
        let t = tempfile::tempdir().unwrap();
        let s = TursoStore::open(&t.path().join("c.db")).await.unwrap();
        let n = now_ms();
        let q = "INSERT OR IGNORE INTO errors (id, scope_key, category, detail, attempts, first_seen_ms, last_seen_ms, open) VALUES (?1,'s','c','d',1,?2,?2,1)";
        let v = |id: &str| vec![turso::Value::Text(id.into()), turso::Value::Integer(n)];
        let mut a = WriterBatch::new();
        a.push(q, v("s07-a"));
        assert_eq!(s.commit_batch("k7", &mut a, n).await.unwrap(), 1);
        let mut b = WriterBatch::new();
        b.push(q, v("s07-b"));
        assert_eq!(s.commit_batch("k7", &mut b, now_ms()).await.unwrap(), 0);
        assert!(b.is_empty() && s.get_error("s07-b").await.unwrap().is_none());
        let mut f = WriterBatch::new();
        f.push(q, v("s07-k"));
        f.push("INSERT INTO missing_xyz (id) VALUES (?1)", v("x"));
        s.flush(&mut f).await.expect_err("bad");
        assert_eq!(f.len(), 2);
        assert!(s.get_error("s07-k").await.unwrap().is_none());
        let mut c = WriterBatch::new();
        c.push(q, v("s07-c"));
        c.push("INSERT INTO missing_xyz (id) VALUES (?1)", v("x"));
        s.commit_batch("k7b", &mut c, n).await.expect_err("bad");
        assert_eq!(c.len(), 2);
        assert!(!s.reconcile_idempotency_key("k7b").await.unwrap());
        s.close().await.unwrap();
    });
}
#[test]
fn sr08_gen_expiry_owner_epoch() {
    rt().block_on(async {
        let t = tempfile::tempdir().unwrap();
        let s = TursoStore::open(&t.path().join("c.db")).await.unwrap();
        let e = s.epoch();
        let n = now_ms();
        enq(&s, "g1", 1, n).await;
        enq(&s, "g2", 2, n).await;
        let c2 = s
            .claim_tasks_in_generation(2, e, 10, 1000, n)
            .await
            .unwrap();
        assert_eq!(c2.len(), 1);
        let l = n + 5000;
        let c1 = s
            .claim_tasks_in_generation(1, e, 10, 60000, l)
            .await
            .unwrap();
        assert_eq!(c1[0].task.id, "g1");
        assert_eq!(
            s.get_task("g2").await.unwrap().unwrap().state,
            TaskState::Leased
        );
        let c2b = s
            .claim_tasks_in_generation(2, e, 10, 60000, l)
            .await
            .unwrap();
        assert_eq!(c2b[0].task.id, "g2");
        assert_ne!(c2b[0].token, c2[0].token);
        let f = e.wrapping_add(9999);
        for r in [
            s.claim_tasks(f, 1, 60000, l).await,
            s.claim_tasks_in_generation(1, f, 1, 60000, l).await,
        ] {
            assert!(r
                .expect_err("foreign")
                .to_string()
                .contains("not this owner"));
        }
        assert!(s
            .renew_lease("g1", c1[0].token, f, 60000, l)
            .await
            .expect_err("f")
            .to_string()
            .contains("not this owner"));
        assert!(s
            .complete_task("g1", c1[0].token, f, &TaskOutcome::Complete, l)
            .await
            .expect_err("f")
            .to_string()
            .contains("not this owner"));
        s.close().await.unwrap();
    });
}
#[test]
fn sr09_fanout_capped() {
    rt().block_on(async {
        let t = tempfile::tempdir().unwrap();
        let s = TursoStore::open(&t.path().join("c.db")).await.unwrap();
        let n = now_ms();
        let sc = repo_scan::config::scope_key_for_dir(&std::path::PathBuf::from("/tmp/s09"));
        let mut b = WriterBatch::new();
        for i in 0..300 {
            TursoStore::buffer_dir_upsert(
                &mut b,
                None,
                b"s09",
                "/tmp/s09",
                "dv",
                &format!("o{i}"),
                "ic",
                n,
            );
            if b.should_flush() {
                s.flush(&mut b).await.unwrap();
            }
        }
        s.flush(&mut b).await.unwrap();
        assert_eq!(s.invalidate_scope(&sc, 1, n).await.unwrap(), 1);
        let id = s.lookup_dir_id("dv", "o0", "ic").await.unwrap().unwrap();
        assert_eq!(s.get_dir(id).await.unwrap().unwrap().invalidation_rev, 1);
        for i in 300..1025 {
            TursoStore::buffer_dir_upsert(
                &mut b,
                None,
                b"s09",
                "/tmp/s09",
                "dv",
                &format!("o{i}"),
                "ic",
                n,
            );
            if b.should_flush() {
                s.flush(&mut b).await.unwrap();
            }
        }
        s.flush(&mut b).await.unwrap();
        assert!(s
            .invalidate_scope(&sc, 1, n)
            .await
            .expect_err("cap")
            .to_string()
            .contains("fanout"));
        assert_eq!(s.scope_rev(&sc).await.unwrap(), 1);
        s.close().await.unwrap();
    });
}

/// SR-STATE-06: the lifetime state-root anchor fails closed when the state
/// directory is swapped under the held FD: `verify_state_root` and the
/// periodic `open_reader` re-verify both refuse.
#[cfg(unix)]
#[test]
fn sr06_state_root_swap_fails_closed() {
    rt().block_on(async {
        let t = tempfile::tempdir().unwrap();
        let state = t.path().join("state");
        let (_guard, store) = TursoStore::open_owned(&state).await.unwrap();
        store.verify_state_root().unwrap();
        store.open_reader().await.unwrap();
        let renamed = t.path().join("state-old");
        std::fs::rename(&state, &renamed).unwrap();
        repo_scan::privacy::private_dir_0700(&state).unwrap();
        let err = store.verify_state_root().expect_err("swapped root refused");
        assert!(
            err.to_string().contains("changed") || err.to_string().contains("refusing"),
            "{err}"
        );
        let err = store
            .open_reader()
            .await
            .expect_err("periodic re-verify refused");
        assert!(
            err.to_string().contains("changed") || err.to_string().contains("refusing"),
            "{err}"
        );
    });
}

/// Privacy: state/payload parents are created `0700` and the catalog/WAL
/// files are tightened to `0600` post-create (best-effort + verify).
#[cfg(unix)]
#[test]
fn privacy_catalog_private_modes() {
    use std::os::unix::fs::PermissionsExt;
    rt().block_on(async {
        let t = tempfile::tempdir().unwrap();
        let state_dir = t.path().join("state");
        let db = state_dir.join("payload").join("catalog.db");
        let s = TursoStore::open(&db).await.unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&state_dir), 0o700);
        assert_eq!(mode(db.parent().unwrap()), 0o700);
        assert_eq!(mode(&db) & 0o077, 0, "catalog.db has no group/other access");
        // Force WAL traffic, then check the sidecar when present.
        let n = now_ms();
        enq(&s, "priv-1", 1, n).await;
        let _ = s.pending_count(1).await.unwrap();
        for suffix in ["-wal", "-shm"] {
            let mut name = db.file_name().unwrap().to_os_string();
            name.push(suffix);
            let sidecar = db.parent().unwrap().join(name);
            if sidecar.exists() {
                assert_eq!(
                    mode(&sidecar) & 0o077,
                    0,
                    "sidecar {} has no group/other access",
                    sidecar.display()
                );
            }
        }
        s.close().await.unwrap();
    });
}
