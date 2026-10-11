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

/// RS-PRIV-03: a symlinked engine sidecar is refused BEFORE the engine
/// open (the path-following engine never meets it), not skipped.
#[cfg(unix)]
#[test]
fn rspriv03_symlinked_sidecar_refused_preopen() {
    rt().block_on(async {
        let t = tempfile::tempdir().unwrap();
        let db = t.path().join("payload").join("catalog.db");
        TursoStore::open(&db).await.unwrap().close().await.unwrap();
        let outside = t.path().join("outside-wal");
        std::fs::write(&outside, b"planted").unwrap();
        let wal = db.parent().unwrap().join("catalog.db-wal");
        if wal.exists() {
            std::fs::remove_file(&wal).unwrap();
        }
        std::os::unix::fs::symlink(&outside, &wal).unwrap();
        let err = match TursoStore::open(&db).await {
            Ok(_) => panic!("symlinked sidecar must be refused"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("symlink"), "{err}");
        let err = match TursoStore::open_read_only(&db).await {
            Ok(_) => panic!("symlinked sidecar must be refused (ro)"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("symlink"), "{err}");
    });
}

/// RS-PRIV-07: ancestor-pinned creation refuses a symlinked ancestor
/// instead of creating through it; nested missing chains still build.
#[cfg(unix)]
#[test]
fn rspriv07_creation_refuses_symlinked_ancestor() {
    use repo_scan::store::owner::ensure_private_dir_all;
    let t = tempfile::tempdir().unwrap();
    let real = t.path().join("real");
    repo_scan::privacy::private_dir_0700(&real).unwrap();
    let link = t.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err =
        ensure_private_dir_all(&link.join("a").join("b")).expect_err("symlinked ancestor refused");
    assert!(err.to_string().contains("symlink"), "{err}");
    assert!(!real.join("a").exists(), "nothing created through the link");
    let nested = t.path().join("n1").join("n2").join("n3");
    ensure_private_dir_all(&nested).unwrap();
    assert!(nested.is_dir());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

/// RS-PRIV-08: the catalog-file identity bound at open is re-checked for
/// the handle lifetime — a swapped catalog file fails `verify_state_root`.
#[cfg(unix)]
#[test]
fn rspriv08_catalog_swap_fails_lifetime_recheck() {
    rt().block_on(async {
        let t = tempfile::tempdir().unwrap();
        let db = t.path().join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.unwrap();
        store.verify_state_root().unwrap();
        let other = t.path().join("other.db");
        TursoStore::open(&other)
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
        std::fs::rename(&other, &db).unwrap();
        let err = store
            .verify_state_root()
            .expect_err("swapped catalog refused");
        assert!(
            err.to_string().contains("changed") || err.to_string().contains("refusing"),
            "{err}"
        );
        let _ = store.close().await;
    });
}

/// RS-PRIV-11: `catalog.db-tshm` is enumerated with the other sidecars —
/// a symlinked one is refused pre-open — and is listed for clearing.
#[cfg(unix)]
#[test]
fn rspriv11_tshm_sidecar_enumerated() {
    rt().block_on(async {
        assert!(
            repo_scan::config::KNOWN_SIDECAR_FILES.contains(&"catalog.db-tshm"),
            "clear must enumerate catalog.db-tshm"
        );
        let t = tempfile::tempdir().unwrap();
        let db = t.path().join("payload").join("catalog.db");
        TursoStore::open(&db).await.unwrap().close().await.unwrap();
        let outside = t.path().join("outside-tshm");
        std::fs::write(&outside, b"planted").unwrap();
        let tshm = db.parent().unwrap().join("catalog.db-tshm");
        std::os::unix::fs::symlink(&outside, &tshm).unwrap();
        let err = match TursoStore::open_read_only(&db).await {
            Ok(_) => panic!("symlinked -tshm must be refused"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("symlink"), "{err}");
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
#[test]
fn p3b_batch_renewal_reports_lost_and_skips_empty() {
    rt().block_on(async {
        let t = tempfile::tempdir().unwrap();
        let s = TursoStore::open(&t.path().join("c.db")).await.unwrap();
        let n = now_ms();
        enq(&s, "b1", 1, n).await;
        enq(&s, "b2", 1, n).await;
        enq(&s, "b3", 1, n).await;
        let e = s.epoch();
        let claimed = s
            .claim_tasks_in_generation(1, e, 10, 1_000, n)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 3);
        // b3 completes, so its lease is gone at batch-renewal time.
        s.complete_task("b3", claimed[2].token, e, &TaskOutcome::Complete, n)
            .await
            .unwrap();
        let tx_before = s.stats().transactions;
        let leases: Vec<(&str, i64, u64)> = claimed
            .iter()
            .map(|c| {
                (
                    c.task.id.as_str(),
                    c.token,
                    c.task.lease_epoch.unwrap_or(u64::MAX),
                )
            })
            .collect();
        let lost = s
            .renew_leases_batch(&leases, 60_000, n + 500)
            .await
            .unwrap();
        assert_eq!(lost, vec![String::from("b3")]);
        assert_eq!(s.stats().transactions, tx_before + 1);
        for c in &claimed[..2] {
            let row = s.get_task(&c.task.id).await.unwrap().unwrap();
            assert_eq!(row.lease_expires_ms, Some(n + 500 + 60_000));
        }
        let tx_empty = s.stats().transactions;
        let none: Vec<(&str, i64, u64)> = Vec::new();
        assert!(s
            .renew_leases_batch(&none, 60_000, n)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(s.stats().transactions, tx_empty);
        s.close().await.unwrap();
    });
}
