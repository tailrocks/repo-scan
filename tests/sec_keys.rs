//! fix4 residual: planner keys are lossless end-to-end. A literal-U+FFFD
//! path and a non-UTF8 sibling whose lossy rendering collides with it
//! must hold distinct planner keys and BOTH be invalidated through the
//! production reconcile path (no fan-out drop).

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

use repo_scan::config::scope_key_for_dir;
use repo_scan::events::{
    dir_scope_for_subtree_key, parse_subtree_scope_key, subtree_scope_key, EventBatch,
    EventCursorId,
};
use repo_scan::store::{now_ms, Store, TursoStore};
use std::path::PathBuf;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

/// Non-UTF8 sibling pair: `weird` holds raw 0xFF bytes, `literal` is its
/// lossy rendering as a real path (embeds U+FFFD). Old display-form keys
/// collided; lossless keys must not.
#[cfg(unix)]
#[test]
fn lossless_planner_keys_invalidate_ufffd_collided_siblings() {
    use std::os::unix::ffi::OsStringExt;

    let rt = runtime();
    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = tmp.path().join("catalog.db");
        let mut raw = repo_scan::config::path_as_bytes(&tmp.path().join("w"));
        raw.extend_from_slice(&[0xff, 0xfe]);
        let weird = PathBuf::from(std::ffi::OsString::from_vec(raw));
        let literal = PathBuf::from(weird.to_string_lossy().into_owned());
        assert_ne!(weird, literal, "pair must be a real collision candidate");

        // Key level: distinct lossless keys, byte-exact round-trip each,
        // scheduler agreement each.
        let key_weird = subtree_scope_key("vol-a", &weird);
        let key_literal = subtree_scope_key("vol-a", &literal);
        assert_ne!(key_weird, key_literal, "lossless keys never collide");
        for (key, path) in [(&key_weird, &weird), (&key_literal, &literal)] {
            assert_eq!(
                parse_subtree_scope_key(key),
                Some(("vol-a".to_string(), path.clone())),
                "{key}"
            );
            assert_eq!(
                dir_scope_for_subtree_key(key),
                Some(scope_key_for_dir(path)),
                "{key}"
            );
        }

        // Fixture realism only: proceed when the platform rejects the
        // non-UTF-8 name itself (macOS/APFS refuses with EILSEQ).
        for dir in [&weird, &literal] {
            match std::fs::create_dir_all(dir) {
                Ok(()) => {}
                Err(e)
                    if e.kind() == std::io::ErrorKind::InvalidInput
                        || e.raw_os_error() == Some(libc::EILSEQ) =>
                {
                    eprintln!("note: OS rejected fixture dir name: {e}; continuing");
                }
                Err(e) => panic!("create fixture dir: {e}"),
            }
        }

        // Production path: one batch naming both siblings invalidates both.
        let store = TursoStore::open(&db).await.expect("open");
        let generation = store
            .create_generation("machine", "running", None, now_ms())
            .await
            .expect("generation");
        let batch = EventBatch {
            volume_key: "vol-a".to_string(),
            high_water: EventCursorId(60),
            invalidations: vec![weird.clone(), literal.clone()],
            history_done: false,
            signals: Vec::new(),
        };
        let outcome = main_under_test::test_apply_event_batch(&store, generation, "uuid-a", &batch)
            .await
            .expect("ingest");
        assert_eq!(outcome.scopes, 3, "weird + literal + shared parent");
        assert_eq!(
            store
                .scope_rev(&scope_key_for_dir(&weird))
                .await
                .expect("rev"),
            1
        );
        assert_eq!(
            store
                .scope_rev(&scope_key_for_dir(&literal))
                .await
                .expect("rev"),
            1
        );
    });
}
