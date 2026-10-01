//! Security-bounds regression tests: one focused test per fix.
//! Run-loop tests drive `src/main.rs` directly (included as a module)
//! through its `#[cfg(test)]` hooks — the same code production executes.

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_under_test;

/// A-F1: display-collided non-UTF-8 siblings share one planner key; both
/// must fan out to their own scopes (no sibling dropped).
#[cfg(unix)]
#[test]
fn planner_key_collision_fans_out_to_all_siblings() {
    assert_eq!(main_under_test::test_subtree_fanout(), 2);
}

/// RSF-SEC-WATCHDOG-ABORT: the in-loop gate fires only on a stall with no
/// completed entry inside grace.
#[test]
fn watchdog_inloop_abort_fires_only_on_stall() {
    let (fires, quiet_progress, quiet_grace) = main_under_test::test_watchdog_inloop_abort();
    assert!(fires, "stall past grace with no progress must abort");
    assert!(!quiet_progress, "progress resets the gate");
    assert!(!quiet_grace, "stalls within grace must not abort");
}

/// A-F5: the alias table caps with a recorded gap; repeats stay quiet.
#[test]
fn alias_table_caps_with_gap() {
    let (held, overflowed, gap_buffered) = main_under_test::test_alias_cap();
    assert_eq!(held, 4096, "alias table must hold exactly MAX_ALIASES");
    assert!(overflowed, "overflow flag must be set");
    assert!(gap_buffered, "overflow must buffer a gap row");
}

/// A-F5: the probe identity index caps with a recorded gap.
#[test]
fn probe_index_caps_with_gap() {
    let (held, overflowed, gap_buffered) = main_under_test::test_probed_git_ids_cap();
    assert_eq!(
        held, 4096,
        "probe index must hold exactly MAX_PROBED_GIT_IDS"
    );
    assert!(overflowed, "overflow flag must be set");
    assert!(gap_buffered, "overflow must buffer a gap row");
}

/// Item 11: the dev-fallback volume id is colon-free and round-trips
/// through planner-key parsing even when the mount path holds `:`.
#[cfg(target_os = "macos")]
#[test]
fn dev_fallback_volume_id_is_colon_free() {
    let id =
        repo_scan::platform::macos::dev_fallback_volume_id("123", std::path::Path::new("/mnt:x"));
    assert!(
        !id.0.contains(':'),
        "fallback id must be colon-free: {}",
        id.0
    );
    let key = repo_scan::events::subtree_scope_key(&id.0, std::path::Path::new("/mnt:x/a:b"));
    let (volume, path) = repo_scan::events::parse_subtree_scope_key(&key).expect("round-trip");
    assert_eq!(volume, id.0);
    assert_eq!(path, std::path::PathBuf::from("/mnt:x/a:b"));
}
