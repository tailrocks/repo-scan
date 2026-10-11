//! Regression tests for the publication review findings
//! (PUB-01A/01B/02/03): one focused test per fix. PUB-01A lives in
//! `tests/fail_report.rs` beside the RSP-003 atomicity coverage it
//! formalizes; the rest are here. Fixture-scale only (tempdirs, no
//! machine scans).

use repo_scan::report::publish::publish_staged;
#[cfg(unix)]
use repo_scan::report::publish::{check_destination_at, DestinationKind};

fn prior_bytes(report_id: &str) -> Vec<u8> {
    serde_json::json!({
        "schema_version": repo_scan::report::model::SCHEMA_VERSION,
        "report_id": report_id,
        "tool": {"name": "repo-scan", "version": "0.1.0", "source_commit": null},
    })
    .to_string()
    .into_bytes()
}

fn fresh_state(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let state = dir.path().join("state");
    repo_scan::privacy::private_dir_0700(&state.join("payload")).expect("payload");
    state
}

/// PUB-01B: the FD-authoritative gate fails closed when the held FD no
/// longer matches the live path (ancestor swap between bind and gate),
/// instead of committing through a detached FD. A freshly bound FD
/// classifies normally, and ancestry re-checked on the held FD still
/// refuses tool state.
#[cfg(unix)]
#[test]
fn pub01b_held_fd_gate_fails_closed_on_swap() {
    use repo_scan::store::owner::open_dir_nofollow;
    let dir = tempfile::tempdir().expect("tempdir");
    let state = fresh_state(&dir);

    // Bind the held FD, then swap the path to a fresh directory.
    let parent = dir.path().join("parent");
    repo_scan::privacy::private_dir_0700(&parent).expect("parent");
    let held = open_dir_nofollow(&parent.canonicalize().expect("canon")).expect("bind");
    std::fs::rename(&parent, dir.path().join("parent-old")).expect("swap aside");
    repo_scan::privacy::private_dir_0700(&parent).expect("new parent");
    let live_canon = parent.canonicalize().expect("canon");

    let dest = live_canon.join("report.json");
    let err = check_destination_at(Some(&held), &live_canon, &dest, &state, false)
        .expect_err("swapped FD refused");
    assert!(
        err.to_string().contains("changed during publication"),
        "{err}"
    );

    // Positive control: a freshly bound FD classifies Missing.
    let fresh = open_dir_nofollow(&live_canon).expect("bind");
    assert_eq!(
        check_destination_at(Some(&fresh), &live_canon, &dest, &state, false).expect("fresh ok"),
        DestinationKind::Missing
    );

    // Ancestry re-checked on the held FD agrees: a held FD inside tool
    // state is refused through the FD gate too.
    let payload = state.join("payload");
    let state_canon = payload.canonicalize().expect("canon");
    let held_state = open_dir_nofollow(&state_canon).expect("bind");
    let evil = state_canon.join("evil.json");
    let err = check_destination_at(Some(&held_state), &state_canon, &evil, &state, false)
        .expect_err("state ancestor refused");
    assert!(
        err.to_string().contains("tool state dir")
            || err.to_string().contains("persistence payload"),
        "{err}"
    );
}

/// PUB-02: sibling names are unpredictable (128-bit random suffix) and
/// cleanup deletes only what this call created, via the bound FD: a
/// blanket of legacy-pattern plants (`pid-clock-counter`) neither blocks
/// publication nor gets deleted, and a failed publish leaves decoys
/// byte-identical with no new residue. (Forcing an `EEXIST` on a random
/// name is infeasible by design; the single FD-bound unlink site plus
/// the `created` flag carry the rest — see `remove_sibling`.)
#[test]
fn pub02_sibling_unpredictable_and_owned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = fresh_state(&dir);

    // Phase 1: plants matching the legacy predictable scheme
    // (.<leaf>.tmp-<pid>-<ms>-<counter>) around the current clock.
    let leaf = "report.json";
    let now = repo_scan::store::now_ms();
    let pid = std::process::id();
    for counter in 1..=32u64 {
        for ms in [now - 1, now, now + 1, now + 2] {
            let plant = dir.path().join(format!(".{leaf}.tmp-{pid}-{ms}-{counter}"));
            repo_scan::privacy::private_write_0600(&plant, b"plant").expect("plant");
        }
    }

    // Fresh publish succeeds despite the plants (the random suffix never
    // collides) and touches none of them; its own sibling is consumed.
    let staged = dir.path().join("staged.json");
    let bytes = prior_bytes("pub02-a");
    repo_scan::privacy::private_write_0600(&staged, &bytes).expect("staged");
    let dest = dir.path().join(leaf);
    publish_staged(&staged, &dest, &state).expect("publish succeeds despite plants");
    assert_eq!(std::fs::read(&dest).expect("read"), bytes);
    for entry in dir.path().read_dir().expect("ls").flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains(".tmp-") {
            assert_eq!(
                std::fs::read(entry.path()).expect("read"),
                b"plant",
                "plant untouched: {name}"
            );
        }
    }

    // Phase 2: a failing publish (no-clobber) deletes no decoy and leaves
    // no new sibling residue; the blocked destination is untouched.
    let decoy = dir.path().join(".other.json.tmp-decoy");
    repo_scan::privacy::private_write_0600(&decoy, b"decoy").expect("decoy");
    let blocked = dir.path().join("other.json");
    repo_scan::privacy::private_write_0600(&blocked, b"user data").expect("blocked");
    let staged2 = dir.path().join("staged2.json");
    repo_scan::privacy::private_write_0600(&staged2, &prior_bytes("pub02-b")).expect("staged2");
    let err = publish_staged(&staged2, &blocked, &state).expect_err("no-clobber");
    assert!(err.to_string().contains("no-clobber"), "{err}");
    assert_eq!(
        std::fs::read(&decoy).expect("read"),
        b"decoy",
        "decoy survives failure"
    );
    assert_eq!(std::fs::read(&blocked).expect("read"), b"user data");
    for entry in dir.path().read_dir().expect("ls").flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains(".tmp-") {
            let content = std::fs::read(entry.path()).expect("read");
            assert!(
                content == b"plant" || content == b"decoy",
                "no fresh residue: {name}"
            );
        }
    }
}

/// PUB-03: coordination is per-destination, not parent-wide. An external
/// `flock` on the parent directory does not block publication (the old
/// parent lock failed `busy` after 2s here), concurrent publishes to
/// distinct leaves all succeed, fresh leaves take no lockfile (atomic
/// `linkat` needs none), and a replacement leaves its `.<leaf>.lock`
/// rendezvous behind.
#[cfg(unix)]
#[test]
fn pub03_per_dest_lockfile_no_parent_serialization() {
    use std::os::unix::io::AsRawFd;
    let dir = tempfile::tempdir().expect("tempdir");
    let state = fresh_state(&dir);

    // Phase 1: hold the parent directory `flock(LOCK_EX)` externally;
    // publication to a leaf must still succeed (the parent lock is no
    // longer consulted).
    let held_dir = std::fs::File::open(dir.path()).expect("open parent");
    // SAFETY: `flock` on an owned open directory FD test fixture.
    let rc = unsafe { libc::flock(held_dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0, "test holds parent flock");
    let staged = dir.path().join("staged.json");
    let bytes = prior_bytes("pub03-a");
    repo_scan::privacy::private_write_0600(&staged, &bytes).expect("staged");
    let dest = dir.path().join("report.json");
    publish_staged(&staged, &dest, &state).expect("parent flock does not block");
    assert_eq!(std::fs::read(&dest).expect("read"), bytes);
    // SAFETY: as above.
    unsafe {
        libc::flock(held_dir.as_raw_fd(), libc::LOCK_UN);
    }
    drop(held_dir);

    // Phase 2: concurrent publishes to distinct leaves under one parent
    // all succeed (no parent-wide serialization).
    std::thread::scope(|scope| {
        for i in 0..8u32 {
            let staged = dir.path().join(format!("staged-{i}.json"));
            let bytes = prior_bytes(&format!("pub03-leaf-{i}"));
            repo_scan::privacy::private_write_0600(&staged, &bytes).expect("staged");
            let dest = dir.path().join(format!("leaf-{i}.json"));
            let state = &state;
            scope.spawn(move || {
                let receipt =
                    publish_staged(&staged, &dest, state).expect("distinct leaf publishes");
                assert_eq!(receipt.bytes, bytes.len() as u64);
                assert_eq!(std::fs::read(&dest).expect("read"), bytes);
            });
        }
    });

    // Fresh leaves took no lockfile; a replacement creates its own.
    for entry in dir.path().read_dir().expect("ls").flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            !name.ends_with(".lock"),
            "fresh path takes no lockfile: {name}"
        );
    }
    let staged2 = dir.path().join("staged2.json");
    repo_scan::privacy::private_write_0600(&staged2, &prior_bytes("pub03-b")).expect("staged2");
    publish_staged(&staged2, &dest, &state).expect("replacement");
    assert!(
        dir.path().join(".report.json.lock").exists(),
        "per-dest lockfile rendezvous exists"
    );
}
