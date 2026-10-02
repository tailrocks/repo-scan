//! RSF-CLEAR-UNKNOWN-FILES regression (spec §15): `cache clear --all`
//! removes snapshot/staging files only with per-file ownership proof (a
//! tool-shaped name plus a catalog-bound checksum row or tool-marker
//! bytes bound to the filename). Unknown direct files, nested
//! directories, and symlinks are preserved and listed; a missing catalog
//! preserves unknowns and a foreign catalog authorizes nothing.
//! End-to-end runs of the built binary in tempdirs; no scans, no
//! machine I/O.

use repo_scan::store::{Store, TursoStore};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Run the binary with `--state-dir <state>` from `cwd`, returning output.
fn run(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    ProcCommand::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

fn stdout_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt")
}

/// Minimal tool-marker report bytes bound to `report_id`.
fn marker_report(report_id: &str) -> String {
    format!(
        "{{\"schema_version\":\"1.0.0\",\
        \"tool\":{{\"name\":\"repo-scan\",\"version\":\"test\"}},\
        \"report_id\":\"{report_id}\"}}"
    )
}

fn write_private(path: &Path, bytes: &[u8]) {
    repo_scan::privacy::private_write_0600(path, bytes).expect("write");
}

/// A fresh owned catalog plus `report-snapshots/` and `staging/` dirs.
fn owned_payload(dir: &Path) -> (PathBuf, PathBuf) {
    let state = dir.join("state");
    let payload = state.join("payload");
    repo_scan::privacy::private_dir_0700(&payload.join("report-snapshots")).expect("mkdir");
    repo_scan::privacy::private_dir_0700(&payload.join("staging")).expect("mkdir");
    runtime().block_on(async {
        let store = TursoStore::open(&payload.join("catalog.db"))
            .await
            .expect("open");
        store.close().await.expect("close");
    });
    (state, payload)
}

/// Record a snapshot row binding `id` to the SHA-256 of `bytes`.
fn save_row(db: &Path, id: &str, bytes: &[u8]) {
    let digest = repo_scan::report::publish::sha256_hex(bytes);
    runtime().block_on(async {
        let store = TursoStore::open(db).await.expect("open");
        let inserted = store
            .save_report_snapshot(
                id,
                "1.0.0",
                1,
                1,
                "staged",
                Some(digest.as_bytes()),
                repo_scan::store::now_ms(),
            )
            .await
            .expect("save row");
        assert!(inserted, "row inserted for {id}");
        store.close().await.expect("close");
    });
}

/// Unknown direct files are preserved (and listed) while an owned clear
/// otherwise proceeds.
fn unknown_preserved_while_owned_clear_proceeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let snapshots = payload.join("report-snapshots");
    let staging = payload.join("staging");
    let unknowns = [
        snapshots.join("evil.txt"),
        snapshots.join("report-planted.json"),
        staging.join("notes.dat"),
        staging.join(".staging-1-2-report-ghost.json"),
    ];
    for path in &unknowns {
        write_private(path, b"not tool state");
    }

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        stdout_text(&out).contains("preserved"),
        "unknowns listed: {}",
        stdout_text(&out)
    );
    assert!(
        !payload.join("catalog.db").exists(),
        "owned clear proceeded"
    );
    for path in &unknowns {
        assert!(path.is_file(), "preserved: {}", path.display());
    }
}

/// A missing catalog preserves unknown files instead of authorizing
/// their removal.
fn missing_db_preserves_unknown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let payload = state.join("payload");
    let snapshots = payload.join("report-snapshots");
    let staging = payload.join("staging");
    repo_scan::privacy::private_dir_0700(&snapshots).expect("mkdir");
    repo_scan::privacy::private_dir_0700(&staging).expect("mkdir");
    let unknowns = [
        snapshots.join("mine.txt"),
        snapshots.join("report-ghost.json"),
        staging.join("blob.dat"),
    ];
    for path in &unknowns {
        write_private(path, b"not tool state");
    }

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    for path in &unknowns {
        assert!(path.is_file(), "preserved: {}", path.display());
    }
}

/// A foreign catalog authorizes nothing, not even tool-marker files.
fn foreign_db_preserves_everything() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let payload = state.join("payload");
    let snapshots = payload.join("report-snapshots");
    let staging = payload.join("staging");
    repo_scan::privacy::private_dir_0700(&snapshots).expect("mkdir");
    repo_scan::privacy::private_dir_0700(&staging).expect("mkdir");
    write_private(&payload.join("catalog.db"), b"this is not a database file");
    let known = snapshots.join("report-a.json");
    write_private(&known, marker_report("report-a").as_bytes());
    let unknown = staging.join("evil.txt");
    write_private(&unknown, b"not tool state");

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(payload.join("catalog.db").exists(), "foreign db stays");
    assert!(known.is_file(), "marker file stays under foreign db");
    assert!(unknown.is_file(), "preserved: {}", unknown.display());
}

/// Nested directories under snapshots/staging are never entered.
fn nested_dirs_kept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let snapshots = payload.join("report-snapshots");
    let staging = payload.join("staging");
    let nested = snapshots.join("nested");
    let tool_named = snapshots.join("report-dir.json");
    let sub = staging.join("sub");
    repo_scan::privacy::private_dir_0700(&nested).expect("mkdir");
    repo_scan::privacy::private_dir_0700(&tool_named).expect("mkdir");
    repo_scan::privacy::private_dir_0700(&sub).expect("mkdir");
    let kept = [
        nested.join("keep.txt"),
        tool_named.join("inner.txt"),
        sub.join("deep.txt"),
    ];
    for path in &kept {
        write_private(path, b"nested");
    }

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        !payload.join("catalog.db").exists(),
        "owned clear proceeded"
    );
    for path in &kept {
        assert!(path.is_file(), "kept: {}", path.display());
    }
}

/// Direct symlinks under snapshots/staging are retained, never followed.
#[cfg(unix)]
fn symlinks_kept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let snapshots = payload.join("report-snapshots");
    let staging = payload.join("staging");
    let target = dir.path().join("target.txt");
    write_private(&target, b"target");
    let links = [
        snapshots.join("link.json"),
        snapshots.join("dangling.json"),
        staging.join("slink"),
    ];
    std::os::unix::fs::symlink(&target, &links[0]).expect("symlink");
    std::os::unix::fs::symlink(dir.path().join("no-such"), &links[1]).expect("symlink");
    std::os::unix::fs::symlink(&target, &links[2]).expect("symlink");

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    for path in &links {
        assert!(
            std::fs::symlink_metadata(path)
                .expect("metadata")
                .file_type()
                .is_symlink(),
            "symlink kept: {}",
            path.display()
        );
    }
    assert!(target.is_file(), "link target untouched");
}

/// Files with ownership proof are removed: catalog row + marker bytes,
/// marker bytes alone, catalog row alone, and a staging leftover.
fn known_tool_files_removed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let snapshots = payload.join("report-snapshots");
    let staging = payload.join("staging");
    let db = payload.join("catalog.db");

    let both = snapshots.join("report-both-a.json");
    let both_bytes = marker_report("report-both-a");
    write_private(&both, both_bytes.as_bytes());
    save_row(&db, "report-both-a", both_bytes.as_bytes());

    let marker_only = snapshots.join("report-marker-a.json");
    write_private(&marker_only, marker_report("report-marker-a").as_bytes());

    let row_only = snapshots.join("report-row-a.json");
    let row_bytes = b"opaque bytes recorded in the catalog";
    write_private(&row_only, row_bytes);
    save_row(&db, "report-row-a", row_bytes);

    let staged = staging.join(".staging-999-888-report-staged-a.json");
    write_private(&staged, marker_report("report-staged-a").as_bytes());

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(!db.exists(), "owned catalog removed");
    for path in [&both, &marker_only, &row_only, &staged] {
        assert!(!path.exists(), "removed: {}", path.display());
    }
}

/// Finding 4: known dirs leave through the validated parent FD only
/// when provably empty — emptied dirs are gone, while a dir kept
/// non-empty by preserved content stays and the run reports INCOMPLETE.
fn empty_dirs_removed_nonempty_report_incomplete() {
    // All-owned payload: every file removable, so every known dir drops.
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let snapshots = payload.join("report-snapshots");
    let staging = payload.join("staging");
    write_private(
        &snapshots.join("report-gone.json"),
        marker_report("report-gone").as_bytes(),
    );
    write_private(
        &staging.join(".staging-7-8-report-gone.json"),
        marker_report("report-gone").as_bytes(),
    );
    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(!snapshots.exists(), "emptied snapshots dir removed");
    assert!(!staging.exists(), "emptied staging dir removed");
    assert!(!payload.exists(), "emptied payload dir removed");
    assert!(
        !stdout.contains("INCOMPLETE"),
        "complete clear stays complete: {stdout}"
    );

    // Preserved content keeps its dir; the run says INCOMPLETE, exit 0.
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let snapshots = payload.join("report-snapshots");
    repo_scan::privacy::private_dir_0700(&snapshots.join("nested")).expect("mkdir");
    write_private(&snapshots.join("nested").join("keep.txt"), b"nested");
    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(
        stdout.contains("INCOMPLETE"),
        "non-empty dir reports incomplete: {stdout}"
    );
    assert!(snapshots.is_dir(), "non-empty dir kept");
    assert!(
        snapshots.join("nested").join("keep.txt").is_file(),
        "nested content kept"
    );
}

/// Finding 5: the deadline/per-read-bounded snapshot loading loop still
/// resolves every checksum row on the normal path — row-bound files
/// with opaque (non-marker) bytes are all removed with no INCOMPLETE.
fn snapshot_row_loading_resolves_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let snapshots = payload.join("report-snapshots");
    let db = payload.join("catalog.db");
    let mut victims = Vec::new();
    for n in 0..150u32 {
        let id = format!("report-row-{n:03}");
        let path = snapshots.join(format!("{id}.json"));
        let bytes = format!("opaque catalog-bound bytes {n}");
        write_private(&path, bytes.as_bytes());
        save_row(&db, &id, bytes.as_bytes());
        victims.push(path);
    }
    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(
        !stdout.contains("INCOMPLETE"),
        "row loading stays within bounds: {stdout}"
    );
    for path in &victims {
        assert!(!path.exists(), "row-bound file removed: {}", path.display());
    }
}

/// Finding 6: a payload-root listing failure is INCOMPLETE with the
/// unknown content preserved — never success-with-uninspected. The
/// payload keeps write+execute (FD-relative removal still works) but
/// drops read, so only the listing fails.
#[cfg(unix)]
fn unlistable_payload_reports_incomplete() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, payload) = owned_payload(dir.path());
    let unknown = payload.join("mine.txt");
    write_private(&unknown, b"not tool state");
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o333)).expect("chmod");
    if std::fs::read_dir(&payload).is_ok() {
        // Privileged environments (root) bypass permission bits, so the
        // listing cannot fail here; nothing to regress.
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o700))
            .expect("chmod back");
        return;
    }
    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o700)).expect("chmod back");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(
        stdout.contains("INCOMPLETE"),
        "listing failure reports incomplete: {stdout}"
    );
    assert!(unknown.is_file(), "unknown payload file preserved");
    assert!(
        !payload.join("catalog.db").exists(),
        "owned clear proceeded where it could"
    );
}

#[test]
fn clear_unknown_files_matrix() {
    unknown_preserved_while_owned_clear_proceeds();
    missing_db_preserves_unknown();
    foreign_db_preserves_everything();
    nested_dirs_kept();
    #[cfg(unix)]
    symlinks_kept();
    known_tool_files_removed();
    empty_dirs_removed_nonempty_report_incomplete();
    snapshot_row_loading_resolves_rows();
    #[cfg(unix)]
    unlistable_payload_reports_incomplete();
}

// ---------------------------------------------------------------------------
// FIXREADY4 C (2AE47A9E + cb2c3c9a): clear atomicity. A refused clear must
// mutate NOTHING (previously catalog.db was removed before a symlinked
// WAL/marker was even discovered); a dangling payload path is an ERROR,
// never success; symlinked ancestors are FD-bound traversal (explicit
// policy). Every consumer case below asserts either full-clear success
// or byte-identical state plus a nonzero exit.
// ---------------------------------------------------------------------------

/// Fresh scratch dir under `/tmp` (0700) for FIXREADY4 C fixtures.
#[cfg(unix)]
fn fresh_scratch() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("fail-clear-fixready4c-")
        .tempdir_in("/tmp")
        .expect("scratch tempdir under /tmp");
    repo_scan::privacy::private_dir_0700(dir.path()).expect("scratch root is 0700");
    dir
}

/// Snapshot of one state tree: relative path -> file bytes or symlink
/// target (lstat semantics, never following). The coordination lock is
/// excluded: every guarded run rewrites its occupancy note by design.
#[cfg(unix)]
fn snapshot_state_tree(state: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    let mut stack = vec![state.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = path.strip_prefix(state).unwrap_or(&path).to_path_buf();
            if rel == Path::new("instance.lock") {
                continue;
            }
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).expect("read link");
                out.insert(rel, target.as_os_str().as_encoded_bytes().to_vec());
            } else if meta.file_type().is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                out.insert(rel, std::fs::read(&path).expect("read file"));
            }
        }
    }
    out
}

/// Assert two state snapshots are byte-identical (same entries, same
/// bytes/targets). `instance.lock` is excluded by the snapshotter.
#[cfg(unix)]
fn assert_state_identical(
    before: &std::collections::BTreeMap<PathBuf, Vec<u8>>,
    state: &Path,
    case: &str,
) {
    let after = snapshot_state_tree(state);
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "{case}: state entry set changed"
    );
    for (rel, bytes) in before {
        assert_eq!(
            after.get(rel),
            Some(bytes),
            "{case}: {} changed",
            rel.display()
        );
    }
}

/// Owned payload with a marker exactly bound to the live catalog `db_id`
/// (the consumer's seeded-scan shape), plus one row-bound snapshot file
/// and one staging leftover.
#[cfg(unix)]
fn owned_bound_payload(dir: &Path) -> (PathBuf, PathBuf) {
    let (state, payload) = owned_payload(dir);
    let db = payload.join("catalog.db");
    let db_id = runtime()
        .block_on(async {
            let store = TursoStore::open(&db).await.expect("open");
            let id = store.catalog_db_id().await.expect("db id");
            store.close().await.expect("close");
            id
        })
        .expect("catalog carries a db_id");
    let marker = format!(
        "{}\ndb_id={db_id}\nwritten_ms=1\npid=1\n",
        repo_scan::store::owner::OWNER_MARKER_TAG
    );
    write_private(&payload.join("owner.marker"), marker.as_bytes());
    let snap = payload.join("report-snapshots").join("report-c.json");
    let snap_bytes = marker_report("report-c");
    write_private(&snap, snap_bytes.as_bytes());
    save_row(&db, "report-c", snap_bytes.as_bytes());
    write_private(
        &payload.join("staging").join(".staging-11-12-report-c.json"),
        marker_report("report-c").as_bytes(),
    );
    (state, payload)
}

/// WAL-symlink case (2AE47A9E): exit 1 with the catalog, marker,
/// snapshot, and staging bytes all intact and the outside sentinel
/// untouched.
#[cfg(unix)]
fn wal_symlink_refusal_is_atomic() {
    let dir = fresh_scratch();
    let (state, payload) = owned_bound_payload(dir.path());
    std::fs::remove_file(payload.join("catalog.db-wal")).ok();
    let sentinel = dir.path().join("wal-sentinel");
    write_private(&sentinel, b"outside bytes");
    std::os::unix::fs::symlink(&sentinel, payload.join("catalog.db-wal")).expect("symlink");
    let before = snapshot_state_tree(&state);

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert_state_identical(&before, &state, "wal-symlink");
    assert_eq!(
        std::fs::read(&sentinel).expect("sentinel"),
        b"outside bytes",
        "outside sentinel untouched"
    );
}

/// Dangling-marker case (cb2c3c9a): a dangling `owner.marker` symlink
/// refuses with zero mutation — catalog, WAL, snapshot, and staging
/// all survive.
#[cfg(unix)]
fn dangling_marker_refusal_is_atomic() {
    let dir = fresh_scratch();
    let (state, payload) = owned_bound_payload(dir.path());
    std::fs::remove_file(payload.join("owner.marker")).expect("remove marker");
    std::os::unix::fs::symlink(
        payload.join("no-such-marker-target"),
        payload.join("owner.marker"),
    )
    .expect("symlink");
    let before = snapshot_state_tree(&state);

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert_state_identical(&before, &state, "dangling-marker");
}

/// Dangling-payload case (cb2c3c9a): a dangling payload-dir symlink is
/// an ERROR (nonzero exit), never exit-0 false success — and the link
/// itself is left untouched.
#[cfg(unix)]
fn dangling_payload_is_error_not_success() {
    let dir = fresh_scratch();
    let state = dir.path().join("state");
    repo_scan::privacy::private_dir_0700(&state).expect("mkdir");
    std::os::unix::fs::symlink(state.join("no-such-payload"), state.join("payload"))
        .expect("symlink");
    let before = snapshot_state_tree(&state);

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_ne!(
        out.status.code(),
        Some(0),
        "dangling payload must not report success: {}",
        stdout_text(&out)
    );
    assert_state_identical(&before, &state, "dangling-payload");
    assert!(
        std::fs::symlink_metadata(state.join("payload"))
            .expect("metadata")
            .file_type()
            .is_symlink(),
        "dangling link left untouched"
    );
}

/// Payload-symlink-to-moved-payload case (cb2c3c9a): exit 1, the moved
/// payload stays intact, the link stays.
#[cfg(unix)]
fn moved_payload_symlink_refusal_is_atomic() {
    let dir = fresh_scratch();
    let (state, payload) = owned_bound_payload(dir.path());
    let moved = dir.path().join("moved-payload");
    std::fs::rename(&payload, &moved).expect("move payload");
    std::os::unix::fs::symlink(&moved, &payload).expect("symlink");
    let before = snapshot_state_tree(&state);
    let moved_bytes = std::fs::read(moved.join("catalog.db")).expect("moved db");

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert_state_identical(&before, &state, "moved-payload-symlink");
    assert_eq!(
        std::fs::read(moved.join("catalog.db")).expect("moved db after"),
        moved_bytes,
        "moved payload intact"
    );
}

/// State-dir and catalog-db symlink cases (cb2c3c9a): exit 1 with no
/// observed changes.
#[cfg(unix)]
fn dir_and_db_symlink_refusals_are_atomic() {
    // Symlinked state dir.
    let dir = fresh_scratch();
    let (state, _payload) = owned_bound_payload(dir.path());
    let link = dir.path().join("state-link");
    std::os::unix::fs::symlink(&state, &link).expect("symlink");
    let before = snapshot_state_tree(&state);
    let out = run(&["cache", "clear", "--all"], dir.path(), &link);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert_state_identical(&before, &state, "state-dir-symlink");

    // Symlinked catalog db.
    let dir = fresh_scratch();
    let (state, payload) = owned_bound_payload(dir.path());
    let outside = dir.path().join("outside.db");
    write_private(&outside, b"outside database bytes");
    std::fs::remove_file(payload.join("catalog.db")).expect("remove db");
    std::os::unix::fs::symlink(&outside, payload.join("catalog.db")).expect("symlink");
    let before = snapshot_state_tree(&state);
    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert_state_identical(&before, &state, "catalog-db-symlink");
    assert_eq!(
        std::fs::read(&outside).expect("outside"),
        b"outside database bytes",
        "outside target untouched"
    );
}

/// Ancestor-symlink policy (cb2c3c9a, explicit): a symlinked
/// intermediate ancestor resolves normally (trust-root model: the
/// operator configured this path) and the clear proceeds as FD-bound
/// traversal — the resolved payload is removed through the alias.
#[cfg(unix)]
fn ancestor_symlink_is_fd_bound_traversal() {
    let dir = fresh_scratch();
    let real = dir.path().join("real");
    let (state, payload) = owned_bound_payload(&real);
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).expect("symlink");
    let via_alias = alias.join("state");

    let out = run(&["cache", "clear", "--all"], dir.path(), &via_alias);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        !payload.exists() && !payload.is_symlink(),
        "resolved payload removed through the alias"
    );
    assert!(
        std::fs::symlink_metadata(&alias)
            .expect("metadata")
            .file_type()
            .is_symlink(),
        "alias itself untouched"
    );
    assert!(
        state.join("instance.lock").is_file(),
        "coordination lock retained"
    );
}

/// Positive control (cb2c3c9a): ordinary owned state clears fully with
/// exit 0 while retaining `instance.lock`.
#[cfg(unix)]
fn positive_control_clears_fully() {
    let dir = fresh_scratch();
    let (state, payload) = owned_bound_payload(dir.path());

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        !payload.exists() && !payload.is_symlink(),
        "payload fully removed"
    );
    assert!(
        state.join("instance.lock").is_file(),
        "coordination lock retained"
    );
}

#[test]
#[cfg(unix)]
fn clear_fixready4_atomicity_matrix() {
    wal_symlink_refusal_is_atomic();
    dangling_marker_refusal_is_atomic();
    dangling_payload_is_error_not_success();
    moved_payload_symlink_refusal_is_atomic();
    dir_and_db_symlink_refusals_are_atomic();
    ancestor_symlink_is_fd_bound_traversal();
    positive_control_clears_fully();
    dangling_known_dir_symlink_refusal_is_atomic();
}

/// Dangling-known-dir case (round-2 C2): a dangling `report-snapshots`
/// symlink is an ERROR (exit 1, zero mutation) — never silent success
/// over uninspected entries. The static plant refuses before any unlink;
/// the raced-in variant (symlink planted after preflight) is pinned by
/// the deterministic seam test in `tests/review_fix_main.rs`, which is
/// the only shape that reaches the removal-phase guard.
#[cfg(unix)]
fn dangling_known_dir_symlink_refusal_is_atomic() {
    let dir = fresh_scratch();
    let (state, payload) = owned_bound_payload(dir.path());
    std::fs::remove_dir_all(payload.join("report-snapshots")).expect("remove snapshots");
    std::os::unix::fs::symlink(
        payload.join("no-such-snapshots-target"),
        payload.join("report-snapshots"),
    )
    .expect("symlink");
    let before = snapshot_state_tree(&state);

    let out = run(&["cache", "clear", "--all"], dir.path(), &state);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert_state_identical(&before, &state, "dangling-known-dir");
    assert!(
        std::fs::symlink_metadata(payload.join("report-snapshots"))
            .expect("metadata")
            .file_type()
            .is_symlink(),
        "dangling link left untouched"
    );
}
