//! Security-lane regressions: installed-git spawn envelope
//! (RSF-SEC-GIT-PROBE), engine-enforced read-only catalog + checked
//! integer conversions (Item 10), private-path docs hygiene
//! (RSF-SEC-DOCS-PATHS), and the documented dependency-audit gate
//! (RSF-SEC-AUDIT-GATE).
//!
//! Git-fixture tests build executable `git` stand-ins in tempdirs
//! (unix-only, like the existing wrapper fixtures). Database tests use
//! tempdir catalogs and a current-thread Tokio runtime; no test sleeps.

use repo_scan::store::{now_ms, Store, TursoStore};

#[cfg(unix)]
use repo_scan::git::fallback::{BinarySource, FallbackGit};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

/// Write an executable `git` fixture: `--version` prints `banner`,
/// every other argv runs `body`.
#[cfg(unix)]
fn git_fixture(dir: &std::path::Path, name: &str, banner: &str, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\necho \"{banner}\"\nexit 0\nfi\n{body}\n"
    );
    std::fs::write(&path, script).expect("write fixture");
    let mut perms = std::fs::metadata(&path).expect("meta").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod");
    path
}

/// RSF-SEC-GIT-PROBE through the public API: the feature probe passes
/// only on status 0 (stock) or 129 (Apple Git) with the porcelain
/// marker; any other status fails even when the text matches. Probing
/// an explicit path records `BinarySource::Explicit`.
#[cfg(unix)]
#[test]
fn git_probe_status_gate_and_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = "echo \" --porcelain[<version>]  machine-readable output\"";
    for (name, code, capable) in [
        ("git-zero", 0, true),
        ("git-apple", 129, true),
        ("git-one", 1, false),
        ("git-fatal", 128, false),
    ] {
        let git = git_fixture(
            dir.path(),
            name,
            "git version 2.47.1",
            &format!("{marker}\nexit {code}"),
        );
        let found = FallbackGit::probe(&git).expect("probe answers --version");
        assert_eq!(found.source(), BinarySource::Explicit, "{name}");
        assert_eq!(
            found.capabilities().feature_probe_ok,
            capable,
            "exit {code} with the marker"
        );
        assert_eq!(
            found.capabilities().porcelain_v2,
            capable,
            "exit {code} with the marker"
        );
    }
}

/// RSF-SEC-GIT-PROBE on the `run()`/`for-each-ref` path: output past
/// the capture cap fails instead of returning partial refs.
#[cfg(unix)]
#[test]
fn git_refs_envelope_rejects_overcap_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let git = git_fixture(
        dir.path(),
        "git",
        "git version 2.47.1",
        "head -c 9000000 /dev/zero\nexit 0",
    );
    let found = FallbackGit::probe(&git).expect("probe answers --version");
    let err = found
        .refs(&dir.path().join("fake.git"), None)
        .expect_err("9 MiB past the 8 MiB cap must fail, not truncate");
    assert!(err.to_string().contains("exceeded"), "{err}");
}

/// Item 10: a read-only handle is engine-enforced read-only — reads
/// work, raw-handle writes fail in the engine, and writer entry points
/// still refuse up front.
#[test]
fn read_only_handle_is_engine_enforced() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        store.close().await.expect("close");

        let cached = TursoStore::open_read_only(&db)
            .await
            .expect("read-only open");
        assert!(cached.is_read_only());

        let mut rows = cached
            .connection()
            .query("SELECT name FROM meta LIMIT 1", ())
            .await
            .expect("read on a read-only handle");
        assert!(
            rows.next().await.expect("next").is_some(),
            "catalog meta must be readable"
        );

        assert!(
            cached
                .connection()
                .execute("CREATE TABLE sec_git_db_probe (x TEXT)", ())
                .await
                .is_err(),
            "raw-handle writes must fail on a read-only handle"
        );
        assert!(
            cached
                .invalidate_scope("dir:00", 1, now_ms())
                .await
                .is_err(),
            "writer entry points must refuse on a read-only handle"
        );
        cached.close().await.expect("close");
    });
}

/// Item 10: out-of-range scope integers fail instead of wrapping —
/// `u64::MAX` generations never reach the database, and a negative
/// stored revision is rejected on read. The happy path still works.
#[test]
fn conversions_reject_out_of_range() {
    let rt = runtime();
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("payload").join("catalog.db");
        let store = TursoStore::open(&db).await.expect("open");
        let now = now_ms();

        let rev = store
            .invalidate_scope("sec-ok", 1, now)
            .await
            .expect("normal invalidation");
        assert_eq!(rev, 1);

        let err = store
            .invalidate_scope("sec-huge", u64::MAX, now)
            .await
            .expect_err("u64::MAX generation must not wrap into i64");
        assert!(err.to_string().contains("exceeds i64"), "{err}");
        assert_eq!(
            store.scope_rev("sec-huge").await.expect("rev"),
            0,
            "failed invalidation must roll back cleanly"
        );

        store
            .connection()
            .execute(
                "INSERT OR REPLACE INTO scope_revisions (scope_key, rev, updated_at_ms) \
                 VALUES ('sec-neg', -5, 0)",
                (),
            )
            .await
            .expect("seed negative rev");
        let err = store
            .scope_rev("sec-neg")
            .await
            .expect_err("negative stored revision must not wrap into u64");
        assert!(err.to_string().contains("not a valid u64"), "{err}");
        store.close().await.expect("close");
    });
}

/// RSF-SEC-DOCS-PATHS: the hygiene-fixed docs carry no private
/// absolute host paths. (`docs/REMOTE.md` is private-only by design
/// and is intentionally not covered here.)
#[test]
fn docs_have_no_private_absolute_paths() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for file in [
        "docs/TROUBLESHOOTING.md",
        "docs/BENCHMARKS.md",
        "README.md",
        "docs/CHECKLIST.md",
        "docs/GATE_DECISION.md",
    ] {
        let text = std::fs::read_to_string(root.join(file)).expect(file);
        assert!(
            !text.contains("/Users/") && !text.contains("/home/"),
            "{file} must not contain private absolute host paths"
        );
    }
}

/// RSF-SEC-AUDIT-GATE: the gate is enforced via CI — the record must
/// exist, name both tools, and point at the enforcing workflow (no
/// unresolved wiring remains).
#[test]
fn audit_gate_is_documented() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let text =
        std::fs::read_to_string(root.join("docs/AUDIT_GATE.md")).expect("docs/AUDIT_GATE.md");
    assert!(text.contains("cargo audit"), "must name cargo-audit");
    assert!(text.contains("cargo deny"), "must name cargo-deny");
    assert!(
        text.contains("ENFORCED") && text.contains(".github/workflows/audit.yml"),
        "must record the enforcing workflow"
    );
}
