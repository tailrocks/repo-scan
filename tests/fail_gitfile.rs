//! Broken-`.git` visibility regression (gitfile): every parent directory
//! carrying a `.git` child is probed; a validate failure surfaces as an
//! open `probe-failed` gap plus a `probe_failed` candidate — never silent
//! absence. Shape (d), an `X.git` non-git directory, is intentionally NOT
//! probed (structures, not names).
//!
//! End-to-end CLI tests: deterministic tempdir fixtures (0700 dirs, 0600
//! files, `common::fixture` patterns), explicit `--root`/`--state-dir`
//! only, CLI via `env!("CARGO_BIN_EXE_repo-scan")`, `scan --status
//! metadata`. Unix-only (symlink + chmod fixtures).
#![cfg(unix)]

mod common;

use common::fixture;
use repo_scan::report::model::Report;
use repo_scan::report::validate::validate_report;
use repo_scan::store::{Store, TursoStore};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Scan target; canonicalizes to `https://github.com/owner/repo` and matches
/// [`fixture::FIXTURE_REMOTE_URL`] under `github-effective-remotes-v1`.
const TARGET: &str = "https://github.com/OWNER/REPO";

const A_GARBAGE: &str = "gf-a-garbage";
const B_NODIR: &str = "gf-b-nodir";
const C_NONGIT: &str = "gf-c-nongit";
const C_TARGET: &str = "gf-c-target";
const D_PLAIN: &str = "gf-d-plain.git";
const E1_DANGLE: &str = "gf-e1-dangle";
const E2_LINK: &str = "gf-e2-link";
const F_NOPERM: &str = "gf-f-noperm";
const VALID_SRC: &str = "gf-valid-src";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Run the CLI with an explicit state dir from `cwd`.
fn run(args: &[&str], cwd: &Path, state: &Path) -> Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    Command::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

/// Scan exactly `root` into `report` in metadata status mode.
fn scan(root: &Path, state: &Path, report: &Path) -> Output {
    run(
        &[
            "scan",
            TARGET,
            "--root",
            root.to_str().expect("utf8 root"),
            "--report",
            report.to_str().expect("utf8 report"),
            "--status",
            "metadata",
        ],
        root,
        state,
    )
}

fn read_report(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("report is JSON")
}

fn stderr_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Map report path id -> path value (fixtures use UTF-8 paths).
fn path_map(report: &Value) -> HashMap<String, String> {
    report["paths"]
        .as_array()
        .expect("paths array")
        .iter()
        .map(|p| {
            (
                p["id"].as_str().expect("path id").to_string(),
                p["value"].as_str().expect("path value").to_string(),
            )
        })
        .collect()
}

fn path_of<'a>(paths: &'a HashMap<String, String>, id: &Value) -> &'a str {
    paths
        .get(id.as_str().expect("path id ref"))
        .map(String::as_str)
        .expect("path id resolves")
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

/// Compile the shipped Draft 2020-12 schema (local `$ref`s only, no I/O).
fn schema_validator() -> jsonschema::Validator {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/report-v1.1.schema.json"
    );
    let bytes = std::fs::read(path).expect("read shipped schema");
    let schema: Value = serde_json::from_slice(&bytes).expect("schema parses");
    jsonschema::validator_for(&schema).expect("shipped schema compiles")
}

/// Full gate for one emitted report: shipped-schema structure + ID
/// resolution + count agreement + exit consistency.
fn assert_report_conforms(report: &Value, exit_code: i32) {
    let validator = schema_validator();
    let violations: Vec<String> = validator
        .iter_errors(report)
        .map(|e| e.to_string())
        .collect();
    assert!(
        violations.is_empty(),
        "schema violations:\n{}",
        violations.join("\n")
    );
    let typed: Report = serde_json::from_value(report.clone()).expect("report is model");
    validate_report(&typed).expect("IDs resolve, counts agree");
    let state = report["scan"]["state"].as_str().expect("scan.state");
    match exit_code {
        3 => assert_ne!(state, "complete", "exit 3 must not claim complete"),
        other => panic!("unexpected exit code for a usable report: {other}"),
    }
}

/// `coverage.gaps` agrees with the emitted `errors[]` records.
fn assert_coverage_agrees(report: &Value, min_gaps: u64) {
    let gaps = report["coverage"]["gaps"].as_u64().expect("gaps");
    let errors = report["errors"].as_array().expect("errors").len() as u64;
    assert_eq!(gaps, errors, "coverage.gaps agrees with errors[]");
    assert!(gaps >= min_gaps, "gaps {gaps} < floor {min_gaps}");
}

/// Stable probe-gap id for a probed parent (`exec_probe` contract).
fn probe_gap_id(parent: &Path) -> String {
    format!(
        "probe:{}",
        repo_scan::config::encode_hex(&repo_scan::config::path_as_bytes(parent))
    )
}

/// Stable symlink-gap id for an unresolvable link (`enqueue_symlink_target`).
fn symlink_gap_id(link: &Path) -> String {
    format!(
        "symlink:{}",
        repo_scan::config::encode_hex(&repo_scan::config::path_as_bytes(link))
    )
}

/// Candidates whose resolved path contains `needle`.
fn candidates_with<'a>(
    report: &'a Value,
    paths: &HashMap<String, String>,
    needle: &str,
) -> Vec<&'a Value> {
    report["candidates"]
        .as_array()
        .expect("candidates array")
        .iter()
        .filter(|c| path_of(paths, &c["path_id"]).contains(needle))
        .collect()
}

/// Errors whose resolved path or message contains `needle`.
fn errors_with<'a>(
    report: &'a Value,
    paths: &HashMap<String, String>,
    needle: &str,
) -> Vec<&'a Value> {
    report["errors"]
        .as_array()
        .expect("errors array")
        .iter()
        .filter(|e| {
            let at_path = e["path_id"]
                .as_str()
                .and_then(|id| paths.get(id))
                .is_some_and(|p| p.contains(needle));
            let in_message = e["message"].as_str().is_some_and(|m| m.contains(needle));
            at_path || in_message
        })
        .collect()
}

/// Repositories whose git or common path contains `needle`.
fn repos_with<'a>(
    report: &'a Value,
    paths: &HashMap<String, String>,
    needle: &str,
) -> Vec<&'a Value> {
    report["repositories"]
        .as_array()
        .expect("repositories array")
        .iter()
        .filter(|r| {
            path_of(paths, &r["git_path_id"]).contains(needle)
                || path_of(paths, &r["common_path_id"]).contains(needle)
        })
        .collect()
}

/// Checkouts whose root or git path contains `needle`.
fn checkouts_with<'a>(
    report: &'a Value,
    paths: &HashMap<String, String>,
    needle: &str,
) -> Vec<&'a Value> {
    report["checkouts"]
        .as_array()
        .expect("checkouts array")
        .iter()
        .filter(|c| {
            let at_root = c["root_path_id"]
                .as_str()
                .and_then(|id| paths.get(id))
                .is_some_and(|p| p.contains(needle));
            at_root || path_of(paths, &c["git_path_id"]).contains(needle)
        })
        .collect()
}

fn error_by_id<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["errors"]
        .as_array()
        .expect("errors array")
        .iter()
        .find(|e| e["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("no error row {id}"))
}

/// Exactly one `probe_failed` candidate for `needle`, wired to `gap_id`.
fn assert_probe_failed_candidate(
    report: &Value,
    paths: &HashMap<String, String>,
    needle: &str,
    gap_id: &str,
) {
    let found = candidates_with(report, paths, needle);
    assert_eq!(found.len(), 1, "one candidate for {needle}");
    let cand = found[0];
    assert_eq!(cand["disposition"].as_str(), Some("probe_failed"));
    assert!(
        !cand["reason"].as_str().unwrap_or("").is_empty(),
        "nonempty reason for {needle}"
    );
    let error_ids = cand["error_ids"].as_array().expect("error_ids");
    assert_eq!(error_ids.len(), 1, "single gap link for {needle}");
    assert_eq!(error_ids[0].as_str(), Some(gap_id));
    let err = error_by_id(report, gap_id);
    assert_eq!(err["category"].as_str(), Some("probe-failed"));
}

/// A checkout rooted at `needle` exists and names a live repository row.
fn assert_repository_present(report: &Value, paths: &HashMap<String, String>, needle: &str) {
    let found = checkouts_with(report, paths, needle);
    assert!(!found.is_empty(), "checkout rooted at {needle}");
    let ids: HashSet<&str> = report["repositories"]
        .as_array()
        .expect("repositories array")
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    for checkout in &found {
        let repo = checkout["repository_id"].as_str().expect("repository_id");
        assert!(ids.contains(repo), "checkout names live repository {repo}");
    }
}

/// Full broken-gitfile layout under one private root.
struct GitfileLayout {
    #[allow(dead_code)]
    scratch: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
    report: PathBuf,
    a: PathBuf,
    b: PathBuf,
    c: PathBuf,
    d: PathBuf,
    e1: PathBuf,
    e2: PathBuf,
    f: PathBuf,
    /// True when the chmod-000 `.git` file still reads (euid 0).
    f_git_readable: bool,
}

fn write_gitfile(dir: &Path, contents: &[u8]) {
    repo_scan::privacy::private_dir_0700(dir).expect("mkdir");
    repo_scan::privacy::private_write_0600(&dir.join(".git"), contents).expect("write");
}

/// Build subdirs (a) garbage file, (b) missing-target pointer, (c)
/// non-git-target pointer, (d) `X.git` junk dir, (e1) dangling symlink,
/// (e2) valid symlink, (f) unreadable valid pointer, plus a valid clone.
fn build_layout() -> GitfileLayout {
    let scratch = fixture::scratch_root("gitfile-");
    let root = scratch.path().join("ws");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let valid = fixture::normal_clone(&root, VALID_SRC);

    let a = root.join(A_GARBAGE);
    write_gitfile(&a, b"not-a-pointer\n");

    let b = root.join(B_NODIR);
    write_gitfile(&b, b"gitdir: ../no-such-dir\n");

    let c = root.join(C_NONGIT);
    write_gitfile(&c, format!("gitdir: ../{C_TARGET}\n").as_bytes());
    let c_target = root.join(C_TARGET);
    repo_scan::privacy::private_dir_0700(&c_target).expect("mkdir");
    repo_scan::privacy::private_write_0600(&c_target.join("notes.txt"), b"not a repo\n")
        .expect("write");

    let d = root.join(D_PLAIN);
    repo_scan::privacy::private_dir_0700(&d).expect("mkdir");
    repo_scan::privacy::private_write_0600(&d.join("junk.txt"), b"junk\n").expect("write");

    let e1 = root.join(E1_DANGLE);
    repo_scan::privacy::private_dir_0700(&e1).expect("mkdir");
    std::os::unix::fs::symlink("no-such-target", e1.join(".git")).expect("symlink");

    let e2 = root.join(E2_LINK);
    repo_scan::privacy::private_dir_0700(&e2).expect("mkdir");
    std::os::unix::fs::symlink(valid.join(".git"), e2.join(".git")).expect("symlink");

    let f = root.join(F_NOPERM);
    write_gitfile(
        &f,
        format!("gitdir: {}\n", valid.join(".git").display()).as_bytes(),
    );
    std::fs::set_permissions(f.join(".git"), std::fs::Permissions::from_mode(0o000))
        .expect("chmod");
    let f_git_readable = std::fs::read(f.join(".git")).is_ok();

    let state = scratch.path().join("state");
    let report = scratch.path().join("rep.json");
    GitfileLayout {
        scratch,
        root,
        state,
        report,
        a,
        b,
        c,
        d,
        e1,
        e2,
        f,
        f_git_readable,
    }
}

/// Scan the layout; broken pointers force exit 3. Returns the report JSON.
fn scan_layout(layout: &GitfileLayout) -> Value {
    let out = scan(&layout.root, &layout.state, &layout.report);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let report = read_report(&layout.report);
    assert_report_conforms(&report, 3);
    report
}

fn catalog_db(layout: &GitfileLayout) -> PathBuf {
    layout.state.join("payload").join("catalog.db")
}

/// The catalog holds an open `probe-failed` gap for `parent`. Returns it.
async fn assert_open_probe_failed(store: &TursoStore, parent: &Path) -> String {
    let gap_id = probe_gap_id(parent);
    let row = store
        .get_error(&gap_id)
        .await
        .expect("get")
        .unwrap_or_else(|| panic!("missing gap {gap_id} for {}", parent.display()));
    assert!(row.open, "gap {gap_id} stays open");
    assert_eq!(row.category, "probe-failed");
    assert_eq!(row.scope_key, repo_scan::config::scope_key_for_git(parent));
    assert!(!row.detail.is_empty(), "gap {gap_id} keeps detail");
    gap_id
}

async fn assert_no_probe_gap(store: &TursoStore, parent: &Path) {
    let gap_id = probe_gap_id(parent);
    assert!(
        store.get_error(&gap_id).await.expect("get").is_none(),
        "no probe gap for {}",
        parent.display()
    );
}

/// Garbage, missing-target, and non-git-target pointers each keep an open
/// catalog gap and a wired `probe_failed` candidate; gaps agree.
#[test]
fn gitfile_broken_pointers_surface_as_probe_failed() {
    let layout = build_layout();
    let report = scan_layout(&layout);
    let paths = path_map(&report);
    assert_coverage_agrees(&report, 5);
    let db = catalog_db(&layout);
    let (gap_a, gap_b, gap_c) = runtime().block_on(async {
        let store = TursoStore::open(&db).await.expect("open");
        let out = (
            assert_open_probe_failed(&store, &layout.a).await,
            assert_open_probe_failed(&store, &layout.b).await,
            assert_open_probe_failed(&store, &layout.c).await,
        );
        store.close().await.expect("close");
        out
    });
    assert_probe_failed_candidate(&report, &paths, A_GARBAGE, &gap_a);
    assert_probe_failed_candidate(&report, &paths, B_NODIR, &gap_b);
    assert_probe_failed_candidate(&report, &paths, C_NONGIT, &gap_c);
}

/// A dangling `.git` symlink fails the parent probe AND records the link
/// gap: both rows stay visible.
#[test]
fn gitfile_dangling_symlink_reports_probe_and_link_gaps() {
    let layout = build_layout();
    let report = scan_layout(&layout);
    let paths = path_map(&report);
    assert_coverage_agrees(&report, 5);
    let link = layout.e1.join(".git");
    let db = catalog_db(&layout);
    let (gap_e1, link_gap) = runtime().block_on(async {
        let store = TursoStore::open(&db).await.expect("open");
        let gap_e1 = assert_open_probe_failed(&store, &layout.e1).await;
        let link_gap = symlink_gap_id(&link);
        let row = store
            .get_error(&link_gap)
            .await
            .expect("get")
            .unwrap_or_else(|| panic!("missing link gap {link_gap}"));
        assert!(row.open, "link gap {link_gap} stays open");
        assert_eq!(row.category, "symlink-unresolvable");
        assert_eq!(row.scope_key, repo_scan::config::scope_key_for_dir(&link));
        store.close().await.expect("close");
        (gap_e1, link_gap)
    });
    assert_probe_failed_candidate(&report, &paths, E1_DANGLE, &gap_e1);
    let err = error_by_id(&report, &link_gap);
    assert_eq!(err["category"].as_str(), Some("symlink-unresolvable"));
}

/// A `.git` symlink into a valid git dir validates: repository row, no
/// candidate, no probe gap.
#[test]
fn gitfile_valid_symlink_is_repository_not_candidate() {
    let layout = build_layout();
    let report = scan_layout(&layout);
    let paths = path_map(&report);
    let db = catalog_db(&layout);
    runtime().block_on(async {
        let store = TursoStore::open(&db).await.expect("open");
        assert_no_probe_gap(&store, &layout.e2).await;
        store.close().await.expect("close");
    });
    assert_repository_present(&report, &paths, E2_LINK);
    assert!(
        candidates_with(&report, &paths, E2_LINK).is_empty(),
        "no candidate for a valid symlinked .git"
    );
    assert!(
        errors_with(&report, &paths, E2_LINK).is_empty(),
        "no error rows for a valid symlinked .git"
    );
}

/// An `X.git` non-git directory is not probed: no candidate, error, or
/// repository/checkout rows, and no catalog gap.
#[test]
fn gitfile_git_suffixed_dir_is_not_probed() {
    let layout = build_layout();
    let report = scan_layout(&layout);
    let paths = path_map(&report);
    let db = catalog_db(&layout);
    runtime().block_on(async {
        let store = TursoStore::open(&db).await.expect("open");
        assert_no_probe_gap(&store, &layout.d).await;
        store.close().await.expect("close");
    });
    assert!(
        candidates_with(&report, &paths, D_PLAIN).is_empty(),
        "plain.git dir is not a candidate"
    );
    assert!(
        errors_with(&report, &paths, D_PLAIN).is_empty(),
        "plain.git dir keeps no error rows"
    );
    assert!(
        repos_with(&report, &paths, D_PLAIN).is_empty(),
        "plain.git dir keeps no repository rows"
    );
    assert!(
        checkouts_with(&report, &paths, D_PLAIN).is_empty(),
        "plain.git dir keeps no checkout rows"
    );
}

/// A chmod-000 pointer fails closed for unprivileged readers; a reader
/// that still sees through (euid 0) validates it as a repository.
#[test]
fn gitfile_unreadable_pointer_fails_closed() {
    let layout = build_layout();
    let report = scan_layout(&layout);
    let paths = path_map(&report);
    if layout.f_git_readable {
        let db = catalog_db(&layout);
        runtime().block_on(async {
            let store = TursoStore::open(&db).await.expect("open");
            assert_no_probe_gap(&store, &layout.f).await;
            store.close().await.expect("close");
        });
        assert_repository_present(&report, &paths, F_NOPERM);
        assert!(
            candidates_with(&report, &paths, F_NOPERM).is_empty(),
            "readable valid pointer keeps no candidate"
        );
    } else {
        let db = catalog_db(&layout);
        let gap_f = runtime().block_on(async {
            let store = TursoStore::open(&db).await.expect("open");
            let gap = assert_open_probe_failed(&store, &layout.f).await;
            store.close().await.expect("close");
            gap
        });
        assert_probe_failed_candidate(&report, &paths, F_NOPERM, &gap_f);
    }
}
