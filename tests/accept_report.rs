//! Report acceptance (REPORT-01, REPORT-02): every CLI-emitted report
//! structurally matches `schemas/report-v1.4.schema.json`, and publication is
//! atomic with honest retry semantics.
//!
//! REPORT-01: scan real tempdir fixtures through the built binary with
//! explicit `--root`/`--state-dir` only (never whole-machine scans), then
//! check the emitted JSON against the shipped schema (required fields,
//! no undeclared fields, enum/const domains), resolve IDs and count
//! agreement via [`validate_report`], and tie exit status to report state.
//!
//! REPORT-02: atomic old-or-new publication, no-clobber refusals, stalled
//! publication pinning no database reader, failed-publication retry from
//! the saved snapshot, and honest inside-tree artifacts.

mod common;

use common::fixture;
use repo_scan::report::publish::{check_destination, publish_staged, DestinationKind};
use repo_scan::report::validate::validate_report;
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

const URL: &str = "https://github.com/OWNER/REPO";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

/// Run the binary with `--state-dir <state>` from `cwd`.
fn run(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    ProcCommand::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

fn stdout_line(output: &std::process::Output, key: &str) -> String {
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(&format!("{key}:")) {
            return value.trim().to_string();
        }
    }
    panic!("missing `{key}:` in stdout:\n{text}");
}

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn git_available() -> bool {
    ProcCommand::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn load_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn schema_doc() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/report-v1.4.schema.json"
    );
    load_json(Path::new(path))
}

// ---------------------------------------------------------------------------
// REPORT-01: structural match against the shipped schema
// ---------------------------------------------------------------------------

/// Minimal JSON-Schema evaluator over the constructs the shipped
/// `report-v1.4.schema.json` uses: `$ref`, `type` (incl. unions), `const`,
/// `enum`, `required`, `properties`, `additionalProperties: false`,
/// `items`, `anyOf`, `allOf`, `if`/`then`, `minLength`/`maxLength`,
/// `minimum`/`exclusiveMinimum`. `pattern`/`format` need a regex engine
/// (no such dependency is allowed here), so `ObjectId.hex` shape and
/// RFC 3339 shape are asserted explicitly in Rust below instead.
fn validate_against(
    doc: &serde_json::Value,
    schema: &serde_json::Value,
    value: &serde_json::Value,
    ctx: &str,
    errors: &mut Vec<String>,
) {
    if let Some(reference) = schema.get("$ref").and_then(|r| r.as_str()) {
        let target = resolve_ref(doc, reference, ctx, errors);
        if let Some(target) = target.cloned() {
            validate_against(doc, &target, value, ctx, errors);
        }
    }
    if let Some(expected) = schema.get("const") {
        if value != expected {
            errors.push(format!("{ctx}: want const {expected}, got {value}"));
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(|e| e.as_array()) {
        if !allowed.iter().any(|a| a == value) {
            errors.push(format!("{ctx}: {value} not in enum {allowed:?}"));
        }
    }
    if let Some(types) = schema.get("type") {
        let names: Vec<&str> = match types {
            serde_json::Value::String(one) => vec![one.as_str()],
            serde_json::Value::Array(many) => many.iter().filter_map(|t| t.as_str()).collect(),
            _ => Vec::new(),
        };
        if !names.iter().any(|t| type_matches(t, value)) {
            errors.push(format!("{ctx}: {value} does not match type {types}"));
            return;
        }
    }
    if let Some(s) = value.as_str() {
        if let Some(min) = schema.get("minLength").and_then(|v| v.as_u64()) {
            if (s.len() as u64) < min {
                errors.push(format!("{ctx}: string shorter than {min}"));
            }
        }
        if let Some(max) = schema.get("maxLength").and_then(|v| v.as_u64()) {
            if (s.len() as u64) > max {
                errors.push(format!("{ctx}: string longer than {max}"));
            }
        }
    }
    if let Some(n) = value.as_f64() {
        if let Some(min) = schema.get("minimum").and_then(|v| v.as_f64()) {
            if n < min {
                errors.push(format!("{ctx}: {n} below minimum {min}"));
            }
        }
        if let Some(min) = schema.get("exclusiveMinimum").and_then(|v| v.as_f64()) {
            if n <= min {
                errors.push(format!("{ctx}: {n} not above exclusive minimum {min}"));
            }
        }
    }
    if let Some(items) = schema.get("items") {
        if let Some(array) = value.as_array() {
            for (i, item) in array.iter().enumerate() {
                validate_against(doc, items, item, &format!("{ctx}[{i}]"), errors);
            }
        }
    }
    if value.is_object() {
        if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
            for key in required.iter().filter_map(|k| k.as_str()) {
                if value.get(key).is_none() {
                    errors.push(format!("{ctx}: missing required field {key:?}"));
                }
            }
        }
        let properties = schema.get("properties").and_then(|p| p.as_object());
        if schema.get("additionalProperties") == Some(&serde_json::Value::Bool(false)) {
            if let Some(object) = value.as_object() {
                for key in object.keys() {
                    let declared = properties.map(|p| p.contains_key(key)).unwrap_or(false);
                    if !declared {
                        errors.push(format!("{ctx}: undeclared field {key:?}"));
                    }
                }
            }
        }
        if let Some(props) = properties {
            if let Some(object) = value.as_object() {
                for (key, prop) in props {
                    if let Some(field) = object.get(key) {
                        validate_against(doc, prop, field, &format!("{ctx}.{key}"), errors);
                    }
                }
            }
        }
    }
    if let Some(any) = schema.get("anyOf").and_then(|a| a.as_array()) {
        let ok = any.iter().any(|branch| {
            let mut probe = Vec::new();
            validate_against(doc, branch, value, ctx, &mut probe);
            probe.is_empty()
        });
        if !ok {
            errors.push(format!("{ctx}: matches no anyOf branch"));
        }
    }
    if let Some(all) = schema.get("allOf").and_then(|a| a.as_array()) {
        for (i, branch) in all.iter().enumerate() {
            validate_against(doc, branch, value, &format!("{ctx}#all{i}"), errors);
        }
    }
    if let Some(if_schema) = schema.get("if") {
        let mut probe = Vec::new();
        validate_against(doc, if_schema, value, ctx, &mut probe);
        if probe.is_empty() {
            if let Some(then) = schema.get("then") {
                validate_against(doc, then, value, ctx, errors);
            }
        }
    }
}

fn type_matches(name: &str, value: &serde_json::Value) -> bool {
    match name {
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        _ => false,
    }
}

fn resolve_ref<'a>(
    doc: &'a serde_json::Value,
    reference: &str,
    ctx: &str,
    errors: &mut Vec<String>,
) -> Option<&'a serde_json::Value> {
    let path = reference
        .strip_prefix("#/")?
        .replace("~1", "/")
        .replace("~0", "~");
    let mut node = doc;
    for part in path.split('/') {
        node = node.get(part)?;
    }
    if node.is_null() {
        errors.push(format!("{ctx}: dangling $ref {reference}"));
        return None;
    }
    Some(node)
}

/// Lowercase-hex, nonempty, even length (the schema `pattern` for
/// `ObjectId.hex`, checked here without a regex engine).
fn assert_oid_hex(hex: &str, ctx: &str) {
    assert!(!hex.is_empty(), "{ctx}: empty oid hex");
    assert_eq!(hex.len() % 2, 0, "{ctx}: odd hex length {hex:?}");
    assert!(
        hex.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "{ctx}: non-lowercase-hex oid {hex:?}"
    );
}

fn assert_oid_object(value: &serde_json::Value, ctx: &str) {
    let algorithm = value
        .get("algorithm")
        .and_then(|a| a.as_str())
        .unwrap_or("");
    let hex = value.get("hex").and_then(|h| h.as_str()).unwrap_or("");
    assert_oid_hex(hex, ctx);
    match algorithm {
        "sha1" => assert_eq!(hex.len(), 40, "{ctx}: sha1 length"),
        "sha256" => assert_eq!(hex.len(), 64, "{ctx}: sha256 length"),
        other => assert!(!other.is_empty(), "{ctx}: empty oid algorithm"),
    }
}

/// Strict-enough RFC 3339 UTC shape for emitted reports: date, `T`,
/// time, and a `Z` suffix (the producer renders UTC with `Z`).
fn is_report_time(s: &str) -> bool {
    s.len() >= 20 && s.as_bytes()[10] == b'T' && s.ends_with('Z')
}

fn assert_time_shape(value: &serde_json::Value, ctx: &str) {
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::String(s) => assert!(is_report_time(s), "{ctx}: not RFC 3339 {s:?}"),
        other => panic!("{ctx}: not a time or null: {other}"),
    }
}

/// Walk every `ObjectId` and time field the schema declares and apply the
/// checks the generic engine cannot (`pattern`, `format`).
fn assert_schema_string_shapes(report: &serde_json::Value) {
    assert_time_shape(&report["created_at"], "created_at");
    assert_time_shape(&report["scan"]["started_at"], "scan.started_at");
    assert_time_shape(&report["scan"]["finished_at"], "scan.finished_at");
    for (i, v) in report["volumes"]
        .as_array()
        .expect("volumes")
        .iter()
        .enumerate()
    {
        assert_time_shape(&v["observed_at"], &format!("volumes[{i}].observed_at"));
    }
    for (i, r) in report["roots"]
        .as_array()
        .expect("roots")
        .iter()
        .enumerate()
    {
        assert_time_shape(&r["observed_at"], &format!("roots[{i}].observed_at"));
    }
    for (i, r) in report["repositories"]
        .as_array()
        .expect("repositories")
        .iter()
        .enumerate()
    {
        assert_time_shape(&r["observed_at"], &format!("repositories[{i}].observed_at"));
    }
    for (i, c) in report["checkouts"]
        .as_array()
        .expect("checkouts")
        .iter()
        .enumerate()
    {
        assert_time_shape(&c["observed_at"], &format!("checkouts[{i}].observed_at"));
        if !c["head"]["oid"].is_null() {
            assert_oid_object(&c["head"]["oid"], &format!("checkouts[{i}].head.oid"));
        }
        assert_time_shape(
            &c["status"]["started_at"],
            &format!("checkouts[{i}].status.started_at"),
        );
        assert_time_shape(
            &c["status"]["finished_at"],
            &format!("checkouts[{i}].status.finished_at"),
        );
    }
    for (i, b) in report["branches"]
        .as_array()
        .expect("branches")
        .iter()
        .enumerate()
    {
        assert_time_shape(&b["observed_at"], &format!("branches[{i}].observed_at"));
        if !b["oid"].is_null() {
            assert_oid_object(&b["oid"], &format!("branches[{i}].oid"));
        }
    }
    for (i, r) in report["remotes"]
        .as_array()
        .expect("remotes")
        .iter()
        .enumerate()
    {
        assert_time_shape(&r["observed_at"], &format!("remotes[{i}].observed_at"));
    }
    for (i, a) in report["aliases"]
        .as_array()
        .expect("aliases")
        .iter()
        .enumerate()
    {
        assert_time_shape(&a["verified_at"], &format!("aliases[{i}].verified_at"));
    }
    for (i, c) in report["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .enumerate()
    {
        assert_time_shape(&c["retry_after"], &format!("candidates[{i}].retry_after"));
    }
    for (i, e) in report["errors"]
        .as_array()
        .expect("errors")
        .iter()
        .enumerate()
    {
        assert_time_shape(&e["first_seen"], &format!("errors[{i}].first_seen"));
        assert_time_shape(&e["last_seen"], &format!("errors[{i}].last_seen"));
        assert_time_shape(&e["next_retry"], &format!("errors[{i}].next_retry"));
    }
}

/// Full REPORT-01 gate for one emitted report: shipped-schema structure +
/// string shapes + ID resolution + count agreement + exit consistency.
fn assert_report_conforms(report: &serde_json::Value, exit_code: i32) {
    let doc = schema_doc();
    assert_eq!(
        doc["$schema"].as_str(),
        Some("https://json-schema.org/draft/2020-12/schema")
    );
    let mut errors = Vec::new();
    validate_against(&doc, &doc, report, "$", &mut errors);
    assert!(
        errors.is_empty(),
        "schema violations:\n{}",
        errors.join("\n")
    );
    assert_schema_string_shapes(report);

    let typed: repo_scan::report::model::Report =
        serde_json::from_value(report.clone()).expect("report deserializes to model");
    validate_report(&typed).expect("IDs resolve, counts agree");

    // Exit status consistent with report state (spec §3 exit table).
    let state = report["scan"]["state"].as_str().expect("scan.state");
    let filesystem = report["coverage"]["filesystem"]
        .as_str()
        .expect("coverage.filesystem");
    let gaps = report["coverage"]["gaps"].as_u64().expect("coverage.gaps");
    let pending = report["coverage"]["tasks_pending"]
        .as_u64()
        .expect("tasks_pending");
    match exit_code {
        0 => {
            assert_eq!(state, "complete", "exit 0 requires scan.state complete");
            assert_eq!(
                filesystem, "complete",
                "exit 0 requires filesystem complete"
            );
            assert_eq!(gaps, 0, "exit 0 requires zero gaps");
            assert_eq!(pending, 0, "exit 0 requires zero pending tasks");
        }
        3 => {
            assert_ne!(state, "complete", "exit 3 must not claim complete");
        }
        other => panic!("unexpected exit code for a usable report: {other}"),
    }
}

#[test]
fn report_01_emitted_report_matches_shipped_schema() {
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    fixture::bare_store(&root, "store.backup");
    repo_scan::privacy::private_write_0600(&root.join("notes.txt"), "unrelated\n".as_bytes())
        .expect("write");
    let root_str = root.to_str().expect("utf8").to_string();

    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "report.json",
        ],
        dir.path(),
        &state,
    );
    // The remote-less bare store is terminally ambiguous (spec §8,
    // GIT-04), so the usable report exits 3 with identity unproven.
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr_text(&out));
    let report = load_json(&dir.path().join("report.json"));
    assert_report_conforms(&report, 3);
    assert_eq!(
        report["coverage"]["identity"].as_str(),
        Some("unproven"),
        "bare store keeps identity unproven"
    );

    // Meaningful content, not just shape: both layouts discovered.
    assert_eq!(report["scan"]["scope"].as_str(), Some("roots"));
    let repos = report["repositories"].as_array().expect("repositories");
    assert!(
        repos
            .iter()
            .any(|r| r["match"].as_str() == Some("confirmed")),
        "normal clone confirmed: {report}"
    );
    // The remote-less bare store is represented either as a repository
    // (bare) or as an unresolved candidate; either way it is not lost.
    let bare_repos = repos
        .iter()
        .filter(|r| r["bare"] == serde_json::Value::Bool(true))
        .count();
    let candidates = report["candidates"].as_array().expect("candidates").len();
    assert!(
        bare_repos + candidates >= 1,
        "bare store represented: {report}"
    );
    assert!(
        !report["checkouts"]
            .as_array()
            .expect("checkouts")
            .is_empty(),
        "normal clone has a checkout"
    );
    assert!(
        !report["branches"].as_array().expect("branches").is_empty(),
        "main branch observed"
    );
}

#[test]
fn report_01_metadata_and_full_modes_validate() {
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    let root_str = root.to_str().expect("utf8").to_string();

    for (mode, units) in [("metadata", "not_requested"), ("full", "files")] {
        let name = format!("report-{mode}.json");
        let out = run(
            &[
                "scan",
                URL,
                "--root",
                root_str.as_str(),
                "--report",
                name.as_str(),
                "--status",
                mode,
            ],
            dir.path(),
            &state,
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "mode {mode}: {}",
            stderr_text(&out)
        );
        let report = load_json(&dir.path().join(&name));
        assert_report_conforms(&report, 0);
        assert_eq!(report["scan"]["status_mode"].as_str(), Some(mode));
        for checkout in report["checkouts"].as_array().expect("checkouts") {
            assert_eq!(checkout["status"]["mode"].as_str(), Some(mode));
            assert_eq!(checkout["status"]["untracked_units"].as_str(), Some(units));
            if mode == "metadata" {
                assert!(checkout["status"]["staged"].is_null());
                assert!(checkout["status"]["unstaged"].is_null());
                assert!(checkout["status"]["untracked"].is_null());
            }
        }
    }
}

#[test]
fn report_01_shipped_example_validates() {
    let bytes = include_bytes!("data/example-report.json");
    let report: serde_json::Value = serde_json::from_slice(bytes).expect("example parses");
    // The example is illustrative, not a live scan: schema + IDs + counts
    // must hold; exit consistency is checked with its recorded state.
    let doc = schema_doc();
    let mut errors = Vec::new();
    validate_against(&doc, &doc, &report, "$", &mut errors);
    assert!(
        errors.is_empty(),
        "schema violations:\n{}",
        errors.join("\n")
    );
    assert_schema_string_shapes(&report);
    let typed: repo_scan::report::model::Report =
        serde_json::from_value(report.clone()).expect("example deserializes");
    validate_report(&typed).expect("example IDs resolve, counts agree");
}

// ---------------------------------------------------------------------------
// REPORT-02: atomic publish, no-clobber, retry, honesty
// ---------------------------------------------------------------------------

/// Minimal verified prior report: schema marker + tool name + report ID.
/// A filename extension alone is never proof (checked by the negative cases).
fn prior_report_bytes(report_id: &str) -> Vec<u8> {
    serde_json::json!({
        "schema_version": repo_scan::report::model::SCHEMA_VERSION,
        "report_id": report_id,
        "tool": {"name": "repo-scan", "version": "0.1.0", "source_commit": null},
    })
    .to_string()
    .into_bytes()
}

fn sibling_leftovers(parent: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') && name.contains(".tmp") {
                out.push(entry.path());
            }
        }
    }
    out
}

#[test]
fn report_02_publish_is_atomic_old_or_new_never_partial() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    repo_scan::privacy::private_dir_0700(&state).expect("mkdir");
    let dest = dir.path().join("report.json");
    let staged = dir.path().join("staged.json");

    // Fresh destination: published bytes equal staged bytes exactly.
    let new_bytes = prior_report_bytes("report-new");
    repo_scan::privacy::private_write_0600(&staged, &new_bytes).expect("write staged");
    assert_eq!(
        check_destination(&dest, &state).expect("check missing"),
        DestinationKind::Missing
    );
    let receipt = publish_staged(&staged, &dest, &state).expect("publish");
    assert_eq!(receipt.bytes, new_bytes.len() as u64);
    assert_eq!(std::fs::read(&dest).expect("read"), new_bytes);
    assert!(
        sibling_leftovers(dir.path()).is_empty(),
        "no sibling left behind"
    );

    // Crash simulation: a partial temporary sibling beside the destination
    // never affects readers of the destination itself (old-or-new).
    let sibling = dir.path().join(".report.json.tmp-1-1-1");
    repo_scan::privacy::private_write_0600(&sibling, &new_bytes[..new_bytes.len() / 2])
        .expect("partial sibling");
    assert_eq!(std::fs::read(&dest).expect("read"), new_bytes);
    std::fs::remove_file(&sibling).expect("cleanup sibling");

    // Replacement of a verified prior report: new bytes land whole.
    let old_bytes = std::fs::read(&dest).expect("read old");
    let newer_bytes = prior_report_bytes("report-newer");
    repo_scan::privacy::private_write_0600(&staged, &newer_bytes).expect("write staged");
    assert_eq!(
        check_destination(&dest, &state).expect("check prior"),
        DestinationKind::VerifiedPriorReport
    );
    let receipt = publish_staged(&staged, &dest, &state).expect("republish");
    assert_eq!(receipt.replaced, DestinationKind::VerifiedPriorReport);
    let observed = std::fs::read(&dest).expect("read");
    assert!(
        observed == newer_bytes || observed == old_bytes,
        "reader sees old-or-new, never a mix"
    );
    assert_eq!(observed, newer_bytes);
    assert!(
        sibling_leftovers(dir.path()).is_empty(),
        "no sibling left behind"
    );

    // Failed publication (unrelated file appears) keeps old bytes and
    // leaves no sibling.
    repo_scan::privacy::private_write_0600(&dest, b"user data, not a report").expect("overwrite");
    repo_scan::privacy::private_write_0600(&staged, &new_bytes).expect("write staged");
    assert!(check_destination(&dest, &state).is_err());
    assert!(publish_staged(&staged, &dest, &state).is_err());
    assert_eq!(
        std::fs::read(&dest).expect("read"),
        b"user data, not a report"
    );
    assert!(
        sibling_leftovers(dir.path()).is_empty(),
        "no sibling left behind"
    );
}

#[test]
fn report_02_stalled_publish_does_not_pin_reader() {
    // Static barrier: staging completes and snapshot bytes are retained
    // before external publication, and publication itself takes no
    // database handle — it runs here with no store open at all.
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    let root_str = root.to_str().expect("utf8").to_string();

    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "report.json",
            "--format",
            "human",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let snapshot = PathBuf::from(stdout_line(&out, "snapshot"));
    assert!(snapshot.is_file(), "staged snapshot retained: {snapshot:?}");
    let snapshot_bytes = std::fs::read(&snapshot).expect("read snapshot");
    let report_bytes = std::fs::read(dir.path().join("report.json")).expect("read report");
    assert_eq!(
        snapshot_bytes, report_bytes,
        "published bytes equal staged bytes"
    );

    // No store handle exists in this process; publication is pure file
    // work over retained bytes (a stalled destination cannot pin a reader
    // it never holds).
    let second = dir.path().join("report-copy.json");
    let receipt = publish_staged(&snapshot, &second, &state).expect("publish retained");
    assert_eq!(receipt.bytes, snapshot_bytes.len() as u64);
    assert_eq!(std::fs::read(&second).expect("read"), snapshot_bytes);
    let report = load_json(&second);
    assert_report_conforms(&report, 0);
}

#[test]
fn report_02_failed_publish_retries_from_snapshot() {
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    let root_str = root.to_str().expect("utf8").to_string();

    // Block publication with an unrelated file: scan discovers fine but
    // publication fails (exit 1) while the snapshot is retained.
    let dest = dir.path().join("blocked.json");
    repo_scan::privacy::private_write_0600(&dest, "precious user bytes".as_bytes())
        .expect("write blocker");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "blocked.json",
            "--format",
            "human",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert_eq!(std::fs::read(&dest).expect("read"), b"precious user bytes");
    let scan_id = stdout_line(&out, "scan_id");
    let snapshot = PathBuf::from(stdout_line(&out, "snapshot"));
    assert!(snapshot.is_file(), "snapshot retained after failed publish");
    let snapshot_bytes = std::fs::read(&snapshot).expect("read snapshot");

    // Remove the blocker; resume retries from the saved snapshot without
    // repeating discovery.
    std::fs::remove_file(&dest).expect("unblock");
    // Wave6: explicit human keeps the footer lines (the redirected
    // default is now the JSONL journal replay).
    let out = run(
        &["resume", scan_id.as_str(), "--format", "human"],
        dir.path(),
        &state,
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout} stderr: {}",
        stderr_text(&out)
    );
    assert!(stdout.contains("no new scan"), "{stdout}");
    assert_eq!(stdout_line(&out, "scan_id"), scan_id);
    assert_eq!(std::fs::read(&dest).expect("read"), snapshot_bytes);
    let report = load_json(&dest);
    assert_report_conforms(&report, 0);
}

#[test]
fn report_02_inside_tree_report_is_honest() {
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    let root_str = root.to_str().expect("utf8").to_string();
    let inside = root.join("scan-report.json");

    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            inside.to_str().expect("utf8"),
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = load_json(&inside);
    assert_report_conforms(&report, 0);

    // The report artifact inside scanned scope is identified, recorded as
    // created after status observation, and resolves to a real path.
    let artifacts = report["generated_artifacts"].as_array().expect("artifacts");
    let found = artifacts.iter().any(|a| {
        a["kind"].as_str() == Some("report")
            && a["created_after_status"] == serde_json::Value::Bool(true)
    });
    assert!(found, "inside-tree report artifact recorded: {report}");
    let paths = report["paths"].as_array().expect("paths");
    for artifact in artifacts {
        let id = artifact["path_id"].as_str().expect("path_id");
        assert!(
            paths.iter().any(|p| p["id"].as_str() == Some(id)),
            "artifact path resolves"
        );
    }
}

#[test]
fn report_02_unrelated_files_never_overwritten() {
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    let repo = fixture::normal_clone(&root, "repo");
    let root_str = root.to_str().expect("utf8").to_string();

    // Case 1: existing unrelated file is refused; bytes and snapshot kept.
    let state = dir.path().join("state-1");
    let dest = dir.path().join("user.json");
    repo_scan::privacy::private_write_0600(&dest, "{\"user\": true}".as_bytes()).expect("write");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "user.json",
            "--format",
            "human",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert_eq!(std::fs::read(&dest).expect("read"), b"{\"user\": true}");
    assert!(PathBuf::from(stdout_line(&out, "snapshot")).is_file());

    // Case 2: Git administrative path is refused.
    let state = dir.path().join("state-2");
    let git_dest = repo.join(".git").join("report.json");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            git_dest.to_str().expect("utf8"),
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert!(!git_dest.exists());

    // Case 3: destination inside tool state is refused.
    let state = dir.path().join("state-3");
    let state_dest = state.join("report.json");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            state_dest.to_str().expect("utf8"),
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
}

#[cfg(unix)]
#[test]
fn report_02_symlink_destination_is_refused() {
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    let root_str = root.to_str().expect("utf8").to_string();

    let target = dir.path().join("target.txt");
    repo_scan::privacy::private_write_0600(&target, "do not touch".as_bytes()).expect("write");
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "link.json",
            "--format",
            "human",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    assert_eq!(std::fs::read(&target).expect("read"), b"do not touch");
    assert!(PathBuf::from(stdout_line(&out, "snapshot")).is_file());
}

#[test]
fn report_01_live_report_validates_against_real_json_schema() {
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    let root_str = root.to_str().expect("utf8").to_string();

    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "report.json",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = load_json(&dir.path().join("report.json"));

    let schema = schema_doc();
    let validator = jsonschema::validator_for(&schema).expect("shipped schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(&report)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "live report schema violations:\n{}",
        errors.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Step 4: reports record the effective worker limits of the invocation
// ---------------------------------------------------------------------------

/// `scan --workers 4` reports `resources.cpu_target_cores == 4.0`, and a
/// default invocation reports `effective_workers(None)` — never the
/// hardcoded 1.0 legacy value. The RSS target stays the §5 table budget.
#[test]
fn report_resources_record_effective_worker_limits() {
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    fixture::normal_clone(&root, "repo");
    let root_str = root.to_str().expect("utf8").to_string();

    // Explicit `--workers 4`.
    let state = dir.path().join("state-4");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "report-4.json",
            "--workers",
            "4",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = load_json(&dir.path().join("report-4.json"));
    assert_report_conforms(&report, 0);
    assert_eq!(
        report["resources"]["cpu_target_cores"].as_f64(),
        Some(4.0),
        "--workers 4 must surface in resources: {report}"
    );
    assert_eq!(
        report["resources"]["profile"].as_str(),
        Some("conservative")
    );
    assert_eq!(
        report["resources"]["rss_target_bytes"].as_u64(),
        Some(256 * 1024 * 1024),
        "rss target stays the §5 table budget: {report}"
    );

    // Default invocation: platform parallelism, clamped to MAX_WORKERS.
    let state = dir.path().join("state-default");
    let out = run(
        &[
            "scan",
            URL,
            "--root",
            root_str.as_str(),
            "--report",
            "report-default.json",
        ],
        dir.path(),
        &state,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let report = load_json(&dir.path().join("report-default.json"));
    assert_report_conforms(&report, 0);
    let expected = repo_scan::config::effective_workers(None) as f64;
    assert_eq!(
        report["resources"]["cpu_target_cores"].as_f64(),
        Some(expected),
        "default workers must surface in resources: {report}"
    );
    assert_eq!(
        report["resources"]["rss_target_bytes"].as_u64(),
        Some(256 * 1024 * 1024),
        "rss target stays the §5 table budget: {report}"
    );
}
