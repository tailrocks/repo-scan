//! Black-box tests for `proof integration` (goal section 3.3): an
//! unrecognized platform and a skipped mandatory test must fail nonzero.
//! Tests inject a fake test command so they never build the real suite.

mod common;

use common::{code, run, stdout, write_json};
use serde_json::json;

const MANDATORY: &str = "native_macos::probe_qualification_tbd";

fn matrix(platform: &str) -> serde_json::Value {
    json!({
        "schema": "repo-scan/platforms/1",
        "known_platforms": ["linux", "macos", "windows"],
        "mandatory_native_jobs": [
            {"id": "macos-apfs-native", "platform": platform},
        ],
        "mandatory_tests": [MANDATORY],
    })
}

fn fake_log(dir: &std::path::Path, name: &str, lines: &[&str]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    format!("cat {}", path.display())
}

#[test]
fn integration_rejects_unrecognized_platform_before_running() {
    let dir = tempfile::TempDir::new().unwrap();
    let m = dir.path().join("matrix.json");
    write_json(&m, &matrix("plan9"));
    // A command that would fail if it ever ran proves validation comes first.
    let out = run(&[
        "proof",
        "integration",
        "--matrix",
        m.to_str().unwrap(),
        "--cmd",
        "exit 99",
        "--out-root",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("plan9"), "stdout: {}", stdout(&out));
}

#[test]
fn integration_rejects_malformed_matrix() {
    let dir = tempfile::TempDir::new().unwrap();
    let m = dir.path().join("matrix.json");
    std::fs::write(&m, b"{broken").unwrap();
    let out = run(&[
        "proof",
        "integration",
        "--matrix",
        m.to_str().unwrap(),
        "--cmd",
        "exit 99",
        "--out-root",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
}

#[test]
fn integration_fails_on_ignored_mandatory_test() {
    let dir = tempfile::TempDir::new().unwrap();
    let m = dir.path().join("matrix.json");
    write_json(&m, &matrix("macos"));
    let cmd = fake_log(
        dir.path(),
        "log.txt",
        &[
            "     Running tests/native_macos.rs (target/debug/deps/native_macos-000)",
            &format!("test {MANDATORY} ... ignored"),
            "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out",
        ],
    );
    let out = run(&[
        "proof",
        "integration",
        "--matrix",
        m.to_str().unwrap(),
        "--repo",
        dir.path().to_str().unwrap(),
        "--cmd",
        &cmd,
        "--out-root",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(
        stdout(&out).contains("skipped/ignored"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn integration_fails_on_absent_mandatory_test() {
    let dir = tempfile::TempDir::new().unwrap();
    let m = dir.path().join("matrix.json");
    write_json(&m, &matrix("macos"));
    let cmd = fake_log(
        dir.path(),
        "log.txt",
        &[
            "     Running tests/native_macos.rs (target/debug/deps/native_macos-000)",
            "test native_macos::some_other_test ... ok",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
        ],
    );
    let out = run(&[
        "proof",
        "integration",
        "--matrix",
        m.to_str().unwrap(),
        "--repo",
        dir.path().to_str().unwrap(),
        "--cmd",
        &cmd,
        "--out-root",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("absent"), "stdout: {}", stdout(&out));
}

#[test]
fn integration_fails_on_failed_test() {
    let dir = tempfile::TempDir::new().unwrap();
    let m = dir.path().join("matrix.json");
    write_json(&m, &matrix("macos"));
    let cmd = fake_log(
        dir.path(),
        "log.txt",
        &[
            "     Running tests/native_macos.rs (target/debug/deps/native_macos-000)",
            &format!("test {MANDATORY} ... ok"),
            "test native_macos::other ... FAILED",
            "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out",
        ],
    );
    // Even with exit 0 from the shell, a FAILED line must fail the verdict.
    let out = run(&[
        "proof",
        "integration",
        "--matrix",
        m.to_str().unwrap(),
        "--repo",
        dir.path().to_str().unwrap(),
        "--cmd",
        &cmd,
        "--out-root",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("FAILED"), "stdout: {}", stdout(&out));
}

#[test]
fn integration_fails_on_nonzero_test_command() {
    let dir = tempfile::TempDir::new().unwrap();
    let m = dir.path().join("matrix.json");
    write_json(&m, &matrix("macos"));
    let out = run(&[
        "proof",
        "integration",
        "--matrix",
        m.to_str().unwrap(),
        "--repo",
        dir.path().to_str().unwrap(),
        "--cmd",
        "exit 3",
        "--out-root",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
}

#[test]
fn integration_passes_clean_log_with_mandatory_test() {
    let dir = tempfile::TempDir::new().unwrap();
    let m = dir.path().join("matrix.json");
    write_json(&m, &matrix("macos"));
    let cmd = fake_log(
        dir.path(),
        "log.txt",
        &[
            "     Running tests/native_macos.rs (target/debug/deps/native_macos-000)",
            &format!("test {MANDATORY} ... ok"),
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
        ],
    );
    let out_root = dir.path().join("proof-out");
    let out = run(&[
        "proof",
        "integration",
        "--matrix",
        m.to_str().unwrap(),
        "--repo",
        dir.path().to_str().unwrap(),
        "--cmd",
        &cmd,
        "--out-root",
        out_root.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));
    // Run dir carries the manifest, log, results and checksums.
    let collected: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("json");
    let run_dir = std::path::PathBuf::from(collected["run_dir"].as_str().unwrap());
    for f in [
        "run-manifest.json",
        "integration-log.txt",
        "integration-results.json",
        "checksums.json",
    ] {
        assert!(run_dir.join(f).is_file(), "missing {f}");
    }
}
