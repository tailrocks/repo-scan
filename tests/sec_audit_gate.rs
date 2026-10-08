//! RSF-SEC-AUDIT-GATE: keep the intended dependency-audit specification
//! and policy documented accurately. This test validates static inputs;
//! it does not schedule the workflow or enforce a GitHub status check.

use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = root().join(rel);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|_| panic!("missing enforced gate file: {}", p.display()))
}

#[test]
fn audit_workflow_specification_matches_policy() {
    let wf_text = read("docs/workflows/audit.yml");
    for needle in [
        "push:",
        "pull_request:",
        "contents: read",
        "actions/checkout@",
        "dtolnay/rust-toolchain@",
        "cargo install cargo-audit --version 0.22.1 --locked",
        "cargo-audit audit",
        "cargo install cargo-deny --version 0.18.3 --locked",
        "cargo-deny ",
        "--locked check",
    ] {
        assert!(
            wf_text.contains(needle),
            "audit.yml must contain {needle:?}"
        );
    }
    assert!(
        !wf_text.contains("pull_request_target"),
        "audit.yml must not use pull_request_target"
    );
    assert!(
        !wf_text.contains("contents: write"),
        "audit.yml must not grant write permissions"
    );
    // CI-SC-03: no floating action tags — every `uses:` must match an
    // exact reviewed (action, SHA) pair from this allowlist. Any 40-hex
    // is NOT enough: an unknown action or a rotated SHA fails closed.
    let allowed = [
        (
            "actions/checkout",
            "11bd71901bbe5b1630ceea73d27597364c9af683",
        ),
        (
            "dtolnay/rust-toolchain",
            "6bed0761d98439e5a578e2877258200ad565ba87",
        ),
    ];
    let mut seen = [false; 2];
    let mut uses = 0;
    for line in wf_text.lines().filter(|l| l.contains("uses:")) {
        uses += 1;
        let spec = line
            .split("uses:")
            .nth(1)
            .unwrap_or_else(|| panic!("uses: must pin a revision: {line}"))
            .trim();
        let pinned = spec.split_whitespace().next().unwrap_or("");
        let (name, sha) = pinned
            .split_once('@')
            .unwrap_or_else(|| panic!("uses: must pin action@sha: {line}"));
        let slot = allowed
            .iter()
            .position(|(want_name, want_sha)| *want_name == name && *want_sha == sha)
            .unwrap_or_else(|| panic!("uses: not in the exact-SHA allowlist: {line}"));
        seen[slot] = true;
    }
    assert!(uses >= 2, "gate must pin at least checkout + toolchain");
    for (n, was_seen) in seen.iter().enumerate() {
        assert!(
            was_seen,
            "allowlisted action {} must still be pinned",
            allowed[n].0
        );
    }

    let deny_text = read("deny.toml");
    for needle in [
        "[advisories]",
        "[licenses]",
        "[sources]",
        "unknown-registry",
        "unknown-git",
        "https://github.com/rust-lang/crates.io-index",
    ] {
        assert!(
            deny_text.contains(needle),
            "deny.toml must contain {needle:?}"
        );
    }
}

// CI-SC-01: checkout persists no credentials; tool installs run outside the
// checkout with isolated Cargo state so PR-controlled config cannot execute.
#[test]
fn checkout_persists_no_credentials() {
    let wf = read("docs/workflows/audit.yml");
    for needle in [
        "persist-credentials: false",
        "extraheader",
        "working-directory: ${{ runner.temp }}",
        "RUNNER_TEMP/cargo-home",
        "CARGO_TARGET_DIR",
    ] {
        assert!(wf.contains(needle), "audit.yml must contain {needle:?}");
    }
}

// CI-SC-02: runner, toolchain, and audit tools are pinned exactly.
#[test]
fn toolchain_and_tools_pinned() {
    let wf = read("docs/workflows/audit.yml");
    for needle in [
        "runs-on: ubuntu-24.04",
        "toolchain: 1.85.0",
        "cargo-audit --version 0.22.1",
        "cargo-deny --version 0.18.3",
        "sha256",
    ] {
        assert!(wf.contains(needle), "audit.yml must contain {needle:?}");
    }
    for banned in ["ubuntu-latest", "toolchain: stable"] {
        assert!(
            !wf.contains(banned),
            "audit.yml must not contain floating pin {banned:?}"
        );
    }
}

// CI-SC-02: provenance records the source OID plus the advisory-DB
// revision even when an audit step fails, and the pinned tool archives
// are SHA-256-verified fail-closed before installation.
#[test]
fn tool_provenance_and_archive_verification() {
    let wf = read("docs/workflows/audit.yml");
    for needle in [
        "Verify pinned tool archives",
        "static.crates.io/crates/",
        "sha256 mismatch",
        "2f4e27b0ab2d116c87c29db159ad42565cdcdccf77eb62ef0486ddd017a02da6",
        "9ed51dacad2ea0880a689cb64bdd52cbae3b44578c19833f6cc4e66ebea8d914",
        "source_oid=$GITHUB_SHA",
        "rev-parse HEAD",
        "advisory-dbs",
        "advisory database checkout missing",
        "if: always()",
    ] {
        assert!(wf.contains(needle), "audit.yml must contain {needle:?}");
    }
    let verify = wf
        .find("Verify pinned tool archives")
        .expect("verify step present");
    let install = wf
        .find("cargo install cargo-audit")
        .expect("install step present");
    assert!(
        verify < install,
        "archive verification must precede tool installation"
    );
    let deny = wf
        .find("cargo-deny --manifest-path")
        .expect("deny step present");
    let provenance = wf
        .find("Record tool provenance")
        .expect("provenance step present");
    assert!(
        deny < provenance,
        "provenance must run after the audits it attributes"
    );
}

// CI-SC-03: keep the unenforced status explicit until a supported workflow
// schedules the audit and a live run confirms its status check.
#[test]
fn unenforced_status_is_documented() {
    let wf = read("docs/workflows/audit.yml");
    assert!(
        wf.contains("docs/AUDIT_GATE.md"),
        "audit.yml must reference docs/AUDIT_GATE.md"
    );
    let doc = read("docs/AUDIT_GATE.md");
    for needle in [
        "Status: NOT ENFORCED BY GITHUB ACTIONS.",
        "Do not treat an `audit` status check as active",
        "tamper-evident",
        "tests/sec_audit_gate.rs",
    ] {
        assert!(
            doc.contains(needle),
            "AUDIT_GATE.md must contain {needle:?}"
        );
    }
}

// CI-SC-04: bounded execution — job timeout plus PR concurrency cancellation.
#[test]
fn bounded_execution() {
    let wf = read("docs/workflows/audit.yml");
    for needle in [
        "timeout-minutes:",
        "concurrency:",
        "cancel-in-progress: true",
    ] {
        assert!(wf.contains(needle), "audit.yml must contain {needle:?}");
    }
    let doc = read("docs/AUDIT_GATE.md");
    assert!(
        doc.contains("timeout-minutes: 20"),
        "AUDIT_GATE.md must record the execution budget"
    );
}
