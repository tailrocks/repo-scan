//! RSF-SEC-AUDIT-GATE: the dependency-audit gate must stay enforced.
//! One focused regression test: the workflow and deny.toml exist and
//! carry the enforced shape (triggers, pinned SHAs, minimal
//! permissions, both tools `--locked`, advisories/licenses/sources).

use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn audit_gate_files_enforced() {
    let wf = root().join(".github/workflows/audit.yml");
    let wf_text = std::fs::read_to_string(&wf)
        .unwrap_or_else(|_| panic!("missing enforced gate: {}", wf.display()));
    for needle in [
        "push:",
        "pull_request:",
        "contents: read",
        "actions/checkout@",
        "dtolnay/rust-toolchain@",
        "cargo install cargo-audit --locked",
        "cargo audit",
        "cargo install cargo-deny --locked",
        "cargo deny check --locked",
    ] {
        assert!(
            wf_text.contains(needle),
            "audit.yml must contain {needle:?}"
        );
    }
    // No floating action tags: every `uses:` pins a full commit SHA.
    let mut uses = 0;
    for line in wf_text.lines().filter(|l| l.contains("uses:")) {
        uses += 1;
        let rev = line
            .split('@')
            .nth(1)
            .unwrap_or_else(|| panic!("uses: must pin a revision: {line}"));
        let sha: String = rev.chars().take(40).collect();
        assert!(
            sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
            "action must pin a full 40-char commit SHA: {line}"
        );
    }
    assert!(uses >= 2, "gate must pin at least checkout + toolchain");

    let deny = root().join("deny.toml");
    let deny_text = std::fs::read_to_string(&deny)
        .unwrap_or_else(|_| panic!("missing enforced policy: {}", deny.display()));
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
