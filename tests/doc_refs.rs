//! BOUNDARY-m12: `docs/ARCHITECTURE.md` file references resolve.
//!
//! Every backticked `src/...`, `tests/...`, `docs/...`, `schemas/...`,
//! `benches/...` path names a file (or directory, for `src/platform/`)
//! that exists. Line `:NNN` suffixes are stripped before the check:
//! line numbers churn with every edit and stay human-audited (m12),
//! while moved/renamed files fail loudly here.

use std::path::PathBuf;

const ROOTS: [&str; 5] = ["src/", "tests/", "docs/", "schemas/", "benches/"];

/// Backticked path references in the doc, line suffixes stripped.
fn doc_paths(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, span) in doc.split('`').enumerate() {
        if i % 2 == 0 {
            continue; // outside backticks
        }
        if !ROOTS.iter().any(|r| span.starts_with(r)) {
            continue;
        }
        // Strip `:NNN`, `:NNN,MMM`, `:NNN-MMM` line suffixes; shorthand
        // same-file continuations (`:440`) never match a root above.
        let path = span.split(':').next().unwrap_or(span);
        // Skip `...` elisions (`schema_v2.rs` … `schema_v6.rs` names both
        // ends literally, so nothing is lost).
        if path.contains("…") || path.contains("...") {
            continue;
        }
        out.push(path.to_string());
    }
    out
}

#[test]
fn architecture_file_references_exist() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let doc =
        std::fs::read_to_string(root.join("docs/ARCHITECTURE.md")).expect("read ARCHITECTURE.md");
    let paths = doc_paths(&doc);
    assert!(
        paths.len() >= 40,
        "ref harvester caught too few ({}); fix the parser, not the doc",
        paths.len()
    );
    let mut missing = Vec::new();
    for path in &paths {
        if path.contains('*') {
            // Glob (`docs/*_QUAL.md`): at least one match must exist.
            let (pre, suf) = path.split_once('*').expect("glob halves");
            let dir = root.join(pre.split('/').next().expect("glob dir"));
            let hit = std::fs::read_dir(&dir)
                .expect("glob dir readable")
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .any(|n| n.ends_with(suf.trim_start_matches('/')));
            if !hit {
                missing.push(path.clone());
            }
            continue;
        }
        if !root.join(path).exists() {
            missing.push(path.clone());
        }
    }
    assert!(missing.is_empty(), "phantom doc paths: {missing:?}");
}
