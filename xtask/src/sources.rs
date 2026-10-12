//! Frozen sources lock loading and live-repository inventory validation.
//!
//! `proof inventory` checks that every frozen ref under refs/goal/sources/
//! exists in the live repository with matching head SHA, tree and parents,
//! and that the repository carries no omitted or extra source refs. A
//! deliberately omitted head is a nonzero-exit failure (goal step 1 exit
//! gate, section 3.3).

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SOURCES_PREFIX: &str = "refs/goal/sources/";

/// One frozen source entry. `ref_name` is validated and retained for audit
/// output even though inventory matching keys on `frozen_ref`.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Source {
    pub id: String,
    pub ref_name: String,
    pub frozen_ref: String,
    pub head: String,
    pub tree: String,
    pub parents: Vec<String>,
    pub object_type: String,
}

#[derive(Debug)]
pub struct SourcesLock {
    pub sources: Vec<Source>,
}

#[derive(Debug)]
pub struct InventoryReport {
    pub sources_checked: usize,
    pub problems: Vec<String>,
}

fn is_hex40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Load and schema-validate a sources lock file.
pub fn load(path: &Path) -> Result<SourcesLock, String> {
    let raw = crate::canon::read_json(path)?;
    let obj = raw
        .as_object()
        .ok_or_else(|| format!("{}: not a JSON object", path.display()))?;
    if obj.get("schema").and_then(Value::as_str).is_none() {
        return Err(format!("{}: missing 'schema' field", path.display()));
    }
    let items = obj
        .get("sources")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{}: missing 'sources' array", path.display()))?;
    let mut sources = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut seen_refs = BTreeSet::new();
    for (i, item) in items.iter().enumerate() {
        let ctx = format!("{}: sources[{i}]", path.display());
        let so = item
            .as_object()
            .ok_or_else(|| format!("{ctx}: not an object"))?;
        let get = |key: &str| -> Result<String, String> {
            so.get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("{ctx}: missing or empty '{key}'"))
        };
        let id = get("id")?;
        let ref_name = get("ref")?;
        let frozen_ref = get("frozen_ref")?;
        if !frozen_ref.starts_with(SOURCES_PREFIX) {
            return Err(format!(
                "{ctx}: frozen_ref '{frozen_ref}' is outside {SOURCES_PREFIX}"
            ));
        }
        let head = get("head")?;
        let tree = get("tree")?;
        if !is_hex40(&head) {
            return Err(format!("{ctx}: head is not a 40-hex object id"));
        }
        if !is_hex40(&tree) {
            return Err(format!("{ctx}: tree is not a 40-hex object id"));
        }
        let object_type = get("object_type")?;
        let parents = so
            .get("parents")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{ctx}: missing 'parents' array"))?
            .iter()
            .enumerate()
            .map(|(j, p)| {
                p.as_str()
                    .filter(|s| is_hex40(s))
                    .map(str::to_string)
                    .ok_or_else(|| format!("{ctx}: parents[{j}] is not a 40-hex object id"))
            })
            .collect::<Result<Vec<String>, String>>()?;
        if !seen_ids.insert(id.clone()) {
            return Err(format!("{ctx}: duplicate source id '{id}'"));
        }
        if !seen_refs.insert(frozen_ref.clone()) {
            return Err(format!("{ctx}: duplicate frozen_ref '{frozen_ref}'"));
        }
        sources.push(Source {
            id,
            ref_name,
            frozen_ref,
            head,
            tree,
            parents,
            object_type,
        });
    }
    Ok(SourcesLock { sources })
}

/// Run git in `repo`; returns trimmed stdout or the stderr message.
pub fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| format!("cannot spawn git: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Parse the header of a commit object into (tree, parents).
fn parse_commit(raw: &str) -> Option<(String, Vec<String>)> {
    let mut tree = None;
    let mut parents = Vec::new();
    for line in raw.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(t) = line.strip_prefix("tree ") {
            tree = Some(t.trim().to_string());
        } else if let Some(p) = line.strip_prefix("parent ") {
            parents.push(p.trim().to_string());
        }
    }
    tree.map(|t| (t, parents))
}

/// Validate the lock against the live repository. Err means the repository
/// itself is unavailable (a BLOCKED prerequisite); Ok carries the problem
/// list (non-empty means FAIL).
pub fn inventory(repo: &Path, lock: &SourcesLock) -> Result<InventoryReport, String> {
    git(repo, &["rev-parse", "--git-dir"])
        .map_err(|e| format!("{} is not a usable git repository: {e}", repo.display()))?;
    let mut problems = Vec::new();

    let refs_out = git(
        repo,
        &["for-each-ref", SOURCES_PREFIX, "--format=%(refname)"],
    )?;
    let repo_refs: BTreeSet<String> = refs_out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    let lock_refs: BTreeSet<String> = lock.sources.iter().map(|s| s.frozen_ref.clone()).collect();

    for src in &lock.sources {
        if !repo_refs.contains(&src.frozen_ref) {
            problems.push(format!(
                "missing source ref in repo: {} (source {})",
                src.frozen_ref, src.id
            ));
            continue;
        }
        match git(repo, &["rev-parse", "--verify", &src.frozen_ref]) {
            Ok(actual) if actual == src.head => {}
            Ok(actual) => problems.push(format!(
                "source {}: ref {} points at {actual}, lock records {}",
                src.id, src.frozen_ref, src.head
            )),
            Err(e) => {
                problems.push(format!("source {}: cannot resolve ref: {e}", src.id));
                continue;
            }
        }
        match git(repo, &["cat-file", "-t", &src.head]) {
            Ok(t) if t == src.object_type => {}
            Ok(t) => problems.push(format!(
                "source {}: head {} has type {t}, lock records {}",
                src.id, src.head, src.object_type
            )),
            Err(_) => {
                problems.push(format!(
                    "source {}: head object {} missing from repo",
                    src.id, src.head
                ));
                continue;
            }
        }
        if src.object_type == "commit" {
            match git(repo, &["cat-file", "commit", &src.head]) {
                Ok(raw) => match parse_commit(&raw) {
                    Some((tree, parents)) => {
                        if tree != src.tree {
                            problems.push(format!(
                                "source {}: tree mismatch ({tree} != lock {})",
                                src.id, src.tree
                            ));
                        }
                        if parents != src.parents {
                            problems.push(format!(
                                "source {}: parents mismatch ({parents:?} != lock {:?})",
                                src.id, src.parents
                            ));
                        }
                    }
                    None => problems.push(format!(
                        "source {}: cannot parse commit header of {}",
                        src.id, src.head
                    )),
                },
                Err(e) => problems.push(format!("source {}: {e}", src.id)),
            }
        }
    }

    for extra in repo_refs.difference(&lock_refs) {
        problems.push(format!(
            "extra source ref in repo not covered by the lock: {extra} \
             (the lock omitted a head present in the repository)"
        ));
    }

    Ok(InventoryReport {
        sources_checked: lock.sources.len(),
        problems,
    })
}

/// `proof inventory` subcommand.
pub fn cmd_inventory(repo: Option<PathBuf>, sources: &Path) -> i32 {
    let repo = repo.unwrap_or_else(|| PathBuf::from("."));
    let lock = match load(sources) {
        Ok(l) => l,
        Err(e) => crate::invalid(e),
    };
    let report = match inventory(&repo, &lock) {
        Ok(r) => r,
        Err(e) => crate::blocked(e),
    };
    if report.problems.is_empty() {
        crate::emit_exit(
            crate::EXIT_PASS,
            "PASS",
            serde_json::json!({
                "sources_checked": report.sources_checked,
                "repo": repo.display().to_string(),
            }),
        );
    }
    crate::emit_exit(
        crate::EXIT_FAIL,
        "FAIL",
        serde_json::json!({
            "sources_checked": report.sources_checked,
            "repo": repo.display().to_string(),
            "problems": report.problems,
        }),
    );
}
