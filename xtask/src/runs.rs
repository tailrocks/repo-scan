//! Run-directory lifecycle: creation, run manifests, and integrity checksums.
//!
//! Every run directory under `proof-out/<run-id>/` contains a
//! `run-manifest.json` (build/host metadata, binary hashes, command, exit,
//! dataset identity, timestamps), raw artifacts (samples.jsonl, logs), and a
//! `checksums.json` covering every other regular file in the directory.
//! `evaluate` and `verify-final` recompute the checksums before trusting any
//! content.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CHECKSUMS_FILE: &str = "checksums.json";
pub const MANIFEST_FILE: &str = "run-manifest.json";
pub const SAMPLES_FILE: &str = "samples.jsonl";

/// RFC3339 UTC timestamp without external crates (Hinnant's civil algorithm).
pub fn now_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub struct RunDir {
    pub id: String,
    pub path: PathBuf,
}

/// Create `proof-out/<run-id>/` (or `<out_root>/<run-id>/`).
pub fn create(out_root: &Path) -> io::Result<RunDir> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let id = format!(
        "{}-{}-{:09}",
        now_rfc3339().replace([':', '-'], ""),
        std::process::id(),
        now.subsec_nanos()
    );
    let path = out_root.join(&id);
    fs::create_dir_all(&path)?;
    Ok(RunDir { id, path })
}

/// All regular files under `dir`, as sorted relative slash paths, excluding
/// the checksums file itself.
fn collect_files(dir: &Path) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        for entry in fs::read_dir(&cur)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                let rel = entry
                    .path()
                    .strip_prefix(dir)
                    .expect("under dir")
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel != CHECKSUMS_FILE {
                    out.push(rel);
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Write checksums.json covering every regular file in the run directory.
pub fn write_checksums(dir: &Path) -> io::Result<()> {
    let mut files = BTreeMap::new();
    for rel in collect_files(dir)? {
        let sha = crate::canon::sha256_file(&dir.join(&rel))?;
        files.insert(rel, Value::String(sha));
    }
    let doc = json!({
        "schema": "repo-scan/run-checksums/1",
        "files": files,
    });
    crate::canon::write_json(&dir.join(CHECKSUMS_FILE), &doc)
}

/// Verify run-directory integrity: every recorded file exists with a matching
/// SHA-256, and no unrecorded files are present. Returns the list of
/// integrity problems (empty means intact).
pub fn verify_checksums(dir: &Path) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let sums_path = dir.join(CHECKSUMS_FILE);
    let doc = match crate::canon::read_json(&sums_path) {
        Ok(v) => v,
        Err(e) => return Err(vec![e]),
    };
    let recorded: BTreeMap<String, String> = match doc.get("files").and_then(Value::as_object) {
        Some(map) => map
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect(),
        None => return Err(vec![format!("{}: missing files map", sums_path.display())]),
    };
    for (rel, sha) in &recorded {
        let p = dir.join(rel);
        if !p.is_file() {
            problems.push(format!("recorded file missing: {rel}"));
            continue;
        }
        match crate::canon::sha256_file(&p) {
            Ok(actual) if &actual == sha => {}
            Ok(actual) => problems.push(format!(
                "checksum mismatch: {rel} (recorded {sha}, actual {actual})"
            )),
            Err(e) => problems.push(format!("cannot hash {rel}: {e}")),
        }
    }
    match collect_files(dir) {
        Ok(actual) => {
            for rel in actual {
                if !recorded.contains_key(&rel) {
                    problems.push(format!("unrecorded file present: {rel}"));
                }
            }
        }
        Err(e) => problems.push(format!("cannot enumerate {}: {e}", dir.display())),
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

pub fn host_metadata() -> Value {
    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "family": std::env::consts::FAMILY,
    })
}

pub fn build_metadata() -> Value {
    let rustc = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string()))
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    json!({
        "rustc": rustc,
        "xtask_version": env!("CARGO_PKG_VERSION"),
    })
}
