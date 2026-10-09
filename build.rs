use std::process::Command;

fn valid_commit(value: &str) -> Option<String> {
    let value = value.trim();
    if (value.len() == 40 || value.len() == 64)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

fn command_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn source_commit() -> Option<String> {
    let configured = std::env::var("REPO_SCAN_SOURCE_COMMIT")
        .ok()
        .and_then(|value| valid_commit(&value))
        .or_else(|| {
            std::env::var("GITHUB_SHA")
                .ok()
                .and_then(|value| valid_commit(&value))
        });

    // GitHub and release builders supply an explicit source SHA. When Git is
    // available, require that it names this exact clean checkout; for source
    // archives without Git metadata, the explicit value is the only evidence.
    let Some(head) = command_output(&["rev-parse", "--verify", "HEAD^{commit}"]) else {
        return configured;
    };
    let status = command_output(&["status", "--porcelain", "--untracked-files=normal"])?;
    if !status.is_empty() {
        return None;
    }
    let head = valid_commit(&head)?;
    if configured.as_ref().is_some_and(|commit| commit != &head) {
        return None;
    }
    Some(head)
}

fn main() {
    println!("cargo:rerun-if-env-changed=REPO_SCAN_SOURCE_COMMIT");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    // Directory inputs make the clean-checkout test run again after source
    // edits, so Cargo cannot reuse a previously embedded HEAD SHA for a dirty
    // incremental build. Cargo recursively checks directory inputs.
    for path in ["src", "schemas", ".cargo", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={path}");
    }
    for git_path in ["HEAD", "index", "packed-refs"] {
        if let Some(path) = command_output(&["rev-parse", "--git-path", git_path]) {
            println!("cargo:rerun-if-changed={}", path.trim());
        }
    }
    if let Some(reference) = command_output(&["symbolic-ref", "--quiet", "HEAD"]) {
        let reference = reference.trim();
        if let Some(path) = command_output(&["rev-parse", "--git-path", reference]) {
            println!("cargo:rerun-if-changed={}", path.trim());
        }
    }
    let commit = source_commit().unwrap_or_default();
    println!("cargo:rustc-env=REPO_SCAN_SOURCE_COMMIT={commit}");
}
