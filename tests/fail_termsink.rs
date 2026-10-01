//! RETEST-7 terminal-sink redaction: every stderr diagnostic and the
//! readable terminal render pass the centralized scrubber, so
//! credential-bearing inputs on error paths and lower-layer URL material
//! never emit raw. Hand-written fixtures under `/tmp` tempdirs only (no
//! git binary, no scans outside the fixture root).

use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_repo-scan"))
}

fn run(args: &[&str], cwd: &Path, state: &Path) -> std::process::Output {
    let mut full = vec!["--state-dir", state.to_str().expect("utf8 state dir")];
    full.extend(args.iter().copied());
    ProcCommand::new(binary())
        .args(&full)
        .current_dir(cwd)
        .output()
        .expect("spawn repo-scan")
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn state_files(state: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![state.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !path.is_symlink() {
                stack.push(path);
            } else if path.is_file() {
                out.push(path);
            }
        }
    }
    out
}

fn assert_no_canary_in_state(state: &Path, canary: &str) {
    for path in state_files(state) {
        let bytes = std::fs::read(&path).expect("read state file");
        assert!(
            !contains_bytes(&bytes, canary.as_bytes()),
            "canary in {}",
            path.display()
        );
    }
}

/// Hand-craft a minimal git dir (`HEAD` + `config` + `objects/` + `refs/`)
/// whose `origin` observes `remote_url`: no git binary, no network. The
/// probe still classifies the remote and persists the instance.
fn seed_git_dir(path: &Path, remote_url: &str) {
    repo_scan::privacy::private_dir_0700(&path.join(".git").join("objects")).expect("mkdir");
    repo_scan::privacy::private_dir_0700(&path.join(".git").join("refs").join("heads"))
        .expect("mkdir");
    repo_scan::privacy::private_write_0600(
        &path.join(".git").join("HEAD"),
        b"ref: refs/heads/main\n",
    )
    .expect("write HEAD");
    let config = format!(
        "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = {remote_url}\n"
    );
    repo_scan::privacy::private_write_0600(&path.join(".git").join("config"), config.as_bytes())
        .expect("write config");
}

/// Error paths echoing credential-bearing input must scrub stderr: a
/// userinfo URL, a `token=` pair, and a `--token` flag as unknown scan IDs
/// all exit 2 with no canary on either stream and nothing persisted.
#[test]
fn termsink_error_paths_scrub_credential_input() {
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    for (name, scan_id, canary) in [
        (
            "userinfo",
            "https://user:TERMSINKSCAN01@github.com/o/r",
            "TERMSINKSCAN01",
        ),
        ("pair", "scan-token=TERMSINKSCAN02", "TERMSINKSCAN02"),
        ("flag", "scan --token TERMSINKSCAN03", "TERMSINKSCAN03"),
    ] {
        let state = dir.path().join(format!("state-{name}"));
        let cwd = dir.path().join(format!("cwd-{name}"));
        repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
        let out = run(&["resume", scan_id], &cwd, &state);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{name}: stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !contains_bytes(&out.stdout, canary.as_bytes()),
            "{name}: canary on stdout"
        );
        assert!(
            !contains_bytes(&out.stderr, canary.as_bytes()),
            "{name}: canary on stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_no_canary_in_state(&state, canary);
    }
}

/// Lower-layer URL material (a credential-bearing remote observed during
/// the probe) never emits raw: terminal/file scans keep the canary out of
/// stdout, stderr, the report file, and every catalog/snapshot byte, while
/// the redacted marker still shows the remote was observed.
#[test]
fn termsink_lower_layer_remote_never_emits_raw() {
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let canary = "TERMSINKREMOTE03";
    let remote = format!("https://user:{canary}@github.com/o/r.git");
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    seed_git_dir(&root.join("proj"), &remote);
    let root_str = root.to_str().expect("utf8").to_string();

    // Terminal mode: the confirmed repository renders, remote stays redacted.
    let state = dir.path().join("state-term");
    let cwd = dir.path().join("cwd-term");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let out = run(
        &[
            "scan",
            "https://github.com/o/r",
            "--root",
            root_str.as_str(),
        ],
        &cwd,
        &state,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!contains_bytes(&out.stdout, canary.as_bytes()));
    assert!(!contains_bytes(&out.stderr, canary.as_bytes()));
    assert_no_canary_in_state(&state, canary);

    // File mode: the report carries the redacted remote, never the secret.
    let state_f = dir.path().join("state-file");
    let cwd_f = dir.path().join("cwd-file");
    repo_scan::privacy::private_dir_0700(&cwd_f).expect("mkdir");
    let out = run(
        &[
            "scan",
            "https://github.com/o/r",
            "--root",
            root_str.as_str(),
            "--report",
            "rep.json",
        ],
        &cwd_f,
        &state_f,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = std::fs::read(cwd_f.join("rep.json")).expect("read report");
    assert!(!contains_bytes(&report, canary.as_bytes()));
    assert!(
        contains_bytes(&report, b"user:<redacted>@github.com/o/r.git"),
        "redacted remote observed in report"
    );
    assert_no_canary_in_state(&state_f, canary);
}

/// Secret-pair path components redact on the terminal display channel
/// only: stdout/stderr stay clean while the report keeps the lossless
/// `value` bytes (display/value split, mirroring the query path display).
#[test]
fn termsink_secret_pair_path_redacted_on_terminal_only() {
    let dir = tempfile::tempdir_in("/tmp").expect("tmpdir under /tmp");
    let canary = "TERMSINKPATH04";
    let root = dir.path().join("root");
    repo_scan::privacy::private_dir_0700(&root).expect("mkdir");
    seed_git_dir(
        &root.join(format!("proj-token={canary}")),
        "https://github.com/o/r.git",
    );
    let root_str = root.to_str().expect("utf8").to_string();

    // Terminal mode (spec §3: no --report renders the readable report):
    // the repository renders with the secret pair scrubbed on stdout.
    // File mode prints only the summary lines, never the render.
    let state = dir.path().join("state-term");
    let cwd = dir.path().join("cwd-term");
    repo_scan::privacy::private_dir_0700(&cwd).expect("mkdir");
    let out = run(
        &[
            "scan",
            "https://github.com/o/r",
            "--root",
            root_str.as_str(),
        ],
        &cwd,
        &state,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("repositories: 1"),
        "repo rendered: {stdout}"
    );
    assert!(
        stdout.contains("token=<redacted>"),
        "scrubbed pair rendered: {stdout}"
    );
    assert!(
        !contains_bytes(&out.stdout, canary.as_bytes()),
        "canary on terminal stdout: {stdout}"
    );
    assert!(!contains_bytes(&out.stderr, canary.as_bytes()));

    // File mode: the report keeps the lossless path value bytes.
    let state_f = dir.path().join("state-file");
    let cwd_f = dir.path().join("cwd-file");
    repo_scan::privacy::private_dir_0700(&cwd_f).expect("mkdir");
    let out = run(
        &[
            "scan",
            "https://github.com/o/r",
            "--root",
            root_str.as_str(),
            "--report",
            "rep.json",
        ],
        &cwd_f,
        &state_f,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!contains_bytes(&out.stdout, canary.as_bytes()));
    assert!(!contains_bytes(&out.stderr, canary.as_bytes()));
    let report = std::fs::read(cwd_f.join("rep.json")).expect("read report");
    assert!(
        contains_bytes(&report, canary.as_bytes()),
        "lossless path value retained in report"
    );
}
