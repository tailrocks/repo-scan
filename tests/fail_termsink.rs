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
/// (SLICE-5: the TTY-only terminal renderer is pinned without a PTY by
/// rendering the parsed report directly — Wave6 redirected scans stream
/// the JSONL journal, whose projection `termsink_secret_pair_omitted_
/// from_jsonl_event_projection` pins below.)
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

    // File mode: the report keeps the lossless path value bytes, and the
    // same report renders scrubbed through the terminal renderer (the
    // TTY-only lane, pinned here without a PTY).
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
    let parsed: repo_scan::report::model::Report =
        serde_json::from_slice(&report).expect("report parses");
    let mut rendered: Vec<u8> = Vec::new();
    repo_scan::report::render::render_terminal(&parsed, &mut rendered).expect("render");
    let text = String::from_utf8(rendered.clone()).expect("utf8");
    assert!(text.contains("repositories: 1"), "repo rendered: {text}");
    assert!(
        text.contains("token=<redacted>"),
        "scrubbed pair rendered: {text}"
    );
    assert!(
        !contains_bytes(&rendered, canary.as_bytes()),
        "canary on terminal render: {text}"
    );
}

/// The terminal `target ...` line passes the same prose scrubber as every
/// other line: a `token=hunter2`-style non-URL target never renders raw.
#[test]
fn termsink_target_line_scrubs_secret_pairs() {
    let bytes = include_bytes!("data/example-report.json");
    let mut report: repo_scan::report::model::Report =
        serde_json::from_slice(bytes).expect("example parses");
    let canary = "TERMSINKTARGET05";
    report.scan.target_url = format!("manual-scan token={canary}");
    let mut out: Vec<u8> = Vec::new();
    repo_scan::report::render::render_terminal(&report, &mut out).expect("render");
    let text = String::from_utf8(out.clone()).expect("utf8");
    assert!(text.contains("token=<redacted>"), "{text}");
    assert!(
        !contains_bytes(&out, canary.as_bytes()),
        "canary on terminal output: {text}"
    );
}

/// ADJ-03 pivot (consolidation slice 3): secret-pair path components are
/// OMITTED from the JSONL event projection — neither the raw path nor its
/// reversible hex/base64 encodings survive `event_safe_records`, while
/// stable opaque join IDs (`evt:`/`root:`) are retained. This pins the
/// projection seam owned by `scan_events.rs`; the binary-level assertion
/// (redirected scan JSONL replay omits the same bytes, B11's rewritten
/// `termsink_secret_pair_path_omitted_from_jsonl_and_redacted_on_terminal`)
/// lands when slice 5 wires the emit/replay paths to this projection.
/// The terminal-redaction lane stays pinned by
/// `termsink_secret_pair_path_redacted_on_terminal_only` above.
#[test]
fn termsink_secret_pair_omitted_from_jsonl_event_projection() {
    use repo_scan::scan_events::{envelope_for_row, event_safe_records, EventType};

    let canary = "TERMSINKPATH04";
    let path = format!("/tmp/probe-root/proj-token={canary}");
    let git_path = format!("{path}/.git");
    let path_hex = repo_scan::config::encode_hex(path.as_bytes());
    let path_b64 = std_base64(path.as_bytes());

    let records = event_safe_records(
        EventType::LocationFound,
        serde_json::json!({
            "checkout_id": format!("co:{path_hex}"),
            "store_id": format!("git:{path_hex}"),
            "path": path,
            "path_hex": path_hex,
            "git_path": git_path,
            "git_path_hex": repo_scan::config::encode_hex(git_path.as_bytes()),
        }),
    );
    for key in ["path", "path_hex", "git_path", "git_path_hex"] {
        assert!(
            records.get(key).is_none(),
            "{key} omitted from location event"
        );
    }
    assert!(
        records["checkout_id"]
            .as_str()
            .expect("checkout id")
            .starts_with("evt:"),
        "checkout id retained as an opaque join key"
    );
    assert!(
        records["store_id"]
            .as_str()
            .expect("store id")
            .starts_with("evt:"),
        "store id retained as an opaque join key"
    );

    // The same omission holds through the replay boundary (envelope build).
    let row = repo_scan::store::ScanEventRow {
        scan_id: "scan-termsink".to_string(),
        seq: 1,
        catalog_rev: 1,
        event_offset: 0,
        event_type: "location_found".to_string(),
        op: "add".to_string(),
        reset: false,
        records: serde_json::to_vec(&serde_json::json!({
            "checkout_id": format!("co:{path_hex}"),
            "store_id": format!("git:{path_hex}"),
            "path": path,
            "path_hex": path_hex,
        }))
        .expect("records"),
    };
    let env = envelope_for_row(&row).expect("envelope");
    let jsonl = serde_json::to_string(&env).expect("JSONL line");

    for text in [
        serde_json::to_string(&records).expect("records JSON"),
        jsonl,
    ] {
        assert!(!text.contains(canary), "canary in projection: {text}");
        assert!(!text.contains(&path), "raw local path in projection");
        assert!(
            !text.contains(&path_hex),
            "reversible hex path in projection"
        );
        assert!(
            !text.contains(&path_b64),
            "reversible base64 path in projection"
        );
    }
}

/// Standard base64 (RFC 4648 §4, padded) for the reversible-encoding
/// canary sweep.
fn std_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
