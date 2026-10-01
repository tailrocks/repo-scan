//! Installed-git compatibility backend (spec §9, GIT_QUAL §11).
//!
//! Triggered only when gix reports a structural gap: reftable ref storage,
//! SSH-alias remotes needing `Host` resolution, unparseable index or
//! worktree admin, or object-format gaps. Never a per-directory scanner.
//!
//! Safety contract: explicit candidate paths (no bare `git` from an
//! unexamined `PATH` entry without recording it), argv arrays with no shell
//! interpolation, `GIT_OPTIONAL_LOCKS=0`, `--no-optional-locks` where
//! supported, `core.hooksPath=/dev/null` plus `core.fsmonitor=false`
//! overrides, `GIT_HTTP_*`/proxy variables unset, no fetch/clone/pull/push
//! subcommand ever invoked, and no configured filter/fsmonitor/helper
//! executed (cases needing one stay `partial`/`unsupported`).
//!
//! Every spawn additionally runs inside one envelope
//! (RSF-SEC-GIT-PROBE): stdin is nulled, config-redirect environment
//! (`GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_CONFIG_COUNT`) is
//! stripped, `-c help.format=man` forbids browser help renderers,
//! captured stdout/stderr are capped (over-cap output fails the call,
//! never truncates silently), the child is killed past `GIT_SPAWN_TIMEOUT`,
//! and the caller-visible result requires the expected exit status.
//!
//! Capabilities are probed once per installed-git identity (binary path +
//! `git --version` plus the `git status --porcelain=v2 --help` feature
//! probe per GIT_QUAL §11) and reused; [`FallbackGit`] caches them at
//! discovery. A version string alone is never feature evidence: wrappers
//! and vendor backports can report a version while lacking an assumed
//! option, so the probe must succeed or the capability stays false.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::{HeadState, Oid, RefObservation, RefTarget};

/// Well-known installed-git locations checked before `$PATH` entries.
pub const KNOWN_GIT_PATHS: &[&str] = &[
    "/usr/bin/git",
    "/usr/local/bin/git",
    "/opt/homebrew/bin/git",
    "/opt/local/bin/git",
];

/// Wall-clock budget for one installed-git spawn. The fallback only runs
/// local read-only subcommands, so anything slower is a stuck helper: the
/// child is killed and the call fails (RSF-SEC-GIT-PROBE).
pub const GIT_SPAWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum captured bytes per stream (stdout, stderr) for one
/// installed-git spawn. Output past the cap fails the call — partial ref
/// lists or status text must never read as complete results.
pub const MAX_CAPTURE_BYTES: u64 = 8 * 1024 * 1024;

/// Where [`FallbackGit::discover`] found the binary. Trusted absolute
/// paths (explicit arguments, then [`KNOWN_GIT_PATHS`]) win over `$PATH`
/// entries; a `$PATH` selection is recorded here (with the absolute
/// candidate in [`FallbackGit::path`]), never a bare `git`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinarySource {
    /// Caller-supplied explicit path (also what [`FallbackGit::probe`]
    /// reports: its argument is explicit by construction).
    Explicit,
    /// One of [`KNOWN_GIT_PATHS`].
    Known,
    /// Resolved by joining a `$PATH` entry with `git`.
    Path,
}

/// Capability record for one installed-git identity.
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Raw `git --version` output (also the identity string).
    pub version: String,
    /// Parsed `(major, minor, patch)`; unknown parts are zero.
    pub version_tuple: (u32, u32, u32),
    /// `--no-optional-locks` supported (git >= 2.14).
    pub no_optional_locks: bool,
    /// `status --porcelain=v2` supported: the version floor (git >= 2.11)
    /// AND the `git status --porcelain=v2 --help` feature probe both held
    /// (RSF-88BA). False when the probe fails, however high the version.
    pub porcelain_v2: bool,
    /// `worktree list --porcelain` supported (git >= 2.7).
    pub worktree_list: bool,
    /// True when the `status --porcelain=v2 --help` feature probe exited
    /// successfully and its output named the porcelain feature
    /// (RSF-88BA). Wrappers hiding the option and version/backport
    /// mismatches fail the probe while still reporting a version.
    pub feature_probe_ok: bool,
}

/// Installed-git fallback bound to one probed binary.
#[derive(Debug, Clone)]
pub struct FallbackGit {
    path: PathBuf,
    source: BinarySource,
    capabilities: Capabilities,
}

impl FallbackGit {
    /// Discover and probe an installed git.
    ///
    /// `explicit` paths are tried first, then [`KNOWN_GIT_PATHS`], then
    /// `$PATH` entries. The first binary answering `git --version` wins;
    /// its capabilities combine documented version floors with the
    /// `status --porcelain=v2 --help` feature probe (RSF-88BA) and are
    /// cached in the returned handle (probe-once-per-identity).
    pub fn discover(explicit: &[PathBuf]) -> Option<Self> {
        Self::discover_from(explicit, KNOWN_GIT_PATHS, std::env::var("PATH").ok())
    }

    /// Discovery with injectable search lists, so tests can prove the
    /// trust order (explicit, then known, then `$PATH`) and the recorded
    /// [`BinarySource`] without touching the real installation paths.
    fn discover_from(
        explicit: &[PathBuf],
        known: &[&str],
        path_var: Option<String>,
    ) -> Option<Self> {
        let mut candidates: Vec<(PathBuf, BinarySource)> = explicit
            .iter()
            .map(|path| (path.clone(), BinarySource::Explicit))
            .collect();
        for known in known {
            let path = PathBuf::from(known);
            if !candidates.iter().any(|(candidate, _)| candidate == &path) {
                candidates.push((path, BinarySource::Known));
            }
        }
        if let Some(path_var) = path_var {
            for entry in std::env::split_paths(&path_var) {
                let path = entry.join("git");
                if !candidates.iter().any(|(candidate, _)| candidate == &path) {
                    candidates.push((path, BinarySource::Path));
                }
            }
        }
        for (candidate, source) in candidates {
            if let Some(found) = Self::probe_with_source(&candidate, source) {
                return Some(found);
            }
        }
        None
    }

    /// Probe one explicit binary path. Returns `None` when it is missing,
    /// not executable, or does not answer `--version`.
    ///
    /// After `--version`, the `status --porcelain=v2 --help` feature probe
    /// runs (RSF-88BA, GIT_QUAL §11): `porcelain_v2` is true only when the
    /// version floor holds AND the probe output names the porcelain
    /// feature with no option error. A failed probe keeps the handle (the
    /// version is still identifying) with the capability false — version
    /// alone is never feature evidence.
    pub fn probe(path: &Path) -> Option<Self> {
        Self::probe_with_source(path, BinarySource::Explicit)
    }

    /// Probe one binary path and record `source` on the handle. The
    /// `--version` spawn runs inside the shared envelope (timeout+kill,
    /// capture cap, sanitized environment) and must exit successfully.
    fn probe_with_source(path: &Path, source: BinarySource) -> Option<Self> {
        let mut version_cmd = Command::new(path);
        version_cmd.arg("--version");
        sanitize_git_env(&mut version_cmd);
        let outcome = spawn_enveloped(
            &mut version_cmd,
            false,
            GIT_SPAWN_TIMEOUT,
            MAX_CAPTURE_BYTES,
        )
        .ok()?;
        if !outcome.status.success() || outcome.truncated {
            return None;
        }
        let version = String::from_utf8_lossy(&outcome.stdout).trim().to_string();
        if !version.starts_with("git version ") {
            return None;
        }
        let tuple = parse_git_version(&version);
        let at_least =
            |major: u32, minor: u32| tuple.0 > major || (tuple.0 == major && tuple.1 >= minor);
        let feature_probe_ok = probe_porcelain_v2(path);
        Some(Self {
            path: path.to_path_buf(),
            source,
            capabilities: Capabilities {
                version,
                version_tuple: tuple,
                no_optional_locks: at_least(2, 14),
                porcelain_v2: at_least(2, 11) && feature_probe_ok,
                worktree_list: at_least(2, 7),
                feature_probe_ok,
            },
        })
    }

    /// Binary path selected at discovery.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Where discovery found this binary (explicit, well-known, or a
    /// recorded `$PATH` selection).
    #[must_use]
    pub fn source(&self) -> BinarySource {
        self.source
    }

    /// Cached capability record (probed once at discovery).
    #[must_use]
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Enumerate refs via `for-each-ref` (covers reftable stores).
    ///
    /// Symbolic targets are preserved from `%(symref)`. Peeled values are
    /// left `None`: peeling here would add object-store reads the caller
    /// did not request.
    pub fn refs(
        &self,
        git_dir: &Path,
        work_tree: Option<&Path>,
    ) -> crate::Result<Vec<RefObservation>> {
        let mut expected_algorithm = "sha1".to_string();
        if let Ok(format) = self.read_config(git_dir, work_tree, "extensions.objectFormat") {
            let format = format.trim().to_lowercase();
            if format == "sha256" {
                expected_algorithm = format;
            }
        }
        // NUL-separated triples: refname, objectname, symref-or-empty.
        let out = self.run(
            git_dir,
            work_tree,
            &[
                "for-each-ref",
                "--format=%(refname)%00%(objectname)%00%(symref)",
            ],
        )?;
        let text = String::from_utf8_lossy(&out);
        let mut refs = Vec::new();
        for line in text.lines() {
            let mut parts = line.split('\0');
            let (Some(name), Some(oid), symref) =
                (parts.next(), parts.next(), parts.next().unwrap_or_default())
            else {
                continue;
            };
            if name.is_empty() || oid.is_empty() {
                continue;
            }
            let target = if symref.is_empty() {
                RefTarget::Object(oid_from_hex(&expected_algorithm, oid))
            } else {
                RefTarget::Symbolic(symref.as_bytes().to_vec())
            };
            refs.push(RefObservation {
                name: name.as_bytes().to_vec(),
                target,
                peeled: None,
            });
        }
        Ok(refs)
    }

    /// Observe HEAD via `symbolic-ref` + `rev-parse` (no checkout touched).
    pub fn head(&self, git_dir: &Path, work_tree: Option<&Path>) -> crate::Result<HeadState> {
        let algorithm = self.object_format(git_dir, work_tree);
        match self.run(git_dir, work_tree, &["symbolic-ref", "-q", "HEAD"]) {
            Ok(out) => {
                let name = String::from_utf8_lossy(&out).trim().to_string();
                if name.is_empty() {
                    return Ok(HeadState::Unknown);
                }
                match self.run(git_dir, work_tree, &["rev-parse", "--verify", "HEAD"]) {
                    Ok(oid_out) => {
                        let hex = String::from_utf8_lossy(&oid_out).trim().to_string();
                        Ok(HeadState::Branch {
                            ref_name: name.into_bytes(),
                            oid: (!hex.is_empty()).then(|| oid_from_hex(&algorithm, &hex)),
                        })
                    }
                    Err(_) => Ok(HeadState::Unborn {
                        ref_name: name.into_bytes(),
                    }),
                }
            }
            Err(_) => match self.run(git_dir, work_tree, &["rev-parse", "HEAD"]) {
                Ok(oid_out) => {
                    let hex = String::from_utf8_lossy(&oid_out).trim().to_string();
                    if hex.is_empty() {
                        return Ok(HeadState::Unknown);
                    }
                    let peeled = self
                        .run(git_dir, work_tree, &["rev-parse", "HEAD^{}"])
                        .ok()
                        .map(|raw| String::from_utf8_lossy(&raw).trim().to_string())
                        .filter(|peeled| !peeled.is_empty() && *peeled != hex)
                        .map(|peeled| oid_from_hex(&algorithm, &peeled));
                    Ok(HeadState::Detached {
                        target: oid_from_hex(&algorithm, &hex),
                        peeled,
                    })
                }
                Err(_) => {
                    if git_dir.join("HEAD").is_file() {
                        Ok(HeadState::Invalid)
                    } else {
                        Ok(HeadState::Unknown)
                    }
                }
            },
        }
    }

    /// Status counts via `status --porcelain=v2`.
    ///
    /// `collapsed` selects `--untracked-files=normal` (one entry per
    /// untracked directory, spec `summary`) versus `all` (spec `full`).
    /// Returns `(staged, unstaged, untracked)`. Renames are disabled for
    /// parity with the gix counting policy.
    pub fn status_counts(
        &self,
        git_dir: &Path,
        work_tree: Option<&Path>,
        collapsed: bool,
    ) -> crate::Result<(u64, u64, u64)> {
        if !self.capabilities.porcelain_v2 {
            return Err(crate::Error::Git(format!(
                "{}installed git ({}) lacks status --porcelain=v2",
                super::UNSUPPORTED_MARKER,
                self.capabilities.version
            )));
        }
        let untracked = if collapsed {
            "--untracked-files=normal"
        } else {
            "--untracked-files=all"
        };
        let out = self.run(
            git_dir,
            work_tree,
            &["status", "--porcelain=v2", untracked, "--no-renames"],
        )?;
        let text = String::from_utf8_lossy(&out);
        let mut staged = 0u64;
        let mut unstaged = 0u64;
        let mut untracked_count = 0u64;
        for line in text.lines() {
            match line.as_bytes().first() {
                Some(b'1') | Some(b'2') => {
                    let fields: Vec<&str> = line.splitn(9, ' ').collect();
                    if fields.len() < 2 {
                        continue;
                    }
                    let xy = fields[1].as_bytes();
                    let staged_dirty = xy.first().is_some_and(|c| !matches!(c, b'.' | b'!'));
                    let unstaged_dirty = xy.get(1).is_some_and(|c| !matches!(c, b'.' | b'!'));
                    if staged_dirty {
                        staged += 1;
                    }
                    if unstaged_dirty {
                        unstaged += 1;
                    }
                }
                Some(b'?') => untracked_count += 1,
                _ => {}
            }
        }
        Ok((staged, unstaged, untracked_count))
    }

    /// Object format via config (defaults to sha1 when unset).
    fn object_format(&self, git_dir: &Path, work_tree: Option<&Path>) -> String {
        self.read_config(git_dir, work_tree, "extensions.objectFormat")
            .map(|value| {
                let value = value.trim().to_lowercase();
                if value == "sha256" {
                    value
                } else {
                    "sha1".to_string()
                }
            })
            .unwrap_or_else(|_| "sha1".to_string())
    }

    /// Read one config value without executing helpers.
    fn read_config(
        &self,
        git_dir: &Path,
        work_tree: Option<&Path>,
        key: &str,
    ) -> crate::Result<String> {
        let out = self.run(git_dir, work_tree, &["config", "--get", key])?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Run a read-only git subcommand with the safety envelope.
    ///
    /// Repository selection travels in argv (`--git-dir`, `--work-tree`);
    /// no shell is involved; locks, hooks, fsmonitor, and proxy/helpful
    /// network variables are neutralized. Only read-only subcommands are
    /// ever passed by this module (for-each-ref, symbolic-ref, rev-parse,
    /// status, config --get). The spawn runs inside the shared envelope
    /// (timeout+kill, capture cap, sanitized config environment,
    /// `-c help.format=man`); over-cap output and unexpected status fail
    /// rather than returning partial data.
    fn run(
        &self,
        git_dir: &Path,
        work_tree: Option<&Path>,
        args: &[&str],
    ) -> crate::Result<Vec<u8>> {
        let mut command = Command::new(&self.path);
        command.arg(format!("--git-dir={}", git_dir.display()));
        sanitize_git_env(&mut command);
        command.env("GIT_OPTIONAL_LOCKS", "0");
        if let Some(work_tree) = work_tree {
            command.arg(format!("--work-tree={}", work_tree.display()));
        } else {
            // No worktree: keep git from guessing one above the git dir.
            command.env("GIT_CEILING_DIRECTORIES", git_dir);
        }
        if self.capabilities.no_optional_locks {
            command.arg("--no-optional-locks");
        }
        command
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("help.format=man")
            .args(args);
        let outcome = spawn_enveloped(&mut command, false, GIT_SPAWN_TIMEOUT, MAX_CAPTURE_BYTES)
            .map_err(|reason| {
                crate::Error::Git(format!(
                    "installed git ({}): `{}` spawn failed: {reason}",
                    self.path.display(),
                    args.join(" ")
                ))
            })?;
        if outcome.truncated {
            return Err(crate::Error::Git(format!(
                "installed git ({}): `{}` output exceeded {MAX_CAPTURE_BYTES} bytes; \
                    refusing partial results",
                self.path.display(),
                args.join(" ")
            )));
        }
        if !outcome.status.success() {
            return Err(crate::Error::Git(format!(
                "installed git ({}): `{}` failed",
                self.path.display(),
                args.join(" ")
            )));
        }
        Ok(outcome.stdout)
    }
}

/// Ambient-environment sanitization shared by every installed-git spawn:
/// repository-selection, proxy, and config-redirect variables are
/// stripped so the ambient environment cannot redirect the repository,
/// inject configuration, or enable network use. Only the *redirects* are
/// stripped — file-based config still applies, so legitimate settings
/// (e.g. `safe.directory` exceptions) keep working. Unsetting
/// `GIT_CONFIG_COUNT` alone neutralizes `GIT_CONFIG_KEY_*`/`VALUE_*`
/// pairs, which git only reads when the count is set.
fn sanitize_git_env(cmd: &mut Command) {
    cmd.env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_PREFIX")
        .env_remove("GIT_HTTP_PROXY")
        .env_remove("GIT_HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("GIT_CONFIG_SYSTEM")
        .env_remove("GIT_CONFIG_COUNT");
}

/// Outcome of one enveloped spawn.
#[derive(Debug)]
struct SpawnOutcome {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

/// Spawn `cmd` with stdin nulled and enforce the shared envelope: a
/// `timeout` wall-clock budget (the child is killed past it) and
/// `cap_bytes` captured bytes per stream (past it the child is killed
/// and `truncated` is set; callers must fail, never use partial
/// output). Stdout is always captured; stderr only when `capture_stderr`
/// (otherwise it is discarded, never inherited). Reader threads keep a
/// verbose stderr from wedging stdout.
fn spawn_enveloped(
    cmd: &mut Command,
    capture_stderr: bool,
    timeout: Duration,
    cap_bytes: u64,
) -> Result<SpawnOutcome, String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(if capture_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;
    let stdout_thread = child
        .stdout
        .take()
        .map(|pipe| std::thread::spawn(move || read_capped(pipe, cap_bytes)));
    let stderr_thread = child
        .stderr
        .take()
        .map(|pipe| std::thread::spawn(move || read_capped(pipe, cap_bytes)));
    let start = Instant::now();
    let mut stdout_thread = stdout_thread;
    let mut stderr_thread = stderr_thread;
    let mut early_stdout: Option<(Vec<u8>, bool)> = None;
    let mut early_stderr: Option<(Vec<u8>, bool)> = None;
    let status = loop {
        match child.try_wait().map_err(|e| format!("wait failed: {e}"))? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    // Reader threads are detached on timeout: joining
                    // could wedge on a pipe a grandchild inherited. They
                    // own their buffers and exit at EOF.
                    return Err(format!("timed out after {timeout:?}; child killed"));
                }
                // Prompt over-cap kill: a finished reader with the child
                // still alive means the child is wedged writing past the
                // cap (or slow to exit after EOF — the truncation flags
                // tell which). Each side is independent: one capped
                // stream must not wait on the other.
                let mut cap_hit = false;
                if stdout_thread.as_ref().is_some_and(|h| h.is_finished()) {
                    let (out, trunc) = join_reader(stdout_thread.take(), cap_bytes, "stdout")?;
                    cap_hit |= trunc;
                    early_stdout = Some((out, trunc));
                }
                if stderr_thread.as_ref().is_some_and(|h| h.is_finished()) {
                    let (err, trunc) = join_reader(stderr_thread.take(), cap_bytes, "stderr")?;
                    cap_hit |= trunc;
                    early_stderr = Some((err, trunc));
                }
                if cap_hit {
                    let _ = child.kill();
                    let status = child.wait().map_err(|e| format!("wait failed: {e}"))?;
                    // Unfinished readers are detached (see timeout path);
                    // their content is moot — callers fail on `truncated`.
                    let (stdout, _) = early_stdout.unwrap_or_default();
                    let (stderr, _) = early_stderr.unwrap_or_default();
                    return Ok(SpawnOutcome {
                        status,
                        stdout,
                        stderr,
                        truncated: true,
                    });
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    };
    let (stdout, stdout_truncated) = match early_stdout {
        Some(pair) => pair,
        None => join_reader(stdout_thread, cap_bytes, "stdout")?,
    };
    let (stderr, stderr_truncated) = match early_stderr {
        Some(pair) => pair,
        None => join_reader(stderr_thread, cap_bytes, "stderr")?,
    };
    Ok(SpawnOutcome {
        status,
        stdout,
        stderr,
        truncated: stdout_truncated || stderr_truncated,
    })
}

/// Read one child pipe up to `cap_bytes + 1` (the extra byte is the
/// truncation tripwire; the waiter kills a child that is still alive
/// once its readers finish past the cap).
fn read_capped(
    pipe: impl Read + Send + 'static,
    cap_bytes: u64,
) -> (std::io::Result<usize>, Vec<u8>) {
    let mut buf = Vec::new();
    let result = pipe.take(cap_bytes.saturating_add(1)).read_to_end(&mut buf);
    (result, buf)
}

/// Join one output-reader thread, reporting whether its stream passed
/// the capture cap.
fn join_reader(
    thread: Option<std::thread::JoinHandle<(std::io::Result<usize>, Vec<u8>)>>,
    cap_bytes: u64,
    what: &str,
) -> Result<(Vec<u8>, bool), String> {
    match thread {
        Some(handle) => {
            let (result, buf) = handle.join().map_err(|_| format!("{what} reader failed"))?;
            result.map_err(|e| format!("{what} read failed: {e}"))?;
            let truncated = buf.len() as u64 > cap_bytes;
            Ok((buf, truncated))
        }
        None => Ok((Vec::new(), false)),
    }
}

/// Feature probe for `status --porcelain=v2` (RSF-88BA, GIT_QUAL §11):
/// run `git status --porcelain=v2 --help` and require the expected exit
/// status plus combined output naming the porcelain feature with no
/// option error. The Apple-Git exception is narrow: stock git exits 0
/// with help text, Apple Git exits 129 with a usage line — any other
/// status fails the probe even when the output text matches.
///
/// The probe runs inside a fresh repository owned by this probe: real
/// git answers `fatal: not a git repository` (exit 128, without
/// validating options at all — bogus options fail identically) outside
/// a repo, so ambient-CWD probing would misread real git as incapable
/// whenever the process starts outside a repository. `LC_ALL=C` pins
/// English diagnostics so error matching is locale-independent. Pagers
/// are neutralized and `-c help.format=man` forbids browser renderers
/// (a `help.format=web` config would otherwise open a browser); both
/// spawns run inside the shared envelope (timeout+kill, capture cap,
/// sanitized config environment).
fn probe_porcelain_v2(path: &Path) -> bool {
    let repo = tempfile::tempdir().ok();
    if let Some(dir) = repo.as_ref() {
        // Best effort: fixtures answer `init` from their canned script
        // (outcome ignored — the probe argv below is the verdict either
        // way); real git always inits an empty temp dir.
        let mut init = Command::new(path);
        init.arg("init")
            .arg("-q")
            .current_dir(dir.path())
            .env("LC_ALL", "C");
        sanitize_git_env(&mut init);
        let _ = spawn_enveloped(&mut init, false, GIT_SPAWN_TIMEOUT, MAX_CAPTURE_BYTES);
    }
    let mut probe = Command::new(path);
    probe
        .arg("-c")
        .arg("help.format=man")
        .arg("status")
        .arg("--porcelain=v2")
        .arg("--help")
        .env("LC_ALL", "C")
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env("MANPAGER", "cat");
    sanitize_git_env(&mut probe);
    if let Some(dir) = repo.as_ref() {
        probe.current_dir(dir.path());
    }
    match spawn_enveloped(&mut probe, true, GIT_SPAWN_TIMEOUT, MAX_CAPTURE_BYTES) {
        Ok(outcome) => {
            if outcome.truncated {
                return false;
            }
            if !matches!(outcome.status.code(), Some(0) | Some(129)) {
                return false;
            }
            let mut text = String::from_utf8_lossy(&outcome.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&outcome.stderr));
            let lower = text.to_ascii_lowercase();
            lower.contains("porcelain")
                && !lower.contains("unknown option")
                && !lower.contains("unsupported porcelain")
        }
        Err(_) => false,
    }
}

/// Parse `git version 2.47.1`-style banners into a version tuple.
fn parse_git_version(banner: &str) -> (u32, u32, u32) {
    let numeric = banner
        .strip_prefix("git version ")
        .unwrap_or_default()
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()
        .unwrap_or_default();
    let mut parts = numeric.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

/// Build an [`Oid`] from hex, tolerating either hash length.
fn oid_from_hex(algorithm: &str, hex: &str) -> Oid {
    let hex = hex.trim().to_lowercase();
    let algorithm = if hex.len() == 64 {
        "sha256".to_string()
    } else if hex.len() == 40 {
        "sha1".to_string()
    } else {
        algorithm.to_string()
    };
    Oid { algorithm, hex }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Write an executable `git` fixture: `--version` prints `banner`,
    /// every other argv runs `body`.
    fn git_fixture(dir: &Path, name: &str, banner: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\necho \"{banner}\"\nexit 0\nfi\n{body}\n"
        );
        std::fs::write(&path, script).expect("write fixture");
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod");
        path
    }

    const CAPABLE_BODY: &str = "echo \" --porcelain[<version>]  machine-readable output\"\nexit 0";

    #[test]
    fn envelope_kills_past_timeout() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("exec sleep 5");
        let err = spawn_enveloped(&mut cmd, false, Duration::from_millis(100), 1024)
            .expect_err("a 5s sleeper must exceed a 100ms budget");
        assert!(err.contains("timed out"), "{err}");
    }

    #[test]
    fn envelope_caps_captured_bytes() {
        let mut cmd = Command::new("head");
        cmd.args(["-c", "4096", "/dev/zero"]);
        let outcome =
            spawn_enveloped(&mut cmd, false, Duration::from_secs(10), 128).expect("spawn");
        assert!(outcome.truncated, "4 KiB past a 128-byte cap must trip");
        assert_eq!(outcome.stdout.len(), 129);
    }

    #[test]
    fn sanitize_strips_config_redirects() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("echo \"global=${GIT_CONFIG_GLOBAL-unset} count=${GIT_CONFIG_COUNT-unset}\"");
        cmd.env("GIT_CONFIG_GLOBAL", "/evil/gitconfig");
        cmd.env("GIT_CONFIG_COUNT", "1");
        sanitize_git_env(&mut cmd);
        let outcome =
            spawn_enveloped(&mut cmd, false, Duration::from_secs(10), 1024).expect("spawn");
        let text = String::from_utf8_lossy(&outcome.stdout);
        assert!(text.contains("global=unset"), "{text}");
        assert!(text.contains("count=unset"), "{text}");
    }

    #[test]
    fn discover_records_path_selection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let git = git_fixture(dir.path(), "git", "git version 2.47.1", CAPABLE_BODY);
        let path_var = dir.path().to_str().expect("utf8").to_string();
        let found = FallbackGit::discover_from(&[], &[], Some(path_var)).expect("discover");
        assert_eq!(found.source(), BinarySource::Path);
        assert_eq!(found.path(), git.as_path());
    }

    #[test]
    fn discover_prefers_trusted_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let explicit = git_fixture(
            dir.path(),
            "git-explicit",
            "git version 1.0.0-explicit",
            CAPABLE_BODY,
        );
        let known_dir = tempfile::tempdir().expect("known tempdir");
        let known = git_fixture(
            known_dir.path(),
            "git",
            "git version 1.0.0-known",
            CAPABLE_BODY,
        );
        let path_dir = tempfile::tempdir().expect("path tempdir");
        git_fixture(
            path_dir.path(),
            "git",
            "git version 1.0.0-path",
            CAPABLE_BODY,
        );
        let known_str = known.to_str().expect("utf8");
        let path_var = path_dir.path().to_str().expect("utf8").to_string();
        let found = FallbackGit::discover_from(&[explicit], &[known_str], Some(path_var.clone()))
            .expect("discover");
        assert_eq!(found.source(), BinarySource::Explicit);
        assert!(found.capabilities().version.contains("explicit"));
        let found =
            FallbackGit::discover_from(&[], &[known_str], Some(path_var)).expect("discover");
        assert_eq!(found.source(), BinarySource::Known);
        assert!(found.capabilities().version.contains("known"));
    }

    #[test]
    fn probe_reports_explicit_source() {
        let dir = tempfile::tempdir().expect("tempdir");
        let git = git_fixture(dir.path(), "git", "git version 2.47.1", CAPABLE_BODY);
        let found = FallbackGit::probe(&git).expect("probe");
        assert_eq!(found.source(), BinarySource::Explicit);
    }

    #[test]
    fn feature_probe_rejects_unexpected_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = "echo \" --porcelain[<version>]  machine-readable output\"";
        // Stock git (0) and Apple Git (129) pass with the marker ...
        for (name, code) in [("git-zero", 0), ("git-apple", 129)] {
            let git = git_fixture(
                dir.path(),
                name,
                "git version 2.47.1",
                &format!("{marker}\nexit {code}"),
            );
            assert!(
                probe_porcelain_v2(&git),
                "exit {code} with the marker must pass"
            );
        }
        // ... any other status fails even when the text matches.
        for (name, code) in [("git-one", 1), ("git-fatal", 128)] {
            let git = git_fixture(
                dir.path(),
                name,
                "git version 2.47.1",
                &format!("{marker}\nexit {code}"),
            );
            assert!(
                !probe_porcelain_v2(&git),
                "exit {code} with the marker must fail"
            );
        }
    }
}
