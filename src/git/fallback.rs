//! Installed-git compatibility backend (spec §9, GIT_QUAL §11).
//!
//! Triggered only when gix reports a structural gap: reftable ref storage,
//! SSH-alias remotes needing `Host` resolution, unparseable index or
//! worktree admin, or object-format gaps. Never a per-directory scanner.
//!
//! Safety contract: explicit candidate paths (group/other-writable
//! `$PATH` entries refused outright, never probed), argv arrays with no
//! shell interpolation, `GIT_OPTIONAL_LOCKS=0`, `--no-optional-locks`
//! where supported, repo-selected execution neutralized per vector
//! (hooks, fsmonitor, pager, ssh/askpass, templates, includes via
//! `-c`/env/flags; clean/smudge/process filter drivers by
//! detect-and-refuse), `GIT_HTTP_*`/proxy variables unset, no
//! fetch/clone/pull/push subcommand ever invoked, and no configured
//! filter/fsmonitor/helper executed (cases needing one stay
//! `partial`/`unsupported`).
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

use std::cell::RefCell;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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

/// Post-exit reader-drain budget (RSF-FALLBACK-HELPER-SECURITY(2)): after
/// the child exits its pipes should EOF promptly. A descendant holding a
/// pipe open past this budget fails the call as an explicit incomplete
/// gap — never a hang, never silently partial bytes.
pub const POST_EXIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Grace to join output readers after a kill (timeout, cap, cancel, or
/// drain paths). Readers still unfinished past it are detached loudly and
/// reported stuck; the helper charge is kept (termination unproven).
const READER_JOIN_GRACE: Duration = Duration::from_millis(500);

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

/// Cooperative cancellation for fallback waits
/// (RSF-FALLBACK-HELPER-SECURITY(5)): SIGINT or a task deadline ends even
/// stuck readers. Every wait slice (ledger wait, child wait, reader joins,
/// post-exit drain) polls [`WaitCancel::cancelled`]; a cancelled wait
/// terminates (group-kill unless the child is already reaped — the drain
/// paths skip the kill, their pgid may be reused), grace-joins, and fails
/// loudly — never hangs, never leaks silently.
#[derive(Clone)]
pub struct WaitCancel {
    check: Arc<dyn Fn() -> bool + Send + Sync>,
    deadline: Option<Instant>,
}

impl WaitCancel {
    /// A token that never cancels (probes and detached use).
    pub fn never() -> Self {
        Self {
            check: Arc::new(|| false),
            deadline: None,
        }
    }

    /// Cancel when `check` fires or `deadline` passes (either; `None`
    /// disables that arm).
    pub fn new(
        check: impl Fn() -> bool + Send + Sync + 'static,
        deadline: Option<Instant>,
    ) -> Self {
        Self {
            check: Arc::new(check),
            deadline,
        }
    }

    /// True once cancelled (flag fired or deadline passed).
    pub fn cancelled(&self) -> bool {
        if self.deadline.is_some_and(|end| Instant::now() >= end) {
            return true;
        }
        (self.check)()
    }
}

impl Default for WaitCancel {
    fn default() -> Self {
        Self::never()
    }
}

impl std::fmt::Debug for WaitCancel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WaitCancel")
            .field("cancelled", &self.cancelled())
            .field("deadline", &self.deadline)
            .finish()
    }
}

thread_local! {
    /// Dynamically scoped wait token: [`spawn_enveloped`] reads this when
    /// no explicit token is passed, so call-sites that cannot change
    /// signatures (unsupported-gap fallbacks) still inherit SIGINT and the
    /// task deadline via [`with_wait_cancel`].
    static CURRENT_WAIT_CANCEL: RefCell<Option<WaitCancel>> = const { RefCell::new(None) };
}

/// Run `f` with `cancel` as the wait token for every fallback spawn on
/// this thread (nesting-safe: the previous token is restored).
pub fn with_wait_cancel<R>(cancel: &WaitCancel, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<WaitCancel>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CURRENT_WAIT_CANCEL.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let previous = CURRENT_WAIT_CANCEL.with(|slot| slot.borrow_mut().replace(cancel.clone()));
    let _restore = Restore(previous);
    f()
}

/// The scoped wait token, or a never-cancelling token outside a scope.
fn current_wait_cancel() -> WaitCancel {
    CURRENT_WAIT_CANCEL.with(|slot| slot.borrow().clone().unwrap_or_else(WaitCancel::never))
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
    identity: BinaryIdentity,
}

/// Executable identity pinned at probe time and re-verified before every
/// spawn (XSEC-02): a binary swapped, replaced, re-permissioned, or
/// modified in place between probe and spawn is refused, never executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BinaryIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    len: u64,
    mtime_nanos: i128,
}

/// Capture the current identity of `path`: a regular executable file only.
/// `None` refuses directories, links, special files, and non-executables.
#[cfg(unix)]
fn binary_identity(path: &Path) -> Option<BinaryIdentity> {
    use std::os::unix::fs::MetadataExt;

    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.file_type().is_file() || (md.mode() & 0o111) == 0 {
        return None;
    }
    Some(BinaryIdentity {
        dev: md.dev(),
        ino: md.ino(),
        uid: md.uid(),
        mode: md.mode(),
        len: md.len(),
        mtime_nanos: mtime_nanos(&md),
    })
}

/// Capture the current identity of `path` (non-unix): regular files only,
/// with size+mtime binding the content.
#[cfg(not(unix))]
fn binary_identity(path: &Path) -> Option<BinaryIdentity> {
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.file_type().is_file() {
        return None;
    }
    Some(BinaryIdentity {
        dev: 0,
        ino: 0,
        uid: 0,
        mode: 0,
        len: md.len(),
        mtime_nanos: mtime_nanos(&md),
    })
}

/// Modification time as epoch nanos for identity binding (0 when unknown).
fn mtime_nanos(md: &std::fs::Metadata) -> i128 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

/// Validate one git binary path: absolute, canonical (no `.`/`..`/link
/// misbinding), a regular file, executable. Empty, relative, missing,
/// directory, or non-executable paths are refused (PATH-GIT-06). The
/// canonical path is what runs; the discovered spelling stays reported.
fn canonical_executable(path: &Path) -> Option<PathBuf> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return None;
    }
    let canonical = path.canonicalize().ok()?;
    if !canonical.is_absolute() {
        return None;
    }
    let md = std::fs::symlink_metadata(&canonical).ok()?;
    if !md.file_type().is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if (md.permissions().mode() & 0o111) == 0 {
            return None;
        }
    }
    Some(canonical)
}

/// True when a `$PATH` entry may supply a `git` binary
/// (RSF-FALLBACK-HELPER-SECURITY(7)): absolute, canonicalizable, a
/// directory, and NOT group/other-writable. A writable entry lets another
/// user swap the binary between probe and spawn, so it is refused before
/// probing (never executed). Explicit and well-known paths are
/// operator-trusted and exempt. Residual, stated honestly: the entry
/// owner (or root) can still swap the file inside the microsecond
/// verify→exec window; pre-spawn identity re-verification (XSEC-02)
/// shrinks the race to that window, it cannot close it.
#[cfg(unix)]
fn path_entry_trusted(entry: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    if entry.as_os_str().is_empty() || !entry.is_absolute() {
        return false;
    }
    let canonical = match entry.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) => return false,
    };
    let md = match std::fs::symlink_metadata(&canonical) {
        Ok(md) => md,
        Err(_) => return false,
    };
    if !md.file_type().is_dir() {
        return false;
    }
    // Mode bits, not access checks: deterministic regardless of the
    // running uid (root passes access checks on any mode).
    (md.mode() & 0o022) == 0
}

/// True when a `$PATH` entry may supply a `git` binary (non-unix): no
/// mode bits exist, so only the empty/relative refusal applies
/// (documented residual: writable-entry refusal is unix-only).
#[cfg(not(unix))]
fn path_entry_trusted(entry: &Path) -> bool {
    !entry.as_os_str().is_empty() && entry.is_absolute()
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
    /// `pub` as the integration seam for `tests/fail_fallback.rs` (the
    /// production path, [`FallbackGit::discover`], reads the real `$PATH`).
    pub fn discover_from(
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
                // Reject untrusted `$PATH` entries (PATH-GIT-06,
                // RSF-FALLBACK-HELPER-SECURITY(7)): empty/relative entries
                // would resolve a binary other than the recorded
                // candidate, and group/other-writable directories let
                // another user swap the binary between probe and spawn.
                if !path_entry_trusted(&entry) {
                    continue;
                }
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
        // Bind the executable before any spawn: the canonical path is
        // what runs, and its identity must be unchanged across the
        // version and feature probes (PATH-GIT-06, XSEC-02). The
        // discovered spelling stays reported in `path`.
        let canonical = match canonical_executable(path) {
            Some(c) => c,
            None => {
                eprintln!(
                    "repo-scan: git probe: canonical_executable failed for {}",
                    path.display()
                );
                return None;
            }
        };
        let identity = match binary_identity(&canonical) {
            Some(id) => id,
            None => {
                eprintln!(
                    "repo-scan: git probe: binary_identity failed for {}",
                    canonical.display()
                );
                return None;
            }
        };
        let mut version_cmd = Command::new(&canonical);
        version_cmd.arg("--version");
        // Sanitize-only (no repo neutralization): `--version` runs with no
        // `--git-dir`, prints one line, and never pages, reads worktree
        // content, or executes helpers — there is no repo-selected vector
        // to neutralize on this argv.
        sanitize_git_env(&mut version_cmd);
        let outcome =
            match spawn_enveloped(&mut version_cmd, true, GIT_SPAWN_TIMEOUT, MAX_CAPTURE_BYTES) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("repo-scan: git probe: version spawn failed: {e}");
                    return None;
                }
            };
        if !outcome.status.success() || outcome.truncated {
            eprintln!(
                "repo-scan: git probe: version command failed: status={:?}, truncated={}, stderr={}",
                outcome.status.code(),
                outcome.truncated,
                String::from_utf8_lossy(&outcome.stderr)
            );
            return None;
        }
        let version = String::from_utf8_lossy(&outcome.stdout).trim().to_string();
        if !version.starts_with("git version ") {
            eprintln!("repo-scan: git probe: unexpected version output: {version:?}");
            return None;
        }
        let tuple = parse_git_version(&version);
        let at_least =
            |major: u32, minor: u32| tuple.0 > major || (tuple.0 == major && tuple.1 >= minor);
        let current_id = binary_identity(&canonical);
        if current_id != Some(identity) {
            eprintln!(
                "repo-scan: git probe: identity changed before feature probe: before={:?}, after={:?}",
                Some(identity),
                current_id
            );
            return None;
        }
        let feature_probe_ok = probe_porcelain_v2(&canonical);
        let current_id_after = binary_identity(&canonical);
        if current_id_after != Some(identity) {
            eprintln!(
                "repo-scan: git probe: identity changed after feature probe: before={:?}, after={:?}",
                Some(identity),
                current_id_after
            );
            return None;
        }
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
            identity,
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
    ///
    /// FIXREADY4 F: both this spawn and its driver guard run under
    /// [`StatusConfigIsolation`] (empty global/system config, empty HOME,
    /// no XDG config), so a repository-selected `filter=` attribute can
    /// never resolve to an operator-configured helper — the installed-git
    /// twin of the gix isolated open. Repo-local drivers still load and
    /// are refused by the guard before any content-converting read.
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
        // Isolation first (fail closed when the empty-config dir cannot
        // be built): the guard and the status read must observe the
        // identical config scope, or the guard proves nothing.
        let isolation = StatusConfigIsolation::create()?;
        // Repo-selected conversion drivers (filter.<name>.clean/smudge/
        // process) would execute during worktree-content comparison on git
        // versions that convert; driver names are unbounded so `-c` cannot
        // enumerate them — refuse and stay `unsupported`, never execute.
        if self.filters_configured(git_dir, work_tree, &isolation) {
            return Err(crate::Error::Git(format!(
                "{}installed git ({}) refuses status: executable filter drivers configured; refusing to execute",
                super::UNSUPPORTED_MARKER,
                self.capabilities.version
            )));
        }
        let untracked = if collapsed {
            "--untracked-files=normal"
        } else {
            "--untracked-files=all"
        };
        let out = self.run_inner(
            git_dir,
            work_tree,
            &["status", "--porcelain=v2", untracked, "--no-renames"],
            Some(&isolation),
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

    /// Effective-config scan for executable filter drivers
    /// (RSF-FALLBACK-HELPER-SECURITY(1), FIXREADY4 F): `config --list`
    /// never executes helpers itself, and it sees through `include.path`
    /// chains, so a `filter.<driver>.clean|smudge|process` command in the
    /// effective config refuses worktree-content reads. The spawn runs
    /// under the SAME [`StatusConfigIsolation`] as the status read, so
    /// the guard observes exactly what git will observe: global/system
    /// drivers are neutralized away (nothing to refuse), repo-local and
    /// included drivers still show and refuse. Scoping to `--local`
    /// would blind the guard on git versions that ignore the redirect
    /// variables — the effective list fails closed there instead (a
    /// leaked global driver refuses rather than executes). Any scan
    /// error fails closed (unknown → refuse).
    ///
    /// FIXREADY6 F2b: the parent effective list never shows
    /// submodule-scope drivers, but installed `git status` descends
    /// into submodule worktrees and loads their configs — so a clean
    /// parent list additionally requires the submodule-scope scan
    /// ([`Self::submodule_filters_configured`]) to pass. Submodule
    /// configs load WITH repo-local includes (isolation redirects only
    /// global/system/HOME; `-c` cannot disable includes), so the
    /// submodule leg follows `[include]`/`[includeIf]` chains —
    /// includeIf unconditionally (over-approximation, safe direction).
    fn filters_configured(
        &self,
        git_dir: &Path,
        work_tree: Option<&Path>,
        isolation: &StatusConfigIsolation,
    ) -> bool {
        let parent_hit =
            match self.run_inner(git_dir, work_tree, &["config", "--list"], Some(isolation)) {
                Ok(out) => String::from_utf8_lossy(&out).lines().any(|line| {
                    line.split_once('=')
                        .is_some_and(|(key, _)| Self::is_exec_filter_key(&key.to_ascii_lowercase()))
                }),
                Err(e) => {
                    eprintln!(
                    "repo-scan: fallback: filter-driver scan failed, refusing content reads: {e}"
                );
                    return true;
                }
            };
        if parent_hit {
            return true;
        }
        Self::submodule_filters_configured(git_dir, work_tree)
    }

    /// Submodule-scope driver scan (FIXREADY6 F2b): installed `git
    /// status` descends RECURSIVELY into submodule worktrees (proven:
    /// drivers in absorbed, non-absorbed depth-1, and nested depth-2
    /// external configs all execute), loading each submodule's own
    /// config — which the parent effective `config --list` never shows
    /// (FAIL-2). Mirrors the descent set: absorbed `modules/` trees
    /// under the git and common dirs (recursive file scan) plus
    /// recursive live enumeration through worktree `.git` files (for
    /// non-absorbed layouts the `modules/<name>` construction cannot
    /// see). True = refuse conversion. Every uncertainty refuses:
    /// unreadable configs/dirs, breached caps, unresolvable gitdirs,
    /// unopenable repos, and any submodule past the depth cap.
    ///
    /// Boundary vs the gix-side guard (`filter_driver_gap_for_repo`,
    /// depth-1 live + proceed-on-enumeration-error): different
    /// executors need different proof. gix fails its own
    /// enumeration/resolution pre-conversion (loud, safe to proceed
    /// past), while installed git is independently lenient (it may
    /// descend where gix stumbles), so this guard refuses on every
    /// miss. Post-F2a the fallback is the only status path for
    /// submodule repos, so its guard is the authoritative one. Every
    /// submodule config is assessed WITH its include chain (installed
    /// git loads them; `-c` cannot disable includes).
    fn submodule_filters_configured(git_dir: &Path, work_tree: Option<&Path>) -> bool {
        // Absorbed trees (recursive, bounded, fail-closed).
        if super::scan_modules_tree_with_includes(&git_dir.join("modules"), 0).refuses() {
            return true;
        }
        let common_dir = match Self::common_dir_for(git_dir) {
            Some(common_dir) => common_dir,
            None => return true,
        };
        if common_dir.as_path() != git_dir
            && super::scan_modules_tree_with_includes(&common_dir.join("modules"), 0).refuses()
        {
            return true;
        }
        let Some(work_tree) = work_tree else {
            // No worktree: submodule checkouts cannot resolve, so any
            // registration (via worktree, index, or HEAD `.gitmodules`)
            // — or an unprovable registration set — refuses.
            return Self::registers_submodules(git_dir);
        };
        Self::live_submodule_filters_configured(git_dir, work_tree)
    }

    /// Resolve the common dir for the absorbed-tree scan: `git_dir`
    /// plus its `commondir` pointer when present. Absent pointer =
    /// `git_dir` itself. Present-but-unreadable/unparseable/empty =
    /// `None` (fail closed: the absorbed set is unprovable).
    fn common_dir_for(git_dir: &Path) -> Option<PathBuf> {
        let pointer = git_dir.join("commondir");
        let text = match super::read_bounded_string(&pointer, super::MAX_GIT_CONTROL_BYTES) {
            Some(text) => text,
            None if std::fs::symlink_metadata(&pointer).is_err() => {
                return Some(git_dir.to_path_buf());
            }
            None => return None,
        };
        let target = text.lines().next().unwrap_or_default().trim();
        if target.is_empty() {
            return None;
        }
        let target_path = Path::new(target);
        if target_path.is_absolute() {
            Some(target_path.to_path_buf())
        } else {
            Some(git_dir.join(target_path))
        }
    }

    /// True when `git_dir` registers any submodule (or registration is
    /// unprovable). Bare-repo path of
    /// [`Self::submodule_filters_configured`].
    fn registers_submodules(git_dir: &Path) -> bool {
        let repo = match super::open_repo(git_dir) {
            Ok(repo) => repo,
            Err(_) => return true,
        };
        let submodules = match repo.submodules() {
            Ok(submodules) => submodules,
            Err(_) => return true,
        };
        match submodules {
            Some(mut iter) => iter.next().is_some(),
            None => false,
        }
    }

    /// Recursive live enumeration of submodule gitdirs (non-absorbed
    /// layouts): each enumerated gitdir's own configs plus its nested
    /// absorbed tree are scanned, then its submodules are enumerated in
    /// turn — mirroring installed git's recursive descent through
    /// worktree `.git` files (`git_dir_try_old_form`, NOT the
    /// `modules/<name>` construction, which is blind to external
    /// gitdirs). True = refuse. Bounded by
    /// `MAX_FILTER_SUBMODULE_SCAN` total visits and
    /// `MAX_FILTER_MODULES_DEPTH` descent depth; past either cap, or on
    /// any open/enumeration/resolution failure, refuse. Absent gitdirs
    /// (uninitialized submodules git cannot descend into) are skipped.
    ///
    /// The superproject worktree is carried down the recursion
    /// (`set_workdir` per level): a submodule gitdir opened standalone
    /// has no usable `core.worktree`, so without the carried worktree
    /// nested `.git` files would resolve against nothing (or the
    /// process cwd) and nested external drivers would be missed —
    /// while git always resolves them against the superproject
    /// worktree. The re-pointed repos are enumeration-only (never
    /// status-scanned); absent worktrees (deinitialized submodules git
    /// cannot descend into) are skipped.
    ///
    /// Top-level exception: when the top gitdir itself cannot open,
    /// git fails loudly downstream on the same broken gitdir — so the
    /// scan proceeds UNLESS a worktree `.gitmodules` is present (any
    /// registration git could descend into refuses instead). Without
    /// that file there is no registration git could read (index/HEAD
    /// need the same unopenable gitdir). Nested opens always refuse on
    /// failure: a present-but-unopenable nested gitdir is unprovable.
    fn live_submodule_filters_configured(git_dir: &Path, work_tree: &Path) -> bool {
        let mut stack = vec![(git_dir.to_path_buf(), work_tree.to_path_buf(), 0u8)];
        let mut seen = 0usize;
        while let Some((dir, worktree, depth)) = stack.pop() {
            if !worktree.is_dir() {
                continue;
            }
            let mut repo = match super::open_repo(&dir) {
                Ok(repo) => repo,
                Err(_) if depth == 0 => {
                    if std::fs::symlink_metadata(worktree.join(".gitmodules")).is_ok() {
                        return true;
                    }
                    continue;
                }
                Err(_) => return true,
            };
            if repo.set_workdir(worktree).is_err() {
                return true;
            }
            let submodules = match repo.submodules() {
                Ok(submodules) => submodules,
                Err(_) => return true,
            };
            let Some(iter) = submodules else {
                continue;
            };
            for sub in iter {
                seen += 1;
                if seen > super::MAX_FILTER_SUBMODULE_SCAN {
                    return true;
                }
                // try_old_form resolves through the worktree `.git`
                // file/dir (external gitdirs included); `git_dir()`
                // alone only constructs `modules/<name>`.
                let sub_gitdir = match sub.git_dir_try_old_form() {
                    Ok(sub_gitdir) => sub_gitdir,
                    Err(_) => return true,
                };
                // Absent gitdir (uninitialized submodule): git cannot
                // descend into nothing, so there is nothing to prove.
                if !sub_gitdir.is_dir() {
                    continue;
                }
                if super::scan_repo_filter_configs_with_includes(&sub_gitdir, &sub_gitdir).refuses()
                    || super::scan_modules_tree_with_includes(&sub_gitdir.join("modules"), 0)
                        .refuses()
                {
                    return true;
                }
                // A submodule existing past the depth cap has
                // unprovable children: refuse (fail closed).
                if depth + 1 > super::MAX_FILTER_MODULES_DEPTH {
                    return true;
                }
                let sub_worktree = match sub.work_dir() {
                    Ok(sub_worktree) => sub_worktree,
                    Err(_) => return true,
                };
                stack.push((sub_gitdir, sub_worktree, depth + 1));
            }
        }
        false
    }

    /// True when `key` (lowercased `section.name.attr` from `config
    /// --list`) selects code git would execute for a filter driver:
    /// clean/smudge/process commands. `required` and other flags are
    /// inert; diff/merge/external drivers never run under the read-only
    /// subcommands this module invokes (no diff display, no merge).
    fn is_exec_filter_key(key: &str) -> bool {
        let mut parts = key.split('.');
        match (parts.next(), parts.next_back()) {
            (Some("filter"), Some(attr)) => matches!(attr, "clean" | "smudge" | "process"),
            _ => false,
        }
    }

    /// Run a read-only git subcommand with the safety envelope.
    ///
    /// Repository selection travels in argv (`--git-dir`, `--work-tree`);
    /// no shell is involved; locks and every repo-selected execution
    /// vector (hooks, fsmonitor, pager, ssh/askpass, includes) are
    /// neutralized via [`apply_repo_neutralization`], and proxy/helpful
    /// network variables are stripped. Only read-only subcommands are
    /// ever passed by this module (for-each-ref, symbolic-ref, rev-parse,
    /// status, config). The spawn runs inside the shared envelope
    /// (timeout+kill, capture cap, sanitized config environment,
    /// scoped wait token); over-cap output and unexpected status fail
    /// rather than returning partial data.
    fn run(
        &self,
        git_dir: &Path,
        work_tree: Option<&Path>,
        args: &[&str],
    ) -> crate::Result<Vec<u8>> {
        self.run_inner(git_dir, work_tree, args, None)
    }

    /// [`run`] with optional status config isolation (FIXREADY4 F): when
    /// `isolation` is `Some`, the spawn additionally observes empty
    /// global/system config, an empty HOME, and no XDG config — applied
    /// AFTER [`sanitize_git_env`] so the isolation values win. Used only
    /// by the content-converting status read and its driver guard, which
    /// share one isolation so both observe the identical config scope.
    fn run_inner(
        &self,
        git_dir: &Path,
        work_tree: Option<&Path>,
        args: &[&str],
        isolation: Option<&StatusConfigIsolation>,
    ) -> crate::Result<Vec<u8>> {
        // Re-bind the executable before every spawn (XSEC-02): the
        // binary must still be the probed (dev, ino, owner, mode, size,
        // mtime) — a swapped, replaced, or re-permissioned binary is
        // refused, never spawned.
        let canonical = self.path.canonicalize().map_err(|e| {
            crate::Error::Git(format!(
                "installed git ({}): refusing spawn: cannot resolve binary: {e}",
                self.path.display()
            ))
        })?;
        if binary_identity(&canonical) != Some(self.identity) {
            return Err(crate::Error::Git(format!(
                "installed git ({}): refusing spawn: binary identity changed since probe",
                self.path.display()
            )));
        }
        let mut command = Command::new(&canonical);
        command.arg(format!("--git-dir={}", git_dir.display()));
        sanitize_git_env(&mut command);
        if let Some(isolation) = isolation {
            isolation.apply(&mut command);
        }
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
        apply_repo_neutralization(&mut command);
        command.args(args);
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

/// Empty-config isolation for the content-converting status read and
/// its driver guard (FIXREADY4 F, installed-git twin of the gix
/// isolated open): an owned 0700 tempdir (holding an empty config file)
/// that becomes the spawn's `HOME`, `GIT_CONFIG_GLOBAL`, and
/// `GIT_CONFIG_SYSTEM`, with `XDG_CONFIG_HOME` removed (so the XDG
/// config falls back under the empty HOME). The guard and the status
/// read share one isolation, so the guard observes exactly what git
/// will observe. Fails closed when the dir cannot be built. On git
/// versions that ignore the redirect variables, the guard's effective
/// `config --list` still sees the leaked drivers and refuses.
struct StatusConfigIsolation {
    _dir: tempfile::TempDir,
    empty_config: PathBuf,
}

impl StatusConfigIsolation {
    fn create() -> crate::Result<Self> {
        let dir = tempfile::TempDir::new().map_err(|e| {
            crate::Error::Git(format!(
                "installed git: refusing status: cannot build config isolation: {e}"
            ))
        })?;
        let empty_config = dir.path().join("gitconfig-empty");
        std::fs::write(&empty_config, b"").map_err(|e| {
            crate::Error::Git(format!(
                "installed git: refusing status: cannot build config isolation: {e}"
            ))
        })?;
        Ok(Self {
            _dir: dir,
            empty_config,
        })
    }

    /// Apply the isolation to one spawn (call AFTER [`sanitize_git_env`]
    /// so these values win over the sanitized ambient environment).
    fn apply(&self, command: &mut Command) {
        command
            .env("GIT_CONFIG_GLOBAL", &self.empty_config)
            .env("GIT_CONFIG_SYSTEM", &self.empty_config)
            .env("HOME", self._dir.path())
            .env_remove("XDG_CONFIG_HOME");
    }
}

/// Append the repo-selected-execution neutralizations to one fallback
/// `git` argv (RSF-FALLBACK-HELPER-SECURITY(1)); call AFTER
/// [`sanitize_git_env`] so these values win:
/// - hooks: `core.hooksPath=/dev/null`
/// - fsmonitor: `core.fsmonitor=false` (wins over repo config AND
///   `include.path` chains by `-c` precedence — proven by the marker test;
///   submodule scope too: parent status descends via a child `git status
///   --porcelain=2` (argv trace) that inherits the `-c` through git's
///   `GIT_CONFIG_COUNT` environment propagation, which overrides config
///   files — so a hook/daemon enabled in a submodule config never runs:
///   probed on Apple Git 2.54.0 and 2.56.0, the hook ran with the `-c`
///   removed and stayed silent with the exact scanner argv on both.
///   Same key covers hook-path and `=true` daemon values, so no
///   fsmonitor guard scan is needed — the `-c` is the neutralization)
/// - pager: `--no-pager` flag + `core.pager=cat` + `GIT_PAGER=cat`
/// - ssh: `core.sshCommand=false` (any transport attempt fails closed;
///   the fallback never runs transport subcommands) + `GIT_SSH*` removed
///   + `GIT_TERMINAL_PROMPT=0`
/// - askpass: `GIT_ASKPASS`/`SSH_ASKPASS*` removed (no credential-prompt
///   helper can be smuggled in)
/// - templates: probe `init` pins `--template=<probe-owned empty dir>`;
///   [`FallbackGit`] read subcommands never init (nothing to neutralize)
/// - includes: `-c` precedence wins over any included file;
///   `GIT_CONFIG_COUNT` is stripped so env-injected includes cannot
///   smuggle overrides
/// - clean/smudge/process filters: driver names are unbounded —
///   neutralized by detect-and-refuse (`status_counts` stays
///   `unsupported`), never executed
fn apply_repo_neutralization(cmd: &mut Command) {
    cmd.arg("--no-pager")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("help.format=man")
        .arg("-c")
        .arg("core.pager=cat")
        .arg("-c")
        .arg("core.sshCommand=false");
    cmd.env("GIT_PAGER", "cat").env("GIT_TERMINAL_PROMPT", "0");
}

/// Ambient-environment allowlist shared by every installed-git spawn
/// (XSEC-03): only explicitly allowlisted `GIT_*` variables may reach the
/// child — every other ambient `GIT_*` variable is stripped, so
/// repository redirects, config injection (`GIT_CONFIG_*`), helper
/// overrides (`GIT_SSH*`, `GIT_ASKPASS`, `GIT_EDITOR`, ...), or network
/// use cannot be smuggled in. Proxy, pager, askpass, and browser
/// variables are stripped too.
/// Only the *environment redirects* are stripped — file-based config
/// still applies, so legitimate settings (e.g. `safe.directory`
/// exceptions) keep working. Callers set allowlisted values AFTER
/// sanitizing.
fn sanitize_git_env(cmd: &mut Command) {
    const ALLOWED_GIT_VARS: &[&str] =
        &["GIT_OPTIONAL_LOCKS", "GIT_CEILING_DIRECTORIES", "GIT_PAGER"];
    // Strip every ambient `GIT_*` outside the allowlist (covers `GIT_DIR`,
    // `GIT_WORK_TREE`, `GIT_PREFIX`, `GIT_CONFIG_*` pairs, `GIT_SSH*`, ...).
    // `vars_os` (not `vars`): a non-Unicode ambient value must never panic
    // the scan from inside sanitization.
    for (key, _) in std::env::vars_os() {
        if let Some(key_str) = key.to_str() {
            if key_str.starts_with("GIT_") && !ALLOWED_GIT_VARS.contains(&key_str) {
                cmd.env_remove(key_str);
            }
        }
    }
    // Explicit removals: also cover values set on the command before
    // sanitizing, plus non-`GIT_` injection vectors.
    cmd.env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_PREFIX")
        .env_remove("GIT_SSH")
        .env_remove("GIT_SSH_COMMAND")
        .env_remove("GIT_ASKPASS")
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_ASKPASS_REQUIRE")
        .env_remove("GIT_TERMINAL_PROMPT")
        .env_remove("GIT_EDITOR")
        .env_remove("GIT_SEQUENCE_EDITOR")
        .env_remove("GIT_EXTERNAL_DIFF")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("GIT_CONFIG_SYSTEM")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_HTTP_PROXY")
        .env_remove("GIT_HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .env_remove("PAGER")
        .env_remove("MANPAGER")
        .env_remove("BROWSER");
}

/// Sticky process-lifetime counts of helpers whose termination was NOT
/// proven (RSF-FALLBACK-HELPER-SECURITY(4, 6)): stuck readers past the
/// join grace, or a failed group kill leaving liveness unknown. Never
/// decremented — leaked charges stay visible until process exit.
static HELPER_STUCK: AtomicUsize = AtomicUsize::new(0);
static HELPER_UNKNOWN: AtomicUsize = AtomicUsize::new(0);

/// Record a helper with readers stuck past the join grace (a descendant
/// outlived the group kill — or the kill was skipped after reap — and
/// still holds a pipe).
fn record_stuck_helper() {
    HELPER_STUCK.fetch_add(1, Ordering::Relaxed);
}

/// Record a helper whose group kill failed (liveness unknown).
fn record_unknown_helper() {
    HELPER_UNKNOWN.fetch_add(1, Ordering::Relaxed);
}

/// Unified helper tally (RSF-FALLBACK-HELPER-SECURITY(6)):
/// [`HELPER_LEDGER`](crate::scheduler::admission::HELPER_LEDGER) live
/// count plus sticky stuck/unknown evidence. The ledger is the source of
/// truth — owner-side counters never see these spawns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperTelemetry {
    /// Currently live (charged) helper spawns.
    pub live: usize,
    /// Process-lifetime helpers with stuck readers (termination unproven).
    pub stuck: usize,
    /// Process-lifetime helpers with failed group kills (liveness unknown).
    pub unknown: usize,
    /// Ledger cap (mirrors `HELPER_LEDGER_CAP`).
    pub cap: usize,
}

/// Read the unified helper tally for telemetry.
pub fn helper_telemetry() -> HelperTelemetry {
    HelperTelemetry {
        live: crate::scheduler::admission::HELPER_LEDGER.live(),
        stuck: HELPER_STUCK.load(Ordering::Relaxed),
        unknown: HELPER_UNKNOWN.load(Ordering::Relaxed),
        cap: crate::scheduler::admission::HELPER_LEDGER_CAP,
    }
}

/// One charged ledger slot; dropping releases it.
struct HelperPermit;

impl Drop for HelperPermit {
    fn drop(&mut self) {
        crate::scheduler::admission::HELPER_LEDGER.release();
    }
}

/// Keep a leaked helper charged: when termination is unproven (stuck
/// readers, unknown kill), forget the ledger permit instead of releasing
/// it — the slot stays occupied until process exit (3, 4).
fn leak_charge_if_unproven(permit: &mut Option<HelperPermit>, report: &CleanupReport) {
    if !report.termination_unproven() {
        return;
    }
    if let Some(held) = permit.take() {
        std::mem::forget(held);
    }
}

/// Outcome of one enveloped spawn. Opaque outside the crate: external
/// callers match on the `Err` side; readers live in this module.
#[derive(Debug)]
pub struct SpawnOutcome {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

/// Spawn `cmd` with stdin nulled and enforce the shared envelope (see
/// [`spawn_enveloped_cancel`]), using the thread-scoped wait token (or a
/// never-cancelling token outside [`with_wait_cancel`]).
pub fn spawn_enveloped(
    cmd: &mut Command,
    capture_stderr: bool,
    timeout: Duration,
    cap_bytes: u64,
) -> Result<SpawnOutcome, String> {
    spawn_enveloped_cancel(
        cmd,
        capture_stderr,
        timeout,
        cap_bytes,
        &current_wait_cancel(),
    )
}

/// Spawn `cmd` with stdin nulled and enforce the shared envelope: a
/// `timeout` wall-clock budget (the child is killed past it) and
/// `cap_bytes` captured bytes per stream (past it the child is killed
/// and `truncated` is set; callers must fail, never use partial
/// output). Stdout is always captured; stderr only when `capture_stderr`
/// (otherwise it is discarded, never inherited). Reader threads keep a
/// verbose stderr from wedging stdout.
///
/// Every wait polls `cancel`: a fired token terminates the helper and
/// fails loudly (group-kill, skipped once the child is reaped and its
/// pgid may be reused). Past the child exit, reader drains are bounded by
/// [`POST_EXIT_DRAIN_TIMEOUT`] (a descendant-held pipe is an explicit
/// incomplete gap, never a hang). Timeout, cap, cancel, error, and drain
/// paths all terminate through [`cleanup_child`] (group-kill unless the
/// child is already reaped — the drain paths skip the kill, their pgid
/// may be reused — plus reap and grace-join); helpers whose termination
/// stays unproven keep their ledger charge and are recorded stuck/unknown.
pub fn spawn_enveloped_cancel(
    cmd: &mut Command,
    capture_stderr: bool,
    timeout: Duration,
    cap_bytes: u64,
    cancel: &WaitCancel,
) -> Result<SpawnOutcome, String> {
    // Process-group isolation (PATH-GIT-04/XSEC-07): the child leads a
    // fresh group so timeout kills reach descendants too (no orphaned
    // grandchildren holding pipes or the volume busy). A setpgid failure
    // aborts the spawn: silently joining the parent's group would let a
    // group kill hit our own process group.
    #[cfg(unix)]
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(cmd, || {
            // SAFETY: setpgid(0, 0) is async-signal-safe; no locks, no
            // allocation. Failure aborts the spawn via the Err return.
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    // Helper accounting (SR-STATE-02): installed-git spawns run below the
    // owner's Admission handle, so they charge the process-wide ledger at
    // this choke point instead. The bounded wait absorbs transient
    // contention; past it the spawn is refused loudly, never queued
    // without bound. Live children never exceed the cap.
    let ledger = &crate::scheduler::admission::HELPER_LEDGER;
    let acquire_until = Instant::now() + crate::scheduler::admission::HELPER_LEDGER_WAIT;
    while !ledger.try_acquire() {
        if cancel.cancelled() {
            return Err(String::from(
                "cancelled by task token (SIGINT/deadline) while waiting for a helper-ledger slot",
            ));
        }
        if Instant::now() >= acquire_until {
            return Err(format!(
                "helper ledger: {} live helpers (cap {}); spawn refused, no slot freed",
                ledger.live(),
                ledger.cap()
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // RAII release: every return path below frees the ledger slot —
    // unless a leak path proves non-termination and forgets the permit
    // instead: leaked helpers stay charged until termination is proven.
    let mut helper_permit: Option<HelperPermit> = Some(HelperPermit);
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
        if cancel.cancelled() {
            let report = cleanup_child(
                &mut child,
                &mut stdout_thread,
                &mut stderr_thread,
                cap_bytes,
                false, // unreaped: try_wait never returned Some, pid reserved
            );
            leak_charge_if_unproven(&mut helper_permit, &report);
            return Err(format!(
                "cancelled by task token (SIGINT/deadline); {}",
                report.notes
            ));
        }
        match child.try_wait() {
            Err(e) => {
                // Error paths terminate through the same cleanup: a
                // failed wait must still kill, join, and account.
                let report = cleanup_child(
                    &mut child,
                    &mut stdout_thread,
                    &mut stderr_thread,
                    cap_bytes,
                    false, // unreaped: a failed wait reaps nothing
                );
                leak_charge_if_unproven(&mut helper_permit, &report);
                return Err(format!("wait failed: {e}; {}", report.notes));
            }
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let report = cleanup_child(
                        &mut child,
                        &mut stdout_thread,
                        &mut stderr_thread,
                        cap_bytes,
                        false, // unreaped: try_wait returned None, pid reserved
                    );
                    leak_charge_if_unproven(&mut helper_permit, &report);
                    return Err(format!("timed out after {timeout:?}; {}", report.notes));
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
                    // Over-cap output terminates through the same cleanup:
                    // group-kill (a lone `child.kill` would orphan
                    // grandchildren), reap, grace-join. Unfinished reader
                    // content is moot — callers fail on `truncated` — but
                    // stuck/unknown helpers still leak their charge loudly.
                    let report = cleanup_child(
                        &mut child,
                        &mut stdout_thread,
                        &mut stderr_thread,
                        cap_bytes,
                        false, // unreaped: try_wait returned None, pid reserved
                    );
                    leak_charge_if_unproven(&mut helper_permit, &report);
                    if report.termination_unproven() {
                        eprintln!(
                            "repo-scan: fallback spawn: over-cap cleanup: {}",
                            report.notes
                        );
                    }
                    let Some(status) = report.status else {
                        return Err(format!("over-cap output; {}", report.notes));
                    };
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
    // Post-exit bounded drain: the child is gone (reaped by `try_wait`)
    // but a descendant may still hold a pipe open — joining unbounded
    // would hang forever. Past the drain budget the call fails as an
    // explicit incomplete gap, never a hang and never silently partial
    // bytes; the group kill is skipped (the reaped pgid may be reused),
    // so surviving holders detach loudly past the grace with the charge
    // kept.
    let drain_until = Instant::now() + POST_EXIT_DRAIN_TIMEOUT;
    loop {
        let readers_pending = stdout_thread.as_ref().is_some_and(|h| !h.is_finished())
            || stderr_thread.as_ref().is_some_and(|h| !h.is_finished());
        if !readers_pending {
            break;
        }
        if cancel.cancelled() {
            let report = cleanup_child(
                &mut child,
                &mut stdout_thread,
                &mut stderr_thread,
                cap_bytes,
                true, // reaped by try_wait: skip the group kill, pgid may be reused
            );
            leak_charge_if_unproven(&mut helper_permit, &report);
            return Err(format!(
                "cancelled during post-exit drain; {}",
                report.notes
            ));
        }
        if Instant::now() >= drain_until {
            let report = cleanup_child(
                &mut child,
                &mut stdout_thread,
                &mut stderr_thread,
                cap_bytes,
                true, // reaped by try_wait: skip the group kill, pgid may be reused
            );
            leak_charge_if_unproven(&mut helper_permit, &report);
            return Err(format!(
                "incomplete: post-exit reader drain timed out after {POST_EXIT_DRAIN_TIMEOUT:?} (descendant-held pipe?); {}",
                report.notes
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
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

/// Report from [`cleanup_child`]: what termination did, and whether
/// any helper's termination stays unproven (leaked charge plus sticky
/// stuck/unknown counters).
struct CleanupReport {
    notes: String,
    stuck: bool,
    unknown: bool,
    status: Option<std::process::ExitStatus>,
}

impl CleanupReport {
    /// True when some helper may still be alive: readers stuck past the
    /// grace (a descendant escaped the group) or a failed group kill.
    fn termination_unproven(&self) -> bool {
        self.stuck || self.unknown
    }
}

/// Centralized termination + join + accounting
/// (RSF-FALLBACK-HELPER-SECURITY(3)): the timeout, cap, cancel, error,
/// and drain paths ALL land here — group-kill (never a lone
/// `child.kill`, which orphans grandchildren), reap, grace-join readers.
/// The drain paths pass `child_reaped`: their child was already reaped
/// by `try_wait`, so the group kill is skipped (the pgid may be reused
/// by an unrelated group) and the wait is not retried — readers still
/// grace-join, stuck ones detach loudly. Stuck readers or a failed group
/// kill mark termination unproven: the caller keeps the ledger charge
/// (never releases a maybe-live helper) and the sticky counters preserve
/// the state for telemetry. Every stage is loud: a lost kill or a stuck
/// reader must never read as clean.
#[allow(clippy::type_complexity)]
fn cleanup_child(
    child: &mut std::process::Child,
    stdout_thread: &mut Option<std::thread::JoinHandle<(std::io::Result<usize>, Vec<u8>)>>,
    stderr_thread: &mut Option<std::thread::JoinHandle<(std::io::Result<usize>, Vec<u8>)>>,
    cap_bytes: u64,
    child_reaped: bool,
) -> CleanupReport {
    let (kill_note, unknown) = terminate_child_group(child, child_reaped);
    // A reaped child must not be waited again: the second `wait` can
    // only fail (ECHILD) and would misread as a lost reap.
    let (reap_note, status) = if child_reaped {
        (String::from("already reaped"), None)
    } else {
        match child.wait() {
            Ok(status) => (String::from("reaped"), Some(status)),
            Err(e) => (format!("wait FAILED: {e}"), None),
        }
    };
    // Join readers with a grace: pipes EOF once the group is dead. A
    // descendant that escaped the group can still hold a pipe, so a
    // stuck reader is reported loudly instead of hanging.
    let join_until = Instant::now() + READER_JOIN_GRACE;
    while Instant::now() < join_until
        && (stdout_thread.as_ref().is_some_and(|h| !h.is_finished())
            || stderr_thread.as_ref().is_some_and(|h| !h.is_finished()))
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut reader_notes = Vec::new();
    let mut stuck = false;
    for (name, thread) in [
        ("stdout", stdout_thread.take()),
        ("stderr", stderr_thread.take()),
    ] {
        match thread {
            None => {}
            Some(handle) if handle.is_finished() => {
                match join_reader(Some(handle), cap_bytes, name) {
                    Ok(_) => reader_notes.push(format!("{name} joined")),
                    Err(e) => {
                        reader_notes.push(format!("{name} join FAILED: {e}"));
                    }
                }
            }
            Some(handle) => {
                // Last resort, loud: the thread owns its buffer and exits
                // at EOF; dropping the handle detaches it.
                drop(handle);
                stuck = true;
                record_stuck_helper();
                reader_notes.push(format!("{name} STUCK past grace (detached, loud)"));
            }
        }
    }
    if reader_notes.is_empty() {
        reader_notes.push(String::from("already joined"));
    }
    CleanupReport {
        notes: format!(
            "{}; {}; readers: {}",
            kill_note,
            reap_note,
            reader_notes.join(", ")
        ),
        stuck,
        unknown,
        status,
    }
}

/// SIGKILL the child's process group so descendants die with it.
/// Returns the loud note plus whether helper liveness stays UNKNOWN: a
/// failed group kill (anything but already-gone) preserves the
/// unknown-helper state and keeps the charge (4).
#[cfg(unix)]
fn terminate_child_group(child: &mut std::process::Child, child_reaped: bool) -> (String, bool) {
    // A reaped child owns no pid anymore: `try_wait` reaps on `Ok(Some)`,
    // so past the wait loop the pgid may already address an unrelated
    // reused group — killpg must be skipped, never fired (a stale kill
    // would SIGKILL strangers). In-group pipe holders then survive; their
    // readers detach loudly past the grace and the charge stays kept.
    if child_reaped {
        return (
            format!(
                "group kill skipped (child already reaped; pgid {} may be reused)",
                child.id()
            ),
            false,
        );
    }
    // SAFETY: the child is unreaped here, so its pid is still reserved
    // for us and cannot be recycled; pre_exec made it a group leader, so
    // killpg cannot reach our own process group. If the group is gone the
    // kill reports ESRCH (benign: the child exited between the last wait
    // and the kill).
    let pgid = child.id() as libc::pid_t;
    if unsafe { libc::killpg(pgid, libc::SIGKILL) } == 0 {
        (String::from("group killed"), false)
    } else {
        let errno = std::io::Error::last_os_error();
        let (note, unknown) = classify_killpg_error(errno.raw_os_error(), pgid, &errno);
        if unknown {
            record_unknown_helper();
        }
        (note, unknown)
    }
}

/// Kill one child (non-unix: no process groups). A failed kill leaves
/// liveness unknown: preserved plus loud, charge kept.
#[cfg(not(unix))]
fn terminate_child_group(child: &mut std::process::Child, child_reaped: bool) -> (String, bool) {
    // Mirrors the unix arm: no kill after reap (the handle is spent; a
    // kill here could only fail loudly and misrecord UNKNOWN).
    if child_reaped {
        return (String::from("kill skipped (child already reaped)"), false);
    }
    match child.kill() {
        Ok(()) => (String::from("child killed"), false),
        Err(e) => {
            record_unknown_helper();
            (
                format!("kill FAILED: {e} (UNKNOWN-HELPER: liveness unproven, charge kept)"),
                true,
            )
        }
    }
}

/// Pure classification of a failed `killpg` (unit-tested):
/// ESRCH is benign (the group was already gone — the child exited
/// between the last wait and the kill); anything else fails closed to
/// UNKNOWN-helper (loud note, sticky counter, kept charge).
#[cfg(unix)]
fn classify_killpg_error(
    raw_errno: Option<i32>,
    pgid: libc::pid_t,
    errno: &std::io::Error,
) -> (String, bool) {
    if raw_errno == Some(libc::ESRCH) {
        (String::from("group already gone"), false)
    } else {
        (
            format!(
                "killpg({pgid}) FAILED: {errno} (UNKNOWN-HELPER: liveness unproven, charge kept)"
            ),
            true,
        )
    }
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
/// English diagnostics so error matching is locale-independent. Both
/// spawns run inside the shared envelope (timeout+kill, capture cap,
/// allowlisted environment, scoped wait token) with the same
/// repo-selected-execution neutralization as the normal spawns. A
/// tempdir failure fails closed (PATH-GIT-05): the
/// probe never runs in the ambient CWD, and `init` uses an empty
/// probe-owned template so file-based `init.templateDir` config cannot
/// trigger arbitrary template reads or copies.
fn probe_porcelain_v2(path: &Path) -> bool {
    let repo = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(_) => return false,
    };
    let empty_template = repo.path().join("probe-template");
    if std::fs::create_dir(&empty_template).is_err() {
        return false;
    }
    // Best effort: fixtures answer `init` from their canned script
    // (outcome ignored — the probe argv below is the verdict either
    // way); real git always inits an empty temp dir.
    let mut init = Command::new(path);
    sanitize_git_env(&mut init);
    apply_repo_neutralization(&mut init);
    init.arg("init")
        .arg("-q")
        .arg(format!("--template={}", empty_template.display()))
        .current_dir(repo.path())
        .env("LC_ALL", "C");
    // Best effort, but loud (XSEC-07): an init failure is noted so a
    // fail-closed "incapable" verdict below stays explainable.
    if let Err(e) = spawn_enveloped(&mut init, false, GIT_SPAWN_TIMEOUT, MAX_CAPTURE_BYTES) {
        eprintln!("repo-scan: git probe: temp-repo init failed (best effort): {e}");
    }
    let mut probe = Command::new(path);
    sanitize_git_env(&mut probe);
    apply_repo_neutralization(&mut probe);
    probe
        .arg("status")
        .arg("--porcelain=v2")
        .arg("--help")
        .current_dir(repo.path())
        .env("LC_ALL", "C")
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env("MANPAGER", "cat");
    match spawn_enveloped(&mut probe, true, GIT_SPAWN_TIMEOUT, MAX_CAPTURE_BYTES) {
        Ok(outcome) => {
            if outcome.truncated {
                eprintln!(
                    "repo-scan: git probe: porcelain-v2 help output past capture cap; incapable"
                );
                return false;
            }
            if !matches!(outcome.status.code(), Some(0) | Some(129)) {
                eprintln!(
                    "repo-scan: git probe: porcelain-v2 help exited {:?}; incapable",
                    outcome.status.code()
                );
                return false;
            }
            let mut text = String::from_utf8_lossy(&outcome.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&outcome.stderr));
            let lower = text.to_ascii_lowercase();
            let capable = lower.contains("porcelain")
                && !lower.contains("unknown option")
                && !lower.contains("unsupported porcelain");
            if !capable {
                eprintln!(
                    "repo-scan: git probe: porcelain-v2 help text missing the feature; incapable"
                );
            }
            capable
        }
        Err(e) => {
            // Loud fail-closed (XSEC-07): timeouts, kills, and ledger
            // refusals surface here instead of a silent `false`.
            eprintln!("repo-scan: git probe: porcelain-v2 help spawn failed: {e}; incapable");
            false
        }
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

    /// Serializes the spawn-charging tests: installed-git spawns share
    /// the process-wide cap-4 helper ledger, and parallel tests on a
    /// loaded machine exhaust the 1s bounded wait, failing probes that
    /// would pass in isolation. Mirrors `spawn_serial` in the
    /// integration tests.
    static SPAWN_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn spawn_serial() -> std::sync::MutexGuard<'static, ()> {
        SPAWN_SERIAL
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

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
        let _serial = spawn_serial();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("exec sleep 5");
        let err = spawn_enveloped(&mut cmd, false, Duration::from_millis(100), 1024)
            .expect_err("a 5s sleeper must exceed a 100ms budget");
        assert!(err.contains("timed out"), "{err}");
    }

    #[test]
    fn envelope_caps_captured_bytes() {
        let _serial = spawn_serial();
        let mut cmd = Command::new("head");
        cmd.args(["-c", "4096", "/dev/zero"]);
        let outcome =
            spawn_enveloped(&mut cmd, false, Duration::from_secs(10), 128).expect("spawn");
        assert!(outcome.truncated, "4 KiB past a 128-byte cap must trip");
        assert_eq!(outcome.stdout.len(), 129);
    }

    #[test]
    fn sanitize_strips_config_redirects() {
        let _serial = spawn_serial();
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
        let _serial = spawn_serial();
        let dir = tempfile::tempdir().expect("tempdir");
        let git = git_fixture(dir.path(), "git", "git version 2.47.1", CAPABLE_BODY);
        let path_var = dir.path().to_str().expect("utf8").to_string();
        let found = FallbackGit::discover_from(&[], &[], Some(path_var)).expect("discover");
        assert_eq!(found.source(), BinarySource::Path);
        assert_eq!(found.path(), git.as_path());
    }

    #[test]
    fn discover_prefers_trusted_paths() {
        let _serial = spawn_serial();
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
        let _serial = spawn_serial();
        let dir = tempfile::tempdir().expect("tempdir");
        let git = git_fixture(dir.path(), "git", "git version 2.47.1", CAPABLE_BODY);
        let found = FallbackGit::probe(&git).expect("probe");
        assert_eq!(found.source(), BinarySource::Explicit);
    }

    #[test]
    fn feature_probe_rejects_unexpected_status() {
        let _serial = spawn_serial();
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

    #[test]
    fn killpg_classification_fails_closed() {
        let gone = std::io::Error::from_raw_os_error(libc::ESRCH);
        assert_eq!(
            classify_killpg_error(Some(libc::ESRCH), 4242, &gone),
            (String::from("group already gone"), false)
        );
        for raw in [Some(libc::EPERM), Some(libc::EINVAL), None] {
            let errno = raw
                .map(std::io::Error::from_raw_os_error)
                .unwrap_or_else(|| std::io::Error::other("no errno"));
            let (note, unknown) = classify_killpg_error(raw, 4242, &errno);
            assert!(unknown, "{raw:?} must classify unknown");
            assert!(
                note.contains("FAILED") && note.contains("UNKNOWN-HELPER"),
                "unknown kill must be loud: {note}"
            );
        }
    }

    #[test]
    fn exec_filter_key_matching() {
        for key in [
            "filter.lfs.clean",
            "filter.evil.smudge",
            "filter.proc.process",
            "FILTER.UPPER.CLEAN",
        ] {
            assert!(
                FallbackGit::is_exec_filter_key(&key.to_ascii_lowercase()),
                "{key} must match"
            );
        }
        for key in [
            "filter.lfs.required",
            "core.fsmonitor",
            "core.sshcommand",
            "diff.text.command",
            "merge.custom.driver",
            "credential.helper",
            "filter",
        ] {
            assert!(
                !FallbackGit::is_exec_filter_key(key),
                "{key} must not match"
            );
        }
    }

    #[test]
    fn wait_cancel_flag_and_deadline() {
        assert!(!WaitCancel::never().cancelled());
        let past = WaitCancel::new(|| false, Some(Instant::now() - Duration::from_secs(1)));
        assert!(past.cancelled(), "a past deadline cancels");
        let future = WaitCancel::new(|| false, Some(Instant::now() + Duration::from_secs(60)));
        assert!(!future.cancelled(), "a future deadline waits");
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let moved = Arc::clone(&flag);
        let token = WaitCancel::new(
            move || moved.load(std::sync::atomic::Ordering::SeqCst),
            None,
        );
        assert!(!token.cancelled());
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(token.cancelled(), "a fired flag cancels");
    }

    #[test]
    fn helper_telemetry_reports_ledger_and_stickies() {
        let _serial = spawn_serial();
        let before = helper_telemetry();
        assert_eq!(
            before.live,
            crate::scheduler::admission::HELPER_LEDGER.live(),
            "telemetry live must read the ledger"
        );
        record_stuck_helper();
        record_unknown_helper();
        let after = helper_telemetry();
        assert_eq!(after.stuck, before.stuck + 1);
        assert_eq!(after.unknown, before.unknown + 1);
        assert_eq!(after.cap, crate::scheduler::admission::HELPER_LEDGER_CAP);
    }

    #[test]
    fn path_entries_reject_writable_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(path_entry_trusted(dir.path()), "0700 tempdir trusted");
        let open = dir.path().join("open");
        std::fs::create_dir(&open).expect("mkdir");
        let mut perms = std::fs::metadata(&open).expect("meta").permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(&open, perms).expect("chmod");
        assert!(!path_entry_trusted(&open), "0777 entry refused");
        assert!(!path_entry_trusted(Path::new("")), "empty refused");
        assert!(
            !path_entry_trusted(Path::new("relative/dir")),
            "relative refused"
        );
    }

    /// PGID-reuse friendly-fire: `try_wait` reaps on `Ok(Some)`, so the
    /// drain paths clean up an already-reaped child whose pgid may be
    /// reused — the group kill must be skipped (loudly), with no failed
    /// wait and no unknown-helper recorded. The unreaped arm still kills.
    #[test]
    fn reaped_child_skips_group_kill() {
        let _serial = spawn_serial();
        let unknown_before = helper_telemetry().unknown;
        // Reaped arm: spawn, reap, then clean up — no killpg, no wait.
        let mut reaped = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn");
        assert!(reaped.wait().expect("reap").success());
        let (note, unknown) = terminate_child_group(&mut reaped, true);
        assert!(note.contains("skipped"), "{note}");
        assert!(note.contains("reaped"), "{note}");
        assert!(!unknown, "a skipped kill is proven, never unknown");
        let mut stdout_thread = None;
        let mut stderr_thread = None;
        let report = cleanup_child(
            &mut reaped,
            &mut stdout_thread,
            &mut stderr_thread,
            1024,
            true,
        );
        assert!(report.notes.contains("skipped"), "{}", report.notes);
        assert!(report.notes.contains("already reaped"), "{}", report.notes);
        assert!(!report.notes.contains("FAILED"), "{}", report.notes);
        assert!(!report.termination_unproven());
        assert!(report.status.is_none());
        assert_eq!(
            helper_telemetry().unknown,
            unknown_before,
            "skipped kills record no unknown"
        );
        // Unreaped arm: a live group leader is still group-killed (own
        // group via pre_exec, exactly like the production spawns).
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("exec sleep 30");
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let mut live = cmd.spawn().expect("spawn");
        let (note, unknown) = terminate_child_group(&mut live, false);
        assert_eq!(note, "group killed");
        assert!(!unknown);
        let status = live.wait().expect("reap after kill");
        assert!(!status.success(), "SIGKILL must not read as success");
    }

    /// Process-env override with `Drop` restore (F-note2): serial-guarded
    /// tests that must mutate ambient env restore exactly, even on
    /// assertion panic, so no other test observes them. Mirrors
    /// `EnvGuard` in `tests/fail_git.rs`.
    struct EnvOverride {
        saved: Vec<(String, Option<std::ffi::OsString>)>,
    }

    impl EnvOverride {
        fn set(vars: &[(&str, &str)]) -> Self {
            let mut saved = Vec::new();
            for (key, value) in vars {
                saved.push((key.to_string(), std::env::var_os(key)));
                std::env::set_var(key, value);
            }
            Self { saved }
        }
    }

    impl Drop for EnvOverride {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..) {
                match value {
                    Some(value) => std::env::set_var(&key, value),
                    None => std::env::remove_var(&key),
                }
            }
        }
    }

    /// F-note2 admitted marker test: a HOME + global-config fixture naming
    /// an executable filter driver, then `FallbackGit::status_counts`
    /// DIRECT — counts come back `Ok` (global drivers are neutralized by
    /// isolation, not refused), the marker helper never executes, and the
    /// fake-git's argv/env log proves every status-path spawn ran under
    /// the isolation (`GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` point at
    /// the empty config, `HOME` is the isolation dir, `XDG_CONFIG_HOME`
    /// is unset). Serial-guarded: ambient env is process-wide.
    #[test]
    #[cfg(unix)]
    fn status_counts_neutralizes_global_drivers_under_isolation() {
        let _serial = spawn_serial();
        // Fixture HOME: a global config naming a marker filter driver
        // plus a global excludes file. If any status-path spawn observed
        // this scope, the guard would refuse (proving the leak); real git
        // would execute the driver during conversion.
        let home = tempfile::tempdir().expect("home");
        let marker = home.path().join("driver-marker");
        let driver = home.path().join("marker-helper.sh");
        std::fs::write(
            &driver,
            format!("#!/bin/sh\ntouch \"{}\"\n", marker.display()),
        )
        .expect("write helper");
        let mut perms = std::fs::metadata(&driver).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&driver, perms).expect("chmod");
        let global_config = home.path().join(".gitconfig");
        std::fs::write(
            &global_config,
            format!(
                "[filter \"marker\"]\n\tclean = {}\n\tsmudge = {}\n[core]\n\texcludesFile = {}\n",
                driver.display(),
                driver.display(),
                home.path().join("global-excludes").display(),
            ),
        )
        .expect("write global config");
        std::fs::write(home.path().join("global-excludes"), "*.ignored\n").expect("excludes");
        let home_str = home.path().to_str().expect("utf8").to_string();
        let global_str = global_config.to_str().expect("utf8").to_string();
        // Poison the ambient env: without sanitize+isolate, every spawn
        // would observe the fixture scope.
        let _env = EnvOverride::set(&[
            ("HOME", home_str.as_str()),
            ("GIT_CONFIG_GLOBAL", global_str.as_str()),
            ("GIT_CONFIG_SYSTEM", global_str.as_str()),
            (
                "XDG_CONFIG_HOME",
                home.path().join("xdg").to_str().expect("utf8"),
            ),
        ]);
        // Fake git: `--version` + the feature probe answer canned; the
        // driver guard (`config --list`) answers empty; the status read
        // answers one staged, one unstaged, one untracked entry. Both
        // status-path spawns append an argv/env block to the log.
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("spawn.log");
        let log_str = log.to_str().expect("utf8").to_string();
        let body = format!(
            "subcmd=\"\"\nhelp=0\nfor a in \"$@\"; do\ncase \"$a\" in\nstatus|config) subcmd=\"$a\" ;;\n--help) help=1 ;;\nesac\ndone\n\
             if [ \"$subcmd\" = \"status\" ] && [ \"$help\" = \"0\" ]; then\n\
             echo \"SPAWN argv=$*\" >> \"{log_str}\"\n\
             echo \"GLOBAL=${{GIT_CONFIG_GLOBAL-unset}}\" >> \"{log_str}\"\n\
             echo \"SYSTEM=${{GIT_CONFIG_SYSTEM-unset}}\" >> \"{log_str}\"\n\
             echo \"HOME=$HOME\" >> \"{log_str}\"\n\
             echo \"XDG=${{XDG_CONFIG_HOME-unset}}\" >> \"{log_str}\"\n\
             echo '1 M. N... 100644 100644 100644 abcdef01 abcdef01 staged.txt'\n\
             echo '1 .M N... 100644 100644 100644 abcdef02 abcdef03 unstaged.txt'\n\
             echo '? untracked.txt'\nexit 0\nfi\n\
             if [ \"$subcmd\" = \"config\" ]; then\n\
             echo \"SPAWN argv=$*\" >> \"{log_str}\"\n\
             echo \"GLOBAL=${{GIT_CONFIG_GLOBAL-unset}}\" >> \"{log_str}\"\n\
             echo \"SYSTEM=${{GIT_CONFIG_SYSTEM-unset}}\" >> \"{log_str}\"\n\
             echo \"HOME=$HOME\" >> \"{log_str}\"\n\
             echo \"XDG=${{XDG_CONFIG_HOME-unset}}\" >> \"{log_str}\"\nexit 0\nfi\n\
             echo \" --porcelain[<version>]  machine-readable output\"\nexit 0\n"
        );
        let git = git_fixture(dir.path(), "git", "git version 2.47.1", &body);
        let found = FallbackGit::probe(&git).expect("probe");
        assert!(found.capabilities().porcelain_v2, "probe must pass");
        let repo = tempfile::tempdir().expect("repo");
        let git_dir = repo.path().join("repo.git");
        std::fs::create_dir(&git_dir).expect("git dir");
        let (staged, unstaged, untracked) = found
            .status_counts(&git_dir, Some(repo.path()), true)
            .expect("global drivers neutralize, never refuse");
        assert_eq!((staged, unstaged, untracked), (1, 1, 1));
        assert!(!marker.exists(), "marker helper must never execute");
        // argv/env proof: exactly the guard + status spawns logged, both
        // isolated, both carrying the status argv.
        let text = std::fs::read_to_string(&log).expect("read spawn log");
        let blocks: Vec<&str> = text.split("SPAWN ").skip(1).collect();
        assert_eq!(blocks.len(), 2, "guard + status spawns: {text}");
        let mut saw_guard = false;
        let mut saw_status = false;
        for block in &blocks {
            let mut global = "";
            let mut system = "";
            let mut spawn_home = "";
            let mut xdg = "";
            for line in block.lines() {
                if let Some(v) = line.strip_prefix("GLOBAL=") {
                    global = v;
                } else if let Some(v) = line.strip_prefix("SYSTEM=") {
                    system = v;
                } else if let Some(v) = line.strip_prefix("HOME=") {
                    spawn_home = v;
                } else if let Some(v) = line.strip_prefix("XDG=") {
                    xdg = v;
                }
            }
            assert!(
                global.ends_with("gitconfig-empty") && !global.contains(home_str.as_str()),
                "global config isolated, not fixture: {block}"
            );
            assert_eq!(
                system, global,
                "system config isolated identically: {block}"
            );
            assert!(
                !spawn_home.contains(home_str.as_str()),
                "HOME isolated, not fixture: {block}"
            );
            assert_eq!(
                std::path::Path::new(global).parent(),
                Some(std::path::Path::new(spawn_home)),
                "empty config lives directly under the isolation HOME: {block}"
            );
            assert_eq!(xdg, "unset", "XDG config removed: {block}");
            let argv = block.lines().next().unwrap_or_default();
            assert!(
                argv.contains("--git-dir="),
                "repo selection in argv: {argv}"
            );
            if argv.contains("config --list") {
                saw_guard = true;
            }
            if argv.contains("status")
                && argv.contains("--porcelain=v2")
                && argv.contains("--untracked-files=normal")
                && argv.contains("--no-renames")
            {
                saw_status = true;
            }
        }
        assert!(saw_guard, "driver-guard spawn logged: {text}");
        assert!(saw_status, "isolated status spawn logged: {text}");
    }
}
