//! Git discovery and inspection (spec §§8–9, docs/GIT_QUAL.md).
//!
//! Backend: `gix = "=0.88.0"`, `default-features = false`, features
//! `status, dirwalk, index, excludes, attributes, sha1, sha256`. No default
//! (parallel) features, no network features. Installed git is an optional
//! compatibility backend for reftable/SSH-alias/index gaps only — never a
//! per-directory scanner, never executing hooks/filters/fetch.
//!
//! Read-only contract: no hooks, no filters, no fetch/GC/maintenance, no
//! index refresh writes (`Outcome::write_changes` is never called), no
//! `git_binary` config execution. Exact-path open only — upward discovery
//! is never proof that a child directory is a checkout (spec §8).
//!
//! [`GixInspector`] implements [`GitInspect`]. Errors whose message starts
//! with [`UNSUPPORTED_MARKER`] signal structural gaps (reftable, unreadable
//! index, unopenable worktree admin) that the scheduler may route to the
//! [`fallback`] backend; anything else is an operational probe failure.

pub mod fallback;

use crate::model::StatusMode;
use gix::bstr::{BString, ByteSlice};

/// Prefix marking structural-gap errors eligible for the installed-git
/// fallback (reftable refs, unsupported index, unopenable worktree admin).
/// `error.rs` is owned by another lane, so the marker travels in the message.
pub const UNSUPPORTED_MARKER: &str = "unsupported: ";

/// True when `err` is a structural gap (fallback-eligible), not a transient.
#[must_use]
pub fn is_unsupported_error(err: &crate::Error) -> bool {
    match err {
        crate::Error::Git(message) => message.starts_with(UNSUPPORTED_MARKER),
        _ => false,
    }
}

/// Object ID with explicit algorithm (never assume 40 hex chars).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid {
    /// `sha1` or `sha256`.
    pub algorithm: String,
    /// Lowercase hex, even length, algorithm-correct length.
    pub hex: String,
}

/// How a checkout relates to its repository (spec §8 topology).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutKind {
    /// Main worktree / common checkout.
    Main,
    /// Linked worktree.
    Linked,
    /// Submodule checkout.
    Submodule,
    /// Could not be determined.
    Unknown,
}

/// Availability of a registered worktree (GIT_QUAL §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorktreeAvailability {
    /// Registered and base directory exists.
    Present,
    /// Registered but base is gone.
    Missing,
    /// Registered but base is not accessible.
    Inaccessible,
    /// Registered but admin data is unparseable/unopenable.
    Broken,
    /// Unknown.
    Unknown,
}

/// HEAD state (spec §9): kind and head are reported separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadState {
    /// Symbolic HEAD pointing at a born branch.
    Branch {
        /// Full ref name (raw bytes preserved by the caller).
        ref_name: Vec<u8>,
        /// Peeled OID, if resolvable.
        oid: Option<Oid>,
    },
    /// Detached HEAD at an OID.
    Detached {
        /// Direct target.
        target: Oid,
        /// Peeled OID.
        peeled: Option<Oid>,
    },
    /// Unborn branch (symbolic ref with no commit yet).
    Unborn {
        /// Full ref name.
        ref_name: Vec<u8>,
    },
    /// HEAD exists but is invalid.
    Invalid,
    /// HEAD state could not be determined.
    Unknown,
}

/// One observed reference (packed refs included; symbolic targets preserved).
#[derive(Debug, Clone)]
pub struct RefObservation {
    /// Full ref name (raw bytes; lossy conversion forbidden).
    pub name: Vec<u8>,
    /// Direct or symbolic target.
    pub target: RefTarget,
    /// Peeled OID when computed.
    pub peeled: Option<Oid>,
}

/// Reference target.
#[derive(Debug, Clone)]
pub enum RefTarget {
    /// Points at an object.
    Object(Oid),
    /// Points at another ref (full name, raw bytes).
    Symbolic(Vec<u8>),
}

/// Effective remote with its role preserved (spec §8).
#[derive(Debug, Clone)]
pub struct RemoteObservation {
    /// Remote name (raw bytes).
    pub name: Vec<u8>,
    /// `fetch` or `push` role.
    pub role: RemoteRole,
    /// URL with credentials redacted.
    pub url: String,
    /// Normalized canonical form, if supported.
    pub canonical_url: Option<String>,
}

/// Remote role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteRole {
    /// `remote.*.url`.
    Fetch,
    /// `pushUrl` else fetch fallback.
    Push,
}

/// Validated Git instance opened at its exact discovered path (spec §8).
#[derive(Debug, Clone)]
pub struct GitInstance {
    /// Discovered git directory.
    pub git_dir: std::path::PathBuf,
    /// Shared common directory.
    pub common_dir: std::path::PathBuf,
    /// Working-tree root, if any.
    pub work_dir: Option<std::path::PathBuf>,
    /// Bare flag honoring config (not the name heuristic).
    pub is_bare: bool,
    /// Object format (`sha1`/`sha256`).
    pub object_format: String,
}

/// Working-state observation for one checkout (spec §9).
#[derive(Debug, Clone)]
pub struct StatusObservation {
    /// Mode actually executed.
    pub mode: StatusMode,
    /// Staged (HEAD<->index) count; `None` for metadata mode / unknown.
    pub staged: Option<u64>,
    /// Unstaged (index<->worktree) count.
    pub unstaged: Option<u64>,
    /// Untracked count in the mode's units.
    pub untracked: Option<u64>,
    /// Fields the backend could not determine.
    pub unknown_fields: Vec<String>,
    /// Input fingerprints (head id, index mtime+size) for instability retry.
    pub fingerprints: Vec<String>,
}

/// Git inspection contract. Read-only: no hooks, no filters, no fetch/GC,
/// no index writes (`Outcome::write_changes` is forbidden). Status honors
/// the shared 1-Git-probe admission and the no-progress watchdog in the
/// admitted helper (GIT_QUAL §§7–10).
pub trait GitInspect: Send + Sync {
    /// Validate a candidate at its exact path (no upward discovery).
    /// Handles `.git` dirs, pointer files, external dirs, bare stores
    /// (via `open_path_as_is` semantics).
    fn open_exact(&self, path: &std::path::Path) -> crate::Result<GitInstance>;

    /// Effective fetch/push remotes with roles, rewrites safely applied,
    /// credentials redacted. SSH aliases that need ssh-config resolution
    /// surface as `unresolvable_identity`, never a connection.
    fn remotes(&self, instance: &GitInstance) -> crate::Result<Vec<RemoteObservation>>;

    /// All refs incl. packed; broken refs surface as per-item errors.
    /// Reftable stores route to the installed-git fallback or `unsupported`.
    fn refs(&self, instance: &GitInstance) -> crate::Result<Vec<RefObservation>>;

    /// HEAD state: symbolic/unborn/detached reported separately from kind.
    fn head(&self, instance: &GitInstance) -> crate::Result<HeadState>;

    /// Registered worktrees (linked only; main never listed) with
    /// availability; missing-`gitdir` entries reported as broken.
    fn worktrees(&self, instance: &GitInstance) -> crate::Result<Vec<WorktreeObservation>>;

    /// Working-state probe at `mode` (`metadata` skips status entirely;
    /// `summary` = collapsed untracked; `full` = per-file untracked).
    fn status(&self, instance: &GitInstance, mode: StatusMode) -> crate::Result<StatusObservation>;
}

/// One registered worktree with availability evidence.
#[derive(Debug, Clone)]
pub struct WorktreeObservation {
    /// Worktree id (dir name under `worktrees/`).
    pub id: String,
    /// Checkout path; may not exist.
    pub base: std::path::PathBuf,
    /// Availability classification.
    pub availability: WorktreeAvailability,
    /// Lock reason, if locked.
    pub lock_reason: Option<String>,
}

/// Filesystem-level shape of a validated candidate (spec §8 layouts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// Worktree root holding a `.git` directory or pointer file
    /// (normal, detached, submodule, nested, or external-gitdir checkout).
    WorktreeCheckout,
    /// The path itself is a non-bare git directory.
    GitDir,
    /// The path itself is a bare store (arbitrary names allowed).
    BareStore,
    /// Linked-worktree admin (`commondir` present, `Kind::LinkedWorkTree`).
    LinkedWorktree,
    /// Submodule admin (gitdir under `.git/modules`, `Kind::Submodule`).
    Submodule,
}

/// A validated candidate: the opened instance plus discovery evidence.
///
/// `continue_below_boundary` is always true: filesystem discovery continues
/// below repository boundaries, including administrative recovery locations
/// (spec §8). Nested repositories are validated independently at their own
/// exact paths; upward discovery never proves a child is a checkout.
#[derive(Debug, Clone)]
pub struct ValidatedCandidate {
    /// Opened instance.
    pub instance: GitInstance,
    /// Filesystem-level shape.
    pub kind: CandidateKind,
    /// Marker for the walk layer: always true (spec §8).
    pub continue_below_boundary: bool,
    /// Evidence lines (pointer targets, commondir, bare detection, counts).
    pub evidence: Vec<String>,
}

/// Marker prefix for the explicit config-include gap (SR-STATE-05).
/// gix include following is disabled at the repository opener, so when
/// [`config_include_gap`] finds
/// `include`/`includeIf` directives the scheduler must persist this gap:
/// remotes and values living in included files are NOT reflected.
pub const CONFIG_INCLUDE_GAP: &str = "config-includes-unexpanded";

/// Bounded pre-scan for config-include directives (SR-STATE-05).
///
/// Reads only `git_dir/config` and `common_dir/config` through
/// [`read_bounded_string`] (regular-only, no-follow, byte-capped), scanning
/// for `[include]`/`[includeIf ...]` section headers. Returns `Some`
/// evidence line (prefixed with [`CONFIG_INCLUDE_GAP`]) when either file
/// carries include directives — meaning the gix observations were made
/// with includes unexpanded — else `None`. Unreadable configs yield `None`
/// (their absence is already covered by [`GixInspector::config_dependencies`]
/// evidence), never a silent all-clear misread: the scan only reports
/// positively observed directives.
pub fn config_include_gap(instance: &GitInstance) -> Option<String> {
    let mut configs = vec![instance.git_dir.join("config")];
    let common = instance.common_dir.join("config");
    if common != configs[0] {
        configs.push(common);
    }
    for config in configs {
        let Some(text) = read_bounded_string(&config, MAX_GIT_CONTROL_BYTES) else {
            continue;
        };
        if has_include_section(&text) {
            return Some(format!(
                "{CONFIG_INCLUDE_GAP}: {} names include directives, but gix include following is disabled; values from included files are not reflected in remotes/config observations",
                config.display()
            ));
        }
    }
    None
}

/// True when config text holds an `[include]`/`[includeIf ...]` header.
fn has_include_section(config_text: &str) -> bool {
    for raw_line in config_text.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            let section = line.to_lowercase();
            if section == "[include]" || section.starts_with("[includeif ") {
                return true;
            }
        }
    }
    false
}

/// Marker prefix for the explicit filter-driver gap (EXACT-2 defect 1).
/// gix status converts stat-dirty worktree files through configured
/// clean/process drivers during index-worktree comparison (and recurses
/// into submodule worktrees the same way), with no API toggle to disable
/// drivers — so [`filter_driver_gap`] refuses the probe before the first
/// status call, and the scheduler records the returned line.
pub const FILTER_DRIVER_GAP: &str = "filter-drivers-configured";

/// Bounded pre-scan for executable filter drivers (EXACT-2 defect 1).
///
/// Inspects the repo-local configs gix loads (`config` and
/// `config.worktree` under both admin dirs), the live-enumerated
/// depth-1 submodule configs, and the recursive `modules/` tree beneath
/// the parent and each enumerated submodule. Returns `Some` evidence
/// line (prefixed with [`FILTER_DRIVER_GAP`]) when any names a
/// `filter.<driver>.clean|smudge|process` command — or when a
/// present-but-unreadable control file makes absence unprovable — else
/// `None`. Included files are not followed (gix loads with includes
/// disabled, so their drivers never execute); user/system/env-configured
/// drivers are the operator's own trust domain (same boundary as
/// [`fallback`](crate::git::fallback) `--local` scoping and gix's
/// `is_trusted` default), not repo-selected code.
///
/// [`GixInspector::status_interruptible`] enforces this before any
/// content-converting status call; metadata/bare probes never convert
/// content and skip the guard.
pub fn filter_driver_gap(instance: &GitInstance) -> Option<String> {
    let repo = open_repo(&instance.git_dir).ok()?;
    filter_driver_gap_for_repo(&repo, instance)
}

/// Full filter-driver assessment against an opened repository.
///
/// `None` means no repo-selected executable drivers were observed;
/// `Some` carries the refusal line. Submodule enumeration failures are
/// not a refusal: gix status itself fails the same enumeration before
/// any content conversion, so the real error surfaces from the probe.
fn filter_driver_gap_for_repo(repo: &gix::Repository, instance: &GitInstance) -> Option<String> {
    if scan_repo_filter_configs(&instance.git_dir, &instance.common_dir).refuses() {
        return Some(format!(
            "{FILTER_DRIVER_GAP}: {} names executable filter drivers (filter.<name>.clean|smudge|process); gix status would execute them during worktree-content comparison, refusing to execute",
            instance.git_dir.display()
        ));
    }
    if scan_modules_tree(&instance.common_dir.join("modules"), 0).refuses() {
        return Some(format!(
            "{FILTER_DRIVER_GAP}: nested submodule configs under {} name executable filter drivers (or cannot be proven absent); gix status recurses into submodule worktrees, refusing to execute",
            instance.common_dir.display()
        ));
    }
    // Live depth-1 enumeration covers non-absorbed layouts the `modules/`
    // walk cannot see; each enumerated gitdir's own nested tree is walked
    // too. Past the cap the set is unknown, so refuse (fail closed).
    let mut seen = 0usize;
    let submodules = match repo.submodules() {
        Ok(submodules) => submodules,
        Err(_) => return None,
    };
    let iter = submodules?;
    for sub in iter {
        seen += 1;
        if seen > MAX_FILTER_SUBMODULE_SCAN {
            return Some(format!(
                "{FILTER_DRIVER_GAP}: more than {MAX_FILTER_SUBMODULE_SCAN} submodules; driver set unprovable, refusing to execute"
            ));
        }
        let git_dir = match sub.git_dir() {
            Ok(git_dir) => git_dir,
            Err(_) => continue,
        };
        if scan_repo_filter_configs(&git_dir, &git_dir).refuses()
            || scan_modules_tree(&git_dir.join("modules"), 0).refuses()
        {
            return Some(format!(
                "{FILTER_DRIVER_GAP}: submodule config under {} names executable filter drivers (or cannot be proven absent); gix status recurses into submodule worktrees, refusing to execute",
                git_dir.display()
            ));
        }
    }
    None
}

/// One inspected configuration dependency (spec §8).
///
/// gix include following is disabled (SR-STATE-05), so these paths are
/// evidence only: they record which files WOULD have been consulted, found
/// by the bounded [`GixInspector::config_dependencies`] scan. No helper is
/// ever executed: conditional guards are not evaluated, include paths are
/// only listed.
#[derive(Debug, Clone)]
pub struct ConfigDependency {
    /// Config or include file path.
    pub path: std::path::PathBuf,
    /// Whether the path existed when inspected.
    pub exists: bool,
    /// True when reached via an `include.path` directive.
    pub via_include: bool,
}

/// One submodule relationship of an opened repository.
#[derive(Debug, Clone)]
pub struct SubmoduleObservation {
    /// Configured submodule name (raw bytes).
    pub name: Vec<u8>,
    /// Checkout path (workdir-anchored when a workdir exists).
    pub path: std::path::PathBuf,
    /// Configured URL with credentials redacted, if any.
    pub url: Option<String>,
    /// Normalized canonical form, if the URL shape is supported.
    pub canonical_url: Option<String>,
    /// Submodule git directory, if derivable.
    pub git_dir: Option<std::path::PathBuf>,
}

/// Upper bound on status items tallied in one probe. Past the cap the probe
/// stops and records `truncated` in `unknown_fields`; counts stay partial,
/// never zeroed (spec §9).
pub const STATUS_ITEM_CAP: u64 = 1_000_000;

/// Maximum bytes read from one Git control file (config, include,
/// alternates): adversarial inputs must never drive unbounded allocation
/// (PATH-GIT-07). Reads past the cap fail closed (unreadable), never
/// silently truncated.
pub const MAX_GIT_CONTROL_BYTES: u64 = 256 * 1024;

/// Maximum bytes read from one `.git` pointer file: only the first
/// `gitdir:` line is ever inspected.
pub const MAX_GITDIR_POINTER_BYTES: u64 = 8192;

/// Bounded, regular-file-only read of one control file: symlinks, FIFOs,
/// sockets, devices, and directories are refused, and content past
/// `cap_bytes` fails closed. `None` means unreadable — the caller must
/// treat the control file as unknown, never as empty evidence of absence.
pub fn read_bounded_bytes(path: &std::path::Path, cap_bytes: u64) -> Option<Vec<u8>> {
    // Fast lstat pre-check (no follow): links and special files never
    // reach the open, so `/dev/zero`/FIFO substitutions cannot hang it.
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > cap_bytes {
        return None;
    }
    let file = open_control_file(path)?;
    // Re-check on the open description (fd-bound): the path may have
    // been swapped between the lstat and the open.
    let live = file.metadata().ok()?;
    if !live.file_type().is_file() || live.len() > cap_bytes {
        return None;
    }
    let mut buf = Vec::new();
    {
        use std::io::Read;
        file.take(cap_bytes.saturating_add(1))
            .read_to_end(&mut buf)
            .ok()?;
    }
    if buf.len() as u64 > cap_bytes {
        return None;
    }
    Some(buf)
}

/// Bounded read of one control file as text (lossy): same rejections as
/// [`read_bounded_bytes`].
pub fn read_bounded_string(path: &std::path::Path, cap_bytes: u64) -> Option<String> {
    read_bounded_bytes(path, cap_bytes).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Open one control file for a bounded read: `O_NOFOLLOW` refuses links
/// and `O_NONBLOCK` refuses to wedge on a swapped-in FIFO, then `fstat`
/// refuses anything non-regular.
#[cfg(unix)]
fn open_control_file(path: &std::path::Path) -> Option<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;

    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) {
        return None;
    }
    let c_path = std::ffi::CString::new(bytes).ok()?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    if file.metadata().is_ok_and(|m| m.file_type().is_file()) {
        Some(file)
    } else {
        None
    }
}

/// Open one control file for a bounded read (non-unix): lstat rejects
/// links and special files before the open.
#[cfg(not(unix))]
fn open_control_file(path: &std::path::Path) -> Option<std::fs::File> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    std::fs::File::open(path).ok()
}

/// Read-only gix inspector. Cheap to clone; every method re-opens the
/// repository from [`GitInstance::git_dir`] with a lazy object store, so
/// instances stay `Send + Sync` data without holding library handles.
#[derive(Debug, Clone, Copy, Default)]
pub struct GixInspector {
    _private: (),
}

impl GixInspector {
    /// Create an inspector.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Validate a candidate at its exact path with layout classification.
    ///
    /// Covers normal `.git` directories, `.git` pointer files (external
    /// gitdirs followed read-only), bare stores under arbitrary names,
    /// linked-worktree admin, submodule admin, detached checkouts, and
    /// nested repositories (each validated at its own path).
    pub fn validate(&self, path: &std::path::Path) -> crate::Result<ValidatedCandidate> {
        let mut evidence = Vec::new();
        let dot_git = path.join(".git");
        let dot_git_kind = dot_git
            .symlink_metadata()
            .ok()
            .map(|m| {
                if m.file_type().is_dir() {
                    "dir"
                } else if m.file_type().is_symlink() {
                    "symlink"
                } else {
                    "file"
                }
            })
            .unwrap_or("absent");
        evidence.push(format!(".git entry: {dot_git_kind}"));
        if dot_git_kind == "file" {
            match read_gitdir_pointer(&dot_git) {
                Some(target) => evidence.push(format!("gitdir pointer: {target}")),
                None => evidence.push("gitdir pointer: unparseable".to_string()),
            }
        }
        if path.join("commondir").is_file() {
            evidence.push("commondir: present (linked-worktree admin)".to_string());
        }
        if looks_like_git_dir(path) {
            evidence.push("direct git dir: HEAD+objects+refs present".to_string());
        }

        let instance = self.open_exact(path)?;
        let repo = open_repo(&instance.git_dir)?;
        let kind = match repo.kind() {
            gix::repository::Kind::LinkedWorkTree => CandidateKind::LinkedWorktree,
            gix::repository::Kind::Submodule => CandidateKind::Submodule,
            gix::repository::Kind::Common => {
                if instance.is_bare {
                    CandidateKind::BareStore
                } else if dot_git_kind == "absent" {
                    CandidateKind::GitDir
                } else {
                    CandidateKind::WorktreeCheckout
                }
            }
        };
        evidence.push(format!(
            "bare: {} (config-honoring), object-format: {}",
            instance.is_bare, instance.object_format
        ));
        if instance.common_dir != instance.git_dir {
            evidence.push(format!("common dir: {}", instance.common_dir.display()));
        }
        match repo.worktrees() {
            Ok(proxies) => evidence.push(format!("registered linked worktrees: {}", proxies.len())),
            Err(e) => evidence.push(format!("worktree registry unreadable: {e}")),
        }
        Ok(ValidatedCandidate {
            instance,
            kind,
            continue_below_boundary: true,
            evidence,
        })
    }

    /// Checkout topology of an opened instance (orthogonal to HEAD state).
    pub fn checkout_kind(&self, instance: &GitInstance) -> crate::Result<CheckoutKind> {
        let repo = open_repo(&instance.git_dir)?;
        Ok(match repo.kind() {
            gix::repository::Kind::LinkedWorkTree => CheckoutKind::Linked,
            gix::repository::Kind::Submodule => CheckoutKind::Submodule,
            gix::repository::Kind::Common => {
                if instance.work_dir.is_some() {
                    CheckoutKind::Main
                } else {
                    CheckoutKind::Unknown
                }
            }
        })
    }

    /// Submodule relationships (path/URL/gitdir) for follow-up discovery.
    pub fn submodules(&self, instance: &GitInstance) -> crate::Result<Vec<SubmoduleObservation>> {
        let repo = open_repo(&instance.git_dir)?;
        let Some(iter) = repo.submodules().map_err(|e| git_err(e.to_string()))? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for sub in iter {
            let name = sub.name().as_bytes().to_vec();
            let rel = match sub.path() {
                Ok(rel) => rel,
                Err(_) => continue,
            };
            let path = match instance.work_dir.as_ref() {
                Some(work) => work.join(os_str_from_bytes(rel.as_bytes())),
                None => std::path::PathBuf::from(os_str_from_bytes(rel.as_bytes())),
            };
            let (url, canonical_url) = match sub.url() {
                Ok(url) => {
                    let full = url.to_bstring().to_string();
                    (
                        Some(crate::identity::redact_remote_url(&full)),
                        crate::identity::normalize_github_url(&full),
                    )
                }
                Err(_) => (None, None),
            };
            out.push(SubmoduleObservation {
                name,
                path,
                url,
                canonical_url,
                git_dir: sub.git_dir().ok(),
            });
        }
        Ok(out)
    }

    /// Per-item reference errors (broken refs) as evidence strings.
    ///
    /// [`GitInspect::refs`] returns the parseable refs; this companion
    /// preserves the invalid ones for the report `errors` channel instead
    /// of silently dropping them (spec §9).
    pub fn reference_errors(&self, instance: &GitInstance) -> Vec<String> {
        let repo = match open_repo(&instance.git_dir) {
            Ok(repo) => repo,
            Err(e) => return vec![format!("open failed: {e}")],
        };
        let platform = match repo.references() {
            Ok(platform) => platform,
            Err(e) => return vec![format!("ref store unavailable: {e}")],
        };
        let iter = match platform.all() {
            Ok(iter) => iter,
            Err(e) => return vec![format!("ref iteration unavailable: {e}")],
        };
        iter.filter_map(|item| item.err().map(|e| format!("invalid ref: {e}")))
            .collect()
    }

    /// Configuration files consulted for an instance (spec §8 evidence).
    ///
    /// Always includes the gitdir/common `config` when present, plus
    /// `include.path` targets found by a narrow read-only scan (depth
    /// capped, no helper execution, no condition evaluation). Evidence
    /// only: gix opens with include following disabled (SR-STATE-05), so
    /// listed include targets are not applied to observations.
    pub fn config_dependencies(&self, instance: &GitInstance) -> Vec<ConfigDependency> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut roots = vec![instance.git_dir.join("config")];
        let common_config = instance.common_dir.join("config");
        if common_config != roots[0] {
            roots.push(common_config);
        }
        for root in roots {
            self.collect_config_deps(&root, false, 0, &mut seen, &mut out);
        }
        out
    }

    /// Status probe with an optional watchdog interrupt flag.
    ///
    /// [`GitInspect::status`] delegates with `None`; the admitted helper
    /// passes its no-progress watchdog flag here (GIT_QUAL §9). Refuses
    /// with an `unsupported` filter-driver gap before any
    /// content-converting call when repo-selected clean/smudge/process
    /// drivers are configured (EXACT-2 defect 1).
    pub fn status_interruptible(
        &self,
        instance: &GitInstance,
        mode: StatusMode,
        interrupt: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> crate::Result<StatusObservation> {
        let repo = open_repo(&instance.git_dir)?;
        let fingerprints = vec![head_fingerprint(&repo), index_fingerprint(&repo)];
        if mode == StatusMode::Metadata {
            return Ok(StatusObservation {
                mode,
                staged: None,
                unstaged: None,
                untracked: None,
                unknown_fields: Vec::new(),
                fingerprints,
            });
        }
        if repo.workdir().is_none() {
            return Ok(StatusObservation {
                mode,
                staged: None,
                unstaged: None,
                untracked: None,
                unknown_fields: vec![
                    "no-worktree: bare or worktree-less repository; status not applicable"
                        .to_string(),
                ],
                fingerprints,
            });
        }
        // EXACT-2 defect 1: refuse before the first content-converting
        // status call when repo-selected filter drivers are configured.
        // Metadata/bare probes above never convert content, so they
        // legitimately skip this guard.
        if let Some(gap) = filter_driver_gap_for_repo(&repo, instance) {
            return Err(unsupported(gap));
        }
        let mut counts = self.run_status_counts(&repo, mode, interrupt.clone())?;
        let after = vec![head_fingerprint(&repo), index_fingerprint(&repo)];
        if after != fingerprints {
            // Retry once within budget; flag instability when it persists.
            // Re-check drivers first: a config swapped in during the first
            // pass must not execute on the retry.
            if let Some(gap) = filter_driver_gap_for_repo(&repo, instance) {
                return Err(unsupported(gap));
            }
            let retry = self.run_status_counts(&repo, mode, interrupt)?;
            let again = vec![head_fingerprint(&repo), index_fingerprint(&repo)];
            counts.fingerprints = again;
            if counts.fingerprints != after {
                counts.unknown_fields.push(
                    "unstable: HEAD/index changed during the probe; counts are best-effort"
                        .to_string(),
                );
            }
            counts.staged = retry.staged;
            counts.unstaged = retry.unstaged;
            counts.untracked = retry.untracked;
            counts.unknown_fields.extend(retry.unknown_fields);
        } else {
            counts.fingerprints = after;
        }
        Ok(counts)
    }

    /// Single status-iteration pass returning raw counts.
    fn run_status_counts(
        &self,
        repo: &gix::Repository,
        mode: StatusMode,
        interrupt: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> crate::Result<StatusObservation> {
        let untracked = match mode {
            StatusMode::Full => gix::status::UntrackedFiles::Files,
            _ => gix::status::UntrackedFiles::Collapsed,
        };
        let mut platform = repo
            .status(gix::progress::Discard)
            .map_err(|e| git_err(format!("status platform: {e}")))?
            .untracked_files(untracked);
        if let Some(flag) = interrupt {
            platform = platform.should_interrupt_owned(flag);
        }
        let iter = platform.into_iter(Vec::<BString>::new()).map_err(|e| {
            if is_index_unsupported(&e.to_string()) {
                unsupported(format!("status iteration: {e}"))
            } else {
                git_err(format!("status iteration: {e}"))
            }
        })?;
        let mut staged = 0u64;
        let mut unstaged = 0u64;
        let mut untracked = 0u64;
        let mut unknown_fields = Vec::new();
        let mut item_errors = 0u32;
        for (tallied, item) in iter.enumerate() {
            if tallied as u64 >= STATUS_ITEM_CAP {
                unknown_fields.push(format!(
                    "truncated: item cap ({STATUS_ITEM_CAP}) reached; counts are partial"
                ));
                break;
            }
            match item {
                Ok(gix::status::Item::TreeIndex(_)) => staged += 1,
                Ok(gix::status::Item::IndexWorktree(
                    gix::status::index_worktree::Item::Modification { .. },
                ))
                | Ok(gix::status::Item::IndexWorktree(
                    gix::status::index_worktree::Item::Rewrite { .. },
                )) => unstaged += 1,
                Ok(gix::status::Item::IndexWorktree(
                    gix::status::index_worktree::Item::DirectoryContents { .. },
                )) => untracked += 1,
                Err(e) => {
                    item_errors += 1;
                    if unknown_fields.len() < 8 {
                        unknown_fields.push(format!("item-error: {e}"));
                    }
                }
            }
        }
        if item_errors > 8 {
            unknown_fields.push(format!("item-error: ({} more suppressed)", item_errors - 8));
        }
        Ok(StatusObservation {
            mode,
            staged: Some(staged),
            unstaged: Some(unstaged),
            untracked: Some(untracked),
            unknown_fields,
            fingerprints: Vec::new(),
        })
    }

    /// Narrow read-only include scan for [`Self::config_dependencies`].
    fn collect_config_deps(
        &self,
        path: &std::path::Path,
        via_include: bool,
        depth: u8,
        seen: &mut std::collections::HashSet<std::path::PathBuf>,
        out: &mut Vec<ConfigDependency>,
    ) {
        if depth > 4 || !seen.insert(path.to_path_buf()) {
            return;
        }
        // Regular files only (lstat, no follow): symlinked control files
        // are recorded as absent, never read through (PATH-GIT-07).
        let exists = std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file());
        out.push(ConfigDependency {
            path: path.to_path_buf(),
            exists,
            via_include,
        });
        if !exists || depth == 4 {
            return;
        }
        // Byte-capped: giant, special, or racing files yield no text, so
        // no include paths are followed from them — never an unbounded
        // read, never a `/dev/zero`/FIFO hang.
        let Some(text) = read_bounded_string(path, MAX_GIT_CONTROL_BYTES) else {
            return;
        };
        let base = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        for target in scan_include_paths(&text) {
            let resolved = resolve_include_path(&target, base);
            self.collect_config_deps(&resolved, true, depth + 1, seen, out);
        }
    }
}

impl GitInspect for GixInspector {
    fn open_exact(&self, path: &std::path::Path) -> crate::Result<GitInstance> {
        let repo = open_repo(path)?;
        Ok(GitInstance {
            git_dir: repo.git_dir().to_path_buf(),
            common_dir: repo.common_dir().to_path_buf(),
            work_dir: repo.workdir().map(std::path::Path::to_path_buf),
            is_bare: repo.is_bare(),
            object_format: repo.object_hash().to_string(),
        })
    }

    fn remotes(&self, instance: &GitInstance) -> crate::Result<Vec<RemoteObservation>> {
        let repo = open_repo(&instance.git_dir)?;
        let mut out = Vec::new();
        for name in repo.remote_names() {
            let Some(remote) = repo.try_find_remote(name.as_bstr()) else {
                continue;
            };
            let remote = remote.map_err(|e| {
                git_err(format!(
                    "remote `{}`: {e}",
                    name.as_bstr().to_string().replace('\n', "?")
                ))
            })?;
            // gix applies url.<base>.insteadOf/pushInsteadOf at construction:
            // pure string rewrites, no helper execution (GIT_QUAL §3).
            for (role, direction) in [
                (RemoteRole::Fetch, gix::remote::Direction::Fetch),
                (RemoteRole::Push, gix::remote::Direction::Push),
            ] {
                for url in remote.urls(direction) {
                    let full = url.to_bstring().to_string();
                    out.push(RemoteObservation {
                        name: name.as_bytes().to_vec(),
                        role,
                        url: crate::identity::redact_remote_url(&full),
                        canonical_url: crate::identity::normalize_github_url(&full),
                    });
                }
            }
        }
        Ok(out)
    }

    fn refs(&self, instance: &GitInstance) -> crate::Result<Vec<RefObservation>> {
        let repo = open_repo(&instance.git_dir)?;
        let platform = repo
            .references()
            .map_err(|e| map_ref_store_error(&e.to_string(), "ref store"))?;
        let iter = platform
            .all()
            .map_err(|e| map_ref_store_error(&e.to_string(), "ref iteration"))?;
        let mut out = Vec::new();
        for item in iter {
            // LooseThenPacked covers packed refs; per-item errors are
            // preserved via `reference_errors`, never skipped silently.
            let reference = match item {
                Ok(reference) => reference,
                Err(_) => continue,
            };
            let raw = reference.detach();
            let name = BString::from(raw.name).as_bytes().to_vec();
            let target = match raw.target {
                gix::refs::Target::Object(oid) => RefTarget::Object(oid_from_oid(&oid)),
                gix::refs::Target::Symbolic(name) => {
                    RefTarget::Symbolic(BString::from(name).as_bytes().to_vec())
                }
            };
            out.push(RefObservation {
                name,
                target,
                peeled: raw.peeled.as_ref().map(|oid| oid_from_oid(oid)),
            });
        }
        Ok(out)
    }

    fn head(&self, instance: &GitInstance) -> crate::Result<HeadState> {
        let repo = open_repo(&instance.git_dir)?;
        match repo.head() {
            Ok(head) => Ok(match head.kind {
                gix::head::Kind::Symbolic(reference) => HeadState::Branch {
                    ref_name: BString::from(reference.name).as_bytes().to_vec(),
                    oid: reference
                        .target
                        .try_id()
                        .map(oid_from_oid)
                        .or_else(|| reference.peeled.as_ref().map(|oid| oid_from_oid(oid))),
                },
                gix::head::Kind::Unborn(name) => HeadState::Unborn {
                    ref_name: BString::from(name).as_bytes().to_vec(),
                },
                gix::head::Kind::Detached { target, peeled } => HeadState::Detached {
                    target: oid_from_oid(&target),
                    peeled: peeled.as_ref().map(|oid| oid_from_oid(oid)),
                },
            }),
            Err(_) => {
                if instance.git_dir.join("HEAD").is_file() {
                    Ok(HeadState::Invalid)
                } else {
                    Ok(HeadState::Unknown)
                }
            }
        }
    }

    fn worktrees(&self, instance: &GitInstance) -> crate::Result<Vec<WorktreeObservation>> {
        let repo = open_repo(&instance.git_dir)?;
        let proxies = repo.worktrees().map_err(|e| {
            if is_admin_unsupported(&e.to_string()) {
                unsupported(format!("worktree registry: {e}"))
            } else {
                git_err(format!("worktree registry: {e}"))
            }
        })?;
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for proxy in &proxies {
            let id = proxy.id().to_string();
            seen.insert(id.clone());
            let lock_reason = proxy.lock_reason().map(|reason| reason.to_string());
            let availability = match proxy.base() {
                Ok(base) if base.is_dir() => WorktreeAvailability::Present,
                Ok(_) => {
                    if proxy.is_locked() {
                        WorktreeAvailability::Inaccessible
                    } else {
                        WorktreeAvailability::Missing
                    }
                }
                Err(_) => {
                    if proxy.is_prunable() && !proxy.is_locked() {
                        WorktreeAvailability::Missing
                    } else {
                        WorktreeAvailability::Inaccessible
                    }
                }
            };
            let base = proxy.base().unwrap_or_default();
            out.push(WorktreeObservation {
                id,
                base,
                availability,
                lock_reason,
            });
        }
        // Entries without a `gitdir` file are silently skipped by
        // `worktrees()`; scan the registry directly and report them broken.
        let registry = instance.common_dir.join("worktrees");
        if let Ok(entries) = std::fs::read_dir(&registry) {
            for entry in entries.flatten() {
                let file_name = entry.file_name().to_string_lossy().into_owned();
                if seen.contains(&file_name) || !entry.path().is_dir() {
                    continue;
                }
                if entry.path().join("gitdir").is_file() {
                    continue;
                }
                out.push(WorktreeObservation {
                    id: file_name,
                    base: std::path::PathBuf::new(),
                    availability: WorktreeAvailability::Broken,
                    lock_reason: None,
                });
            }
        }
        Ok(out)
    }

    fn status(&self, instance: &GitInstance, mode: StatusMode) -> crate::Result<StatusObservation> {
        self.status_interruptible(instance, mode, None)
    }
}

/// Open a repository at its exact path: normal attempt first, then
/// `open_path_as_is` for arbitrarily named bare stores (GIT_QUAL §1).
/// Never searches upward.
///
/// Include following is DISABLED (SR-STATE-05): gix 0.88 `open` exposes
/// only `Permissions.config.includes: bool` — no depth, file-count, or
/// byte cap. The enabled path hardcodes `includes::Options::follow`
/// (`max_depth: 10`, error past it) with unbounded per-file reads through
/// gix's own loader (no regular-only/no-follow guard, no byte cap, fan-out
/// across sibling includes uncounted). Bounding is impossible at this
/// layer, so includes stay off and include-bearing repos are flagged by
/// the bounded pre-scan [`config_include_gap`] (explicit gap evidence for
/// the scheduler; included values are not reflected in observations).
fn open_repo(path: &std::path::Path) -> crate::Result<gix::Repository> {
    let mut permissions = gix::open::Permissions::default();
    permissions.config.includes = false;
    permissions.config.git_binary = false;
    let options = gix::open::Options::default().permissions(permissions);
    match gix::ThreadSafeRepository::open_opts(path.to_path_buf(), options) {
        Ok(repo) => Ok(repo.to_thread_local()),
        Err(first) => {
            let mut permissions = gix::open::Permissions::default();
            permissions.config.includes = false;
            permissions.config.git_binary = false;
            let options = gix::open::Options::default()
                .permissions(permissions)
                .open_path_as_is(true);
            gix::ThreadSafeRepository::open_opts(path.to_path_buf(), options)
                .map(|repo| repo.to_thread_local())
                .map_err(|second| {
                    git_err(format!(
                        "not a repository at {}: {first} / {second}",
                        path.display()
                    ))
                })
        }
    }
}

/// Convert a gix object id without assuming its hash length.
fn oid_from_oid(oid: &gix::hash::oid) -> Oid {
    Oid {
        algorithm: oid.kind().to_string(),
        hex: oid.to_hex().to_string(),
    }
}

/// Wrap a message as an operational git error.
fn git_err(message: impl Into<String>) -> crate::Error {
    crate::Error::Git(message.into())
}

/// Wrap a message as a fallback-eligible structural gap.
fn unsupported(message: impl Into<String>) -> crate::Error {
    crate::Error::Git(format!("{UNSUPPORTED_MARKER}{}", message.into()))
}

/// Map ref-store failures, routing reftable/structural gaps to fallback.
fn map_ref_store_error(message: &str, what: &str) -> crate::Error {
    if message.contains("reftable") || message.contains("unsupported storage backend") {
        unsupported(format!("{what}: {message}"))
    } else {
        git_err(format!("{what}: {message}"))
    }
}

/// True when a status failure smells like an unsupported index version.
fn is_index_unsupported(message: &str) -> bool {
    message.contains("unsupported")
        && (message.contains("index")
            || message.contains("version")
            || message.contains("extension"))
}

/// True when a worktree-admin failure smells structural, not transient.
fn is_admin_unsupported(message: &str) -> bool {
    message.contains("unsupported") || message.contains("reftable")
}

/// Cheap filesystem pre-check: HEAD + objects/ + refs/ directly under `path`.
fn looks_like_git_dir(path: &std::path::Path) -> bool {
    path.join("HEAD").is_file() && path.join("objects").is_dir() && path.join("refs").is_dir()
}

/// Read a `.git` pointer file's `gitdir: <target>` line, if well-formed.
fn read_gitdir_pointer(path: &std::path::Path) -> Option<String> {
    let text = read_bounded_string(path, MAX_GITDIR_POINTER_BYTES)?;
    let line = text.lines().next()?;
    let target = line.strip_prefix("gitdir:")?.trim();
    if target.is_empty() {
        return None;
    }
    Some(target.to_string())
}

/// `head:<hex|unborn|unknown>` fingerprint for instability detection.
fn head_fingerprint(repo: &gix::Repository) -> String {
    match repo.head() {
        Ok(head) => match head.kind {
            gix::head::Kind::Symbolic(reference) => reference
                .target
                .try_id()
                .map(|id| format!("head:{}", id.to_hex()))
                .unwrap_or_else(|| "head:unresolved".to_string()),
            gix::head::Kind::Unborn(name) => {
                format!("head:unborn:{}", BString::from(name))
            }
            gix::head::Kind::Detached { target, .. } => {
                format!("head:detached:{}", target.to_hex())
            }
        },
        Err(_) => "head:unknown".to_string(),
    }
}

/// `index:<mtime-nanos>:<size>` fingerprint for instability detection.
fn index_fingerprint(repo: &gix::Repository) -> String {
    match std::fs::metadata(repo.index_path()) {
        Ok(meta) => {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("index:{mtime}:{}", meta.len())
        }
        Err(_) => "index:missing".to_string(),
    }
}

/// Narrow scan for `path = ...` values under `[include]`/`[includeIf]`.
fn scan_include_paths(config_text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_include = false;
    for raw_line in config_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') {
            let section = line.to_lowercase();
            in_include = section == "[include]" || section.starts_with("[includeif ");
            continue;
        }
        if !in_include {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if key.trim().eq_ignore_ascii_case("path") {
                let value = value.trim().trim_matches('"').trim().to_string();
                if !value.is_empty() {
                    out.push(value);
                }
            }
        }
    }
    out
}

/// Maximum live-enumerated submodules assessed for filter drivers.
/// Past the cap the driver set is unknown, so the probe refuses
/// (fail closed) instead of scanning unboundedly.
const MAX_FILTER_SUBMODULE_SCAN: usize = 4096;

/// Maximum `modules/` nesting depth assessed for filter drivers
/// (mirrors the depth cap in [`GixInspector::config_dependencies`]).
const MAX_FILTER_MODULES_DEPTH: u8 = 4;

/// Maximum entries read from one `modules/` directory during the
/// filter-driver scan; past the cap the set is unknown, so refuse.
const MAX_FILTER_MODULES_ENTRIES: usize = 256;

/// Outcome of one bounded filter-driver scan step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterScan {
    /// No executable drivers observed.
    Clean,
    /// Drivers observed, or absence unprovable (present-but-unreadable
    /// control file, unreadable directory, breached cap): refuse.
    Refuse,
}

impl FilterScan {
    fn refuses(self) -> bool {
        matches!(self, FilterScan::Refuse)
    }
}

/// Scan the repo-local configs gix loads for one admin dir pair:
/// `config` plus `config.worktree` under each dir (gix reads only the
/// git dir's worktree config, and only when `extensions.worktreeConfig`
/// holds — scanning all four is a conservative superset that never
/// misses a driver gix would execute).
fn scan_repo_filter_configs(git_dir: &std::path::Path, common_dir: &std::path::Path) -> FilterScan {
    let mut candidates = vec![
        git_dir.join("config"),
        common_dir.join("config"),
        git_dir.join("config.worktree"),
        common_dir.join("config.worktree"),
    ];
    candidates.sort();
    candidates.dedup();
    for candidate in candidates {
        if scan_config_file_for_filters(&candidate).refuses() {
            return FilterScan::Refuse;
        }
    }
    FilterScan::Clean
}

/// Scan one config file for executable filter-driver keys. A missing
/// file is clean (no drivers to execute); a present-but-unreadable one
/// (over-cap, link, FIFO, directory, race) refuses — gix follows links
/// and reads unboundedly, so absence is unprovable there.
fn scan_config_file_for_filters(path: &std::path::Path) -> FilterScan {
    match read_bounded_string(path, MAX_GIT_CONTROL_BYTES) {
        Some(text) if config_text_names_exec_filter(&text) => FilterScan::Refuse,
        Some(_) => FilterScan::Clean,
        None if std::fs::symlink_metadata(path).is_err() => FilterScan::Clean,
        None => FilterScan::Refuse,
    }
}

/// True when config text names an executable driver: a
/// `clean`/`smudge`/`process` key inside any `[filter ...]` section
/// (case-insensitive; value ignored — presence alone makes gix spawn
/// the driver on attribute match). `required` and other flags are
/// inert without a command key. Mirrors the fallback's
/// `is_exec_filter_key` boundary (key-only, value ignored).
fn config_text_names_exec_filter(config_text: &str) -> bool {
    let mut in_filter = false;
    for raw_line in config_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') {
            // Section name runs to the first whitespace or `]`:
            // `[filter "my.driver"]`, `[filter]`, `[Filter]`.
            let name = line
                .strip_prefix('[')
                .unwrap_or_default()
                .split([' ', '\t', ']'])
                .next()
                .unwrap_or_default();
            in_filter = name.eq_ignore_ascii_case("filter");
            continue;
        }
        if !in_filter {
            continue;
        }
        let key = line.split_once('=').map_or(line, |(key, _)| key).trim();
        if key.eq_ignore_ascii_case("clean")
            || key.eq_ignore_ascii_case("smudge")
            || key.eq_ignore_ascii_case("process")
        {
            return true;
        }
    }
    false
}

/// Recursive `modules/`-tree scan for nested-submodule driver configs.
/// Depth- and entry-capped; unreadable directories, breached caps, and
/// unreadable configs refuse (fail closed). Nothing is followed through
/// links (PATH-GIT-07): a linked `config` refuses via
/// [`scan_config_file_for_filters`], and a linked entry that could be a
/// submodule gitdir refuses as unprovable.
fn scan_modules_tree(modules_dir: &std::path::Path, depth: u8) -> FilterScan {
    if depth > MAX_FILTER_MODULES_DEPTH {
        return FilterScan::Refuse;
    }
    let entries = match std::fs::read_dir(modules_dir) {
        Ok(entries) => entries,
        // Absent `modules/` (no submodules) is clean; any other failure
        // (permissions, races, non-directories) is unknown, so refuse —
        // except a provably absent path, which simply has no submodules.
        Err(_) if std::fs::symlink_metadata(modules_dir).is_err() => return FilterScan::Clean,
        Err(_) => return FilterScan::Refuse,
    };
    let mut count = 0usize;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return FilterScan::Refuse,
        };
        count += 1;
        if count > MAX_FILTER_MODULES_ENTRIES {
            return FilterScan::Refuse;
        }
        let path = entry.path();
        // lstat, no follow: links never resolve outside the tree.
        let file_type = match std::fs::symlink_metadata(&path).map(|m| m.file_type()) {
            Ok(file_type) => file_type,
            Err(_) => return FilterScan::Refuse,
        };
        if file_type.is_symlink() {
            // A linked name could be a submodule gitdir gix status would
            // open and recurse into — unprovable, so refuse.
            return FilterScan::Refuse;
        }
        if !file_type.is_dir() {
            continue;
        }
        if scan_repo_filter_configs(&path, &path).refuses()
            || scan_modules_tree(&path.join("modules"), depth + 1).refuses()
        {
            return FilterScan::Refuse;
        }
    }
    FilterScan::Clean
}

/// Resolve an include path the way git does: `~/` against HOME, relative
/// against the including file's directory, absolute as-is.
fn resolve_include_path(target: &str, base: &std::path::Path) -> std::path::PathBuf {
    if let Some(rest) = target.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::Path::new(&home).join(rest);
        }
    }
    let path = std::path::Path::new(target);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// Lossless bytes-to-`OsStr` on unix; lossy fallback elsewhere.
fn os_str_from_bytes(bytes: &[u8]) -> &std::ffi::OsStr {
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStrExt::from_bytes(bytes)
    }
    #[cfg(not(unix))]
    {
        std::ffi::OsStr::new(std::str::from_utf8(bytes).unwrap_or_default())
    }
}
