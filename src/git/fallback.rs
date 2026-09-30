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
//! Capabilities are probed once per installed-git identity (binary path +
//! `git --version`) and reused; [`FallbackGit`] caches them at discovery.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{HeadState, Oid, RefObservation, RefTarget};

/// Well-known installed-git locations checked before `$PATH` entries.
pub const KNOWN_GIT_PATHS: &[&str] = &[
    "/usr/bin/git",
    "/usr/local/bin/git",
    "/opt/homebrew/bin/git",
    "/opt/local/bin/git",
];

/// Capability record for one installed-git identity.
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Raw `git --version` output (also the identity string).
    pub version: String,
    /// Parsed `(major, minor, patch)`; unknown parts are zero.
    pub version_tuple: (u32, u32, u32),
    /// `--no-optional-locks` supported (git >= 2.14).
    pub no_optional_locks: bool,
    /// `status --porcelain=v2` supported (git >= 2.11).
    pub porcelain_v2: bool,
    /// `worktree list --porcelain` supported (git >= 2.7).
    pub worktree_list: bool,
}

/// Installed-git fallback bound to one probed binary.
#[derive(Debug, Clone)]
pub struct FallbackGit {
    path: PathBuf,
    capabilities: Capabilities,
}

impl FallbackGit {
    /// Discover and probe an installed git.
    ///
    /// `explicit` paths are tried first, then [`KNOWN_GIT_PATHS`], then
    /// `$PATH` entries. The first binary answering `git --version` wins;
    /// its capabilities are derived from documented version floors and
    /// cached in the returned handle (probe-once-per-identity).
    pub fn discover(explicit: &[PathBuf]) -> Option<Self> {
        let mut candidates: Vec<PathBuf> = explicit.to_vec();
        for known in KNOWN_GIT_PATHS {
            let path = PathBuf::from(known);
            if !candidates.contains(&path) {
                candidates.push(path);
            }
        }
        if let Ok(path_var) = std::env::var("PATH") {
            for entry in std::env::split_paths(&path_var) {
                let path = entry.join("git");
                if !candidates.contains(&path) {
                    candidates.push(path);
                }
            }
        }
        for candidate in candidates {
            if let Some(found) = Self::probe(&candidate) {
                return Some(found);
            }
        }
        None
    }

    /// Probe one explicit binary path. Returns `None` when it is missing,
    /// not executable, or does not answer `--version`.
    pub fn probe(path: &Path) -> Option<Self> {
        let output = Command::new(path)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !version.starts_with("git version ") {
            return None;
        }
        let tuple = parse_git_version(&version);
        let at_least =
            |major: u32, minor: u32| tuple.0 > major || (tuple.0 == major && tuple.1 >= minor);
        Some(Self {
            path: path.to_path_buf(),
            capabilities: Capabilities {
                version,
                version_tuple: tuple,
                no_optional_locks: at_least(2, 14),
                porcelain_v2: at_least(2, 11),
                worktree_list: at_least(2, 7),
            },
        })
    }

    /// Binary path selected at discovery.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
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
    /// status, config --get).
    fn run(
        &self,
        git_dir: &Path,
        work_tree: Option<&Path>,
        args: &[&str],
    ) -> crate::Result<Vec<u8>> {
        let mut command = Command::new(&self.path);
        command
            .arg(format!("--git-dir={}", git_dir.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_PREFIX")
            .env_remove("GIT_HTTP_PROXY")
            .env_remove("GIT_HTTPS_PROXY")
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY");
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
            .args(args);
        let output = command.output().map_err(|e| {
            crate::Error::Git(format!(
                "installed git ({}): spawn failed: {e}",
                self.path.display()
            ))
        })?;
        if !output.status.success() {
            return Err(crate::Error::Git(format!(
                "installed git ({}): `{}` failed",
                self.path.display(),
                args.join(" ")
            )));
        }
        Ok(output.stdout)
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
