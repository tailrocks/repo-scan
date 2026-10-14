//! Deterministic benchmark corpus generator (goal §7.1 dataset families).
//!
//! Recovers and generalizes B21's `benches/corpus.rs` builder: from a frozen
//! recipe JSON (`proof/datasets/<id>.json`, schema `repo-scan/dataset-recipe/1`)
//! plus a scale tier (`smoke` | `pilot` | `full`) it materializes a real
//! on-disk fixture tree under a caller-provided output root and emits a truth
//! manifest (`repo-scan/dataset-manifest/1`) beside it.
//!
//! Invocation (a bench main; `cargo run` has no `--bench` selector):
//!
//! ```text
//! cargo bench --bench corpus -- --recipe <id-or-path> --out <dir> [--tier smoke|pilot|full]
//! ```
//!
//! Layout of `<dir>` after a run:
//!
//! - `<dir>/tree/`     — the corpus root a benchmark scans.
//! - `<dir>/manifest.json` — truth manifest (repositories, worktrees, common
//!   stores, refs, HEAD states, special entries, counts, tree digest).
//!
//! Truth independence (TDD-04): the manifest is built from the recipe plus
//! safe installed-git inspection (`git rev-parse`, `git for-each-ref`,
//! `git worktree list --porcelain`, …) and the generator's own std::fs walk —
//! never from repo-scan output.
//!
//! Determinism: one fixed committer/author identity and timestamp, seeded
//! splitmix64 content, and a root-independent tree digest
//! (`corpus-digest-v1`, see proof/datasets/README.md). The same
//! (recipe, tier, seed, generator version, git version) tuple yields the same
//! `tree_sha256` in any output root.
//!
//! This file is also compiled into `tests/corpus_impl.rs` via `#[path]`, so
//! everything the tests need is `pub` and dead code is allowed.

#![allow(dead_code)]

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

/// Manifest schema identifier written into every emitted manifest.
pub const MANIFEST_SCHEMA: &str = "repo-scan/dataset-manifest/1";
/// Generator version; bump on any behavioral change to layout or digest.
pub const GENERATOR_VERSION: u64 = 1;
/// Tree digest algorithm identifier (documented in proof/datasets/README.md).
pub const DIGEST_ALGORITHM: &str = "corpus-digest-v1";
/// Fixed author/committer timestamp (git raw date format, like git's own
/// test_tick): identical commits get identical OIDs on every host.
const FIXED_DATE: &str = "1234567890 +0000";

/// Result type for all generator operations: loud string errors, no panics.
pub type Res<T> = Result<T, String>;

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

/// Seeded splitmix64: cheap, stable, fully specified content RNG.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(n);
        out
    }
}

/// Lowercase hex encoding (no hex crate in the dependency set).
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Standard base64 with padding (no base64 crate in the dependency set).
pub fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(unix)]
fn os_bytes(s: &OsStr) -> Vec<u8> {
    s.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn os_bytes(s: &OsStr) -> Vec<u8> {
    s.to_string_lossy().into_owned().into_bytes()
}

#[cfg(unix)]
fn path_from_bytes(b: &[u8]) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(b))
}

#[cfg(not(unix))]
fn path_from_bytes(b: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(b).into_owned())
}

/// Raw bytes of a path as the platform stores them (unix) or lossy UTF-8.
fn path_bytes(p: &Path) -> Vec<u8> {
    os_bytes(p.as_os_str())
}

/// Lexical normalization: resolve `.`/`..` without touching the filesystem.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn write_file(path: &Path, contents: &[u8]) -> Res<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(path, contents).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Evenly spread `count` distinct indices over `0..total` (endpoints included).
fn spread(total: u64, count: u64) -> Vec<u64> {
    if count == 0 || total == 0 {
        return Vec::new();
    }
    if count == 1 {
        return vec![0];
    }
    (0..count).map(|i| i * (total - 1) / (count - 1)).collect()
}

// ---------------------------------------------------------------------------
// Hermetic git runner (mirrors tests/common/fixture.rs git_cmd style, plus a
// fixed commit date so commit OIDs are reproducible)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn null_device() -> &'static str {
    "/dev/null"
}

#[cfg(not(unix))]
fn null_device() -> &'static str {
    "NUL"
}

/// Base git command: hermetic config, fixed identity and date, no background
/// maintenance, local file protocol allowed (clones/pushes stay on-disk).
fn git_cmd(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_CONFIG_SYSTEM", null_device())
        .env("GIT_AUTHOR_NAME", "repo-scan-corpus")
        .env("GIT_AUTHOR_EMAIL", "corpus@example.invalid")
        .env("GIT_COMMITTER_NAME", "repo-scan-corpus")
        .env("GIT_COMMITTER_EMAIL", "corpus@example.invalid")
        .env("GIT_AUTHOR_DATE", FIXED_DATE)
        .env("GIT_COMMITTER_DATE", FIXED_DATE)
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-c")
        .arg("user.name=repo-scan-corpus")
        .arg("-c")
        .arg("user.email=corpus@example.invalid")
        .arg("-c")
        .arg("init.defaultBranch=main")
        .arg("-c")
        .arg("commit.gpgsign=false")
        .arg("-c")
        .arg("maintenance.auto=false")
        .arg("-c")
        .arg("gc.autoDetach=false")
        .arg("-c")
        .arg("gc.auto=0")
        .arg("-c")
        .arg("protocol.file.allow=always");
    cmd
}

/// Run git, returning stdout bytes; Err carries command + stderr.
fn git(dir: &Path, args: &[&str]) -> Res<Vec<u8>> {
    let out = git_try(dir, args)?;
    if !out.status.success() {
        return Err(format!(
            "git {args:?} in {} failed ({}): {}",
            dir.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

/// Run git without asserting success (optional-state queries).
fn git_try(dir: &Path, args: &[&str]) -> Res<Output> {
    git_cmd(dir)
        .args(args)
        .output()
        .map_err(|e| format!("spawn git {args:?} in {}: {e}", dir.display()))
}

fn git_line(dir: &Path, args: &[&str]) -> Res<String> {
    let out = git(dir, args)?;
    Ok(String::from_utf8_lossy(&out).trim().to_owned())
}

/// Seed a working-tree repo at `dir`: init, write+commit `files` (flat
/// names), extra local `branches`, optional origin remote. Empty `files`
/// leaves the repo unborn (no commit).
fn mkrepo(
    dir: &Path,
    files: &[(&str, Vec<u8>)],
    branches: &[String],
    remote: Option<&str>,
) -> Res<()> {
    fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    git(dir, &["init", "-q"])?;
    for (name, content) in files {
        write_file(&dir.join(name), content)?;
        git(dir, &["add", "--", name])?;
    }
    if !files.is_empty() {
        git(dir, &["commit", "-q", "-m", "seed"])?;
    }
    for b in branches {
        git(dir, &["branch", b])?;
    }
    if let Some(url) = remote {
        git(dir, &["remote", "add", "origin", url])?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Recipe loading (schema repo-scan/dataset-recipe/1 + scale tiers)
// ---------------------------------------------------------------------------

/// A recipe resolved to one scale tier.
pub struct Recipe {
    pub id: String,
    pub title: String,
    pub seed: u64,
    pub tier: String,
    pub scale: Map<String, Value>,
    pub recipe_path: PathBuf,
    pub recipe_sha256: String,
    pub expected_graph: Value,
}

/// Resolve `--recipe` argument: a file path, or a recipe id looked up under
/// `proof/datasets/` of this repository (same resolution as xtask baseline).
pub fn load_recipe(arg: &str, tier: &str) -> Res<Recipe> {
    let path = {
        let as_path = Path::new(arg);
        if as_path.is_file() {
            as_path.to_path_buf()
        } else {
            let candidate = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("proof")
                .join("datasets")
                .join(format!("{arg}.json"));
            if candidate.is_file() {
                candidate
            } else {
                return Err(format!(
                    "recipe '{arg}' is neither a file nor an id under proof/datasets/"
                ));
            }
        }
    };
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let recipe_sha256 = hex(&Sha256::digest(&bytes));
    let v: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let id = v
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{}: recipe lacks 'id'", path.display()))?
        .to_string();
    let title = v
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let seed = v
        .get("seed")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{}: recipe lacks numeric 'seed'", path.display()))?;
    let key = match tier {
        "smoke" => "scale_smoke",
        "pilot" => "scale_pilot",
        "full" => "scale",
        other => return Err(format!("unknown tier '{other}': expected smoke|pilot|full")),
    };
    let scale = v
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("recipe '{id}' lacks tier '{tier}' (key '{key}')"))?
        .clone();
    let expected_graph = v.get("expected_graph").cloned().unwrap_or(Value::Null);
    Ok(Recipe {
        id,
        title,
        seed,
        tier: tier.to_string(),
        scale,
        recipe_path: path,
        recipe_sha256,
        expected_graph,
    })
}

fn parse_scale<T: for<'de> Deserialize<'de>>(scale: &Map<String, Value>, family: &str) -> Res<T> {
    serde_json::from_value(Value::Object(scale.clone()))
        .map_err(|e| format!("recipe '{family}' scale parameters: {e}"))
}

// ---------------------------------------------------------------------------
// Per-family scale parameters (field names match proof/datasets/*.json)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct WideScale {
    dirs: u64,
    files_per_dir: u64,
    repos: u64,
    refs_per_repo: u64,
    #[serde(default)]
    max_depth: u64,
    #[serde(default)]
    roots: u64,
    #[serde(default)]
    non_utf8_entries: u64,
}

#[derive(Deserialize)]
struct DirHeavyScale {
    dirs: u64,
    files: u64,
    repos: u64,
    max_depth: u64,
    #[serde(default)]
    roots: u64,
    #[serde(default)]
    avg_files_per_dir: f64,
    #[serde(default)]
    permission_denied_dirs: u64,
}

#[derive(Deserialize)]
struct DeepScale {
    chain_depth: u64,
    side_branches: u64,
    side_branch_depth: u64,
    repos: u64,
    deepest_repo_depth: u64,
    #[serde(default)]
    dirs: u64,
    #[serde(default)]
    files: u64,
    #[serde(default)]
    roots: u64,
}

#[derive(Deserialize)]
struct HugeStoreScale {
    loose_objects: u64,
    packfiles: u64,
    pack_bytes_approx: u64,
    refs: u64,
    #[serde(default)]
    repos: u64,
    #[serde(default)]
    roots: u64,
}

#[derive(Deserialize)]
struct TinyScale {
    repos: u64,
    files_per_repo: u64,
    commits_per_repo: u64,
    remotes_per_repo: u64,
    #[serde(default)]
    roots: u64,
}

#[derive(Deserialize)]
struct LinkedScale {
    common_stores: u64,
    worktrees_per_store: u64,
    refs_per_store: u64,
    #[serde(default)]
    total_checkouts: u64,
    #[serde(default)]
    roots: u64,
}

#[derive(Deserialize)]
struct RefsScale {
    repos: u64,
    refs_per_repo: u64,
    loose_fraction: f64,
    packed_fraction: f64,
    symbolic_heads: u64,
    detached_heads: u64,
    unborn_heads: u64,
    #[serde(default)]
    roots: u64,
}

#[derive(Deserialize)]
struct ClonesScale {
    clones: u64,
    upstream_bare_repos: u64,
    identical_remote_url: bool,
    #[serde(default)]
    roots: u64,
}

#[derive(Deserialize)]
struct NestedScale {
    hidden_repos: u64,
    ignored_repos: u64,
    nested_repos: u64,
    cache_tmp_build_package_dirs: u64,
    administrative_nesting_repos: u64,
    repos: u64,
    #[serde(default)]
    roots: u64,
}

/// Everything a family generator produced that the manifest must record.
#[derive(Default)]
pub struct GenOut {
    /// Absolute paths of every repository working tree / bare store created.
    pub repos: Vec<PathBuf>,
    /// Non-UTF-8 ordinary entries: (absolute path, kind "dir"|"file",
    /// created). Hosts rejecting non-UTF-8 names (EILSEQ, e.g. macOS/APFS)
    /// record the intended entries with created=false — an explicit
    /// unavailable capability, never a silent skip.
    pub non_utf8: Vec<(PathBuf, &'static str, bool)>,
    /// Directories chmodded unreadable (unix).
    pub denied: Vec<PathBuf>,
}

// ---------------------------------------------------------------------------
// Family generators
// ---------------------------------------------------------------------------

fn check_roots(roots: u64, family: &str) -> Res<()> {
    if roots > 1 {
        return Err(format!("recipe '{family}': roots > 1 not supported yet"));
    }
    Ok(())
}

/// wide-file-heavy: `dirs` leaf dirs in two levels of groups, each leaf with
/// `files_per_dir` plain files; `repos` spread leaves become repos (seed
/// commit + untracked files); `non_utf8_entries` invalid-name entries
/// (unix only).
fn gen_wide_file_heavy(root: &Path, r: &Recipe, out: &mut GenOut) -> Res<()> {
    let s: WideScale = parse_scale(&r.scale, "wide-file-heavy")?;
    check_roots(s.roots, "wide-file-heavy")?;
    if s.repos > s.dirs {
        return Err("wide-file-heavy: repos > dirs".into());
    }
    let mut rng = Rng::new(r.seed);
    let wide = root.join("wide");
    let leaves_per_group = (s.dirs as f64).sqrt().ceil() as u64;
    let leaves_per_group = leaves_per_group.max(1);
    let repo_leaves: BTreeSet<u64> = spread(s.dirs, s.repos).into_iter().collect();
    let mut created = 0u64;
    let mut g = 0u64;
    while created < s.dirs {
        let group = wide.join(format!("g{g:03}"));
        for l in 0..leaves_per_group {
            if created >= s.dirs {
                break;
            }
            let leaf = group.join(format!("l{l:03}"));
            if repo_leaves.contains(&created) {
                let extra: Vec<String> = (1..s.refs_per_repo).map(|j| format!("b{j:02}")).collect();
                let url = format!(
                    "https://example.invalid/bench-o{:03}/bench-r{created:06}.git",
                    created % 100
                );
                mkrepo(
                    &leaf,
                    &[("seed.txt", format!("leaf {created}\n").into_bytes())],
                    &extra,
                    Some(&url),
                )?;
                for f in 0..s.files_per_dir {
                    write_file(&leaf.join(format!("f{f:03}.txt")), &rng.bytes(48))?;
                }
                out.repos.push(leaf);
            } else {
                for f in 0..s.files_per_dir {
                    write_file(&leaf.join(format!("f{f:03}.txt")), &rng.bytes(48))?;
                }
            }
            created += 1;
        }
        g += 1;
    }
    gen_non_utf8(&wide.join("nonutf8"), s.non_utf8_entries, out)
}

/// Non-UTF-8 ordinary entries: guaranteed-invalid UTF-8 names (unix only;
/// recorded as unsupported elsewhere). Hosts that reject invalid UTF-8 names
/// at the syscall layer (EILSEQ — macOS/APFS) get the intended entries
/// recorded with created=false instead of a hard error.
#[cfg(unix)]
fn gen_non_utf8(dir: &Path, count: u64, out: &mut GenOut) -> Res<()> {
    if count == 0 {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    for i in 0..count {
        // 0x80..=0xBF can never start a UTF-8 sequence; 0xFE never appears.
        let mut name = b"bad-".to_vec();
        name.push(0x80 + (i % 0x40) as u8);
        name.push(0xFE);
        name.extend_from_slice(format!("-{i}").as_bytes());
        let name = OsStr::from_bytes(&name);
        let path = dir.join(name);
        let (result, kind) = if i % 2 == 0 {
            (fs::create_dir_all(&path), "dir")
        } else {
            (fs::write(&path, b"non-utf8\n"), "file")
        };
        match result {
            Ok(()) => out.non_utf8.push((path, kind, true)),
            Err(e) if e.raw_os_error() == Some(libc::EILSEQ) => {
                out.non_utf8.push((path, kind, false));
            }
            Err(e) => return Err(format!("create {}: {e}", path.display())),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn gen_non_utf8(_dir: &Path, _count: u64, _out: &mut GenOut) -> Res<()> {
    Ok(()) // unsupported platform: manifest records zero non-UTF-8 entries
}

/// dir-heavy: `dirs` directories in a breadth-first tree of bounded depth,
/// `files` round-robin files, `repos` spread repos, `permission_denied_dirs`
/// empty chmod-000 leaf dirs (unix).
fn gen_dir_heavy(root: &Path, r: &Recipe, out: &mut GenOut) -> Res<()> {
    let s: DirHeavyScale = parse_scale(&r.scale, "dir-heavy")?;
    check_roots(s.roots, "dir-heavy")?;
    if s.permission_denied_dirs + s.repos > s.dirs {
        return Err("dir-heavy: repos + permission_denied_dirs > dirs".into());
    }
    let base = root.join("tree");
    fs::create_dir_all(&base).map_err(|e| format!("mkdir {}: {e}", base.display()))?;
    // Branching factor: smallest b >= 2 whose b-ary tree of depth max_depth
    // holds `dirs` nodes.
    let mut b = ((s.dirs as f64)
        .powf(1.0 / (s.max_depth.max(1) as f64))
        .ceil() as u64)
        .max(2);
    let capacity = |b: u64, depth: u64| -> u64 {
        let mut total = 0u64;
        let mut level = 1u64;
        for _ in 0..depth {
            level = level.saturating_mul(b);
            total = total.saturating_add(level);
        }
        total
    };
    while capacity(b, s.max_depth) < s.dirs {
        b += 1;
    }
    // Breadth-first creation until `dirs` nodes exist.
    let mut dirs_created: Vec<PathBuf> = Vec::with_capacity(s.dirs as usize);
    let mut frontier = vec![base.clone()];
    let mut level = 0u64;
    while dirs_created.len() < s.dirs as usize && level < s.max_depth {
        let mut next = Vec::new();
        for parent in &frontier {
            for c in 0..b {
                if dirs_created.len() >= s.dirs as usize {
                    break;
                }
                let child = parent.join(format!("d{c:04}"));
                fs::create_dir_all(&child)
                    .map_err(|e| format!("mkdir {}: {e}", child.display()))?;
                dirs_created.push(child.clone());
                next.push(child);
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
        level += 1;
    }
    if dirs_created.len() < s.dirs as usize {
        return Err(format!(
            "dir-heavy: max_depth {} holds only {} of {} dirs",
            s.max_depth,
            dirs_created.len(),
            s.dirs
        ));
    }
    // Denied dirs: the last-created (deepest, leaf) dirs, kept empty.
    let total = dirs_created.len() as u64;
    let denied_start = total - s.permission_denied_dirs;
    let eligible = denied_start; // dirs that may hold files/repos
                                 // Files: round-robin over eligible dirs, first `rem` dirs get one extra.
    let per = s.files / eligible.max(1);
    let rem = s.files % eligible.max(1);
    let mut file_counts = vec![per; eligible as usize];
    for fc in file_counts.iter_mut().take(rem as usize) {
        *fc += 1;
    }
    let repo_dirs: BTreeSet<u64> = spread(eligible, s.repos).into_iter().collect();
    for (i, dir) in dirs_created.iter().enumerate() {
        let i = i as u64;
        if i >= eligible {
            continue; // denied dir: stays empty
        }
        let n = file_counts[i as usize];
        if repo_dirs.contains(&i) {
            let files: Vec<(String, Vec<u8>)> = (0..n)
                .map(|f| (format!("f{f:05}.dat"), format!("{i}:{f}\n").into_bytes()))
                .collect();
            let borrowed: Vec<(&str, Vec<u8>)> =
                files.iter().map(|(n, c)| (n.as_str(), c.clone())).collect();
            mkrepo(dir, &borrowed, &[], None)?;
            out.repos.push(dir.clone());
        } else {
            for f in 0..n {
                write_file(
                    &dir.join(format!("f{f:05}.dat")),
                    format!("{i}:{f}\n").as_bytes(),
                )?;
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in dirs_created.iter().skip(denied_start as usize) {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o000))
                .map_err(|e| format!("chmod {}: {e}", dir.display()))?;
            out.denied.push(dir.clone());
        }
    }
    Ok(())
}

/// deep-tree: one `chain_depth` chain (cycling short names), `side_branches`
/// side chains of `side_branch_depth`, repos AT chain levels evenly spaced
/// down to `deepest_repo_depth` (the chain dir itself becomes a repo; deeper
/// levels stay inside its working tree).
fn gen_deep_tree(root: &Path, r: &Recipe, out: &mut GenOut) -> Res<()> {
    let s: DeepScale = parse_scale(&r.scale, "deep-tree")?;
    check_roots(s.roots, "deep-tree")?;
    if s.deepest_repo_depth > s.chain_depth {
        return Err("deep-tree: deepest_repo_depth > chain_depth".into());
    }
    if s.repos == 0 {
        return Err("deep-tree: repos must be >= 1".into());
    }
    let mut levels: Vec<PathBuf> = Vec::with_capacity(s.chain_depth as usize);
    let mut dir = root.join("deep");
    for i in 1..=s.chain_depth {
        let name = char::from(b'a' + (i % 26) as u8).to_string();
        dir = dir.join(name);
        fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        write_file(&dir.join("f.txt"), format!("level {i}\n").as_bytes())?;
        levels.push(dir.clone());
    }
    // Side branches, spread along the chain.
    for (k, origin) in spread(s.chain_depth, s.side_branches)
        .into_iter()
        .enumerate()
    {
        let mut sdir = levels[origin as usize].join(format!("s{k:03}"));
        fs::create_dir_all(&sdir).map_err(|e| format!("mkdir {}: {e}", sdir.display()))?;
        write_file(
            &sdir.join("f.txt"),
            format!("side {k} level 0\n").as_bytes(),
        )?;
        for d in 1..s.side_branch_depth {
            sdir = sdir.join("d");
            fs::create_dir_all(&sdir).map_err(|e| format!("mkdir {}: {e}", sdir.display()))?;
            write_file(
                &sdir.join("f.txt"),
                format!("side {k} level {d}\n").as_bytes(),
            )?;
        }
    }
    // Repos at evenly spaced depths: ceil(deepest * (k+1) / repos).
    for k in 0..s.repos {
        let depth = (s.deepest_repo_depth * (k + 1)).div_ceil(s.repos);
        let dir = &levels[(depth - 1) as usize];
        git(dir, &["init", "-q"])?;
        git(dir, &["add", "--", "f.txt"])?;
        git(dir, &["commit", "-q", "-m", &format!("depth {depth}")])?;
        out.repos.push(dir.clone());
    }
    Ok(())
}

/// huge-git-object-store: one repo with `loose_objects` dangling loose blobs
/// (batched `git hash-object -w --stdin-paths`) plus `packfiles` synthetic
/// packs (`git pack-objects`, loose sources deleted after packing).
fn gen_huge_git_object_store(root: &Path, stage: &Path, r: &Recipe, out: &mut GenOut) -> Res<()> {
    let s: HugeStoreScale = parse_scale(&r.scale, "huge-git-object-store")?;
    check_roots(s.roots, "huge-git-object-store")?;
    let mut rng = Rng::new(r.seed ^ 0x5eed);
    let store = root.join("store");
    let extra: Vec<String> = (1..s.refs).map(|j| format!("b{j:02}")).collect();
    mkrepo(&store, &[("seed.txt", b"store\n".to_vec())], &extra, None)?;
    let stage_dir = stage.join("huge");
    fs::create_dir_all(&stage_dir).map_err(|e| format!("mkdir {}: {e}", stage_dir.display()))?;

    // Loose objects in batches (one git process per batch).
    const BATCH: u64 = 2000;
    let mut written = 0u64;
    while written < s.loose_objects {
        let n = BATCH.min(s.loose_objects - written);
        let mut names = Vec::with_capacity(n as usize);
        for i in 0..n {
            let p = stage_dir.join(format!("o{}.bin", written + i));
            write_file(&p, &rng.bytes(64))?;
            names.push(p);
        }
        let list: String = names.iter().map(|p| format!("{}\n", p.display())).collect();
        git_stdin(
            &store,
            &["hash-object", "-w", "--stdin-paths"],
            list.as_bytes(),
        )?;
        for p in &names {
            fs::remove_file(p).map_err(|e| format!("rm {}: {e}", p.display()))?;
        }
        written += n;
    }

    // Packfiles: batch of sized objects each, packed then loosened-deleted.
    let per_pack_objs = 128u64;
    let obj_size = (s.pack_bytes_approx / s.packfiles.max(1) / per_pack_objs).max(64) as usize;
    for p in 0..s.packfiles {
        let mut oids = Vec::with_capacity(per_pack_objs as usize);
        for i in 0..per_pack_objs {
            let file = stage_dir.join(format!("p{p}-{i}.bin"));
            write_file(&file, &rng.bytes(obj_size))?;
            let oid = git_line(
                &store,
                &["hash-object", "-w", file.to_str().ok_or("utf8 stage path")?],
            )?;
            fs::remove_file(&file).map_err(|e| format!("rm {}: {e}", file.display()))?;
            oids.push(oid);
        }
        let input = oids.join("\n") + "\n";
        git_stdin(
            &store,
            &["pack-objects", ".git/objects/pack/pack"],
            input.as_bytes(),
        )?;
        for oid in &oids {
            let loose = store
                .join(".git")
                .join("objects")
                .join(&oid[..2])
                .join(&oid[2..]);
            let _ = fs::remove_file(&loose);
        }
    }
    out.repos.push(store);
    Ok(())
}

/// Run git with stdin bytes, asserting success.
fn git_stdin(dir: &Path, args: &[&str], stdin: &[u8]) -> Res<Vec<u8>> {
    use std::io::Write;
    let mut child = git_cmd(dir)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn git {args:?} in {}: {e}", dir.display()))?;
    child
        .stdin
        .as_mut()
        .ok_or("stdin pipe")?
        .write_all(stdin)
        .map_err(|e| format!("stdin git {args:?}: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait git {args:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {args:?} in {} failed ({}): {}",
            dir.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

/// many-tiny-repos: `repos` independent one-commit repos in groups of 100.
fn gen_many_tiny_repos(root: &Path, r: &Recipe, out: &mut GenOut) -> Res<()> {
    let s: TinyScale = parse_scale(&r.scale, "many-tiny-repos")?;
    check_roots(s.roots, "many-tiny-repos")?;
    let base = root.join("tiny");
    for i in 0..s.repos {
        let dir = base
            .join(format!("g{:02}", i / 100))
            .join(format!("r{i:05}"));
        let files: Vec<(String, Vec<u8>)> = (0..s.files_per_repo)
            .map(|f| {
                (
                    format!("f{f}.txt"),
                    format!("repo {i} file {f}\n").into_bytes(),
                )
            })
            .collect();
        let borrowed: Vec<(&str, Vec<u8>)> =
            files.iter().map(|(n, c)| (n.as_str(), c.clone())).collect();
        let url = if s.remotes_per_repo > 0 {
            Some(format!("https://example.invalid/tiny/r{i:05}.git"))
        } else {
            None
        };
        mkrepo(&dir, &borrowed, &[], url.as_deref())?;
        for c in 1..s.commits_per_repo {
            write_file(
                &dir.join(format!("extra{c}.txt")),
                format!("commit {c}\n").as_bytes(),
            )?;
            git(&dir, &["add", "--", &format!("extra{c}.txt")])?;
            git(&dir, &["commit", "-q", "-m", &format!("commit {c}")])?;
        }
        out.repos.push(dir);
    }
    Ok(())
}

/// many-linked-worktrees: `common_stores` repos, each with `refs_per_store`
/// branches and `worktrees_per_store` linked worktrees (one branch each).
fn gen_many_linked_worktrees(root: &Path, r: &Recipe, out: &mut GenOut) -> Res<()> {
    let s: LinkedScale = parse_scale(&r.scale, "many-linked-worktrees")?;
    check_roots(s.roots, "many-linked-worktrees")?;
    if s.refs_per_store < s.worktrees_per_store + 1 {
        return Err(format!(
            "many-linked-worktrees: refs_per_store ({}) must be >= worktrees_per_store + 1 ({})",
            s.refs_per_store,
            s.worktrees_per_store + 1
        ));
    }
    for st in 0..s.common_stores {
        let base = root.join("linked").join(format!("s{st:02}"));
        let main = base.join("main");
        let branches: Vec<String> = (0..s.refs_per_store - 1)
            .map(|b| format!("b{b:02}"))
            .collect();
        mkrepo(
            &main,
            &[("seed.txt", format!("store {st}\n").into_bytes())],
            &branches,
            None,
        )?;
        out.repos.push(main.clone());
        for w in 0..s.worktrees_per_store {
            let wt = base.join(format!("wt{w:02}"));
            let branch = format!("b{w:02}");
            git(
                &main,
                &[
                    "worktree",
                    "add",
                    wt.to_str().ok_or("utf8 wt path")?,
                    &branch,
                ],
            )?;
            out.repos.push(wt);
        }
    }
    Ok(())
}

/// many-refs: `repos` repos with `refs_per_repo` refs each written directly
/// (loose ref files + a sorted packed-refs, verified by git inspection later).
/// Head-state cases are assigned to the last repos: unborn last, detached
/// before them, nested-symbolic before those.
fn gen_many_refs(root: &Path, r: &Recipe, out: &mut GenOut) -> Res<()> {
    let s: RefsScale = parse_scale(&r.scale, "many-refs")?;
    check_roots(s.roots, "many-refs")?;
    if s.symbolic_heads + s.detached_heads + s.unborn_heads > s.repos {
        return Err("many-refs: head-state cases exceed repos".into());
    }
    let base = root.join("refs");
    for i in 0..s.repos {
        let dir = base.join(format!("r{i:02}"));
        let is_unborn = i >= s.repos - s.unborn_heads;
        let is_detached = !is_unborn && i >= s.repos - s.unborn_heads - s.detached_heads;
        let is_symbolic = !is_unborn
            && !is_detached
            && i >= s.repos - s.unborn_heads - s.detached_heads - s.symbolic_heads;
        if is_unborn {
            mkrepo(&dir, &[], &[], None)?; // init only: unborn HEAD
            write_file(&dir.join("untracked.txt"), b"unborn\n")?;
            out.repos.push(dir);
            continue;
        }
        mkrepo(
            &dir,
            &[("seed.txt", format!("refs repo {i}\n").into_bytes())],
            &[],
            None,
        )?;
        let oid = git_line(&dir, &["rev-parse", "HEAD"])?;
        let loose = (s.refs_per_repo as f64 * s.loose_fraction).round() as u64;
        let packed = s.refs_per_repo - loose;
        let gitdir = dir.join(".git");
        for j in 0..loose {
            write_file(
                &gitdir.join("refs").join("heads").join(format!("lo-{j:06}")),
                format!("{oid}\n").as_bytes(),
            )?;
        }
        if packed > 0 {
            let mut lines = String::from("# pack-refs with: peeled fully-peeled sorted \n");
            for j in 0..packed {
                lines.push_str(&format!("{oid} refs/heads/pk-{j:06}\n"));
            }
            write_file(&gitdir.join("packed-refs"), lines.as_bytes())?;
        }
        if is_detached {
            git(&dir, &["update-ref", "--no-deref", "HEAD", &oid])?;
        } else if is_symbolic {
            git(
                &dir,
                &["symbolic-ref", "refs/heads/alias", "refs/heads/main"],
            )?;
            git(&dir, &["symbolic-ref", "HEAD", "refs/heads/alias"])?;
        }
        out.repos.push(dir);
    }
    Ok(())
}

/// independent-clones: `upstream_bare_repos` bare stores (seeded via a
/// scratch clone that is pushed and deleted) and `clones` local clones whose
/// origin URLs are the identical absolute path string per upstream.
fn gen_independent_clones(root: &Path, stage: &Path, r: &Recipe, out: &mut GenOut) -> Res<()> {
    let s: ClonesScale = parse_scale(&r.scale, "independent-clones")?;
    check_roots(s.roots, "independent-clones")?;
    if !s.identical_remote_url {
        return Err("independent-clones: identical_remote_url=false unsupported".into());
    }
    if s.upstream_bare_repos == 0 {
        return Err("independent-clones: upstream_bare_repos must be >= 1".into());
    }
    let up_base = root.join("upstream");
    let clone_base = root.join("clones");
    fs::create_dir_all(&up_base).map_err(|e| format!("mkdir {}: {e}", up_base.display()))?;
    fs::create_dir_all(&clone_base).map_err(|e| format!("mkdir {}: {e}", clone_base.display()))?;
    let mut upstreams = Vec::new();
    for u in 0..s.upstream_bare_repos {
        let bare = up_base.join(format!("up{u:02}.git"));
        git(
            &up_base,
            &["init", "-q", "--bare", bare.to_str().ok_or("utf8")?],
        )?;
        // Seed via scratch repo, push, delete scratch.
        let seed = stage.join(format!("seed{u:02}"));
        mkrepo(
            &seed,
            &[
                ("README.md", format!("upstream {u}\n").into_bytes()),
                ("src.txt", b"fn main() {}\n".to_vec()),
            ],
            &[],
            None,
        )?;
        git(
            &seed,
            &["push", "-q", bare.to_str().ok_or("utf8")?, "main:main"],
        )?;
        git(&bare, &["symbolic-ref", "HEAD", "refs/heads/main"])?;
        fs::remove_dir_all(&seed).map_err(|e| format!("rm {}: {e}", seed.display()))?;
        upstreams.push(bare.clone());
        out.repos.push(bare);
    }
    for c in 0..s.clones {
        let src = &upstreams[(c % s.upstream_bare_repos) as usize];
        let dest = format!("c{c:03}");
        git(
            &clone_base,
            &["clone", "-q", src.to_str().ok_or("utf8 src")?, &dest],
        )?;
        out.repos.push(clone_base.join(dest));
    }
    Ok(())
}

/// ignored-hidden-nested: repos under dot-dirs, repos ignored by a host
/// repo's .gitignore/.ignore, repos nested in another working tree (plus one
/// twice-nested case), repos under cache/tmp/build/node_modules names, and
/// repos nested under a host's conventional `.git/objects/<fanout>/` paths
/// (strict-mode administrative-nesting traps).
fn gen_ignored_hidden_nested(root: &Path, r: &Recipe, out: &mut GenOut) -> Res<()> {
    let s: NestedScale = parse_scale(&r.scale, "ignored-hidden-nested")?;
    check_roots(s.roots, "ignored-hidden-nested")?;
    let declared = s.hidden_repos
        + s.ignored_repos
        + s.nested_repos
        + s.cache_tmp_build_package_dirs
        + s.administrative_nesting_repos;
    if declared != s.repos {
        return Err(format!(
            "ignored-hidden-nested: category counts ({declared}) != repos ({})",
            s.repos
        ));
    }
    // Hidden under dot-directories.
    for i in 0..s.hidden_repos {
        let dir = root.join("hidden").join(format!(".h{i:02}")).join("repo");
        mkrepo(
            &dir,
            &[("seed.txt", format!("hidden {i}\n").into_bytes())],
            &[],
            None,
        )?;
        out.repos.push(dir);
    }
    // Ignored by host repo rules.
    if s.ignored_repos > 0 {
        let host = root.join("ignored_host");
        mkrepo(
            &host,
            &[
                (".gitignore", b"ignored/\n".to_vec()),
                (".ignore", b"ignored2/\n".to_vec()),
                ("seed.txt", b"ignored host\n".to_vec()),
            ],
            &[],
            None,
        )?;
        out.repos.push(host.clone());
        for i in 0..s.ignored_repos {
            let sub = if i % 2 == 0 { "ignored" } else { "ignored2" };
            let dir = host.join(sub).join(format!("r{i:02}"));
            mkrepo(
                &dir,
                &[("seed.txt", format!("ignored {i}\n").into_bytes())],
                &[],
                None,
            )?;
            out.repos.push(dir);
        }
    }
    // Nested inside another working tree (+ one twice-nested repo).
    if s.nested_repos > 0 {
        let host = root.join("nested_host");
        mkrepo(&host, &[("seed.txt", b"nested host\n".to_vec())], &[], None)?;
        out.repos.push(host.clone());
        for i in 0..s.nested_repos {
            let dir = host.join("vendor").join(format!("inner{i:02}"));
            mkrepo(
                &dir,
                &[("seed.txt", format!("inner {i}\n").into_bytes())],
                &[],
                None,
            )?;
            out.repos.push(dir.clone());
            if i == 0 {
                let innermost = dir.join("sub").join("innermost");
                mkrepo(
                    &innermost,
                    &[("seed.txt", b"innermost\n".to_vec())],
                    &[],
                    None,
                )?;
                out.repos.push(innermost);
            }
        }
    }
    // Cache/tmp/build/package-style placements.
    const PLACEMENT: [&str; 4] = ["cache", "tmp", "build", "node_modules"];
    for i in 0..s.cache_tmp_build_package_dirs {
        let dir = root
            .join("placed")
            .join(PLACEMENT[(i % PLACEMENT.len() as u64) as usize])
            .join(format!("r{i:02}"));
        mkrepo(
            &dir,
            &[("seed.txt", format!("placed {i}\n").into_bytes())],
            &[],
            None,
        )?;
        out.repos.push(dir);
    }
    // Administrative nesting under the host's .git/objects/<fanout>/.
    if s.administrative_nesting_repos > 0 {
        let host = root.join("admin_host");
        mkrepo(&host, &[("seed.txt", b"admin host\n".to_vec())], &[], None)?;
        out.repos.push(host.clone());
        for i in 0..s.administrative_nesting_repos {
            let fanout = format!("{:02x}", 0xa0u64 + i);
            let dir = host
                .join(".git")
                .join("objects")
                .join(fanout)
                .join(format!("r{i:02}"));
            mkrepo(
                &dir,
                &[("seed.txt", format!("admin-nested {i}\n").into_bytes())],
                &[],
                None,
            )?;
            out.repos.push(dir);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Truth inspection (installed git only — never repo-scan output)
// ---------------------------------------------------------------------------

/// One porcelain worktree record.
pub struct WorktreeTruth {
    pub path: PathBuf,
    pub head_oid: Option<String>,
    pub branch: Option<String>,
    pub bare: bool,
    pub detached: bool,
    pub locked: bool,
    pub prunable: bool,
}

/// Independently inspected repository truth.
pub struct RepoTruth {
    pub path: PathBuf,
    pub git_dir: PathBuf,
    pub common_dir: PathBuf,
    pub is_bare: bool,
    /// (state, symref target, oid): state in branch|detached|unborn|broken.
    pub head: (String, Option<String>, Option<String>),
    pub refs: Vec<(String, String)>,
    pub remotes: Vec<(String, String)>,
    pub worktrees: Vec<WorktreeTruth>,
}

/// Inspect one repository with safe read-only git commands.
pub fn inspect_repo(path: &Path) -> Res<RepoTruth> {
    let abs = path_from_bytes(git(path, &["rev-parse", "--absolute-git-dir"])?.trim_ascii());
    let common = match fs::read(abs.join("commondir")) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes).trim().to_owned();
            let rel = Path::new(&text);
            if rel.is_absolute() {
                normalize(rel)
            } else {
                normalize(&abs.join(rel))
            }
        }
        Err(_) => abs.clone(),
    };
    let is_bare = git_line(path, &["rev-parse", "--is-bare-repository"])? == "true";
    // --no-recurse: the immediate HEAD target (nested symbolic refs stay
    // visible; the chain tail is derivable from the refs list).
    let symref = git_try(path, &["symbolic-ref", "-q", "--no-recurse", "HEAD"])?
        .status
        .success()
        .then(|| git_line(path, &["symbolic-ref", "-q", "--no-recurse", "HEAD"]))
        .transpose()?;
    let oid = git_try(path, &["rev-parse", "--verify", "-q", "HEAD"])?
        .status
        .success()
        .then(|| git_line(path, &["rev-parse", "--verify", "-q", "HEAD"]))
        .transpose()?;
    let state = match (&symref, &oid) {
        (Some(_), Some(_)) => "branch",
        (Some(_), None) => "unborn",
        (None, Some(_)) => "detached",
        (None, None) => "broken",
    }
    .to_string();
    let refs_raw = git(
        path,
        &["for-each-ref", "--format=%(refname)%09%(objectname)"],
    )?;
    let refs = String::from_utf8_lossy(&refs_raw)
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(n, o)| (n.to_string(), o.to_string()))
        .collect();
    let mut remotes = Vec::new();
    for name in String::from_utf8_lossy(&git(path, &["remote"])?).lines() {
        let url = git_line(path, &["remote", "get-url", name])?;
        remotes.push((name.to_string(), url));
    }
    let worktrees = parse_worktree_porcelain(&git(path, &["worktree", "list", "--porcelain"])?)?;
    Ok(RepoTruth {
        path: path.to_path_buf(),
        git_dir: abs,
        common_dir: common,
        is_bare,
        head: (state, symref, oid),
        refs,
        remotes,
        worktrees,
    })
}

fn parse_worktree_porcelain(out: &[u8]) -> Res<Vec<WorktreeTruth>> {
    let text = String::from_utf8_lossy(out);
    let mut list = Vec::new();
    let mut cur: Option<WorktreeTruth> = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix("worktree ") {
            if let Some(w) = cur.take() {
                list.push(w);
            }
            cur = Some(WorktreeTruth {
                path: PathBuf::from(p),
                head_oid: None,
                branch: None,
                bare: false,
                detached: false,
                locked: false,
                prunable: false,
            });
        } else if let Some(w) = cur.as_mut() {
            if let Some(h) = line.strip_prefix("HEAD ") {
                w.head_oid = Some(h.to_string());
            } else if let Some(b) = line.strip_prefix("branch ") {
                w.branch = Some(b.to_string());
            } else if line == "bare" || line.starts_with("bare ") {
                w.bare = true;
            } else if line == "detached" {
                w.detached = true;
            } else if line == "locked" || line.starts_with("locked ") {
                w.locked = true;
            } else if line == "prunable" || line.starts_with("prunable ") {
                w.prunable = true;
            }
        }
    }
    if let Some(w) = cur.take() {
        list.push(w);
    }
    Ok(list)
}

// ---------------------------------------------------------------------------
// Tree digest (corpus-digest-v1)
// ---------------------------------------------------------------------------

/// Realized on-disk counts (everything under the tree root, git internals
/// included), recorded in the manifest.
#[derive(Default, Clone)]
pub struct Counts {
    pub dirs: u64,
    pub files: u64,
    pub symlinks: u64,
    pub inaccessible_dirs: u64,
    pub git_admin_files: u64,
}

/// Root-independent digest of the generated tree.
///
/// Line-based stream (sorted raw-name order), hashed with SHA-256:
///   `D <hex relpath>`                       directory
///   `F <hex relpath> <len> <hex sha256>`    regular file with hashed content
///   `L <hex relpath> <hex target>`          symlink
///   `X <hex relpath>`                       unreadable entry (e.g. EACCES)
///   `G <hex relpath>`                       git admin file, content not
///                                           hashed (volatile or root-bound)
///   `R <hex relpath> <hex state sha256>`    git admin root (a gitdir); state
///                                           = refs/HEAD/remotes/links from
///                                           installed-git inspection
///
/// Inside a git admin root only `HEAD`, `description`, `packed-refs`,
/// `objects/**` and `refs/**` have their content hashed; everything else
/// (config, index, logs, hooks, info, commondir/gitdir link files) is `G`.
/// Any file named exactly `.git` (gitfile) is `G` anywhere.
struct DigestWalk<'a> {
    root: &'a Path,
    admin: &'a BTreeMap<Vec<u8>, String>,
    h: Sha256,
    counts: Counts,
}

impl<'a> DigestWalk<'a> {
    fn line(&mut self, s: &str) {
        self.h.update(s.as_bytes());
        self.h.update(b"\n");
    }

    fn walk(&mut self, abs: &Path, rel: &Path, admin_ctx: Option<&Path>) -> Res<()> {
        let rd = match fs::read_dir(abs) {
            Ok(rd) => rd,
            Err(_) => {
                self.counts.inaccessible_dirs += 1;
                self.line(&format!("X {}", hex(&path_bytes(rel))));
                return Ok(());
            }
        };
        let mut entries: Vec<(OsString, PathBuf, fs::FileType)> = Vec::new();
        for e in rd {
            let e = e.map_err(|e| format!("read_dir {}: {e}", abs.display()))?;
            let ft = match e.file_type() {
                Ok(ft) => ft,
                Err(err) => {
                    return Err(format!("file_type {}: {err}", e.path().display()));
                }
            };
            entries.push((e.file_name(), e.path(), ft));
        }
        entries.sort_by_key(|e| os_bytes(&e.0));
        for (name, child, ft) in entries {
            let child_rel = rel.join(&name);
            let relhex = hex(&path_bytes(&child_rel));
            if ft.is_symlink() {
                self.counts.symlinks += 1;
                let target = fs::read_link(&child)
                    .map_err(|e| format!("read_link {}: {e}", child.display()))?;
                self.line(&format!("L {relhex} {}", hex(&path_bytes(&target))));
            } else if ft.is_dir() {
                self.counts.dirs += 1;
                let key = path_bytes(&child);
                if let Some(state) = self.admin.get(&key) {
                    self.line(&format!("R {relhex} {state}"));
                    self.walk(&child, &child_rel, Some(&child))?;
                } else {
                    self.line(&format!("D {relhex}"));
                    self.walk(&child, &child_rel, admin_ctx)?;
                }
            } else {
                self.counts.files += 1;
                let gitfile = name == OsStr::new(".git");
                let hashed = !gitfile
                    && match admin_ctx {
                        None => true,
                        Some(admin) => child
                            .strip_prefix(admin)
                            .map(admin_content_hashed)
                            .unwrap_or(false),
                    };
                if !hashed {
                    self.counts.git_admin_files += 1;
                    self.line(&format!("G {relhex}"));
                    continue;
                }
                match fs::read(&child) {
                    Ok(content) => {
                        self.line(&format!(
                            "F {relhex} {} {}",
                            content.len(),
                            hex(&Sha256::digest(&content))
                        ));
                    }
                    Err(_) => self.line(&format!("X {relhex}")),
                }
            }
        }
        Ok(())
    }
}

/// Whether a file inside a git admin area has deterministic, root-independent
/// content worth hashing (objects, refs, packed-refs, HEAD, description).
fn admin_content_hashed(rel_in_admin: &Path) -> bool {
    rel_in_admin == Path::new("HEAD")
        || rel_in_admin == Path::new("description")
        || rel_in_admin == Path::new("packed-refs")
        || rel_in_admin.starts_with("objects")
        || rel_in_admin.starts_with("refs")
}

/// Canonical per-gitdir state text for digest `R` records: refs, HEAD,
/// remotes (root-normalized URLs), gitdir/commondir links, worktree list.
fn repo_state_text(t: &RepoTruth, root: &Path) -> Res<String> {
    let mut s = String::new();
    s.push_str(&format!("bare={}\n", t.is_bare));
    s.push_str(&format!(
        "head={} {} {}\n",
        t.head.0,
        t.head.1.as_deref().unwrap_or("-"),
        t.head.2.as_deref().unwrap_or("-")
    ));
    s.push_str(&format!("git_dir={}\n", hex(&rel_bytes(root, &t.git_dir)?)));
    s.push_str(&format!(
        "common_dir={}\n",
        hex(&rel_bytes(root, &t.common_dir)?)
    ));
    for (name, oid) in &t.refs {
        s.push_str(&format!("ref {name} {oid}\n"));
    }
    let root_str = root.to_string_lossy().into_owned();
    for (name, url) in &t.remotes {
        s.push_str(&format!(
            "remote {name} {}\n",
            url.replace(&root_str, "<ROOT>")
        ));
    }
    for w in &t.worktrees {
        s.push_str(&format!(
            "worktree {} {} {} bare={} detached={} locked={} prunable={}\n",
            hex(&rel_bytes(root, &w.path)?),
            w.head_oid.as_deref().unwrap_or("-"),
            w.branch.as_deref().unwrap_or("-"),
            w.bare as u8,
            w.detached as u8,
            w.locked as u8,
            w.prunable as u8
        ));
    }
    Ok(s)
}

fn rel_bytes(root: &Path, p: &Path) -> Res<Vec<u8>> {
    p.strip_prefix(root)
        .map(path_bytes)
        .map_err(|_| format!("{} escapes corpus root {}", p.display(), root.display()))
}

// ---------------------------------------------------------------------------
// Manifest assembly + top-level generate()
// ---------------------------------------------------------------------------

/// JSON path field: `path` when the relative path is UTF-8, else `path_b64`.
fn path_json(root: &Path, abs: &Path) -> Res<(Option<String>, Option<String>)> {
    let bytes = rel_bytes(root, abs)?;
    match std::str::from_utf8(&bytes) {
        Ok(s) => Ok((Some(s.to_string()), None)),
        Err(_) => Ok((None, Some(b64(&bytes)))),
    }
}

fn worktree_json(root: &Path, w: &WorktreeTruth) -> Res<Value> {
    let (path, path_b64) = path_json(root, &w.path)?;
    Ok(json!({
        "path": path,
        "path_b64": path_b64,
        "head_oid": w.head_oid,
        "branch": w.branch,
        "bare": w.bare,
        "detached": w.detached,
        "locked": w.locked,
        "prunable": w.prunable,
    }))
}

fn repo_json(root: &Path, t: &RepoTruth) -> Res<Value> {
    let (path, path_b64) = path_json(root, &t.path)?;
    let (git_dir, git_dir_b64) = path_json(root, &t.git_dir)?;
    let (common_dir, common_dir_b64) = path_json(root, &t.common_dir)?;
    let kind = if t.is_bare {
        "bare"
    } else if t.git_dir != t.common_dir {
        "linked_worktree"
    } else {
        "checkout"
    };
    let worktrees: Vec<Value> = t
        .worktrees
        .iter()
        .map(|w| worktree_json(root, w))
        .collect::<Res<_>>()?;
    Ok(json!({
        "path": path,
        "path_b64": path_b64,
        "kind": kind,
        "is_bare": t.is_bare,
        "git_dir": git_dir,
        "git_dir_b64": git_dir_b64,
        "common_dir": common_dir,
        "common_dir_b64": common_dir_b64,
        "head": {
            "state": t.head.0,
            "ref": t.head.1,
            "oid": t.head.2,
        },
        "refs": t.refs.iter().map(|(n, o)| json!({"name": n, "oid": o})).collect::<Vec<_>>(),
        "remotes": t.remotes.iter().map(|(n, u)| json!({"name": n, "url": u})).collect::<Vec<_>>(),
        "worktrees": worktrees,
    }))
}

/// Outcome of one generation run.
pub struct GenReport {
    pub manifest_path: PathBuf,
    pub manifest: Value,
    pub stage_ms: BTreeMap<String, f64>,
}

/// Generate the fixture for `recipe_arg` at tier `tier` under `out`.
///
/// Refuses a non-empty `out` (no double-counts). Everything is written under
/// `out` and nowhere else: `out/tree/` is the corpus root, `out/manifest.json`
/// the truth manifest, `out/stage/` a scratch area removed before return.
pub fn generate(recipe_arg: &str, out: &Path, tier: &str) -> Res<GenReport> {
    let t0 = Instant::now();
    let recipe = load_recipe(recipe_arg, tier)?;
    if out.exists()
        && fs::read_dir(out)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
    {
        return Err(format!(
            "refusing to generate into non-empty {} (wipe it first)",
            out.display()
        ));
    }
    fs::create_dir_all(out).map_err(|e| format!("mkdir {}: {e}", out.display()))?;
    let out = fs::canonicalize(out).map_err(|e| format!("canonicalize {}: {e}", out.display()))?;
    let root = out.join("tree");
    fs::create_dir_all(&root).map_err(|e| format!("mkdir {}: {e}", root.display()))?;
    let stage = out.join("stage");
    fs::create_dir_all(&stage).map_err(|e| format!("mkdir {}: {e}", stage.display()))?;

    let mut gen = GenOut::default();
    match recipe.id.as_str() {
        "wide-file-heavy" => gen_wide_file_heavy(&root, &recipe, &mut gen)?,
        "dir-heavy" => gen_dir_heavy(&root, &recipe, &mut gen)?,
        "deep-tree" => gen_deep_tree(&root, &recipe, &mut gen)?,
        "huge-git-object-store" => gen_huge_git_object_store(&root, &stage, &recipe, &mut gen)?,
        "many-tiny-repos" => gen_many_tiny_repos(&root, &recipe, &mut gen)?,
        "many-linked-worktrees" => gen_many_linked_worktrees(&root, &recipe, &mut gen)?,
        "many-refs" => gen_many_refs(&root, &recipe, &mut gen)?,
        "independent-clones" => gen_independent_clones(&root, &stage, &recipe, &mut gen)?,
        "ignored-hidden-nested" => gen_ignored_hidden_nested(&root, &recipe, &mut gen)?,
        other => return Err(format!("unknown dataset family '{other}'")),
    }
    let _ = fs::remove_dir_all(&stage);
    let t_generate = t0.elapsed();

    // --- Truth inspection (installed git, read-only). ---
    let t1 = Instant::now();
    gen.repos.sort_by_key(|r| path_bytes(r));
    gen.repos.dedup();
    let mut truths = Vec::with_capacity(gen.repos.len());
    for repo in &gen.repos {
        truths.push(inspect_repo(repo)?);
    }
    let mut admin: BTreeMap<Vec<u8>, String> = BTreeMap::new();
    for t in &truths {
        let state = hex(&Sha256::digest(repo_state_text(t, &root)?.as_bytes()));
        admin.insert(path_bytes(&t.git_dir), state.clone());
        admin.entry(path_bytes(&t.common_dir)).or_insert(state);
    }
    let t_inspect = t1.elapsed();

    // --- Tree digest + realized counts. ---
    let t2 = Instant::now();
    let mut walker = DigestWalk {
        root: &root,
        admin: &admin,
        h: Sha256::new(),
        counts: Counts::default(),
    };
    walker.h.update(b"corpus-digest-v1\n");
    walker.walk(&root, Path::new(""), None)?;
    let tree_sha256 = hex(&walker.h.finalize());
    let counts = walker.counts.clone();
    let t_digest = t2.elapsed();

    // --- Manifest. ---
    let repos_json: Vec<Value> = truths
        .iter()
        .map(|t| repo_json(&root, t))
        .collect::<Res<_>>()?;
    let mut worktree_seen: BTreeMap<Vec<u8>, Value> = BTreeMap::new();
    for t in &truths {
        for w in &t.worktrees {
            let key = rel_bytes(&root, &w.path)?;
            if let std::collections::btree_map::Entry::Vacant(e) = worktree_seen.entry(key) {
                e.insert(worktree_json(&root, w)?);
            }
        }
    }
    let common_stores: BTreeSet<Vec<u8>> = truths
        .iter()
        .map(|t| rel_bytes(&root, &t.common_dir))
        .collect::<Res<_>>()?;
    let non_utf8: Vec<Value> = gen
        .non_utf8
        .iter()
        .map(|(p, kind, created)| {
            let (path, path_b64) = path_json(&root, p)?;
            Ok(json!({"path": path, "path_b64": path_b64, "kind": kind, "created": created}))
        })
        .collect::<Res<_>>()?;
    let non_utf8_supported = gen.non_utf8.iter().all(|(_, _, created)| *created);
    let denied: Vec<Value> = gen
        .denied
        .iter()
        .map(|p| {
            let (path, path_b64) = path_json(&root, p)?;
            Ok(json!({"path": path, "path_b64": path_b64}))
        })
        .collect::<Res<_>>()?;
    let parameters = json!({
        "scale": Value::Object(recipe.scale.clone()),
        "seed": recipe.seed,
        "tier": recipe.tier,
    });
    let parameters_sha256 = hex(&Sha256::digest(parameters.to_string().as_bytes()));
    let git_version = git_line(&root, &["--version"]).unwrap_or_else(|_| "unknown".into());
    let manifest = json!({
        "schema": MANIFEST_SCHEMA,
        "dataset_id": recipe.id,
        "title": recipe.title,
        "tier": recipe.tier,
        "seed": recipe.seed,
        "recipe_path": recipe.recipe_path.display().to_string(),
        "recipe_sha256": recipe.recipe_sha256,
        "parameters": parameters,
        "parameters_sha256": parameters_sha256,
        "generator": {
            "name": "repo-scan-corpus",
            "version": GENERATOR_VERSION,
            "source": "benches/corpus.rs",
        },
        "git": {"program": "git", "version_stdout": git_version},
        "root": root.display().to_string(),
        "digest_algorithm": DIGEST_ALGORITHM,
        "tree_sha256": tree_sha256,
        "expected_graph": recipe.expected_graph,
        "counts": {
            "dirs": counts.dirs,
            "files": counts.files,
            "symlinks": counts.symlinks,
            "inaccessible_dirs": counts.inaccessible_dirs,
            "git_admin_files": counts.git_admin_files,
            "repos": truths.len() as u64,
            "common_stores": common_stores.len() as u64,
            "worktrees": worktree_seen.len() as u64,
            "refs": truths.iter().map(|t| t.refs.len() as u64).sum::<u64>(),
        },
        "repositories": repos_json,
        "worktrees": worktree_seen.into_values().collect::<Vec<_>>(),
        "special_entries": {
            "non_utf8": non_utf8,
            "non_utf8_supported": non_utf8_supported,
            "permission_denied": denied,
        },
    });
    let manifest_path = out.join("manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("write {}: {e}", manifest_path.display()))?;
    let mut stage_ms = BTreeMap::new();
    stage_ms.insert("generate".into(), t_generate.as_secs_f64() * 1000.0);
    stage_ms.insert("inspect".into(), t_inspect.as_secs_f64() * 1000.0);
    stage_ms.insert("digest".into(), t_digest.as_secs_f64() * 1000.0);
    Ok(GenReport {
        manifest_path,
        manifest,
        stage_ms,
    })
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE: &str = "\
corpus — deterministic repo-scan benchmark corpus generator

USAGE:
    cargo bench --bench corpus -- --recipe <id-or-path> --out <dir> [--tier T]

ARGS:
    --recipe <id-or-path>  recipe id under proof/datasets/ or a JSON file path
    --out <dir>            output root (must be empty/absent); gets tree/ and
                           manifest.json
    --tier <T>             smoke | pilot | full   [default: pilot]
";

fn main() {
    let mut recipe = None;
    let mut out = None;
    let mut tier = "pilot".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--recipe" => recipe = args.next(),
            "--out" => out = args.next(),
            "--tier" => tier = args.next().unwrap_or_default(),
            // cargo bench appends `--bench` when running harness=false benches.
            "--bench" => {}
            "-h" | "--help" => {
                print!("{USAGE}");
                return;
            }
            other => {
                eprintln!("corpus: unknown argument '{other}'\n{USAGE}");
                std::process::exit(2);
            }
        }
    }
    let (Some(recipe), Some(out)) = (recipe, out) else {
        eprintln!("corpus: --recipe and --out are required\n{USAGE}");
        std::process::exit(2);
    };
    match generate(&recipe, Path::new(&out), &tier) {
        Ok(report) => {
            for (name, ms) in &report.stage_ms {
                println!("STAGE {name} {ms:.3}");
            }
            let m = &report.manifest;
            println!(
                "corpus ready: dataset={} tier={} seed={} repos={} dirs={} files={} tree_sha256={}",
                m["dataset_id"].as_str().unwrap_or("?"),
                m["tier"].as_str().unwrap_or("?"),
                m["seed"].as_u64().unwrap_or(0),
                m["counts"]["repos"].as_u64().unwrap_or(0),
                m["counts"]["dirs"].as_u64().unwrap_or(0),
                m["counts"]["files"].as_u64().unwrap_or(0),
                m["tree_sha256"].as_str().unwrap_or("?"),
            );
            println!("manifest: {}", report.manifest_path.display());
        }
        Err(e) => {
            eprintln!("corpus: error: {e}");
            std::process::exit(2);
        }
    }
}
