//! Branch upstream resolution (goal Step 10, D10) and graph-context
//! selection, ported from the B11 analysis path into the git layer so
//! `main.rs` only wires inputs and persists results.
//!
//! `[branch "X"]` with `remote = R` and `merge = M` resolves through the
//! remote's actual fetch refspecs to the full ref git's `@{upstream}`
//! names (e.g. `refs/remotes/origin/main`, or `refs/custom/main` under a
//! custom fetch refspec) — never a fabricated `remote/leaf` guess.
//!
//! Effective config = `common_dir/config` with `include`/`includeIf`
//! chains expanded inline (bounded depth, cycle-safe, byte-capped),
//! overlaid per checkout by that checkout's own `config.worktree` when
//! the effective `extensions.worktreeConfig` is true. Every rule was
//! probed against installed git 2.56.0: last-wins single values,
//! first-wins `branch.merge`, first-match-wins fetch mapping with no
//! fallback, `remote = .` resolving locally, case-sensitive
//! remote/subsection lookup, and existence of the mapped ref (absent
//! targets yield no upstream, exactly like git's `rev-parse
//! --symbolic-full-name '@{u}'` failing there).
//!
//! Fail-closed throughout: unparseable or unreadable effective config is
//! reported as incomplete (callers keep comparisons `pending`, never
//! `no_upstream`), missing remotes/refspecs/targets yield no entry only
//! after a complete read, and divergent per-checkout overlays drop the
//! branch rather than guess. Read-only and offline: bounded regular-file
//! reads only, no spawns.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::fallback::{FallbackGit, WaitCancel};
use super::graph::{self, Comparison, ComparisonCache};
use super::{GitInstance, RefObservation, RefTarget};

/// Effective branch-config resolution is either complete, including a
/// genuinely empty upstream map, or incomplete because some config input
/// could not be read or parsed. Keeping these outcomes distinct prevents
/// an unknown upstream from becoming `no_upstream`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchUpstreams {
    /// Complete read: branch short-name bytes → full comparison ref.
    Complete(HashMap<Vec<u8>, Vec<u8>>),
    /// Some config input could not be read or parsed: no trustworthy
    /// negative upstream result exists; comparisons stay `pending`.
    Incomplete,
}

/// Upstream (full local comparison ref) per local branch (R16, Step 10).
///
/// `checkout_git_dirs` are the git dirs of every checkout of the store,
/// in row order (the caller maps catalog rows to paths; this module
/// deliberately takes no store dependency). Config includes are
/// evaluated from each checkout's perspective: Git's `includeIf.gitdir`
/// can make the shared config effective for one linked worktree but not
/// another. The effective worktree-config gate can also vary by checkout
/// when an include sets it.
///
/// Merge across checkouts: present wins over absent (union), any
/// divergent present value drops the branch (fail closed). Deterministic
/// and order-independent.
pub fn load_branch_upstreams(
    instance: &GitInstance,
    checkout_git_dirs: &[PathBuf],
    refs: &[RefObservation],
) -> BranchUpstreams {
    let known: HashSet<&[u8]> = refs.iter().map(|r| r.name.as_slice()).collect();
    // Checkout git dirs in row order, deduplicated; the store instance
    // dir covers the degenerate no-checkout case.
    let mut git_dirs: Vec<std::path::PathBuf> = Vec::new();
    for dir in checkout_git_dirs {
        if !git_dirs.contains(dir) {
            git_dirs.push(dir.clone());
        }
    }
    if git_dirs.is_empty() {
        git_dirs.push(instance.git_dir.clone());
    }
    let mut participants: Vec<HashMap<Vec<u8>, Vec<u8>>> = Vec::new();
    let mut overlay_seen: HashSet<std::path::PathBuf> = HashSet::new();
    for dir in &git_dirs {
        let mut base = UpstreamConfig::default();
        let mut chain = IncludeChain::default();
        if parse_config_tree(
            &instance.common_dir.join("config"),
            &mut base,
            &mut chain,
            dir,
            false,
        )
        .is_err()
        {
            return BranchUpstreams::Incomplete;
        }
        let base_map = resolve_all_upstreams(&base, &known);
        // Worktree overlays apply only under this checkout's effective
        // common-config gate; a gate inside config.worktree itself never
        // counts (probed). Overlay values follow common-config values.
        let gate = base
            .last(b"extensions", b"", b"worktreeconfig")
            .is_some_and(super::refspec::config_bool_is_true);
        if !gate {
            participants.push(base_map);
            continue;
        }
        // An absent overlay leaves this checkout at its common config; a
        // present but unreadable overlay makes its upstreams unknown.
        let overlay = dir.join("config.worktree");
        if !overlay_seen.insert(overlay.clone()) {
            continue;
        }
        match std::fs::symlink_metadata(&overlay) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Absent overlay: the checkout observes the base map.
                // (Duplicates across checkouts are harmless: merging below
                // is idempotent.)
                participants.push(base_map.clone());
            }
            Err(_) => return BranchUpstreams::Incomplete,
            Ok(_) => {
                let mut effective = base.clone();
                let mut overlay_chain = IncludeChain::default();
                if parse_config_tree(&overlay, &mut effective, &mut overlay_chain, dir, true)
                    .is_err()
                {
                    return BranchUpstreams::Incomplete;
                }
                participants.push(resolve_all_upstreams(&effective, &known));
            }
        }
    }
    let mut merged: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut dropped: HashSet<Vec<u8>> = HashSet::new();
    for map in &participants {
        for (branch, upstream) in map {
            if dropped.contains(branch) {
                continue;
            }
            match merged.get(branch) {
                None => {
                    merged.insert(branch.clone(), upstream.clone());
                }
                Some(prev) if prev == upstream => {}
                Some(_) => {
                    merged.remove(branch);
                    dropped.insert(branch.clone());
                }
            }
        }
    }
    BranchUpstreams::Complete(merged)
}

/// Upstream bytes for one ref, if it is a local branch with config tracking.
/// Byte-exact: non-UTF-8 branch names resolve like any other.
#[must_use]
pub fn upstream_for_ref(upstreams: &HashMap<Vec<u8>, Vec<u8>>, name: &[u8]) -> Option<Vec<u8>> {
    let short = name.strip_prefix(b"refs/heads/")?;
    upstreams.get(short).cloned()
}

/// Maximum include-chain depth followed for upstream resolution (mirrors
/// `GixInspector::config_dependencies`).
const UPSTREAM_INCLUDE_MAX_DEPTH: u8 = 4;
/// Maximum config files read per tree (mirrors the filter-guard scan).
const UPSTREAM_INCLUDE_MAX_FILES: usize = 256;
/// Maximum `gitdir:` pattern bytes evaluated (fail closed past it).
const UPSTREAM_GITDIR_PATTERN_MAX: usize = 1024;
/// Glob-match step budget per pattern (fail closed past it).
const UPSTREAM_GLOB_STEP_BUDGET: u64 = 100_000;

/// Bounded include traversal for one config tree: lexical cycle set (no
/// symlink following anywhere, so no canonicalization for identity —
/// the depth cap bounds missed aliases) plus a shared file budget.
#[derive(Default)]
struct IncludeChain {
    seen: HashSet<std::path::PathBuf>,
    files: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IncompleteUpstreamConfig;

/// Ordered config values: `(section, subsection, key)` (section/key
/// ASCII-lowercased, subsection raw bytes) to values in file order.
/// Callers pass lowercase section/key literals. Last-wins keys read
/// [`UpstreamConfig::last`], first-wins [`UpstreamConfig::first`],
/// ordered multi-values [`UpstreamConfig::all`].
type UpstreamValues = HashMap<(Vec<u8>, Vec<u8>, Vec<u8>), Vec<Vec<u8>>>;

#[derive(Clone, Default)]
struct UpstreamConfig {
    values: UpstreamValues,
}

impl UpstreamConfig {
    fn push(&mut self, section: &[u8], subsection: &[u8], key: &[u8], value: Vec<u8>) {
        self.values
            .entry((
                section.to_ascii_lowercase(),
                subsection.to_vec(),
                key.to_ascii_lowercase(),
            ))
            .or_default()
            .push(value);
    }

    fn all(&self, section: &[u8], subsection: &[u8], key: &[u8]) -> &[Vec<u8>] {
        self.values
            .get(&(section.to_vec(), subsection.to_vec(), key.to_vec()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn last(&self, section: &[u8], subsection: &[u8], key: &[u8]) -> Option<&[u8]> {
        self.all(section, subsection, key).last().map(Vec::as_slice)
    }

    fn first(&self, section: &[u8], subsection: &[u8], key: &[u8]) -> Option<&[u8]> {
        self.all(section, subsection, key)
            .first()
            .map(Vec::as_slice)
    }

    /// Branch names carrying any config, sorted and deduplicated.
    fn branch_names(&self) -> Vec<&[u8]> {
        let mut names: Vec<&[u8]> = self
            .values
            .keys()
            .filter(|(section, _, _)| section == b"branch")
            .map(|(_, subsection, _)| subsection.as_slice())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

/// Parse one config tree root (common `config` or a worktree overlay).
/// A missing common config is a valid empty config; unreadable roots and
/// incomplete config trees stay distinct from that complete empty result.
fn parse_config_tree(
    path: &std::path::Path,
    cfg: &mut UpstreamConfig,
    chain: &mut IncludeChain,
    git_dir: &std::path::Path,
    required: bool,
) -> Result<(), IncompleteUpstreamConfig> {
    if chain.files >= UPSTREAM_INCLUDE_MAX_FILES {
        return Err(IncompleteUpstreamConfig);
    }
    if !chain.seen.insert(path.to_path_buf()) {
        return Ok(());
    }
    chain.files += 1;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => return Ok(()),
        Err(_) => return Err(IncompleteUpstreamConfig),
        Ok(_) => {}
    }
    let Some(bytes) = super::read_bounded_bytes(path, super::MAX_GIT_CONTROL_BYTES) else {
        return Err(IncompleteUpstreamConfig);
    };
    let base = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    parse_config_bytes(&bytes, cfg, chain, base, git_dir, 0)
}

/// Parse one config file's bytes, following includes inline in file
/// order. Any construct git fatals on (bad header, bad key, bad escape,
/// content outside a section, NUL bytes, unreadable include target) stops
/// the file with earlier values kept, but also marks the effective config
/// incomplete so that the partial map cannot prove `no_upstream`. CRLF,
/// trailing comments/junk after `]`, and valueless keys (empty value) are
/// accepted, all probed.
fn parse_config_bytes(
    bytes: &[u8],
    cfg: &mut UpstreamConfig,
    chain: &mut IncludeChain,
    base: &std::path::Path,
    git_dir: &std::path::Path,
    depth: u8,
) -> Result<(), IncompleteUpstreamConfig> {
    // git skips a BOM at file start.
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let joined = join_config_continuations(bytes);
    let mut section: Option<(Vec<u8>, Vec<u8>)> = None;
    for logical in joined.split(|b| *b == b'\n') {
        let line = logical.strip_suffix(b"\r").unwrap_or(logical).trim_ascii();
        if line.is_empty() || matches!(line.first(), Some(b'#') | Some(b';')) {
            continue;
        }
        if line.contains(&b'\0') {
            return Err(IncompleteUpstreamConfig);
        }
        if line.first() == Some(&b'[') {
            let Some(header) = parse_config_header(line) else {
                return Err(IncompleteUpstreamConfig);
            };
            section = Some(header);
            continue;
        }
        let Some((name, subsection)) = section.as_ref() else {
            return Err(IncompleteUpstreamConfig);
        };
        let is_include = name == b"include" && subsection.is_empty();
        let is_include_if = name == b"includeif";
        let (key, value): (&[u8], Vec<u8>) = match line.iter().position(|b| *b == b'=') {
            None => (strip_config_comment(line).trim_ascii(), Vec::new()),
            Some(eq) => {
                let raw = strip_config_comment(line[eq + 1..].trim_ascii()).trim_ascii();
                let Some(value) = unescape_config_value(raw) else {
                    return Err(IncompleteUpstreamConfig);
                };
                (line[..eq].trim_ascii(), value)
            }
        };
        if key.is_empty() || !key.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-') {
            return Err(IncompleteUpstreamConfig);
        }
        if is_include && key.eq_ignore_ascii_case(b"path") {
            follow_config_include(&value, base, cfg, chain, git_dir, depth)?;
        } else if is_include_if && key.eq_ignore_ascii_case(b"path") {
            if subsection.is_empty() {
                return Err(IncompleteUpstreamConfig);
            }
            if include_condition_matches(subsection, git_dir)? {
                follow_config_include(&value, base, cfg, chain, git_dir, depth)?;
            }
        } else {
            cfg.push(name, subsection, key, value);
        }
    }
    Ok(())
}

/// Parse a section header line (already trimmed, starts with `[`):
/// `[name]` (no leading space, probed), `[name.sub]` dotted (probed:
/// defines the subsection), or `[name "quoted"]` (`]` immediately after
/// the closing quote, probed). Anything after a bare `]` is ignored
/// (probed: junk and comments both accepted). `None` = malformed.
fn parse_config_header(line: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let rest = &line[1..];
    let mut end = 0;
    while end < rest.len() && (rest[end].is_ascii_alphanumeric() || rest[end] == b'-') {
        end += 1;
    }
    if end == 0 {
        return None;
    }
    let name = rest[..end].to_ascii_lowercase();
    let rest = &rest[end..];
    if rest.first() == Some(&b']') {
        return Some((name, Vec::new()));
    }
    if rest.first() == Some(&b'.') {
        let after_dot = &rest[1..];
        let close = after_dot.iter().position(|b| *b == b']')?;
        let subsection = &after_dot[..close];
        if subsection.is_empty()
            || subsection
                .iter()
                .any(|b| b.is_ascii_whitespace() || *b == b'"')
        {
            return None;
        }
        return Some((name, subsection.to_vec()));
    }
    let mut indent = 0;
    while indent < rest.len() && (rest[indent] == b' ' || rest[indent] == b'\t') {
        indent += 1;
    }
    if indent == 0 || indent >= rest.len() || rest[indent] != b'"' {
        return None;
    }
    let inner = &rest[indent + 1..];
    let mut subsection = Vec::new();
    let mut next = 0;
    let mut closed = false;
    while next < inner.len() {
        match inner[next] {
            b'"' => {
                closed = true;
                next += 1;
                break;
            }
            b'\\' => {
                next += 1;
                match inner.get(next) {
                    Some(b'n') => subsection.push(b'\n'),
                    Some(b't') => subsection.push(b'\t'),
                    Some(b'b') => subsection.push(0x08),
                    Some(b'"') => subsection.push(b'"'),
                    Some(b'\\') => subsection.push(b'\\'),
                    _ => return None,
                }
                next += 1;
            }
            byte => {
                subsection.push(byte);
                next += 1;
            }
        }
    }
    if !closed || inner[next..].first() != Some(&b']') {
        return None;
    }
    Some((name, subsection))
}

/// Join git line continuations the way git 2.56.0 parses values: a `\`
/// IMMEDIATELY before `\n` (or `\r\n`) joins the next line by pure
/// concatenation (leading whitespace kept, inside and outside quotes);
/// the parity of a trailing `\` run decides (odd joins, even stays
/// literal); a trailing `\` at EOF is dropped (odd) or paired (even); a
/// `\` before anything else stays literal for the escape parser (which
/// fails the file there exactly as git fatals). Byte port of the
/// `git::join_continuations` rule-set (private there; this path needs
/// byte-exact values for non-UTF-8 names).
fn join_config_continuations(config: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(config.len());
    let mut i = 0;
    while i < config.len() {
        if config[i] != b'\\' {
            out.push(config[i]);
            i += 1;
            continue;
        }
        let mut run_end = i;
        while run_end < config.len() && config[run_end] == b'\\' {
            run_end += 1;
        }
        let run = run_end - i;
        let mut break_end = run_end;
        if break_end < config.len() && config[break_end] == b'\r' {
            break_end += 1;
        }
        if break_end < config.len() && config[break_end] == b'\n' {
            out.extend(std::iter::repeat_n(b'\\', run - run % 2));
            if run % 2 == 0 {
                out.extend_from_slice(&config[run_end..=break_end]);
            }
            i = break_end + 1;
        } else if run_end == config.len() {
            out.extend(std::iter::repeat_n(b'\\', run - run % 2));
            i = run_end;
        } else {
            out.extend(std::iter::repeat_n(b'\\', run));
            i = run_end;
        }
    }
    out
}

/// Strip a git trailing comment: `;`/`#` outside double quotes ends the
/// value (only double quotes protect); a backslash escapes the next
/// byte. Byte port of the `git::strip_git_comment` rule.
fn strip_config_comment(value: &[u8]) -> &[u8] {
    let mut in_quotes = false;
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'\\' => i += 2,
            b'"' => {
                in_quotes = !in_quotes;
                i += 1;
            }
            b';' | b'#' if !in_quotes => return &value[..i],
            _ => i += 1,
        }
    }
    value
}

/// Resolve git quote grouping + backslash escapes in an already
/// comment-stripped, trimmed value: drop `"` chars, map `\\` `\"` `\n`
/// `\t` `\b` (the full set git 2.56.0 accepts — anything else, or a
/// trailing lone `\`, makes git reject the file, reported here as
/// `None` so the caller stops the file too). Byte port of the
/// `git::unescape_git_value` rule.
fn unescape_config_value(value: &[u8]) -> Option<Vec<u8>> {
    if !value.contains(&b'"') && !value.contains(&b'\\') {
        return Some(value.to_vec());
    }
    let mut out = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'"' => {
                i += 1;
            }
            b'\\' => {
                i += 1;
                match value.get(i) {
                    Some(b'n') => out.push(b'\n'),
                    Some(b't') => out.push(b'\t'),
                    Some(b'b') => out.push(0x08),
                    Some(b'"') => out.push(b'"'),
                    Some(b'\\') => out.push(b'\\'),
                    _ => return None,
                }
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    Some(out)
}

/// Follow one `include.path` value inline (file order). Missing targets
/// and revisits (cycles) are skipped as Git does. A present target that
/// cannot be read or parsed makes the effective config incomplete.
fn follow_config_include(
    value: &[u8],
    base: &std::path::Path,
    cfg: &mut UpstreamConfig,
    chain: &mut IncludeChain,
    git_dir: &std::path::Path,
    depth: u8,
) -> Result<(), IncompleteUpstreamConfig> {
    if value.is_empty() {
        return Ok(());
    }
    if depth >= UPSTREAM_INCLUDE_MAX_DEPTH {
        return Err(IncompleteUpstreamConfig);
    }
    let target = resolve_include_target(value, base).ok_or(IncompleteUpstreamConfig)?;
    if chain.seen.contains(&target) {
        return Ok(());
    }
    if chain.files >= UPSTREAM_INCLUDE_MAX_FILES {
        return Err(IncompleteUpstreamConfig);
    }
    match std::fs::symlink_metadata(&target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(IncompleteUpstreamConfig),
        Ok(_) => {}
    }
    let Some(bytes) = super::read_bounded_bytes(&target, super::MAX_GIT_CONTROL_BYTES) else {
        return Err(IncompleteUpstreamConfig);
    };
    chain.seen.insert(target.clone());
    chain.files += 1;
    let child_base = target.parent().unwrap_or_else(|| std::path::Path::new("."));
    parse_config_bytes(&bytes, cfg, chain, child_base, git_dir, depth + 1)
}

/// Resolve an include target the way git does: `~`/`~/` against HOME
/// (probed), relative against the including file's directory, absolute
/// as-is. Byte-exact on unix (a path, never lossy text). No variable
/// expansion (git does none).
fn resolve_include_target(value: &[u8], base: &std::path::Path) -> Option<std::path::PathBuf> {
    if value == b"~" || value.starts_with(b"~/") {
        let home = std::env::var_os("HOME")?;
        let mut out = std::path::PathBuf::from(home);
        if value.len() > 1 {
            out.push(super::os_str_from_bytes(&value[2..]));
        }
        return Some(out);
    }
    let path = std::path::Path::new(super::os_str_from_bytes(value));
    if path.is_absolute() {
        Some(path.to_path_buf())
    } else {
        Some(base.join(path))
    }
}

/// Whether an `includeIf` subsection condition matches a checkout git dir.
/// Only absolute `gitdir:`/`gitdir/i:` patterns are evaluated
/// (probed git 2.56.0, condition keywords case-sensitive: `*` never crosses
/// `/`, `?` matches one non-`/` byte, `**` crosses, a trailing `/` appends
/// `**`, matching runs against both the spelled and canonicalized dir).
/// Unsupported or unevaluable conditions return incomplete instead of
/// claiming that their include cannot affect upstream resolution.
fn include_condition_matches(
    condition: &[u8],
    git_dir: &std::path::Path,
) -> Result<bool, IncompleteUpstreamConfig> {
    let (pattern, ignore_case) = if let Some(pattern) = condition.strip_prefix(b"gitdir:") {
        (pattern, false)
    } else if let Some(pattern) = condition.strip_prefix(b"gitdir/i:") {
        (pattern, true)
    } else {
        return Err(IncompleteUpstreamConfig);
    };
    if pattern.is_empty()
        || !pattern.starts_with(b"/")
        || pattern.len() > UPSTREAM_GITDIR_PATTERN_MAX
        || pattern.contains(&b'[')
    {
        return Err(IncompleteUpstreamConfig);
    }
    let mut expanded;
    let mut pattern = pattern;
    if pattern.ends_with(b"/") {
        expanded = pattern.to_vec();
        expanded.extend_from_slice(b"**");
        pattern = &expanded;
    }
    let mut budget_exhausted = false;
    for form in gitdir_match_forms(git_dir) {
        let mut memo = HashSet::new();
        let mut budget = UPSTREAM_GLOB_STEP_BUDGET;
        if glob_match(pattern, &form, ignore_case, &mut memo, &mut budget) {
            return Ok(true);
        }
        budget_exhausted |= budget == 0;
    }
    if budget_exhausted {
        Err(IncompleteUpstreamConfig)
    } else {
        Ok(false)
    }
}

/// Candidate spellings of one git dir for `gitdir:` matching: the spelled
/// path plus its canonicalized form when that succeeds (probed: git
/// matches both, e.g. `/tmp/…` and `/private/tmp/…` on macOS).
/// Canonicalization is for matching only — no file is read through it.
fn gitdir_match_forms(dir: &std::path::Path) -> Vec<Vec<u8>> {
    let mut forms = vec![os_bytes(dir.as_os_str())];
    if let Ok(canonical) = std::fs::canonicalize(dir) {
        let bytes = os_bytes(canonical.as_os_str());
        if !forms.contains(&bytes) {
            forms.push(bytes);
        }
    }
    forms
}

/// Match one expanded `gitdir:` pattern against one dir spelling: `**`
/// crosses `/`, `*`/`?` never do, `\` escapes the next byte, and `[`
/// classes are unsupported (fail closed). Bounded by a step budget plus
/// a visited-state memo (adversarial patterns cannot hang the scan).
fn glob_match(
    pattern: &[u8],
    value: &[u8],
    ignore_case: bool,
    memo: &mut HashSet<(usize, usize)>,
    budget: &mut u64,
) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    // Pointer-pair memo: every recursive slice derives from the same two
    // buffers, so pairs are unique positions; recursion always shrinks
    // `pattern.len() + value.len()`, so a revisited state already failed.
    if !memo.insert((pattern.as_ptr() as usize, value.as_ptr() as usize)) {
        return false;
    }
    if pattern.is_empty() {
        return value.is_empty();
    }
    if pattern[0] == b'*' {
        let mut end = 0;
        while end < pattern.len() && pattern[end] == b'*' {
            end += 1;
        }
        let rest = &pattern[end..];
        let double = end >= 2;
        let mut split = 0;
        loop {
            if glob_match(rest, &value[split..], ignore_case, memo, budget) {
                return true;
            }
            if split == value.len() || (!double && value[split] == b'/') {
                return false;
            }
            split += 1;
        }
    }
    if value.is_empty() {
        return false;
    }
    match pattern[0] {
        b'?' => {
            if value[0] == b'/' {
                return false;
            }
            glob_match(&pattern[1..], &value[1..], ignore_case, memo, budget)
        }
        b'\\' => {
            if pattern.len() < 2 || !glob_byte_eq(pattern[1], value[0], ignore_case) {
                return false;
            }
            glob_match(&pattern[2..], &value[1..], ignore_case, memo, budget)
        }
        b'[' => false,
        literal => {
            if !glob_byte_eq(literal, value[0], ignore_case) {
                return false;
            }
            glob_match(&pattern[1..], &value[1..], ignore_case, memo, budget)
        }
    }
}

/// Byte equality with optional ASCII case folding.
fn glob_byte_eq(left: u8, right: u8, ignore_case: bool) -> bool {
    left == right || (ignore_case && left.eq_ignore_ascii_case(&right))
}

/// Lossless `OsStr`-to-bytes on unix; lossy fallback elsewhere.
fn os_bytes(os: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStrExt::as_bytes(os).to_vec()
    }
    #[cfg(not(unix))]
    {
        os.to_string_lossy().into_owned().into_bytes()
    }
}

/// Resolve every branch in the effective config to its full comparison ref.
fn resolve_all_upstreams(
    cfg: &UpstreamConfig,
    known: &HashSet<&[u8]>,
) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut out = HashMap::new();
    for branch in cfg.branch_names() {
        if branch.is_empty() {
            continue;
        }
        if let Some(upstream) = resolve_branch_upstream(cfg, branch, known) {
            out.insert(branch.to_vec(), upstream);
        }
    }
    out
}

/// Resolve one branch to its full comparison ref: last `remote`, first
/// `merge` (both probed). `remote = .` resolves locally to the merge ref
/// itself. Otherwise the first positive fetch refspec (config order)
/// whose source matches the merge ref maps it to the local tracking ref
/// — with no fallback when that target is missing and no default when
/// the remote carries no fetch lines (all probed). Garbage (unparseable
/// or non-UTF-8), negative/destination-less, and source-mismatching
/// refspecs SKIP to the next line — probed: installed git iterates the
/// fetch list past a garbage-first, negative-first, or
/// non-matching-first fetch list to the later valid refspec. The mapped
/// ref must exist in the same observation; anything else yields no
/// upstream. A first match whose target is missing stays missing
/// (probed: installed git reports the missing target as `gone`, never
/// the later refspec's target), so a match never falls through.
fn resolve_branch_upstream(
    cfg: &UpstreamConfig,
    branch: &[u8],
    known: &HashSet<&[u8]>,
) -> Option<Vec<u8>> {
    let remote = cfg.last(b"branch", branch, b"remote")?;
    if remote.is_empty() {
        return None;
    }
    let merge = cfg.first(b"branch", branch, b"merge")?;
    if merge.is_empty() {
        return None;
    }
    if remote == b"." {
        return known.contains(merge).then(|| merge.to_vec());
    }
    for fetch in cfg.all(b"remote", remote, b"fetch") {
        let Ok(text) = std::str::from_utf8(fetch) else {
            continue;
        };
        let Some(spec) = super::refspec::parse_fetch_refspec(text) else {
            continue;
        };
        if spec.negative || spec.dst.is_none() {
            continue;
        }
        let Some(mapped) = map_fetch_refspec(&spec, merge) else {
            continue;
        };
        return known.contains(mapped.as_slice()).then_some(mapped);
    }
    None
}

/// Map a merge ref through one positive fetch refspec with a destination:
/// a literal source requires equality, a `*` source substitutes the
/// middle capture into the destination pattern (exact bytes; the parser
/// guarantees at most one `*` per side with `*` in source iff `*` in
/// destination). `None` = no match.
fn map_fetch_refspec(spec: &super::refspec::FetchRefspec, merge: &[u8]) -> Option<Vec<u8>> {
    let dst = spec.dst.as_deref()?;
    match spec.src.split_once('*') {
        None => {
            if merge == spec.src.as_bytes() {
                Some(dst.as_bytes().to_vec())
            } else {
                None
            }
        }
        Some((pre, post)) => {
            let middle = merge
                .strip_prefix(pre.as_bytes())?
                .strip_suffix(post.as_bytes())?;
            let (dst_pre, dst_post) = dst.split_once('*')?;
            let mut out = Vec::with_capacity(dst_pre.len() + middle.len() + dst_post.len());
            out.extend_from_slice(dst_pre.as_bytes());
            out.extend_from_slice(middle);
            out.extend_from_slice(dst_post.as_bytes());
            Some(out)
        }
    }
}

/// Honest ref state (R16): directly observed targets are valid, as is
/// any symbolic ref whose target exists in the same observation (peel data
/// is backend-optional, never the validity proof). Only a dangling
/// symbolic ref is non-valid: unborn for a branch target, invalid else.
#[must_use]
pub fn ref_state_for(reference: &RefObservation, known: &HashSet<&[u8]>) -> &'static str {
    match &reference.target {
        RefTarget::Object(_) => "valid",
        RefTarget::Symbolic(_) if reference.peeled.is_some() => "valid",
        RefTarget::Symbolic(target) if known.contains(target.as_slice()) => "valid",
        RefTarget::Symbolic(target) if target.starts_with(b"refs/heads/") => "unborn",
        RefTarget::Symbolic(_) => "invalid",
    }
}

/// Graph inputs that belong to one checkout. `head_ref` records which
/// local branch this checkout owns; the replacement context is absent
/// when its effective repository config could not be resolved safely.
#[derive(Debug, Clone)]
pub struct BranchGraphContext {
    /// Checkout's git dir (worktree admin dir for linked checkouts).
    pub git_dir: PathBuf,
    /// Working-tree root for fallback spawns, when any.
    pub work_tree: Option<PathBuf>,
    /// The local branch (`refs/heads/...`) this checkout's HEAD owns.
    pub head_ref: Option<Vec<u8>>,
    /// Effective `core.useReplaceRefs` for this checkout.
    pub use_replace_refs: bool,
    /// Effective `gitoxide.objects.replaceRefBase` for this checkout.
    pub replace_ref_base: String,
}

/// One checkout's graph-context inputs, mapped by the caller from
/// catalog rows (kept store-free here): git dir, worktree root, and the
/// checkout's current HEAD branch when it is on one.
#[derive(Debug, Clone)]
pub struct CheckoutGraphInput {
    /// Checkout's git dir.
    pub git_dir: PathBuf,
    /// Working-tree root, when any.
    pub work_tree: Option<PathBuf>,
    /// Current HEAD branch (`refs/heads/...`) when the checkout is on one.
    pub head_ref: Option<Vec<u8>>,
}

/// Build one graph context per checkout from the current HEAD reads.
/// The no-checkout case retains the store instance context.
#[must_use]
pub fn branch_graph_contexts(
    instance: &GitInstance,
    checkouts: &[CheckoutGraphInput],
) -> Vec<Option<BranchGraphContext>> {
    if checkouts.is_empty() {
        return vec![
            effective_replace_ref_settings(&instance.git_dir, &instance.common_dir).map(
                |(use_replace_refs, replace_ref_base)| BranchGraphContext {
                    git_dir: instance.git_dir.clone(),
                    work_tree: instance.work_dir.clone(),
                    head_ref: None,
                    use_replace_refs,
                    replace_ref_base,
                },
            ),
        ];
    }
    checkouts
        .iter()
        .map(|checkout| {
            effective_replace_ref_settings(&checkout.git_dir, &instance.common_dir).map(
                |(use_replace_refs, replace_ref_base)| BranchGraphContext {
                    git_dir: checkout.git_dir.clone(),
                    work_tree: checkout.work_tree.clone(),
                    head_ref: checkout.head_ref.clone(),
                    use_replace_refs,
                    replace_ref_base,
                },
            )
        })
        .collect()
}

/// Resolve the local effective replace-ref settings for one checkout.
/// Gix opens with isolated permissions, so repository config (including
/// `config.worktree`) is the relevant scope. Any unreadable or invalid
/// input is unknown and causes affected branch results to stay pending.
#[must_use]
pub fn effective_replace_ref_settings(git_dir: &Path, common_dir: &Path) -> Option<(bool, String)> {
    let mut effective = UpstreamConfig::default();
    let mut chain = IncludeChain::default();
    parse_config_tree(
        &common_dir.join("config"),
        &mut effective,
        &mut chain,
        git_dir,
        false,
    )
    .ok()?;

    let worktree_config = match effective.last(b"extensions", b"", b"worktreeconfig") {
        None => false,
        Some(value) => parse_repo_config_bool(value)?,
    };
    if worktree_config {
        let overlay = git_dir.join("config.worktree");
        let mut overlay_chain = IncludeChain::default();
        parse_config_tree(&overlay, &mut effective, &mut overlay_chain, git_dir, false).ok()?;
    }

    // Git defaults to using replacement refs. A valueless config key is
    // also true under Git's boolean rules.
    let use_replace_refs = match effective.last(b"core", b"", b"usereplacerefs") {
        None => true,
        Some(value) => parse_repo_config_bool(value)?,
    };
    let replace_ref_base = effective
        .last(b"gitoxide", b"objects", b"replacerefbase")
        .unwrap_or(b"refs/replace/");
    let replace_ref_base = std::str::from_utf8(replace_ref_base).ok()?;
    if !replace_ref_base.starts_with("refs/")
        || !replace_ref_base.ends_with('/')
        || replace_ref_base.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'=' | b'"' | b'\\')
        })
        || replace_ref_base
            .split('/')
            .any(|part| part == "." || part == "..")
    {
        return None;
    }
    Some((use_replace_refs, replace_ref_base.to_owned()))
}

/// Strict subset of Git's config boolean grammar. Unknown spellings stay
/// unknown instead of being treated as false, which would make ancestry
/// comparison depend on a guessed config value.
fn parse_repo_config_bool(value: &[u8]) -> Option<bool> {
    if value.is_empty() {
        return Some(true);
    }
    if value.eq_ignore_ascii_case(b"true")
        || value.eq_ignore_ascii_case(b"yes")
        || value.eq_ignore_ascii_case(b"on")
        || super::refspec::config_bool_is_true(value)
    {
        return Some(true);
    }
    if value.eq_ignore_ascii_case(b"false")
        || value.eq_ignore_ascii_case(b"no")
        || value.eq_ignore_ascii_case(b"off")
        || value == b"0"
        || std::str::from_utf8(value)
            .ok()?
            .parse::<i128>()
            .is_ok_and(|number| number == 0)
    {
        return Some(false);
    }
    None
}

/// Select the graph context owned by `branch`. An exactly one checkout
/// with that HEAD wins. An unowned branch can use a shared context only
/// when every checkout has the same known replace-ref settings.
#[must_use]
pub fn graph_context_for_branch<'a>(
    branch: &[u8],
    contexts: &'a [Option<BranchGraphContext>],
) -> Option<&'a BranchGraphContext> {
    let mut owners = contexts
        .iter()
        .filter_map(Option::as_ref)
        .filter(|context| context.head_ref.as_deref() == Some(branch));
    let owner = owners.next();
    if owners.next().is_some() {
        return None;
    }
    if let Some(owner) = owner {
        return Some(owner);
    }

    let mut contexts = contexts.iter();
    let first = contexts.next()?.as_ref()?;
    if contexts.any(|candidate| {
        candidate.as_ref().is_none_or(|context| {
            context.use_replace_refs != first.use_replace_refs
                || context.replace_ref_base != first.replace_ref_base
        })
    }) {
        return None;
    }
    Some(first)
}

/// Compare every local (`refs/heads/`) branch against its resolved
/// full upstream ref (goal Step 10, Step 15 case 9). The OID map
/// carries direct tips plus peeled symbolic tips; a branch or
/// upstream without an OID (unborn, dangling symbolic, broken ref)
/// compares as `error` via [`graph::compare_branch`] — never
/// `equal`. Non-local refs are skipped (they carry no upstream, so
/// no comparison is persisted and they read `pending`). Offline and
/// read-only: object walks only, with the installed-git `rev-list`
/// fallback behind the existing spawn guards.
///
/// An incomplete config has no trustworthy negative upstream result:
/// every local branch maps to an explicit [`Comparison::pending`] so an
/// older comparison cannot remain visible as if it used the current
/// config. Cancellation drops the whole observation (`None`) rather
/// than persisting the graph layer's error-shaped placeholder as
/// branch state.
#[must_use]
pub fn compute_branch_comparisons(
    instance: &GitInstance,
    refs: &[RefObservation],
    upstreams: &BranchUpstreams,
    graph_contexts: &[Option<BranchGraphContext>],
    cache: &ComparisonCache,
    fallback: Option<&FallbackGit>,
    cancel: Option<&WaitCancel>,
) -> Option<HashMap<Vec<u8>, Comparison>> {
    let BranchUpstreams::Complete(upstreams) = upstreams else {
        return Some(
            refs.iter()
                .filter(|reference| reference.name.starts_with(b"refs/heads/"))
                .map(|reference| (reference.name.clone(), Comparison::pending()))
                .collect(),
        );
    };
    let mut oids: HashMap<&[u8], (&str, &str)> = HashMap::new();
    // Presence set: EVERY iterated ref name, including OID-less ones
    // (unpeeled symbolic, dangling, broken-but-returned). `upstream_known`
    // keys off this set — never off `oids` — so an existing-but-OID-less
    // upstream compares as `error`, not `upstream_missing`.
    let mut names: HashSet<&[u8]> = HashSet::new();
    for reference in refs {
        names.insert(reference.name.as_slice());
        match &reference.target {
            RefTarget::Object(oid) => {
                oids.insert(
                    reference.name.as_slice(),
                    (oid.hex.as_str(), oid.algorithm.as_str()),
                );
            }
            RefTarget::Symbolic(_) => {
                if let Some(peeled) = reference.peeled.as_ref() {
                    oids.insert(
                        reference.name.as_slice(),
                        (peeled.hex.as_str(), peeled.algorithm.as_str()),
                    );
                }
            }
        }
    }
    // Cache store key: the common dir identifies this object
    // database for the cache's lifetime (one analysis pass).
    let store_key = instance.common_dir.to_string_lossy().into_owned();
    let mut out = HashMap::new();
    for reference in refs {
        if cancel.is_some_and(|cancel| cancel.cancelled()) {
            return None;
        }
        if !reference.name.starts_with(b"refs/heads/") {
            continue;
        }
        let upstream = upstream_for_ref(upstreams, &reference.name);
        let local = oids.get(reference.name.as_slice()).copied();
        let (upstream_hex, upstream_algo, upstream_known) = match upstream.as_deref() {
            None => (None, None, false),
            Some(name) => {
                let (hex, algo) = oids.get(name).copied().unzip();
                (hex, algo, names.contains(name))
            }
        };
        let tips = graph::BranchTips {
            local_hex: local.map(|(hex, _)| hex),
            local_algo: local.map(|(_, algo)| algo),
            upstream: upstream.as_deref(),
            upstream_hex,
            upstream_algo,
            upstream_known,
        };
        let comparison = match graph_context_for_branch(&reference.name, graph_contexts) {
            Some(owner) => {
                let graph_ctx = graph::CompareContext {
                    git_dir: &owner.git_dir,
                    common_dir: &instance.common_dir,
                    store_id: &store_key,
                    use_replace_refs: Some(owner.use_replace_refs),
                    replace_ref_base: Some(&owner.replace_ref_base),
                    work_tree: owner.work_tree.as_deref(),
                    cache: Some(cache),
                    fallback,
                    cancel,
                };
                graph::compare_branch(&graph_ctx, &tips)
            }
            // A conflicting or unreadable checkout context cannot prove
            // which ancestry semantics apply. Keep this branch pending
            // rather than publishing counts from an arbitrary worktree.
            None => Comparison::pending(),
        };
        if cancel.is_some_and(|cancel| cancel.cancelled()) {
            // The graph layer returns an error-shaped placeholder when a
            // cancellation interrupts a walk. Drop the whole observation
            // rather than persisting that placeholder as branch state.
            return None;
        }
        out.insert(reference.name.clone(), comparison);
    }
    if cancel.is_some_and(|cancel| cancel.cancelled()) {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance_at(dir: &Path) -> GitInstance {
        GitInstance {
            git_dir: dir.to_path_buf(),
            common_dir: dir.to_path_buf(),
            work_dir: None,
            is_bare: false,
            object_format: String::from("sha1"),
        }
    }

    fn assert_config_failure_keeps_local_branch_pending(common_dir: &Path) {
        let instance = instance_at(common_dir);
        let refs = [RefObservation {
            name: b"refs/heads/main".to_vec(),
            target: RefTarget::Symbolic(b"refs/heads/main".to_vec()),
            peeled: None,
        }];
        let upstreams = load_branch_upstreams(&instance, &[], &refs);
        assert_eq!(upstreams, BranchUpstreams::Incomplete);

        let comparisons = compute_branch_comparisons(
            &instance,
            &refs,
            &upstreams,
            &[],
            &ComparisonCache::new(),
            None,
            None,
        )
        .expect("incomplete config is not a cancelled analysis");
        assert_eq!(
            comparisons.get(b"refs/heads/main".as_slice()),
            Some(&Comparison::pending()),
            "incomplete config persists `pending`, not `no_upstream`"
        );
    }

    #[test]
    fn malformed_effective_config_keeps_local_branch_comparison_pending() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("config"),
            b"[malformed\n[branch \"main\"]\nremote = origin\nmerge = refs/heads/main\n",
        )
        .expect("write malformed config");
        assert_config_failure_keeps_local_branch_pending(tmp.path());
    }

    #[test]
    fn unreadable_effective_config_keeps_local_branch_comparison_pending() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(tmp.path().join("config")).expect("create unreadable config path");
        assert_config_failure_keeps_local_branch_pending(tmp.path());
    }

    #[test]
    fn unevaluable_include_condition_keeps_local_branch_comparison_pending() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("config"),
            b"[includeIf \"onbranch:main\"]\npath = conditional-config\n",
        )
        .expect("write conditional include");
        assert_config_failure_keeps_local_branch_pending(tmp.path());
    }

    #[test]
    fn gitdir_include_is_evaluated_for_each_checkout() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let common_dir = tmp.path().join(".git");
        let linked_git_dir = common_dir.join("worktrees/linked");
        std::fs::create_dir_all(&linked_git_dir).expect("linked git dir");
        let gitdir_condition = format!("gitdir:{}", linked_git_dir.display());
        assert_eq!(
            include_condition_matches(gitdir_condition.as_bytes(), &common_dir),
            Ok(false)
        );
        assert_eq!(
            include_condition_matches(gitdir_condition.as_bytes(), &linked_git_dir),
            Ok(true)
        );
        let common_config = format!(
            "[remote \"origin\"]\n\
             \tfetch = +refs/heads/*:refs/remotes/origin/*\n\
             [remote \"other\"]\n\
             \tfetch = +refs/heads/*:refs/remotes/other/*\n\
             [branch \"main\"]\n\
             \tremote = origin\n\
             \tmerge = refs/heads/main\n\
             [includeIf \"gitdir:{}\"]\n\
             \tpath = linked.inc\n",
            linked_git_dir.display()
        );
        std::fs::write(common_dir.join("config"), common_config).expect("common config");
        std::fs::write(
            common_dir.join("linked.inc"),
            b"[branch \"main\"]\n\tremote = other\n",
        )
        .expect("conditional include");

        let instance = instance_at(&common_dir);
        let checkouts = [common_dir.clone(), linked_git_dir.clone()];
        let refs = [
            RefObservation {
                name: b"refs/heads/main".to_vec(),
                target: RefTarget::Symbolic(b"refs/heads/main".to_vec()),
                peeled: None,
            },
            RefObservation {
                name: b"refs/remotes/origin/main".to_vec(),
                target: RefTarget::Symbolic(b"refs/remotes/origin/main".to_vec()),
                peeled: None,
            },
            RefObservation {
                name: b"refs/remotes/other/main".to_vec(),
                target: RefTarget::Symbolic(b"refs/remotes/other/main".to_vec()),
                peeled: None,
            },
        ];

        assert_eq!(
            load_branch_upstreams(&instance, &checkouts, &refs),
            BranchUpstreams::Complete(HashMap::new()),
            "the checkout-specific include makes main's upstream divergent; do not broadcast it"
        );
    }

    #[test]
    fn graph_context_uses_branch_owner_and_pending_for_unowned_conflict() {
        let main = BranchGraphContext {
            git_dir: PathBuf::from("/repo/.git"),
            work_tree: Some(PathBuf::from("/repo")),
            head_ref: Some(b"refs/heads/main".to_vec()),
            use_replace_refs: true,
            replace_ref_base: String::from("refs/replace/"),
        };
        let linked = BranchGraphContext {
            git_dir: PathBuf::from("/repo/.git/worktrees/linked"),
            work_tree: Some(PathBuf::from("/linked")),
            head_ref: Some(b"refs/heads/linked".to_vec()),
            use_replace_refs: false,
            replace_ref_base: String::from("refs/replace/"),
        };
        let contexts = [Some(main), Some(linked)];
        assert_eq!(
            graph_context_for_branch(b"refs/heads/main", &contexts)
                .map(|context| context.git_dir.as_path()),
            Some(Path::new("/repo/.git"))
        );
        assert_eq!(
            graph_context_for_branch(b"refs/heads/linked", &contexts)
                .map(|context| context.git_dir.as_path()),
            Some(Path::new("/repo/.git/worktrees/linked"))
        );
        assert!(
            graph_context_for_branch(b"refs/heads/unowned", &contexts).is_none(),
            "an unowned branch cannot pick between different replacement settings"
        );
    }

    #[test]
    fn effective_replace_ref_settings_read_worktree_override() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let common = tmp.path().join(".git");
        let main_git_dir = common.clone();
        let linked_git_dir = common.join("worktrees/linked");
        std::fs::create_dir_all(&linked_git_dir).expect("linked git dir");
        std::fs::write(
            common.join("config"),
            b"[extensions]\nworktreeConfig = true\n[core]\nuseReplaceRefs = true\n",
        )
        .expect("common config");
        std::fs::write(
            linked_git_dir.join("config.worktree"),
            b"[core]\nuseReplaceRefs = false\n",
        )
        .expect("linked worktree config");
        assert_eq!(
            effective_replace_ref_settings(&main_git_dir, &common),
            Some((true, String::from("refs/replace/")))
        );
        assert_eq!(
            effective_replace_ref_settings(&linked_git_dir, &common),
            Some((false, String::from("refs/replace/")))
        );
    }
}
