//! Branch ahead/behind comparison (goal Step 10, Step 15 case 9).
//!
//! Compares a local branch tip against its resolved full comparison ref
//! (D10: `refs.upstream`, what `git rev-parse --symbolic-full-name '@{u}'`
//! prints). Never default-compares to `main`: a branch without a resolved
//! upstream is [`NO_UPSTREAM`](Comparison::no_upstream), never `equal`.
//!
//! Backend table (offline, read-only; no fetch, no helper execution
//! beyond the existing [`FallbackGit`](super::fallback::FallbackGit)
//! guards):
//!
//! | Situation | Backend |
//! |---|---|
//! | Equal OIDs | fast path: `equal` 0/0, no walk, no object read |
//! | Otherwise | gix `rev_walk` primary (isolated open, no includes) |
//! | gix open fails but installed git reads the store | fallback `rev-list --left-right --count` |
//! | gix walk fails mid-traversal (missing/corrupt object) | fallback retry, then `error` |
//! | Shallow/grafted cut crossed by the walk | `incomplete_history`, null counts |
//! | Grafted (`info/grafts` non-empty) | `incomplete_history` outright: gix 0.88 |
//! | | has no graft support, so the primary would lie; conservative refusal |
//!
//! `rev-list` fallback output is parsed strictly (`"<ahead>\t<behind>"`,
//! nothing else) and travels the standard fallback spawn envelope
//! (identity re-verification, neutralization, timeout, capture cap).
//! Filter drivers cannot execute on either path: rev-walk and `rev-list`
//! read commit objects only, never worktree content, so the
//! [`FILTER_DRIVER_GAP`](super::FILTER_DRIVER_GAP) refusal (a status-path
//! guard) has no trigger here — documented, not bypassed.
//!
//! Shallow honesty: a shallow walk that never yields a shallow-boundary
//! commit provably stayed above the cut, so its counts are complete and
//! reported. Any yielded boundary commit means grafted parents were
//! pruned and the counts are undercounts → `incomplete_history` with
//! null counts. The fallback cannot prove cut-avoidance (it reports no
//! boundary contact), so a shallow repo that reaches the fallback is
//! always `incomplete_history`.
//!
//! [`ComparisonCache`] reuses saved graph results for equal OID pairs
//! within a compatible object database: the key is
//! `(store-id, oid-a, oid-b, algo)` — same store (same common dir),
//! ordered tips (ahead/behind are directional), explicit algorithm.
//! Only successful count pairs are cached; `error`/`incomplete_history`
//! are recomputed (object stores change under fetch/GC). Bounded
//! ([`MAX_GRAPH_CACHE_ENTRIES`], FIFO eviction).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Branch and upstream tips are the same commit.
pub const STATE_EQUAL: &str = "equal";
/// Branch has commits the upstream lacks; upstream has none it lacks.
pub const STATE_AHEAD: &str = "ahead";
/// Upstream has commits the branch lacks; branch has none it lacks.
pub const STATE_BEHIND: &str = "behind";
/// Both sides have commits the other lacks.
pub const STATE_DIVERGED: &str = "diverged";
/// Branch has no resolved upstream (never default-compare to main).
pub const STATE_NO_UPSTREAM: &str = "no_upstream";
/// Upstream resolved but its ref is absent from the observation.
pub const STATE_UPSTREAM_MISSING: &str = "upstream_missing";
/// Analysis has not run (or the ref kind is never compared).
pub const STATE_PENDING: &str = "pending";
/// Shallow/grafted cut crossed; counts would be undercounts.
pub const STATE_INCOMPLETE_HISTORY: &str = "incomplete_history";
/// Comparison failed (missing/corrupt objects, unreadable store).
pub const STATE_ERROR: &str = "error";

/// All nine comparison states (D7 vocabulary).
pub const COMPARISON_STATES: &[&str] = &[
    STATE_EQUAL,
    STATE_AHEAD,
    STATE_BEHIND,
    STATE_DIVERGED,
    STATE_NO_UPSTREAM,
    STATE_UPSTREAM_MISSING,
    STATE_PENDING,
    STATE_INCOMPLETE_HISTORY,
    STATE_ERROR,
];

/// Maximum cached OID-pair results per [`ComparisonCache`].
pub const MAX_GRAPH_CACHE_ENTRIES: usize = 1024;

/// One branch-vs-upstream comparison: state plus counts.
///
/// Counts are `Some` only for the four counted states
/// (`equal`/`ahead`/`behind`/`diverged`); every other state carries
/// null counts — unknown is never zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    /// One of [`COMPARISON_STATES`].
    pub state: &'static str,
    /// Commits reachable from the branch but not the upstream.
    pub ahead: Option<u64>,
    /// Commits reachable from the upstream but not the branch.
    pub behind: Option<u64>,
}

impl Comparison {
    /// Derive the counted state from exact ahead/behind numbers.
    #[must_use]
    pub fn from_counts(ahead: u64, behind: u64) -> Self {
        let state = match (ahead, behind) {
            (0, 0) => STATE_EQUAL,
            (_, 0) => STATE_AHEAD,
            (0, _) => STATE_BEHIND,
            _ => STATE_DIVERGED,
        };
        Self {
            state,
            ahead: Some(ahead),
            behind: Some(behind),
        }
    }

    /// Branch has no resolved upstream.
    #[must_use]
    pub fn no_upstream() -> Self {
        Self {
            state: STATE_NO_UPSTREAM,
            ahead: None,
            behind: None,
        }
    }

    /// Upstream resolved but its ref is absent from the observation.
    #[must_use]
    pub fn upstream_missing() -> Self {
        Self {
            state: STATE_UPSTREAM_MISSING,
            ahead: None,
            behind: None,
        }
    }

    /// Analysis has not run (also the legacy-NULL read for rows that
    /// predate comparison storage, and for ref kinds that are never
    /// compared — remote-tracking and other refs carry no upstream).
    #[must_use]
    pub fn pending() -> Self {
        Self {
            state: STATE_PENDING,
            ahead: None,
            behind: None,
        }
    }

    /// Shallow/grafted cut crossed; counts would be undercounts.
    #[must_use]
    pub fn incomplete_history() -> Self {
        Self {
            state: STATE_INCOMPLETE_HISTORY,
            ahead: None,
            behind: None,
        }
    }

    /// Comparison failed: missing/corrupt objects, malformed OID,
    /// unreadable store, or both backends exhausted.
    #[must_use]
    pub fn error() -> Self {
        Self {
            state: STATE_ERROR,
            ahead: None,
            behind: None,
        }
    }
}

/// Cache key: `(store-id, oid-a, oid-b, algo)`.
///
/// Store-id pins the object database (same common dir ⇒ same objects);
/// tips are ordered (ahead/behind are directional: swapping tips
/// swaps the counts); the algorithm is explicit (hex alone never
/// implies sha1 vs sha256).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    store_id: String,
    oid_a_hex: String,
    oid_b_hex: String,
    algo: String,
}

/// Bounded reuse of saved graph results for equal OID pairs within a
/// compatible object database. Only successful `(ahead, behind)` count
/// pairs are stored; failures are recomputed every time. Thread-safe:
/// worker threads may share one cache across stores (the store-id key
/// keeps object databases apart).
#[derive(Debug, Default)]
pub struct ComparisonCache {
    entries: Mutex<HashMap<CacheKey, (u64, u64)>>,
    insertion_order: Mutex<VecDeque<CacheKey>>,
    hits: AtomicU64,
    walks: AtomicU64,
}

impl ComparisonCache {
    /// Empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Cached counts for this exact key, if present.
    fn get(&self, key: &CacheKey) -> Option<(u64, u64)> {
        let entries = self.entries.lock().expect("graph cache lock");
        let found = entries.get(key).copied();
        drop(entries);
        if found.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        found
    }

    /// Store a successful count pair, evicting the oldest entries past
    /// [`MAX_GRAPH_CACHE_ENTRIES`] (FIFO; re-insertion of a live key
    /// refreshes its value but not its eviction position).
    fn insert(&self, key: CacheKey, counts: (u64, u64)) {
        let mut entries = self.entries.lock().expect("graph cache lock");
        let mut order = self.insertion_order.lock().expect("graph cache lock");
        if entries.insert(key.clone(), counts).is_none() {
            order.push_back(key);
        }
        while entries.len() > MAX_GRAPH_CACHE_ENTRIES {
            if let Some(oldest) = order.pop_front() {
                entries.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Count a completed object walk (primary or fallback success).
    /// Tests use `hits`/`walks` to prove reuse without re-walking.
    fn note_walk(&self) {
        self.walks.fetch_add(1, Ordering::Relaxed);
    }

    /// Cache hits served so far.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Object walks completed so far (cache misses that succeeded).
    #[must_use]
    pub fn walks(&self) -> u64 {
        self.walks.load(Ordering::Relaxed)
    }

    /// Entries currently cached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().expect("graph cache lock").len()
    }

    /// True when no entries are cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// True when `git_dir` or `common_dir` carries a non-empty `shallow`
/// file (the store is a shallow clone, or was made shallow by hand).
/// Read-only control-file probe; unreadable files read as absent —
/// the gix open below re-checks via `shallow_commits` before any
/// walk, so a missed file degrades to the walk-time check, never to
/// a false complete claim.
#[must_use]
pub fn shallow_present(git_dir: &Path, common_dir: &Path) -> bool {
    for dir in [git_dir, common_dir] {
        let path = dir.join("shallow");
        if let Ok(bytes) = std::fs::read(&path) {
            if bytes.iter().any(|b| !b.is_ascii_whitespace()) {
                return true;
            }
        }
    }
    false
}

/// True when `git_dir` or `common_dir` carries a live `info/grafts`
/// entry (a non-blank, non-comment line). gix 0.88 honors no grafts,
/// so any grafted store compares as [`STATE_INCOMPLETE_HISTORY`].
#[must_use]
pub fn grafts_present(git_dir: &Path, common_dir: &Path) -> bool {
    for dir in [git_dir, common_dir] {
        let path = dir.join("info").join("grafts");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                return true;
            }
        }
    }
    false
}

/// Validate a tip OID: even-length lowercase hex of the algorithm's
/// exact length (`sha1`: 40, `sha256`: 64). Anything else is `error`,
/// never walked.
fn valid_oid_hex(hex: &str, algo: &str) -> bool {
    let want = match algo {
        "sha1" => 40,
        "sha256" => 64,
        _ => return false,
    };
    hex.len() == want && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Object-store context for one store's comparisons: admin dirs,
/// store identity for cache keying, shared cache, and the optional
/// installed-git fallback.
#[derive(Debug, Clone, Copy)]
pub struct CompareContext<'a> {
    /// Checkout's git dir (worktree admin or common dir).
    pub git_dir: &'a Path,
    /// Shared common dir (object database home).
    pub common_dir: &'a Path,
    /// Store id (common-dir identity); pins the cache key to this
    /// object database.
    pub store_id: &'a str,
    /// Working-tree root for fallback spawns, when any.
    pub work_tree: Option<&'a Path>,
    /// Shared result cache, if reuse is wanted.
    pub cache: Option<&'a ComparisonCache>,
    /// Installed-git fallback for stores gix cannot walk.
    pub fallback: Option<&'a super::fallback::FallbackGit>,
}

/// One local branch with its resolved upstream, as observed: OID hex
/// plus algorithms, or `None` where the observation has no OID
/// (unborn, dangling symbolic, broken). Names stay byte-exact —
/// comparison keys on bytes and never converts them.
#[derive(Debug, Clone, Copy)]
pub struct BranchTips<'a> {
    /// Branch tip OID hex (`None` = unborn/dangling: explicit `error`).
    pub local_hex: Option<&'a str>,
    /// Branch tip algorithm.
    pub local_algo: Option<&'a str>,
    /// Resolved full upstream ref (`None` = [`STATE_NO_UPSTREAM`]).
    pub upstream: Option<&'a [u8]>,
    /// Upstream tip OID hex (`None` with a known ref = `error`).
    pub upstream_hex: Option<&'a str>,
    /// Upstream tip algorithm.
    pub upstream_algo: Option<&'a str>,
    /// False when the upstream ref is absent from the observation
    /// ([`STATE_UPSTREAM_MISSING`]). Defensive-only under D10's
    /// existence-checked resolution, which never emits an absent
    /// upstream — but re-observation skew across phases must stay
    /// explicit rather than silently becoming `no_upstream`.
    pub upstream_known: bool,
}

/// Compare one local branch against its resolved upstream.
///
/// State assignment without object reads: no upstream ⇒
/// `no_upstream`; unknown upstream ⇒ `upstream_missing`; either tip
/// OID missing (unborn branch, dangling symbolic, broken ref) ⇒
/// `error` — detached HEAD, unborn, and missing objects stay
/// explicit and are never forced into `equal`. Algorithm mismatch
/// between the two tips is also `error` (mixed object formats have
/// no defined merge-base). Otherwise delegates to [`compare_oids`].
#[must_use]
pub fn compare_branch(ctx: &CompareContext<'_>, tips: &BranchTips<'_>) -> Comparison {
    if tips.upstream.is_none() {
        return Comparison::no_upstream();
    }
    if !tips.upstream_known {
        return Comparison::upstream_missing();
    }
    let (Some(local_hex), Some(local_algo), Some(upstream_hex), Some(upstream_algo)) = (
        tips.local_hex,
        tips.local_algo,
        tips.upstream_hex,
        tips.upstream_algo,
    ) else {
        return Comparison::error();
    };
    if local_algo != upstream_algo {
        return Comparison::error();
    }
    compare_oids(ctx, local_hex, upstream_hex, local_algo)
}

/// Compare two tip OIDs: ahead = commits reachable from `local_hex`
/// but not `upstream_hex`; behind = the reverse.
///
/// Order: malformed hex ⇒ `error`; equal OIDs ⇒ `equal` 0/0 with no
/// walk; cache hit ⇒ saved counts; grafted store ⇒
/// `incomplete_history`; gix walk ⇒ counts or shallow-cut detection;
/// gix failure ⇒ installed-git `rev-list` fallback (non-shallow
/// stores only — a shallow fallback cannot prove cut-avoidance, so
/// it stays `incomplete_history`); fallback failure ⇒ `error`.
#[must_use]
pub fn compare_oids(
    ctx: &CompareContext<'_>,
    local_hex: &str,
    upstream_hex: &str,
    algo: &str,
) -> Comparison {
    if !valid_oid_hex(local_hex, algo) || !valid_oid_hex(upstream_hex, algo) {
        return Comparison::error();
    }
    // Equal-OID fast path: same commit ⇒ same history, no walk, no
    // object read, no cache touch. Honest even in shallow stores.
    if local_hex.eq_ignore_ascii_case(upstream_hex) {
        return Comparison::from_counts(0, 0);
    }
    let key = CacheKey {
        store_id: ctx.store_id.to_string(),
        oid_a_hex: local_hex.to_ascii_lowercase(),
        oid_b_hex: upstream_hex.to_ascii_lowercase(),
        algo: algo.to_string(),
    };
    if let Some(cache) = ctx.cache {
        if let Some((ahead, behind)) = cache.get(&key) {
            return Comparison::from_counts(ahead, behind);
        }
    }
    // Grafts are unreadable to gix 0.88: refuse before the primary
    // can produce graft-ignorant counts.
    if grafts_present(ctx.git_dir, ctx.common_dir) {
        return Comparison::incomplete_history();
    }
    let shallow_file = shallow_present(ctx.git_dir, ctx.common_dir);
    match open_isolated(ctx.git_dir) {
        Ok(repo) => match walk_counts(&repo, local_hex, upstream_hex) {
            Ok(WalkOutcome::Counts(ahead, behind)) => {
                if let Some(cache) = ctx.cache {
                    cache.insert(key, (ahead, behind));
                    cache.note_walk();
                }
                Comparison::from_counts(ahead, behind)
            }
            Ok(WalkOutcome::CutCrossed) => Comparison::incomplete_history(),
            Ok(WalkOutcome::MissingObject) if repo_is_shallow(&repo) || shallow_file => {
                Comparison::incomplete_history()
            }
            Ok(WalkOutcome::MissingObject) => {
                fallback_counts(ctx, local_hex, upstream_hex, shallow_file, key.as_ref())
            }
            Err(_) => fallback_counts(ctx, local_hex, upstream_hex, shallow_file, key.as_ref()),
        },
        // gix cannot open the store (unsupported object format, …):
        // the fallback's `rev-list` reads what gix cannot.
        Err(_) => fallback_counts(ctx, local_hex, upstream_hex, shallow_file, key.as_ref()),
    }
}

impl CacheKey {
    /// Borrow for the fallback path without re-cloning fields.
    fn as_ref(&self) -> CacheKeyRef<'_> {
        CacheKeyRef { key: self }
    }
}

/// Borrowed cache key for [`fallback_counts`].
struct CacheKeyRef<'a> {
    key: &'a CacheKey,
}

/// Outcome of the primary gix walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkOutcome {
    /// Exact counts; the walk provably stayed above any shallow cut.
    Counts(u64, u64),
    /// A shallow-boundary commit was yielded: grafted parents were
    /// pruned, so counts would be undercounts.
    CutCrossed,
    /// A needed object is absent from the store.
    MissingObject,
}

/// Isolated exact-path open mirroring the inspector's opener
/// (includes disabled, no operator scope): normal attempt, then
/// `open_path_as_is` for arbitrarily named bare stores.
fn open_isolated(path: &Path) -> crate::Result<gix::Repository> {
    let permissions = gix::open::Permissions::isolated();
    let options = gix::open::Options::default().permissions(permissions);
    match gix::ThreadSafeRepository::open_opts(path.to_path_buf(), options) {
        Ok(repo) => Ok(repo.to_thread_local()),
        Err(first) => {
            let options = gix::open::Options::default()
                .permissions(permissions)
                .open_path_as_is(true);
            gix::ThreadSafeRepository::open_opts(path.to_path_buf(), options)
                .map(|repo| repo.to_thread_local())
                .map_err(|second| {
                    crate::Error::Git(format!(
                        "graph: not a repository at {}: {first} / {second}",
                        path.display()
                    ))
                })
        }
    }
}

/// True when the opened repo reports shallow (file check is the
/// pre-open signal; this is the authoritative post-open one).
fn repo_is_shallow(repo: &gix::Repository) -> bool {
    repo.is_shallow()
}

/// Shallow-boundary commit set for cut detection. `None` = not
/// shallow (or unreadable boundary, which reads as not-shallow only
/// when `is_shallow` is also false — a shallow repo with an
/// unreadable boundary file fails the walk below instead of
/// claiming complete counts).
fn shallow_boundary(repo: &gix::Repository) -> Option<HashSet<gix::hash::ObjectId>> {
    let commits = repo.shallow_commits().ok()??;
    let mut set = HashSet::new();
    for id in commits.iter() {
        set.insert(*id);
    }
    Some(set)
}

/// Count commits reachable from `tip` but not from `hidden`,
/// reporting shallow-boundary contact. `Err` = object read failure
/// (missing or corrupt object mid-walk).
fn count_exclusive(
    repo: &gix::Repository,
    tip: gix::hash::ObjectId,
    hidden: gix::hash::ObjectId,
    boundary: &Option<HashSet<gix::hash::ObjectId>>,
) -> Result<(u64, bool), ()> {
    let walk = repo
        .rev_walk([tip])
        .with_hidden([hidden])
        .all()
        .map_err(|_| ())?;
    let mut count = 0u64;
    let mut touched = false;
    for info in walk {
        let info = info.map_err(|_| ())?;
        count = count.saturating_add(1);
        if let Some(set) = boundary {
            if set.contains(&info.id) {
                touched = true;
            }
        }
    }
    Ok((count, touched))
}

/// Primary ahead/behind walk: two exclusive counts plus cut
/// detection. Both tips are existence-checked first so a missing
/// tip reports [`WalkOutcome::MissingObject`] instead of whatever
/// the traversal surfaces.
fn walk_counts(
    repo: &gix::Repository,
    local_hex: &str,
    upstream_hex: &str,
) -> Result<WalkOutcome, ()> {
    let local = gix::hash::ObjectId::from_hex(local_hex.as_bytes()).map_err(|_| ())?;
    let upstream = gix::hash::ObjectId::from_hex(upstream_hex.as_bytes()).map_err(|_| ())?;
    // Existence first: a missing tip is MissingObject even when the
    // other tip's walk would fail differently.
    if repo.find_object(local).is_err() || repo.find_object(upstream).is_err() {
        return Ok(WalkOutcome::MissingObject);
    }
    let boundary = shallow_boundary(repo);
    // A shallow repo whose boundary file is unreadable must not
    // claim complete counts: without the boundary set, cut contact
    // is unprovable.
    if repo_is_shallow(repo) && boundary.is_none() {
        return Ok(WalkOutcome::CutCrossed);
    }
    let (ahead, touched_a) = count_exclusive(repo, local, upstream, &boundary)?;
    let (behind, touched_b) = count_exclusive(repo, upstream, local, &boundary)?;
    if touched_a || touched_b {
        return Ok(WalkOutcome::CutCrossed);
    }
    Ok(WalkOutcome::Counts(ahead, behind))
}

/// Installed-git fallback: `rev-list --left-right --count` for
/// stores gix cannot walk. Fires only when (a) gix cannot open the
/// store, (b) a needed object is missing from a non-shallow store,
/// or (c) the gix traversal itself errors. No fallback handle ⇒
/// `error`. Shallow ⇒ `incomplete_history` (the fallback reports
/// no boundary contact, so cut-avoidance is unprovable).
fn fallback_counts(
    ctx: &CompareContext<'_>,
    local_hex: &str,
    upstream_hex: &str,
    shallow_file: bool,
    key: CacheKeyRef<'_>,
) -> Comparison {
    let Some(fallback) = ctx.fallback else {
        return Comparison::error();
    };
    if shallow_file {
        return Comparison::incomplete_history();
    }
    match fallback.rev_list_count(ctx.git_dir, ctx.work_tree, local_hex, upstream_hex) {
        Ok((ahead, behind)) => {
            if let Some(cache) = ctx.cache {
                cache.insert(key.key.clone(), (ahead, behind));
                cache.note_walk();
            }
            Comparison::from_counts(ahead, behind)
        }
        Err(_) => Comparison::error(),
    }
}
