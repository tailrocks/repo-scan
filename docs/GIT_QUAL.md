# gix 0.88 qualification (spec sections 8–9)

Qualified: `gix 0.88.0` (+ `gix-discover 0.56.0`, `gix-ref 0.68.0`,
`gix-hash 0.27.0`, `gix-config 0.61.0`, `gix-odb 0.85.0`,
`gix-url 0.39.0`, `gix-sec 0.15.0`) from
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`.
All line citations below refer to those sources.

Recommended dependency shape (minimal, no network, no implicit parallelism):

```toml
gix = { version = "=0.88.0", default-features = false, features = [
  "status", "dirwalk", "index", "excludes", "attributes",
] }
```

`default` pulls `extras`/`max-performance-safe` (parallel thread pools);
the spec resource policy (§5) forbids unaudited library parallelism, so do
not use default features. Do NOT enable `blocking-network-client` /
`async-network-client`: fetch/push/connect APIs must be unreachable.
Enable hash support for both `sha1` and `sha256` (gix Cargo features
`sha1`/`sha256` gate `gix-hash` backends; `default` only sets `sha1`).

## 1. Candidate validation at the exact path (spec §8)

Do NOT use upward discovery for validation: `gix::discover()` /
`ThreadSafeRepository::discover_opts()` search parent directories, which §8
forbids as proof that a child is a checkout. Use exact-path open:

- `ThreadSafeRepository::open_opts(path, options)` (`gix-0.88.0/src/open/repository.rs:81`):
  tries `path/.git` via `gix_discover::is_git()`, falls back to `path` itself.
- `open::Options::open_path_as_is(true)` (`gix-0.88.0/src/open/options.rs:103`):
  required for arbitrarily named bare stores (skips the `.git` suffix probe).
  The flag is consumed per call, not retained.
- Pre-filter without full open: `gix_discover::is_git(&git_dir)`
  (`gix-discover-0.56.0/src/is.rs:33`) requires `HEAD` + `objects/` + `refs/`
  and follows `.git` pointer files (`from_gitdir_file`). Fast-fail on missing
  `HEAD`. Note: hash kind is NOT guessed here; detached-HEAD parsing must not
  fail on wrong hash length (comment at `is.rs` re ref-table/hash).
- Bare check: `gix_discover::bare()` (`is.rs:11`) is only a heuristic
  (no `index`, name not `.git`). Authoritative: `Repository::is_bare()`
  (`gix-0.88.0/src/repository/worktree.rs:90`), which honors config.
- Topology after open (`gix-0.88.0/src/repository/location.rs`):
  `git_dir()` (:14), `common_dir()` (:36), `work_dir()`/`workdir()` (:63/:101),
  `kind()` (:208) -> `repository::Kind::{Common, Submodule, LinkedWorkTree}`
  (`gix-0.88.0/src/repository/mod.rs:6`). Old-form nested-`.git` submodules
  report `Common`; only `.git/modules/**` checkouts report `Submodule`.
- Submodules: `Submodule::{path,url,is_active,state,open,git_dir,work_dir}`
  (`gix-0.88.0/src/submodule/mod.rs:106-233,296-311`).

## 2. Config incl. includes (spec §8)

- Trust/permissions selected at open (`gix-0.88.0/src/open/permissions.rs`):
  `Permissions{env,config,attributes}`; `Config{git_binary,system,git,user,env,includes}`
  (:10-33). `Config::all()` enables everything except `git_binary`
  (`git_binary` shells out to installed git; keep `false`). `Config::isolated()`
  reads only repo-local config and follows no includes.
- `Options::isolated()` (:31-33 `open/options.rs`) + `Permissions::isolated()`
  for untrusted candidates; `filter_config_section()` (:144) to restrict which
  sections are readable (`config::section::is_trusted` is the full-trust default).
- `strict_config(true)` (`open/options.rs:165`) makes bad values/IO errors hard
  errors instead of lenient defaults; recommended for identity evidence.
- Include resolution: `gix_config::File::resolve_includes()`
  (`gix-config-0.61.0/src/file/includes/mod.rs:33`) with
  `includes::Options::follow()` / `no_follow()` (`includes/types.rs:32-69`);
  gix wires `includes` permission + conditional context (gitdir/branch) in
  `config/cache/init.rs:272-332`. Effective config is `repo.config.resolved`.
- Record inspected config dependencies from `config.resolved` metadata
  (`gix_config::file::Metadata`: source path per value) for §8 evidence.

## 3. Remote / URL reads (spec §8)

- Enumerate: `Repository::remote_names()` (`repository/config/remote.rs:23`)
  returns trustworthy sections only, bytewise sorted.
- Lookup: `try_find_remote()` / `find_remote()` / `find_fetch_remote()`
  (`repository/remote.rs:69-180`). `find_fetch_remote(None)` emulates
  `git fetch` remote selection (HEAD branch -> default -> single remote).
- Role-preserving URLs: `Remote::url(dir)` / `Remote::urls(dir)`
  (`remote/access.rs:40-62`) for `Direction::{Fetch,Push}`. Fetch = `remote.*.url`;
  push = `pushUrl` else fetch URLs as fallback.
- Rewrites: `url.<base>.insteadOf|pushInsteadOf` applied at construction
  (`repository/remote.rs:110-113`); `try_find_remote_without_url_rewrite()` +
  `Remote::rewrite_urls()` (:101-131 `remote/access.rs`) defers rewriting and
  keeps malformed results on original URLs non-destructively. Safe to use:
  pure string rewrites, no helper execution.
- Parsing: `gix_url::parse()` (`gix-url-0.39.0/src/lib.rs:78`) handles HTTPS,
  SSH, scp-like syntax, `file://`, local paths, `<helper>::<address>`
  (`Scheme::Helper`), `ext` (`Scheme::Ext`), unknown transports
  (`Scheme::HelperUrl`). Deviation: rejects textual/overflowing ports where
  git would fold them into the hostname.
- SSH aliases: NO ssh-config `Host` alias resolution exists in gix 0.88
  (no ssh-config module under `gix-0.88.0/src/` or `gix-protocol-0.66.0/src/`).
  Either parse `~/.ssh/config` narrowly in repo-scan (read-only, no
  `ProxyCommand` execution) or mark affected remotes `unresolvable_identity`
  / use the installed-git fallback with `ssh -G` (still no connection).
- Credentials: `gix_url::Url` exposes user/password fields; redact before
  storing (spec §8). `ArgumentSafety` (`gix-url-0.39.0/src/lib.rs:115`) flags
  `-`-leading URL parts for safe argv passing to the fallback backend.

## 4. Ref enumeration incl. packed (spec §9)

- `Repository::references()` -> `reference::iter::Platform`
  (`repository/reference.rs:336`): `all()`, `prefixed()`, `local_branches()`
  (`refs/heads/`), `remote_branches()` (`refs/remotes/`), `tags()`, `pseudo()`
  (`reference/iter.rs:38-90`).
- Packed refs ARE covered: iterator inner type is
  `gix_ref::file::iter::LooseThenPacked` (`reference/iter.rs:21`); never assume
  loose files under `.git/refs/heads`.
- Per ref: `Reference::name()` (full name), `target()` (`gix_ref::TargetRef`),
  `try_id()`/`id()` (`reference/mod.rs:24-55`); symbolic targets preserved via
  `Target::{Symbolic(name),Object(oid)}` + `peeled` (`gix-ref-0.68.0/src/target.rs`).
  Peel with `peel_to_id*()` / `Iter::peeled()` (holds packed buffer for the
  iteration). Broken/unparsable refs are yielded as per-item `Err`, not skipped.
- Reftable: UNSUPPORTED. `gix-ref` reports "unsupported storage backend, such
  as reftable" (`gix-ref-0.68.0/src/store/file/loose/reference/decode.rs:26`);
  only `store::{file,packed}` backends exist. -> installed-git fallback.
- Upstream mapping: `branch` config helpers (`repository/config/branch.rs`)
  map `refs/heads/*` <-> `refs/remotes/*` via fetch refspecs (for `Branch.upstream`).

## 5. Worktree listing (spec §8)

- `Repository::worktrees()` (`repository/worktree.rs:39`): linked worktrees only
  (main worktree never listed; bare repos may still have linked worktrees),
  sorted by private gitdir; missing `worktrees/` dir yields empty vec (not error).
- `worktree::Proxy` (`worktree/proxy.rs`): `id()` (:53, dir name under
  `worktrees/`), `git_dir()` (:48), `base()` (:43, checkout path; may not exist),
  `is_locked()` (:59), `lock_reason()` (:78), `is_prunable()` (:67),
  `into_repo()` (:102, fails unless base `is_dir()`),
  `into_repo_with_possibly_inaccessible_worktree()` (:90, opens gitdir with
  maybe-missing base for metadata-only reads).
- Availability mapping: registered = proxy exists (has `gitdir` file);
  existing = `base().is_dir()`; inaccessible/missing = `base()` IO error or
  `is_prunable()`; broken = `into_repo*` fails or `gitdir` target unparseable.
  Entries whose `gitdir` file is absent are silently skipped by `worktrees()`
  (:49) — scan `common_dir/worktrees/` directly to report those as broken.
- Current checkout: `Repository::worktree()` -> `Worktree` (`worktree.rs:82`);
  `Worktree::{id,is_main,is_locked,dot_git_exists}` (`worktree/mod.rs:64-103`).
  `main_repo()` (`worktree.rs:69`) re-opens via `common_dir`.
- HEAD state is orthogonal to kind: a linked worktree with detached HEAD is
  still `Kind::LinkedWorkTree` (§9: report kind + head separately).

## 6. HEAD / detached / unborn (spec §9)

- `Repository::head()` (`repository/reference.rs:179`):
  `HEAD` symbolic -> referent exists ? `Symbolic` : `Unborn`;
  `HEAD` direct -> `Detached{target,peeled}`.
- `Head::Kind::{Symbolic,Unborn,Detached}` (`head/mod.rs:13-31`);
  `is_detached()` (:70), `is_unborn()` (:77), `referent_name()` (:61, `None`
  when detached), `id()` (:94, `None` when unborn),
  `try_into_referent()` (:117, `Some` only for born symbolic).
- Convenience: `head_id()` (peeled; fails on unborn), `head_name()`
  (`Some` incl. unborn, `None` when detached), `head_ref()`
  (`Some` only born symbolic), `head_commit()`, `head_tree_id()`,
  `head_tree_id_or_empty()` (empty-tree hash on unborn)
  (`repository/reference.rs:203-260+`).

## 7. Status: summary vs full untracked semantics (spec §9)

- Entry: `Repository::status(progress)` (`status/mod.rs:89`) ~=
  `git status --ignored=no`; honors `status.showUntrackedFiles`
  (`config/tree/sections/status.rs:8`, `try_into_show_untracked_files` :32).
- Untracked mode: `Platform::untracked_files(UntrackedFiles::{None,Collapsed,Files})`
  (`status/platform.rs:32`): `Collapsed` -> `EmissionMode::CollapseDirectory`
  (untracked dir = ONE entry); `Files` -> `EmissionMode::Matching` (individual
  files). Spec mapping: `summary` = `Collapsed`, `full` = `Files`,
  `metadata` = skip `status()` entirely. `None` disables the dirwalk.
- Iterators: `into_index_worktree_iter(patterns)` (index<->worktree only,
  `status/index_worktree.rs:559`) vs `into_iter(patterns)` (combined HEAD-tree
  + index + worktree, `status/iter/mod.rs:44`). Combined `Item::{IndexWorktree,
  TreeIndex}` (`status/iter/types.rs:55`).
- Count mapping: staged = `TreeIndex(Change)` items (or low-level
  `tree_index_status()` callback, `status/tree_index.rs:45`);
  unstaged = `IndexWorktree::Modification` items; untracked =
  `IndexWorktree::DirectoryContents` items (`status/index_worktree.rs:315-340`).
  `Rewrite{...}` items need a counting policy (count destination once as
  unstaged; record copies/renames consistently). Ignore semantics come from
  the `excludes` feature (gitignore + excludes); ignored files are not emitted
  unless `emit_ignored` is set (`dirwalk/options.rs:85`).
- Counts are caller-side tallies over the iterator; gix provides no
  pre-aggregated staged/unstaged/untracked counters. Stream, do not collect.
- Submodules: `index_worktree_submodules(Submodule::{AsConfigured,Given})`
  (`status/mod.rs:22`, `platform.rs:66`); `Given{ignore: Ignore::All}` =
  `submodules: not_requested`; else `checked`. Rename tracking off by default
  for index<->worktree (`index_worktree_rewrites(None)`); HEAD<->index renames
  via `tree_index_track_renames()` (default `AsConfigured`).
- NO index writes: `Outcome::write_changes()` (`status/iter/types.rs:89`)
  persists stat refreshes — spec §9 forbids index refresh writes, so NEVER
  call it; accept slower repeat probes. `has_changes()` may inform `unstable`.
- Fingerprints for instability retry: capture `head_id`/`index` mtime+size
  before/after; `Outcome.worktree_index` tells which index was used.

## 8. Hash kinds incl. sha256 (spec §9)

- `gix_hash::Kind::{Sha1,Sha256}` (`gix-hash-0.27.0/src/kind.rs`);
  `len_in_hex()` (:91) = 40/64; `len()` (:~105) = 20/32;
  `ObjectId`/`oid` carry their kind; `null_sha1/null_sha256` provided.
- `Repository::object_hash()` (`repository/config/mod.rs:295`) from
  `extensions.objectFormat` + `core.repositoryFormatVersion`
  (`config/cache/incubate.rs:50-58`; legacy default sha1, `:114-117`).
- Report `ObjectId{algorithm: kind.to_string() ("sha1"/"sha256"), hex}`.
  Never assume 40 chars; validate even-length lowercase hex per schema.

## 9. Limits and watchdog hooks

- `index_worktree::Options{sorting,dirwalk_options,rewrites,thread_limit}`
  (`status/index_worktree.rs:15-42`): set `thread_limit = Some(1)` (or 0/None
  semantics per docs) to honor the 1-Git-probe / shared-permit budget; without
  the `parallel` feature the iterator is serial and non-interruptible.
- `Platform::should_interrupt_{shared,owned}` (`status/platform.rs:48-64`)
  for watchdog cancellation; first `next()` may block until first item.
- `Options::object_store_slots(Slots)` (`open/options.rs:86`) bounds odb cache;
  `Slots::Given` keeps odb open fully lazy (no disk IO at open).
- `dirwalk::Options` (`dirwalk/options.rs`): `emit_untracked`,
  `emit_ignored(None)`, `emit_tracked`, `recurse_repositories` (keep `false`:
  nested repos are separate discoveries, §8), empty-dir handling.
- No byte/entry budget inside status iteration: enforce admission (1 Git probe),
  item-count caps, and the no-progress watchdog in repo-scan's admitted helper.

## 10. Safety: no hooks / filters / fetch (spec §9)

Verified by source inspection:

- No hook execution on read paths. `hook` matches in `gix-0.88.0/src/` are
  sample files under `assets/init/`, `open_with_environment_overrides` docs
  (for implementing hooks, not running them), and config plumbing. There is no
  `core.hooksPath` executor in open/config/ref/status paths.
- No filter/process execution unless explicitly requested. Content filters run
  only via `Repository::filter_pipeline()` (`repository/filter.rs:20`) and
  `command_context()` (`repository/config/mod.rs:262`); status hashing and
  dirwalk do not invoke clean/smudge helpers or fsmonitor. Do not call these
  APIs; if a filter is REQUIRED for an accurate answer, report
  `unsupported`/`partial` per §9 instead.
- No fetch/GC/maintenance. Network needs `blocking/async-network-client`
  features (excluded) plus explicit `connect()`; status/ref/discover paths
  perform no writes except the explicitly forbidden `write_changes()` (§7).
- Config-trust: `Permissions::config.git_binary = true` would execute the git
  binary to read its config (`open/permissions.rs:11-15`); keep `false`.
  `filter_config_section` + `bail_if_untrusted` contain doctored repos.

## 11. Installed-git fallback triggers

Use the §9 compatibility backend (explicit paths, `GIT_CONFIG_*` /
`GIT_CEILING_DIRECTORIES`-style selection env, no shell interpolation, no
locks, `core.hooksPath=/dev/null`-equivalent empty hooks, `--no-optional-locks`,
`GIT_HTTP_*` unset, `c core.fsmonitor=false`, protocol/file-process filters
disabled) when gix reports:

1. Reftable ref storage (§4) or any `reference` open/iteration error that is
   structural rather than IO-transient.
2. SSH-alias remote URLs (§3) needing `Host` resolution (read-only `ssh -G`;
   never connect).
3. `gix_index` parse failures (future index versions/extensions) or worktree
   admin layouts gix cannot open (`into_repo*` errors on otherwise-registered
   worktrees).
4. Object-format gaps at runtime (e.g. sha256 backend feature missing):
   surface as `unsupported`, do not mis-hash.
5. Any case where accurate status would require executing a configured
   filter/fsmonitor/helper: fallback ALSO must not execute it; record
   `partial`/`unsupported` with the reason (spec §9, last paragraph of the
   compatibility bullet).

Probe fallback-git capabilities once per installed-git identity
(`git --version` + `git status --porcelain=v2 --help` feature probe) and reuse.
