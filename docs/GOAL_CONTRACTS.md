# Goal contracts: fast, complete, easy repo-scan (v1, 2026-10-07)

Coordinator-selected contracts. Implementation waves must follow these; changes
need a coordinator decision recorded here. Terms per goal Step 5 (`Discovery`,
`Analysis`, `GitHub group`, `Local store`, `Checkout`, `Path alias`, `Catalog`,
`Snapshot`, `Event`, `Coverage gap`).

## D1. Record types and IDs (Step 5)

Reuse existing Catalog tables; add what is missing. No renames.

| Record | Catalog source | Report record | ID rule |
|---|---|---|---|
| Local store | `git_instances` (= existing) | `Repository` | existing `id` (common dir + physical identity); independent clones stay separate |
| Checkout | `checkouts` | `Checkout` | existing `id`; HEAD/index/config/refs per checkout |
| Branch | `refs` | `Branch` + comparison fields | `(instance_id, full refname)`; never merge across stores |
| Path alias | derived (alias index) | `Alias` | `(path_id, target_path_id, kind)` |
| Remote assoc | `remotes` | `Remote` | existing `id`; keep name + role + normalized identity; fork/upstream never merged |
| GitHub group | NEW `github_groups` (migration v2) | NEW `groups[]` | `lower(host) + '/' + lower(account) + '/' + lower(repo)`; exact match for targets |
| Coverage gap | `errors` | `ErrorRecord` | existing `id` |
| Candidate | derived | `Candidate` | existing `id`; identity `unknown` when unresolvable |

Totals (NEW `totals` object in report): accounts/orgs, unique groups,
stores (+bare), present checkouts (+linked worktrees), observed paths
(+aliases), local branches, remote-tracking refs, analysis
completed/pending/failed/unavailable, unresolved candidates, gaps.
Unknown counts are `null`; pre-analysis fields are `pending`.
Filesystem coverage, identity coverage, analysis completion, remote
freshness stay separate properties.

## D2. Schema versions (Step 5)

- Report `1.0.0` → `1.1.0` (additive: `groups[]`, `totals`, branch
  comparison fields, freshness basis; no field removed/renamed).
- Report `1.1.0` → `1.2.0` (additive, Step 11: branch `freshness` /
  `freshness_at`, remote `refresh` summary; no field removed/renamed;
  pre-1.2 snapshots deserialize with `unknown` / `None`).
- Report `1.2.0` → `1.3.0` (additive, Step 10: status `conflicts` /
  `working_state` vocabulary; no field removed/renamed; pre-1.3
  snapshots deserialize with `None` / `unknown`).
- Report `1.3.0` → `1.4.0` (additive, Step 10: branch `comparison` /
  `ahead` / `behind`; no field removed/renamed; pre-1.4 snapshots
  deserialize as `pending` / null; validator accepts `1.3.0` + `1.4.0`).
- Catalog migration v6: `refs.comparison_state` / `ahead` / `behind`
  (Step 10); legacy rows read `NULL` (`pending` / null counts).
- NEW scan-event stream schema `1.0.0` (JSONL).
- Catalog migration v2: `github_groups`, `scan_events` journal,
  `scan_requests` multi-target columns, full scope key (D5). v1 data migrates.
- Catalog migration v5: `status_observations.conflicts` /
  `working_state` (Step 10); legacy rows read `NULL` (unknown).
- Reason for new IDs: only `github_groups` and `scan_events` IDs are new;
  both are new entities, so no stability break.

## D3. Phase transitions (Step 8)

`Discovery → inventory_ready → Analysis → (Fetch?) → Completed`.
`Fetch` runs only with explicit `--fetch`, after local Analysis.

`inventory_ready` is saved when ALL hold: enumeration + metadata-expansion
tasks terminal (complete or recorded gap), zero active Discovery workers,
zero buffered discoveries, zero pending retries. Empty queue alone is NOT
completion. Bounded wait: after the retry budget a stuck scope becomes a
gap and the boundary closes as `incomplete`. Later refreshes open a NEW
generation; the closed boundary is never edited.

Order proof: instrumented test asserts no branch/status/graph read starts
before the generation's `inventory_ready` row commits.

## D4. Event classes (Step 12)

One envelope: `{schema_version, scan_id, seq, catalog_rev, type, op, records[]}`.
`op` is `add` | `replace` | `remove`. Per-record `rev` where stale updates
are possible. Queues bounded; progress events coalesce to newest per scan;
record/error events never silently dropped (durable replay or backpressure).

| `type` | `op` | Payload |
|---|---|---|
| `scan_started` | add | scan id, scope, targets, options, resume cmd |
| `discovery_progress` | replace | phase, elapsed, discovered, pending, gaps (no % of unknown total) |
| `location_found` | add | checkout/store/path/alias ids, identity or `unknown`, analysis=`pending` |
| `repository_found` | add | store id + GitHub group assoc |
| `inventory_ready` | add | complete\|incomplete, generation, counts, gaps |
| `branch_batch` | add/replace | branch records w/ `rev` |
| `location_updated` | replace | checkout analysis/state change w/ `rev` |
| `coverage_updated` | replace | gaps/candidates delta |
| `error` | add | ErrorRecord |
| `remote_updated` | replace | per-store remote op: success/failure/time/ref coverage |
| `scan_completed`/`scan_incomplete` | add | final counts + resume cmd |
| `scan_interrupted` | add | scan id, cursor, saved scope/options |
| `scan_failed` | add | last cursor, error, resume capability |

Cursor: opaque; `scan seq` + `(catalog_rev, event offset)`. Snapshot cursor
= exact end of included changes. Events sent only after their Catalog
transaction commits. Cursor outside retention → fresh snapshot + `reset:true`.
Duplicates: same `(seq)` re-delivery is idempotent; consumers dedupe by seq.

Wave1d deltas (Step 12, branch `work/fast-complete-scan`):

- Gauge coalescing is write-side seq-reuse: the first `discovery_progress`
  tick takes a fresh seq; later ticks UPDATE its payload in place at the
  immutable `(catalog_rev, event_offset)`. Exactly one progress row per scan
  holds the NEWEST payload; record events are never dropped by coalescing.
- Retention bound: newest 50,000 rows per scan journal
  (`MAX_RETAINED_SCAN_EVENTS`); prefix prune in one transaction; the tip row
  always survives. Cursors at/below the prune cutoff resync as a snapshot
  with `reset:true` on the first envelope (never a silent resume).
- Cursor classification: a covered record cursor with a drifted
  `(catalog_rev, event_offset)` diverges (snapshot + `reset:true`); the
  coalescible `discovery_progress` gauge NEVER diverges on position drift —
  the reader resumes after its own position. Corrupt `--after` stays a usage
  error (exit 2); pruned/beyond-tip cursors stay snapshots (exit 0).

Wave2b deltas (Steps 6 + 12 output matrix, branch `work/fast-complete-scan`):

- `branch_batch` branch records carry `comparison` / `ahead` / `behind`
  (additive envelope fields): local branches carry the computed triple
  persisted on the `refs` row, every other kind carries
  `pending`/null — exactly the final-JSON rendering. Consumers must
  treat absent triples as `pending`/null (pre-Wave2b journals).
- Terminal payloads are pinned: `scan_completed`/`scan_incomplete`
  carry `counts` (matched_per_target, pending, open_gaps,
  unresolvable, status_pending, event_gaps) + `generation` +
  `report_id` + `published` + `resume_cmd`; `scan_interrupted`
  carries `scan_id` + `cursor` + `generation` + `scope` + `options` +
  `resume_cmd`; `scan_failed` carries `cursor` (last committed event,
  null when nothing journaled) + `error` (scrubbed) + `resumable`
  (always true) + `resume_cmd`.
- JSONL replay folds into the final JSON inventory (case 15):
  `repository_found` store IDs, `location_found` checkout IDs,
  `branch_batch` branch IDs + triples, and `error` IDs reconstruct the
  same records and totals. Proven in `tests/output_impl.rs`, never by
  self-comparison.
- Machine stdout discipline: JSON/JSONL lanes emit serialized bytes
  only — no prose, no ANSI escapes, no cursor codes, no CR bytes.
  Diagnostics go to stderr. A broken pipe ends the writer quietly
  (exit 0 for replays; the scan's own exit for scan tails) with
  committed catalog records untouched.
- `--follow --format json` stays rejected (exit 2): JSON supplies one
  snapshot; followers use human or jsonl.

## D5. Scope key and scheduling (Steps 7–9)

Scope key = normalized roots + volume identities + exclusions + traversal
policy (replaces bare `roots`/`machine` policy names; fixes stale-root
reuse). Targets stay OUT of the key: one filesystem pass serves all targets;
later target queries reuse valid coverage. Worker results go to one writer
in bounded batches (row/byte/age caps); no per-task flush+completion
transactions. Children persist in the same transaction as parent completion;
stale generations rejected; redelivery idempotent.

## D6. CLI (Step 6)

Additive. Existing single-URL/local-path commands keep working.

- `scan [TARGET]... [--all] [--root R...] [--format human|json|jsonl]
  [--report F] [--follow] [--fetch] [--color auto|always|never]
  [--status M] [--force-rescan]`: targets = `owner/name` or GitHub URL
  forms; `--all` = filesystem discovery (no GitHub inventory first);
  targets XOR `--all` (reject both/neither... neither with no targets =
  error unless `--all`); no roots = machine scope.
- `query (--all | --scan ID | URL) [--cached] [--format ...] [--follow]
  [--after CURSOR]`: `--follow` only with human|jsonl (reject with json).
- `resume SCAN_ID [--format ...]`: restores ALL saved options.
- Format default: live human on TTY, JSONL when redirected; explicit wins.
- `--fetch` help states exactly which refs/objects change; never moves
  branch tips (unsafe refspec → `unsupported` refresh, no write).
- `--report` = atomic complete-JSON snapshot destination (Step 12 rules).

Wave2b deltas (output matrix, branch `work/fast-complete-scan`):

- One state model: `scan`, `query --scan`, and `resume` serve all
  lanes from the same retained snapshot bytes (human renders them,
  json prints them, jsonl replays the journal committed with them).
  Totals and record IDs agree across lanes for one scan revision.
- Explicit `--format` wins; no explicit format keeps the legacy
  output (readable terminal report or `scan_id:`/`report_id:`/
  `snapshot:`/`report:` footers). Explicit `scan --format human`
  renders the stable plain-text lane (`src/report/live_text.rs`:
  header, coverage, totals, `R`/`C`/`B`/`?`/`!` rows, capped at 200
  with an overflow line) plus the legacy footers; the default
  terminal rendering is unchanged.
- `scan --format json` prints one JSON document (the retained
  snapshot bytes verbatim); with `--report` the file is also
  published. `scan --format jsonl` retains the snapshot and replays
  the scan journal. `query --scan --format json` prints the scan's
  verified retained snapshot verbatim; `--format human` renders it as
  plain text. `resume --format json|jsonl|human` follows the same
  lanes (explicit wins, else the scan's saved format is restored).
- `query --scan --follow --format human` was unimplemented in
  Wave2b (exit 1); Wave3 implements it (D11): the live TUI on a TTY,
  the plain live lane when redirected.
- Live `--report` (case 17): while a scan runs, `--report` holds a
  live snapshot (`scan.state == "running"`, `finished_at == null`,
  report ID `<scan-report-id>-live`) replaced atomically at phase
  boundaries (post-`inventory_ready`, post-analysis, post-fetch) and
  at most once per 2 s — never a rebuild per discovery. Every
  concurrent read is valid JSON from exactly one revision. Live ticks
  are best-effort (a failed tick logs to stderr, never fails the
  scan) and are never retained: the destination is the replaceable
  snapshot. Completed snapshots are retained bounded (newest 32;
  snapshots named by a scan outcome are never pruned).

Consumer-migration notes (README rewrite is a later wave):

- Consumers parsing default scan stdout (`scan_id:` footers) are
  unaffected: defaults are byte-compatible with Wave2a.
- New machine consumers should pass an explicit `--format`:
  `json` for one inventory document, `jsonl` for the event stream
  (fold per case 15 to rebuild the inventory, dedupe by `seq`,
  honor `reset:true` by dropping buffered state).
- `branch_batch` consumers gain `comparison`/`ahead`/`behind` per
  branch; absent fields mean `pending`/null (old journals).
- `query --scan` consumers: `--format json` now serves the retained
  snapshot (previously "not yet implemented"); the no-catalog and
  unbound-catalog notes moved from stdout to stderr (exit 3,
  empty machine stdout).
- `--report` readers may now observe `running` revisions mid-scan
  before the terminal revision; every read is still one complete
  JSON document — atomic replacement, no torn reads.

## D7. Git semantics (Steps 10–11)

Normalize https/ssh/scp + `ssh.github.com:443`; strip credentials pre-output;
SSH aliases apply to SSH transports ONLY. Upstream resolution becomes
Git-compatible (last-wins, unescape, includes, refspecs, worktree config;
replaces first-wins manual parser). Shared refs read once per store; per
checkout HEAD/index/status. Branch comparison states: `equal|ahead|behind|
diverged|no_upstream|upstream_missing|pending|incomplete_history|error`
(counts null when unknown; no-upstream ≠ synced; never default-compare to
main). Working states: `clean|dirty|conflicted|pending|partial|unstable|
unknown|error|not_applicable` (never `clean` for metadata-only/failed).

Wave2a deltas (Step 10 branch comparison, branch `work/fast-complete-scan`):

- Backend: equal-OID fast path (0/0, no walk) → gix `rev_walk`
  primary (isolated open) → installed-git `rev-list --left-right
  --count` fallback ONLY when gix cannot open the store, a needed
  object is missing from a non-shallow store, or the traversal
  errors. Result cache keyed `(store-id, oid-a, oid-b, algo)`,
  ordered tips, bounded 1024 entries (FIFO); only successful count
  pairs cached.
- Shallow: a walk yielding a shallow-boundary commit is
  `incomplete_history` (null counts); walks staying above the cut
  report exact counts. Grafted stores (`info/grafts` live entries)
  are `incomplete_history` outright (gix 0.88 honors no grafts).
  Missing objects: `error` in full stores, `incomplete_history` in
  shallow stores.
- Scope: local (`refs/heads/`) branches only; unborn/dangling
  branches and oidless upstreams are `error`, never `equal`.
  `upstream_missing` is defensive-only under D10's
  existence-checked resolution. Non-local ref kinds persist no
  comparison and read `pending` (comparison never runs for them).
- `--fetch` does NOT recompute comparisons: post-fetch labels may
  read stale until the next analysis pass.

Wave2b deltas (fetch recompute, branch `work/fast-complete-scan`):

- `--fetch` DOES recompute comparisons (supersedes the Wave2a stale
  note above): after each store's fetches, every local branch whose
  resolved upstream the fetch observed `current` is re-compared from
  the post-fetch catalog oids and relabeled. Only those branches
  move: branches tracking excluded, deleted-upstream, failed, or
  unfetched refs keep their analysis-pass label. Only successfully
  observed refs become `current`; excluded and deleted refs stay
  `stale` — never a false `current`, never a recompute without a
  fresh observation. Skipped on pre-v6 catalogs.
Default probes offline + read-only (no helper exec, fetch, hooks, fsmonitor,
index writes); porcelain-v2 unmerged records parsed byte-safe (NUL-delimited).

## D8. File ownership for waves (Step 1)

New files = parallel-safe (one owner each). Existing files = coordinator
wires/integrates; one owner at a time.

| Owner | New files owned |
|---|---|
| scan-events | `src/scan_events.rs` (envelope, classes, ops, cursor, retention) |
| live-text | `src/report/live_text.rs` (plain live renderer from `Report`) |
| baseline | `/tmp` only + evidence text (no repo writes) |
| coordinator | ALL edits to existing files (`cli.rs`, `main.rs`, `lib.rs`, `schema.rs`, `Cargo.toml`, docs) + all commits/pushes |

Later waves: catalog migration v2, probe split, parallel workers, TUI
(`src/tui.rs`, needs new deps → coordinator adds deps first), `--fetch`,
fixtures/acceptance tests, corpus + gates.

## D9. Baseline facts (Phase-A + coordinator)

- Code revision `13e534b`, clean tree; release binary
  `f69a315b…ac7b43a`, 27.5 MiB, `cargo build --release` 4m08s (cache-aided).
- Toolchain: rustc/cargo 1.98.1, macOS 27 arm64. No `[profile.release]`:
  receipt claim (opt-level=3/lto/codegen-units=1/panic=abort) is UNVERIFIED;
  cargo defaults apply until proven otherwise.
- Proven current costs: sequential claim→execute (1 op in flight);
  ≥2 txns/task + up to 6 lease renewals on probe path; 4 aggregate
  SELECTs per probe via `emit_progress`; probe spawns installed-git
  subprocesses; scope reuse by bare policy name (stale-root reuse bug).
- `src/main.rs` (11,318 lines) is the shared-contention file: only the
  coordinator edits it until the planned small module splits land.

## D10. Upstream storage shape (Step 10, Wave1c-3)

`branch.upstream` (catalog `refs.upstream` blob, report `Branch.upstream`,
`branch_batch` event `upstream`/`upstream_hex`) stores the RESOLVED full
local comparison ref — what `git rev-parse --symbolic-full-name '@{u}'`
prints when the target exists (`refs/remotes/<remote>/…`, custom fetch
destinations, or the local merge ref for `remote = .`) — NOT the old
`remote/leaf` short guess. Rationale: only the full refname identifies
the comparison target under custom fetch refspecs; no consumer
constrains the shape (blob storage, shape-agnostic validation, branch
comparison unimplemented). Resolution is Git-compatible (last-wins
singles, first-wins `branch.merge`, first-match fetch mapping, no
fallback, existence-checked, includes + per-checkout `config.worktree`
under effective `extensions.worktreeConfig`); unresolvable is null,
never fabricated. Consequence: the `tests/review_fix_main.rs` R16 pin
`origin/main` must move to `refs/remotes/origin/main` (coordinator-owned
file; Wave1c-3 may not touch it).
Worktree config is read per checkout gitdir
(`<gitdir>/config.worktree`), not from the common dir — probed against
git 2.56.0 (a linked worktree ignores the common `config.worktree`).

## D11. Live terminal TUI (Step 13, Wave3, branch `work/fast-complete-scan`)

Interactive live view for explicit `scan --format human` on a TTY
and `query --scan --follow --format human` (cases 24/25). Lives in
`src/report/tui.rs` with NO new dependencies (libc termios + ANSI
directly; supersedes the D8 `src/tui.rs` + new-deps expectation).
View state and rendering split so tests drive scripted key streams
against fixture snapshots with no PTY (`tests/tui_impl.rs`).

- Grouped account/org > repository > local store > checkout;
  aggregate counts render before rows; the header carries
  phase/elapsed/discoveries/completed/pending/gaps and NEVER a
  percentage of the unknown discovery total. New locations appear
  before analysis completes (rows labeled `pending`); rows update
  in place; cached snapshots show `cached age=<age>` plus
  `pending-refresh` while analysis is outstanding.
- Selection and scroll anchor to stable record ids
  (`group:`/`store:`/`checkout:`/`branch:` + catalog id): live
  updates never reset either (a vanished id falls to the nearest
  visible row). Detail (`v`/leaf enter) and help (`h`/`?`) are
  overlays; `q` quits from anywhere including overlays, esc closes
  the overlay (or stops the search) and quits when nothing is open.
- Pinned keys (verbatim in the help overlay and `tests/tui_impl.rs`):
  up/down or `j`/`k` move; left/right collapse/expand (left also
  moves to the parent); enter/space expands/collapses a group,
  store, or checkout with branches and opens detail on a leaf; `/`
  searches account/repo/path/branch (enter keeps, esc clears); `f`
  cycles `dirty > conflicted > ahead > behind > diverged > pending
  > failed > off`; `s` cycles `group > path > state`; `v` opens
  detail (full paths + state explanations); `h`/`?` help; `q`
  quit; esc close/quit. Ctrl-C interrupts (scan: bounded save,
  exit 130; follow: exit 130); stdin EOF quits the view.
- Filter semantics: `dirty`/`conflicted` match working state;
  `ahead`/`behind` match branch comparisons (diverged counts for
  both); `diverged` matches diverged only; `pending` matches rows
  awaiting analysis; `failed` matches error state, attached error
  records, or `missing`/`broken`/`inaccessible` availability.
  Matching leaves render with ancestors for context. Sorts: `group`
  (canonical hierarchy), `path` (siblings by path/name), `state`
  (failed, conflicted, dirty, diverged, ahead/behind, pending,
  clean, rest).
- Color rides with text labels (never color alone). `scan`
  `--color auto|always|never` is honored; `query` has no `--color`
  flag and always uses auto. `NO_COLOR` set or `TERM=dumb`
  disables color under every mode. Redirected output stays
  machine-clean: the plain lane reuses `live_text` renders only.
- Terminal discipline: sane minimum 40x8 (narrower degrades to a
  truncated header + notice, never panics); size re-queried every
  redraw (resize-safe); long paths keep the tail with `…`; Unicode
  column width via an internal width table; control characters
  escaped via `escape_display`; the RAII guard restores termios +
  leaves the alternate screen on completion, interruption,
  failure, and drop. Bounded redraw (~10fps full frames); live
  catalog row refresh at most every 2 s, main thread only,
  read-only connection, no per-probe aggregate queries on workers.
- No daemon/web service. Scan TUI: `q`/esc mid-scan detaches to
  plain stderr progress (the scan continues); at completion the
  view browses the exact retained bytes, then the legacy footers
  print. Follow TUI: folds the journal live, swaps to the retained
  snapshot at the terminal event, quits to exit 0. Quitting never
  disturbs the scan or the catalog. `--after` applies to the TUI
  follow (reset positions drop buffered state); the plain lane
  ignores it (byte-change renders have no cursor).

## D12. Wave4b documentation decisions (Step 17, branch `work/fast-complete-scan`)

Observed delivered behavior pinned by running the debug binary against
fixture repos (one clone + one bare store under `--root`); README
examples quote that output (IDs/paths trimmed, never invented).

- Report `1.4.0` carries NO top-level `totals` object and NO `groups[]`:
  the D1 totals/groups plan is unimplemented in the delivered JSON.
  Counts are record vec lengths (the human `totals` line prints exactly
  those) plus the three independent `coverage` properties
  (`filesystem` / `identity` / `status`) with `gaps` ==
  `len(errors)` and `unresolvable_candidates` == unresolvable
  `candidates`. Docs must not promise `totals`/`groups[]` until a wave
  ships them (additive schema bump when it does).
- `query TARGET --cached` always prints the short human summary and
  ignores `--format` (observed: `--format json`/`jsonl` still print the
  summary, exit 0). `query --all` parses but is unimplemented (exit 1
  with a redirect hint). Query without `--cached` is exit 2 (live
  queries unsupported). Short `owner/name` targets under `--cached` may
  report `canonical: unresolved` (exit 3) where the full URL resolves.
- No `--format` keeps the legacy terminal report + footers for
  `scan`/`resume`, but `query --scan` with no `--format` replays the
  journal as JSONL when redirected (explicit `--format` always wins).
  `query --scan --format human` prints the plain lane with no footers.
  Unknown scan IDs are exit 2 for both `query --scan` and `resume`.
- `--fetch` ships: post-analysis, remote-tracking refs + `FETCH_HEAD` +
  objects only, never branch tips or checkout files; unsafe refspecs
  are `unsupported`, never written (observed stderr summary:
  `fetch: N refreshed, N failed, N unsupported, N resumed-skip`).

## D13. Wave6 query/format behaviors (Step 6, branch `work/fast-complete-scan`)

Supersedes the D12 output pins (the D12 bullets above stay as the
Wave4b record). Verified against the debug binary on the Wave6 tree;
README examples quote that output (IDs/paths trimmed, never invented).
Pinned by `wave6_*` tests in `tests/cli_impl.rs`.

- `query --all --cached` resolves the latest suitable scan — newest
  `complete`/`incomplete`/`interrupted` row, machine or explicit-roots
  scope alike, whose outcome parses and whose retained snapshot file
  still exists — and serves it through the same replay core as
  `query --scan`: `--format json` prints the retained snapshot,
  `--format jsonl` replays the journal (byte-identical to
  `query --scan --format jsonl`), `--format human` renders the plain
  lane. No `--format` auto-selects (human on a TTY, JSONL when
  redirected). `--cached` is required (exit 2 without); no suitable
  scan is exit 3 with an empty stdout. The old exit-1
  "not yet implemented" path is gone.
- `query TARGET --cached` honors `--format`: `json` prints the
  resolved scan's retained snapshot (latest scan covering the target —
  primary canonical, multi-target set, or an `--all` scan, whose
  snapshot covers every repository); `jsonl` replays its journal
  (byte-identical to `query --scan --format jsonl`; `--follow`
  supported and stops at the tip for finished scans); `human` and the
  default keep the short human summary. Machine lanes stay
  machine-clean on misses (stderr note, exit 3, empty stdout);
  unresolvable shapes and fresh state dirs keep today's human notes.
- Redirected `scan`/`resume` with no `--format` replay the scan
  journal as JSONL (every line parses; the scan's own exit code is
  kept); the TTY default keeps the legacy terminal report + footers.
  Explicit `--format` wins everywhere; `--report` still publishes the
  JSON snapshot file in all lanes. A bare `scan` on a TTY does NOT
  open the interactive TUI — that needs explicit `--format human`
  (Step 13 gate `scan_tui_gate`, unit-pinned).
- Unchanged pins: `--follow` only rides human|jsonl (exit 2 with
  `--format json`); `--after` requires `--follow`; query without
  `--cached` is exit 2 (now also for `--all`); unknown scan IDs stay
  exit 2 for `query --scan` and `resume`; short `owner/name` targets
  under `--cached` may still report `canonical: unresolved` (exit 3).
