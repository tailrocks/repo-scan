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
- NEW scan-event stream schema `1.0.0` (JSONL).
- Catalog migration v2: `github_groups`, `scan_events` journal,
  `scan_requests` multi-target columns, full scope key (D5). v1 data migrates.
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
