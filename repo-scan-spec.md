# repo-scan specification

Version: 1.0 implementation specification  
Date: 30 September 2026  
Primary platform: macOS  
Implementation: Rust library and command-line application

## 1. Problem and intended outcome

The original workflow asked an agent to find local copies of a GitHub repository, inspect their unfinished work, consolidate worthwhile changes, and clean up redundant copies. Discovery became the bottleneck. Repeated, inefficient filesystem commands consumed substantial CPU and memory on the user's host; the user reports that a job expected to take hours ran for five days without finishing. Some scans timed out, and a later verification only revisited already known paths. That verified an inventory without establishing whether undiscovered copies still existed.

`repo-scan` replaces improvised agent-driven filesystem discovery with a deterministic, resource-conscious tool. Given a GitHub repository URL, it discovers matching local repository instances, working copies, linked worktrees, bare stores, branches, and their observed state. It produces a detailed report that a separate recovery agent can consume.

The product must prioritize low repeated work, bounded admission of expensive operations, durable progress, and honest coverage. A timeout is unfinished work, never proof that a directory is empty. A warm cached query must not trigger another whole-machine scan. A force rescan must genuinely re-examine scope. Neither a cache nor a previous successful scan proves that the filesystem has remained unchanged indefinitely.

This project does not decide which code to merge. It does not compare implementations for product value, create PRs, merge branches, fetch remote objects, push work, delete clones, or clean another application's caches. Those operations belong to a separate agent and goal. The scanner reports enough precise evidence for that later work without performing it.

## 2. Product requirements and boundaries

Build a new, small Rust project with one reusable library and one `repo-scan` binary. Begin from an empty project or an explicitly designated implementation checkout. An implementation remote is optional: build and commit locally when no authorized remote exists. Never infer an implementation repository owner from the URL being searched.

Required components are:

- `dua-core`, using its native macOS directory-reading facilities through an application-owned one-directory adapter.
- `ignore`, through a genuinely equivalent shallow, sequential alternative adapter used for fallback and comparison.
- The native embedded Rust `turso` database engine. Cloud Turso, `libsql`, `rusqlite`, or another database are not substitutes.
- `gix` for Git inspection, with a carefully controlled installed-Git compatibility path for unsupported cases.
- Native macOS FSEvents history handling for persistent incremental discovery.

The project must work without an LLM, cloud service, mandatory background daemon, GUI, or TUI. On-demand commands are sufficient; an owner process can remain alive while commands are active. Use a portable core and Linux fixtures to exercise platform-independent behavior, while treating native macOS discovery, topology, events, and durability as required functionality.

The scanner may write its own state and explicitly requested reports. It must leave examined Git state unchanged. Report output inside a scanned working tree is valid: record status before publishing that report and identify the generated artifact. This is not a promise of zero filesystem writes.

## 3. Required command interface

These six commands must work exactly as shown:

```sh
# Discover matching copies and produce a report.
repo-scan scan https://github.com/OWNER/REPO \
  --scope machine \
  --report repository-report.json

# Query the catalog immediately, with freshness information.
repo-scan query https://github.com/OWNER/REPO --cached

# Continue unfinished work.
repo-scan resume SCAN_ID

# Perform a fresh traversal generation.
repo-scan scan https://github.com/OWNER/REPO \
  --scope machine --force-rescan

# Rescan one area.
repo-scan cache invalidate --root /private/var/folders

# Clear only this tool's saved state.
repo-scan cache clear --all
```

Additional optional controls may expose state-directory location, resource budgets, traversal backend, report format, status depth, and explicit roots. They must not change the meaning of these commands or make extra options necessary for safe default operation.

Expose `--status metadata|summary|full`, defaulting to `summary`, with the inspection semantics in section 9. On macOS, the default state directory is `~/Library/Application Support/repo-scan`. Resolve it once to an absolute path. Keep a stable coordination lock and ownership marker at that location, with the database, sidecars, internal snapshots, and other replaceable derived state inside a dedicated `payload/` namespace. `--state-dir` may change the location, subject to section 15. Do not place the default durable frontier in temporary storage or an automatically purged cache directory.

### Command semantics

| Command | Required behavior |
|---|---|
| `scan URL --scope machine` | Resolve the target, reuse valid catalog information, resume compatible unfinished discovery, reconcile events and invalidated scope, refresh matching metadata, and publish a report. |
| `query URL --cached` | Read only the tool's existing state, directly as the owner or through local IPC. Do not examine repositories, enumerate mounts, read Git configuration outside state, refresh status, fetch, or start discovery. Resolve aliases only from cached identity/configuration observations; otherwise report the unresolved query. Show recorded freshness and gaps. |
| `resume SCAN_ID` | Restore the saved URL, scope, policies, status mode, report destination, and unfinished work. Never depend on the caller's current directory. |
| `scan ... --force-rescan` | Create a fresh traversal generation for the requested scope, bypass prior completion shortcuts, and preserve old findings as provisional until replacement coverage is established. |
| `cache invalidate --root PATH` | Durably invalidate the specified scope and schedule reconciliation. A running owner may process it immediately; otherwise the next scan or appropriate resume processes it. Invalidation success does not claim the rescan is already complete. |
| `cache clear --all` | Coordinate with the owner, fence workers, and remove only verified tool-owned persisted payload, including internal derived report snapshots. Preserve exported user reports and unrelated files. Retain the stable coordination namespace while needed. Clearing already absent state is successful. |

Resolve a supplied report path to an absolute destination when creating the scan request. Without `--report`, produce a readable terminal report and retain a versioned report snapshot in state. JSON to a file is written atomically and streamed with bounded memory. Progress and diagnostics use stderr; machine-readable output must not be polluted by progress text.

A scan ID identifies a user's request. Traversal generations belong to the machine catalog and can serve multiple target URLs. Concurrent requests must share compatible directory work instead of independently walking the same tree.

Completed `resume` requests are idempotent: return their recorded terminal result and original snapshot, without secretly starting a fresh scan. A superseded request returns a usable incomplete result identifying the successor; it must not silently switch targets or report destinations. A failed report publication can be retried against the saved snapshot without repeating discovery.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Requested operation succeeded. For discovery reports, coverage and required probes are complete under the declared matching policy and recorded observation boundaries. A complete search with zero matches also returns `0`. |
| `1` | Operational failure prevented the requested operation or report publication, including a database failure or unsafe reset refusal. |
| `2` | Invalid arguments or configuration. |
| `3` | A usable report has unresolved coverage, identity, or required-status gaps; or a cached query has no suitable catalog. Also used for an explicitly superseded resume. |
| `130` | Interrupted by the user after making the best bounded attempt to save progress. |

A cached query can return `0` for a previously complete recorded generation while explicitly saying that it is cached. It cannot imply live verification. Identity ambiguity that no further permitted probe can resolve produces a terminal incomplete report, not an endless retry loop.

## 4. Architecture and ownership

Use one catalog-owning process per state directory. Other CLI invocations connect through local IPC. If no owner exists, a command can acquire the instance lock and assume ownership. Maintain a stable coordination lock outside the replaceable database payload; never unlink an active lock pathname as an availability probe.

Only the owner opens the database. It owns a bounded writer actor and any tested read connections. Enumeration and Git helpers exchange bounded messages with the owner and never open the database themselves. The owner authenticates local clients using platform-appropriate local permissions and peer identity where available.

Run every potentially blocking operation against inspected filesystem scope through an admitted helper: directory enumeration, metadata, readlink, canonicalization, path-identity checks, mount validation, Git configuration includes, alternate-store access, and status. Do not perform an unbounded network-path `stat` or `realpath` in the coordinator before creating its task. External report-sink operations use the same isolation and bounded failure handling. Tool-owned state I/O follows the qualified storage contract in section 10. Watchdog progress is attributed to the specific operation; activity elsewhere cannot hide its stall.

Keep modules understandable: `cli`, `config`, `model`, `platform`, `walk`, `scheduler`, `store`, `git`, `identity`, `events`, `report`, and `telemetry` are sufficient starting boundaries. Avoid creating a crate for every module. Isolate native platform calls and database APIs behind narrow interfaces that can be exercised with deterministic fixtures.

There is one durable scheduler. A traversal backend must not recursively own an independent universe of jobs while the database schedules those same children again. The owner supplies one directory task, receives bounded child batches, persists discoveries, and decides which children run next.

## 5. Resource policy

The default profile must be conservative enough for a working desktop. Distinguish hard admission limits, enforceable application buffer bounds, and measured operating targets. CPU and RSS targets are not guaranteed kernel ceilings.

| Resource | Default | Contract |
|---|---:|---|
| Active enumeration operations | 2 | Hard admission maximum. |
| Active Git probes | 1 | Hard admission maximum. |
| Shared expensive-operation permits | 2 | Enumeration, Git probes, and other inspected-scope or external-sink operations together may hold at most two. |
| Helper processes | 4 | Hard maximum, including idle and still-stuck helpers. |
| CPU target | One logical core over a rolling 10-second window | Feedback target for the entire process family; reduce admission and add pacing under sustained excess. |
| Aggregate RSS target | 256 MiB | Measured target including owner and helpers; report accounting method. |
| Memory-pressure threshold | 512 MiB | Trigger stopped admission, bounded draining, released caches, and operation containment; not a claimed OS-enforced cap. |
| Scheduler prefetch | 1,024 tasks or 4 MiB | Stop at the first limit; remaining work stays in the database. |
| Enumeration IPC batch | 256 entries or 256 KiB | Flush at the first limit. Stream exceptionally large records through a bounded protocol. |
| Pending producer batches | 2 per producer | Backpressure the producer at the first byte or batch limit; include transport buffers in accounting. |
| Writer batch | 512 rows, 512 KiB, or 250 ms age | Commit at the first applicable limit; flush earlier when necessary for scheduler progress. |
| Application data descriptors | 64 | Track descriptors under application control and retain additional OS/runtime headroom. |
| Progress refresh | At most 2 Hz | Coalesce updates. |
| Resource telemetry | At most 1 Hz | Keep collection cheap. |

An enumeration slot and a Git slot are not additive permission to exceed the shared limit. Backend thread pools, library parallelism, and runtime settings must be audited so they cannot silently bypass these limits. Prefer one active operation per slow volume; allow measured exceptions for healthy local storage within the global budget.

CPU accounting includes the owner and all helpers, retaining exited-child CPU so respawning cannot reset the measurement. Scheduling priority or QoS may improve desktop responsiveness but does not establish a CPU quota. Track application-controlled descriptors against their cap and monitor dependency-owned descriptors separately; do not mislabel that cap as an absolute count of every runtime handle.

On sustained memory pressure, stop admitting new work and prefetching, release bounded caches, and drain or commit already accepted results within a bounded grace period. If an active library operation continues allocating, contain or terminate its helper and preserve its unfinished lease. If the owner cannot recover, make a controlled incomplete shutdown rather than continuing unbounded allocation. Record the peak, trigger, response, and any sampling or noncooperative-call overshoot. Never convert a contained probe to a clean status or complete traversal.

No whole-filesystem array, unbounded channel, unbounded future collection, or in-memory set of every path is permitted. Store long-lived path identity and deduplication state durably. Do not retain `DirEntry` values in the persistent frontier. Read source-file contents only where an explicit matching-repository status operation requires them.

Persist directories, Git candidates, required relationships, and reconciliation evidence; do not turn the catalog into a full text or ordinary-file search index. Retain individual ordinary-file observations only when needed for a documented discovery or status invariant. This product must not pay the storage and synchronization cost of indexing every source file merely to find repository boundaries.

Database durability must be amortized across tasks. Do not force a commit per directory entry or unconditionally per directory. The 250 ms setting is maximum batch age, not a fixed sleep before every operation. Benchmark transaction and sync rates so persistence does not recreate the original excessive-work problem.

## 6. Filesystem enumeration adapters

The primary macOS reader uses the public native `dua-core` 4.1.0 `read_dir(path, options)` one-directory iterator and emits immediate children only. Its native API is platform-conditional; Linux uses the portable adapter. Verify source and allocation behavior at the pinned version. Use names and the minimum file-type information needed for discovery; request additional metadata only for identity, topology, or a candidate probe. Preserve both directory-open and per-entry errors. Do not use a lifetime-long `stream_roots` sender as the durable frontier; its bookkeeping is not a replacement for a bounded application scheduler.

The `ignore` adapter must use a shallow, sequential builder with `standard_filters(false)` and `max_depth(Some(1))`, or the verified API-equivalent settings. Its output must include hidden and ignored entries and expose every traversal error. It is an alternate backend for the same task contract, not a second simultaneous traversal.

Both adapters must pass the same fixtures, emit equivalent immediate-child semantics, and run under the same admission and buffer limits. Filter any backend-emitted root record without counting it as a child. Do not follow symlinks through backend recursion; resolve and schedule them through the topology layer.

If either library necessarily materializes an unbounded child list for a huge flat directory, a narrow `std::fs::read_dir` escape hatch is permitted. Document the evidence, select it explicitly under the adapter contract, and test equivalent results, errors, interruption, and resource behavior. Keep meaningful `dua-core` and `ignore` integration; do not retain unused dependencies merely to claim compliance.

Do not use shell `find`, broad `rg`, source-content searches, or a Git process per ordinary directory as the production discovery engine.

## 7. Scope, topology, and paths

`machine` scope inventories mounted, addressable filesystem roots and attempts every root in scope fairly. Include accessible user homes, hidden folders, temporary directories, package caches, tool caches, nested repositories, Git administrative directories, and mounted external or network volumes. Do not silently exclude a directory because its name is `target`, `.cargo`, `.cache`, `node_modules`, or `.git`.

Seed likely locations for early useful results without limiting coverage to those seeds. `/tmp`, `/private/tmp`, the effective user home, `/private/var/folders`, and configured Cargo locations are priorities, not substitutes for complete scope. A large ordinary root must not starve temporary locations indefinitely.

On macOS, reconcile mount topology and APFS System/Data aliases. Deduplicate verified target objects using volume identity, filesystem object identity, and necessary mount or snapshot namespace information. Do not assume string prefix removal or `realpath` alone collapses firmlinks correctly. Preserve all pathname aliases for reports.

Resolve symlink targets explicitly, detect cycles, and schedule unseen in-scope targets. Crossing a volume boundary creates work for that volume rather than silently discarding it. Keep unavailable or permission-denied roots as coverage gaps. No automatic mounting, unlocking, archive extraction, or traversal into unexposed VM or container filesystems is required; report these scope boundaries.

Store paths without lossy UTF-8 conversion. Use parent/component records or another compact representation, and encode raw bytes losslessly in reports. Escape terminal control characters. Native file identifiers can be reused; revalidate identity after replacement, remounting, or uncertain cache recovery.

Treat filesystem observations as race-prone. An entry can disappear or become a different type between enumeration and inspection. Record the relevant result and invalidate or retry affected work; never reinterpret every race as a confirmed absence.

## 8. Git discovery and identity

Discover Git structures rather than directory-name patterns. Required layouts include normal `.git` directories, `.git` pointer files, external Git directories, main and linked worktrees, shared common directories, detached checkouts, submodules, nested repositories, and arbitrarily named bare stores.

Validate a candidate at its exact discovered path. Upward discovery is not proof that a child directory is another checkout. Continue filesystem discovery below repository boundaries, including administrative recovery locations. Follow explicit Git relationships to common storage and registered worktrees outside initially discovered paths. Distinguish registered, existing, inaccessible, missing, and broken worktrees.

Represent independent clones separately even when they use the same remote, identical commits, hard-linked packs, or alternates. Shared object storage is a dependency edge; a common Git directory is a repository/worktree relationship. Those relationships must not be confused.

Normalize supported GitHub HTTPS, SSH, and scp-like URLs with host-aware rules and optional `.git` suffix handling. Inspect effective fetch and push remotes with their roles preserved. Account for safely interpretable Git URL rewrites, configuration includes, and SSH aliases without executing configured helpers. Do not publish embedded credentials in reports or logs.

Use `confirmed`, `related`, `probable`, `nonmatch`, and `unresolvable_identity` dispositions. Record evidence, inspected configuration dependencies, and the matching-policy version. Directory names and shared commits are evidence at most, not proof of exact identity. Optional cached GitHub rename or transfer information may improve matching; network access is not required for scanning.

Some repositories have had identifying remotes removed. After successful inspection they may remain permanently ambiguous. This is distinct from an unread directory or failed probe. It makes strict target-match exhaustiveness unproven and yields code `3`, but does not create perpetual retries. Re-probe only after metadata invalidation, changed policy, or an explicit relevant rescan.

The tool's claim is completeness under its declared identity policy, not omniscient reconstruction of every repository's original provenance. Never print “no copies anywhere” when unresolved candidates remain.

## 9. Branches and working-state inspection

Use `gix` for routine metadata and reference inspection. Read actual references, including packed or supported alternative storage, rather than assuming branch files exist under `.git/refs/heads`. Preserve unsupported-format candidates and use the installed Git compatibility path when available.

A branch observation is identified by repository/common-storage instance, full reference name, object ID, and observation. The same branch name in independent clones may represent different work. Preserve symbolic references, detached HEADs, unborn branches, invalid references, and object-format information; never assume all object IDs have 40 characters.

Include every observed local branch and remote-tracking reference for a matching instance. Record their full reference names and kinds; do not fetch to make them current. Optional inexpensive custom/stash references can use the same observation model. Checkout kind describes topology, while HEAD state independently describes whether a checkout is on a branch, detached, or unborn. A linked worktree with detached HEAD remains a linked worktree.

Use lightweight identity inspection first. Inspect detailed working state only for matching or explicitly selected candidates. The default `summary` status mode counts staged and unstaged tracked paths and Git-style collapsed untracked entries; an untracked directory is one entry, not a count of all files below it. `full` requests individual untracked-file counts. Both respect ordinary Git ignore semantics for status, so ignored files are not counted. `metadata` requests repository, reference, and HEAD observations without a working-state probe. Report count units and whether submodule state was inspected. Status filtering must never narrow filesystem discovery. Expensive status runs are separately queued and resumable. Never report zero or clean when a field is unknown, not requested, pending, unsupported, or failed.

Capture relevant HEAD/index/configuration observations before and after a status probe. Retry within budget or flag instability when they change. A report may legitimately contain observations from different times, provided those times and scopes are explicit. Remote-tracking references are previously observed local state, not proof of the current remote `main`.

The compatibility backend uses explicit candidate paths, controlled repository-selection environment variables, no shell interpolation, no optional Git locks, and no lazy fetching where the installed Git supports these controls. Prevent executable filesystem-monitor helpers, configured filters, and other inspection-time commands from being invoked in either backend. If accurate inspection requires executing an untrusted configured program, preserve the limitation as an unsupported or partial observation. Probe capabilities once per installed Git identity, and preserve unsupported results.

Do not run hooks, fetch, maintenance, GC, prune, index refresh writes, or configuration writes. Stash/custom-ref metadata can be exposed when inexpensive; exhaustive reflog and unreachable-object archaeology is outside this project's default scope.

## 10. Native Turso storage contract

Use the native embedded `turso` engine, beginning qualification with `turso = { version = "=0.8.1", default-features = false }` and source release commit `8549c16595d2faf1bdd6ee24aee0be8bfabb3d4a`. Pin the validated dependency and lockfile. Recheck source and release correspondence before implementation; any later version must pass the same gates and have its change documented.

Do not substitute `libsql`, `rusqlite`, a remote database, or another engine to work around a failing test. Investigate and isolate engine limitations. A smaller supported schema or narrowly documented engine fix can be appropriate; a silent backend change is not.

Use local `Builder::new_local(...)`, an owner-held database handle, and explicit transaction begin, commit, and awaited rollback. In the qualified API, `transaction` takes a mutable connection. Its transaction destructor schedules a dangling rollback for the next connection access; dropping a transaction is therefore not proof that cleanup has already completed. Explicitly roll back after errors and cancellation, and finish or reset outstanding statements before reusing a connection. Validate actual async behavior, configuration support, and error semantics against the pinned engine. SQLite-compatible SQL does not establish that every SQLite PRAGMA or durability behavior is implemented identically.

Use conventional WAL and same-process read connections only after qualifying their interaction with the writer. Do not depend on experimental multiprocess WAL or MVCC modes. Store raw path and reference identities in BLOB columns because engine TEXT is UTF-8. Prefer a simple supported schema: do not assume recursive CTEs, `WITHOUT ROWID`, automatic checkpointing, or `journal_size_limit` support. Implement bounded tree traversal in scheduler queries and coordinate checkpoints explicitly.

Qualify `PRAGMA synchronous = FULL` and, on macOS, `PRAGMA fullfsync = ON` through observed engine behavior and targeted tests. Verify effective configuration and synchronization-error propagation; do not silently downgrade the acknowledgment contract. Do not issue familiar PRAGMAs and assume success means the intended mode took effect. Acknowledged durable progress must survive the defined crash tests; failures to commit or synchronize must remain visible.

The owner must not hold a database transaction open while enumerating filesystems, inspecting Git, waiting on helpers, or awaiting external input. It batches completed observations and scheduling transitions. Children may be committed in earlier batches; final parent completion must verify the expected revision and preserved child records.

Contain synchronous database work so it does not monopolize event processing. The qualified Unix backend's synchronization operations are synchronous despite the async Rust API, so use a separate storage execution context from the responsive coordinator. A stalled database filesystem cannot be made instantaneously responsive by naming an operation async; preserve clear error and shutdown behavior without claiming otherwise.

## 11. Persistence model

The logical entities below are required. Physical tables may be combined where justified, but their invariants and indexes must remain explicit.

| Entity | Main contents | Required lookup or uniqueness |
|---|---|---|
| Catalog metadata | Schema version, database identity, epoch, committed revision, engine qualification | One active catalog identity |
| Scan requests | URL, scope, policies, absolute report destination, status mode, state, outcome, successor | Unique scan ID; unfinished requests |
| Traversal generations | Scope policy, creation boundary, completion state, prior generation | Generation and root |
| Volumes and roots | Native identity, aliases, mount namespace, access state, event-history identity | Native identity plus namespace |
| Directories and aliases | Parent/components, object identity, last observation, invalidation revision | Physical identity; lossless alias path |
| Frontier tasks | Kind, generation, directory, expected revision, state, lease, retry time | Deduplication key; state/time/volume scheduling index |
| Directory observations | Enumeration completion, entry generation, error, subtree accounting | Directory and generation |
| Git instances | Git/common paths, format, bare state, identity disposition, evidence | Common-storage identity with incarnation |
| Checkouts | Root, Git directory, instance relationship, availability, HEAD observation | Checkout identity and instance |
| Remotes and refs | Effective role, normalized identity, full ref name, OID, observation | Instance/check-out scope and reference name |
| Status observations | Mode, results, unknown fields, input fingerprints, timestamps | Checkout and observation revision |
| Event journal | Volume, history UUID, received events, invalidations, cursors | Volume/history/cursor ordering |
| Errors and retries | Scope, stable category, detail, attempts, next eligibility | Open gaps by scope and category |
| Report snapshots | Schema, catalog revision, generation, publication state, checksum | Immutable snapshot/report ID |

Use parameterized queries and schema migrations tested against realistic data. Index the queries actually used for scheduling, identity matching, and report streaming. Do not load an entire table to sort or filter it in Rust.

Bound retained diagnostics and obsolete historical state through documented compaction. Never compact away unfinished work, unresolved evidence, or data required by a retained report snapshot. Coordinate checkpointing with readers and measure WAL growth and checkpoint cost.

## 12. Scheduler and crash invariants

Each task has an epoch, generation, operation kind, expected invalidation revision, and idempotency key. Its state is one of `pending`, `leased`, `complete`, `retry_wait`, `unavailable`, `unsupported`, `cancelled`, or `superseded`. A directory can be fully enumerated while its subtree still has unfinished descendants.

The owner durably claims bounded work, sends it to a helper, and accepts only results matching the current epoch and lease. Persist discovered children and candidate records before marking parent enumeration complete. Completion requires end-of-enumeration and successful revision validation; an error after partial enumeration preserves both the discoveries and the gap.

An invalidation arriving during enumeration increments the relevant revision. A stale completion cannot erase it. Duplicate batches after restart are safe through idempotent upserts and task keys. Expired leases return to pending state. Restart an interrupted directory from its beginning when necessary; do not persist unreliable directory-stream offsets or use the last emitted pathname as a resume cursor.

Do not acknowledge a batch until commit succeeds. A lost acknowledgment or connection error can leave commit outcome uncertain; reopen and reconcile the batch's idempotency key before deciding whether to apply it again. Never assume that an unobserved acknowledgment proves the transaction did not commit.

Do not delete catalog findings because an errored or incomplete scan failed to observe them. Confirm disappearance only within successfully reconciled scope. A replaced directory invalidates dependent path relationships rather than quietly inheriting the previous object's completion state.

During shutdown, stop admitting work, accept bounded in-flight results, commit what can be committed safely, and leave unfinished leases recoverable. A worker killed before acknowledgment may repeat work later. Document the distinction between committed observations and transient telemetry.

## 13. Incremental macOS discovery

Implement persistent per-volume FSEvents handling with event-history UUIDs and cursor state. A plain watcher active only while the process runs is insufficient. Begin monitoring before the initial traversal, record changes during it, and reconcile those changes before making the corresponding completeness claim.

Keep separate ingestion and reconciliation positions. Advance the ingestion position only with durable event/invalidation records. Advance reconciliation only when the work required by that recorded boundary is satisfied. Do not expect event IDs visible to this application to be consecutive.

Recursively inspect newly created or moved-in directories. Handle subtree-rescan flags, dropped events, root changes, history loss, UUID changes, and event-ID wrap according to native semantics. When continuity is unavailable, invalidate and reconcile the affected scope rather than assuming the old catalog is current.

Use bounded event batches and coalesced invalidations. A busy directory must not create an unbounded queue of identical work. Events generated by the tool's own exact bookkeeping files can be recognized and suppressed with identity and operation evidence; never exclude their entire parent directory.

Completion is relative to explicit per-volume observation boundaries, not a fictional globally atomic filesystem snapshot. Do not wait forever for the whole computer to become quiet. Record later arrivals as work beyond the published boundary, and preserve them for subsequent reconciliation. Schedule periodic full reconciliation as a documented policy, since event history is an optimization rather than proof of eternal completeness.

## 14. Timeouts, fairness, and error handling

Use a no-progress watchdog for individual operations, not a fixed deadline after which a large directory tree is declared searched. Progress includes meaningful enumeration or probe output and durable scheduler advancement, not an endlessly repeated heartbeat.

Ordinary entries count as enumeration progress even when none is a Git candidate. A large progressing directory must remain eligible to finish. Configure separate no-progress and cancellation-grace policies for operation classes, document their defaults, and test them with injected stalls; do not disguise a fixed whole-tree timeout as a watchdog.

On a stalled operation, persist its exact scope, request cancellation, allow a bounded termination grace period, and continue independent work. Keep still-stuck helpers counted against the helper limit. Do not keep spawning replacements into an unavailable volume. Apply per-volume backoff and a circuit breaker while preserving pending work.

| Condition | Disposition | Retry trigger |
|---|---|---|
| Permission denied | Coverage gap | Backoff, changed access evidence, or explicit relevant resume/rescan |
| Offline or unavailable volume | Coverage gap | Mount/access change or eligible retry |
| No-progress timeout | Pending/retryable operation | Backoff and available helper capacity |
| Disappeared entry | Reconcile containing scope | Parent invalidation or identity check |
| Unsupported Git format | Preserved candidate | Compatible backend, dependency change, or metadata change |
| Successfully probed but identity ambiguous | `unresolvable_identity` | Metadata invalidation or matching-policy change |
| Database commit failure | Operational failure | Owner recovery after storage is usable |
| Report publication failure | Saved snapshot, failed publication | Repeat publication without repeating traversal |

Finish a run when all currently actionable work for its boundary has been processed and remaining gaps are durably represented. This does not convert those gaps to success. Return code `3` with actionable information instead of spinning indefinitely.

## 15. Cache reset and output safety

State reset must be safe even if configuration points at an unfortunate or malicious `--state-dir`. Use a verified ownership marker, database identity, and dedicated payload namespace. Operate on exact known engine files and sidecars with native path-identity and symlink checks. Preserve unknown files or refuse the unsafe reset; never recursively delete an arbitrary configured directory.

Keep coordination outside the replaceable payload. Fence old epochs, quiesce the storage actor, and close every database statement, read connection, writer connection, and database handle before replacing or removing files. Treat the database and its engine sidecars as one payload; never leave a stale WAL beside a replacement database. Late worker messages must not resurrect cleared state. Do not modify Cargo caches, Cargo locks, Git directories, repository branches, OS event logs, or unrelated application state.

Report publication may create a file inside scanned scope. Observe requested working state before publication and list the report as a generated artifact. Refuse destinations that would overwrite Git administrative files, the active persistence payload, or an existing unrelated user file. A destination may replace a verified previous `repo-scan` report for that requested output; a filename extension alone is not proof. Use ownership/publication evidence and content validation, and reject symlink or path-substitution surprises. The output argument authorizes a report artifact, not replacement of arbitrary source code. Suppress only verified self-generated event records, not all events in the destination's parent.

First stream the consistent report into controlled local staging, release database snapshot readers, and then publish to the external destination through an admitted helper. Use a temporary sibling and atomic replacement, verified directory handles and destination identity, and a documented no-clobber policy for unexpected files. A stalled network destination must not retain a database read transaction indefinitely. Bound staging memory and disk use, propagate write/flush/rename errors, and retain the saved snapshot when publication fails. Keep completed report contents immutable by report ID; a new scan produces a new snapshot even when replacing the user's chosen output filename.

## 16. Report schema

Deliver `schemas/report-v1.schema.json` using JSON Schema Draft 2020-12 and test every emitted report against it. The following logical schema is normative. All listed fields are required; an unknown value uses an explicitly allowed `null` or state, not omission. Record objects reject undeclared fields in version 1. Adding fields requires a documented schema revision. Arrays are flat relationships keyed by IDs, avoiding repeatedly embedding complete repositories under each worktree.

Primitive types: `Id` is a nonempty opaque string; `Time` is RFC 3339 UTC; `Count` is a nonnegative integer; `Nullable(T)` permits `null`. Non-null relationship IDs must resolve within the report. Envelope, scan, and historical successor IDs identify external catalog history and are explicitly exempt from that relationship rule. Native identities and event cursors are opaque strings, not report foreign keys. Relationship counts must agree with emitted records; traversal counters summarize work, including nonmatching scope that need not be emitted.

| Record | Required fields and domains |
|---|---|
| Envelope | `schema_version` = `1.0.0`; `report_id: Id`; `created_at: Time`; `tool: Tool`; `scan: Scan`; `coverage: Coverage`; `resources: Resources`; arrays `volumes`, `paths`, `roots`, `repositories`, `checkouts`, `branches`, `remotes`, `storage_links`, `aliases`, `candidates`, `errors`, `generated_artifacts` |
| Tool | `name` = `repo-scan`; `version: string`; `source_commit: Nullable(string)` |
| Scan | `id: Id`; `generation: Count`; `epoch: Count`; `catalog_revision: Count`; `target_url: string`; `canonical_url: Nullable(string)`; `matching_policy: string`; `scope` = `machine` or `roots`; `state` = `running`, `complete`, `incomplete`, `interrupted`, `failed`, or `superseded`; `started_at: Time`; `finished_at: Nullable(Time)`; `superseded_by: Nullable(Id)`; `cached: boolean`; `status_mode` = `metadata`, `summary`, or `full` |
| Coverage | `filesystem` = `complete`, `incomplete`, or `unknown`; `identity` = `complete_under_policy` or `unproven`; `status` = `complete`, `incomplete`, or `not_requested`; `directories_complete: Count`; `tasks_pending: Count`; `gaps: Count`; `unresolvable_candidates: Count`; `scope_boundaries: string[]` |
| Resources | `profile: string`; `cpu_target_cores: number greater than 0`; `rss_target_bytes: Count`; `peak_rss_bytes: Nullable(Count)`; `cpu_seconds: Nullable(number at least 0)`; `enumerated_entries: Count`; `db_transactions: Count`; `db_sync_calls: Nullable(Count)` |
| Volume | `id: Id`; `native_identity: Nullable(string)`; `namespace: string`; `filesystem: Nullable(string)`; `kind` = `local`, `network`, `virtual`, or `unknown`; `state` = `available`, `inaccessible`, `unavailable`, or `unknown`; `observed_at: Nullable(Time)`; `error_ids: Id[]` |
| Path | `id: Id`; `display: string`; `encoding` = `utf8` or `base64`; `value: string`; `volume_id: Nullable(Id)`; `object_id: Nullable(string)`; `incarnation: Nullable(string)` |
| EncodedName | `display: string`; `encoding` = `utf8` or `base64`; `value: string` |
| Root | `id: Id`; `path_id: Id`; `volume_id: Nullable(Id)`; `state` = `complete`, `pending`, `inaccessible`, `unavailable`, or `error`; `observed_at: Nullable(Time)`; `event_history_uuid: Nullable(string)`; `ingested_cursor: Nullable(string)`; `reconciled_cursor: Nullable(string)`; `error_ids: Id[]` |
| Repository | `id: Id`; `git_path_id: Id`; `common_path_id: Id`; `bare: Nullable(boolean)`; `format: string`; `object_format: string`; `match` = `confirmed`, `related`, `probable`, `nonmatch`, or `unresolvable_identity`; `evidence: string[]`; `observed_at: Time`; `tool_managed: Nullable(string)`; `error_ids: Id[]` |
| Checkout | `id: Id`; `repository_id: Id`; `root_path_id: Nullable(Id)`; `git_path_id: Id`; `kind` = `main`, `linked`, `submodule`, or `unknown`; `availability` = `present`, `missing`, `inaccessible`, `broken`, or `unknown`; `head: Head`; `status: Status`; `observed_at: Time`; `error_ids: Id[]` |
| Head | `state` = `branch`, `detached`, `unborn`, `invalid`, or `unknown`; `ref_name: Nullable(EncodedName)`; `oid: Nullable(ObjectId)` |
| ObjectId | `algorithm: string`; `hex: string` containing a nonempty even number of lowercase hexadecimal characters; known algorithms enforce their own lengths |
| Branch | `id: Id`; `repository_id: Id`; `checkout_scope_id: Nullable(Id)`; `kind` = `local`, `remote_tracking`, or `other`; `name: EncodedName`; `oid: Nullable(ObjectId)`; `symbolic_target: Nullable(EncodedName)`; `upstream: Nullable(EncodedName)`; `state` = `valid`, `unborn`, `invalid`, or `unsupported`; `observed_at: Time`; `error_ids: Id[]` |
| Status | `state` = `complete`, `partial`, `pending`, `not_requested`, `unsupported`, `unstable`, or `error`; `mode` = `metadata`, `summary`, or `full`; `started_at: Nullable(Time)`; `finished_at: Nullable(Time)`; `staged: Nullable(Count)`; `unstaged: Nullable(Count)`; `untracked: Nullable(Count)`; `untracked_units` = `collapsed_entries`, `files`, or `not_requested`; `submodules` = `checked`, `not_requested`, or `unknown`; `unknown_fields: string[]`; `error_ids: Id[]` |
| Remote | `id: Id`; `repository_id: Id`; `checkout_scope_id: Nullable(Id)`; `name: EncodedName`; `role` = `fetch` or `push`; `url: string` with credentials redacted; `canonical_url: Nullable(string)`; `observed_at: Time` |
| StorageLink | `id: Id`; `from_repository_id: Id`; `to_path_id: Id`; `kind` = `common_directory`, `alternate_objects`, `shared_object_store`, or `observed_hardlink`; `evidence: string[]` |
| Alias | `path_id: Id`; `target_path_id: Id`; `kind` = `symlink`, `firmlink`, `mount_alias`, or `same_object`; `verified_at: Time` |
| Candidate | `id: Id`; `path_id: Id`; `repository_id: Nullable(Id)`; `disposition` = `probe_pending`, `probe_failed`, `unsupported`, or `unresolvable_identity`; `reason: string`; `retry_after: Nullable(Time)`; `error_ids: Id[]` |
| Error | `id: Id`; `path_id: Nullable(Id)`; `operation: string`; `category: string`; `message: string`; `retryable: boolean`; `attempts: Count`; `first_seen: Time`; `last_seen: Time`; `next_retry: Nullable(Time)` |
| GeneratedArtifact | `path_id: Id`; `kind` = `report` or `tool_state`; `created_after_status: boolean` |

For `Path` and `EncodedName`, `value` contains the exact Unicode string when its underlying bytes are valid UTF-8, or the standard Base64 encoding of the original bytes otherwise. `display` is escaped presentation text only. Use `EncodedName` uniformly for branch names, HEAD references, symbolic targets, upstream references, and remote names. Lossy replacement is forbidden. Validate cross-field states: a metadata-only status has null counts and `untracked_units: not_requested`; summary uses `collapsed_entries`; full uses `files`. Unknown counts remain null even when their requested units are known.

Include all matching repositories, checkouts, local branches, and remote-tracking references, with their required paths and relationships. The `branches` collection holds those reference observations and identifies their kind explicitly. Include unresolved candidates that prevent strict exhaustiveness. Nonmatching repositories need not be emitted in a target report, but their durable catalog observations must remain reusable for another URL.

Coverage, identity, and status are independent. A fully enumerated filesystem can still contain an unresolvable-identity candidate; a confirmed repository can still have pending status. Neither condition should be folded into a single misleading `clean` field.

### Illustrative valid report

The following deliberately small synthetic example contains one exact bare match and no checkout. Its IDs and OID are illustrative, not observations of the user's machine.

```json
{
  "schema_version": "1.0.0",
  "report_id": "report-example-1",
  "created_at": "2026-09-30T12:00:00Z",
  "tool": {"name": "repo-scan", "version": "0.1.0", "source_commit": null},
  "scan": {
    "id": "scan-example-1", "generation": 1, "epoch": 1,
    "catalog_revision": 12,
    "target_url": "https://github.com/OWNER/REPO",
    "canonical_url": "https://github.com/owner/repo",
    "matching_policy": "github-effective-remotes-v1",
    "scope": "roots", "state": "complete",
    "started_at": "2026-09-30T11:59:58Z",
    "finished_at": "2026-09-30T12:00:00Z",
    "superseded_by": null, "cached": false, "status_mode": "summary"
  },
  "coverage": {
    "filesystem": "complete", "identity": "complete_under_policy",
    "status": "complete", "directories_complete": 4,
    "tasks_pending": 0, "gaps": 0, "unresolvable_candidates": 0,
    "scope_boundaries": ["Only the explicit fixture root was requested."]
  },
  "resources": {
    "profile": "conservative", "cpu_target_cores": 1,
    "rss_target_bytes": 268435456, "peak_rss_bytes": null,
    "cpu_seconds": null, "enumerated_entries": 8,
    "db_transactions": 3, "db_sync_calls": null
  },
  "volumes": [{
    "id": "volume-fixture", "native_identity": "fixture-volume-1",
    "namespace": "fixture-mount-1", "filesystem": "fixture",
    "kind": "local", "state": "available",
    "observed_at": "2026-09-30T12:00:00Z", "error_ids": []
  }],
  "paths": [{
    "id": "path-bare", "display": "/fixture/cache/store",
    "encoding": "utf8", "value": "/fixture/cache/store",
    "volume_id": "volume-fixture", "object_id": "100", "incarnation": "1"
  }],
  "roots": [{
    "id": "root-fixture", "path_id": "path-bare", "volume_id": "volume-fixture",
    "state": "complete", "observed_at": "2026-09-30T12:00:00Z",
    "event_history_uuid": null, "ingested_cursor": null,
    "reconciled_cursor": null, "error_ids": []
  }],
  "repositories": [{
    "id": "repo-fixture", "git_path_id": "path-bare", "common_path_id": "path-bare",
    "bare": true, "format": "git-files", "object_format": "sha1",
    "match": "confirmed", "evidence": ["Effective origin fetch URL matches the target."],
    "observed_at": "2026-09-30T11:59:59Z", "tool_managed": null, "error_ids": []
  }],
  "checkouts": [],
  "branches": [{
    "id": "branch-main", "repository_id": "repo-fixture", "checkout_scope_id": null, "kind": "local",
    "name": {"display": "refs/heads/main", "encoding": "utf8", "value": "refs/heads/main"},
    "oid": {"algorithm": "sha1", "hex": "1111111111111111111111111111111111111111"},
    "symbolic_target": null, "upstream": null, "state": "valid",
    "observed_at": "2026-09-30T11:59:59Z", "error_ids": []
  }],
  "remotes": [{
    "id": "remote-origin", "repository_id": "repo-fixture", "checkout_scope_id": null,
    "name": {"display": "origin", "encoding": "utf8", "value": "origin"},
    "role": "fetch", "url": "https://github.com/owner/repo.git",
    "canonical_url": "https://github.com/owner/repo", "observed_at": "2026-09-30T11:59:59Z"
  }],
  "storage_links": [], "aliases": [], "candidates": [], "errors": [],
  "generated_artifacts": []
}
```

Stream a report from one consistent catalog revision. Test the pinned engine's actual read/write behavior before choosing concurrent snapshot readers; otherwise use an explicit publication barrier with bounded upstream backpressure. A long report must not create unbounded WAL growth or force all records into memory.

## 17. Acceptance tests and traceability

Implement deterministic Rust fixtures and fault injection. Each requirement below has a stable acceptance ID recorded in the implementation checklist and final evidence. Tests must assert meaningful outcomes, not merely restate implementation details.

| ID | Required verification |
|---|---|
| CLI-01 | All six exact commands parse and obey the command table and exit codes. |
| CLI-02 | Cached query performs no live repository, mount, Git-config, or network reads. No catalog yields `3`. |
| CLI-03 | Resume preserves absolute output destination and original options across different caller directories. Completed/superseded behavior is idempotent. |
| FS-01 | Hidden/temp/cache paths, nested repositories, and a clone inside another `.git/recovery` are found without exclusions. |
| FS-02 | Arbitrarily named bare stores, `.git` files, external common directories, detached copies, and outside-root registered worktrees are represented. |
| FS-03 | Native symlink cycles, APFS aliases, mount changes, and path replacement do not duplicate work or erase distinct instances. |
| FS-04 | Non-UTF-8 names and control characters survive round-trip JSON and safe terminal rendering. |
| FS-05 | Huge flat and very deep fixtures respect bounded buffers with equivalent dua-core, ignore, and justified escape-hatch results. |
| GIT-01 | Same branch names with different OIDs, unborn and detached HEADs, packed refs, and unsupported formats remain distinguishable. |
| GIT-02 | Hard-linked packs and alternates do not collapse independent clones. |
| GIT-03 | All relevant remotes, URL variants, rewrites, forks, and removed remotes follow documented identity policy. |
| GIT-04 | Ambiguous identity ends as terminal incomplete without futile retries; metadata invalidation makes it eligible again. |
| STATUS-01 | Dirty/untracked/unstable/unknown states are accurate; unrelated repositories do not receive expensive status probes. |
| READ-01 | Repository trees, index/config/ref state, package-manager locks, and network operations remain unchanged by inspection. Explicit report effects are separately identified. |
| DB-01 | The exact native Turso version executes the production schema and all transaction paths successfully. |
| DB-02 | Commit, rollback, cancellation, read/write interleaving, migrations, checkpointing, and synchronization errors have tested semantics. |
| DB-03 | Crash at each claim/batch/completion/cursor boundary, before the first checkpoint, during checkpoint backfill, and after the first acknowledged commit following WAL reset preserves acknowledged work and reconciles uncertain commits. Include disk-full, write/sync-error, and corrupt/truncated-payload cases; assert acknowledged operation IDs and frontier semantics in addition to database integrity checks. |
| DB-04 | FULL and macOS full-sync behavior is source-qualified and exercised; no unsupported PRAGMA is accepted as proof. |
| RESUME-01 | Mid-scan process death resumes the saved frontier without rescanning already reconciled scope unnecessarily. |
| RESUME-02 | New invalidation during enumeration survives stale completion; failed scans never remove old findings. |
| EVENT-01 | Clone insertion while stopped, moved-in directories, history loss, dropped events, and root changes trigger correct reconciliation. |
| EVENT-02 | Ingestion/reconciliation cursor crash points cannot lose work; continuous unrelated events do not prevent finite-boundary reports. |
| ERROR-01 | Permission denied then restored, offline roots, and stalled enumeration, metadata, canonicalization, configuration, alternate-store, and report-sink operations preserve obligations and allow independent work to progress. Unrelated activity cannot reset an operation's watchdog. |
| ERROR-02 | Still-stuck helpers count against the fixed process cap and do not create unlimited replacements. |
| CACHE-01 | Invalidate, force rescan, and clear have distinct semantics. Concurrent clear fences old workers. |
| CACHE-02 | Unsafe state paths, symlink substitution, and unknown files cannot cause arbitrary recursive deletion. |
| REPORT-01 | Every report validates against the shipped schema, resolves internal references, and agrees with counts and exit status. |
| REPORT-02 | Large output is staged and published atomically; stalled publication does not pin a database reader; failed publication retries the saved snapshot; inside-tree reports are represented honestly; unrelated existing files and substituted destinations are never overwritten. |
| PERF-01 | Default hard admission and buffer bounds hold under sustained work, slow consumers, and event bursts. |
| PERF-02 | On the declared native macOS corpus and sustained fixture in section 18, mean aggregate CPU is at most 1.1 logical cores after warmup and aggregate RSS is at most 256 MiB. Measure transaction/sync rates and first-result/full-scan performance as well. Recording excessive resource use is a failed gate, not successful verification. |
| PERF-03 | Injected memory pressure triggers admission stop and containment at the configured 512 MiB response threshold; unfinished work remains resumable and no status becomes falsely clean. Record overshoot and prove that repeated helper termination cannot reset CPU accounting or bypass process limits. |

Use realistic abrupt-process-termination tests and injected I/O failures. Distinguish those results from a hardware power-loss guarantee; document the storage and OS assumptions behind acknowledged durability. Native macOS evidence is mandatory before claiming macOS support, even if Linux fixtures pass.

## 18. Performance evaluation

Benchmark identical scope and expected results across the directory adapters. A backend that skips `.cargo`, hidden paths, or nested repositories has failed the comparison regardless of its elapsed time.

Measure first discovery with cold and warm OS caches separately; cached URL query separately from live status; one-subtree updates; resumed interruption; huge flat directories; deep paths; and stalled-volume behavior. Record wall time, CPU seconds, rolling CPU, aggregate RSS, open descriptors, directories and entries visited, metadata calls where measurable, database transactions and syncs, database/WAL growth, bytes written, time to first match, and repeated work after restart.

Use recorded hardware, OS, filesystem, dependency, dataset, and build versions. Provide reproducible Rust benchmark commands and raw machine-readable results. No invented absolute latency or “ten times faster” claim is acceptable. Optimize measured bottlenecks while preserving the correctness corpus.

For `PERF-02`, predeclare a representative corpus including large flat and deep trees and several matching Git layouts, the aggregate RSS method, sampling cadence, and warmup interval. Exercise sustained work for at least 30 measured seconds after warmup, using a larger or repeated controlled fixture when necessary. The default one-core governor passes at a mean of at most 1.1 logical cores, with the 0.1 margin reserved for sampling and control overhead. The declared fixed corpus must stay at or below 256 MiB aggregate RSS. Publish raw samples and short overshoots rather than hiding them in an average. For `PERF-03`, inject pressure and noncooperative operations to verify containment separately. These are reproducible engineering acceptance targets, not universal OS-enforced limits or invented measurements of the user's machine.

The warm query must read indexed state rather than walk the computer. Incremental work should be proportional to invalidated scope where event continuity permits. Resume should repeat only unfinished or invalidated scope. These are architectural acceptance requirements even before a particular timing target is met.

## 19. Rust quality, CI, and delivery

Use small cohesive modules, minimal dependency features, typed state transitions, parameterized SQL, structured errors, and explicit cancellation. Keep unsafe code confined to documented native interfaces and test its invariants. Avoid panics in production paths, unchecked path assumptions, giant error-swallowing filters, and unnecessary abstractions.

Deliver the library and CLI, locked dependencies, schema and fixtures, user documentation, architecture decisions, reproducible performance evidence, and the acceptance checklist. Document installation through standard Rust tooling and produce a local macOS release binary on the qualified platform. Provide reproducible release-build instructions and CI artifacts where an authorized repository supports them. Package publication, deployment, and remote release creation require separate authorization and are not completion gates for this goal. A missing implementation remote does not excuse unfinished local work or authorize invented publication claims.

Keep the runtime Rust-native with no Python, Node, or shell-search runtime dependency. Use Rust tooling for fixtures and performance harnesses. Installed Git is an optional compatibility backend, not a per-directory scanner.

Run formatting, strict linting, meaningful tests, schema validation, and dependency checks appropriate to the project. Organize CI to avoid redundant builds and unchanged-scope jobs. Target an end-to-end required CI critical path below two minutes on the documented runner/cache baseline, consistent with the user's requirement. Report cold-build and queue times separately. If the target is missed, optimize the build and job structure; do not remove correctness gates or relabel unrun tests as passing.

Completion requires all applicable acceptance IDs to pass, a clean implementation worktree, documented native macOS evidence, reproducible reports, and an honest list of any external verification gaps. A useful partial implementation is not the completed product described here.

## 20. Primary references and source qualification

The architectural choices above derive from the earlier source inspection and must be verified against pinned dependencies during implementation. These references are starting evidence, not permission to assume current APIs or behavior.

- [dua-core 4.1.0 source, including the native one-directory reader](https://docs.rs/dua-core/4.1.0/src/dua_core/lib.rs.html) and [documentation](https://docs.rs/dua-core/4.1.0/dua_core/).
- [ignore WalkBuilder](https://docs.rs/ignore/latest/ignore/struct.WalkBuilder.html).
- [gix documentation](https://docs.rs/gix/latest/gix/) and [Gitoxide feature status](https://github.com/GitoxideLabs/gitoxide/blob/main/crate-status.md).
- [Native Turso source at the qualification commit](https://github.com/tursodatabase/turso/tree/8549c16595d2faf1bdd6ee24aee0be8bfabb3d4a), [turso crate](https://docs.rs/turso/0.8.1/turso/), [Rust API reference](https://docs.turso.tech/sdk/rust/reference), and [release dependency features](https://github.com/tursodatabase/turso/blob/8549c16595d2faf1bdd6ee24aee0be8bfabb3d4a/bindings/rust/Cargo.toml).
- [Turso transaction behavior](https://github.com/tursodatabase/turso/blob/8549c16595d2faf1bdd6ee24aee0be8bfabb3d4a/bindings/rust/src/transaction.rs), [Unix synchronization](https://github.com/tursodatabase/turso/blob/8549c16595d2faf1bdd6ee24aee0be8bfabb3d4a/core/io/unix.rs), and [PRAGMA implementation](https://github.com/tursodatabase/turso/blob/8549c16595d2faf1bdd6ee24aee0be8bfabb3d4a/core/translate/pragma.rs).
- [Turso first-checkpoint crash regression](https://github.com/tursodatabase/turso/blob/8549c16595d2faf1bdd6ee24aee0be8bfabb3d4a/tests/integration/wal/test_power_loss_before_first_checkpoint.rs) and [checkpoint crash atomicity](https://github.com/tursodatabase/turso/blob/8549c16595d2faf1bdd6ee24aee0be8bfabb3d4a/tests/integration/checkpoint_crash_atomicity.rs).
- [Git repository layout](https://git-scm.com/docs/gitrepository-layout), [Git worktree](https://git-scm.com/docs/git-worktree), and [Git command environment and options](https://git-scm.com/docs/git).
- [Cargo home storage](https://doc.rust-lang.org/cargo/guide/cargo-home.html).
- [Apple FSEvents usage and recovery](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html).
- [Apple FSEvents technology overview](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/TechnologyOverview/TechnologyOverview.html).
- [Apple APFS System and Data volumes](https://developer.apple.com/videos/play/wwdc2019/710/) and [getattrlistbulk](https://github.com/apple/darwin-xnu/blob/main/bsd/man/man2/getattrlistbulk.2).
- [Rust DirEntry](https://doc.rust-lang.org/std/fs/struct.DirEntry.html).
- [FFF walker at the inspected commit](https://github.com/dmtrKovalenko/fff/blob/89c19270ea2dfc20829a7429f72022571558093e/crates/fff-core/src/walk/ripgrep.rs) and [scan lifecycle](https://github.com/dmtrKovalenko/fff/blob/89c19270ea2dfc20829a7429f72022571558093e/crates/fff-core/src/scan.rs).
- [Worktee scanner](https://github.com/ditsuke/worktee/blob/e370ad7df7baaa46f0fb18a978752cbe4c2d259f/src/adapters/scanner.rs) and [restart lifecycle](https://github.com/ditsuke/worktee/blob/e370ad7df7baaa46f0fb18a978752cbe4c2d259f/src/application/daemon/lifecycle.rs).
- [Cardinal filesystem walker](https://github.com/cardisoft/cardinal/blob/master/doc/inner/fswalk.md) and [persistent search-cache design](https://github.com/cardisoft/cardinal/blob/master/doc/inner/search-cache.md).
