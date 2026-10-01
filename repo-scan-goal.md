Build repo-scan from scratch and complete the implementation described below and in repo-scan-spec.md.

## Mission

Build a small, maintainable Rust CLI named `repo-scan` that accepts a GitHub repository URL, discovers its local clones, linked worktrees, bare stores and branch references throughout the computer, and produces a detailed report for a separate recovery agent.

This project exists because an earlier agent-driven consolidation task repeatedly ran expensive filesystem commands, consumed excessive CPU and memory, took approximately five days, and still failed to establish complete discovery. Searches timed out in temporary directories and other important locations. Rechecking previously known paths could not establish complete discovery. Replace that repeated improvisation with one purpose-built tool whose traversal, resource use, progress, errors and coverage are explicit and measurable.

The product must efficiently find where work exists. It must preserve completed work and unfinished tasks across interruption, reuse trustworthy cached information, discover changes since previous runs, and support deliberate invalidation and full rescanning. A timed-out directory remains an unfinished obligation; it never becomes an empty, completed or silently excluded directory.

The product does not decide which code should merge. It does not merge branches, create recovery PRs, commit or push examined repositories, delete clones or worktrees, manipulate Cargo locks, or clean other applications' caches. A separate agent will consume its report and perform any subsequently authorized recovery work.

Runtime writes are confined to application-owned state and the explicitly requested report artifact. A report may be placed inside a scanned tree; identify that artifact, preserve the actual working-status observation time, and follow the specification's destination protections. Do not exclude its containing directory or treat the output request as permission to overwrite Git metadata or source code.

## Read the specification and fix the scope

Read the complete companion [repo-scan-spec.md](repo-scan-spec.md) before implementing. Treat its requirements, command semantics, resource table, report schema, durability rules and acceptance tests as the implementation contract. Create a traceable checklist mapping every mandatory requirement to its implementation and verification evidence. Read applicable repository instructions and current primary documentation for the selected dependencies.

Use these components:

- Rust for the CLI, library, platform integration and tests.
- `dua-core` and `ignore` behind one filesystem-enumeration contract. Integrate both as specified and benchmark equivalent scope; select the operational backend using evidence. They must not create competing schedulers or duplicate traversal.
- Native embedded `turso` through its Rust API for durable local state. Use the actual Turso engine, with no required cloud service, account, credentials or network connection. Do not substitute `libsql`, `rusqlite`, a SQLite executable, or another database.
- `gix` for Git identity, configuration, references and worktree relationships, with a carefully controlled installed-Git compatibility path where the specification allows one.
- Native macOS filesystem identity, mount and event facilities where the specification requires them.

Keep one catalog-owning process and one writer actor. Concurrent CLI commands coordinate through local IPC; they do not independently open the same live catalog and assume that the embedded engine supports the required cross-process behavior. Validate the actual Turso transaction, recovery and checkpoint behavior with the required failure tests. Engine uncertainty must become investigation and tests, never an undisclosed database substitution.

Build a CLI and reusable Rust library. Keep the initial project small. Do not add a GUI, web service, recovery agent, merge engine, remote synchronization service or unrelated framework.

## Resolve the implementation destination autonomously

Use an explicitly supplied project directory and remote if present. Otherwise reuse an existing working repository only when its context clearly identifies it as the intended `repo-scan` implementation. If no such target exists, create a new `repo-scan` directory inside the current writable workspace. Do not overwrite or initialize over an unrelated repository.

Record the resolved project directory, current branch and authorized remote before implementation. Initialize local Git when needed. Use one integration branch unless a concrete isolation or workflow requirement justifies another. When synchronizing with an existing main branch, prefer merge over rebase.

Push verified incremental progress regularly when an authorized remote exists. A missing remote does not authorize creating a public repository, inventing a destination or using an unrelated origin. Finish all possible local implementation and verification, and disclose the missing publication destination. Do not expand this goal into deployment, package publication or merging the implementation PR unless separately authorized.

The frequent-commit policy below applies to development of `repo-scan` itself. It never authorizes the scanner to commit, push or otherwise modify repositories that it discovers.

## Required CLI

Implement these exact commands without requiring additional arguments:

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

Follow the companion specification for output, exit status and invalidation semantics. Invalidation durably schedules fresh examination; it does not itself certify that traversal completed. Additional options must preserve these commands and their meanings.

## Execution and implementation phases

### Phase 1 Establish contracts and independent workstreams

Create the project, requirement checklist, architecture notes and reproducible development commands. Define shared domain types, the walker contract, the durable task lifecycle and the first report schema before independent agents implement competing assumptions.

Delegate separate workstreams for filesystem traversal and resource controls, Turso persistence and recovery, Git identity and worktree inspection, macOS integration, CLI and reporting, fixtures and performance measurement, and independent correctness review. Combine roles when concurrency is limited, but retain independent verification of critical conclusions.

Assign clear file ownership. The coordinator owns shared Git-index operations and integration commits; agents must not race through simultaneous staging or commits in the same working tree. Parallelize disjoint edits and read-only analysis. Use additional worktrees only where concrete edit conflicts require isolation, and account for agent-created resources in the development ledger.

Assign one build/test owner. Start Cargo with a job limit of two and change it only with resource measurements. Do not run concurrent Cargo/rustc process trees across agents on the host or through a shared target directory. Coordinate tests and benchmarks through that owner while other agents perform disjoint analysis and review. Use synthetic fixtures first. Do not run broad host `rg`/`find` sweeps or untested whole-machine scans during development. Agent parallelism is not permission to create CPU, memory or I/O storms.

### Phase 2 Prove persistence and bounded scheduling

Implement the Turso owner, IPC, migrations, task leases, catalog epochs, invalidation revisions and transactional publication rules. Demonstrate crash recovery before building a large scanner on an unproven store.

Use one durable scheduler. Persist discovered child tasks and findings before marking a parent enumeration complete. Requeue unfinished leases after interruption. A directory changed during traversal must retain its newer invalidation. An incomplete new generation must not erase old findings merely because it has not rediscovered them yet.

Implement bounded worker queues, memory accounting, descriptors, retry state and separate status-work budgets according to the resource table. Isolate potentially blocked operations as required. Stop scheduling replacements indefinitely when an operation cannot be cancelled. The coordinator must remain responsive while exact unfinished obligations survive.

Have an independent agent challenge transaction boundaries, reset races, interrupted enumeration and the engine's verified durability behavior before proceeding.

### Phase 3 Implement complete discovery and identity

Build the machine root plan, mount accounting, pathname aliases and physical-directory deduplication. Include user directories, hidden directories, temporary storage, Cargo locations and accessible mounted scope. Do not stop descending merely because a repository was found. Record access failures and unsupported candidates explicitly.

Enumerate directory names and necessary types before doing expensive inspection. Do not search source-file contents for repository URLs, invoke Git for every ordinary directory, or repeatedly launch broad `rg` or `find` scans. Inspect likely Git candidates, then follow explicit Git relationships to external administrative directories and registered worktrees.

Normalize supported repository URL forms and inspect relevant effective remotes. Preserve evidence and uncertainty when provenance cannot be established. Distinguish independent clones, shared common directories, separate worktrees and same-named branches at different OIDs. Support detached checkouts and arbitrary-name bare stores as required by the fixtures. Do not classify unsupported formats as absent repositories.

### Phase 4 Implement freshness and report delivery

Add the specified macOS event history, replay, invalidation and reconciliation behavior. Demonstrate updates that occurred while the CLI was not running. Event loss and unavailable history must schedule the necessary reconciliation; an unchanged parent timestamp must not stand in for subtree evidence.

Keep the catalog reusable across target URLs. Implement immediate cached queries without filesystem traversal, Git probes or network requests. Preserve the original request configuration for `resume SCAN_ID`. Keep force-rescan, invalidation and cache clearing distinct.

Emit discovered locations before expensive status work finishes. Inspect working state only for relevant matches and declare what was inspected. Unknown status is not clean status. Local remote-tracking references are observations, not proof of today's remote main. Do not produce semantic merge or deletion recommendations.

Ship the versioned JSON Schema, atomic report writing and readable output. Distinguish coverage, identity resolution and working-state freshness. Reports must remain usable when work is interrupted or incomplete and must identify exact remaining obligations.

### Phase 5 Verify correctness and resource behavior

Run the companion specification's correctness corpus, interruption tests, database failure tests, read-only checks, cache-reset races and macOS integration tests. Use independent verifier agents to challenge both implementation and evidence.

Compare enumeration backends on the same roots, exclusions, error policy and expected results. Measure cold traversal separately from warm operating-system caches, cached catalog queries, incremental refresh and crash resume. Record hardware, dataset, wall time, CPU, peak memory, queue bounds, descriptor use and repeated work. A faster run that skipped required scope fails the comparison.

Profile concrete bottlenecks and fix them. Do not invent benchmark numbers, call an algorithm fastest without measurement, silently raise resource limits, or omit difficult directories to improve a score. Meet the companion resource and CI gates on their declared test environment. Clearly identify any physical-host measurement that cannot be performed in the current environment.

### Phase 6 Integrate and finish

Resolve every actionable finding from implementation, review, tests and profiling. Keep small verified commits and propagate them to the authorized remote. Re-run deterministic final checks after integration, including the six exact CLI examples against controlled fixtures.

Finish the README, architecture and recovery documentation, JSON contract, troubleshooting guidance and reproducible benchmark instructions. Reconcile the requirement checklist against actual evidence. Do not confuse fixture success with having scanned the user's entire Mac.

## Required execution policy

Use subagents aggressively for all work.

Always delegate work to subagents whenever delegation is possible. Treat subagents as the default execution mechanism, not an optional optimization.

Your execution strategy must:
- decompose the goal into independent or partially independent workstreams;
- spawn subagents for each workstream;
- parallelize all work that can safely run concurrently;
- use additional subagents for research, implementation, review, testing, verification, and cross-checking;
- avoid doing work serially in the parent agent when it can be delegated;
- keep spawning useful subagents as new independent tasks are discovered;
- use independent subagents to verify important conclusions and completed changes;
- coordinate and synthesize subagent results into the final implementation.

Do not merely recommend parallelization—actually execute the goal through subagents.

The parent agent should primarily orchestrate, resolve dependencies/conflicts, integrate results, run final deterministic checks, and ensure the complete goal is finished.

Default rule: **delegate first, parallelize aggressively, verify independently, then integrate.**

Always commit changes frequently while working.

Prefer small, incremental, logically scoped commits instead of keeping a large dirty working tree for a long time and committing everything at the end. As soon as a meaningful unit of work is complete and verified, commit it.

Push progress to the remote repository regularly so work is continuously propagated, recoverable, reviewable, and easy to bisect or revert.

At the same time, avoid unnecessary branches. Prefer doing as much work as possible on a single working branch and keep committing to that branch throughout the task.

Create additional branches only when there is a clear technical or workflow reason that makes working safely on the existing branch impractical or impossible.

In short: **commit often, push regularly, and minimize branch proliferation.**

Never ask the user questions or wait for clarification. Work fully autonomously.

If anything is ambiguous, uncertain, conflicting, incomplete, or requires a decision:
- Spawn subagents to investigate it independently.
- Analyze the available context, repository, documentation, code, history, external references, and relevant best practices.
- Research alternative approaches where necessary.
- Compare multiple options and their tradeoffs.
- Verify important assumptions and findings independently.
- Re-verify critical decisions before acting.
- Make the best reasonable decision yourself and continue execution.

Do not stop because information is imperfect. Infer intent from the goal, existing architecture, conventions, documentation, and surrounding context. Prefer making a well-researched, reversible decision over asking the user.

When uncertainty is significant, use multiple independent subagents to challenge the proposed solution and resolve disagreements through evidence.

Your responsibility is to unblock yourself. Questions that would normally be sent to the user should instead become internal research, analysis, verification, or subagent tasks.

Continue working until the goal is fully completed, verified, and no meaningful actionable work remains.

## Definition of done

All mandatory specification requirements have implementation and verification evidence. The six commands work unchanged. Reports validate against the shipped schema. Correctness fixtures cover the required Git layouts and filesystem locations. Interrupted work resumes without forgetting tasks or restarting all completed scope. Cache operations are coordinated and confined to tool-owned state. The scanner does not mutate examined Git metadata or source code; only application-owned state and the identified, explicitly requested report artifact may be written. Status observations retain accurate timestamps when that artifact is placed within a checkout. Resource and performance gates have measured evidence. Independent correctness and performance findings are resolved. Documentation matches actual behavior, and final deterministic checks pass.

External access limitations remain explicit unresolved obligations. They do not become exclusions or success claims. If a required-platform or other genuine external gate cannot be satisfied, complete the independent work that is still authorized and possible, preserve reproducible state, and report the specific unmet gate honestly. Never declare full completion while a mandatory gate lacks evidence.

## Final delivery format

Provide a self-contained final implementation report with:

1. Outcome: `COMPLETE` only when every mandatory gate is satisfied; otherwise state the precise incomplete condition.
2. Project directory, branch, final commit and authorized remote/push status.
3. Effective coordinator/subagent model and effort verification.
4. Implemented commands and concise examples.
5. Requirement checklist and locations of the schema, docs, tests and benchmark evidence.
6. Correctness, durability, interruption, concurrency and read-only verification results.
7. Measured resource and performance results, with environment and remaining unmeasured claims.
8. Independent reviewers' findings and their resolutions.
9. Exact pending external obligations, if any, and reproducible resume instructions.

Do not end with an offer to continue work that is already authorized and actionable. Continue until this project's stated goal and verification gates are satisfied, subject to the explicit constraints above.
