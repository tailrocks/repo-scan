# Acceptance checklist (spec §17) with test evidence

Checked = a dedicated test maps to the ID (file:line cited). This lane never runs
`cargo`, so a check means *covered by the named test*, not *observed passing here*.
Residual gaps are noted inline; see [docs/REVIEW_WF4.md](/Users/donbeave/Projects/repo-scan/docs/REVIEW_WF4.md)
for product gaps tests cannot see (R1 multi-target disposition, R2 cross-generation
claim, R3 untested binary publish path, R5 unwired events).

- [x] CLI-01 — six commands + exit codes. Evidence: `tests/cli_impl.rs:47` (parse),
  `tests/cli_impl.rs:164` (exit mapping), `tests/cli_impl.rs:409` (binary lifecycle).
- [x] CLI-02 — cached query, no catalog yields 3. Evidence: `tests/cli_impl.rs:335`
  (exit 3, nothing created), `tests/cli_impl.rs:503` (cached-only lifecycle).
  Gap: no tracing test proving zero live FS/Git/network reads (holds by construction,
  `src/main.rs:3735-3754,3841-3852`).
- [x] CLI-03 — resume preserves absolute destination + options; idempotent replay.
  Evidence: `tests/cli_impl.rs:409` (relative `--report` from cwd-a, resume from
  cwd-b, `tests/cli_impl.rs:495-500` replay). Gap: superseded-resume exit-3 path
  (`src/main.rs:3904`) has no binary test.
- [x] FS-01 — hidden/tmp/cache, nested, `.git/recovery` layouts. Evidence:
  `tests/common/fixture.rs:233`, `tests/fixtures_impl.rs:179`, `tests/walk_impl.rs:94`
  (adapter agreement). Gap: no binary scan asserting every layout is found.
- [x] FS-02 — bare stores, `.git` files, external/common dirs, detached, outside-root
  worktrees. Evidence: `tests/git_impl.rs:116,154,202`, `tests/fixtures_impl.rs:140`,
  `tests/common/fixture.rs:120,179`. Gap: outside-root follow (`src/main.rs:1780`) has
  no end-to-end test.
- [x] FS-03 — cycles, dedupe, replacement. Evidence: `tests/walk_impl.rs:203`
  (symlinks never followed), `tests/walk_impl.rs:302` (dev/ino+namespace dedupe),
  `tests/fixtures_impl.rs:206`. Gap: no APFS firmlink/mount-change test (Linux fixtures).
- [x] FS-04 — non-UTF-8 / control-char round-trip. Evidence: `tests/walk_impl.rs:268`,
  `tests/fixtures_impl.rs:217`, `tests/report_impl.rs:395`.
- [x] FS-05 — huge flat / deep, bounded buffers, backend equivalence. Evidence:
  `tests/fixtures_impl.rs:248`, `tests/walk_impl.rs:324`, `benches/walk_compare.rs:137`
  (exits 1 on mismatch).
- [x] GIT-01 — same branch different OIDs, unborn/detached, packed refs, unsupported.
  Evidence: `tests/fixtures_impl.rs:154`, `tests/git_impl.rs:202,226,249,420`.
- [x] GIT-02 — alternates do not collapse clones. Evidence:
  `tests/common/fixture.rs:216`, `tests/fixtures_impl.rs:165`. Gap: hard-linked packs
  have no test and no inspection (`src/main.rs:3273`, REVIEW R16).
- [x] GIT-03 — remotes, URL variants, rewrites, redaction. Evidence:
  `tests/git_impl.rs:335,387,444,632,653`.
- [x] GIT-04 — ambiguous identity terminal; invalidation re-eligibles. Evidence:
  `tests/git_impl.rs:444` (identity table), `tests/store_impl.rs:518`,
  `tests/walk_impl.rs:427` (stale requeue), `tests/cli_impl.rs:512` (invalidate).
  Gap: no test asserting probe-failure completes without retry (`src/main.rs:1606`).
- [x] STATUS-01 — status counts per Git semantics. Evidence: `tests/git_impl.rs:280`,
  `tests/fixtures_impl.rs:264`, `tests/common/fixture.rs:328`. Gap: unstable/unknown
  mapping and matching-only gating (`src/main.rs:1877,2163`) untested end-to-end.
- [ ] READ-01 — unchecked: no test asserts inspected trees, indexes, configs, locks,
  or network state are unchanged (read-only holds by gix read-only construction only).
- [x] DB-01 — pinned Turso runs schema + paths. Evidence: `Cargo.toml:22` (`=0.8.1`),
  `tests/store_impl.rs:26` (round-trip across reopen).
- [x] DB-02 — tx/commit/rollback/migrate/checkpoint paths. Evidence:
  `tests/store_impl.rs:26,359,518,597`, `src/store/catalog.rs:375-410` (with_tx
  discipline). Gap: no sync-error, cancellation-interleave, or checkpoint-contention
  injection tests.
- [ ] DB-03 — unchecked: no abrupt-termination, disk-full, write/sync-error, or
  corrupt/truncated-payload tests; only reopen round-trip and uncertain-marker
  recovery (`tests/store_impl.rs:689-698`).
- [x] DB-04 — FULL + fullsync qualified. Evidence: `tests/store_impl.rs:35-43`
  (query-back assertions incl. macOS-gated fullfsync).
- [ ] RESUME-01 — unchecked: no mid-scan kill/resume test; only `recover_now` unit
  (`tests/store_impl.rs:698`) and completed-replay (`tests/cli_impl.rs:495`).
- [x] RESUME-02 — stale completion requeues; findings kept. Evidence:
  `tests/store_impl.rs:518`, `tests/walk_impl.rs:427`, `tests/cli_impl.rs:451`
  (generation/findings reuse). Gap: no failed-scan-keeps-findings test.
- [ ] EVENT-01/02 — unchecked: module covered (`tests/events_impl.rs:148,379,693`),
  but no command path invokes it — scan/resume emit null cursors
  (`src/main.rs:3116-3118`, REVIEW R5). Live FSEvents tests (`tests/events_impl.rs:805,827`)
  are macOS-only and unwired.
- [ ] ERROR-01 — unchecked: only backoff/breaker shape tested
  (`tests/walk_impl.rs:481`); no permission-restore, offline-root, or injected-stall
  tests; no per-op watchdog exists (slow-task log only, `src/main.rs:993-999`, REVIEW R9).
- [x] ERROR-02 — helper cap. Evidence: `tests/walk_impl.rs:498` (hard non-additive
  limits incl. helpers). By design the binary spawns 0 helpers (sequential owner,
  `src/main.rs:4-11`); no still-stuck replacement test exists.
- [x] CACHE-01 — invalidate vs force-rescan vs clear. Evidence: `tests/cli_impl.rs:373`
  (clear), `tests/cli_impl.rs:471` (force-rescan), `tests/cli_impl.rs:512` (invalidate).
  Gap: no concurrent-clear fencing test.
- [x] CACHE-02 — unsafe paths / foreign files. Evidence: `tests/cli_impl.rs:301`
  (snapshot traversal), `tests/cli_impl.rs:373` (foreign preserved, lock retained).
  Gap: no symlink-substitution attack test.
- [x] REPORT-01 — schema, refs, counts, exit agreement. Evidence:
  `tests/report_impl.rs:208,296,315,323,430`, `tests/cli_impl.rs:441-448`.
  Gap: tests cover the lib builder; the binary ships its own emit path (REVIEW R3).
- [x] REPORT-02 — atomic publish, no-clobber, retry. Evidence:
  `tests/report_impl.rs:493,553,570,623`; binary exercises fresh-publish + verified
  prior-report replace (`tests/cli_impl.rs:424-469`). Gap: binary refusal paths and
  stalled-publish reader release untested (REVIEW R3).
- [ ] PERF-01 — unchecked: limits unit-tested (`tests/walk_impl.rs:498,324`) but no
  sustained-work / slow-consumer / event-burst cap-hold test.
- [ ] PERF-02 — unchecked: no declared corpus, no ≥30 s sustained measurement, no
  RSS method; benches record samples only (`benches/scan_cycle.rs:53-62`).
- [ ] PERF-03 — unchecked: only `set_pressure` unit (`tests/walk_impl.rs:540`); no
  injection/containment test; nothing in the binary samples RSS or calls it.
