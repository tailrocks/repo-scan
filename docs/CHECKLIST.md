# Acceptance checklist (spec §17) with test evidence

Checked = a dedicated test maps to the ID (file:line cited). This lane never runs
`cargo`, so a check means *covered by the named test*, not *observed passing here*.
Residual gaps are noted inline. The REVIEW_WF4 findings called out here
previously (R1/R2/R3/R5) now have regressions in `tests/review_fix_main.rs` and
`tests/review_fix_store.rs`; see
[docs/REVIEW_WF4.md](/Users/donbeave/Projects/repo-scan/docs/REVIEW_WF4.md) for the
original finding texts.

- [x] CLI-01 — six commands + exit codes. Evidence: `tests/cli_impl.rs:47` (parse),
  `tests/cli_impl.rs:164` (exit mapping), `tests/cli_impl.rs:409` (binary lifecycle).
- [x] CLI-02 — cached query, no catalog yields 3. Evidence: `tests/cli_impl.rs:335`
  (exit 3, nothing created), `tests/cli_impl.rs:503` (cached-only lifecycle).
  Gap: no tracing test proving zero live FS/Git/network reads (holds by construction,
  `src/main.rs:4110-4132`).
- [x] CLI-03 — resume preserves absolute destination + options; idempotent replay.
  Evidence: `tests/cli_impl.rs:409` (relative `--report` from cwd-a, resume from
  cwd-b, `tests/cli_impl.rs:495-500` replay), `tests/accept_cli.rs:583`
  (superseded resume exits 3 naming the successor, `src/main.rs:4282-4295`).
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
  `tests/common/fixture.rs:216`, `tests/fixtures_impl.rs:165`,
  `tests/accept_git.rs:278` (alternates + hard-linked clones stay independent).
  Hard-link sharing is inspected via sampled `observed_hardlink` links
  (`src/main.rs:3885-3892,3917`, REVIEW R16 closed).
- [x] GIT-03 — remotes, URL variants, rewrites, redaction. Evidence:
  `tests/git_impl.rs:335,387,444,632,653`.
- [x] GIT-04 — ambiguous identity terminal; invalidation re-eligibles. Evidence:
  `tests/git_impl.rs:444` (identity table), `tests/store_impl.rs:518`,
  `tests/walk_impl.rs:427` (stale requeue), `tests/cli_impl.rs:512` (invalidate).
  Gap: no test asserting probe-failure completes without retry (`src/main.rs:1606`).
- [x] STATUS-01 — status counts per Git semantics. Evidence: `tests/git_impl.rs:280`,
  `tests/fixtures_impl.rs:264`, `tests/common/fixture.rs:328`. Gap: unstable/unknown
  mapping and matching-only gating (`src/main.rs:1877,2163`) untested end-to-end.
- [x] READ-01 — inspection leaves repos/locks untouched. Evidence:
  `tests/accept_git.rs:655` (HEAD/index/config/ref + lock bytes/mtimes unchanged,
  `.git` inventory identical, no FETCH_HEAD), `tests/accept_report.rs:757`
  (inside-tree report identified as a generated artifact). Gap: network-unchanged
  rests on the no-fetch assertion plus gix read-only construction (no packet capture).
- [x] DB-01 — pinned Turso runs schema + paths. Evidence: `Cargo.toml:22` (`=0.8.1`),
  `tests/store_impl.rs:26` (round-trip across reopen).
- [x] DB-02 — tx/commit/rollback/migrate/checkpoint paths. Evidence:
  `tests/store_impl.rs:26,359,518,597`, `tests/accept_db.rs:96,139,199,257`
  (commit/rollback, cancelled-lease requeue, reader/checkpoint/migration/durability,
  visible failure), `src/store/catalog.rs:500-544` (with_tx discipline).
  Gap: no sync-error, cancellation-interleave, or checkpoint-contention
  injection tests.
- [ ] DB-03 — unchecked: crash boundaries (`tests/accept_db.rs:277`), pre-first-
  checkpoint WAL durability (`:393`), post-WAL-reset commit (`:437`), uncertain
  reconcile (`:479`), and corrupt/truncated payloads (`:565`) are now tested; still
  missing per spec: crash during checkpoint backfill, and disk-full / write/sync-
  error injection (no hook exists, `tests/accept_db.rs:9-16`).
- [x] DB-04 — FULL + fullsync qualified. Evidence: `tests/store_impl.rs:35-43`
  (query-back assertions incl. macOS-gated fullfsync).
- [x] RESUME-01 — SIGKILL mid-scan resumes without redo. Evidence:
  `tests/accept_resume.rs:112` (acknowledged work survives, attempt counts frozen,
  redo bounded to one claim batch, dir-complete counts agree with a fresh
  traversal), plus `tests/accept_misc.rs:349` (kill/resume converges on complete).
- [x] RESUME-02 — stale completion requeues; findings kept. Evidence:
  `tests/store_impl.rs:518`, `tests/walk_impl.rs:427`, `tests/cli_impl.rs:451`
  (generation/findings reuse), `tests/accept_resume.rs:309` (stale completion keeps
  newer rev), `tests/accept_resume.rs:412` (incomplete scan keeps old findings).
- [x] EVENT-01/02 — insertion/history-loss/crash-point/flood reconciliation. Evidence:
  `tests/accept_misc.rs:101` (while-stopped insertion + moved-in repo reconcile),
  `:181` (history loss), `:259` (moved-in subtrees), `:291` (kill between ingest
  and reconcile), `:349` (CLI kill/resume), `:406,461` (flood finite boundary),
  `tests/events_impl.rs:148,249,270,379,693` (protocol incl. dropped/root-change),
  `tests/review_fix_main.rs:242` (main.rs ingest/reconcile hooks + report note).
  Wired: scan reconciles cursors (`src/main.rs:540`), invalidate ingests
  (`src/main.rs:4523-4536`). Gap: non-macOS degrades to null cursors + honest note
  (`src/main.rs:1093-1095`); live-stream tests are macOS-gated
  (`tests/accept_misc.rs:503`, `tests/events_impl.rs:805,827`).
- [ ] ERROR-01 — unchecked: permission-denied-then-restored (`tests/accept_db.rs:642`),
  offline-root gap (`:738`), and watchdog grace (`tests/review_fix_main.rs:400`,
  tripped-count log `src/main.rs:522-527`) are now tested; still missing per spec:
  stalled-op injection for enumeration/metadata/canonicalization/configuration/
  alternate-store/report-sink (no hook exists, `tests/accept_db.rs:9-16`) and the
  unrelated-activity-cannot-reset-watchdog clause.
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
- [ ] PERF-01 — unchecked: spec-table values (`tests/accept_misc.rs:579`), burst +
  10k-churn cap-hold (`:603`), and live counter agreement (`:708`) are now tested;
  still missing: sustained (time-based) work, slow-consumer, and event-burst
  admission-cap tests.
- [ ] PERF-02 — unchecked: corpus declared (`fixtures/corpus.json`) and tx/sync
  counters exist for rates (`tests/review_fix_store.rs:244`), but no ≥30 s sustained
  measurement harness and no RSS/CPU gate test (`docs/BENCHMARKS.md:50-51`); benches
  record samples only (`benches/scan_cycle.rs:53-62`).
- [ ] PERF-03 — unchecked: pressure stops admission and work resumes
  (`tests/accept_misc.rs:759`), no-false-clean + CPU-accounting-survives-respawn
  (`:800`); still missing: 512 MiB-threshold wiring (nothing in the binary samples
  RSS or calls `set_pressure`), and overshoot recording.
