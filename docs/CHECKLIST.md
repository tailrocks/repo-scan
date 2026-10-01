# Acceptance checklist (spec §17) with test evidence

Checked = a dedicated test maps to the ID (file:line cited). This lane never runs
`cargo`, so a check means *covered by the named test*, not *observed passing here*.
Freeze-gate pass record: `/tmp/repo-scan-gate-freeze.log` (`TEST_EXIT:0`,
fmt/clippy/test all green; `perf_02_03_gates_hold` passed in 137 s).
Residual gaps are noted inline. The REVIEW_WF4 findings called out here
previously (R1/R2/R3/R5) now have regressions in `tests/review_fix_main.rs` and
`tests/review_fix_store.rs`; see
[docs/REVIEW_WF4.md](../docs/REVIEW_WF4.md) for the
original finding texts.

- [x] CLI-01 — six commands + exit codes. Evidence: `tests/cli_impl.rs:47` (parse),
  `tests/cli_impl.rs:164` (exit mapping), `tests/cli_impl.rs:420` (binary lifecycle).
- [x] CLI-02 — cached query, no catalog yields 3. Evidence: `tests/cli_impl.rs:335`
  (exit 3, nothing created), `tests/cli_impl.rs:515-523` (cached-only lifecycle +
  unresolvable exit 3), `tests/accept_cli.rs:368,387` (absent-state reads nothing,
  lockdown survival).
  Gap: no tracing test proving zero live FS/Git/network reads (holds by construction,
  `src/main.rs:7392-7404`; read-only open `tests/sec_git_db.rs:97`).
- [x] CLI-03 — resume preserves absolute destination + options; idempotent replay.
  Evidence: `tests/cli_impl.rs:420` (relative `--report` from cwd-a, resume from
  cwd-b, `tests/cli_impl.rs:506-513` replay), `tests/accept_cli.rs:583`
  (superseded resume exits 3 naming the successor, `src/main.rs:1140-1157`).
- [x] FS-01 — hidden/tmp/cache, nested, `.git/recovery` layouts. Evidence:
  `tests/common/fixture.rs:256`, `tests/fixtures_impl.rs:179`, `tests/walk_impl.rs:94`
  (adapter agreement), `tests/accept_fs.rs:220` (binary scan finds every layout).
- [x] FS-02 — bare stores, `.git` files, external/common dirs, detached, outside-root
  worktrees. Evidence: `tests/git_impl.rs:116,154,202`, `tests/fixtures_impl.rs:140`,
  `tests/common/fixture.rs:128,205`, `tests/accept_fs.rs:265,295,349` (bare,
  pointer/external/detached, outside-root follow end-to-end).
- [x] FS-03 — cycles, dedupe, replacement. Evidence: `tests/walk_impl.rs:203`
  (symlinks never followed), `tests/walk_impl.rs:302` (dev/ino+namespace dedupe),
  `tests/fixtures_impl.rs:206`, `tests/accept_fs.rs:381,401` (cycle + replacement
  end-to-end). Gap: no APFS firmlink/mount-change test (Linux fixtures).
- [x] FS-04 — non-UTF-8 / control-char round-trip. Evidence: `tests/walk_impl.rs:268`,
  `tests/fixtures_impl.rs:217`, `tests/report_impl.rs:395`, `tests/accept_fs.rs:480`.
- [x] FS-05 — huge flat / deep, bounded buffers, backend equivalence. Evidence:
  `tests/fixtures_impl.rs:248`, `tests/walk_impl.rs:324`, `benches/walk_compare.rs:144`
  (exits 1 on mismatch), `tests/accept_fs.rs:588,620`.
- [x] GIT-01 — same branch different OIDs, unborn/detached, packed refs, unsupported.
  Evidence: `tests/fixtures_impl.rs:154`, `tests/git_impl.rs:202,226,249`,
  `tests/fail_gix.rs:70` (filter-driver probe refused as unsupported),
  `tests/accept_git.rs:118,164,237` (branch OIDs, HEAD states + packed refs,
  unsupported marker preserved distinct).
- [x] GIT-02 — alternates do not collapse clones. Evidence:
  `tests/common/fixture.rs:240`, `tests/fixtures_impl.rs:165`,
  `tests/accept_git.rs:283` (alternates + hard-linked clones stay independent).
  Hard-link sharing is inspected via sampled `observed_hardlink` links
  (`src/main.rs:6873-6883`, helper `:7090-7093`, REVIEW R16 closed).
- [x] GIT-03 — remotes, URL variants, rewrites, redaction. Evidence:
  `tests/git_impl.rs:340,387,449,632,653`.
- [x] GIT-04 — ambiguous identity terminal; invalidation re-eligibles. Evidence:
  `tests/git_impl.rs:449` (identity table), `tests/store_impl.rs:518`,
  `tests/walk_impl.rs:427` (stale requeue), `tests/cli_impl.rs:525` (invalidate).
  Gap: no test asserting probe-failure completes without retry
  (`src/main.rs:4808-4812,4891-4901`; nearest: `tests/accept_git.rs:237` preserves a broken
  marker as terminal `probe_failed`/`unsupported`).
- [x] STATUS-01 — status counts per Git semantics. Evidence: `tests/git_impl.rs:280`,
  `tests/fixtures_impl.rs:264`, `tests/common/fixture.rs:336`,
  `tests/accept_git.rs:570` (dirty counts, nonmatch unprobed, metadata nulls).
  Gap: unstable mapping (`src/main.rs:6193-6196`) untested end-to-end; matching-only
  gating is covered (`:570`, filter `src/main.rs:5564-5574`).
- [x] READ-01 — inspection leaves repos/locks untouched. Evidence:
  `tests/accept_git.rs:660` (HEAD/index/config/ref + lock bytes/mtimes unchanged,
  `.git` inventory identical, no FETCH_HEAD), `tests/accept_report.rs:760`
  (inside-tree report identified as a generated artifact). Gap: network-unchanged
  rests on the no-fetch assertion plus gix read-only construction (no packet capture).
- [x] DB-01 — pinned Turso runs schema + paths. Evidence: `Cargo.toml:34` (`=0.8.1`),
  `tests/store_impl.rs:26` (round-trip across reopen).
- [x] DB-02 — tx/commit/rollback/migrate/checkpoint paths. Evidence:
  `tests/store_impl.rs:26,359,518,597`, `tests/accept_db.rs:96,139,199,257`
  (commit/rollback, cancelled-lease requeue, reader/checkpoint/migration/durability,
  visible failure), `src/store/catalog.rs:871-876` (with_tx discipline).
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
  `tests/accept_resume.rs:155` (acknowledged work survives, attempt counts frozen,
  redo bounded to one claim batch, dir-complete counts agree with a fresh
  traversal), plus `tests/accept_misc.rs:358` (kill/resume converges on complete).
- [x] RESUME-02 — stale completion requeues; findings kept. Evidence:
  `tests/store_impl.rs:518`, `tests/walk_impl.rs:427`, `tests/cli_impl.rs:478-482`
  (generation/findings reuse), `tests/accept_resume.rs:395` (stale completion keeps
  newer rev), `tests/accept_resume.rs:498` (incomplete scan keeps old findings).
- [x] EVENT-01/02 — insertion/history-loss/crash-point/flood reconciliation. Evidence:
  `tests/accept_misc.rs:102` (while-stopped insertion + moved-in repo reconcile),
  `:182` (history loss), `:260` (moved-in subtrees), `:300` (kill between ingest
  and reconcile), `:358` (CLI kill/resume), `:415,470` (flood finite boundary),
  `tests/events_impl.rs:150,251,272,298,381,649` (protocol incl. dropped/root-change),
  `tests/review_fix_main.rs:242` (main.rs ingest/reconcile hooks + report note).
  Wired: scan ingests + reconciles cursors (`src/main.rs:687,800`), invalidate ingests
  (`src/main.rs:7895-7912`). Gap: non-macOS degrades to null cursors + honest note
  (`src/main.rs:1370-1373`); live-stream tests are macOS-gated
  (`tests/accept_misc.rs:512`, `tests/events_impl.rs:825,847`).
- [ ] ERROR-01 — unchecked: permission-denied-then-restored (`tests/accept_db.rs:642`),
  offline-root gap (`:738`), and watchdog grace (`tests/review_fix_main.rs:403`,
  tripped-count log `src/main.rs:718-721`) are now tested; still missing per spec:
  stalled-op injection for enumeration/metadata/canonicalization/configuration/
  alternate-store/report-sink (no hook exists, `tests/accept_db.rs:9-16`) and the
  unrelated-activity-cannot-reset-watchdog clause.
- [x] ERROR-02 — helper cap. Evidence: `tests/walk_impl.rs:498` (hard non-additive
  limits incl. helpers). By design the binary spawns 0 helpers (sequential owner,
  `src/main.rs:4-11`); no still-stuck replacement test exists.
- [x] CACHE-01 — invalidate vs force-rescan vs clear. Evidence: `tests/cli_impl.rs:373`
  (clear), `tests/cli_impl.rs:484` (force-rescan), `tests/cli_impl.rs:525` (invalidate),
  `tests/accept_db.rs:859,984` (three ops distinct, clear fences a live owner).
- [x] CACHE-02 — unsafe paths / foreign files. Evidence: `tests/cli_impl.rs:301`
  (snapshot traversal), `tests/cli_impl.rs:373` (foreign preserved, lock retained),
  `tests/accept_db.rs:1012,1094` (symlink state dir refused, foreign preserved).
- [x] REPORT-01 — schema, refs, counts, exit agreement. Evidence:
  `tests/report_impl.rs:208,296,315,323,430`, `tests/cli_impl.rs:441-448`,
  `tests/accept_report.rs:421,491,908` (live emission validates against the real
  JSON schema, all status modes). The binary stages through the lib pipeline
  (`src/main.rs:7206-7217`, REVIEW R3 closed; `tests/review_fix_main.rs:140`).
- [x] REPORT-02 — atomic publish, no-clobber, retry. Evidence:
  `tests/report_impl.rs:548,553,570,623`; binary exercises fresh-publish + verified
  prior-report replace (`tests/cli_impl.rs:451-484`); binary refusal paths
  (`tests/accept_report.rs:807,875`), stalled-publish reader release (`:656`),
  snapshot retry (`:704`, `tests/review_fix_main.rs:140`), receipt + caps
  (`tests/sec_publish.rs:33,95,109,285`).
- [ ] PERF-01 — unchecked: spec-table values (`tests/accept_misc.rs:588`), burst +
  10k-churn cap-hold (`:612`), and live counter agreement (`:717`) are now tested,
  and the sustained gate exercises repeated real scans with queue bounds held
  (`tests/accept_perf.rs:362`); still missing: slow-consumer and event-burst
  admission-cap tests.
- [x] PERF-02 — sustained RSS/CPU gate. Evidence: corpus declared
  (`fixtures/corpus.json`), harness `benches/perf_gates.rs` (≥30 s sustained window,
  RSS ≤ 256 MiB, mean ≤ 1.1 cores, tx/sync rates, queue bounds), gate test
  `tests/accept_perf.rs:362` (passes per `/tmp/repo-scan-gate-freeze.log`).
  Gap: no isolated first-result-latency record (per-iteration full-scan records only).
- [x] PERF-03 — pressure containment. Evidence: `tests/accept_misc.rs:768`
  (pressure stops admission, work resumes), `:809` (no false clean, CPU accounting
  survives respawn), binary 512 MiB wiring (`src/main.rs:2468-2469,2509`,
  `src/config.rs:75`), pressure injection record with all nine sub-proofs plus
  overshoot/peak/threshold fields (`benches/perf_gates.rs:852-1019`), gate test
  `tests/accept_perf.rs:362` (passes per `/tmp/repo-scan-gate-freeze.log`).
