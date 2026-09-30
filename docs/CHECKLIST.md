# Acceptance checklist (Phase 1: contracts only)

Every spec §17 acceptance ID mapped to its contract files. All unchecked:
implementation + verification evidence land in later phases. Check an item
only when its test passes and evidence is cited.

- [ ] CLI-01 — six exact commands + exit codes. Files: `src/cli.rs`, `src/main.rs`, `src/model.rs` (`ExitCode`). Evidence: TODO (CLI parse tests).
- [ ] CLI-02 — cached query performs no live reads; no catalog yields 3. Files: `src/cli.rs` (`QueryArgs`), `src/store/mod.rs`. Evidence: TODO.
- [ ] CLI-03 — resume preserves absolute destination + options; idempotent terminal replay. Files: `src/cli.rs`, `src/scheduler/mod.rs`, `src/store/mod.rs`. Evidence: TODO.
- [ ] FS-01 — hidden/temp/cache, nested repos, clone inside `.git/recovery` found. Files: `src/walk/mod.rs`, `src/platform/mod.rs`. Evidence: TODO.
- [ ] FS-02 — bare stores, `.git` files, external common dirs, detached copies, outside-root worktrees. Files: `src/git/mod.rs`, `src/walk/mod.rs`. Evidence: TODO.
- [ ] FS-03 — symlink cycles, APFS aliases, mount changes, path replacement. Files: `src/platform/mod.rs`, `src/identity.rs`. Evidence: TODO.
- [ ] FS-04 — non-UTF-8 / control-char round-trip + safe terminal rendering. Files: `src/walk/mod.rs`, `schemas/report-v1.schema.json`. Evidence: TODO.
- [ ] FS-05 — huge flat / deep fixtures, bounded buffers, backend equivalence. Files: `src/walk/mod.rs`, `src/config.rs`. Evidence: TODO.
- [ ] GIT-01 — same branch names different OIDs, unborn/detached HEADs, packed refs, unsupported formats. Files: `src/git/mod.rs`. Evidence: TODO.
- [ ] GIT-02 — hard-linked packs / alternates do not collapse clones. Files: `src/git/mod.rs`, `src/identity.rs`. Evidence: TODO.
- [ ] GIT-03 — remotes, URL variants, rewrites, forks, removed remotes per policy. Files: `src/identity.rs`, `src/git/mod.rs`. Evidence: TODO.
- [ ] GIT-04 — ambiguous identity ends terminal-incomplete; invalidation re-eligibles. Files: `src/identity.rs`, `src/scheduler/mod.rs`. Evidence: TODO.
- [ ] STATUS-01 — dirty/untracked/unstable/unknown accuracy; no stray probes. Files: `src/git/mod.rs`, `src/model.rs` (`StatusMode`). Evidence: TODO.
- [ ] READ-01 — inspection mutates nothing except owned state + requested report. Files: `src/git/mod.rs`, `src/report/mod.rs`. Evidence: TODO.
- [ ] DB-01 — pinned Turso runs production schema + all transaction paths. Files: `src/store/mod.rs`, `Cargo.toml`. Evidence: TODO.
- [ ] DB-02 — commit/rollback/cancel/interleave/migrate/checkpoint/sync-error semantics. Files: `src/store/mod.rs`. Evidence: TODO.
- [ ] DB-03 — crash at every boundary incl. checkpoint/WAL-reset/disk-full/corrupt cases. Files: `src/store/mod.rs`, `src/scheduler/mod.rs`. Evidence: TODO.
- [ ] DB-04 — FULL + macOS full-sync qualified and exercised; no unproven PRAGMA. Files: `src/store/mod.rs` (`DurabilityProof`). Evidence: TODO.
- [ ] RESUME-01 — mid-scan death resumes frontier without needless rescan. Files: `src/scheduler/mod.rs`, `src/store/mod.rs`. Evidence: TODO.
- [ ] RESUME-02 — invalidation survives stale completion; failures keep findings. Files: `src/scheduler/mod.rs`. Evidence: TODO.
- [ ] EVENT-01 — insert-while-stopped, moved-in dirs, history loss, drops, root changes. Files: `src/events.rs`, `src/platform/`. Evidence: TODO.
- [ ] EVENT-02 — cursor crash points lossless; unrelated events don't block boundary. Files: `src/events.rs`, `src/scheduler/mod.rs`. Evidence: TODO.
- [ ] ERROR-01 — permission/offline/stall classes preserve obligations; watchdog per-op. Files: `src/error.rs`, `src/scheduler/mod.rs`, `src/config.rs`. Evidence: TODO.
- [ ] ERROR-02 — still-stuck helpers count against the fixed cap. Files: `src/config.rs`, `src/telemetry.rs`. Evidence: TODO.
- [ ] CACHE-01 — invalidate vs force-rescan vs clear; concurrent clear fences workers. Files: `src/cli.rs`, `src/scheduler/mod.rs`, `src/store/mod.rs`. Evidence: TODO.
- [ ] CACHE-02 — unsafe state paths / symlink substitution / unknown files safe. Files: `src/config.rs`, `src/store/mod.rs`. Evidence: TODO.
- [ ] REPORT-01 — every report validates, resolves refs, agrees counts + exit status. Files: `schemas/report-v1.schema.json`, `tests/data/example-report.json`, `src/report/mod.rs`. Evidence: TODO.
- [ ] REPORT-02 — staged atomic publish; stalled publish frees readers; retry-from-snapshot; no clobber. Files: `src/report/mod.rs`. Evidence: TODO.
- [ ] PERF-01 — hard admission + buffer bounds hold under load. Files: `src/config.rs`, `src/telemetry.rs`. Evidence: TODO.
- [ ] PERF-02 — ≤1.1 cores mean, ≤256 MiB RSS on declared corpus + full metrics. Files: `src/config.rs`, `src/telemetry.rs`. Evidence: TODO.
- [ ] PERF-03 — 512 MiB pressure containment; resumable; CPU accounting survives. Files: `src/config.rs`, `src/telemetry.rs`, `src/scheduler/mod.rs`. Evidence: TODO.
