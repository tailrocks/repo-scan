# Repository merge run — tailrocks/repo-scan

- Invocation: human, `/tailrocks-repository-merge --all-work`
- Observation time: 2026-10-11T08:56:41Z
- Repository: `tailrocks/repo-scan` (resolved via `gh repo view`)
- Target: `refs/heads/main` @ `e12f250e9415d7194b9d9a37591d69880ba1860e` (exists; verified via `git ls-remote`)
- Mode: default (focused contribution PRs). `--transition-mode` NOT selected.
- Scope: frozen `--all-work` = 6 remote branches + 2 open PRs (drafts #1, #3). Listing complete (counts well under pagination limits; no coverage gaps).

## Source inventory

| Source | Head SHA | Identity | State vs target |
|---|---|---|---|
| `chore/velnor-0.1.4-generated-workflows` | `8fc5d1870baa63949e0ccce546b5fc5169ff2bd5` | branch | **Fully on main** — tree identical to squash `ff201b3` (PR #2) |
| `codex/machine-scan-streaming` | `29b4110c3140859edb0f209cc9cbb15f0544b3f9` | branch | **Fully on main** — tree identical to main tip `e12f250` (PR #5 squash) |
| `docs/repo-scan-pr-template-ci-alignment` | `989305679e7a24dd7b98a6a2abc246c83f2c3348` | branch | **Content on main** — its `.github/PULL_REQUEST_TEMPLATE.md` is byte-identical to main's (landed via PR #4 `6eda7f4`) |
| `chore/repo-scan-pr-template` (PR #3, draft) | `0502919d0013de78b3f10566736c56fc4d5ef39f` | PR #3 | **Superseded** — older CI-misaligned template variant; PR #4's version is on main and matches real CI gates |
| `work/fast-complete-scan` (PR #1, draft) | `8289a839d26a44f4820441349ac040a62348ef50` | PR #1 | **Real unmerged work** — 103 commits, +46,705/−7,339 over 102 files, based on `13e534b` (3 squash merges behind main) |
| `main` | `e12f250e` | target | — |

All sources same-repository (`tailrocks`), no forks. No machine-wide discovery performed.

## Contribution map — already-resolved sources (verdicts verified against live main)

1. Velnor 0.1.4 workflow regeneration (`.github/`, `.velnor/`, ci.yml V2 cache, composite actions) — ON MAIN (PR #2). Verdict: resolved; branch is cleanup-only.
2. Audit-gate "NOT ENFORCED" honesty fix (`docs/AUDIT_GATE.md`, `tests/sec_audit_gate.rs`, `tests/sec_git_db.rs`) — ON MAIN (PR #2). Verdict: resolved.
3. CI.md rewrite (job table, generator ownership) — ON MAIN (PR #2). Verdict: resolved.
4. Canonical PR template — ON MAIN in the CI-aligned form (PR #4). PR #3's older variant (bare `cargo`, no mise pin, no actionlint section) contradicts real gates (`VELNOR_NEEDS_EXPECTED: actionlint, plan, rust-repo-scan`). Verdict: reject PR #3 content as superseded; retain PR #3 open (closure not authorized by this request).
5. Streaming staged-report validation, build.rs source-commit provenance, deny_unknown_fields strictness, hardened base64, bounded diagnostics, report-ID de-echo, `retry_terminal` "retained" semantics — ON MAIN (PR #5). Verdict: resolved; branch is cleanup-only.

## Contribution map — `work/fast-complete-scan` (the one live body of work)

| # | Contribution | Files (evidence SHAs) | Class |
|---|---|---|---|
| C1 | Behavior contracts + baseline docs (GOAL_CONTRACTS D1–D12, BASELINE_RECEIPT, README rewrite) | docs/ (`eeaca66`, `0861c16`, `870019d`) | supporting |
| C2 | Multi-target scan, scan-event journal, query replay; report 1.1.0, catalog v2 | `src/scan_events.rs`, `src/store/{schema_v2,catalog}.rs` (`6128691`…`9d00199`) | user-facing |
| C3 | Fetch phase: `--fetch`, refspec safety, freshness; report 1.2.0, catalog v3 | `src/git/{refspec,fallback}.rs`, `tests/accept_fetch.rs` (`3cd8190`…`495fea6`) | user-facing |
| C4 | Firm scan boundary at `inventory_ready`; Topology guard deleted (M4); exit-3 retry semantics | `src/main.rs`, `src/walk/*`, deletes `tests/fail_topo.rs` (`8d4f54c`…`44315ee`) | user-facing |
| C5 | Worker-pool `--workers` (1–32), scaled admission, lease gates; catalog v4 | `src/config.rs`, `src/scheduler/admission.rs`, `src/store/schema_v4.rs` (`8c59f65`…`e1d1e34`) | user-facing |
| C6 | Git working-state vocabulary + ahead/behind/diverged comparison; report 1.3/1.4, catalog v5/v6 | `src/git/graph.rs`, `src/identity.rs`, schemas v1.4/v1.5 (`815679f`…`3d61950`) | user-facing |
| C7 | Report 1.5.0 groups/totals, output matrix, interactive TUI, live `--report` | `src/report/{tui,live_text,output,model}.rs` (`8399a4d`, `5226dc8`, `9be91c8`) | user-facing |
| C8 | Indexed bounded claim query (~1100× at 1M tasks), release-only perf gates | `src/store/catalog.rs`, `benches/perf_gates.rs` (`7cc53f3`…`06b1e54`) | internal perf |
| C9 | Review-fix hardening sweeps incl. branch's own streaming validator in `validate.rs` | `src/report/validate.rs` +1,436 (`6a6fbfe`), sweeps (`8c4d408`…`3083142`) | internal hardening |
| C10 | Corpus bench infra + Wave4a performance receipt (median ratio 0.191, target MET) | `benches/corpus.rs`, `docs/WAVE4A_RECEIPT.md` (`1d3316f`…`c14c4c6`) | supporting |
| C11 | macOS CI gate as inert `docs/workflows/macos.yml` + stale-model CI.md edit | (`a7409f9`, `59b4409`) | supporting |

### Exclusion candidates (recorded; not silently dropped)

- `docs/REMOTE.md` — internal agent-session workflow notes ("Git writer: the coordinator session only…"), not project documentation; also self-references this work branch. Recommend EXCLUDE.
- `benches/results/claim_bench.jsonl` — committed artifact whose own metadata says the "after" run included uncommitted edits; repo policy gitignores raw bench logs. Recommend EXCLUDE.
- `machine_scale_performance_receipt.md` — kept with SUPERSEDED banners as audit trail. Recommend KEEP (deliberate), confirm with owner.
- Branch's `docs/CI.md` edit (`59b4409`) — written against the pre-PR#2 Velnor 0.1.0 ownership model; main's 0.1.4 doc supersedes it. Recommend DROP in favor of main.
- ~10 `WIP:` + ~20 receipt-only commits — vanish under squash merge; no action.

## Merge-risk analysis (fast-complete-scan → current main)

`git merge-tree --write-tree origin/main origin/work/fast-complete-scan`: only 4 textual conflicts (`docs/CI.md`, `src/main.rs`, `src/report/builder.rs`, `src/report/validate.rs`), but the report pipeline is an architecture collision:

- **Two parallel streaming validators** (keep-one decision required): main's `src/report/validate_stream.rs` (19-field ROOT_FIELDS bitmask, rejects v1.5.0 `groups`/`totals` today) vs branch's validator inside `validate.rs`. Main's is the reviewed, merged architecture; it must be extended for v1.5.0 envelope fields. Branch's also re-introduces the report-ID echo PR #5 removed.
- **Compile breakage on naive merge**: 3-arg vs 4-arg `check_staged_memory_budget`; branch's deleted-on-main `probe_staged_records`; poisoned auto-merge in `verified_retain_and_publish` (`&bound` vs `&Path` type error).
- **Semantic reconciliation**: branch's `source_commit_from_build` vs main's build.rs trio (keep main's); branch `retry_publication` "published" vs main `retry_terminal` "retained" (keep main's); `tests/fail_topo.rs` deletion (branch intent, M4) vs main's retained test (accept deletion with eyes open).
- **No conflict at all** on `.github/`, `.velnor/`, `tests/sec_*`, PR template — branch never touched them; PR #2/#4 content merges clean.

Overall integration risk: HIGH for the report pipeline; LOW elsewhere. Not a mechanical merge — requires porting C7/C9-validation onto main's validate_stream architecture.

## Grouping plan (default mode: focused sequential PRs)

Strictly serial — every group touches `src/main.rs`/`src/store/catalog.rs`, and catalog migrations (v2→v6) + report schema (1.1→1.5) chain in order. Each candidate starts from the advancing target.

| Order | Group | Contributions | Depends on |
|---|---|---|---|
| G1 | Foundation + scan events + multi-target + output lanes (report 1.1, catalog v2) | C1, C2 | — |
| G2 | Fetch phase (report 1.2, catalog v3) | C3 | G1 |
| G3 | Firm scan boundary | C4 | G1 |
| G4 | Worker pool (catalog v4) | C5 | G3 |
| G5 | Git comparison + working-state (report 1.3/1.4, catalog v5/v6) | C6 | G1 |
| G6 | Report 1.5 groups/totals + live outputs + TUI + validator reconciliation with PR #5 | C7, C9(validator) | G1, G5 |
| G7 | Perf gates + hardening sweeps + corpus/bench docs + CI notes | C8, C9(rest), C10, C11 | G4, G6 |

Exclusions above applied to all groups. No contribution dropped silently: resolved (5), grouped (C1–C11), exclusion-recommended (4 items, pending owner confirmation).

## Progress / blockers / next action

- G1 **MERGED** 2026-10-11T12:25:37Z: PR #6, squash commit `1772d70822397f7bb02a6b6e6acb0739e9472aa3` onto main. Candidate `merge/g1-scan-events` final head `2d4cb5471cadf956d7d7c7729bb2166e3054468d` (retained). Integration fixes beyond the raw prefix (all reviewed + CI-green): resume restores saved multi-target/`--all` request shape; unwired `--format`/`--fetch` lanes refuse loudly; follow-mode drains terminal journal event past row state; same-spelling repeat-probe double-persist fixed (Linux CI); DCO sign-off rebase (tree-identical); PR-template version assignments corrected. 4 codex-bot review threads resolved with replies.
- Target advanced: main = `1772d70`. Remaining groups re-base onto it.
- Next: G2 fetch phase (commits 3cd8190..495fea6 on source), which also removes the G1 `--fetch` loud refusal.
- Retention: all source branches and both draft PRs retained. PR #3 closure and remote branch deletion NOT authorized by this request — cleanup candidates only.

## Evidence

- `gh pr list --repo tailrocks/repo-scan --state open --limit 1000` → PRs #1, #3 only.
- `git ls-remote --heads` → 6 branches, SHAs as tabled above.
- Empty-diff verifications: `git diff origin/main origin/codex/machine-scan-streaming` (0 lines); `git diff ff201b3 8fc5d187` (0 lines); `git diff origin/main origin/docs/repo-scan-pr-template-ci-alignment -- .github/PULL_REQUEST_TEMPLATE.md` (0 lines).
- Conflict prediction: `git merge-tree --write-tree origin/main origin/work/fast-complete-scan` (exit 1, 4 conflicted files, result tree `8f6ec96b`).
- Deep per-branch analyses: subagent reports for velnor branch, codex branch, both template branches, fast-complete-scan contribution map, and fast-complete-scan↔main conflict inventory (this session, 2026-10-11).

Coverage gaps: none.
