# Baseline receipt: pre-optimization scan measurements (2026-10-07)

Step 4 evidence for the fast-complete-scan goal. All runs use the release
binary built from a clean tree; no debug binary anywhere in this receipt.

## Binary and toolchain

- Source commit: `13e534b5d2ad688a4d05901d36d5afc95bc454ce` (clean tree)
- Binary: `target/release/repo-scan`, 27,519,616 bytes
- Digest: `sha256:f69a315b346eab5a6a24b363701bdffeac920f430822fd841ecc6ad76ac7b43a`
- Build: `cargo build --release`, 4m08s wall (cache-aided), exit 0
- Toolchain: rustc/cargo 1.98.1 (48a229cea)
- Release settings: cargo defaults. There is NO `[profile.release]` in
  Cargo.toml, so the `machine_scale_performance_receipt.md` claim
  (opt-level=3/lto=true/codegen-units=1/panic=abort) is UNVERIFIED and must
  not be cited until proven.

## Machine

- macOS 27.0.1 (build 26A434), Apple M5 Max, 18 logical CPUs, 128 GiB RAM
- Filesystem: APFS on `/dev/disk3s5` (Data volume); `/tmp` → `private/tmp`
- Worker limits: production defaults (max_enum_ops=2, max_git_probes=1,
  shared_permits=2); sequential claim→execute loop, 1 op in flight

## Dataset (small, ephemeral)

`/tmp/scan-bench/corpus` (see `/tmp/scan-bench/EXPECTED.md` for the full
listing; a committed large corpus fixture is future work):

- ~20 plain dirs + 320 enumerated entries, 5 Git stores, all found every run
- Matching `https://github.com/bench-owner/bench-repo`: normal repo (2
  branches, dirty file), bare `beta.git`, repo with submodule + linked worktree
- Nonmatching: other-owner repo, node_modules-nested repo, submodule source
- Command per run (fresh `--state-dir` each time):
  `target/release/repo-scan --state-dir /tmp/scan-bench/state-N scan
  https://github.com/bench-owner/bench-repo --root /tmp/scan-bench/corpus
  --report /tmp/scan-bench/report-N.json --status summary`
- Catalog state: fresh for every run. Filesystem cache: NOT controlled —
  runs 1→5 show cold→warm drift (a new temp dir does NOT prove a cold
  cache; verified cold-cache runs are future work).

## Results (5 fresh-catalog repetitions)

| run | wall | user | sys | maxRSS | first stderr | repos | checkouts | branches | txns | entries |
|-----|------|------|-----|--------|--------------|-------|-----------|----------|------|---------|
| 1 | 19.37s | 0.27s | 0.71s | 23.3 MB | 0.451s | 5 | 5 | 9 | 555 | 320 |
| 2 | 8.20s | 0.23s | 0.34s | 23.2 MB | 2.512s | 5 | 5 | 9 | 551 | 320 |
| 3 | 4.18s | 0.27s | 0.39s | 23.2 MB | 0.081s | 5 | 5 | 9 | 550 | 320 |
| 4 | 3.62s | 0.27s | 0.35s | 23.4 MB | 0.135s | 5 | 5 | 9 | 550 | 320 |
| 5 | 3.45s | 0.24s | 0.31s | 23.5 MB | 0.079s | 5 | 5 | 9 | 550 | 320 |

- Median wall: 4.18s (all runs); warm median (runs 3–5): 3.62s
- Variation: 19.37s → 3.45s, dominated by filesystem-cache warmth, not the tool
- Recall: stable — 5 repos / 5 checkouts / 9 branches in all 5 runs
- Raw logs: `/tmp/scan-bench/run-N.{stdout,stderr,time}.log`, reports
  `/tmp/scan-bench/report-N.json`

## Findings

1. IO/wait-bound: ~0.25s user CPU vs 3.6–19s wall. Parallel discovery
   workers (Step 8) target wall time, not CPU.
2. Transaction-heavy: ~550 txns for 320 entries (~1.7/entry) plus probe-path
   lease renewals — matches the ≥2-txns/task floor. Batching (Step 9) is the
   second lever.
3. First progress is fast when warm (~0.1s) but run 2 shows a 2.5s
   event-history stall before any output — first-discovery latency needs its
   own gate (no time-to-first-candidate metric exists yet).
4. Per-probe progress does 4 aggregate SELECTs (`emit_progress`); on this
   corpus it is noise, but it scales with probe count, not entries.

## Not yet measured (tracked, not dropped)

- Discovery vs analysis split: unmeasurable — no phase boundary exists yet
- Large dataset (100k dirs / 1M files / 200 stores), deep/wide trees,
  multi-volume, slow-op controls (Step 16)
- 10/100-target and --all runs (commands do not exist yet)
- Verified cold-cache runs, warm refreshes, interrupted-run resume timing
- Human/JSON/JSONL output overhead comparison
