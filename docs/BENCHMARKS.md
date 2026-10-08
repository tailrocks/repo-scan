# Benchmarks and performance gates

All numbers are recorded on run as JSONL. Never invent latencies or speedups.

## Reproducible commands

```sh
# Adapter equivalence + per-backend wall time over one identical scope.
# Exits 1 on any backend mismatch (a skipping backend fails regardless of speed).
cargo bench --bench walk_compare
# results: benches/results/walk_compare.jsonl (override dir with $BENCH_RESULTS)

# Cold-vs-warm traversal, cached-query latency, invalidate-one-subtree cost,
# resume (recover + claim) cost, RSS footprint.
cargo bench --bench scan_cycle
# results: benches/results/scan_cycle.jsonl (override dir with $BENCH_RESULTS)

# Step 16 measurement corpus: deterministic developer-machine-like tree
# (>=100k dirs, >=1M files, 200 Git stores + worktrees/submodule/bare).
CORPUS_DIR=/path/to/corpus cargo bench --bench corpus
# refuses into an existing ws/ dir; CORPUS_SMALL=1 shrinks all dimensions.
# manifest: $CORPUS_DIR/manifest.json (every expected store path).

# PERF-02/03 sustained gates (declared corpus, >=30 s measurement,
# 512 MiB pressure injection). Asserts via tests/accept_perf.rs.
# Release-only: a missing/non-release binary FAILS the gate (no debug
# fallback). Gate pins --workers 8 and needs >= 3 iters (median/variance);
# binary sha256 + profile are recorded per run.
cargo bench --release --bench perf_gates
# results: benches/results/perf_gates.jsonl (override dir with $BENCH_RESULTS)
```

Harness: [benches/support.rs](../benches/support.rs) (`Recorder`, traversal driver,
RSS sampler). Scopes are built in tempdirs per run
([benches/walk_compare.rs](../benches/walk_compare.rs:19),
[benches/scan_cycle.rs](../benches/scan_cycle.rs:24)):
hidden/tmp/cache repos, arbitrarily named bare store, linked worktree, nested repo,
flat (500 files) and deep (32 levels) trees, non-UTF-8 names on Unix.

Record the hardware, OS, filesystem, dataset, `--workers` setting, and build
versions alongside every run. Scans default to platform-parallelism workers
(`--workers`, max 32); worker-count comparisons measure against that default,
which is a starting point, not a tuned optimum (`src/config.rs`).

## Results

### walk_compare (per adapter; scope identical)

| date | host / OS / fs | adapter | wall_ms | dirs | entries | errors | equivalent_to_baseline | peak_rss_bytes |
| ---- | -------------- | ------- | ------- | ---- | ------- | ------ | ---------------------- | -------------- |
| 2026-10-01 | Apple M5 Max / macOS 27.0 / APFS | ignore | 9.06 | 172 | 891 | 0 | true | 7929856 |
| 2026-10-01 | Apple M5 Max / macOS 27.0 / APFS | std-escape | 3.80 | 172 | 891 | 0 | true | 8142848 |
| 2026-10-01 | Apple M5 Max / macOS 27.0 / APFS | dua | 2.99 | 172 | 891 | 0 | true | 8290304 |

Verdict record: `adapters`, `equivalent`, `baseline_dirs/entries/errors`.

Provenance: the rows above carry no commit/binary-digest provenance
(pre-provenance harness) and each wall is a single shot — do not cite
without re-running. Current runs record commit + diff fingerprint
(`build_evidence`) and binary sha256 + profile (`binary`) per run.

### scan_cycle

| date | host / OS / fs | record | cold_wall_ms | warm_wall_ms | dirs | entries | errors | mean_wall_ms | reps | new_revision | pending_after | enqueued | claimed | peak_rss_bytes |
| ---- | -------------- | ------ | ------------ | ------------ | ---- | ------- | ------ | ------------ | ---- | ------------ | ------------- | -------- | ------- | -------------- |
| 2026-10-01 | M5 Max / macOS 27.0 / APFS | traversal | 1.34 | 0.97 | 50 | 630 | 0 | — | — | — | — | — | — | 8355840 |
| 2026-10-01 | M5 Max / macOS 27.0 / APFS | cached_query | — | — | — | — | — | 0.091 | 50 | — | — | — | — | — |
| 2026-10-01 | M5 Max / macOS 27.0 / APFS | invalidate | — | — | — | — | — | — | — | 1 | 1 | — | — | 4.47 ms wall |
| 2026-10-01 | M5 Max / macOS 27.0 / APFS | resume | — | — | — | — | — | — | — | — | — | 500 | 501 | enqueue 2068.81 ms, recover+claim 55.94 ms, recovered_to_pending 0 |
| 2026-10-01 | M5 Max / macOS 27.0 / APFS | footprint | — | — | — | — | — | — | — | — | — | — | — | 17711104 |

Provenance: same caveat as walk_compare — no commit/digest on the rows
above, traversal walls are single-shot, and scan_cycle emits no verdict
record. Do not cite without re-running.

PERF-02/03 gates run from [benches/perf_gates.rs](../benches/perf_gates.rs)
(declared corpus, ≥30 s sustained measurement, 512 MiB pressure injection),
asserted by [tests/accept_perf.rs](../tests/accept_perf.rs)
(`perf_02_03_gates_hold`; results: `benches/results/perf_gates.jsonl`).
Traceability: [docs/CHECKLIST.md](../docs/CHECKLIST.md) PERF-02/03.

LIMITATION (M6): the gate corpus lives on a single volume with no
latency/fault injection (deferred in `docs/BASELINE_RECEIPT.md`, still
open) — slow-filesystem behavior is unmeasured.
