# Benchmarks (spec §18)

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
```

Harness: [benches/support.rs](/Users/donbeave/Projects/repo-scan/benches/support.rs) (`Recorder`, traversal driver,
RSS sampler). Scopes are built in tempdirs per run
([benches/walk_compare.rs](/Users/donbeave/Projects/repo-scan/benches/walk_compare.rs:19),
[benches/scan_cycle.rs](/Users/donbeave/Projects/repo-scan/benches/scan_cycle.rs:24)):
hidden/tmp/cache repos, arbitrarily named bare store, linked worktree, nested repo,
flat (500 files) and deep (32 levels) trees, non-UTF-8 names on Unix.

Record the hardware, OS, filesystem, dataset, and build versions alongside every run.

## Results

### walk_compare (per adapter; scope identical)

| date | host / OS / fs | adapter | wall_ms | dirs | entries | errors | equivalent_to_baseline | peak_rss_bytes |
| ---- | -------------- | ------- | ------- | ---- | ------- | ------ | ---------------------- | -------------- |
|      |                |         |         |      |         |        |                        |              |

Verdict record: `adapters`, `equivalent`, `baseline_dirs/entries/errors`.

### scan_cycle

| date | host / OS / fs | record | cold_wall_ms | warm_wall_ms | dirs | entries | errors | mean_wall_ms | reps | new_revision | pending_after | enqueued | claimed | peak_rss_bytes |
| ---- | -------------- | ------ | ------------ | ------------ | ---- | ------- | ------ | ------------ | ---- | ------------ | ------------- | -------- | ------- | -------------- |
|      |                | traversal |           |              |      |         |        | —            | —    | —            | —             | —        | —       |              |
|      |                | cached_query | —      | —            | —    | —       | —      |              |      | —            | —             | —        | —       | —            |
|      |                | invalidate | —        | —            | —    | —       | —      | —            | —    |              |               | —        | —       | —            |
|      |                | resume | —            | —            | —    | —       | —      | —            | —    | —            | —             |          |         | —            |
|      |                | footprint | —         | —            | —    | —       | —      | —            | —    | —            | —             | —        | —       |              |

PERF-02/03 gates (declared corpus, ≥30 s sustained measurement, 512 MiB injection)
have no harness yet — see [docs/CHECKLIST.md](/Users/donbeave/Projects/repo-scan/docs/CHECKLIST.md).
