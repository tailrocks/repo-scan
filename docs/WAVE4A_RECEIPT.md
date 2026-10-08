# Wave4a performance receipt: fast-complete-scan vs baseline (Steps 4 + 16)

## Completion definition (B1)

A rep counts as COMPLETE when ALL hold:

- `coverage.filesystem == "complete"` AND `coverage.tasks_pending == 0`
- recall: discovered stores cover all 221 manifest expected paths
  plus the 1 known extra (embedded submodule gitdir at
  `special/super/.git/modules/sub`): 222/222 on `/tmp/corpus16`
- exit 0 with `gaps == 0` and `unresolvable_candidates == 0`.

History: this definition supersedes the earlier "exit 3 with exactly
4 known unresolvables" rule (template commit `c14c4c6`). The 4
remote-less/unborn candidates (`bare_one.store`, `bare_two`,
unborn repo, submodule gitdir) are now inventoried with unknown
identity per Step 7 instead of parked unresolvable — verified by
manifest-diff on the shakedown rep (221/221 + 1 known extra,
exit 0). The `perf_gates` corpus instead adds origins (see
`benches/perf_gates.rs:616-618`).

Discovery time = wall from process start to the first stderr tick
with `dirs == <rep max tick dirs>` (plateau rule, identical for
both binaries; both emit `dirs=` ticks at multi-Hz cadence so
quantization is <1s). The plateau form is required because the
baseline's final tick lags its committed coverage (r1-base tick
max 104130 vs coverage 104132; r2-base tick max 104126 vs
104132): a literal `dirs == directories_complete` rule would
never fire for the baseline. Total time = wall to process exit.
Analysis time = total − discovery (approximation; baseline
interleaves probes with enumeration).

## Binaries and toolchain

TODO (measured): for EACH binary — source commit, `sha256` digest,
`cargo build --release` invocation, rustc version
(`rustc --version --verbose`), effective release profile (cargo
defaults: lto off, codegen-units 16, panic unwind — no
`[profile.release]` in `Cargo.toml`).

## Machine

TODO (measured): OS, CPU model, RAM, filesystem, storage device,
core count, ambient load before/during (uptime samples per rep).

## Dataset

TODO (measured): corpus path, manifest counts (dirs/files/stores),
deep/wide/many-branch/many-file shapes, expected-locations file.
LIMITATION (M6): single APFS volume, no latency/fault injection
(deferred in `docs/BASELINE_RECEIPT.md`, still open).

## Method

- Release binaries only; missing release binary FAILS the run
  (never silently debug).
- Fresh catalog (new state dir) per rep; `--status summary` both.
- Alternating order A/B/A/B…; cache condition labeled per rep
  (fresh-catalog/warm); a new temp dir is NOT a cold cache.
- Equal scope: same `--root`, same target URL(s), same depth.
- Load: no other benchmarks during reps; uptime sampled per rep.
- recall: manifest-diff per rep (discovered stores vs
  `manifest.json` expected paths), not tick counters alone.
- Scope: manual-receipt-only (M11); CI gates absolute resource
  bounds, not wall-clock ratios.

## Per-rep ledger (REQUIRED — one row per rep, no exceptions)

| rep | binary+digest8 | cmd (exact) | workers | cache | load_before/after | exit | wall_s | discovery_s | analysis_s | dirs | entries | txns | syncs | recall | unresolvables |
|-----|----------------|-------------|---------|-------|-------------------|------|--------|-------------|------------|------|---------|------|-------|--------|---------------|
| _example_ | _new@a4d45b81_ | _…_ | _8_ | _fresh_ | _…_ | _3_ | _…_ | _…_ | _…_ | _…_ | _…_ | _…_ | _…_ | _222/222_ | _4 known_ |
| r1-base | base@94bb89c6 | `scan https://github.com/bench-special/family --root /tmp/corpus16/ws --status summary` | 1 | fresh-catalog | 16.25→33.21 | 3 | 4225 | 4183 | 42 | 104130 | 1160577 | 325269 | 218652 | 222/221 | 4 known |
| r1-new | new@98ea5fde | `scan --all --root /tmp/corpus16/ws --status summary --workers 8 --format jsonl` | 8 | fresh-catalog | 34.32→35.20 | 0 | 3573 | 3415 | 158 | 104132 | 1160577 | 241229 | 30683 | 222/221 | 0 |
| r2-base | base@94bb89c6 | `scan https://github.com/bench-special/family --root /tmp/corpus16/ws --status summary` | 1 | fresh-catalog | 39.02→12.44 | 3 | 4655 | 4636 | 19 | 104126 | 1160577 | 326119 | 219502 | 222/221 | 4 known |
| r2-new | new@98ea5fde | `scan --all --root /tmp/corpus16/ws --status summary --workers 8 --format jsonl` | 8 | fresh-catalog | 12.44→15.37 | 0 | 2935 | 2850 | 85 | 104132 | 1160577 | 239819 | 29266 | 222/221 | 0 |

Raw logs per rep (git-ignored): `benches/results/w4a/<rep>.{stdout,stderr,time,meta,report.json}`,
`.meta.json` carries cmd/exit/wall/digest. Claim microbench artifact:
`benches/results/claim_bench.jsonl` (commit
...[truncated 1474 chars]