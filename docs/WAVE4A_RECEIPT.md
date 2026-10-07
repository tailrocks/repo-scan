# Wave4a performance receipt: fast-complete-scan vs baseline (Steps 4 + 16)

## Completion definition (B1)

A rep counts as COMPLETE when ALL hold:

- `coverage.filesystem == "complete"` AND `coverage.tasks_pending == 0`
- recall: discovered stores == manifest expected paths (222/222 on
  `/tmp/corpus16`: 221 manifest paths + 1 submodule gitdir)
- exit 3 with EXACTLY the 4 known unresolvable candidates
  (`bare_one.store`, `bare_two` — remote-less by construction in
  `benches/corpus.rs:235-252` — plus the unborn repo and the
  submodule `.git/modules` gitdir, all `unresolvable_identity`).
  Exit 3 is the ACCEPTED terminal state on this corpus: the bare
  stores deliberately exercise the unknown-identity path (the
  `perf_gates` corpus instead adds origins; see
  `benches/perf_gates.rs:616-618`). Exit 0 is unachievable here.

Discovery time = wall from process start to the first stderr tick
with `dirs == coverage.directories_complete` (identical rule for
both binaries; both emit `dirs=` ticks). Total time = wall to
process exit. Analysis time = total − discovery (approximation;
baseline interleaves probes with enumeration).

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

Raw logs per rep (git-ignored): `benches/results/w4a/<rep>.{stdout,stderr,time,meta,report.json}`,
`.meta.json` carries cmd/exit/wall/digest. Claim microbench artifact:
`benches/results/claim_bench.jsonl` (commit
...[truncated 1474 chars]