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
| r3-base | base@94bb89c6 | `scan https://github.com/bench-special/family --root /tmp/corpus16/ws --status summary` | 1 | fresh-catalog | 15.37→11.92 | 3 | 4125 | 4083 | 42 | 104132 | 1160577 | 325059 | 218442 | 222/221 | 4 known |
| r3-new | new@98ea5fde | `scan --all --root /tmp/corpus16/ws --status summary --workers 8 --format jsonl` | 8 | fresh-catalog | 11.92→15.60 | 0 | 3323 | 3162 | 161 | 104132 | 1160577 | 240115 | 29555 | 222/221 | 0 |
| r4-base | base@94bb89c6 | `scan https://github.com/bench-special/family --root /tmp/corpus16/ws --status summary` | 1 | fresh-catalog | 15.23→10.28 | 3 | 4417 | 4388 | 29 | 104126 | 1160566 | 325436 | 218820 | 222/221 | 4 known |
| r4-new | new@d2ef7208 | `scan --all --root /tmp/corpus16/ws --status summary --workers 8 --format jsonl` | 8 | fresh-catalog | 10.90→12.92 | 0 | 2453 | 2379 | 74 | 104132 | 1160577 | 238649 | 28087 | 222/221 | 0 |
| r5-base | base@94bb89c6 | `scan https://github.com/bench-special/family --root /tmp/corpus16/ws --status summary` | 1 | fresh-catalog | 12.92→11.29 | 3 | 3535 | 3511 | 24 | 104122 | 1160558 | 323900 | 217284 | 222/221 | 4 known |
| r5-new | new@d2ef7208 | `scan --all --root /tmp/corpus16/ws --status summary --workers 8 --format jsonl` | 8 | fresh-catalog | 11.29→9.91 | 0 | 2332 | 2277 | 55 | 104132 | 1160577 | 238460 | 27899 | 222/221 | 0 |
| r6-base | base@94bb89c6 | `scan https://github.com/bench-special/family --root /tmp/corpus16/ws --status summary` | 1 | fresh-catalog | 9.17→9.88 | 3 | 3661 | 3639 | 22 | 104125 | 1160577 | 323824 | 217207 | 222/221 | 4 known |
| r6-new | new@962b2824 | `scan --all --root /tmp/corpus16/ws --status summary --workers 8 --format jsonl` | 8 | fresh-catalog | 9.88→9.33 | 0 | 615 | 565 | 50 | 104132 | 1160577 | 27248 | 27022 | 222/221 | 0 |
| r7-base | base@94bb89c6 | `scan https://github.com/bench-special/family --root /tmp/corpus16/ws --status summary` | 1 | fresh-catalog | 9.33→13.27 | 3 | 3751 | 3716 | 35 | 104127 | 1160577 | 324489 | 217872 | 222/221 | 4 known |
| r7-new | new@962b2824 | `scan --all --root /tmp/corpus16/ws --status summary --workers 8 --format jsonl` | 8 | fresh-catalog | 13.27→10.56 | 0 | 864 | 785 | 79 | 104132 | 1160577 | 27292 | 27068 | 222/221 | 0 |
| r8-base | base@94bb89c6 | `scan https://github.com/bench-special/family --root /tmp/corpus16/ws --status summary` | 1 | fresh-catalog | 10.56→57.40 | 3 | 3756 | 3706 | 50 | 104128 | 1160577 | 324329 | 217713 | 222/221 | 4 known |
| r8-new | new@962b2824 | `scan --all --root /tmp/corpus16/ws --status summary --workers 8 --format jsonl` | 8 | fresh-catalog | 57.40→19.80 | 0 | 1145 | 1084 | 61 | 104132 | 1160577 | 27420 | 27198 | 222/221 | 0 |
| r9-base | base@94bb89c6 | `scan https://github.com/bench-special/family --root /tmp/corpus16/ws --status summary` | 1 | fresh-catalog | 19.80→11.85 | 3 | 3840 | 3818 | 22 | 104124 | 1160577 | 324100 | 217483 | 222/221 | 4 known |
| r9-new | new@962b2824 | `scan --all --root /tmp/corpus16/ws --status summary --workers 8 --format jsonl` | 8 | fresh-catalog | 11.85→12.04 | 0 | 771 | 730 | 41 | 104132 | 1160577 | 27263 | 27041 | 222/221 | 0 |

Raw logs per rep (git-ignored): `benches/results/w4a/<rep>.{stdout,stderr,time,meta,report.json}`,
`.meta.json` carries cmd/exit/wall/digest. Claim microbench artifact:
`benches/results/claim_bench.jsonl` (commit `3948d0c`).

## Series incident 2026-10-08 (attempt-2, after r4-base)

- During r4-base, an unknown ambient process deleted the whole
  `/tmp/reps/new/` shelter checkout (dir mtime 11:06, disk 757Gi
  free — not space pressure). `run_rep.sh` failed safe:
  `missing binary ...` for r4-new, exit 1, no debug fallback.
- The series runner (no `set -e`) skipped r4-new and started
  r5-base. Coordinator stopped the runner ~10min into r5-base
  (killed, state dir discarded) to preserve alternation.
- Rebuilt the new binary from pristine `44315ee` (Wave8d tip):
  digest `d2ef7208...` differs from the original `98ea5fde...`.
  Cause: original build env irreproducible — the active
  toolchain is a franken-pair (cargo 1.98.1 `797e8a9bc` +
  rustc 1.98.1 `48a229cea`), no pins in repo, no spare binary
  anywhere, and the `797e8a9bc` rustc build is no longer
  installed. Rebuild determinism proven: two independent
  pristine builds (shelter path + `$HOME` path) produce
  identical `d2ef7208...` (embedded paths are relative, no
  `[profile.release]`, no RUSTFLAGS, same committed lockfile).
- Equivalence basis for r4-new/r5-new: identical source
  commit, identical release profile, identical flags/lock;
  discovery is IO/DB-bound (~20 dirs/s), so codegen drift
  between two 1.98.1 builds is second-order. Smoke-tested
  (`scan --all` on a scratch repo: exit 0, valid report +
  JSONL events). Per-rep digests stay honest in `.meta.json`
  and the ledger rows above/below.
- Backups now kept outside the shelter for both binaries, so a
  repeat deletion costs a copy instead of a rebuild.
- Remaining order after the stop: r4-new, r5-base, r5-new
  (strict alternation preserved; the killed r5-base partial
  run is discarded, not recorded).