# xtask — repo-scan proof acceptance runner

Implements the executable proof system of
`repo-scan-consolidate-and-optimize-goal.md` section 3. This crate is the
single documented runner; do not add duplicate runners.

## Invocation

```sh
cargo run --locked -p xtask -- proof <subcommand>
```

`xtask` is a workspace member of the repository root (see the `[workspace]`
section in the root `Cargo.toml`). This placement was chosen over a
standalone crate because the goal freezes the `-p xtask` invocation, and
because every xtask dependency (clap, serde, serde_json, sha2, tempfile) is
already in the workspace `Cargo.lock`, so `--locked` stays satisfiable. The
root package remains the default workspace member: existing
`cargo build` / `cargo test` / `cargo bench` invocations in the repository
root keep targeting only the `repo-scan` package, and xtask adds nothing to
the repo-scan dependency graph.

## Subcommands

| command | purpose | exit codes |
| --- | --- | --- |
| `proof inventory` | validate `proof/sources.lock.json` against a live repo (`--repo`), rejecting omitted/extra source refs | 0 PASS, 1 FAIL, 2 invalid lock, 3 repo unavailable |
| `proof baseline` | run a binary against a dataset recipe into `proof-out/<run-id>/` with a run manifest and checksums | 0 collected, 2 invalid inputs, 3 unavailable prerequisites |
| `proof red` | list requirements with empty `green_evidence` | 0 none pending, 1 pending, 2 invalid manifest |
| `proof integration` | run `cargo test --locked --test '*'` (or `--cmd`), classify per-file results, reject skipped/absent mandatory tests | 0 PASS, 1 FAIL, 2 invalid matrix/unrecognized platform, 3 spawn failure |
| `proof benchmark` | paired-block benchmark (`--baseline-bin`/`--candidate-bin`/`--scenario`/`--blocks`) with seeded randomized balanced order, raw JSONL samples | 0 collected, 2 policy violation, 3 unavailable binaries |
| `proof evaluate` | verify run-dir checksums, recompute seeded bootstrap bounds, compare frozen gates, emit verdict JSON | 0 PASS, 1 FAIL, 2 INVALID_EVIDENCE, 3 BLOCKED |
| `proof verify-final` | reconcile requirements, evidence hashes, source coverage for `--commit` | 0 PASS, 1 FAIL, 2 INVALID_EVIDENCE, 3 BLOCKED |

Missing samples, malformed JSON, empty timing arrays, changed policy hashes,
checksum mismatches, unrecognized platforms, and skipped mandatory tests are
never converted into exit 0.

Two anti-cherry-picking rules are enforced by `evaluate` and `benchmark`:

- The block-order/bootstrap seed is frozen in `policy.json`. A manifest (or
  `--seed`) carrying any other seed is INVALID_EVIDENCE.
- `gates_evaluated` must include every gate the policy binds to a scenario
  the run covers (`scenario_mandatory_gates`), and a run covering every
  PERF-SUITE scenario must declare PERF-SUITE. A primary-scenario run
  evaluated only against PERF-NOREGRESS cannot PASS.

`verify-final` additionally loads `proof/experiments.json`: every experiment
needs a disposition of `qualified_enabled` or `evaluated_not_enabled` with
hashed evidence, or `not_triggered` with hashed executed-trigger evidence
(goal section 3.2).

## Run bundles

`baseline`/`benchmark`/`integration` write run directories under
`proof-out/` (gitignored) containing `run-manifest.json`, raw artifacts
(`samples.jsonl`, logs), and `checksums.json` covering every other file.
`evaluate` refuses directories whose checksums do not match exactly.

Measured binaries may print `STAGE <name> <milliseconds>` lines on stdout;
`baseline` parses them into per-sample stage timings.

## Tests

Black-box integration tests only (goal section 3.3); no unit modules:

```sh
cargo test -p xtask --locked
```
