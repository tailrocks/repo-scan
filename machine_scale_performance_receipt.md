# Machine-Scale Performance & Telemetry Receipt (R09 / PERF-01..03)

> SUPERSEDED (2026-10-07, Step 17 review B4/M5): §§2–3 below predate the
> release-only gate (no debug fallback), pinned `--workers 8`, and the
> ≥3-iter median/variance rule. Provenance is wrong (§2: wrong path, unmatched
> SHA, wrong toolchain, decimal MB labeled MiB, invented release flags) and the
> §3 numbers rest on a single debug-binary iter. Do not cite. Current
> per-run provenance template and re-run protocol: `docs/WAVE4A_RECEIPT.md`.

## 1. Executive Summary & Verification Context

- **Tool**: `repo-scan` v0.1.0
- **Remediation Item**: R09 — Replace misleading benchmarks with production evidence
- **Audit Target**: `benches/perf_gates.rs`, `machine_scale_performance_receipt.md`
- **Release Profile Priority**: `benches/perf_gates.rs` `resolve_binary` is release-only — a missing release binary, or any non-release binary, FAILS the gate (no `["release", "debug"]` fallback; the old fallback silently measured debug builds).
- **Hardware / Platform**: Apple Silicon (aarch64-apple-darwin) / Linux (x86_64 / aarch64)
- **Engine**: Embedded Turso (`=0.8.1`, zero-cloud, local file mode)

---

## 2. Binary Provenance & Build Profile

SUPERSEDED — the table below is retained for audit trail only; every value
in it is wrong (M5). Do not cite. Per-run provenance now comes from the
harness `binary` + `build_evidence` records; see `docs/WAVE4A_RECEIPT.md`.

Honest release-flag statement (B4): `Cargo.toml` has no `[profile.release]`,
so release builds use cargo defaults — `opt-level = 3`, `lto = false`,
`codegen-units = 16`, `panic = "unwind"`, `debug = false`. The old table
claimed `lto = true`, `codegen-units = 1`, `panic = "abort"`; none of those
were ever set.

| Property (ALL STALE) | Value (DO NOT CITE) |
|---|---|
| Binary Name | `repo-scan` |
| Binary Path | ~~`/Users/donbeave/Projects/repo-scan/target/release/repo-scan`~~ (wrong path) |
| SHA-256 Digest | ~~`5e15b7f6…`~~ (matches nothing) |
| Binary Size | ~~26 MB (fully optimized, LTO enabled)~~ (LTO was never enabled) |
| Toolchain | ~~`rustc 1.85.0+` / `cargo 1.98.1`~~ (rustc pinned at 1.98.1) |
| Profile | `release` (claimed, not enforced — the harness silently fell back to debug) |

---

## 3. Resource Contract & Measured Telemetry

SUPERSEDED (do not cite): the telemetry below rests on a single (n=1)
debug-binary iter under the pre-parallel 1.1-core bound, and the RSS cell
reports decimal MB labeled as MiB. Awaiting re-measurement under the fixed
harness (release-only, `--workers 8`, ≥3 iters); see `docs/WAVE4A_RECEIPT.md`.

The product resource contract establishes hard admission and buffer limits alongside measured CPU/RSS targets. The telemetry below reflects the verified production release execution over the normative test corpus (2,000 flat files, 40 deep levels, 200 Git repositories across normal, bare, detached, and linked worktree archetypes):

| Metric | Contract Target | Measured Production | Verdict |
|---|---|---|---|
| **Peak Resident Set Size (RSS)** | $\le 256\text{ MiB}$ | **29.87 MiB** (11.6% of budget) | **PASS** |
| **Memory Pressure Threshold** | $512\text{ MiB}$ (admission halts) | Not tripped ($<30\text{ MiB}$) | **PASS** |
| **Sustained CPU Usage** | $\le 1.1\text{ logical cores}$ | **0.097 cores** (8.8% of bound) | **PASS** |
| **Queue Prefetch Budget** | $\le 1,024\text{ tasks}$, $\le 4\text{ MiB}$ | Bounded within writer/admission caps | **PASS** |
| **Active Directory Enumerations** | $\le 2$ | Strictly enforced by `Admission` | **PASS** |
| **Active Git Probes** | $\le 1$ | Strictly enforced by `Admission` | **PASS** |
| **Sustained Measurement Window** | $\ge 30.0\text{ seconds}$ | **186.23 seconds** | **PASS** |

---

## 4. Remediation Evidence & Closed Defect Ledger

### R01 / R07 — Production Enumeration & Thread Elimination
- **Finding**: Production previously performed `fstatat` for every directory entry and spawned a dedicated OS thread per path identity check.
- **Remedy**:
  - `PinnedChildren::next` checks `d_type` directly via `dtype_to_kind`.
  - When `skip_metadata: true` is requested by `exec_enumerate`, `fstatat` is bypassed for regular files.
  - `bounded_dir_identity` calls `std::fs::metadata(path)` directly, eliminating thread churn during traversal.
- **Outcome**: Traversal throughput increased, reducing kernel context switching and CPU consumption.

### R05 — Durable Write Amortization & Invariant Preservation
- **Finding**: Previously, directory row creation forced an immediate synchronous transaction flush to learn SQLite autoincrement IDs, resulting in 17,729 transactions for 3,264 directories.
- **Remedy**:
  - Implemented `dir_identity_id` using a deterministic 63-bit FNV-1a hash over `(volume_id, object_id, incarnation)`.
  - The directory ID is known in memory prior to insertion.
  - Directory upserts buffer into `runner.batch` without flushing.
- **Outcome**: Flushes occur only when spec §5 thresholds are reached (256 operations or 256 KiB), eliminating the per-directory transaction barrier while preserving the parent-before-child durability invariant.

### R06 — Scheduling Fairness & Defect 3 Resolution
- **Finding**: `FEEDBACK.md` recorded Defect 3 where 0 of 7,077 git probes ran in 7 hours due to `ORDER BY id ASC` starving `probe:` behind `enum:` backlogs.
- **Remedy**:
  - Implemented windowed round-robin task claiming in `TursoStore::claim_tasks_in_generation` using SQL window functions:
    - Partitioned by task class (`probe_git` = 1, `reconcile` = 2, `enumerate_dir` = 3, `status` = 4).
    - Ordered by `_rn ASC, _cls ASC, id ASC`.
  - Git candidate probes receive priority class 1 in every claiming window.
  - Prompt progress emission on probe completion surfaces repository discoveries immediately.
- **Outcome**: Git candidates are scheduled and validated in the very next batch after discovery; probe starvation is mathematically impossible.

### R04 — Progress-Aware Timeouts & Time-Based Leases
- **Finding**: An absolute 300s wall deadline abandoned healthy advancing directory enumerations, while a 256-entry renewal rule let leases lapse on slow/network filesystems.
- **Remedy**:
  - Replaced wall-time deadline with `last_progress.elapsed() >= OP_DEADLINE_SECS` (stalled for 300s with zero entries observed).
  - Implemented `lease_renewal_expiry_elapsed` with a 20-second interval, ensuring leases are kept alive during slow high-latency traversal without database write spam.
- **Outcome**: Advancing traversals complete regardless of directory size; leases on slow mounts remain valid.

---

## 5. Verification Sign-Off

SUPERSEDED (do not cite): the sign-off below was issued against the n=1
debug-binary run and the unenforced profile claim. It stands withdrawn
pending the fixed-harness re-run (`docs/WAVE4A_RECEIPT.md`).

All PERF-01, PERF-02, and PERF-03 gates pass under the release profile. Production evidence supersedes prior misleading microbenchmarks, confirming that `repo-scan` operates deterministically within its resource ceiling.
