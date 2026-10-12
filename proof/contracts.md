# Frozen cross-branch contracts (Step 3)

Authority: goal §1.3 + six family ledgers. These decisions bind all integration slices. Changing any requires a recorded policy amendment + rerun of affected evidence.

## C1. Phases
`Discovery → committed inventory_ready → requested Analysis → explicit Fetch → requested refresh/recomparison → final publication`.
- inventory_ready requires: no active discovery workers, no buffered discoveries, no pending retry/metadata expansion, durable children/evidence, honest recorded gaps. Tests observe actual work starts and committed rows (B21 G-b7 order-proof style), not phase counters.
- includeIf/onbranch minimal branch context read = classified+budgeted identity work, not hidden graph enrichment.

## C2. Schema lineage (single migration owner: store/schema.rs chain)
- Producer fingerprints: main v2, B06/B21 v3 (identical blob a70d972c), B21 v4–v6, rescue v7–v9 (B11 blobs 4fe3d92e/cb8971cf/063b3151), supported v1.
- Same number ≠ same structure: main v2 vs B21 v2 are different SQL — fingerprint by DDL hash, normalize transactionally, unknown shapes fail closed with data preserved.
- New integration work uses FRESH version numbers (v10+); never rewrite shipped migration files as the only recovery path.
- Read-only queries never perform hidden upgrades.

## C3. Event lifecycle
- Durable scan identity ≠ execution attempts. Interrupted/retryable-failed attempts retain resume records; terminal notification does not delete dedupe markers needed by continuations (B11 v8 atomic cleanup only at scan-final/supersession).
- Cursor v2 scan-bound (`v2:{b64url(scan_id)}:{seq}:{rev}:{off}`); legacy v1/foreign/malformed/beyond-tip → documented reset or fail-closed. Expired/pruned prefix → FAIL CLOSED (ADJ-02), never reset-snapshot masquerade.
- Replay: prefix check + page read in ONE bounded read transaction, closed before output/wait. Slow reader gets covered replay/reset or explicit gap — never silent skip.
- Progress coalescing retains cursor-advancing visibility (DiscoveryProgressUpdated).
- Privacy: JSONL path-free opaque IDs (`evt:`/`root:` domain-separated SHA-256); owner-local JSON/report retain native paths; comparison via declared projection. Termsink secrets omitted from JSONL (ADJ-03).

## C4. Streaming/privacy/reports (one pipeline)
- Structural base: main's `validate_stream.rs` (non-echoing, 19-field mask, two-pass IDs, 256-problem cap).
- Extend with B21/G-b22: memory-budget pre-flight, 1.5 groups/totals recomputation, per-field byte caps (24MB ID fail-closed), version-gated required fields, multi-version acceptance (envelope 1.0–1.5; schema truth single source).
- NEVER echo raw report_id (ADJ-05). Atomic live report ≠ retained final snapshot ≠ published; retained ≠ published complete.

## C5. Scope and topology
- Fence/alias/cycle/incarnation protections from main survive everywhere. **ADJ-01: restore Topology/TOPOLOGY_SEEN_CAP bounded-seen guard + tests/fail_topo.rs equivalent.**
- Exhaustive vs administrative pruning explicit; finding a repo never silently prunes its working tree.
- Scope keys: roots + volume identities + exclusions + traversal/access/detail policies. Targets/worker counts never cause stale coverage reuse or duplicate scans.

## C6. Outputs and CLI
- Working lanes: single/all/multi-target, JSON, JSONL, plain, TUI (explicit), follow, resume, cached query, live report. No parsed-but-refused lanes remain (B06 tip pattern: wire or remove).
- Backward-compatible defaults; metadata-first = distinct explicit profile (no silent reinterpretation of `summary` default). not_requested/unknown/zero distinct.
- Fetch: explicit opt-in only; `--atomic`; executable repo-config refusal (credential helpers, core.sshCommand, gitProxy, hooks, includes); writes only validated tracking refs; never local heads/HEAD/index/worktree; B11 refspec.rs strictest variant (ADJ-04/06).
- Machine output: valid serialized data only; no prose/ANSI from filenames/remotes/errors.

## C7. Execution architecture
- One catalog owner + one recursion-owning scheduler (B21 G-b8/G-b9 recovered, not duplicated).
- Bounded blocking workers; barrier-proven concurrency; byte+item capped batches; continuous result drainage; slow/network roots isolated admission.
- Durability invariant: parent not durably complete until all discovered child work durable; intermediate batches leave parent incomplete; restart rescans unfinished dirs + dedupes.
- Test failpoints disabled in production build; verified in production binary.

## Conflicts ledger
Recorded in proof/contributions.json open_adjudications (ADJ-01..06) — all ruled above. Merge-tree evidence: family ledgers (B21→main 31 conflicts; B13 31; B14 37; B06 clean).
