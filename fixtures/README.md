# Fixtures

Deterministic inputs for acceptance (§17) and performance (§18). Fixtures are
*generated at test/bench time* by Rust code — this directory holds no checked-in
git repositories, only the corpus declaration and this note.

- Builders: `tests/common/fixture.rs` (installed `git` binary + `tempfile`).
- Builder acceptance: `tests/fixtures_impl.rs` (every builder asserts markers).
- Bench scopes: `benches/support.rs` (`seed_repo`, `traverse`) used by
  `benches/walk_compare.rs` and `benches/scan_cycle.rs`.
- Corpus declaration: `corpus.json` (PERF-02 predeclared corpus).

Bench results are recorded on run to `benches/results/*.jsonl` (gitignored
derived data); nothing under `fixtures/` contains invented measurements.
