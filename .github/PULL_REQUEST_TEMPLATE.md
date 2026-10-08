<!--
Write one short paragraph under each prose heading. Describe the shipped outcome and the problem it solves, not the implementation history. Do not add a file-by-file changelog or a full test list; the diff and check output already show those details.

Keep only sections this change needs. Include Related pull requests only for coordinated work across repositories. Include Not included only when a real scope boundary helps reviewers. Include Migration notes only when CLI behavior, configuration, report formats, or persisted state changes. Include Smoke only for changes to command-line or scanning behavior.
-->

## Related pull requests

<For coordinated work across repositories, list each related PR. Drop this section for a standalone change.>

- <Add a link to a related PR in another repository.>

## Summary

<State what this PR adds or changes and who benefits.>

## What ships

- <Describe a user-visible or contributor-visible outcome.>
- <Describe another outcome when useful.>

## What this addresses

- <Name the practical problem, gap, or regression resolved.>

## Not included

- <Name a deferred follow-up or scope boundary. Drop this section when there is none.>

## Verify locally

### Static checks

<For Rust source changes, run the repository format and lint checks used by CI.>

```sh
cargo fmt --check --manifest-path Cargo.toml
cargo clippy --locked --offline --manifest-path Cargo.toml --package repo-scan --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --offline --manifest-path Cargo.toml --package repo-scan --no-deps
```

### Tests

<For Rust source changes, run the repository test suites used by CI.>

```sh
cargo test --locked --offline --manifest-path Cargo.toml --package repo-scan --lib --tests
cargo test --locked --offline --manifest-path Cargo.toml --package repo-scan --doc
```

### Smoke

<For CLI or scanning changes, build the binary and scan a temporary local checkout with the canonical repo-scan remote. The report should identify one local checkout. Drop this section for changes without a runtime surface.>

```sh
cargo build --release
fixture="$(mktemp -d)"
state="$(mktemp -d)"
git -C "$fixture" init -q
git -C "$fixture" remote add origin https://github.com/tailrocks/repo-scan.git
./target/release/repo-scan --state-dir "$state" scan https://github.com/tailrocks/repo-scan --root "$fixture" --report "$state/report.json"
```

Expected: the report contains one checkout for `tailrocks/repo-scan` and records the explicit fixture root.

## Migration notes

<For CLI, configuration, report-format, or persisted-state changes, state what an existing user must do. Drop this section when no migration is required.>
