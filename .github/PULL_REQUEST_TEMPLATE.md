<!--
Keep one short paragraph under each prose heading. Describe the shipped outcome and the practical problem it solves, not the implementation history. Do not add a file-by-file changelog or a separate test-results list.

Keep only sections that help reviewers understand this change. Use Related pull requests only for work coordinated across repositories. Keep Behavior changes only when it adds information beyond What ships. Use Not included for a real scope boundary. Include Smoke only for CLI, scanning, or binary-release changes. Include Migration notes only for CLI behavior, configuration, report formats, or persisted state changes.
-->

## Related pull requests

<For work coordinated across repositories, list each related pull request by link only. Drop this section for a change contained in this repository.>

- <https://github.com/org/repo/pull/N>

## Summary

<In one paragraph, state what this pull request changes, who benefits, and how it changes their work.>

## What ships

- <Describe a user-visible or contributor-visible outcome.>
- <Describe another outcome when useful.>

## Behavior changes

<Describe a changed default, validation result, CLI behavior, or runtime effect. Drop this section when it only repeats What ships.>

## What this addresses

- <Name the practical problem, gap, or regression that this change resolves.>

## Not included

- <Name a deferred follow-up or scope boundary. Drop this section when there is none.>

## Verify locally

### Static checks

<For Rust changes, run the relevant formatting, lint, documentation, and workflow checks used by CI. Keep only commands that apply to the files changed.>

```sh
mise --no-config --no-env --no-hooks exec rust@1.98.1 -- cargo fmt --check --manifest-path Cargo.toml
mise --no-config --no-env --no-hooks exec rust@1.98.1 -- cargo clippy --locked --offline --manifest-path Cargo.toml --package repo-scan --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" mise --no-config --no-env --no-hooks exec rust@1.98.1 -- cargo doc --locked --offline --manifest-path Cargo.toml --package repo-scan --no-deps
env -u ACTIONS_ID_TOKEN_REQUEST_TOKEN -u ACTIONS_ID_TOKEN_REQUEST_URL -u ACTIONS_RUNTIME_TOKEN -u GITHUB_TOKEN -u MISE_GITHUB_TOKEN -u GH_TOKEN -u GH_HOST -u GH_CONFIG_DIR mise --no-config --no-env --no-hooks exec actionlint@1.7.12 shellcheck@0.11.0 -- actionlint -color
```

### Tests

<For Rust code changes, run the package tests and doctests used by CI. Drop this section when the change has no testable code.>

```sh
mise --no-config --no-env --no-hooks exec rust@1.98.1 -- cargo test --locked --offline --manifest-path Cargo.toml --package repo-scan --lib --tests
mise --no-config --no-env --no-hooks exec rust@1.98.1 -- cargo test --locked --offline --manifest-path Cargo.toml --package repo-scan --doc
```

### Smoke

<For changes to CLI, scanning, or binary release behavior, build the package and scan a temporary local checkout with the canonical repository remote. Drop this section when there is no runtime surface.>

```sh
mise --no-config --no-env --no-hooks exec rust@1.98.1 -- cargo build --release --locked --offline --manifest-path Cargo.toml --package repo-scan
fixture="$(mktemp -d)"
state="$(mktemp -d)"
output="$(mktemp -d)"
git -C "$fixture" init -q
git -C "$fixture" remote add origin https://github.com/tailrocks/repo-scan.git
./target/release/repo-scan --state-dir "$state" scan https://github.com/tailrocks/repo-scan --root "$fixture" --report "$output/report.json"
```

Expected: the report identifies one `tailrocks/repo-scan` checkout and records the explicit fixture root.

## Migration notes

<State what existing users must do for CLI, configuration, report-format, or persisted-state changes. Drop this section when no migration is needed.>
