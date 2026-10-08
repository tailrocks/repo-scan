<!--
Rules:
- Use one paragraph per section, with no hard wrapping.
- Describe the user or maintainer outcome, not a file-by-file changelog or a list of functions and tests.
- Keep only sections that add useful information; remove every unused heading and its guidance.
- Include Verify-locally blocks only for the repository paths named below. Use commands exactly as written and state expected results for smoke checks.
-->

## Summary

<In one short paragraph, say what this change does and who benefits.>

## What ships

<Keep the bullets that describe outcomes visible to users or maintainers.>

- <User or maintainer outcome>
- <Configuration, documentation, or verification outcome>

## Behavior changes

<Keep this section only when changes to `src/`, `.velnor/`, or `.github/` change CLI behavior, scan results, stored state, or CI behavior. Describe the observable change.>

- <Observable behavior change>

## What this addresses

<Keep this section when the change resolves a specific problem, regression, or documented roadmap item; name it and state the practical outcome.>

- <Problem or gap addressed>

## Not included

<Keep this section only when the change has a useful boundary, such as work deferred from `src/`, `.velnor/`, or `.github/`.>

- <Deferred or out-of-scope behavior>

## Verify locally

### Static checks

<Keep for changes to Rust sources or tests, `Cargo.toml`, `.velnor/`, or `.github/`.>

```sh
mise --no-config --no-env --no-hooks exec rust@1.98.1 -- cargo fmt --check --manifest-path Cargo.toml
mise --no-config --no-env --no-hooks exec rust@1.98.1 -- cargo clippy --locked --offline --manifest-path Cargo.toml --package repo-scan --all-targets -- -D warnings
```

### Tests

<Keep for changes to Rust sources or tests, `Cargo.toml`, `.velnor/`, or `.github/`.>

```sh
mise --no-config --no-env --no-hooks exec rust@1.98.1 -- cargo test --locked --offline --manifest-path Cargo.toml --package repo-scan --lib --tests
mise --no-config --no-env --no-hooks exec rust@1.98.1 -- cargo test --locked --offline --manifest-path Cargo.toml --package repo-scan --doc
```

### Smoke

<Keep when `src/cli.rs`, `src/main.rs`, or the command examples in `README.md` change.>

```sh
mise --no-config --no-env --no-hooks exec rust@1.98.1 -- cargo build --release
target/release/repo-scan --state-dir target/repo-scan-smoke-state scan https://github.com/tailrocks/repo-scan --root . --status metadata --report target/repo-scan-smoke.json
```

Expected: writes a JSON report for this checkout and exits with a usable scan result.

## Migration notes

<Keep when `src/store/schema*.rs` or persistent scan-state compatibility changes. Describe how existing local state is read or upgraded; otherwise remove this section.>
