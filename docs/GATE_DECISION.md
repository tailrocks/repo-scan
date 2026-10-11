# Gate and destination record (2026-09-30)

## Implementation destination

- Project directory: this checkout (repo root; in place; the
  directory is already named `repo-scan` and contains only spec/goal docs, so
  it is the designated implementation checkout — no nested `repo-scan/`
  created, no unrelated repo overwritten).
- Branch: `main` (single integration branch).
- Remote: none authorized. Local commits only; no public repo created.
- Toolchain: cargo/rustc 1.98.1, git 2.56.0, macOS.
- Pinned deps verified present on crates.io: turso 0.8.1, dua-core 4.1.0,
  gix newest 0.88.0 (2026-09-30).
