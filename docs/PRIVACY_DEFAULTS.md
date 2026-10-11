# Privacy Defaults (CONSUMER-SCOPE-PRIVACY-001)

All tool and fixture outputs are owner-only by default: directories `0o700`,
files `0o600` (unix). No group/other read, write, or traversal.

## Constructors

One creation primitive, two thin call layers (RS-PRIV-05/07):

- `ensure_private_dir_all` ([src/store/owner.rs](../src/store/owner.rs))
  is the single ancestor-pinned creation primitive: the nearest
  existing ancestor is bound through an `O_NOFOLLOW|O_DIRECTORY` FD
  (a symlinked ancestor is refused, never followed), each missing
  component is created with `mkdirat`/`openat` relative to the pinned
  parent FD, modes are tightened with `fchmod` on the FD (never the
  path), and the bound `(dev, ino)` re-verifies against the path so a
  transient ancestor swap is refused loudly instead of silently
  trusted. No `canonicalize`-then-trust anywhere on this path.
- General outputs — [src/privacy.rs](../src/privacy.rs):
  `private_dir_0700(path)` routes through that primitive (`0o700`);
  `private_file_0600(path)` (exclusive `O_CREAT|O_EXCL|O_NOFOLLOW`
  create, `0o600`) and `private_write_0600(path, bytes)`
  (create-or-truncate, `O_NOFOLLOW`, `0o600`) apply the mode with
  `fchmod` on the open FD. Used by report/log/scratch writers and
  test fixtures.
- State layout — [src/store/owner.rs](../src/store/owner.rs):
  `ensure_private_dir_all` plus the `instance.lock` creation in
  `OwnerGuard::acquire` (likewise `fchmod`-on-FD). Same
  `0o700`/`0o600` contract.

Both refuse symlinked targets (fail closed, never write through a
link) and apply modes explicitly, so the result never depends on
the caller's umask. Parents are not created by the file
constructors — build them with `private_dir_0700` first.

## Scope

- State, payload, staging, snapshot, report, and log paths go
  through these constructors (state layout via `owner.rs`, the
  rest via `privacy.rs`).
- Test fixtures: every builder in `tests/common/fixture.rs` and
  fixture construction across `tests/` create roots via
  `private_dir_0700` / `private_write_0600` / `private_file_0600`;
  scratch roots come from `fixture::scratch_root()` (fresh
  tempdir pinned under `/tmp`, `0o700`). Fixtures never touch
  machine-wide paths. Reads, queries, removals, permission-probing
  setup, and `io::ErrorKind`-matching platform probes stay raw —
  only directory/file construction goes through the helpers.

## Verifying

- Regression test `private_constructors_enforce_owner_only` in
  `src/privacy.rs` asserts modes, `O_EXCL` rerun failure, and symlink
  refusal (builder runs `cargo test`; workers never run cargo here).
- Manual: `stat -c '%a %n' <state_dir> <state_dir>/payload/*` must show
  `700` dirs and `600` files.
