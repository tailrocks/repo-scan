# proof/datasets — deterministic fixture recipes

Each `*.json` file is a frozen, seeded recipe for one benchmark/integration
corpus family required by goal section 7.1. Recipes are inputs to the dataset
generator; they are not generated fixtures and not execution evidence.

## Recipe fields

- `id`, `title`: stable dataset identity used in run manifests.
- `seed`: RNG seed; generation is deterministic for a given
  (recipe, tier, seed, generator version, git version) tuple.
- `scale`, `scale_pilot`, `scale_smoke`: explicit
  directory/entry/repository/ref counts for the FINAL target scale, the
  M5-Max pilot scale (measurable in seconds), and the CI smoke scale. Every
  recipe carries `"status": "pending_baseline_pilot"` until the
  baseline-only pilot (policy.json `sample_size_selection`) freezes final
  scales; pilot/smoke tiers are concrete and usable today.
- `manifest_schema`: `repo-scan/dataset-manifest/1` — the truth manifest the
  generator emits beside each fixture. Manifests record native path bytes,
  entry kind, repository identity, gitdir/commondir links and ref layouts,
  and are built from the recipe plus safe installed-Git inspection, never
  from repo-scan output.
- `expected_graph`: human-readable graph description plus machine-checkable
  invariants the integration oracle asserts.

## Generating a fixture

The generator is the `corpus` bench binary (`benches/corpus.rs`,
`harness = false`; `cargo run` has no `--bench` selector, so the invocation
goes through `cargo bench`):

```sh
cargo bench --bench corpus -- --recipe <id-or-path> --out <dir> [--tier smoke|pilot|full]
```

- `--recipe` accepts a recipe id (resolved under `proof/datasets/`, same rule
  as `xtask proof baseline --dataset`) or a direct JSON file path.
- `--tier` defaults to `pilot`.
- `<dir>` must be absent or empty (the generator refuses otherwise).
  Everything lands under it: `<dir>/tree/` is the corpus root a benchmark
  scans, `<dir>/manifest.json` is the truth manifest, `<dir>/stage/` is a
  scratch area that is removed before the run returns. Generation never
  writes outside `--out`, never touches the network, and never mutates user
  repositories.
- Stdout prints `STAGE generate|inspect|digest <ms>` markers (parseable by
  `xtask proof baseline`), a one-line summary, and the manifest path.

## Manifest format (repo-scan/dataset-manifest/1)

- `recipe_sha256`: SHA-256 of the recipe file bytes; `parameters_sha256`:
  SHA-256 of the canonical `{scale, seed, tier}` JSON actually used.
- `root`: absolute corpus root; all repository/worktree paths are relative
  to it. Paths that are not valid UTF-8 are recorded as `path_b64` (standard
  base64 of the raw relative bytes) with `path: null`.
- `repositories[]`: `kind` (`checkout` | `bare` | `linked_worktree`),
  `is_bare`, `git_dir`, `common_dir`, `head` (`state`:
  branch|detached|unborn|broken, `ref` = immediate HEAD symref target via
  `git symbolic-ref --no-recurse`, `oid`), full `refs` (name+oid, from
  `git for-each-ref`), `remotes`, and the store's `worktrees`.
- `worktrees[]`: de-duplicated union of `git worktree list --porcelain`
  across all repositories.
- `counts`: realized on-disk totals (including git internals) plus
  repos/common_stores/worktrees/refs totals.
- `special_entries`: `non_utf8` (with `created: false` +
  `non_utf8_supported: false` on hosts rejecting invalid-UTF-8 names, e.g.
  macOS/APFS — an explicit unavailable capability, never a silent skip) and
  `permission_denied` (chmod-000 dirs, unix).
- `tree_sha256`: root-independent fixture hash (`corpus-digest-v1`).

## corpus-digest-v1

SHA-256 over a sorted, line-based stream (raw path bytes hex-encoded):
`D` dir, `F` file (length + content SHA-256), `L` symlink, `X` unreadable
entry, `G` git admin file whose content is volatile or root-bound (config,
index, logs, commondir/gitdir link files, any file named `.git`), and `R`
gitdir records carrying a state hash of refs/HEAD/remotes/gitdir-commondir
links/worktrees from installed-git inspection. Inside a gitdir only `HEAD`,
`description`, `packed-refs`, `objects/**` and `refs/**` contents are hashed.
Identical (recipe, tier, seed, generator version, git version) tuples produce
identical `tree_sha256` in any output root.

## Families

| recipe | family |
| --- | --- |
| `wide-file-heavy.json` | wide file-heavy tree (+ non-UTF-8 ordinary names) |
| `dir-heavy.json` | directory-heavy tree (PERF-PRIMARY family; + permission-denied dirs) |
| `deep-tree.json` | deep tree |
| `huge-git-object-store.json` | huge Git object store |
| `many-tiny-repos.json` | many tiny repositories |
| `many-linked-worktrees.json` | many linked worktrees per common store |
| `many-refs.json` | many refs (loose+packed, symbolic/detached/unborn HEAD) |
| `independent-clones.json` | independent clones of one remote |
| `ignored-hidden-nested.json` | ignored/hidden nested repositories (incl. `.git/objects/<fanout>/` administrative nesting) |

Fixture generation runs offline in dedicated temporary roots; it never
mutates user repositories and never touches the network.

## Benchmark custodian flow

1. Generate: `cargo bench --bench corpus -- --recipe <id> --out $RUN/fixture --tier pilot`.
2. Scan `$RUN/fixture/tree` with the binary under test.
3. Compare the scan's repository/worktree/common-store/ref sets against
   `$RUN/fixture/manifest.json` (`repositories`, `worktrees`, `counts`); the
   manifest is the sole truth source (TDD-04: built from recipe + installed
   git, never from repo-scan output).
4. Record `tree_sha256`, `recipe_sha256`, and `parameters_sha256` in the run
   evidence to bind results to the exact fixture.
