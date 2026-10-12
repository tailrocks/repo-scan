# proof/datasets — deterministic fixture recipes

Each `*.json` file is a frozen, seeded recipe for one benchmark/integration
corpus family required by goal section 7.1. Recipes are inputs to the dataset
generator; they are not generated fixtures and not execution evidence.

## Recipe fields

- `id`, `title`: stable dataset identity used in run manifests.
- `seed`: RNG seed; generation must be deterministic for a given
  (recipe, seed, tool version) triple.
- `scale`: explicit directory/entry/repository/ref counts. Current values are
  pilot-calibration placeholders: every recipe carries
  `"status": "pending_baseline_pilot"` until the baseline-only pilot
  (policy.json `sample_size_selection`) freezes final scales.
- `manifest_schema`: `repo-scan/dataset-manifest/1` — the truth manifest the
  generator emits beside each fixture. Manifests record native path bytes,
  entry kind, repository identity, gitdir/commondir links and ref layouts,
  and are built from the recipe plus safe installed-Git inspection, never
  from repo-scan output.
- `expected_graph`: human-readable graph description plus machine-checkable
  invariants the integration oracle asserts.

## Families

| recipe | family |
| --- | --- |
| `wide-file-heavy.json` | wide file-heavy tree |
| `dir-heavy.json` | directory-heavy tree (PERF-PRIMARY family) |
| `deep-tree.json` | deep tree |
| `huge-git-object-store.json` | huge Git object store |
| `many-tiny-repos.json` | many tiny repositories |
| `many-linked-worktrees.json` | many linked worktrees per common store |
| `many-refs.json` | many refs |
| `independent-clones.json` | independent clones of one remote |
| `ignored-hidden-nested.json` | ignored/hidden nested repositories |

Fixture generation runs offline in dedicated temporary roots; it never
mutates user repositories and never touches the network.
