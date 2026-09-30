# Troubleshooting

## Lock contention: "another repo-scan owner holds …"

One process owns a state directory at a time
([src/store/owner.rs](/Users/donbeave/Projects/repo-scan/src/store/owner.rs:60)). A second
command waits up to 5 s (`OWNER_WAIT_MAX_MS`,
[src/config.rs](/Users/donbeave/Projects/repo-scan/src/config.rs:130)), then exits `1`
with `owner busy` rather than opening the database independently
([src/main.rs](/Users/donbeave/Projects/repo-scan/src/main.rs:131)). Wait for the running
scan to finish and retry. Never delete `instance.lock` to force progress.

## Cached query reports no suitable catalog (exit 3)

`query URL --cached` reads only existing state and never scans
([src/main.rs](/Users/donbeave/Projects/repo-scan/src/main.rs:3735)). `suitable_catalog: false`
means no catalog or no traversal generation exists yet — run a `scan` first. An
`unresolved` canonical with exit `3` means the URL shape or host alias cannot be
resolved from cached observations alone; no live probe is performed
([src/main.rs](/Users/donbeave/Projects/repo-scan/src/main.rs:3841)).

## Unsafe state dir: "refusing unsafe cache clear"

`cache clear --all` removes only verified tool-owned files (engine file + sidecars,
snapshot/staging files) and refuses symlink substitution anywhere on the reset path
([src/main.rs](/Users/donbeave/Projects/repo-scan/src/main.rs:4159)). If it refuses,
inspect the named path: a symlinked state/payload/snapshots dir or engine file must be
resolved by hand. Unknown files are always preserved and listed, never deleted.

## Interrupted scans (exit 130)

Ctrl-C sets a flag; the owner finishes bounded work, commits what is safe, stages the
report, and exits `130` ([src/main.rs](/Users/donbeave/Projects/repo-scan/src/main.rs:947)).
Leased tasks are requeued by new-epoch recovery on the next open
([src/store/catalog.rs](/Users/donbeave/Projects/repo-scan/src/store/catalog.rs:613)).
Resume with `repo-scan resume SCAN_ID` from any directory — the saved absolute report
destination and options are restored ([src/main.rs](/Users/donbeave/Projects/repo-scan/src/main.rs:4020)).
Note: in-flight breaker-held leases take up to 60 s to expire; a prompt resume may
briefly report them pending (see [docs/REVIEW_WF4.md](/Users/donbeave/Projects/repo-scan/docs/REVIEW_WF4.md) R4).

## Report not published (exit 1, snapshot retained)

Publication failures (no-clobber refusal, `.git`/payload destination, IO error) keep the
staged snapshot in state ([src/main.rs](/Users/donbeave/Projects/repo-scan/src/main.rs:440)).
Re-run `resume SCAN_ID` to retry publication from the saved snapshot without repeating
discovery ([src/main.rs](/Users/donbeave/Projects/repo-scan/src/main.rs:3951)).
