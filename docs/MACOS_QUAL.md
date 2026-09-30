# macOS integration qualification (spec §§7+13)

Date: 2026-09-30. Survey from local SDK header, local crate sources, crates.io / docs.rs.
Normative spec: `repo-scan-spec.md` §§7 (scope/topology/paths), 13 (incremental discovery).

## 1. Recommended crate + API per function

### 1.1 FSEvents history: `objc2-core-services` 0.3 + `objc2-core-foundation` 0.3 (RECOMMENDED)

Use `objc2-core-services` with features `FSEvents` (+ `libc`, + `dispatch2` for queue
scheduling) and `objc2-core-foundation` for `CFUUID`/`CFArray`/`CFString` types.
It is the only surveyed Rust binding that exposes the full §13 surface:

| Function | Need | objc2-core-services 0.3.2 |
|---|---|---|
| `FSEventStreamCreateRelativeToDevice` | per-volume stream from stored cursor | bound (`FSEvents`+`libc`) |
| `FSEventsCopyUUIDForDevice` | volume history identity | bound (`FSEvents`+`libc`) |
| `FSEventStreamGetLatestEventId` | persistable cursor | bound (`FSEvents`) |
| `FSEventsGetCurrentEventId` | observation boundary | bound (`FSEvents`) |
| `FSEventStreamSetDispatchQueue` | non-deprecated scheduling (runloop API deprecated macOS 13+) | bound (`dispatch2`+`FSEvents`) |
| `FSEventsGetLastEventIdForDeviceBeforeTime` | conservative restart cursor | bound |
| `kFSEventStreamCreateFlagNoDefer` / `FileEvents` / `FullHistory` / `WatchRoot` / `MarkSelf` | stream behavior | bound |
| `CFUUIDGetUUIDBytes` / `CFUUIDCreateString` | UUID persistence | in `objc2-core-foundation` 0.3.2 |

Per-volume streams (`...RelativeToDevice`, `dev_t` from `stat`) are required: the SDK
documents cursor+UUID reuse specifically against `CreateRelativeToDevice`, and per-host
IDs can conflict across volumes imported from other machines. Event IDs are
"guaranteed to always be increasing, usually in leaps and bounds" — never assume
consecutive (spec §13 already requires this).

Flag selection per stream: `FileEvents | NoDefer | WatchRoot | FullHistory`
(`FullHistory` needs macOS 10.15+; gate or set 10.15 floor). Notes:

- `NoDefer` only changes latency accounting (first event after idle is immediate);
  it does not gate historical delivery — history comes from a real `sinceWhen`.
- `FullHistory` returns the whole first chunk containing `sinceWhen` (even IDs below
  it), closing the unclean-restart gap. Ingestion must therefore tolerate duplicate /
  already-reconciled IDs idempotently.
- `IgnoreSelf`/`MarkSelf` have **no effect on historical events** (pre-`HistoryDone`).
  Self-event suppression must be identity+operation evidence on the reconciler side
  (spec §13), never a stream flag.
- `WatchRoot` yields `RootChanged` with event ID **zero**; never persist 0 as a cursor.
- `UseExtendedData`/`WithDocID` (10.13+/10.15+) are optional; file IDs can also be
  re-observed via `getattrlistbulk` (see §1.3). Defer unless measured necessary.

### 1.2 Rejected / insufficient alternatives (evidence, not preference)

- `fsevent-sys` **4.1.0** (currently in `Cargo.toml`, `fsevent-sys = "4"`): binds
  `Create`, `CreateRelativeToDevice`, `GetLatestEventId`, `GetCurrentEventId`,
  `GetLastEventIdForDeviceBeforeTime` — but `FSEventsCopyUUIDForDevice` and
  `FSEventStreamSetDispatchQueue` are commented out. No UUID = no §13. Replace.
- `fsevent-sys` **5.x** (latest 5.2.0, 2025-11-17; deps `core-foundation ^0.10`,
  `dispatch2 ^0.3`): master adds `SetDispatchQueue` but `FSEventsCopyUUIDForDevice`
  is still commented out. Viable only with an app-owned UUID `extern` block; no
  advantage over objc2.
- `fsevent` safe wrapper (latest 2.3.0): `new()` hardcodes
  `since_when = kFSEventStreamEventIdSinceNow` with no public cursor setter.
  Live-watch only; unsuitable for persistent history.
- `notify` (main `fsevent.rs`): hardcodes `since_when = ...SinceNow`, discards
  `HistoryDone` (translates to zero events), exposes no cursor/UUID persistence.
  Live-watch only; unsuitable for §13. (notify 8.x used `fsevent-sys`; notify 9
  moved to `objc2-core-services` — same direction as this recommendation.)

### 1.3 Volume / mount / file identity: `libc` (already a transitive dep; add direct)

All symbols verified present in `libc` 0.2.182–0.2.189 `src/unix/bsd/apple/mod.rs`:

| Function | API | Use |
|---|---|---|
| mount table | `getfsstat` (`MNT_NOWAIT`), `statfs` struct (`f_flags`, `f_fstypename`, `f_mntonname`, `f_mntfromname`) | enumerate roots; `MNT_LOCAL`/`MNT_ROOTFS`/`MNT_SNAPSHOT`/`MNT_DONTBROWSE`/`MNT_AUTOMOUNTED` classify local/network/snapshot/hidden (§7 volume kinds; header also advises `MNT_LOCAL` check on Mount events) |
| volume UUID | `getattrlist(2)` with `ATTR_VOL_UUID` per mountpoint | stable volume identity independent of `dev_t` (dev numbers may change across reboots) |
| file identity (bulk) | `getattrlistbulk` on dirfd with `ATTR_CMN_NAME` + `ATTR_CMN_RETURNED_ATTRS` (both mandatory) + `ATTR_CMN_FILEID`/`OBJID` | (dev,fileID) identity during enumeration without per-entry `stat` |
| symlink/canonicalization probes | `getattrlistat` + `FSOPT_NOFOLLOW`, `freadlink` | lstat-like identity for topology layer |

Constraints from the `getattrlistbulk` man page: bulk vends the link itself for
symlinks (lstat semantics); volume attributes **cannot** be requested via bulk
(use per-path `getattrlist` for `ATTR_VOL_UUID`); entry order unspecified;
`ATTR_CMN_FULLPATH` may be invalid — never depend on it.

`dev_t` from `stat` remains the key into FSEvents (`CreateRelativeToDevice`,
`GetDeviceBeingWatched`, `CopyUUIDForDevice`) but must always be paired with the
stored UUID: on mismatch the cursor is invalid (reformat/replace/purge/wrap).

### 1.4 Firmlink / APFS Data-volume alias handling: identity dedupe, no special API

APFS volume groups stitch System and Data volumes with firmlinks: one file appears
at multiple paths on different group volumes but is stored once (roles: System,
Data, Recovery, VM, Preboot, …). repo-scan must NOT special-case path prefixes or
trust `realpath` alone (spec §7). Handling:

1. Enumerate every mounted volume from `getfsstat`, including `/System/Volumes/Data`
   and the firmlink-stitched `/` view.
2. Dedupe objects by `(volume-UUID, fileID)`; record each discovered pathname as an
   `Alias` (`firmlink`/`mount_alias`/`same_object` kind per report schema) instead of
   collapsing or double-scheduling.
3. Cross-volume scheduling: crossing a `dev_t`/UUID boundary creates work for that
   volume (spec §7), it never silently discards.
4. FSEvents gives one history/UUID per volume; the Data volume and the System volume
   have independent cursors. A firmlinked path change surfaces on the volume that
   owns the data; reconciler maps event path → owning volume via mount table.

## 2. Cursor / UUID persistence plan (spec §§11+13)

Per-volume record (extends `Volumes and roots` + `Event journal` entities):

- `fsevents_uuid`: text from `CFUUIDCreateString`/`GetUUIDBytes` at stream setup.
- `ingested_cursor`: highest event ID durably recorded (advance only with the
  commit that stores its invalidations).
- `reconciled_cursor`: highest ID whose required work is satisfied (advance only
  when the recorded boundary's work is done). Separate columns, separate advances.
- `flags_seen`: wrap/drop/root-changed markers for audit.

Protocol:

1. **Monitor before traverse.** Create + start the stream (with stored cursor or
   `SinceNow`) before the initial traversal; rescan any subdirectory modified
   during scanning rather than comparing timestamps (Apple "Important" note).
2. **Open rule.** Reuse stored `(uuid, cursor)` only if `CopyUUIDForDevice(dev)`
   is non-NULL, equals stored UUID, and `GetCurrentEventId() >= cursor`. If the
   live ID is *lower* than stored → backup-restore/wrap/purge: cursors invalid.
3. **Boundary.** At scan start record `boundary = FSEventsGetCurrentEventId()`.
   Completion is claimed relative to this per-volume boundary; later arrivals stay
   queued past it (spec §13: no waiting for global quiet).
4. **Ingest.** Callback batches → bounded queue (spec §5 batch caps; coalesce
   same-directory invalidations) → writer actor commits `(uuid, ingested_cursor)`.
   `HistoryDone` sentinel ends the historical phase; ignore its path. Tolerate
   `FullHistory` overlap (IDs ≤ cursor) via idempotent upsert.
5. **Reconcile.** Scheduler turns invalidations into frontier tasks; on completion
   advances `reconciled_cursor`. Must-scan-subdirs path ⇒ recursive re-inspection
   task for exactly that subtree.

## 3. Fallback when history unavailable

Any of these invalidates the stored cursor for the affected volume and forces
reconciliation (never silent reuse):

| Signal | Meaning | Response |
|---|---|---|
| `CopyUUIDForDevice` NULL | no historical events (e.g. read-only / unsupported volume) | stream with `SinceNow` only; volume marked eventless — full traversal + periodic re-reconciliation; honest gap |
| UUID mismatch | reformat / replace / purge / different disk same name | discard cursors, invalidate volume scope, fresh traversal generation |
| live ID < stored cursor | restore-from-backup / wrap / purge | same as mismatch |
| `EventIdsWrapped` | 64-bit counter wrapped; all prior IDs invalid | same as mismatch |
| `MustScanSubDirs` (±`UserDropped`/`KernelDropped`, informational only) | coalescing / buffering overrun | recursive rescan task for the event path (whole watched roots if stream-level) |
| `RootChanged` (id 0) | watched root moved/deleted | rescan hierarchy; re-resolve root identity; never store 0 |
| `Mount` / `Unmount` under watch | topology change | mount-table refresh; new volume ⇒ new UUID/cursor row; uncovered hierarchy ⇒ invalidation |
| history gap too large to bound | burst exceeds IPC/queue caps | coalesce to ancestor invalidation; keep pending-work accounting exact |

Conservative restart alternative: `FSEventsGetLastEventIdForDeviceBeforeTime(dev, t)`
yields a cursor guaranteed not to miss events since `t` (may replay extras — safe
under idempotent ingest). Use after ambiguous shutdown when the last committed
`ingested_cursor` is uncertain. Never call `FSEventsPurgeEventsForDeviceUpToEventId`
(not root; destroys other consumers' history). Periodic full reconciliation stays a
documented policy: event history is an optimization, not proof of eternal
completeness.

## 4. Linux-fixture seams

Native calls stay behind narrow traits in `platform/` so Linux CI exercises the
reconciler/scheduler without macOS (spec §§4, 17: Linux fixtures + mandatory native
macOS evidence before claiming macOS support):

- `platform::events::EventSource` trait: `open(volume, Option<(Uuid, CursorId)>)
  -> EventStream`; `EventStream: Iterator<Item = EventBatch>` with `fn boundary()`.
  macOS impl (`platform::events::fsevents`, `cfg(target_os = "macos")`) wraps §1.1.
- `platform::events::mock_log`: scripted `Vec<EventBatch>` replay including
  `HistoryDone`, dropped/coalesced flags, wrap, UUID change, NULL-UUID volumes —
  drives EVENT-01/EVENT-02 acceptance fixtures on Linux.
- `platform::topology::{MountTable, VolumeId, FileId}` traits: macOS impl via §1.3;
  fixture impl returns canned `statfs`-shaped rows (APFS System/Data pair with
  shared fileIDs across mountpoints for firmlink tests, FS-03).
- Cursor store (`store::event_journal`) is platform-free: tested against the mock
  log on Linux (ingestion/reconciliation crash points, EVENT-02); macOS target
  adds an integration test asserting real `CopyUUIDForDevice` round-trips.
- No `notify`/`fsevent` wrapper dependency: the seam is at the raw history API,
  which neither wrapper exposes (§1.2).

## Evidence

- SDK header `FSEvents.h` (MacOSX.sdk, inspected locally): persistence/cursor+UUID
  contract lines 124–136; `CopyUUIDForDevice` NULL/mismatch semantics 976–1009;
  non-consecutive increasing IDs 700–715; `sinceWhen` contract 752–761;
  `NoDefer` 221–238; `FullHistory` 297–308; `IgnoreSelf`/`MarkSelf` no-history
  effect 257–284; `WatchRoot`/`RootChanged` 240–255, 437–448; dropped flags
  informational 400–414; wrap 416–422; `HistoryDone` 424–435; Mount/`MNT_LOCAL`
  450–463; Unmount 465–476; runloop deprecated → dispatch queue 1162, 1192, 1197+;
  `GetLastEventIdForDeviceBeforeTime` conservative 172–178, 1013–1019.
- Apple File System Events Programming Guide (Using the FSEvents Framework):
  monitor-before-scan; per-host/per-disk ID uniqueness; UUID re-verification across
  reboots; lower-than-stored ID ⇒ invalid; snapshot+compare pattern.
  <https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html>
- `fsevent-sys` 4.1.0 `src/fsevent.rs` (local cargo registry): full flag consts +
  `Create`/`CreateRelativeToDevice`/`GetLatestEventId` bound; `SetDispatchQueue`
  (line 112) and `FSEventsCopyUUIDForDevice` (line 125) commented out.
- `fsevent-sys` master `src/fsevent.rs` (5.x): `SetDispatchQueue` added via
  `dispatch2`; `FSEventsCopyUUIDForDevice` still commented out.
  <https://raw.githubusercontent.com/octplane/fsevent-rust/master/fsevent-sys/src/fsevent.rs>
- crates.io API: `fsevent-sys` latest 5.2.0 (2025-11-17); 5.2.0 deps
  `core-foundation ^0.10.1` + `dispatch2 ^0.3`.
  <https://crates.io/api/v1/crates/fsevent-sys>
  <https://crates.io/api/v1/crates/fsevent-sys/5.2.0/dependencies>
- `fsevent` 2.3.0 `src/lib.rs` (master): `new()` hardcodes `SinceNow`, no public
  cursor setter (lines ~204–211).
  <https://raw.githubusercontent.com/octplane/fsevent-rust/master/src/lib.rs>
- crates.io API: `fsevent` latest 2.3.0 (2025-11-17).
  <https://crates.io/api/v1/crates/fsevent>
- `notify` main `notify/src/fsevent.rs`: `since_when: ...SinceNow` hardcoded
  (line 393); `HistoryDone` → 0 events (lines 167, 202); no cursor/UUID API.
  <https://raw.githubusercontent.com/notify-rs/notify/main/notify/src/fsevent.rs>
- docs.rs `objc2-core-services` 0.3.2 item list: `FSEventsCopyUUIDForDevice`,
  `FSEventStreamSetDispatchQueue`, `FSEventStreamCreateRelativeToDevice`,
  `FSEventStreamGetLatestEventId`, `FSEventsGetCurrentEventId`, `NoDefer`,
  `FullHistory` all bound under `FSEvents` (+`libc`/`dispatch2`) features.
  <https://docs.rs/objc2-core-services/latest/objc2_core_services/>
- docs.rs `objc2-core-foundation` 0.3.2 item list: `CFUUID`, `CFUUIDBytes`,
  `CFUUIDGetUUIDBytes`, `CFUUIDCreateString` bound.
  <https://docs.rs/objc2-core-foundation/latest/objc2_core_foundation/all.html>
- `libc` 0.2.189 `src/unix/bsd/apple/mod.rs` (local): `statfs` struct 1364–1381;
  `MNT_*` 3785–3806, `MNT_NOWAIT` 3924; `FSOPT_*` 4065–4070; `ATTR_CMN_*` 4071–4101;
  `ATTR_VOL_UUID` 4120; `statfs`/`getfsstat`/`getattrlist`/`getattrlistat`/
  `getattrlistbulk` extern decls (~4557–5200).
- `getattrlistbulk.2` (darwin-xnu): bulk-over-dirfd; lstat symlink semantics;
  NAME+RETURNED_ATTRS mandatory; no volume attrs via bulk; FULLPATH unreliable.
  <https://raw.githubusercontent.com/apple/darwin-xnu/main/bsd/man/man2/getattrlistbulk.2>
- TinkerTool System APFS docs: volume groups, firmlink = one file at several paths
  stored once, volume roles (System/Data/Recovery/VM/Preboot/…).
  <https://www.bresink.com/osx/134807/Docs-en/pgs/0166-APFS.html>
- `Cargo.toml:26-27`: current `fsevent-sys = "4"` macOS dep to replace.
