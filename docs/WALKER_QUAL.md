# Walker qualification (spec §6)

Pinned sources inspected: `dua-core 4.1.0`, `ignore 0.4.33` (the resolved
`ignore-0.4` line), `walkdir 2.5.0` (ignore's traversal engine).
Registry root below is abbreviated `R/...`.

## 1. dua-core adapter (primary, macOS)

Use ONLY the one-directory iterator. Never `walk`, `walk_roots`,
`walk_root_entries`, or `stream_roots`: those spawn worker threads and own a
job universe, which spec §4 forbids duplicating.

```rust
use std::path::Path;

// Cheap listing: names + file types only.
let it = dua_core::read_dir(path, dua_core::Options::default().skip_metadata())?;
// Identity/topology listing: adds native metadata (dev/ino/nlink/len/mtime).
let it = dua_core::read_dir(path, dua_core::Options::default())?;
for item in it {
    let entry: dua_core::Entry = item?; // preserve Err, do not skip
    let _ = (entry.file_name, entry.file_type, entry.parent_path, entry.depth);
    // entry.metadata: Option<io::Result<Metadata>>; preserve inner Err too.
}
```

- Signature: `pub fn read_dir(path: &Path, options: Options)
  -> io::Result<impl Iterator<Item = io::Result<Entry>>>`
  (`R/dua-core-4.1.0/src/lib.rs:424-430`). `cfg(any(windows, target_os =
  "macos"))` only: Linux builds use the portable adapter.
- Entries come out at `depth 0` for direct handoff to walk roots
  (`R/dua-core-4.1.0/src/lib.rs:418-423`); `directory_id` is `None` on this
  path. No root record is emitted, so there is nothing to filter.
- `Options { skip_metadata: bool, apfs_clone_metadata: bool (macOS only) }`
  (`R/dua-core-4.1.0/src/lib.rs:155-167`); `Default` is both `false`.
  `skip_metadata` takes the `std::fs::read_dir` + `DirEntry::file_type` path
  with `metadata: None` and disables APFS clone metadata
  (`R/dua-core-4.1.0/src/lib.rs:86-99,101-126`).
  Keep `apfs_clone_metadata: false` (default): clone identity is not in the
  discovery contract, and enabling it makes bulk reads more expensive
  (`R/dua-core-4.1.0/src/macos/mod.rs:247-249`).
- macOS-native path: opens the dir with `O_DIRECTORY`, then loops
  `libc::getattrlistbulk` with `FSOPT_PACK_INVAL_ATTRS` into a fixed
  `Box<AlignedBuffer<64*1024>>` reused across refills
  (`R/dua-core-4.1.0/src/macos/mod.rs:27,325-344,346-382`). One `Iterator::next`
  parses at most one record (`R/dua-core-4.1.0/src/macos/mod.rs:535-561`).
  `.`/`..` are skipped by the iterator itself (same).
- Symlinks are reported, never followed: explicit roots use
  `fs::symlink_metadata` (`R/dua-core-4.1.0/src/macos/mod.rs:47-70`); clone
  probes pass `FSOPT_NOFOLLOW` (`R/dua-core-4.1.0/src/macos/mod.rs:563-589`).
  Precondition (both adapters): the scheduler hands the adapter an
  already-resolved directory, never a symlink root.
- `FileType` exposes `is_dir/is_file/is_symlink`
  (`R/dua-core-4.1.0/src/macos/mod.rs:115-132`); `Metadata` exposes
  `dev/ino/nlink/len/modified/blocks` for identity/topology
  (`R/dua-core-4.1.0/src/macos/mod.rs:171-236`).
- Allocation: public `read_dir` spawns no threads and holds no per-child
  `Vec`; memory is the 64 KiB buffer plus one in-flight record. The
  `ENTRY_CHUNK_SIZE = 4` batching and `Vec::with_capacity(4)` buffers exist
  only inside the multi-threaded `walk` worker path, which this adapter does
  not use (`R/dua-core-4.1.0/src/lib.rs:137,1170-1171,1214-1220`).

### dua-core error preservation (all three layers)

1. Directory-open failure: `read_dir` itself returns `Err` (the `O_DIRECTORY`
   open failed). Record as the directory's enumeration error.
2. Iterator-item `Err`: mid-enumeration failures (bulk-refill errno,
   malformed record, per-entry read/`file_type` failure). Structural record
   errors mark the reader exhausted, so an `Err` item ends reliable
   enumeration for that directory: preserve partial children AND the gap
   (`R/dua-core-4.1.0/src/macos/mod.rs:447-462,544-558`).
3. `entry.metadata: Some(Err(e))`: per-entry metadata failure with the name
   still usable (bulk `EACCES` degrades to listing-only and reports per-entry
   errors; filesystems rejecting bulk calls fall back to `std::fs::read_dir`
   inside the iterator) (`R/dua-core-4.1.0/src/macos/mod.rs:391-421,476-499`).

## 2. ignore adapter (fallback/comparison)

Shallow, sequential, filterless. One `WalkBuilder` per directory task;
`build()` (sequential `Walk`), never `build_parallel()` (`threads()` only
affects the parallel iterator: `R/ignore-0.4.33/src/walk.rs:767-776`).

```rust
let mut b = ignore::WalkBuilder::new(path);
b.standard_filters(false)   // keep hidden + ignored entries, read no ignore files
 .max_depth(Some(1))         // root (0) + immediate children (1); no descent below
 .follow_links(false)       // default; stated for the audit trail
 .same_file_system(false)   // default; volume crossings become scheduled work, not drops
 .max_filesize(None)        // default: no size filtering
 .skip_stdout(false);       // default: no stdout skipping
// Do NOT set: sorter, min_depth, overrides, types, filter_entry, custom ignore names.
for item in b.build() {
    match item {
        Err(e) => { /* preserve: traversal error, see §2.1 */ }
        Ok(ent) => {
            if ent.depth() == 0 { continue; } // filter backend-emitted root, not a child
            if let Some(e) = ent.error() { /* preserve attached error */ }
            let _ = (ent.path(), ent.file_name(), ent.file_type(), ent.depth());
        }
    }
}
```

- `standard_filters(false)` disables `hidden`, `parents`, `ignore`,
  `git_ignore`, `git_global`, `git_exclude` as a group
  (`R/ignore-0.4.33/src/walk.rs:848-869`). With all matchers off:
  `matched_dir_entry` can only return no-match
  (`R/ignore-0.4.33/src/dir.rs:484-494`); hidden Name check is gated on
  `opts.hidden` (same); every ignore-file matcher short-circuits to
  `Gitignore::empty()` with no file I/O (`R/ignore-0.4.33/src/dir.rs:340-446`);
  `add_parents` returns the matcher unchanged
  (`R/ignore-0.4.33/src/dir.rs:192-205`). Overrides/types default to empty,
  so nothing else can skip entries either
  (`R/ignore-0.4.33/src/dir.rs:784-800`).
- `max_depth(Some(1))` flows into `WalkDir::max_depth(1)`
  (`R/ignore-0.4.33/src/walk.rs:593-644`); walkdir documents depth 0 = root,
  depth 1 = direct children, and avoids descending past the limit rather than
  merely filtering (`R/walkdir-2.5.0/src/lib.rs:318-335`). At max depth the
  ignore layer also skips ignore-file reads
  (`R/ignore-0.4.33/src/walk.rs:1239-1243`).
- The root IS yielded at `depth() == 0` and must be filtered by the adapter,
  never counted as a child (`R/walkdir-2.5.0/src/lib.rs:840-874`;
  `DirEntry::depth` at `R/ignore-0.4.33/src/walk.rs:80-83`). Depth-0 entries
  are never filter-skipped (`R/ignore-0.4.33/src/walk.rs:1149-1152`), so the
  root always arrives exactly once per built walker.
- Do not follow symlinks through backend recursion: `follow_links` defaults
  to `false` (`R/ignore-0.4.33/src/walk.rs:560-575`), and walkdir then never
  descends into symlinked dirs (`R/walkdir-2.5.0/src/lib.rs:846-874`).
  Caveat: walkdir ALWAYS follows a symlink given as the ROOT
  (`follow_root_links: true`, not exposed through `WalkBuilder::build`)
  (`R/walkdir-2.5.0/src/lib.rs:282-299`, `R/ignore-0.4.33/src/walk.rs:593-644`
  sets no equivalent). The resolved-directory precondition in §1 covers this.
- `DirEntry::file_type() -> Option<FileType>` is `None` only for stdin,
  which this configuration never produces; `metadata()` stats on demand
  (`R/ignore-0.4.33/src/walk.rs:60-70`).

### 2.1 ignore error preservation (both channels)

1. Iterator-item `Err(ignore::Error)`: every walkdir traversal failure
   (directory-open, per-entry read, loop) is converted with path+depth tags
   and yielded (`R/ignore-0.4.33/src/walk.rs:1216-1219`;
   `Error::from_walkdir` at `R/ignore-0.4.33/src/lib.rs:286-307`;
   `Error::{path,depth,is_io,io_error}` accessors at
   `R/ignore-0.4.33/src/lib.rs:156-260`).
2. `DirEntry::error() -> Option<&Error>`: ignore-file parse errors attach to
   the surviving entry instead of failing traversal
   (`R/ignore-0.4.33/src/walk.rs:93-100,1223-1247`). Expected `None` with
   filters off, but the adapter must still check and preserve it, since
   traversal errors "are reported as part of yielding the directory entry,
   and not with this method" (same doc comment) — the two channels are
   complementary, not redundant.

## 3. Escape-hatch criterion (huge flat directory)

Spec §6 permits a narrow `std::fs::read_dir` hatch ONLY if a library
necessarily materializes an unbounded child list. Inspected evidence says
neither does under the §1–§2 configurations, so the hatch is OFF at these
pins and must be re-verified on any version bump:

- dua-core `read_dir`: fixed 64 KiB buffer, one record per `next()` (§1).
  No `collect`/`Vec` of children on this path.
- ignore `Walk`: walkdir streams each open directory through `fs::ReadDir`
  one entry at a time (`R/walkdir-2.5.0/src/lib.rs:1014-1030`). The ONLY
  unbounded per-directory `Vec` materializations are: (a) a configured
  `sorter` collects the whole directory
  (`R/walkdir-2.5.0/src/lib.rs:913-924`) — forbidden by §2; (b) `DirList::close`
  under fd pressure (`max_open`, default 10) reads a remainder into memory
  (`R/walkdir-2.5.0/src/lib.rs:1006-1012`) — unreachable here because a
  depth-1 walk holds at most one open directory stream (stack ≤ 2 <
  max_open), and `WalkBuilder::build` never lowers `max_open`.

Detection procedure (acceptance FS-05): run the huge-flat fixture through
each adapter streaming (no caller-side `collect`), sampling adapter RSS vs
emitted entry count. Criterion: RSS delta must stay ~flat (O(buffer)) as
count grows; RSS growing O(entries) proves materialization and triggers the
hatch for that backend: select `std::fs::read_dir` explicitly under the same
adapter contract (same immediate-children semantics, root filtering n/a,
per-entry `file_type`/`metadata` errors preserved as items, depth-0
labelling, interruption between items), and test equivalence, errors,
interruption, and resource behavior per §6. Keep real dua-core/ignore
integration for the non-triggered cases; never keep an unused dependency
for compliance.
