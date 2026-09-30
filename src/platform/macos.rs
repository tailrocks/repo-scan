//! macOS native implementation (MACOS_QUAL §§1–3). Compiled only on
//! `target_os = "macos"`.
//!
//! - FSEvents history via `objc2-core-services` 0.3 (`FSEvents` + `libc` +
//!   `dispatch2`) and `objc2-core-foundation` 0.3: per-volume
//!   `FSEventStreamCreateRelativeToDevice` streams with flags
//!   `FileEvents | NoDefer | WatchRoot | FullHistory`, UUID persistence via
//!   `FSEventsCopyUUIDForDevice` + `CFUUID*`.
//! - Mounts/volume UUID/file identity via `libc`: `getfsstat` (`MNT_NOWAIT`),
//!   `getattrlist` (`ATTR_VOL_UUID`), `getattrlistbulk` (bulk file IDs).
//!
//! Mount-table output is never obtained by parsing `mount` command output:
//! only `getfsstat(2)` plus per-mount `getattrlist(2)` identity probes.
//! `unsafe` is confined to documented native call sites in this file.

use super::{EventBatchIter, EventSource, MountPoint, MountTable, VolumeId};
use crate::events::{ContinuitySignal, EventBatch, EventCursorId, VolumeCursor};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Mount table (getfsstat + getattrlist volume UUID)
// ---------------------------------------------------------------------------

/// Parse one fixed-size `statfs` C-string field (NUL-terminated within a
/// fixed buffer) into raw bytes. Pure and unit-testable.
fn field_bytes(field: &[libc::c_char]) -> &[u8] {
    // SAFETY: statfs string fields are always NUL-terminated by the kernel
    // within their fixed buffers.
    unsafe { CStr::from_ptr(field.as_ptr()) }.to_bytes()
}

/// Format 16 raw UUID bytes as canonical lowercase `8-4-4-4-12` hex.
/// Pure and unit-testable.
fn format_uuid_bytes(bytes: &[u8; 16]) -> String {
    let h = |i: usize| format!("{:02x}", bytes[i]);
    format!(
        "{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        h(0),
        h(1),
        h(2),
        h(3),
        h(4),
        h(5),
        h(6),
        h(7),
        h(8),
        h(9),
        h(10),
        h(11),
        h(12),
        h(13),
        h(14),
        h(15)
    )
}

/// Stable volume UUID for one mountpoint via `getattrlist(ATTR_VOL_UUID)`.
/// Returns `None` when the volume has no UUID (unsupported filesystem,
/// permission, race) — the caller falls back to device-anchored identity.
fn volume_uuid_of(mount_path: &Path) -> Option<String> {
    let cpath = CString::new(mount_path.as_os_str().as_bytes()).ok()?;
    let mut attr = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_UUID,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut buf = [0u8; 16];
    // SAFETY: attr is a valid ATTR_VOL_UUID request; buf is 16 writable
    // bytes, exactly the fixed size of a volume UUID (no attrreference
    // indirection for fixed-size attributes).
    let ret = unsafe {
        libc::getattrlist(
            cpath.as_ptr(),
            &mut attr as *mut libc::attrlist as *mut libc::c_void,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as libc::size_t,
            0,
        )
    };
    if ret != 0 {
        return None;
    }
    Some(format_uuid_bytes(&buf))
}

/// Native macOS mount table (`getfsstat`).
#[derive(Debug, Default)]
pub struct MacOsMountTable;

impl MountTable for MacOsMountTable {
    fn mounts(&self) -> crate::Result<Vec<MountPoint>> {
        // Phase 1: count only.
        // SAFETY: null buffer with size 0 asks for the mount count.
        let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
        if count < 0 {
            return Err(crate::Error::Platform(format!(
                "getfsstat count failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        // Sanity bound: a real mount table never approaches this; garbage
        // here would otherwise drive a huge allocation.
        if count as usize > 4096 {
            return Err(crate::Error::Platform(format!(
                "implausible getfsstat count: {count}"
            )));
        }
        let mut buf: Vec<libc::statfs> = Vec::with_capacity(count as usize);
        // SAFETY: buf has capacity for `count` entries; getfsstat fills the
        // first `got` entries and set_len is called only for those.
        let got = unsafe {
            libc::getfsstat(
                buf.as_mut_ptr(),
                (count as usize * std::mem::size_of::<libc::statfs>()) as libc::c_int,
                libc::MNT_NOWAIT,
            )
        };
        if got < 0 {
            return Err(crate::Error::Platform(format!(
                "getfsstat failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        unsafe { buf.set_len(got as usize) };

        let mut mounts = Vec::with_capacity(buf.len());
        for st in &buf {
            let mnton = field_bytes(&st.f_mntonname);
            let fstype = String::from_utf8_lossy(field_bytes(&st.f_fstypename)).into_owned();
            let mntfrom = String::from_utf8_lossy(field_bytes(&st.f_mntfromname)).into_owned();
            let mount_path = PathBuf::from(std::ffi::OsString::from_vec(mnton.to_vec()));
            let flags = st.f_flags as libc::c_int;
            let is_local = flags & libc::MNT_LOCAL != 0;
            let is_snapshot = flags & libc::MNT_SNAPSHOT != 0;
            // Read-only system snapshots are real, enumerable roots, but
            // not live user-data volumes: report them as Virtual.
            let kind = if is_snapshot {
                super::VolumeKind::Virtual
            } else {
                super::classify_volume_kind(is_local, &fstype, &mntfrom)
            };
            let volume = match volume_uuid_of(&mount_path) {
                Some(uuid) => VolumeId(uuid),
                // Fallback: device-anchored identity. Documented as weaker:
                // dev numbers may change across reboots, so this
                // identity never qualifies for event-history UUID reuse —
                // the FSEvents open rule still requires a real UUID match.
                // (statfs f_fsid is unreadable: libc keeps __fsid_val
                // private, so stat.st_dev of the mountpoint anchors instead.)
                None => {
                    let anchor = device_of(&mount_path)
                        .map(|d| d.to_string())
                        .unwrap_or_else(|_| String::from("unknown"));
                    VolumeId(format!("dev:{anchor}@{}", mount_path.display()))
                }
            };
            mounts.push(MountPoint {
                volume,
                mount_path,
                filesystem: Some(fstype),
                kind,
            });
        }
        Ok(mounts)
    }
}

/// Device number of the filesystem containing `path` (the FSEvents key;
/// always paired with the stored UUID per MACOS_QUAL §1.3).
fn device_of(path: &Path) -> std::io::Result<libc::dev_t> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: cpath is NUL-terminated; st is writable for the call.
    let ret = unsafe { libc::stat(cpath.as_ptr(), &mut st) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st.st_dev)
}

// ---------------------------------------------------------------------------
// FSEvents history source
// ---------------------------------------------------------------------------

use dispatch2::DispatchQueue;
use objc2_core_foundation::{CFArray, CFRetained, CFString, CFStringBuiltInEncodings};
use objc2_core_services::{
    kFSEventStreamCreateFlagFileEvents, kFSEventStreamCreateFlagFullHistory,
    kFSEventStreamCreateFlagNoDefer, kFSEventStreamCreateFlagWatchRoot,
    kFSEventStreamEventFlagEventIdsWrapped, kFSEventStreamEventFlagHistoryDone,
    kFSEventStreamEventFlagMount, kFSEventStreamEventFlagMustScanSubDirs,
    kFSEventStreamEventFlagRootChanged, kFSEventStreamEventFlagUnmount, ConstFSEventStreamRef,
    FSEventStreamContext, FSEventStreamCreateRelativeToDevice, FSEventStreamEventFlags,
    FSEventStreamEventId, FSEventStreamInvalidate, FSEventStreamRef, FSEventStreamRelease,
    FSEventStreamSetDispatchQueue, FSEventStreamStart, FSEventStreamStop,
    FSEventsCopyUUIDForDevice, FSEventsGetCurrentEventId,
};

/// `kFSEventStreamEventIdSinceNow` (no new-history scan; the binding crate
/// does not export the constant, so it is defined from the SDK header:
/// `(FSEventStreamEventId)ULLONG_MAX`).
const SINCE_NOW: FSEventStreamEventId = u64::MAX;

/// Stream flags per MACOS_QUAL §1.1. `UseCFTypes` is deliberately absent:
/// paths then arrive as plain C strings, which keeps path extraction free
/// of CF container handling and lossless for non-UTF-8 bytes.
const STREAM_FLAGS: u32 = kFSEventStreamCreateFlagFileEvents
    | kFSEventStreamCreateFlagNoDefer
    | kFSEventStreamCreateFlagWatchRoot
    | kFSEventStreamCreateFlagFullHistory;

/// Coalescing latency in seconds. `NoDefer` makes the first event after an
/// idle period immediate; this only paces bursts.
const STREAM_LATENCY: f64 = 0.3;

/// Bounded callback channel depth (spec §5: 2 pending producer batches of
/// 256 entries each).
const CHANNEL_DEPTH: usize = 512;

/// One raw callback triple: path bytes (lossless), event flags, event ID.
struct RawEvent {
    path: Vec<u8>,
    flags: FSEventStreamEventFlags,
    id: FSEventStreamEventId,
}

/// Callback context: a bounded channel plus an overflow latch. When the
/// channel is full, events coalesce into a volume-wide `MustScanSubDirs`
/// signal instead of growing memory (spec §13).
struct StreamContext {
    tx: std::sync::mpsc::SyncSender<RawEvent>,
    overflow: AtomicBool,
}

/// FSEvents history callback. Runs on the stream's dispatch queue; only
/// forwards (path, flags, id) triples through the bounded channel.
/// Without `UseCFTypes`, `event_paths` is a C array of NUL-terminated
/// `char*` with `num_events` entries; `event_flags`/`event_ids` are
/// parallel C arrays of the same length.
unsafe extern "C-unwind" fn fsevents_callback(
    _stream: ConstFSEventStreamRef,
    info: *mut std::ffi::c_void,
    num_events: usize,
    event_paths: std::ptr::NonNull<std::ffi::c_void>,
    event_flags: std::ptr::NonNull<FSEventStreamEventFlags>,
    event_ids: std::ptr::NonNull<FSEventStreamEventId>,
) {
    if info.is_null() {
        return;
    }
    // SAFETY: info is the Box<StreamContext> installed at creation, alive
    // until Drop after FSEventStreamStop + Invalidate; the arrays have
    // num_events entries per the FSEvents contract.
    let ctx = unsafe { &*(info as *const StreamContext) };
    let paths = event_paths.as_ptr() as *const *const libc::c_char;
    let flags = event_flags.as_ptr() as *const FSEventStreamEventFlags;
    let ids = event_ids.as_ptr() as *const FSEventStreamEventId;
    for i in 0..num_events {
        let path_ptr = unsafe { *paths.add(i) };
        if path_ptr.is_null() {
            continue;
        }
        let event = RawEvent {
            path: unsafe { CStr::from_ptr(path_ptr) }.to_bytes().to_vec(),
            flags: unsafe { *flags.add(i) },
            id: unsafe { *ids.add(i) },
        };
        if ctx.tx.try_send(event).is_err() {
            ctx.overflow.store(true, Ordering::Relaxed);
        }
    }
}

/// Live history UUID for one device, canonically formatted, or `None` when
/// the volume has no history (NULL from the API: read-only / unsupported
/// volume → eventless handling per MACOS_QUAL §3).
fn fs_uuid_for_device(dev: libc::dev_t) -> Option<String> {
    // SAFETY: dev comes from stat of a known mountpoint; the call has no
    // additional preconditions.
    let uuid: CFRetained<objc2_core_foundation::CFUUID> =
        unsafe { FSEventsCopyUUIDForDevice(dev) }?;
    let b = uuid.uuid_bytes();
    let bytes = [
        b.byte0, b.byte1, b.byte2, b.byte3, b.byte4, b.byte5, b.byte6, b.byte7, b.byte8, b.byte9,
        b.byte10, b.byte11, b.byte12, b.byte13, b.byte14, b.byte15,
    ];
    Some(format_uuid_bytes(&bytes))
}

/// Native macOS FSEvents history source.
#[derive(Debug, Default)]
pub struct FsEventsSource;

impl EventSource for FsEventsSource {
    fn open_stream(
        &mut self,
        volume: &VolumeId,
        stored: Option<VolumeCursor>,
    ) -> crate::Result<(EventCursorId, Box<dyn EventBatchIter>)> {
        let mounts = MacOsMountTable.mounts()?;
        let mount = mounts
            .iter()
            .find(|m| &m.volume == volume)
            .ok_or_else(|| crate::Error::Events(format!("unknown volume {}", volume.0)))?;
        let dev = device_of(&mount.mount_path).map_err(|e| {
            crate::Error::Events(format!(
                "stat of {} failed: {e}",
                mount.mount_path.display()
            ))
        })?;

        let live_uuid = fs_uuid_for_device(dev);
        // SAFETY: no preconditions.
        let live_id = unsafe { FSEventsGetCurrentEventId() };

        // Open rule (MACOS_QUAL §2): reuse stored (uuid, cursor) only if the
        // live UUID is non-NULL, equals the stored UUID, and the live ID is
        // at or above the stored cursor. Anything else is HistoryInvalid:
        // discard cursors, invalidate volume scope, fresh traversal.
        let mut initial_signals = Vec::new();
        let since_when = match (&live_uuid, stored.as_ref()) {
            (None, _) => {
                initial_signals.push(ContinuitySignal::HistoryInvalid);
                SINCE_NOW
            }
            (Some(live), Some(stored)) => match (&stored.uuid, stored.ingested) {
                (Some(want), Some(cursor)) if *live == want.0 && live_id >= cursor.0 => cursor.0,
                (Some(_), _) | (None, _) => {
                    if stored.uuid.is_some() {
                        initial_signals.push(ContinuitySignal::HistoryInvalid);
                    }
                    SINCE_NOW
                }
            },
            (Some(_), None) => SINCE_NOW,
        };

        // Observation boundary for this scan, recorded at open, before the
        // stream starts and before any traversal (monitor-before-traverse).
        // Completion is claimed relative to it; later arrivals stay queued.
        let boundary = EventCursorId(live_id);

        // Whole-volume watch path array: ["/"] relative to the device.
        let root: CFRetained<CFString> = unsafe {
            CFString::with_c_string(
                None,
                c"/".as_ptr(),
                CFStringBuiltInEncodings::EncodingUTF8.0,
            )
        }
        .ok_or_else(|| crate::Error::Events(String::from("CFString for / failed")))?;
        let mut values: [*const std::ffi::c_void; 1] =
            [&*root as *const CFString as *const std::ffi::c_void];
        // NULL callbacks: the array does not retain its values, which is
        // sound here because `root` outlives the Create call below, and
        // FSEventStreamCreateRelativeToDevice copies the watch paths.
        let paths: CFRetained<CFArray> =
            unsafe { CFArray::new(None, values.as_mut_ptr(), 1, std::ptr::null()) }.ok_or_else(
                || crate::Error::Events(String::from("CFArray for watch paths failed")),
            )?;

        let (tx, rx) = std::sync::mpsc::sync_channel(CHANNEL_DEPTH);
        let ctx = Box::new(StreamContext {
            tx,
            overflow: AtomicBool::new(false),
        });
        let info = Box::into_raw(ctx) as *mut std::ffi::c_void;
        let mut context = FSEventStreamContext {
            version: 0,
            info,
            retain: None,
            release: None,
            copyDescription: None,
        };
        // SAFETY: callback is implemented correctly; context points at a
        // live FSEventStreamContext; paths is a CFArray of CFString.
        let stream: FSEventStreamRef = unsafe {
            FSEventStreamCreateRelativeToDevice(
                None,
                Some(fsevents_callback),
                std::ptr::addr_of_mut!(context),
                dev,
                &paths,
                since_when,
                STREAM_LATENCY,
                STREAM_FLAGS,
            )
        };
        if stream.is_null() {
            unsafe {
                let _ = Box::from_raw(info as *mut StreamContext);
            }
            return Err(crate::Error::Events(String::from(
                "FSEventStreamCreateRelativeToDevice returned NULL",
            )));
        }
        let queue = DispatchQueue::new("repo-scan.fsevents", None);
        // SAFETY: stream is valid; the stream retains the queue.
        unsafe { FSEventStreamSetDispatchQueue(stream, Some(&*queue)) };
        // SAFETY: stream is valid and scheduled.
        let started = unsafe { FSEventStreamStart(stream) };
        if !started {
            unsafe {
                FSEventStreamInvalidate(stream);
                FSEventStreamRelease(stream);
                let _ = Box::from_raw(info as *mut StreamContext);
            }
            return Err(crate::Error::Events(String::from(
                "FSEventStreamStart failed",
            )));
        }

        Ok((
            boundary,
            Box::new(FsEventStreamIter {
                stream,
                info,
                rx,
                volume_key: volume.0.clone(),
                last_high_water: 0,
                initial_signals,
                _queue: queue,
            }),
        ))
    }
}

/// Live-stream batch iterator: drains the bounded callback channel into
/// bounded, coalesced [`EventBatch`]es (256 entries / 256 KiB, first limit
/// wins). `Send` because the stream handle is only touched on this thread
/// (Drop) while the callback thread only uses the channel + atomics.
struct FsEventStreamIter {
    stream: FSEventStreamRef,
    info: *mut std::ffi::c_void,
    rx: std::sync::mpsc::Receiver<RawEvent>,
    volume_key: String,
    last_high_water: FSEventStreamEventId,
    initial_signals: Vec<ContinuitySignal>,
    _queue: dispatch2::DispatchRetained<DispatchQueue>,
}

// SAFETY: the FSEventStream handle is created, started, and destroyed on
// this thread; the dispatch-queue callback only touches the SyncSender and
// the overflow AtomicBool, both safe to share.
unsafe impl Send for FsEventStreamIter {}

impl Drop for FsEventStreamIter {
    fn drop(&mut self) {
        unsafe {
            // Stop delivery before invalidating so no callback can run
            // against the freed context; then reclaim the context box.
            FSEventStreamStop(self.stream);
            FSEventStreamInvalidate(self.stream);
            FSEventStreamRelease(self.stream);
            let _ = Box::from_raw(self.info as *mut StreamContext);
        }
    }
}

/// Collapse invalidations: sorted, deduplicated, and any path below an
/// already-listed ancestor removed (a busy directory must not create an
/// unbounded queue of identical work). Pure and unit-testable.
fn coalesce_invalidations(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.sort();
    paths.dedup();
    let mut out: Vec<PathBuf> = Vec::with_capacity(paths.len());
    for path in paths {
        let covered = out
            .last()
            .map(|a: &PathBuf| path.starts_with(a))
            .unwrap_or(false);
        if !covered {
            out.push(path);
        }
    }
    out
}

impl EventBatchIter for FsEventStreamIter {
    fn next_batch(&mut self) -> crate::Result<Option<EventBatch>> {
        const MAX_EVENTS: usize = 256;
        const MAX_BYTES: usize = 256 * 1024;

        let mut invalidations: Vec<PathBuf> = Vec::new();
        let mut signals: Vec<ContinuitySignal> = std::mem::take(&mut self.initial_signals);
        let mut high_water = self.last_high_water;
        let mut history_done = false;
        let mut bytes = 0usize;
        let mut count = 0usize;

        loop {
            if count >= MAX_EVENTS || bytes >= MAX_BYTES {
                break;
            }
            match self.rx.try_recv() {
                Err(_) => break,
                Ok(event) => {
                    count += 1;
                    bytes += event.path.len();
                    let flags = event.flags;
                    if flags & kFSEventStreamEventFlagHistoryDone != 0 {
                        // Sentinel ends the historical phase; its path is
                        // meaningless and must be ignored.
                        history_done = true;
                    } else {
                        // RootChanged carries event ID zero: never persist 0
                        // as a cursor.
                        if event.id != 0 && event.id > high_water {
                            high_water = event.id;
                        }
                        invalidations.push(PathBuf::from(std::ffi::OsString::from_vec(event.path)));
                    }
                    if flags & kFSEventStreamEventFlagMustScanSubDirs != 0 {
                        signals.push(ContinuitySignal::MustScanSubDirs);
                    }
                    if flags & kFSEventStreamEventFlagEventIdsWrapped != 0 {
                        signals.push(ContinuitySignal::HistoryInvalid);
                    }
                    if flags & kFSEventStreamEventFlagRootChanged != 0 {
                        signals.push(ContinuitySignal::RootChanged);
                    }
                    if flags & (kFSEventStreamEventFlagMount | kFSEventStreamEventFlagUnmount) != 0
                    {
                        signals.push(ContinuitySignal::MountChanged);
                    }
                    // UserDropped/KernelDropped are informational only; the
                    // accompanying MustScanSubDirs drives the rescan.
                }
            }
        }

        // Channel overflow coalesces to a volume-wide MustScanSubDirs: an
        // empty invalidation list plus that signal means "rescan the watched
        // roots", never "nothing changed".
        // SAFETY: the context box is alive until Drop (which stops the
        // stream first), and next_batch cannot run during Drop.
        let overflowed = unsafe { &*(self.info as *const StreamContext) }
            .overflow
            .swap(false, Ordering::Relaxed);
        if overflowed {
            signals.push(ContinuitySignal::MustScanSubDirs);
        }

        if count == 0 && signals.is_empty() && !history_done {
            return Ok(None);
        }
        signals.sort_by_key(|s| *s as u8);
        signals.dedup();
        self.last_high_water = high_water;
        Ok(Some(EventBatch {
            volume_key: self.volume_key.clone(),
            high_water: EventCursorId(high_water),
            invalidations: coalesce_invalidations(invalidations),
            history_done,
            signals,
        }))
    }
}
