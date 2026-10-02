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
use crate::scheduler::admission::{
    stream_restart_due, stream_stall_suspected, StreamBudget, NATIVE_STREAM_BUDGET,
};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

/// Device-anchored fallback volume identity (Item 11): colon-free and
/// byte-exact. The mount path hex-encodes raw bytes instead of the lossy
/// display rendering (which could collide), and carries no `:` that would
/// corrupt planner-key parsing, which splits the volume at the first `:`.
pub use super::dev_fallback_volume_id;

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
                    dev_fallback_volume_id(&anchor, &mount_path)
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

/// Stall-suspicion grace (SR-EVENT-01): when the global FSEvents clock
/// advances while one stream delivers no callback for this long, the
/// stream is recreated and the volume rescanned instead of reporting
/// caught-up over a possibly unobserved gap.
const STALL_SUSPICION_GRACE_MS: u64 = 60_000;

/// Preventive stream rotation (SR-EVENT-01): silent native teardown is
/// undetectable without activity, so every stream is recreated past this
/// age, bounding any unobserved gap to one rotation window.
const STREAM_ROTATION_MAX_AGE_MS: u64 = 30 * 60 * 1000;

/// Milliseconds since the Unix epoch, saturating on clock failure. Used
/// for stream-heartbeat stamps; a plain clock read, safe to call on the
/// dispatch-queue callback thread.
fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

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
    /// Aggregate budget (SR-STATE-02): every queued event's path bytes are
    /// charged here and released on dequeue or drop; over-budget events
    /// drop with the overflow latch set, preserving the volume-wide
    /// rescan signal instead of growing memory.
    budget: &'static StreamBudget,
    /// Last callback delivery in unix millis (SR-EVENT-01 heartbeat).
    last_callback_ms: AtomicU64,
    /// A dropped event carried the `HistoryDone` sentinel. Flood drops
    /// must not lose the historical-phase close: the rescan signal
    /// covers the dropped paths, and this latch carries the sentinel
    /// into the next emitted batch. Drained (swap) by `next_batch`.
    dropped_history_done: AtomicBool,
    /// Highest event ID seen on dropped events. Merged into the next
    /// emitted batch's high-water mark so ingested cursors stay ahead
    /// of coalesced-away events (their paths are covered by the
    /// overflow rescan). Drained (swap) by `next_batch`.
    dropped_max_id: AtomicU64,
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
    // until teardown drains the queue (Stop + Invalidate + synchronous
    // barrier) before freeing it, so no callback runs against a freed
    // box; the arrays have num_events entries per the FSEvents contract.
    let ctx = unsafe { &*(info as *const StreamContext) };
    let paths = event_paths.as_ptr() as *const *const libc::c_char;
    let flags = event_flags.as_ptr() as *const FSEventStreamEventFlags;
    let ids = event_ids.as_ptr() as *const FSEventStreamEventId;
    for i in 0..num_events {
        let path_ptr = unsafe { *paths.add(i) };
        if path_ptr.is_null() {
            continue;
        }
        // path_ptr is a NUL-terminated C string per the FSEvents contract.
        let path_bytes = unsafe { CStr::from_ptr(path_ptr) }.to_bytes();
        ctx.last_callback_ms.store(unix_millis(), Ordering::Relaxed);
        let observed_flags: FSEventStreamEventFlags = unsafe { *flags.add(i) };
        let observed_id: FSEventStreamEventId = unsafe { *ids.add(i) };
        // A drop preserves what the rescan signal cannot carry: the
        // historical-phase sentinel and the highest observed event ID.
        // Drained into the next emitted batch by `next_batch`, so a
        // flood can delay but never lose the history close.
        let preserve_dropped = || {
            if observed_flags & kFSEventStreamEventFlagHistoryDone != 0 {
                ctx.dropped_history_done.store(true, Ordering::Relaxed);
            }
            ctx.dropped_max_id.fetch_max(observed_id, Ordering::Relaxed);
        };
        if !ctx.budget.try_charge_bytes(path_bytes.len()) {
            // Aggregate queue-byte budget exhausted (SR-STATE-02): drop
            // the path but keep the volume-wide rescan signal — never
            // grow memory, never go silent.
            ctx.overflow.store(true, Ordering::Relaxed);
            preserve_dropped();
            continue;
        }
        let event = RawEvent {
            path: path_bytes.to_vec(),
            flags: observed_flags,
            id: observed_id,
        };
        if ctx.tx.try_send(event).is_err() {
            ctx.overflow.store(true, Ordering::Relaxed);
            ctx.budget.release_bytes(path_bytes.len());
            preserve_dropped();
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

        let (stream, info, rx, queue) = create_stream(dev, since_when, &volume.0)?;
        Ok((
            boundary,
            Box::new(FsEventStreamIter {
                stream,
                info,
                rx,
                volume_key: volume.0.clone(),
                dev,
                open_since: since_when,
                opened_ms: unix_millis(),
                last_global_id: live_id,
                last_high_water: 0,
                initial_signals,
                _queue: queue,
            }),
        ))
    }
}

/// Create, schedule, and start one whole-volume FSEventStream for `dev`,
/// delivering events after `since_when`. Shared by [`EventSource::open_stream`]
/// and the inline restart path so both enforce the same contract.
///
/// Aggregate admission (SR-STATE-02) runs BEFORE the stream, dispatch
/// queue, and 512-slot channel are created: past the live-stream cap the
/// call fails and the volume degrades honestly instead of retaining
/// unbounded queues and path buffers. Every failure path unwinds partial
/// state and releases the budget slot, so a failed creation never leaks.
fn create_stream(
    dev: libc::dev_t,
    since_when: FSEventStreamEventId,
    volume_key: &str,
) -> crate::Result<(
    FSEventStreamRef,
    *mut std::ffi::c_void,
    std::sync::mpsc::Receiver<RawEvent>,
    dispatch2::DispatchRetained<DispatchQueue>,
)> {
    if !NATIVE_STREAM_BUDGET.try_acquire_stream() {
        return Err(crate::Error::Events(format!(
            "FSEvents stream refused for volume {volume_key}: {} live streams (aggregate cap)",
            NATIVE_STREAM_BUDGET.streams_live()
        )));
    }
    // Whole-volume watch path array: ["/"] relative to the device.
    let root: CFRetained<CFString> = unsafe {
        CFString::with_c_string(
            None,
            c"/".as_ptr(),
            CFStringBuiltInEncodings::EncodingUTF8.0,
        )
    }
    .ok_or_else(|| {
        NATIVE_STREAM_BUDGET.release_stream();
        crate::Error::Events(String::from("CFString for / failed"))
    })?;
    let mut values: [*const std::ffi::c_void; 1] =
        [&*root as *const CFString as *const std::ffi::c_void];
    // NULL callbacks: the array does not retain its values, which is
    // sound here because `root` outlives the Create call below, and
    // FSEventStreamCreateRelativeToDevice copies the watch paths.
    let paths: CFRetained<CFArray> =
        unsafe { CFArray::new(None, values.as_mut_ptr(), 1, std::ptr::null()) }.ok_or_else(
            || {
                NATIVE_STREAM_BUDGET.release_stream();
                crate::Error::Events(String::from("CFArray for watch paths failed"))
            },
        )?;

    let (tx, rx) = std::sync::mpsc::sync_channel(CHANNEL_DEPTH);
    let ctx = Box::new(StreamContext {
        tx,
        overflow: AtomicBool::new(false),
        budget: &NATIVE_STREAM_BUDGET,
        last_callback_ms: AtomicU64::new(unix_millis()),
        dropped_history_done: AtomicBool::new(false),
        dropped_max_id: AtomicU64::new(0),
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
        NATIVE_STREAM_BUDGET.release_stream();
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
        // Start-failure no-enqueue: `FSEventStreamStart` returned false,
        // so no callback was ever enqueued on the queue and no barrier
        // is needed before freeing the context. (Contrast
        // `teardown_stream`, where a started stream may have callbacks
        // in flight and the barrier must precede both `Release` and the
        // free.)
        unsafe {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            let _ = Box::from_raw(info as *mut StreamContext);
        }
        NATIVE_STREAM_BUDGET.release_stream();
        return Err(crate::Error::Events(String::from(
            "FSEventStreamStart failed",
        )));
    }
    Ok((stream, info, rx, queue))
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
    /// Device the stream watches (restart recreates on the same device).
    dev: libc::dev_t,
    /// Cursor the stream opened from (restart resumes from the high-water
    /// mark when one was observed, else from this).
    open_since: FSEventStreamEventId,
    /// When the current native stream was (re)created, unix millis.
    opened_ms: u64,
    /// Global FSEvents clock at the last health check.
    last_global_id: FSEventStreamEventId,
    last_high_water: FSEventStreamEventId,
    initial_signals: Vec<ContinuitySignal>,
    _queue: dispatch2::DispatchRetained<DispatchQueue>,
}

// SAFETY: the FSEventStream handle is created, started, and destroyed on
// this thread; the dispatch-queue callback only touches the SyncSender,
// the overflow latch, the heartbeat stamp, and the aggregate budget's
// atomics, all safe to share.
unsafe impl Send for FsEventStreamIter {}

/// Tear down one started native stream and reclaim its callback context.
///
/// `FSEventStreamStop` is asynchronous with respect to the dispatch
/// queue: a callback already enqueued or running can still execute
/// after Stop/Invalidate return. The context box must therefore stay
/// alive until a synchronous barrier on the stream's private serial
/// queue proves no callback is in flight; freeing it earlier is a
/// use-after-free (SIGSEGV observed under parallel-test load, with the
/// faulting frame inside `fsevents_callback` after Drop had freed the
/// context). `FSEventStreamRelease` runs after the barrier for the same
/// reason: the stream object must stay alive while a callback may still
/// reference it.
///
/// Must run on the scan thread, never on the stream's own queue (a
/// synchronous dispatch onto the current serial queue deadlocks). The
/// barrier cannot deadlock against the dropping thread: the callback
/// only uses `try_send` and atomics, so in-flight callbacks always
/// finish without help from this thread.
fn teardown_stream(stream: FSEventStreamRef, info: *mut std::ffi::c_void, queue: &DispatchQueue) {
    unsafe {
        FSEventStreamStop(stream);
        FSEventStreamInvalidate(stream);
    }
    // The queue is serial and private to this stream, and the stream is
    // stopped and invalidated, so when this empty block runs, every
    // previously enqueued callback has finished and none can follow:
    // the context is unreachable from the queue from here on. Only then
    // is the stream released and the context freed.
    queue.exec_sync(|| {});
    unsafe {
        FSEventStreamRelease(stream);
        let _ = Box::from_raw(info as *mut StreamContext);
    }
}

impl Drop for FsEventStreamIter {
    fn drop(&mut self) {
        teardown_stream(self.stream, self.info, &self._queue);
        // Freeing the context dropped the only sender, so no new charges
        // are possible: this drain releases every still-queued byte
        // exactly once (SR-STATE-02). Then free the stream slot.
        for event in self.rx.try_iter() {
            NATIVE_STREAM_BUDGET.release_bytes(event.path.len());
        }
        NATIVE_STREAM_BUDGET.release_stream();
    }
}

impl FsEventStreamIter {
    /// Liveness gate for an empty poll (SR-EVENT-01): an empty connected
    /// channel is "nothing delivered", never "caught up". A rotation-aged
    /// or stall-suspect stream is recreated inline and yields a
    /// volume-wide rescan batch instead of silence. Returns `Ok(None)`
    /// when the stream is idle with no suspicion.
    fn check_stream_health(&mut self) -> crate::Result<Option<EventBatch>> {
        let now_ms = unix_millis();
        // SAFETY: no preconditions.
        let live_global = unsafe { FSEventsGetCurrentEventId() };
        // SAFETY: the context box is alive until Drop/restart (which
        // stop the stream and barrier-drain the queue before freeing),
        // and next_batch cannot run during Drop.
        let last_callback = unsafe { &*(self.info as *const StreamContext) }
            .last_callback_ms
            .load(Ordering::Relaxed);
        let previous_global = self.last_global_id;
        self.last_global_id = live_global;
        let rotate = stream_restart_due(self.opened_ms, now_ms, STREAM_ROTATION_MAX_AGE_MS);
        let suspect = stream_stall_suspected(
            last_callback,
            now_ms,
            previous_global,
            live_global,
            STALL_SUSPICION_GRACE_MS,
        );
        if !rotate && !suspect {
            return Ok(None);
        }
        self.restart_stream(live_global, now_ms, rotate)
    }

    /// Recreate the native stream inline (SR-EVENT-01 restart path) and
    /// force a volume-wide rescan: the teardown window may have dropped
    /// events, so silence is never reported. The new stream is created
    /// before the old one is torn down, so a recreation failure leaves the
    /// old stream in place and returns an error (the owner's batch-error
    /// path schedules the same rescan durably).
    fn restart_stream(
        &mut self,
        live_global: FSEventStreamEventId,
        now_ms: u64,
        rotate: bool,
    ) -> crate::Result<Option<EventBatch>> {
        let since = if self.last_high_water > 0 {
            self.last_high_water
        } else {
            self.open_since
        };
        let (stream, info, rx, queue) = create_stream(self.dev, since, &self.volume_key)?;
        // The new stream is live: tear down the old one exactly like Drop
        // (stop / invalidate / queue barrier / release / free), then
        // drain its channel — freeing the context dropped the only
        // sender, so the drain releases every still-queued byte exactly
        // once. `self._queue` is still the OLD queue here (replaced
        // below), which is what the barrier must drain.
        let old_rx = std::mem::replace(&mut self.rx, rx);
        teardown_stream(self.stream, self.info, &self._queue);
        for event in old_rx.try_iter() {
            NATIVE_STREAM_BUDGET.release_bytes(event.path.len());
        }
        // The new stream acquired its own budget slot; release the old one.
        NATIVE_STREAM_BUDGET.release_stream();
        self.stream = stream;
        self.info = info;
        self._queue = queue;
        self.opened_ms = now_ms;
        self.last_global_id = live_global;
        eprintln!(
            "repo-scan: FSEvents stream for volume {} recreated ({})",
            self.volume_key,
            if rotate {
                "rotation"
            } else {
                "stall suspicion"
            },
        );
        Ok(Some(EventBatch {
            volume_key: self.volume_key.clone(),
            high_water: EventCursorId(self.last_high_water),
            invalidations: Vec::new(),
            history_done: false,
            signals: vec![ContinuitySignal::MustScanSubDirs],
        }))
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
                // RSF-F940: Empty (caught up) and Disconnected (stream
                // lost) must never be conflated. A dead callback channel
                // is lost history: surface it so the owner invalidates
                // the volume scope instead of silently ending the stream.
                Err(error) => match crate::events::classify_try_recv(error) {
                    crate::events::TryRecvAction::CaughtUp => break,
                    crate::events::TryRecvAction::StreamLost => {
                        if count == 0 && signals.is_empty() && !history_done {
                            return Err(crate::Error::Events(format!(
                                "FSEvents callback channel disconnected for volume {}; \
                                 stream lost, volume scope must be invalidated",
                                self.volume_key
                            )));
                        }
                        break;
                    }
                },
                Ok(event) => {
                    count += 1;
                    bytes += event.path.len();
                    // Dequeued: release the aggregate byte charge (SR-STATE-02).
                    NATIVE_STREAM_BUDGET.release_bytes(event.path.len());
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
        // SAFETY: the context box is alive until Drop/restart (which
        // stop the stream and barrier-drain the queue before freeing),
        // and next_batch cannot run during Drop.
        let dropped = unsafe { &*(self.info as *const StreamContext) };
        let overflowed = dropped.overflow.swap(false, Ordering::Relaxed);
        if overflowed {
            signals.push(ContinuitySignal::MustScanSubDirs);
        }
        // Flood drops preserve the historical-phase sentinel and the
        // highest dropped event ID (the callback records both): merge
        // them here so a flood delays but never loses the history
        // close, and ingested cursors stay ahead of coalesced-away
        // events (covered by the rescan above). A concurrent delivery
        // lands in the next batch via the same latches.
        if dropped.dropped_history_done.swap(false, Ordering::Relaxed) {
            history_done = true;
        }
        high_water = high_water.max(dropped.dropped_max_id.swap(0, Ordering::Relaxed));

        if count == 0 && signals.is_empty() && !history_done {
            // SR-EVENT-01: prove liveness before reporting idle — an empty
            // channel must not imply caught-up. A stale stream restarts
            // inline (volume-wide rescan batch) or errors; only a healthy
            // idle stream returns `None`.
            if let Some(batch) = self.check_stream_health()? {
                return Ok(Some(batch));
            }
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
