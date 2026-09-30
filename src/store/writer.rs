//! Writer batching (spec §5 resource table).
//!
//! The owner batches completed observations and scheduling transitions and
//! commits at the first applicable limit: 512 rows, 512 KiB, or 250 ms of
//! batch age. The 250 ms setting is maximum batch age, never a fixed sleep:
//! [`WriterBatch::should_flush`] reports when any limit is reached and the
//! owner flushes earlier whenever scheduler progress needs it.

use std::time::{Duration, Instant};

/// Writer batch row cap (spec §5).
pub const WRITER_BATCH_ROWS: usize = 512;
/// Writer batch byte cap: 512 KiB (spec §5).
pub const WRITER_BATCH_BYTES: usize = 512 * 1024;
/// Writer maximum batch age: 250 ms (spec §5). A ceiling, not a sleep.
pub const WRITER_BATCH_MAX_AGE: Duration = Duration::from_millis(250);

/// One parameterized statement held for batched commit.
#[derive(Debug)]
pub struct PendingOp {
    /// Single-statement SQL with `?1..?N` positional parameters.
    pub sql: String,
    /// Bound values (BLOBs carry exact path/ref bytes).
    pub params: Vec<turso::Value>,
    /// Accounted bytes: SQL text plus parameter payload.
    pub bytes: usize,
}

/// Accumulates [`PendingOp`]s until a spec §5 flush limit is reached.
/// Flushing executes every op inside one `BEGIN IMMEDIATE` transaction
/// (see [`crate::store::TursoStore::flush`]).
#[derive(Debug)]
pub struct WriterBatch {
    ops: Vec<PendingOp>,
    bytes: usize,
    created: Instant,
}

impl WriterBatch {
    /// Empty batch; age counts from creation.
    pub fn new() -> Self {
        Self {
            ops: Vec::new(),
            bytes: 0,
            created: Instant::now(),
        }
    }

    /// Push an op. Returns true when a flush limit is now reached.
    pub fn push(&mut self, sql: impl Into<String>, params: Vec<turso::Value>) -> bool {
        let sql = sql.into();
        let mut bytes = sql.len();
        for param in &params {
            bytes += match param {
                turso::Value::Blob(blob) => blob.len(),
                turso::Value::Text(text) => text.len(),
                _ => 8,
            };
        }
        self.bytes += bytes;
        self.ops.push(PendingOp { sql, params, bytes });
        self.should_flush()
    }

    /// True when rows, bytes, or maximum age requires a commit.
    pub fn should_flush(&self) -> bool {
        self.ops.len() >= WRITER_BATCH_ROWS
            || self.bytes >= WRITER_BATCH_BYTES
            || self.created.elapsed() >= WRITER_BATCH_MAX_AGE
    }

    /// Number of held ops.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// True when no ops are held.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Accounted bytes of held ops.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Time since the batch was created (or last drained).
    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }

    /// Take all held ops and reset age accounting.
    pub(crate) fn drain(&mut self) -> Vec<PendingOp> {
        self.bytes = 0;
        self.created = Instant::now();
        std::mem::take(&mut self.ops)
    }
}

impl Default for WriterBatch {
    fn default() -> Self {
        Self::new()
    }
}
