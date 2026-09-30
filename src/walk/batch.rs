//! Bounded enumeration batching (spec §5: 256 entries or 256 KiB).
//!
//! Helpers flush at the first limit reached. Exceptionally large single
//! records stream through the bounded protocol instead of growing the
//! batch; transport buffers count toward the byte cap.

use super::ChildEntry;
use crate::config::ResourceLimits;

/// Flush limits for one producer batch.
#[derive(Debug, Clone, Copy)]
pub struct BatchLimits {
    /// Flush after this many entries.
    pub max_entries: usize,
    /// Flush after this many accounted bytes.
    pub max_bytes: usize,
}

impl BatchLimits {
    /// Limits from the effective resource configuration.
    pub fn from_resources(limits: &ResourceLimits) -> Self {
        Self {
            max_entries: limits.batch_entries,
            max_bytes: limits.batch_bytes,
        }
    }

    /// Spec §5 defaults: 256 entries or 256 KiB.
    pub fn spec_default() -> Self {
        Self::from_resources(&ResourceLimits::default())
    }
}

/// Estimated wire size of one child entry: raw name bytes plus a fixed
/// per-record overhead (kind tag, metadata, framing). The estimate is
/// deliberately conservative so transport buffers stay within budget.
pub fn entry_wire_size(entry: &ChildEntry) -> usize {
    const PER_RECORD_OVERHEAD: usize = 64;
    entry.name.len() + PER_RECORD_OVERHEAD
}

/// One bounded batch of immediate children from a single directory listing.
#[derive(Debug, Default)]
pub struct EntryBatch {
    items: Vec<ChildEntry>,
    bytes: usize,
    limits: Option<BatchLimits>,
}

impl EntryBatch {
    /// Empty batch with the spec §5 default limits.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            bytes: 0,
            limits: Some(BatchLimits::spec_default()),
        }
    }

    /// Empty batch with explicit limits.
    pub fn with_limits(limits: BatchLimits) -> Self {
        Self {
            items: Vec::new(),
            bytes: 0,
            limits: Some(limits),
        }
    }

    fn limits(&self) -> BatchLimits {
        self.limits.unwrap_or(BatchLimits::spec_default())
    }

    /// Try to add one entry. Returns `Some(entry)` back to the caller when
    /// the batch is full at either limit — the caller flushes and retries.
    /// A single entry larger than the byte cap is still accepted into an
    /// empty batch so it streams alone instead of blocking forever.
    pub fn try_push(&mut self, entry: ChildEntry) -> Option<ChildEntry> {
        let limits = self.limits();
        let size = entry_wire_size(&entry);
        let full = self.items.len() >= limits.max_entries
            || (!self.items.is_empty() && self.bytes + size > limits.max_bytes);
        if full {
            return Some(entry);
        }
        self.bytes += size;
        self.items.push(entry);
        None
    }

    /// True when either flush limit is reached.
    pub fn is_full(&self) -> bool {
        let limits = self.limits();
        self.items.len() >= limits.max_entries || self.bytes >= limits.max_bytes
    }

    /// True when the batch holds no entries.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Number of entries held.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Accounted bytes held.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Entries held (for the flush path).
    pub fn items(&self) -> &[ChildEntry] {
        &self.items
    }

    /// Drain all entries for a flush, resetting byte accounting.
    pub fn drain(&mut self) -> Vec<ChildEntry> {
        self.bytes = 0;
        std::mem::take(&mut self.items)
    }
}
