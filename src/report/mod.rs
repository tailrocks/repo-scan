//! Report publication (spec §§3, 15–16).
//!
//! Every emitted report validates against `schemas/report-v1.schema.json`
//! (JSON Schema Draft 2020-12). JSON to a file is streamed from one
//! consistent catalog revision with bounded memory into controlled local
//! staging; readers are released; then an admitted helper publishes via a
//! temporary sibling + atomic replacement. Failed publication retries the
//! saved snapshot without repeating discovery.

pub mod builder;
pub mod encode;
pub mod live_text;
pub mod model;
pub mod publish;
pub mod render;
pub mod stream;
pub mod validate;

pub use builder::{ReportInputs, ReportPipeline, StreamStats};
pub use model::Report;

use crate::model::{ScanId, StatusMode};

/// What to publish.
#[derive(Debug, Clone)]
pub struct ReportRequest {
    /// Scan request being reported.
    pub scan_id: ScanId,
    /// File destination, if any (absolute, validated per spec §15).
    /// `None` = readable terminal report + versioned snapshot in state.
    pub destination: Option<std::path::PathBuf>,
    /// Status depth declared on the report.
    pub status_mode: StatusMode,
}

/// Outcome of a publication attempt.
#[derive(Debug, Clone)]
pub struct Publication {
    /// Immutable snapshot/report ID retained in state.
    pub report_id: String,
    /// Whether the external destination now holds the report.
    pub published: bool,
    /// Content checksum of the staged bytes.
    pub checksum: String,
}

/// Report writer contract.
pub trait ReportWriter: Send {
    /// Stream the consistent report for `request` from one catalog revision,
    /// validate it against the shipped schema, retain the immutable snapshot,
    /// and publish per the destination policy. Returns the publication
    /// record; on publication failure the snapshot is still retained.
    fn write_report(
        &mut self,
        request: &ReportRequest,
    ) -> impl std::future::Future<Output = crate::Result<Publication>> + Send;
}
