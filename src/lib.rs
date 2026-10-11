// Phase-1 contract stubs. See docs/ARCHITECTURE.md for ownership.
pub mod cli;
pub mod config;
pub mod error;
pub mod events;
pub mod git;
pub mod identity;
pub mod model;
pub mod platform;
pub mod privacy;
pub mod report;
pub mod scan_events;
pub mod scheduler;
pub mod store;
pub mod telemetry;
pub mod walk;

pub use error::{Error, Result};

/// Crate version from Cargo.toml.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
