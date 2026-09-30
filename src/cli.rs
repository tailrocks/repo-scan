//! CLI surface (spec §3). Defines the six exact commands plus the
//! optional `--status` and `--state-dir` controls. No business logic here.

use crate::model::{Scope, StatusMode};
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// repo-scan: discover local clones of a GitHub repository.
#[derive(Debug, Parser)]
#[command(
    name = "repo-scan",
    version,
    about = "Discover local Git repository copies"
)]
pub struct Cli {
    /// Tool state directory. macOS default:
    /// `~/Library/Application Support/repo-scan` (spec §3).
    #[arg(long, global = true)]
    pub state_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// The six exact commands from spec §3.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Discover matching copies and produce a report.
    Scan(ScanArgs),
    /// Query the catalog immediately, with freshness information.
    Query(QueryArgs),
    /// Continue unfinished work.
    Resume(ResumeArgs),
    /// Cache maintenance.
    Cache(CacheArgs),
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// GitHub repository URL to discover.
    pub url: String,
    /// Discovery scope.
    #[arg(long, value_enum, default_value = "machine")]
    pub scope: Scope,
    /// Report destination (absolute resolution at request creation).
    #[arg(long)]
    pub report: Option<PathBuf>,
    /// Create a fresh traversal generation, bypassing completion shortcuts.
    #[arg(long)]
    pub force_rescan: bool,
    /// Working-state inspection depth (spec §9).
    #[arg(long, value_enum, default_value = "summary")]
    pub status: StatusMode,
    /// Explicit roots to scan (repeatable). When present, the scan covers
    /// exactly these paths and the scope is recorded as `roots`; otherwise
    /// `--scope` applies. This optional control never changes the meaning
    /// of the six spec §3 commands.
    #[arg(long)]
    pub root: Vec<PathBuf>,
}

#[derive(Debug, Args)]
pub struct QueryArgs {
    /// GitHub repository URL to look up.
    pub url: String,
    /// Read only existing tool state; never probe the live machine.
    #[arg(long)]
    pub cached: bool,
}

#[derive(Debug, Args)]
pub struct ResumeArgs {
    /// Saved scan request ID.
    pub scan_id: String,
}

#[derive(Debug, Args)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub action: CacheAction,
}

#[derive(Debug, Subcommand)]
pub enum CacheAction {
    /// Durably invalidate scope and schedule reconciliation.
    Invalidate(InvalidateArgs),
    /// Remove only verified tool-owned persisted payload.
    Clear(ClearArgs),
}

#[derive(Debug, Args)]
pub struct InvalidateArgs {
    /// Root path whose scope must be invalidated.
    #[arg(long)]
    pub root: PathBuf,
}

#[derive(Debug, Args)]
pub struct ClearArgs {
    /// Confirm removal of all tool-owned persisted payload.
    #[arg(long)]
    pub all: bool,
}
