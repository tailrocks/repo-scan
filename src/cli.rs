//! CLI surface (spec §3 + goal Step 6). Parses the scan/query/resume/cache
//! commands with their target, scope, format, and follow controls. No
//! business logic here beyond contradictory-option validation.

use crate::model::{Scope, StatusMode};
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// repo-scan: discover local clones of GitHub repositories.
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

/// The six exact commands from spec §3, extended per goal Step 6.
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

/// Machine/human output selection (goal Step 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Live human view (interactive terminal default).
    Human,
    /// One valid JSON snapshot at the command boundary.
    Json,
    /// Newline-delimited JSON events (redirected-output default).
    Jsonl,
}

impl OutputFormat {
    /// Step 6 auto-selection (Wave6): an explicit `--format` always wins;
    /// otherwise the live human view goes to a terminal and JSONL goes to
    /// redirected output. Never yields `Json` by default (a bare command
    /// never prints a bare snapshot). Every command resolves through this
    /// one selector so TTY/redirected behavior stays uniform and
    /// unit-testable.
    pub fn resolve(explicit: Option<OutputFormat>, stdout_is_tty: bool) -> OutputFormat {
        match explicit {
            Some(format) => format,
            None if stdout_is_tty => OutputFormat::Human,
            None => OutputFormat::Jsonl,
        }
    }
}

/// Interactive-TUI gate for `scan` (Step 13, Wave6 pin): only an explicit
/// `scan --format human` on a TTY opens the interactive live view. A bare
/// `scan` on a TTY keeps the legacy terminal rendering — the TTY default
/// selects the human *lane*, never the fullscreen TUI by itself.
pub fn scan_tui_gate(
    explicit: Option<OutputFormat>,
    stdout_is_tty: bool,
    stdin_is_tty: bool,
) -> bool {
    explicit == Some(OutputFormat::Human) && stdout_is_tty && stdin_is_tty
}

/// Terminal color control (goal Step 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

/// Validated scan target selection: explicit targets XOR `--all`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSet {
    /// Filesystem discovery over the planned scope (no GitHub inventory).
    All,
    /// One or more explicit `owner/name` or GitHub URL targets.
    Targets(Vec<String>),
}

/// Validated query selection: exactly one of target / `--all` / `--scan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuerySelection {
    Target(String),
    All,
    Scan(String),
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// GitHub targets: `owner/name` or supported GitHub URL forms.
    /// Repeatable; exactly one filesystem pass serves all targets.
    /// Mutually exclusive with `--all`.
    pub targets: Vec<String>,
    /// Scan all local repositories found by filesystem discovery.
    /// Mutually exclusive with explicit targets.
    #[arg(long)]
    pub all: bool,
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
    /// `--scope` applies. With no roots, machine scope applies.
    #[arg(long)]
    pub root: Vec<PathBuf>,
    /// Output format. Default: live human view on a terminal, JSONL when
    /// redirected. An explicit value always wins.
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,
    /// After discovery and local analysis, fetch current remote state.
    /// Updates remote-tracking refs, FETCH_HEAD, and fetched objects
    /// only; checkout files and local branch tips are never moved
    /// (unsafe refspecs report `unsupported` instead of writing). No
    /// prune, no tags, no submodules, no automatic maintenance.
    #[arg(long)]
    pub fetch: bool,
    /// Terminal color control. `NO_COLOR` and `TERM=dumb` also disable color.
    #[arg(long, value_enum)]
    pub color: Option<ColorChoice>,
    /// Parallel read workers for discovery and analysis. Default: the
    /// platform's available parallelism (4 when unknown). Values above
    /// 32 clamp to 32; 0 is rejected. Saved with the request and
    /// restored on resume.
    #[arg(long)]
    pub workers: Option<usize>,
}

impl ScanArgs {
    /// Validate the target selection: explicit targets XOR `--all`.
    pub fn target_set(&self) -> Result<TargetSet, String> {
        match (self.all, self.targets.is_empty()) {
            (true, false) => Err(String::from(
                "--all cannot be combined with explicit targets",
            )),
            (true, true) => Ok(TargetSet::All),
            (false, true) => Err(String::from("provide at least one TARGET or --all")),
            (false, false) => Ok(TargetSet::Targets(self.targets.clone())),
        }
    }

    /// The single explicit target for the current single-target execution
    /// path. `None` for `--all`, zero, or multiple targets.
    pub fn primary_target(&self) -> Option<&str> {
        if self.all || self.targets.len() != 1 {
            return None;
        }
        self.targets.first().map(String::as_str)
    }
}

#[derive(Debug, Args)]
pub struct QueryArgs {
    /// GitHub repository target (`owner/name` or URL) to look up.
    /// Exactly one of TARGET, `--all`, `--scan` is required.
    pub target: Option<String>,
    /// Query all local repositories in the catalog.
    #[arg(long)]
    pub all: bool,
    /// Follow or inspect one saved scan request.
    #[arg(long)]
    pub scan: Option<String>,
    /// Read only existing tool state; never probe the live machine.
    #[arg(long)]
    pub cached: bool,
    /// Output format (default: human on a terminal, JSONL redirected).
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,
    /// Follow committed scan data as it arrives. Human or JSONL only:
    /// `--follow --format json` is rejected (JSON is one snapshot).
    #[arg(long)]
    pub follow: bool,
    /// Resume a following reader after this opaque cursor. Requires `--follow`.
    #[arg(long)]
    pub after: Option<String>,
}

impl QueryArgs {
    /// Validate the query selection and follow/format combination.
    pub fn selection(&self) -> Result<QuerySelection, String> {
        if self.follow && self.format == Some(OutputFormat::Json) {
            return Err(String::from(
                "--follow --format json is rejected: JSON supplies one snapshot; use human or jsonl",
            ));
        }
        if self.after.is_some() && !self.follow {
            return Err(String::from("--after requires --follow"));
        }
        match (&self.target, self.all, &self.scan) {
            (Some(t), false, None) => Ok(QuerySelection::Target(t.clone())),
            (None, true, None) => Ok(QuerySelection::All),
            (None, false, Some(s)) => Ok(QuerySelection::Scan(s.clone())),
            _ => Err(String::from(
                "provide exactly one of TARGET, --all, or --scan SCAN_ID",
            )),
        }
    }
}

#[derive(Debug, Args)]
pub struct ResumeArgs {
    /// Saved scan request ID.
    pub scan_id: String,
    /// Output format (default: human on a terminal, JSONL redirected).
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,
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
