//! xtask — repo-scan proof acceptance runner (goal section 3).
//!
//! Single documented invocation path:
//!
//! ```sh
//! cargo run --locked -p xtask -- proof inventory
//! cargo run --locked -p xtask -- proof red --requirements proof/requirements.json
//! ```
//!
//! Exit codes follow goal section 3.2:
//! 0 = PASS, 1 = FAIL, 2 = INVALID_EVIDENCE, 3 = BLOCKED.
//! An absent sample, malformed JSON, unrecognized platform, or skipped
//! mandatory test is never converted into exit 0.

mod canon;
mod requirements;
mod sources;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub const EXIT_PASS: i32 = 0;
pub const EXIT_FAIL: i32 = 1;
pub const EXIT_INVALID: i32 = 2;
pub const EXIT_BLOCKED: i32 = 3;

/// Print a machine-readable verdict object on stdout and exit with `code`.
pub fn emit_exit(code: i32, verdict: &str, detail: serde_json::Value) -> ! {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "verdict".to_string(),
        serde_json::Value::String(verdict.to_string()),
    );
    if let serde_json::Value::Object(extra) = detail {
        obj.extend(extra);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::Value::Object(obj)).expect("verdict json")
    );
    std::process::exit(code);
}

pub fn invalid(msg: impl Into<String>) -> ! {
    emit_exit(
        EXIT_INVALID,
        "INVALID_EVIDENCE",
        serde_json::json!({"error": msg.into()}),
    )
}

pub fn blocked(msg: impl Into<String>) -> ! {
    emit_exit(
        EXIT_BLOCKED,
        "BLOCKED",
        serde_json::json!({"error": msg.into()}),
    )
}

#[derive(Parser)]
#[command(
    name = "xtask",
    version,
    about = "repo-scan proof acceptance runner (goal section 3)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Executable proof system commands.
    Proof {
        #[command(subcommand)]
        command: ProofCommands,
    },
}

#[derive(Subcommand)]
enum ProofCommands {
    /// Validate the frozen sources lock against a live repository: every
    /// listed frozen ref exists with matching SHA/tree/parents, and no
    /// omitted or extra sources exist under refs/goal/sources/.
    Inventory {
        /// Repository to inspect (default: current directory).
        #[arg(long)]
        repo: Option<PathBuf>,
        /// Frozen sources lock file.
        #[arg(long, default_value = "proof/sources.lock.json")]
        sources: PathBuf,
    },
    /// List requirements with empty green_evidence; exit 1 while any
    /// required item lacks evidence (shows the pending state).
    Red {
        #[arg(long, default_value = "proof/requirements.json")]
        requirements: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Proof { command } => match command {
            ProofCommands::Inventory { repo, sources } => sources::cmd_inventory(repo, &sources),
            ProofCommands::Red { requirements } => requirements::cmd_red(&requirements),
        },
    };
    std::process::exit(code);
}
