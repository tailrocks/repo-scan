//! xtask — repo-scan proof acceptance runner (goal section 3).
//!
//! Single documented invocation path:
//!
//! ```sh
//! cargo run --locked -p xtask -- proof inventory
//! cargo run --locked -p xtask -- proof baseline --policy proof/policy.json --bin <bin> --dataset dir-heavy
//! cargo run --locked -p xtask -- proof red --requirements proof/requirements.json
//! cargo run --locked -p xtask -- proof benchmark --policy proof/policy.json \
//!     --baseline-bin <a> --candidate-bin <b> --scenario <id> --blocks 20
//! cargo run --locked -p xtask -- proof integration --matrix proof/platforms.json
//! cargo run --locked -p xtask -- proof evaluate --run-dir proof-out/<run-id>
//! cargo run --locked -p xtask -- proof verify-final --commit <sha>
//! ```
//!
//! Exit codes follow goal section 3.2:
//! 0 = PASS, 1 = FAIL, 2 = INVALID_EVIDENCE, 3 = BLOCKED.
//! An absent sample, malformed JSON, unrecognized platform, or skipped
//! mandatory test is never converted into exit 0.

mod baseline;
mod benchmark;
mod canon;
mod evaluate;
mod experiments;
mod integration;
mod policy;
mod requirements;
mod runs;
mod sources;
mod stats;
mod verify;

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
    /// Run a binary against a dataset recipe, capturing timing samples and
    /// counters into `proof-out/<run-id>/` with a run manifest.
    Baseline {
        #[arg(long, default_value = "proof/policy.json")]
        policy: PathBuf,
        /// Binary under measurement.
        #[arg(long)]
        bin: PathBuf,
        /// Dataset recipe id (`proof/datasets/<id>.json`) or path to a recipe.
        #[arg(long)]
        dataset: String,
        /// Repetitions (default 5).
        #[arg(long)]
        samples: Option<usize>,
        /// Output root for run evidence.
        #[arg(long, default_value = "proof-out")]
        out_root: PathBuf,
        /// Arguments passed to the measured binary (after --).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// List requirements with empty green_evidence; exit 1 while any
    /// required item lacks evidence (shows the pending state).
    Red {
        #[arg(long, default_value = "proof/requirements.json")]
        requirements: PathBuf,
    },
    /// Validate a run directory's integrity, recompute statistics, compare
    /// against the frozen policy gates, and emit the verdict JSON.
    Evaluate {
        /// Run directory produced by `proof benchmark`.
        #[arg(long)]
        run_dir: PathBuf,
    },
    /// Run the integration test matrix (default: cargo test --locked
    /// --test '*'), capture the full log, classify per-file results, and
    /// fail on failures or skipped/absent mandatory tests.
    Integration {
        #[arg(long, default_value = "proof/platforms.json")]
        matrix: PathBuf,
        /// Repository to test (default: current directory).
        #[arg(long)]
        repo: Option<PathBuf>,
        /// Test command to execute instead of the default cargo invocation.
        #[arg(long)]
        cmd: Option<String>,
        /// Specific mandatory native job id to execute/validate.
        #[arg(long)]
        job: Option<String>,
        /// Aggregate multiple completed per-platform run directories into a matrix verdict.
        #[arg(long, num_args = 1..)]
        aggregate: Option<Vec<PathBuf>>,
        /// Output root for run evidence.
        #[arg(long, default_value = "proof-out")]
        out_root: PathBuf,
    },
    /// Final reconciliation: every mandatory requirement has green evidence
    /// with verifier != implementer, evidence hashes match, every experiment
    /// has a valid disposition, source coverage is complete, and the named
    /// commit exists. Prints PASS only then.
    VerifyFinal {
        /// Final code commit to reconcile.
        #[arg(long)]
        commit: String,
        #[arg(long, default_value = "proof/requirements.json")]
        requirements: PathBuf,
        #[arg(long, default_value = "proof/sources.lock.json")]
        sources: PathBuf,
        #[arg(long, default_value = "proof/experiments.json")]
        experiments: PathBuf,
        /// Repository to reconcile against (default: current directory).
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    /// Paired-block benchmark between two binaries with seeded randomized
    /// balanced order; raw samples are written as JSONL to the run dir.
    Benchmark {
        #[arg(long, default_value = "proof/policy.json")]
        policy: PathBuf,
        #[arg(long)]
        baseline_bin: PathBuf,
        #[arg(long)]
        candidate_bin: PathBuf,
        /// Scenario id from the frozen policy.
        #[arg(long)]
        scenario: String,
        /// Paired blocks (default: policy minimum; never below it).
        #[arg(long)]
        blocks: Option<usize>,
        /// RNG seed for block order (default: policy seed).
        #[arg(long)]
        seed: Option<u64>,
        /// Comma-separated gate ids to declare for later evaluation
        /// (default: PERF-PRIMARY for the primary scenario, else
        /// PERF-NOREGRESS).
        #[arg(long)]
        gates: Option<String>,
        /// Output root for run evidence.
        #[arg(long, default_value = "proof-out")]
        out_root: PathBuf,
        /// Arguments passed to both binaries (after --).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Proof { command } => match command {
            ProofCommands::Inventory { repo, sources } => sources::cmd_inventory(repo, &sources),
            ProofCommands::Baseline {
                policy,
                bin,
                dataset,
                samples,
                out_root,
                args,
            } => baseline::cmd_baseline(&policy, &bin, &dataset, samples, &out_root, &args),
            ProofCommands::Red { requirements } => requirements::cmd_red(&requirements),
            ProofCommands::Evaluate { run_dir } => evaluate::cmd_evaluate(&run_dir),
            ProofCommands::Integration {
                matrix,
                repo,
                cmd,
                job,
                aggregate,
                out_root,
            } => integration::cmd_integration(&matrix, repo, cmd, job, aggregate, &out_root),
            ProofCommands::VerifyFinal {
                commit,
                requirements,
                sources,
                experiments,
                repo,
            } => verify::cmd_verify_final(&commit, &requirements, &sources, &experiments, repo),
            ProofCommands::Benchmark {
                policy,
                baseline_bin,
                candidate_bin,
                scenario,
                blocks,
                seed,
                gates,
                out_root,
                args,
            } => benchmark::cmd_benchmark(
                &policy,
                &baseline_bin,
                &candidate_bin,
                &scenario,
                blocks,
                seed,
                gates,
                &out_root,
                &args,
            ),
        },
    };
    std::process::exit(code);
}
