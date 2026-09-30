//! Binary entry point: parse CLI, dispatch to handlers, exit with the
//! spec §3 code (0/1/2/3/130). Clap parse failures exit 2 by default.

use clap::Parser;
use repo_scan::cli::{CacheAction, Cli, Command};
use repo_scan::model::ExitCode;

fn main() {
    std::process::exit(dispatch().code());
}

fn dispatch() -> ExitCode {
    // TODO(phase-2): install signal handling; on SIGINT perform the bounded
    // progress save, then return ExitCode::Interrupted (130).
    let cli = Cli::parse();
    match &cli.command {
        Command::Scan(args) => scan(args),
        Command::Query(args) => query(args),
        Command::Resume(args) => resume(args),
        Command::Cache(args) => match &args.action {
            CacheAction::Invalidate(args) => invalidate(args),
            CacheAction::Clear(args) => clear(args),
        },
    }
}

// TODO(phase-2+): move each handler into its owning module and implement the
// spec §3 command table. Stubs return InvalidArgs until wired.

fn scan(_args: &repo_scan::cli::ScanArgs) -> ExitCode {
    todo!("scan: resolve target, reuse catalog, reconcile, publish report")
}

fn query(_args: &repo_scan::cli::QueryArgs) -> ExitCode {
    todo!("query --cached: read state only, show freshness and gaps")
}

fn resume(_args: &repo_scan::cli::ResumeArgs) -> ExitCode {
    todo!("resume: restore saved request, idempotent terminal replay")
}

fn invalidate(_args: &repo_scan::cli::InvalidateArgs) -> ExitCode {
    todo!("cache invalidate: durable invalidation + reconciliation schedule")
}

fn clear(_args: &repo_scan::cli::ClearArgs) -> ExitCode {
    todo!("cache clear --all: fenced, verified tool-owned payload removal")
}
