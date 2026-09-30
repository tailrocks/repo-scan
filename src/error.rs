//! Structured errors. Every variant maps to a spec §3 exit code via
//! [`Error::exit_code`]. Production paths must return these, never panic.

use crate::model::ExitCode;

/// Top-level repo-scan error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid CLI arguments or configuration (exit 2).
    #[error("invalid arguments: {0}")]
    InvalidArgs(String),
    /// Invalid configuration file or state-directory layout (exit 2).
    #[error("config error: {0}")]
    Config(String),
    /// Durable store failure: commit, checkpoint, migration, IO (exit 1).
    #[error("store error: {0}")]
    Store(String),
    /// Scheduler invariant violation (exit 1).
    #[error("scheduler error: {0}")]
    Scheduler(String),
    /// Filesystem enumeration failure for one scope (gap, usually exit 3).
    #[error("walk error: {0}")]
    Walk(String),
    /// Git probe failure (exit 1 for operational, gap for unsupported).
    #[error("git error: {0}")]
    Git(String),
    /// Identity could not be resolved under the matching policy (exit 3).
    #[error("unresolvable identity: {0}")]
    UnresolvableIdentity(String),
    /// Event-history handling failure (exit 1).
    #[error("events error: {0}")]
    Events(String),
    /// Report publication failure; snapshot retained (exit 1).
    #[error("report error: {0}")]
    Report(String),
    /// Platform facility failure (exit 1).
    #[error("platform error: {0}")]
    Platform(String),
    /// Underlying IO failure (exit 1).
    #[error("io error: {0}")]
    Io(String),
    /// Request superseded by a successor scan (exit 3).
    #[error("superseded by {0}")]
    Superseded(String),
    /// Usable result with unresolved coverage/identity/status gaps (exit 3).
    #[error("incomplete: {0}")]
    Incomplete(String),
    /// Interrupted by the user after bounded progress save (exit 130).
    #[error("interrupted")]
    Interrupted,
}

impl Error {
    /// Map this error to its spec §3 exit code.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Error::InvalidArgs(_) | Error::Config(_) => ExitCode::InvalidArgs,
            Error::Superseded(_)
            | Error::Incomplete(_)
            | Error::UnresolvableIdentity(_)
            | Error::Walk(_) => ExitCode::Incomplete,
            Error::Interrupted => ExitCode::Interrupted,
            _ => ExitCode::OperationalFailure,
        }
    }

    /// True when the condition is retryable after backoff or new evidence.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Walk(_)
                | Error::UnresolvableIdentity(_)
                | Error::Incomplete(_)
                | Error::Events(_)
        )
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

/// Fallible result with [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
