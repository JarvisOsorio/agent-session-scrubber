use std::path::PathBuf;
use thiserror::Error;

/// Process exit codes per the agentscrub specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Ok = 0,
    General = 1,
    BadArgs = 2,
    Unsupported = 3,
    Permission = 4,
    Validation = 5,
    Remediation = 6,
    Policy = 7,
    IncompleteScan = 8,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

#[derive(Debug, Error)]
pub enum AgentscrubError {
    #[error("invalid arguments: {0}")]
    BadArgs(String),

    #[error("unsupported operation or format: {0}")]
    Unsupported(String),

    #[error("permission denied: {0}")]
    Permission(String),

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("remediation failed: {0}")]
    Remediation(String),

    #[error("policy violation: {0}")]
    Policy(String),

    #[error("incomplete scan: {0}")]
    IncompleteScan(String),

    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("config error: {0}")]
    Config(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl AgentscrubError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::BadArgs(_) => ExitCode::BadArgs,
            Self::Unsupported(_) => ExitCode::Unsupported,
            Self::Permission(_) => ExitCode::Permission,
            Self::Validation(_) => ExitCode::Validation,
            Self::Remediation(_) => ExitCode::Remediation,
            Self::Policy(_) => ExitCode::Policy,
            Self::IncompleteScan(_) => ExitCode::IncompleteScan,
            Self::Io { .. } | Self::Config(_) | Self::Other(_) => ExitCode::General,
        }
    }
}

pub type Result<T> = std::result::Result<T, AgentscrubError>;
