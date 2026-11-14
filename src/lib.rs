//! Agent Session Scrubber (`agentscrub`) — local-first secret & PII remediation
//! for AI agent session transcripts.

pub mod adapters;
pub mod classification;
pub mod cli;
pub mod config;
pub mod detectors;
pub mod discovery;
pub mod errors;
pub mod models;
pub mod normalization;
pub mod policy;
pub mod remediation;
pub mod reporting;
pub mod utils;

pub use config::AppConfig;
pub use errors::{AgentscrubError, ExitCode, Result};
