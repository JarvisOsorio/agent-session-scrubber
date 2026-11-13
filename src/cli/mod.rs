pub mod commands;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "agentscrub",
    version,
    about = "Local-first secret & PII scrubber for AI agent session transcripts",
    long_about = "Discovers, scans, classifies, and redacts sensitive data in agent transcripts. Offline by default. Dry-run by default. No telemetry."
)]
pub struct Cli {
    /// Path to TOML config (defaults to config/default.toml when present)
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Extra discovery roots / scan targets
    #[arg(long = "path", global = true)]
    pub paths: Vec<PathBuf>,

    /// Output format
    #[arg(long, global = true, default_value = "terminal")]
    pub format: OutputFormat,

    /// Write JSON report to this path
    #[arg(long, global = true)]
    pub output: Option<PathBuf>,

    /// Increase logging verbosity
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Markdown,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Discover agent session files under configured roots
    Discover {
        /// Force adapter id (claude_code, codex, cursor, generic_jsonl, generic_json)
        #[arg(long)]
        adapter: Option<String>,
    },
    /// Scan discovered or specified files for secrets and PII
    Scan {
        #[arg(long)]
        adapter: Option<String>,
        /// Treat .jsonl as generic_jsonl
        #[arg(long, value_name = "FORMAT")]
        force_format: Option<String>,
    },
    /// Emit a report from a previous scan JSON (or re-scan)
    Report {
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Redact findings (dry-run by default)
    Scrub {
        #[arg(long)]
        adapter: Option<String>,
        /// Apply changes (otherwise dry-run)
        #[arg(long)]
        confirm: bool,
        /// Disable .bak backups when confirming
        #[arg(long)]
        no_backup: bool,
    },
    /// Verify a file no longer contains previously found fingerprints (or any findings)
    Verify {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Fingerprints that must be absent
        #[arg(long = "fingerprint")]
        fingerprints: Vec<String>,
    },
    /// Retention planning / status (deletion behind feature flag)
    Retention {
        #[command(subcommand)]
        action: RetentionCommands,
    },
    /// Show effective configuration
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum RetentionCommands {
    Status,
    Plan,
    Apply {
        #[arg(long)]
        confirm: bool,
    },
    Verify,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ConfigCommands {
    Show,
    Path,
}
