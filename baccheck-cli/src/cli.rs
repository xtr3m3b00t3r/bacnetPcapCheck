//! Argument definitions for `baccheck`. Doc comments here become the generated CLI reference.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use baccheck_core::report::Severity as CoreSeverity;

/// Analyse a BACnet/IP capture for common network problems.
#[derive(Parser)]
#[command(name = "baccheck", version)]
pub struct Cli {
    /// Path to the .pcap or .pcapng capture to analyse
    pub capture: PathBuf,

    /// Where to write the report: a file path, or a directory (default: alongside the capture)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Hide findings below this severity in the report (never affects the exit code)
    #[arg(short = 's', long, value_enum)]
    pub min_severity: Option<Severity>,

    /// Print decode and parse diagnostics to stderr
    #[arg(short, long, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Do not print the summary line (errors still print)
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Copy, Clone, ValueEnum)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl From<Severity> for CoreSeverity {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::Critical => CoreSeverity::Critical,
            Severity::High => CoreSeverity::High,
            Severity::Medium => CoreSeverity::Medium,
            Severity::Low => CoreSeverity::Low,
        }
    }
}
