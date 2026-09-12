//! Thin CLI wiring around `baccheck-core`. See wayfinder ticket #10 for the decided surface.
//!
//! Only the parts with something behind them are wired up here: argument parsing and exit codes
//! `0` (no findings — currently just "read the capture without error"), `2` (usage error, handled
//! by clap itself), and `3` (input error). `--output` and `--min-severity` are accepted and
//! validated but have no effect yet, and exit codes `1` (findings present) and `4` (decode
//! failure) are unreachable, because the decoding, detection, and report-generation seams
//! (wayfinder tickets #7, #4, #6) don't exist yet.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

use baccheck_core::pcap::read_capture;

/// Analyse a BACnet/IP capture for common network problems.
#[derive(Parser)]
#[command(name = "baccheck", version)]
struct Cli {
    /// Path to the .pcap or .pcapng capture to analyse
    capture: PathBuf,

    /// Where to write the report: a file path, or a directory (default: alongside the capture)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Hide findings below this severity in the report (never affects the exit code)
    #[arg(short = 's', long, value_enum)]
    min_severity: Option<Severity>,

    /// Print extra detail while running
    #[arg(short, long)]
    verbose: bool,

    /// Print nothing but the final summary line
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let _not_yet_wired = (&cli.output, cli.min_severity, cli.verbose);

    let packets = match read_capture(&cli.capture) {
        Ok(packets) => packets,
        Err(e) => {
            eprintln!("Error. Baccheck cannot read the capture. {e}");
            return ExitCode::from(3);
        }
    };

    let mut frame_count: u64 = 0;
    for packet in packets {
        match packet {
            Ok(_) => frame_count += 1,
            Err(e) => {
                eprintln!("Error. Baccheck cannot read the capture. {e}");
                return ExitCode::from(3);
            }
        }
    }

    if !cli.quiet {
        println!("{frame_count} frame(s) read from {}", cli.capture.display());
    }
    ExitCode::from(0)
}
