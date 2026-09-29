//! Thin CLI wiring around `baccheck-core`. See wayfinder ticket #10 for the decided surface.
//!
//! Exit codes: `0` no findings, `1` findings present (any severity, whatever `--min-severity`
//! says), `2` usage error (clap), `3` input error, `4` internal failure (also: report not written).
//! Still inert: the first-run notice, and `--verbose` beyond the frame counts.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

use baccheck_core::analyse_capture;
use baccheck_core::report::{render_html, Severity as CoreSeverity};

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

/// `<capture-stem>.baccheck.html`, next to the capture unless `--output` says otherwise.
fn report_path(capture: &Path, output: Option<&Path>) -> PathBuf {
    let file_name = format!(
        "{}.baccheck.html",
        capture
            .file_stem()
            .unwrap_or(capture.as_os_str())
            .to_string_lossy()
    );
    match output {
        Some(dir) if dir.is_dir() => dir.join(file_name),
        Some(file) => file.to_path_buf(),
        None => capture.with_file_name(file_name),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let report = match analyse_capture(&cli.capture) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("Error. Baccheck cannot read the capture. {e}");
            return ExitCode::from(3);
        }
    };

    let path = report_path(&cli.capture, cli.output.as_deref());
    let html = render_html(&report, cli.min_severity.map(CoreSeverity::from));
    if let Err(e) = std::fs::write(&path, html) {
        eprintln!(
            "Error. Baccheck cannot write the report to {}. {e}",
            path.display()
        );
        return ExitCode::from(4);
    }

    let stats = &report.stats;
    if cli.verbose {
        println!(
            "{} frame(s) read. {} decoded. {} undecoded. {} not BACnet.",
            stats.total_frames,
            stats.decoded_frames,
            stats.undecoded_frames,
            stats.non_bacnet_frames
        );
    }
    if report.capture_health_warning && !cli.quiet {
        eprintln!("Warning. More than half of the capture is not decodable BACnet. Read the report with care.");
    }
    let count = report.findings.len();
    println!(
        "Baccheck found {count} {}. The report is at {}.",
        if count == 1 { "finding" } else { "findings" },
        path.display()
    );

    ExitCode::from(if count == 0 { 0 } else { 1 })
}
