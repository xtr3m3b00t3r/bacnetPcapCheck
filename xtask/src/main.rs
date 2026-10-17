//! `cargo xtask docs-build` writes the site: the landing page at `docs/index.html`, the
//! self-contained manual at `docs/manual.html` (both from `docs/src/*.md` and the code), and the
//! sample report at `docs/sample-report.html` (from the synthetic sample capture).

use std::io;
use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask")]
struct Args {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Build the landing page (docs/index.html), the manual (docs/manual.html) and the sample
    /// report (docs/sample-report.html)
    DocsBuild,
}

/// Writes one built page under `docs/`, or says why it could not.
fn write_page(docs: &Path, name: &str, page: io::Result<String>) -> Result<usize, ExitCode> {
    let html = page.map_err(|e| {
        eprintln!("docs-build failed on docs/{name}: {e}");
        ExitCode::FAILURE
    })?;
    std::fs::write(docs.join(name), &html).map_err(|e| {
        eprintln!("cannot write docs/{name}: {e}");
        ExitCode::FAILURE
    })?;
    Ok(html.len() / 1024)
}

fn main() -> ExitCode {
    match Args::parse().task {
        Task::DocsBuild => {
            let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs");
            let built = (|| {
                Ok::<_, ExitCode>([
                    write_page(&docs, "index.html", Ok(xtask::docs::build_landing_page()))?,
                    write_page(
                        &docs,
                        "manual.html",
                        xtask::docs::build_site(&docs.join("src")),
                    )?,
                    write_page(
                        &docs,
                        "sample-report.html",
                        xtask::docs::build_sample_report(),
                    )?,
                ])
            })();
            match built {
                Ok([landing, manual, sample]) => {
                    println!(
                        "wrote docs/index.html ({landing} KB), docs/manual.html ({manual} KB), \
                         docs/sample-report.html ({sample} KB)"
                    );
                    ExitCode::SUCCESS
                }
                Err(code) => code,
            }
        }
    }
}
