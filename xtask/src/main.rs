//! `cargo xtask docs-build` writes the site: the landing page at `docs/index.html` and the
//! self-contained manual at `docs/manual.html`, both from `docs/src/*.md` and the code.

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
    /// Build the landing page (docs/index.html) and the manual (docs/manual.html)
    DocsBuild,
}

fn main() -> ExitCode {
    match Args::parse().task {
        Task::DocsBuild => {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
            let landing = xtask::docs::build_landing_page();
            if let Err(e) = std::fs::write(root.join("docs/index.html"), &landing) {
                eprintln!("cannot write docs/index.html: {e}");
                return ExitCode::FAILURE;
            }
            let html = match xtask::docs::build_site(&root.join("docs/src")) {
                Ok(html) => html,
                Err(e) => {
                    eprintln!("docs-build failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(e) = std::fs::write(root.join("docs/manual.html"), &html) {
                eprintln!("cannot write docs/manual.html: {e}");
                return ExitCode::FAILURE;
            }
            println!(
                "wrote docs/index.html ({} KB), docs/manual.html ({} KB)",
                landing.len() / 1024,
                html.len() / 1024
            );
            ExitCode::SUCCESS
        }
    }
}
