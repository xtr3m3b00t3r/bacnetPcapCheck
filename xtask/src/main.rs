//! `cargo xtask docs-build` writes `docs/index.html` from `docs/src/*.md` and the code.

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
    /// Build the self-contained documentation site at docs/index.html
    DocsBuild,
}

fn main() -> ExitCode {
    match Args::parse().task {
        Task::DocsBuild => {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
            let html = match xtask::docs::build_site(&root.join("docs/src")) {
                Ok(html) => html,
                Err(e) => {
                    eprintln!("docs-build failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let out = root.join("docs/index.html");
            if let Err(e) = std::fs::write(&out, &html) {
                eprintln!("cannot write {}: {e}", out.display());
                return ExitCode::FAILURE;
            }
            println!("wrote docs/index.html ({} KB)", html.len() / 1024);
            ExitCode::SUCCESS
        }
    }
}
