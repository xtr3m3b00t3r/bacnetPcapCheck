//! The first-run notice. It prints once to stderr and never blocks the run.
//!
//! Acknowledgement lives in `baccheck/state.toml` in the per-user config directory. The file holds
//! one key, `acknowledged_notice`, the revision of the notice the user has seen. Raise
//! [`NOTICE_REVISION`] when the notice text changes in a way that needs a new reading.

use std::path::PathBuf;

use directories::ProjectDirs;

const NOTICE_REVISION: u32 = 1;
const STATE_KEY: &str = "acknowledged_notice";

const NOTICE: &str = "\
Notice. This is the first run of Baccheck.
Baccheck is free software under the MIT licence.
Baccheck is not a commercial product. It has no warranty.
Baccheck makes no network calls. It reads your capture and writes a report.
Baccheck shows this notice one time.";

fn state_path() -> Option<PathBuf> {
    ProjectDirs::from("", "", "baccheck").map(|dirs| dirs.config_dir().join("state.toml"))
}

fn acknowledged(contents: &str) -> bool {
    contents.lines().any(|line| {
        line.split_once('=').is_some_and(|(key, value)| {
            key.trim() == STATE_KEY
                && value
                    .trim()
                    .parse::<u32>()
                    .is_ok_and(|seen| seen >= NOTICE_REVISION)
        })
    })
}

/// Prints the notice when the user has not seen this revision, then records that they have.
/// A state file that cannot be read or written never stops the run.
pub fn show_first_run_notice() {
    let Some(path) = state_path() else {
        return;
    };
    if std::fs::read_to_string(&path).is_ok_and(|contents| acknowledged(&contents)) {
        return;
    }
    eprintln!("{NOTICE}");
    let write = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::write(&path, format!("{STATE_KEY} = {NOTICE_REVISION}\n")));
    if write.is_err() {
        eprintln!("Baccheck cannot save this choice. It will show the notice again.");
    }
}
