//! Docs generator contract (spec #16, "Docs xtask"): the generated fragments must cover every
//! CLI flag and every issue, and the assembled site must hold all 13 pages and stay offline.

use std::path::Path;

use baccheck_core::report::IssueId;
use clap::CommandFactory;

use xtask::docs::{build_site, cli_flags_fragment, issue_catalogue_fragment, PAGES};

#[test]
fn cli_fragment_names_every_defined_flag() {
    let fragment = cli_flags_fragment();
    let command = baccheck_cli::cli::Cli::command();
    let mut checked = 0;
    for arg in command.get_arguments().filter(|a| !a.is_positional()) {
        let long = arg.get_long().expect("every flag has a long name");
        if long == "help" {
            continue;
        }
        assert!(fragment.contains(&format!("--{long}")), "missing --{long}");
        checked += 1;
    }
    assert!(
        checked >= 4,
        "expected output, min-severity, verbose, quiet"
    );
    assert!(fragment.contains("<CAPTURE>"));
}

#[test]
fn issue_fragment_lists_every_issue_with_its_remediation() {
    let fragment = issue_catalogue_fragment();
    assert_eq!(IssueId::ALL.len(), 10);
    for issue in IssueId::ALL {
        assert!(
            fragment.contains(issue.as_str()),
            "missing {}",
            issue.as_str()
        );
        for step in issue.spec().remediation {
            assert!(
                fragment.contains(step),
                "missing step of {}",
                issue.as_str()
            );
        }
    }
}

fn docs_src() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/src"))
}

#[test]
fn site_holds_all_thirteen_pages() {
    assert_eq!(PAGES.len(), 13);
    let html = build_site(docs_src()).expect("site builds");
    for page in PAGES {
        assert!(
            html.contains(&format!("id=\"page-{}\"", page.slug)),
            "missing page {}",
            page.slug
        );
    }
}

#[test]
fn site_is_self_contained() {
    let html = build_site(docs_src()).expect("site builds");
    for forbidden in ["<link", "<script src", "@import", "src=\"http", "url(http"] {
        assert!(!html.contains(forbidden), "found {forbidden}");
    }
}

#[test]
fn site_loads_no_external_resources_and_has_no_root_relative_links() {
    let html = build_site(docs_src()).expect("site builds");
    // Root-relative URLs break under the /bacnetPcapCheck/ GitHub Pages subpath.
    for forbidden in ["href=\"/", "src=\"/", "srcset=\"/", "href='/", "src='/"] {
        assert!(
            !html.contains(forbidden),
            "found root-relative URL ({forbidden})"
        );
    }
    // Resource loads from another origin. Hyperlinks (<a href="https://…") are fine; the
    // footer's LinkedIn link is one. Analytics and tracking elements are covered above too:
    // they all load from another origin.
    for forbidden in [
        "<script src=",
        "<link ",
        "<img ",
        "<iframe",
        "<embed",
        "<object",
        "@import",
        "url(http",
        "src='http",
        "src=\"http",
    ] {
        assert!(
            !html.contains(forbidden),
            "found external resource ({forbidden})"
        );
    }
}

#[test]
fn generated_markers_are_all_replaced() {
    let html = build_site(docs_src()).expect("site builds");
    assert!(!html.contains("GENERATED:"));
    assert!(html.contains("--min-severity"));
    assert!(html.contains("foreign-device-registration-failure"));
}

#[test]
fn committed_site_matches_the_sources() {
    let built = build_site(docs_src()).expect("site builds");
    let committed = std::fs::read_to_string(docs_src().join("../index.html"))
        .expect("docs/index.html is committed");
    assert!(
        built == committed,
        "docs/index.html is stale. Run `cargo xtask docs-build`."
    );
}
