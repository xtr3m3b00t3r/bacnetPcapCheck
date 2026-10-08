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

/// The site root: the landing page. Separate file from the manual.
fn landing() -> String {
    xtask::docs::build_landing_page()
}

/// The manual: the existing self-contained one-file documentation site.
fn manual() -> String {
    build_site(docs_src()).expect("site builds")
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
fn site_is_self_contained_and_subpath_safe() {
    // Every page of the site: the landing page and the manual.
    let pages = [landing(), manual()];
    // Root-relative URLs break under the /bacnetPcapCheck/ GitHub Pages subpath, so no
    // page, stylesheet or script may use one.
    for forbidden in [
        "href=\"/",
        "src=\"/",
        "srcset=\"/",
        "href='/",
        "src='/",
        "url(/",
        "url('/",
        "url(\"/",
    ] {
        for html in &pages {
            assert!(
                !html.contains(forbidden),
                "found root-relative URL ({forbidden})"
            );
        }
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
        for html in &pages {
            assert!(
                !html.contains(forbidden),
                "found external resource ({forbidden})"
            );
        }
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
        xtask::docs::build_landing_page() == committed,
        "docs/index.html is stale. Run `cargo xtask docs-build`."
    );
    let committed = std::fs::read_to_string(docs_src().join("../manual.html"))
        .expect("docs/manual.html is committed");
    assert!(
        built == committed,
        "docs/manual.html is stale. Run `cargo xtask docs-build`."
    );
}

#[test]
fn landing_page_says_what_it_is_and_links_to_manual_and_download() {
    let page = landing();
    // The manual and the download are both reachable from the landing page, at their new
    // locations. The download points at the releases page; the manual stays relative.
    assert!(page.contains("href=\"manual.html\""), "no manual link");
    assert!(
        page.contains("https://github.com/xtr3m3b00t3r/bacnetPcapCheck/releases"),
        "no download link"
    );
    // The author block is short, links the profile, and carries no hire-me call to action.
    assert!(
        page.contains("https://www.linkedin.com/in/benjamin-dw-truman/"),
        "no LinkedIn link"
    );
    // The no-outbound-calls rule is stated on the site, not just tested.
    assert!(
        page.contains("outbound"),
        "no statement of the no-outbound-calls rule"
    );
}
