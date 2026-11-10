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

/// Visible text of a built page: styles, scripts and markup stripped, whitespace collapsed.
fn seen_text(html: &str) -> String {
    let mut text = html.to_string();
    for tag in ["style", "script"] {
        let (open, close) = (format!("<{tag}"), format!("</{tag}>"));
        while let Some(start) = text.find(&open) {
            let close_at = text[start..]
                .find(&close)
                .expect("style/script block never closes");
            let end = start + close_at + close.len();
            text.replace_range(start..end, " ");
        }
    }
    // A block-level tag separates text the way a browser lays it out (`</li><li>` is two
    // lines); an inline tag does not, so a lost space before a link still shows.
    const BLOCK: [&str; 13] = [
        "p", "li", "ol", "ul", "div", "td", "th", "tr", "br", "h1", "h2", "h3", "section",
    ];
    let mut out = String::with_capacity(text.len());
    let mut tag: Option<String> = None;
    for c in text.chars() {
        match (&mut tag, c) {
            (None, '<') => tag = Some(String::new()),
            (Some(name), '>') => {
                let name = name.trim_start_matches('/');
                let name = name.split([' ', '/']).next().unwrap_or("");
                if BLOCK.contains(&name) {
                    out.push(' ');
                }
                tag = None;
            }
            (Some(name), _) => name.push(c),
            (None, _) => out.push(c),
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Loss-of-space bug signature: a letter, sentence punctuation, a capital and a letter,
/// all with no whitespace around the punctuation (as produced by string literals joined
/// across escaped newlines). "e.g." with a lowercase letter after the dot, and camel
/// case without punctuation, do not match.
fn lost_space(text: &str) -> Option<usize> {
    let cs: Vec<char> = text.chars().collect();
    for (i, w) in cs.windows(4).enumerate() {
        let (a, p, b, c) = (w[0], w[1], w[2], w[3]);
        if a.is_ascii_lowercase()
            && ";,.".contains(p)
            && b.is_ascii_uppercase()
            && c.is_ascii_lowercase()
        {
            return text.char_indices().nth(i).map(|(byte, _)| byte);
        }
    }
    None
}

/// Glyphs that legitimately appear in the prose, beyond ASCII. Kept explicit and tiny:
/// a stray non-ASCII fragment in prose is corruption, these are deliberate typography.
fn is_allowed_glyph(c: char) -> bool {
    matches!(c, '·' | '–' | '—')
}

#[test]
fn visible_text_is_clean() {
    // The staleness guard compares built output to itself, so a glitch baked into the
    // builder reproduces itself faithfully. Guard the built text itself, on every page:
    // no stray non-ASCII glyph beyond the documented allowlist, and no lost whitespace
    // after sentence punctuation. Both failed once in real output (a stray CJK fragment
    // in a doc comment and "business.Benjamin"), which is what this test catches.
    let pages = [landing(), manual(), sample_report()];
    for html in &pages {
        let text = seen_text(html);
        for c in text.chars() {
            assert!(
                c.is_ascii() || is_allowed_glyph(c),
                "stray non-ASCII glyph {c:?} in built page text"
            );
        }
        if let Some(pos) = lost_space(&text) {
            let from = text[..pos].rfind(' ').unwrap_or(0);
            let to = pos + 12;
            panic!(
                "lost whitespace after punctuation in built page text: …{}…",
                &text[from..to.min(text.len())]
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

/// The sample report: the real report rendered from the synthetic sample capture.
fn sample_report() -> String {
    xtask::docs::build_sample_report().expect("sample report builds")
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

/// URL forms that break under the /bacnetPcapCheck/ GitHub Pages subpath: no page,
/// stylesheet or script may use a root-relative URL.
const ROOT_RELATIVE: [&str; 8] = [
    "href=\"/",
    "src=\"/",
    "srcset=\"/",
    "href='/",
    "src='/",
    "url(/",
    "url('/",
    "url(\"/",
];

/// Resource loads from another origin. Hyperlinks (<a href="https://…") are fine; the
/// footer's LinkedIn link is one. Analytics and tracking elements are covered here too:
/// they all load from another origin.
const EXTERNAL_RESOURCE: [&str; 10] = [
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
];

/// The first offline rule a page breaks, if any. Shared by the guard so the same rules
/// cover the built pages and the committed series pages.
fn offline_violation(html: &str) -> Option<String> {
    for forbidden in ROOT_RELATIVE {
        if html.contains(forbidden) {
            return Some(format!("root-relative URL ({forbidden})"));
        }
    }
    for forbidden in EXTERNAL_RESOURCE {
        if html.contains(forbidden) {
            return Some(format!("external resource ({forbidden})"));
        }
    }
    None
}

/// Every committed page under `docs/series`: the index and any mirrored post, by name.
fn committed_series_pages() -> Vec<(String, String)> {
    let dir = docs_src().join("../series");
    let mut pages = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("docs/series is committed") {
        let path = entry.expect("series entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("series page has a name")
            .to_string();
        let html = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        pages.push((name, html));
    }
    pages.sort();
    pages
}

#[test]
fn site_is_self_contained_and_subpath_safe() {
    // Every page of the site: the landing page, the manual, the sample report, and every
    // committed page under docs/series.
    let series = committed_series_pages();
    assert!(
        series.iter().any(|(name, _)| name == "index.html"),
        "docs/series/index.html was not read"
    );
    let mut pages = vec![
        ("landing page".to_string(), landing()),
        ("manual".to_string(), manual()),
        ("sample report".to_string(), sample_report()),
    ];
    pages.extend(series);

    // Prove the guard is live rather than passing because it checks nothing: each class
    // of forbidden URL is caught by the same rules the pages run through.
    for sample in [
        "<a href=\"/bacnetPcapCheck/manual.html\">manual</a>",
        "<script src=\"https://example.com/app.js\"></script>",
    ] {
        assert!(
            offline_violation(sample).is_some(),
            "the guard misses {sample}"
        );
    }

    for (name, html) in &pages {
        if let Some(violation) = offline_violation(html) {
            panic!("{name}: found {violation}");
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
    let committed = std::fs::read_to_string(docs_src().join("../sample-report.html"))
        .expect("docs/sample-report.html is committed");
    assert!(
        sample_report() == committed,
        "docs/sample-report.html is stale. Run `cargo xtask docs-build`."
    );
}

#[test]
fn landing_page_says_what_it_is_and_links_to_manual_and_download() {
    let page = landing();
    // The manual and the download are both reachable from the landing page, at their new
    // locations. The download points at the releases page; the manual stays relative.
    assert!(page.contains("href=\"manual.html\""), "no manual link");
    assert!(
        page.contains("href=\"sample-report.html\""),
        "no sample report link"
    );
    // The series index is reachable too, and by a relative link under the subpath.
    assert!(
        page.contains("href=\"series/index.html\""),
        "no series index link"
    );
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
