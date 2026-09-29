//! Renders a [`Report`] to one self-contained HTML file: vendored Carbon CSS inlined, BLUF-first
//! layout, print styling for A4, a few lines of vanilla JS for the accordion. No network requests.

use std::fmt::Write;
use std::time::Duration;

use super::{Finding, Report, Severity};

const CARBON_CSS: &str = include_str!("../../assets/carbon.min.css");
const REPORT_CSS: &str = include_str!("../../assets/report.css");

const ARROW_SVG: &str = r#"<svg class="cds--accordion__arrow" focusable="false" aria-hidden="true" width="16" height="16" viewBox="0 0 16 16"><path d="M11 8 6 3 5 4l4 4-4 4 1 1z"/></svg>"#;
const WARNING_SVG: &str = r#"<svg focusable="false" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 4 2 28h28Zm-2 8h4v8h-4Zm0 10h4v4h-4Z"/></svg>"#;

const ACCORDION_JS: &str = "function toggleAccordion(heading) {
    var item = heading.closest('.cds--accordion__item');
    var active = item.classList.toggle('cds--accordion__item--active');
    heading.setAttribute('aria-expanded', active);
  }";

/// How many affected devices the fix list names before it abbreviates.
const FIX_LIST_DEVICES: usize = 3;

/// Renders the report. `min_severity` hides findings below that level from the fix list and the
/// detail sections; it changes what is displayed, nothing else.
pub fn render_html(report: &Report, min_severity: Option<Severity>) -> String {
    let shown: Vec<(usize, &Finding)> = report
        .findings
        .iter()
        .enumerate()
        .filter(|(_, f)| min_severity.is_none_or(|min| f.severity >= min))
        .collect();
    let hidden = report.findings.len() - shown.len();

    let stats = &report.stats;
    let capture = esc(&stats.capture_name);
    let span = format_span(stats.span());
    let range = match (stats.first_timestamp, stats.last_timestamp) {
        (Some(first), Some(last)) => format!("{} – {} UTC", format_time(first), format_time(last)),
        _ => "no frames".to_string(),
    };

    let mut out = String::with_capacity(CARBON_CSS.len() + 32 * 1024);
    let _ = write!(
        out,
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>BACcheck — BACnet Network Health Report — {capture}</title>\n\
         <style>{CARBON_CSS}</style>\n<style>\n{REPORT_CSS}</style>\n</head>\n<body>\n"
    );

    let _ = writeln!(
        out,
        "<header class=\"rpt-header\"><div class=\"rpt-header__inner\">\
         <span class=\"rpt-header__product\">BACcheck</span>\
         <span class=\"rpt-header__meta\">BACnet Network Health Report · {capture} · {}</span>\
         </div></header>",
        esc(&range)
    );

    out.push_str("<div class=\"cds--css-grid rpt-grid\">\n<div class=\"cds--css-grid-column cds--col-span-16\">\n");

    // ---- BLUF ----
    let _ = write!(
        out,
        "<div class=\"rpt-bluf\"{}>\n<p class=\"rpt-bluf__line\">{}</p>\n",
        if report.findings.is_empty() {
            " style=\"border-inline-start-color:#198038\""
        } else {
            ""
        },
        bluf_line(report)
    );
    let _ = writeln!(
        out,
        "<div class=\"rpt-bluf__stats\">Capture: {capture} · {} frames over {span} · \
         {} decoded · {} not decodable BACnet ({:.1}%)</div>",
        stats.total_frames,
        stats.decoded_frames,
        stats.undecoded_frames + stats.non_bacnet_frames,
        stats.undecodable_proportion() * 100.0
    );
    if hidden > 0 {
        let _ = writeln!(
            out,
            "<div class=\"rpt-bluf__stats\">Showing findings at {} severity or above. \
             {hidden} lower finding(s) are hidden.</div>",
            min_severity.map_or("any", Severity::label)
        );
    }
    out.push_str("</div>\n");

    if report.capture_health_warning {
        let _ = write!(
            out,
            "<div class=\"cds--inline-notification cds--inline-notification--low-contrast \
             cds--inline-notification--warning\" style=\"margin-top:1rem\" role=\"status\">\n\
             <div class=\"cds--inline-notification__details\">\
             <div class=\"cds--inline-notification__icon\">{WARNING_SVG}</div>\
             <div class=\"cds--inline-notification__text-wrapper\">\
             <p class=\"cds--inline-notification__title\">Capture-health warning</p>\
             <p class=\"cds--inline-notification__subtitle\">More than half of the frames in this \
             capture could not be decoded as BACnet ({:.1}%). Findings rest on the rest of the \
             capture. Other findings may be under-counted or over-counted. Capture again with a \
             BACnet/IP filter before you trust an absence of findings.</p>\
             </div></div></div>\n",
            stats.undecodable_proportion() * 100.0
        );
    }

    if !shown.is_empty() {
        write_fix_list(&mut out, &shown);
        write_findings(&mut out, &shown);
    }

    out.push_str("</div>\n</div>\n");

    out.push_str(
        "<footer class=\"rpt-footer\"><div class=\"rpt-footer__inner\">\
         <span class=\"rpt-footer__app\">BACcheck</span>\
         <span class=\"rpt-footer__credit\">MIT-licensed · Not a commercial product · Designed by \
         <a href=\"https://www.linkedin.com/in/benjamin-dw-truman/\" target=\"_blank\" rel=\"noopener\">\
         Benjamin D.W Truman</a></span></div></footer>\n",
    );
    let _ = write!(
        out,
        "<script>\n  {ACCORDION_JS}\n</script>\n</body>\n</html>\n"
    );
    out
}

/// One sentence, conclusion first: counts by severity, then the two worst problems.
fn bluf_line(report: &Report) -> String {
    if report.findings.is_empty() {
        return "<strong>No findings.</strong> BACcheck found none of its ten known problems in this capture."
            .to_string();
    }
    let count = |sev| report.findings.iter().filter(|f| f.severity == sev).count();
    let parts: Vec<String> = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ]
    .into_iter()
    .filter(|&sev| count(sev) > 0)
    .map(|sev| format!("{} {}", count(sev), sev.label()))
    .collect();

    let total = report.findings.len();
    let headline: Vec<String> = report
        .findings
        .iter()
        .take(2)
        .map(|f| esc(f.issue.spec().display_name))
        .collect();
    let advice = if count(Severity::Critical) > 0 {
        "Fix the critical findings first."
    } else {
        "Fix the findings from the top of the list."
    };
    format!(
        "<strong>{total} finding{}: {}.</strong> Worst: {}. {advice}",
        if total == 1 { "" } else { "s" },
        parts.join(", "),
        headline.join("; ")
    )
}

fn write_fix_list(out: &mut String, shown: &[(usize, &Finding)]) {
    out.push_str(
        "<section class=\"rpt-section\">\n<h2 class=\"rpt-h2\">Fix list</h2>\n\
         <p class=\"rpt-muted\">Work top to bottom. Order is severity, not the order things were found.</p>\n\
         <div class=\"cds--data-table-container\" style=\"margin-top:0.75rem\">\n\
         <table class=\"cds--data-table\" style=\"width:100%\">\n<thead><tr>\
         <th style=\"width:2.5rem\"><span class=\"cds--visually-hidden\">Done</span></th>\
         <th style=\"width:7rem\">Severity</th><th>Issue</th>\
         <th style=\"width:10rem\">Where</th><th style=\"width:28rem\">Action</th>\
         </tr></thead>\n<tbody>\n",
    );
    for (n, (idx, finding)) in shown.iter().enumerate() {
        let spec = finding.issue.spec();
        let action = finding
            .remediation_steps()
            .into_iter()
            .next()
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "<tr><td data-previous-value=\"Row\"><div class=\"cds--checkbox-wrapper\">\
             <input id=\"cb-{id}\" class=\"cds--checkbox\" type=\"checkbox\" value=\"{id}\">\
             <label for=\"cb-{id}\" class=\"cds--checkbox-label\" aria-label=\"Mark done\"></label>\
             </div></td><td>{tag}</td>\
             <td><a class=\"cds--link\" href=\"#f-{idx}\">{name}</a></td>\
             <td>{location}</td><td>{action}</td></tr>",
            id = n + 1,
            tag = severity_tag(finding.severity),
            name = esc(spec.display_name),
            location = esc(&short_location(finding)),
            action = esc(&action),
        );
    }
    out.push_str("</tbody>\n</table>\n</div>\n</section>\n");
}

fn write_findings(out: &mut String, shown: &[(usize, &Finding)]) {
    out.push_str(
        "<section class=\"rpt-section\">\n<h2 class=\"rpt-h2\">Findings</h2>\n\
         <p class=\"rpt-muted\">Each finding: what BACcheck saw, the frames that show it, and the \
         steps to fix it. Critical findings are open. The rest are closed.</p>\n\
         <ul class=\"cds--accordion\">\n",
    );
    for (idx, finding) in shown {
        let spec = finding.issue.spec();
        let open = finding.severity == Severity::Critical;
        let frames = finding
            .evidence
            .frames
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let steps: String = finding
            .remediation_steps()
            .iter()
            .map(|step| format!("<li>{}</li>", esc(step)))
            .collect();
        let _ = write!(
            out,
            "<li class=\"cds--accordion__item{active}\" id=\"f-{idx}\">\n\
             <button class=\"cds--accordion__heading\" type=\"button\" aria-expanded=\"{open}\" \
             onclick=\"toggleAccordion(this)\"><p class=\"cds--accordion__title\">{tag} {name}</p>{ARROW_SVG}</button>\n\
             <div class=\"cds--accordion__wrapper\"><div class=\"cds--accordion__content\">\n\
             <p class=\"rpt-finding-meta\"><strong>Affected:</strong> {location} · {occurrences} occurrence(s)</p>\n\
             <p class=\"rpt-evidence\">{summary}</p>\n\
             <p class=\"rpt-frames\">Frames: {frames} · First seen {first} UTC — last seen {last} UTC</p>\n\
             <p class=\"rpt-label\">What to do</p>\n<ol class=\"rpt-steps\">{steps}</ol>\n\
             </div></div>\n</li>\n",
            active = if open { " cds--accordion__item--active" } else { "" },
            tag = severity_tag(finding.severity),
            name = esc(spec.display_name),
            location = esc(&finding.location()),
            occurrences = finding.occurrences,
            summary = esc(&finding.evidence.summary),
            first = format_time(finding.first_seen),
            last = format_time(finding.last_seen),
        );
    }
    out.push_str("</ul>\n</section>\n");
}

/// Carbon tag colours: critical→red, high→magenta, medium→warm-gray, low→cool-gray.
fn severity_tag(severity: Severity) -> String {
    let colour = match severity {
        Severity::Critical => "red",
        Severity::High => "magenta",
        Severity::Medium => "warm-gray",
        Severity::Low => "cool-gray",
    };
    format!(
        "<span class=\"cds--tag cds--tag--{colour} rpt-sev\">{}</span>",
        severity.label().to_uppercase()
    )
}

fn short_location(finding: &Finding) -> String {
    let devices = &finding.affected;
    if devices.len() <= FIX_LIST_DEVICES {
        return finding.location();
    }
    let shown: Vec<String> = devices
        .iter()
        .take(FIX_LIST_DEVICES)
        .map(|d| d.describe())
        .collect();
    format!(
        "{} (+{} more)",
        shown.join(", "),
        devices.len() - FIX_LIST_DEVICES
    )
}

fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn format_span(span: Duration) -> String {
    let total = span.as_secs();
    let (h, m, s) = (total / 3600, (total / 60) % 60, total % 60);
    match (h, m) {
        (0, 0) => format!("{s} s"),
        (0, _) => format!("{m} min {s} s"),
        _ => format!("{h} h {m} min {s} s"),
    }
}

/// `YYYY-MM-DD HH:MM:SS` in UTC from a Unix timestamp.
fn format_time(since_epoch: Duration) -> String {
    let secs = since_epoch.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_timestamps() {
        assert_eq!(format_time(Duration::from_secs(0)), "1970-01-01 00:00:00");
        assert_eq!(
            format_time(Duration::from_secs(1_700_000_000)),
            "2023-11-14 22:13:20"
        );
        // Leap day.
        assert_eq!(
            format_time(Duration::from_secs(1_709_164_800)),
            "2024-02-29 00:00:00"
        );
    }

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(
            esc("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
