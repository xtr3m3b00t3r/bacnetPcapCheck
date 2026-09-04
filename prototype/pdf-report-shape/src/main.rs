//! PROTOTYPE — throwaway code answering one question (wayfinder ticket #6):
//! "What does the delivered field-engineer PDF report look like?"
//!
//! Three structurally different variants, each rendered from the same fake
//! `Report` (Finding schema per decision on ticket #3):
//!   out/report-a-sections.pdf — section-per-finding
//!   out/report-b-tables.pdf   — table-driven, remediation appendix
//!   out/report-c-devices.pdf  — device-centric with an actions checklist
//!
//! It also trials genpdf 0.2 as the PDF library (vs raw printpdf) for the
//! library decision the ticket carries.
//!
//! Run: cargo run   (from this directory; PDFs land in ./out)

use genpdf::elements::{FrameCellDecorator, Paragraph, TableLayout};
use genpdf::fonts;
use genpdf::style::{Color, Style};
use genpdf::{Alignment, Document, Margins, PaperSize};

// ---------------------------------------------------------------------------
// Fake model — mirrors the Finding schema decided on ticket #3
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Sev {
    Critical,
    Major,
    Warning,
    Info,
}

impl Sev {
    fn name(self) -> &'static str {
        match self {
            Sev::Critical => "CRITICAL",
            Sev::Major => "MAJOR",
            Sev::Warning => "WARNING",
            Sev::Info => "INFO",
        }
    }

    fn color(self) -> Color {
        match self {
            Sev::Critical => Color::Rgb(179, 38, 30),   // red
            Sev::Major => Color::Rgb(230, 81, 0),       // deep orange
            Sev::Warning => Color::Rgb(200, 140, 0),    // amber
            Sev::Info => Color::Rgb(21, 101, 192),      // blue
        }
    }

    fn bg(self) -> Color {
        match self {
            Sev::Critical => Color::Rgb(253, 231, 229),
            Sev::Major => Color::Rgb(255, 236, 224),
            Sev::Warning => Color::Rgb(255, 248, 225),
            Sev::Info => Color::Rgb(227, 240, 253),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Scope {
    /// Affects the network as a whole (no single device to visit).
    Network,
    /// Primary affected device: instance + address.
    Device(u32, &'static str),
}

struct Finding {
    id: &'static str,      // kebab-case IssueId
    name: &'static str,    // display name
    severity: Sev,         // base severity escalated where evidence warrants
    scope: Scope,
    /// All affected devices as display strings (may be several).
    affected: &'static [&'static str],
    occurrence_label: &'static str, // e.g. "61 I-Am frames"
    evidence: &'static str,
    frames: &'static [u32], // ≤5 exemplar frame refs
    more_frames: usize,
    first: &'static str,
    last: &'static str,
    action: &'static str,  // one-line remediation headline
    steps: &'static [&'static str],
}

struct CaptureInfo {
    file: &'static str,
    span: &'static str,
    frames_total: usize,
    bacnet_frames: usize,
    undecodable: usize,
    undecodable_pct: f64,
    devices_seen: usize,
}

struct Report {
    capture: CaptureInfo,
    findings: Vec<Finding>,
}

impl Finding {
    /// The address half of the scope, for headings.
    fn scope_addr(&self) -> String {
        match self.scope {
            Scope::Device(_, a) => a.to_string(),
            Scope::Network => "network-wide".to_string(),
        }
    }

    fn frames_line(&self) -> String {
        let list = self.frames.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ");
        if self.more_frames > 0 {
            format!("Frames: {} (+{} more)", list, self.more_frames)
        } else {
            format!("Frames: {}", list)
        }
    }
}

impl Report {
    fn sorted(&self) -> Vec<&Finding> {
        let mut v: Vec<&Finding> = self.findings.iter().collect();
        v.sort_by_key(|f| f.severity);
        v
    }
}

fn fake_report() -> Report {
    let findings = vec![
        Finding {
            id: "duplicate-device-id",
            name: "Duplicate device instance number",
            severity: Sev::Critical,
            scope: Scope::Device(101, "192.168.10.24 / 192.168.10.87"),
            affected: &["Device 101 @ 192.168.10.24:47808", "Device 101 @ 192.168.10.87:47808"],
            occurrence_label: "61 I-Am frames from two addresses",
            evidence: "Two distinct IP addresses answered I-Am with device instance 101 within \
                       40 s (frames 412 and 458). ReadProperty requests addressed to instance \
                       101 received conflicting replies from both addresses for the rest of \
                       the capture.",
            frames: &[412, 458, 2210, 4997, 11023],
            more_frames: 56,
            first: "08:43:12",
            last: "09:16:58",
            action: "Renumber one of the two devices claiming instance 101.",
            steps: &[
                "Physically locate both devices answering as instance 101 (192.168.10.24 and 192.168.10.87).",
                "Check the device-ID dip switch / configuration on each and renumber the newer replacement to a free instance.",
                "Power-cycle the renumbered device and confirm a single I-Am for instance 101 on the next capture.",
            ],
        },
        Finding {
            id: "duplicate-bbmd",
            name: "Duplicate BBMD / forwarding loop",
            severity: Sev::Critical,
            scope: Scope::Device(0, "192.168.40.10 / 192.168.40.11"),
            affected: &["BBMD @ 192.168.40.10:47808", "BBMD @ 192.168.40.11:47808"],
            occurrence_label: "23 looped broadcasts",
            evidence: "The same original broadcast NPDU reappeared on subnet 192.168.10.x five \
                       times with a decrementing hop count, each lap tagged from alternating \
                       BBMD addresses 192.168.40.10 and 192.168.40.11. Both advertise an \
                       identical BDT entry for 192.168.20.255.",
            frames: &[1880, 1902, 1927, 1955, 1988],
            more_frames: 18,
            first: "08:51:04",
            last: "09:15:41",
            action: "Take one of the two BBMDs out of service or correct its BDT.",
            steps: &[
                "Confirm which of 192.168.40.10 / 192.168.40.11 is the commissioned BBMD.",
                "Disable the BBMD function on the other unit, or correct the duplicated BDT entry for 192.168.20.255.",
                "Verify forwarding stops looping by re-capturing for 10 minutes.",
            ],
        },
        Finding {
            id: "broadcast-storm",
            name: "Who-Is broadcast storm",
            severity: Sev::Major,
            scope: Scope::Network,
            affected: &[
                "Device 52 @ 192.168.10.52",
                "Device 77 @ 192.168.10.77",
                "Device 214 @ 192.168.10.214",
                "Device 330 @ 192.168.10.330",
                "Device 401 @ 192.168.10.401",
                "Device 512 @ 192.168.10.512",
            ],
            occurrence_label: "8,212 Who-Is broadcasts (3.9/s)",
            evidence: "Who-Is broadcasts carried 94% of all BACnet traffic in the capture, \
                       sustained at 3.9/s over the full 35 minutes. Six devices on \
                       192.168.10.x re-broadcast the same Who-Is range at 2–5 s intervals. \
                       Undecodable traffic is 2.3% — the storm itself is fully decodable \
                       BVLC/NPDU traffic, so the volume is real, not a decoding gap.",
            frames: &[205, 611, 1029, 1477, 1901],
            more_frames: 8207,
            first: "08:42:31",
            last: "09:17:35",
            action: "Throttle the Who-Is re-broadcast rate on the six named devices.",
            steps: &[
                "On each of the six listed devices, increase the Who-Is retry/back-off interval to ≥30 s.",
                "Replace broad-range Who-Is (0–4194303) with directed reads where the controller config supports it.",
                "Re-capture after changes; the Who-Is share of BACnet traffic should fall below 20%.",
            ],
        },
        Finding {
            id: "unresponsive-device",
            name: "Unresponsive device",
            severity: Sev::Major,
            scope: Scope::Device(310, "192.168.12.31"),
            affected: &["Device 310 @ 192.168.12.31:47808"],
            occurrence_label: "44 unanswered confirmed requests",
            evidence: "44 ReadProperty requests to device 310 were never answered (invoke IDs \
                       0x1F, 0x2A, 0x33 and 41 others); the longest silent wait was 9.8 s. \
                       The device answers broadcast Who-Is but drops confirmed traffic.",
            frames: &[5310, 5488, 6122, 6670, 7204],
            more_frames: 39,
            first: "08:57:19",
            last: "09:17:30",
            action: "Inspect device 310's application layer for a full request queue.",
            steps: &[
                "Ping 192.168.12.31 and confirm the device is still on the network.",
                "Read the controller's service queue / connection count; a saturated queue drops confirmed requests.",
                "Reboot the device if the queue stays full; check its firmware revision against the vendor's list of known BACnet stack defects.",
            ],
        },
        Finding {
            id: "incomplete-bdt",
            name: "Incomplete BDT on BBMD",
            severity: Sev::Major,
            scope: Scope::Device(0, "192.168.40.10"),
            affected: &["BBMD @ 192.168.40.10:47808", "Subnet 192.168.60.x (missing)"],
            occurrence_label: "23 missing forwards",
            evidence: "The BDT read from BBMD 192.168.40.10 lists 2 of the 3 site subnets; \
                       192.168.60.x is absent. Broadcasts originating on 192.168.60.x were \
                       never seen on the other two subnets, while 23 such broadcasts were \
                       captured on the source subnet itself.",
            frames: &[8830, 8901, 9110, 9412, 9987],
            more_frames: 18,
            first: "09:01:22",
            last: "09:16:44",
            action: "Add the missing 192.168.60.x entry to the BBMD's BDT.",
            steps: &[
                "Open the BBMD configuration on 192.168.40.10 and read the current BDT.",
                "Add a BDT entry for 192.168.60.x (mask 255.255.255.0) pointing at the third subnet's BBMD or broadcast address.",
                "Confirm a Who-Is issued on 192.168.60.x now appears on subnets 192.168.10.x and 192.168.20.x.",
            ],
        },
        Finding {
            id: "segmentation-misuse",
            name: "Segmentation misuse",
            severity: Sev::Warning,
            scope: Scope::Device(205, "192.168.11.5"),
            affected: &["Device 205 @ 192.168.11.5:47808"],
            occurrence_label: "127 aborts",
            evidence: "Device 205 advertises max-NPDU 480 bytes but requests objects needing \
                       1,497-byte replies. 127 exchange aborts (abort-reason \
                       buffer-capacity) follow, and no segmented transfer is ever negotiated.",
            frames: &[3102, 3388, 3640, 4011, 4390],
            more_frames: 122,
            first: "08:49:02",
            last: "09:14:10",
            action: "Align device 205's advertised segmentation support with its request size.",
            steps: &[
                "Set device 205's max-APDU / segmentation config to match its real capability, or move it to a client that requests small properties.",
                "If the device supports segmentation, enable 'segmented responses both' on it and its peers.",
            ],
        },
        Finding {
            id: "unicast-i-am",
            name: "Unicast I-Am without directed Who-Is",
            severity: Sev::Warning,
            scope: Scope::Device(322, "192.168.10.92"),
            affected: &["Device 322 @ 192.168.10.92:47808", "Receiver 192.168.10.1"],
            occurrence_label: "18 unicast I-Ams",
            evidence: "Device 322 sent unicast I-Am messages to 192.168.10.1 after broadcast \
                       Who-Is frames. None of the 18 followed a directed (unicast) Who-Is, \
                       so the receiver's table is being primed by a reply it did not ask for.",
            frames: &[7450, 7602, 7719, 7888, 8011],
            more_frames: 13,
            first: "08:55:47",
            last: "09:12:03",
            action: "Correct device 322's I-Am response mode to broadcast-only.",
            steps: &[
                "Check device 322's BACnet configuration for a 'directed I-Am' / unicast-response option and disable it.",
                "Confirm on the next capture that I-Am frames from 322 are sent to 192.168.10.255.",
            ],
        },
        Finding {
            id: "foreign-device-registration-failure",
            name: "Foreign-device registration failure",
            severity: Sev::Warning,
            scope: Scope::Device(407, "192.168.60.7"),
            affected: &["Device 407 @ 192.168.60.7:47808", "BBMD @ 192.168.40.10:47808"],
            occurrence_label: "6 of 12 registrations rejected",
            evidence: "Device 407 attempted to register as a foreign device with BBMD \
                       192.168.40.10 twelve times (TTL 300 s); six attempts were answered \
                       with BVLC-Result nack (result 0x0010). The BBMD's foreign-device \
                       table appears to be full at 128 entries.",
            frames: &[12044, 12188, 12402, 12566, 12871],
            more_frames: 7,
            first: "09:06:15",
            last: "09:15:52",
            action: "Raise the BBMD's foreign-device table limit or clear stale registrations.",
            steps: &[
                "Read the BBMD's foreign-device table; clear entries with expired TTLs.",
                "Raise the table limit if the site intentionally supports more than 128 foreign devices, then confirm device 407's next registration succeeds (BVLC-Result success).",
            ],
        },
        Finding {
            id: "confirmed-retransmission",
            name: "Confirmed-service retransmission",
            severity: Sev::Warning,
            scope: Scope::Device(415, "192.168.13.15"),
            affected: &["Device 118 @ 192.168.11.18:47808 (sender)", "Device 415 @ 192.168.13.15:47808 (responder)"],
            occurrence_label: "9 retransmissions on one invoke ID",
            evidence: "Device 118 retransmitted the same ReadProperty (invoke ID 0x44) nine \
                       times at ~3 s intervals; device 415 answered each only after the \
                       fourth try. Retransmissions are attributed to the sender, the \
                       silence to the responder.",
            frames: &[13340, 13405, 13471, 13538, 13604],
            more_frames: 4,
            first: "09:08:41",
            last: "09:08:59",
            action: "Shorten device 415's response latency or widen device 118's APDU timeout.",
            steps: &[
                "Check device 415 for a busy schedule (point writes, COV floods) that delays its replies.",
                "Raise device 118's APDU timeout from ~3 s to 6–10 s so slow-but-correct answers are not re-asked.",
            ],
        },
        Finding {
            id: "routing-rejection",
            name: "Routing rejection",
            severity: Sev::Info,
            scope: Scope::Device(0, "192.168.20.1"),
            affected: &["Router @ 192.168.20.1", "DNET 77 (unreachable)"],
            occurrence_label: "5 rejections",
            evidence: "Five NPDU reject-message-to-network frames from router 192.168.20.1 \
                       give reason 0x02 (network unreachable) for DNET 77. No device ever \
                       answered on DNET 77, so the route appears decommissioned but still \
                       referenced by clients on 192.168.20.x.",
            frames: &[15210, 15288, 15991, 16402, 17005],
            more_frames: 0,
            first: "09:10:12",
            last: "09:13:55",
            action: "Find the client still routing to DNET 77 and remove the stale route.",
            steps: &[
                "Identify the device on 192.168.20.x sending to DNET 77 (check the frames listed).",
                "Remove or repoint its DNET 77 route entry; confirm the rejections stop.",
            ],
        },
    ];
    Report {
        capture: CAPTURE,
        findings,
    }
}

const CAPTURE: CaptureInfo = CaptureInfo {
    file: "plant-floor-chiller-loop.pcapng",
    span: "2026-09-04 08:42:10 – 09:17:36 (35 min 26 s)",
    frames_total: 18_442,
    bacnet_frames: 17_704,
    undecodable: 431,
    undecodable_pct: 2.3,
    devices_seen: 14,
};

// ---------------------------------------------------------------------------
// Shared rendering helpers
// ---------------------------------------------------------------------------

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn para(text: impl Into<String>, style: Style, align: Alignment) -> Paragraph {
    Paragraph::new("").styled_string(text, style).aligned(align)
}

fn gray() -> Style {
    Style::new().with_color(Color::Rgb(110, 110, 110))
}

fn heading(text: &str, size: u8) -> Paragraph {
    para(text, Style::new().bold().with_font_size(size), Alignment::Left)
}

fn sev_text(sev: Sev, size: u8) -> Paragraph {
    para(sev.name(), Style::new().bold().with_font_size(size).with_color(sev.color()), Alignment::Left)
}

fn sev_badge_text(sev: Sev) -> String {
    format!("{} — ", sev.name())
}

fn label(text: &str) -> Paragraph {
    para(text, Style::new().bold().with_font_size(10), Alignment::Left)
}

fn body(text: impl Into<String>) -> Paragraph {
    para(text, Style::new().with_font_size(10), Alignment::Left)
}

fn body_gray(text: impl Into<String>) -> Paragraph {
    para(text, Style::new().with_font_size(9).with_color(Color::Rgb(110, 110, 110)), Alignment::Left)
}

fn spacer() -> Paragraph {
    para(" ", Style::new().with_font_size(6), Alignment::Left)
}

fn thousands(n: usize) -> String {
    n.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// The capture-health warning required by the Finding schema at >50% undecodable.
/// Our fake capture is healthy (2.3%), so this box does not render — raise
/// `CAPTURE.undecodable_pct` above 50 to see it.
fn capture_warning_box(report: &Report) -> Option<TableLayout> {
    if report.capture.undecodable_pct <= 50.0 {
        return None;
    }
    let mut table = TableLayout::new(vec![1]);
    table.set_cell_decorator(FrameCellDecorator::new(true, true, false));
    table
        .row()
        .element(para(
            format!(
                "CAPTURE HEALTH WARNING: {:.0}% of frames could not be decoded as BACnet. \
                 Findings below rest on the remaining {:.0}%; re-capture with a BACnet/IP \
                 filter before acting on the absence of a finding.",
                report.capture.undecodable_pct,
                100.0 - report.capture.undecodable_pct
            ),
            Style::new().bold().with_color(Color::Rgb(179, 38, 30)),
            Alignment::Left,
        ))
        .push()
        .expect("warning row");
    Some(table)
}

fn capture_summary_table(report: &Report) -> TableLayout {
    let c = &report.capture;
    let rows: Vec<(&str, String)> = vec![
        ("Capture file", c.file.to_string()),
        ("Capture span", c.span.to_string()),
        ("Frames analysed", format!("{}", thousands(c.frames_total))),
        ("BACnet frames", format!("{}", thousands(c.bacnet_frames))),
        ("Undecodable frames", format!("{} ({:.1}%)", thousands(c.undecodable), c.undecodable_pct)),
        ("Devices seen", format!("{}", c.devices_seen)),
    ];
    let mut table = TableLayout::new(vec![2, 5]);
    for (k, v) in rows {
        table
            .row()
            .element(para(k, Style::new().bold().with_font_size(10), Alignment::Left))
            .element(body(v))
            .push()
            .expect("summary row");
    }
    table
}

fn new_doc(fonts: &fonts::FontFamily<fonts::FontData>, title: &str) -> Document {
    let mut doc = Document::new(fonts.clone());
    doc.set_title(title);
    doc.set_paper_size(PaperSize::A4);
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(Margins::trbl(20.0, 18.0, 20.0, 18.0));
    decorator.set_header(|page| {
        if page <= 1 {
            para("", Style::new().with_font_size(1), Alignment::Left)
        } else {
            para(
                format!("BACnet Network Health Report — page {}", page),
                Style::new().with_font_size(8).with_color(Color::Rgb(130, 130, 130)),
                Alignment::Right,
            )
        }
    });
    doc.set_page_decorator(decorator);
    doc
}

fn title_block(doc: &mut Document, subtitle: &str) {
    doc.push(heading("BACcheck — BACnet Network Health Report", 22));
    doc.push(body_gray(subtitle));
    doc.push(spacer());
}

fn steps_table(steps: &[&'static str]) -> TableLayout {
    let mut steps_tbl = TableLayout::new(vec![1, 14]);
    for (i, s) in steps.iter().enumerate() {
        steps_tbl
            .row()
            .element(para(
                format!("{}.", i + 1),
                Style::new().bold().with_font_size(10),
                Alignment::Left,
            ))
            .element(body(*s))
            .push()
            .expect("step row");
    }
    steps_tbl
}

// ---------------------------------------------------------------------------
// Variant A — section-per-finding
// ---------------------------------------------------------------------------

fn render_a(report: &Report, fonts: &fonts::FontFamily<fonts::FontData>) -> Res<()> {
    let mut doc = new_doc(fonts, "BACnet Network Health Report — variant A");
    title_block(&mut doc, "Variant A: section per finding — summary page, then a deep-dive section for each problem.");

    if let Some(w) = capture_warning_box(report) {
        doc.push(w);
        doc.push(spacer());
    }

    doc.push(heading("Capture summary", 14));
    doc.push(capture_summary_table(report));
    doc.push(spacer());

    doc.push(heading("Findings summary", 14));
    let mut table = TableLayout::new(vec![2, 6, 5, 3]);
    table.set_cell_decorator(FrameCellDecorator::new(true, true, false));
    table
        .row()
        .element(para("Severity", Style::new().bold().with_font_size(10), Alignment::Left))
        .element(para("Issue", Style::new().bold().with_font_size(10), Alignment::Left))
        .element(para("Affected", Style::new().bold().with_font_size(10), Alignment::Left))
        .element(para("Occurrences", Style::new().bold().with_font_size(10), Alignment::Left))
        .push()
        .expect("header row");
    for f in report.sorted() {
        table
            .row()
            .element(para(
                f.severity.name(),
                Style::new().bold().with_font_size(9).with_color(f.severity.color()),
                Alignment::Left,
            ))
            .element(body(f.name))
            .element(body(match f.affected.len() {
                1 => f.affected[0].to_string(),
                n => format!("{} affected — {}", n, f.affected[0]),
            }))
            .element(body(f.occurrence_label))
            .push()
            .expect("summary row");
    }
    doc.push(table);
    doc.push(spacer());
    doc.push(para(
        "Each finding is detailed on the pages that follow, ordered by severity.",
        gray().with_font_size(9),
        Alignment::Left,
    ));
    doc.push(spacer());

    for f in report.sorted() {
        doc.push(para(
            format!("{}{}", sev_badge_text(f.severity), f.name),
            Style::new().bold().with_font_size(13).with_color(f.severity.color()),
            Alignment::Left,
        ));

        doc.push(label("Affected devices"));
        let mut tbl = TableLayout::new(vec![1]);
        for a in f.affected {
            tbl.row().element(body(*a)).push().expect("affected row");
        }
        doc.push(tbl);

        doc.push(spacer());
        doc.push(label("Evidence"));
        doc.push(body(f.evidence));
        doc.push(body_gray(f.frames_line()));
        doc.push(body_gray(format!("First seen {} — last seen {}", f.first, f.last)));

        doc.push(spacer());
        doc.push(label("What to do"));
        doc.push(steps_table(f.steps));
        doc.push(spacer());
    }

    std::fs::create_dir_all("out")?;
    doc.render_to_file("out/report-a-sections.pdf")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Variant B — table-driven with remediation appendix
// ---------------------------------------------------------------------------

fn render_b(report: &Report, fonts: &fonts::FontFamily<fonts::FontData>) -> Res<()> {
    let mut doc = new_doc(fonts, "BACnet Network Health Report — variant B");
    title_block(&mut doc, "Variant B: table-driven — one findings matrix, then evidence and remediation appendices keyed by issue id.");

    if let Some(w) = capture_warning_box(report) {
        doc.push(w);
        doc.push(spacer());
    }

    doc.push(heading("Capture", 14));
    doc.push(capture_summary_table(report));
    doc.push(spacer());

    doc.push(heading("Findings matrix", 14));
    let mut table = TableLayout::new(vec![3, 2, 3, 1, 2, 2]);
    table.set_cell_decorator(FrameCellDecorator::new(true, true, false));
    table
        .row()
        .element(para("Issue", Style::new().bold().with_font_size(9), Alignment::Left))
        .element(para("Severity", Style::new().bold().with_font_size(9), Alignment::Left))
        .element(para("Affected", Style::new().bold().with_font_size(9), Alignment::Left))
        .element(para("Count", Style::new().bold().with_font_size(9), Alignment::Left))
        .element(para("First seen", Style::new().bold().with_font_size(9), Alignment::Left))
        .element(para("Last seen", Style::new().bold().with_font_size(9), Alignment::Left))
        .push()
        .expect("matrix header");
    for f in report.sorted() {
        table
            .row()
            .element(para(
                f.id,
                Style::new().with_font_size(8).with_color(Color::Rgb(60, 60, 60)),
                Alignment::Left,
            ))
            .element(para(
                f.severity.name(),
                Style::new().bold().with_font_size(8).with_color(f.severity.color()),
                Alignment::Left,
            ))
            .element(body_gray(match f.affected.len() {
                1 => f.affected[0].to_string(),
                n => format!("{} devices ({}…)", n, f.affected[0]),
            }))
            .element(para(
                f.occurrence_label.split(' ').next().unwrap_or("—").to_string(),
                Style::new().with_font_size(8),
                Alignment::Left,
            ))
            .element(para(f.first, Style::new().with_font_size(8), Alignment::Left))
            .element(para(f.last, Style::new().with_font_size(8), Alignment::Left))
            .push()
            .expect("matrix row");
    }
    doc.push(table);
    doc.push(spacer());

    doc.push(heading("Evidence appendix", 14));
    for f in report.sorted() {
        let mut head = TableLayout::new(vec![3, 7]);
        head.row()
            .element(para(f.id, Style::new().bold().with_font_size(10), Alignment::Left))
            .element(sev_text(f.severity, 9))
            .push()
            .expect("evidence head");
        doc.push(head);
        doc.push(body(f.evidence));
        doc.push(body_gray(f.frames_line()));
        doc.push(spacer());
    }

    doc.push(heading("Remediation appendix", 14));
    for f in report.sorted() {
        let mut head = TableLayout::new(vec![3, 7]);
        head.row()
            .element(para(f.id, Style::new().bold().with_font_size(10), Alignment::Left))
            .element(para(
                f.action,
                Style::new().with_font_size(10).with_color(Color::Rgb(60, 60, 60)),
                Alignment::Left,
            ))
            .push()
            .expect("remediation head");
        doc.push(head);
        doc.push(steps_table(f.steps));
        doc.push(spacer());
    }

    std::fs::create_dir_all("out")?;
    doc.render_to_file("out/report-b-tables.pdf")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Variant C — device-centric with actions checklist
// ---------------------------------------------------------------------------

fn render_c(report: &Report, fonts: &fonts::FontFamily<fonts::FontData>) -> Res<()> {
    let mut doc = new_doc(fonts, "BACnet Network Health Report — variant C");
    title_block(&mut doc, "Variant C: device-centric — a fix list ordered by severity, then everything to do, device by device.");

    if let Some(w) = capture_warning_box(report) {
        doc.push(w);
        doc.push(spacer());
    }

    doc.push(heading("Fix list", 16));
    doc.push(body_gray("Work top to bottom. Order is severity, the order things matter, not the order they were found."));
    doc.push(spacer());
    let mut table = TableLayout::new(vec![1, 2, 3, 9]);
    table.set_cell_decorator(FrameCellDecorator::new(true, true, false));
    table
        .row()
        .element(para("", Style::new().bold().with_font_size(10), Alignment::Left))
        .element(para("Severity", Style::new().bold().with_font_size(10), Alignment::Left))
        .element(para("Where", Style::new().bold().with_font_size(10), Alignment::Left))
        .element(para("Action", Style::new().bold().with_font_size(10), Alignment::Left))
        .push()
        .expect("checklist header");
    for f in report.sorted() {
        table
            .row()
            .element(para("[  ]", Style::new().with_font_size(10), Alignment::Left))
            .element(sev_text(f.severity, 9))
            .element(body(match f.scope {
                Scope::Device(inst, _) if inst > 0 => format!("Device {}", inst),
                _ => "Network-wide".to_string(),
            }))
            .element(body(f.action))
            .push()
            .expect("checklist row");
    }
    doc.push(table);
    doc.push(spacer());
    doc.push(heading("Capture facts", 12));
    doc.push(capture_summary_table(report));
    doc.push(spacer());

    // Group findings: per device (by instance), then network-wide.
    let mut devices: Vec<(u32, Vec<&Finding>)> = Vec::new();
    let mut network: Vec<&Finding> = Vec::new();
    for f in report.sorted() {
        match f.scope {
            Scope::Device(inst, _) if inst > 0 => {
                if let Some(entry) = devices.iter_mut().find(|(i, _)| *i == inst) {
                    entry.1.push(f);
                } else {
                    devices.push((inst, vec![f]));
                }
            }
            _ => network.push(f),
        }
    }

    doc.push(heading("Per device", 16));
    for (inst, fs) in &devices {
        let addr = fs[0].scope_addr();
        let mut head = TableLayout::new(vec![2, 8]);
        head.row()
            .element(para(
                format!("Device {}", inst),
                Style::new().bold().with_font_size(13).with_color(Color::Rgb(30, 30, 30)),
                Alignment::Left,
            ))
            .element(para(addr, Style::new().with_font_size(11).with_color(Color::Rgb(110, 110, 110)), Alignment::Left))
            .push()
            .expect("device head");
        doc.push(head);
        doc.push(para(
            format!("{} finding(s) on this device.", fs.len()),
            gray().with_font_size(9),
            Alignment::Left,
        ));
        doc.push(spacer());
        for f in fs {
            doc.push(para(
                format!("{}{}", sev_badge_text(f.severity), f.name),
                Style::new().bold().with_font_size(11).with_color(f.severity.color()),
                Alignment::Left,
            ));
            doc.push(body(f.evidence));
            doc.push(body_gray(f.frames_line()));
            doc.push(steps_table(f.steps));
            doc.push(spacer());
        }
    }

    doc.push(heading("Network-wide", 16));
    doc.push(body_gray("Problems spanning devices — fix these before per-device clean-up."));
    doc.push(spacer());
    for f in &network {
        doc.push(para(
            format!("{}{}", sev_badge_text(f.severity), f.name),
            Style::new().bold().with_font_size(11).with_color(f.severity.color()),
            Alignment::Left,
        ));
        doc.push(body(f.evidence));
        doc.push(body_gray(f.frames_line()));
        doc.push(steps_table(f.steps));
        doc.push(spacer());
    }

    std::fs::create_dir_all("out")?;
    doc.render_to_file("out/report-c-devices.pdf")?;
    Ok(())
}

// ---------------------------------------------------------------------------

fn main() -> Res<()> {
    let fonts = fonts::from_files("assets/fonts", "LiberationSans", None)?;
    let report = fake_report();
    render_a(&report, &fonts)?;
    render_b(&report, &fonts)?;
    render_c(&report, &fonts)?;
    println!("done — see out/report-a-sections.pdf, out/report-b-tables.pdf, out/report-c-devices.pdf");
    Ok(())
}
