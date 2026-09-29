use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use baccheck_core::report::{
    render_html, CaptureStats, DeviceRef, Evidence, Finding, IssueId, Report, Severity,
};

fn device(instance: Option<u32>, last_octet: u8) -> DeviceRef {
    DeviceRef {
        device_instance: instance,
        ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)),
        port: Some(47808),
    }
}

fn finding(
    issue: IssueId,
    severity: Severity,
    affected: Vec<DeviceRef>,
    frames: &[u64],
) -> Finding {
    Finding {
        issue,
        severity,
        affected,
        occurrences: frames.len() as u64,
        evidence: Evidence {
            summary: format!("evidence for {}", issue.as_str()),
            frames: frames.to_vec(),
        },
        first_seen: Duration::from_secs(1_700_000_000),
        last_seen: Duration::from_secs(1_700_000_600),
    }
}

fn stats(total: u64, undecoded: u64, non_bacnet: u64) -> CaptureStats {
    CaptureStats {
        capture_name: "site.pcap".to_string(),
        total_frames: total,
        decoded_frames: total - undecoded - non_bacnet,
        undecoded_frames: undecoded,
        non_bacnet_frames: non_bacnet,
        first_timestamp: Some(Duration::from_secs(1_700_000_000)),
        last_timestamp: Some(Duration::from_secs(1_700_000_600)),
    }
}

#[test]
fn issue_table_covers_all_ten_issues_with_remediation() {
    assert_eq!(IssueId::ALL.len(), 10);
    for issue in IssueId::ALL {
        let spec = issue.spec();
        assert_eq!(spec.id, issue);
        assert!(!spec.display_name.is_empty());
        assert!(
            !spec.remediation.is_empty(),
            "{} has no remediation",
            issue.as_str()
        );
        assert_eq!(IssueId::from_id(issue.as_str()), Some(issue));
    }
    assert_eq!(IssueId::DuplicateDeviceId.as_str(), "duplicate-device-id");
}

#[test]
fn findings_are_ordered_severity_then_issue_then_device() {
    let report = Report::build(
        stats(100, 0, 0),
        vec![
            finding(
                IssueId::UnicastIAm,
                Severity::Low,
                vec![device(None, 9)],
                &[1],
            ),
            finding(
                IssueId::BroadcastStorm,
                Severity::High,
                vec![device(None, 8)],
                &[2],
            ),
            finding(
                IssueId::DuplicateDeviceId,
                Severity::High,
                vec![device(Some(1), 7)],
                &[3],
            ),
            finding(
                IssueId::RoutingRejection,
                Severity::Critical,
                vec![device(None, 6)],
                &[4],
            ),
            finding(
                IssueId::DuplicateDeviceId,
                Severity::High,
                vec![device(Some(1), 5)],
                &[5],
            ),
        ],
    );

    let order: Vec<_> = report
        .findings
        .iter()
        .map(|f| (f.severity, f.issue))
        .collect();
    assert_eq!(
        order,
        vec![
            (Severity::Critical, IssueId::RoutingRejection),
            (Severity::High, IssueId::DuplicateDeviceId),
            (Severity::High, IssueId::DuplicateDeviceId),
            (Severity::High, IssueId::BroadcastStorm),
            (Severity::Low, IssueId::UnicastIAm),
        ]
    );
    // Same issue and severity: the device breaks the tie.
    assert!(report.findings[1].affected < report.findings[2].affected);
}

#[test]
fn same_issue_and_device_set_merge_and_severity_never_drops() {
    let devices = vec![device(Some(101), 5), device(Some(101), 6)];
    let mut reversed = devices.clone();
    reversed.reverse();

    let report = Report::build(
        stats(100, 0, 0),
        vec![
            finding(
                IssueId::DuplicateDeviceId,
                Severity::Critical,
                devices,
                &[10, 11, 12],
            ),
            finding(
                IssueId::DuplicateDeviceId,
                Severity::High,
                reversed,
                &[1, 2, 3, 4],
            ),
        ],
    );

    assert_eq!(report.findings.len(), 1);
    let merged = &report.findings[0];
    assert_eq!(merged.severity, Severity::Critical);
    assert_eq!(merged.occurrences, 7);
    assert_eq!(merged.evidence.frames, vec![1, 2, 3, 4, 10]);
}

#[test]
fn capture_health_warning_needs_more_than_half_undecodable() {
    let at_half = Report::build(stats(100, 30, 20), vec![]);
    assert!(!at_half.capture_health_warning);

    let over_half = Report::build(stats(100, 30, 21), vec![]);
    assert!(over_half.capture_health_warning);

    let empty = Report::build(CaptureStats::default(), vec![]);
    assert!(!empty.capture_health_warning);
}

#[test]
fn remediation_fills_in_the_affected_devices() {
    let f = finding(
        IssueId::DuplicateDeviceId,
        Severity::High,
        vec![device(Some(101), 5), device(Some(101), 6)],
        &[1],
    );

    let steps = f.remediation_steps();

    assert!(steps[0].contains("Device 101 @ 10.0.0.5:47808"));
    assert!(steps.iter().all(|s| !s.contains('{')));
}

fn sample_report() -> Report {
    Report::build(
        stats(200, 0, 0),
        vec![
            finding(
                IssueId::DuplicateDeviceId,
                Severity::Critical,
                vec![device(Some(101), 5), device(Some(101), 6)],
                &[3, 9],
            ),
            finding(
                IssueId::UnicastIAm,
                Severity::Low,
                vec![device(Some(7), 7)],
                &[4],
            ),
        ],
    )
}

#[test]
fn html_has_severity_tags_fix_list_checkboxes_and_footer() {
    let html = render_html(&sample_report(), None);

    assert!(html.contains("cds--tag--red"));
    assert!(html.contains("cds--tag--cool-gray"));
    assert_eq!(html.matches("type=\"checkbox\"").count(), 2);
    assert!(html.contains("Duplicate device instance number"));
    assert!(html.contains("Unicast I-Am without directed Who-Is"));
    assert!(html.contains("Frames: 3, 9"));
    assert!(html.contains("What to do"));
    assert!(html.contains("MIT-licensed"));
    assert!(html.contains("BACcheck"));
    assert!(html.contains("@media print"));
    assert!(html.contains("size: A4") || html.contains("size:A4"));
    assert!(html.contains("toggleAccordion"));
    assert!(html.contains("2 finding"));
}

#[test]
fn html_expands_critical_findings_only() {
    let html = render_html(&sample_report(), None);

    assert_eq!(
        html.matches("class=\"cds--accordion__item cds--accordion__item--active\"")
            .count(),
        1
    );
}

#[test]
fn html_makes_no_network_requests() {
    let html = render_html(&sample_report(), None);

    // The only URL allowed is the designer credit link the reader must click.
    assert!(!html.contains("src=\"http"));
    assert!(!html.contains("@import"));
    assert!(!html.contains("url(http"));
    assert!(!html.contains("<link"));
}

#[test]
fn min_severity_hides_lower_findings_from_display_only() {
    let report = sample_report();

    let html = render_html(&report, Some(Severity::High));

    // The low finding is neither in the fix list nor a detail section. The summary still counts it.
    assert!(html.contains("id=\"f-0\""));
    assert!(!html.contains("id=\"f-1\""));
    assert_eq!(html.matches("type=\"checkbox\"").count(), 1);
    assert!(html.contains("1 lower finding(s) are hidden"));
    assert!(html.contains("2 findings"));
    assert_eq!(report.findings.len(), 2);
}

#[test]
fn capture_health_warning_renders_only_when_flagged() {
    let healthy = render_html(&sample_report(), None);
    assert!(!healthy.contains("Capture-health warning"));

    let unhealthy = render_html(&Report::build(stats(100, 60, 0), vec![]), None);
    assert!(unhealthy.contains("Capture-health warning"));
}

#[test]
fn clean_report_says_no_findings() {
    let html = render_html(&Report::build(stats(50, 0, 0), vec![]), None);

    assert!(html.contains("No findings."));
    assert!(!html.contains("type=\"checkbox\""));
}

#[test]
fn html_escapes_capture_name_and_evidence() {
    let mut s = stats(10, 0, 0);
    s.capture_name = "<script>alert(1)</script>.pcap".to_string();
    let mut f = finding(
        IssueId::UnicastIAm,
        Severity::Low,
        vec![device(None, 1)],
        &[1],
    );
    f.evidence.summary = "a < b & c".to_string();

    let html = render_html(&Report::build(s, vec![f]), None);

    assert!(!html.contains("<script>alert(1)"));
    assert!(html.contains("&lt;script&gt;alert(1)"));
    assert!(html.contains("a &lt; b &amp; c"));
}
