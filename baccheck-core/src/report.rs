//! Seam 4: the `Finding`/`Report` schema and its rendering into the self-contained Carbon-styled
//! HTML deliverable (see [`render_html`]).
//!
//! Contract (wayfinder tickets #3 and #6):
//! - [`IssueId`] is the closed set of ten issues; [`IssueSpec`] holds each one's display name, base
//!   severity, and remediation template.
//! - A [`Finding`] is one issue against one set of devices. [`Report::build`] merges findings that
//!   share (issue × device set) and never lowers a severity while doing so.
//! - A [`Report`] is ordered severity (worst first) → issue → devices, and carries the
//!   capture-health warning flag, set when more than half of the capture is not decodable BACnet.

use std::net::IpAddr;
use std::time::Duration;

mod html;

pub use html::render_html;

/// The most exemplar frame references a finding's evidence may carry.
pub const MAX_EVIDENCE_FRAMES: usize = 5;

/// A capture is flagged unhealthy when more than this share of it is not decodable BACnet.
pub const CAPTURE_HEALTH_THRESHOLD: f64 = 0.5;

/// Four-level severity. Ordered so that `Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// The closed vocabulary of issues the tool detects. Declaration order is report order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IssueId {
    DuplicateDeviceId,
    BroadcastStorm,
    UnresponsiveDevice,
    DuplicateBbmd,
    IncompleteBdt,
    ForeignDeviceRegistrationFailure,
    SegmentationMisuse,
    UnicastIAm,
    RoutingRejection,
    ConfirmedServiceRetransmission,
}

impl IssueId {
    pub const ALL: [IssueId; 10] = [
        IssueId::DuplicateDeviceId,
        IssueId::BroadcastStorm,
        IssueId::UnresponsiveDevice,
        IssueId::DuplicateBbmd,
        IssueId::IncompleteBdt,
        IssueId::ForeignDeviceRegistrationFailure,
        IssueId::SegmentationMisuse,
        IssueId::UnicastIAm,
        IssueId::RoutingRejection,
        IssueId::ConfirmedServiceRetransmission,
    ];

    /// The canonical kebab-case id, used for rendering and lookup.
    pub fn as_str(self) -> &'static str {
        match self {
            IssueId::DuplicateDeviceId => "duplicate-device-id",
            IssueId::BroadcastStorm => "broadcast-storm",
            IssueId::UnresponsiveDevice => "unresponsive-device",
            IssueId::DuplicateBbmd => "duplicate-bbmd",
            IssueId::IncompleteBdt => "incomplete-bdt",
            IssueId::ForeignDeviceRegistrationFailure => "foreign-device-registration-failure",
            IssueId::SegmentationMisuse => "segmentation-misuse",
            IssueId::UnicastIAm => "unicast-i-am",
            IssueId::RoutingRejection => "routing-rejection",
            IssueId::ConfirmedServiceRetransmission => "confirmed-service-retransmission",
        }
    }

    pub fn from_id(id: &str) -> Option<IssueId> {
        IssueId::ALL.into_iter().find(|issue| issue.as_str() == id)
    }

    pub fn spec(self) -> &'static IssueSpec {
        &ISSUE_SPECS[self as usize]
    }
}

/// Static facts about one issue. The remediation steps may use two placeholders: `{where}`
/// (the affected devices) and `{count}` (the occurrence count).
#[derive(Debug)]
pub struct IssueSpec {
    pub id: IssueId,
    pub display_name: &'static str,
    pub base_severity: Severity,
    pub remediation: &'static [&'static str],
}

/// Indexed by `IssueId as usize`, so entries must stay in `IssueId` declaration order.
static ISSUE_SPECS: [IssueSpec; 10] = [
    IssueSpec {
        id: IssueId::DuplicateDeviceId,
        display_name: "Duplicate device instance number",
        base_severity: Severity::High,
        remediation: &[
            "Find each device that answers with the shared instance number: {where}.",
            "Read the device instance number set in each device. Give the newer device a free number.",
            "Restart the changed device. Capture again. Confirm that only one device answers.",
        ],
    },
    IssueSpec {
        id: IssueId::BroadcastStorm,
        display_name: "Broadcast / Who-Is storm",
        base_severity: Severity::High,
        remediation: &[
            "Find the busiest senders in the evidence: {where}.",
            "Stop the repeated Who-Is requests. Turn off automatic discovery loops, or lengthen their interval.",
            "Reduce the size of the broadcast domain. Use a BBMD or a router to limit where broadcasts go.",
            "Capture again for 10 minutes. Confirm that the broadcast rate is lower.",
        ],
    },
    IssueSpec {
        id: IssueId::UnresponsiveDevice,
        display_name: "Unresponsive device",
        base_severity: Severity::Medium,
        remediation: &[
            "Check power and network cabling for {where}.",
            "Check the device for a full request queue. Restart it if it does not recover.",
            "Capture again from a second point in the network. Confirm that the silence is not a capture-point effect.",
        ],
    },
    IssueSpec {
        id: IssueId::DuplicateBbmd,
        display_name: "Duplicate BBMD / forwarding loop",
        base_severity: Severity::High,
        remediation: &[
            "Find out which of these is the commissioned BBMD: {where}.",
            "Turn off the BBMD function on the other unit, or correct the repeated entry in the BDT.",
            "Capture again for 10 minutes. Confirm that forwarded broadcasts do not repeat.",
        ],
    },
    IssueSpec {
        id: IssueId::IncompleteBdt,
        display_name: "Incomplete BDT on BBMD",
        base_severity: Severity::Low,
        remediation: &[
            "Read the BDT of the BBMD at {where}.",
            "Compare it with the list of all BBMDs on the network. Add each missing entry.",
            "Make sure that every BBMD lists every other BBMD.",
        ],
    },
    IssueSpec {
        id: IssueId::ForeignDeviceRegistrationFailure,
        display_name: "Foreign-device registration failure",
        base_severity: Severity::Medium,
        remediation: &[
            "Check that the BBMD accepts foreign devices. Check its foreign device table limit for {where}.",
            "Check the BBMD address and the time-to-live set in the foreign device.",
            "Register the device again. Confirm that the BBMD accepts it.",
        ],
    },
    IssueSpec {
        id: IssueId::SegmentationMisuse,
        display_name: "Segmentation misuse",
        base_severity: Severity::Medium,
        remediation: &[
            "Check the segmentation support that {where} advertises in its I-Am.",
            "Make the request or reply smaller, or turn on segmentation in both devices.",
            "Check that the maximum APDU length is the same in both devices.",
        ],
    },
    IssueSpec {
        id: IssueId::UnicastIAm,
        display_name: "Unicast I-Am without directed Who-Is",
        base_severity: Severity::Low,
        remediation: &[
            "Find the setting that controls how {where} sends I-Am.",
            "Set the device to broadcast its I-Am, unless it answers a directed Who-Is.",
            "Update the device firmware if the setting does not exist.",
        ],
    },
    IssueSpec {
        id: IssueId::RoutingRejection,
        display_name: "Routing rejection",
        base_severity: Severity::Medium,
        remediation: &[
            "Find the device that sends to the network that {where} rejects. Use the frames in the evidence.",
            "Remove the old route from that device, or repair the route in the router.",
            "Capture again. Confirm that the rejections stop.",
        ],
    },
    IssueSpec {
        id: IssueId::ConfirmedServiceRetransmission,
        display_name: "Confirmed-service retransmission",
        base_severity: Severity::Medium,
        remediation: &[
            "Find the device that repeats its requests: {where}.",
            "Lengthen the APDU timeout in that device, or reduce the load on the device that answers.",
            "Check the network for delay between the two devices.",
        ],
    },
];

/// An addressable BACnet node. Not every finding knows both halves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceRef {
    pub device_instance: Option<u32>,
    pub ip: IpAddr,
    /// `None` means the default BACnet/IP port (47808).
    pub port: Option<u16>,
}

impl DeviceRef {
    /// Human-readable form: `Device 101 @ 10.0.0.5:47808`, or just the address when the instance is unknown.
    pub fn describe(&self) -> String {
        let port = self.port.unwrap_or(crate::decode::BACNET_IP_PORT);
        let addr = match self.ip {
            IpAddr::V4(ip) => format!("{ip}:{port}"),
            IpAddr::V6(ip) => format!("[{ip}]:{port}"),
        };
        match self.device_instance {
            Some(instance) => format!("Device {instance} @ {addr}"),
            None => addr,
        }
    }
}

/// What a detector saw: a summary plus a few exemplar frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub summary: String,
    /// At most [`MAX_EVIDENCE_FRAMES`] frame numbers, in capture order.
    pub frames: Vec<u64>,
}

/// One issue against one set of devices, with every occurrence aggregated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub issue: IssueId,
    pub severity: Severity,
    /// Sorted, deduplicated.
    pub affected: Vec<DeviceRef>,
    pub occurrences: u64,
    pub evidence: Evidence,
    pub first_seen: Duration,
    pub last_seen: Duration,
}

impl Finding {
    /// The remediation steps for this finding, from the issue's template.
    pub fn remediation_steps(&self) -> Vec<String> {
        let location = self.location();
        let count = self.occurrences.to_string();
        self.issue
            .spec()
            .remediation
            .iter()
            .map(|step| {
                step.replace("{where}", &location)
                    .replace("{count}", &count)
            })
            .collect()
    }

    /// The affected devices as one line of text.
    pub fn location(&self) -> String {
        if self.affected.is_empty() {
            return "the whole network".to_string();
        }
        self.affected
            .iter()
            .map(DeviceRef::describe)
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn merge(&mut self, other: Finding) {
        self.severity = self.severity.max(other.severity);
        self.occurrences += other.occurrences;
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        for frame in other.evidence.frames {
            if !self.evidence.frames.contains(&frame) {
                self.evidence.frames.push(frame);
            }
        }
        self.evidence.frames.sort_unstable();
        self.evidence.frames.truncate(MAX_EVIDENCE_FRAMES);
    }
}

/// Frame counts and timing for the whole capture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureStats {
    pub capture_name: String,
    pub total_frames: u64,
    /// BACnet frames that decoded to something typed.
    pub decoded_frames: u64,
    /// BACnet-shaped frames that did not decode.
    pub undecoded_frames: u64,
    /// Frames that are not BACnet/IP at all.
    pub non_bacnet_frames: u64,
    pub first_timestamp: Option<Duration>,
    pub last_timestamp: Option<Duration>,
}

impl CaptureStats {
    /// Share of the capture that is not decodable BACnet (undecoded plus non-BACnet), 0.0 to 1.0.
    pub fn undecodable_proportion(&self) -> f64 {
        if self.total_frames == 0 {
            return 0.0;
        }
        (self.undecoded_frames + self.non_bacnet_frames) as f64 / self.total_frames as f64
    }

    pub fn span(&self) -> Duration {
        match (self.first_timestamp, self.last_timestamp) {
            (Some(first), Some(last)) => last.saturating_sub(first),
            _ => Duration::ZERO,
        }
    }
}

/// The aggregated result of one analysis run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub stats: CaptureStats,
    /// Ordered severity (worst first) → issue → devices.
    pub findings: Vec<Finding>,
    /// Set when more than half of the capture is not decodable BACnet.
    pub capture_health_warning: bool,
}

impl Report {
    /// Merges findings that share (issue × device set), orders them, and sets the warning flag.
    pub fn build(stats: CaptureStats, findings: Vec<Finding>) -> Report {
        let mut merged: Vec<Finding> = Vec::new();
        for mut finding in findings {
            finding.affected.sort();
            finding.affected.dedup();
            match merged
                .iter_mut()
                .find(|m| m.issue == finding.issue && m.affected == finding.affected)
            {
                Some(existing) => existing.merge(finding),
                None => merged.push(finding),
            }
        }
        merged.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(a.issue.cmp(&b.issue))
                .then_with(|| a.affected.cmp(&b.affected))
        });
        let capture_health_warning = stats.undecodable_proportion() > CAPTURE_HEALTH_THRESHOLD;
        Report {
            stats,
            findings: merged,
            capture_health_warning,
        }
    }
}
