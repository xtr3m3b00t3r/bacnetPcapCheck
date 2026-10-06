//! Seam 3: the ten pure-function detectors (`stream -> Vec<Finding>`) over the decode seam's output.
//!
//! Implemented so far: [`duplicate_device_id`] and [`broadcast_storm`]. The other nine are separate tickets; see wayfinder
//! ticket #4 for the decided rules. [`detect_all`] runs every detector that exists.
//!
//! Contract for `duplicate_device_id` (one test per line, in `tests/detect.rs`):
//! - An I-Am claiming one device instance from two or more distinct source IP:port pairs is a
//!   High finding, one per instance.
//! - Three or more distinct source IPs make it Critical.
//! - Device instance 4194303 is the wildcard and never counts.
//! - One address sending many I-Ams for one instance is not a duplicate.
//!
//! Contract for `broadcast_storm` (one test per line, in `tests/detect.rs`):
//! - Stays silent below the evidence floor: capture span under 5 minutes, or (for the saturation
//!   trigger) under 200 decoded BACnet messages.
//! - Fires High on any trigger: more than 10 global Who-Is/s, or more than 50 broadcast I-Am/s,
//!   in a fixed 60 s bucket counted from the capture start; or broadcasts above 30% of decoded BACnet messages.
//! - Escalates to Critical above 25 broadcasting sources or a broadcast share above 50%.
//! - Broadcast context is the limited broadcast address, or an `x.x.x.255` destination inside a
//!   /24 that the capture's own source addresses occupy.
//! - Evidence names the triggers, the peak window, at most five top talkers, and the capture's
//!   undecodable/non-BACnet proportion, with a verify-the-source note when that is high.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::decode::DecodeRecord;
use crate::report::{
    CaptureStats, DeviceRef, Evidence, Finding, IssueId, Severity, MAX_EVIDENCE_FRAMES,
};

/// The device instance number that means "any device". It is not a real device.
pub const WILDCARD_DEVICE_INSTANCE: u32 = 4_194_303;

/// Distinct source IPs at which a duplicate device ID becomes Critical.
pub const DUPLICATE_ID_CRITICAL_IPS: usize = 3;

/// Shortest capture span a rate-based rule needs before it may fire.
pub const RATE_RULE_MIN_SPAN: Duration = Duration::from_secs(5 * 60);

/// Width of the fixed buckets that storm-class rules measure peak rate over.
pub const RATE_BUCKET: Duration = Duration::from_secs(60);

/// Global Who-Is per second, in one bucket, above which the Who-Is flood trigger fires.
pub const WHO_IS_FLOOD_PER_SEC: u64 = 10;

/// Broadcast I-Am per second, in one bucket, above which the I-Am flood trigger fires.
pub const I_AM_FLOOD_PER_SEC: u64 = 50;

/// Broadcast share of decoded BACnet messages above which the saturation trigger fires.
pub const BROADCAST_SATURATION_SHARE: f64 = 0.30;

/// Decoded BACnet messages the saturation trigger needs before it may fire.
pub const BROADCAST_SATURATION_MIN_MESSAGES: u64 = 200;

/// Broadcasting source addresses above which a storm is Critical.
pub const STORM_CRITICAL_SOURCES: usize = 25;

/// Broadcast share above which a storm is Critical.
pub const STORM_CRITICAL_SHARE: f64 = 0.50;

/// Undecodable/non-BACnet share of the capture above which a storm finding tells the engineer to
/// verify the storm is BACnet-sourced. Lower than the capture-health threshold: it is a caution,
/// not a verdict on the whole report.
pub const STORM_UNDECODABLE_NOTE_SHARE: f64 = 0.25;

/// Top talkers a storm finding names.
const STORM_TOP_TALKERS: usize = 5;

/// Runs every detector that exists over the decode stream.
pub fn detect_all(records: &[DecodeRecord], stats: &CaptureStats) -> Vec<Finding> {
    let mut findings = duplicate_device_id(records);
    findings.extend(broadcast_storm(records, stats));
    findings
}

struct Claim {
    frames: Vec<u64>,
    first: Duration,
    last: Duration,
    i_am_count: u64,
}

pub fn duplicate_device_id(records: &[DecodeRecord]) -> Vec<Finding> {
    let mut by_instance: BTreeMap<u32, BTreeMap<SocketAddr, Claim>> = BTreeMap::new();
    for record in records {
        let DecodeRecord::IAm {
            envelope,
            device_instance,
            ..
        } = record
        else {
            continue;
        };
        if *device_instance == WILDCARD_DEVICE_INSTANCE {
            continue;
        }
        let claim = by_instance
            .entry(*device_instance)
            .or_default()
            .entry(envelope.src)
            .or_insert(Claim {
                frames: Vec::new(),
                first: envelope.timestamp,
                last: envelope.timestamp,
                i_am_count: 0,
            });
        claim.frames.push(envelope.frame_no);
        claim.first = claim.first.min(envelope.timestamp);
        claim.last = claim.last.max(envelope.timestamp);
        claim.i_am_count += 1;
    }

    by_instance
        .into_iter()
        .filter(|(_, claims)| claims.len() >= 2)
        .map(|(instance, claims)| finding_for(instance, claims))
        .collect()
}

fn finding_for(instance: u32, claims: BTreeMap<SocketAddr, Claim>) -> Finding {
    let distinct_ips = claims
        .keys()
        .map(SocketAddr::ip)
        .collect::<std::collections::BTreeSet<IpAddr>>()
        .len();
    let severity = if distinct_ips >= DUPLICATE_ID_CRITICAL_IPS {
        Severity::Critical
    } else {
        IssueId::DuplicateDeviceId.spec().base_severity
    };

    let affected: Vec<DeviceRef> = claims
        .keys()
        .map(|addr| DeviceRef {
            device_instance: Some(instance),
            ip: addr.ip(),
            port: Some(addr.port()),
        })
        .collect();
    let occurrences = claims.values().map(|c| c.i_am_count).sum();
    let first_seen = claims.values().map(|c| c.first).min().unwrap_or_default();
    let last_seen = claims.values().map(|c| c.last).max().unwrap_or_default();

    let mut frames: Vec<u64> = claims.values().flat_map(|c| c.frames.clone()).collect();
    frames.sort_unstable();
    frames.truncate(MAX_EVIDENCE_FRAMES);

    let addresses = claims
        .iter()
        .map(|(addr, claim)| format!("{addr} ({} I-Am)", claim.i_am_count))
        .collect::<Vec<_>>()
        .join(", ");
    let summary = format!(
        "Device instance {instance} was claimed from {} different addresses: {addresses}. \
         Each device must have its own instance number.",
        claims.len()
    );

    Finding {
        issue: IssueId::DuplicateDeviceId,
        severity,
        affected,
        occurrences,
        evidence: Evidence { summary, frames },
        first_seen,
        last_seen,
    }
}

/// One fired rule: its description for the evidence summary and the frames that tripped it.
struct Trigger {
    description: String,
    frames: Vec<u64>,
}

fn broadcast_destinations(records: &[DecodeRecord]) -> BTreeSet<Ipv4Addr> {
    // x.x.x.255 destinations inside a /24 that some captured source address occupies.
    let sources: BTreeSet<[u8; 3]> = records
        .iter()
        .filter_map(|r| match envelope_of(r)?.src.ip() {
            IpAddr::V4(ip) => Some([ip.octets()[0], ip.octets()[1], ip.octets()[2]]),
            IpAddr::V6(_) => None,
        })
        .collect();
    records
        .iter()
        .filter_map(|r| match envelope_of(r)?.dst.ip() {
            IpAddr::V4(ip) if ip.octets()[3] == 255 => Some(ip),
            _ => None,
        })
        .filter(|ip| {
            let o = ip.octets();
            sources.contains(&[o[0], o[1], o[2]])
        })
        .collect()
}

fn envelope_of(record: &DecodeRecord) -> Option<&crate::decode::Envelope> {
    match record {
        DecodeRecord::Undecoded { .. } => None,
        DecodeRecord::WhoIs { envelope, .. }
        | DecodeRecord::IAm { envelope, .. }
        | DecodeRecord::BvlcResult { envelope, .. }
        | DecodeRecord::NetworkMessage { envelope, .. }
        | DecodeRecord::Apdu { envelope, .. } => Some(envelope),
    }
}

/// Peak bucket of `(timestamp, frame)` events, buckets counted from `origin` (the capture start):
/// its start offset in seconds, count, and frames in capture order.
fn peak_bucket(events: &[(Duration, u64)], origin: Duration) -> Option<(u64, u64, Vec<u64>)> {
    let mut buckets: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (timestamp, frame) in events {
        buckets
            .entry(timestamp.saturating_sub(origin).as_secs() / RATE_BUCKET.as_secs())
            .or_default()
            .push(*frame);
    }
    buckets
        .into_iter()
        .max_by_key(|(bucket, frames)| (frames.len(), std::cmp::Reverse(*bucket)))
        .map(|(bucket, frames)| (bucket * RATE_BUCKET.as_secs(), frames.len() as u64, frames))
}

/// Rate-based over decoded messages only; the undecodable proportion never decides whether it fires.
pub fn broadcast_storm(records: &[DecodeRecord], stats: &CaptureStats) -> Vec<Finding> {
    if stats.span() < RATE_RULE_MIN_SPAN {
        return Vec::new();
    }
    let capture_start = stats.first_timestamp.unwrap_or_default();
    let broadcast_ips = broadcast_destinations(records);
    let is_broadcast = |dst: IpAddr| match dst {
        IpAddr::V4(ip) => ip == Ipv4Addr::BROADCAST || broadcast_ips.contains(&ip),
        IpAddr::V6(_) => false,
    };

    let mut total_messages = 0u64;
    let mut who_is: Vec<(Duration, u64)> = Vec::new();
    let mut i_am: Vec<(Duration, u64)> = Vec::new();
    let mut broadcasts: Vec<(Duration, u64)> = Vec::new();
    let mut talkers: BTreeMap<SocketAddr, u64> = Default::default();
    let mut instances: BTreeMap<SocketAddr, u32> = Default::default();

    for record in records {
        let Some(envelope) = envelope_of(record) else {
            continue;
        };
        total_messages += 1;
        if let DecodeRecord::IAm {
            device_instance, ..
        } = record
        {
            instances.insert(envelope.src, *device_instance);
        }
        if !is_broadcast(envelope.dst.ip()) {
            continue;
        }
        let event = (envelope.timestamp, envelope.frame_no);
        broadcasts.push(event);
        *talkers.entry(envelope.src).or_default() += 1;
        match record {
            DecodeRecord::WhoIs { .. } => who_is.push(event),
            DecodeRecord::IAm { .. } => i_am.push(event),
            _ => {}
        }
    }

    let share = if total_messages == 0 {
        0.0
    } else {
        broadcasts.len() as f64 / total_messages as f64
    };

    let mut triggers: Vec<Trigger> = Vec::new();
    for (name, events, per_sec) in [
        ("global Who-Is", &who_is, WHO_IS_FLOOD_PER_SEC),
        ("broadcast I-Am", &i_am, I_AM_FLOOD_PER_SEC),
    ] {
        if let Some((start, count, frames)) = peak_bucket(events, capture_start) {
            if count > per_sec * RATE_BUCKET.as_secs() {
                triggers.push(Trigger {
                    description: format!(
                        "{name} flood: peak {:.1}/s ({count} in the 60 s from {start} s into the capture), limit {per_sec}/s",
                        count as f64 / RATE_BUCKET.as_secs() as f64
                    ),
                    frames,
                });
            }
        }
    }
    if total_messages >= BROADCAST_SATURATION_MIN_MESSAGES && share > BROADCAST_SATURATION_SHARE {
        triggers.push(Trigger {
            description: format!(
                "broadcast saturation: {:.0}% of {total_messages} BACnet messages were broadcasts, limit {:.0}%",
                share * 100.0,
                BROADCAST_SATURATION_SHARE * 100.0
            ),
            frames: broadcasts.iter().map(|(_, frame)| *frame).collect(),
        });
    }
    let Some(first_trigger) = triggers.first() else {
        return Vec::new();
    };

    let severity = if talkers.len() > STORM_CRITICAL_SOURCES || share > STORM_CRITICAL_SHARE {
        Severity::Critical
    } else {
        IssueId::BroadcastStorm.spec().base_severity
    };

    let mut ranked: Vec<(SocketAddr, u64)> = talkers.into_iter().collect();
    ranked.sort_by_key(|(addr, count)| (std::cmp::Reverse(*count), *addr));
    ranked.truncate(STORM_TOP_TALKERS);
    let affected: Vec<DeviceRef> = ranked
        .iter()
        .map(|(addr, _)| DeviceRef {
            device_instance: instances.get(addr).copied(),
            ip: addr.ip(),
            port: Some(addr.port()),
        })
        .collect();
    let talker_text = ranked
        .iter()
        .map(|(addr, count)| format!("{addr} ({count})"))
        .collect::<Vec<_>>()
        .join(", ");

    let proportion = stats.undecodable_proportion();
    let mut summary = format!(
        "{}. Top talkers: {talker_text}. {:.0}% of the capture was not decodable BACnet.",
        triggers
            .iter()
            .map(|t| t.description.as_str())
            .collect::<Vec<_>>()
            .join("; "),
        proportion * 100.0
    );
    if proportion > STORM_UNDECODABLE_NOTE_SHARE {
        summary.push_str(
            " That is a high share: verify the storm is BACnet-sourced before acting on this finding.",
        );
    }

    let mut frames = first_trigger.frames.clone();
    frames.sort_unstable();
    frames.truncate(MAX_EVIDENCE_FRAMES);

    vec![Finding {
        issue: IssueId::BroadcastStorm,
        severity,
        affected,
        occurrences: broadcasts.len() as u64,
        evidence: Evidence { summary, frames },
        first_seen: broadcasts.iter().map(|(t, _)| *t).min().unwrap_or_default(),
        last_seen: broadcasts.iter().map(|(t, _)| *t).max().unwrap_or_default(),
    }]
}
