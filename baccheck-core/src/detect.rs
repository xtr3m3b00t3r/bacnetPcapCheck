//! Seam 3: the ten pure-function detectors (`stream -> Vec<Finding>`) over the decode seam's output.
//!
//! Implemented so far: [`duplicate_device_id`], [`broadcast_storm`] and [`unresponsive_device`]. The others are separate tickets; see wayfinder
//! ticket #4 for the decided rules. [`detect_all`] runs every detector that exists.
//!
//! Contract for `duplicate_device_id` (one test per line, in `tests/detect.rs`):
//! - An I-Am claiming one device instance from two or more distinct source IP:port pairs is a
//!   High finding, one per instance.
//! - Three or more distinct source IPs make it Critical.
//! - Device instance 4194303 is the wildcard and never counts.
//! - One address sending many I-Ams for one instance is not a duplicate.
//!
//! Contract for `unresponsive_device` (one test per line, in `tests/detect.rs`):
//! - A confirmed request is answered by an ack, error, reject or abort with the same invoke ID and
//!   reversed addresses, within 10 s of the request's last transmission.
//! - Retransmissions of an unanswered request, each within 10 s of the last, count once; a reused invoke ID after an answer is a new request.
//! - Judged per responder: silent below 10 requests received; Medium under 50% answered, High under 20%.
//! - Evidence lists at most five unanswered request frames and states the single-vantage caveat.
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

pub mod thresholds;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::decode::{ApduHeader, DecodeRecord};
use crate::report::{
    CaptureStats, DeviceRef, Evidence, Finding, IssueId, Severity, MAX_EVIDENCE_FRAMES,
};
use thresholds::*;

/// The device instance number that means "any device". It is not a real device.
pub const WILDCARD_DEVICE_INSTANCE: u32 = 4_194_303;

/// Runs every detector that exists over the decode stream.
pub fn detect_all(records: &[DecodeRecord], stats: &CaptureStats) -> Vec<Finding> {
    let mut findings = duplicate_device_id(records);
    findings.extend(broadcast_storm(records, stats));
    findings.extend(unresponsive_device(records));
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

/// One confirmed request, after folding retransmissions together.
struct Request {
    responder: SocketAddr,
    first_frame: u64,
    first: Duration,
    last_sent: Duration,
    answered: bool,
}

fn confirmed_key(
    envelope: &crate::decode::Envelope,
    invoke_id: u8,
) -> (SocketAddr, SocketAddr, u8) {
    (envelope.src, envelope.dst, invoke_id)
}

/// Correlates confirmed requests with their responses by (requester, responder, invoke ID).
/// Silence is attributed to the responder.
pub fn unresponsive_device(records: &[DecodeRecord]) -> Vec<Finding> {
    let mut requests: Vec<Request> = Vec::new();
    // Index into `requests` of the request still waiting for an answer, per key.
    let mut open: BTreeMap<(SocketAddr, SocketAddr, u8), usize> = BTreeMap::new();
    let mut instances: BTreeMap<SocketAddr, u32> = BTreeMap::new();

    for record in records {
        match record {
            DecodeRecord::IAm {
                envelope,
                device_instance,
                ..
            } => {
                instances.insert(envelope.src, *device_instance);
            }
            DecodeRecord::Apdu { envelope, header } => match header {
                ApduHeader::ConfirmedRequest { invoke_id, .. } => {
                    let key = confirmed_key(envelope, *invoke_id);
                    // A repeat is a retransmission only while the previous send is within the
                    // response window; later than that, the invoke ID has been reused.
                    let retransmitted = open.get(&key).copied().filter(|&index| {
                        envelope.timestamp.saturating_sub(requests[index].last_sent)
                            <= RESPONSE_WINDOW
                    });
                    match retransmitted {
                        Some(index) => requests[index].last_sent = envelope.timestamp,
                        None => {
                            open.insert(key, requests.len());
                            requests.push(Request {
                                responder: envelope.dst,
                                first_frame: envelope.frame_no,
                                first: envelope.timestamp,
                                last_sent: envelope.timestamp,
                                answered: false,
                            });
                        }
                    }
                }
                ApduHeader::SimpleAck { invoke_id, .. }
                | ApduHeader::ComplexAck { invoke_id, .. }
                | ApduHeader::Error { invoke_id, .. }
                | ApduHeader::Reject { invoke_id }
                | ApduHeader::Abort { invoke_id, .. } => {
                    // Reversed addresses: the response's src is the request's dst.
                    let key = (envelope.dst, envelope.src, *invoke_id);
                    if let Some(index) = open.remove(&key) {
                        let request = &mut requests[index];
                        request.answered =
                            envelope.timestamp.saturating_sub(request.last_sent) <= RESPONSE_WINDOW;
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    let mut by_responder: BTreeMap<SocketAddr, Vec<&Request>> = BTreeMap::new();
    for request in &requests {
        by_responder
            .entry(request.responder)
            .or_default()
            .push(request);
    }

    by_responder
        .into_iter()
        .filter_map(|(responder, received)| {
            unresponsive_finding(responder, instances.get(&responder).copied(), &received)
        })
        .collect()
}

fn unresponsive_finding(
    responder: SocketAddr,
    device_instance: Option<u32>,
    received: &[&Request],
) -> Option<Finding> {
    let total = received.len() as u64;
    if total < UNRESPONSIVE_MIN_REQUESTS {
        return None;
    }
    let unanswered: Vec<&&Request> = received.iter().filter(|r| !r.answered).collect();
    let answered_share = (total - unanswered.len() as u64) as f64 / total as f64;
    let severity = if answered_share < UNRESPONSIVE_HIGH_BELOW {
        Severity::High
    } else if answered_share < UNRESPONSIVE_MEDIUM_BELOW {
        IssueId::UnresponsiveDevice.spec().base_severity
    } else {
        return None;
    };

    let mut frames: Vec<u64> = unanswered.iter().map(|r| r.first_frame).collect();
    frames.sort_unstable();
    frames.truncate(MAX_EVIDENCE_FRAMES);

    let summary = format!(
        "{responder} answered {:.0}% of the {total} confirmed requests sent to it ({} unanswered within {} s). \
         This is seen from one point in the network: a response that took another path would look like silence.",
        answered_share * 100.0,
        unanswered.len(),
        RESPONSE_WINDOW.as_secs()
    );

    Some(Finding {
        issue: IssueId::UnresponsiveDevice,
        severity,
        affected: vec![DeviceRef {
            device_instance,
            ip: responder.ip(),
            port: Some(responder.port()),
        }],
        occurrences: unanswered.len() as u64,
        evidence: Evidence { summary, frames },
        first_seen: unanswered.iter().map(|r| r.first).min().unwrap_or_default(),
        last_seen: unanswered
            .iter()
            .map(|r| r.last_sent)
            .max()
            .unwrap_or_default(),
    })
}
