//! Seam 3: the ten pure-function detectors (`stream -> Vec<Finding>`) over the decode seam's output.
//!
//! The rules live in issue #4 (`gh issue view 4 --comments`), numbered; [`detect_all`] runs every
//! detector that exists.

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

/// BVLC-Result code for Register-Foreign-Device-NAK.
const REGISTER_FOREIGN_DEVICE_NAK: u16 = 0x0030;

/// Runs every detector that exists over the decode stream.
pub fn detect_all(records: &[DecodeRecord], stats: &CaptureStats) -> Vec<Finding> {
    let mut findings = duplicate_device_id(records);
    findings.extend(broadcast_storm(records, stats));
    findings.extend(unresponsive_device(records));
    findings.extend(duplicate_bbmd(records, stats));
    findings.extend(incomplete_bdt(records));
    findings.extend(foreign_device_registration_failure(records));
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
        | DecodeRecord::RegisterForeignDevice { envelope, .. }
        | DecodeRecord::ForwardedNpdu { envelope, .. }
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

/// One sighting of a Forwarded-NPDU.
struct Forwarded {
    frame: u64,
    timestamp: Duration,
    forwarder: SocketAddr,
}

/// What one repeated forwarded broadcast showed.
struct Offence {
    severity: Severity,
    forwarders: BTreeSet<SocketAddr>,
    sightings: Vec<Forwarded>,
}

/// Judges one broadcast's sightings (chronological) against both triggers.
fn forwarded_offence(
    sightings: Vec<Forwarded>,
    capture_start: Duration,
    rate_rule_may_fire: bool,
) -> Option<Offence> {
    let base = IssueId::DuplicateBbmd.spec().base_severity;
    let mut severity: Option<Severity> = None;

    // Duplicate forwarders: distinct IPs within one episode, which ends after a quiet gap. Only
    // forwarders from an episode that crossed the threshold are named.
    let mut episode: BTreeSet<SocketAddr> = BTreeSet::new();
    let mut offenders: BTreeSet<SocketAddr> = BTreeSet::new();
    let mut previous: Option<Duration> = None;
    for sighting in &sightings {
        if previous.is_some_and(|p| sighting.timestamp.saturating_sub(p) > FORWARD_DUPLICATE_WINDOW)
        {
            episode.clear();
        }
        previous = Some(sighting.timestamp);
        episode.insert(sighting.forwarder);
        let distinct_ips = episode
            .iter()
            .map(SocketAddr::ip)
            .collect::<BTreeSet<IpAddr>>()
            .len();
        if distinct_ips >= FORWARD_DUPLICATE_FORWARDERS {
            offenders.extend(episode.iter().copied());
            severity = severity.max(Some(base));
        }
        if distinct_ips >= FORWARD_CRITICAL_FORWARDERS {
            severity = Some(Severity::Critical);
        }
    }

    if rate_rule_may_fire {
        let events: Vec<(Duration, u64)> =
            sightings.iter().map(|s| (s.timestamp, s.frame)).collect();
        if let Some((_, count, _)) = peak_bucket(&events, capture_start) {
            if count > FORWARD_LOOP_PER_BUCKET {
                offenders.extend(sightings.iter().map(|s| s.forwarder));
                severity = severity.max(Some(base));
            }
            if count > FORWARD_LOOP_CRITICAL_PER_BUCKET {
                severity = Some(Severity::Critical);
            }
        }
    }

    let severity = severity?;
    Some(Offence {
        severity,
        forwarders: offenders,
        sightings,
    })
}

/// Recognises one broadcast relayed twice: by several BBMDs (duplicate BBMD) or many times in a
/// minute (forwarding loop). Identity is the Forwarded-NPDU's original source plus NPDU bytes.
pub fn duplicate_bbmd(records: &[DecodeRecord], stats: &CaptureStats) -> Vec<Finding> {
    let capture_start = stats.first_timestamp.unwrap_or_default();
    let rate_rule_may_fire = stats.span() >= RATE_RULE_MIN_SPAN;

    let mut by_hash: BTreeMap<u64, Vec<Forwarded>> = BTreeMap::new();
    for record in records {
        if let DecodeRecord::ForwardedNpdu {
            envelope,
            payload_hash,
            ..
        } = record
        {
            by_hash.entry(*payload_hash).or_default().push(Forwarded {
                frame: envelope.frame_no,
                timestamp: envelope.timestamp,
                forwarder: envelope.src,
            });
        }
    }

    let offences: Vec<Offence> = by_hash
        .into_values()
        .filter_map(|sightings| forwarded_offence(sightings, capture_start, rate_rule_may_fire))
        .collect();
    let Some(severity) = offences.iter().map(|o| o.severity).max() else {
        return Vec::new();
    };

    let forwarders: BTreeSet<SocketAddr> = offences
        .iter()
        .flat_map(|o| o.forwarders.iter().copied())
        .collect();
    let sightings: Vec<&Forwarded> = offences.iter().flat_map(|o| &o.sightings).collect();
    let mut frames: Vec<u64> = sightings.iter().map(|s| s.frame).collect();
    frames.sort_unstable();
    frames.truncate(MAX_EVIDENCE_FRAMES);

    let forwarder_text = forwarders
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let summary = format!(
        "{} forwarded broadcast(s) were relayed repeatedly: {} sightings via {forwarder_text}. \
         Either several BBMDs relay the same broadcast, or one broadcast is looping between BBMDs.",
        offences.len(),
        sightings.len()
    );

    vec![Finding {
        issue: IssueId::DuplicateBbmd,
        severity,
        affected: forwarders
            .iter()
            .map(|addr| DeviceRef {
                device_instance: None,
                ip: addr.ip(),
                port: Some(addr.port()),
            })
            .collect(),
        occurrences: sightings.len() as u64,
        evidence: Evidence { summary, frames },
        first_seen: sightings
            .iter()
            .map(|s| s.timestamp)
            .min()
            .unwrap_or_default(),
        last_seen: sightings
            .iter()
            .map(|s| s.timestamp)
            .max()
            .unwrap_or_default(),
    }]
}

/// Spots a peer BBMD relaying broadcasts into the capture's segment while no broadcast from the
/// segment's own hosts is ever relayed back: a single-vantage proxy for a BDT missing this segment.
pub fn incomplete_bdt(records: &[DecodeRecord]) -> Vec<Finding> {
    let broadcasts = broadcast_destinations(records);
    let is_broadcast = |dst: &SocketAddr| match dst.ip() {
        IpAddr::V4(ip) => ip == Ipv4Addr::BROADCAST || broadcasts.contains(&ip),
        IpAddr::V6(_) => false,
    };

    // Local hosts: IPs that sent a broadcast themselves and never forwarded one.
    let forwarders: BTreeSet<IpAddr> = records
        .iter()
        .filter_map(|r| match r {
            DecodeRecord::ForwardedNpdu { envelope, .. } => Some(envelope.src.ip()),
            _ => None,
        })
        .collect();
    let mut local_hosts: BTreeSet<IpAddr> = BTreeSet::new();
    let mut local_broadcasts: u64 = 0;
    for record in records {
        if matches!(record, DecodeRecord::ForwardedNpdu { .. }) {
            continue;
        }
        if let Some(envelope) = envelope_of(record)
            .filter(|e| is_broadcast(&e.dst) && !forwarders.contains(&e.src.ip()))
        {
            local_hosts.insert(envelope.src.ip());
            local_broadcasts += 1;
        }
    }

    let mut inbound: Vec<&crate::decode::Envelope> = Vec::new();
    for record in records {
        let DecodeRecord::ForwardedNpdu {
            envelope,
            original_source,
            ..
        } = record
        else {
            continue;
        };
        if local_hosts.contains(&original_source.ip()) {
            return Vec::new();
        }
        if is_broadcast(&envelope.dst) {
            inbound.push(envelope);
        }
    }
    if local_broadcasts < INCOMPLETE_BDT_MIN_LOCAL_BROADCASTS || inbound.is_empty() {
        return Vec::new();
    }

    let peers: BTreeSet<SocketAddr> = inbound.iter().map(|e| e.src).collect();
    let mut frames: Vec<u64> = inbound.iter().map(|e| e.frame_no).collect();
    frames.sort_unstable();
    frames.truncate(MAX_EVIDENCE_FRAMES);
    let peer_text = peers
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let summary = format!(
        "{peer_text} relayed {} broadcast(s) into this segment, but none of the {local_broadcasts} \
         broadcasts sent by local hosts was relayed back. This is a single-vantage inference, not a \
         read of the BDT: the peer may be missing this segment's BBMD.",
        inbound.len()
    );

    vec![Finding {
        issue: IssueId::IncompleteBdt,
        severity: IssueId::IncompleteBdt.spec().base_severity,
        affected: peers
            .iter()
            .map(|addr| DeviceRef {
                device_instance: None,
                ip: addr.ip(),
                port: Some(addr.port()),
            })
            .collect(),
        occurrences: inbound.len() as u64,
        evidence: Evidence { summary, frames },
        first_seen: inbound
            .iter()
            .map(|e| e.timestamp)
            .min()
            .unwrap_or_default(),
        last_seen: inbound
            .iter()
            .map(|e| e.timestamp)
            .max()
            .unwrap_or_default(),
    }]
}

/// Spots Register-Foreign-Device requests that the BBMD NAKed within [`REGISTRATION_NAK_WINDOW`].
/// The NAK must come back from the BBMD the request went to, addressed to the registrant; each NAK
/// answers one request.
pub fn foreign_device_registration_failure(records: &[DecodeRecord]) -> Vec<Finding> {
    // Requests per (registrant, BBMD) still waiting for an answer: (frame, timestamp).
    let mut open: BTreeMap<(SocketAddr, SocketAddr), Vec<(u64, Duration)>> = BTreeMap::new();
    // NAKed registrations per registrant: (request frame, NAK frame, NAK time).
    let mut failures: BTreeMap<SocketAddr, Vec<(u64, u64, Duration)>> = BTreeMap::new();

    for record in records {
        match record {
            DecodeRecord::RegisterForeignDevice { envelope, .. } => {
                open.entry((envelope.src, envelope.dst))
                    .or_default()
                    .push((envelope.frame_no, envelope.timestamp));
            }
            DecodeRecord::BvlcResult {
                envelope,
                result_code: REGISTER_FOREIGN_DEVICE_NAK,
            } => {
                let Some(pending) = open.get_mut(&(envelope.dst, envelope.src)) else {
                    continue;
                };
                // Latest request first: the NAK most plausibly answers the newest one.
                let matched = pending.iter().rposition(|(_, sent)| {
                    envelope.timestamp >= *sent
                        && envelope.timestamp - *sent <= REGISTRATION_NAK_WINDOW
                });
                if let Some(index) = matched {
                    let (request_frame, _) = pending.remove(index);
                    failures.entry(envelope.dst).or_default().push((
                        request_frame,
                        envelope.frame_no,
                        envelope.timestamp,
                    ));
                }
            }
            _ => {}
        }
    }

    if failures.is_empty() {
        return Vec::new();
    }

    let worst = failures.values().map(Vec::len).max().unwrap_or(0) as u64;
    let severity = if worst > REGISTRATION_NAK_HIGH_ABOVE {
        Severity::High
    } else {
        IssueId::ForeignDeviceRegistrationFailure
            .spec()
            .base_severity
    };
    let total: u64 = failures.values().map(|f| f.len() as u64).sum();
    let mut frames: Vec<u64> = failures
        .values()
        .flatten()
        .flat_map(|(request, nak, _)| [*request, *nak])
        .collect();
    frames.sort_unstable();
    frames.truncate(MAX_EVIDENCE_FRAMES);
    let times = || failures.values().flatten().map(|(_, _, at)| *at);
    let registrants_text = failures
        .iter()
        .map(|(addr, naks)| format!("{addr} ({} NAK(s))", naks.len()))
        .collect::<Vec<_>>()
        .join(", ");
    let summary = format!(
        "{total} Register-Foreign-Device request(s) were NAKed by the BBMD within {} s: \
         {registrants_text}.",
        REGISTRATION_NAK_WINDOW.as_secs()
    );

    vec![Finding {
        issue: IssueId::ForeignDeviceRegistrationFailure,
        severity,
        affected: failures
            .keys()
            .map(|addr| DeviceRef {
                device_instance: None,
                ip: addr.ip(),
                port: Some(addr.port()),
            })
            .collect(),
        occurrences: total,
        evidence: Evidence { summary, frames },
        first_seen: times().min().unwrap_or_default(),
        last_seen: times().max().unwrap_or_default(),
    }]
}
