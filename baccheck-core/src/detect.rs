//! Seam 3: the ten pure-function detectors (`stream -> Vec<Finding>`) over the decode seam's output.
//!
//! Implemented so far: [`duplicate_device_id`]. The other nine are separate tickets; see wayfinder
//! ticket #4 for the decided rules. [`detect_all`] runs every detector that exists.
//!
//! Contract for `duplicate_device_id` (one test per line, in `tests/detect.rs`):
//! - An I-Am claiming one device instance from two or more distinct source IP:port pairs is a
//!   High finding, one per instance.
//! - Three or more distinct source IPs make it Critical.
//! - Device instance 4194303 is the wildcard and never counts.
//! - One address sending many I-Ams for one instance is not a duplicate.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::decode::DecodeRecord;
use crate::report::{DeviceRef, Evidence, Finding, IssueId, Severity, MAX_EVIDENCE_FRAMES};

/// The device instance number that means "any device". It is not a real device.
pub const WILDCARD_DEVICE_INSTANCE: u32 = 4_194_303;

/// Distinct source IPs at which a duplicate device ID becomes Critical.
pub const DUPLICATE_ID_CRITICAL_IPS: usize = 3;

/// Runs every detector that exists over the decode stream.
pub fn detect_all(records: &[DecodeRecord]) -> Vec<Finding> {
    duplicate_device_id(records)
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
