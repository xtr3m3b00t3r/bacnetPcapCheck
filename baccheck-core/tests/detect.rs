use std::net::SocketAddr;
use std::time::Duration;

use baccheck_core::decode::{DecodeRecord, Envelope};
use baccheck_core::detect::duplicate_device_id;
use baccheck_core::report::{IssueId, Severity};
use bacnet_rs::object::Segmentation;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn i_am(frame_no: u64, secs: u64, src: &str, instance: u32) -> DecodeRecord {
    DecodeRecord::IAm {
        envelope: Envelope {
            frame_no,
            timestamp: Duration::from_secs(secs),
            src: addr(src),
            dst: addr("10.0.0.255:47808"),
        },
        device_instance: instance,
        max_apdu_length_accepted: 1476,
        segmentation_supported: Segmentation::NoSegmentation,
        vendor_identifier: 260,
    }
}

#[test]
fn two_addresses_claiming_one_instance_is_a_high_finding() {
    let records = [
        i_am(1, 100, "10.0.0.5:47808", 101),
        i_am(2, 110, "10.0.0.6:47808", 101),
        i_am(3, 120, "10.0.0.5:47808", 101),
    ];

    let findings = duplicate_device_id(&records);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.issue, IssueId::DuplicateDeviceId);
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.affected.len(), 2);
    assert!(f.affected.iter().all(|d| d.device_instance == Some(101)));
    assert_eq!(f.occurrences, 3);
    assert_eq!(f.evidence.frames, vec![1, 2, 3]);
    assert_eq!(f.first_seen, Duration::from_secs(100));
    assert_eq!(f.last_seen, Duration::from_secs(120));
    assert!(f.evidence.summary.contains("101"));
}

#[test]
fn three_distinct_ips_is_critical() {
    let records = [
        i_am(1, 1, "10.0.0.5:47808", 7),
        i_am(2, 2, "10.0.0.6:47808", 7),
        i_am(3, 3, "10.0.0.7:47808", 7),
    ];

    let findings = duplicate_device_id(&records);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn one_ip_on_three_ports_is_not_critical() {
    let records = [
        i_am(1, 1, "10.0.0.5:47808", 7),
        i_am(2, 2, "10.0.0.5:47809", 7),
        i_am(3, 3, "10.0.0.5:47810", 7),
    ];

    let findings = duplicate_device_id(&records);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn wildcard_instance_never_matches() {
    let records = [
        i_am(1, 1, "10.0.0.5:47808", 4_194_303),
        i_am(2, 2, "10.0.0.6:47808", 4_194_303),
    ];

    assert!(duplicate_device_id(&records).is_empty());
}

#[test]
fn one_address_repeating_its_i_am_is_not_a_duplicate() {
    let records: Vec<_> = (0..20)
        .map(|n| i_am(n + 1, n, "10.0.0.5:47808", 101))
        .collect();

    assert!(duplicate_device_id(&records).is_empty());
}

#[test]
fn different_instances_from_different_addresses_are_not_duplicates() {
    let records = [
        i_am(1, 1, "10.0.0.5:47808", 101),
        i_am(2, 2, "10.0.0.6:47808", 102),
    ];

    assert!(duplicate_device_id(&records).is_empty());
}

#[test]
fn evidence_carries_at_most_five_frames() {
    let mut records = Vec::new();
    for n in 0..10u64 {
        records.push(i_am(n * 2 + 1, n, "10.0.0.5:47808", 101));
        records.push(i_am(n * 2 + 2, n, "10.0.0.6:47808", 101));
    }

    let findings = duplicate_device_id(&records);

    assert_eq!(findings[0].evidence.frames, vec![1, 2, 3, 4, 5]);
    assert_eq!(findings[0].occurrences, 20);
}
