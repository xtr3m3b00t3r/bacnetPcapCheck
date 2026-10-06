use std::net::SocketAddr;
use std::time::Duration;

use baccheck_core::decode::{DecodeRecord, Envelope};
use baccheck_core::detect::{broadcast_storm, duplicate_device_id};
use baccheck_core::report::{CaptureStats, IssueId, Severity};
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

fn who_is(frame_no: u64, secs: u64, src: &str, dst: &str) -> DecodeRecord {
    DecodeRecord::WhoIs {
        envelope: Envelope {
            frame_no,
            timestamp: Duration::from_secs(secs),
            src: addr(src),
            dst: addr(dst),
        },
        low_limit: None,
        high_limit: None,
    }
}

fn stats(span_secs: u64, decoded: u64, undecoded: u64, non_bacnet: u64) -> CaptureStats {
    CaptureStats {
        capture_name: "fixture.pcap".into(),
        total_frames: decoded + undecoded + non_bacnet,
        decoded_frames: decoded,
        undecoded_frames: undecoded,
        non_bacnet_frames: non_bacnet,
        first_timestamp: Some(Duration::ZERO),
        last_timestamp: Some(Duration::from_secs(span_secs)),
    }
}

fn unicast_apdu(frame_no: u64, secs: u64, src: &str, dst: &str) -> DecodeRecord {
    DecodeRecord::NetworkMessage {
        envelope: Envelope {
            frame_no,
            timestamp: Duration::from_secs(secs),
            src: addr(src),
            dst: addr(dst),
        },
        message_type: 0,
    }
}

/// `count` global Who-Is spread evenly over the first minute from `src`, frames 1..=count.
fn who_is_burst(count: u64, src: &str) -> Vec<DecodeRecord> {
    (0..count)
        .map(|n| who_is(n + 1, n * 60 / count, src, "10.0.0.255:47808"))
        .collect()
}

/// `count` unicast messages spread over `span_secs`, frames from 10_000.
fn background(count: u64, span_secs: u64) -> Vec<DecodeRecord> {
    (0..count)
        .map(|n| {
            unicast_apdu(
                10_000 + n,
                n * span_secs / count,
                "10.0.0.5:47808",
                "10.0.0.6:47808",
            )
        })
        .collect()
}

fn decoded_stats(span_secs: u64, records: &[DecodeRecord]) -> CaptureStats {
    stats(span_secs, records.len() as u64, 0, 0)
}

#[test]
fn who_is_flood_over_the_capture_span_floor_is_a_high_finding() {
    let mut records = who_is_burst(700, "10.0.0.9:47808");
    records.extend(background(1800, 600));

    let findings = broadcast_storm(&records, &decoded_stats(600, &records));

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.issue, IssueId::BroadcastStorm);
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.affected.len(), 1);
    assert_eq!(
        f.affected[0].ip,
        "10.0.0.9".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(f.evidence.frames, vec![1, 2, 3, 4, 5]);
    assert_eq!(f.occurrences, 700);
    assert!(f.evidence.summary.contains("Who-Is"));
}

#[test]
fn a_flood_in_a_capture_shorter_than_five_minutes_stays_silent() {
    let mut records = who_is_burst(700, "10.0.0.9:47808");
    records.extend(background(1800, 299));

    assert!(broadcast_storm(&records, &decoded_stats(299, &records)).is_empty());
}

#[test]
fn a_who_is_rate_at_the_limit_stays_silent() {
    // Exactly 10/s for a minute is not "more than 10/s".
    let mut records = who_is_burst(600, "10.0.0.9:47808");
    records.extend(background(2400, 600));

    assert!(broadcast_storm(&records, &decoded_stats(600, &records)).is_empty());
}

#[test]
fn directed_who_is_does_not_count_as_a_global_flood() {
    let mut records: Vec<_> = (0..700)
        .map(|n| who_is(n + 1, n * 60 / 700, "10.0.0.9:47808", "10.0.0.6:47808"))
        .collect();
    records.extend(background(1800, 600));

    assert!(broadcast_storm(&records, &decoded_stats(600, &records)).is_empty());
}

#[test]
fn i_am_flood_fires() {
    // 3100 broadcast I-Am in one minute (> 50/s), diluted below the saturation share.
    let mut records: Vec<_> = (0..3100)
        .map(|n| i_am(n + 1, n * 60 / 3100, "10.0.0.5:47808", 101))
        .collect();
    records.extend(background(8000, 600));

    let findings = broadcast_storm(&records, &decoded_stats(600, &records));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].affected[0].device_instance, Some(101));
    assert!(findings[0].evidence.summary.contains("I-Am"));
}

#[test]
fn broadcast_saturation_fires_without_a_rate_spike() {
    // 40% broadcast share spread thinly over ten minutes: no bucket flood, but saturated.
    let mut records: Vec<_> = (0..400)
        .map(|n| {
            who_is(
                n + 1,
                n * 600 / 400,
                "10.0.0.9:47808",
                "255.255.255.255:47808",
            )
        })
        .collect();
    records.extend(background(600, 600));

    let findings = broadcast_storm(&records, &decoded_stats(600, &records));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].evidence.summary.contains("saturation"));
}

#[test]
fn saturation_needs_two_hundred_messages() {
    let mut records: Vec<_> = (0..100)
        .map(|n| {
            who_is(
                n + 1,
                n * 600 / 100,
                "10.0.0.9:47808",
                "255.255.255.255:47808",
            )
        })
        .collect();
    records.extend(background(99, 600));

    assert!(broadcast_storm(&records, &decoded_stats(600, &records)).is_empty());
}

#[test]
fn broadcast_share_above_half_is_critical() {
    let mut records = who_is_burst(700, "10.0.0.9:47808");
    records.extend(background(100, 600));

    let findings = broadcast_storm(&records, &decoded_stats(600, &records));

    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn more_than_twenty_five_broadcasting_sources_is_critical() {
    // 26 sources, 28 Who-Is each: 728 in one minute, ~28% of the capture.
    let mut records = Vec::new();
    for source in 0..26u64 {
        for n in 0..28u64 {
            records.push(who_is(
                source * 28 + n + 1,
                n * 2,
                &format!("10.0.0.{}:47808", source + 10),
                "10.0.0.255:47808",
            ));
        }
    }
    records.extend(background(1900, 600));

    let findings = broadcast_storm(&records, &decoded_stats(600, &records));

    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[0].affected.len(), 5);
}

#[test]
fn a_dotted_255_destination_is_broadcast_only_in_an_observed_subnet() {
    // 10.9.9.255 is in no subnet the capture has a source in, so it is just a unicast address.
    let mut records: Vec<_> = (0..700)
        .map(|n| who_is(n + 1, n * 60 / 700, "10.0.0.9:47808", "10.9.9.255:47808"))
        .collect();
    records.extend(background(1800, 600));

    assert!(broadcast_storm(&records, &decoded_stats(600, &records)).is_empty());
}

#[test]
fn evidence_always_states_the_undecodable_share_and_cautions_when_high() {
    let mut records = who_is_burst(700, "10.0.0.9:47808");
    records.extend(background(1800, 600));
    let decoded = records.len() as u64;

    let low = broadcast_storm(&records, &stats(600, decoded, 10, 0));
    let high = broadcast_storm(&records, &stats(600, decoded, 0, decoded));

    assert!(low[0]
        .evidence
        .summary
        .contains("0% of the capture was not decodable"));
    assert!(!low[0]
        .evidence
        .summary
        .contains("verify the storm is BACnet-sourced"));
    assert!(high[0]
        .evidence
        .summary
        .contains("50% of the capture was not decodable"));
    assert!(high[0]
        .evidence
        .summary
        .contains("verify the storm is BACnet-sourced"));
}

#[test]
fn undecodable_share_never_decides_whether_the_storm_fires() {
    let mut records = who_is_burst(700, "10.0.0.9:47808");
    records.extend(background(1800, 600));

    let findings = broadcast_storm(&records, &stats(600, 2500, 0, 100_000));

    assert_eq!(findings.len(), 1);
}

#[test]
fn evidence_names_at_most_five_top_talkers_busiest_first() {
    let mut records = Vec::new();
    for (i, count) in [10u64, 400, 20, 30, 40, 50, 60].iter().enumerate() {
        for n in 0..*count {
            records.push(who_is(
                (i as u64) * 1000 + n + 1,
                n % 60,
                &format!("10.0.0.{}:47808", i + 10),
                "10.0.0.255:47808",
            ));
        }
    }
    records.extend(background(1800, 600));

    let findings = broadcast_storm(&records, &decoded_stats(600, &records));

    let ips: Vec<String> = findings[0]
        .affected
        .iter()
        .map(|d| d.ip.to_string())
        .collect();
    assert_eq!(ips.len(), 5);
    assert!(ips.contains(&"10.0.0.11".to_string()));
    assert!(!ips.contains(&"10.0.0.10".to_string()));
    assert!(findings[0]
        .evidence
        .summary
        .contains("10.0.0.11:47808 (400)"));
}
