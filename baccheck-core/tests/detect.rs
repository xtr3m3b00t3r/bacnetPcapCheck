use std::time::Duration;

mod common;

use common::*;

use baccheck_core::decode::DecodeRecord;
use baccheck_core::detect::{
    broadcast_storm, duplicate_bbmd, duplicate_device_id, foreign_device_registration_failure,
    incomplete_bdt, segmentation_misuse, unicast_i_am, unresponsive_device,
};
use baccheck_core::report::{IssueId, Severity};

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

#[test]
fn peak_window_is_reported_relative_to_the_capture_start() {
    // Real captures carry epoch timestamps; the window must read as an offset, not an epoch.
    let epoch = 1_700_000_000u64;
    let mut records: Vec<_> = (0..700)
        .map(|n| {
            who_is(
                n + 1,
                epoch + 120 + n * 60 / 700,
                "10.0.0.9:47808",
                "10.0.0.255:47808",
            )
        })
        .collect();
    records.extend((0..1800).map(|n| {
        unicast_apdu(
            10_000 + n,
            epoch + n * 600 / 1800,
            "10.0.0.5:47808",
            "10.0.0.6:47808",
        )
    }));
    let mut capture = decoded_stats(600, &records);
    capture.first_timestamp = Some(Duration::from_secs(epoch));
    capture.last_timestamp = Some(Duration::from_secs(epoch + 600));

    let findings = broadcast_storm(&records, &capture);

    assert!(findings[0]
        .evidence
        .summary
        .contains("from 120 s into the capture"));
}

#[test]
fn device_answering_under_half_its_requests_is_a_medium_finding() {
    let records = requests_to_device(10, 4);

    let findings = unresponsive_device(&records);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.issue, IssueId::UnresponsiveDevice);
    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.affected.len(), 1);
    assert_eq!(f.affected[0].ip.to_string(), "10.0.0.9");
    assert_eq!(f.occurrences, 6);
    assert_eq!(f.evidence.frames, vec![5, 6, 7, 8, 9]);
    assert!(f.evidence.summary.contains("one point"));
}

#[test]
fn device_answering_under_a_fifth_is_high() {
    let findings = unresponsive_device(&requests_to_device(10, 1));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn unresponsive_stays_silent_below_the_request_floor() {
    assert!(unresponsive_device(&requests_to_device(9, 0)).is_empty());
}

#[test]
fn unresponsive_stays_silent_when_half_or_more_are_answered() {
    assert!(unresponsive_device(&requests_to_device(10, 5)).is_empty());
}

#[test]
fn reject_and_error_style_replies_count_as_answers() {
    let mut records = requests_to_device(10, 0);
    records.push(reject(2000, 1, "10.0.0.9:47808", "10.0.0.5:47808", 1));
    records.push(reject(2001, 3, "10.0.0.9:47808", "10.0.0.5:47808", 2));
    records.push(reject(2002, 5, "10.0.0.9:47808", "10.0.0.5:47808", 3));
    records.push(reject(2003, 7, "10.0.0.9:47808", "10.0.0.5:47808", 4));
    records.push(reject(2004, 9, "10.0.0.9:47808", "10.0.0.5:47808", 5));

    assert!(unresponsive_device(&records).is_empty());
}

#[test]
fn a_reply_after_the_response_window_does_not_count() {
    let mut records = requests_to_device(10, 0);
    for n in 0..10u8 {
        records.push(simple_ack(
            3000 + u64::from(n),
            u64::from(n) * 2 + 11,
            "10.0.0.9:47808",
            "10.0.0.5:47808",
            n + 1,
        ));
    }

    let findings = unresponsive_device(&records);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn retransmissions_of_one_unanswered_request_count_once() {
    let mut records = requests_to_device(10, 10);
    // One extra request, sent three times, never answered: 11 requests, 10 answered.
    for (n, secs) in [20u64, 23, 26].into_iter().enumerate() {
        records.push(confirmed_request(
            4000 + n as u64,
            secs,
            "10.0.0.5:47808",
            "10.0.0.9:47808",
            99,
        ));
    }

    assert!(unresponsive_device(&records).is_empty());
}

#[test]
fn a_reused_invoke_id_is_a_new_request() {
    let mut records = requests_to_device(10, 10);
    records.push(confirmed_request(
        5000,
        100,
        "10.0.0.5:47808",
        "10.0.0.9:47808",
        1,
    ));

    // 11 requests, the late one unanswered: 10/11 answered, silent.
    assert!(unresponsive_device(&records).is_empty());
}

#[test]
fn an_invoke_id_reused_after_silence_is_a_new_request() {
    // Ten requests to one device, all unanswered, every one reusing invoke ID 1 a minute apart.
    let records: Vec<_> = (0..10u64)
        .map(|n| confirmed_request(n + 1, n * 60, "10.0.0.5:47808", "10.0.0.9:47808", 1))
        .collect();

    let findings = unresponsive_device(&records);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].occurrences, 10);
}

#[test]
fn one_broadcast_relayed_by_two_bbmds_is_a_high_finding_naming_both() {
    let records = vec![
        forwarded_npdu(1, 10, "10.0.1.2:47808", 7),
        forwarded_npdu(2, 11, "10.0.2.2:47808", 7),
    ];

    let findings = duplicate_bbmd(&records, &decoded_stats(600, &records));

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.issue, IssueId::DuplicateBbmd);
    assert_eq!(finding.severity, Severity::High);
    let ips: Vec<String> = finding.affected.iter().map(|d| d.ip.to_string()).collect();
    assert_eq!(ips, ["10.0.1.2", "10.0.2.2"]);
    assert_eq!(finding.occurrences, 2);
    assert_eq!(finding.evidence.frames, [1, 2]);
    assert_eq!(finding.first_seen, Duration::from_secs(10));
    assert_eq!(finding.last_seen, Duration::from_secs(11));
}

#[test]
fn two_bbmds_relaying_different_broadcasts_is_not_a_duplicate() {
    let records = vec![
        forwarded_npdu(1, 10, "10.0.1.2:47808", 7),
        forwarded_npdu(2, 11, "10.0.2.2:47808", 8),
    ];
    assert!(duplicate_bbmd(&records, &decoded_stats(600, &records)).is_empty());
}

#[test]
fn a_hash_reused_by_another_bbmd_after_silence_is_a_new_broadcast() {
    let records = vec![
        forwarded_npdu(1, 10, "10.0.1.2:47808", 7),
        forwarded_npdu(2, 3_000, "10.0.2.2:47808", 7),
    ];
    assert!(duplicate_bbmd(&records, &decoded_stats(3_600, &records)).is_empty());
}

#[test]
fn three_bbmds_relaying_one_broadcast_is_critical() {
    let records = vec![
        forwarded_npdu(1, 10, "10.0.1.2:47808", 7),
        forwarded_npdu(2, 11, "10.0.2.2:47808", 7),
        forwarded_npdu(3, 12, "10.0.3.2:47808", 7),
    ];
    let findings = duplicate_bbmd(&records, &decoded_stats(600, &records));
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn six_repeats_in_one_minute_is_a_high_loop_finding() {
    let records: Vec<_> = (0..6)
        .map(|n| forwarded_npdu(n + 1, 10 + n * 5, "10.0.1.2:47808", 7))
        .collect();

    let findings = duplicate_bbmd(&records, &decoded_stats(600, &records));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].affected.len(), 1);
    assert_eq!(findings[0].occurrences, 6);
}

#[test]
fn five_repeats_in_one_minute_stays_silent() {
    let records: Vec<_> = (0..5)
        .map(|n| forwarded_npdu(n + 1, 10 + n * 5, "10.0.1.2:47808", 7))
        .collect();
    assert!(duplicate_bbmd(&records, &decoded_stats(600, &records)).is_empty());
}

#[test]
fn repeats_spread_over_several_minutes_stay_silent() {
    let records: Vec<_> = (0..6)
        .map(|n| forwarded_npdu(n + 1, n * 90, "10.0.1.2:47808", 7))
        .collect();
    assert!(duplicate_bbmd(&records, &decoded_stats(600, &records)).is_empty());
}

#[test]
fn more_than_twenty_repeats_in_one_minute_is_critical() {
    let records: Vec<_> = (0..21)
        .map(|n| forwarded_npdu(n + 1, 10 + n, "10.0.1.2:47808", 7))
        .collect();
    let findings = duplicate_bbmd(&records, &decoded_stats(600, &records));
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn twenty_repeats_in_one_minute_is_still_high() {
    let records: Vec<_> = (0..20)
        .map(|n| forwarded_npdu(n + 1, 10 + n, "10.0.1.2:47808", 7))
        .collect();
    let findings = duplicate_bbmd(&records, &decoded_stats(600, &records));
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn the_loop_rate_needs_a_five_minute_capture_but_two_bbmds_do_not() {
    let looping: Vec<_> = (0..6)
        .map(|n| forwarded_npdu(n + 1, 10 + n, "10.0.1.2:47808", 7))
        .collect();
    assert!(duplicate_bbmd(&looping, &decoded_stats(299, &looping)).is_empty());

    let two_bbmds = vec![
        forwarded_npdu(1, 10, "10.0.1.2:47808", 7),
        forwarded_npdu(2, 11, "10.0.2.2:47808", 7),
    ];
    assert_eq!(
        duplicate_bbmd(&two_bbmds, &decoded_stats(299, &two_bbmds)).len(),
        1
    );
}

#[test]
fn repeat_buckets_are_counted_from_the_capture_start() {
    // Epoch-aligned buckets would split these six across the minute boundary at 1_700_000_080.
    let origin = 1_700_000_050;
    let records: Vec<_> = (0..6)
        .map(|n| forwarded_npdu(n + 1, origin + 5 + n * 5, "10.0.1.2:47808", 7))
        .collect();
    let capture = stats(600, records.len() as u64, 0, 0);
    let capture = baccheck_core::report::CaptureStats {
        first_timestamp: Some(Duration::from_secs(origin)),
        last_timestamp: Some(Duration::from_secs(origin + 600)),
        ..capture
    };
    assert_eq!(duplicate_bbmd(&records, &capture).len(), 1);
}

#[test]
fn bbmd_evidence_carries_at_most_five_frames_and_one_finding_covers_every_hash() {
    let mut records: Vec<_> = (0..8)
        .map(|n| forwarded_npdu(n + 1, 10 + n, "10.0.1.2:47808", 7))
        .collect();
    records.push(forwarded_npdu(20, 30, "10.0.5.2:47808", 9));
    records.push(forwarded_npdu(21, 31, "10.0.6.2:47808", 9));

    let findings = duplicate_bbmd(&records, &decoded_stats(600, &records));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].evidence.frames.len(), 5);
    assert_eq!(findings[0].affected.len(), 3);
    assert_eq!(findings[0].occurrences, 10);
}

#[test]
fn bbmd_severity_is_the_worst_across_hashes() {
    let mut records = vec![
        forwarded_npdu(1, 10, "10.0.1.2:47808", 7),
        forwarded_npdu(2, 11, "10.0.2.2:47808", 7),
    ];
    records.extend((0..3).map(|n| {
        forwarded_npdu(
            10 + n,
            20,
            ["10.0.3.2:47808", "10.0.4.2:47808", "10.0.5.2:47808"][n as usize],
            9,
        )
    }));
    let findings = duplicate_bbmd(&records, &decoded_stats(600, &records));
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn a_bbmd_outside_the_duplicate_episode_is_not_named() {
    let records = vec![
        forwarded_npdu(1, 10, "10.0.1.2:47808", 7),
        forwarded_npdu(2, 11, "10.0.2.2:47808", 7),
        forwarded_npdu(3, 3_000, "10.0.3.2:47808", 7),
    ];
    let findings = duplicate_bbmd(&records, &decoded_stats(3_600, &records));
    let ips: Vec<String> = findings[0]
        .affected
        .iter()
        .map(|d| d.ip.to_string())
        .collect();
    assert_eq!(ips, ["10.0.1.2", "10.0.2.2"]);
}

#[test]
fn a_peer_forwarding_in_while_no_local_broadcast_comes_back_is_a_low_finding_naming_the_peer() {
    let mut records = local_broadcasts(50);
    records.push(forwarded_from(
        51,
        60,
        "10.0.5.1:47808",
        "10.0.9.9:47808",
        1,
    ));
    records.push(forwarded_from(
        52,
        70,
        "10.0.5.1:47808",
        "10.0.9.8:47808",
        2,
    ));

    let findings = incomplete_bdt(&records);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.issue, IssueId::IncompleteBdt);
    assert_eq!(f.severity, Severity::Low);
    assert_eq!(f.affected.len(), 1);
    assert_eq!(f.affected[0].ip, addr("10.0.5.1:47808").ip());
    assert_eq!(f.occurrences, 2);
    assert_eq!(f.evidence.frames, vec![51, 52]);
    assert_eq!(f.first_seen, Duration::from_secs(60));
    assert_eq!(f.last_seen, Duration::from_secs(70));
    assert!(f.evidence.summary.contains("single-vantage"));
}

#[test]
fn incomplete_bdt_stays_silent_below_the_local_broadcast_floor() {
    let mut records = local_broadcasts(49);
    records.push(forwarded_from(
        50,
        60,
        "10.0.5.1:47808",
        "10.0.9.9:47808",
        1,
    ));

    assert!(incomplete_bdt(&records).is_empty());
}

#[test]
fn incomplete_bdt_stays_silent_when_a_local_broadcast_is_relayed_back() {
    let mut records = local_broadcasts(50);
    records.push(forwarded_from(
        51,
        60,
        "10.0.5.1:47808",
        "10.0.9.9:47808",
        1,
    ));
    records.push(forwarded_from(
        52,
        61,
        "10.0.5.1:47808",
        "10.0.0.5:47808",
        2,
    ));

    assert!(incomplete_bdt(&records).is_empty());
}

#[test]
fn incomplete_bdt_never_escalates_however_much_evidence_there_is() {
    let mut records = local_broadcasts(500);
    for n in 0..100 {
        let peer = format!("10.0.{}.1:47808", 5 + n % 4);
        records.push(forwarded_from(501 + n, 600 + n, &peer, "10.0.9.9:47808", n));
    }

    let findings = incomplete_bdt(&records);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Low);
    assert_eq!(findings[0].affected.len(), 4);
    assert_eq!(findings[0].occurrences, 100);
    assert_eq!(findings[0].evidence.frames.len(), 5);
}

#[test]
fn incomplete_bdt_does_not_count_broadcasts_from_a_host_that_also_forwards() {
    let mut records = local_broadcasts(50);
    records.push(forwarded_from(
        51,
        60,
        "10.0.0.5:47808",
        "10.0.9.9:47808",
        1,
    ));

    assert!(incomplete_bdt(&records).is_empty());
}

#[test]
fn incomplete_bdt_ignores_a_unicast_forwarded_npdu() {
    let mut records = local_broadcasts(50);
    let mut unicast = forwarded_from(51, 60, "10.0.5.1:47808", "10.0.9.9:47808", 1);
    if let DecodeRecord::ForwardedNpdu { envelope, .. } = &mut unicast {
        envelope.dst = addr("10.0.0.7:47808");
    }
    records.push(unicast);

    assert!(incomplete_bdt(&records).is_empty());
}

#[test]
fn a_nak_answering_a_registration_is_a_medium_finding_naming_the_registrant() {
    let records = rejected_registrations(1, "192.168.5.20:47808", "10.0.0.10:47808");

    let findings = foreign_device_registration_failure(&records);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.issue, IssueId::ForeignDeviceRegistrationFailure);
    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.affected.len(), 1);
    assert_eq!(f.affected[0].ip, addr("192.168.5.20:47808").ip());
    assert_eq!(f.occurrences, 1);
    assert_eq!(f.evidence.frames, vec![1, 1000]);
    assert_eq!(f.first_seen, Duration::from_secs(1));
    assert_eq!(f.last_seen, Duration::from_secs(1));
}

#[test]
fn five_naks_for_one_registrant_stay_medium_and_six_are_high() {
    let five = rejected_registrations(5, "192.168.5.20:47808", "10.0.0.10:47808");
    let six = rejected_registrations(6, "192.168.5.20:47808", "10.0.0.10:47808");

    assert_eq!(
        foreign_device_registration_failure(&five)[0].severity,
        Severity::Medium
    );
    let f = &foreign_device_registration_failure(&six)[0];
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.occurrences, 6);
    // Pairs in time order: the sample ends on a request whose NAK was cut off.
    assert_eq!(f.evidence.frames, vec![1, 1000, 2, 1001, 3]);
}

#[test]
fn naks_spread_across_registrants_do_not_add_up_to_high() {
    let mut records = rejected_registrations(3, "192.168.5.20:47808", "10.0.0.10:47808");
    records.extend(rejected_registrations(
        3,
        "192.168.5.21:47808",
        "10.0.0.10:47808",
    ));

    let findings = foreign_device_registration_failure(&records);

    assert_eq!(findings[0].severity, Severity::Medium);
    assert_eq!(findings[0].affected.len(), 2);
    assert_eq!(findings[0].occurrences, 6);
}

#[test]
fn a_nak_more_than_ten_seconds_after_the_request_is_not_a_failure() {
    let records = [
        register_fd(1, 0, "192.168.5.20:47808", "10.0.0.10:47808"),
        bvlc_result(2, 11, "10.0.0.10:47808", "192.168.5.20:47808", 0x0030),
    ];

    assert!(foreign_device_registration_failure(&records).is_empty());
}

#[test]
fn a_nak_exactly_ten_seconds_after_the_request_counts() {
    let records = [
        register_fd(1, 0, "192.168.5.20:47808", "10.0.0.10:47808"),
        bvlc_result(2, 10, "10.0.0.10:47808", "192.168.5.20:47808", 0x0030),
    ];

    assert_eq!(foreign_device_registration_failure(&records).len(), 1);
}

#[test]
fn a_successful_registration_is_silent() {
    let records = [
        register_fd(1, 0, "192.168.5.20:47808", "10.0.0.10:47808"),
        bvlc_result(2, 1, "10.0.0.10:47808", "192.168.5.20:47808", 0x0000),
    ];

    assert!(foreign_device_registration_failure(&records).is_empty());
}

#[test]
fn other_nak_codes_are_not_registration_failures() {
    let records = [
        register_fd(1, 0, "192.168.5.20:47808", "10.0.0.10:47808"),
        bvlc_result(2, 1, "10.0.0.10:47808", "192.168.5.20:47808", 0x0010),
    ];

    assert!(foreign_device_registration_failure(&records).is_empty());
}

#[test]
fn a_nak_with_no_matching_request_or_from_another_bbmd_is_silent() {
    let unrequested = [bvlc_result(
        1,
        1,
        "10.0.0.10:47808",
        "192.168.5.20:47808",
        0x0030,
    )];
    let wrong_bbmd = [
        register_fd(1, 0, "192.168.5.20:47808", "10.0.0.10:47808"),
        bvlc_result(2, 1, "10.0.0.11:47808", "192.168.5.20:47808", 0x0030),
    ];

    assert!(foreign_device_registration_failure(&unrequested).is_empty());
    assert!(foreign_device_registration_failure(&wrong_bbmd).is_empty());
}

#[test]
fn one_request_is_answered_by_at_most_one_nak() {
    let records = [
        register_fd(1, 0, "192.168.5.20:47808", "10.0.0.10:47808"),
        bvlc_result(2, 1, "10.0.0.10:47808", "192.168.5.20:47808", 0x0030),
        bvlc_result(3, 2, "10.0.0.10:47808", "192.168.5.20:47808", 0x0030),
    ];

    assert_eq!(
        foreign_device_registration_failure(&records)[0].occurrences,
        1
    );
}

#[test]
fn a_request_reusing_the_key_after_silence_starts_a_new_registration() {
    let records = [
        register_fd(1, 0, "192.168.5.20:47808", "10.0.0.10:47808"),
        register_fd(2, 100, "192.168.5.20:47808", "10.0.0.10:47808"),
        bvlc_result(3, 101, "10.0.0.10:47808", "192.168.5.20:47808", 0x0030),
    ];

    let findings = foreign_device_registration_failure(&records);

    assert_eq!(findings[0].occurrences, 1);
    assert_eq!(findings[0].evidence.frames, vec![2, 3]);
}

#[test]
fn three_abandoned_exchanges_for_one_pair_is_a_medium_finding_naming_the_sender() {
    let mut records = segmented_exchanges(3, 0);
    records.push(unicast_apdu(900, 300, "10.0.0.5:47808", "10.0.0.6:47808"));

    let findings = segmentation_misuse(&records);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.issue, IssueId::SegmentationMisuse);
    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.affected.len(), 1);
    assert_eq!(f.affected[0].ip, addr("10.0.0.5:47808").ip());
    assert_eq!(f.occurrences, 3);
    assert_eq!(f.evidence.frames, vec![2, 12, 22]);
    assert_eq!(f.first_seen, Duration::from_secs(1));
    assert_eq!(f.last_seen, Duration::from_secs(201));
}

#[test]
fn two_abandoned_exchanges_stay_silent() {
    let mut records = segmented_exchanges(2, 0);
    records.push(unicast_apdu(900, 300, "10.0.0.5:47808", "10.0.0.6:47808"));

    assert!(segmentation_misuse(&records).is_empty());
}

#[test]
fn an_exchange_open_when_the_capture_ends_is_not_judged() {
    // The last exchange's final segment is at t=201; the capture ends 20 s later.
    let mut records = segmented_exchanges(3, 0);
    records.push(unicast_apdu(900, 221, "10.0.0.5:47808", "10.0.0.6:47808"));

    assert!(segmentation_misuse(&records).is_empty());
}

#[test]
fn a_majority_abandoned_of_ten_exchanges_is_high_and_five_of_nine_stay_medium() {
    let mut high = segmented_exchanges(10, 4);
    high.push(unicast_apdu(900, 2000, "10.0.0.5:47808", "10.0.0.6:47808"));
    let mut medium = segmented_exchanges(9, 4);
    medium.push(unicast_apdu(900, 2000, "10.0.0.5:47808", "10.0.0.6:47808"));
    let mut half = segmented_exchanges(10, 5);
    half.push(unicast_apdu(900, 2000, "10.0.0.5:47808", "10.0.0.6:47808"));

    let f = &segmentation_misuse(&high)[0];
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.occurrences, 6);
    // Sample capped at five of the six abandoned exchanges.
    assert_eq!(f.evidence.frames.len(), 5);
    assert_eq!(segmentation_misuse(&medium)[0].severity, Severity::Medium);
    // Exactly half is not "more than half".
    assert_eq!(segmentation_misuse(&half)[0].severity, Severity::Medium);
}

#[test]
fn an_abort_from_the_receiver_closes_an_exchange_without_abandoning_it() {
    let mut records = segmented_exchanges(3, 0);
    for n in 0..3u8 {
        records.push(abort(
            500 + u64::from(n),
            u64::from(n) * 100 + 5,
            "10.0.0.9:47808",
            "10.0.0.5:47808",
            n + 1,
        ));
    }
    records.push(unicast_apdu(900, 2000, "10.0.0.5:47808", "10.0.0.6:47808"));

    assert!(segmentation_misuse(&records).is_empty());
}

#[test]
fn a_reused_invoke_id_after_the_abandon_window_starts_a_new_exchange() {
    // One key, three times, 100 s apart: each earlier use is abandoned, none is completed by the
    // next use's segments.
    let records = [
        segment(1, 0, "10.0.0.5:47808", "10.0.0.9:47808", 7, true),
        segment(2, 100, "10.0.0.5:47808", "10.0.0.9:47808", 7, true),
        segment(3, 200, "10.0.0.5:47808", "10.0.0.9:47808", 7, true),
        unicast_apdu(900, 300, "10.0.0.5:47808", "10.0.0.6:47808"),
    ];

    let f = &segmentation_misuse(&records)[0];

    assert_eq!(f.occurrences, 3);
    assert_eq!(f.evidence.frames, vec![1, 2, 3]);
}

#[test]
fn abandoned_exchanges_split_across_pairs_do_not_add_up() {
    let mut records = segmented_exchanges(2, 0);
    for n in 0..2u8 {
        records.push(segment(
            700 + u64::from(n),
            u64::from(n) * 100,
            "10.0.0.5:47808",
            "10.0.0.10:47808",
            n + 50,
            true,
        ));
    }
    records.push(unicast_apdu(900, 2000, "10.0.0.5:47808", "10.0.0.6:47808"));

    assert!(segmentation_misuse(&records).is_empty());
}

#[test]
fn a_reject_from_the_receiver_closes_an_exchange_but_a_segment_ack_does_not() {
    let rejected = [
        segment(1, 0, "10.0.0.5:47808", "10.0.0.9:47808", 3, true),
        reject(2, 5, "10.0.0.9:47808", "10.0.0.5:47808", 3),
    ];
    let acked = [
        segment(1, 0, "10.0.0.5:47808", "10.0.0.9:47808", 3, true),
        segment_ack(2, 5, "10.0.0.9:47808", "10.0.0.5:47808", 3),
    ];
    let judge = |records: &[DecodeRecord]| {
        // Three copies of the exchange on distinct IDs, then the capture clock runs on.
        let mut all = Vec::new();
        for id in 0..3u8 {
            for record in records {
                all.push(match record.clone() {
                    DecodeRecord::Apdu { envelope, header } => DecodeRecord::Apdu {
                        envelope,
                        header: with_invoke_id(header, id + 1),
                    },
                    other => other,
                });
            }
        }
        all.push(capture_ends_at(2000));
        segmentation_misuse(&all)
    };

    assert!(judge(&rejected).is_empty());
    assert_eq!(judge(&acked).len(), 1);
}

fn with_invoke_id(
    header: baccheck_core::decode::ApduHeader,
    id: u8,
) -> baccheck_core::decode::ApduHeader {
    use baccheck_core::decode::ApduHeader as H;
    match header {
        H::ConfirmedRequest {
            segmented,
            more_follows,
            segmented_response_accepted,
            service_choice,
            ..
        } => H::ConfirmedRequest {
            segmented,
            more_follows,
            segmented_response_accepted,
            invoke_id: id,
            service_choice,
        },
        H::SegmentAck {
            negative, server, ..
        } => H::SegmentAck {
            negative,
            server,
            invoke_id: id,
        },
        H::Reject { .. } => H::Reject { invoke_id: id },
        other => other,
    }
}

#[test]
fn complex_ack_segments_are_their_own_exchange_naming_the_responder() {
    let mut records: Vec<DecodeRecord> = (0..3u8)
        .map(|n| {
            ack_segment(
                u64::from(n) + 1,
                u64::from(n) * 100,
                "10.0.0.9:47808",
                "10.0.0.5:47808",
                n + 1,
                true,
            )
        })
        .collect();
    records.push(capture_ends_at(2000));

    let f = &segmentation_misuse(&records)[0];

    assert_eq!(f.affected.len(), 1);
    assert_eq!(f.affected[0].ip, addr("10.0.0.9:47808").ip());
}

#[test]
fn a_final_segment_after_the_abandon_window_still_counts_as_abandoned() {
    let records: Vec<DecodeRecord> = (0..3u8)
        .flat_map(|n| {
            let base = u64::from(n) * 100;
            let frame = u64::from(n) * 10;
            [
                segment(
                    frame + 1,
                    base,
                    "10.0.0.5:47808",
                    "10.0.0.9:47808",
                    n + 1,
                    true,
                ),
                segment(
                    frame + 2,
                    base + 31,
                    "10.0.0.5:47808",
                    "10.0.0.9:47808",
                    n + 1,
                    false,
                ),
            ]
        })
        .collect();

    assert_eq!(segmentation_misuse(&records)[0].occurrences, 3);
}

#[test]
fn the_worst_pair_sets_the_severity() {
    // 10.0.0.5 -> .9: 6 of 10 abandoned (High). 10.0.0.7 -> .9: 3 abandoned (Medium).
    let mut records = segmented_exchanges(10, 4);
    for n in 0..3u8 {
        records.push(segment(
            700 + u64::from(n),
            u64::from(n) * 100,
            "10.0.0.7:47808",
            "10.0.0.9:47808",
            n + 50,
            true,
        ));
    }
    records.push(capture_ends_at(2000));

    let f = &segmentation_misuse(&records)[0];

    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.affected.len(), 2);
}

/// An I-Am from `src` to the unicast address `dst`.
fn unicast_i_am_to(frame_no: u64, secs: u64, src: &str, dst: &str, instance: u32) -> DecodeRecord {
    let mut record = i_am(frame_no, secs, src, instance);
    if let DecodeRecord::IAm { envelope, .. } = &mut record {
        envelope.dst = addr(dst);
    }
    record
}

#[test]
fn an_unsolicited_unicast_i_am_is_a_low_finding_naming_the_sender() {
    let records = [unicast_i_am_to(
        7,
        50,
        "10.0.0.5:47808",
        "10.0.0.9:47808",
        101,
    )];

    let findings = unicast_i_am(&records);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.issue, IssueId::UnicastIAm);
    assert_eq!(f.severity, Severity::Low);
    assert_eq!(f.affected.len(), 1);
    assert_eq!(f.affected[0].ip, addr("10.0.0.5:47808").ip());
    assert_eq!(f.affected[0].device_instance, Some(101));
    assert_eq!(f.occurrences, 1);
    assert_eq!(f.evidence.frames, vec![7]);
    assert_eq!(f.first_seen, Duration::from_secs(50));
    assert_eq!(f.last_seen, Duration::from_secs(50));
}

#[test]
fn a_broadcast_i_am_is_silent() {
    let records = [
        i_am(1, 10, "10.0.0.5:47808", 101),
        unicast_i_am_to(2, 20, "10.0.0.5:47808", "255.255.255.255:47808", 101),
    ];

    assert!(unicast_i_am(&records).is_empty());
}

#[test]
fn a_unicast_i_am_answering_a_directed_who_is_within_sixty_seconds_is_silent() {
    let records = [
        who_is(1, 100, "10.0.0.9:47808", "10.0.0.5:47808"),
        unicast_i_am_to(2, 160, "10.0.0.5:47808", "10.0.0.9:47808", 101),
    ];

    assert!(unicast_i_am(&records).is_empty());
}

#[test]
fn a_who_is_that_does_not_exempt_leaves_the_i_am_flagged() {
    // Too old, broadcast, from another host, aimed at another device, or sent after the I-Am.
    let cases = [
        who_is(1, 100, "10.0.0.9:47808", "10.0.0.5:47808"), // 61 s before
        who_is(1, 130, "10.0.0.9:47808", "10.0.0.255:47808"),
        who_is(1, 130, "10.0.0.8:47808", "10.0.0.5:47808"),
        who_is(1, 130, "10.0.0.9:47808", "10.0.0.6:47808"),
        who_is(1, 162, "10.0.0.9:47808", "10.0.0.5:47808"),
    ];
    for who in cases {
        let records = [
            i_am(9, 10, "10.0.0.5:47808", 101),
            who,
            unicast_i_am_to(2, 161, "10.0.0.5:47808", "10.0.0.9:47808", 101),
        ];
        // Frame 9 is a broadcast I-Am; only frame 2 is unicast.
        let findings = unicast_i_am(&records);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.frames, vec![2]);
    }
}

#[test]
fn one_directed_who_is_exempts_every_i_am_in_its_window() {
    let records = [
        who_is(1, 100, "10.0.0.9:47808", "10.0.0.5:47808"),
        unicast_i_am_to(2, 110, "10.0.0.5:47808", "10.0.0.9:47808", 101),
        unicast_i_am_to(3, 120, "10.0.0.5:47808", "10.0.0.9:47808", 101),
    ];

    assert!(unicast_i_am(&records).is_empty());
}

#[test]
fn a_directed_broadcast_destination_is_a_broadcast_not_a_unicast() {
    // 10.0.0.255 is in a /24 the capture has sources in.
    let records = [unicast_i_am_to(
        1,
        10,
        "10.0.0.5:47808",
        "10.0.0.255:47808",
        101,
    )];

    assert!(unicast_i_am(&records).is_empty());
}

#[test]
fn more_than_half_of_ten_i_ams_unmatched_is_medium_and_exactly_half_stays_low() {
    let build = |unmatched: u64| {
        let mut records = Vec::new();
        for n in 0..10u64 {
            records.push(if n < unmatched {
                unicast_i_am_to(n + 1, n * 5, "10.0.0.5:47808", "10.0.0.9:47808", 101)
            } else {
                i_am(n + 1, n * 5, "10.0.0.5:47808", 101)
            });
        }
        records
    };

    assert_eq!(unicast_i_am(&build(6))[0].severity, Severity::Medium);
    assert_eq!(unicast_i_am(&build(5))[0].severity, Severity::Low);
}

#[test]
fn fewer_than_ten_i_ams_never_escalate_and_exempted_ones_count_as_matched() {
    let few: Vec<_> = (0..9u64)
        .map(|n| unicast_i_am_to(n + 1, n, "10.0.0.5:47808", "10.0.0.9:47808", 101))
        .collect();
    assert_eq!(unicast_i_am(&few)[0].severity, Severity::Low);

    // 12 I-Ams, 5 unmatched, 7 exempted by a directed Who-Is: 5/12 is under half.
    let mut records = vec![who_is(100, 1000, "10.0.0.9:47808", "10.0.0.5:47808")];
    for n in 0..7u64 {
        records.push(unicast_i_am_to(
            n + 1,
            1000 + n,
            "10.0.0.5:47808",
            "10.0.0.9:47808",
            101,
        ));
    }
    for n in 0..5u64 {
        records.push(unicast_i_am_to(
            n + 20,
            2000 + n,
            "10.0.0.5:47808",
            "10.0.0.9:47808",
            101,
        ));
    }
    let f = &unicast_i_am(&records)[0];
    assert_eq!(f.severity, Severity::Low);
    assert_eq!(f.occurrences, 5);
}

#[test]
fn evidence_is_capped_and_devices_are_judged_separately() {
    let mut records: Vec<_> = (0..8u64)
        .map(|n| unicast_i_am_to(n + 1, n, "10.0.0.5:47808", "10.0.0.9:47808", 101))
        .collect();
    records.push(unicast_i_am_to(
        50,
        9,
        "10.0.0.6:47808",
        "10.0.0.9:47808",
        102,
    ));

    let findings = unicast_i_am(&records);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.occurrences, 9);
    assert_eq!(f.affected.len(), 2);
    assert_eq!(f.evidence.frames, vec![1, 2, 3, 4, 5]);
    assert_eq!(f.first_seen, Duration::from_secs(0));
    assert_eq!(f.last_seen, Duration::from_secs(9));
    assert!(f.evidence.summary.contains("10.0.0.5:47808"));
}

#[test]
fn a_who_is_from_another_port_or_long_ago_does_not_exempt_and_a_fresh_one_does() {
    let flagged = |who: DecodeRecord| {
        let records = [
            who,
            unicast_i_am_to(2, 500, "10.0.0.5:47808", "10.0.0.9:47808", 101),
        ];
        unicast_i_am(&records).len()
    };
    assert_eq!(
        flagged(who_is(1, 499, "10.0.0.9:47809", "10.0.0.5:47808")),
        1
    );
    assert_eq!(
        flagged(who_is(1, 100, "10.0.0.9:47808", "10.0.0.5:47808")),
        1
    );
    assert_eq!(
        flagged(who_is(1, 499, "10.0.0.9:47808", "10.0.0.5:47808")),
        0
    );

    // The key reused after silence: an old Who-Is must not exempt a much later I-Am.
    let records = [
        who_is(1, 100, "10.0.0.9:47808", "10.0.0.5:47808"),
        unicast_i_am_to(2, 110, "10.0.0.5:47808", "10.0.0.9:47808", 101),
        unicast_i_am_to(3, 900, "10.0.0.5:47808", "10.0.0.9:47808", 101),
    ];
    assert_eq!(unicast_i_am(&records)[0].evidence.frames, vec![3]);
}

#[test]
fn a_forwarded_npdu_is_not_a_unicast_i_am() {
    let records = [forwarded_from(1, 10, "10.0.5.1:47808", "10.0.5.7:47808", 1)];

    assert!(unicast_i_am(&records).is_empty());
}
