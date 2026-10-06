//! Shared fixture builders for the detector tests: synthetic decode records and capture stats.
#![allow(dead_code)] // each test crate uses a different subset

use std::net::SocketAddr;
use std::time::Duration;

use baccheck_core::decode::{DecodeRecord, Envelope};
use baccheck_core::report::CaptureStats;
use bacnet_rs::object::Segmentation;

pub fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

pub fn i_am(frame_no: u64, secs: u64, src: &str, instance: u32) -> DecodeRecord {
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

pub fn who_is(frame_no: u64, secs: u64, src: &str, dst: &str) -> DecodeRecord {
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

pub fn stats(span_secs: u64, decoded: u64, undecoded: u64, non_bacnet: u64) -> CaptureStats {
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

pub fn unicast_apdu(frame_no: u64, secs: u64, src: &str, dst: &str) -> DecodeRecord {
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
pub fn who_is_burst(count: u64, src: &str) -> Vec<DecodeRecord> {
    (0..count)
        .map(|n| who_is(n + 1, n * 60 / count, src, "10.0.0.255:47808"))
        .collect()
}

/// `count` unicast messages spread over `span_secs`, frames from 10_000.
pub fn background(count: u64, span_secs: u64) -> Vec<DecodeRecord> {
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

pub fn decoded_stats(span_secs: u64, records: &[DecodeRecord]) -> CaptureStats {
    stats(span_secs, records.len() as u64, 0, 0)
}
