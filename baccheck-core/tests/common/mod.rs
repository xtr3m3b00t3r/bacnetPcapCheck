//! Shared fixture builders for the detector tests: synthetic decode records and capture stats.
#![allow(dead_code)] // each test crate uses a different subset

use std::net::SocketAddr;
use std::time::Duration;

use baccheck_core::decode::{ApduHeader, DecodeRecord, Envelope};
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

fn apdu(frame_no: u64, secs: u64, src: &str, dst: &str, header: ApduHeader) -> DecodeRecord {
    DecodeRecord::Apdu {
        envelope: Envelope {
            frame_no,
            timestamp: Duration::from_secs(secs),
            src: addr(src),
            dst: addr(dst),
        },
        header,
    }
}

pub fn confirmed_request(
    frame_no: u64,
    secs: u64,
    src: &str,
    dst: &str,
    invoke_id: u8,
) -> DecodeRecord {
    apdu(
        frame_no,
        secs,
        src,
        dst,
        ApduHeader::ConfirmedRequest {
            segmented: false,
            more_follows: false,
            segmented_response_accepted: false,
            invoke_id,
            service_choice: 12,
        },
    )
}

pub fn simple_ack(frame_no: u64, secs: u64, src: &str, dst: &str, invoke_id: u8) -> DecodeRecord {
    apdu(
        frame_no,
        secs,
        src,
        dst,
        ApduHeader::SimpleAck {
            invoke_id,
            service_choice: 15,
        },
    )
}

pub fn reject(frame_no: u64, secs: u64, src: &str, dst: &str, invoke_id: u8) -> DecodeRecord {
    apdu(frame_no, secs, src, dst, ApduHeader::Reject { invoke_id })
}

/// `total` confirmed requests from 10.0.0.5 to 10.0.0.9, invoke IDs 1.., 2 s apart from t=0,
/// frames 1..; the first `answered` get a simple ack from the responder 1 s later (frames 1000..).
pub fn requests_to_device(total: u8, answered: u8) -> Vec<DecodeRecord> {
    let mut records = Vec::new();
    for n in 0..total {
        let secs = u64::from(n) * 2;
        records.push(confirmed_request(
            u64::from(n) + 1,
            secs,
            "10.0.0.5:47808",
            "10.0.0.9:47808",
            n + 1,
        ));
        if n < answered {
            records.push(simple_ack(
                1000 + u64::from(n),
                secs + 1,
                "10.0.0.9:47808",
                "10.0.0.5:47808",
                n + 1,
            ));
        }
    }
    records
}
