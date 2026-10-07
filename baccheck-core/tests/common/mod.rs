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

/// A Forwarded-NPDU relayed by `forwarder` to the local broadcast address; `hash` stands for the
/// forwarded broadcast, so equal hashes are one broadcast seen again.
pub fn forwarded_npdu(frame_no: u64, secs: u64, forwarder: &str, hash: u64) -> DecodeRecord {
    DecodeRecord::ForwardedNpdu {
        envelope: Envelope {
            frame_no,
            timestamp: Duration::from_secs(secs),
            src: addr(forwarder),
            dst: addr("10.0.0.255:47808"),
        },
        original_source: addr("10.0.9.9:47808"),
        payload_hash: hash,
    }
}

/// A Forwarded-NPDU relayed by `forwarder` whose embedded original source is `original`.
pub fn forwarded_from(
    frame_no: u64,
    secs: u64,
    forwarder: &str,
    original: &str,
    hash: u64,
) -> DecodeRecord {
    match forwarded_npdu(frame_no, secs, forwarder, hash) {
        DecodeRecord::ForwardedNpdu {
            envelope,
            payload_hash,
            ..
        } => DecodeRecord::ForwardedNpdu {
            envelope,
            original_source: addr(original),
            payload_hash,
        },
        other => other,
    }
}

/// `count` Who-Is broadcasts from hosts on the local segment, frames 1..=count, one per second.
pub fn local_broadcasts(count: u64) -> Vec<DecodeRecord> {
    (0..count)
        .map(|n| who_is(n + 1, n, "10.0.0.5:47808", "10.0.0.255:47808"))
        .collect()
}

/// A Register-Foreign-Device request from `registrant` to the BBMD `bbmd`.
pub fn register_fd(frame_no: u64, secs: u64, registrant: &str, bbmd: &str) -> DecodeRecord {
    DecodeRecord::RegisterForeignDevice {
        envelope: Envelope {
            frame_no,
            timestamp: Duration::from_secs(secs),
            src: addr(registrant),
            dst: addr(bbmd),
        },
        ttl_seconds: 60,
    }
}

/// A BVLC-Result with `result_code` from `bbmd` back to `registrant`.
pub fn bvlc_result(
    frame_no: u64,
    secs: u64,
    bbmd: &str,
    registrant: &str,
    result_code: u16,
) -> DecodeRecord {
    DecodeRecord::BvlcResult {
        envelope: Envelope {
            frame_no,
            timestamp: Duration::from_secs(secs),
            src: addr(bbmd),
            dst: addr(registrant),
        },
        result_code,
    }
}

/// `count` Register-Foreign-Device requests from `registrant` to `bbmd`, each NAKed (0x0030) one
/// second later; request frames 1.., NAK frames 1000.., a pair every 20 s.
pub fn rejected_registrations(count: u64, registrant: &str, bbmd: &str) -> Vec<DecodeRecord> {
    (0..count)
        .flat_map(|n| {
            [
                register_fd(n + 1, n * 20, registrant, bbmd),
                bvlc_result(1000 + n, n * 20 + 1, bbmd, registrant, 0x0030),
            ]
        })
        .collect()
}

/// A segmented ConfirmedRequest segment from `src` to `dst`.
pub fn segment(
    frame_no: u64,
    secs: u64,
    src: &str,
    dst: &str,
    invoke_id: u8,
    more_follows: bool,
) -> DecodeRecord {
    apdu(
        frame_no,
        secs,
        src,
        dst,
        ApduHeader::ConfirmedRequest {
            segmented: true,
            more_follows,
            segmented_response_accepted: true,
            invoke_id,
            service_choice: 12,
        },
    )
}

pub fn abort(frame_no: u64, secs: u64, src: &str, dst: &str, invoke_id: u8) -> DecodeRecord {
    apdu(
        frame_no,
        secs,
        src,
        dst,
        ApduHeader::Abort {
            server: true,
            invoke_id,
        },
    )
}

/// `count` segmented exchanges from 10.0.0.5 to 10.0.0.9, invoke IDs 1.., 100 s apart from t=0.
/// Each opens with two more-follows segments (frames 10n+1, 10n+2, 1 s apart). The first
/// `completed` exchanges then close with a final segment (frame 10n+3); the rest go quiet.
pub fn segmented_exchanges(count: u8, completed: u8) -> Vec<DecodeRecord> {
    let mut records = Vec::new();
    for n in 0..count {
        let base = u64::from(n) * 100;
        let frame = u64::from(n) * 10;
        for (i, more) in [(0, true), (1, true), (2, false)] {
            if i == 2 && n >= completed {
                continue;
            }
            records.push(segment(
                frame + i + 1,
                base + i,
                "10.0.0.5:47808",
                "10.0.0.9:47808",
                n + 1,
                more,
            ));
        }
    }
    records
}

pub fn segment_ack(frame_no: u64, secs: u64, src: &str, dst: &str, invoke_id: u8) -> DecodeRecord {
    apdu(
        frame_no,
        secs,
        src,
        dst,
        ApduHeader::SegmentAck {
            negative: false,
            server: true,
            invoke_id,
        },
    )
}

/// A segmented ComplexAck segment from `src` to `dst`.
pub fn ack_segment(
    frame_no: u64,
    secs: u64,
    src: &str,
    dst: &str,
    invoke_id: u8,
    more_follows: bool,
) -> DecodeRecord {
    apdu(
        frame_no,
        secs,
        src,
        dst,
        ApduHeader::ComplexAck {
            segmented: true,
            more_follows,
            invoke_id,
            service_choice: 12,
        },
    )
}

/// A closing record for the capture clock: a unicast message at `secs`.
pub fn capture_ends_at(secs: u64) -> DecodeRecord {
    unicast_apdu(900, secs, "10.0.0.5:47808", "10.0.0.6:47808")
}

/// A network-layer message of `message_type` from `src` to `dst`.
pub fn network_message(
    frame_no: u64,
    secs: u64,
    src: &str,
    dst: &str,
    message_type: u8,
) -> DecodeRecord {
    DecodeRecord::NetworkMessage {
        envelope: Envelope {
            frame_no,
            timestamp: Duration::from_secs(secs),
            src: addr(src),
            dst: addr(dst),
        },
        message_type,
    }
}

/// A Reject-Message-To-Network (0x03) from `router` to `sender`.
pub fn reject_to_network(frame_no: u64, secs: u64, router: &str, sender: &str) -> DecodeRecord {
    network_message(frame_no, secs, router, sender, 0x03)
}
