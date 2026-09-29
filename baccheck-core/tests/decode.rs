use std::net::SocketAddr;
use std::time::Duration;

use bacnet_rs::app::{Apdu, MaxApduSize, MaxSegments};
use bacnet_rs::datalink::bip::{BvlcFunction, BvlcHeader};
use bacnet_rs::object::{ObjectIdentifier, ObjectType, Segmentation};
use bacnet_rs::service::{
    ConfirmedServiceChoice, IAmRequest, UnconfirmedServiceChoice, WhoIsRequest,
};

use baccheck_core::decode::{decode_packet, ApduHeader, DecodeRecord, Envelope};
use baccheck_core::pcap::RawPacket;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A minimal, unrouted NPDU header: version 1, no destination/source/network-message
/// control bits set, i.e. "just carry an APDU, no routing".
fn plain_npdu() -> Vec<u8> {
    vec![0x01, 0x00]
}

fn bvlc_frame(function: BvlcFunction, npdu_and_beyond: &[u8]) -> Vec<u8> {
    let total_len = 4 + npdu_and_beyond.len();
    let mut frame = BvlcHeader::new(function, total_len as u16).encode();
    frame.extend_from_slice(npdu_and_beyond);
    frame
}

fn raw_packet(frame_no: u64, src: SocketAddr, dst: SocketAddr, payload: Vec<u8>) -> RawPacket {
    RawPacket {
        frame_no,
        timestamp: Duration::new(1_700_000_000, 0),
        src: Some(src),
        dst: Some(dst),
        payload,
    }
}

#[test]
fn decodes_a_broadcast_who_is_with_no_device_range() {
    let src = addr("10.0.0.2:47808");
    let dst = addr("10.0.0.255:47808");

    let who_is = WhoIsRequest::new();
    let mut who_is_bytes = Vec::new();
    who_is.encode(&mut who_is_bytes).expect("encode who-is");

    let apdu = Apdu::UnconfirmedRequest {
        service_choice: UnconfirmedServiceChoice::WhoIs,
        service_data: who_is_bytes,
    };

    let mut npdu_and_apdu = plain_npdu();
    npdu_and_apdu.extend_from_slice(&apdu.encode());

    let payload = bvlc_frame(BvlcFunction::OriginalBroadcastNpdu, &npdu_and_apdu);
    let packet = raw_packet(1, src, dst, payload);

    let record = decode_packet(&packet).expect("decodes as BACnet traffic");

    assert_eq!(
        record,
        DecodeRecord::WhoIs {
            envelope: Envelope {
                frame_no: 1,
                timestamp: packet.timestamp,
                src,
                dst,
            },
            low_limit: None,
            high_limit: None,
        }
    );
}

#[test]
fn decodes_an_i_am_with_typed_device_fields() {
    let src = addr("10.0.0.2:47808");
    let dst = addr("10.0.0.255:47808");

    let i_am = IAmRequest::new(
        ObjectIdentifier::new(ObjectType::Device, 4242),
        1476,
        Segmentation::NoSegmentation,
        260,
    );
    let mut i_am_bytes = Vec::new();
    i_am.encode(&mut i_am_bytes).expect("encode i-am");

    let apdu = Apdu::UnconfirmedRequest {
        service_choice: UnconfirmedServiceChoice::IAm,
        service_data: i_am_bytes,
    };

    let mut npdu_and_apdu = plain_npdu();
    npdu_and_apdu.extend_from_slice(&apdu.encode());

    let payload = bvlc_frame(BvlcFunction::OriginalBroadcastNpdu, &npdu_and_apdu);
    let packet = raw_packet(7, src, dst, payload);

    let record = decode_packet(&packet).expect("decodes as BACnet traffic");

    assert_eq!(
        record,
        DecodeRecord::IAm {
            envelope: Envelope {
                frame_no: 7,
                timestamp: packet.timestamp,
                src,
                dst,
            },
            device_instance: 4242,
            max_apdu_length_accepted: 1476,
            segmentation_supported: Segmentation::NoSegmentation,
            vendor_identifier: 260,
        }
    );
}

#[test]
fn decodes_another_confirmed_service_to_header_level_only() {
    let src = addr("10.0.0.5:47808");
    let dst = addr("10.0.0.10:47808");

    let apdu = Apdu::ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted: true,
        max_segments: MaxSegments::Unspecified,
        max_response_size: MaxApduSize::Up1476,
        invoke_id: 9,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: ConfirmedServiceChoice::ReadProperty,
        service_data: vec![0x0C, 0x02, 0x00, 0x00, 0x00, 0x19, 0x4B],
    };

    let mut npdu_and_apdu = plain_npdu();
    npdu_and_apdu.extend_from_slice(&apdu.encode());

    let payload = bvlc_frame(BvlcFunction::OriginalUnicastNpdu, &npdu_and_apdu);
    let packet = raw_packet(2, src, dst, payload);

    let record = decode_packet(&packet).expect("decodes as BACnet traffic");

    assert_eq!(
        record,
        DecodeRecord::Apdu {
            envelope: Envelope {
                frame_no: 2,
                timestamp: packet.timestamp,
                src,
                dst,
            },
            header: ApduHeader::ConfirmedRequest {
                segmented: false,
                more_follows: false,
                segmented_response_accepted: true,
                invoke_id: 9,
                service_choice: ConfirmedServiceChoice::ReadProperty as u8,
            },
        }
    );
}

#[test]
fn hand_decodes_bvlc_result() {
    let src = addr("10.0.0.5:47808");
    let dst = addr("10.0.0.10:47808");

    // 0x81 (BVLC type), 0x00 (function: BVLC-Result), length 0x0006, result code 0x0010
    // (unrecognized BVLC function) big-endian. Not in bacnet-rs's `BvlcFunction` at all.
    let payload = vec![0x81, 0x00, 0x00, 0x06, 0x00, 0x10];
    let packet = raw_packet(3, src, dst, payload);

    let record = decode_packet(&packet).expect("decodes as BACnet traffic");

    assert_eq!(
        record,
        DecodeRecord::BvlcResult {
            envelope: Envelope {
                frame_no: 3,
                timestamp: packet.timestamp,
                src,
                dst,
            },
            result_code: 0x0010,
        }
    );
}

#[test]
fn truncated_bvlc_result_is_undecoded_not_a_panic() {
    let src = addr("10.0.0.5:47808");
    let dst = addr("10.0.0.10:47808");

    // Header claims BVLC-Result but the 2-byte result code never arrives.
    let payload = vec![0x81, 0x00, 0x00, 0x05, 0x00];
    let packet = raw_packet(4, src, dst, payload);

    let record = decode_packet(&packet).expect("decodes as BACnet traffic");

    assert!(matches!(record, DecodeRecord::Undecoded { .. }));
}

#[test]
fn malformed_who_is_body_is_undecoded_not_a_panic() {
    let src = addr("10.0.0.2:47808");
    let dst = addr("10.0.0.255:47808");

    let apdu = Apdu::UnconfirmedRequest {
        service_choice: UnconfirmedServiceChoice::WhoIs,
        // Context tag 0 (low limit) = 10, followed by a byte that isn't a valid context
        // tag 1: WhoIsRequest::decode requires a high limit once a low limit is present.
        service_data: vec![0x09, 0x0A, 0x00],
    };

    let mut npdu_and_apdu = plain_npdu();
    npdu_and_apdu.extend_from_slice(&apdu.encode());

    let payload = bvlc_frame(BvlcFunction::OriginalBroadcastNpdu, &npdu_and_apdu);
    let packet = raw_packet(5, src, dst, payload);

    let record = decode_packet(&packet).expect("decodes as BACnet traffic");

    assert!(matches!(record, DecodeRecord::Undecoded { .. }));
}

#[test]
fn truncated_bvlc_header_is_undecoded_not_a_panic() {
    let src = addr("10.0.0.2:47808");
    let dst = addr("10.0.0.255:47808");

    // Only 2 of the 4 BVLC header bytes arrived.
    let payload = vec![0x81, 0x0B];
    let packet = raw_packet(6, src, dst, payload);

    let record = decode_packet(&packet).expect("decodes as BACnet traffic");

    assert!(matches!(record, DecodeRecord::Undecoded { .. }));
}

#[test]
fn non_bacnet_port_udp_traffic_is_not_decoded() {
    let src = addr("10.0.0.2:12345");
    let dst = addr("10.0.0.255:12345");

    let payload = vec![0x81, 0x0B, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08];
    let packet = raw_packet(8, src, dst, payload);

    assert_eq!(decode_packet(&packet), None);
}

#[test]
fn non_bvlc_payload_on_the_bacnet_port_is_not_decoded() {
    let src = addr("10.0.0.2:47808");
    let dst = addr("10.0.0.255:47808");

    // Looks nothing like a BVLC frame (wrong type byte) — some other UDP/47808 protocol.
    let payload = vec![0x00, 0x01, 0x02, 0x03];
    let packet = raw_packet(9, src, dst, payload);

    assert_eq!(decode_packet(&packet), None);
}
