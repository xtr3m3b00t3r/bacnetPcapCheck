//! Seam 2: turning the pcap seam's [`RawPacket`](crate::pcap::RawPacket) stream into typed BACnet/IP
//! records (envelope + typed Who-Is/I-Am service bodies, `Undecoded` for everything else).
//!
//! Contract (one test per line, in `tests/decode.rs`):
//! - Envelope (frame number, timestamp, src/dst IP:port) is carried on every decode record.
//! - Who-Is and I-Am decode to typed service bodies.
//! - Other BACnet-shaped traffic decodes to header level: APDU control bits/invoke ID/service
//!   choice, or NPDU network-message type for network-layer messages.
//! - BVLC-Result (function code 0x00) is hand-decoded; bacnet-rs doesn't implement it.
//! - Malformed, truncated, or unrecognised BACnet payloads produce `Undecoded` with a reason,
//!   never a panic.
//! - Non-BACnet traffic (wrong port, non-BVLC payload) decodes to `None` — skipped from the
//!   decode stream, counted separately by the caller.
//!
//! Scope note: BVLC functions other than Original-Unicast-NPDU, Original-Broadcast-NPDU, and
//! BVLC-Result (e.g. Forwarded-NPDU, foreign-device/BDT management) become `Undecoded` for now.
//! They matter to the duplicate-BBMD/forwarding-loop detector, a separate ticket that can extend
//! this seam when it needs them.

use std::net::SocketAddr;
use std::time::Duration;

use bacnet_rs::app::Apdu;
use bacnet_rs::datalink::bip::{BvlcFunction, BvlcHeader};
use bacnet_rs::network::{NetworkLayerMessage, Npdu};
use bacnet_rs::object::Segmentation;
use bacnet_rs::service::{IAmRequest, UnconfirmedServiceChoice, WhoIsRequest};

use crate::pcap::RawPacket;

/// The default BACnet/IP UDP port (47808 / 0xBAC0).
pub const BACNET_IP_PORT: u16 = 47808;

/// Frame identity carried on every decode record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub frame_no: u64,
    pub timestamp: Duration,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// APDU header fields, uniform across bacnet-rs's per-variant [`Apdu`] shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApduHeader {
    ConfirmedRequest {
        segmented: bool,
        more_follows: bool,
        segmented_response_accepted: bool,
        invoke_id: u8,
        service_choice: u8,
    },
    UnconfirmedRequest {
        service_choice: u8,
    },
    SimpleAck {
        invoke_id: u8,
        service_choice: u8,
    },
    ComplexAck {
        segmented: bool,
        more_follows: bool,
        invoke_id: u8,
        service_choice: u8,
    },
    SegmentAck {
        negative: bool,
        server: bool,
        invoke_id: u8,
    },
    Error {
        invoke_id: u8,
        service_choice: u8,
    },
    Reject {
        invoke_id: u8,
    },
    Abort {
        server: bool,
        invoke_id: u8,
    },
}

/// One decoded BACnet/IP record, or the reason it couldn't be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeRecord {
    WhoIs {
        envelope: Envelope,
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    },
    IAm {
        envelope: Envelope,
        device_instance: u32,
        max_apdu_length_accepted: u32,
        segmentation_supported: Segmentation,
        vendor_identifier: u16,
    },
    BvlcResult {
        envelope: Envelope,
        result_code: u16,
    },
    NetworkMessage {
        envelope: Envelope,
        message_type: u8,
    },
    Apdu {
        envelope: Envelope,
        header: ApduHeader,
    },
    Undecoded {
        envelope: Envelope,
        reason: String,
    },
}

/// Decodes one [`RawPacket`].
///
/// Returns `None` when the packet isn't BACnet/IP traffic: wrong port, or a payload that isn't
/// shaped like a BVLC frame. Non-`None` results always carry an [`Envelope`], even when decoding
/// past the BVLC header fails.
pub fn decode_packet(packet: &RawPacket) -> Option<DecodeRecord> {
    let (src, dst) = match (packet.src, packet.dst) {
        (Some(src), Some(dst)) => (src, dst),
        _ => return None,
    };
    if src.port() != BACNET_IP_PORT && dst.port() != BACNET_IP_PORT {
        return None;
    }
    if packet.payload.first() != Some(&0x81) {
        return None;
    }

    let envelope = Envelope {
        frame_no: packet.frame_no,
        timestamp: packet.timestamp,
        src,
        dst,
    };

    // BVLC-Result (function 0x00) isn't in bacnet-rs's `BvlcFunction`, so it must be hand-decoded
    // before calling `BvlcHeader::decode`, which would otherwise reject it as an unknown function.
    if packet.payload.get(1) == Some(&0x00) {
        return Some(decode_bvlc_result(envelope, &packet.payload));
    }

    let header = match BvlcHeader::decode(&packet.payload) {
        Ok(header) => header,
        Err(e) => {
            return Some(DecodeRecord::Undecoded {
                envelope,
                reason: format!("BVLC header: {e}"),
            })
        }
    };

    match header.function {
        BvlcFunction::OriginalUnicastNpdu | BvlcFunction::OriginalBroadcastNpdu => {
            Some(decode_npdu(envelope, &packet.payload[4..]))
        }
        other => Some(DecodeRecord::Undecoded {
            envelope,
            reason: format!("BVLC function {other:?} not decoded by this seam"),
        }),
    }
}

/// Hand-decodes BVLC-Result: 4-byte BVLC header (type 0x81, function 0x00, 2-byte length)
/// followed by a 2-byte result code. bacnet-rs has no support for this function code at all.
fn decode_bvlc_result(envelope: Envelope, payload: &[u8]) -> DecodeRecord {
    match payload.get(4..6) {
        Some(bytes) => DecodeRecord::BvlcResult {
            envelope,
            result_code: u16::from_be_bytes([bytes[0], bytes[1]]),
        },
        None => DecodeRecord::Undecoded {
            envelope,
            reason: "BVLC-Result: truncated before result code".to_string(),
        },
    }
}

fn decode_npdu(envelope: Envelope, npdu_bytes: &[u8]) -> DecodeRecord {
    let (npdu, consumed) = match Npdu::decode(npdu_bytes) {
        Ok(v) => v,
        Err(e) => {
            return DecodeRecord::Undecoded {
                envelope,
                reason: format!("NPDU: {e}"),
            }
        }
    };

    let rest = &npdu_bytes[consumed..];

    if npdu.is_network_message() {
        match NetworkLayerMessage::decode(rest) {
            Ok(msg) => DecodeRecord::NetworkMessage {
                envelope,
                message_type: msg.message_type as u8,
            },
            Err(e) => DecodeRecord::Undecoded {
                envelope,
                reason: format!("network-layer message: {e}"),
            },
        }
    } else {
        match Apdu::decode(rest) {
            Ok(apdu) => decode_apdu(envelope, apdu),
            Err(e) => DecodeRecord::Undecoded {
                envelope,
                reason: format!("APDU: {e}"),
            },
        }
    }
}

fn decode_apdu(envelope: Envelope, apdu: Apdu) -> DecodeRecord {
    match apdu {
        Apdu::UnconfirmedRequest {
            service_choice,
            service_data,
        } => decode_unconfirmed_service(envelope, service_choice, &service_data),

        Apdu::ConfirmedRequest {
            segmented,
            more_follows,
            segmented_response_accepted,
            invoke_id,
            service_choice,
            ..
        } => DecodeRecord::Apdu {
            envelope,
            header: ApduHeader::ConfirmedRequest {
                segmented,
                more_follows,
                segmented_response_accepted,
                invoke_id,
                service_choice: service_choice as u8,
            },
        },

        Apdu::SimpleAck {
            invoke_id,
            service_choice,
        } => DecodeRecord::Apdu {
            envelope,
            header: ApduHeader::SimpleAck {
                invoke_id,
                service_choice,
            },
        },

        Apdu::ComplexAck {
            segmented,
            more_follows,
            invoke_id,
            service_choice,
            ..
        } => DecodeRecord::Apdu {
            envelope,
            header: ApduHeader::ComplexAck {
                segmented,
                more_follows,
                invoke_id,
                service_choice: service_choice as u8,
            },
        },

        Apdu::SegmentAck {
            negative,
            server,
            invoke_id,
            ..
        } => DecodeRecord::Apdu {
            envelope,
            header: ApduHeader::SegmentAck {
                negative,
                server,
                invoke_id,
            },
        },

        Apdu::Error {
            invoke_id,
            service_choice,
            ..
        } => DecodeRecord::Apdu {
            envelope,
            header: ApduHeader::Error {
                invoke_id,
                service_choice: service_choice as u8,
            },
        },

        Apdu::Reject { invoke_id, .. } => DecodeRecord::Apdu {
            envelope,
            header: ApduHeader::Reject { invoke_id },
        },

        Apdu::Abort {
            server, invoke_id, ..
        } => DecodeRecord::Apdu {
            envelope,
            header: ApduHeader::Abort { server, invoke_id },
        },
    }
}

fn decode_unconfirmed_service(
    envelope: Envelope,
    service_choice: UnconfirmedServiceChoice,
    service_data: &[u8],
) -> DecodeRecord {
    match service_choice {
        UnconfirmedServiceChoice::WhoIs => match WhoIsRequest::decode(service_data) {
            Ok(who_is) => DecodeRecord::WhoIs {
                envelope,
                low_limit: who_is.device_instance_range_low_limit,
                high_limit: who_is.device_instance_range_high_limit,
            },
            Err(e) => DecodeRecord::Undecoded {
                envelope,
                reason: format!("Who-Is body: {e}"),
            },
        },
        UnconfirmedServiceChoice::IAm => match IAmRequest::decode(service_data) {
            Ok(i_am) => DecodeRecord::IAm {
                envelope,
                device_instance: i_am.device_identifier.instance,
                max_apdu_length_accepted: i_am.max_apdu_length_accepted,
                segmentation_supported: i_am.segmentation_supported,
                vendor_identifier: i_am.vendor_identifier,
            },
            Err(e) => DecodeRecord::Undecoded {
                envelope,
                reason: format!("I-Am body: {e}"),
            },
        },
        other => DecodeRecord::Apdu {
            envelope,
            header: ApduHeader::UnconfirmedRequest {
                service_choice: other as u8,
            },
        },
    }
}
