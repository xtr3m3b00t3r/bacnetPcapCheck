//! Synthetic BACnet/IP captures for the public site's sample report and demos (spec #30).
//! Development only: the CLI takes this as a dev-dependency, xtask as a build tool.
//!
//! Every frame is built byte by byte (Ethernet, IPv4, UDP, BVLC, NPDU, APDU), the way the CLI
//! test fixtures are. No byte comes from a real network.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use pcap_file::pcap::{PcapPacket, PcapWriter};

/// Capture start: Friday 4 September 2026, 09:00:00 UTC.
const START_SECS: u64 = 1_788_512_400;

/// The directed broadcast of the demo segment, 10.0.0.0/24.
const BROADCAST: &str = "10.0.0.255";

/// The segment's supervisor.
const SUPERVISOR: &str = "10.0.0.1";

/// The segment's BBMD: the supervisor holds that role too.
const BBMD: &str = SUPERVISOR;

/// A second BBMD on the segment, which the duplicate-BBMD demo adds.
const SECOND_BBMD: &str = "10.0.0.2";

/// A supervisor on remote network 10.1.0.0/24, whose broadcasts BBMDs relay into the segment.
const REMOTE_SUPERVISOR: &str = "10.1.0.5";

/// A foreign device whose BBMD NAKs every registration.
const REFUSED_FOREIGN_DEVICE: &str = "192.168.50.20";

/// The BACnet/IP UDP port.
const BACNET_PORT: u16 = 47808;

/// The sample capture's file name. It shows in the report, so the site's copy and the binary's
/// must use the same one.
pub const SAMPLE_CAPTURE_NAME: &str = "sample.pcap";

/// The multi-finding capture behind the sample report and the hero recording. It holds three
/// problems: device instance 101 on two IPs, a device that answers none of its twelve
/// ReadProperty requests, and a foreign device whose BBMD NAKs every registration.
pub fn sample_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    let broadcast = addr(BROADCAST);

    capture.push(0, addr("10.0.0.5"), broadcast, &i_am(101));
    capture.push(1, addr("10.0.0.6"), broadcast, &i_am(101));
    capture.push(2, addr("10.0.0.7"), broadcast, &i_am(202));
    capture.push(3, addr("10.0.0.9"), broadcast, &i_am(303));

    for n in 0..12u8 {
        let at = 10 + u64::from(n) * 5;
        capture.push(
            at,
            addr("10.0.0.5"),
            addr("10.0.0.9"),
            &read_property(n + 1, 303),
        );
    }

    for n in 0..3 {
        let at = 20 + n * 20;
        capture.push(
            at,
            addr(REFUSED_FOREIGN_DEVICE),
            addr(BBMD),
            &register_foreign_device(60),
        );
        capture.push(
            at + 1,
            addr(BBMD),
            addr(REFUSED_FOREIGN_DEVICE),
            &register_nak(),
        );
    }

    capture.into_pcap()
}

/// Rule 1 demo: device instance 101 answers from two IPs while three other devices are unique.
/// Each device broadcasts an I-Am every 60 s, five rounds over four minutes: under the rate rules'
/// five-minute span floor, so the storm rule stays silent.
pub fn duplicate_device_id_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    let broadcast = addr(BROADCAST);
    let devices = [
        ("10.0.0.5", 101),
        ("10.0.0.6", 101),
        ("10.0.0.7", 202),
        ("10.0.0.8", 303),
        ("10.0.0.9", 404),
    ];
    for round in 0..5 {
        for (n, (ip, instance)) in (0u64..).zip(devices) {
            capture.push(round * 60 + n, addr(ip), broadcast, &i_am(instance));
        }
    }
    capture.into_pcap()
}

/// Rule 8 demo: device 1200 sends an unprompted unicast I-Am to the supervisor every 30 s, twelve
/// in all. Device 202 also answers unicast, but to a directed Who-Is, which is correct; the other
/// devices announce themselves by broadcast.
pub fn unicast_i_am_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    capture.announce_bystanders();
    for n in 0..12 {
        capture.push(
            5 + n * 30,
            addr("10.0.0.12"),
            addr(SUPERVISOR),
            &unicast_i_am(1200),
        );
    }
    capture.push(100, addr(SUPERVISOR), addr("10.0.0.7"), &directed_who_is());
    capture.push(101, addr("10.0.0.7"), addr(SUPERVISOR), &unicast_i_am(202));
    capture.into_pcap()
}

/// Rule 2 demo: a supervisor broadcasts a Who-Is once a minute for six minutes, past the
/// five-minute span floor. From 120 s to 180 s three controllers each broadcast four Who-Is a
/// second: 12/s against a limit of 10/s. Every frame is a broadcast, so broadcast saturation
/// fires as well and the share above 50% makes it Critical, as a real Who-Is storm would.
pub fn broadcast_storm_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    let broadcast = addr(BROADCAST);
    for minute in 0..=6 {
        capture.push(minute * 60, addr(SUPERVISOR), broadcast, &who_is());
    }
    for tick in 0..240u64 {
        let at = Duration::from_secs(120) + Duration::from_millis(tick * 250);
        for ip in ["10.0.0.21", "10.0.0.22", "10.0.0.23"] {
            capture.push_at(at, addr(ip), broadcast, &who_is());
        }
    }
    capture.into_pcap()
}

/// Rule 4 demo: two BBMDs, 10.0.0.1 and 10.0.0.2, both hold a BDT entry for remote network
/// 10.1.0.0/24, so each relays the remote supervisor's Who-Is into this segment: every broadcast
/// arrives twice, twelve sightings in all. Two forwarders make it High. The loop trigger cannot
/// fire: no minute holds more than four sightings, against a limit of five. The frames also span
/// under the rate rules' five-minute floor, which keeps the storm rule silent.
pub fn duplicate_bbmd_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    let broadcast = addr(BROADCAST);
    capture.announce_bystanders();
    for round in 0..6u64 {
        let at = Duration::from_secs(10 + round * 40);
        capture.push_at(at, addr(BBMD), broadcast, &forwarded_remote_who_is());
        capture.push_at(
            at + Duration::from_millis(3),
            addr(SECOND_BBMD),
            broadcast,
            &forwarded_remote_who_is(),
        );
    }
    capture.into_pcap()
}

/// Rule 5 demo: peer BBMD 10.1.0.1 relays the remote supervisor's Who-Is into this segment once a
/// minute, four times, but none of the fifty I-Ams that ten local devices broadcast (one a minute
/// each, five rounds) ever comes back forwarded: the peer's BDT is missing this segment. Low, the
/// rule's only severity. The frames span under five minutes, so the storm rule stays silent.
pub fn incomplete_bdt_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    let broadcast = addr(BROADCAST);
    for round in 0..5 {
        for n in 0..10u8 {
            let ip = Ipv4Addr::new(10, 0, 0, 11 + n);
            capture.push(
                round * 60 + u64::from(n),
                SocketAddrV4::new(ip, BACNET_PORT),
                broadcast,
                &i_am(1101 + u32::from(n)),
            );
        }
    }
    for n in 0..4 {
        capture.push(
            30 + n * 60,
            addr("10.1.0.1"),
            broadcast,
            &forwarded_remote_who_is(),
        );
    }
    capture.into_pcap()
}

/// Rule 6 demo: foreign device 192.168.50.20 tries to register with the segment's BBMD every 30 s
/// and is NAKed each time, eight in all: more than five makes it High. Foreign device
/// 192.168.60.30 registers once and is accepted, which is not a finding.
pub fn foreign_device_registration_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    capture.announce_bystanders();
    let accepted = addr("192.168.60.30");
    capture.push(5, accepted, addr(BBMD), &register_foreign_device(300));
    capture.push(6, addr(BBMD), accepted, &register_ack());
    for n in 0..8 {
        let at = 10 + n * 30;
        capture.push(
            at,
            addr(REFUSED_FOREIGN_DEVICE),
            addr(BBMD),
            &register_foreign_device(60),
        );
        capture.push(
            at + 1,
            addr(BBMD),
            addr(REFUSED_FOREIGN_DEVICE),
            &register_nak(),
        );
    }
    capture.into_pcap()
}

/// Rule 9 demo: the supervisor looks for devices on network 2001 through router 10.0.0.30 every
/// 5 s, and the router, which has lost its route there, rejects each one: twelve rejections in the
/// first minute, more than ten makes it High.
pub fn routing_rejection_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    let router = addr("10.0.0.30");
    capture.announce_bystanders();
    for n in 0..12 {
        let at = 2 + n * 5;
        capture.push(
            at,
            addr(SUPERVISOR),
            router,
            &routed_who_is(UNREACHABLE_NETWORK),
        );
        capture.push(
            at + 1,
            router,
            addr(SUPERVISOR),
            &reject_message_to_network(UNREACHABLE_NETWORK),
        );
    }
    capture.into_pcap()
}

/// Rule 3 demo: the supervisor sends twelve ReadProperty requests to device 10.0.0.9, five
/// seconds apart, and none is ever answered: 0% answered over the floor of ten makes it High.
/// Distinct invoke IDs keep the retransmission rule silent; nothing is segmented.
pub fn unresponsive_device_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    capture.announce_bystanders();
    for n in 0..12u8 {
        capture.push(
            10 + u64::from(n) * 5,
            addr(SUPERVISOR),
            addr("10.0.0.9"),
            &read_property(n + 1, 303),
        );
    }
    capture.into_pcap()
}

/// Rule 7 demo: device 10.0.0.5 opens three segmented ReadProperty exchanges toward 10.0.0.9, ten
/// seconds apart, and never sends a final segment, abort or reject. The capture runs well past the
/// 30 s abandon window after the last segment, so all three count as abandoned: at the rule's floor
/// of three for one directed pair, which makes it Medium. Fewer than ten judged exchanges keeps the
/// ratio trigger, and the unresponsive rule's floor, out of reach.
pub fn segmentation_misuse_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    capture.announce_bystanders();
    for n in 0..3u8 {
        capture.push(
            10 + u64::from(n) * 10,
            addr("10.0.0.5"),
            addr("10.0.0.9"),
            &segmented_read_property(n + 1),
        );
    }
    capture.push(100, addr("10.0.0.10"), addr(BROADCAST), &i_am(404));
    capture.into_pcap()
}

/// Rule 10 demo: the supervisor sends five ReadProperty requests to device 10.0.0.9, each
/// retransmitted twice a second apart before the device answers. That is fifteen confirmed request
/// frames, ten of them repeats: 67% against a High trigger of 50%. Each request is answered within
/// the response window, so the unresponsive rule stays silent; five requests are also under its
/// floor of ten.
pub fn confirmed_service_retransmission_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    capture.announce_bystanders();
    for n in 0..5u8 {
        let at = 10 + u64::from(n) * 10;
        let invoke_id = n + 1;
        for repeat in 0..3u64 {
            capture.push(
                at + repeat,
                addr(SUPERVISOR),
                addr("10.0.0.9"),
                &read_property(invoke_id, 303),
            );
        }
        capture.push(
            at + 3,
            addr("10.0.0.9"),
            addr(SUPERVISOR),
            &read_property_ack(invoke_id),
        );
    }
    capture.into_pcap()
}

/// Frames in capture order, each with its offset from [`START_SECS`].
#[derive(Default)]
struct Capture {
    frames: Vec<(Duration, Vec<u8>)>,
}

impl Capture {
    /// Two well-behaved devices, 202 and 303, broadcast an I-Am in the first two seconds.
    fn announce_bystanders(&mut self) {
        let broadcast = addr(BROADCAST);
        for (n, (ip, instance)) in (0u64..).zip([("10.0.0.7", 202), ("10.0.0.8", 303)]) {
            self.push(n, addr(ip), broadcast, &i_am(instance));
        }
    }

    fn push(&mut self, at_secs: u64, src: SocketAddrV4, dst: SocketAddrV4, bvlc: &[u8]) {
        self.push_at(Duration::from_secs(at_secs), src, dst, bvlc);
    }

    fn push_at(&mut self, at: Duration, src: SocketAddrV4, dst: SocketAddrV4, bvlc: &[u8]) {
        self.frames.push((at, ethernet_ipv4_udp(src, dst, bvlc)));
    }

    fn into_pcap(mut self) -> Vec<u8> {
        self.frames.sort_by_key(|(at, _)| *at);
        let mut buf = Vec::new();
        {
            let mut writer = PcapWriter::new(&mut buf).expect("pcap header");
            for (at, frame) in &self.frames {
                let packet = PcapPacket::new(
                    Duration::from_secs(START_SECS) + *at,
                    frame.len() as u32,
                    frame,
                );
                writer.write_packet(&packet).expect("pcap packet");
            }
        }
        buf
    }
}

/// `ip` on the BACnet/IP port.
fn addr(ip: &str) -> SocketAddrV4 {
    SocketAddrV4::new(ip.parse().expect("IPv4 literal"), BACNET_PORT)
}

/// An Ethernet II frame carrying `payload` in IPv4/UDP from `src` to `dst`. Checksums are zero.
pub fn ethernet_ipv4_udp(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    // Locally administered MAC addresses, then EtherType IPv4.
    let mut frame = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00];
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    frame.extend_from_slice(&src.ip().octets());
    frame.extend_from_slice(&dst.ip().octets());
    frame.extend_from_slice(&src.port().to_be_bytes());
    frame.extend_from_slice(&dst.port().to_be_bytes());
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(payload);
    frame
}

/// BVLC function BVLC-Result.
const BVLC_RESULT: u8 = 0x00;

/// BVLC function Forwarded-NPDU.
const FORWARDED_NPDU: u8 = 0x04;

/// BVLC function Register-Foreign-Device.
const REGISTER_FOREIGN_DEVICE: u8 = 0x05;

/// BVLC function Original-Unicast-NPDU.
const ORIGINAL_UNICAST: u8 = 0x0A;

/// BVLC function Original-Broadcast-NPDU.
const ORIGINAL_BROADCAST: u8 = 0x0B;

/// A BVLC frame: type 0x81, `function`, the 2-byte total length, then `body`.
fn bvlc(function: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x81, function];
    frame.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

/// The application-tagged object identifier of device `instance` (object type 8).
fn device_object_id(instance: u32) -> [u8; 4] {
    ((8 << 22) | instance).to_be_bytes()
}

/// A broadcast I-Am: max APDU 1476, no segmentation, vendor 999.
fn i_am(instance: u32) -> Vec<u8> {
    i_am_with(ORIGINAL_BROADCAST, instance)
}

/// The same I-Am sent Original-Unicast-NPDU.
fn unicast_i_am(instance: u32) -> Vec<u8> {
    i_am_with(ORIGINAL_UNICAST, instance)
}

/// An I-Am in a BVLC frame of `function`.
fn i_am_with(function: u8, instance: u32) -> Vec<u8> {
    let mut npdu = vec![0x01, 0x00, 0x10, 0x00, 0xC4];
    npdu.extend_from_slice(&device_object_id(instance));
    npdu.extend_from_slice(&[0x22, 0x05, 0xC4, 0x91, 0x03, 0x22, 0x03, 0xE7]);
    bvlc(function, &npdu)
}

/// The APDU of a Who-Is with no device range: unconfirmed request, service Who-Is (8).
const WHO_IS_APDU: [u8; 2] = [0x10, 0x08];

/// The same Who-Is behind a local NPDU with no options.
const WHO_IS_NPDU: [u8; 4] = [0x01, 0x00, WHO_IS_APDU[0], WHO_IS_APDU[1]];

/// A broadcast Who-Is with no device range: every device should answer.
fn who_is() -> Vec<u8> {
    who_is_with(ORIGINAL_BROADCAST)
}

/// The same Who-Is sent Original-Unicast-NPDU: a directed Who-Is.
fn directed_who_is() -> Vec<u8> {
    who_is_with(ORIGINAL_UNICAST)
}

/// A Who-Is with no device range in a BVLC frame of `function`.
fn who_is_with(function: u8) -> Vec<u8> {
    bvlc(function, &WHO_IS_NPDU)
}

/// The remote BACnet network the routing demo's router can no longer reach.
const UNREACHABLE_NETWORK: u16 = 2001;

/// A Who-Is with no device range, sent unicast to a router for broadcast on network `dnet`.
fn routed_who_is(dnet: u16) -> Vec<u8> {
    // NPDU with a destination: network, zero-length address (broadcast there), hop count 255.
    let mut npdu = vec![0x01, 0x20];
    npdu.extend_from_slice(&dnet.to_be_bytes());
    npdu.extend_from_slice(&[0x00, 0xFF]);
    npdu.extend_from_slice(&WHO_IS_APDU);
    bvlc(ORIGINAL_UNICAST, &npdu)
}

/// Reject-Message-To-Network (0x03) for network `dnet`, reason 1: no route to it.
fn reject_message_to_network(dnet: u16) -> Vec<u8> {
    // NPDU carrying a network-layer message, then message type, reason, network.
    let mut npdu = vec![0x01, 0x80, 0x03, 0x01];
    npdu.extend_from_slice(&dnet.to_be_bytes());
    bvlc(ORIGINAL_UNICAST, &npdu)
}

/// A Forwarded-NPDU relaying the remote supervisor's broadcast Who-Is.
fn forwarded_remote_who_is() -> Vec<u8> {
    let original_source = addr(REMOTE_SUPERVISOR);
    let mut body = original_source.ip().octets().to_vec();
    body.extend_from_slice(&original_source.port().to_be_bytes());
    body.extend_from_slice(&WHO_IS_NPDU);
    bvlc(FORWARDED_NPDU, &body)
}

// Wire format for the APDU helpers below, which build frames byte by byte. An NPDU is
// `version (0x01)`, control, then the APDU. The APDU starts with a nibble for the PDU type
// (0 ConfirmedRequest, 1 UnconfirmedRequest, 2 SimpleAck) and, for requests, control flags:
// segmented 0x08, more-follows 0x04, segmented-response-accepted 0x02. `bacnet-rs` is the
// authority (`src/app/mod.rs`, `src/network/mod.rs`), not this comment.

/// A unicast ReadProperty of device `instance`'s Object_Name (property 77).
fn read_property(invoke_id: u8, instance: u32) -> Vec<u8> {
    // NPDU expecting a reply; confirmed request, max APDU 1476, ReadProperty (12).
    let mut npdu = vec![0x01, 0x04, 0x00, 0x05, invoke_id, 0x0C, 0x0C];
    npdu.extend_from_slice(&device_object_id(instance));
    npdu.extend_from_slice(&[0x19, 0x4D]);
    bvlc(ORIGINAL_UNICAST, &npdu)
}

/// A SimpleAck to a ReadProperty with `invoke_id`.
fn read_property_ack(invoke_id: u8) -> Vec<u8> {
    // NPDU with no options; SimpleAck (2), invoke ID, ReadProperty (12).
    bvlc(ORIGINAL_UNICAST, &[0x01, 0x00, 0x20, invoke_id, 0x0C])
}

/// An opening segment of a segmented ReadProperty of device 303: more-follows set, sequence 0.
fn segmented_read_property(invoke_id: u8) -> Vec<u8> {
    // NPDU expecting a reply: confirmed request, segmented and more-follows, max APDU 1476,
    // invoke ID, sequence number, window size, ReadProperty (12).
    bvlc(
        ORIGINAL_UNICAST,
        &[0x01, 0x04, 0x0C, 0x05, invoke_id, 0x00, 0x01, 0x0C],
    )
}

/// Register-Foreign-Device with a time-to-live of `ttl_secs`.
fn register_foreign_device(ttl_secs: u16) -> Vec<u8> {
    bvlc(REGISTER_FOREIGN_DEVICE, &ttl_secs.to_be_bytes())
}

/// BVLC-Result 0x0000: Successful completion.
fn register_ack() -> Vec<u8> {
    bvlc(BVLC_RESULT, &[0x00, 0x00])
}

/// BVLC-Result 0x0030: Register-Foreign-Device NAK.
fn register_nak() -> Vec<u8> {
    bvlc(BVLC_RESULT, &[0x00, 0x30])
}
