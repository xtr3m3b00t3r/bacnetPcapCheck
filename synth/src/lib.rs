//! Synthetic BACnet/IP captures for the public site's sample report and demos (spec #30).
//! Development only: the CLI takes this as a dev-dependency, xtask as a build tool.
//!
//! Every frame is built byte by byte (Ethernet, IPv4, UDP, BVLC, NPDU, APDU), the way the CLI
//! test fixtures are. No byte comes from a real network.

use std::net::SocketAddrV4;
use std::time::Duration;

use pcap_file::pcap::{PcapPacket, PcapWriter};

/// Capture start: Friday 4 September 2026, 09:00:00 UTC.
const START_SECS: u64 = 1_788_512_400;

/// The multi-finding capture behind the sample report and the hero recording. It holds three
/// problems: device instance 101 on two IPs, a device that answers none of its twelve
/// ReadProperty requests, and a foreign device whose BBMD NAKs every registration.
pub fn sample_capture() -> Vec<u8> {
    let mut capture = Capture::default();
    let broadcast = addr("10.0.0.255");

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
            addr("192.168.50.20"),
            addr("10.0.0.1"),
            &register_foreign_device(60),
        );
        capture.push(
            at + 1,
            addr("10.0.0.1"),
            addr("192.168.50.20"),
            &register_nak(),
        );
    }

    capture.into_pcap()
}

/// Frames in capture order, each with its offset from [`START_SECS`].
#[derive(Default)]
struct Capture {
    frames: Vec<(u64, Vec<u8>)>,
}

impl Capture {
    fn push(&mut self, at_secs: u64, src: SocketAddrV4, dst: SocketAddrV4, bvlc: &[u8]) {
        self.frames
            .push((at_secs, ethernet_ipv4_udp(src, dst, bvlc)));
    }

    fn into_pcap(mut self) -> Vec<u8> {
        self.frames.sort_by_key(|(at, _)| *at);
        let mut buf = Vec::new();
        {
            let mut writer = PcapWriter::new(&mut buf).expect("pcap header");
            for (at, frame) in &self.frames {
                let packet = PcapPacket::new(
                    Duration::from_secs(START_SECS + at),
                    frame.len() as u32,
                    frame,
                );
                writer.write_packet(&packet).expect("pcap packet");
            }
        }
        buf
    }
}

/// `ip` on the BACnet/IP port, 47808.
fn addr(ip: &str) -> SocketAddrV4 {
    SocketAddrV4::new(ip.parse().expect("IPv4 literal"), 47808)
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
    let mut npdu = vec![0x01, 0x00, 0x10, 0x00, 0xC4];
    npdu.extend_from_slice(&device_object_id(instance));
    npdu.extend_from_slice(&[0x22, 0x05, 0xC4, 0x91, 0x03, 0x22, 0x03, 0xE7]);
    bvlc(0x0B, &npdu)
}

/// A unicast ReadProperty of device `instance`'s Object_Name (property 77).
fn read_property(invoke_id: u8, instance: u32) -> Vec<u8> {
    // NPDU expecting a reply; confirmed request, max APDU 1476, ReadProperty (12).
    let mut npdu = vec![0x01, 0x04, 0x00, 0x05, invoke_id, 0x0C, 0x0C];
    npdu.extend_from_slice(&device_object_id(instance));
    npdu.extend_from_slice(&[0x19, 0x4D]);
    bvlc(0x0A, &npdu)
}

/// Register-Foreign-Device with a time-to-live of `ttl_secs`.
fn register_foreign_device(ttl_secs: u16) -> Vec<u8> {
    bvlc(0x05, &ttl_secs.to_be_bytes())
}

/// BVLC-Result 0x0030: Register-Foreign-Device NAK.
fn register_nak() -> Vec<u8> {
    bvlc(0x00, &[0x00, 0x30])
}
