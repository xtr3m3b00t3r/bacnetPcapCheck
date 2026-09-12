use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;

use pcap_file::pcap::{PcapPacket, PcapWriter};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;

use baccheck_core::pcap::read_capture;

/// Builds a 14-byte Ethernet header (dst mac, src mac, ethertype) followed by an IPv4/UDP
/// datagram carrying `payload`. Checksums are left zero — this seam doesn't validate them.
fn ethernet_ipv4_udp_frame(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (src, dst) else {
        panic!("test helper only supports IPv4");
    };

    let mut frame = Vec::new();

    // Ethernet header: arbitrary locally-administered MACs, IPv4 ethertype.
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // dst mac
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src mac
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype: IPv4

    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    // IPv4 header, no options.
    frame.push(0x45); // version 4, IHL 5 (20 bytes)
    frame.push(0x00); // DSCP/ECN
    frame.extend_from_slice(&(total_len as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // identification
    frame.extend_from_slice(&0u16.to_be_bytes()); // flags/fragment offset
    frame.push(64); // TTL
    frame.push(17); // protocol: UDP
    frame.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unvalidated)
    frame.extend_from_slice(&src.ip().octets());
    frame.extend_from_slice(&dst.ip().octets());

    // UDP header.
    frame.extend_from_slice(&src.port().to_be_bytes());
    frame.extend_from_slice(&dst.port().to_be_bytes());
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // checksum (unvalidated)

    frame.extend_from_slice(payload);
    frame
}

fn write_pcap(frames: &[(Duration, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut writer = PcapWriter::new(&mut buf).expect("pcap header write");
        for (timestamp, data) in frames {
            let packet = PcapPacket::new(*timestamp, data.len() as u32, data);
            writer.write_packet(&packet).expect("pcap packet write");
        }
    }
    buf
}

fn write_pcapng(frames: &[(Duration, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut writer = PcapNgWriter::new(&mut buf).expect("pcapng section header write");
        let interface = InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: 0xFFFF,
            options: vec![],
        };
        writer
            .write_pcapng_block(interface)
            .expect("pcapng interface description write");

        for (timestamp, data) in frames {
            let packet = EnhancedPacketBlock {
                interface_id: 0,
                timestamp: *timestamp,
                original_len: data.len() as u32,
                data: std::borrow::Cow::Borrowed(data),
                options: vec![],
            };
            writer
                .write_pcapng_block(packet)
                .expect("pcapng packet write");
        }
    }
    buf
}

fn temp_capture_file(bytes: &[u8], suffix: &str) -> tempfile::TempPath {
    let mut file = tempfile::Builder::new()
        .suffix(suffix)
        .tempfile()
        .expect("create temp capture file");
    file.write_all(bytes).expect("write temp capture file");
    file.into_temp_path()
}

#[test]
fn reads_udp_frames_from_a_valid_pcap_in_order() {
    let a_src: SocketAddr = "10.0.0.1:47808".parse().unwrap();
    let a_dst: SocketAddr = "10.0.0.255:47808".parse().unwrap();
    let b_src: SocketAddr = "10.0.0.2:47808".parse().unwrap();
    let b_dst: SocketAddr = "10.0.0.1:47808".parse().unwrap();

    let frame_a = ethernet_ipv4_udp_frame(a_src, a_dst, b"who-is");
    let frame_b = ethernet_ipv4_udp_frame(b_src, b_dst, b"i-am");

    let bytes = write_pcap(&[
        (Duration::new(1_700_000_000, 0), frame_a),
        (Duration::new(1_700_000_001, 500_000_000), frame_b),
    ]);
    let path = temp_capture_file(&bytes, ".pcap");

    let packets: Vec<_> = read_capture(path.as_ref())
        .expect("read_capture should accept a valid pcap")
        .collect::<Result<_, _>>()
        .expect("no packet should error");

    assert_eq!(packets.len(), 2);

    assert_eq!(packets[0].frame_no, 1);
    assert_eq!(packets[0].timestamp, Duration::new(1_700_000_000, 0));
    assert_eq!(packets[0].src, Some(a_src));
    assert_eq!(packets[0].dst, Some(a_dst));
    assert_eq!(packets[0].payload, b"who-is");

    assert_eq!(packets[1].frame_no, 2);
    assert_eq!(
        packets[1].timestamp,
        Duration::new(1_700_000_001, 500_000_000)
    );
    assert_eq!(packets[1].src, Some(b_src));
    assert_eq!(packets[1].dst, Some(b_dst));
    assert_eq!(packets[1].payload, b"i-am");
}

#[test]
fn a_non_udp_frame_still_yields_a_packet_with_no_addresses() {
    // Ethertype 0x0806 is ARP, not IPv4 — this seam doesn't understand it, so the whole frame
    // becomes the payload verbatim rather than being dropped or misparsed.
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xff; 6]); // broadcast dst mac
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src mac
    frame.extend_from_slice(&0x0806u16.to_be_bytes()); // ethertype: ARP
    frame.extend_from_slice(b"not-ip-payload");

    let bytes = write_pcap(&[(Duration::new(1_700_000_000, 0), frame.clone())]);
    let path = temp_capture_file(&bytes, ".pcap");

    let packets: Vec<_> = read_capture(path.as_ref())
        .expect("read_capture should accept a valid pcap")
        .collect::<Result<_, _>>()
        .expect("no packet should error");

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].frame_no, 1);
    assert_eq!(packets[0].src, None);
    assert_eq!(packets[0].dst, None);
    assert_eq!(packets[0].payload, frame);
}

#[test]
fn reads_the_same_udp_frames_from_a_valid_pcapng() {
    let src: SocketAddr = "10.0.0.1:47808".parse().unwrap();
    let dst: SocketAddr = "10.0.0.255:47808".parse().unwrap();
    let frame = ethernet_ipv4_udp_frame(src, dst, b"who-is");

    let bytes = write_pcapng(&[(Duration::new(1_700_000_000, 0), frame)]);
    let path = temp_capture_file(&bytes, ".pcapng");

    let packets: Vec<_> = read_capture(path.as_ref())
        .expect("read_capture should accept a valid pcapng")
        .collect::<Result<_, _>>()
        .expect("no packet should error");

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].frame_no, 1);
    assert_eq!(packets[0].timestamp, Duration::new(1_700_000_000, 0));
    assert_eq!(packets[0].src, Some(src));
    assert_eq!(packets[0].dst, Some(dst));
    assert_eq!(packets[0].payload, b"who-is");
}

#[test]
fn an_empty_but_well_formed_capture_yields_no_packets_and_no_error() {
    let bytes = write_pcap(&[]);
    let path = temp_capture_file(&bytes, ".pcap");

    let packets: Vec<_> = read_capture(path.as_ref())
        .expect("an empty capture is still a valid capture")
        .collect::<Result<_, _>>()
        .expect("no packet should error");

    assert!(packets.is_empty());
}

#[test]
fn an_unrecognised_file_header_is_reported_as_unsupported_format() {
    let bytes = b"not a capture file at all, just plain bytes".to_vec();
    let path = temp_capture_file(&bytes, ".pcap");

    match read_capture(path.as_ref()) {
        Err(baccheck_core::pcap::PcapError::UnsupportedFormat) => {}
        Ok(_) => panic!("expected UnsupportedFormat, got Ok"),
        Err(e) => panic!("expected UnsupportedFormat, got {e:?}"),
    }
}

#[test]
fn a_truncated_pcap_header_is_reported_as_corrupt_not_a_panic() {
    // Valid pcap magic number, but far too short to hold the rest of the global header.
    let bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00];
    let path = temp_capture_file(&bytes, ".pcap");

    match read_capture(path.as_ref()) {
        Err(baccheck_core::pcap::PcapError::Corrupt(_)) => {}
        Ok(_) => panic!("expected Corrupt, got Ok"),
        Err(e) => panic!("expected Corrupt, got {e:?}"),
    }
}

#[test]
fn a_pcap_with_a_truncated_packet_body_errors_from_the_iterator_not_a_panic() {
    let src: SocketAddr = "10.0.0.1:47808".parse().unwrap();
    let dst: SocketAddr = "10.0.0.255:47808".parse().unwrap();
    let frame = ethernet_ipv4_udp_frame(src, dst, b"who-is");

    let mut bytes = write_pcap(&[(Duration::new(1_700_000_000, 0), frame)]);
    bytes.truncate(bytes.len() - 4); // chop the end off the one packet's data
    let path = temp_capture_file(&bytes, ".pcap");

    let mut iter = read_capture(path.as_ref()).expect("global header is still intact");
    match iter.next() {
        Some(Err(baccheck_core::pcap::PcapError::Corrupt(_))) => {}
        other => panic!("expected a Corrupt error from the iterator, got {other:?}"),
    }
}
