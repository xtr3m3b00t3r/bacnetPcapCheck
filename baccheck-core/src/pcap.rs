//! Seam 1: turning capture bytes (pcap or pcapng) into a chronological stream of [`RawPacket`]s.
//!
//! This seam is deliberately dumb and total — it classifies nothing about BACnet, drops nothing,
//! and every frame in the capture surfaces as exactly one `RawPacket`. Frames it can't resolve to
//! a UDP datagram (wrong link layer, non-IPv4, non-UDP) still come out, just with `src`/`dst` unset
//! and `payload` holding the raw link-layer frame. Classifying BACnet vs. non-BACnet traffic is the
//! decoding seam's job, not this one's.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};
use pcap_file::DataLink;
use pcap_file::PcapError as LibPcapError;

const PCAP_MAGICS: [[u8; 4]; 4] = [
    [0xa1, 0xb2, 0xc3, 0xd4],
    [0xd4, 0xc3, 0xb2, 0xa1],
    [0xa1, 0xb2, 0x3c, 0x4d],
    [0x4d, 0x3c, 0xb2, 0xa1],
];
const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IPV4_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const IPPROTO_UDP: u8 = 17;

/// One frame from a capture, in the order it appears.
///
/// `src`/`dst` are set only when the frame resolves to an IPv4/UDP datagram; otherwise `payload`
/// is the raw link-layer frame and both are `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacket {
    pub frame_no: u64,
    pub timestamp: Duration,
    pub src: Option<SocketAddr>,
    pub dst: Option<SocketAddr>,
    pub payload: Vec<u8>,
}

/// Why a capture couldn't be read.
#[derive(Debug)]
pub enum PcapError {
    /// The file's header doesn't match any known pcap or pcapng magic number.
    UnsupportedFormat,
    /// The file matched a known format but its contents don't parse.
    Corrupt(String),
    /// The file couldn't be opened or read.
    Io(std::io::Error),
}

impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcapError::UnsupportedFormat => write!(f, "not a recognised pcap or pcapng file"),
            PcapError::Corrupt(msg) => write!(f, "capture is corrupt: {msg}"),
            PcapError::Io(e) => write!(f, "could not read capture: {e}"),
        }
    }
}

impl std::error::Error for PcapError {}

impl From<std::io::Error> for PcapError {
    fn from(e: std::io::Error) -> Self {
        PcapError::Io(e)
    }
}

fn map_lib_error(e: LibPcapError) -> PcapError {
    match e {
        // pcap-file surfaces a capture that ends mid-structure as a bare `UnexpectedEof` I/O
        // error (not its own `IncompleteBuffer`) when reading from a `File` — that's truncation,
        // not a real I/O failure, so it's corruption from this seam's point of view.
        LibPcapError::IoError(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => {
            PcapError::Corrupt("capture ends abruptly (truncated)".into())
        }
        LibPcapError::IoError(io) => PcapError::Io(io),
        other => PcapError::Corrupt(other.to_string()),
    }
}

/// Opens `path` and returns a chronological iterator over its packets.
///
/// Auto-detects `.pcap` vs `.pcapng` from the file's own magic number (not its extension).
pub fn read_capture(path: &Path) -> Result<CaptureIter, PcapError> {
    let mut file = File::open(path)?;

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => {
            PcapError::Corrupt("file shorter than a format header".into())
        }
        _ => PcapError::Io(e),
    })?;
    file.seek(SeekFrom::Start(0))?;

    if PCAP_MAGICS.contains(&magic) {
        let reader = PcapReader::new(file).map_err(map_lib_error)?;
        let datalink = reader.header().datalink;
        Ok(CaptureIter::Pcap {
            reader,
            datalink,
            frame_no: 0,
        })
    } else if magic == PCAPNG_MAGIC {
        let reader = PcapNgReader::new(file).map_err(map_lib_error)?;
        Ok(CaptureIter::PcapNg {
            reader,
            frame_no: 0,
        })
    } else {
        Err(PcapError::UnsupportedFormat)
    }
}

/// Iterator returned by [`read_capture`].
pub enum CaptureIter {
    Pcap {
        reader: PcapReader<File>,
        datalink: DataLink,
        frame_no: u64,
    },
    PcapNg {
        reader: PcapNgReader<File>,
        frame_no: u64,
    },
}

impl Iterator for CaptureIter {
    type Item = Result<RawPacket, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            CaptureIter::Pcap {
                reader,
                datalink,
                frame_no,
            } => {
                let packet = match reader.next_packet()? {
                    Ok(p) => p,
                    Err(e) => return Some(Err(map_lib_error(e))),
                };
                *frame_no += 1;
                let timestamp = packet.timestamp;
                let data = packet.data.into_owned();
                Some(Ok(build_raw_packet(*frame_no, timestamp, *datalink, data)))
            }
            CaptureIter::PcapNg { reader, frame_no } => loop {
                let block = match reader.next_block()? {
                    Ok(b) => b,
                    Err(e) => return Some(Err(map_lib_error(e))),
                };

                let Block::EnhancedPacket(epb) = block else {
                    continue;
                };

                *frame_no += 1;
                let interface_id = epb.interface_id;
                let timestamp = epb.timestamp;
                let data = epb.data.into_owned();
                let datalink = reader
                    .interfaces()
                    .get(interface_id as usize)
                    .map(|i| i.linktype)
                    .unwrap_or(DataLink::NULL);

                return Some(Ok(build_raw_packet(*frame_no, timestamp, datalink, data)));
            },
        }
    }
}

fn build_raw_packet(
    frame_no: u64,
    timestamp: Duration,
    datalink: DataLink,
    frame: Vec<u8>,
) -> RawPacket {
    let resolved = match datalink {
        DataLink::ETHERNET => extract_ethernet_ipv4_udp(&frame),
        DataLink::RAW => extract_ipv4_udp(&frame),
        _ => None,
    };

    match resolved {
        Some((src, dst, payload)) => RawPacket {
            frame_no,
            timestamp,
            src: Some(src),
            dst: Some(dst),
            payload,
        },
        None => RawPacket {
            frame_no,
            timestamp,
            src: None,
            dst: None,
            payload: frame,
        },
    }
}

fn extract_ethernet_ipv4_udp(frame: &[u8]) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    extract_ipv4_udp(&frame[ETHERNET_HEADER_LEN..])
}

fn extract_ipv4_udp(ip_packet: &[u8]) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
    if ip_packet.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }

    let version = ip_packet[0] >> 4;
    if version != 4 {
        return None;
    }

    let header_len = (ip_packet[0] & 0x0f) as usize * 4;
    if header_len < IPV4_MIN_HEADER_LEN || ip_packet.len() < header_len {
        return None;
    }

    let protocol = ip_packet[9];
    if protocol != IPPROTO_UDP {
        return None;
    }

    let src_ip = Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
    let dst_ip = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

    let udp = &ip_packet[header_len..];
    if udp.len() < UDP_HEADER_LEN {
        return None;
    }

    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let payload = udp[UDP_HEADER_LEN..].to_vec();

    Some((
        SocketAddr::new(IpAddr::V4(src_ip), src_port),
        SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
        payload,
    ))
}
