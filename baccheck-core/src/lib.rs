pub mod decode;
pub mod detect;
pub mod pcap;
pub mod report;

use std::path::Path;

use decode::{decode_packet, DecodeRecord};
use pcap::{read_capture, PcapError};
use report::{CaptureStats, Report};

/// Runs the whole pipeline on one capture: read, decode, detect, aggregate.
///
/// Fails only when the capture cannot be read. A frame that cannot be decoded is counted in the
/// report's stats, never an error.
pub fn analyse_capture(path: &Path) -> Result<Report, PcapError> {
    let mut stats = CaptureStats {
        capture_name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        ..CaptureStats::default()
    };
    let mut records: Vec<DecodeRecord> = Vec::new();

    for packet in read_capture(path)? {
        let packet = packet?;
        stats.total_frames += 1;
        stats.first_timestamp = Some(match stats.first_timestamp {
            Some(first) => first.min(packet.timestamp),
            None => packet.timestamp,
        });
        stats.last_timestamp = Some(match stats.last_timestamp {
            Some(last) => last.max(packet.timestamp),
            None => packet.timestamp,
        });
        match decode_packet(&packet) {
            None => stats.non_bacnet_frames += 1,
            Some(DecodeRecord::Undecoded { .. }) => stats.undecoded_frames += 1,
            Some(record) => {
                stats.decoded_frames += 1;
                records.push(record);
            }
        }
    }

    let findings = detect::detect_all(&records, &stats);
    Ok(Report::build(stats, findings))
}
