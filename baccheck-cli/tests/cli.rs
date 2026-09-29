use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use bacnet_rs::app::Apdu;
use bacnet_rs::datalink::bip::{BvlcFunction, BvlcHeader};
use bacnet_rs::object::{ObjectIdentifier, ObjectType, Segmentation};
use bacnet_rs::service::{IAmRequest, UnconfirmedServiceChoice};
use pcap_file::pcap::{PcapPacket, PcapWriter};

fn baccheck(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_baccheck"))
        .args(args)
        .output()
        .expect("run baccheck")
}

fn i_am_payload(instance: u32) -> Vec<u8> {
    let i_am = IAmRequest::new(
        ObjectIdentifier::new(ObjectType::Device, instance),
        1476,
        Segmentation::NoSegmentation,
        260,
    );
    let mut body = Vec::new();
    i_am.encode(&mut body).expect("encode i-am");
    let apdu = Apdu::UnconfirmedRequest {
        service_choice: UnconfirmedServiceChoice::IAm,
        service_data: body,
    };
    let mut npdu_and_apdu = vec![0x01, 0x00];
    npdu_and_apdu.extend_from_slice(&apdu.encode());
    let mut frame = BvlcHeader::new(
        BvlcFunction::OriginalBroadcastNpdu,
        4 + npdu_and_apdu.len() as u16,
    )
    .encode();
    frame.extend_from_slice(&npdu_and_apdu);
    frame
}

fn ethernet_ipv4_udp_frame(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (src, dst) else {
        panic!("IPv4 only");
    };
    let udp_len = 8 + payload.len();
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

/// Writes a pcap holding one I-Am per `(source, device instance)` pair.
fn write_capture(path: &Path, i_ams: &[(&str, u32)]) {
    let mut buf = Vec::new();
    {
        let mut writer = PcapWriter::new(&mut buf).expect("pcap header");
        for (n, (src, instance)) in i_ams.iter().enumerate() {
            let frame = ethernet_ipv4_udp_frame(
                src.parse().unwrap(),
                "10.0.0.255:47808".parse().unwrap(),
                &i_am_payload(*instance),
            );
            let packet = PcapPacket::new(
                Duration::from_secs(1_700_000_000 + n as u64),
                frame.len() as u32,
                &frame,
            );
            writer.write_packet(&packet).expect("pcap packet");
        }
    }
    std::fs::write(path, buf).expect("write capture");
}

fn duplicate_id_capture(dir: &Path) -> PathBuf {
    let path = dir.join("dup.pcap");
    write_capture(
        &path,
        &[
            ("10.0.0.5:47808", 101),
            ("10.0.0.6:47808", 101),
            ("10.0.0.7:47808", 202),
        ],
    );
    path
}

fn clean_capture(dir: &Path) -> PathBuf {
    let path = dir.join("clean.pcap");
    write_capture(&path, &[("10.0.0.5:47808", 101), ("10.0.0.7:47808", 202)]);
    path
}

#[test]
fn findings_present_exits_1_and_writes_default_report_next_to_capture() {
    let dir = tempfile::tempdir().unwrap();
    let capture = duplicate_id_capture(dir.path());

    let out = baccheck(&[capture.as_os_str()]);

    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let report = std::fs::read_to_string(dir.path().join("dup.baccheck.html")).expect("report");
    assert!(report.contains("Duplicate device instance number"));
    assert!(report.contains("cds--tag--magenta"), "High severity tag");
    assert!(report.contains("dup.pcap"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1 finding."), "{stdout}");
}

#[test]
fn no_findings_exits_0_and_still_writes_a_report() {
    let dir = tempfile::tempdir().unwrap();
    let capture = clean_capture(dir.path());

    let out = baccheck(&[capture.as_os_str()]);

    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let report = std::fs::read_to_string(dir.path().join("clean.baccheck.html")).expect("report");
    assert!(report.contains("No findings."));
}

#[test]
fn unreadable_capture_exits_3() {
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("bogus.pcap");
    std::fs::write(&bogus, b"this is not a capture file at all").unwrap();

    let out = baccheck(&[bogus.as_os_str()]);
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    assert!(!dir.path().join("bogus.baccheck.html").exists());

    let missing = baccheck(&[dir.path().join("missing.pcap").as_os_str()]);
    assert_eq!(missing.status.code(), Some(3));
}

#[test]
fn usage_error_exits_2() {
    let out = baccheck(&[]);
    assert_eq!(out.status.code(), Some(2));

    let capture = Path::new("x.pcap");
    let bad_flag = baccheck(&[
        capture.as_os_str(),
        "--min-severity".as_ref(),
        "bogus".as_ref(),
    ]);
    assert_eq!(bad_flag.status.code(), Some(2));
}

#[test]
fn unwritable_report_path_exits_4() {
    let dir = tempfile::tempdir().unwrap();
    let capture = duplicate_id_capture(dir.path());
    let output = dir.path().join("no-such-dir").join("report.html");

    let out = baccheck(&[capture.as_os_str(), "-o".as_ref(), output.as_os_str()]);

    assert_eq!(out.status.code(), Some(4), "{out:?}");
}

#[test]
fn output_as_file_path_writes_there() {
    let dir = tempfile::tempdir().unwrap();
    let capture = duplicate_id_capture(dir.path());
    let output = dir.path().join("custom-name.html");

    let out = baccheck(&[capture.as_os_str(), "-o".as_ref(), output.as_os_str()]);

    assert_eq!(out.status.code(), Some(1));
    assert!(output.exists());
    assert!(!dir.path().join("dup.baccheck.html").exists());
}

#[test]
fn output_as_directory_uses_the_default_file_name() {
    let dir = tempfile::tempdir().unwrap();
    let capture = duplicate_id_capture(dir.path());
    let out_dir = dir.path().join("reports");
    std::fs::create_dir(&out_dir).unwrap();

    let out = baccheck(&[capture.as_os_str(), "-o".as_ref(), out_dir.as_os_str()]);

    assert_eq!(out.status.code(), Some(1));
    assert!(out_dir.join("dup.baccheck.html").exists());
}

#[test]
fn existing_report_is_overwritten_silently() {
    let dir = tempfile::tempdir().unwrap();
    let capture = duplicate_id_capture(dir.path());
    let report = dir.path().join("dup.baccheck.html");
    std::fs::write(&report, "old").unwrap();

    baccheck(&[capture.as_os_str()]);

    assert_ne!(std::fs::read_to_string(&report).unwrap(), "old");
}

#[test]
fn min_severity_filters_the_report_but_not_the_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let capture = duplicate_id_capture(dir.path());

    let out = baccheck(&[capture.as_os_str(), "-s".as_ref(), "critical".as_ref()]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "the High finding still gates the exit code"
    );
    let report = std::fs::read_to_string(dir.path().join("dup.baccheck.html")).unwrap();
    assert!(
        !report.contains("id=\"f-0\""),
        "the High finding is hidden from the detail list"
    );
    assert!(report.contains("1 lower finding(s) are hidden"));
}
