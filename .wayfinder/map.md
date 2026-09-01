# The BACnet Pcap Health Check

## Destination

A small, fast Rust CLI (`bacnet-pcapcheck <in.pcap> -o report.pdf`) that reads a BACnet/IP capture, decodes it, detects the top ~10 network problems, and emits a field-engineer-facing PDF with prescriptive steps to improve the network. The way is clear when every decision between pcap-in and PDF-out is resolved and nothing remains to decide before building.

## Notes

- **Domain**: BACnet (building automation), BACnet/IP over UDP 47808. pcap/pcapng capture analysis. Field-engineering remediation.
- **Working method**: TDD throughout; every seam is a testable boundary with fixture data. Keep the seams clean: pcap parsing → BACnet decoding → issue detection → PDF generation. Library crate + thin binary.
- **Skills every session should consult**: "grilling", "domain-modeling", "tdd", "implement" (when building), "research" (for AFK research tickets).
- **Standing preferences**:
  - BACnet/IP only (no MS/TP, no BACnet/Ethernet in scope).
  - Field-engineer-facing, device-specific, prescriptive remediation. One PDF per pcap, no interactivity.
  - CLI only — analysis engine stays wrapper-agnostic.
  - Canned per-issue remediation text to start; reasoned per-device recommendations are a possible later upgrade, not required for the destination.

## Decisions so far

<!-- the index: one line per closed ticket, enough to judge relevance, then zoom the link for the detail the ticket holds -->

- [Name the top 10 issues](https://github.com/xtr3m3b00t3r/bacnetPcapCheck/issues/2): chose the 10 pcap-diagnosable problems a field engineer most wants, ranked — duplicate device IDs, broadcast/Who-Is storms, unresponsive devices, duplicate BBMDs/forwarding loops, incomplete BDT, foreign-device registration failure, segmentation misuse, unicast I-Am, routing rejections, confirmed-service retransmissions. Full report at `.wayfinder/assets/001-top-10-issues.md`.

## Not yet specified

- **The Finding schema** (the seam between detection and PDF): what fields a machine-readable `Finding` carries — severity, affected device(s), evidence, canonical issue id, and the remediation steps. Sharp enough to design once the top-10 issues list is settled, too coarse to ticket before then.
- **Detection algorithms per issue**: for each of the top 10 issues, the exact rule that says "this capture shows X" (thresholds, e.g. retransmission rate, duplicate-ID count, broadcast-storm packets/sec). Graduates one ticket per issue once the list is fixed.
- **Decode scope**: exactly which BACnet services/PDUs the decoder must understand to feed all 10 detectors (Who-Is/I-Am, ReadProperty/Response addresses, etc.). Harbors if the 10 issues reach into services we haven't decoded yet.
- **CLI surface**: exact flags/behavior of the binary (input, output path, severity filter, exit codes, error handling for malformed pcap). Sharp, but feels like a small design/later concern; may stay here or graduate late.
- **Performance budget**: "small, fast" was stated but not quantified. Whether we need a measured target (e.g. process N MB/s) or just "doesn't blow the heap" is open.

## Out of scope

- MS/TP (Clause 9) and BACnet/Ethernet (Clause 7) link layers — BACnet/IP only per the destination.
- Interactive tooling, web/GUI wrapper — a thin seam keeps the engine wrapper-agnostic, but no UI is part of this effort.
- Replacing/augmenting a live network analyzer — this reads captures offline only; pulling live statistics is a different effort.
