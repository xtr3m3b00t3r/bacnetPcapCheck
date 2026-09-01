# Top 10 BACnet/IP Network Issues Diagnosable from Pcap

**Date:** 2026-08-31
**Scope:** BACnet/IP only (UDP port 47808, BVLC). MS/TP and other link layers out of scope.
**Input:** Offline `.pcap` / `.pcapng` capture files.

---

## 1. Duplicate Device Instance IDs

**Description:** Two or more devices on the same BACnet internetwork share the same device instance number (0–4194302), causing address-cache oscillation in the BAS supervisor.

**Pcap evidence:**
- Two or more I-Am (unconfirmed-request-pdu type 1) responses to a single Who-Is broadcast, carrying the same `Device Identifier` object instance but different source IP addresses.
- Alternatively, two I-Am responses with the same instance but different NPDU source addresses (SADR) when routed.

**Detection signal:**
- Group all I-Am packets by `(device_instance, capture_window)`. If count > 1 with distinct source IP/MAC within the same window → flag.
- Threshold: ≥2 distinct source IPs for the same device instance within any 30-second window.

**Source citations:**
- Chipkin BACnet/IP reference: https://docs.chipkin.com/protocols/bacnet/ip/ (common failure table — "Duplicate Device Instance")
- Chipkin BACnet Discovery & Architecture: https://docs.chipkin.com/articles/bacnet-discovery-network-architecture-reference/ (discovery failures, device instance conflict)
- SiteConduit: https://siteconduit.com/kb/bacnet/duplicate-device-id-fix
- Johnson Controls Metasys BACnet troubleshooting: https://docs.johnsoncontrols.com/bas/r/Metasys/en-US/BACnet-Controller-Integration-Technical-Bulletin/14.0/Troubleshooting/BACnet-System-Integration-troubleshooting-guide
- Optigo: https://www.optigo.net/blog/common-bacnet-ip-and-ethernet-issues/ (duplicate device instance section)

---

## 2. Excessive Global Who-Is / Broadcast Storm

**Description:** One or more devices emit Global Who-Is broadcasts (targeting the full device-instance range) at a rate that saturates bandwidth, overwhelms device CPUs, and triggers cascading I-Am response storms.

**Pcap evidence:**
- High-rate `unconfirmed-request-pdu` packets with `service-choice = who-is` (service 0x00), where the device-instance-range-low/high fields target the wildcard range (0–4194303 or large range).
- Corresponding burst of `unconfirmed-request-pdu` packets with `service-choice = i-am` (service 0x01) from many devices in response.

**Detection signal:**
- Count Who-Is broadcast packets per source IP per minute.
- Threshold: >1 Global Who-Is per source per 5 minutes, or >10 Who-Is per source per minute for targeted ranges, is excessive (per BTL Implementation Guideline §6.6–6.7).
- Also flag if total I-Am broadcast count in any 10-second window exceeds 50% of device count.

**Source citations:**
- BTL Implementation Guidelines §6.5–6.7 (restrict Who-Is range, space out broadcasts, reduce repeat rate): https://bacnetglobal.org/wp-content/uploads/2022/08/BTL_Implementation_Guideline.pdf
- Optigo — Global Who-Is Storms: https://www.optigo.net/identifying-problematic-global-who-visual-bacnet/
- Optigo — broadcast storms and APDU timeout relationship: https://www.optigo.net/blog/your-bacnet-questions-answered-episode-4/
- Actility Wireshark BACnet setup: https://www.actility.com/wireshark-for-bacnet-setup/

---

## 3. Unresponsive Devices (Confirmed Requests Without Acknowledgment)

**Description:** A device is sent a confirmed service request (ReadProperty, ReadPropertyMultiple, WriteProperty, etc.) but never replies within the capture window — either the device is offline, misconfigured, or its BACnet stack has locked up.

**Pcap evidence:**
- `confirmed-request-pdu` (type 0) packets from a client to a specific IP, with no matching `complex-ack-pdu` (type 3), `simple-ack-pdu` (type 2), `error-pdu` (type 5), `reject-pdu` (type 6), or `abort-pdu` (type 7) within the APDU timeout window.
- Repeated retransmissions of the same confirmed request with the same `invoke-id`.

**Detection signal:**
- For each confirmed request, check for a response (any response PDU) with the same `invoke-id` from the target IP within 3–5 seconds (typical APDU_Timeout).
- Flag a device as unresponsive if ≥3 consecutive confirmed requests to the same IP receive no response within the timeout.
- Also flag: retransmission count (same invoke-id, same src/dst) exceeding device's advertised APDU_Retries value.

**Source citations:**
- Chipkin BACnet/IP reference: https://docs.chipkin.com/protocols/bacnet/ip/ ("Reads fail after discovery works")
- Optigo — common BACnet/IP issues (unreachable devices): https://www.optigo.net/blog/common-bacnet-ip-and-ethernet-issues/
- Optigo — APDU timeout explanation: https://www.optigo.net/blog/your-bacnet-questions-answered-episode-4/
- ASHRAE 135 / BTL Guidelines §7.4 (polling rate, APDU timeout defaults): https://bacnetglobal.org/wp-content/uploads/2022/08/BTL_Implementation_Guideline.pdf

---

## 4. Duplicate BBMDs / BBMD Forwarding Loops

**Description:** Two or more devices on the same subnet are acting as BBMDs, each forwarding every broadcast it receives. This creates amplified (2x, 3x, or more) broadcast traffic that can overwhelm the network.

**Pcap evidence:**
- `Forwarded-NPDU` (BVLC function 0x04) packets where the same original broadcast appears multiple times arriving at different IPs on the same subnet, or identical Forwarded-NPDU packets arriving within microseconds of each other.
- `bacnet.hopc` (hop count) decrementing rapidly across successive forwarded copies of the same broadcast — approaching zero indicates a loop.

**Detection signal:**
- For each unique original broadcast (identified by original source IP + timestamp + payload hash), count the number of Forwarded-NPDU copies received within 100ms.
- Threshold: >2 copies of the same broadcast within 100ms on the same subnet → likely duplicate BBMDs.
- Also flag: hop count decrementing by 2+ per forwarded hop (each BBMD decrements once).

**Source citations:**
- Optigo — Duplicate BBMD: https://optigo.zendesk.com/hc/en-us/articles/27457719911309-Duplicate-BACnet-Broadcast-Management-Device-BBMD
- Optigo — BBMD issues: https://www.optigo.net/blog/your-bacnet-questions-bbmds-1/
- SiteConduit — BBMD Setup Guide: https://siteconduit.com/kb/bacnet/bbmd-setup-guide ("Multiple BBMDs on the same subnet" section)
- Automated Academy Wireshark Basics (BBMD loop detection): https://www.automatedacademy.com/post/wireshark-basics

---

## 5. Incomplete BBMD Broadcast Distribution Table (Cross-Subnet Discovery Failure)

**Description:** A BBMD's Broadcast Distribution Table (BDT) is missing entries, causing broadcasts to be forwarded to some subnets but not others — devices on unlisted subnets become invisible to the BAS supervisor.

**Pcap evidence:**
- Who-Is broadcast visible on subnet A, but no corresponding `Forwarded-NPDU` (BVLC 0x04) appears on subnet B.
- Or: Forwarded-NPDU appears on subnet B but no Forwarded-NPDU from BDT entries points back to subnet A (asymmetric routing).
- Devices respond with I-Am only on the local subnet where the Who-Is originated; cross-subnet I-Am is absent.

**Detection signal:**
- Count Forwarded-NPDU packets per source-subnet to destination-subnet pair.
- Flag if any pair shows traffic in only one direction (asymmetric).
- Flag if expected subnets (identified by IP ranges of captured devices) never appear as destination of a Forwarded-NPDU.

**Source citations:**
- SiteConduit — BBMD Setup Guide: https://siteconduit.com/kb/bacnet/bbmd-setup-guide ("Mismatched BDT entries across BBMDs" section)
- Chipkin — BACnet/IP reference: https://docs.chipkin.com/protocols/bacnet/ip/ ("Discovery works on one subnet only")
- Chipkin — BACnet Discovery & Architecture: https://docs.chipkin.com/articles/bacnet-discovery-network-architecture-reference/ (partial discovery section)

---

## 6. Foreign Device Registration Failure / TTL Expiry

**Description:** A remote BACnet/IP device attempts to register as a Foreign Device (FDR) with a BBMD but the registration is rejected, or the device fails to renew before TTL expiry, losing broadcast visibility.

**Pcap evidence:**
- `Register-Foreign-Device` BVLC message (0x05) sent to a BBMD, followed by a `Result` BVLC (0x00) with a non-zero result code (NACK).
- Or: `Register-Foreign-Device` sent but no `Result` received at all.
- For TTL expiry: The device is absent from the Foreign Device Table — confirmed by seeing no `Forwarded-NPDU` traffic being sent to the device's IP/port during broadcasts, despite the device being on a different subnet.

**Detection signal:**
- Count Register-Foreign-Device packets and their corresponding Result packets.
- Flag if result code ≠ 0 or if no Result arrives within 2 seconds.
- Flag if a device that previously sent Register-Foreign-Device stops receiving Forwarded-NPDU within the TTL window (typically 300–600 seconds).

**Source citations:**
- Chipkin — BACnet FDR reference: https://docs.chipkin.com/protocols/bacnet/fdr/
- bacpypes issue #275 (registration timing, NACK debugging): https://github.com/JoelBender/bacpypes/issues/275
- bacpypes issue #445 (path discovery timing with FDR): https://github.com/JoelBender/bacpypes/issues/455
- Wireshark bug #1545 (FDR decode): https://lists.wireshark.org/archives/wireshark-bugs/200704/msg00291.html

---

## 7. Segmentation Misuse / Oversized APDUs

**Description:** A device sends a response too large for the receiver's Max_APDU_Length_Accepted, and either the receiver does not support segmentation (causing an abort) or the segmentation is misconfigured, leading to dropped messages and timeouts.

**Pcap evidence:**
- `segmented-response-pdu` or `segmented-request-pdu` APDU type (type 15 or type 3 in the BACnet APDU type field) where the `moreFollows` bit is set.
- `abort-pdu` (type 7) with reason code `SEGMENTATION_NOT_SUPPORTED` (0x06) or `BUFFER_OVERFLOW` (0x04).
- A `confirmed-request-pdu` with `segmented-message` bit set but the receiver's Max_Segments_Accepted advertised in a prior I-Am is very low (2) or absent.
- ReadPropertyMultiple requests consistently failing while ReadProperty to the same device succeeds.

**Detection signal:**
- Count abort-pdus with segmentation-related reason codes.
- Flag if: confirmed requests to a device exceed its advertised Max_APDU_Length_Accepted (extractable from the device's I-Am or prior ReadProperty of Device object).
- Flag: presence of segmented-response-pdus where the segment count exceeds the receiver's Max_Segments_Accepted.

**Source citations:**
- BTL Implementation Guidelines §5 (segmentation rules): https://bacnetglobal.org/wp-content/uploads/2022/08/BTL_Implementation_Guideline.pdf
- LinkedIn / Steve The BMS Engineer — APDU Segmentation and Timeouts: https://www.linkedin.com/posts/steve-the-bms-engineer-277716363_bacnet-buildingautomation-buildingautomationsystems-activity-7480851936376729600-3qqX
- bacpypes issue #127 (segmentationNotSupported error): https://github.com/JoelBender/bacpypes/issues/127

---

## 8. Unicast I-Am Response (Discovery Interoperability Gap)

**Description:** A device responds to Who-Is with a unicast I-Am to the requesting IP instead of a broadcast, making it invisible to BMS platforms that only listen for broadcast I-Am responses.

**Pcap evidence:**
- A Who-Is broadcast packet (destination = subnet broadcast IP, e.g. `255.255.255.255` or `x.x.x.255`) is followed by an I-Am response where `ip.dst` is the requester's unicast IP rather than the broadcast address.
- Compare: standard I-Am responses from other devices in the same capture show `ip.dst = broadcast`.

**Detection signal:**
- For each Who-Is broadcast, examine the I-Am responses.
- Flag if: I-Am `ip.dst` ≠ broadcast address (255.255.255.255 or subnet broadcast).
- Threshold: any unicast I-Am to a broadcast Who-Is is an interoperability concern.

**Source citations:**
- Chipkin — BACnet Discovery & Architecture (unicast I-Am section): https://docs.chipkin.com/articles/bacnet-discovery-network-architecture-reference/
- Chipkin — BACnet/IP reference: https://docs.chipkin.com/protocols/bacnet/ip/ ("Tool sees device but BMS does not")

---

## 9. Routing Failures (Reject-Message-To-Network)

**Description:** A BACnet router cannot route a message to the destination network and sends a `Reject-Message-To-Network` NPDU back to the sender with a reason code (unreachable, too long, addressing error, etc.).

**Pcap evidence:**
- NPDU network-layer message type `0x03` (Reject-Message-To-Network) visible in the capture.
- The rejection reason byte is present: 0x01 = unreachable network, 0x04 = message too long, 0x05 = addressing error.
- The DNET (destination network number) in the reject identifies which network was unreachable.
- Often preceded by `Who-Is-Router-To-Network` (0x00) messages that go unanswered.

**Detection signal:**
- Count NPDU messages with `mesg_type == 0x03` per capture.
- Any occurrence is a finding; group by rejection reason and target DNET.
- Flag if: >3 Reject-Message-To-Network within a 60-second window targeting the same DNET (persistent routing failure).
- Also flag: Who-Is-Router-To-Network messages with no I-Am-Router-To-Network response (missing route discovery).

**Source citations:**
- Chipkin — Reject-Message-To-Network: https://docs.chipkin.com/protocols/bacnet/services/reject-message-to-network/
- Wireshark dissector source (reject reason rvals): https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-bacnet.c
- Ask Wireshark forum — Reject-Message-To-Network diagnosis: https://ask.wireshark.org/questions/25438/revisions/
- Optigo — what's in a BACnet packet capture (NPDU reject): https://www.optigo.net/blog/whats-in-a-bacnet-packet-capture/

---

## 10. Excessive Confirmed-Service Retransmissions (Unacknowledged Requests)

**Description:** A device sends confirmed service requests but receives no acknowledgment, and retransmits multiple times — indicating network congestion, a silently dropped connection, or a device-side stack problem.

**Pcap evidence:**
- Multiple `confirmed-request-pdu` packets from the same source to the same destination IP, with the same `invoke-id`, appearing at intervals matching the APDU timeout (typically 3000ms default, or 60000ms).
- No `simple-ack-pdu`, `complex-ack-pdu`, `error-pdu`, `reject-pdu`, or `abort-pdu` matching that invoke-id between retransmissions.

**Detection signal:**
- Group confirmed requests by `(src_ip, dst_ip, invoke-id)`.
- Flag if: the same (src, dst, invoke-id) appears ≥3 times without any response PDU in between.
- Correlate with APDU_Timeout (if known from device object reads): retransmission interval ≈ APDU_Timeout.
- Threshold: ≥3 unacknowledged retransmissions to the same device within any 30-second window.

**Source citations:**
- ASHRAE 135 — APDU_Timeout and APDU_Retries defaults (3000ms, 3 retries): https://docs.johnsoncontrols.com/bas/r/BCPro/en-US/BCPro-Data-Server/4.0/BACnet-Device-Object/BACnet-Device-Attributes/BACnet-Device-Attribute-Details/APDU-Segment-Timeout
- Optigo — APDU timeout and network congestion: https://www.optigo.net/blog/your-bacnet-questions-answered-episode-4/
- BTL Implementation Guidelines §7.4 (polling and retry behavior): https://bacnetglobal.org/wp-content/uploads/2022/08/BTL_Implementation_Guideline.pdf

---

## Excluded from Pcap: Valuable Field-Knowledge That Requires Live or Physical Access

The following BACnet problems are real and high-impact per Chipkin and other field resources, but **cannot** be diagnosed from an offline pcap alone:

1. **MS/TP physical-layer faults** — wiring errors, polarity reversal, missing termination resistors, EOL bias problems, RS-485 noise. These require serial-layer diagnostics or oscilloscope on the trunk. (Chipkin MS/TP troubleshooting guide, MS/TP troubleshooting guide on store.chipkin.com)

2. **MS/TP MAC address conflicts on a trunk** — while visible if MS/TP frames are captured, MS/TP over RS-485 cannot be captured in a standard IP pcap without a dedicated MS/TP-to-pcap bridge. (Chipkin MS/TP troubleshooting guide)

3. **MS/TP Max Masters misconfiguration** — a controller set too low, causing devices above the threshold to be invisible to token passing. This manifests as physical-layer token-passing behavior, not IP-level packets. (Chipkin MS/TP reference, SiteConduit BACnet discovery troubleshooting)

4. **Physical device health** — power supply failures, overheating, hardware degradation. These produce no network signal; they require on-site physical inspection. (Optigo — what's in a BACnet packet capture)

5. **BACnet object/service feature mismatches** — a device's PICS (Protocol Implementation Conformance Statement) not supporting the required objects or services. This requires querying Device object properties (Protocol_Objects_Supported, Protocol_Services_Supported), which is a live interrogation, not a passive pcap analysis. (ControlsHub BACnet troubleshooting guide — "Feature mismatch" bucket)

6. **BACnet security configuration issues** — BACnet/SC (Secure Connect) TLS misconfigurations, key exchange failures. These are encrypted at the transport layer and invisible to pcap-based BACnet decoding. (Out of scope for BACnet/IP classic anyway.)

7. **Configuration drift after firmware updates** — devices losing their Device Instance, port, or network number after a firmware flash. Detection requires comparing device identity before and after, not a single pcap snapshot. (Chipkin BACnet Discovery — "Discovery worked before, now fails" table)

---

## Summary Table

| Rank | Issue | Severity to Field Engineer | Pcap Detectability |
|------|-------|---------------------------|-------------------|
| 1 | Duplicate Device Instance IDs | Critical — wrong data, wrong control commands | High — I-Am analysis |
| 2 | Excessive Global Who-Is / Broadcast Storm | High — network saturation, device overload | High — Who-Is/I-Am rate counting |
| 3 | Unresponsive Devices | High — lost data, stale BAS readings | High — request/response matching |
| 4 | Duplicate BBMDs / Forwarding Loops | High — broadcast amplification | Medium — Forwarded-NPDU dedup + hop count |
| 5 | Incomplete BDT (Cross-Subnet Gaps) | High — invisible devices on remote subnets | Medium — Forwarded-NPDU presence/absence per subnet |
| 6 | Foreign Device Registration Failure | Medium — lost remote device visibility | Medium — BVLC Register-Foreign-Device + Result |
| 7 | Segmentation Misuse / Oversized APDUs | Medium — dropped large responses, timeouts | Medium — segmented APDU + abort analysis |
| 8 | Unicast I-Am Response | Medium — invisible to some BMS platforms | Medium — I-Am destination address check |
| 9 | Routing Failures (Reject-Message-To-Network) | Medium — unreachable networks, dropped traffic | Medium — NPDU reject message analysis |
| 10 | Excessive Confirmed-Service Retransmissions | Medium — degraded responsiveness, wasted bandwidth | High — invoke-id retransmission counting |
