# Can undecodable traffic be the signature of a BACnet broadcast storm?

Research finding, backed by primary sources (Wireshark dissector source, libpcap man pages, Fisher/PolarSoft field papers, Optigo/Chipkin field-engineering guides).

## 1. What a Who-Is broadcast storm looks like on the wire

A BACnet broadcast storm is, by every field account, made of **well-formed, decodable BACnet/IP packets**. There is no stage in a Who-Is/I-Am storm where the traffic becomes malformed:

- David Fisher's (PolarSoft) tutorial *Broadcast Storms in BACnet* defines a storm as "a large percentage of network message traffic" being broadcasts: Who-Is requests (often with ranges like `Who-Is(0,100000)` or no range at all) sent too frequently, answered by a flood of I-Am broadcasts — all normal BACnet messages (https://polarsoft.com/bex/papers/Broadcast%20Storms.pdf).
- Optigo's field guide to spotting global Who-Is storms describes the same shape: "Global Who-Is requests … every device on the network responds with an I-Am … broadcast back", detected by counting global Who-Is/I-Am rates — i.e., by parsing decoded BACnet messages (https://www.optigo.net/blog/identifying-problematic-global-who-visual-bacnet/).
- Chipkin built a commercial tool specifically to **replay** storm pcaps as BACnet UDP messages (flood/DoS testing against BACnet servers), which only works because storm pcaps contain parseable BACnet payloads (https://store.chipkin.com/products/cas-bacnet-wireshark-storm-tool).

On the IP layer these are BVLC-encapsulated frames. Wireshark's BVLC dissector (epan/dissectors/packet-bvlc.c) enumerates the function codes relevant to broadcast storms (https://gitlab.com/wireshark/wireshark/-/raw/master/epan/dissectors/packet-bvlc.c):

- `0x04` Original-Broadcast-NPDU — the direct local-subnet broadcast form of a Who-Is/I-Am.
- `0x09` Distribute-Broadcast-To-Network — BBMD re-broadcast to local devices.
- `0x02` Forwarded-NPDU — BBMD-to-BBMD forwarding of the same broadcast.
- `0x05` Register-Foreign-Device / `0x08` Delete-Foreign-Device-Table-Entry, and `0x00` BVLC-Result (carrying Result-Code / NAKs such as Register-Foreign-Device NAK, `0x90` in the IPv6 table).

The Wireshark source notes that frames with unknown BVLC function codes still get their header dissected and are labelled "unknown" rather than dropped (`val_to_str_const(bvlc_function, bvlc_function_names, "unknown")`), and mismatched BVLC lengths are flagged as "invalid length" in the tree — the dissector degrades gracefully, it does not classify BACnet-looking frames as foreign garbage.

**Conclusion (sub-q 1):** A Who-Is storm always arrives as decodable BVLC traffic (`0x04`/`0x02`/`0x09`), so a rate-based detector over decoded messages will catch it. Note the *mitigation traffic* is also decodable: misconfigured BBMD/foreign-device setups flood `BVLC-Result` NAKs (`0x00`) and Register-Foreign-Device messages, not garbage (https://polarsoft.com/bex/papers/BACnetIP%20and%20BBMDs.pdf).

## 2. What actually produces undecodable/UDP-47808 "garbage"

Field sources attribute undecodable traffic to mundane causes, none of which is a Who-Is storm:

- **Non-standard BACnet ports.** Chipkin documents that BACnet/IP legitimately runs on non-47808 ports (e.g. 47808–47817, "BAC0–BAC9"); Wireshark decodes only the well-known port, so valid BACnet traffic on other ports "will typically classify the packets as generic UDP data" — it looks undecodable to a port-based dissector (https://store.chipkin.com/articles/decoding-bacnet-traffic-on-non-standard-ports-using-wireshark).
- **BBMD/foreign-device misconfiguration.** Produces NAK-bearing `BVLC-Result` messages and triple-replicated foreign-device traffic — malformed only in intent, decodable in form (https://polarsoft.com/bex/papers/BACnetIP%20and%20BBMDs.pdf).
- **Checksum-offload false positives.** The Wireshark User's Guide: locally generated packets carry "empty (zero or garbage filled) checksum field[s]" and Wireshark "displays them as invalid, even though the packets will contain valid checksums when they transit the network" (https://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html). This inflates "invalid/bad" counts without any network problem.
- **Capture-level drops.** libpcap's `pcap_stats()` reports `ps_drop` ("packets dropped because there was no room in the operating system's buffer") and `ps_ifdrop` (dropped "by the network interface or its driver"), supported only on live captures (https://www.tcpdump.org/manpages/pcap_stats.3pcap.html, https://www.tcpdump.org/manpages/pcap.3pcap.txt). Dropped packets are *absent* from the pcap, not present as garbage — so drops skew rates and completeness, but never appear as undecodable bytes in the file.
- **Genuinely malformed devices.** Wireshark's BACnet/APDU dissector handles these with expert infos — `bacapp.bad_length`, `bacapp.bad_tag`, `bacapp.bad_opening_tag`, all registered as `PI_MALFORMED`/`PI_ERROR` (epan/dissectors/packet-bacapp.c, https://gitlab.com/wireshark/wireshark/-/raw/master/epan/dissectors/packet-bacapp.c) — i.e., it dissects as far as it can and flags the rest; the frames remain attributed to BACnet.

**Conclusion (sub-q 2):** Undecodable traffic is dominated by port heuristics and capture artifacts, plus genuinely broken devices; malformed frames are flagged piecemeal by the dissector, not converted into a storm signature.

## 3. Can non-BACnet floods mimic or co-occur with a BACnet storm?

Yes, mechanically. UDP/47808 is merely the registered BACnet port; any host can emit traffic there, and a port-sniffing tool cannot tell BACnet payloads from other UDP payloads without attempting decode. On the shared L2 segment, non-BACnet floods (ARP storms, other UDP floods) coexist with BACnet traffic in a capture and can produce a "high packet rate, much of it not BACnet" profile that superficially resembles the network-health symptoms of a storm (Optigo describes the *symptoms* of storms as network-wide slowdown and "overall network instability", which any flood also causes — https://www.optigo.net/blog/identifying-problematic-global-who-visual-bacnet/).

However, the mimicry is distinguishable: a genuine BACnet storm is a **high rate of decoded BACnet broadcast messages**, while a non-BACnet flood is a high rate of *unparsed* frames. Only the former is actionable by a BACnet-focused tool — remediating an ARP storm is outside its remit (it has no BACnet device, remediation text, or finding vocabulary for it; see CONTEXT.md: findings are per-device BACnet problems with remediation for field engineers). The tool's job is to *not mis-attribute* non-BACnet noise to BACnet devices, not to diagnose it.

**Conclusion (sub-q 3):** Co-occurrence is common; mimicry is possible but detectable by checking whether the flood traffic decodes. Diagnosing non-BACnet floods is out of scope for a BACnet field tool, but surfacing their existence is cheap and prevents wrong attribution.

## 4. Assessment of the three options

- **(a) Merely a report stat:** Correct that undecodable proportion is rarely itself a *finding* — but as a bare stat it would hide a real trap: a capture dominated by non-BACnet flood traffic or mis-port BACnet invalidates the detector's rate baselines (packets-per-second denominators) and can cause false negatives for storms (missing or swamped decoded traffic).
- **(b) Signal cross-referenced into the storm finding's evidence:** Matches the evidence. Storms are always decodable, so detection stays rate-based on decoded messages (Fisher; Optigo). But the undecodable/non-BACnet proportion is exactly the evidence needed to answer "is this high broadcast rate really BACnet?" and to flag captures whose health makes other findings untrustworthy.
- **(c) Its own finding:** Overweight. Undecodable traffic has too many benign causes (checksum offload artifacts, non-standard ports, drops) per §2; promoting it to a finding would cry wolf.

## Verdict

**Recommend (b): treat 'high proportion of undecodable / non-BACnet packets' as a report statistic that is cross-referenced into the 'Excessive Global Who-Is / Broadcast Storm' finding's evidence — not as an independent finding, and not as mere bookkeeping.**

Justification:

1. A Who-Is storm is always visible as decodable BVLC traffic (Original-Broadcast-NPDU `0x04`, Forwarded-NPDU `0x02`, Distribute-Broadcast-To-Network `0x09`), so the rate-based detector catches storms on its own; undecodable traffic is *never* the storm's signature (Fisher; Optigo; Wireshark packet-bvlc.c).
2. But undecodable/non-BACnet proportion is the discriminating evidence for two real failure modes of a BACnet health-check: (i) non-BACnet floods mimicking storm-like network symptoms, and (ii) valid BACnet on non-standard ports appearing undecodable to port-based decoding (Chipkin). Embedding the proportion (and ideally the top non-BACnet protocol/port breakdown) in the storm finding's evidence lets the field engineer distinguish "BACnet storm" from "capture polluted by something else" without the tool claiming out-of-scope expertise.
3. It should not be its own finding because the dominant causes are benign capture artifacts — checksum-offload "invalid" checksums on locally generated packets (Wireshark WSUG) and libpcap buffer drops that remove packets entirely rather than garbling them (libpcap `pcap_stats`) — plus malformed devices, which Wireshark handles as per-frame PI_MALFORMED expert infos on otherwise BACnet-classified frames.

Concretely: keep the storm detector rate-based over decoded messages; report undecodable/non-BACnet as a capture-health stat on every report; and when a storm finding fires, include the undecodable proportion in its evidence with a note such as "X% of captured traffic was not decodable BACnet — verify the storm is BACnet-sourced." Optionally add a lightweight capture-health warning (not a numbered finding) when the undecodable proportion is extreme (e.g. >50%), advising that other findings in the report may be under-counted.
