# 001 - The top 10 issues to detect

- **Type**: `wayfinder:research`
- **Status**: open
- **Claimed by**: (unclaimed)
- **Blocks**: `002-the-finding-schema`, `003-issue-detection-rules`

## Question

Which are the ~10 BACnet network problems most worth detecting from a .pcap, and which of them can actually be diagnosed from pcap data alone?

Pull the Chipkin "BACnet for field engineers" guide(s) and cross-reference each candidate problem against what a BACnet/IP pcap exposes (BVLC headers, NPDU/APDU, Who-Is/I-Am traffic, ReadProperty/Response, retransmissions, timing). Weigh candidates (e.g. duplicate device IDs, broadcast storms, excessive retransmissions, unresponsive devices, segmentation misuse, Who-Is flooding, no I-Am responses, APDU timeouts, foreign-device registration issues, BACnet/IP broadcast addressing) and pick the top 10 that are (a) high-value to a field engineer and (b) demonstrable from packet data.

For each selected issue, record: a one-line description, the pcap evidence that would reveal it, and a rough detection signal (the data a rule would inspect). These become the input to `003` (the per-issue detection rules) and `002` (the Finding schema).

## Deliverable

A researched, ranked list of 10 issues with pcap evidence and detection signals, written up as a markdown asset linked from this ticket.
