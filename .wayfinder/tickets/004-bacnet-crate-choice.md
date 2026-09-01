# 004 - The BACnet crate choice

- **Type**: `wayfinder:prototype`
- **Status**: open
- **Claimed by**: (unclaimed)
- **Blocks**: `002-finding-schema`, `006-decode-scope`

## Question

Which BACnet decoding approach does the project build on for the "BACnet decoding" seam?

The candidates surfaced in charting: `bacnet-rs` (full protocol stack — encoding/decoding, BACnet/IP, Who-Is/I-Am, ReadProperty — but described as "not production-ready", async/client-oriented, heavier than a passive decoder needs) versus `bacnet_parse` (lighter parse-only, but stale since 2019) versus hand-rolling a minimal BACnet/IP+APDU decoder ourselves (full control, more work, but the decoding seam is the core of the tool).

Build a cheap prototype taking a representative set of real BACnet/IP packets and see how far each approach gets decoding Who-Is/I-Am and ReadProperty/Response reliably, and how cleanly it fits a passive, offline decode (no live networking, no async).

## Deliverable

A working prototype on these packets, comparing the candidates, with a recommendation; the chosen approach unblocks the decode-scope ticket.
