# 004 - The BACnet crate choice

- **Type**: `wayfinder:prototype`
- **Status**: closed (resolved 2026-09-01)
- **Resolution**: use `bacnet-rs` 0.3.1 with `default-features=false, features=["std"]` for the BACnet decoding seam.
- **Blocks**: `002-finding-schema`, `006-decode-scope`

## Question

Which BACnet decoding approach does the project build on for the "BACnet decoding" seam?

The candidates surfaced in charting: `bacnet-rs` (full protocol stack — encoding/decoding, BACnet/IP, Who-Is/I-Am, ReadProperty — but described as "not production-ready", async/client-oriented, heavier than a passive decoder needs) versus `bacnet_parse` (lighter parse-only, but stale since 2019) versus hand-rolling a minimal BACnet/IP+APDU decoder ourselves (full control, more work, but the decoding seam is the core of the tool).

Build a cheap prototype taking a representative set of real BACnet/IP packets and see how far each approach gets decoding Who-Is/I-Am and ReadProperty/Response reliably, and how cleanly it fits a passive, offline decode (no live networking, no async).

## Deliverable

A working prototype on these packets, comparing the candidates, with a recommendation; the chosen approach unblocks the decode-scope ticket.

**Done 2026-09-01:** prototype `prototype/crate-comparison/` (commit `13f0668`, branch `prototype/crate-choice`) compared the candidates over 3610 real BACnet/IP payloads. bacnet-rs 0.3.1 won on decode rate (99.75%), typed service bodies in-crate, lean deps (29, no async), and active maintenance. rusty-bacnet is a near-equal but heavier 50-dep client/server stack; bacnet_parse is insufficient (no confirmed-service classification, Who-Is/I-Am unreliable). Full write-up: `prototype/crate-comparison/COMPARISON.md`. Resolution comment: <https://github.com/xtr3m3b00t3r/bacnetPcapCheck/issues/5#issuecomment-5502368436>.
