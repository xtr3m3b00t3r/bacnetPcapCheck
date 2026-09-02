# 006 - Decode scope

- **Type**: `wayfinder:grilling`
- **Status**: open
- **Claimed by**: (unclaimed)
- **Blocked by**: `001-top-10-issues` (was also blocked by `004-bacnet-crate-choice`; that resolved 2026-09-01 — decode seam is bacnet-rs 0.3.1)
- **Blocks**: (none)

## Question

Exactly which BACnet services and PDUs must the decoding seam understand so the 10 detectors (from `001`/`003`) have everything they need — nothing more?

Once the 10 issues are known (duplicate IDs need I-Am; broadcast storms need packet-level timing and addressing; retransmissions need APDU/sequence data; unresponsive devices need request→no-response mapping) and the decode approach is chosen (`004`), decide the minimal decode surface: which BVLC functions, NPDU/APDU layers, and which service choices (confirmed/unconfirmed, Who-Is/I-Am, ReadProperty/Response, etc.) are in scope, and explicitly what is not decoded (segmentation unless a detector needs it, alarm/event, etc.).

## Deliverable

An agreed decode-scope contract: the typed record stream produced for detectors, and the explicit out-of-scope decode surface.
