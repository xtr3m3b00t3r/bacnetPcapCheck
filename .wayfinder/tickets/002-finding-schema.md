# 002 - The Finding schema

- **Type**: `wayfinder:grilling`
- **Status**: open
- **Claimed by**: (unclaimed)
- **Blocked by**: `001-top-10-issues`, `004-bacnet-crate-choice`
- **Blocks**: `003-issue-detection-rules`, `005-pdf-report-shape`

## Question

What does a machine-readable `Finding` look like at the detection→PDF seam? The 10 issues (from `001`) define the vocabulary of canonical issue ids and severities; the decoder (from `004`) defines the device/address model. Design the `Finding` struct: canonical issue id, severity, affected device(s) identified by which key, the evidence summary, and the prescriptive remediation steps (canned text referencing the issue, device, and IP).

Also settle the `Report` model: how findings aggregate (grouped by device? by issue? ordering by severity?), and what the PDF shaper consumes (findings → ordered sections). This object lives in the library as the typed contract between detection and report generation.

## Deliverable

An agreed `Finding`/`Report` schema (types written out or prototyped), recorded as the decision on this ticket.
