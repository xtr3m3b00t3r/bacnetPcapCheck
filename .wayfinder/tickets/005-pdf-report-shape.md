# 005 - The PDF report shape

- **Type**: `wayfinder:prototype`
- **Status**: open
- **Claimed by**: (unclaimed)
- **Blocked by**: `002-finding-schema`, `003-issue-detection-rules`
- **Blocks**: (none)

## Question

What does the delivered PDF look like? The `Report` model (from `002`) and the populated findings (from `003`) must render into a field-engineer-facing document whose structure leads a reader from "here's what's wrong" to "here's exactly what to do".

Prototype the document layout with realistic placeholder findings: a summary page (severity-ranked issue list), then per-finding detail pages (affected device/IP, evidence, concrete remediation steps). Decide on the PDF library (genpdf/printpdf surfaced in charting) and whether the layout is section-per-finding or table-driven. The output must be readable by a non-specialist field engineer.

## Deliverable

A rendered prototype PDF (with realistic fake findings) and an agreed document structure this ticket records.
