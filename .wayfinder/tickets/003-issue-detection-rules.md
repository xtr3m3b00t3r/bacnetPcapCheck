# 003 - Issue detection rules

- **Type**: `wayfinder:grilling`
- **Status**: open
- **Claimed by**: (unclaimed)
- **Blocked by**: `001-top-10-issues`, `002-finding-schema`
- **Blocks**: `005-pdf-report-shape`

## Question

For each of the 10 issues from `001`, what is the exact detection rule — the predicate over decoded traffic that turns a stream of decoded BACnet/network data into a finding of a given severity, with the threshold that separates "healthy" from "problem"?

The decoder (from `004`) yields a stream of typed records; this ticket decides how each detector runs over that stream (per-packet against rolling state? whole-capture aggregates?) and pins the concrete thresholds and what constitutes evidence worth reporting. TDD orienting: each rule should be expressible as a function `(stream of decoded data) -> Vec<Finding>` testable against fixture captures.

## Deliverable

An agreed detection-rule spec: per issue, the predicate, the thresholds, the evidence carried into the `Finding`, all testable.
