# Coding standards

Judgement calls only. Formatting, lints and tests are enforced by `.githooks/pre-commit` and CI.

## Detectors

- Tuning numbers live in `baccheck-core/src/detect/thresholds.rs`, one named, documented constant each. A detector file holds no magic numbers.
- Count time windows from the capture's first timestamp, never from the epoch. Real captures carry epoch timestamps, so epoch-aligned buckets split a burst depending on the capture clock and print meaningless offsets.
- A rate rule checks the capture span floor before anything else.
- Severity escalates on magnitude and never drops below the worst evidence in the run.
- Evidence carries at most five exemplar frames; aggregates go in the summary text.

## Tests

- Test detectors at the `fn(&[DecodeRecord], …) -> Vec<Finding>` seam with synthetic records. Build them from `tests/common/mod.rs`; add a builder there when a second test file wants it.
- Per detector: one fixture that fires, one below the evidence floor that stays silent, and the severity-escalation case.
