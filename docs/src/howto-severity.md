# Interpret severity

Use this guide to decide which findings to fix first.

1. Fix every Critical finding first. The network is badly affected now.
2. Fix High findings next. They degrade the network in normal use.
3. Schedule Medium findings for your next planned visit.
4. Note Low findings. Fix them when you work on the same device.

A rule can raise a severity when the evidence is stronger. A rule never lowers a severity below the worst evidence it saw. See [Severity levels](ref-severity.md).

The `--min-severity` flag hides lower findings in the report. It does not change the exit code.
