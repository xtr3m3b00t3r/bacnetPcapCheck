# Why evidence floors exist

A short or quiet capture can look the same for a healthy network and for a network with an intermittent problem. There is not enough evidence to tell the two apart.

Evidence floors stop BACcheck from guessing in that gap. A rule stays silent and does not raise a finding that it cannot support. Each finding in a report has enough evidence to act on.

The cost is that BACcheck can miss a real problem that is rare, or that does not show in a short capture. An empty report is not proof of a healthy network. If you suspect a problem, record a longer capture. See [Run a capture](howto-run.md).

For the rules themselves, see [Evidence-floor semantics](ref-floors.md).
