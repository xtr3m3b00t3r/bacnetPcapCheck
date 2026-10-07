# How the detectors work

BACcheck has ten detectors. Each detector is an independent function. It reads the decoded BACnet records of the capture in time order. It gives zero or more findings.

A detector keeps its own state while it reads. For example, a detector that checks requests keeps a table of requests that wait for an answer. That state expires. A request that gets no answer within its window closes. A repeat after that starts a new exchange. This matters because the invoke ID of a confirmed request has only 8 bits, and devices reuse it.

Detectors do not share state. This keeps each detector simple to test on its own with a synthetic capture.

After all detectors run, BACcheck merges findings of the same issue and device set. It orders them and builds the report. A frame that BACcheck cannot decode is not dropped. It is counted, and it appears in the capture statistics.

See [Evidence-floor semantics](ref-floors.md) for when a detector stays silent.
