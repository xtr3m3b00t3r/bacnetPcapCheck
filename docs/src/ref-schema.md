# Finding & Report schema

## Finding

A finding is one issue against one set of devices. Findings of the same issue against the same devices merge into one finding. A finding has these fields:

| Field | Meaning |
| --- | --- |
| Issue id | One of the ten ids in the [Issue catalogue](ref-issues.md). |
| Severity | Critical, High, Medium, or Low. See [Severity levels](ref-severity.md). |
| Affected | Zero or more devices. Each has a device instance number, an IP address and port, or both. |
| Occurrences | The number of times BACcheck saw the issue. |
| Evidence | A summary text, and at most five example frame numbers. |
| First seen, last seen | The capture times of the first and last occurrence. |

The remediation steps are not stored in the finding. The report adds them from the issue table.

## Report

A report holds the findings, summary statistics, and a capture-health warning.

- Findings are ordered by severity (worst first), then issue, then device.
- The statistics give the total frames, and the shares that are decoded, undecoded, and not BACnet. They also give the capture time span.
- The capture-health warning shows when more than half of the capture is not decodable BACnet.
