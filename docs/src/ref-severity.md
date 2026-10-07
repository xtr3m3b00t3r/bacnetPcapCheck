# Severity levels

BACcheck uses four severity levels. From worst to least: Critical, High, Medium, Low.

- Each issue has a base severity. See [Issue catalogue](ref-issues.md).
- A rule raises the severity when the evidence is larger. Examples are more devices involved, a higher message rate, or a higher share of failed exchanges.
- A severity never drops below the worst evidence in the run. When findings merge, the merged finding keeps the highest severity.
- `--min-severity` hides findings below a level in the report. It does not change the exit code. A finding of any severity gives exit code 1.
