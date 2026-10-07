# Evidence-floor semantics

An evidence floor is the least evidence a rule needs before it can raise a finding. Below the floor, the rule stays silent.

- A floor is a count of relevant messages. Examples are confirmed requests sent by one device, or broadcasts sent by local hosts.
- A rate-based rule also needs a capture of at least 5 minutes. The rule checks this before it checks anything else.
- Rate rules count time in fixed buckets, measured from the first frame of the capture. They do not use the clock time of the capture.
- A ratio rule needs a minimum number of judged exchanges before it reads the ratio.
- A finding carries at most five example frames. The evidence text gives the totals.

## Floors in use

| Rule | Floor |
| --- | --- |
| Rate-based rules | A capture of at least 5 minutes. |
| Broadcast saturation | At least 200 decoded BACnet messages. |
| Unresponsive device | At least 10 confirmed requests received by the device. |
| Incomplete BDT | At least 50 broadcasts sent by local hosts. |
| Segmentation misuse | At least 3 abandoned exchanges for one pair. The ratio needs 10 judged exchanges. |
| Unicast I-Am | At least 10 I-Ams sent by the device. |
| Confirmed-service retransmission | At least 10 confirmed request frames sent by the sender. |

Each tuning number is one named constant in the BACcheck source. See [Why evidence floors exist](exp-floors.md) for the reason.
