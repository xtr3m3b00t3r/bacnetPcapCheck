# First capture to first report

This tutorial shows you how to make your first BACcheck report. You need a BACnet/IP capture file. The file must end in `.pcap` or `.pcapng`.

## 1. Install BACcheck

Download the `baccheck` binary for your system. Put it on your PATH.

## 2. Run BACcheck on your capture

Open a terminal. Run this command:

```text
baccheck plant-floor-chiller-loop.pcapng
```

BACcheck reads the file. It writes a report next to it, named `plant-floor-chiller-loop.baccheck.html`. It also prints one summary line that gives the number of findings.

## 3. Open the report

Open the report file in a web browser. The top of the report states the number of findings. Read the summary first.

## 4. Work the fix list

1. Find the fix list below the summary.
2. Start at the top row. Rows are ordered by severity, most severe first.
3. Open a finding to see its detail: affected devices, evidence, and steps to fix it.
4. Mark a row done when you finish it.

You made your first report. See [Read a finding](howto-read.md) for what each part of a finding means.

On the first run, BACcheck also prints a short notice about the licence. It prints the notice once.
