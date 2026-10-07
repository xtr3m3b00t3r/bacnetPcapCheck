# Run a capture

Use this guide to record a BACnet/IP capture that BACcheck can read.

1. Connect your laptop to the BACnet/IP segment you want to check.
2. Start your capture tool. Filter on UDP port 47808.
3. Record for at least 5 minutes. Rate-based rules need this much time before they raise a finding. See [Evidence-floor semantics](ref-floors.md).
4. Stop the capture. Save it as `.pcap` or `.pcapng`.
5. Run `baccheck` on the file. See [CLI flags](ref-cli.md).

If more than half of the capture is not decodable BACnet, the report shows a capture-health warning. Capture again with a BACnet/IP filter.
