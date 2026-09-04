# CONTEXT

A glossary of the domain terms for the BACnet Pcap Health Check project. Implementation-free.

## Core terms

- **BACnet** — Building Automation and Control Networks, ASHRAE Standard 135. The building-automation protocol the tool analyses.
- **Capture / pcap** — A recording of network packets. The tool's input. Two file formats in scope: classic `.pcap` and `.pcapng`.
- **BACnet/IP** — The variant of BACnet that rides over UDP, default port 47808. The only link layer in scope for this effort.
- **Device** — An addressable BACnet node on the network, identified by its device instance number and/or IP address. The unit the tool reasons about and reports against.
- **Finding** — A detected problem: one issue instance on the network, with severity, affected device(s), evidence, and remediation steps. The unit of output from detection.
- **Issue** — A category of network problem the tool is built to detect (e.g. duplicate device ID, broadcast storm). Currently scoped to a chosen top 10.
- **Remediation** — The prescriptive "steps to improve" text a finding carries, aimed at a field engineer.
- **Report** — The aggregated set of findings, shaped for output as a PDF.

## Seams (the analysis pipeline)

- **Pcap parsing** — Turning capture bytes into a stream of packets. Input is pcap/pcapng; output is packets.
- **BACnet decoding** — Turning BACnet/IP packets into typed, decoded protocol records. Input is packets; output is decoded records.
- **Issue detection** — Turning decoded records into findings. Input is decoded records; output is findings.
- **PDF generation** — Turning findings into the delivered PDF. Input is the report; output is bytes/PDF.

These are the four testable seams of the system.

## Service-layer terms (may appear in decode scope)

- **Who-Is / I-Am** — The BACnet discovery handshake: a device asks "who is out there" and devices answer "I am (device #X)". Relevant to duplicate-ID detection.
- **ReadProperty / ReadPropertyMultiple** — Services that read a device's object properties. Relevant to addressing and responsiveness.
- **APDU** — Application-layer protocol data unit, the payload of a BACnet message.
- **NPDU** — Network-layer protocol data unit, the routing header.
- **BVLC** — BACnet Virtual Link Control, the BACnet/IP encapsulation header.
- **Invoke ID** — The correlation token carried by confirmed BACnet services: a request and its response, abort, or reject share it. Detection correlates exchanges on it.
- **Directed Who-Is** — A unicast Who-Is sent to one specific device. A unicast I-Am answering a directed Who-Is is correct; a unicast I-Am answering broadcast context is the violation unicast-I-Am detection targets.
- **Evidence floor** — The minimum number of relevant messages (and, for rate-based rules, capture span) a detection rule requires before it may produce a finding. Below the floor the rule stays silent.
- **Broadcast context** — A frame sent to the limited broadcast address, or to a subnet-directed broadcast address inferred from the capture's own address population. I-Am and Who-Is behaviour is judged against it.
