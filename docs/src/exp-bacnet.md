# BACnet/IP in brief

BACnet is a protocol that building-automation devices use to talk to each other. Examples are chillers, air handlers, and lighting controllers. BACnet/IP is the variant that runs over IP networks. It uses UDP port 47808 by default.

- **Discovery.** A device sends a Who-Is. Devices answer with an I-Am that gives their device instance number.
- **Requests.** A device reads or writes properties of another device with services such as ReadProperty. A confirmed request carries an invoke ID. The answer, abort, or reject carries the same invoke ID.
- **Broadcast management.** A BBMD (BACnet Broadcast Management Device) forwards broadcasts between IP subnets. It uses a BDT (Broadcast Distribution Table). A device on another subnet can register with a BBMD as a foreign device.
- **Routing.** A router passes messages between BACnet networks. It can reject a message for a network it does not reach.

BACcheck reads BACnet/IP only. It does not read MS/TP or BACnet/Ethernet.
