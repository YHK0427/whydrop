# Wireshark dissector for whydrop

**English** | [한국어](README.ko.md)

`whydrop.lua` decodes the agent ↔ reflector traffic described in [docs/protocol](../../docs/protocol.md): WD packets over UDP and the WT handshake and frames over TCP, with every field named as in that document. The 8-byte MAC is shown as bytes; it is not checked, because the secret isn't in the capture.

## Install
1. In Wireshark, open **Help → About Wireshark → Folders** and note **Personal Lua Plugins**.
2. Copy `whydrop.lua` there and restart Wireshark (or press Ctrl+Shift+L to reload Lua plugins).
3. Filter with `whydrop`. The default port is 48100; change it under **Preferences → Protocols → WHYDROP**. WD packets on other UDP ports are found by their shape (44 bytes starting with `WD`).

With tshark: `tshark -X lua_script:whydrop.lua -r capture.pcap -Y whydrop`.

## What to look at
- A drop in precision mode: PROBEs keep going out while ECHOs stop; the first ECHO after the gap shows `recv_count` and `rx_bitmap`, which is how whydrop tells upload loss from download loss.
- The hot connection: `HB` once a second, and during a drop the kernel's retransmissions of the same `HB` with growing gaps (the RTO doubling).
