**English** | [한국어](how-it-works.ko.md)

# How whydrop works

This page explains what whydrop sends, what it learns from TCP and UDP, and how it turns that into "where did it break, and why". The byte-level wire format is in [protocol](protocol.md); the full rule tables are in [design](design.md).

## 1. What goes on the wire

Every probe is small and timed by when it was **sent**, so a reply that comes back late is still filed under the second it belongs to.

| Probe | Transport | Every | What it answers |
|---|---|---|---|
| Router check | TCP SYN to a closed port (RST = alive); ICMP echo on Windows | 1 s | Is the router reachable from this device? |
| Line heartbeat | UDP: STUN binding requests and a DNS query, rotating across providers | 1 s | Does a packet get through the internet line and back? |
| DNS | UDP and TCP queries to the router, the ISP's resolvers and public resolvers | 5 s | Which DNS layer answers? |
| STUN | UDP, two providers | 10 s | What is my public IP and mapped port? |
| TCP connect | TCP handshake to port 443 of large public services | 2 s | Does a full TCP handshake complete, and how long does it take? |
| Wi-Fi / link | the OS (`iw`, `netsh`, `/sys`) | 1–2 s | Associated? Which access point? Signal? Carrier? |
| udp_stream (precision) | UDP to your reflector | 0.1 s | Which packets are lost, and on the way up or down? |
| Hot canary (precision) | one TCP connection to your reflector | 1 s | What does TCP do during a drop? |
| Idle canary (precision) | one silent TCP connection | 10 min (configurable) | Does a NAT forget an idle connection? |

Total traffic stays under 8 kbit/s in basic mode and 20 kbit/s in precision mode (checked by the test suite).

## 2. What UDP tells you

UDP has no connection and no retransmission: a lost datagram is simply gone. That makes it the honest witness of the path.

- **Loss, per second.** Each udp_stream packet carries a sequence number. The reflector answers each one with an ECHO that says how many packets of this session it has received so far (`recv_count`) and which of the previous 32 it saw (`rx_bitmap`).
- **Upload or download.** For a packet that got no ECHO, if a later ECHO's bitmap shows the reflector *did* receive it, the ECHO was lost on the way **down**; if not, the packet was lost on the way **up**. For a whole outage, the change in `recv_count` across the gap gives the totals: everything the reflector didn't count was lost going up.
- **Replay protection.** Every packet carries an HMAC with your secret, and the reflector answers each sequence number once (and remembers the highest one across restarts), so the reflector can't be used to bounce traffic at someone else.
- **NAT behaviour.** STUN shows your public address and mapped port; a change in either is a public-IP change or a NAT state reset. `nat-test` asks the reflector to answer *after* a delay: if the late answer never arrives, a NAT on the path forgot the mapping.

## 3. What TCP tells you

TCP hides loss from applications by retransmitting, which is exactly why it is worth watching.

- **The handshake.** A TCP connect probe measures SYN → SYN-ACK time; a closed router port answering with RST proves the router is alive without any service running on it.
- **Stalls and retransmission.** During a drop the hot canary's heartbeats stop being acknowledged. On Linux, the kernel's `TCP_INFO` shows the retransmission timeout (RTO) doubling — 0.2, 0.4, 0.8, 1.6 s — and how many segments are unacknowledged. When the line comes back, the first acknowledgement arrives only when the next retransmission fires, which is why TCP applications feel a drop longer than it was.
- **Reset or survive.** If the drop is short, the connection survives (no RST). If a NAT or the reflector forgot the connection, the next segment gets an RST. If the drop lasts long enough, the kernel gives up on its own (Windows reports this as an abort, which whydrop records as a kernel timeout, not as an RST).
- **Idle state.** The idle canary stays silent for minutes and lets the reflector speak first. If that ping never arrives, something on the path dropped the connection's state while it was quiet.

## 4. From probes to a verdict

Every second (about 14 seconds behind real time, so late replies are counted) the analysis decides the state of each hop:

1. **This device**: no address or default route for 3 s.
2. **Wi-Fi or cable**: disassociated, no access point, re-association, carrier lost.
3. **Router**: two router checks in a row unanswered — *and* nothing answered from the internet through the router in those seconds.
4. **Internet line**: every line probe sent in the last few seconds failed, across **at least two independent providers** and at least three sends. Router DNS and ISP DNS never vote here: they can answer from cache while the line is down.
5. **DNS**: every resolver of one kind (router, ISP, public) failed at least twice while the line was fine.

A hop that goes down opens a **drop**. Drops that follow each other closely are merged (a router reboot is one drop, not three). Some things are drops without any hop going down: a public IP change, an idle connection forgotten by a NAT, a NAT state reset.

Then **rules in priority order** name the likely cause (Wi-Fi first, then cable, this device, router, public IP change, NAT, DNS, the ISP line; queueing is checked before blaming the router or the line). The cause is provisional while the drop is open and becomes final 80 s after it ends, when late evidence (such as a public-IP change seen a minute later) has arrived.

**Things that are not drops:** random packet loss is a *rough patch*, not an outage — a short failure inside a period of ongoing loss is treated as part of it, which keeps a lossy line from producing dozens of fake drops an hour. The agent's own host being busy, or asleep, is excluded from every decision.

## 5. Where to see each idea

whydrop was built as a networking course project; these are the course topics it puts on screen.

| Topic | In whydrop | Where to see it |
|---|---|---|
| Delay, loss, throughput | RTT, loss and traffic per probe | Now: the latency and loss lanes; `/api/status` |
| DNS | DNS over UDP and over TCP (2-byte length prefix), CHAOS queries, the router → ISP resolver chain | DNS causes and their evidence; My network (excluded resolvers) |
| UDP and reliability built on top | sequence numbers, `recv_count`, `rx_bitmap`, replay protection | The packet strip in a drop; Protocol tab |
| Multiplexing, sequence/ack numbers, RTT and timeouts | one port for UDP and TCP; RTO backoff from `TCP_INFO`; keepalive recommendations | TCP lane; *In protocol terms*; NAT timeouts |
| The 3-way handshake | handshake RTT; router liveness from an RST | TCP connect samples; router state |
| Router queueing | the queueing rule (latency ≥ 3× the usual + 50 ms before a drop) | Queueing causes; rough patches |
| IP, NAT | public IP change, STUN mapped address, NAT idle timeouts | NAT timeouts; public-IP-change drops |

## 6. Seeing it in Wireshark

[`contrib/wireshark/whydrop.lua`](../contrib/wireshark/README.md) decodes every field of both protocols. During a drop in precision mode you can watch PROBEs go out unanswered, the first ECHO after the gap carry the counters that split upload from download, and the kernel retransmit the same heartbeat at growing intervals.
