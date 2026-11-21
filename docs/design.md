**English** | [한국어](design.ko.md)

# Design

The rules whydrop uses to decide, with every threshold. All thresholds live in `src/whydrop/analysis/constants.py`, and `whydrop replay --set NAME=VALUE` re-runs the analysis over a recorded database with a different value, so a rule can be tested against real history before it changes. For the ideas behind the rules, read [how-it-works](how-it-works.md) first.

## What whydrop will not do

- Become an uptime monitor.
- Be useless without a reflector: basic mode needs no server.
- State a cause as certain. Every cause reads "likely" (a test checks every string).
- Invent drops. Specifically not: a target that was never reachable, a single dying target, the agent's own host stalling, the reflector alone being down, normal Wi-Fi roaming, a VPN tunnel mistaken for the line, Docker Desktop's VM network mistaken for the home network.
- Become an amplifier: the reflector never answers more bytes than it received.
- Disturb other services on a shared server, or use more than 8 kbit/s (basic) / 20 kbit/s (precision) in total.

## Pipeline

1. **Samples**, keyed by send time. Every probe keeps listening up to 10 s past its timeout, so late replies are counted as late, not lost.
2. **Frames**: one per second, built 14 s behind real time, once nothing can still change them.
3. **Segment states**, decided per frame (below).
4. **Incidents** open when a segment goes down; some open as points without any segment going down.
5. **Conditions** (loss, latency, weak signal, Wi-Fi/LAN loss, busy host): lasting over 30 s they become *rough patches*. They label patches; they never open incidents on their own.
6. **Causes**: provisional while open; final 80 s after the end (R4's 60 s window plus two STUN intervals), or 120 s when this device, Wi-Fi, the cable or the router was down, so a line drop that follows can still join it (see Merging); then frozen. Whether the final differs from the provisional is stored.

An incident's end is the first success that counts as recovery; for the line, the first success of a basic line-quorum probe — never the canary, whose TCP retransmission timer makes it recover late, and never udp_stream.

## Segments

| Segment | Down | Recovered |
|---|---|---|
| `host_net` | no IPv4 address or no default route on the egress interface for 3 s (sends fail locally) | address and route back, held 3 s |
| `wifi` | not up, no BSSID, or a re-association | up with a BSSID, held 3 s |
| `link` (wired) | carrier lost or a link flap | carrier back, held 3 s |
| `lan` | 2 consecutive router checks unanswered, while Wi-Fi or the cable is up, **and no line-quorum probe got an answer through the router in that frame**. If the router never answered during the self-check, `lan` is *unobservable*: the line is judged without it, and router and line causes read "router or line (can't separate)" | 1 reply from the router, or any line-quorum reply |
| `line` | `lan` fine or unobservable, **every** line-quorum probe sent in [T−3 s, T−its timeout] failed, across **≥ 2 providers and ≥ 3 sends**. The start is back-dated to the first failed send. udp_stream ≥ 80 % loss for 2 s counts only if basic line-quorum probes failed too | line-quorum successes for 3 s |
| `dns_router` / `dns_isp` / `dns_public` | every UDP resolver of that class attempted in the window failed, ≥ 2 attempts each, while the line is fine. Window = 3 × the class's interval. Only attempts sent after the last lan/line recovery count. TCP DNS is evidence only | 1 success |

**Line-quorum probes**: line heartbeat, STUN, public DNS (UDP and TCP), TCP connect, and in precision mode udp_stream and the hot canary. Router DNS and ISP DNS never count. The reflector is one provider; two addresses of the same company are one provider.

**Local vs. remote errors**: a send error is local only when the route table has no route for it (→ `host_net`). Errors reported back by the network with a route present (host unreachable, refused, administratively prohibited) are failures with the evidence "router reported unreachable".

**The lossy-period gate**: if line heartbeat loss over the 60 s before a line-down start was ≥ 5 %, a down that recovers within 10 s is not an incident; it is a burst inside the loss condition. In a simulation (basic mode, 1 h per point), random loss of 5 / 10 / 20 / 30 % per direction produced 3 / 19 / 106 / 127 false line drops an hour without the gate and 0 / 0 / 2 / 0 with it, while 400 of 400 three-second blackholes on a clean line were caught either way.

**Why the router rule needs the line too**: on a Wi-Fi host, power save and contention can delay the router check past its 1.5 s timeout twice in a row while the internet keeps answering through the same router. Replaying 10 hours recorded on a real Wi-Fi home server, requiring that nothing answered through the router removed 18 of 32 drops, all 2–7 s "router" drops during which line probes were succeeding.

**Busy host**: failures whose timeout window overlaps a measured event-loop lag (`agent_lag`) are excluded from every decision. After the host resumes from sleep, nothing is decided for 30 s.

## Conditions

| Condition | Criterion |
|---|---|
| Loss | udp_stream ≥ 5 % over 30 s; in basic mode, line heartbeat ≥ 5 % over 60 s |
| Latency | over 30 s, ≥ 2 providers at ≥ 3× baseline and ≥ +50 ms (RTT from TCP connect, STUN, line heartbeat, udp_stream, canary; never DNS) |
| Weak signal | ≤ −75 dBm and ≥ 10 dB below the 1-hour median |
| Wi-Fi/LAN loss | associated, but ≥ 10 % of router checks failing over 60 s |
| Busy host | event-loop lag p95 ≥ 10 ms |

**Baseline** for latency: per probe target, the 10th percentile over the last 24 h, excluding incidents. Not evaluated in the first hour; "learning" between 1 and 24 h.

## Merging

- A segment down starting within 10 s of the previous incident's end joins it.
- A line down starting within 120 s of a Wi-Fi, cable or router recovery joins that incident; with the router down, it reads "router restart (likely)".
- Past 1 h an incident is marked a long outage.
- Gaps in recording (from the agent's 30 s heartbeat) show as "not recording"; incidents left open by a restart are closed and tagged.

## Cause rules

In priority order; windows are anchored on the incident start unless a rule says otherwise.

| # | Likely cause | Condition | What to do next |
|---|---|---|---|
| R1a | Wi-Fi problem | wifi down, a re-association or a roam within [start − 5 s, start + 15 s] | If the signal was weak, move the AP or change channel. If the AP vanished, check its power or reboot it |
| R1c | Wired link problem | link down or flap within ±5 s of the start | Check the cable and the switch port |
| R1d | Host network config lost | host_net down (address or route gone while the link is up) | Restart the host's network service; if it repeats, check DHCP leases |
| R1b | Router problem | lan down, Wi-Fi/cable up. Not evaluated when link state is unknown or egress is a VPN | Reboot the router; if it repeats, attach the records |
| R4 | Public IP change | during the incident or within 60 s after it, both STUN providers report the same new IP twice in a row. Also a point incident on its own | Your ISP reassigned your IP; if it happens often, contact them with the records |
| R5 | NAT/firewall state lost | the idle canary's ping never arrived while the hot connection and udp_stream lost nothing around it → point incident. "Expiry" if the idle interval exceeded the measured timeout, otherwise "loss". Also: an RST on the hot canary with a NAT mapping reset within ±10 s and no IP change → "NAT state reset" | Set keepalive below the timeout nat-test measured. For a reset: look for router or CGNAT restarts |
| R3 | DNS failure | a DNS segment down while the line is fine. Router only → router DNS. ISP only → ISP DNS. Router + ISP with public fine → ISP DNS outage. Public only → public resolvers blocked on this network. Public together with another class → DNS-wide | Switch your device or router to a public DNS |
| R2 | Line drop (ISP segment) | line down, lan fine, egress not via a VPN. Upload/download split added after settling | Save the evidence with export and contact your ISP |
| R6 | Lossy line | labels a loss rough patch. "Line" in basic mode, or in precision mode when line heartbeat loss is ≥ 2.5 % too; otherwise "path to the reflector" | Save the evidence and contact your ISP |
| R7 | High latency (queueing) | labels a latency rough patch; also the primary cause of a router or line drop under the queueing-first rule below | Enable SQM (cake/fq_codel) on the router, or limit uploads |
| — | Unknown | none of the above | File a "wrong diagnosis" issue with the bug report attached |

**Queueing first**: before R1b, R2 or R6, if successful samples in the previous 10 s were ≥ 3× baseline and ≥ +50 ms, or at least half the failures behind a line down came back late, R7 is the primary cause ("queueing → timeouts"); with the router's RTT rising too, "in-home queueing".

Examples: a PPPoE redial → R4 with R2 as secondary. A router reboot seen over Wi-Fi → one incident, R1a, with the WAN coming back later joining it as "router restart (likely)". A saturated uplink → R7.

## Security

- **UDP**: before any hashing, packets that aren't 44 bytes with the right magic, version and a request type are dropped, and each source IP is limited to 200 packets/s. A bad HMAC is dropped without a reply. Replies are never larger than the request, and one NAT_REQ gets at most 2 replies. After the HMAC, 50/s per source IP.
- **Replay**: each sequence number is answered once. The highest sequence per session is kept for 7 days on disk (flushed every 10 s), so replaying captured packets gets nothing, also after a restart; after a crash, packets from the last ≤ 10 s could be answered once (a known limit).
- **TCP**: a nonce challenge before anything is accepted, and connection caps.
- **Secret**: `WHYDROP_SECRET` from the environment only, ≥ 32 bytes; example values refuse to start. Never logged, never exposed by the API. Basic mode needs no secret.
- **Agent**: checks the HMAC, session and source of every ECHO and NAT_REPLY.
- **Dashboard**: a token (Bearer header or WebSocket subprotocol, never a cookie), a custom header on every request that changes something, a Host allowlist against DNS rebinding, a strict Content-Security-Policy, and the public view for anything that leaves the machine.
- **Known limit**: an attacker on the path can inject an RST and fake R4 or R5. That is one more reason every cause says "likely".

To report a vulnerability, see [SECURITY](../SECURITY.md).

## Storage

SQLite in WAL mode, committing every 5 s (less wear on SD cards).

- 1-second aggregates are kept 7 days, then rolled up into 1-minute aggregates.
- The 1-second data within ±10 min of an incident, and its packet strip (±60 s), are kept 90 days.
- When free space drops below min(2 GB, 5 % of the volume), writing stops and the log says so (`storage.min_free_mb` overrides the threshold).
- `whydrop replay` re-runs the analysis over the 1-second aggregates and events, so it covers about the last 7 days, and prints the incidents; it never writes to the database. Its results are approximate.
