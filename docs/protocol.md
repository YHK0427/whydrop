# whydrop wire protocol (v1)

**English** | [한국어](protocol.ko.md)

whydrop's agent talks to your own reflector on **port 48100**, over UDP (WD packets) and TCP (WT messages). This page is the byte-level reference; it is what the code in `src/whydrop/proto/` implements and what the Wireshark dissector decodes.

Conventions: every integer is **big-endian** (network order). IPv4 only. `HMAC8(k, m)` = the first 8 bytes of HMAC-SHA256 with key `k` over `m`. The key is the shared secret `WHYDROP_SECRET` (at least 32 bytes).

## Message sizes

| Message | Transport | Size |
|---|---|---|
| `WD` | UDP | 44 B |
| `NONCE` | TCP | 20 B |
| `HELLO` | TCP | 30 B |
| `HELLO_OK` | TCP | 16 B |
| `AUTH_FAIL` | TCP | 4 B |
| `VERSION` | TCP | 4 B |
| `BUSY` | TCP | 4 B |
| `FRAME` | TCP | 16 B |

## UDP: the WD packet

Every WD packet is exactly 44 bytes:

| Offset | Field | Size | Meaning |
|---|---|---|---|
| 0 | magic | 2 | `"WD"` |
| 2 | version | 1 | `1` |
| 3 | type | 1 | 1 = PROBE, 2 = ECHO, 3 = NAT_REQ, 4 = NAT_REPLY |
| 4 | session_id | 4 | Random per agent run; nat-test uses one per socket |
| 8 | seq | 4 | Send sequence number |
| 12 | t_send_ns | 8 | Agent's monotonic send time, echoed back unchanged |
| 20 | recv_count | 4 | ECHO: distinct PROBEs the reflector has received in this session |
| 24 | epoch | 4 | ECHO / NAT_REPLY: random reflector boot ID |
| 28 | rx_bitmap | 4 | ECHO: bit *i* (bit 0 = least significant) is set if seq − 1 − *i* was received |
| 32 | arg | 4 | NAT_REQ: delay in seconds. NAT_REPLY: 0 = immediate, 1 = delayed. ECHO: the reflector's own socket receive drops so far |
| 36 | hmac | 8 | `HMAC8(secret, bytes 0–35)` |

**PROBE → ECHO.** The agent sends PROBEs (10 per second in precision mode). The reflector answers each new seq with one ECHO carrying the same session_id, seq and t_send_ns.

**NAT_REQ → NAT_REPLY.** `arg` must be one of 10, 20, 30, 45, 60, 90, 120, 180, 300, 600. The reflector answers at once with NAT_REPLY(arg = 0), then again with NAT_REPLY(arg = 1) after the delay, to the address the request came from. If that second reply never arrives, a NAT or firewall on the path forgot the mapping before the delay ran out. A newer NAT_REQ in the same session replaces the pending one and restarts the delay.

### Which way was a packet lost?
For a seq that got no ECHO, look at the first later ECHO within 32 seqs. If its rx_bitmap has the bit for that seq set, the reflector got the PROBE and the ECHO was lost on the way **down**. If the bit is clear, the PROBE was lost on the way **up**. Further back than 32 seqs, the direction is unknown.

For a whole outage, take the last ECHO before it (*a*) and the first after it (*b*):
- upload lost = (seq_b − seq_a) − (recv_count_b − recv_count_a)
- download lost = (recv_count_b − recv_count_a) − ECHOs received for seqs in (seq_a, seq_b], ECHO_b included
- If only b's own PROBE got through, upload was 100% lost and download can't be measured.
- If the epoch changed or recv_count went backwards, the reflector restarted and the direction is unknown.

## TCP: handshake

The reflector speaks first:

| Message | Direction | Layout | Size |
|---|---|---|---|
| `NONCE` | reflector → agent | `"WT"` version(1) type=1 nonce(16) | 20 B |
| `HELLO` | agent → reflector | `"WT"` version(1) type=2 role(1) reserved(1) session_id(4) param_s(4) anonce(8) hmac(8) | 30 B |
| `HELLO_OK` | reflector → agent | `"WT"` version(1) type=3 epoch(4) hmac(8) | 16 B |
| `AUTH_FAIL` | reflector → agent | `"WT"` version(1) type=4, then close | 4 B |
| `VERSION` | reflector → agent | `"WT"` version(1) type=5, then close | 4 B |
| `BUSY` | reflector → agent | `"WT"` version(1) type=6, then close | 4 B |

- HELLO's hmac = `HMAC8(secret, nonce ‖ HELLO bytes 0–21)`. Because the nonce is fresh per connection, a recorded HELLO can't be replayed.
- HELLO_OK's hmac = `HMAC8(secret, anonce ‖ HELLO_OK bytes 0–7)`. `anonce` is 8 random bytes chosen by the agent, so the agent knows it is talking to its own reflector, not to something that took over the address.
- **role** and **param_s**:
  - 1 = hot: `param_s` must be 0.
  - 2 = idle: `param_s` is the ping interval, 30–7500 s.
  - 3 = nat: `param_s` is one of 60, 300, 600, 1200, 1800, 3600 (7500 only if the reflector was started with `--enable-7500`).
- A wrong version gets `VERSION`. A wrong MAC gets `AUTH_FAIL`. A `param_s` the reflector doesn't support gets `VERSION`. A connection that sends no complete HELLO within 5 s is closed.

## TCP: frames after HELLO_OK

Every frame is 16 bytes:

| Message | Direction | Layout | Size |
|---|---|---|---|
| `FRAME` | both | type(1) flags(1) reserved(2) seq(4) t_send_ns(8) | 16 B |

| type | Name | Direction | Use |
|---|---|---|---|
| 0x10 | HB | agent → reflector | hot: once per second |
| 0x11 | HB_ACK | reflector → agent | answer to HB with the same seq and t_send_ns |
| 0x20 | IDLE_PING | reflector → agent | idle: every `param_s` seconds, reflector first |
| 0x21 | IDLE_PONG | agent → reflector | answer to IDLE_PING |
| 0x30 | NAT_PROBE | reflector → agent | nat: sent once after `param_s` seconds, then the reflector closes |

The idle ping is sent by the reflector on purpose: if the agent spoke first, a NAT that had forgotten the connection could quietly re-learn it, and the loss of state would never show.

## What the reflector never does

- It never answers a packet whose MAC is wrong, and never creates state before the MAC checks out.
- A reply is never larger than the request (44 B for 44 B), and one NAT_REQ gets at most two replies.
- It drops ECHO and NAT_REPLY packets coming **in**, so it can't be made to reflect its own replies.
- Each (session, seq) is answered once. The highest seq per session is kept on disk for 7 days, so packets captured before a restart still get no answer.

## Limits

| What | Limit |
|---|---|
| UDP before the MAC check | 200 packets/s per source IP |
| UDP after the MAC check | 50 packets/s per source IP |
| Pending NAT_REQs | 1 per session, 16 per source IP, 1024 in total |
| TCP connections before HELLO | 4 per source IP, 64 in total |
| TCP connections after HELLO_OK | hot 1 and idle 1 per session (a newer HELLO replaces the older connection), nat 7 per session, 256 in total; over the cap → `BUSY` |
| Hot connection without HB | closed after 30 s |
