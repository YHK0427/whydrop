# Changelog

All notable changes. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased] — 0.1.0

First release.

### Agent (basic mode)
- Probes every second over TCP and UDP: router check (TCP RST from a closed port; ICMP echo on Windows), line heartbeat (STUN, rotating providers), DNS over UDP and TCP to the router, the ISP's resolvers and public resolvers, STUN mapped address, TCP connect to port 443.
- Wi-Fi and link state from `iw`, `netsh` (English and Korean) and `/sys`: re-associations, roams, signal, carrier.
- Environment detection and a self-check; watches for network changes every 5 s; refuses to run in a VM-backed Docker.
- SQLite storage with 1-second and 1-minute aggregates, retention and a disk guard. About 19 MiB of memory, under 8 kbit/s.

### Precision mode
- Reflector on UDP+TCP 48100 with HMAC on every packet, replay tombstones that survive restarts, rate limits before and after the HMAC, no amplification.
- udp_stream at 10 packets/s with per-packet upload/download attribution from `recv_count` and `rx_bitmap`.
- Hot TCP canary (stalls, retransmissions and RTO from `TCP_INFO` on Linux, RST vs. kernel timeout) and idle canary (NAT/firewall state loss).
- `whydrop nat-test`: UDP mapping and TCP idle timeouts, all delays in parallel, with a keepalive recommendation.

### Analysis
- Per-second segment states (host network, Wi-Fi, cable, router, line, three DNS classes) with provider quorum and a lossy-period gate.
- Incidents with merging and point events; conditions and rough patches; prioritised cause rules R1a–R7 with queueing-first; provisional and final (80 s) causes.
- `whydrop replay` re-runs the analysis over a recorded database, with `--set` to try other thresholds.

### Dashboard and exports
- Now, Drops, NAT timeouts, Protocol and My network pages; English and Korean; light and dark; phone-sized.
- Token, Host allowlist, strict CSP; public view (`?public=1`) that hides addresses and makes times relative.
- CSV/JSON exports, copyable summary, card image, public bug report; webhooks (json, ntfy, discord) with retries; Uptime Kuma push.
- `whydrop export-static`: a read-only public demo of the dashboard.

### Project
- Wireshark Lua dissector for both protocols (`contrib/wireshark`).
- CI on Linux (Python 3.11–3.13) and Windows, browser tests with accessibility checks, dissector and image smoke tests, secret scanning.
- Multi-arch images (amd64, arm64, armv7) with SBOM and provenance on release.
