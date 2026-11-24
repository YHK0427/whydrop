# Changelog

All notable changes. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Fixed
- The 6 h, 24 h and 7 d charts were empty for the first 7 days: 1-minute aggregates were only made from 1-second rows older than 7 days. They are now made as data comes in, 5 minutes behind, and the long views read them together with the latest 1-second rows, counting each second once.
- An in-home queueing verdict was shown as "Internet line dropped" with the line drawn cut. Queueing (R7) is now shown as slowing down, and in-home queueing names the home network and marks the Wi-Fi or cable hop, in the dashboard, alerts and the copied summary.
- The Korean dashboard and summary showed the *In protocol terms* paragraph and evidence values (upload, download) in English. New drops store the paragraph in both languages; drops recorded before keep the English one.
- The public demo's protocol page said packets appear once precision mode is on, with a pause button and an empty table. It now says the demo has no packets and links the protocol document.
- NAT chart: the UDP label could sit on the TCP line.
- Korean text wrapped inside words (for example "(추 / 정)"), and table headers stacked on a phone.
- `[nat] enable_7500 = true` was read but ignored: `whydrop nat-test` and the dashboard's NAT test now include the 7500 s TCP delay when it is set.
- Alert titles now name the agent (`agent_name`, `WHYDROP_AGENT_NAME`), as the example config said they did. Compose passes `WHYDROP_AGENT_NAME` through.
- The packet strip and events were never deleted, and 1-minute aggregates grew forever. They are now kept 90 days (strip, events) and a year (minutes), as documented.
- `whydrop replay --set STREAM_LOSS_S=…` had no effect (the 2 s was hard-coded); the unused `TIMEOUT_S` is gone, and three thresholds that lived outside `constants.py` (`LOSS_MIN_SENDS`, `WEAK_MIN_SAMPLES`, `ROAM_LOSS_WINDOW_S`) can now be set too.
- `[intervals] link` was accepted and ignored (the link check runs every second by design); it is now rejected as an unknown key.
- Alerts can be in Korean (`[notify] lang = "ko"`), with the dashboard's wording; the Korean summary and the public demo's Korean copy button no longer mix in English cause labels. An ntfy title with a non-ASCII or multi-line agent name no longer fails to send.
- The config now refuses values that parsed but misbehaved: `udp_stream.pps` outside 1–100 and intervals outside 0.5–3600 s (which could hammer the router or public servers), a `notify.format` typo (alerts silently went out as JSON), non-http(s) alert URLs, target or `web.bind` ports outside 1–65535, a negative `storage.min_free_mb` and an `agent_name` over 64 characters.
- An empty host, port 0 or an IPv6 address in `reflector` now turns precision mode off with the reason, as `host:abc` already did, instead of starting precision mode against an address it can't use (the sockets are IPv4).
- A test reflector could fail to start on Windows, where TCP port blocks inside the UDP ephemeral range are reserved.

## [0.1.0] - 2026-11-23

First release.

### Added

**Agent (basic mode)**
- Probes every second over TCP and UDP: router check (TCP RST from a closed port; ICMP echo on Windows), line heartbeat (STUN, rotating providers), DNS over UDP and TCP to the router, the ISP's resolvers and public resolvers, STUN mapped address, TCP connect to port 443.
- Wi-Fi and link state from `iw`, `netsh` (English and Korean) and `/sys`: re-associations, roams, signal, carrier.
- Environment detection and a self-check; watches for network changes every 5 s; refuses to run in a VM-backed Docker.
- SQLite storage with 1-second and 1-minute aggregates, retention and a disk guard. About 19 MiB of memory, under 8 kbit/s.

**Precision mode**
- Reflector on UDP+TCP 48100 with HMAC on every packet, replay tombstones that survive restarts, rate limits before and after the HMAC, no amplification.
- udp_stream at 10 packets/s with per-packet upload/download attribution from `recv_count` and `rx_bitmap`.
- Hot TCP canary (stalls, retransmissions and RTO from `TCP_INFO` on Linux, RST vs. kernel timeout) and idle canary (NAT/firewall state loss).
- `whydrop nat-test`: UDP mapping and TCP idle timeouts, all delays in parallel, with a keepalive recommendation.

**Analysis**
- Per-second segment states (host network, Wi-Fi, cable, router, line, three DNS classes) with provider quorum and a lossy-period gate.
- Incidents with merging and point events; conditions and rough patches; prioritised cause rules R1a–R7 with queueing-first; provisional and final (80 s) causes.
- `whydrop replay` re-runs the analysis over a recorded database, with `--set` to try other thresholds.
- Verdicts checked by replaying the first days of real data from a home server: late replies count as having crossed the router, queueing before the router is in-home queueing, and loss the router checks share is home-network loss rather than the line.

**Dashboard and exports**
- Now, Drops, NAT timeouts, Protocol and My network pages; English and Korean; light and dark; phone-sized.
- Token, Host allowlist, strict CSP; public view (`?public=1`) that hides addresses and makes times relative.
- CSV/JSON exports, copyable summary, card image, public bug report; webhooks (json, ntfy, discord) with retries; Uptime Kuma push.
- `whydrop export-static`: a read-only public demo of the dashboard.

**Project**
- Wireshark Lua dissector for both protocols (`contrib/wireshark`).
- CI on Linux (Python 3.11–3.13) and Windows, browser tests with accessibility checks, dissector and image smoke tests, secret scanning.
- Multi-arch images (amd64, arm64, armv7) with SBOM and provenance on release.
