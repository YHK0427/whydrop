# Changelog

All notable changes. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [0.6.1] - 2026-11-25

### Changed
- `export-static` includes the ISP report, so the public demo opens the report page too (Save as PDF works there; the text download needs a live agent).

## [0.6.0] - 2026-11-25

### Added
- The ISP report is a printable page (#/isp): one sentence that sums it up, the month as days recorded with event marks, and each event as a pair of bars in path order, the router at that moment next to what was lost beyond it. "Save as PDF" prints it on A4; "Download as text" keeps the plain-text form. `GET /api/isp-report?format=json` gives the same numbers.

## [0.5.0] - 2026-11-25

### Added
- ISP report: "ISP report (this month)" on the Drops page and `GET /api/isp-report` give plain text with only the events beyond the router (line drops, slowdowns, lossy periods, public IP changes, ISP DNS failures), each with the router's answers at the same moment. Home-network events and periods annotated as tests are counted, not listed.

## [0.4.0] - 2026-11-24

### Added
- `GET /api/metrics` in the Prometheus text format (behind the dashboard token): segment up/down, per-probe loss, late share and RTT over the last complete minute, this month's availability and drops, the last drop and its rule. Labels carry probe classes, never addresses. `docs/integrations` has Prometheus, Grafana and Home Assistant configs.

### Changed
- The copied summary says "Cause:" without "(likely)" when it lists the measurements, as the drop page does.

## [0.3.0] - 2026-11-24

### Added
- "Why this verdict" on every drop: the measurements the cause rests on (router RTT usual vs. peak and timeouts, replies from beyond the router on time / late / lost, upload vs. download loss, TCP retransmissions, RTO and RST, Wi-Fi events, IP change, failed DNS classes) and the causes they rule out. The headline no longer ends in "(likely)" when it has them; the copied summary lists them too. `replay --write` adds them to past drops.

## [0.2.1] - 2026-11-24

### Fixed
- Under Compose, `agent_name` and `[web] bind` in `whydrop.toml` were ignored (Compose always passed its own defaults). Compose now passes a lower-priority default (`WHYDROP_DEFAULT_WEB_BIND`), so the file wins and `.env` still wins over both.
- A drop that ended less than 80 s before an agent restart, or was open across it, never alerted; it is now finalized (and alerted) at the restart.
- Findings a crashed run left open (e.g. secret mismatch) stayed on the dashboard forever; they are closed at the next start and raised again if they still hold.
- After a backward clock step, timestamps stayed ahead of the wall clock until a restart, so the dashboard missed the newest data. They now run at half speed until they meet it, never going back.
- `replay --write` called drops 8-90 days old "not a drop now"; they are "no 1 s data", as replay only reads the last 8 days.
- The public self-check view always had an empty `verdict`; it now carries the report card's DNS-interception verdict. The dashboard falls back to uvicorn's default WebSocket implementation on versions older than the one it prefers.

## [0.2.0] - 2026-11-24

### Added
- `whydrop replay --write`: after an upgrade, store the current analysis's verdict on past drops (backup first; point events and drops without 1-second data are left alone).

### Fixed
- A Wi-Fi roam just before a line drop was reported twice, as a "roaming with loss" point and as the drop's Wi-Fi cause. The roam is now judged after the drop could be confirmed, so it is one drop.
- A drop of exactly 1 h was marked a long outage: the tag was set while its recovery was still being confirmed. Only drops longer than 1 h keep it.
- A line drop starting 119–120 s after a Wi-Fi, cable or router recovery (or up to 10 s earlier during a lossy period) became a separate drop: the earlier drop's cause was made final at 120 s, before the line drop could be confirmed. Those drops are now final 130 s after they end, and the line drop joins them as documented.
- A short line drop soon after a router outage was dropped as a "burst": the router outage's own lost heartbeats counted as a lossy period. Seconds inside an earlier outage no longer count, so the drop joins the router's incident as a restart.
- The 6 h, 24 h and 7 d charts were empty for the first 7 days: 1-minute aggregates were only made from 1-second rows older than 7 days. They are now made as data comes in, 5 minutes behind, and the long views read them together with the latest 1-second rows, counting each second once.
- An in-home queueing verdict was shown as "Internet line dropped" with the line drawn cut. Queueing (R7) is now shown as slowing down, and in-home queueing names the home network and marks the Wi-Fi or cable hop, in the dashboard, alerts and the copied summary.
- The Korean dashboard and summary showed the *In protocol terms* paragraph and evidence values (upload, download) in English. New drops store the paragraph in both languages; drops recorded before keep the English one.
- The public demo's protocol page said packets appear once precision mode is on, with a pause button and an empty table. It now says the demo has no packets and links the protocol document.
- NAT chart: the UDP label could sit on the TCP line. On a phone its text was about 7 px; it is now drawn at the phone's width, with full-size text.
- Dashboard errors: with the agent stopped every screen said "Couldn't load data (server returned ?)"; it now says the agent can't be reached. A server error no longer prints the raw API address with its query twice, and the protocol page shows the error instead of "no packets yet".
- A long unbroken word in a cause, next step or evidence value (a hostname, a hash) pushed the drops table, the cause filter, the drop page and the Now page's lists past the screen edge. It now wraps.
- The chart tables of the 6 h, 24 h and 7 d views now show the date when they cross midnight; the same clock time on two days looked identical.
- The public Now page with no drops yet said to press a test button it doesn't have. The skip link said "Skip to content" on the Korean page, and the Korean token message broke "?token=" across lines.
- Korean text wrapped inside words (for example "(추 / 정)"), and table headers stacked on a phone.
- `[nat] enable_7500 = true` was read but ignored: `whydrop nat-test` and the dashboard's NAT test now include the 7500 s TCP delay when it is set.
- Alert titles now name the agent (`agent_name`, `WHYDROP_AGENT_NAME`), as the example config said they did. Compose passes `WHYDROP_AGENT_NAME` through.
- The packet strip and events were never deleted, and 1-minute aggregates grew forever. They are now kept 90 days (strip, events) and a year (minutes), as documented.
- `whydrop replay --set STREAM_LOSS_S=…` had no effect (the 2 s was hard-coded); the unused `TIMEOUT_S` is gone, and three thresholds that lived outside `constants.py` (`LOSS_MIN_SENDS`, `WEAK_MIN_SAMPLES`, `ROAM_LOSS_WINDOW_S`) can now be set too.
- `[intervals] link` was accepted and ignored (the link check runs every second by design); it is now rejected as an unknown key.
- Alerts can be in Korean (`[notify] lang = "ko"`), with the dashboard's wording; the Korean summary and the public demo's Korean copy button no longer mix in English cause labels. An ntfy title with a non-ASCII or multi-line agent name no longer fails to send.
- The config now refuses values that parsed but misbehaved: `udp_stream.pps` outside 1–100 and intervals outside 0.5–3600 s (which could hammer the router or public servers), a `notify.format` typo (alerts silently went out as JSON), non-http(s) alert URLs, target or `web.bind` ports outside 1–65535, a negative `storage.min_free_mb` and an `agent_name` over 64 characters.
- An empty host, port 0 or an IPv6 address in `reflector` now turns precision mode off with the reason, as `host:abc` already did, instead of starting precision mode against an address it can't use (the sockets are IPv4).
- Alerts: at most 12 delivered an hour, retries included (the next one says how many were held), at most 100 waiting for retry, and a retry that fails again is saved with its backoff so a restart doesn't start the backoff over.
- A late reply for a second split across two writes was applied to the part without the loss, so the second showed the loss and the late reply both; a late reply with no loss left (a duplicate) no longer counts.
- The analysis kept only the later part of a second written in two parts, so a loss in the first part could vanish from the verdict.
- The dashboard API answered times or drop ids past 2^63 (or negative times) with a 500; they are now a 400.
- CSV exports: text starting with `=`, `+`, `-` or `@` is prefixed with `'` so a spreadsheet shows it instead of running it as a formula.
- A drop open across a stretch with no data (agent stopped, clock stepped forward) stretched over it, becoming a multi-hour "long outage" in a replay; it now ends at the last second with data, tagged `data_gap`.
- A test reflector could fail to start on Windows, where TCP port blocks inside the UDP ephemeral range are reserved.
- The reflector failed to start when its tombstone file held an infinite seq or very deeply nested JSON; it now logs the file as unreadable and starts empty, as it already did for other corrupt files.
- On Windows, a UDP probe rejected with ICMP port or host unreachable (for example DNS on UDP 53 blocked by a firewall that rejects) was stored as a plain loss; it now carries the ICMP mark, as on Linux.
- On Windows in a language other than English or Korean (for example Japanese), `netsh` was always read as "Wi-Fi disconnected", so Wi-Fi was never watched. The listed BSSID now decides whether Wi-Fi is associated.
- On Linux, a network name (SSID) containing text such as `freq: 2412` or `signal: -10` replaced the frequency and signal read from `iw`. Each value is now read from its own line only.
- With two default routes (for example cable and Wi-Fi at once), the agent took the first one listed as the router and interface, not the one with the lowest metric that the system actually uses.
- Precision mode: one ECHO arriving more than 3 s out of order made the next ECHO look like the end of an outage and recorded a UDP outage with made-up download loss. An ECHO delayed from before a reflector restart was counted as a lost packet although it came back.
- Precision mode: a canary whose TCP connection opened but whose handshake got no answer within 5 s recorded a "kernel timeout" (the kernel giving up on a connection). It is now a failed connection attempt, retried with the usual backoff.
- `whydrop nat-test` said "no keepalive advice until the range is closed" also when every delay survived or none did, which more runs can't change. It now says "no keepalive needed below N s" or "keepalive below N s (the shortest delay tried)".

## [0.1.0] - 2026-11-23

First release.

### Added

**Agent (basic mode)**
- Probes every second over TCP and UDP: router check (TCP RST from a closed port; ICMP echo on Windows), line heartbeat (a STUN or DNS question, rotating providers), DNS over UDP and TCP to the router, the ISP's resolvers and public resolvers, STUN mapped address, TCP connect to port 443.
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
