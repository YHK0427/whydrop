**English** | [한국어](ROADMAP.ko.md)

# Roadmap

Not in v0.1, in no particular order. Each becomes an issue; say which one you need.

- **A latency label for the path to the reflector.** Loss on that path gets its own verdict; a delay only there (seen with 400 ms injected) shows in the latency chart but gets no rough-patch label, because the line itself is fine.
- **IPv6 measurement.** v0.1 measures IPv4 only; an IPv6 path is not judged.
- **A monthly PDF report** for an ISP complaint (v0.1 has CSV/JSON, the copyable summary and the bug report).
- **Wi-Fi details on macOS.** Basic and precision probes should run; the Wi-Fi probe doesn't exist yet.
- **Prometheus `/metrics`.**
- **Plugin probes**, for checks specific to your network.
- **Applying the keepalive recommendation** automatically (v0.1 only recommends).
- **Several agents in one view.** The database already has an `agent_id` column.
- **Logins and multiple users** (v0.1 has a single token).
- **Verification on more hardware**: Raspberry Pi, Synology, Unraid, mesh Wi-Fi systems.
