# How Agentic AI was used to build whydrop

**English** | [한국어](ai-process.ko.md)

This log is kept **while the work happens**, not reconstructed afterwards. A coding agent (Claude Code) was used as a pair engineer. The human made every product decision; the agent researched, drafted, reviewed, measured and implemented.

## 2026-11-17 — Idea and design

| Step | What the agent did | What the human decided |
|---|---|---|
| Problem search | Generated many candidate ideas; checked live GitHub data (star counts, closed feature requests) instead of relying on memory | Must use **both** TCP and UDP; must be a real open-source product, not a toy |
| Positioning | Compared established self-hosted monitoring tools. The first pass found none that explain *why* a home connection dropped using TCP and UDP together; a later live re-check (second round, below) found a newer tool with a similar pitch, so this claim was dropped | Picked "self-hosted network black box" |
| Architecture options | Laid out three approaches (public servers only / reflector required / hybrid) with trade-offs | Chose the hybrid |
| Design draft | Wrote the design doc | Required docs in English and Korean; "no faked demos" |
| Builder check | A separate agent read only the doc and listed what it would have to guess | — |
| Field measurements | Probed public DNS/STUN over UDP and TCP from two real networks; read Wi-Fi state on a Linux host (directly and from a container); confirmed router RST behavior, resolver chain, kernel conntrack defaults, Windows timer resolution | Scenes that would disrupt a shared network are reproduced on a phone hotspot instead |
| Design review | Four independent review agents, each with one lens: networking correctness, detection logic (walked nine outage timelines through the rules), security/privacy, completeness | — |
| Revision | Folded in the reviews: segment/quorum analysis, self-check that can't blind itself, byte-exact TCP handshake with nonce, replay protection, dashboard Origin/Host checks, public-view masking, annotations for reproduced scenes, distribution section | — |
| Second review round | Three more independent agents: a live competitor re-check (GitHub API + source reading), a product/adoption review, and an EN/KO consistency and arithmetic audit | Keep the product and differentiate on seconds-level drops and protocol-level evidence; include every mid-effort addition (evidence export, webhook alerts, Wireshark dissector, static demo) |
| Field spike | Ran the designed 1 Hz probes on one real host for 10 minutes: 0 incidents during a quiet run, event-loop lag p95 0.4 ms. Verified kernel `TCP_INFO` is readable from the stdlib and that probes bind to the physical interface rather than a VPN route | — |
| Document split | — | Public docs (user/contributor facing) stay in this repo; the internal design, plans, raw reviews and environment notes are kept outside it |
| Adversarial round | Three more agents told to break the design rather than review it: a red team (walked outage timelines and simulated the line rule), a skeptic (scope, honesty, demo risk), and a parity/leak audit. The agent re-ran the red team's simulation before accepting it, then simulated its own fix | Asked for the adversarial round. Fixes adopted; kept the full feature list for v0.1 despite the skeptic's estimate |

## 2026-11-20 — UI/UX design and implementation plans

| Step | What the agent did | What the human decided |
|---|---|---|
| UI/UX design | Applied three design skills (usability heuristics, a data-visualization procedure, visual direction). Chart colors were checked with a color-vision validator script instead of by eye, and text contrast was computed (all text ≥ 4.5:1) | Asked for UI/UX to be planned from the start, with skills |
| References | Opened similar products in a browser and compared them (a competing ISP-blame tool's live demo, a status-page tool, an uptime monitor, a path-tracing tool, a speed test, router apps). Recorded what to take and what to avoid | Asked for the design to be grounded in similar products |
| Plans | Split the work into seven plans with a schedule; wrote the first one (codecs, protocol, reflector) as test-first tasks with exact byte layouts, then self-reviewed it and fixed two wrong test expectations | Chose to keep the full scope; repo published |

## 2026-11-20 — Plan 1 built: codecs, protocol, reflector (merged as `ae5a50e`)

| Step | What the agent did | What the human decided |
|---|---|---|
| Test-first build | 11 tasks, each started from a failing test (red observed for 9 of 11; for two the test and code were written together, noted honestly). 120 tests: codecs, replay window, rate limits, UDP and TCP reflector over real loopback sockets, a loss-injecting proxy that checks upload/download loss classification end to end | Asked that the agent implement directly instead of spawning one implementer per task; asked for frequent commits and pushes |
| Independent reviews | Four batch reviews by separate agents, one whole-branch review by the most capable model, one re-review of its fixes. Real bugs found and fixed: a NAT slot could be taken over by another IP; a set leaked at the connection cap; a reset connection could skip cleanup; a shutdown write could race a periodic write and corrupt the replay file; abandoned NAT tests held slots for up to an hour. A test that could not fail without the fix was rewritten until it could | Merge after review |
| Measurements that changed the design | On Windows a TCP connect to a closed port takes about 2 s (the OS retries the SYN after each RST), so the router check uses an unprivileged ICMP echo there instead (4–8 ms). Windows `netsh` prints Korean field names as UTF-8; the parser tests use the real labels | — |

## 2026-11-20 to 11-21 — Plan 2 built: the basic-mode agent

| Step | What the agent did | What the human decided |
|---|---|---|
| Test-first build | 11 tasks: config, time base and scheduler, DNS/STUN wire helpers, SQLite store, probe primitives, network probes, Wi-Fi and link, environment and self-check, the `whydrop agent` command, retention and traffic budget, the container. 270 tests | Keep going without asking between plans; assume the cloud account exists and build precision mode anyway |
| Reviews | Three batch reviews and one whole-branch review found real faults before deployment, among them: clock steps measured against a fixed anchor (a backward step would have emitted an event every second), a start-up self-check that blocked recording for up to 8.5 minutes during exactly the outage the tool exists for, DNS outages that could masquerade as line drops, false provider-outage findings from 10-minute re-checks, a STUN watcher stuck on stale sockets after a network change | — |
| Live runs | Ran the agent on the laptop against the real internet several times. The self-check excluded exactly the targets measured as blocked by hand on 11-17. The live runs found three bugs the tests had missed, the most interesting being Cloudflare's real CHAOS answer (`icn06`, not the documented `ICN`), which made the interception check cry wolf | — |
| A wrong claim, corrected | The agent reported Linux CI as green when it had not checked it; one Windows-only test assumption had kept CI red for several pushes. The human spotted it. The test was fixed, the claim corrected in the log and to the reviewer, and the agent now waits for each CI run before reporting it | Caught the red CI |

## 2026-11-21 — Plan 3 built: precision mode

| Step | What the agent did | What the human decided |
|---|---|---|
| Test-first build | 7 tasks: precision switch, udp_stream (10 pps with send-time buckets and up/down direction), a kernel `TCP_INFO` reader, the hot and idle TCP canaries, `whydrop nat-test`, and wiring with a measured traffic budget (≈ 18.5 kbps of the 20 kbps allowed). Every protocol test runs against the real reflector over loopback, through proxies that stall, reset or forget connections like a NAT does. 329 tests | Build precision mode before the cloud account exists |
| Reviews | Two batch reviews and one whole-branch review by the most capable model, then a re-review of its fixes. Real faults found before any deployment, among them: after one ICMP error a Windows UDP socket in asyncio never receives again, so a reflector restart would have silently ended all precision measurements (the reviewer reproduced it on three Python versions); nat-test opened more TCP handshakes at once than the reflector's own per-IP limit allows; a laptop waking from sleep would have recorded hours-long "TCP stalls"; two suspend tests could not fail and were rewritten with negative controls | Merge after review |
| Tests that prove themselves | For each fix the agent removed the fix again and checked that its new test fails, before committing | — |

## 2026-11-21 — Plan 4 built: the analysis

| Step | What the agent did | What the human decided |
|---|---|---|
| Test-first build | 8 tasks: per-second frames, segment state machines (this device, Wi-Fi/cable, router, line, DNS) with the line quorum and the lossy-period gate, conditions and rough patches, drops with merging and point events, likely causes with an 80 s settle, live wiring in the agent, `whydrop replay` and `whydrop annotate`. A small scenario language builds synthetic seconds; all 22 scenarios of the spec pass through the full engine. 453 tests | — |
| Reviews | One batch review, one whole-branch review by the most capable model, and two rounds of re-review on the fixes. Faults found before deployment, among them: a Wi-Fi probe that could not read its interface counted as "Wi-Fi down", which would have opened a drop that never ends and switched off line detection; a drop open when the laptop went to sleep would have lasted the whole night; Windows timer steps (15.6 ms) would have marked the host as permanently busy; a reflector outage would have been reported as a lossy ISP line; one fix crashed the agent at startup when `netsh` timed out | Merge after review |
| A CI failure that pointed at a real bug | The Linux CI runner read its own network interface during a test and produced a false "cable problem". The test was fixed, and the reviewer then showed the same mistake would happen on real machines, which led to the fix above | — |

Counts so far: 26 review agents, roughly 410 findings. Each adopted finding was either checked by measurement or source, or adopted as a design decision (not separately verified). Rejected or corrected agent output: one reviewer claimed a competitor had "refused" UDP support; reading the actual issue threads showed otherwise, so the claim was not used.

Notable catches from the reviews and measurements:
- The first design would have excluded *every* target if the agent started during an outage.
- Checking router liveness via its DNS would have mislabelled every ISP outage as a router failure; a closed TCP port's RST is used instead (measured: ~1.3 ms).
- Linux conntrack only applies the 120 s UDP timer to flows still active more than 2 s after the first packet, so the NAT test keeps the exchange alive for 3 s (verified in kernel source).
- Windows `time.monotonic()` ticks in ~15 ms steps on Python ≤ 3.12 (3.13 switched to QPC); all timing uses `perf_counter_ns()`.
- Random packet loss alone would have produced about 19 false "line drop" incidents per hour at 10% loss. The fix (only public probes vote, and short drops inside a lossy period are reported as part of it) brought that to 0 in simulation while still catching every 3.0 s drop.
