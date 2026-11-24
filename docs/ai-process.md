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

## 2026-11-21 — Plan 5 built: the dashboard

| Step | What the agent did | What the human decided |
|---|---|---|
| Build | 8 tasks: the web app served from the agent's own event loop with host, origin and token guards; a public-view allowlist used by every output; REST, exports and a change bus with WebSocket; webhook alerts on finalized drops; a static, no-build frontend (Now with the path diagram, drop detail with the packet strip and "in protocol terms", NAT, Protocol, My network) in English and Korean, light and dark | Designed earlier with the UI/UX skills and reference products; "keep going without asking" |
| Checks in a real browser | Screenshots of every screen in both themes, both languages and two widths reviewed by eye; axe-core with zero serious violations; a full keyboard path; no sideways scroll on a 360 px phone in Korean; one run under the real Content-Security-Policy with a token | — |
| Reviews | One batch review, one whole-branch review by the most capable model and two re-reviews. The reviewer measured, not guessed: chart requests stalled the agent's loop for 1.2–3 s and added 60–90 MB of memory (fixed: columnar charts, encoding off the loop, streamed exports; re-measured at under 10 ms and a few kB). Also caught: the reflector's address leaking through one probe's name in public view, a busy port letting the web server exit the whole agent, copy-to-clipboard failing on a LAN address, exports dying mid-stream on one table | Merge after review |

## 2026-11-22 — The first day of real data

| Step | What the agent did | What the human decided |
|---|---|---|
| Reading its own output | Pulled a copy of the database from the home server after ~10 h and replayed it: 32 drops, most of them 2–7 s "router" drops. In those seconds the router check (a TCP probe to a closed port) had timed out twice while line probes were answering *through the same router* — Wi-Fi power save and 500–800 ms spikes, not a dead router | — |
| Fix | A router drop now also needs that nothing answered from the internet through the router in that second; a new test covers the case. Replay of the same 10 h: 32 → 14 drops (the rest: four UDP-DNS episodes and a real Wi-Fi trouble window) | Merge after the tests and CI |
| Second night | Two 3–7 s "router" drops remained: every probe came back *late* (0.5–1.2 s) while the router check, which records no late replies, counted as lost. Late replies now count as having crossed the router. Replaying also showed one incident finalized twice; the first fix (freeze final incidents) was caught by review cutting the 120 s router-restart merge window to 80 s, and was redone (local drops settle after the merge window). Replay of the two snapshots: 14 → 10 and 16 → 11 drops | Merge after review |
| First 12 h on the fixed version | One drop in 12 h: a 5 s stall where the router's own RTT had risen to 300–700 ms and everything behind it came back 1–1.7 s late. It was called "queueing caused the timeouts" with "enable SQM on the router", because the late-replies trigger returned before checking the router's RTT. It is now in-home queueing, with a next step pointing at the Wi-Fi. The same snapshots showed that 16 of 28 loss periods had the router checks failing as much as the line (e.g. line 6 % / router 47 %), all labelled "lossy line, contact your ISP"; those are now home-network loss. Two reviews caught a one-sample decision, mismatched windows in precision mode, and routers that never answer pings | Merge after review |
| The reflector goes up; a UX audit and QA on the real screens | The reflector went up on a small cloud VM and the home agent switched to precision mode. A UX heuristics audit of screenshots of the live dashboard, then a click-through QA pass over a snapshot of the real database, found what the browser tests with fixture data had missed: a literal "null" on the NAT page and on a point event's drop page, a headline saying "line loss" while the path diagram showed the line as fine (the loss was on the path to the reflector), findings shown as internal keys, English reasons and am/pm times in the Korean UI, injected scenes not marked on the Now page. A review then found two more finding kinds without words and the static demo missing the scene tags; a test now scans the source for every finding kind. The human asked whether UX and QA skills had been used: the honest answer was only partly, which is why this pass happened | Merge after review |
| Scenes, and a natural drop the same night | Loss injected on the reflector with `tc netem` (annotated first) was read exactly: 273 and 312 packets lost all on the way down, 288 all on the way up, each "lossy path to the reflector" with the line kept green. A 400 ms delay on that path got no label at all (now on the roadmap). Between scenes a real 8 s stall happened: the router check timed out for 8 s while everything behind the router came back up to 1.9 s late. It was called line queueing; a router that can't answer its own check while replies through it are merely late means the delay is in the home. The same stall exposed a middlebox check that flipped 20 times in one night (two medians over different windows). A review then caught that the first in-home fix would also have counted a router that really failed | Merge after review |

## 2026-11-22 — Plan 6: release work

| Step | What the agent did | What the human decided |
|---|---|---|
| Build | A Wireshark dissector for both protocols (checked with tshark against a capture built byte by byte); `whydrop export-static` for a read-only public demo; CI on Windows, a dissector job and image smoke tests; release images for three architectures with SBOM and provenance; a manual Pages workflow behind an address scanner; the public docs in English and Korean | Publishing the demo and tagging v0.1.0 wait for the human's review |
| Reviews | One code review, one documentation-accuracy review (every claim checked against the source), and a re-review of the fixes. Caught: `export-static` would have deleted whatever directory `--out` pointed at; demo pages exported days after recording came out empty and chart times were absolute; the address scanner missed an address at the end of a sentence and passed when its directory didn't exist; the leak test could not fail (its data held no private values — once seeded, it found an interface name leaking); the docs described rule details, a disk-full banner and example verdict sentences that the code doesn't have; compose never passed the reflector settings to the container, so precision mode could not be turned on from the README's instructions | Merge after review |

## 2026-11-23 — Going public

| Step | What the agent did | What the human decided |
|---|---|---|
| Demo check | Before publishing the static demo, checked it file by file: no addresses (the public scanner and a separate grep), no packet bytes, relative times only, and code identical to the already public dashboard | Asked for a security check before anything went public, then said to publish |
| Release | The first `v0.1.0` release failed on arm64: Debian ships iw there as the rebuild `6.9-1+b1`, so the exact pin `6.9-1` matched nothing. Checked in containers that `6.9-1*` installs iw 6.9 on amd64 and arm64, then moved the tag (nothing had been pushed) | Tag, release, vulnerability reporting, branch protection |
| A stale demo verdict | While making the README GIF, noticed the demo's one drop still said "queueing caused the timeouts, enable SQM", the verdict this log records as wrong (see "Scenes, and a natural drop the same night"): the demo was exported before the fix. A replay with the current analysis gives in-home queueing; the demo, GIFs and social preview were re-made from that. The two NAT point events replay only approximately and were left as recorded | — |
| PyPI prep | Package metadata, a smaller sdist, and a manual trusted-publishing workflow. A review caught relative links that are dead on PyPI and that a run from another branch would have published that branch | Publishing needs the owner's PyPI account |

Counts so far: 38 review agents, roughly 550 findings. Each adopted finding was either checked by measurement or source, or adopted as a design decision (not separately verified). Rejected or corrected agent output: one reviewer claimed a competitor had "refused" UDP support; reading the actual issue threads showed otherwise, so the claim was not used.

Notable catches from the reviews and measurements:
- The first design would have excluded *every* target if the agent started during an outage.
- Checking router liveness via its DNS would have mislabelled every ISP outage as a router failure; a closed TCP port's RST is used instead (measured: ~1.3 ms).
- Linux conntrack only applies the 120 s UDP timer to flows still active more than 2 s after the first packet, so the NAT test keeps the exchange alive for 3 s (verified in kernel source).
- Windows `time.monotonic()` ticks in ~15 ms steps on Python ≤ 3.12 (3.13 switched to QPC); all timing uses `perf_counter_ns()`.
- Random packet loss alone would have produced about 19 false "line drop" incidents per hour at 10% loss. The fix (only public probes vote, and short drops inside a lossy period are reported as part of it) brought that to 0 in simulation while still catching every 3.0 s drop.

## 2026-11-23 to 11-24 — The full audit

The owner looked at the finished project and said it was full of errors: every feature, every edge case, from the smallest unit up. The agent wrote an audit plan first (each module: branch coverage, the cases at each threshold and one step either side, a test for every missing case, a deliberate break of the code to prove each new test can fail, a root-cause fix with the failing test first, an independent review per layer).

| Step | What the agent did | What the human decided |
|---|---|---|
| Known defects first | 15 found while planning, among them the worst of the project: the 6 h, 24 h and 7 d charts were empty for an install's first week, because minute rows were only made from 1-second rows older than 7 days. It is visible in the first demo video. Checked on a copy of the home database: the rolled-up charts now equal the raw 1-second result on every series | "Plan first", then "go on" |
| Five layers in parallel | The reflector, the probes, precision mode, the analysis rules and the dashboard states were audited by five agents in separate worktrees; the agent merged their branches after reading them | "Go with your recommendations, faster" |
| Replay writes | `whydrop replay --write` rewrites stored verdicts after a backup. Its first run on the home database paired a stored router drop with a DNS drop that only overlapped in time, then left stale "router problem" verdicts because the segments differed; both rules were fixed on the real output before the home database was rewritten | Rewrite past verdicts (with a backup), keep the original video |
| Submission | Report, demo, GIFs and a new captions-only promo video recorded from the re-exported demo | No voice-over, captions only, service-intro style |

Counts: 46 review and audit agents in all, roughly 600 findings; this audit fixed 37 user-visible defects (CHANGELOG 0.2.0) and the test suite grew from about 550 to 833 tests.

What the agent got wrong and caught on real data or in review:
- It claimed `host:abc` as a reflector address crashed precision start-up; an existing test showed it was already handled (precision off with the reason). The config check was moved back to that path.
- Its first alert-rate cap counted failed sends and let retries bypass the cap; a review found both.
- Several flaky tests were not timing luck: Hyper-V reserves blocks of 100 TCP and UDP ports inside the Windows dynamic range and moves them, so a test that bound a UDP port and then the same TCP number failed in bursts.
- A memory rise on the home server (40 → 54 MiB over 40 h) was measured with tracemalloc before any change, rather than guessed at: after warm-up the heap grew about 80 KiB in 20 minutes; the rise is the 1-hour signal window and the 24-hour RTT baselines filling, not a leak.
