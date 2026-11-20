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

Counts so far: 11 review agents, roughly 180 findings. Each adopted finding was either checked by measurement or source, or adopted as a design decision (not separately verified). Rejected or corrected agent output: one reviewer claimed a competitor had "refused" UDP support; reading the actual issue threads showed otherwise, so the claim was not used.

Notable catches from the reviews and measurements:
- The first design would have excluded *every* target if the agent started during an outage.
- Checking router liveness via its DNS would have mislabelled every ISP outage as a router failure; a closed TCP port's RST is used instead (measured: ~1.3 ms).
- Linux conntrack only applies the 120 s UDP timer to flows still active more than 2 s after the first packet, so the NAT test keeps the exchange alive for 3 s (verified in kernel source).
- Windows `time.monotonic()` ticks in ~15 ms steps on Python ≤ 3.12 (3.13 switched to QPC); all timing uses `perf_counter_ns()`.
- Random packet loss alone would have produced about 19 false "line drop" incidents per hour at 10% loss. The fix (only public probes vote, and short drops inside a lossy period are reported as part of it) brought that to 0 in simulation while still catching every 3.0 s drop.
