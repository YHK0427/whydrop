# How Agentic AI was used to build whydrop

**English** | [한국어](ai-process.ko.md)

This log is kept **while the work happens**, not reconstructed afterwards. A coding agent (Claude Code) was used as a pair engineer. The human made every product decision; the agent researched, drafted, reviewed, measured and implemented.

## 2026-11-17 — Idea and design

| Step | What the agent did | What the human decided |
|---|---|---|
| Problem search | Generated many candidate ideas; checked live GitHub data (star counts, closed feature requests) instead of relying on memory | Must use **both** TCP and UDP; must be a real open-source product, not a toy |
| Positioning | Compared self-hosted monitoring tools; found that none explain *why* a home connection dropped using TCP and UDP together | Picked "self-hosted network black box" |
| Architecture options | Laid out three approaches (public servers only / reflector required / hybrid) with trade-offs | Chose the hybrid |
| Design draft | Wrote the design doc | Required docs in English and Korean; "no faked demos" |
| Builder check | A separate agent read only the doc and listed what it would have to guess | — |
| Field measurements | Probed public DNS/STUN over UDP and TCP from two real networks; read Wi-Fi state on the real home server (host and container); confirmed router RST behavior, resolver chain, kernel conntrack defaults, Windows timer resolution | Router is outside the user's control → router scenes moved to a phone hotspot; no Wi-Fi scenes on the shared home server |
| Design review | Four independent review agents, each with one lens: networking correctness, detection logic (walked nine outage timelines through the rules), security/privacy, completeness | — |
| Revision | Folded in the reviews: segment/quorum analysis, self-check that can't blind itself, byte-exact TCP handshake with nonce, replay protection, dashboard Origin/Host checks, public-view masking, annotations for reproduced scenes, distribution section | Approved / pending |

| Second review round | Three more independent agents: a live competitor re-check (GitHub API + source reading), a product/adoption + grader review, and an EN/KO consistency and arithmetic audit | Keep the product and differentiate on seconds-level drops and protocol-level evidence; include every mid-effort addition (evidence export, webhook alerts, Wireshark dissector, static demo) |
| Field spike | Ran the designed 1 Hz probes on a real host for 10 minutes: 0 false positives, event-loop lag p95 0.4 ms. Verified kernel `TCP_INFO` is readable from the stdlib and that probes don't leave through the VPN | — |
| Document split | — | Public docs (user/contributor facing) stay in this repo; the internal design, plans, raw reviews and environment notes are kept outside it |

Counts so far: 8 review agents, roughly 120 findings; every adopted finding was either verified by measurement/source or turned into an explicit design rule. One claim from a reviewer (that a competitor's UDP support was "refused") was corrected after reading the actual issue threads.

Notable catches from the reviews and measurements:
- The first design would have excluded *every* target if the agent started during an outage.
- Checking router liveness via its DNS would have mislabelled every ISP outage as a router failure; a closed TCP port's RST is used instead (measured: ~1.3 ms).
- Linux conntrack only applies the 120 s UDP timer to flows still active more than 2 s after the first packet, so the NAT test keeps the exchange alive for 3 s (verified in kernel source).
- Windows `time.monotonic()` ticks in ~15 ms steps; all timing uses `perf_counter_ns()`.
