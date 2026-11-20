"""Self-check (spec §5.1): which pairs answer on this network, findings at runtime, NAT mapping behaviour."""
import asyncio
import os
import socket
import statistics
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal

from whydrop.agent.events import Event
from whydrop.agent.results import Result
from whydrop.net import stun

TARGET_SPECIFIC_MS = 5 * 60_000
PROVIDER_OUTAGE_MS = 2 * 60_000
RECHECK_MS = 10 * 60_000


@dataclass
class CheckPair:
    pair: str
    provider: str | None
    cls: str
    addr: str
    proto: str
    run: Callable[[], Awaitable[Result]]


@dataclass
class SelfCheck:
    status: Literal["ok", "inconclusive"]
    excluded: dict[str, str] = field(default_factory=dict)
    successes: dict[str, int] = field(default_factory=dict)
    median_rtt: dict[str, float] = field(default_factory=dict)
    gateway_ok: bool = False


async def run_selfcheck(pairs: list[CheckPair], gateway: Callable[[], Awaitable[Result]] | None, *, tries: int = 3,
                        per_provider_qps: float = 2, sleep=asyncio.sleep) -> SelfCheck:
    by_provider: dict[str, list[CheckPair]] = defaultdict(list)
    for p in pairs:
        by_provider[p.provider or p.cls].append(p)
    ok_rounds: dict[str, list[bool]] = {p.pair: [] for p in pairs}
    rtts: dict[str, list[float]] = defaultdict(list)
    gw_ok = []

    async def provider_round(items: list[CheckPair]) -> None:
        for i, p in enumerate(items):
            if i:
                await sleep(1 / per_provider_qps)  # ≤ 2 queries/s per provider
            r = await p.run()
            ok_rounds[p.pair].append(r.ok)
            if r.ok and r.rtt_ms is not None:
                rtts[p.cls].append(r.rtt_ms)

    for _ in range(tries):
        if gateway is not None:
            gw_ok.append((await gateway()).ok)
        await asyncio.gather(*(provider_round(v) for v in by_provider.values()))

    successes = {k: sum(v) for k, v in ok_rounds.items()}
    failed = [k for k, n in successes.items() if n == 0]
    gateway_ok = any(gw_ok) if gateway is not None else True
    median = {c: statistics.median(v) for c, v in rtts.items() if v}
    if not gateway_ok or (pairs and len(failed) * 2 >= len(pairs)):
        return SelfCheck("inconclusive", {}, successes, median, gateway_ok)  # starting mid-outage: exclude nothing

    excluded = {}
    meta = {p.pair: p for p in pairs}
    for name in failed:
        p = meta[name]
        rounds_ok = all(  # in every round, at least two *other* providers answered
            len({(q.provider or q.cls) for q in pairs if (q.provider or q.cls) != (p.provider or p.cls)
                 and len(ok_rounds[q.pair]) > r and ok_rounds[q.pair][r]}) >= 2
            for r in range(tries))
        if not rounds_ok:
            continue
        sibling_ok = any(q.addr == p.addr and q.proto != p.proto and successes[q.pair] for q in pairs)
        excluded[name] = f"blocked on this network ({p.proto} only)" if sibling_ok else "no answer on this network"
    return SelfCheck("ok", excluded, successes, median, gateway_ok)


class FindingsTracker:
    """Runtime findings: one pair dead while its peers are fine (target-specific), or one provider dead while
    others are fine (provider outage). Both are left out of decisions until they answer again."""

    def __init__(self, targets, now_ms):
        self._t, self._now_ms = targets, now_ms
        self._fail_since: dict[str, int | None] = {}
        self._last_ok: dict[str, int] = {}
        self._provider_of: dict[str, str | None] = {}
        self._active_pairs: set[str] = set()
        self._active_providers: set[str] = set()

    @staticmethod
    def _cls(pair: str) -> str:
        return pair.split(":", 1)[0]

    def feed(self, r: Result) -> None:
        if r.local_fail:
            return
        self._provider_of[r.pair] = r.provider
        if r.ok:
            self._last_ok[r.pair] = r.t_send_ms
            self._fail_since[r.pair] = None
        elif self._fail_since.get(r.pair) is None:
            self._fail_since[r.pair] = r.t_send_ms

    def _recent_ok(self, pair: str, now: int, window: int) -> bool:
        return now - self._last_ok.get(pair, -10**12) <= window

    def check(self) -> list[Event]:
        now = self._now_ms()
        out: list[Event] = []
        for pair, since in self._fail_since.items():
            if since is None and pair in self._active_pairs:
                self._active_pairs.discard(pair)
                self._t.include(pair)
                out.append(Event("finding", now, pair, {"kind": "target_specific", "phase": "end"}))
            elif (since is not None and pair not in self._active_pairs and now - since >= TARGET_SPECIFIC_MS
                  and any(self._cls(q) == self._cls(pair) and q != pair and self._recent_ok(q, now, TARGET_SPECIFIC_MS)
                          for q in self._last_ok)):
                self._active_pairs.add(pair)
                self._t.exclude(pair, "target-specific problem")
                out.append(Event("finding", now, pair, {"kind": "target_specific", "phase": "start"}))
        providers = {p for p in self._provider_of.values() if p}
        for prov in providers:
            mine = [q for q, p in self._provider_of.items() if p == prov]
            down = all(self._fail_since.get(q) is not None and now - self._fail_since[q] >= PROVIDER_OUTAGE_MS for q in mine)
            others_ok = {self._provider_of[q] for q in self._last_ok
                         if self._provider_of.get(q) not in (prov, None) and self._recent_ok(q, now, PROVIDER_OUTAGE_MS)}
            if down and len(others_ok) >= 2 and prov not in self._active_providers:
                self._active_providers.add(prov)
                self._t.exclude_provider(prov, "provider outage")
                out.append(Event("finding", now, None, {"kind": "provider_outage", "phase": "start", "provider": prov}))
            elif prov in self._active_providers and any(self._fail_since.get(q) is None for q in mine):
                self._active_providers.discard(prov)
                self._t.include_provider(prov)
                out.append(Event("finding", now, None, {"kind": "provider_outage", "phase": "end", "provider": prov}))
        return out


class _Collect(asyncio.DatagramProtocol):
    def __init__(self):
        self.replies: dict[bytes, bytes] = {}

    def datagram_received(self, data, addr):
        if len(data) >= 20:
            self.replies[data[8:20]] = data

    def error_received(self, exc):
        pass


async def nat_mapping(servers: list[tuple[str, int]], timeout_s: float = 1.0) -> dict | None:
    """One socket, one binding request to each STUN server (spec §5.1): same mapped port from both =
    endpoint-independent mapping; mapped port equal to our own = port-preserving."""
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(_Collect, local_addr=("0.0.0.0", 0), family=socket.AF_INET)
    try:
        local_port = transport.get_extra_info("sockname")[1]
        txids = []
        for host, port in servers:
            txid = os.urandom(12)
            txids.append(txid)
            transport.sendto(stun.build_binding(txid), (host, port))
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline and len(proto.replies) < len(txids):
            await asyncio.sleep(0.02)
        mapped = [stun.parse_binding_response(proto.replies[t], t) for t in txids if t in proto.replies]
        mapped = [m for m in mapped if m]
        if len(mapped) < 2:
            return None
        return {"endpoint_independent": len(set(mapped)) == 1, "port_preserving": all(m[1] == local_port for m in mapped),
                "public_ip": mapped[0][0]}
    finally:
        transport.close()
