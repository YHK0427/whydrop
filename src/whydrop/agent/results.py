"""Probe results and the send-time keyed 1 s aggregation into samples_1s (spec §5.0, §7)."""
import json
from dataclasses import dataclass, field

from whydrop.agent.store import SampleRow


@dataclass
class Result:
    probe: str
    pair: str
    provider: str | None
    t_send_ms: int
    ok: bool
    rtt_ms: float | None
    local_fail: bool = False
    detail: dict = field(default_factory=dict)


@dataclass
class _Bucket:
    sent: int = 0
    ok: int = 0
    lost: int = 0
    late: int = 0
    local_fail: int = 0
    rtts: list[float] = field(default_factory=list)
    icmp: int = 0


class Aggregator:
    """Results arrive after their timeout; each is counted in the second it was *sent*. A second is written
    once `finalize_after_s` has passed after its end, so every probe's timeout has had time to expire."""

    def __init__(self, store, now_ms, finalize_after_s: float = 4.5):
        self._store, self._now_ms = store, now_ms
        self._after_ms = int(finalize_after_s * 1000)
        self._open: dict[tuple[int, str, str], _Bucket] = {}

    def add(self, r: Result) -> None:
        b = self._open.setdefault((r.t_send_ms // 1000 * 1000, r.probe, r.pair), _Bucket())
        b.sent += 1
        if r.ok:
            b.ok += 1
            if r.rtt_ms is not None:
                b.rtts.append(r.rtt_ms)
        elif r.local_fail:
            b.local_fail += 1
        else:
            b.lost += 1
            b.icmp += bool(r.detail.get("icmp"))

    async def late(self, probe: str, pair: str, t_send_ms: int) -> None:
        key = (t_send_ms // 1000 * 1000, probe, pair)
        b = self._open.get(key)
        if b is not None:
            b.late += 1
            b.lost = max(0, b.lost - 1)
        else:
            await self._store.late(*key)

    async def flush_ready(self, force: bool = False) -> None:
        cutoff = self._now_ms() - 1000 - self._after_ms
        ready = [k for k in self._open if force or k[0] <= cutoff]
        rows = []
        for k in sorted(ready):
            b = self._open.pop(k)
            rtts = sorted(b.rtts)
            rows.append(SampleRow(
                k[0], k[1], k[2], sent=b.sent, ok=b.ok, lost=b.lost, late=b.late, local_fail=b.local_fail,
                rtt_min=rtts[0] if rtts else None, rtt_max=rtts[-1] if rtts else None,
                rtt_avg=round(sum(rtts) / len(rtts), 3) if rtts else None,
                rtt_p95=rtts[max(0, int(len(rtts) * 0.95) - 1)] if rtts else None,
                extra_json=json.dumps({"icmp": b.icmp}) if b.icmp else None))
        if rows:
            await self._store.add_samples(rows)
