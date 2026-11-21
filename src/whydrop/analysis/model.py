"""Analysis input: one Frame per second (by send time) and the Context the decisions need (spec §6.1–6.2)."""
from collections.abc import Callable
from dataclasses import dataclass, field

from whydrop.agent.events import Event
from whydrop.agent.store import SampleRow
from whydrop.analysis import constants as K

LINE_QUORUM = ("line_hb", "stun", "dns", "dns_tcp", "tcp_connect", "udp_stream", "canary")


@dataclass
class Frame:
    t_ms: int
    samples: dict[tuple[str, str], SampleRow] = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)
    lag: bool = False          # an agent_lag period covers this second: its sends don't count
    suspended: bool = False    # the host slept, or woke less than 30 s ago

    def rows(self, probe: str) -> list[SampleRow]:
        return [r for (p, _), r in self.samples.items() if p == probe]


@dataclass
class Context:
    provider_of: Callable[[str], str | None] = lambda pair: None
    excluded_pairs: set[str] = field(default_factory=set)
    excluded_providers: set[str] = field(default_factory=set)
    mode: str = "basic"                 # "basic" | "precision"
    lan_observable: bool = True
    vpn: bool = False
    link_kind: str = "unknown"          # "wifi" | "wired" | "unknown"
    intervals: dict = field(default_factory=dict)

    def provider(self, probe: str, pair: str) -> str | None:
        if probe in ("udp_stream", "canary"):
            return "reflector"           # the reflector counts as one provider
        return self.provider_of(pair)

    def usable(self, probe: str, pair: str) -> bool:
        return pair not in self.excluded_pairs and self.provider(probe, pair) not in self.excluded_providers


def line_quorum(probe: str, pair: str, ctx: Context) -> bool:
    """Probes that vote on the line. Router and ISP DNS never do: they can answer from cache while the line is down."""
    if probe not in LINE_QUORUM or not ctx.usable(probe, pair):
        return False
    if probe in ("dns", "dns_tcp"):
        return pair.startswith("dns_public:")
    if probe in ("udp_stream", "canary"):
        return ctx.mode == "precision"
    return True


class FrameBuilder:
    """Collects finalized rows and events; hands out frames strictly in order, one per second, empty ones included,
    once nothing can still change them (now − FINALIZE_LAG_MS)."""

    def __init__(self, start_ms: int | None = None, finalize_lag_ms: int | None = None):
        self.next_ms = None if start_ms is None else start_ms // 1000 * 1000
        self.lag_ms = K.FINALIZE_LAG_MS if finalize_lag_ms is None else finalize_lag_ms
        self._rows: dict[int, dict] = {}
        self._events: dict[int, list] = {}
        self._lag: list[list[int | None]] = []        # [start, end] (end None while open)
        self._sleep: list[tuple[int, int]] = []       # [slept from, resume + grace]
        self.late_rows = 0

    def add_rows(self, rows: list[SampleRow]) -> None:
        for r in rows:
            if self.next_ms is not None and r.ts_ms < self.next_ms:
                self.late_rows += 1                   # that second was already judged
                continue
            self._rows.setdefault(r.ts_ms, {})[(r.probe, r.pair)] = r
            if self.next_ms is None:
                self.next_ms = r.ts_ms

    def add_events(self, events: list[Event]) -> None:
        for e in events:
            if e.kind == "agent_lag":
                if e.detail.get("phase") == "start":
                    self._lag.append([e.ts_ms - e.detail.get("lag_ms", 0), None])
                elif self._lag and self._lag[-1][1] is None:
                    self._lag[-1][1] = e.ts_ms
            elif e.kind == "suspend":
                self._sleep.append((e.ts_ms - int(e.detail.get("slept_s", 0) * 1000), e.ts_ms + K.RESUME_GRACE_S * 1000))
            b = e.ts_ms // 1000 * 1000
            if self.next_ms is not None and b < self.next_ms:
                b = self.next_ms                      # a late event lands in the next frame, never dropped
            self._events.setdefault(b, []).append(e)
            if self.next_ms is None:
                self.next_ms = b

    def _covered(self, spans, t: int) -> bool:
        return any(s <= t + 999 and (e is None or t <= e) for s, e in spans)

    def ready(self, now_ms: int) -> list[Frame]:
        out = []
        while self.next_ms is not None and self.next_ms + 1000 <= now_ms - self.lag_ms:
            t = self.next_ms
            out.append(Frame(t, self._rows.pop(t, {}), self._events.pop(t, []), self._covered(self._lag, t),
                             self._covered(self._sleep, t)))
            self.next_ms += 1000
        horizon = (self.next_ms or 0) - 3_600_000
        self._lag = [x for x in self._lag if x[1] is None or x[1] > horizon]
        self._sleep = [x for x in self._sleep if x[1] > horizon]
        return out
