"""Conditions and degraded periods (spec §6.1 step 4, §6.2 conditions table, §6.4 R7 baseline). A condition that
lasts more than 30 s becomes a degraded period; conditions never open incidents on their own."""
import json
from collections import deque
from dataclasses import dataclass, field

from whydrop.analysis import constants as K
from whydrop.analysis.model import Context, Frame

KINDS = ("loss", "weak_signal", "wifi_lan_loss", "agent_busy", "latency")
RTT_SOURCES = ("tcp_connect", "stun", "line_hb", "udp_stream", "canary")  # no DNS (§6.4 R7)
MIN_SENDS = 20                       # don't call 1 lost out of 3 a loss condition


@dataclass
class ConditionChange:
    kind: str
    phase: str            # "start" (back-dated to when it began) | "end"
    t_ms: int
    detail: dict = field(default_factory=dict)


def _pct(values: list[float], q: float) -> float:
    v = sorted(values)
    return v[min(len(v) - 1, int(len(v) * q))]


class _Sums:
    """Per-second (a, b) pairs over a sliding window, e.g. (lost, sent)."""

    def __init__(self, seconds: int):
        self.ms = seconds * 1000
        self.q: deque = deque()
        self.a = self.b = 0

    def add(self, t, a, b):
        self.q.append((t, a, b))
        self.a, self.b = self.a + a, self.b + b

    def trim(self, t):
        while self.q and self.q[0][0] <= t - self.ms:
            _, a, b = self.q.popleft()
            self.a, self.b = self.a - a, self.b - b


class Conditions:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.first_ms: int | None = None
        self._loss = _Sums(K.LOSS_STREAM_WINDOW_S if ctx.mode == "precision" else K.LOSS_BASIC_WINDOW_S)
        self._gw = _Sums(K.WIFI_LAN_WINDOW_S)
        self._hb = _Sums(K.LOSS_BASIC_WINDOW_S)   # line_hb loss: "line" vs "path to reflector"
        self._loop: deque = deque()                          # (t, p95 ms)
        self._rssi: deque = deque()                          # (t, dBm) for the 1 h median
        self._rtt: dict[str, deque] = {}                     # pair → (t, rtt) over the latency window
        self._minute: dict[str, float] = {}                  # pair → min RTT of the current minute
        self._minute_at: int | None = None
        self._base_hist: dict[str, deque] = {}               # pair → per-minute minima over 24 h
        self._base: dict[str, float] = {}                    # pair → p10 (recomputed once a minute)
        self._since: dict[str, int | None] = dict.fromkeys(KINDS)
        self._shown: set[str] = set()
        self.detail: dict[str, dict] = {}

    def line_hb_lossy(self) -> bool:
        return self._hb.b >= MIN_SENDS and self._hb.a / self._hb.b >= K.LOSS_FRAC / 2

    def loss_at_home(self) -> bool:
        """The router checks lose at least the loss bar and half as much as the line heartbeat over the same 60 s
        (in both modes): the loss starts at home. A router that never answers can't tell home from line."""
        if self._gw.b < MIN_SENDS or self._gw.a >= self._gw.b:
            return False
        gw = self._gw.a / self._gw.b
        line = self._hb.a / self._hb.b if self._hb.b else 0.0
        return gw >= K.LOSS_FRAC and gw >= line / 2

    def active(self, kind: str) -> bool:
        return kind in self._shown

    def since(self, kind: str) -> int | None:
        return self._since[kind]

    def baseline_state(self, now_ms: int | None = None) -> str:
        if self.first_ms is None:
            return "none"
        age = (now_ms if now_ms is not None else self._last) - self.first_ms
        return "none" if age < K.BASELINE_NONE_S * 1000 else "learning" if age < K.BASELINE_LEARNING_S * 1000 else "ready"

    def baseline(self, pair: str) -> float | None:
        return self._base.get(pair)

    def _set(self, kind: str, on: bool, t: int, detail: dict | None = None) -> list[ConditionChange]:
        if on:
            if self._since[kind] is None:
                self._since[kind] = t
            if detail:
                self.detail[kind] = detail
            if kind not in self._shown and t - self._since[kind] >= K.DEGRADED_AFTER_S * 1000:
                self._shown.add(kind)
                return [ConditionChange(kind, "start", self._since[kind], dict(self.detail.get(kind, {})))]
            return []
        self._since[kind] = None
        if kind in self._shown:
            self._shown.discard(kind)
            return [ConditionChange(kind, "end", t, dict(self.detail.pop(kind, {})))]
        return []

    def step(self, frame: Frame, seg) -> list[ConditionChange]:
        t = self._last = frame.t_ms
        if self.first_ms is None:
            self.first_ms = t
        outage = any(seg.state(s) == "down" for s in ("line", "lan", "wifi", "link", "host_net"))
        usable = not (frame.lag or frame.suspended)
        for w in (self._loss, self._gw, self._hb):
            w.trim(t)
        out = []

        # loss: precision from udp_stream, basic from line_hb; outage seconds belong to the incident instead
        if usable and not outage:
            probe = "udp_stream" if self.ctx.mode == "precision" else "line_hb"
            for (p, pair), r in frame.samples.items():
                judged = r.sent - r.local_fail
                if p == probe and self.ctx.usable(p, pair) and judged > 0:
                    if p == "udp_stream" and (r.lost + r.late) >= K.STREAM_LOSS_FRAC * judged:
                        continue  # an outage of the path (reflector or line), not random loss
                    self._loss.add(t, r.lost + r.late, judged)
                if p == "line_hb" and self.ctx.usable(p, pair) and judged > 0:
                    self._hb.add(t, r.lost + r.late, judged)
        loss = self._loss.a / self._loss.b if self._loss.b >= MIN_SENDS else 0.0
        on = loss >= (K.LOSS_FRAC / 2 if self.active("loss") or self._since["loss"] else K.LOSS_FRAC)  # hysteresis
        out += self._set("loss", on, t, {"loss": round(loss, 3)})

        # weak signal: absolute and relative to the 1 h median (Windows without dBm: never evaluated)
        wifi = frame.samples.get(("wifi", "wifi"))
        dbm = None
        if wifi is not None and wifi.extra_json and not frame.suspended:
            try:
                dbm = json.loads(wifi.extra_json).get("signal_dbm")
            except (ValueError, AttributeError):
                dbm = None
        if dbm is not None:
            self._rssi.append((t, dbm))
        while self._rssi and self._rssi[0][0] <= t - 3_600_000:
            self._rssi.popleft()
        weak = False
        if dbm is not None and len(self._rssi) >= 60:
            med = _pct([x[1] for x in self._rssi], 0.5)
            weak = dbm <= K.WEAK_DBM and med - dbm >= K.WEAK_BELOW_MEDIAN_DB
        if dbm is not None:
            out += self._set("weak_signal", weak, t, {"dbm": dbm})

        # Wi-Fi/LAN loss: associated, but the gateway misses ≥ 10 % over 60 s
        gw = frame.samples.get(("gateway", "gateway"))
        if usable and not outage and gw is not None and (wifi is None or wifi.ok) and gw.sent - gw.local_fail > 0:
            self._gw.add(t, gw.lost, gw.sent - gw.local_fail)
        gw_loss = self._gw.a / self._gw.b if self._gw.b >= MIN_SENDS else 0.0
        out += self._set("wifi_lan_loss", gw_loss >= K.WIFI_LAN_LOSS_FRAC, t, {"gateway_loss": round(gw_loss, 3)})

        # agent host busy: loop-lag p95 ≥ 10 ms over 30 s
        loop = frame.samples.get(("loop", "loop"))
        if loop is not None and loop.rtt_p95 is not None:
            self._loop.append((t, loop.rtt_p95))
        while self._loop and self._loop[0][0] <= t - K.LATENCY_WINDOW_S * 1000:
            self._loop.popleft()
        lag_p95 = _pct([x[1] for x in self._loop], 0.95) if self._loop else 0.0
        busy = lag_p95 >= K.BUSY_LAG_MS
        out += self._set("agent_busy", busy, t, {"loop_lag_p95_ms": round(lag_p95, 1)})

        out += self._latency(frame, t, usable and not outage, busy)
        return out

    def _latency(self, frame: Frame, t: int, learn: bool, busy: bool) -> list[ConditionChange]:
        minute = t // 60_000
        if self._minute_at is None:
            self._minute_at = minute
        if minute != self._minute_at:                       # roll the minute into the 24 h baseline
            for pair, v in self._minute.items():
                h = self._base_hist.setdefault(pair, deque(maxlen=24 * 60))
                h.append(v)
                self._base[pair] = _pct(list(h), 0.10)
            self._minute, self._minute_at = {}, minute
        for (p, pair), r in frame.samples.items():
            if p not in RTT_SOURCES or r.rtt_avg is None or not self.ctx.usable(p, pair):
                continue
            q = self._rtt.setdefault(pair, deque())
            q.append((t, r.rtt_avg, self.ctx.provider(p, pair)))
            if learn:
                self._minute[pair] = min(self._minute.get(pair, r.rtt_avg), r.rtt_min or r.rtt_avg)
        for q in self._rtt.values():
            while q and q[0][0] <= t - K.LATENCY_WINDOW_S * 1000:
                q.popleft()
        if self.baseline_state(t) == "none" or busy or frame.lag or frame.suspended:
            return self._set("latency", False, t)
        slow = set()
        for pair, q in self._rtt.items():
            b = self._base.get(pair)
            if b is None or not q:
                continue
            avg = sum(x[1] for x in q) / len(q)
            if avg >= K.LATENCY_FACTOR * b and avg >= b + K.LATENCY_PLUS_MS:
                slow.add(q[-1][2] or pair)
        return self._set("latency", len(slow) >= K.LATENCY_MIN_PROVIDERS, t, {"providers": sorted(slow)})
