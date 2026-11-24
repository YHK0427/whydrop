"""Segment states, one state machine each (spec §6.2). Pure: fed one Frame per second, in order."""
from collections import deque
from dataclasses import dataclass, field

from whydrop.analysis import constants as K
from whydrop.analysis.model import Context, Frame, line_quorum

LOCAL = ("host_net", "wifi", "link")
DNS_CLASSES = ("dns_router", "dns_isp", "dns_public")
REFLECTOR = ("udp_stream", "canary")


@dataclass
class SegmentChange:
    t_ms: int              # when the state really changed (back-dated to the first bad / first good send)
    segment: str
    state: str             # "down" | "up" | "unobservable"
    detail: dict = field(default_factory=dict)


class _Held:
    """Down once bad for `hold_s` seconds in a row, up once good for `hold_s` in a row; both back-dated to the
    first second of the run. Seconds without evidence neither extend nor break a run."""

    def __init__(self, hold_s: int, recover_s: int | None = None):
        self.down_ms, self.up_ms = (hold_s - 1) * 1000, ((recover_s or hold_s) - 1) * 1000
        self.state = "unknown"
        self._run: tuple[bool, int] | None = None

    def feed(self, t_ms: int, good: bool | None, force_bad: bool = False) -> str | None:
        if force_bad:
            self._run = (False, t_ms)
            if self.state == "up":
                self.state = "down"
                return "down"
            return None
        if good is None:
            return None
        if self._run is None or self._run[0] != good:
            self._run = (good, t_ms)
        started = self._run[1]
        if good and self.state != "up" and t_ms - started >= (self.up_ms if self.state == "down" else 0):
            was, self.state = self.state, "up"
            return "up" if was == "down" else None   # the first "up" is just the start of watching
        if not good and self.state == "up" and t_ms - started >= self.down_ms:  # never up → no evidence it broke
            self.state = "down"
            return "down"
        return None


class Segments:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.local = {s: _Held(K.LOCAL_HOLD_S) for s in LOCAL}
        self._starts: dict[str, int] = {}
        self._lan = "unobservable" if not ctx.lan_observable else "unknown"
        self._lan_misses: list[int] = []
        self._announced = False
        self._seen: dict[str, int] = {}
        self._q: deque = deque()                 # (t_ms, probe, pair, provider, failed, row) of line-quorum sends
        self._line = "unknown"
        self._line_start: int | None = None
        self._line_detail: dict = {}
        self._gated = False
        self._first_ok: int | None = None
        self._stream_run = 0   # seconds in a row the stream has been bad
        self.last_recovery_ms = -1                # last lan/line recovery: DNS attempts before it don't count
        self._local_up_ms = -1                    # last wifi/link/lan recovery: a line down never starts before it
        self._outage_spans: deque = deque(maxlen=16)   # (down, up) of line, lan and local downs
        self._down_from: dict[str, int] = {}
        self._dns = {c: "unknown" for c in DNS_CLASSES}
        self._dns_hist = {c: deque() for c in DNS_CLASSES}

    def state(self, segment: str) -> str:
        if segment == "lan":
            return self._lan
        if segment == "line":
            return "down" if self._line == "down" else self._line
        if segment in self._dns:
            return self._dns[segment]
        return self.local[segment].state

    def _local_good(self, frame: Frame, seg: str) -> bool | None:
        r = frame.samples.get((seg, seg))
        return None if r is None or frame.lag or frame.suspended else r.ok > 0

    def step(self, frame: Frame) -> list[SegmentChange]:
        out: list[SegmentChange] = []
        if not self._announced:
            self._announced = True
            if self._lan == "unobservable":
                out.append(SegmentChange(frame.t_ms, "lan", "unobservable"))
        kinds = {e.kind for e in frame.events} if not frame.suspended else set()
        for seg in LOCAL:
            if frame.samples.get((seg, seg)) is not None:
                self._seen[seg] = frame.t_ms
            elif self.local[seg].state == "down" and frame.t_ms - self._seen.get(seg, frame.t_ms) > K.LOCAL_STALE_S * 1000:
                self.local[seg].state, self.local[seg]._run = "unknown", None   # its probe went away (network switch)
                out.append(SegmentChange(frame.t_ms, seg, "up", {"stale": True}))
        for seg in LOCAL:
            forced = (seg == "wifi" and "reassoc" in kinds) or (seg == "link" and "link_flap" in kinds)
            held = self.local[seg]
            change = held.feed(frame.t_ms, self._local_good(frame, seg), force_bad=forced)
            if change:
                t = frame.t_ms if forced else held._run[1]
                out.append(SegmentChange(t, seg, change))
                if change == "up" and seg != "host_net":
                    self._local_up_ms = max(self._local_up_ms, t)
        if any(e.kind == "suspend" for e in frame.events):  # the host slept: whatever was down is no longer known
            woke = {"host_slept": True}
            for seg, held in self.local.items():
                if held.state == "down":
                    out.append(SegmentChange(frame.t_ms, seg, "up", woke))
                held.state, held._run = ("unknown" if held.state == "down" else held.state), None
            if self._line == "down":
                if not self._gated:
                    out.append(SegmentChange(frame.t_ms, "line", "up", woke))
                self._line, self._gated, self._first_ok = "up", False, None
            self._lan_misses.clear()
            if self._lan == "down":
                out.append(SegmentChange(frame.t_ms, "lan", "up", woke))
                self._lan = "up"
            for c in self._dns:
                if self._dns[c] == "down":
                    out.append(SegmentChange(frame.t_ms, c, "up", woke))
                    self._dns[c] = "up"
        lan_before = self._lan
        out += self._step_lan(frame)
        if lan_before == "down" and self._lan == "up":
            self.last_recovery_ms = frame.t_ms
            self._local_up_ms = max(self._local_up_ms, frame.t_ms)
        for c in out:
            if c.segment in LOCAL or c.segment == "lan":   # its failed sends are no lossy period for the line gate
                if c.state == "down":
                    self._down_from[c.segment] = c.t_ms
                elif c.segment in self._down_from:
                    self._outage_spans.append((self._down_from.pop(c.segment), c.t_ms))
        if frame.lag or frame.suspended:
            self._stream_run = 0
        else:
            out += self._step_line(frame)
            out += self._step_dns(frame)
        return out

    def _step_lan(self, frame: Frame) -> list[SegmentChange]:
        if self._lan == "unobservable":
            g = frame.samples.get(("gateway", "gateway"))
            if g is None or g.ok == 0:
                return []
            self._lan = "up"                     # it answers after all (e.g. booted after us): judge it from now on
            self.ctx.lan_observable = True
            return [SegmentChange(frame.t_ms, "lan", "up", {"observable": True})]
        link_seg = "wifi" if self.ctx.link_kind != "wired" else "link"
        link_now = self._local_good(frame, link_seg)
        if self.local[link_seg].state == "down" or link_now is False:  # also before wifi's 3 s hold confirms it
            self._lan_misses.clear()                  # the router can't be judged without a link to it
            return []
        r = frame.samples.get(("gateway", "gateway"))
        if r is None or frame.lag or frame.suspended or (r.ok == 0 and r.lost == 0):
            return []                                 # no evidence (or only local send failures → host_net)
        through = any(x.ok + x.late > 0 for (p, pair), x in frame.samples.items()   # late: it still crossed the router
                      if line_quorum(p, pair, self.ctx) and x.sent - x.local_fail > 0)
        if r.ok > 0 or through:
            # a reply from the router, or one from the internet *through* it, proves the router is up; a gateway probe
            # that timed out meanwhile was slow (Wi-Fi power save, queueing), not lost (measured on a Wi-Fi host)
            self._lan_misses.clear()
            if self._lan == "down":
                self._lan = "up"
                return [SegmentChange(frame.t_ms, "lan", "up")]
            self._lan = "up"
            return []
        self._lan_misses.append(frame.t_ms)
        if len(self._lan_misses) >= K.LAN_MISSES and self._lan != "down":
            self._lan = "down"
            return [SegmentChange(self._lan_misses[0], "lan", "down")]
        return []

    # ---------- line ----------
    def _quorum_rows(self, frame: Frame):
        stream_bad = False
        for (probe, pair), r in frame.samples.items():
            if not line_quorum(probe, pair, self.ctx):
                continue
            judged = r.sent - r.local_fail
            if judged <= 0:
                continue                                 # only local send failures: that's host_net's business
            if probe == "udp_stream":                    # ≥ 80 % loss for STREAM_LOSS_S counts as a failed send
                bad = (r.lost + r.late) >= K.STREAM_LOSS_FRAC * judged
                failed, stream_bad = bad and self._stream_run + 1 >= K.STREAM_LOSS_S, bad
                if failed:                               # the run's earlier seconds count too, once confirmed
                    earlier = [x for x in reversed(self._q) if x[1] == "udp_stream"][:K.STREAM_LOSS_S - 1]
                    for x in earlier:
                        x[4] = True
            else:
                failed = r.ok == 0
            yield probe, pair, self.ctx.provider(probe, pair), failed, r
        self._stream_run = self._stream_run + 1 if stream_bad else 0

    def _link_ok(self) -> bool:
        link_seg = "wifi" if self.ctx.link_kind != "wired" else "link"
        return self.local[link_seg].state != "down" and self._lan != "down"

    def _step_line(self, frame: Frame) -> list[SegmentChange]:
        t = frame.t_ms
        rows = list(self._quorum_rows(frame))
        for probe, pair, prov, failed, r in rows:
            self._q.append([t, probe, pair, prov, failed, r])
        while self._q and self._q[0][0] < t - (K.GATE_WINDOW_S + K.GATE_SHORT_S + 5) * 1000:
            self._q.popleft()
        return self._line_down_check(t) if self._line != "down" else self._line_recovery(t, rows)

    def _line_down_check(self, t: int) -> list[SegmentChange]:
        self._line = "up" if any(not x[4] for x in self._q if x[0] == t) else self._line
        if not self._link_ok():
            return []
        win = [x for x in self._q if x[0] >= t - (K.LINE_LOOKBACK_S - 1) * 1000]
        basic = [x for x in win if x[1] not in REFLECTOR]
        refl = [x for x in win if x[1] in REFLECTOR]
        if not basic or not all(x[4] for x in basic) or not all(x[4] for x in refl):
            return []
        failing = basic + refl
        if len({x[3] for x in failing}) < K.LINE_MIN_PROVIDERS or sum(x[5].sent if x[1] not in REFLECTOR else 1
                                                                   for x in failing) < K.LINE_MIN_SENDS:
            return []
        oks = [x[0] for x in self._q if not x[4] and x[0] < win[0][0]]
        start = min(x[0] for x in self._q if x[4] and x[0] > (max(oks) if oks else -1))
        start = max(start, self._local_up_ms)
        span = [x[5] for x in self._q if x[0] >= start]
        lost, late = sum(r.lost for r in span), sum(r.late for r in span)
        in_outage = lambda u: any(a <= u < b for a, b in self._outage_spans)  # noqa: E731
        hb = [x[5] for x in self._q if x[1] == "line_hb" and start - K.GATE_WINDOW_S * 1000 <= x[0] < start
              and not in_outage(x[0])]                 # a previous outage is not "a lossy period"
        sent_hb = sum(r.sent - r.local_fail for r in hb)
        hb_loss = sum(r.lost + r.late for r in hb) / sent_hb if sent_hb else 0.0
        self._line, self._line_start, self._first_ok = "down", start, None
        self._gated = hb_loss >= K.GATE_LOSS_FRAC
        self._line_detail = {"providers": sorted(p for p in {x[3] for x in failing} if p),
                             "queueing_evidence": (lost + late) > 0 and late / (lost + late) >= K.LATE_QUEUEING_FRAC,
                             "prior_line_hb_loss": round(hb_loss, 3)}
        if self._gated:
            return []                                    # a lossy period: wait to see whether it's only a burst
        return [SegmentChange(start, "line", "down", dict(self._line_detail))]

    def _line_recovery(self, t: int, rows) -> list[SegmentChange]:
        out = []
        basic = [x for x in rows if x[0] not in REFLECTOR]   # the end is never the canary (spec §6.1)
        if any(not x[3] for x in basic):
            if self._first_ok is None:
                self._first_ok = t
        elif basic:
            self._first_ok = None                      # every basic send failed again
        recovered = self._first_ok is not None and t - self._first_ok >= (K.LINE_RECOVER_S - 1) * 1000
        short = K.GATE_SHORT_S * 1000
        if self._gated:
            if recovered and self._first_ok - self._line_start < short:
                out.append(SegmentChange(self._line_start, "line", "burst",
                                         {"duration_s": (self._first_ok - self._line_start) / 1000}))
                self._line, self._gated = "up", False
                return out
            if t - self._line_start >= short and (self._first_ok is None or self._first_ok - self._line_start >= short):
                self._gated = False
                out.append(SegmentChange(self._line_start, "line", "down", dict(self._line_detail)))
        if recovered and not self._gated:
            out.append(SegmentChange(self._first_ok, "line", "up"))
            self._line = "up"
            self.last_recovery_ms = self._first_ok
            self._outage_spans.append((self._line_start, self._first_ok))
        return out

    # ---------- DNS ----------
    def _dns_window_ms(self, cls: str) -> int:
        base = self.ctx.intervals.get("dns", 5)
        iv = max(base, 10) if cls == "dns_public" and self.ctx.mode == "precision" else base
        return int(K.DNS_WINDOW_INTERVALS * iv * 1000)

    def _step_dns(self, frame: Frame) -> list[SegmentChange]:
        t, out = frame.t_ms, []
        for (probe, pair), r in frame.samples.items():
            if probe != "dns" or not self.ctx.usable(probe, pair) or r.sent - r.local_fail <= 0:
                continue
            cls = pair.split(":", 1)[0]
            if cls in self._dns_hist:
                self._dns_hist[cls].append((t, pair, r.ok == 0))
        for cls in DNS_CLASSES:
            h = self._dns_hist[cls]
            win = self._dns_window_ms(cls)
            while h and h[0][0] <= t - 3 * win:
                h.popleft()
            now = [x for x in h if x[0] == t]
            if self._dns[cls] == "down":
                ok = [x for x in now if not x[2]]
                if ok:
                    self._dns[cls] = "up"
                    out.append(SegmentChange(t, cls, "up"))
                continue
            if any(not x[2] for x in now):
                self._dns[cls] = "up"
            if self._line == "down" or not self._link_ok():
                continue
            recent = [x for x in h if x[0] > t - win and x[0] > self.last_recovery_ms]
            pairs: dict[str, list[bool]] = {}
            for _, pair, failed in recent:
                pairs.setdefault(pair, []).append(failed)
            if pairs and all(len(v) >= K.DNS_MIN_ATTEMPTS and all(v) for v in pairs.values()):
                self._dns[cls] = "down"
                out.append(SegmentChange(min(x[0] for x in recent), cls, "down", {"pairs": len(pairs)}))
        return out
