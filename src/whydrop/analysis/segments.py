"""Segment states, one state machine each (spec §6.2). Pure: fed one Frame per second, in order."""
from dataclasses import dataclass, field

from whydrop.analysis import constants as K
from whydrop.analysis.model import Context, Frame

LOCAL = ("host_net", "wifi", "link")


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
            if self.state != "down":
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
        if not good and self.state != "down" and t_ms - started >= self.down_ms:
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

    def state(self, segment: str) -> str:
        if segment == "lan":
            return self._lan
        return self.local[segment].state

    def _local_good(self, frame: Frame, seg: str) -> bool | None:
        r = frame.samples.get((seg, seg))
        return None if r is None or frame.lag else r.ok > 0

    def step(self, frame: Frame) -> list[SegmentChange]:
        out: list[SegmentChange] = []
        if not self._announced:
            self._announced = True
            if self._lan == "unobservable":
                out.append(SegmentChange(frame.t_ms, "lan", "unobservable"))
        kinds = {e.kind for e in frame.events}
        for seg in LOCAL:
            forced = (seg == "wifi" and "reassoc" in kinds) or (seg == "link" and "link_flap" in kinds)
            held = self.local[seg]
            change = held.feed(frame.t_ms, self._local_good(frame, seg), force_bad=forced)
            if change:
                t = frame.t_ms if forced else held._run[1]
                out.append(SegmentChange(t, seg, change))
        out += self._step_lan(frame)
        return out

    def _step_lan(self, frame: Frame) -> list[SegmentChange]:
        if self._lan == "unobservable":
            return []
        link_seg = "wifi" if self.ctx.link_kind != "wired" else "link"
        link_now = self._local_good(frame, link_seg)
        if self.local[link_seg].state == "down" or link_now is False:  # also before wifi's 3 s hold confirms it
            self._lan_misses.clear()                  # the router can't be judged without a link to it
            return []
        r = frame.samples.get(("gateway", "gateway"))
        if r is None or frame.lag or frame.suspended or (r.ok == 0 and r.lost == 0):
            return []                                 # no evidence (or only local send failures → host_net)
        if r.ok > 0:
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
