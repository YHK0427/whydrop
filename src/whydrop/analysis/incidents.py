"""Incidents: opened by segment downs, merged, ended, plus point incidents (spec §6.1 steps 3 and 6, §6.2 merging,
§6.3 gaps, §6.4 R4/R5/NAT reset)."""
import itertools
from collections import deque
from dataclasses import dataclass, field

from whydrop.agent.events import Event
from whydrop.analysis import constants as K
from whydrop.analysis import texts
from whydrop.analysis.model import Context, Frame

INCIDENT_SEGMENTS = ("host_net", "wifi", "link", "lan", "line", "dns_router", "dns_isp", "dns_public")
LOCAL_RECOVERY = ("wifi", "link", "lan")
EVIDENCE_EVENTS = {"reassoc", "roam", "link_flap", "link_speed", "ip_change", "mapping_reset", "rst", "stall",
                   "reconnect", "kernel_timeout", "tcp_info", "udp_outage", "idle_state_lost", "net_change", "host_net"}
_ids = itertools.count(1)


@dataclass(eq=False)
class Incident:
    start_ms: int
    end_ms: int | None = None
    segments: set = field(default_factory=set)          # every segment that was down during it
    point: str | None = None                            # point incidents: ip_change / idle_state_lost / nat_reset / roam_loss
    tags: set = field(default_factory=set)
    evidence: dict = field(default_factory=dict)
    chain: list = field(default_factory=list)
    events: list = field(default_factory=list)
    open_segments: set = field(default_factory=set)
    downs: list = field(default_factory=list)           # SegmentChange downs, in order
    key: int = field(default_factory=lambda: next(_ids))
    final: bool = False                                 # its cause is final: frozen, never merged into again


@dataclass
class IncidentChange:
    op: str                    # "open" | "update" | "close" | "finding"
    incident: Incident | None
    kind: str | None = None
    ts_ms: int | None = None


class Incidents:
    def __init__(self, ctx: Context, reopen: list[Incident] | None = None):
        self.ctx = ctx
        self.current: Incident | None = None
        self.last: Incident | None = None
        self._reopen = list(reopen or [])
        self._recent: deque[Event] = deque()            # events of the last 2 minutes
        self._loss: deque[tuple[int, str]] = deque()     # (t, probe) seconds with any loss
        self._pending: list[tuple[int, str, Event]] = []  # (decide at, kind, event)
        self._local_up: dict[str, int] = {}
        self._idle_seen: set[int] = set()

    # ---------- helpers ----------
    def _open(self, inc: Incident, out: list) -> None:
        inc.events += [e for e in self._recent if e.ts_ms >= inc.start_ms - K.R1A_AFTER_S * 1000 and e not in inc.events]
        self.current = inc
        out.append(IncidentChange("open", inc))

    def _close(self, inc: Incident, t: int, out: list) -> None:
        inc.end_ms = t
        if t - inc.start_ms <= K.LONG_OUTAGE_S * 1000:
            inc.tags.discard("long_outage")             # tagged while the recovery was being confirmed, but not past 1 h
        self.current, self.last = None, inc
        out.append(IncidentChange("close", inc))

    def _point(self, kind: str, at: int, out: list, **evidence) -> None:
        inc = Incident(start_ms=at, end_ms=at, point=kind, evidence=evidence)
        inc.events = [e for e in self._recent if abs(e.ts_ms - at) <= K.NAT_RESET_WINDOW_S * 1000]
        out.append(IncidentChange("open", inc))
        out.append(IncidentChange("close", inc))

    def _lost_between(self, a: int, b: int, probes) -> bool:
        return any(a <= t <= b and p in probes for t, p in self._loss)

    def _near(self, kind: str, at: int, window_s: int) -> list[Event]:
        return [e for e in self._recent if e.kind == kind and abs(e.ts_ms - at) <= window_s * 1000]

    # ---------- step ----------
    def step(self, frame: Frame, seg_changes, cond_changes, seg) -> list[IncidentChange]:
        t, out = frame.t_ms, []
        for inc in self._reopen:                         # left open by a previous run
            inc.tags.add("agent_restarted")
            self._close(inc, t, out)
        self._reopen = []

        for e in frame.events:
            self._recent.append(e)
        while self._recent and self._recent[0].ts_ms < t - 120_000:
            self._recent.popleft()
        for (p, _), r in frame.samples.items():
            judged = r.sent - r.local_fail
            if p == "udp_stream":
                if judged > 0 and (r.lost + r.late) >= K.STREAM_LOSS_FRAC * judged:
                    self._loss.append((t, p))       # an outage on the stream, not background loss
            elif r.lost or r.late:
                self._loss.append((t, p))
        while self._loss and self._loss[0][0] < t - 120_000:
            self._loss.popleft()

        for e in frame.events:
            if e.kind == "suspend" and self.current is not None:
                slept_at = e.ts_ms - int(e.detail.get("slept_s", 0) * 1000)
                self.current.tags.add("host_slept")
                self.current.open_segments.clear()
                self._close(self.current, max(self.current.start_ms, slept_at), out)
        live = self.current
        for e in frame.events:
            if live is not None and e.kind in EVIDENCE_EVENTS:
                live.events.append(e)
            elif e.kind in EVIDENCE_EVENTS and self.last is not None and self.last.point is None and not self.last.final \
                    and t - self.last.end_ms <= K.SETTLE_S * 1000:
                self.last.events.append(e)               # still settling: R4 looks 60 s past the end

        for c in seg_changes:
            if c.segment not in INCIDENT_SEGMENTS or c.state not in ("down", "up"):
                continue
            if c.state == "up":
                if c.segment in LOCAL_RECOVERY:
                    self._local_up[c.segment] = c.t_ms
                if self.current and c.segment in self.current.open_segments:
                    self.current.open_segments.discard(c.segment)
                    if not self.current.open_segments:
                        self._close(self.current, c.t_ms, out)
                continue
            if self.ctx.vpn and c.segment in ("lan", "line"):
                continue                                 # through a VPN these describe the tunnel (standing finding)
            out += self._down(c)

        if self.current and "long_outage" not in self.current.tags and t - self.current.start_ms > K.LONG_OUTAGE_S * 1000:
            self.current.tags.add("long_outage")
            out.append(IncidentChange("update", self.current))

        for e in frame.events:
            if e.kind == "ip_change":
                tgt = self.current or (self.last if self.last and self.last.point is None and not self.last.final
                                       and t - self.last.end_ms <= K.R4_AFTER_S * 1000 else None)
                if tgt is None:
                    self._point("ip_change", e.ts_ms, out)
                elif tgt is not self.current and e not in tgt.events:
                    tgt.events.append(e)
                    out.append(IncidentChange("update", tgt))
            elif e.kind == "idle_state_lost":
                self._pending.append((e.ts_ms + K.R5_MARGIN_S * 1000, "idle", e))
            elif e.kind == "rst" and e.detail.get("canary", "hot") == "hot":
                self._pending.append((e.ts_ms + K.NAT_RESET_WINDOW_S * 1000, "rst", e))
            elif e.kind == "roam":
                self._pending.append((e.ts_ms + (K.ROAM_LOSS_WINDOW_S + K.GATE_SHORT_S) * 1000, "roam", e))  # a drop it belongs to may take 10 s to confirm
        out += self._decide(t)
        return out

    def _down(self, c) -> list[IncidentChange]:
        out = []
        inc = self.current
        if inc is None and self.last is not None and self.last.point is None and not self.last.final:
            since_end = c.t_ms - self.last.end_ms
            after_local = c.segment == "line" and any(c.t_ms - u <= K.MERGE_AFTER_LOCAL_S * 1000
                                                       for s, u in self._local_up.items() if s in self.last.segments)
            if since_end <= K.MERGE_AFTER_END_S * 1000 or after_local:
                inc = self.last
                inc.end_ms = None
                self.current = inc
                out.append(IncidentChange("update", inc))
        if inc is None:
            inc = Incident(start_ms=c.t_ms)
            self._open(inc, out)
        elif out == []:
            out.append(IncidentChange("update", inc))
        if {c.segment} | inc.segments >= {"lan", "line"} and texts.ROUTER_RESTART not in inc.chain:
            inc.chain.append(texts.ROUTER_RESTART)
        inc.segments.add(c.segment)
        inc.open_segments.add(c.segment)
        inc.downs.append(c)
        return out

    def _decide(self, t: int) -> list[IncidentChange]:
        out, keep = [], []
        for due, kind, e in self._pending:
            if due > t:
                keep.append((due, kind, e))
                continue
            if kind == "idle":
                a, b = e.ts_ms - 2 * K.R5_MARGIN_S * 1000, e.ts_ms + K.R5_MARGIN_S * 1000
                if self._lost_between(a, b, ("udp_stream", "canary")) or self._near("stall", e.ts_ms, 10) \
                        or self._near("rst", e.ts_ms, 10):
                    continue                             # the hot paths lost too: part of a wider problem
                interval = e.detail.get("interval_s")
                if interval in self._idle_seen:
                    out.append(IncidentChange("finding", None, "idle_expiry_repeat", e.ts_ms))
                    continue
                self._idle_seen.add(interval)
                self._point("idle_state_lost", e.ts_ms, out, interval_s=interval)
            elif kind == "rst":
                w = K.NAT_RESET_WINDOW_S
                new_port = self._near("mapping_reset", e.ts_ms, w) or [
                    x for x in self._near("reconnect", e.ts_ms, w) if x.detail.get("new_port")]
                if new_port and not self._near("ip_change", e.ts_ms, w):
                    self._point("nat_reset", e.ts_ms, out)
            elif kind == "roam":
                busy = self.current is not None or (self.last is not None and self.last.end_ms is not None
                                                    and e.ts_ms - self.last.end_ms <= K.MERGE_AFTER_END_S * 1000)
                if not busy and self._lost_between(e.ts_ms - K.ROAM_LOSS_WINDOW_S * 1000, e.ts_ms + K.ROAM_LOSS_WINDOW_S * 1000, ("gateway", "line_hb", "stun", "tcp_connect",
                                                                      "udp_stream", "canary", "dns")):
                    self._point("roam_loss", e.ts_ms, out)
        self._pending = keep
        return out
