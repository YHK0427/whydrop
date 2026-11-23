"""Likely causes (spec §6.4): rules in priority order, the queueing-first rule, the 80 s settle, and the
"in protocol terms" paragraph."""
from dataclasses import dataclass, field

from whydrop.analysis import constants as K
from whydrop.analysis import texts
from whydrop.analysis.conditions import RTT_SOURCES
from whydrop.analysis.incidents import Incident
from whydrop.analysis.model import Context, line_quorum

POINT_RULES = {"ip_change": "R4", "idle_state_lost": "R5", "nat_reset": "R5_reset", "roam_loss": "R1a_roam"}


@dataclass
class Cause:
    rule: str
    label: str
    next_step: str
    secondary: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


@dataclass
class Final:
    incident: Incident
    cause: Cause
    provisional: Cause
    changed: bool


def _cause(rule: str, label: str | None = None, **kw) -> Cause:
    lab, step = texts.CAUSES[rule]
    return Cause(rule.split("_")[0], label or lab, step, **kw)


def _events(inc: Incident, kind: str, a_ms: int, b_ms: int) -> list:
    return [e for e in inc.events if e.kind == kind and a_ms <= e.ts_ms <= b_ms]


def _queueing(inc: Incident, frames, cond, ctx: Context) -> tuple[bool, bool]:
    """(queueing before the drop, also on the gateway) — successful samples in the 10 s before were ≥ 3× baseline
    and ≥ +50 ms, or most sends behind the line down came back late."""
    late = any(d.detail.get("queueing_evidence") for d in inc.downs if d.segment == "line")
    based = cond is not None and cond.baseline_state(inc.start_ms) != "none"   # no baseline in the first hour
    if not late and not based:
        return False, False
    a, b = inc.start_ms - K.QUEUE_LOOKBACK_S * 1000, inc.start_ms
    end = inc.end_ms if inc.end_ms is not None else max((f.t_ms for f in frames), default=b)
    slow, gw_slow, gw_before, gw_timeouts = set(), 0, [], 0
    for f in frames:
        gw = f.samples.get(("gateway", "gateway"))
        if late and gw is not None and gw.lost > 0 and b - K.GW_TIMEOUT_LEAD_S * 1000 <= f.t_ms <= end:
            gw_timeouts += any(x.late > 0 for (p, pair), x in f.samples.items() if line_quorum(p, pair, ctx))
            # a reply from beyond the router came back late in the same second: the router is up, its hop is slow
        if f.t_ms >= b or f.t_ms < a - 600_000:
            continue
        if f.t_ms < a:
            if gw is not None and gw.rtt_avg is not None:
                gw_before.append(gw.rtt_avg)
            continue
        for (p, pair), r in f.samples.items():
            base = cond.baseline(pair) if based else None
            if p in RTT_SOURCES and r.ok and r.rtt_avg is not None and base is not None \
                    and r.rtt_avg >= K.LATENCY_FACTOR * base and r.rtt_avg >= base + K.LATENCY_PLUS_MS:
                slow.add(pair)
        if gw is not None and gw.ok and gw.rtt_avg is not None and gw_before:
            g0 = min(gw_before)
            gw_slow += gw.rtt_avg >= K.LATENCY_FACTOR * g0 and gw.rtt_avg >= g0 + K.LATENCY_PLUS_MS
    return late or len(slow) >= 2, gw_slow >= 2 or gw_timeouts >= 2   # two pairs, not one twice; the router twice


def _direction(inc: Incident, frames) -> dict:
    up = down = 0
    outs = [e for e in inc.events if e.kind == "udp_outage"]
    if outs:
        if any(e.detail.get("status") == "unknown" for e in outs):
            return {"direction": "unknown"}
        up = sum(e.detail.get("lost_up") or 0 for e in outs)
        if any(e.detail.get("status") == "down_unmeasurable" for e in outs):
            return {"direction": "upload", "lost_up": up, "lost_down": None}  # nothing came back to judge down by
        down = sum(e.detail.get("lost_down") or 0 for e in outs)
    else:
        for f in frames:
            if inc.start_ms <= f.t_ms <= (inc.end_ms or f.t_ms):
                r = f.samples.get(("udp_stream", "reflector"))
                if r is not None:
                    up, down = up + r.lost_up, down + r.lost_down
    if not up and not down:
        return {}
    return {"direction": "upload" if not down else "download" if not up else "both", "lost_up": up, "lost_down": down}


def classify(inc: Incident, frames, cond, ctx: Context) -> Cause:
    if inc.point == "idle_state_lost":
        iv, limit = inc.evidence.get("interval_s"), ctx.nat_tcp_timeout_s
        rule = "R5" if iv is None or limit is None else "R5_expiry" if iv > limit else "R5_loss"
        return _cause(rule, evidence=dict(inc.evidence))
    if inc.point:
        return _cause(POINT_RULES[inc.point], evidence=dict(inc.evidence))
    segs, s = inc.segments, inc.start_ms

    def near(seg, before, after):
        return any(d.segment == seg and s - before * 1000 <= d.t_ms <= s + after * 1000 for d in inc.downs)
    if near("wifi", K.R1A_BEFORE_S, K.R1A_AFTER_S) \
            or _events(inc, "reassoc", s - K.R1A_BEFORE_S * 1000, s + K.R1A_AFTER_S * 1000) \
            or _events(inc, "roam", s - K.R1A_BEFORE_S * 1000, s + K.R1A_AFTER_S * 1000):
        return _cause("R1a", secondary=_secondary(inc))
    if near("link", K.R1C_WINDOW_S, K.R1C_WINDOW_S) \
            or _events(inc, "link_flap", s - K.R1C_WINDOW_S * 1000, s + K.R1C_WINDOW_S * 1000):
        return _cause("R1c", secondary=_secondary(inc))
    if near("host_net", K.R1A_BEFORE_S, K.R1A_AFTER_S):
        return _cause("R1d")
    queued, at_home = _queueing(inc, frames, cond, ctx)
    if queued and segs & {"lan", "line"}:
        if at_home:
            c = _cause("R7", texts.IN_HOME_QUEUEING, evidence={"where": "home"})   # the line timed out; the delay is at home
            c.next_step = texts.IN_HOME_STEP
            return c
        return _cause("R7", texts.QUEUEING_TIMEOUTS)
    if "lan" in segs:
        known = ctx.link_kind != "unknown" and not ctx.vpn
        return _cause("R1b" if known else "R1b_unobservable", secondary=_secondary(inc))
    end = inc.end_ms if inc.end_ms is not None else s
    if _events(inc, "ip_change", s, end + K.R4_AFTER_S * 1000):
        sec = ["R2"] if "line" in segs else []
        if _events(inc, "rst", s, end + K.R4_AFTER_S * 1000):
            sec.append("RST")
        return _cause("R4", secondary=sec)
    dns = segs & {"dns_router", "dns_isp", "dns_public"}
    if dns and "line" not in segs:
        kind = _r3_kind(dns)
        if kind == "router" and not ctx.isp_dns_known:
            kind = "router_upstream"
        return _cause("R3", texts.R3_LABELS[kind], evidence={"classes": sorted(dns)})
    if "line" in segs:
        return _cause("R2" if ctx.lan_observable else "R2_unobservable", evidence=_direction(inc, frames))
    return _cause("unknown")


def _secondary(inc: Incident) -> list:
    sec = []
    if any(e.kind == "ip_change" for e in inc.events):
        sec.append("R4")
    if "line" in inc.segments:
        sec.append("R2")
    return sec


def _r3_kind(dns: set) -> str:
    if dns == {"dns_router"}:
        return "router"
    if dns == {"dns_isp"}:
        return "isp"
    if dns == {"dns_router", "dns_isp"}:
        return "isp_outage"
    if dns == {"dns_public"}:
        return "public"
    return "wide"


def label_period(kind: str, ctx: Context, line_hb_lossy: bool = True, at_home: bool = False) -> Cause | None:
    """R6 and R7 label degraded periods (they never open incidents)."""
    if kind == "loss" and at_home:
        return _cause("R6_home", evidence={"where": "home"})
    if kind == "loss":
        line = ctx.mode == "basic" or line_hb_lossy
        return _cause("R6" if line else "R6_path", evidence={"where": "line" if line else "path"})
    if kind == "latency":
        return _cause("R7")
    return None


class Settler:
    """Provisional cause while open; final at end + 80 s, frozen, with `changed` when it differs."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self._due: dict[int, tuple[int, Incident, Cause]] = {}

    def step(self, frame, changes, frames, cond) -> list[Final]:
        for c in changes:
            if c.incident is None:
                continue
            if c.op == "close" and c.incident.end_ms is not None:  # (None: reopened by a merge in this same step)
                prov = classify(c.incident, frames, cond, self.ctx)
                c.incident.evidence["provisional"] = prov.rule
                wait = K.SETTLE_S
                if c.incident.segments & {"lan", "wifi", "link", "host_net"}:
                    wait = max(wait, K.MERGE_AFTER_LOCAL_S)   # a line drop may still join it (router restart)
                self._due[c.incident.key] = (c.incident.end_ms + wait * 1000, c.incident, prov)
            elif c.op != "close":
                self._due.pop(c.incident.key, None)   # reopened by a merge: settle again after the new end
        out = []
        for key, (due, inc, prov) in list(self._due.items()):
            if due <= frame.t_ms:
                del self._due[key]
                inc.final = True
                final = classify(inc, frames, cond, self.ctx)
                out.append(Final(inc, final, prov, (final.rule, final.label) != (prov.rule, prov.label)))
        return out


_PROTO = {   # the "In protocol terms" panel in both dashboard languages; the codes stay as they are on the wire
    "en": {"unknown": "direction unknown (the reflector restarted)", "all_up": "all lost upstream",
           "all_down": "all lost downstream", "up_only": "{up} lost upstream; downstream not measurable",
           "both": "{up} lost upstream, {down} downstream",
           "udp": "UDP: sent seq {a}–{b}; reflector recv_count +{got} → {what}.",
           "stall": "HB got no reply", "retrans": "the kernel retransmitted {n} times (RTO {lo:g} → {hi:g} s)",
           "rst": "an RST ended the connection", "no_rst": "no RST, so the connection survived",
           "ack": "the first HB_ACK came after {s} s of silence", "tcp": "TCP: {items}.", "sep": "; "},
    "ko": {"unknown": "방향은 알 수 없어요(reflector가 재시작했어요)", "all_up": "모두 올라가는 길에서 사라졌어요",
           "all_down": "모두 내려오는 길에서 사라졌어요", "up_only": "올라가는 길에서 {up}개가 사라졌고, 내려오는 쪽은 잴 수 없었어요",
           "both": "올라가는 길에서 {up}개, 내려오는 길에서 {down}개가 사라졌어요",
           "udp": "UDP: seq {a}–{b} 전송, reflector의 recv_count +{got} → {what}.",
           "stall": "HB에 응답이 없었어요", "retrans": "커널이 {n}번 재전송했어요(RTO {lo:g} → {hi:g}초)",
           "rst": "RST로 연결이 끊겼어요", "no_rst": "RST가 없어 연결은 살아 있었어요",
           "ack": "{s}초 동안 조용하다가 첫 HB_ACK가 왔어요", "tcp": "TCP: {items}.", "sep": ". "},
}


def protocol_paragraph(inc: Incident, lang: str = "en") -> str:
    """The "In protocol terms" panel: a paragraph built only from recorded evidence."""
    w = _PROTO[lang]
    parts = []
    for e in inc.events:
        if e.kind != "udp_outage":
            continue
        d = e.detail
        a, b = d.get("from_seq"), d.get("to_seq")
        gap = (b - a - 1) if a is not None and b is not None else None   # seqs between the ECHO before and after
        up, down, status = d.get("lost_up"), d.get("lost_down"), d.get("status")
        if status == "unknown" or up is None:
            what = w["unknown"]
        elif up == gap:
            what = w["all_up"]
        elif status == "ok" and down == gap and not up:
            what = w["all_down"]
        elif down is None:
            what = w["up_only"].format(up=up)
        else:
            what = w["both"].format(up=up, down=down)
        got = gap - up if gap is not None and up is not None else 0          # reached the reflector in the gap
        parts.append(w["udp"].format(a=a + 1, b=b - 1, got=max(0, got), what=what))
    tcp = []
    if any(e.kind == "stall" and e.detail.get("phase") == "start" for e in inc.events):
        tcp.append(w["stall"])
    rtos = [e.detail["rto_ms"] for e in inc.events if e.kind == "tcp_info" and "rto_ms" in e.detail]
    retrans = max((e.detail.get("retransmits", 0) for e in inc.events if e.kind == "tcp_info"), default=0)
    if rtos and max(rtos) > min(rtos):
        tcp.append(w["retrans"].format(n=retrans, lo=min(rtos) / 1000, hi=max(rtos) / 1000))
    if tcp:
        rst = any(e.kind == "rst" for e in inc.events)
        tcp.append(w["rst"] if rst else w["no_rst"])
        ends = [e for e in inc.events if e.kind == "stall" and e.detail.get("phase") == "end"]
        if ends and not rst:
            tcp.append(w["ack"].format(s=ends[-1].detail.get("duration_s")))
        parts.append(w["tcp"].format(items=w["sep"].join(tcp)))
    return " ".join(parts)
