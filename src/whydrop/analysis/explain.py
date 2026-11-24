"""Why a verdict: the measurements behind it ("facts") and why the other causes don't fit ("ruled_out").

Language-neutral: each entry is {"k": key, ...numbers}; the dashboard and the summary word them from the i18n files.
Computed once, when the cause is final, from the frames still in the engine's history."""
import statistics

from whydrop.analysis import constants as K
from whydrop.analysis.incidents import Incident
from whydrop.analysis.model import Context, line_quorum

LOCAL = ("wifi", "link", "host_net")
WIFI_WINDOW_S = 15


def _window(inc: Incident, frames):
    end = inc.end_ms if inc.end_ms is not None else inc.start_ms
    a, b = inc.start_ms - 3_000, end + 1_000
    return [f for f in frames if a <= f.t_ms <= b], [f for f in frames if inc.start_ms - 70_000 <= f.t_ms < inc.start_ms - 10_000]


def _gateway(during, before) -> dict | None:
    rows = [f.samples.get(("gateway", "gateway")) for f in during]
    rows = [r for r in rows if r is not None and r.sent - r.local_fail > 0]
    if not rows:
        return None
    base = [r.rtt_avg for f in before if (r := f.samples.get(("gateway", "gateway"))) is not None and r.rtt_avg is not None]
    peak = max((r.rtt_max or r.rtt_avg for r in rows if (r.rtt_max or r.rtt_avg) is not None), default=None)
    return {"k": "gw", "sent": sum(r.sent - r.local_fail for r in rows), "ok": sum(r.ok for r in rows),
            "lost": sum(r.lost for r in rows), "late": sum(r.late for r in rows),
            "base": round(statistics.median(base), 1) if base else None, "peak": round(peak, 1) if peak is not None else None}


def _line(during, ctx: Context) -> dict | None:
    sent = ok = late = lost = 0
    rtt = []
    for f in during:
        for (p, pair), r in f.samples.items():
            if p == "gateway" or not line_quorum(p, pair, ctx):
                continue
            sent += r.sent - r.local_fail
            ok += r.ok
            late += r.late
            lost += r.lost
            if r.rtt_max is not None:
                rtt.append(r.rtt_max)
    if not sent:
        return None
    return {"k": "line", "sent": sent, "ok": ok, "late": late, "lost": lost, "peak": round(max(rtt), 1) if rtt else None}


def _stream(during) -> dict | None:
    rows = [r for f in during if (r := f.samples.get(("udp_stream", "reflector"))) is not None]
    up, down = sum(r.lost_up for r in rows), sum(r.lost_down for r in rows)
    if not rows or not (up or down):
        return None
    return {"k": "stream", "sent": sum(r.sent for r in rows), "up": up, "down": down,
            "unknown": sum(r.lost_dir_unknown for r in rows)}


def _tcp(inc: Incident) -> dict | None:
    ev = inc.events
    stalls = [e.detail.get("duration_s") for e in ev if e.kind == "stall" and e.detail.get("phase") == "end"]
    rtos = [e.detail["rto_ms"] for e in ev if e.kind == "tcp_info" and "rto_ms" in e.detail]
    retrans = max((e.detail.get("retransmits", 0) for e in ev if e.kind == "tcp_info"), default=0)
    rst = any(e.kind == "rst" for e in ev)
    if not stalls and not rtos and not rst:
        return None
    return {"k": "tcp", "stall": max((s for s in stalls if s is not None), default=None), "retrans": retrans,
            "rto_lo": round(min(rtos) / 1000, 2) if rtos else None, "rto_hi": round(max(rtos) / 1000, 2) if rtos else None,
            "rst": rst}


def explain(inc: Incident, frames, ctx: Context, rule: str) -> dict:
    during, before = _window(inc, list(frames))
    s = inc.start_ms
    end = inc.end_ms if inc.end_ms is not None else s
    facts, out = [], []
    facts.append({"k": "dur", "dur": round((end - s) / 1000), "segs": sorted(inc.segments)})
    gw, line, stream, tcp = _gateway(during, before), _line(during, ctx), _stream(during), _tcp(inc)
    wifi = [e for e in inc.events if e.kind in ("reassoc", "roam") and s - WIFI_WINDOW_S * 1000 <= e.ts_ms <= end + WIFI_WINDOW_S * 1000]
    ipc = [e for e in inc.events if e.kind == "ip_change" and s <= e.ts_ms <= end + K.R4_AFTER_S * 1000]
    dns = sorted(x for x in inc.segments if x.startswith("dns"))
    for x in (gw, line, stream, tcp):
        if x:
            facts.append(x)
    if wifi:
        facts.append({"k": "wifi", "n": len(wifi)})
    if ipc:
        facts.append({"k": "ip", "at": round((ipc[0].ts_ms - s) / 1000)})
    if dns:
        facts.append({"k": "dns", "classes": dns})

    # the other causes, and the measurement that rules each out
    if not rule.startswith("R1a") and not wifi and ctx.link_kind == "wifi":
        out.append({"k": "wifi", "window": WIFI_WINDOW_S})
    crossed = (line["ok"] + line["late"]) if line else 0   # replies from beyond the router: they crossed it
    if rule not in ("R1b",) and gw and (gw["ok"] > 0 or crossed):
        out.append({"k": "router", "ok": gw["ok"], "sent": gw["sent"], "crossed": crossed})
    if not rule.startswith("R2") and line and line["ok"] + line["late"] > 0 and "line" not in inc.segments:
        out.append({"k": "line_ok", "ok": line["ok"], "sent": line["sent"]})
    elif not rule.startswith("R2") and line and line["late"] > 0 and line["lost"] <= line["late"]:
        out.append({"k": "line_late", "answered": line["ok"] + line["late"], "late": line["late"], "sent": line["sent"]})
    dns_ok = sum(r.ok for f in during for (p, _), r in f.samples.items() if p in ("dns", "dns_tcp"))
    if rule != "R3" and not dns and dns_ok:
        out.append({"k": "dns", "ok": dns_ok})
    if rule != "R4" and not ipc and not inc.point:
        out.append({"k": "ip"})
    if not any(x in inc.segments for x in LOCAL) and rule not in ("R1a", "R1c", "R1d"):
        out.append({"k": "local"})
    return {"facts": facts, "ruled_out": out}
