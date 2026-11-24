"""Prometheus text format for GET /api/metrics: the live state, the last minute per probe, this month's line drops.

Labels never carry an address: a pair like "dns_isp:203.0.113.5:53/udp" is reported by its class ("dns_isp")."""
import json

from whydrop.web.queries import availability, rows

WINDOW_MS = 60_000
LAG_MS = 15_000   # 1 s rows land after the analysis lag: the minute before that is complete


def _esc(v) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _num(v) -> str:
    return repr(round(float(v), 6)) if isinstance(v, float) else str(int(v))


class _Out:
    def __init__(self):
        self.lines: list[str] = []

    def metric(self, name: str, kind: str, help_: str, samples: list[tuple[dict, float]]) -> None:
        if not samples:
            return
        self.lines += [f"# HELP {name} {help_}", f"# TYPE {name} {kind}"]
        for labels, v in samples:
            lab = ",".join(f'{k}="{_esc(x)}"' for k, x in labels.items())
            self.lines.append(f"{name}{{{lab}}} {_num(v)}" if lab else f"{name} {_num(v)}")


def render(db, status: dict, now_ms: int, month_from_ms: int) -> str:
    o = _Out()
    o.metric("whydrop_info", "gauge", "Agent version, mode and link type.",
             [({"version": status.get("version", ""), "mode": status.get("mode") or "", "link": status.get("link", "")}, 1)])
    segs = status.get("segments") or {}
    o.metric("whydrop_segment_up", "gauge", "1 when the path segment is up, 0 when down (absent while unknown).",
             [({"segment": s}, 1 if v == "up" else 0) for s, v in sorted(segs.items()) if v in ("up", "down")])
    if status.get("signal_dbm") is not None:
        o.metric("whydrop_wifi_signal_dbm", "gauge", "Wi-Fi signal strength.", [({}, status["signal_dbm"])])

    to = now_ms - LAG_MS
    agg: dict[tuple[str, str], dict] = {}
    for r in rows(db, "SELECT probe, pair, sent, ok, lost, late, local_fail, rtt_avg, rtt_max FROM samples_1s "
                      "WHERE agent_id = 1 AND ts_ms >= ? AND ts_ms < ?", (to - WINDOW_MS, to)):
        a = agg.setdefault((r["probe"], r["pair"].split(":")[0]), {"sent": 0, "lost": 0, "late": 0, "w": 0, "rtt": 0.0, "max": None})
        a["sent"] += (r["sent"] or 0) - (r["local_fail"] or 0)
        a["lost"] += r["lost"] or 0
        a["late"] += r["late"] or 0
        if r["rtt_avg"] is not None and r["ok"]:
            a["w"] += r["ok"]
            a["rtt"] += r["rtt_avg"] * r["ok"]
        if r["rtt_max"] is not None:
            a["max"] = max(a["max"] or 0.0, r["rtt_max"])
    keys = sorted(k for k, a in agg.items() if a["sent"] > 0)
    lab = lambda k: {"probe": k[0], "target": k[1]}
    o.metric("whydrop_probe_loss_ratio", "gauge", "Share of probes lost over the last complete minute.",
             [(lab(k), agg[k]["lost"] / agg[k]["sent"]) for k in keys])
    o.metric("whydrop_probe_late_ratio", "gauge", "Share of probes answered late over the last complete minute.",
             [(lab(k), agg[k]["late"] / agg[k]["sent"]) for k in keys])
    o.metric("whydrop_probe_rtt_milliseconds", "gauge", "Round-trip time over the last complete minute (stat: avg or max).",
             [(lab(k) | {"stat": "avg"}, agg[k]["rtt"] / agg[k]["w"]) for k in keys if agg[k]["w"]]
             + [(lab(k) | {"stat": "max"}, agg[k]["max"]) for k in keys if agg[k]["max"] is not None])

    m = availability(db, month_from_ms, now_ms)
    o.metric("whydrop_line_availability_ratio", "gauge", "Line availability this month (recorded time only).",
             [({}, m["availability"] / 100)])
    o.metric("whydrop_month_drops", "gauge", "Drops on the path this month.", [({}, m["drops"])])
    o.metric("whydrop_month_down_seconds", "gauge", "Seconds the path was down this month.", [({}, m["down_s"])])
    for r in rows(db, "SELECT end_ms, cause_final, primary_cause, tags_json FROM incidents WHERE agent_id = 1 "
                      "AND end_ms IS NOT NULL ORDER BY end_ms DESC LIMIT 50"):
        if json.loads(r["tags_json"] or "{}").get("point"):
            continue   # a point event (IP change, NAT reset) isn't a drop
        o.metric("whydrop_last_drop_end_timestamp_seconds", "gauge", "When the latest drop ended; cause is its rule.",
                 [({"cause": r["cause_final"] or r["primary_cause"] or ""}, r["end_ms"] / 1000)])
        break
    o.metric("whydrop_probe_bytes_total", "counter", "Bytes the probes sent and received since the agent started.",
             [({"probe": p}, b) for p, b in sorted((status.get("bytes") or {}).items())])
    return "\n".join(o.lines) + "\n"
