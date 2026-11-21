"""Public view (spec §8): one allowlist serializer for REST, WS, exports, evidence text and webhooks.
Hidden: public IP, mapped ports, ISP DNS, reflector address, hostnames, interface names, CHAOS site code.
Internal IPs keep only the last octet. Times become relative (seconds from now)."""
import ipaddress
import json
import re

KNOWN_RESOLVERS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222",
                   "208.67.220.220"}
_V4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?\b")
_V6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F:]*::[0-9a-fA-F:]*|(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4})(?![\w:])")  # never hh:mm:ss
_HOST = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")   # FQDNs (reflector, this host)
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                               "127.0.0.0/8", "169.254.0.0/16")]  # not is_private: that includes TEST-NETs
_IFACE = re.compile(r"\b(?:eth\d+|en[ops]\w+|en\d+|wlan\d+|wl[ops]\w+|wlx\w+|wg\d+|tun\d+|tailscale\d+|ppp\d+)\b")

EVENT_DETAIL = {   # kind → detail keys that are safe to show
    "reassoc": {"cause", "ap"}, "roam": {"from", "to"}, "link_flap": {"flaps"}, "link_speed": {"from", "to"},
    "stall": {"phase", "duration_s", "reconnected"}, "rst": set(), "reconnect": set(), "kernel_timeout": set(),
    "tcp_info": {"rto_ms", "backoff", "retransmits", "unacked", "rtt_ms", "rttvar_ms", "total_retrans"},
    "udp_outage": {"from_seq", "to_seq", "lost_up", "lost_down", "status"}, "agent_lag": {"phase", "lag_ms", "max_lag_ms"},
    "suspend": {"slept_s"}, "clock_step": {"delta_s"}, "idle_state_lost": {"interval_s", "waited_s"},
    "net_change": {"gateway_changed", "vpn"}, "middlebox": {"flag"}, "auth_fail": set(), "busy": set(),
    "version_mismatch": set(), "cpu_throttle": {"nr_throttled"}, "reflector_restart": set(),
}
INCIDENT_EVIDENCE = {"label", "cause", "next_step", "secondary", "protocol", "events", "provisional",
                     "cause_direction", "cause_lost_up", "cause_lost_down", "cause_classes", "interval_s"}
STATUS = {"version", "mode", "baseline", "segments", "signal_dbm", "link", "vpn", "analysis_lag_s", "public"}


def _ip(m: re.Match) -> str:
    ip = m.group(1)
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return m.group(0)
    if ip in KNOWN_RESOLVERS:
        return m.group(0)
    if any(a in n for n in _INTERNAL):
        return "x.x.x." + ip.rsplit(".", 1)[1]
    return "hidden"


def mask_text(s: str) -> str:
    s = _V4.sub(_ip, s)
    s = _V6.sub("hidden", s)
    s = _HOST.sub("hidden", s)
    return _IFACE.sub("(interface)", s)


def mask_pair(pair: str | None) -> str | None:
    if not pair:
        return pair
    cls, _, rest = pair.partition(":")
    if cls == "dns_isp":
        return "dns_isp:hidden"
    if cls == "dns_router":
        addr, _, tail = rest.partition(":")
        return f"dns_router:{mask_text(addr)}:{tail}" if tail else f"dns_router:{mask_text(addr)}"
    if cls == "line_hb":
        return "line_hb:hidden"     # its address can be the reflector's
    if cls in ("dns_public", "stun", "tcp"):
        addr, _, tail = rest.partition(":")
        return f"{cls}:{mask_text(addr)}:{tail}" if tail else f"{cls}:{mask_text(addr)}"
    return cls


def _rel(ms, now_ms):
    return None if ms is None else round((ms - now_ms) / 1000)


def _j(v):
    return json.loads(v) if isinstance(v, str) and v else (v or {})


def public(row: dict, kind: str, now_ms: int) -> dict:
    """Allowlisted copy of one row; unknown kinds yield {} (nothing leaks by default)."""
    r = row
    if kind == "incident":
        tags, ev = _j(r.get("tags_json")), _j(r.get("evidence_json"))
        evidence = {k: (mask_text(v) if isinstance(v, str) else v) for k, v in ev.items() if k in INCIDENT_EVIDENCE}
        return {"id": r.get("id"), "start_s": _rel(r.get("start_ms"), now_ms), "end_s": _rel(r.get("end_ms"), now_ms),
                "cause": r.get("cause_final") or r.get("primary_cause"), "final": r.get("cause_final") is not None,
                "cause_changed": bool(r.get("cause_changed")), "tags": tags.get("tags", []),
                "segments": tags.get("segments", []), "chain": tags.get("chain", []), "point": tags.get("point"),
                "evidence": evidence}
    if kind == "event":
        allowed = EVENT_DETAIL.get(r.get("kind"), set())
        d = {k: (mask_text(v) if isinstance(v, str) else v)
             for k, v in _j(r.get("detail_json", r.get("detail"))).items() if k in allowed}
        return {"kind": r.get("kind"), "t_s": _rel(r.get("ts_ms"), now_ms), "pair": mask_pair(r.get("pair")), "detail": d}
    if kind == "segment":
        d = _j(r.get("detail_json", r.get("detail")))
        return {"t_s": _rel(r.get("ts_ms"), now_ms), "segment": r.get("segment"), "state": r.get("state"),
                "detail": {k: v for k, v in d.items() if k in ("providers", "queueing_evidence", "duration_s", "stale",
                                                               "host_slept", "observable", "pairs")}}
    if kind == "condition":
        d = _j(r.get("detail_json", r.get("detail")))
        return {"kind": r.get("kind"), "start_s": _rel(r.get("start_ms"), now_ms), "end_s": _rel(r.get("end_ms"), now_ms),
                "detail": {k: v for k, v in d.items() if k in ("cause", "label", "loss", "providers", "dbm",
                                                               "gateway_loss", "loop_lag_p95_ms")}}
    if kind == "finding":
        return {"kind": r.get("kind"), "start_s": _rel(r.get("start_ms"), now_ms), "end_s": _rel(r.get("end_ms"), now_ms)}
    if kind == "sample":
        keep = ("probe", "sent", "ok", "lost", "lost_up", "lost_down", "lost_dir_unknown", "late", "local_fail",
                "rtt_min", "rtt_avg", "rtt_max", "rtt_p95")
        return {"t_s": _rel(r.get("ts_ms"), now_ms), "pair": mask_pair(r.get("pair")), **{k: r[k] for k in keep if k in r}}
    if kind == "status":
        out = {k: r[k] for k in STATUS if k in r}
        if r.get("since_ms"):
            out["since_s"] = _rel(r["since_ms"], now_ms)
        return out
    if kind == "selfcheck":
        res = _j(r.get("result_json"))
        return {"t_s": _rel(r.get("ts_ms"), now_ms), "excluded": len(res.get("excluded", {})),
                "verdict": res.get("verdict")}
    if kind == "nat":
        return {k: r[k] for k in ("proto", "delay_s", "alive") if k in r}
    if kind == "strip":
        return {"t_s": _rel(r.get("ts_ms"), now_ms), "seq": r.get("seq"), "echoed": r.get("echoed"),
                "dir": r.get("dir")}
    if kind == "packet":
        return {"t_s": _rel(r.get("ts_ms"), now_ms), "dir": r.get("dir"), "type": r.get("type"),
                "seq": r.get("seq"), "size": r.get("size"), "hex": r.get("hex")}
    if kind == "gap":
        return {"start_s": _rel(r.get("start_ms"), now_ms), "end_s": _rel(r.get("end_ms"), now_ms)}
    if kind == "annotation":
        return {"start_s": _rel(r.get("start_ms"), now_ms), "end_s": _rel(r.get("end_ms"), now_ms), "label": r.get("label")}
    return {}
