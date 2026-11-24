"""A plain-text report for the ISP: only what happened beyond the router, each event with what the home side did at
the same time, so support can't answer "restart your router". Home-network events and test periods are counted, not listed."""
import json
import re
from datetime import datetime, timezone

from whydrop.web import queries as Q
from whydrop.web.public import localized

TESTS = ("reproduced", "injected", "user-test")
W = {"en": {"title": "Internet line report (recorded by whydrop)", "period": "Period", "recorded": "Recorded",
            "hours": " h, gaps excluded", "drops": "Line drops beyond the router", "slow": "Line slowdowns beyond the router",
            "lossy": "Lossy line periods", "ip": "Public IP changes", "dns": "ISP DNS failures", "total": "total",
            "worst": "worst", "excluded": "Not included: {home} events on the home network (Wi-Fi, router, in-home), {tests} marked as tests.",
            "events": "Each event, with what the home side did at the same time:", "none": "No line events in this period.",
            "router": "router answered {ok} of {sent} checks", "beyond": "beyond the router {ans} of {sent} answered ({late} late)",
            "loss": "{pct} % loss beyond the router", "unsure": "router or line, can't separate", "s": " s"},
     "ko": {"title": "인터넷 회선 보고서 (whydrop 기록)", "period": "기간", "recorded": "기록 시간",
            "hours": "시간, 기록 공백 제외", "drops": "공유기 너머 회선 끊김", "slow": "공유기 너머 회선 지연",
            "lossy": "회선 손실 구간", "ip": "공인 IP 변경", "dns": "통신사 DNS 장애", "total": "합계",
            "worst": "최대", "excluded": "제외: 집 안 네트워크 원인 {home}건(와이파이·공유기·집 안), 테스트로 표시한 {tests}건.",
            "events": "각 사건과, 같은 시각 집 쪽 상태:", "none": "이 기간에는 회선 사건이 없어요.",
            "router": "공유기는 확인 {sent}번 중 {ok}번 응답", "beyond": "공유기 너머는 {sent}개 중 {ans}개 응답(늦게 {late})",
            "loss": "공유기 너머 손실 {pct} %", "unsure": "공유기와 회선을 구분할 수 없음", "s": "초"}}


def _kind(inc: dict, tags: dict, ev: dict) -> str | None:
    """The report section an incident belongs to, or None when the cause is on the home side."""
    rule = str(inc.get("cause_final") or inc.get("primary_cause") or "")
    if rule.startswith("R2"):
        return "drops"
    if rule.startswith("R7") and ev.get("cause_where") != "home" and "line" in tags.get("segments", []):
        return "slow"
    if rule == "R4":
        return "ip"
    if rule == "R3" and any(s == "dns_isp" for s in tags.get("segments", [])):
        return "dns"
    return None


def _stamp(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


DAY_MS = 86_400_000


def data(db, from_ms: int, to_ms: int) -> dict:
    """The report as numbers (language-neutral; labels stay the stored English): what the page and the text render."""
    tests = [a for a in Q.rows(db, "SELECT start_ms, end_ms, label FROM annotations WHERE start_ms < ? AND "
                                   "(end_ms IS NULL OR end_ms >= ?)", (to_ms, from_ms)) if a["label"] in TESTS]
    in_test = lambda a, b: any(t["start_ms"] <= b and (t["end_ms"] or t["start_ms"]) >= a for t in tests)
    gap_list = Q.gaps(db, from_ms, to_ms)
    first = Q.rows(db, "SELECT MIN(ts_ms) t FROM (SELECT MIN(ts_ms) ts_ms FROM samples_1m UNION ALL SELECT MIN(ts_ms) FROM samples_1s)")
    start = max(from_ms, (first[0]["t"] or to_ms) if first else to_ms)

    def recorded(a: int, b: int) -> int:   # ms in [a, b) after the first sample and outside the gaps
        a = max(a, start)
        if b <= a:
            return 0
        return b - a - sum(max(0, min(g["end_ms"], b) - max(g["start_ms"], a)) for g in gap_list)
    events, counts, secs, home, skipped, worst = [], {}, {}, 0, 0, 0.0
    for inc in Q.overlapping(db, "incidents", from_ms, to_ms, limit=100_000):
        end = inc["end_ms"] or to_ms
        tags, ev = json.loads(inc["tags_json"] or "{}"), json.loads(inc["evidence_json"] or "{}")
        kind = _kind(inc, tags, ev)
        if in_test(inc["start_ms"], end):
            skipped += 1
            continue
        if kind is None:
            home += 1
            continue
        counts[kind] = counts.get(kind, 0) + 1
        secs[kind] = secs.get(kind, 0) + (end - inc["start_ms"]) / 1000
        facts = {f["k"]: f for f in ev.get("facts") or []}
        g, b = facts.get("gw"), facts.get("line")
        events.append({"start_ms": inc["start_ms"], "dur_s": round((end - inc["start_ms"]) / 1000), "kind": kind,
                       "label": ev.get("label", inc.get("cause_final") or ""), "unsure": "unobservable" in str(inc.get("cause_final") or ""),
                       "router": {"ok": g["ok"], "sent": g["sent"]} if g and g.get("sent") else None,
                       "beyond": {"ans": b["ok"] + b["late"], "sent": b["sent"], "late": b["late"]} if b and b.get("sent") else None,
                       "loss": None})
    for c in Q.overlapping(db, "conditions", from_ms, to_ms, limit=100_000):
        d = json.loads(c["detail_json"] or "{}")
        end = c["end_ms"] or to_ms
        if c["kind"] != "loss" or d.get("where") != "line" or in_test(c["start_ms"], end):
            continue
        counts["lossy"] = counts.get("lossy", 0) + 1
        secs["lossy"] = secs.get("lossy", 0) + (end - c["start_ms"]) / 1000
        worst = max(worst, d.get("loss") or 0)
        g = Q.rows(db, "SELECT SUM(sent - local_fail) sent, SUM(ok) ok FROM samples_1s WHERE agent_id = 1 AND probe = 'gateway' "
                       "AND ts_ms >= ? AND ts_ms < ?", (c["start_ms"], end))
        events.append({"start_ms": c["start_ms"], "dur_s": round((end - c["start_ms"]) / 1000), "kind": "lossy",
                       "label": d.get("label", ""), "unsure": False, "loss": d.get("loss") or 0,
                       "router": {"ok": g[0]["ok"], "sent": g[0]["sent"]} if g and g[0]["sent"] else None, "beyond": None})
    events.sort(key=lambda e: e["start_ms"])
    day0 = int(datetime.fromtimestamp(from_ms / 1000).replace(hour=0, minute=0, second=0, microsecond=0).timestamp() * 1000)
    days = []
    for d0 in range(day0, to_ms, DAY_MS):   # ponytail: fixed 24 h days, a DST day is off by an hour
        d1 = d0 + DAY_MS
        days.append({"start_ms": d0, "recorded": round(recorded(max(d0, from_ms), min(d1, to_ms)) / DAY_MS, 3),
                     "events": sum(1 for e in events if d0 <= e["start_ms"] < d1)})
    return {"from_ms": from_ms, "to_ms": to_ms, "recorded_h": round(recorded(from_ms, to_ms) / 3_600_000, 1),
            "counts": counts, "secs": {k: round(v) for k, v in secs.items()}, "worst": worst, "home": home, "tests": skipped,
            "events": events, "days": days}


def report(db, from_ms: int, to_ms: int, lang: str = "en") -> str:
    w = W["ko" if lang == "ko" else "en"]
    d = data(db, from_ms, to_ms)
    counts, secs = d["counts"], d["secs"]
    events = []
    for e in d["events"]:
        head = f"{_stamp(e['start_ms'])}  {e['dur_s']}{w['s']}  "
        if e["kind"] == "lossy":
            head += w["loss"].format(pct=round(100 * e["loss"], 1))
        else:
            head += re.sub(r"\s*\((likely|추정)\)$", "", localized(e["label"], lang))
        notes = [w["unsure"]] if e["unsure"] else []
        if e["router"]:
            notes.append(w["router"].format(**e["router"]))
        if e["beyond"]:
            notes.append(w["beyond"].format(**e["beyond"]))
        events.append(head + ("\n    " + "; ".join(notes) if notes else ""))
    out = [w["title"], f"{w['period']}: {_stamp(from_ms)} – {_stamp(to_ms)}", f"{w['recorded']}: {d['recorded_h']:.1f}{w['hours']}", ""]
    for k in ("drops", "slow", "lossy", "ip", "dns"):
        if counts.get(k):
            extra = f", {w['worst']} {round(100 * d['worst'], 1)} %" if k == "lossy" else ""
            out.append(f"{w[k]}: {counts[k]} ({w['total']} {secs[k]}{w['s']}{extra})" if k != "ip" else f"{w[k]}: {counts[k]}")
    if d["home"] or d["tests"]:
        out.append(w["excluded"].format(home=d["home"], tests=d["tests"]))
    out += ["", w["events"] if events else w["none"], *events]
    return "\n".join(out) + "\n"
