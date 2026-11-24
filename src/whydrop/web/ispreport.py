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


def report(db, from_ms: int, to_ms: int, lang: str = "en") -> str:
    w = W["ko" if lang == "ko" else "en"]
    tests = [a for a in Q.rows(db, "SELECT start_ms, end_ms, label FROM annotations WHERE start_ms < ? AND "
                                   "(end_ms IS NULL OR end_ms >= ?)", (to_ms, from_ms)) if a["label"] in TESTS]
    in_test = lambda a, b: any(t["start_ms"] <= b and (t["end_ms"] or t["start_ms"]) >= a for t in tests)
    gaps = sum(min(g["end_ms"], to_ms) - max(g["start_ms"], from_ms) for g in Q.gaps(db, from_ms, to_ms))
    first = Q.rows(db, "SELECT MIN(ts_ms) t FROM (SELECT MIN(ts_ms) ts_ms FROM samples_1m UNION ALL SELECT MIN(ts_ms) FROM samples_1s)")
    start = max(from_ms, (first[0]["t"] or to_ms) if first else to_ms)
    events, counts, secs, home, skipped = [], {}, {}, 0, 0
    for inc in sorted(Q.overlapping(db, "incidents", from_ms, to_ms, limit=100_000), key=lambda r: r["start_ms"]):
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
        label = localized(ev.get("label", inc.get("cause_final") or ""), lang)
        label = re.sub(r"\s*\((likely|추정)\)$", "", label)
        line = f"{_stamp(inc['start_ms'])}  {round((end - inc['start_ms']) / 1000)}{w['s']}  {label}"
        notes = []
        if "unobservable" in str(inc.get("cause_final") or ""):
            notes.append(w["unsure"])
        if (g := facts.get("gw")) and g.get("sent"):
            notes.append(w["router"].format(ok=g["ok"], sent=g["sent"]))
        if (b := facts.get("line")) and b.get("sent"):
            notes.append(w["beyond"].format(ans=b["ok"] + b["late"], sent=b["sent"], late=b["late"]))
        events.append(line + ("\n    " + "; ".join(notes) if notes else ""))
    worst = 0.0
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
        home_side = ("\n    " + w["router"].format(ok=g[0]["ok"], sent=g[0]["sent"])) if g and g[0]["sent"] else ""
        events.append(f"{_stamp(c['start_ms'])}  {round((end - c['start_ms']) / 1000)}{w['s']}  "
                      + w["loss"].format(pct=round(100 * (d.get("loss") or 0), 1)) + home_side)
    out = [w["title"], f"{w['period']}: {_stamp(from_ms)} – {_stamp(to_ms)}",
           f"{w['recorded']}: {max(0, to_ms - start - gaps) / 3_600_000:.1f}{w['hours']}", ""]
    for k in ("drops", "slow", "lossy", "ip", "dns"):
        if counts.get(k):
            extra = f", {w['worst']} {round(100 * worst, 1)} %" if k == "lossy" else ""
            out.append(f"{w[k]}: {counts[k]} ({w['total']} {round(secs[k])}{w['s']}{extra})" if k != "ip"
                       else f"{w[k]}: {counts[k]}")
    if home or skipped:
        out.append(w["excluded"].format(home=home, tests=skipped))
    out += ["", w["events"] if events else w["none"]]
    out += sorted(events)   # each starts with its timestamp
    return "\n".join(out) + "\n"
