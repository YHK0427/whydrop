"""Exports (spec §8): CSV/JSON tables, the ±10 min bug report (always public view) and the plain-text summary
for an ISP support chat (private view: absolute local time with its UTC offset)."""
import csv
import io
import json
from datetime import datetime, timezone

from whydrop.web import queries as Q
from whydrop.web.public import public

TABLES = {"incidents": "incidents", "conditions": "conditions", "samples_1m": "samples_1m", "events": "events"}
KIND = {"incidents": "incident", "conditions": "condition", "samples_1m": "sample", "events": "event"}
BUG_WINDOW_MS = 10 * 60_000

SEGMENT_WORDS = {"en": {"line": "Internet line", "lan": "Router", "wifi": "Wi-Fi", "link": "Cable", "host_net": "This device",
                        "dns_router": "DNS", "dns_isp": "DNS", "dns_public": "DNS"},
                 "ko": {"line": "인터넷 회선", "lan": "공유기", "wifi": "와이파이", "link": "유선", "host_net": "이 기기",
                        "dns_router": "DNS", "dns_isp": "DNS", "dns_public": "DNS"}}


def table_rows(db, name: str, from_ms: int, to_ms: int) -> list[dict]:
    if name in ("incidents", "conditions"):
        return Q.overlapping(db, name, from_ms, to_ms, limit=100_000)
    return Q.ranged(db, TABLES[name], from_ms, to_ms, limit=1_000_000)


def render(name: str, rows: list[dict], fmt: str, pub: bool, now_ms: int) -> tuple[str, str]:
    rows = [{k: v for k, v in r.items() if k != "agent_id"} for r in rows]   # internal column
    if pub:
        rows = [public(r, KIND[name], now_ms) for r in rows]
    if fmt == "json":
        return json.dumps(rows, ensure_ascii=False, default=str), "application/json"
    buf = io.StringIO()
    cols = sorted({k for r in rows for k in r}) or ["empty"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v for k, v in r.items()})
    return buf.getvalue(), "text/csv; charset=utf-8"


def bugreport(db, iid: int, now_ms: int) -> dict | None:
    inc = Q.incident(db, iid)
    if inc is None:
        return None
    a, b = inc["start_ms"] - BUG_WINDOW_MS, (inc["end_ms"] or now_ms) + BUG_WINDOW_MS
    return {"whydrop_bugreport": 1, "incident": public(inc, "incident", now_ms),
            "segments": [public(r, "segment", now_ms) for r in Q.ranged(db, "segments", a, b)],
            "events": [public(r, "event", now_ms) for r in Q.ranged(db, "events", a, b) if r["kind"] != "tcp_info"],
            "samples": [public(r, "sample", now_ms) for r in Q.ranged(db, "samples_1s", a, b, limit=200_000)]}


def summary(db, iid: int, lang: str = "en") -> str | None:
    """Ready to paste into an ISP support chat: time with offset, duration, likely cause, next step, evidence."""
    inc = Q.incident(db, iid)
    if inc is None:
        return None
    tags, ev = json.loads(inc["tags_json"] or "{}"), json.loads(inc["evidence_json"] or "{}")
    words = SEGMENT_WORDS.get(lang, SEGMENT_WORDS["en"])
    start = datetime.fromtimestamp(inc["start_ms"] / 1000, timezone.utc).astimezone()
    dur = ((inc["end_ms"] or inc["start_ms"]) - inc["start_ms"]) / 1000
    where = ", ".join(dict.fromkeys(words.get(s, s) for s in tags.get("segments", []))) or tags.get("point") or "-"
    when = start.strftime("%Y-%m-%d %H:%M:%S %z")
    if lang == "ko":
        lines = [f"끊김: {when}, {dur:.0f}초, {where}", f"추정 원인: {ev.get('label', '-')}",
                 f"다음에 할 일: {ev.get('next_step', '-')}"]
        if ev.get("protocol"):
            lines.append(f"프로토콜로 보면: {ev['protocol']}")
    else:
        lines = [f"Drop: {when}, {dur:.0f} s, {where}", f"Likely cause: {ev.get('label', '-')}",
                 f"What to do next: {ev.get('next_step', '-')}"]
        if ev.get("protocol"):
            lines.append(f"In protocol terms: {ev['protocol']}")
    lines.append("Recorded by whydrop (rule " + str(inc.get("cause_final") or inc.get("primary_cause")) + ")")
    return "\n".join(lines)
