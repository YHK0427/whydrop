"""Exports (spec §8): CSV/JSON tables, the ±10 min bug report (always public view) and the plain-text summary
for an ISP support chat (private view: absolute local time with its UTC offset)."""
import csv
import io
import json
import sqlite3
import time
from datetime import datetime, timezone

from pathlib import Path

from whydrop.web import queries as Q
from whydrop.web.public import public

TABLES = {"incidents": "incidents", "conditions": "conditions", "samples_1m": "samples_1m", "events": "events"}
KIND = {"incidents": "incident", "conditions": "condition", "samples_1m": "sample", "events": "event"}
BUG_WINDOW_MS = 10 * 60_000

SEGMENT_WORDS = {"en": {"home": "Home network", "line": "Internet line", "lan": "Router", "wifi": "Wi-Fi", "link": "Cable", "host_net": "This device",
                        "dns_router": "DNS", "dns_isp": "DNS", "dns_public": "DNS"},
                 "ko": {"home": "집 안 네트워크", "line": "인터넷 회선", "lan": "공유기", "wifi": "와이파이", "link": "유선", "host_net": "이 기기",
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
            "samples": [public(r, "sample", now_ms) for r in Q.rows(
                db, "SELECT * FROM samples_1s WHERE ts_ms >= ? AND ts_ms < ? AND probe IN "
                    "('udp_stream','line_hb','stun','tcp_connect','canary','gateway') ORDER BY ts_ms LIMIT 60000", (a, b))]}


def summary(db, iid: int, lang: str = "en", public_view: bool = False, now_ms: int | None = None) -> str | None:
    """Ready to paste into an ISP support chat: time with offset, duration, likely cause, next step, evidence."""
    inc = Q.incident(db, iid)
    if inc is None:
        return None
    tags, ev = json.loads(inc["tags_json"] or "{}"), json.loads(inc["evidence_json"] or "{}")
    words = SEGMENT_WORDS.get(lang, SEGMENT_WORDS["en"])
    start = datetime.fromtimestamp(inc["start_ms"] / 1000, timezone.utc).astimezone()
    dur = ((inc["end_ms"] or inc["start_ms"]) - inc["start_ms"]) / 1000
    from whydrop.web.public import shown_segments
    where = ", ".join(dict.fromkeys(words.get(s, s) for s in shown_segments(tags.get("segments", []), ev)))         or tags.get("point") or "-"
    when = start.strftime("%Y-%m-%d %H:%M:%S %z")
    if public_view:   # no absolute time or address in the public view
        from whydrop.web.public import mask_text
        mins = max(0, round(((now_ms or time.time() * 1000) - inc["start_ms"]) / 60000))
        when = f"{mins} min ago" if lang != "ko" else f"{mins}분 전"
        ev = {k: mask_text(v) if isinstance(v, str) else v for k, v in ev.items()}
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


def _batched(cur, n: int = 1000):
    while rows := cur.fetchmany(n):
        yield from rows


def stream(db, name: str, from_ms: int, to_ms: int, fmt: str, pub: bool, now_ms: int):
    """Yield the export row by row straight from the cursor (a sync generator; Starlette runs it in a thread)."""
    from contextlib import closing
    table = TABLES[name]
    where = ("start_ms < ? AND (end_ms IS NULL OR end_ms >= ?)", (to_ms, from_ms)) if name in ("incidents", "conditions") \
        else ("ts_ms >= ? AND ts_ms < ?", (from_ms, to_ms))
    if db is None or not Path(db).exists():
        yield "[]" if fmt == "json" else ""
        return
    order = "start_ms" if name in ("incidents", "conditions") else "ts_ms"   # samples_* are WITHOUT ROWID
    # Starlette may resume this generator on a different worker thread for each chunk
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5, check_same_thread=False)
    con.row_factory = sqlite3.Row
    with closing(con):
        cur = con.execute(f"SELECT * FROM {table} WHERE {where[0]} ORDER BY {order}", where[1])
        cols = [c[0] for c in cur.description if c[0] != "agent_id"]
        first, chunk = True, []
        if fmt == "json":
            chunk.append("[")
        for raw in _batched(cur):
            r = {k: raw[k] for k in cols}
            if pub:
                r = public(r, KIND[name], now_ms)
            if fmt == "json":
                chunk.append(("" if first else ",") + json.dumps(r, ensure_ascii=False, default=str))
            else:
                if first:
                    hdr = sorted(r)
                    buf = io.StringIO()
                    w = csv.DictWriter(buf, fieldnames=hdr, extrasaction="ignore")
                    w.writeheader()
                    chunk.append(buf.getvalue())
                buf = io.StringIO()
                csv.DictWriter(buf, fieldnames=hdr, extrasaction="ignore").writerow(
                    {k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v for k, v in r.items()})
                chunk.append(buf.getvalue())
            first = False
            if len(chunk) >= 1000:   # one thread hop per ~1000 rows, not per row
                yield "".join(chunk)
                chunk = []
        if fmt == "json":
            chunk.append("]")
        yield "".join(chunk)
