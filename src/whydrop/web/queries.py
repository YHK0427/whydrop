"""Read queries for the API on their own read-only SQLite connection (the agent's Store stays the only writer,
except annotations, which the spec lets the dashboard add)."""
import json
import sqlite3
from contextlib import closing
from pathlib import Path

STEPS = (1, 10, 60, 600, 3600)           # seconds
MAX_POINTS = 5000
CHART_POINTS = 2000
CHART_PROBES = ("udp_stream", "line_hb", "stun", "tcp_connect", "canary")
ONE_S_KEPT_MS = 7 * 86_400_000
LABELS = ("reproduced", "injected", "user-test")
LINE_SEGMENTS = ("line", "lan", "wifi", "link", "host_net")


def connect(db: Path, write: bool = False) -> sqlite3.Connection:
    con = sqlite3.connect(db, timeout=5) if write else sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def rows(db: Path, sql: str, params=()) -> list[dict]:
    if db is None or not Path(db).exists():
        return []
    with closing(connect(db)) as con:
        return [dict(r) for r in con.execute(sql, params)]


def pick_step(from_ms: int, to_ms: int, step: int | None, cap: int = MAX_POINTS) -> int:
    """The requested step, but never finer than what keeps the answer under `cap` points."""
    span = max(1, (to_ms - from_ms) // 1000)
    floor = next((s for s in STEPS if span / s <= cap), STEPS[-1])
    return max(step, floor) if step in STEPS else floor


def samples(db, from_ms: int, to_ms: int, step: int | None, probe: str | None = None, now_ms: int | None = None) -> dict:
    import time
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    step = pick_step(from_ms, to_ms, step, CHART_POINTS // 4)   # per pair: keep the answer small (the UI uses /api/chart)
    table = "samples_1s" if from_ms > now_ms - ONE_S_KEPT_MS and step < 60 else "samples_1m"  # 1 s rows live 7 days
    if table == "samples_1m":
        step = max(step, 60)
    where, params = "ts_ms >= ? AND ts_ms < ?", [from_ms, to_ms]
    if probe:
        where += " AND probe = ?"
        params.append(probe)
    sql = (f"SELECT (ts_ms / {step * 1000}) * {step * 1000} AS ts_ms, probe, pair, SUM(sent) sent, SUM(ok) ok, "
           "SUM(lost) lost, SUM(lost_up) lost_up, SUM(lost_down) lost_down, SUM(lost_dir_unknown) lost_dir_unknown, "
           "SUM(late) late, SUM(local_fail) local_fail, MIN(rtt_min) rtt_min, "
           "SUM(rtt_avg * ok) / NULLIF(SUM(CASE WHEN rtt_avg IS NULL THEN 0 ELSE ok END), 0) rtt_avg, "
           f"MAX(rtt_max) rtt_max, MAX(rtt_p95) rtt_p95 FROM {table} WHERE {where} "
           "GROUP BY 1, probe, pair ORDER BY 1")
    return {"step_s": step, "table": table, "rows": rows(db, sql, params)}


def ranged(db, table: str, from_ms: int, to_ms: int, ts: str = "ts_ms", extra: str = "", params=(), limit=5000):
    return rows(db, f"SELECT * FROM {table} WHERE {ts} >= ? AND {ts} < ? {extra} ORDER BY {ts} LIMIT {int(limit)}",
                (from_ms, to_ms, *params))


def overlapping(db, table: str, from_ms: int, to_ms: int, limit=1000):
    """Incidents/conditions/findings that overlap [from, to) (open ones included)."""
    return rows(db, f"SELECT * FROM {table} WHERE start_ms < ? AND (end_ms IS NULL OR end_ms >= ?) "
                    f"ORDER BY start_ms DESC LIMIT {int(limit)}", (to_ms, from_ms))


def incident(db, iid: int) -> dict | None:
    r = rows(db, "SELECT * FROM incidents WHERE id = ?", (iid,))
    return r[0] if r else None


def gaps(db, from_ms: int, to_ms: int, slack_ms: int = 60_000) -> list[dict]:
    """'Not recording' spans: from a run's last sign of life to the next run's start (spec §6.3)."""
    runs = rows(db, "SELECT start_ms, COALESCE(stop_ms, heartbeat_ms, start_ms) AS last FROM agent_runs ORDER BY start_ms")
    out = []
    for a, b in zip(runs, runs[1:]):
        if b["start_ms"] - a["last"] > slack_ms and b["start_ms"] > from_ms and a["last"] < to_ms:
            out.append({"start_ms": a["last"], "end_ms": b["start_ms"]})
    return out


def availability(db, from_ms: int, to_ms: int) -> dict:
    """'Line availability this month 99.93 % · 7 drops · 14 min' from closed incidents touching the path."""
    incs = overlapping(db, "incidents", from_ms, to_ms, limit=100_000)
    down_ms, drops = 0, 0
    for i in incs:
        tags = json.loads(i.get("tags_json") or "{}")
        if not set(tags.get("segments", [])) & set(LINE_SEGMENTS) or tags.get("point"):
            continue
        a, b = max(i["start_ms"], from_ms), min(i["end_ms"] or to_ms, to_ms)
        down_ms += max(0, b - a)
        drops += 1
    recorded = max(1, to_ms - from_ms - sum(min(g["end_ms"], to_ms) - max(g["start_ms"], from_ms)
                                           for g in gaps(db, from_ms, to_ms)))
    pct = 100 * (1 - down_ms / recorded)
    shown = min(round(pct, 3), 99.999) if down_ms else 100.0   # a drop never rounds up to a perfect month
    return {"availability": shown, "drops": drops, "down_s": round(down_ms / 1000)}


def add_annotation(db, start_ms: int, end_ms: int | None, label: str, note: str | None) -> int:
    if db is None or not Path(db).exists():
        raise FileNotFoundError("no database yet")
    if note is not None and not isinstance(note, str):
        raise ValueError("note must be text")
    if label not in LABELS:
        raise ValueError("label must be reproduced, injected or user-test")
    if end_ms is not None and end_ms < start_ms:
        raise ValueError("end is before start")
    with closing(connect(db, write=True)) as con, con:
        cur = con.execute("INSERT INTO annotations (agent_id, start_ms, end_ms, label, note) VALUES (1, ?, ?, ?, ?)",
                          (start_ms, end_ms, label, (note or "")[:500]))
        return cur.lastrowid


def chart(db, from_ms: int, to_ms: int, step: int | None, now_ms: int | None = None) -> dict:
    """Columnar series for the lanes, bucketed in SQL by probe (not per pair): x, up, down, lost, rtt, canary."""
    import time
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    step = pick_step(from_ms, to_ms, step, CHART_POINTS)
    table = "samples_1s" if from_ms > now_ms - ONE_S_KEPT_MS and step < 60 else "samples_1m"
    if table == "samples_1m":
        step = max(step, 60)
    marks = ",".join("?" * len(CHART_PROBES))
    sql = (f"SELECT (ts_ms / {step * 1000}) AS b, probe, SUM(sent), SUM(ok), SUM(lost), SUM(lost_up), SUM(lost_down), "
           "SUM(rtt_avg * ok), SUM(CASE WHEN rtt_avg IS NULL THEN 0 ELSE ok END) "
           f"FROM {table} WHERE ts_ms >= ? AND ts_ms < ? AND probe IN ({marks}) GROUP BY b, probe ORDER BY b")
    by: dict[int, dict] = {}
    if db is not None and Path(db).exists():
        with closing(connect(db)) as con:
            for b, probe, sent, ok, lost, up, down, rtt_sum, rtt_n in con.execute(sql, (from_ms, to_ms, *CHART_PROBES)):
                d = by.setdefault(b * step, {"up": 0, "down": 0, "lost": 0, "rs": 0.0, "rn": 0, "cs": 0, "co": 0})
                if probe == "udp_stream":
                    d["up"] += up or 0
                    d["down"] += down or 0
                    d["lost"] += lost or 0
                elif probe == "canary":
                    d["cs"] += sent or 0
                    d["co"] += ok or 0
                else:
                    d["basic_lost"] = d.get("basic_lost", 0) + (lost or 0)
                    if rtt_n:
                        d["rs"] += rtt_sum or 0
                        d["rn"] += rtt_n
    xs = sorted(by)
    col = lambda f: [f(by[x]) for x in xs]  # noqa: E731
    return {"step_s": step, "table": table, "x": xs,
            "up": col(lambda d: d["up"] or None), "down": col(lambda d: -d["down"] if d["down"] else None),
            "stream_unknown": col(lambda d: max(0, d["lost"] - d["up"] - d["down"]) or None),
            "basic_lost": col(lambda d: d.get("basic_lost") or None),
            "rtt": col(lambda d: round(d["rs"] / d["rn"], 1) if d["rn"] else None),
            "tcp": col(lambda d: (2 if d["co"] == d["cs"] else 1 if d["co"] else 0) if d["cs"] else None)}
