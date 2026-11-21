"""Read queries for the API on their own read-only SQLite connection (the agent's Store stays the only writer,
except annotations, which the spec lets the dashboard add)."""
import json
import sqlite3
from contextlib import closing
from pathlib import Path

STEPS = (1, 10, 60, 600)                 # seconds
MAX_POINTS = 5000
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


def pick_step(from_ms: int, to_ms: int, step: int | None) -> int:
    if step in STEPS:
        return step
    span = max(1, (to_ms - from_ms) // 1000)
    return next((s for s in STEPS if span / s <= MAX_POINTS), STEPS[-1])


def samples(db, from_ms: int, to_ms: int, step: int | None, probe: str | None = None) -> dict:
    step = pick_step(from_ms, to_ms, step)
    table = "samples_1s" if to_ms - from_ms <= ONE_S_KEPT_MS and step < 60 else "samples_1m"
    if table == "samples_1m":
        step = max(step, 60)
    where, params = "ts_ms >= ? AND ts_ms < ?", [from_ms, to_ms]
    if probe:
        where += " AND probe = ?"
        params.append(probe)
    sql = (f"SELECT (ts_ms / {step * 1000}) * {step * 1000} AS ts_ms, probe, pair, SUM(sent) sent, SUM(ok) ok, "
           "SUM(lost) lost, SUM(lost_up) lost_up, SUM(lost_down) lost_down, SUM(lost_dir_unknown) lost_dir_unknown, "
           "SUM(late) late, SUM(local_fail) local_fail, MIN(rtt_min) rtt_min, AVG(rtt_avg) rtt_avg, "
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
    return {"availability": round(100 * (1 - down_ms / recorded), 2), "drops": drops, "down_s": round(down_ms / 1000)}


def add_annotation(db, start_ms: int, end_ms: int | None, label: str, note: str | None) -> int:
    if label not in LABELS:
        raise ValueError("label must be reproduced, injected or user-test")
    if end_ms is not None and end_ms < start_ms:
        raise ValueError("end is before start")
    with closing(connect(db, write=True)) as con, con:
        cur = con.execute("INSERT INTO annotations (agent_id, start_ms, end_ms, label, note) VALUES (1, ?, ?, ?, ?)",
                          (start_ms, end_ms, label, (note or "")[:500]))
        return cur.lastrowid
