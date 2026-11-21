"""`whydrop replay`: run the analysis over a recorded DB (1 s aggregates and events; approximate, spec §7)."""
import json
import sqlite3
from pathlib import Path

from whydrop.agent.events import Event
from whydrop.agent.store import SampleRow, _SAMPLE_COLS
from whydrop.analysis.engine import Engine
from whydrop.analysis.model import Context, FrameBuilder


def context_from_db(con: sqlite3.Connection) -> Context:
    meta = dict(con.execute("SELECT key, value FROM meta").fetchall())
    prov = json.loads(meta.get("pair_providers", "{}"))
    excl = json.loads(meta.get("excluded", "{}"))
    run = con.execute("SELECT tags_json FROM agent_runs ORDER BY id DESC LIMIT 1").fetchone()
    tags = json.loads(run[0]) if run and run[0] else {}
    ctx_meta = json.loads(meta.get("analysis_context", "{}"))
    return Context(provider_of=prov.get, excluded_pairs=set(excl.get("pairs", [])),
                   excluded_providers=set(excl.get("providers", [])), mode=tags.get("mode", "basic"),
                   lan_observable=ctx_meta.get("lan_observable", True), vpn=ctx_meta.get("vpn", False),
                   link_kind=ctx_meta.get("link_kind", "unknown"), intervals=ctx_meta.get("intervals", {"dns": 5}),
                   isp_dns_known=ctx_meta.get("isp_dns_known", True), nat_tcp_timeout_s=_nat_tcp_lower(con))


def _nat_tcp_lower(con) -> int | None:
    row = con.execute("SELECT detail_json FROM nat_runs ORDER BY id DESC LIMIT 1").fetchone()
    lo = (json.loads(row[0] or "{}").get("tcp_range") or [None])[0] if row else None
    return int(lo) if lo is not None else None


CHUNK_MS = 3_600_000   # read an hour at a time: a week of 1 s rows doesn't fit in 128 MB


def replay(db: Path, from_ms: int | None = None, to_ms: int | None = None) -> list:
    """Returns the engine changes; closed incidents carry their final causes. Reads the DB in hourly chunks."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        ctx = context_from_db(con)
        lo_hi = con.execute("SELECT MIN(ts_ms), MAX(ts_ms) FROM samples_1s WHERE ts_ms BETWEEN ? AND ?",
                            (from_ms if from_ms is not None else 0, to_ms if to_ms is not None else 2 ** 62)).fetchone()
        if lo_hi[0] is None:
            return []
        hi = lo_hi[1]
        lo = max(lo_hi[0], hi - 8 * 86_400_000)   # 1 s data lives 7 days: anything older is a bad timestamp
        fb, eng, out = FrameBuilder(finalize_lag_ms=0), Engine(ctx), []
        fb.next_ms = con.execute("SELECT MIN(ts_ms) FROM samples_1s WHERE ts_ms >= ?", (lo,)).fetchone()[0] // 1000 * 1000
        start = fb.next_ms
        while start <= hi:
            stop = min(start + CHUNK_MS, hi + 1)
            fb.add_events([Event(k, t, p, json.loads(d or "{}")) for t, k, p, d in con.execute(
                "SELECT ts_ms, kind, pair, detail_json FROM events WHERE ts_ms >= ? AND ts_ms < ? ORDER BY ts_ms",
                (start, stop))])
            fb.add_rows([SampleRow(*r) for r in con.execute(
                f"SELECT {_SAMPLE_COLS} FROM samples_1s WHERE ts_ms >= ? AND ts_ms < ? ORDER BY ts_ms", (start, stop))])
            last_chunk = stop > hi
            for f in fb.ready(stop + 200_000 if last_chunk else stop - 30_000):  # 30 s of slack at each seam
                out += [c for c in eng.step(f) if c.type in ("incident", "final", "condition", "finding")]
            start = stop
        return out
    finally:
        con.close()


def summary(changes) -> list[dict]:
    """Final incidents, in order: what `whydrop replay` prints and what the live/replay test compares."""
    out = []
    for ch in changes:
        if ch.type == "final":
            inc = ch.obj.incident
            out.append({"start_ms": inc.start_ms, "end_ms": inc.end_ms, "cause": ch.obj.cause.rule,
                        "label": ch.obj.cause.label, "point": inc.point, "segments": sorted(inc.segments)})
    return out
