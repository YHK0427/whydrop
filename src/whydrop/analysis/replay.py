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
                   link_kind=ctx_meta.get("link_kind", "unknown"), intervals=ctx_meta.get("intervals", {"dns": 5}))


def replay(db: Path, from_ms: int | None = None, to_ms: int | None = None) -> list:
    """Returns the engine changes; closed incidents carry their final causes."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        ctx = context_from_db(con)
        lo, hi = from_ms if from_ms is not None else 0, to_ms if to_ms is not None else 2 ** 62
        fb = FrameBuilder(finalize_lag_ms=0)
        rows = con.execute(f"SELECT {_SAMPLE_COLS} FROM samples_1s WHERE ts_ms BETWEEN ? AND ? ORDER BY ts_ms",
                           (lo, hi)).fetchall()
        events = con.execute("SELECT ts_ms, kind, pair, detail_json FROM events WHERE ts_ms BETWEEN ? AND ? ORDER BY ts_ms",
                             (lo, hi)).fetchall()
    finally:
        con.close()
    if rows:
        horizon = rows[-1][0] - 8 * 86_400_000   # 1 s data lives 7 days: anything older is a bad timestamp
        rows = [r for r in rows if r[0] >= horizon]
        events = [e for e in events if e[0] >= horizon]
    if not rows:
        return []
    fb.next_ms = rows[0][0] // 1000 * 1000
    fb.add_events([Event(k, t, p, json.loads(d or "{}")) for t, k, p, d in events])
    fb.add_rows([SampleRow(*r) for r in rows])
    eng, out = Engine(ctx), []
    last = rows[-1][0] + 200_000            # run on past the end so open incidents settle
    for f in fb.ready(last):
        out += eng.step(f)
    return out


def summary(changes) -> list[dict]:
    """Final incidents, in order: what `whydrop replay` prints and what the live/replay test compares."""
    out = []
    for ch in changes:
        if ch.type == "final":
            inc = ch.obj.incident
            out.append({"start_ms": inc.start_ms, "end_ms": inc.end_ms, "cause": ch.obj.cause.rule,
                        "label": ch.obj.cause.label, "point": inc.point, "segments": sorted(inc.segments)})
    return out
