"""Streamed exports: every table (samples_1m is WITHOUT ROWID), complete documents, and safe across worker threads."""
import json
import threading

from fastapi.testclient import TestClient

from whydrop.web.app import create_app
from whydrop.web.bus import Bus


def db_with_rows(tmp_path):
    import asyncio

    from whydrop.agent.events import Event
    from whydrop.agent.store import SampleRow, Store

    async def go():
        s = Store(tmp_path / "w.db")
        await s.open()
        await s.execute("INSERT INTO samples_1m (agent_id, ts_ms, probe, pair, sent, ok, lost) VALUES (1, 60000, 'dns', 'p', 60, 59, 1)")
        await s.add_samples([SampleRow(1000 * i, "line_hb", "line_hb:x", 1, 1, 0) for i in range(10)])
        await s.add_events([Event("stall", 1000 * i, "reflector", {"phase": "start"}) for i in range(3000)])
        await s.flush()
        await s.close()
    asyncio.run(go())
    return tmp_path / "w.db"


def test_every_table_exports(tmp_path):
    db = db_with_rows(tmp_path)
    c = TestClient(create_app(db, Bus(), token=None, allowed_hosts=["testserver"], public_default=False))
    for name in ("incidents", "conditions", "samples_1m", "events"):
        for fmt in ("json", "csv"):
            r = c.get(f"/api/export/{name}.{fmt}?from=0&to=999999999")
            assert r.status_code == 200, (name, fmt)
            if fmt == "json":
                json.loads(r.text)                          # a complete document, not a truncated stream
    assert json.loads(c.get("/api/export/samples_1m.json?from=0&to=999999999").text)[0]["lost"] == 1
    assert len(json.loads(c.get("/api/export/events.json?from=0&to=999999999").text)) == 3000


def test_parallel_exports_dont_trip_over_threads(tmp_path):
    db = db_with_rows(tmp_path)
    c = TestClient(create_app(db, Bus(), token=None, allowed_hosts=["testserver"], public_default=False))
    errors = []

    def one():
        try:
            assert len(json.loads(c.get("/api/export/events.json?from=0&to=999999999").text)) == 3000
            c.get("/tokens.css")
        except Exception as e:
            errors.append(repr(e))
    ts = [threading.Thread(target=one) for _ in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors, errors[:2]
