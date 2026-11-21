import asyncio
import sqlite3

import pytest

from whydrop.agent.events import Event
from whydrop.agent.store import Store, SampleRow

TABLES = {"meta", "samples_1s", "samples_1m", "udp_seq_ring", "segments", "events", "incidents", "conditions",
          "selfcheck", "findings", "nat_runs", "nat_results", "annotations", "agent_runs"}


def run(coro):
    return asyncio.run(coro)


def tables(path):
    con = sqlite3.connect(path)
    try:
        names = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
        cols = {t: {r[1] for r in con.execute(f"pragma table_info({t})")} for t in names}
        return names, cols, con.execute("pragma user_version").fetchone()[0]
    finally:
        con.close()


def test_schema_v1_tables(tmp_path):
    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()
        await s.close()
    run(main())
    names, cols, version = tables(tmp_path / "w.db")
    assert TABLES <= names and version == 1
    assert all("agent_id" in cols[t] for t in TABLES - {"meta"})


def test_migrations_idempotent(tmp_path):
    async def main():
        for _ in range(2):
            s = Store(tmp_path / "w.db")
            await s.open()
            await s.close()
    run(main())
    assert tables(tmp_path / "w.db")[2] == 1


def test_samples_and_late(tmp_path):
    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()
        await s.add_samples([SampleRow(1000, "dns", "isp:1/udp", sent=1, ok=0, lost=1)])
        await s.flush()
        await s.late(1000, "dns", "isp:1/udp")
        await s.add_samples([SampleRow(2000, "dns", "isp:1/udp", sent=1, ok=0, lost=1)])
        await s.late(2000, "dns", "isp:1/udp")  # still buffered: updated in memory
        await s.close()
    run(main())
    con = sqlite3.connect(tmp_path / "w.db")
    rows = con.execute("select ts_ms, lost, late from samples_1s order by ts_ms").fetchall()
    con.close()
    assert rows == [(1000, 0, 1), (2000, 0, 1)]


def test_events_roundtrip(tmp_path):
    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()
        await s.add_events([Event("reassoc", 5, None, {"ap": "AP-1"})])
        await s.close()
    run(main())
    con = sqlite3.connect(tmp_path / "w.db")
    assert con.execute("select ts_ms, kind, detail_json from events").fetchall() == [(5, "reassoc", '{"ap": "AP-1"}')]
    con.close()


def test_agent_runs_lifecycle(tmp_path):
    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()
        rid = await s.run_start(100, "0.1.0", {"clock": "synced"})
        await s.run_heartbeat(rid, 130)
        await s.run_stop(rid, 160)
        await s.close()
        return rid
    rid = run(main())
    con = sqlite3.connect(tmp_path / "w.db")
    assert con.execute("select start_ms, heartbeat_ms, stop_ms from agent_runs where id=?", (rid,)).fetchone() == (100, 130, 160)
    con.close()


def test_meta_salt_persists(tmp_path):
    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()
        a = await s.meta_get("salt")
        if a is None:
            await s.meta_set("salt", "abc")
        await s.close()
        s = Store(tmp_path / "w.db")
        await s.open()
        b = await s.meta_get("salt")
        await s.close()
        return b
    assert run(main()) == "abc"


def test_insert_only_known_tables(tmp_path):
    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()
        await s.insert("selfcheck", ts_ms=1, result_json="{}")
        with pytest.raises(ValueError):
            await s.insert("sqlite_master; drop table events", ts_ms=1)
        await s.close()
    run(main())


def test_same_second_written_twice_is_merged(tmp_path):
    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()
        await s.add_samples([SampleRow(1000, "dns", "p", sent=2, ok=2, lost=0, rtt_min=10.0, rtt_avg=10.0, rtt_max=10.0)])
        await s.flush()
        await s.late(1000, "dns", "p")
        await s.add_samples([SampleRow(1000, "dns", "p", sent=1, ok=1, lost=0, rtt_min=40.0, rtt_avg=40.0, rtt_max=40.0)])
        await s.close()
    run(main())
    con = sqlite3.connect(tmp_path / "w.db")
    row = con.execute("select sent, ok, late, rtt_min, rtt_avg, rtt_max from samples_1s").fetchone()
    con.close()
    assert row == (3, 3, 1, 10.0, 20.0, 40.0)


def test_failed_flush_keeps_the_batch(tmp_path, monkeypatch):
    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()
        await s.add_samples([SampleRow(1000, "dns", "p", sent=1, ok=1, lost=0)])
        real = s._flush_sync

        def boom(*a):
            raise sqlite3.OperationalError("database is locked")
        s._flush_sync = boom
        with pytest.raises(sqlite3.OperationalError):
            await s.flush()
        s._flush_sync = real
        await s.close()
    run(main())
    con = sqlite3.connect(tmp_path / "w.db")
    assert con.execute("select count(*) from samples_1s").fetchone()[0] == 1
    con.close()


def test_buffer_is_capped_when_sqlite_keeps_failing(tmp_path, monkeypatch):
    import whydrop.agent.store as st
    monkeypatch.setattr(st, "MAX_BUFFERED", 100)

    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()

        def boom(*a):
            raise sqlite3.OperationalError("attempt to write a readonly database")
        s._flush_sync = boom
        for i in range(5):
            await s.add_samples([SampleRow(i * 1000 + j, "dns", "p", 1, 1, 0) for j in range(60)])
            with pytest.raises(sqlite3.OperationalError):
                await s.flush()
        n = len(s._samples)
        s._flush_sync = lambda *a: None
        await s.close()
        return n
    assert run(main()) == 100
