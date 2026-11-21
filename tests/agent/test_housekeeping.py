import asyncio
import sqlite3

from whydrop.agent.housekeeping import housekeep
from whydrop.agent.store import SampleRow, Store

DAY = 86_400_000
NOW = 100 * DAY


def run(coro):
    return asyncio.run(coro)


async def seeded(path, rows, incidents=()):
    s = Store(path)
    await s.open()
    await s.add_samples(rows)
    await s.flush()
    for start, end in incidents:
        await s.insert("incidents", start_ms=start, end_ms=end, primary_cause="R2 likely")
    return s


def count(path, sql):
    con = sqlite3.connect(path)
    try:
        return con.execute(sql).fetchone()[0]
    finally:
        con.close()


def test_rollup_keeps_incident_window(tmp_path):
    old = NOW - 10 * DAY
    rows = [SampleRow(old + i * 1000, "gateway", "gateway", 1, 1, 0, rtt_min=5.0, rtt_avg=5.0, rtt_max=5.0)
            for i in range(0, 3600)]  # one hour of 1 s rows, 10 days old
    incident = (old + 1800_000, old + 1860_000)

    async def main():
        s = await seeded(tmp_path / "w.db", rows, [incident])
        await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))
        await s.close()
    run(main())
    p = tmp_path / "w.db"
    assert count(p, "select count(*) from samples_1m") == 60
    assert count(p, "select sum(sent) from samples_1m") == 3600
    kept = count(p, "select count(*) from samples_1s")
    assert kept == 60 + 2 * 600  # incident minute plus ±10 min around it


def test_everything_older_than_90_days_goes(tmp_path):
    rows = [SampleRow(NOW - 91 * DAY + i * 1000, "dns", "p", 1, 1, 0) for i in range(100)]

    async def main():
        s = await seeded(tmp_path / "w.db", rows, [(NOW - 91 * DAY, NOW - 91 * DAY + 50_000)])
        await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))
        await s.close()
    run(main())
    assert count(tmp_path / "w.db", "select count(*) from samples_1s") == 0


def test_chunked_delete(tmp_path):
    rows = [SampleRow(NOW - 8 * DAY + i * 1000, "dns", "p", 1, 1, 0) for i in range(12_000)]

    async def main():
        s = await seeded(tmp_path / "w.db", rows)
        report = await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12), chunk=5000)
        await s.close()
        return report
    report = run(main())
    assert report["deleted_1s"] == 12_000 and report["chunks"] == 3


def test_disk_guard_threshold(tmp_path):
    async def main():
        s = await seeded(tmp_path / "w.db", [])
        low = await housekeep(s, NOW, free_bytes=lambda: (1 * 2**30, 100 * 2**30))   # 1 GB free of 100 GB
        ok = await housekeep(s, NOW, free_bytes=lambda: (6 * 2**30, 100 * 2**30))    # above min(2 GB, 5 GB)
        override = await housekeep(s, NOW, free_bytes=lambda: (6 * 2**30, 100 * 2**30), min_free_mb=8192)
        await s.close()
        return low, ok, override
    low, ok, override = run(main())
    assert low["disk_full"] and not ok["disk_full"] and override["disk_full"]
