import asyncio
import sqlite3

from whydrop.agent.housekeeping import ROLLUP_LAG_MS, housekeep
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


def test_recent_seconds_are_rolled_up_without_waiting_a_week(tmp_path):
    rows = [SampleRow(NOW - 3 * 3_600_000 + i * 1000, "line_hb", "p", 1, 1, 0) for i in range(3 * 3600)]

    async def main():
        s = await seeded(tmp_path / "w.db", rows)
        await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))
        await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))   # a second pass adds nothing twice
        until = int(await s.meta_get("rollup_until"))
        await s.close()
        return until
    until = run(main())
    p = tmp_path / "w.db"
    assert until == (NOW - ROLLUP_LAG_MS) // 60_000 * 60_000
    assert count(p, f"select sum(sent) from samples_1s where ts_ms < {until}") == count(p, "select sum(sent) from samples_1m")
    assert count(p, "select max(ts_ms) from samples_1m") == until - 60_000
    assert count(p, "select count(*) from samples_1s") == 3 * 3600      # 1 s rows still live 7 days


def test_first_rollup_goes_an_hour_per_transaction(tmp_path):
    first = NOW - 5 * 3_600_000 + 17_000                                  # not on a minute: the start rounds down
    rows = [SampleRow(first + i * 10_000, "gateway", "gateway", 1, 1, 0) for i in range(5 * 360)]
    spans = []

    async def main():
        s = await seeded(tmp_path / "w.db", rows)
        real = s.execute_atomic

        async def spy(statements):
            spans.append(statements[0][1][1:])                           # (since, stop) of the rollup statement
            await real(statements)
        s.execute_atomic = spy
        await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))
        await s.close()
    run(main())
    roll_to = (NOW - ROLLUP_LAG_MS) // 60_000 * 60_000
    assert spans[0][0] == first // 60_000 * 60_000 and spans[-1][1] == roll_to
    assert all(b - a <= 3_600_000 for a, b in spans)
    assert all(spans[i][1] == spans[i + 1][0] for i in range(len(spans) - 1))   # no gap, no overlap
    assert count(tmp_path / "w.db", "select sum(sent) from samples_1m") == sum(1 for r in rows if r.ts_ms < roll_to)


def test_empty_store_starts_the_rollup_point_now(tmp_path):
    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()
        await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))
        until = await s.meta_get("rollup_until")
        await s.close()
        return int(until)
    assert run(main()) == (NOW - ROLLUP_LAG_MS) // 60_000 * 60_000


def test_rollup_waits_for_the_latest_late_reply():
    from whydrop.agent.precision.udp_stream import LATE_MS
    from whydrop.agent.probes.base import LATE_S
    assert ROLLUP_LAG_MS > 2 * max(LATE_MS, LATE_S * 1000)              # a late reply never lands in a rolled-up second


def test_rollup_skips_empty_hours(tmp_path):
    first = NOW - 2 * 3_600_000
    rows = [SampleRow(first + i * 1000, "gateway", "gateway", 1, 1, 0) for i in range(7200)]
    spans = []

    async def main():
        s = await seeded(tmp_path / "w.db", rows)
        await s.meta_set("rollup_until", str(NOW - 7 * DAY))              # what the 7-day rollup of 0.1.0 left behind
        real = s.execute_atomic

        async def spy(statements):
            spans.append(statements[0][1][1:])
            await real(statements)
        s.execute_atomic = spy
        await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))
        until = int(await s.meta_get("rollup_until"))
        await s.close()
        return until
    until = run(main())
    assert spans[0][0] == first and len(spans) == 2                       # two hours of rows, two statements
    assert until == (NOW - ROLLUP_LAG_MS) // 60_000 * 60_000
    assert count(tmp_path / "w.db", "select sum(sent) from samples_1m") == 7200 - ROLLUP_LAG_MS // 1000


def test_seconds_written_after_a_clock_step_back_are_rolled_up(tmp_path):
    """A Pi without an RTC loses power and boots 40 min in the past with the line down: those seconds land behind
    the rollup point. Found in review: they were never rolled up, so the long views showed the outage as fine."""
    rows = [SampleRow(NOW - 2 * 3_600_000 + i * 1000, "line_hb", "p", 1, 1, 0) for i in range(7200)]
    back = NOW - 40 * 60_000
    outage = [SampleRow(back + i * 1000, "line_hb", "p", 1, 0, 1) for i in range(600)]   # same seconds as before

    async def main():
        s = await seeded(tmp_path / "w.db", rows)
        await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))
        await s.run_start(back, "t", {})                                    # the reboot, 40 min in the past
        await s.add_samples(outage)
        await s.flush()
        await housekeep(s, back + 600_000, free_bytes=lambda: (10**12, 10**12))   # still in the past
        await housekeep(s, NOW + 3_600_000, free_bytes=lambda: (10**12, 10**12))  # NTP is back
        await s.close()
    run(main())
    p = tmp_path / "w.db"
    assert count(p, "select sum(lost) from samples_1m") == 600
    assert count(p, "select sum(sent) from samples_1m") == 7200 + 600     # each second once, the outage included


def test_a_clock_reset_far_back_does_not_recompute_minutes_whose_seconds_are_gone(tmp_path):
    """Seconds kept around an old incident start mid-minute: recomputing that minute from them would shrink it."""
    rows = [SampleRow(NOW - 10 * DAY + i * 10_000, "line_hb", "p", 1, 1, 0) for i in range(10 * 8640)]
    inc = NOW - 9 * DAY + 30_000                                            # its ±10 min edges fall mid-minute

    async def main():
        s = await seeded(tmp_path / "w.db", rows, [(inc, inc + 60_000)])
        await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))      # rolls 10 days, deletes the oldest 3
        await s.run_start(NOW - 30 * DAY, "t", {})                          # a board that booted a month in the past
        await housekeep(s, NOW - 30 * DAY + 60_000, free_bytes=lambda: (10**12, 10**12))
        await housekeep(s, NOW + 600_000, free_bytes=lambda: (10**12, 10**12))
        await s.close()
    run(main())
    assert count(tmp_path / "w.db", "select sum(sent) from samples_1m") == 10 * 8640   # every minute still whole


def test_strip_events_and_minutes_have_an_end(tmp_path):
    """The packet strip and events were never deleted (the docs said 90 days); minute rows grew 36 k a day forever."""
    from whydrop.agent.events import Event

    async def main():
        s = await seeded(tmp_path / "w.db", [])
        for age in (89, 91):
            t = NOW - age * DAY
            await s.executemany("INSERT INTO udp_seq_ring (agent_id, ts_ms, seq, echoed, dir) VALUES (1, ?, ?, 1, 'ok')",
                                [(t, age)])
            await s.add_events([Event("stall", t, "reflector", {"phase": "start"})])
        for age in (364, 366):
            await s.execute("INSERT INTO samples_1m (agent_id, ts_ms, probe, pair, sent, ok, lost, lost_up, lost_down, "
                            "lost_dir_unknown, late, local_fail) VALUES (1, ?, 'line_hb', 'p', 60, 60, 0, 0, 0, 0, 0, 0)",
                            (NOW - age * DAY,))
        await s.flush()
        await s.meta_set("rollup_until", str(NOW))                         # nothing to roll up here
        await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))
        await s.close()
    run(main())
    p = tmp_path / "w.db"
    assert count(p, "select group_concat(seq) from udp_seq_ring") == "89"
    assert count(p, f"select count(*) from events where ts_ms < {NOW - 90 * DAY}") == 0
    assert count(p, "select count(*) from events") == 1
    assert count(p, f"select count(*) from samples_1m where ts_ms = {NOW - 364 * DAY}") == 1
    assert count(p, "select count(*) from samples_1m") == 1

