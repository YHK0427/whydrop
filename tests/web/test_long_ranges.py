"""6 h / 24 h / 7 d views: minute rows for what is rolled up, second rows after that, nothing counted twice."""
import asyncio
import sqlite3

import pytest

from whydrop.agent.housekeeping import housekeep
from whydrop.agent.store import SampleRow, Store
from whydrop.web.queries import chart, samples

H = 3_600_000
NOW = 1_800_000_000_000          # a fixed clock: minute-aligned
LOST_EVERY = 97                  # every 97th second of the line heartbeat is lost


def rows(hours: int):
    out = []
    for i in range(hours * 3600):
        t = NOW - hours * H + i * 1000
        lost = 1 if i % LOST_EVERY == 0 else 0
        out.append(SampleRow(t, "line_hb", "p", 1, 1 - lost, lost, rtt_min=20.0, rtt_avg=20.0, rtt_max=20.0))
    return out


def make(path, hours, roll: bool):
    async def main():
        s = Store(path)
        await s.open()
        await s.add_samples(rows(hours))
        await s.flush()
        if roll:
            await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))
        await s.close()
    asyncio.run(main())
    return path


def total_lost(hours):
    return sum(1 for i in range(hours * 3600) if i % LOST_EVERY == 0)


@pytest.mark.parametrize("roll", [False, True], ids=["before-any-rollup", "after-rollup"])
@pytest.mark.parametrize("span_h", [6, 24])
def test_long_views_show_every_second_once(tmp_path, roll, span_h):
    db = make(tmp_path / "w.db", span_h, roll)
    c = chart(db, NOW - span_h * H, NOW, None, now_ms=NOW)
    assert c["step_s"] >= 60
    assert sum(v or 0 for v in c["basic_lost"]) == total_lost(span_h)
    assert c["x"][-1] * 1000 >= NOW - 2 * c["step_s"] * 1000   # x is in seconds; the last minutes are there, not only rolled-up ones
    assert all(r == 20.0 for r in c["rtt"] if r is not None)


def test_samples_api_counts_once_too(tmp_path):
    db = make(tmp_path / "w.db", 24, roll=True)
    out = samples(db, NOW - 24 * H, NOW, None, probe="line_hb", now_ms=NOW)
    assert sum(r["lost"] for r in out["rows"]) == total_lost(24)
    assert sum(r["sent"] for r in out["rows"]) == 24 * 3600


def test_a_minute_with_kept_seconds_counts_once(tmp_path):
    """Seconds around an incident outlive the 7 days next to their minute row: the view reads one of them, not both."""
    old = NOW - 8 * 24 * H
    data = [SampleRow(old + i * 1000, "line_hb", "p", 1, 1 - (i % LOST_EVERY == 0), int(i % LOST_EVERY == 0))
            for i in range(3600)]

    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()
        await s.add_samples(data)
        await s.flush()
        await s.insert("incidents", start_ms=old + 1800_000, end_ms=old + 1860_000, primary_cause="R2 likely")
        await housekeep(s, NOW, free_bytes=lambda: (10**12, 10**12))
        await s.close()
    asyncio.run(main())
    db = tmp_path / "w.db"
    with sqlite3.connect(db) as con:
        assert con.execute("select count(*) from samples_1s").fetchone()[0] > 0    # the seconds really are still there
    c = chart(db, NOW - 9 * 24 * H, NOW, None, now_ms=NOW)
    assert sum(v or 0 for v in c["basic_lost"]) == total_lost(1)
    out = samples(db, NOW - 9 * 24 * H, NOW, None, probe="line_hb", now_ms=NOW)
    assert sum(r["sent"] for r in out["rows"]) == 3600


def test_a_range_starting_mid_minute_reads_the_same_before_and_after_rollup(tmp_path):
    start = NOW - 6 * H + 30_000                                          # half a minute into the first minute
    seen = [chart(make(tmp_path / f"{roll}.db", 6, roll), start, NOW, None, now_ms=NOW) for roll in (False, True)]
    assert seen[0] == seen[1]
    assert sum(v or 0 for v in seen[1]["basic_lost"]) == total_lost(6)   # the minute the range starts in is whole


@pytest.mark.parametrize("window", ["ends-before-the-rollup-point", "starts-after-it"])
def test_windows_on_one_side_of_the_rollup_point_count_once(tmp_path, window):
    """Yesterday's 6 h ends before `rollup_until`; a forced 60 s step on the last 3 min starts after it."""
    db = make(tmp_path / "w.db", 24, roll=True)
    a, b = (NOW - 24 * H, NOW - 18 * H) if window == "ends-before-the-rollup-point" else (NOW - 3 * 60_000, NOW)
    c = chart(db, a, b, 60, now_ms=NOW)
    want = sum(1 for i in range(24 * 3600) if i % LOST_EVERY == 0 and a <= NOW - 24 * H + i * 1000 < b)
    assert c["step_s"] == 60 and sum(v or 0 for v in c["basic_lost"]) == want
