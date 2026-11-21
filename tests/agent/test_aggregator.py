import asyncio

from whydrop.agent.results import Aggregator, Result


class FakeStore:
    def __init__(self):
        self.rows, self.lates = [], []

    async def add_samples(self, rows):
        self.rows.extend(rows)

    async def late(self, ts_ms, probe, pair):
        self.lates.append((ts_ms, probe, pair))


def r(t, ok=True, rtt=10.0, local=False, pair="p"):
    return Result("dns", pair, "google", t, ok, rtt if ok else None, local_fail=local)


def test_aggregator_buckets_by_send_time():
    now = [10_000]
    st = FakeStore()
    a = Aggregator(st, now_ms=lambda: now[0])

    async def main():
        a.add(r(10_100))
        a.add(r(10_900, ok=False))
        now[0] = 12_500  # results arrive later, still land in the second they were sent
        a.add(r(10_950, rtt=30.0))
        await a.flush_ready()
        assert st.rows == []  # 10 s bucket isn't final until 10 + 1 + 4.5 s
        now[0] = 15_600
        await a.flush_ready()
    asyncio.run(main())
    [row] = st.rows
    assert (row.ts_ms, row.sent, row.ok, row.lost) == (10_000, 3, 2, 1)
    assert (row.rtt_min, row.rtt_max, row.rtt_avg) == (10.0, 30.0, 20.0)


def test_local_fail_is_not_loss():
    now = [0]
    st = FakeStore()
    a = Aggregator(st, now_ms=lambda: now[0])

    async def main():
        a.add(r(100, ok=False, local=True))
        now[0] = 10_000
        await a.flush_ready()
    asyncio.run(main())
    [row] = st.rows
    assert (row.sent, row.ok, row.lost, row.local_fail) == (1, 0, 0, 1)


def test_aggregator_late_before_and_after_flush():
    now = [0]
    st = FakeStore()
    a = Aggregator(st, now_ms=lambda: now[0])

    async def main():
        a.add(r(100, ok=False))
        await a.late("dns", "p", 100)           # still in memory
        a.add(r(1100, ok=False))
        now[0] = 10_000
        await a.flush_ready()
        await a.late("dns", "p", 1100)          # already written: goes to the store
    asyncio.run(main())
    first = next(x for x in st.rows if x.ts_ms == 0)
    assert (first.lost, first.late) == (0, 1)
    assert st.lates == [(1000, "dns", "p")]
