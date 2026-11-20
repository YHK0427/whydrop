import asyncio
import random

import pytest

from whydrop.agent.scheduler import LagWatchdog, Scheduler


class FakeTime:
    def __init__(self):
        self.t = 0.0

    def mono(self):
        return self.t

    async def sleep(self, d):
        await asyncio.sleep(0)  # let tasks created at the current time run before time moves on
        self.t += max(d, 0)
        await asyncio.sleep(0)


def test_scheduler_absolute_ticks_and_jitter():
    ft = FakeTime()
    calls = []

    async def job():
        calls.append(ft.t)

    async def main():
        stop = asyncio.Event()
        s = Scheduler(rng=random.Random(1), mono=ft.mono, sleep=ft.sleep)
        s.every("j", 1.0, job, phase_s=0.0)
        task = asyncio.create_task(s.run(stop))
        while len(calls) < 10:
            await asyncio.sleep(0)
        stop.set()
        await task

    asyncio.run(main())
    offsets = [t - k for k, t in enumerate(calls[:10])]
    assert all(abs(o) <= 0.1 + 1e-9 for o in offsets) and any(abs(o) > 1e-6 for o in offsets)


def test_slow_job_does_not_delay_others():
    ft = FakeTime()
    fast = []
    never = asyncio.Event()

    async def slow():
        await never.wait()

    async def quick():
        fast.append(ft.t)

    async def main():
        stop = asyncio.Event()
        s = Scheduler(rng=random.Random(2), mono=ft.mono, sleep=ft.sleep)
        s.every("slow", 1.0, slow)
        s.every("quick", 1.0, quick, phase_s=0.5)
        task = asyncio.create_task(s.run(stop))
        while len(fast) < 5:
            await asyncio.sleep(0)
        stop.set()
        await task

    asyncio.run(main())
    assert len(fast) >= 5


def test_failing_job_keeps_scheduling():
    ft = FakeTime()
    n = []

    async def boom():
        n.append(1)
        raise RuntimeError("probe bug")

    async def main():
        stop = asyncio.Event()
        s = Scheduler(rng=random.Random(3), mono=ft.mono, sleep=ft.sleep)
        s.every("boom", 1.0, boom)
        task = asyncio.create_task(s.run(stop))
        while len(n) < 3:
            await asyncio.sleep(0)
        stop.set()
        await task

    asyncio.run(main())
    assert len(n) >= 3


def test_lag_watchdog_emits_start_and_end():
    ft = FakeTime()
    lags = iter([0.0, 0.0, 0.5, 0.8, 0.0, 0.0])
    events = []

    async def laggy_sleep(d):
        ft.t += d + next(lags, 0.0)
        await asyncio.sleep(0)

    async def main():
        stop = asyncio.Event()
        w = LagWatchdog(events.append, now_ms=lambda: int(ft.t * 1000), mono=ft.mono, sleep=laggy_sleep,
                        cpu_stat_path=None)
        task = asyncio.create_task(w.run(stop))
        while len(events) < 2:
            await asyncio.sleep(0)
        stop.set()
        await task

    asyncio.run(main())
    start, end = events[:2]
    assert start.kind == end.kind == "agent_lag"
    assert start.detail["phase"] == "start" and end.detail["phase"] == "end"
    assert round(end.detail["max_lag_ms"]) == 800


def test_missed_ticks_are_skipped_not_burst():
    ft = FakeTime()
    calls = []

    async def job():
        calls.append(ft.t)

    async def main():
        stop = asyncio.Event()
        s = Scheduler(rng=random.Random(4), mono=ft.mono, sleep=ft.sleep)
        s.every("j", 1.0, job)
        task = asyncio.create_task(s.run(stop))
        while len(calls) < 3:
            await asyncio.sleep(0)
        ft.t += 300  # the host slept for 5 minutes
        while len(calls) < 6:
            await asyncio.sleep(0)
        stop.set()
        await task

    asyncio.run(main())
    after = [t for t in calls if t > 300]
    assert len(after) >= 2 and after[1] - after[0] > 0.5  # not a burst of 300 catch-up runs


def test_hung_job_is_not_stacked():
    ft = FakeTime()
    starts = []
    never = asyncio.Event()

    async def hung():
        starts.append(ft.t)
        await never.wait()

    async def main():
        stop = asyncio.Event()
        s = Scheduler(rng=random.Random(5), mono=ft.mono, sleep=ft.sleep)
        s.every("hung", 1.0, hung)
        task = asyncio.create_task(s.run(stop))
        while ft.t < 10:
            await asyncio.sleep(0)
        stop.set()
        await task
        return s

    s = asyncio.run(main())
    assert len(starts) == 1 and s.skipped["hung"] >= 8


def test_interval_must_be_positive():
    with pytest.raises(ValueError):
        Scheduler().every("x", 0, None)
