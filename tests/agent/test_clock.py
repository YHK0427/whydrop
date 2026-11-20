import asyncio

from whydrop.agent import clock
from whydrop.agent.clock import TimeBase


class Fake:
    def __init__(self, wall=1_700_000_000.0, mono=100.0, boot=200.0):
        self.wall, self.mono, self.boot = wall, mono, boot

    def advance(self, s, *, asleep=False):
        self.wall += s
        self.boot += s
        if not asleep:
            self.mono += s


def tb(f, platform="linux"):
    return TimeBase(wall=lambda: f.wall, mono=lambda: f.mono,
                    boot=(lambda: f.boot) if platform == "linux" else None, platform=platform)


def test_now_ms_monotonic_between_steps():
    f = Fake()
    t = tb(f)
    a = t.now_ms()
    f.advance(1.5)
    assert t.check() == [] and t.now_ms() - a == 1500


def test_clock_step_forward_reanchors():
    f = Fake()
    t = tb(f)
    f.advance(1)
    f.wall += 3600  # NTP fixes a clock that was an hour behind (fake-hwclock on a Pi)
    [e] = t.check()
    assert e.kind == "clock_step" and round(e.detail["delta_s"]) == 3600
    assert abs(t.now_ms() - f.wall * 1000) < 1


def test_clock_step_backward_never_repeats_a_second():
    f = Fake()
    t = tb(f)
    f.advance(10)
    before = t.now_ms()
    f.wall -= 3600
    [e] = t.check()
    assert e.kind == "clock_step" and e.detail["delta_s"] < -3599
    f.advance(1)
    assert t.now_ms() > before  # timestamps keep moving forward; the step is recorded, not replayed


def test_suspend_detected_linux():
    f = Fake()
    t = tb(f)
    f.advance(300, asleep=True)  # CLOCK_MONOTONIC stops while asleep, BOOTTIME and wall don't
    [e] = t.check()
    assert e.kind == "suspend" and round(e.detail["slept_s"]) == 300
    assert abs(t.now_ms() - f.wall * 1000) < 1


def test_suspend_detected_windows_wall_jump():
    f = Fake()
    t = tb(f, platform="win32")
    f.advance(1)
    t.check()
    f.advance(120, asleep=True)
    [e] = t.check()
    assert e.kind == "suspend"


def test_small_drift_is_ignored():
    f = Fake()
    t = tb(f)
    f.advance(1)
    f.wall += 0.5
    assert t.check() == []


def test_wait_time_sync(monkeypatch):
    states = iter([5, 5, 0])
    monkeypatch.setattr(clock, "_adjtimex_state", lambda: next(states))
    monkeypatch.setattr(clock.sys, "platform", "linux")

    async def fast_sleep(d):
        pass
    assert asyncio.run(clock.wait_time_sync(60, sleep=fast_sleep)) is True


def test_wait_time_sync_times_out(monkeypatch):
    monkeypatch.setattr(clock, "_adjtimex_state", lambda: 5)
    monkeypatch.setattr(clock.sys, "platform", "linux")

    async def fast_sleep(d):
        pass
    assert asyncio.run(clock.wait_time_sync(3, sleep=fast_sleep)) is False
