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


def test_backward_step_reported_once():
    f = Fake()
    t = tb(f)
    f.advance(1)
    f.wall -= 3600
    assert len(t.check()) == 1
    for _ in range(5):
        f.advance(1)
        assert t.check() == []


def test_slew_never_reports_a_step():
    f = Fake()
    t = tb(f)
    for _ in range(3 * 3600):   # 3 h of 1 s ticks with the wall clock running 500 ppm slow
        f.mono += 1
        f.boot += 1
        f.wall += 1 - 500e-6
        assert t.check() == []
    assert abs(t.now_ms() - f.wall * 1000) < 1000  # timestamps still follow wall time


def test_rebase_hides_startup_gap_on_windows():
    f = Fake()
    t = tb(f, platform="win32")
    f.advance(12)  # self-check took 12 s before the first tick
    t.rebase()
    f.advance(1)
    assert t.check() == []


def test_boot_step_before_rebase_is_followed():
    f = Fake()
    t = tb(f)
    f.advance(20)
    f.wall += 3600  # NTP fixes a clock without RTC while the agent waits for time sync and the route
    t.rebase()
    assert abs(t.now_ms() - f.wall * 1000) < 1
    f.advance(1)
    assert t.check() == [] and abs(t.now_ms() - f.wall * 1000) < 1


def test_after_a_backward_step_timestamps_catch_up_with_the_wall_without_going_back():
    """Final review: after a backward step the timestamps stayed ahead forever, so the dashboard (which asks by wall
    time) missed the newest data until a restart. They now run at half speed until they meet the wall clock."""
    f = Fake()
    t = tb(f)
    f.advance(10)
    f.wall -= 3600
    t.check()
    last = t.now_ms()
    for _ in range(7300):                                  # a little over two hours of 1 s ticks
        f.advance(1)
        t.check()
        now = t.now_ms()
        assert now > last                                  # never back, never a repeated second
        last = now
    assert abs(t.now_ms() / 1000 - f.wall) < 1.0
