"""Agent time base: wall-anchored monotonic timestamps, clock steps and suspend detection (spec §4 "Time")."""
import asyncio
import ctypes
import ctypes.util
import sys
import time

from whydrop.agent.events import Event

STEP_S = 2.0               # wall vs. expected drift that counts as a clock step
SUSPEND_LINUX_S = 2.0      # growth of BOOTTIME − MONOTONIC that means the host slept
SUSPEND_WINDOWS_S = 5.0
SLEW_BACK_MAX_S = 1.0     # follow wall time backwards only by less than this per tick
TIME_ERROR = 5             # adjtimex state: clock not synchronized


def _linux_boottime() -> float:
    return time.clock_gettime(time.CLOCK_BOOTTIME)


class TimeBase:
    def __init__(self, wall=time.time, mono=time.monotonic, boot=None, platform: str = sys.platform):
        if boot is None and platform.startswith("linux") and hasattr(time, "CLOCK_BOOTTIME"):
            boot = _linux_boottime
        self._wall, self._mono, self._boot = wall, mono, boot
        self._windows = platform == "win32"
        self._anchor(wall(), mono())
        self._last_wall, self._last_mono = self._anchor_wall, self._anchor_mono
        self._last_gap = boot() - mono() if boot else 0.0

    def _anchor(self, w: float, m: float) -> None:
        self._anchor_wall, self._anchor_mono = w, m

    def now_ms(self) -> int:
        return int((self._anchor_wall + self._mono() - self._anchor_mono) * 1000)

    def check(self) -> list[Event]:
        """Call every tick. Forward clock steps and wake-ups re-anchor; a backward step is recorded but
        timestamps keep moving forward, so 1 s buckets are never reused."""
        w, m = self._wall(), self._mono()
        out: list[Event] = []
        slept = None
        if self._boot:
            gap = self._boot() - m
            if gap - self._last_gap > SUSPEND_LINUX_S:
                slept = gap - self._last_gap
            self._last_gap = gap
        elif self._windows:
            wall_adv, mono_adv = w - self._last_wall, m - self._last_mono
            if wall_adv - mono_adv > SUSPEND_WINDOWS_S or mono_adv > SUSPEND_WINDOWS_S:
                slept = max(wall_adv, mono_adv)
        if slept is not None:
            self._anchor(w, m)
            out.append(Event("suspend", int(w * 1000), detail={"slept_s": round(slept, 1)}))
        else:
            jump = (w - self._last_wall) - (m - self._last_mono)  # step since the previous tick, not since start
            ahead = (self._anchor_wall + m - self._anchor_mono) - w  # how far our timestamps run ahead of wall
            if abs(jump) > STEP_S:
                if jump > 0:
                    self._anchor(w, m)
                out.append(Event("clock_step", self.now_ms(), detail={"delta_s": round(jump, 3)}))
            elif -STEP_S < ahead < SLEW_BACK_MAX_S:
                self._anchor(w, m)  # follow NTP slew; a sub-second move back stays inside an open 1 s bucket
        self._last_wall, self._last_mono = w, m
        return out


_libc = None


def _adjtimex_state() -> int:
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    buf = ctypes.create_string_buffer(512)  # struct timex (208 B on 64-bit) with modes = 0: read-only, unprivileged
    return _libc.adjtimex(buf)


async def wait_time_sync(timeout_s: float = 60, sleep=asyncio.sleep) -> bool:
    """Linux: wait until the kernel says the clock is synchronized. Other platforms: assume it is."""
    if not sys.platform.startswith("linux"):
        return True
    for _ in range(int(timeout_s)):
        try:
            if _adjtimex_state() != TIME_ERROR:  # -1 (call failed) also passes: can't tell, don't block
                return True
        except (OSError, AttributeError, TypeError):
            return True  # can't tell: don't block startup
        await sleep(1)
    return False
