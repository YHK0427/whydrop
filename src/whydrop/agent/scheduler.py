"""Absolute-time scheduler with jitter, and the event-loop lag watchdog (spec §4)."""
import asyncio
import logging
import random
import sys
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from whydrop.agent.events import Event

log = logging.getLogger(__name__)

JITTER = 0.10
LAG_SAMPLE_S = 0.1
LAG_THRESHOLD_S = 0.3
CPU_STAT_EVERY = 100  # samples (10 s)


class Scheduler:
    def __init__(self, rng: random.Random | None = None, mono=time.monotonic, sleep=asyncio.sleep):
        self._rng = rng or random.Random()
        self._mono, self._sleep = mono, sleep
        self._jobs: list[tuple[str, float, Callable[[], Awaitable[None]], float]] = []
        self._running: set[asyncio.Task] = set()

    def every(self, name: str, interval_s: float, fn: Callable[[], Awaitable[None]], phase_s: float = 0.0) -> None:
        self._jobs.append((name, interval_s, fn, phase_s))

    async def _safe(self, name: str, fn) -> None:
        try:
            await fn()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("job %s failed", name)

    async def _loop(self, name: str, interval: float, fn, phase: float, start: float) -> None:
        k = 0
        while True:
            target = start + phase + k * interval + self._rng.uniform(-JITTER, JITTER) * interval
            await self._sleep(max(0.0, target - self._mono()))
            t = asyncio.create_task(self._safe(name, fn))  # a slow run never delays the next tick
            self._running.add(t)
            t.add_done_callback(self._running.discard)
            k += 1

    async def run(self, stop: asyncio.Event) -> None:
        start = self._mono()
        loops = [asyncio.create_task(self._loop(n, i, f, p, start)) for n, i, f, p in self._jobs]
        try:
            await stop.wait()
        finally:
            for t in loops + list(self._running):
                t.cancel()
            await asyncio.gather(*loops, *self._running, return_exceptions=True)


class LagWatchdog:
    def __init__(self, on_event: Callable[[Event], None], *, now_ms, mono=time.monotonic, sleep=asyncio.sleep,
                 cpu_stat_path: str | None = "/sys/fs/cgroup/cpu.stat"):
        self._emit, self._now_ms, self._mono, self._sleep = on_event, now_ms, mono, sleep
        self._cpu = cpu_stat_path if cpu_stat_path and sys.platform.startswith("linux") else None
        self._throttled: int | None = None

    def _read_throttled(self) -> int | None:
        try:
            for line in Path(self._cpu).read_text().splitlines():
                if line.startswith("nr_throttled "):
                    return int(line.split()[1])
        except (OSError, ValueError):
            return None
        return None

    async def run(self, stop: asyncio.Event) -> None:
        in_lag, worst, n = False, 0.0, 0
        while not stop.is_set():
            t0 = self._mono()
            await self._sleep(LAG_SAMPLE_S)
            lag = self._mono() - t0 - LAG_SAMPLE_S
            if lag > LAG_THRESHOLD_S:
                worst = max(worst, lag)
                if not in_lag:
                    in_lag = True
                    self._emit(Event("agent_lag", self._now_ms(), detail={"phase": "start", "lag_ms": round(lag * 1000)}))
            elif in_lag:
                in_lag = False
                self._emit(Event("agent_lag", self._now_ms(), detail={"phase": "end", "max_lag_ms": round(worst * 1000)}))
                worst = 0.0
            n += 1
            if self._cpu and n % CPU_STAT_EVERY == 0:
                cur = self._read_throttled()
                if cur is not None and self._throttled is not None and cur > self._throttled:
                    self._emit(Event("cpu_throttle", self._now_ms(), detail={"nr_throttled": cur - self._throttled}))
                self._throttled = cur if cur is not None else self._throttled
