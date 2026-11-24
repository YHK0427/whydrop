"""Per-session replay window and the tombstones that keep it closed across restarts (spec §5.4, §5.5)."""
import json
import logging
import math
import os
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)


class ReplayWindow:
    """Accepts each seq once; seqs more than WIDTH behind the highest, or at/below floor, are rejected."""

    WIDTH = 1024
    _FULL = (1 << WIDTH) - 1

    def __init__(self, floor: int = -1):
        self._floor = floor
        self._highest = -1
        self._mask = 0  # bit i set = seq (highest - i) was seen

    @property
    def highest(self) -> int:
        return self._highest

    def accept(self, seq: int) -> bool:
        if seq <= self._floor:
            return False
        if seq > self._highest:
            shift = seq - self._highest
            self._mask = ((self._mask << shift) | 1) & self._FULL if shift < self.WIDTH else 1
            self._highest = seq
            return True
        off = self._highest - seq
        if off >= self.WIDTH or self._mask >> off & 1:
            return False
        self._mask |= 1 << off
        return True

    def seen(self, seq: int) -> bool:
        off = self._highest - seq
        return 0 <= off < self.WIDTH and self._highest >= 0 and bool(self._mask >> off & 1)


class Tombstones:
    """session_id → highest accepted seq, kept 7 days and persisted atomically."""

    def __init__(self, path: Path | None, *, ttl_s: float = 7 * 86400, cap: int = 100_000, wall=time.time):
        self._path = Path(path) if path is not None else None
        self._ttl = ttl_s
        self._cap = cap
        self._wall = wall
        self._t: dict[int, list[float]] = {}  # sid -> [highest, last_seen_wall]
        self._io = threading.Lock()  # a periodic write may still run in its thread when the shutdown write starts

    def get(self, session_id: int) -> int | None:
        e = self._t.get(session_id)
        return int(e[0]) if e else None

    def update(self, session_id: int, highest: int) -> None:
        self._t[session_id] = [highest, self._wall()]

    def load(self) -> None:
        self._t = {}
        if self._path is None or not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            self._t = {int(k): [int(v[0]), float(v[1])] for k, v in raw["t"].items() if math.isfinite(float(v[1]))}
        except (ValueError, KeyError, TypeError, IndexError, AttributeError, OverflowError, RecursionError) as e:
            log.warning("tombstone file %s unreadable (%s); starting empty, replays inside the gap may be answered once", self._path, e)
            self._t = {}
        self._prune()

    def flush(self) -> None:
        self.write(self.snapshot())

    def snapshot(self) -> dict[int, list[float]]:
        """Pruned copy, taken on the event loop so write() can run in a thread."""
        self._prune()
        return dict(self._t)

    def write(self, entries: dict[int, list[float]]) -> None:
        if self._path is None:
            return
        tmp = self._path.with_name(self._path.name + ".tmp")
        with self._io:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"v": 1, "t": {str(k): v for k, v in entries.items()}}, f)
                f.flush()
                os.fsync(f.fileno())  # survive power loss: never replace with an empty file
            os.replace(tmp, self._path)

    def _prune(self) -> None:
        now = self._wall()
        self._t = {k: v for k, v in self._t.items() if now - v[1] <= self._ttl}
        if len(self._t) > self._cap:
            keep = sorted(self._t.items(), key=lambda kv: kv[1][1])[-self._cap:]
            self._t = dict(keep)
