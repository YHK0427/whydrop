"""In-process change bus: the agent publishes, every /ws client gets its own bounded queue (drop-oldest), so a slow
browser can never hold up the probes (spec §8, plan 5 review focus 3)."""
import asyncio
import time

QUEUE_MAX = 500


class Bus:
    def __init__(self):
        self._subs: set[asyncio.Queue] = set()
        self.dropped = 0

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def publish(self, type_: str, data) -> None:
        msg = {"type": type_, "ts": int(time.time() * 1000), "data": data}
        for q in self._subs:
            if q.full():
                q.get_nowait()          # the oldest goes; the newest state matters more
                self.dropped += 1
            q.put_nowait(msg)
