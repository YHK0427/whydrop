"""Token-bucket rate limits for the reflector (spec §5.5)."""
import time
from collections import OrderedDict
from collections.abc import Hashable


class TokenBucket:
    def __init__(self, rate: float, burst: float, clock=time.monotonic):
        self._rate = rate
        self._burst = burst
        self._clock = clock
        self._tokens = burst
        self._last = clock()

    def take(self, n: float = 1.0) -> bool:
        now = self._clock()
        self._tokens = min(self._burst, self._tokens + (now - self._last) * self._rate)
        self._last = now
        if self._tokens < n:
            return False
        self._tokens -= n
        return True


class PerKeyBuckets:
    """One bucket per key (source IP), least-recently-used keys evicted past max_keys."""

    def __init__(self, rate: float, burst: float, *, max_keys: int = 65536, clock=time.monotonic):
        self._rate = rate
        self._burst = burst
        self._max = max_keys
        self._clock = clock
        self.buckets: OrderedDict[Hashable, TokenBucket] = OrderedDict()

    def take(self, key: Hashable) -> bool:
        b = self.buckets.get(key)
        if b is None:
            b = self.buckets[key] = TokenBucket(self._rate, self._burst, self._clock)
            if len(self.buckets) > self._max:
                self.buckets.popitem(last=False)
        else:
            self.buckets.move_to_end(key)
        return b.take()
