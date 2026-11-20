from whydrop.reflector.limits import PerKeyBuckets, TokenBucket


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def test_burst_then_refill():
    c = Clock()
    b = TokenBucket(200, 200, clock=c)
    assert all(b.take() for _ in range(200))
    assert not b.take()
    c.t += 0.5
    assert all(b.take() for _ in range(100))
    assert not b.take()


def test_refill_capped_at_burst():
    c = Clock()
    b = TokenBucket(10, 5, clock=c)
    c.t += 100
    assert sum(b.take() for _ in range(20)) == 5


def test_keys_independent():
    c = Clock()
    b = PerKeyBuckets(1, 1, clock=c)
    assert b.take("192.0.2.1") and not b.take("192.0.2.1")
    assert b.take("192.0.2.2")


def test_lru_eviction_bounds_memory():
    b = PerKeyBuckets(1, 1, max_keys=3, clock=Clock())
    for i in range(10):
        b.take(i)
    assert len(b.buckets) == 3 and list(b.buckets) == [7, 8, 9]
