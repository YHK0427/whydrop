"""udp_stream: send-time buckets, direction, late replies (StreamBook with synthetic time) and a real loopback run."""
import asyncio
import socket

from helpers.lossproxy import LossProxy
from whydrop.agent.precision.udp_stream import StreamBook, UdpStream
from whydrop.measure.direction import Echo
from whydrop.reflector.replay import Tombstones
from whydrop.reflector.udp import UdpReflector, serve_udp

S = b"s" * 32


def feed(book, seqs, t0=10_000, pps=10, epoch=1, drop_up=(), drop_down=(), now_offset=50):
    """Simulate the reflector: rc counts PROBEs that arrived; rx_bitmap marks seq-1-i received."""
    arrived, rc = set(), 0
    for seq in seqs:
        t = t0 + (seq - 1) * (1000 // pps)
        book.sent(seq, t)
        if seq in drop_up:
            continue
        arrived.add(seq)
        rc += 1
        bitmap = sum(1 << i for i in range(32) if (seq - 1 - i) in arrived)
        if seq not in drop_down:
            book.echo(Echo(seq, rc, epoch, bitmap), rtt_ms=20.0, now_ms=t + now_offset)


def test_buckets_and_direction():
    book = StreamBook()
    feed(book, range(1, 41), drop_up={15, 16, 17}, drop_down={30})
    rows, late = book.finalize(now_ms=10_000 + 4000 + 3500)
    total = {k: sum(getattr(r, k) for r in rows) for k in ("sent", "ok", "lost", "lost_up", "lost_down", "lost_dir_unknown")}
    assert total == {"sent": 40, "ok": 36, "lost": 4, "lost_up": 3, "lost_down": 1, "lost_dir_unknown": 0}
    assert {r.ts_ms for r in rows} == {10_000, 11_000, 12_000, 13_000} and late == []
    assert rows[0].probe == "udp_stream" and rows[0].pair == "reflector" and rows[0].rtt_avg == 20.0


def test_bucket_not_final_before_3_5_s():
    book = StreamBook()
    feed(book, range(1, 11))
    assert book.finalize(now_ms=10_000 + 3499)[0] == []   # t = bucket start; 1 s bucket + 2 s window + 0.5 s
    assert len(book.finalize(now_ms=10_000 + 3500)[0]) == 1


def test_late_echo_before_and_after_finalize():
    book = StreamBook()
    book.sent(1, 10_000)
    book.sent(2, 10_100)
    book.echo(Echo(1, 1, 1, 0), rtt_ms=2500.0, now_ms=12_500)      # 2.5 s: late, still before finalize
    [row], _ = book.finalize(now_ms=14_500)
    assert (row.ok, row.late, row.lost) == (0, 1, 1)
    book.echo(Echo(2, 2, 1, 0b1), rtt_ms=6000.0, now_ms=16_100)    # 6 s: after finalize, before t + 11 s
    _, late = book.finalize(now_ms=16_200)
    assert late == [(10_000, "unknown")]
    book.echo(Echo(2, 2, 1, 0b1), rtt_ms=0, now_ms=22_000)         # past t + 11 s: ignored
    assert book.finalize(now_ms=22_100)[1] == []


def test_epoch_change_marks_unknown():
    book = StreamBook()
    book.sent(1, 10_000)
    book.echo(Echo(1, 1, 1, 0), 20.0, 10_020)
    book.sent(2, 10_100)                                           # lost; the reflector restarts
    book.sent(3, 10_200)
    book.echo(Echo(3, 1, 2, 0), 20.0, 10_220)                      # new epoch: empty bitmap must not read as "up"
    [row], _ = book.finalize(now_ms=14_600)
    assert (row.lost, row.lost_up, row.lost_dir_unknown) == (1, 0, 1)


def test_memory_bounded_during_long_outage():
    book = StreamBook()
    for seq in range(1, 6001):                                     # 10 min at 10 pps, nothing comes back
        book.sent(seq, seq * 100)
        if seq % 10 == 0:
            book.finalize(now_ms=seq * 100)
    assert len(book.pending) <= 120 and len(book.ring) <= 1200 and len(book.echoes) <= 64


def test_ring_window():
    book = StreamBook()
    feed(book, range(1, 21), drop_up={5})
    book.finalize(now_ms=20_000)
    w = book.ring_window(10_000, 10_999)
    assert [x[1] for x in w] == list(range(1, 11)) and w[4][2] is False and w[4][3] == "up"


def test_loopback_stream_matches_injected_loss(tmp_path):
    rows = []

    class Store:
        async def add_samples(self, r):
            rows.extend(r)

        async def late_dir(self, *a):
            pass

    async def main():
        srv = await serve_udp(UdpReflector(S, epoch=7, tombstones=Tombstones(None)), "127.0.0.1", 0)
        proxy = await LossProxy(("127.0.0.1", srv.port), drop_up={5, 6}, drop_down={12}).start()
        st = UdpStream(("127.0.0.1", proxy.port), S, Store(), pps=10)
        await st.start()
        await asyncio.sleep(3.2)  # > 2 s after the injected losses, so shutdown doesn't leave them unjudged
        await st.stop(flush=True)
        proxy.close()
        await srv.close()
        return st
    st = asyncio.run(main())
    total = {k: sum(getattr(r, k) for r in rows) for k in ("lost_up", "lost_down")}
    assert total["lost_up"] >= 2 and total["lost_down"] >= 1 and sum(r.sent for r in rows) >= 18  # a slow runner may add loss
    assert st.rtt_median_ms() is not None


def test_force_finalize_skips_sends_still_in_their_window():
    book = StreamBook()
    book.sent(1, 10_000)
    book.sent(2, 11_900)                                           # sent 100 ms before shutdown, no ECHO yet
    rows, _ = book.finalize(now_ms=12_000, force=True)
    assert sum(r.sent for r in rows) == 1 and sum(r.lost for r in rows) == 1


def test_local_fail_then_echo_is_not_late():
    book = StreamBook()
    book.sent(1, 10_000, local_fail=True)
    book.finalize(now_ms=14_000)
    book.echo(Echo(1, 1, 1, 0), 3000.0, 14_500)
    assert book.finalize(now_ms=14_600)[1] == []


def test_stale_echo_from_old_epoch_ignored():
    book = StreamBook()
    for seq in (1, 2, 3):
        book.sent(seq, 10_000 + seq * 100)
    book.echo(Echo(3, 1, 2, 0), 20.0, 10_400)                      # new boot answers seq 3
    book.echo(Echo(1, 1, 1, 0), 20.0, 10_500)                      # a delayed ECHO from the old boot
    assert book.epoch == 2


def test_echo_at_exactly_2000_ms_is_ok():
    book = StreamBook()
    book.sent(1, 10_000)
    book.echo(Echo(1, 1, 1, 0), 2000.0, 12_000)
    [row], _ = book.finalize(now_ms=14_000)
    assert (row.ok, row.late) == (1, 0)
