"""nat-test against the real Plan 1 reflector, through a proxy that forgets idle UDP mappings like a NAT does.
Time runs 20x faster on both sides (reflector clock and agent sleeps)."""
import asyncio
import socket
import time

from whydrop.agent.precision.natprobe import (
    DelayResult, bracket, format_report, keepalive, nat_test, store_report,
)
from whydrop.reflector.replay import Tombstones
from whydrop.reflector.tcp import TcpReflector, serve_tcp
from whydrop.reflector.udp import UdpReflector, serve_udp

S = b"s" * 32
SPEED = 20.0  # the reflector sends due NAT replies every 0.1 s real = 2 s fake


async def fast_sleep(d):
    await asyncio.sleep(d / SPEED)


class ForgetfulNat:
    """UDP relay with one upstream socket per client mapping; a mapping idle longer than `timeout_s` (fake
    seconds) is dropped, so a reply arriving later has nowhere to go."""

    def __init__(self, upstream, timeout_s, drop_all_down=False):
        self.upstream, self.timeout, self.drop_all_down = upstream, timeout_s / SPEED, drop_all_down
        self.maps = {}
        self.req_times = {}

    async def start(self):
        loop = asyncio.get_running_loop()
        nat = self

        class Front(asyncio.DatagramProtocol):
            def connection_made(self, t):
                nat.front = t

            def datagram_received(self, data, addr):
                asyncio.ensure_future(nat._out(data, addr))
        await loop.create_datagram_endpoint(Front, local_addr=("127.0.0.1", 0), family=socket.AF_INET)
        self.port = self.front.get_extra_info("sockname")[1]
        asyncio.ensure_future(self._reaper())
        return self

    async def _out(self, data, addr):
        loop = asyncio.get_running_loop()
        m = self.maps.get(addr)
        if m is None:
            nat = self

            class Back(asyncio.DatagramProtocol):
                def datagram_received(self, d, a):
                    if addr in nat.maps and not nat.drop_all_down:
                        nat.maps[addr][1] = time.perf_counter()
                        nat.front.sendto(d, addr)
            t, _ = await loop.create_datagram_endpoint(Back, remote_addr=self.upstream, family=socket.AF_INET)
            m = self.maps[addr] = [t, time.perf_counter()]
        m[1] = time.perf_counter()
        if len(data) == 44 and data[3] == 3:
            self.req_times.setdefault(addr, []).append(time.perf_counter())
        m[0].sendto(data)

    async def _reaper(self):
        while True:
            await asyncio.sleep(0.01)
            for addr, (t, last) in list(self.maps.items()):
                if time.perf_counter() - last > self.timeout:
                    t.close()
                    del self.maps[addr]


async def udp_reflector():
    t0 = time.perf_counter()
    r = UdpReflector(S, epoch=1, tombstones=Tombstones(None), clock=lambda: (time.perf_counter() - t0) * SPEED)
    return await serve_udp(r, "127.0.0.1", 0)


def test_udp_alive_and_dead_by_proxy_timeout():
    async def main():
        srv = await udp_reflector()
        nat = await ForgetfulNat(("127.0.0.1", srv.port), timeout_s=45).start()
        rep = await nat_test(("127.0.0.1", nat.port), S, udp_delays=(10, 20, 30, 60), tcp_delays=(), sleep=fast_sleep)
        await srv.close()
        return rep, nat
    rep, nat = asyncio.run(main())
    assert [(r.delay_s, r.alive) for r in rep.udp] == [(10, True), (20, True), (30, True), (60, False)]
    assert rep.udp_range == (30, 60) and rep.keepalive_s["udp"] == 20


def test_second_req_sent_3s_later():
    async def main():
        srv = await udp_reflector()
        nat = await ForgetfulNat(("127.0.0.1", srv.port), timeout_s=1000).start()
        await nat_test(("127.0.0.1", nat.port), S, udp_delays=(10,), tcp_delays=(), sleep=fast_sleep)
        await srv.close()
        return nat
    nat = asyncio.run(main())
    [times] = nat.req_times.values()
    assert len(times) == 2 and 2.5 <= (times[1] - times[0]) * SPEED <= 4.0


def test_lost_immediate_reply_is_inconclusive():
    async def main():
        srv = await udp_reflector()
        nat = await ForgetfulNat(("127.0.0.1", srv.port), timeout_s=1000, drop_all_down=True).start()
        rep = await nat_test(("127.0.0.1", nat.port), S, udp_delays=(10,), tcp_delays=(), sleep=fast_sleep)
        await srv.close()
        return rep, nat
    rep, nat = asyncio.run(main())
    assert rep.udp[0].alive is None and len(list(nat.req_times.values())[0]) == 3  # 3 tries, then inconclusive
    assert rep.keepalive_s["udp"] is None


def test_tcp_nat_probe():
    async def main():
        async def instant(d):
            await asyncio.sleep(0.05)
        srv = await serve_tcp(TcpReflector(S, epoch=1, sleep=instant), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        rep = await nat_test(("127.0.0.1", port), S, udp_delays=(), tcp_delays=(60, 300), sleep=fast_sleep)
        srv.close()
        return rep
    rep = asyncio.run(main())
    assert [(r.delay_s, r.alive) for r in rep.tcp] == [(60, True), (300, True)] and rep.tcp_range == (300, None)


def test_keepalive_rounding():
    assert keepalive(30, 45) == 20 and keepalive(600, 1200) == 480 and keepalive(10, 20) == 5


def test_no_advice_for_open_range():
    assert keepalive(600, None) is None and keepalive(None, 10) is None
    assert bracket([DelayResult("udp", 10, True), DelayResult("udp", 20, True)]) == (20, None)
    assert bracket([DelayResult("udp", 10, False)]) == (None, 10)
    assert bracket([DelayResult("udp", 10, True), DelayResult("udp", 20, None), DelayResult("udp", 30, False)]) == (10, 30)


def test_cli_report_and_store(tmp_path):
    from whydrop.agent.precision.natprobe import NatReport
    from whydrop.agent.store import Store
    rep = NatReport([DelayResult("udp", 30, True), DelayResult("udp", 60, False)], [], (30, 60), (None, None),
                    {"udp": 20, "tcp": None})
    text = format_report(rep)
    assert "30 s" in text and "alive" in text and "keepalive 20 s" in text.lower()

    async def main():
        s = Store(tmp_path / "w.db")
        await s.open()
        run_id = await store_report(s, rep, start_ms=1, end_ms=2)
        rows = await s.execute("select proto, delay_s, alive from nat_results where run_id = ?", (run_id,))
        await s.close()
        return rows
    assert asyncio.run(main()) == [("udp", 30, 1), ("udp", 60, 0)]


def test_udp_and_tcp_run_together_and_errors_are_inconclusive(monkeypatch):
    from whydrop.agent.precision import natprobe
    started = []

    async def udp(addr, secret, d, *, sleep):
        started.append(("udp", asyncio.get_running_loop().time()))
        raise OSError("boom")

    async def tcp(addr, secret, d, *, sleep):
        started.append(("tcp", asyncio.get_running_loop().time()))
        await asyncio.sleep(0.2)
        return DelayResult("tcp", d, True)
    monkeypatch.setattr(natprobe, "udp_delay", udp)
    monkeypatch.setattr(natprobe, "tcp_delay", tcp)
    rep = asyncio.run(nat_test(("127.0.0.1", 1), S, udp_delays=(10,), tcp_delays=(60,)))
    assert rep.udp[0].alive is None and rep.udp[0].detail["reason"] == "OSError" and rep.tcp[0].alive
    assert abs(started[0][1] - started[1][1]) < 0.1  # TCP didn't wait for UDP


def test_delay_the_reflector_refuses_is_inconclusive_and_results_come_as_they_finish():
    got = []

    async def main():
        async def instant(d):
            await asyncio.sleep(0.05)
        srv = await serve_tcp(TcpReflector(S, epoch=1, sleep=instant), "127.0.0.1", 0)   # started without --enable-7500
        port = srv.sockets[0].getsockname()[1]
        rep = await nat_test(("127.0.0.1", port), S, udp_delays=(), tcp_delays=(60, 7500), sleep=fast_sleep,
                             on_progress=got.append)
        srv.close()
        return rep
    rep = asyncio.run(main())
    assert [(r.delay_s, r.alive) for r in rep.tcp] == [(60, True), (7500, None)] and rep.tcp[1].detail["reason"] == "version"
    assert [r.delay_s for r in got] == [7500, 60] and rep.tcp_range == (60, None)   # the refusal didn't wait for 60 s
    assert "forgotten" not in format_report(rep)


def test_unreachable_reflector_is_inconclusive_not_forgotten():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                       # nothing listens there, UDP or TCP
    rep = asyncio.run(nat_test(("127.0.0.1", port), S, udp_delays=(10, 20), tcp_delays=(60,), sleep=fast_sleep))
    assert all(r.alive is None for r in rep.udp + rep.tcp), [(r.delay_s, r.alive, r.detail) for r in rep.udp + rep.tcp]
    assert rep.udp_range == rep.tcp_range == (None, None) and rep.keepalive_s == {"udp": None, "tcp": None}
    assert format_report(rep).count("timeout not measured; no keepalive advice") == 2


def test_report_when_nothing_or_everything_survives():
    from whydrop.agent.precision.natprobe import NatReport
    udp = [DelayResult("udp", 10, False), DelayResult("udp", 20, False)]
    tcp = [DelayResult("tcp", 60, True), DelayResult("tcp", 300, True)]
    rep = NatReport(udp, tcp, bracket(udp), bracket(tcp), {"udp": keepalive(*bracket(udp)), "tcp": keepalive(*bracket(tcp))})
    text = format_report(rep)
    assert "timeout less than 10 s; keepalive below 10 s (the shortest delay tried)" in text
    assert "timeout more than 300 s; no keepalive needed below 300 s" in text


def test_full_tcp_delay_set_stays_under_unauthenticated_cap():
    from whydrop.agent.precision.natprobe import TCP_DELAYS

    async def main():
        async def instant(d):
            await asyncio.sleep(0.05)
        refl = TcpReflector(S, epoch=1, sleep=instant)
        srv = await serve_tcp(refl, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        rep = await nat_test(("127.0.0.1", port), S, udp_delays=(), tcp_delays=TCP_DELAYS, sleep=fast_sleep)
        srv.close()
        return rep
    rep = asyncio.run(main())
    assert all(r.alive is True for r in rep.tcp), [(r.delay_s, r.alive, r.detail) for r in rep.tcp]
