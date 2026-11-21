"""Hot TCP canary against the real Plan 1 TCP reflector on loopback (plus a small proxy for stalls and resets)."""
import asyncio
import socket
import struct

from whydrop.agent.precision.canary import HotCanary, classify_conn_error
from whydrop.proto.wt import WtType, encode_hello_ok, encode_nonce, encode_short
from whydrop.reflector.tcp import TcpReflector, serve_tcp

S = b"s" * 32


async def reflector(**kw):
    srv = await serve_tcp(TcpReflector(S, epoch=5, **kw), "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


class Proxy:
    """Forwards both ways; can hold reflector→agent bytes for a while, or reset the client connection."""

    def __init__(self, upstream_port):
        self.up = upstream_port
        self.hold_until = 0.0
        self.clients = []

    async def start(self):
        self.srv = await asyncio.start_server(self._client, "127.0.0.1", 0, family=socket.AF_INET)
        return self.srv.sockets[0].getsockname()[1]

    async def _client(self, cr, cw):
        ur, uw = await asyncio.open_connection("127.0.0.1", self.up)
        self.clients.append(cw)

        async def pipe(r, w, hold):
            try:
                while data := await r.read(4096):
                    while hold and asyncio.get_running_loop().time() < self.hold_until:
                        await asyncio.sleep(0.02)
                    w.write(data)
                    await w.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                w.close()
        await asyncio.gather(pipe(cr, uw, False), pipe(ur, cw, True))

    def reset_clients(self):
        """A real RST: close the raw socket with SO_LINGER 0 (asyncio's abort would send a FIN first on Windows)."""
        for w in self.clients:
            ts = w.get_extra_info("socket")
            raw = getattr(ts, "_sock", ts)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH" if hasattr(socket, "SIO_RCVALL") else "ii", 1, 0))
            raw.close()
            w.transport.abort()
        self.clients.clear()


def canary(port, events, **kw):
    return HotCanary(("127.0.0.1", port), S, events.append, session_id=7, **kw)


def kinds(events):
    return [e.kind for e in events]


def test_hb_ack_rtt():
    events = []

    async def main():
        srv, port = await reflector()
        c = canary(port, events)
        stop = asyncio.Event()
        task = asyncio.create_task(c.run(stop))
        await asyncio.sleep(1.5)
        stop.set()
        await task
        srv.close()
        return c
    c = asyncio.run(main())
    assert c.state == "ok" and c.rtt_ms is not None and c.rtt_ms < 100 and "auth_fail" not in kinds(events)


def test_stall_then_recovery():
    events = []

    async def main():
        srv, port = await reflector()
        p = Proxy(port)
        pport = await p.start()
        c = canary(pport, events, hb_s=0.1, stall_s=0.3)
        stop = asyncio.Event()
        task = asyncio.create_task(c.run(stop))
        await asyncio.sleep(0.5)
        p.hold_until = asyncio.get_running_loop().time() + 1.0
        await asyncio.sleep(1.6)
        stop.set()
        await task
        srv.close()
    asyncio.run(main())
    stalls = [e for e in events if e.kind == "stall"]
    assert [s.detail["phase"] for s in stalls] == ["start", "end"]
    assert 0.6 <= stalls[1].detail["duration_s"] <= 1.4 and "reconnect" not in kinds(events)  # connection kept


def test_rst_triggers_reconnect():
    events = []

    async def main():
        srv, port = await reflector()
        p = Proxy(port)
        pport = await p.start()
        c = canary(pport, events, hb_s=0.1, retry_s=0.1)
        stop = asyncio.Event()
        task = asyncio.create_task(c.run(stop))
        await asyncio.sleep(0.5)
        p.reset_clients()
        await asyncio.sleep(1.0)
        stop.set()
        await task
        srv.close()
        return c
    c = asyncio.run(main())
    assert "rst" in kinds(events) and "reconnect" in kinds(events) and c.state == "ok"


def test_reconnect_after_eof_backs_off():
    slept, t = [], [0.0]

    async def fake_sleep(d):
        slept.append(d)
        t[0] += d
        await asyncio.sleep(0)

    async def refuse(*a, **k):
        raise ConnectionRefusedError()

    async def main():
        c = canary(1, [], sleep=fake_sleep, mono=lambda: t[0], open_connection=refuse)
        stop = asyncio.Event()
        task = asyncio.create_task(c.run(stop))
        while t[0] < 300:
            await asyncio.sleep(0)
        stop.set()
        await task
    asyncio.run(main())
    first_minute = [d for d, at in zip(slept, __import__("itertools").accumulate(slept)) if at <= 60]
    later = slept[len(first_minute):]
    assert all(abs(d - 1.5) < 1e-9 for d in first_minute) and len(first_minute) >= 39
    assert later and max(later) <= 30 and later[-1] >= 15  # backed off towards 30 s, with jitter


def test_auth_fail_is_a_finding_not_a_loop():
    events, slept, t = [], [], [0.0]

    async def fake_sleep(d):
        slept.append(d)
        t[0] += d
        await asyncio.sleep(0.001)

    async def main():
        srv, port = await reflector()
        c = HotCanary(("127.0.0.1", port), b"z" * 32, events.append, session_id=7, sleep=fake_sleep, mono=lambda: t[0])
        stop = asyncio.Event()
        task = asyncio.create_task(c.run(stop))
        while len(slept) < 3:
            await asyncio.sleep(0.01)
        stop.set()
        await task
        srv.close()
        return c
    c = asyncio.run(main())
    assert kinds(events).count("auth_fail") == 1 and c.state == "auth_failed" and min(slept) >= 30


def test_bad_hello_ok_mac_rejected():
    events = []

    async def fake_reflector(r, w):
        w.write(encode_nonce(bytes(16)))
        await r.readexactly(30)
        w.write(encode_hello_ok(5, S, b"\x00" * 8))  # signed over the wrong anonce: not our reflector
        await w.drain()
        await asyncio.sleep(1)
        w.close()

    async def main():
        srv = await asyncio.start_server(fake_reflector, "127.0.0.1", 0, family=socket.AF_INET)
        c = canary(srv.sockets[0].getsockname()[1], events, retry_s=5)
        stop = asyncio.Event()
        task = asyncio.create_task(c.run(stop))
        await asyncio.sleep(0.5)
        stop.set()
        await task
        srv.close()
        return c
    c = asyncio.run(main())
    assert "reflector_unauthenticated" in kinds(events) and "tcp_info" not in kinds(events) and c.rtt_ms is None


def test_short_replies_become_findings():
    for t, kind in ((WtType.VERSION, "version_mismatch"), (WtType.BUSY, "busy")):
        events = []

        async def fake(r, w, t=t):
            w.write(encode_nonce(bytes(16)))
            await r.readexactly(30)
            w.write(encode_short(t))
            await w.drain()
            w.close()

        async def main():
            srv = await asyncio.start_server(fake, "127.0.0.1", 0, family=socket.AF_INET)
            c = canary(srv.sockets[0].getsockname()[1], events, retry_s=5)
            stop = asyncio.Event()
            task = asyncio.create_task(c.run(stop))
            await asyncio.sleep(0.4)
            stop.set()
            await task
            srv.close()
        asyncio.run(main())
        assert kind in kinds(events)


def test_windows_abort_is_kernel_timeout():
    assert classify_conn_error(ConnectionAbortedError()) == "kernel_timeout"
    assert classify_conn_error(TimeoutError()) == "kernel_timeout"
    assert classify_conn_error(ConnectionResetError()) == "rst"
    assert classify_conn_error(asyncio.IncompleteReadError(b"", 16)) == "eof"


def test_middlebox_flag_when_tcp_much_faster_than_udp():
    events = []

    async def main():
        srv, port = await reflector()
        c = canary(port, events, hb_s=0.05, udp_rtt=lambda: 100.0)  # loopback TCP < 1 ms vs "100 ms" UDP
        stop = asyncio.Event()
        task = asyncio.create_task(c.run(stop))
        await asyncio.sleep(1.0)
        stop.set()
        await task
        srv.close()
        return c
    c = asyncio.run(main())
    [m] = [e for e in events if e.kind == "middlebox"]
    assert c.middlebox and m.detail["flag"] is True and m.detail["udp_ms"] == 100.0


def test_suspend_gives_no_stall_or_rst_evidence():
    events = []

    async def main():
        srv, port = await reflector()
        p = Proxy(port)
        pport = await p.start()
        c = canary(pport, events, hb_s=0.1, stall_s=0.3, retry_s=0.1)
        stop = asyncio.Event()
        task = asyncio.create_task(c.run(stop))
        await asyncio.sleep(0.4)
        p.hold_until = asyncio.get_running_loop().time() + 1.0   # the host "sleeps": nothing gets through
        await asyncio.sleep(0.1)
        c.notify_suspend()
        await asyncio.sleep(1.5)
        stop.set()
        await task
        srv.close()
        return c
    c = asyncio.run(main())
    kinds = [e.kind for e in events]
    assert "stall" not in kinds and "rst" not in kinds and "reconnect" in kinds and c.state == "ok"
