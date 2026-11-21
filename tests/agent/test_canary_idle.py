"""Idle TCP canary against the real Plan 1 reflector (its role sleep is injected so 30 s becomes 0.1 s)."""
import asyncio
import socket

from whydrop.agent.precision.canary import IdleCanary
from whydrop.reflector.tcp import TcpReflector, serve_tcp

S = b"s" * 32


async def reflector():
    async def short(d):
        await asyncio.sleep(0.1)
    srv = await serve_tcp(TcpReflector(S, epoch=5, sleep=short), "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


class BlackholeAfterHandshake:
    """Forwards the handshake (first 20 + 16 bytes back), then silently drops everything: a NAT that forgot."""

    async def start(self, up):
        self.up = up
        self.srv = await asyncio.start_server(self._client, "127.0.0.1", 0, family=socket.AF_INET)
        return self.srv.sockets[0].getsockname()[1]

    async def _client(self, cr, cw):
        ur, uw = await asyncio.open_connection("127.0.0.1", self.up)

        async def up_pipe():
            while data := await cr.read(4096):
                uw.write(data)

        async def down_pipe():
            passed = 0
            while data := await ur.read(4096):
                if passed < 36:
                    cw.write(data[:36 - passed])
                    passed += len(data[:36 - passed])
        await asyncio.gather(up_pipe(), down_pipe(), return_exceptions=True)


def run_canary(port, seconds, events, **kw):
    async def main():
        c = IdleCanary(("127.0.0.1", port), S, events.append, session_id=9, interval_s=30, expect_s=0.1,
                       grace_s=0.3, **kw)
        stop = asyncio.Event()
        task = asyncio.create_task(c.run(stop))
        await asyncio.sleep(seconds)
        if kw.get("_suspend_at"):
            pass
        stop.set()
        await task
        return c
    return main()


def test_pings_answered():
    events = []

    async def main():
        srv, port = await reflector()
        c = await run_canary(port, 1.0, events)
        srv.close()
        return c
    c = asyncio.run(main())
    assert c.pings >= 3 and "idle_state_lost" not in [e.kind for e in events]


def test_missing_ping_is_state_lost():
    events = []

    async def main():
        srv, port = await reflector()
        bh = BlackholeAfterHandshake()
        pport = await bh.start(port)
        await run_canary(pport, 1.0, events)
        srv.close()
    asyncio.run(main())
    lost = [e for e in events if e.kind == "idle_state_lost"]
    assert lost and lost[0].detail["interval_s"] == 30


def test_idle_lost_suppressed_during_suspend():
    events = []

    async def main():
        srv, port = await reflector()
        bh = BlackholeAfterHandshake()
        pport = await bh.start(port)
        c = IdleCanary(("127.0.0.1", pport), S, events.append, session_id=9, interval_s=30, expect_s=0.1, grace_s=0.3)
        stop = asyncio.Event()
        task = asyncio.create_task(c.run(stop))
        for _ in range(10):
            await asyncio.sleep(0.1)
            c.notify_suspend()  # the host itself was asleep during the wait
        stop.set()
        await task
        srv.close()
    asyncio.run(main())
    assert "idle_state_lost" not in [e.kind for e in events]
