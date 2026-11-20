"""TCP reflector over real loopback sockets; role delays use an injected sleep."""
import asyncio

from whydrop.proto.wt import (
    Frame, FrameType, Hello, Role, WtType,
    decode_frame, decode_hello_ok, decode_nonce, decode_short, encode_frame, encode_hello,
)
from whydrop.reflector.tcp import TcpReflector, serve_tcp

S = b"s" * 32
AN = b"\x07" * 8
EPOCH = 0xBEEF


async def _server(**kw):
    r = TcpReflector(S, epoch=EPOCH, **kw)
    srv = await serve_tcp(r, "127.0.0.1", 0)
    return r, srv, srv.sockets[0].getsockname()[1]


async def _hello(port, role=Role.HOT, sid=1, param=0, secret=S):
    rd, wr = await asyncio.open_connection("127.0.0.1", port)
    n = decode_nonce(await rd.readexactly(20))
    wr.write(encode_hello(Hello(role, sid, param, AN), secret, n))
    await wr.drain()
    return rd, wr


async def _closed(rd, timeout=2.0) -> bool:
    try:
        return await asyncio.wait_for(rd.read(), timeout) == b""
    except (ConnectionError, asyncio.IncompleteReadError):
        return True


def run(coro):
    return asyncio.run(coro)


def test_hello_ok_and_hb_ack():
    async def main():
        r, srv, port = await _server()
        rd, wr = await _hello(port)
        assert decode_hello_ok(await rd.readexactly(16), S, AN) == EPOCH
        wr.write(encode_frame(Frame(FrameType.HB, 0, 5, 123)))
        f = decode_frame(await rd.readexactly(16))
        assert (f.type, f.seq, f.t_send_ns) == (FrameType.HB_ACK, 5, 123)
        wr.close(); srv.close()
    run(main())


def test_wrong_secret_auth_fail():
    async def main():
        r, srv, port = await _server()
        rd, _ = await _hello(port, secret=b"z" * 32)
        assert decode_short(await rd.readexactly(4)) == WtType.AUTH_FAIL
        assert await _closed(rd) and r.drops["bad_hmac"] == 1
        srv.close()
    run(main())


def test_bad_param_version():
    async def main():
        r, srv, port = await _server()
        rd, _ = await _hello(port, role=Role.NAT, param=7500)
        assert decode_short(await rd.readexactly(4)) == WtType.VERSION
        assert r.drops["bad_param"] == 1
        srv.close()
    run(main())


def test_hello_fragmented_bytes():
    async def main():
        r, srv, port = await _server()
        rd, wr = await asyncio.open_connection("127.0.0.1", port)
        n = decode_nonce(await rd.readexactly(20))
        for b in encode_hello(Hello(Role.HOT, 1, 0, AN), S, n):
            wr.write(bytes([b]))
            await wr.drain()
            await asyncio.sleep(0.001)
        assert decode_hello_ok(await rd.readexactly(16), S, AN) == EPOCH
        wr.close(); srv.close()
    run(main())


def test_silent_client_closed():
    async def main():
        r, srv, port = await _server(hello_timeout_s=0.2)
        rd, _ = await asyncio.open_connection("127.0.0.1", port)
        await rd.readexactly(20)
        assert await _closed(rd) and r.drops["hello_timeout"] == 1
        srv.close()
    run(main())


def test_unauth_cap_per_ip():
    async def main():
        r, srv, port = await _server()
        held = []
        for _ in range(4):
            rd, wr = await asyncio.open_connection("127.0.0.1", port)
            await rd.readexactly(20)  # got a NONCE, now holding an unauthenticated slot
            held.append(wr)
        rd5, _ = await asyncio.open_connection("127.0.0.1", port)
        assert await rd5.read(20) == b"" and r.drops["unauth_cap"] == 1
        for wr in held:
            wr.close()
        srv.close()
    run(main())


def test_hot_replaced_by_newer_hello():
    async def main():
        r, srv, port = await _server()
        rd1, _ = await _hello(port)
        await rd1.readexactly(16)
        rd2, wr2 = await _hello(port)
        assert decode_hello_ok(await rd2.readexactly(16), S, AN) == EPOCH
        assert await _closed(rd1)
        wr2.write(encode_frame(Frame(FrameType.HB, 0, 1, 1)))  # the new connection still works
        assert decode_frame(await rd2.readexactly(16)).type == FrameType.HB_ACK
        wr2.close(); srv.close()
    run(main())


def test_hot_closed_when_silent():
    async def main():
        r, srv, port = await _server(hot_idle_close_s=0.2)
        rd, _ = await _hello(port)
        await rd.readexactly(16)
        assert await _closed(rd)
        srv.close()
    run(main())


def test_nat_probe_after_delay():
    slept = []

    async def fake_sleep(d):
        slept.append(d)

    async def main():
        r, srv, port = await _server(sleep=fake_sleep)
        rd, _ = await _hello(port, role=Role.NAT, param=60)
        await rd.readexactly(16)
        assert decode_frame(await rd.readexactly(16)).type == FrameType.NAT_PROBE
        assert await _closed(rd)
        srv.close()
    run(main())
    assert slept == [60]


def test_idle_pings():
    async def fake_sleep(d, _n=[0]):
        _n[0] += 1
        if _n[0] > 2:
            await asyncio.sleep(10)

    async def main():
        r, srv, port = await _server(sleep=fake_sleep)
        rd, wr = await _hello(port, role=Role.IDLE, param=30)
        await rd.readexactly(16)
        seqs = [decode_frame(await rd.readexactly(16)) for _ in range(2)]
        assert [(f.type, f.seq) for f in seqs] == [(FrameType.IDLE_PING, 1), (FrameType.IDLE_PING, 2)]
        wr.close(); srv.close()
    run(main())


def test_nat_cap_busy():
    async def forever(d):
        await asyncio.Event().wait()

    async def main():
        r, srv, port = await _server(sleep=forever)
        held = []
        for _ in range(7):
            rd, wr = await _hello(port, role=Role.NAT, param=60)
            await rd.readexactly(16)
            held.append(wr)
        rd8, _ = await _hello(port, role=Role.NAT, param=60)
        assert decode_short(await rd8.readexactly(4)) == WtType.BUSY and r.drops["busy"] == 1
        for wr in held:
            wr.close()
        srv.close()
    run(main())


def test_busy_at_total_cap_leaves_no_state(monkeypatch):
    import whydrop.reflector.tcp as tcp

    async def forever(d):
        await asyncio.Event().wait()

    async def main():
        monkeypatch.setattr(tcp, "AUTH_TOTAL", 1)
        r, srv, port = await _server(sleep=forever)
        rd1, wr1 = await _hello(port, role=Role.NAT, sid=1, param=60)
        await rd1.readexactly(16)
        for sid in range(2, 6):
            rd, _ = await _hello(port, role=Role.NAT, sid=sid, param=60)
            assert decode_short(await rd.readexactly(4)) == WtType.BUSY
        assert set(r._nat) == {1}
        wr1.close(); srv.close()
    run(main())


def test_hot_junk_frames_do_not_hold_slot():
    async def main():
        r, srv, port = await _server(hot_idle_close_s=0.3)
        rd, wr = await _hello(port)
        await rd.readexactly(16)
        try:
            for _ in range(6):  # IDLE_PONG frames on a hot connection are not heartbeats
                wr.write(encode_frame(Frame(FrameType.IDLE_PONG, 0, 1, 1)))
                await wr.drain()
                await asyncio.sleep(0.1)
        except ConnectionError:
            pass  # the reflector already closed us, which is the point
        assert await _closed(rd)
        srv.close()
    run(main())


def test_nat_slot_freed_when_agent_leaves():
    async def forever(d):
        await asyncio.Event().wait()

    async def main():
        r, srv, port = await _server(sleep=forever)
        rd, wr = await _hello(port, role=Role.NAT, param=60)
        await rd.readexactly(16)
        assert sum(len(s) for s in r._nat.values()) == 1
        wr.close()
        for _ in range(100):
            if not r._nat:
                break
            await asyncio.sleep(0.02)
        assert r._nat == {}
        srv.close()
    run(main())
