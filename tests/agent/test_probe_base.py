import asyncio
import errno
import socket
import sys

import pytest

from whydrop.agent.probes import base
from whydrop.agent.probes.base import classify_oserror, tcp_probe, udp_exchange


class Server(asyncio.DatagramProtocol):
    def __init__(self, delay=0.0, junk_first=False):
        self.delay, self.junk_first = delay, junk_first

    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        async def reply():
            await asyncio.sleep(self.delay)
            if self.junk_first:
                self.t.sendto(b"junk", addr)
            self.t.sendto(b"re:" + data, addr)
        asyncio.ensure_future(reply())


async def _server(**kw):
    t, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: Server(**kw), local_addr=("127.0.0.1", 0),
                                                                      family=socket.AF_INET)
    return t, t.get_extra_info("sockname")[1]


def match(data, addr):
    return data.startswith(b"re:")


def test_udp_exchange_ok():
    async def main():
        t, port = await _server()
        reply, rtt, detail = await udp_exchange(("127.0.0.1", port), b"hi", 1.0, match=match)
        t.close()
        return reply, rtt
    reply, rtt = asyncio.run(main())
    assert reply == b"re:hi" and 0 <= rtt < 500


def test_timeout_then_late_reply_marks_late():
    late = []

    async def main():
        t, port = await _server(delay=0.4)
        reply, rtt, detail = await udp_exchange(("127.0.0.1", port), b"x", 0.2, match=match, late_s=2.0,
                                                on_late=lambda: late.append(1))
        await asyncio.sleep(0.6)
        t.close()
        return reply, detail
    reply, detail = asyncio.run(main())
    assert reply is None and detail.get("timeout") and late == [1]


def test_mismatch_ignored():
    async def main():
        t, port = await _server(junk_first=True)
        reply, _, _ = await udp_exchange(("127.0.0.1", port), b"y", 1.0, match=match)
        t.close()
        return reply
    assert asyncio.run(main()) == b"re:y"


@pytest.mark.parametrize("code,key", [(errno.ENETUNREACH, "local_fail"), (errno.ENETDOWN, "local_fail"),
                                      (errno.EADDRNOTAVAIL, "local_fail"), (errno.EHOSTUNREACH, "icmp"),
                                      (errno.ECONNREFUSED, "icmp")])
def test_local_vs_icmp_errors(code, key):
    d = classify_oserror(OSError(code, "x"))
    assert d.get(key) is True and len([k for k in ("local_fail", "icmp") if d.get(k)]) == 1


def test_windows_winsock_codes_classified():
    assert classify_oserror(OSError(None, "x", None, 10051)).get("local_fail")  # WSAENETUNREACH
    assert classify_oserror(OSError(None, "x", None, 10065)).get("icmp")        # WSAEHOSTUNREACH


@pytest.mark.skipif(sys.platform == "win32", reason="Windows retries SYN after RST (~2 s); gateway uses ICMP there")
def test_tcp_rst_alive():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens: the kernel answers with RST
    ok, rtt, detail = asyncio.run(tcp_probe(("127.0.0.1", port), 1.5, rst_ok=True))
    assert ok and detail.get("rst") and rtt < 900


def test_tcp_open_port_alive():
    async def main():
        srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0, family=socket.AF_INET)
        port = srv.sockets[0].getsockname()[1]
        res = await tcp_probe(("127.0.0.1", port), 1.5, rst_ok=True)
        srv.close()
        return res
    ok, rtt, detail = asyncio.run(main())
    assert ok and not detail.get("rst")


def test_slow_syn_recorded_as_failure(monkeypatch):
    async def slow_connect(sock, dest):
        await asyncio.sleep(0.95)
    monkeypatch.setattr(base, "_connect", slow_connect)
    ok, rtt, detail = asyncio.run(tcp_probe(("192.0.2.1", 443), 1.5, rst_ok=False))
    assert not ok and detail["slow_syn_ms"] >= 900
