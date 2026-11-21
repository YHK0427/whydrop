import socket
import struct
import sys

import pytest

from whydrop.agent.precision.tcpinfo import parse_tcp_info, read_tcp_info


def buf(rto_us=200_000, backoff=2, retransmits=3, unacked=4, rtt_us=25_000, rttvar_us=5_000, total=9):
    b = bytearray(104)
    b[2], b[4] = retransmits, backoff
    struct.pack_into("=I", b, 8, rto_us)
    struct.pack_into("=I", b, 24, unacked)
    struct.pack_into("=I", b, 68, rtt_us)
    struct.pack_into("=I", b, 72, rttvar_us)
    struct.pack_into("=I", b, 100, total)
    return bytes(b)


def test_parse_known_bytes():
    assert parse_tcp_info(buf()) == {"rto_ms": 200.0, "backoff": 2, "retransmits": 3, "unacked": 4,
                                     "rtt_ms": 25.0, "rttvar_ms": 5.0, "total_retrans": 9}


def test_short_buffer_is_none():
    assert parse_tcp_info(b"\x00" * 50) is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="TCP_INFO is Linux-only")
def test_live_socket_linux_only():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    c = socket.create_connection(srv.getsockname())
    info = read_tcp_info(c)
    c.close()
    srv.close()
    assert info is not None and info["rto_ms"] >= 200


def test_non_linux_returns_none(monkeypatch):
    import whydrop.agent.precision.tcpinfo as ti
    monkeypatch.setattr(ti.sys, "platform", "win32")
    assert read_tcp_info(object()) is None
