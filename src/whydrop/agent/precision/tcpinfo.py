"""Kernel TCP state for the canary socket (Linux `struct tcp_info`, offsets from linux/tcp.h)."""
import socket
import struct
import sys

TCP_INFO = getattr(socket, "TCP_INFO", 11)
_U32 = struct.Struct("=I")


def parse_tcp_info(raw: bytes) -> dict | None:
    if len(raw) < 104:
        return None
    u32 = lambda off: _U32.unpack_from(raw, off)[0]  # noqa: E731
    return {"rto_ms": u32(8) / 1000, "backoff": raw[4], "retransmits": raw[2], "unacked": u32(24),
            "rtt_ms": u32(68) / 1000, "rttvar_ms": u32(72) / 1000, "total_retrans": u32(100)}


def read_tcp_info(sock) -> dict | None:
    if not sys.platform.startswith("linux"):
        return None  # Windows exposes no equivalent through the socket API ("n/a", spec §5.3)
    try:
        return parse_tcp_info(sock.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 232))
    except OSError:
        return None
