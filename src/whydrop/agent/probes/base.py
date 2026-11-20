"""Probe primitives: one UDP request/reply with late-reply tracking, and a TCP connect check (spec §5.0)."""
import asyncio
import errno
import socket
import struct
import sys
import time
from collections.abc import Callable

from whydrop.agent import traffic

LATE_S = 10.0
SLOW_SYN_MS = 900
_LOCAL = {errno.ENETUNREACH, errno.ENETDOWN, errno.EADDRNOTAVAIL, 10051, 10050, 10049}  # + WSAENETUNREACH/DOWN/ADDRNOTAVAIL
_ICMP = {errno.EHOSTUNREACH, errno.ECONNREFUSED, 10065, 10061}                          # + WSAEHOSTUNREACH/CONNREFUSED
_late_listeners: set[asyncio.Task] = set()


def classify_oserror(e: OSError) -> dict:
    """No route on this host → local_fail (not loss). An ICMP error from the path → a real failure."""
    code = getattr(e, "winerror", None) or e.errno
    if code in _LOCAL:
        return {"local_fail": True, "error": code}
    if code in _ICMP or isinstance(e, ConnectionRefusedError):
        return {"icmp": True, "error": code}
    return {"error": code}


def _ms_since(t0_ns: int) -> float:
    return (time.perf_counter_ns() - t0_ns) / 1e6


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, match, fut: asyncio.Future):
        self.match, self.fut = match, fut
        self.timed_out = False
        self.on_late: Callable[[], None] | None = None
        self.late_seen = False

    def datagram_received(self, data, addr):
        if not self.match(data, addr):
            return
        if self.timed_out:  # the send already counted as lost; a reply now is queueing evidence
            if not self.late_seen:
                self.late_seen = True
                if self.on_late:
                    self.on_late()
        elif not self.fut.done():
            self.fut.set_result((data, time.perf_counter_ns()))

    def error_received(self, exc):
        if not self.timed_out and not self.fut.done():
            self.fut.set_exception(exc)


async def udp_exchange(dest: tuple[str, int], payload: bytes, timeout_s: float, *,
                       match: Callable[[bytes, tuple], bool], late_s: float = LATE_S,
                       on_late: Callable[[], None] | None = None, count_as: str | None = None
                       ) -> tuple[bytes | None, float | None, dict]:
    """Send one datagram and wait for a matching reply. After a timeout the socket keeps listening for
    `late_s` and calls `on_late` once if the reply turns up (queueing evidence, spec §6.2)."""
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    try:
        transport, proto = await loop.create_datagram_endpoint(lambda: _Proto(match, fut), remote_addr=dest,
                                                               family=socket.AF_INET)
    except OSError as e:
        return None, None, classify_oserror(e)
    t0 = time.perf_counter_ns()
    handed_off = False
    try:
        transport.sendto(payload)
        data, t1 = await asyncio.wait_for(asyncio.shield(fut), timeout_s)
        if count_as:
            traffic.udp(count_as, len(payload), len(data))
        return data, (t1 - t0) / 1e6, {}
    except asyncio.TimeoutError:
        proto.timed_out, proto.on_late = True, on_late

        async def linger():
            try:
                await asyncio.sleep(late_s)
            finally:
                transport.close()
        task = asyncio.create_task(linger())
        _late_listeners.add(task)
        task.add_done_callback(_late_listeners.discard)
        handed_off = True
        if count_as:
            traffic.udp(count_as, len(payload), None)
        return None, None, {"timeout": True}
    except OSError as e:
        return None, None, classify_oserror(e)
    finally:
        if not handed_off:  # also on cancellation
            transport.close()


async def _connect(sock: socket.socket, dest: tuple[str, int]) -> None:
    await asyncio.get_running_loop().sock_connect(sock, dest)


def _abort(sock: socket.socket) -> None:
    """Close with an RST (SO_LINGER 0): no FIN handshake, less traffic (spec §5.0)."""
    fmt = "HH" if sys.platform == "win32" else "ii"
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(fmt, 1, 0))
    except OSError:
        pass
    sock.close()


async def tcp_probe(dest: tuple[str, int], timeout_s: float, *, rst_ok: bool,
                    count_as: str | None = None) -> tuple[bool, float | None, dict]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    t0 = time.perf_counter_ns()
    try:
        await asyncio.wait_for(_connect(sock, dest), timeout_s)
        ok, detail = True, {}
        if count_as:
            traffic.tcp_connect(count_as, "open")
    except ConnectionRefusedError:
        ok, detail = rst_ok, {"rst": True}
        if count_as:
            traffic.tcp_connect(count_as, "rst")
    except asyncio.TimeoutError:
        if count_as:
            traffic.tcp_connect(count_as, "timeout")
        return False, None, {"timeout": True, "elapsed_ms": round(_ms_since(t0))}
    except OSError as e:
        return False, None, classify_oserror(e)
    finally:
        rtt = _ms_since(t0)
        _abort(sock)  # every path, including cancellation
    if ok and rtt >= SLOW_SYN_MS:  # a lost SYN shows up as a slow success; count it as a failure
        return False, rtt, {**detail, "slow_syn_ms": round(rtt)}
    return ok, rtt, detail
