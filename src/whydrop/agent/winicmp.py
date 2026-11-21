"""Unprivileged ICMP echo on Windows via iphlpapi IcmpSendEcho (used for the gateway probe, spec §5.0)."""
import ctypes
import socket
import struct
import sys
import threading
import time

_lock = threading.Lock()
_api = None
_handle = None


def _init():
    global _api, _handle
    from ctypes import wintypes as wt
    api = ctypes.WinDLL("iphlpapi")
    api.IcmpCreateFile.restype = wt.HANDLE
    api.IcmpSendEcho.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.WORD, ctypes.c_void_p, ctypes.c_void_p,
                                 wt.DWORD, wt.DWORD]
    api.IcmpSendEcho.restype = wt.DWORD
    handle = api.IcmpCreateFile()
    if handle in (None, 0, ctypes.c_void_p(-1).value):
        raise OSError("IcmpCreateFile failed")
    _api, _handle = api, handle


def echo(addr: str, timeout_ms: int) -> float | None:
    """Blocking: returns the round-trip time in ms, or None on timeout/unreachable. Call via asyncio.to_thread."""
    if sys.platform != "win32":
        raise OSError("IcmpSendEcho is Windows-only")
    with _lock:
        if _api is None:
            _init()
        dst = struct.unpack("<I", socket.inet_aton(addr))[0]
        payload = b"whydrop"
        reply = ctypes.create_string_buffer(64 + len(payload) + 8)
        t0 = time.perf_counter_ns()
        n = _api.IcmpSendEcho(_handle, dst, payload, len(payload), None, reply, len(reply), timeout_ms)
        elapsed = (time.perf_counter_ns() - t0) / 1e6
    if not n:
        return None
    status = struct.unpack_from("<4xI", reply.raw)[0]
    return elapsed if status == 0 else None
