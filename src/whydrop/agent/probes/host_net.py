"""Does this host have an IPv4 address and a default route? (the `host_net` segment, spec §6.2)"""
import asyncio
import re
import socket
import struct
import sys

from whydrop.agent.proc import run_cmd
from whydrop.agent.results import Result

_WIN_DEFAULT = re.compile(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)", re.M)


def parse_linux_route(text: str) -> tuple[str | None, str | None]:
    """/proc/net/route → (gateway or None for point-to-point, interface) of the default route the kernel uses:
    the lowest metric when there are several."""
    best = None
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 8 and cols[1] == "00000000" and cols[7] == "00000000" and int(cols[3], 16) & 0x1:
            if best is None or int(cols[6]) < int(best[6]):
                best = cols
    if best is None:
        return None, None
    gw = int(best[2], 16)
    return (socket.inet_ntoa(struct.pack("<I", gw)) if gw else None), best[0]


def parse_windows_route(text: str) -> tuple[str | None, str | None]:
    """`route print -4 0.0.0.0` → (gateway or None when "On-link", interface address) of the default route."""
    routes = list(_WIN_DEFAULT.finditer(text))
    if not routes:
        return None, None
    m = min(routes, key=lambda r: int(r.group(3)))  # several default routes: Windows uses the lowest metric
    gw = m.group(1) if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", m.group(1)) else None
    return gw, m.group(2)


async def default_route() -> tuple[str | None, str | None]:
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/route", encoding="ascii") as f:
                return parse_linux_route(f.read())
        except OSError:
            return None, None
    if sys.platform == "win32":
        try:
            out = await run_cmd("route", "print", "-4", "0.0.0.0", timeout_s=5)
            return parse_windows_route(out.decode("utf-8", "replace"))
        except (OSError, asyncio.TimeoutError):
            return None, None
    return None, None


def source_address() -> str | None:
    """The IPv4 source the kernel would use toward the internet (connect on UDP sends nothing)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        addr = s.getsockname()[0]
        return None if addr == "0.0.0.0" else addr
    except OSError:
        return None
    finally:
        s.close()


async def probe(now_ms) -> Result:
    t_send = now_ms()
    gw, iface = await default_route()
    addr = source_address()
    ok = iface is not None and addr is not None  # a default route exists (with or without a gateway)
    return Result("host_net", "host_net", None, t_send, ok, None,
                  detail={"route": iface is not None, "addr": addr is not None, "iface": iface})
