"""Does this host have an IPv4 address and a default route? (the `host_net` segment, spec §6.2)"""
import asyncio
import re
import socket
import struct
import sys

from whydrop.agent.results import Result

_WIN_DEFAULT = re.compile(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", re.M)


def parse_linux_route(text: str) -> tuple[str | None, str | None]:
    """/proc/net/route → (gateway, interface) of the default route."""
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 4 and cols[1] == "00000000" and int(cols[3], 16) & 0x2:
            return socket.inet_ntoa(struct.pack("<I", int(cols[2], 16))), cols[0]
    return None, None


def parse_windows_route(text: str) -> tuple[str | None, str | None]:
    """`route print -4 0.0.0.0` → (gateway, interface address) of the default route."""
    m = _WIN_DEFAULT.search(text)
    return (m.group(1), m.group(2)) if m else (None, None)


async def default_route() -> tuple[str | None, str | None]:
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/route", encoding="ascii") as f:
                return parse_linux_route(f.read())
        except OSError:
            return None, None
    if sys.platform == "win32":
        try:
            proc = await asyncio.create_subprocess_exec("route", "print", "-4", "0.0.0.0",
                                                        stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(proc.communicate(), 5)
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
    ok = gw is not None and addr is not None
    return Result("host_net", "host_net", None, t_send, ok, None,
                  detail={"route": gw is not None, "addr": addr is not None, "iface": iface})
