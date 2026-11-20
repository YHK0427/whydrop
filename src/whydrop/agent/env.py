"""Environment detection (spec §5.1): where probes leave from, ISP DNS, VM refusal, interception checks."""
import asyncio
import ipaddress
import platform
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from whydrop.agent.probes import host_net

VM_MESSAGE = ("This measures a VM's network, not yours. Run it on a Linux host, or natively on Windows with "
              "`pipx install whydrop` (not inside WSL2).")
_NOT_ISP = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                              "127.0.0.0/8")]
_NOT_ISP_HOSTS = {"100.100.100.100", "127.0.0.11"}
_DOCKER_DESKTOP = ipaddress.ip_network("192.168.65.0/24")
_VPN_PREFIXES = ("tun", "wg", "tailscale", "utun", "zt", "nordlynx")
_RESOLV_PATHS = (Path("/run/systemd/resolve/resolv.conf"), Path("/etc/resolv.conf"))


@dataclass
class EnvInfo:
    iface: str | None
    gateway: str | None
    link: Literal["wifi", "wired", "unknown"]
    isp_dns: tuple[str, ...]
    egress_vpn: bool
    ipv6_default: bool
    egress_iface: str | None = None


def isp_dns_from(text: str, gateway: str | None) -> tuple[str, ...]:
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                ip = ipaddress.IPv4Address(parts[1])
            except ValueError:
                continue  # IPv6 resolvers are out of scope
            if str(ip) == gateway or str(ip) in _NOT_ISP_HOSTS or any(ip in n for n in _NOT_ISP):
                continue
            out.append(str(ip))
    return tuple(dict.fromkeys(out))


def vm_refusal(kernel_release: str, gateway: str | None) -> str | None:
    rel = kernel_release.lower()
    in_dd = False
    if gateway:
        try:
            in_dd = ipaddress.IPv4Address(gateway) in _DOCKER_DESKTOP
        except ValueError:
            pass
    return VM_MESSAGE if ("linuxkit" in rel or "microsoft-standard" in rel or in_dd) else None


def is_vpn_iface(name: str | None) -> bool:
    return bool(name) and name.lower().startswith(_VPN_PREFIXES)


def parse_ip_route_get(text: str) -> str | None:
    m = re.search(r"\bdev\s+(\S+)", text)
    return m.group(1) if m else None


def has_ipv6_default(text: str) -> bool:
    for line in text.splitlines():
        c = line.split()
        if len(c) >= 10 and c[0] == "0" * 32 and c[1] == "00" and c[9] != "lo" and c[4] != "0" * 32:
            return True
    return False


def chaos_verdict(strings: list[str]) -> Literal["ok", "suspect", "unknown"]:
    """Cloudflare answers CHAOS id.server with its site's airport code (e.g. ICN); anything else means a
    middlebox answered for it."""
    if not strings:
        return "unknown"
    return "ok" if any(re.fullmatch(r"[A-Z]{3}", s.strip()) for s in strings) else "suspect"


async def _egress_iface() -> str | None:
    if not sys.platform.startswith("linux"):
        return None
    try:
        proc = await asyncio.create_subprocess_exec("ip", "-o", "-4", "route", "get", "8.8.8.8",
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), 3)
        return parse_ip_route_get(out.decode("ascii", "replace"))
    except (OSError, asyncio.TimeoutError):
        return None


def _read_resolvers() -> str:
    for p in _RESOLV_PATHS:
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return ""


async def detect_env(cfg) -> EnvInfo:
    gw, iface = await host_net.default_route()
    gw = cfg.gateway or gw
    egress = await _egress_iface()
    vpn = is_vpn_iface(egress)
    if sys.platform == "win32":
        # route print gives the interface *address*; probes leaving from another address means a tunnel
        src = host_net.source_address()
        vpn = vpn or (iface is not None and src is not None and src != iface)
    if cfg.wifi_interface:
        link = "wifi"
    elif sys.platform.startswith("linux") and iface:
        link = "wifi" if Path(f"/sys/class/net/{iface}/wireless").exists() else "wired"
    elif sys.platform == "win32":
        from whydrop.agent.probes.wifi import WindowsWifi
        link = "wifi" if (await WindowsWifi().snapshot()).up else "unknown"
    else:
        link = "unknown"
    isp = cfg.isp_dns or isp_dns_from(_read_resolvers(), gw)
    try:
        v6 = has_ipv6_default(Path("/proc/net/ipv6_route").read_text())
    except OSError:
        v6 = False
    return EnvInfo(cfg.wifi_interface or iface, gw, link, isp, vpn, v6, egress)


def kernel_release() -> str:
    return platform.release() if sys.platform.startswith("linux") else ""
