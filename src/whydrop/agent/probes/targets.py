"""Which targets are probed right now, and which are excluded and why (spec §5.1, §5.2)."""
import asyncio
import socket

from whydrop.agent.config import Config, Target

LINE_HB_SLOTS = (("stun", "cloudflare"), ("stun", "google"), ("dns", "opendns"))
TCP_ROTATION = ("8.8.8.8", "1.0.0.1", "208.67.222.222")


def pair_id(cls: str, addr: str, port: int, proto: str) -> str:
    return f"{cls}:{addr}:{port}/{proto}"


class Targets:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.excluded: dict[str, str] = {}            # pair id → reason
        self.excluded_providers: dict[str, str] = {}  # provider → reason
        self.resolved: dict[str, str] = {}            # hostname → last good IPv4 (so a DNS outage can't fake a line drop)
        self.router_dns: str | None = cfg.router_dns
        self.isp_dns: tuple[str, ...] = cfg.isp_dns

    def by_kind(self, kind: str) -> list[Target]:
        return [t for t in self.cfg.targets if t.kind == kind]

    def exclude(self, pair: str, reason: str) -> None:
        self.excluded[pair] = reason

    def include(self, pair: str) -> None:
        self.excluded.pop(pair, None)

    def exclude_provider(self, provider: str, reason: str) -> None:
        self.excluded_providers[provider] = reason

    def include_provider(self, provider: str) -> None:
        self.excluded_providers.pop(provider, None)

    def usable(self, t: Target, cls: str) -> bool:
        return t.provider not in self.excluded_providers and pair_id(cls, t.addr, t.port, t.proto) not in self.excluded

    def line_hb_rotation(self) -> list[Target]:
        slots = []
        for kind, provider in LINE_HB_SLOTS:
            t = next((x for x in self.by_kind(kind) if x.provider == provider and (kind == "stun" or x.addr == "208.67.222.222")), None)
            if t and self.usable(t, "line_hb"):
                slots.append(t)
        return slots

    def line_hb_degraded(self) -> bool:
        return len({t.provider for t in self.line_hb_rotation()}) < 2

    def tcp_rotation(self) -> list[Target]:
        t443 = {t.addr: t for t in self.by_kind("tcp443")}
        return [t443[a] for a in TCP_ROTATION if a in t443 and self.usable(t443[a], "tcp")] or \
            [t for t in self.by_kind("tcp443") if self.usable(t, "tcp")]

    def dns_pairs(self, cls: str) -> list[tuple[str, str | None]]:
        """(address, provider) for router / isp / public DNS."""
        if cls == "dns_router":
            return [(self.router_dns, None)] if self.router_dns else []
        if cls == "dns_isp":
            return [(a, None) for a in self.isp_dns[:2]]
        return [(t.addr, t.provider) for t in self.by_kind("dns") if self.usable(t, "dns_public")]

    def addr(self, host: str) -> str:
        return self.resolved.get(host, host)

    async def resolve(self) -> None:
        loop = asyncio.get_running_loop()
        for t in self.cfg.targets:
            try:
                socket.inet_aton(t.addr)
                continue
            except OSError:
                pass
            try:
                infos = await loop.getaddrinfo(t.addr, t.port, family=socket.AF_INET, type=socket.SOCK_DGRAM)
                self.resolved[t.addr] = infos[0][4][0]
            except OSError:
                pass  # keep the last good address
