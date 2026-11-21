import asyncio
import socket
import struct
import sys

import pytest

from whydrop.agent.config import Target, load_config
from whydrop.agent.probes import dns_probe, host_net, line_hb
from whydrop.agent.probes.stun_probe import StunWatcher
from whydrop.agent.probes.targets import Targets
from whydrop.net.dns import parse_reply

NOW = lambda: 1_000_000  # noqa: E731


class FakeDns(asyncio.DatagramProtocol):
    def __init__(self, rcode=0):
        self.rcode = rcode

    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        self.t.sendto(self.answer(data), addr)

    def answer(self, q):
        qid = struct.unpack_from("!H", q)[0]
        return struct.pack("!HHHHHH", qid, 0x8180 | self.rcode, 1, 0, 0, 0) + q[12:]


async def fake_dns(rcode=0):
    loop = asyncio.get_running_loop()
    proto = FakeDns(rcode)
    t, _ = await loop.create_datagram_endpoint(lambda: proto, local_addr=("127.0.0.1", 0), family=socket.AF_INET)
    port = t.get_extra_info("sockname")[1]

    async def tcp(r, w):
        n = int.from_bytes(await r.readexactly(2), "big")
        a = proto.answer(await r.readexactly(n))
        w.write(len(a).to_bytes(2, "big") + a)
        await w.drain()
        w.close()
    srv = await asyncio.start_server(tcp, "127.0.0.1", port, family=socket.AF_INET)
    return t, srv, port


def test_dns_udp_and_tcp_success():
    async def main():
        t, srv, port = await fake_dns()
        u = await dns_probe.udp("127.0.0.1", "dns_public", "google", NOW, port=port)
        k = await dns_probe.tcp("127.0.0.1", "dns_public", "google", NOW, port=port)
        t.close(); srv.close()
        return u, k
    u, k = asyncio.run(main())
    assert u.ok and u.probe == "dns" and u.pair == "dns_public:127.0.0.1:%d/udp" % u.detail["port"]
    assert k.ok and k.probe == "dns_tcp" and k.rtt_ms is not None


def test_dns_servfail_is_failure():
    async def main():
        t, srv, port = await fake_dns(rcode=2)
        r = await dns_probe.udp("127.0.0.1", "dns_isp", None, NOW, port=port)
        t.close(); srv.close()
        return r
    r = asyncio.run(main())
    assert not r.ok and r.detail["rcode"] == 2


def test_router_cache_check_accepts_nxdomain():
    async def main():
        t, srv, port = await fake_dns(rcode=3)
        r = await dns_probe.router_cache_check("127.0.0.1", NOW, port=port)
        t.close(); srv.close()
        return r
    r = asyncio.run(main())
    assert r.ok and r.probe == "dns_cache" and r.detail["name"].endswith(".example.com")


def stun_reply(req: bytes, ip: str, port: int) -> bytes:
    txid = req[8:20]
    xip = struct.unpack("!I", socket.inet_aton(ip))[0] ^ 0x2112A442
    attr = struct.pack("!HHBBHI", 0x0020, 8, 0, 1, port ^ 0x2112, xip)
    return struct.pack("!HHI12s", 0x0101, len(attr), 0x2112A442, txid) + attr


class FakeStun(asyncio.DatagramProtocol):
    def __init__(self):
        self.mapped = ("203.0.113.5", 40000)

    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        self.t.sendto(stun_reply(data, *self.mapped), addr)


async def fake_stun():
    proto = FakeStun()
    t, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: proto, local_addr=("127.0.0.1", 0),
                                                                      family=socket.AF_INET)
    return t, proto, t.get_extra_info("sockname")[1]


def test_stun_ip_change_needs_two_rounds_both_servers():
    async def main():
        (t1, a, p1), (t2, b, p2) = await fake_stun(), await fake_stun()
        w = StunWatcher([("a", "127.0.0.1", p1, "cloudflare"), ("b", "127.0.0.1", p2, "google")], NOW)
        first = await w.probe()
        a.mapped = ("203.0.113.9", 40000)  # only one server sees a new IP: not a change
        one = await w.probe()
        b.mapped = ("203.0.113.9", 40000)
        two = await w.probe()                # both agree once
        three = await w.probe()              # both agree twice → ip_change
        w.close(); t1.close(); t2.close()
        return first, one, two, three
    first, one, two, three = asyncio.run(main())
    kinds = lambda xs: [x.kind for x in xs if hasattr(x, "kind")]  # noqa: E731
    assert all(r.ok for r in first) and kinds(first) == [] and kinds(two) == []
    assert "ip_change" not in kinds(one)
    [e] = [x for x in three if getattr(x, "kind", None) == "ip_change"]
    assert e.detail["new"] == "203.0.113.9"


def test_stun_port_only_change_is_mapping_reset():
    async def main():
        (t1, a, p1), (t2, b, p2) = await fake_stun(), await fake_stun()
        w = StunWatcher([("a", "127.0.0.1", p1, "cloudflare"), ("b", "127.0.0.1", p2, "google")], NOW)
        await w.probe()
        a.mapped = ("203.0.113.5", 40001)
        out = await w.probe()
        w.close(); t1.close(); t2.close()
        return out
    out = asyncio.run(main())
    assert [x.kind for x in out if hasattr(x, "kind")] == ["mapping_reset"]


def test_line_hb_rotation_skips_excluded_provider():
    t = Targets(load_config(None, {}))
    assert [s.provider for s in t.line_hb_rotation()] == ["cloudflare", "google", "opendns"]
    t.exclude_provider("cloudflare", "provider outage")
    rot = t.line_hb_rotation()
    assert [s.provider for s in rot] == ["google", "opendns"] and not t.line_hb_degraded()
    t.exclude_provider("google", "provider outage")
    assert t.line_hb_degraded()


def test_line_hb_probe_against_fake_dns_slot():
    async def main():
        tr, srv, port = await fake_dns()
        r = await line_hb.probe(Target("127.0.0.1", port, "udp", "dns", "opendns"), NOW)
        tr.close(); srv.close()
        return r
    r = asyncio.run(main())
    assert r.ok and r.probe == "line_hb" and r.provider == "opendns"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only ICMP gateway probe")
def test_gateway_windows_uses_icmp():
    from whydrop.agent.probes import gateway
    r = asyncio.run(gateway.probe("127.0.0.1", None, NOW))
    assert r.ok and r.detail.get("method") == "icmp"


LINUX_ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlan0\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
"""
WINDOWS_ROUTE = """===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.0.2.1     192.0.2.50     35
===========================================================================
"""


def test_host_net_parses_route_fixtures():
    assert host_net.parse_linux_route(LINUX_ROUTE) == ("192.168.0.1", "wlan0")
    assert host_net.parse_linux_route(LINUX_ROUTE.splitlines()[0] + "\n") == (None, None)
    assert host_net.parse_windows_route(WINDOWS_ROUTE) == ("192.0.2.1", "192.0.2.50")
    assert host_net.parse_windows_route("Active Routes:\nNone\n") == (None, None)


def test_probes_refuse_hostnames():
    with pytest.raises(ValueError):
        asyncio.run(line_hb.probe(Target("stun.cloudflare.com", 3478, "udp", "stun", "cloudflare"), NOW))
    with pytest.raises(ValueError):
        StunWatcher([("stun.l.google.com", "stun.l.google.com", 19302, "google")], NOW)
    with pytest.raises(ValueError):
        asyncio.run(line_hb.probe(Target("127.1", 53, "udp", "dns", "opendns"), NOW))


def test_targets_addr_only_after_resolve():
    t = Targets(load_config(None, {}))
    assert t.addr("8.8.8.8") == "8.8.8.8" and t.addr("stun.cloudflare.com") is None
    assert set(t.unresolved()) == {"stun.cloudflare.com", "stun.l.google.com"}
    t.resolved["stun.cloudflare.com"] = "192.0.2.10"
    assert t.addr("stun.cloudflare.com") == "192.0.2.10"


PTP_ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
"""
WIN_ONLINK = WINDOWS_ROUTE.replace("192.0.2.1    ", "On-link      ")


def test_host_net_point_to_point_and_onlink():
    assert host_net.parse_linux_route(PTP_ROUTE) == (None, "ppp0")
    assert host_net.parse_windows_route(WIN_ONLINK) == (None, "192.0.2.50")


def test_stun_pair_ids_use_the_name_and_public_ip_carries_over():
    async def main():
        (t1, a, p1), (t2, b, p2) = await fake_stun(), await fake_stun()
        w = StunWatcher([("stun.example", "127.0.0.1", p1, "cloudflare"), ("stun2.example", "127.0.0.1", p2, "google")],
                        NOW, public_ip="203.0.113.5")
        out = await w.probe()
        w.close(); t1.close(); t2.close()
        return out
    out = asyncio.run(main())
    pairs = sorted(r.pair.split(":")[1] for r in out if hasattr(r, "probe"))
    assert pairs == ["stun.example", "stun2.example"]
    assert not [x for x in out if getattr(x, "kind", None)]  # same public IP as before: no ip_change
