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
    from helpers.ports import tcp_then_udp
    loop = asyncio.get_running_loop()
    proto = FakeDns(rcode)

    async def tcp(r, w):
        n = int.from_bytes(await r.readexactly(2), "big")
        a = proto.answer(await r.readexactly(n))
        w.write(len(a).to_bytes(2, "big") + a)
        await w.drain()
        w.close()
    srv, (t, _), port = await tcp_then_udp(
        lambda p: asyncio.start_server(tcp, "127.0.0.1", p, family=socket.AF_INET),
        lambda p: loop.create_datagram_endpoint(lambda: proto, local_addr=("127.0.0.1", p), family=socket.AF_INET))
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


def test_udp_53_refused_but_tcp_53_answers():
    async def main():
        proto = FakeDns()

        async def tcp(r, w):
            n = int.from_bytes(await r.readexactly(2), "big")
            a = proto.answer(await r.readexactly(n))
            w.write(len(a).to_bytes(2, "big") + a)
            await w.drain()
            w.close()
        srv = await asyncio.start_server(tcp, "127.0.0.1", 0, family=socket.AF_INET)
        port = srv.sockets[0].getsockname()[1]  # nothing bound on UDP: the kernel answers port unreachable
        u = await dns_probe.udp("127.0.0.1", "dns_isp", None, NOW, port=port)
        k = await dns_probe.tcp("127.0.0.1", "dns_isp", None, NOW, port=port)
        srv.close()
        return u, k
    u, k = asyncio.run(main())
    assert not u.ok and not u.local_fail and u.detail.get("icmp")  # an ICMP reject, counted as such on every OS
    assert k.ok and k.pair.endswith("/tcp")


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

TWO_DEFAULTS = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t016433C6\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlan0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
"""
WIN_TWO_DEFAULTS = WINDOWS_ROUTE.replace(
    "          0.0.0.0          0.0.0.0      192.0.2.1     192.0.2.50     35",
    "          0.0.0.0          0.0.0.0  198.51.100.1  198.51.100.50     55\n"
    "          0.0.0.0          0.0.0.0      192.0.2.1     192.0.2.50     35")


def test_two_default_routes_pick_the_lowest_metric():
    assert host_net.parse_linux_route(TWO_DEFAULTS) == ("192.0.2.1", "wlan0")  # the one the kernel uses
    assert host_net.parse_windows_route(WIN_TWO_DEFAULTS) == ("192.0.2.1", "192.0.2.50")


def test_ipv6_only_host_is_host_net_down_not_a_crash(monkeypatch):
    v6_only = LINUX_ROUTE.splitlines()[0] + "\n"  # no IPv4 routes at all
    assert host_net.parse_linux_route(v6_only) == (None, None)

    async def no_route():
        return host_net.parse_linux_route(v6_only)

    class NoV4(socket.socket):
        def connect(self, addr):
            raise OSError(101, "Network is unreachable")
    with monkeypatch.context() as m:
        m.setattr(host_net.socket, "socket", NoV4)
        assert host_net.source_address() is None
    monkeypatch.setattr(host_net, "default_route", no_route)
    monkeypatch.setattr(host_net, "source_address", lambda: None)
    r = asyncio.run(host_net.probe(NOW))
    assert not r.ok and r.detail == {"route": False, "addr": False, "iface": None}

def _gateway_as(monkeypatch, platform):
    import types

    from whydrop.agent.probes import gateway
    monkeypatch.setattr(gateway, "sys", types.SimpleNamespace(platform=platform))
    return gateway


def test_gateway_tcp_open_port_syn_ack_is_alive(monkeypatch):
    gateway = _gateway_as(monkeypatch, "linux")

    async def main():
        srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0, family=socket.AF_INET)
        r = await gateway.probe("127.0.0.1", srv.sockets[0].getsockname()[1], NOW)
        srv.close()
        return r
    r = asyncio.run(main())
    assert r.ok and r.detail["method"] == "tcp" and not r.detail.get("rst") and not r.local_fail


def test_gateway_no_route_is_local_fail(monkeypatch):
    import errno

    from whydrop.agent.probes import base
    gateway = _gateway_as(monkeypatch, "linux")

    async def no_route(sock, dest):
        raise OSError(errno.ENETUNREACH, "Network is unreachable")
    monkeypatch.setattr(base, "_connect", no_route)
    r = asyncio.run(gateway.probe("192.0.2.1", None, NOW))
    assert not r.ok and r.local_fail and r.rtt_ms is None


def test_gateway_windows_icmp_no_reply_is_a_failure(monkeypatch):
    from whydrop.agent import winicmp
    gateway = _gateway_as(monkeypatch, "win32")
    monkeypatch.setattr(winicmp, "echo", lambda addr, timeout_ms: None)
    r = asyncio.run(gateway.probe("192.0.2.1", None, NOW))
    assert not r.ok and r.rtt_ms is None and r.detail == {"method": "icmp"}


def _agent(monkeypatch, tmp_path, sent, dead=()):
    from whydrop.agent import run as runmod
    from whydrop.agent.results import Result

    async def probe(slot, now_ms, **k):
        sent.append(slot.provider)
        return Result("line_hb", "p", slot.provider, 0, slot.provider not in dead, None)
    monkeypatch.setattr(runmod.line_hb, "probe", probe)
    a = runmod.Agent(load_config(None, {"WHYDROP_DB_PATH": str(tmp_path / "w.db")}), asyncio.Event())
    for s in a.targets.by_kind("stun"):
        a.targets.resolved[s.addr] = "192.0.2.10"
    a.agg = runmod.Aggregator(None, a.now)
    a.findings = runmod.FindingsTracker(a.targets, a.now)
    return a


def test_line_hb_rotation_is_fair_with_one_provider_dead(monkeypatch, tmp_path):
    from collections import Counter
    sent = []
    a = _agent(monkeypatch, tmp_path, sent, dead=("google",))

    async def main():
        for _ in range(9):
            await a.job_line_hb()
        a.targets.exclude_provider("google", "provider outage")
        for _ in range(4):
            await a.job_line_hb()
    asyncio.run(main())
    assert Counter(sent[:9]) == {"cloudflare": 3, "google": 3, "opendns": 3}  # a dead provider keeps its turn
    assert Counter(sent[9:]) == {"cloudflare": 2, "opendns": 2}


def test_every_provider_excluded_sends_nothing(monkeypatch, tmp_path):
    sent = []
    a = _agent(monkeypatch, tmp_path, sent)
    for p in ("cloudflare", "google", "opendns", "quad9"):
        a.targets.exclude_provider(p, "provider outage")

    async def main():
        for _ in range(3):
            await a.job_line_hb()
            await a.job_tcp()
            await a.job_dns_tcp()
    asyncio.run(main())
    t = a.targets
    assert sent == [] and t.line_hb_rotation() == [] and t.line_hb_degraded()
    assert t.tcp_rotation() == [] and t.dns_pairs("dns_public") == []
    assert len(t.dns_pairs("dns_public", include_excluded=True)) == 5  # the self-check still re-tests them


def test_isp_resolver_unknown_drops_only_the_isp_class(tmp_path):
    from whydrop.agent import run as runmod
    a = runmod.Agent(load_config(None, {"WHYDROP_DB_PATH": str(tmp_path / "w.db")}), asyncio.Event())
    a.targets.router_dns, a.targets.isp_dns = "192.0.2.1", ()
    assert a.targets.dns_pairs("dns_isp") == []
    classes = {c for c, _, _ in a.dns_now()}
    assert classes == {"dns_router", "dns_public"}
    assert not [p for p in a.check_pairs() if p.cls == "dns_isp"]
    a.targets.isp_dns = ("198.51.100.53",)
    assert ("dns_isp", "198.51.100.53", None) in a.dns_now()


def test_stun_cgnat_style_disagreement_then_ip_change():
    async def main():
        (t1, a, p1), (t2, b, p2) = await fake_stun(), await fake_stun()
        w = StunWatcher([("a", "127.0.0.1", p1, "cloudflare"), ("b", "127.0.0.1", p2, "google")], NOW)
        rounds = [await w.probe()]
        a.mapped, b.mapped = ("100.64.0.7", 40000), ("100.64.0.8", 40000)  # two public IPs: multi-IP NAT
        rounds += [await w.probe() for _ in range(5)]
        b.mapped = ("100.64.0.7", 40002)
        rounds += [await w.probe() for _ in range(2)]
        w.close(); t1.close(); t2.close()
        return rounds, w.public_ip
    rounds, ip = asyncio.run(main())
    kinds = [[x.kind for x in r if hasattr(x, "kind")] for r in rounds]
    assert sum(k.count("multi_ip_nat") for k in kinds) == 1 and kinds[3] == ["multi_ip_nat"]
    assert kinds[6] == [] and kinds[7] == ["ip_change"] and ip == "100.64.0.7"
