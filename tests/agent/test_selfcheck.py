import asyncio
import socket
import struct

from whydrop.agent.config import load_config
from whydrop.agent.probes.targets import Targets
from whydrop.agent.results import Result
from whydrop.agent.selfcheck import CheckPair, FindingsTracker, nat_mapping, run_selfcheck


async def no_sleep(d):
    pass


def pair(name, provider, ok, cls="dns_public", addr=None, proto="udp"):
    async def run():
        return Result("dns", name, provider, 0, ok, 5.0 if ok else None)
    return CheckPair(name, provider, cls, addr or name.split(":")[1], proto, run)


def gw(ok=True):
    async def run():
        return Result("gateway", "gateway", None, 0, ok, 1.0 if ok else None)
    return run


PUBLIC = [("dns_public:1.0.0.1:53/udp", "cloudflare"), ("dns_public:8.8.8.8:53/udp", "google"),
          ("dns_public:208.67.222.222:53/udp", "opendns"), ("dns_public:9.9.9.9:53/udp", "quad9")]


def test_selfcheck_starting_mid_outage_excludes_nothing():
    pairs = [pair(n, p, ok=False) for n, p in PUBLIC]
    sc = asyncio.run(run_selfcheck(pairs, gw(False), sleep=no_sleep))
    assert sc.status == "inconclusive" and sc.excluded == {}


def test_selfcheck_half_failing_is_inconclusive():
    pairs = [pair(n, p, ok=i < 2) for i, (n, p) in enumerate(PUBLIC)]
    sc = asyncio.run(run_selfcheck(pairs, gw(True), sleep=no_sleep))
    assert sc.status == "inconclusive" and sc.excluded == {}


def test_selfcheck_excludes_single_blocked_pair():
    pairs = [pair(n, p, ok=True) for n, p in PUBLIC]
    pairs.append(pair("dns_public:1.1.1.1:53/tcp", "cloudflare", ok=False, addr="1.1.1.1", proto="tcp"))
    pairs.append(pair("dns_public:1.1.1.1:53/udp", "cloudflare", ok=True, addr="1.1.1.1"))
    sc = asyncio.run(run_selfcheck(pairs, gw(True), sleep=no_sleep))
    assert sc.status == "ok"
    assert sc.excluded == {"dns_public:1.1.1.1:53/tcp": "blocked on this network (tcp only)"}
    assert sc.median_rtt["dns_public"] == 5.0


def test_selfcheck_paces_per_provider():
    slept = []

    async def rec(d):
        slept.append(d)
    pairs = [pair(n, "google", ok=True) for n, _ in PUBLIC]
    asyncio.run(run_selfcheck(pairs, gw(True), tries=1, per_provider_qps=2, sleep=rec))
    assert slept.count(0.5) >= 3  # 4 queries to one provider → at least 3 half-second gaps


def res(pair_name, provider, ok, t):
    return Result("dns", pair_name, provider, t, ok, 5.0 if ok else None)


def test_target_specific_after_5_min():
    now = [0]
    t = Targets(load_config(None, {}))
    f = FindingsTracker(t, now_ms=lambda: now[0])
    for s in range(0, 7 * 60):
        now[0] = s * 1000
        f.feed(res("dns_public:9.9.9.9:53/udp", "quad9", False, now[0]))
        f.feed(res("dns_public:8.8.8.8:53/udp", "google", True, now[0]))
        ev = f.check()
        if ev:
            break
    [e] = ev
    assert e.kind == "finding" and e.detail["kind"] == "target_specific" and 300 <= s <= 302
    assert "dns_public:9.9.9.9:53/udp" in t.excluded
    f.feed(res("dns_public:9.9.9.9:53/udp", "quad9", True, now[0] + 1000))
    [end] = f.check()
    assert end.detail["phase"] == "end" and "dns_public:9.9.9.9:53/udp" not in t.excluded


def test_provider_outage_after_2_min():
    now = [0]
    t = Targets(load_config(None, {}))
    f = FindingsTracker(t, now_ms=lambda: now[0])
    found = None
    for s in range(0, 4 * 60):
        now[0] = s * 1000
        for p, prov, ok in (("dns_public:1.0.0.1:53/udp", "cloudflare", False), ("tcp:1.0.0.1:443/tcp", "cloudflare", False),
                            ("dns_public:8.8.8.8:53/udp", "google", True), ("dns_public:9.9.9.9:53/udp", "quad9", True)):
            f.feed(res(p, prov, ok, now[0]))
        ev = [e for e in f.check() if e.detail["kind"] == "provider_outage"]
        if ev:
            found = (s, ev[0])
            break
    s, e = found
    assert 120 <= s <= 122 and e.detail["provider"] == "cloudflare" and "cloudflare" in t.excluded_providers


def stun_reply(req, ip, port):
    xip = struct.unpack("!I", socket.inet_aton(ip))[0] ^ 0x2112A442
    attr = struct.pack("!HHBBHI", 0x0020, 8, 0, 1, port ^ 0x2112, xip)
    return struct.pack("!HHI12s", 0x0101, len(attr), 0x2112A442, req[8:20]) + attr


class SameMapping(asyncio.DatagramProtocol):
    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        self.t.sendto(stun_reply(data, "203.0.113.7", addr[1]), addr)  # reports the client's own port back


def test_nat_mapping_same_socket():
    async def main():
        loop = asyncio.get_running_loop()
        servers = []
        for _ in range(2):
            t, _ = await loop.create_datagram_endpoint(SameMapping, local_addr=("127.0.0.1", 0), family=socket.AF_INET)
            servers.append(t)
        r = await nat_mapping([("127.0.0.1", t.get_extra_info("sockname")[1]) for t in servers])
        for t in servers:
            t.close()
        return r
    r = asyncio.run(main())
    assert r == {"endpoint_independent": True, "port_preserving": True, "public_ip": "203.0.113.7"}
