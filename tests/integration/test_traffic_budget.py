"""Basic mode must stay ≤ 8 kbps both directions summed (spec §10). Each probe runs once against loopback servers
sized like real answers (DNS with 6 A records = the spec's worst case); the measured bytes are scaled by the
configured rates."""
import asyncio
import socket
import struct

from whydrop.agent import traffic
from whydrop.agent.config import Target, load_config
from whydrop.agent.probes import dns_probe, line_hb, tcp_connect
from whydrop.agent.probes.stun_probe import StunWatcher

NOW = lambda: 0  # noqa: E731
REAL_STUN_REPLY = 64  # bytes: header + XOR-MAPPED + MAPPED + a short SOFTWARE attribute


class DnsServer(asyncio.DatagramProtocol):
    def connection_made(self, t):
        self.t = t

    def datagram_received(self, q, addr):
        self.t.sendto(answer(q), addr)


def answer(q: bytes) -> bytes:
    qid = struct.unpack_from("!H", q)[0]
    rr = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([192, 0, 2, i]) for i in range(6))
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 6, 0, 0) + q[12:] + rr


class StunServer(asyncio.DatagramProtocol):
    def connection_made(self, t):
        self.t = t

    def datagram_received(self, req, addr):
        xip = struct.unpack("!I", socket.inet_aton("203.0.113.5"))[0] ^ 0x2112A442
        attrs = struct.pack("!HHBBHI", 0x0020, 8, 0, 1, 40000 ^ 0x2112, xip)
        attrs += struct.pack("!HHBBH4s", 0x0001, 8, 0, 1, 40000, socket.inet_aton("203.0.113.5"))
        attrs += struct.pack("!HH", 0x8022, REAL_STUN_REPLY - 20 - len(attrs) - 4) + b"x" * (REAL_STUN_REPLY - 20 - len(attrs) - 4)
        self.t.sendto(struct.pack("!HHI12s", 0x0101, len(attrs), 0x2112A442, req[8:20]) + attrs, addr)


def measure() -> dict[str, int]:
    async def main():
        loop = asyncio.get_running_loop()
        dt, _ = await loop.create_datagram_endpoint(DnsServer, local_addr=("127.0.0.1", 0), family=socket.AF_INET)
        dport = dt.get_extra_info("sockname")[1]

        async def tcp(r, w):
            n = int.from_bytes(await r.readexactly(2), "big")
            a = answer(await r.readexactly(n))
            w.write(len(a).to_bytes(2, "big") + a)
            await w.drain()
        dsrv = await asyncio.start_server(tcp, "127.0.0.1", dport, family=socket.AF_INET)
        st, _ = await loop.create_datagram_endpoint(StunServer, local_addr=("127.0.0.1", 0), family=socket.AF_INET)
        sport = st.get_extra_info("sockname")[1]
        osrv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0, family=socket.AF_INET)
        oport = osrv.sockets[0].getsockname()[1]

        per_run = {}

        async def one(name, coro):
            before = traffic.BYTES[name]
            await coro
            per_run[name] = traffic.BYTES[name] - before

        await one("dns", dns_probe.udp("127.0.0.1", "dns_public", "google", NOW, port=dport))
        await one("dns_tcp", dns_probe.tcp("127.0.0.1", "dns_public", "google", NOW, port=dport))
        await one("line_hb", line_hb.probe(Target("127.0.0.1", sport, "udp", "stun", "cloudflare"), NOW))
        await one("tcp_connect", tcp_connect.probe(Target("127.0.0.1", oport, "tcp", "tcp443", "google"), NOW))
        w = StunWatcher([("127.0.0.1", sport, "cloudflare"), ("127.0.0.1", sport, "google")], NOW)
        await one("stun", w.probe())
        w.close()
        for x in (dt, st):
            x.close()
        dsrv.close()
        osrv.close()
        return per_run
    return asyncio.run(main())


def test_traffic_budget_basic():
    per_run = measure()
    iv = load_config(None, {}).intervals
    gateway = traffic.TCP_SYN + traffic.TCP_RST  # closed-port probe (Linux); the Windows ICMP echo is smaller
    dns_pairs = 8  # router + 2 ISP + 5 public, the most the spec allows
    bps = 8 * (gateway / iv["gateway"]
               + per_run["line_hb"] / iv["line_hb"]
               + dns_pairs * per_run["dns"] / iv["dns"]
               + per_run["dns_tcp"] / iv["dns_tcp"]
               + per_run["stun"] / iv["stun"]
               + per_run["tcp_connect"] / iv["tcp_connect"])
    kbps = bps / 1000
    assert per_run["dns"] == 28 + 29 + 28 + 29 + 6 * 16  # query and a 6-answer reply, IP+UDP headers included
    assert 4.0 < kbps <= 8.0, f"basic mode {kbps:.2f} kbps"
