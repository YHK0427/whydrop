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
        w = StunWatcher([("a", "127.0.0.1", sport, "cloudflare"), ("b", "127.0.0.1", sport, "google")], NOW)
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



def measure_precision() -> dict[str, float]:
    """Bytes per second of udp_stream and the hot canary, measured against the real reflector on loopback."""
    from whydrop.agent.precision.canary import HotCanary
    from whydrop.agent.precision.udp_stream import UdpStream
    from whydrop.reflector.replay import Tombstones
    from whydrop.reflector.tcp import TcpReflector, serve_tcp
    from whydrop.reflector.udp import UdpReflector, serve_udp
    S = b"s" * 32

    class Sink:
        async def add_samples(self, rows):
            pass

        async def late_dir(self, *a):
            pass

    async def main():
        u = await serve_udp(UdpReflector(S, epoch=1, tombstones=Tombstones(None)), "127.0.0.1", 0)
        t = await serve_tcp(TcpReflector(S, epoch=1), "127.0.0.1", u.port)
        before = traffic.BYTES["udp_stream"]
        st = UdpStream(("127.0.0.1", u.port), S, Sink(), pps=10)
        await st.start()
        await asyncio.sleep(2.0)
        await st.stop()
        stream_per_pkt = (traffic.BYTES["udp_stream"] - before) / st._seq
        before = traffic.BYTES["canary"]
        c = HotCanary(("127.0.0.1", u.port), S, lambda e: None, session_id=1, hb_s=0.1)
        stop = asyncio.Event()
        task = asyncio.create_task(c.run(stop))
        await asyncio.sleep(1.05)
        stop.set()
        await task
        hb_round = (traffic.BYTES["canary"] - before) / max(1, len(c._rtts))  # an unanswered last HB only overcounts
        await u.close()
        t.close()
        return {"stream_per_pkt": stream_per_pkt, "hb_round": hb_round}
    return asyncio.run(main())


import pytest  # noqa: E402


@pytest.mark.parametrize("gateway_open", [False, True])
def test_traffic_budget_precision(gateway_open):
    per_run = measure()
    p = measure_precision()
    iv = load_config(None, {}).intervals
    gateway = (2 * traffic.TCP_SYN + traffic.TCP_SEG + traffic.TCP_RST) if gateway_open else traffic.TCP_SYN + traffic.TCP_RST
    hb_rate = 2 if gateway_open else 1  # run.py halves line_hb only when the gateway answers on an open port
    pure_acks = 2 * traffic.TCP_SEG  # worst case: neither side piggybacks its ACK on the next frame
    bps = 8 * (gateway / iv["gateway"]
               + per_run["line_hb"] / (hb_rate * iv["line_hb"])
               + 3 * per_run["dns"] / iv["dns"]                      # router + 2 ISP at the basic interval
               + 5 * per_run["dns"] / max(iv["dns"], 10)             # 5 public pairs at 10 s
               + per_run["dns_tcp"] / iv["dns_tcp"]
               + per_run["stun"] / iv["stun"]
               + per_run["tcp_connect"] / iv["tcp_connect"]
               + 10 * p["stream_per_pkt"]                            # udp_stream at 10 pps, PROBE + ECHO
               + p["hb_round"] + pure_acks)                          # hot canary: 1 HB + 1 HB_ACK per second
    kbps = bps / 1000
    assert p["stream_per_pkt"] == 2 * (28 + 44)
    assert 15.0 < kbps <= 20.0, f"precision mode {kbps:.2f} kbps"
