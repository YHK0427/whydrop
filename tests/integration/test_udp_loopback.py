"""Real sockets on 127.0.0.1: reflector ← loss proxy ← client."""
import asyncio
import socket

from helpers.lossproxy import LossProxy
from whydrop.measure.direction import Echo, outage_totals, packet_direction
from whydrop.proto.wd import WdPacket, WdType, decode, encode
from whydrop.reflector.replay import Tombstones
from whydrop.reflector.udp import UdpReflector, serve_udp

S = b"s" * 32


class Client(asyncio.DatagramProtocol):
    def __init__(self):
        self.echoes: dict[int, Echo] = {}
        self.raw: list[bytes] = []

    def datagram_received(self, data, addr):
        self.raw.append(data)
        p = decode(data, S)
        self.echoes[p.seq] = Echo(p.seq, p.recv_count, p.epoch, p.rx_bitmap)

    def error_received(self, exc):
        pass


async def _client(port: int) -> tuple[asyncio.DatagramTransport, Client]:
    loop = asyncio.get_running_loop()
    return await loop.create_datagram_endpoint(Client, remote_addr=("127.0.0.1", port), family=socket.AF_INET)


def probe(sid: int, seq: int) -> bytes:
    return encode(WdPacket(WdType.PROBE, sid, seq, seq * 1000), S)


async def _settle(cond, timeout=3.0):
    for _ in range(int(timeout / 0.02)):
        if cond():
            return
        await asyncio.sleep(0.02)


def test_loopback_direction_matches_injected_loss():
    up, down = {10, 11, 12, 30}, {15, 16, 35}  # 40 packets fit inside the reflector's 50-packet post-HMAC burst

    async def main():
        srv = await serve_udp(UdpReflector(S, epoch=1, tombstones=Tombstones(None)), "127.0.0.1", 0)
        proxy = await LossProxy(("127.0.0.1", srv.port), up, down).start()
        tr, c = await _client(proxy.port)
        for s in range(1, 41):
            tr.sendto(probe(1, s))
            await asyncio.sleep(0.001)
        await _settle(lambda: 40 in c.echoes and len(c.echoes) == 40 - len(up) - len(down))
        tr.close(); proxy.close(); await srv.close()
        return c.echoes

    echoes = asyncio.run(main())
    lost = {s for s in range(1, 41) if s not in echoes}
    ordered = [echoes[k] for k in sorted(echoes)]
    dirs = {s: packet_direction(s, [e for e in ordered if e.seq > s]) for s in lost}
    assert {s for s, d in dirs.items() if d == "up"} == up
    assert {s for s, d in dirs.items() if d == "down"} == down
    t = outage_totals(echoes[9], echoes[13], echoes_received_in_range=1)
    assert (t.up, t.down, t.status) == (3, None, "down_unmeasurable")
    t = outage_totals(echoes[14], echoes[17], echoes_received_in_range=1)
    assert (t.up, t.down, t.status) == (0, 2, "ok")


def test_restart_new_epoch_and_replay_rejected(tmp_path):
    path = tmp_path / "tombstones.json"

    async def run1():
        t = Tombstones(path)
        srv = await serve_udp(UdpReflector(S, epoch=1, tombstones=t), "127.0.0.1", 0)
        tr, c = await _client(srv.port)
        sent = [probe(9, s) for s in range(1, 6)]
        for pkt in sent:
            tr.sendto(pkt)
        await _settle(lambda: len(c.echoes) == 5)
        t.flush()
        tr.close(); await srv.close()
        return sent, c.echoes

    async def run2(captured):
        t = Tombstones(path)
        t.load()
        srv = await serve_udp(UdpReflector(S, epoch=2, tombstones=t), "127.0.0.1", 0)
        tr, c = await _client(srv.port)
        for pkt in captured:
            tr.sendto(pkt)
        await asyncio.sleep(0.3)
        replayed = dict(c.echoes)
        tr.sendto(probe(9, 6))
        await _settle(lambda: 6 in c.echoes)
        tr.close(); await srv.close()
        return replayed, c.echoes

    captured, first = asyncio.run(run1())
    assert len(first) == 5 and all(e.epoch == 1 for e in first.values())
    replayed, after = asyncio.run(run2(captured))
    assert replayed == {}
    assert after[6].epoch == 2
