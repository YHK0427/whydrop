"""STUN watcher: public IP and port mapping from two servers over persistent sockets (spec §5.2 "STUN")."""
import asyncio
import os
import socket
import time

from whydrop.agent import traffic
from whydrop.agent.events import Event
from whydrop.agent.probes.base import classify_oserror
from whydrop.agent.probes.targets import pair_id, require_ipv4
from whydrop.agent.results import Result
from whydrop.net import stun

TIMEOUT_S = 1.0
CONFIRM_ROUNDS = 2
MULTI_IP_ROUNDS = 3


class _Server(asyncio.DatagramProtocol):
    def __init__(self):
        self.waiting: dict[bytes, asyncio.Future] = {}
        self.transport = None

    def connection_made(self, t):
        self.transport = t

    def datagram_received(self, data, addr):
        if len(data) >= 20:
            fut = self.waiting.pop(data[8:20], None)
            if fut and not fut.done():
                fut.set_result((data, time.perf_counter_ns()))

    def error_received(self, exc):
        for fut in self.waiting.values():
            if not fut.done():
                fut.set_exception(exc)
        self.waiting.clear()


class StunWatcher:
    """One connected UDP socket per server, kept open so its NAT mapping stays the same between probes."""

    def __init__(self, servers: list[tuple[str, str, int, str]], now_ms, *, public_ip: str | None = None):
        """servers: (name for the pair id, resolved IPv4, port, provider). Pair ids use the name, so history
        survives a provider rotating its addresses."""
        self._servers = [(name, require_ipv4(ip), port, prov) for name, ip, port, prov in servers]
        self._now_ms = now_ms
        self._conns: dict[int, _Server] = {}
        self.public_ip: str | None = public_ip
        self._ports: dict[int, int] = {}
        self._candidate: tuple[str | None, int] = (None, 0)
        self._disagree = 0

    async def _ask(self, i: int) -> tuple[tuple[str, int] | None, float | None, dict]:
        _, ip, port, _ = self._servers[i]
        loop = asyncio.get_running_loop()
        conn = self._conns.get(i)
        if conn is None or conn.transport is None or conn.transport.is_closing():
            try:
                _, conn = await loop.create_datagram_endpoint(_Server, remote_addr=(ip, port), family=socket.AF_INET)
            except OSError as e:
                return None, None, classify_oserror(e)
            self._conns[i] = conn
        txid = os.urandom(12)
        fut = loop.create_future()
        conn.waiting[txid] = fut
        t0 = time.perf_counter_ns()
        conn.transport.sendto(stun.build_binding(txid))
        try:
            data, t1 = await asyncio.wait_for(fut, TIMEOUT_S)
        except asyncio.TimeoutError:
            conn.waiting.pop(txid, None)
            traffic.udp("stun", 20, None)
            return None, None, {"timeout": True}
        except OSError as e:
            return None, None, classify_oserror(e)
        traffic.udp("stun", 20, len(data))
        return stun.parse_binding_response(data, txid), (t1 - t0) / 1e6, {}

    async def probe(self) -> list:
        t_send = self._now_ms()
        answers = await asyncio.gather(*(self._ask(i) for i in range(len(self._servers))))
        out: list = []
        for i, (mapped, rtt, detail) in enumerate(answers):
            name, _, port, provider = self._servers[i]
            out.append(Result("stun", pair_id("stun", name, port, "udp"), provider, t_send, mapped is not None,
                              rtt, local_fail=bool(detail.get("local_fail")), detail=detail))
        mapped = [a[0] for a in answers]
        out.extend(self._judge(mapped, t_send))
        return out

    def _judge(self, mapped: list[tuple[str, int] | None], t_ms: int) -> list[Event]:
        events: list[Event] = []
        got = [m for m in mapped if m]
        if len(got) < 2:
            return events
        ips = {m[0] for m in got}
        if len(ips) > 1:
            self._disagree += 1
            if self._disagree == MULTI_IP_ROUNDS:
                events.append(Event("multi_ip_nat", t_ms, detail={"ips": sorted(ips)}))
            return events
        self._disagree = 0
        ip = ips.pop()
        if self.public_ip is None:
            self.public_ip = ip  # first sighting: remember IP and ports below
        if ip != self.public_ip:
            cand, n = self._candidate
            n = n + 1 if cand == ip else 1
            self._candidate = (ip, n)
            if n >= CONFIRM_ROUNDS:  # both servers, two rounds in a row
                events.append(Event("ip_change", t_ms, detail={"old": self.public_ip, "new": ip}))
                self.public_ip, self._candidate, self._ports = ip, (None, 0), {}
            return events
        else:
            self._candidate = (None, 0)
            for i, m in enumerate(mapped):
                if m is None:
                    continue
                old = self._ports.get(i)
                if old is not None and old != m[1]:
                    events.append(Event("mapping_reset", t_ms, pair_id("stun", self._servers[i][0], self._servers[i][2], "udp"),
                                        {"old_port": old, "new_port": m[1]}))
                self._ports[i] = m[1]
        return events

    def close(self) -> None:
        for c in self._conns.values():
            if c.transport:
                c.transport.close()
        self._conns.clear()
