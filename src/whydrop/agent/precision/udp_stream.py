"""udp_stream (spec §5.3): WD PROBEs at 10 pps to the reflector; ECHOs give loss per second and its direction.

StreamBook is the pure state machine (testable with synthetic time); UdpStream is the socket around it."""
import asyncio
import logging
import os
import socket
import statistics
import time
from collections import deque
from dataclasses import dataclass

from whydrop.agent import traffic
from whydrop.agent.clock import TimeBase
from whydrop.agent.events import Event
from whydrop.agent.probes.base import classify_oserror
from whydrop.agent.store import SampleRow
from whydrop.measure.direction import Echo, packet_direction
from whydrop.proto import wd
from whydrop.proto.wd import WdError, WdPacket, WdType

log = logging.getLogger(__name__)

RECEIVE_MS = 2_000     # an ECHO within 2 s of its send counts as a round trip
FINAL_MS = 3_500       # bucket t is written at t + 3.5 s (1 s bucket + 2 s window + 0.5 s margin)
LATE_MS = 11_000       # late ECHOs still update the written row until t + 11 s
RING_S = 120
PROBE = "udp_stream"
PAIR = "reflector"


@dataclass
class _Send:
    t_ms: int
    epoch: int | None
    echo_after_ms: int | None = None
    rtt_ms: float | None = None
    local_fail: bool = False
    final: bool = False
    dir: str | None = None
    late_counted: bool = False


def _bucket(t_ms: int) -> int:
    return t_ms // 1000 * 1000


class StreamBook:
    def __init__(self, pps: int = 10):
        self.pending: dict[int, _Send] = {}
        self.echoes: deque[Echo] = deque(maxlen=64)
        self.ring: deque[tuple[int, int, bool, str]] = deque(maxlen=RING_S * pps)
        self.rtts: deque[float] = deque(maxlen=100)
        self.epoch: int | None = None
        self._late_out: list[tuple[int, str]] = []

    def sent(self, seq: int, t_ms: int, local_fail: bool = False) -> None:
        self.pending[seq] = _Send(t_ms, self.epoch, local_fail=local_fail)

    def echo(self, e: Echo, rtt_ms: float, now_ms: int) -> None:
        s = self.pending.get(e.seq)
        if s is None:
            return
        if self.epoch is not None and e.epoch != self.epoch and self.echoes and e.seq < self.echoes[-1].seq:
            return  # a delayed ECHO from before a reflector restart: ignore it
        self.epoch = e.epoch
        self.echoes.append(e)
        if s.final:
            if s.dir in ("up", "down", "unknown") and s.echo_after_ms is None and not s.late_counted \
                    and now_ms - _bucket(s.t_ms) <= LATE_MS:
                s.late_counted = True
                self._late_out.append((_bucket(s.t_ms), s.dir or "unknown"))
            return
        if s.echo_after_ms is None:
            s.echo_after_ms, s.rtt_ms = round(rtt_ms), rtt_ms  # monotonic: immune to clock steps
            if s.echo_after_ms <= RECEIVE_MS:
                self.rtts.append(rtt_ms)

    def finalize(self, now_ms: int, force: bool = False) -> tuple[list[SampleRow], list[tuple[int, str]]]:
        ready: dict[int, list[tuple[int, _Send]]] = {}
        for seq, s in self.pending.items():
            if s.final:
                continue
            if force and s.echo_after_ms is None and not s.local_fail and now_ms - s.t_ms < RECEIVE_MS:
                continue  # still inside its receive window at shutdown: unknown, so not counted at all
            if force or _bucket(s.t_ms) + FINAL_MS <= now_ms:
                ready.setdefault(_bucket(s.t_ms), []).append((seq, s))
        echoes = sorted(self.echoes, key=lambda e: e.seq)
        rows = []
        for b in sorted(ready):
            ok = lost = late = local = up = down = unknown = 0
            rtts = []
            for seq, s in sorted(ready[b]):
                s.final = True
                if s.local_fail:
                    local += 1
                    s.dir = "local"
                elif s.echo_after_ms is not None and s.echo_after_ms <= RECEIVE_MS:
                    ok += 1
                    rtts.append(s.rtt_ms)
                    s.dir = "ok"
                elif s.echo_after_ms is not None:
                    late += 1
                    s.dir = "late"
                else:
                    lost += 1
                    d = packet_direction(seq, (e for e in echoes if e.seq > seq), epoch=s.epoch) if s.epoch is not None \
                        else "unknown"
                    s.dir = d
                    up += d == "up"
                    down += d == "down"
                    unknown += d == "unknown"
                self.ring.append((s.t_ms, seq, s.dir in ("ok", "late"), s.dir))
            rtts.sort()
            rows.append(SampleRow(b, PROBE, PAIR, sent=len(ready[b]), ok=ok, lost=lost, lost_up=up, lost_down=down,
                                  lost_dir_unknown=unknown, late=late, local_fail=local,
                                  rtt_min=rtts[0] if rtts else None, rtt_max=rtts[-1] if rtts else None,
                                  rtt_avg=round(sum(rtts) / len(rtts), 3) if rtts else None,
                                  rtt_p95=rtts[max(0, int(len(rtts) * 0.95) - 1)] if rtts else None))
        for seq in [q for q, s in self.pending.items() if s.final and _bucket(s.t_ms) + LATE_MS < now_ms]:
            del self.pending[seq]  # bounded: about 11 s of sends
        late_out, self._late_out = self._late_out, []
        return rows, late_out

    def ring_window(self, from_ms: int, to_ms: int) -> list[tuple[int, int, bool, str]]:
        return [x for x in self.ring if from_ms <= x[0] <= to_ms]


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, stream: "UdpStream"):
        self.stream = stream

    def datagram_received(self, data, addr):
        self.stream._on_datagram(data, addr)

    def error_received(self, exc):
        self.stream._on_error(exc)


class UdpStream:
    def __init__(self, reflector: tuple[str, int], secret: bytes, store, timebase: TimeBase | None = None, *,
                 pps: int = 10, on_event=None):
        self.host, self.port = reflector
        self.secret, self.store, self.pps = secret, store, pps
        self.tb = timebase or TimeBase()
        self.on_event = on_event or (lambda e: None)
        self.book = StreamBook(pps)
        self.session_id = int.from_bytes(os.urandom(4), "big")
        self._seq = 0
        self._ip: str | None = None
        self._transport = None
        self._tasks: list[asyncio.Task] = []
        self._last_epoch: int | None = None
        self._reconnect: asyncio.Task | None = None
        self._warned = -1e9

    @property
    def ring(self):
        return self.book.ring

    def rtt_median_ms(self) -> float | None:
        return statistics.median(self.book.rtts) if self.book.rtts else None

    async def _connect(self) -> bool:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(self.host, self.port, family=socket.AF_INET, type=socket.SOCK_DGRAM)
            self._ip = infos[0][4][0]
            self._transport, _ = await loop.create_datagram_endpoint(lambda: _Proto(self), remote_addr=(self._ip, self.port),
                                                                     family=socket.AF_INET)
            return True
        except OSError as e:
            if time.monotonic() - self._warned > 60:  # at most one warning a minute
                self._warned = time.monotonic()
                log.warning("udp_stream: cannot reach the reflector (%s)", classify_oserror(e).get("error"))
            await asyncio.sleep(1)
            return False

    async def start(self) -> None:
        await self._connect()
        self._tasks = [asyncio.create_task(self._send_loop()), asyncio.create_task(self._finalize_loop())]

    async def _send_loop(self) -> None:
        start, k = time.monotonic(), 0
        while True:
            k += 1
            behind = time.monotonic() - (start + k / self.pps)
            if behind > 1 / self.pps:  # after a stall or a wake-up: skip the missed slots, never burst
                k = int((time.monotonic() - start) * self.pps) + 1
            await asyncio.sleep(max(0.0, start + k / self.pps - time.monotonic()))
            self._seq = (self._seq + 1) & 0xFFFFFFFF
            now = self.tb.now_ms()
            if self._transport is None or self._transport.is_closing():
                self.book.sent(self._seq, now, local_fail=True)
                if self._reconnect is None or self._reconnect.done():  # resolving can block: never on the send path
                    self._reconnect = asyncio.create_task(self._connect())
                continue
            self.book.sent(self._seq, now)
            self._transport.sendto(wd.encode(WdPacket(WdType.PROBE, self.session_id, self._seq, time.perf_counter_ns()),
                                             self.secret))
            traffic.BYTES[PROBE] += traffic.IP_UDP + wd.WD_LEN

    def _on_datagram(self, data: bytes, addr) -> None:
        if addr[0] != self._ip:
            return
        try:
            p = wd.decode(data, self.secret)
        except WdError:
            return
        if p.type != WdType.ECHO or p.session_id != self.session_id:
            return
        traffic.BYTES[PROBE] += traffic.IP_UDP + wd.WD_LEN
        if self._last_epoch is not None and p.epoch != self._last_epoch:
            self.on_event(Event("reflector_restart", self.tb.now_ms(), "reflector", {"epoch": p.epoch}))
        self._last_epoch = p.epoch
        self.book.echo(Echo(p.seq, p.recv_count, p.epoch, p.rx_bitmap), (time.perf_counter_ns() - p.t_send_ns) / 1e6,
                       self.tb.now_ms())

    def _on_error(self, exc: Exception) -> None:
        if isinstance(exc, OSError) and classify_oserror(exc).get("local_fail") and self._seq in self.book.pending:
            self.book.pending[self._seq].local_fail = True

    async def _write(self, force: bool = False) -> None:
        rows, late = self.book.finalize(self.tb.now_ms(), force=force)
        if rows:
            await self.store.add_samples(rows)
        for ts, d in late:
            await self.store.late_dir(ts, PROBE, PAIR, d)

    async def _finalize_loop(self) -> None:
        while True:
            await asyncio.sleep(0.25)
            try:
                await self._write()
            except Exception:
                log.exception("udp_stream: writing samples failed")  # keep pruning and retrying

    async def stop(self, flush: bool = False) -> None:
        tasks = [t for t in [*self._tasks, self._reconnect] if t]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if flush:
            await asyncio.sleep(0.3)  # let in-flight ECHOs land
            await self._write(force=True)
        if self._transport:
            self._transport.close()
