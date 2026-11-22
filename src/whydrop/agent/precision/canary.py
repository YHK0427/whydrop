"""TCP canaries to the reflector (spec §5.3): the hot one heartbeats every second and shows what TCP does during
a drop (stall, retransmissions, RST); the idle one shows whether a NAT forgets a silent connection."""
import asyncio
import logging
import os
import random
import socket
import time
from collections import deque

from whydrop.agent import traffic
from whydrop.agent.clock import TimeBase
from whydrop.agent.events import Event
from whydrop.agent.precision.tcpinfo import read_tcp_info
from whydrop.proto.wt import (
    FRAME_LEN, Frame, FrameType, Hello, Role, WtError, WtType,
    decode_frame, decode_hello_ok, decode_nonce, encode_frame, encode_hello,
)

log = logging.getLogger(__name__)

CONNECT_TIMEOUT_S = 1.5
HELLO_TIMEOUT_S = 5.0
FAST_RETRY_FOR_S = 60
MAX_BACKOFF_S = 30
REFUSED = {WtType.AUTH_FAIL: "auth_fail", WtType.VERSION: "version_mismatch", WtType.BUSY: "busy"}


def classify_conn_error(e: BaseException) -> str:
    """Windows reports its own retransmission give-up as an abort or timeout: that is the kernel, not an RST."""
    if isinstance(e, asyncio.IncompleteReadError):
        return "eof"
    if isinstance(e, ConnectionResetError):
        return "rst"
    if isinstance(e, (ConnectionAbortedError, TimeoutError)):
        return "kernel_timeout"
    return "error"


def _tune(writer) -> None:
    sock = writer.get_extra_info("socket")
    if sock is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 0)


class _Canary:
    role: Role = Role.HOT

    def __init__(self, reflector: tuple[str, int], secret: bytes, on_event, *, session_id: int,
                 timebase: TimeBase | None = None, retry_s: float = 1.5, sleep=asyncio.sleep, mono=time.monotonic,
                 open_connection=None, param_s: int = 0):
        self.host, self.port = reflector
        self.secret, self.on_event, self.session_id = secret, on_event, session_id
        self.tb = timebase or TimeBase()
        self.retry_s, self.sleep, self.mono = retry_s, sleep, mono
        self.open_connection = open_connection or (lambda h, p: asyncio.open_connection(h, p, family=socket.AF_INET))
        self.param_s = param_s
        self.state = "down"
        self._connected_before = False
        self._suspended_at: float | None = None
        self.err_hold_s = 1.5
        self._held: set[asyncio.Task] = set()
        self._refusal_reported = False

    def emit(self, kind: str, ts_ms: int | None = None, **detail) -> None:
        detail.setdefault("canary", self.role.name.lower())
        self.on_event(Event(kind, self.tb.now_ms() if ts_ms is None else ts_ms, "reflector", detail))

    def emit_conn_error(self, kind: str, **detail) -> None:
        """rst / kernel_timeout wait a moment: after a host sleep the reset comes before the suspend report."""
        at, ts = self.mono(), self.tb.now_ms()

        async def later():
            await asyncio.sleep(self.err_hold_s)
            if self._suspended_at is None or self._suspended_at < at - 2:
                self.emit(kind, ts, **detail)
        t = asyncio.ensure_future(later())
        self._held.add(t)
        t.add_done_callback(self._held.discard)

    async def _pause(self, seconds: float, stop: asyncio.Event) -> None:
        sleeper = asyncio.ensure_future(self.sleep(seconds))
        waiter = asyncio.ensure_future(stop.wait())
        await asyncio.wait({sleeper, waiter}, return_when=asyncio.FIRST_COMPLETED)
        for t in (sleeper, waiter):
            t.cancel()

    async def _handshake(self, reader, writer) -> str | None:
        """None when HELLO_OK verified; otherwise the reason the reflector (or an impostor) refused us."""
        nonce = decode_nonce(await asyncio.wait_for(reader.readexactly(20), HELLO_TIMEOUT_S))
        anonce = os.urandom(8)
        writer.write(encode_hello(Hello(self.role, self.session_id, self.param_s, anonce), self.secret, nonce))
        await writer.drain()
        head = await asyncio.wait_for(reader.readexactly(4), HELLO_TIMEOUT_S)
        if head[3] in REFUSED:
            return REFUSED[WtType(head[3])]
        try:
            decode_hello_ok(head + await asyncio.wait_for(reader.readexactly(12), HELLO_TIMEOUT_S), self.secret, anonce)
        except WtError:
            return "reflector_unauthenticated"  # something answered on the address but can't prove it's ours
        return None

    async def _session(self, reader, writer, stop) -> str:
        raise NotImplementedError

    async def run(self, stop: asyncio.Event) -> None:
        fail_since, backoff = None, self.retry_s
        while not stop.is_set():
            outcome = await self._attempt(stop)
            if stop.is_set():
                break
            now = self.mono()
            if outcome in REFUSED.values() or outcome == "reflector_unauthenticated":
                wait = MAX_BACKOFF_S + random.uniform(0, 3)  # a wrong secret won't fix itself in a second
            elif outcome == "connect_failed":
                fail_since = fail_since if fail_since is not None else now
                if now - fail_since < FAST_RETRY_FOR_S:
                    wait = self.retry_s
                else:
                    backoff = min(MAX_BACKOFF_S, backoff * 2)
                    wait = backoff * random.uniform(0.8, 1.0)
            else:  # the connection worked and then ended (rst, eof, stall): try again quickly
                fail_since, backoff, wait = None, self.retry_s, self.retry_s
            await self._pause(wait, stop)

    async def _attempt(self, stop) -> str:
        try:
            reader, writer = await asyncio.wait_for(self.open_connection(self.host, self.port), CONNECT_TIMEOUT_S)
        except (OSError, asyncio.TimeoutError):
            self.state = "down"
            return "connect_failed"
        try:
            _tune(writer)
            refused = await self._handshake(reader, writer)
            if refused:
                self.state = "auth_failed" if refused == "auth_fail" else "down"
                if not self._refusal_reported:
                    self.emit(refused)
                    self._refusal_reported = True
                return refused
            self._refusal_reported = False
            if self._connected_before:
                self.emit("reconnect")
            self._connected_before = True
            self.state = "ok"
            return await self._session(reader, writer, stop)
        except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError, WtError) as e:
            kind = classify_conn_error(e)
            if kind in ("rst", "kernel_timeout"):
                self.emit_conn_error(kind)
            return kind
        except Exception:
            log.exception("%s canary: unexpected error", self.role.name.lower())
            return "error"
        finally:
            if not stop.is_set() and self.state in ("ok", "stall"):
                self.state = "down"
            writer.transport.abort()


MIDDLEBOX_GAP_S = 5.0   # heartbeat answers further apart than this (a stall, a reconnect) restart the middlebox hold

class HotCanary(_Canary):
    role = Role.HOT

    def __init__(self, reflector, secret, on_event, *, hb_s: float = 1.0, stall_s: float = 3.0,
                 reconnect_stall_s: float = 20.0, tcp_info_s: float = 10.0, udp_rtt=None, on_result=None,
                 middlebox_hold_s: float = 60.0, **kw):
        super().__init__(reflector, secret, on_event, **kw)
        self.hb_s, self.stall_s, self.reconnect_stall_s, self.tcp_info_s = hb_s, stall_s, reconnect_stall_s, tcp_info_s
        self._rtts: deque[float] = deque(maxlen=20)
        self.rtt_ms: float | None = None
        self.udp_rtt = udp_rtt          # () -> udp_stream RTT median, for the middlebox check
        self.on_result = on_result      # Result per HB (ok, or lost after stall_s) for the analysis
        self._suspend = False
        self.middlebox = False
        self.middlebox_hold_s, self._mb_since, self._mb_last = middlebox_hold_s, None, None

    def _result(self, t_ms, ok: bool, rtt=None) -> None:
        if self.on_result and t_ms is not None:
            from whydrop.agent.results import Result
            self.on_result(Result("canary", "reflector", None, t_ms, ok, rtt))

    def notify_suspend(self) -> None:
        """The host slept: the connection is stale, and what happens to it now is not network evidence."""
        self._suspend = True
        self._suspended_at = self.mono()

    def _check_middlebox(self) -> None:
        """A TCP answer much faster than UDP over the same path means something nearer ends the TCP connection."""
        u = self.udp_rtt() if self.udp_rtt else None
        now = self.mono()
        gap, self._mb_last = now - (self._mb_last if self._mb_last is not None else now), now
        if u is None or len(self._rtts) < 10 or gap > MIDDLEBOX_GAP_S:
            self._mb_since = None                            # the hold needs continuous evidence: no gaps, no stalls
            return
        flag = self.rtt_ms < (0.7 if self.middlebox else 0.5) * u  # on below 0.5x, off above 0.7x
        if flag == self.middlebox:
            self._mb_since = None
            return
        self._mb_since = now if self._mb_since is None else self._mb_since
        if now - self._mb_since >= self.middlebox_hold_s:   # a middlebox lasts; after a stall the two medians differ for seconds
            self.middlebox, self._mb_since = flag, None
            self.emit("middlebox", flag=flag, canary_ms=round(self.rtt_ms, 2), udp_ms=round(u, 2))

    async def _session(self, reader, writer, stop) -> str:
        sent: dict[int, int] = {}
        sent_ms: dict[int, int] = {}
        st = {"last_ack": self.mono(), "stall_at": None}
        sock = writer.get_extra_info("socket")

        async def sender():
            seq = 0
            while True:
                seq = (seq + 1) & 0xFFFFFFFF
                sent[seq] = time.perf_counter_ns()
                sent_ms[seq] = self.tb.now_ms()
                if len(sent) > 64:
                    old = next(iter(sent))
                    sent.pop(old)
                    self._result(sent_ms.pop(old, None), False)
                writer.write(encode_frame(Frame(FrameType.HB, 0, seq, sent[seq])))
                traffic.BYTES["canary"] += traffic.TCP_SEG + 16
                await writer.drain()
                await asyncio.sleep(self.hb_s)

        async def receiver():
            while True:
                f = decode_frame(await reader.readexactly(FRAME_LEN))
                if f.type != FrameType.HB_ACK:
                    continue
                traffic.BYTES["canary"] += traffic.TCP_SEG + 16
                t0 = sent.pop(f.seq, None)
                self._result(sent_ms.pop(f.seq, None), t0 is not None,
                             (time.perf_counter_ns() - t0) / 1e6 if t0 is not None else None)
                if t0 is not None:
                    self._rtts.append((time.perf_counter_ns() - t0) / 1e6)
                    self.rtt_ms = sorted(self._rtts)[len(self._rtts) // 2]
                    self._check_middlebox()
                st["last_ack"] = self.mono()
                if st["stall_at"] is not None:
                    self.emit("stall", phase="end", duration_s=round(self.mono() - st["stall_at"], 2))
                    st["stall_at"] = None
                    self.state = "ok"

        self._suspend = False  # a report from before this session is about the old one

        async def watchdog():
            last_run = self.mono()
            while True:
                await asyncio.sleep(min(0.1, self.hb_s))
                if self._suspend:
                    self._suspend = False
                    st["stall_at"] = None  # no stall/rst evidence from a host that was asleep
                    return "suspended"
                if self.mono() - last_run > self.stall_s:  # we ourselves didn't run (sleep, long loop stall)
                    st["stall_at"] = None
                    return "suspended"  # start clean rather than judge this connection
                last_run = self.mono()
                quiet = self.mono() - st["last_ack"]
                cutoff = self.tb.now_ms() - int(self.stall_s * 1000)
                for q in [q for q, t in sent_ms.items() if t < cutoff]:
                    sent.pop(q, None)
                    self._result(sent_ms.pop(q), False)
                if st["stall_at"] is None and sent and quiet > self.stall_s:
                    st["stall_at"] = st["last_ack"]
                    self.state = "stall"
                    self.emit("stall", phase="start")  # keep the connection: let TCP retransmit (spec §5.3)
                if st["stall_at"] is not None and quiet > self.reconnect_stall_s:
                    return "stall"

        async def tcp_info():
            next_at = self.mono() + 1.0  # a baseline 1 s after connecting
            while True:  # then every 10 s, every 1 s during a stall
                await asyncio.sleep(min(1.0, self.tcp_info_s))
                if st["stall_at"] is None and self.mono() < next_at:
                    continue
                next_at = self.mono() + self.tcp_info_s
                info = read_tcp_info(sock) if sock is not None else None
                if info:
                    self.emit("tcp_info", **info)

        tasks = [asyncio.create_task(c()) for c in (sender, receiver, watchdog, tcp_info)]
        stopper = asyncio.create_task(stop.wait())
        try:
            done, _ = await asyncio.wait({*tasks, stopper}, return_when=asyncio.FIRST_COMPLETED)
            finished = done.pop()
            if finished is stopper:
                return "stopped"
            exc = finished.exception()
            if exc is not None:
                kind = classify_conn_error(exc)
                if kind in ("rst", "kernel_timeout"):
                    self.emit_conn_error(kind)
                return kind
            return finished.result()
        finally:
            for t in (*tasks, stopper):
                t.cancel()
            await asyncio.gather(*tasks, stopper, return_exceptions=True)
            if st["stall_at"] is not None:
                self.emit("stall", phase="end", duration_s=round(self.mono() - st["stall_at"], 2), reconnected=True)


class IdleCanary(_Canary):
    """A connection that stays silent for `interval_s`; the reflector pings first (an agent-first send would let a
    NAT that forgot the connection quietly learn it again). No ping by schedule + grace → `idle_state_lost`."""
    role = Role.IDLE

    def __init__(self, reflector, secret, on_event, *, interval_s: int, expect_s: float | None = None,
                 grace_s: float = 5.0, verdict_delay_s: float = 1.5, **kw):
        super().__init__(reflector, secret, on_event, param_s=interval_s, **kw)
        self.interval_s = interval_s
        self.expect_s = expect_s if expect_s is not None else float(interval_s)
        self.grace_s = grace_s
        self.verdict_delay_s = verdict_delay_s
        self.pings = 0
        self._suspended_at: float | None = None

    def notify_suspend(self) -> None:
        """The host slept; a missing ping during that time says nothing about the NAT."""
        self._suspended_at = self.mono()

    async def _session(self, reader, writer, stop) -> str:
        started = self.mono()
        due = started + self.expect_s

        async def receiver():
            nonlocal due
            while True:
                f = decode_frame(await reader.readexactly(FRAME_LEN))
                if f.type == FrameType.IDLE_PING:
                    self.pings += 1
                    writer.write(encode_frame(Frame(FrameType.IDLE_PONG, 0, f.seq, f.t_send_ns)))
                    await writer.drain()
                    due = self.mono() + self.expect_s

        async def watchdog():
            while True:
                await asyncio.sleep(min(0.1, self.grace_s / 3))
                if self.mono() > due + self.grace_s:
                    window_start = due - self.expect_s
                    await asyncio.sleep(self.verdict_delay_s)  # the suspend event arrives on the next tick
                    if self._suspended_at is not None and self._suspended_at >= window_start:
                        return "suspended"  # reconnect quietly
                    self.emit("idle_state_lost", interval_s=self.interval_s,
                              waited_s=round(self.mono() - window_start, 1))
                    return "idle_lost"

        tasks = [asyncio.create_task(receiver()), asyncio.create_task(watchdog())]
        stopper = asyncio.create_task(stop.wait())
        try:
            done, _ = await asyncio.wait({*tasks, stopper}, return_when=asyncio.FIRST_COMPLETED)
            finished = done.pop()
            if finished is stopper:
                return "stopped"
            exc = finished.exception()
            if exc is not None:
                kind = classify_conn_error(exc)
                if kind in ("rst", "kernel_timeout"):
                    self.emit_conn_error(kind)
                return kind
            return finished.result()
        finally:
            for t in (*tasks, stopper):
                t.cancel()
            await asyncio.gather(*tasks, stopper, return_exceptions=True)
