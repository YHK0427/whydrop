"""TCP canaries to the reflector (spec §5.3): the hot one heartbeats every second and shows what TCP does during
a drop (stall, retransmissions, RST); the idle one shows whether a NAT forgets a silent connection."""
import asyncio
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
        self._refusal_reported = False

    def emit(self, kind: str, **detail) -> None:
        self.on_event(Event(kind, self.tb.now_ms(), "reflector", detail))

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
                self.emit(kind)
            return kind
        finally:
            if not stop.is_set() and self.state in ("ok", "stall"):
                self.state = "down"
            writer.transport.abort()


class HotCanary(_Canary):
    role = Role.HOT

    def __init__(self, reflector, secret, on_event, *, hb_s: float = 1.0, stall_s: float = 3.0,
                 reconnect_stall_s: float = 20.0, tcp_info_s: float = 10.0, **kw):
        super().__init__(reflector, secret, on_event, **kw)
        self.hb_s, self.stall_s, self.reconnect_stall_s, self.tcp_info_s = hb_s, stall_s, reconnect_stall_s, tcp_info_s
        self._rtts: deque[float] = deque(maxlen=20)
        self.rtt_ms: float | None = None

    async def _session(self, reader, writer, stop) -> str:
        sent: dict[int, int] = {}
        st = {"last_ack": self.mono(), "stall_at": None}
        sock = writer.get_extra_info("socket")

        async def sender():
            seq = 0
            while True:
                seq = (seq + 1) & 0xFFFFFFFF
                sent[seq] = time.perf_counter_ns()
                if len(sent) > 64:
                    sent.pop(next(iter(sent)))
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
                if t0 is not None:
                    self._rtts.append((time.perf_counter_ns() - t0) / 1e6)
                    self.rtt_ms = sorted(self._rtts)[len(self._rtts) // 2]
                st["last_ack"] = self.mono()
                if st["stall_at"] is not None:
                    self.emit("stall", phase="end", duration_s=round(self.mono() - st["stall_at"], 2))
                    st["stall_at"] = None
                    self.state = "ok"

        async def watchdog():
            while True:
                await asyncio.sleep(min(0.1, self.hb_s))
                quiet = self.mono() - st["last_ack"]
                if st["stall_at"] is None and sent and quiet > self.stall_s:
                    st["stall_at"] = st["last_ack"]
                    self.state = "stall"
                    self.emit("stall", phase="start")  # keep the connection: let TCP retransmit (spec §5.3)
                if st["stall_at"] is not None and quiet > self.reconnect_stall_s:
                    return "stall"

        async def tcp_info():
            while True:
                await asyncio.sleep(1.0 if st["stall_at"] is not None else self.tcp_info_s)
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
                    self.emit(kind)
                return kind
            return finished.result()
        finally:
            for t in (*tasks, stopper):
                t.cancel()
            await asyncio.gather(*tasks, stopper, return_exceptions=True)
            if st["stall_at"] is not None:
                self.emit("stall", phase="end", duration_s=round(self.mono() - st["stall_at"], 2), reconnected=True)
