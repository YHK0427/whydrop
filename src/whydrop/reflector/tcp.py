"""TCP side of the reflector: nonce handshake, then hot / idle / nat roles (spec §5.3–5.5)."""
import asyncio
import logging
import os
import socket
import sys
from collections import Counter

from whydrop.proto.wt import (
    FRAME_LEN, HELLO_LEN, Frame, FrameType, Hello, Role, WtError, WtType,
    decode_frame, decode_hello, encode_frame, encode_hello_ok, encode_nonce, encode_short, valid_param,
)

log = logging.getLogger(__name__)

UNAUTH_PER_IP = 4
UNAUTH_TOTAL = 64
AUTH_TOTAL = 256
NAT_PER_SESSION = 7
USER_TIMEOUT_MS = 30_000


def _tune(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 0)
    if sys.platform.startswith("linux"):
        sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, "TCP_USER_TIMEOUT", 18), USER_TIMEOUT_MS)


class TcpReflector:
    def __init__(self, secret: bytes, *, epoch: int, enable_7500: bool = False, hello_timeout_s: float = 5.0,
                 hot_idle_close_s: float = 30.0, sleep=asyncio.sleep):
        self._secret = secret
        self._epoch = epoch
        self._enable_7500 = enable_7500
        self._hello_timeout = hello_timeout_s
        self._hot_idle_close = hot_idle_close_s
        self._sleep = sleep
        self._unauth: Counter[str] = Counter()
        self._unauth_total = 0
        self._single: dict[tuple[int, Role], asyncio.StreamWriter] = {}   # hot/idle: one per session
        self._nat: dict[int, set[asyncio.StreamWriter]] = {}
        self.drops: Counter[str] = Counter()

    @property
    def _auth_total(self) -> int:
        return len(self._single) + sum(len(s) for s in self._nat.values())

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            ip = (writer.get_extra_info("peername") or ("?",))[0]
            if self._unauth[ip] >= UNAUTH_PER_IP or self._unauth_total >= UNAUTH_TOTAL:
                self.drops["unauth_cap"] += 1
                return
            _tune(writer)
            hello = await self._handshake(ip, reader, writer)
            if hello is None:
                return
            if not self._register(hello, writer):
                self.drops["busy"] += 1
                writer.write(encode_short(WtType.BUSY))
                return
            try:
                writer.write(encode_hello_ok(self._epoch, self._secret, hello.anonce))
                await writer.drain()
                await {Role.HOT: self._hot, Role.IDLE: self._idle, Role.NAT: self._nat_role}[hello.role](
                    hello, reader, writer)
            finally:
                self._unregister(hello, writer)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError, WtError):
            pass
        except Exception:  # never let one connection's bug reach asyncio's default handler silently
            log.exception("tcp handler failed")
        finally:
            writer.close()

    async def _handshake(self, ip: str, reader, writer) -> Hello | None:
        self._unauth[ip] += 1
        self._unauth_total += 1
        try:
            nonce = os.urandom(16)
            writer.write(encode_nonce(nonce))
            await writer.drain()
            try:
                raw = await asyncio.wait_for(reader.readexactly(HELLO_LEN), self._hello_timeout)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                self.drops["hello_timeout"] += 1
                return None
        finally:
            self._unauth[ip] -= 1
            if not self._unauth[ip]:
                del self._unauth[ip]
            self._unauth_total -= 1
        try:
            hello = decode_hello(raw, self._secret, nonce)
        except WtError as e:
            self.drops["bad_" + e.reason] += 1
            reply = {"version": WtType.VERSION, "hmac": WtType.AUTH_FAIL}.get(e.reason)
            if reply:
                writer.write(encode_short(reply))
            return None
        if not valid_param(hello.role, hello.param_s, enable_7500=self._enable_7500):
            self.drops["bad_param"] += 1
            writer.write(encode_short(WtType.VERSION))  # "this reflector doesn't support that request"
            return None
        return hello

    def _register(self, h: Hello, writer) -> bool:
        if h.role == Role.NAT:
            conns = self._nat.get(h.session_id, set())
            if len(conns) >= NAT_PER_SESSION or self._auth_total >= AUTH_TOTAL:
                return False
            self._nat[h.session_id] = conns | {writer}
            return True
        key = (h.session_id, h.role)
        old = self._single.get(key)
        if old is None and self._auth_total >= AUTH_TOTAL:
            return False
        if old is not None:
            old.close()  # a newer authenticated HELLO replaces the old connection
        self._single[key] = writer
        return True

    def _unregister(self, h: Hello, writer) -> None:
        if h.role == Role.NAT:
            conns = self._nat.get(h.session_id, set()) - {writer}
            if conns:
                self._nat[h.session_id] = conns
            else:
                self._nat.pop(h.session_id, None)
        elif self._single.get((h.session_id, h.role)) is writer:
            del self._single[(h.session_id, h.role)]

    async def _hot(self, h: Hello, reader, writer) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._hot_idle_close  # only HBs extend it (spec: "no HB for 30 s")
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            f = decode_frame(await asyncio.wait_for(reader.readexactly(FRAME_LEN), remaining))
            if f.type == FrameType.HB:
                deadline = loop.time() + self._hot_idle_close
                writer.write(encode_frame(Frame(FrameType.HB_ACK, 0, f.seq, f.t_send_ns)))
                await writer.drain()

    async def _idle(self, h: Hello, reader, writer) -> None:
        async def ping():
            seq = 0
            while True:
                await self._sleep(h.param_s)
                seq += 1
                writer.write(encode_frame(Frame(FrameType.IDLE_PING, 0, seq, 0)))
                await writer.drain()

        async def drain_pongs():  # only to notice the agent going away
            while await reader.read(FRAME_LEN):
                pass

        tasks = [asyncio.create_task(ping()), asyncio.create_task(drain_pongs())]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _nat_role(self, h: Hello, reader, writer) -> None:
        await self._sleep(h.param_s)
        writer.write(encode_frame(Frame(FrameType.NAT_PROBE, 0, 0, 0)))
        await writer.drain()


async def serve_tcp(r: TcpReflector, host: str, port: int) -> asyncio.Server:
    return await asyncio.start_server(r.handle, host, port, family=socket.AF_INET)
