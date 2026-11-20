"""UDP side of the reflector: ECHO for PROBEs, immediate + delayed replies for NAT_REQ (spec §5.3–5.5)."""
import time
from collections import Counter, OrderedDict
from dataclasses import dataclass, field

from whydrop.proto import wd
from whydrop.proto.wd import NAT_DELAYS_S, WdError, WdPacket, WdType
from whydrop.reflector.limits import PerKeyBuckets
from whydrop.reflector.replay import ReplayWindow, Tombstones

SESSION_IDLE_S = 24 * 3600
NAT_PENDING_PER_IP = 16
NAT_PENDING_TOTAL = 1024
_INBOUND = (WdType.PROBE, WdType.NAT_REQ)  # ECHO/NAT_REPLY coming in would reflect, so they are dropped
Addr = tuple[str, int]


@dataclass
class Session:
    window: ReplayWindow
    recv_count: int = 0
    last_seen: float = 0.0


@dataclass
class _Pending:
    due: float
    addr: Addr
    packet: bytes = field(repr=False)


class UdpReflector:
    def __init__(self, secret: bytes, *, epoch: int, tombstones: Tombstones, clock=time.monotonic,
                 max_sessions: int = 10_000):
        self._secret = secret
        self._epoch = epoch
        self._tomb = tombstones
        self._clock = clock
        self._max_sessions = max_sessions
        self._pre = PerKeyBuckets(200, 200, clock=clock)   # before hashing
        self._post = PerKeyBuckets(50, 50, clock=clock)    # after the MAC verifies
        self._pending: dict[int, _Pending] = {}            # session_id -> delayed NAT_REPLY
        self.sessions: OrderedDict[int, Session] = OrderedDict()
        self.drops: Counter[str] = Counter()
        self.rxq_ovfl = 0  # kernel receive-queue drops, set by the transport, echoed in ECHO.arg

    def handle(self, data: bytes, addr: Addr) -> list[bytes]:
        reason = wd.precheck(data)
        if reason:
            return self._drop("bad_" + reason)
        if data[3] not in _INBOUND:
            return self._drop("bad_type")
        ip = addr[0]
        if not self._pre.take(ip):
            return self._drop("pre_rate")
        try:
            p = wd.decode(data, self._secret)
        except WdError as e:
            return self._drop("bad_" + e.reason)
        if not self._post.take(ip):
            return self._drop("post_rate")
        if p.type == WdType.NAT_REQ:
            if p.arg not in NAT_DELAYS_S:
                return self._drop("nat_delay")
            if p.session_id not in self._pending and self._nat_full(ip):
                return self._drop("nat_cap")
        s = self._session(p.session_id)
        if not s.window.accept(p.seq):
            return self._drop("replay")
        now = self._clock()
        s.last_seen = now
        self._tomb.update(p.session_id, s.window.highest)
        if p.type == WdType.PROBE:
            s.recv_count += 1
            return [self._reply(p, WdType.ECHO, recv_count=s.recv_count,
                                rx_bitmap=self._bitmap(s.window, p.seq), arg=self.rxq_ovfl & 0xFFFFFFFF)]
        self._pending[p.session_id] = _Pending(now + p.arg, addr, self._reply(p, WdType.NAT_REPLY, arg=1))
        return [self._reply(p, WdType.NAT_REPLY, arg=0)]

    def due(self) -> list[tuple[Addr, bytes]]:
        now = self._clock()
        ready = [sid for sid, x in self._pending.items() if x.due <= now]
        return [(x.addr, x.packet) for x in (self._pending.pop(sid) for sid in ready)]

    def sweep(self) -> None:
        cutoff = self._clock() - SESSION_IDLE_S
        for sid in [sid for sid, s in self.sessions.items() if s.last_seen < cutoff]:
            del self.sessions[sid]

    def _drop(self, reason: str) -> list[bytes]:
        self.drops[reason] += 1
        return []

    def _session(self, sid: int) -> Session:
        s = self.sessions.get(sid)
        if s is None:
            floor = self._tomb.get(sid)
            s = self.sessions[sid] = Session(ReplayWindow(-1 if floor is None else floor))
            if len(self.sessions) > self._max_sessions:
                self.sessions.popitem(last=False)
        else:
            self.sessions.move_to_end(sid)
        return s

    def _nat_full(self, ip: str) -> bool:
        if len(self._pending) >= NAT_PENDING_TOTAL:
            return True
        return sum(1 for x in self._pending.values() if x.addr[0] == ip) >= NAT_PENDING_PER_IP

    @staticmethod
    def _bitmap(w: ReplayWindow, seq: int) -> int:
        return sum(1 << i for i in range(32) if w.seen(seq - 1 - i))

    def _reply(self, p: WdPacket, t: WdType, **kw) -> bytes:
        return wd.encode(WdPacket(t, p.session_id, p.seq, p.t_send_ns, epoch=self._epoch, **kw), self._secret)
