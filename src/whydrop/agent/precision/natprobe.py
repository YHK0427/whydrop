"""`whydrop nat-test` (spec §5.3): how long a NAT or firewall on the path keeps an idle UDP mapping or TCP
connection, measured with the reflector, and the keepalive that follows from it."""
import asyncio
import json
import os
import socket
from dataclasses import dataclass, field

from whydrop.proto import wd, wt
from whydrop.proto.wd import WdError, WdPacket, WdType

UDP_DELAYS = (10, 20, 30, 45, 60, 90, 120, 180, 300, 600)
TCP_DELAYS = (60, 300, 600, 1200, 1800, 3600)
IMMEDIATE_WAIT_S = 2.0
AFTER_DELAY_WAIT_S = 5.0
SECOND_REQ_AFTER_S = 3.0   # Linux conntrack applies its long UDP timer only to flows still active 2 s in
TRIES = 3


@dataclass
class DelayResult:
    proto: str
    delay_s: int
    alive: bool | None          # None = inconclusive
    detail: dict = field(default_factory=dict)


@dataclass
class NatReport:
    udp: list[DelayResult]
    tcp: list[DelayResult]
    udp_range: tuple[int | None, int | None]
    tcp_range: tuple[int | None, int | None]
    keepalive_s: dict[str, int | None]


def bracket(results: list[DelayResult]) -> tuple[int | None, int | None]:
    """(longest delay that survived, shortest that didn't). Either side may be open."""
    dead = [r.delay_s for r in results if r.alive is False]
    upper = min(dead) if dead else None
    alive = [r.delay_s for r in results if r.alive and (upper is None or r.delay_s < upper)]
    return (max(alive) if alive else None), upper


def keepalive(lower: int | None, upper: int | None) -> int | None:
    """Only for a closed range: 80% of the longest delay that survived, rounded down to 5 s."""
    if lower is None or upper is None:
        return None
    return max(5, lower * 4 // 5 // 5 * 5)


async def _race(coro, seconds: float, sleep):
    """coro's result, or None if `sleep(seconds)` finishes first (so injected fast time scales the waits too)."""
    work, timer = asyncio.ensure_future(coro), asyncio.ensure_future(sleep(seconds))
    done, _ = await asyncio.wait({work, timer}, return_when=asyncio.FIRST_COMPLETED)
    for t in (work, timer):
        if t not in done:
            t.cancel()
    await asyncio.gather(work, timer, return_exceptions=True)
    return work.result() if work in done and not work.cancelled() and work.exception() is None else None


class _Replies(asyncio.DatagramProtocol):
    def __init__(self, secret, session_id):
        self.secret, self.sid = secret, session_id
        self.q: asyncio.Queue = asyncio.Queue()

    def datagram_received(self, data, addr):
        try:
            p = wd.decode(data, self.secret)
        except WdError:
            return
        if p.type == WdType.NAT_REPLY and p.session_id == self.sid:
            self.q.put_nowait(p)

    def error_received(self, exc):
        pass


async def _expect(q: asyncio.Queue, seq: int, arg: int) -> bool:
    while True:
        p = await q.get()
        if p.seq == seq and p.arg == arg:
            return True


async def udp_delay(addr: tuple[str, int], secret: bytes, delay: int, *, sleep=asyncio.sleep) -> DelayResult:
    """One socket and one session per delay, so each delay tests its own NAT mapping."""
    loop = asyncio.get_running_loop()
    sid = int.from_bytes(os.urandom(4), "big")
    transport, proto = await loop.create_datagram_endpoint(lambda: _Replies(secret, sid), remote_addr=addr,
                                                           family=socket.AF_INET)
    try:
        seq = 0

        def req():
            nonlocal seq
            seq += 1
            transport.sendto(wd.encode(WdPacket(WdType.NAT_REQ, sid, seq, 0, arg=delay), secret))

        for _ in range(TRIES):
            req()
            if await _race(_expect(proto.q, seq, 0), IMMEDIATE_WAIT_S, sleep):
                break
        else:
            return DelayResult("udp", delay, None, {"reason": "no immediate reply"})
        await sleep(SECOND_REQ_AFTER_S)
        req()  # restarts the delay at the reflector and keeps the flow "established" past the 2 s mark
        await _race(_expect(proto.q, seq, 0), IMMEDIATE_WAIT_S, sleep)
        alive = await _race(_expect(proto.q, seq, 1), delay + AFTER_DELAY_WAIT_S, sleep)
        return DelayResult("udp", delay, bool(alive))
    finally:
        transport.close()


async def tcp_delay(addr: tuple[str, int], secret: bytes, delay: int, *, sleep=asyncio.sleep) -> DelayResult:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(*addr, family=socket.AF_INET), 5)
    except (OSError, asyncio.TimeoutError) as e:
        return DelayResult("tcp", delay, None, {"reason": f"connect failed: {type(e).__name__}"})
    try:
        nonce = wt.decode_nonce(await asyncio.wait_for(reader.readexactly(20), 5))
        anonce = os.urandom(8)
        writer.write(wt.encode_hello(wt.Hello(wt.Role.NAT, int.from_bytes(os.urandom(4), "big"), delay, anonce),
                                     secret, nonce))
        await writer.drain()
        head = await asyncio.wait_for(reader.readexactly(4), 5)
        if head[3] != wt.WtType.HELLO_OK:
            known = {t.value: t.name.lower() for t in wt.WtType}
            return DelayResult("tcp", delay, None, {"reason": known.get(head[3], f"type {head[3]}")})
        wt.decode_hello_ok(head + await asyncio.wait_for(reader.readexactly(12), 5), secret, anonce)

        async def probe():
            try:
                return wt.decode_frame(await reader.readexactly(wt.FRAME_LEN)).type == wt.FrameType.NAT_PROBE
            except (asyncio.IncompleteReadError, ConnectionError, OSError, wt.WtError):
                return False
        return DelayResult("tcp", delay, bool(await _race(probe(), delay + AFTER_DELAY_WAIT_S, sleep)))
    except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError, wt.WtError, OSError) as e:
        return DelayResult("tcp", delay, None, {"reason": type(e).__name__})
    finally:
        writer.transport.abort()


async def nat_test(reflector: tuple[str, int], secret: bytes, *, udp_delays=UDP_DELAYS, tcp_delays=TCP_DELAYS,
                   sleep=asyncio.sleep, on_progress=None) -> NatReport:
    """All delays run at once (each with its own socket/session), so a full run takes about the longest delay."""
    async def tracked(proto, delay, coro):
        try:
            r = await coro
        except Exception as e:  # one broken delay must not take the whole run down
            r = DelayResult(proto, delay, None, {"reason": type(e).__name__})
        if on_progress:
            on_progress(r)
        return r
    jobs = [tracked("udp", d, udp_delay(reflector, secret, d, sleep=sleep)) for d in udp_delays] + \
           [tracked("tcp", d, tcp_delay(reflector, secret, d, sleep=sleep)) for d in tcp_delays]
    done = await asyncio.gather(*jobs)
    udp, tcp = done[:len(udp_delays)], done[len(udp_delays):]
    ur, tr = bracket(list(udp)), bracket(list(tcp))
    return NatReport(list(udp), list(tcp), ur, tr, {"udp": keepalive(*ur), "tcp": keepalive(*tr)})


def _range_text(r: tuple[int | None, int | None]) -> str:
    lo, hi = r
    if lo is None and hi is None:
        return "not measured"
    if hi is None:
        return f"more than {lo} s"
    if lo is None:
        return f"less than {hi} s"
    return f"between {lo} s and {hi} s"


def format_report(rep: NatReport) -> str:
    lines = []
    for proto, rows, rng in (("UDP", rep.udp, rep.udp_range), ("TCP", rep.tcp, rep.tcp_range)):
        if not rows:
            continue
        lines.append(f"{proto} idle mapping")
        for r in rows:
            state = {True: "alive", False: "forgotten", None: "inconclusive"}[r.alive]
            lines.append(f"  {r.delay_s:>5} s  {state}" + (f" ({r.detail['reason']})" if r.detail.get("reason") else ""))
        k = rep.keepalive_s[proto.lower()]
        lines.append(f"  timeout {_range_text(rng)}; " +
                     (f"keepalive {k} s or less" if k else "no keepalive advice until the range is closed"))
    return "\n".join(lines)


async def store_report(store, rep: NatReport, *, start_ms: int, end_ms: int) -> int:
    run_id = await store.insert("nat_runs", start_ms=start_ms, end_ms=end_ms, status="done",
                                detail_json=json.dumps({"udp_range": rep.udp_range, "tcp_range": rep.tcp_range,
                                                        "keepalive_s": rep.keepalive_s}))
    for r in rep.udp + rep.tcp:
        await store.insert("nat_results", run_id=run_id, proto=r.proto, delay_s=r.delay_s,
                           alive=None if r.alive is None else int(r.alive), detail_json=json.dumps(r.detail))
    return run_id
