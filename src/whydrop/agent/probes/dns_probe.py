"""DNS probes over UDP and TCP, and the router's once-a-minute uncached check (spec §5.0, §5.2)."""
import asyncio
import os
import secrets
import socket
import time

from whydrop.agent import traffic
from whydrop.agent.probes.base import classify_oserror, udp_exchange
from whydrop.agent.probes.targets import pair_id
from whydrop.agent.results import Result
from whydrop.net import dns

UDP_TIMEOUT_S = 2.0
TCP_TIMEOUT_S = 3.0
QUERY = "example.com"


def _judge(data: bytes | None, qid: int) -> tuple[bool, dict]:
    if data is None:
        return False, {}
    try:
        reply = dns.parse_reply(data)
    except ValueError:
        return False, {"malformed": True}
    return dns.is_success(reply, qid), {"rcode": reply.rcode, "answers": len(reply.answers)}


async def udp(addr: str, cls: str, provider: str | None, now_ms, *, port: int = 53, name: str = QUERY,
              probe: str = "dns", on_late=None, timeout_s: float = UDP_TIMEOUT_S) -> Result:
    qid = int.from_bytes(os.urandom(2), "big")
    t_send = now_ms()

    def match(data, src):
        return len(data) >= 2 and int.from_bytes(data[:2], "big") == qid and src[0] == addr

    data, rtt, detail = await udp_exchange((addr, port), dns.build_query(qid, name), timeout_s, match=match,
                                           on_late=on_late, count_as=probe)
    ok, extra = _judge(data, qid)
    return Result(probe, pair_id(cls, addr, port, "udp"), provider, t_send, ok, rtt if ok else None,
                  local_fail=bool(detail.get("local_fail")), detail={**detail, **extra, "port": port})


async def tcp(addr: str, cls: str, provider: str | None, now_ms, *, port: int = 53) -> Result:
    qid = int.from_bytes(os.urandom(2), "big")
    t_send, t0 = now_ms(), time.perf_counter_ns()
    pair = pair_id(cls, addr, port, "tcp")
    writer = None

    async def exchange():
        nonlocal writer
        reader, writer = await asyncio.open_connection(addr, port, family=socket.AF_INET)
        writer.write(dns.tcp_frame(dns.build_query(qid, QUERY)))
        await writer.drain()
        n = int.from_bytes(await reader.readexactly(2), "big")
        return await reader.readexactly(n)

    try:
        data = await asyncio.wait_for(exchange(), TCP_TIMEOUT_S)  # the whole exchange, not just connect
        detail: dict = {}
    except asyncio.TimeoutError:
        data, detail = None, {"timeout": True}
    except ConnectionRefusedError as e:
        data, detail = None, classify_oserror(e)
    except (asyncio.IncompleteReadError, ConnectionError) as e:
        data, detail = None, {"error": type(e).__name__}
    except OSError as e:
        data, detail = None, classify_oserror(e)
    finally:
        if writer is not None:
            writer.transport.abort()
    traffic.tcp_dns("dns_tcp", len(dns.build_query(qid, QUERY)), len(data) if data is not None else None)
    ok, extra = _judge(data, qid)
    rtt = (time.perf_counter_ns() - t0) / 1e6
    return Result("dns_tcp", pair, provider, t_send, ok, rtt if ok else None,
                  local_fail=bool(detail.get("local_fail")), detail={**detail, **extra})


async def router_cache_check(router: str, now_ms, *, port: int = 53) -> Result:
    """A random label can't be cached, so the router has to forward it; NXDOMAIN back = forwarding works."""
    name = f"{secrets.token_hex(4)}.{QUERY}"
    r = await udp(router, "dns_router", None, now_ms, port=port, name=name, probe="dns_cache")
    r.detail["name"] = name
    return r
