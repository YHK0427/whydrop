"""Router liveness: TCP SYN answered by SYN-ACK or RST (Linux), ICMP echo (Windows). Spec §5.0, §5.2."""
import asyncio
import sys

from whydrop.agent.probes.base import tcp_probe
from whydrop.agent.results import Result

TIMEOUT_S = 1.5
DEFAULT_PORT = 1  # tcpmux: almost never open, so the router answers with an RST


async def probe(gw: str, port: int | None, now_ms) -> Result:
    t_send = now_ms()
    if sys.platform == "win32":
        from whydrop.agent import winicmp
        rtt = await asyncio.to_thread(winicmp.echo, gw, int(TIMEOUT_S * 1000))
        from whydrop.agent import traffic
        traffic.icmp("gateway", 7, rtt is not None)
        return Result("gateway", "gateway", None, t_send, rtt is not None, rtt, detail={"method": "icmp"})
    ok, rtt, detail = await tcp_probe((gw, port or DEFAULT_PORT), TIMEOUT_S, rst_ok=True, count_as="gateway")
    return Result("gateway", "gateway", None, t_send, ok, rtt, local_fail=bool(detail.get("local_fail")),
                  detail={**detail, "method": "tcp"})
