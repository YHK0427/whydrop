"""TCP handshake to port 443, closed at once with an RST (spec §5.2)."""
from whydrop.agent.config import Target
from whydrop.agent.probes.base import tcp_probe
from whydrop.agent.probes.targets import pair_id
from whydrop.agent.results import Result

TIMEOUT_S = 1.5


async def probe(t: Target, now_ms) -> Result:
    t_send = now_ms()
    ok, rtt, detail = await tcp_probe((t.addr, t.port), TIMEOUT_S, rst_ok=False)
    return Result("tcp_connect", pair_id("tcp", t.addr, t.port, "tcp"), t.provider, t_send, ok, rtt,
                  local_fail=bool(detail.get("local_fail")), detail=detail)
