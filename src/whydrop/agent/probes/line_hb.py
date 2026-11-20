"""line_hb: one UDP question per second, rotating across providers (spec §5.2)."""
import os

from whydrop.agent.config import Target
from whydrop.agent.probes import dns_probe
from whydrop.agent.probes.base import udp_exchange
from whydrop.agent.probes.targets import pair_id
from whydrop.agent.results import Result
from whydrop.net import stun

TIMEOUT_S = 1.0


async def probe(slot: Target, now_ms, *, addr: str | None = None, on_late=None) -> Result:
    ip = addr or slot.addr
    if slot.kind == "dns":
        r = await dns_probe.udp(ip, "line_hb", slot.provider, now_ms, port=slot.port, probe="line_hb",
                                on_late=on_late, timeout_s=TIMEOUT_S)
        r.pair = pair_id("line_hb", slot.addr, slot.port, "udp")
        return r
    txid = os.urandom(12)
    t_send = now_ms()
    data, rtt, detail = await udp_exchange((ip, slot.port), stun.build_binding(txid), TIMEOUT_S,
                                           match=lambda d, src: stun.parse_binding_response(d, txid) is not None,
                                           on_late=on_late)
    return Result("line_hb", pair_id("line_hb", slot.addr, slot.port, "udp"), slot.provider, t_send,
                  data is not None, rtt, local_fail=bool(detail.get("local_fail")), detail=detail)
