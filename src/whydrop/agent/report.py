"""The network report card (spec §5.1): the first screen, filled within a minute of start."""
import ipaddress
import os
from pathlib import Path

from whydrop.agent.env import EnvInfo, chaos_verdict
from whydrop.agent.probes.base import udp_exchange
from whydrop.agent.selfcheck import SelfCheck
from whydrop.net import dns

# Ranges Google's public resolvers recurse from (a short list is enough for a "suspect / ok" verdict)
GOOGLE_RANGES = [ipaddress.ip_network(n) for n in ("74.125.0.0/16", "172.217.0.0/16", "172.253.0.0/16",
                                                   "173.194.0.0/16", "108.177.0.0/17", "35.199.192.0/19")]
CONNTRACK = ("nf_conntrack_udp_timeout", "nf_conntrack_udp_timeout_stream", "nf_conntrack_tcp_timeout_established")
CGNAT = ipaddress.ip_network("100.64.0.0/10")


async def _txt(server: str, name: str, qclass: int = 1) -> list[str]:
    qid = int.from_bytes(os.urandom(2), "big")
    data, _, _ = await udp_exchange((server, 53), dns.build_query(qid, name, 16, qclass), 2.0, late_s=0,
                                    match=lambda d, src: len(d) >= 2 and int.from_bytes(d[:2], "big") == qid)
    if data is None:
        return []
    try:
        reply = dns.parse_reply(data)
    except ValueError:
        return []
    return [s for rd in reply.answers for s in dns.txt_strings(rd)] if dns.is_success(reply, qid) else []


def google_verdict(strings: list[str]) -> str:
    for s in strings:
        try:
            ip = ipaddress.ip_address(s.strip())
        except ValueError:
            continue
        return "ok" if any(ip in n for n in GOOGLE_RANGES) else "suspect"
    return "unknown"


async def dns_interception() -> dict:
    chaos = await _txt("1.1.1.1", "id.server", qclass=3)
    goog = await _txt("8.8.8.8", "o-o.myaddr.l.google.com")
    verdicts = {chaos_verdict(chaos), google_verdict(goog)}
    overall = "suspect" if "suspect" in verdicts else ("ok" if "ok" in verdicts else "unknown")
    return {"verdict": overall}  # only the verdict is stored, never the strings (spec §5.1)


def conntrack_values(root: Path = Path("/proc/sys/net/netfilter")) -> dict:
    out = {}
    for k in CONNTRACK:
        try:
            out[k] = int((root / k).read_text())
        except (OSError, ValueError):
            pass
    return out


def report_card(env: EnvInfo, sc: SelfCheck, nat: dict | None, *, wifi: dict | None = None,
                interception: dict | None = None, multi_ip: bool = False) -> dict:
    blocked = sorted(k for k, why in sc.excluded.items() if "only" in why)
    cgnat = bool(nat and nat.get("public_ip") and ipaddress.ip_address(nat["public_ip"]) in CGNAT) or multi_ip
    return {
        "link": env.link,
        "median_rtt_ms": {k: round(v, 1) for k, v in sc.median_rtt.items()},
        "protocol_blocks": blocked,
        "excluded": dict(sc.excluded),
        "selfcheck": sc.status,
        "dns_interception": (interception or {}).get("verdict", "unknown"),
        "cgnat_hint": cgnat,
        "nat_mapping": {k: v for k, v in (nat or {}).items() if k != "public_ip"} or None,
        "wifi": wifi,
        "conntrack": conntrack_values(),
        "ipv6_unmeasured": env.ipv6_default,
        "egress_vpn": env.egress_vpn,
    }
