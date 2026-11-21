"""IP-layer byte counters per probe (spec §10 traffic budget; shown in /api/status by Plan 5)."""
from collections import Counter

IP_UDP = 20 + 8
TCP_SYN = 60       # IPv4 20 + TCP 20 + options 20
TCP_SEG = 52       # IPv4 20 + TCP 20 + timestamps 12
TCP_RST = 40
ICMP = 20 + 8

BYTES: Counter[str] = Counter()


def udp(probe: str, sent: int, received: int | None) -> None:
    BYTES[probe] += IP_UDP + sent + (IP_UDP + received if received is not None else 0)


def tcp_connect(probe: str, outcome: str) -> None:
    """outcome: open (SYN, SYN-ACK, ACK, RST) | rst (SYN, RST) | timeout (SYN only)."""
    BYTES[probe] += {"open": TCP_SYN * 2 + TCP_SEG + TCP_RST, "rst": TCP_SYN + TCP_RST, "timeout": TCP_SYN}[outcome]


def tcp_dns(probe: str, query: int, reply: int | None) -> None:
    b = TCP_SYN * 2 + TCP_SEG + (TCP_SEG + 2 + query) + TCP_RST
    if reply is not None:
        b += TCP_SEG + (TCP_SEG + 2 + reply)  # ACK of the query + the answer
    BYTES[probe] += b


def icmp(probe: str, payload: int, replied: bool) -> None:
    BYTES[probe] += (ICMP + payload) * (2 if replied else 1)
