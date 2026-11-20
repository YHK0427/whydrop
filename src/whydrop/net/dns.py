"""Hand-built DNS over UDP and TCP (RFC 1035): just enough to ask and to judge the answer."""
import struct
from dataclasses import dataclass

_HDR = struct.Struct("!HHHHHH")
MAX_JUMPS = 32


@dataclass(frozen=True)
class DnsReply:
    qid: int
    rcode: int
    truncated: bool
    answers: tuple[bytes, ...]  # raw RDATA of each answer


def build_query(qid: int, name: str, qtype: int = 1, qclass: int = 1) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split("."))
    return _HDR.pack(qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", qtype, qclass)  # RD=1


def _skip_name(data: bytes, off: int) -> int:
    """Returns the offset after a (possibly compressed) name at `off`; validates pointers."""
    jumps, end = 0, None
    while True:
        if off >= len(data):
            raise ValueError("name runs past the message")
        n = data[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise ValueError("truncated pointer")
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            jumps += 1
            if jumps > MAX_JUMPS:
                raise ValueError("name pointer loop")
            continue
        if n == 0:
            return end if end is not None else off + 1
        off += 1 + n


def parse_reply(data: bytes) -> DnsReply:
    if len(data) < _HDR.size:
        raise ValueError("short DNS message")
    qid, flags, qd, an, _, _ = _HDR.unpack_from(data)
    off = _HDR.size
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    answers = []
    for _ in range(an):
        off = _skip_name(data, off)
        if off + 10 > len(data):
            raise ValueError("truncated answer")
        rdlen = struct.unpack_from("!H", data, off + 8)[0]
        off += 10
        if off + rdlen > len(data):
            raise ValueError("truncated rdata")
        answers.append(data[off:off + rdlen])
        off += rdlen
    return DnsReply(qid, flags & 0x000F, bool(flags & 0x0200), tuple(answers))


def is_success(reply: DnsReply, qid: int) -> bool:
    return reply.qid == qid and reply.rcode in (0, 3)  # NOERROR or NXDOMAIN; SERVFAIL/REFUSED fail


def txt_strings(rdata: bytes) -> list[str]:
    out, off = [], 0
    while off < len(rdata):
        n = rdata[off]
        out.append(rdata[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    return out


def tcp_frame(msg: bytes) -> bytes:
    return len(msg).to_bytes(2, "big") + msg


def tcp_unframe(buf: bytes) -> bytes | None:
    if len(buf) < 2:
        return None
    n = int.from_bytes(buf[:2], "big")
    return buf[2:2 + n] if len(buf) >= 2 + n else None
