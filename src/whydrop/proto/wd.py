"""WD: the fixed 44-byte UDP packet between agent and reflector (spec §5.3, docs/protocol)."""
import hmac
import struct
from dataclasses import dataclass
from enum import IntEnum

from whydrop.proto.mac import MAC_LEN, hmac8

WD_LEN = 44
WD_MAGIC = b"WD"
WD_VERSION = 1
NAT_DELAYS_S = (10, 20, 30, 45, 60, 90, 120, 180, 300, 600)

_BODY = struct.Struct("!2sBBIIQIIII")  # magic ver type session seq t_send_ns recv_count epoch rx_bitmap arg
assert _BODY.size + MAC_LEN == WD_LEN


class WdType(IntEnum):
    PROBE = 1
    ECHO = 2
    NAT_REQ = 3
    NAT_REPLY = 4


class WdError(ValueError):
    def __init__(self, reason: str):
        super().__init__(f"bad WD packet: {reason}")
        self.reason = reason  # len | magic | version | type | hmac


@dataclass(frozen=True)
class WdPacket:
    type: WdType
    session_id: int
    seq: int
    t_send_ns: int
    recv_count: int = 0
    epoch: int = 0
    rx_bitmap: int = 0
    arg: int = 0


def precheck(data: bytes) -> str | None:
    """Cheap checks that need no hashing; returns the failure reason or None."""
    if len(data) != WD_LEN:
        return "len"
    if data[:2] != WD_MAGIC:
        return "magic"
    if data[2] != WD_VERSION:
        return "version"
    try:
        WdType(data[3])
    except ValueError:
        return "type"
    return None


def encode(p: WdPacket, secret: bytes) -> bytes:
    body = _BODY.pack(WD_MAGIC, WD_VERSION, p.type, p.session_id, p.seq, p.t_send_ns,
                      p.recv_count, p.epoch, p.rx_bitmap, p.arg)
    return body + hmac8(secret, body)


def decode(data: bytes, secret: bytes) -> WdPacket:
    reason = precheck(data)
    if reason:
        raise WdError(reason)
    body = data[:_BODY.size]
    if not hmac.compare_digest(data[_BODY.size:], hmac8(secret, body)):
        raise WdError("hmac")
    _, _, t, sid, seq, t_ns, rc, epoch, bitmap, arg = _BODY.unpack(body)
    return WdPacket(WdType(t), sid, seq, t_ns, rc, epoch, bitmap, arg)
