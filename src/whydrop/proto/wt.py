"""WT: the TCP handshake and 16-byte frames between agent and reflector (spec §5.3, docs/protocol)."""
import hmac
import struct
from dataclasses import dataclass
from enum import IntEnum

from whydrop.proto.mac import MAC_LEN, hmac8

WT_MAGIC = b"WT"
WT_VERSION = 1
NONCE_LEN, HELLO_LEN, HELLO_OK_LEN, SHORT_LEN, FRAME_LEN = 20, 30, 16, 4, 16
IDLE_RANGE_S = (30, 7500)
NAT_PARAMS_S = (60, 300, 600, 1200, 1800, 3600, 7500)

_HEAD = struct.Struct("!2sBB")                 # magic ver type
_NONCE = struct.Struct("!2sBB16s")
_HELLO = struct.Struct("!2sBBBBII8s")          # + role rsv session_id param_s anonce, then hmac
_HELLO_OK = struct.Struct("!2sBBI")            # + epoch, then hmac
_FRAME = struct.Struct("!BBHIQ")               # type flags rsv seq t_send_ns
assert (_NONCE.size, _HELLO.size + MAC_LEN, _HELLO_OK.size + MAC_LEN, _HEAD.size, _FRAME.size) == \
    (NONCE_LEN, HELLO_LEN, HELLO_OK_LEN, SHORT_LEN, FRAME_LEN)


class WtType(IntEnum):
    NONCE = 1
    HELLO = 2
    HELLO_OK = 3
    AUTH_FAIL = 4
    VERSION = 5
    BUSY = 6


class Role(IntEnum):
    HOT = 1
    IDLE = 2
    NAT = 3


class FrameType(IntEnum):
    HB = 0x10
    HB_ACK = 0x11
    IDLE_PING = 0x20
    IDLE_PONG = 0x21
    NAT_PROBE = 0x30


class WtError(ValueError):
    def __init__(self, reason: str):
        super().__init__(f"bad WT message: {reason}")
        self.reason = reason  # len | magic | version | type | hmac


@dataclass(frozen=True)
class Hello:
    role: Role
    session_id: int
    param_s: int
    anonce: bytes


@dataclass(frozen=True)
class Frame:
    type: FrameType
    flags: int
    seq: int
    t_send_ns: int


_SHORT_TYPES = (WtType.AUTH_FAIL, WtType.VERSION, WtType.BUSY)


def _check_head(b: bytes, size: int, want: tuple[WtType, ...]) -> WtType:
    if len(b) != size:
        raise WtError("len")
    magic, ver, t = _HEAD.unpack_from(b)
    if magic != WT_MAGIC:
        raise WtError("magic")
    if ver != WT_VERSION:
        raise WtError("version")
    if t not in want:
        raise WtError("type")
    return WtType(t)


def _check_mac(expected: bytes, got: bytes) -> None:
    if not hmac.compare_digest(expected, got):
        raise WtError("hmac")


def encode_nonce(nonce: bytes) -> bytes:
    return _NONCE.pack(WT_MAGIC, WT_VERSION, WtType.NONCE, nonce)


def decode_nonce(b: bytes) -> bytes:
    _check_head(b, NONCE_LEN, (WtType.NONCE,))
    return _NONCE.unpack(b)[3]


def encode_hello(h: Hello, secret: bytes, nonce: bytes) -> bytes:
    body = _HELLO.pack(WT_MAGIC, WT_VERSION, WtType.HELLO, h.role, 0, h.session_id, h.param_s, h.anonce)
    return body + hmac8(secret, nonce + body)


def decode_hello(b: bytes, secret: bytes, nonce: bytes) -> Hello:
    _check_head(b, HELLO_LEN, (WtType.HELLO,))
    body = b[:_HELLO.size]
    _check_mac(hmac8(secret, nonce + body), b[_HELLO.size:])
    _, _, _, role, _, sid, param, anonce = _HELLO.unpack(body)
    try:
        return Hello(Role(role), sid, param, anonce)
    except ValueError:
        raise WtError("type") from None


def encode_hello_ok(epoch: int, secret: bytes, anonce: bytes) -> bytes:
    body = _HELLO_OK.pack(WT_MAGIC, WT_VERSION, WtType.HELLO_OK, epoch)
    return body + hmac8(secret, anonce + body)


def decode_hello_ok(b: bytes, secret: bytes, anonce: bytes) -> int:
    _check_head(b, HELLO_OK_LEN, (WtType.HELLO_OK,))
    body = b[:_HELLO_OK.size]
    _check_mac(hmac8(secret, anonce + body), b[_HELLO_OK.size:])
    return _HELLO_OK.unpack(body)[3]


def encode_short(t: WtType) -> bytes:
    if t not in _SHORT_TYPES:
        raise ValueError(f"{t!r} is not a short message")
    return _HEAD.pack(WT_MAGIC, WT_VERSION, t)


def decode_short(b: bytes) -> WtType:
    return _check_head(b, SHORT_LEN, _SHORT_TYPES)


def encode_frame(f: Frame) -> bytes:
    return _FRAME.pack(f.type, f.flags, 0, f.seq, f.t_send_ns)


def decode_frame(b: bytes) -> Frame:
    if len(b) != FRAME_LEN:
        raise WtError("len")
    t, flags, _, seq, t_ns = _FRAME.unpack(b)  # rsv is ignored on receive, sent as 0
    try:
        return Frame(FrameType(t), flags, seq, t_ns)
    except ValueError:
        raise WtError("type") from None


def valid_param(role: Role, param_s: int, *, enable_7500: bool) -> bool:
    if role == Role.HOT:
        return param_s == 0
    if role == Role.IDLE:
        return IDLE_RANGE_S[0] <= param_s <= IDLE_RANGE_S[1]
    return param_s in NAT_PARAMS_S and (param_s != 7500 or enable_7500)
