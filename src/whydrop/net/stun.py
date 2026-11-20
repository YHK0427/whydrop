"""STUN binding request/response (RFC 5389), only what's needed to learn the public IP and port."""
import socket
import struct

COOKIE = 0x2112A442
_HDR = struct.Struct("!HHI12s")
XOR_MAPPED, MAPPED = 0x0020, 0x0001


def build_binding(txid: bytes) -> bytes:
    return _HDR.pack(0x0001, 0, COOKIE, txid)


def _addr(value: bytes, xor: bool) -> tuple[str, int] | None:
    if len(value) < 8 or value[1] != 0x01:  # IPv4 family only
        return None
    port = int.from_bytes(value[2:4], "big")
    ip = int.from_bytes(value[4:8], "big")
    if xor:
        port ^= COOKIE >> 16
        ip ^= COOKIE
    return socket.inet_ntoa(ip.to_bytes(4, "big")), port


def parse_binding_response(data: bytes, txid: bytes) -> tuple[str, int] | None:
    if len(data) < _HDR.size:
        return None
    mtype, mlen, cookie, rx = _HDR.unpack_from(data)
    if mtype != 0x0101 or cookie != COOKIE or rx != txid or len(data) < _HDR.size + mlen:
        return None
    off, end, fallback = _HDR.size, _HDR.size + mlen, None
    while off + 4 <= end:
        atype, alen = struct.unpack_from("!HH", data, off)
        value = data[off + 4:off + 4 + alen]
        if atype == XOR_MAPPED:
            return _addr(value, True)
        if atype == MAPPED:
            fallback = _addr(value, False)
        off += 4 + alen + (-alen % 4)  # attributes are padded to 4 bytes
    return fallback
