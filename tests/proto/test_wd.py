import pytest

from whydrop.proto.wd import WD_LEN, WdError, WdPacket, WdType, decode, encode, precheck

S = b"s" * 32
P = WdPacket(WdType.PROBE, 1, 2, 3)


def test_roundtrip_and_size():
    p = WdPacket(WdType.ECHO, 0xDEADBEEF, 7, 123456789, recv_count=5, epoch=9, rx_bitmap=0b101, arg=3)
    b = encode(p, S)
    assert len(b) == WD_LEN == 44 and b[:2] == b"WD" and b[2] == 1 and b[3] == 2
    assert decode(b, S) == p


def test_field_offsets():  # big-endian, offsets per the spec table
    b = encode(WdPacket(WdType.PROBE, 1, 2, 3, 4, 5, 6, 7), S)
    assert b[4:8] == (1).to_bytes(4, "big") and b[8:12] == (2).to_bytes(4, "big")
    assert b[12:20] == (3).to_bytes(8, "big") and b[20:24] == (4).to_bytes(4, "big")
    assert b[24:28] == (5).to_bytes(4, "big") and b[28:32] == (6).to_bytes(4, "big")
    assert b[32:36] == (7).to_bytes(4, "big")


@pytest.mark.parametrize("mut,reason", [
    (lambda b: b[:43], "len"),
    (lambda b: b + b"\x00", "len"),
    (lambda b: b"XX" + b[2:], "magic"),
    (lambda b: b[:2] + b"\x02" + b[3:], "version"),
    (lambda b: b[:3] + b"\x09" + b[4:], "type"),
    (lambda b: b[:-1] + bytes([b[-1] ^ 1]), "hmac"),
    (lambda b: b[:12] + bytes([b[12] ^ 1]) + b[13:], "hmac"),
])
def test_rejects(mut, reason):
    with pytest.raises(WdError) as e:
        decode(mut(encode(P, S)), S)
    assert e.value.reason == reason


def test_precheck_no_hash_needed():
    assert precheck(b"\x00" * 10) == "len"
    assert precheck(encode(P, S)) is None


def test_wrong_secret():
    with pytest.raises(WdError, match="hmac"):
        decode(encode(P, S), b"z" * 32)
