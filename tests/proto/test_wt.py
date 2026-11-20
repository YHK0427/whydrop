import pytest

from whydrop.proto.wt import (
    Frame, FrameType, Hello, Role, WtError, WtType,
    decode_frame, decode_hello, decode_hello_ok, decode_nonce, decode_short,
    encode_frame, encode_hello, encode_hello_ok, encode_nonce, encode_short, valid_param,
)

S = b"s" * 32
N = bytes(range(16))
AN = b"\xaa" * 8
H = Hello(Role.HOT, 0x01020304, 0, AN)


def test_sizes():
    assert len(encode_nonce(N)) == 20 and len(encode_hello(H, S, N)) == 30
    assert len(encode_hello_ok(9, S, AN)) == 16 and len(encode_short(WtType.BUSY)) == 4
    assert len(encode_frame(Frame(FrameType.HB, 0, 1, 2))) == 16


def test_nonce_roundtrip():
    assert decode_nonce(encode_nonce(N)) == N


def test_hello_roundtrip():
    assert decode_hello(encode_hello(H, S, N), S, N) == H


def test_hello_bound_to_nonce():  # replaying a HELLO under a fresh nonce fails
    with pytest.raises(WtError, match="hmac"):
        decode_hello(encode_hello(H, S, N), S, b"\x01" * 16)


def test_hello_wrong_secret():
    with pytest.raises(WtError) as e:
        decode_hello(encode_hello(H, b"z" * 32, N), S, N)
    assert e.value.reason == "hmac"


def test_hello_version_checked_before_hmac():
    b = bytearray(encode_hello(H, S, N)); b[2] = 9
    with pytest.raises(WtError) as e:
        decode_hello(bytes(b), S, N)
    assert e.value.reason == "version"


def test_hello_ok_bound_to_anonce():
    b = encode_hello_ok(9, S, AN)
    assert decode_hello_ok(b, S, AN) == 9
    with pytest.raises(WtError, match="hmac"):
        decode_hello_ok(b, S, b"\x02" * 8)


def test_short_types():
    assert decode_short(encode_short(WtType.VERSION)) == WtType.VERSION
    with pytest.raises(WtError) as e:
        decode_short(b"WT\x01\x09")
    assert e.value.reason == "type"


def test_frame_roundtrip():
    f = Frame(FrameType.IDLE_PING, 0, 0xFFFFFFFF, 2**63)
    assert decode_frame(encode_frame(f)) == f


@pytest.mark.parametrize("role,p,ok7500,expected", [
    (Role.HOT, 0, False, True), (Role.HOT, 5, False, False),
    (Role.IDLE, 29, False, False), (Role.IDLE, 30, False, True), (Role.IDLE, 7500, False, True),
    (Role.IDLE, 7501, False, False),
    (Role.NAT, 61, False, False), (Role.NAT, 60, False, True),
    (Role.NAT, 7500, False, False), (Role.NAT, 7500, True, True),
])
def test_valid_param(role, p, ok7500, expected):
    assert valid_param(role, p, enable_7500=ok7500) is expected
