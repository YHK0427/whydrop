"""L0 audit: boundaries and hostile input for every hand-written codec. A decoder facing the internet may refuse
anything, but only with its own error type (or None), never with another exception, and never by hanging."""
import random
import struct

import pytest

from whydrop.measure.direction import Echo, packet_direction
from whydrop.net.dns import build_query, parse_reply, tcp_frame, tcp_unframe
from whydrop.net.stun import build_binding, parse_binding_response
from whydrop.proto.wd import WD_LEN, WdError, WdPacket, WdType, decode, encode
from whydrop.proto.wt import (Frame, FrameType, Hello, Role, WtError, decode_frame, decode_hello, decode_hello_ok,
                              decode_nonce, decode_short, encode_frame, encode_hello, encode_hello_ok)

S = b"s" * 32
RNG = random.Random(20261124)          # fixed: a failure reproduces
U32, U64 = 2**32 - 1, 2**64 - 1


def blobs(n=3000, top=80):
    yield b""
    for _ in range(n):
        yield RNG.randbytes(RNG.randint(0, top))


# ---------- WD ----------
def test_wd_every_single_bit_flip_is_refused():
    good = encode(WdPacket(WdType.ECHO, 1, 2, 3, 4, 5, 6, 7), S)
    for i in range(WD_LEN * 8):
        bad = bytearray(good)
        bad[i // 8] ^= 1 << (i % 8)
        with pytest.raises(WdError):
            decode(bytes(bad), S)


def test_wd_largest_values_round_trip():
    p = WdPacket(WdType.NAT_REPLY, U32, U32, U64, U32, U32, U32, U32)
    assert decode(encode(p, S), S) == p


def test_wd_empty_and_random_input_only_raise_wd_error():
    for b in blobs(top=60):
        with pytest.raises(WdError):
            decode(b, S)
    for _ in range(2000):                                   # right length, valid head: still only WdError
        b = b"WD\x01" + bytes([RNG.randint(1, 4)]) + RNG.randbytes(WD_LEN - 4)
        with pytest.raises(WdError):
            decode(b, S)


# ---------- WT ----------
def test_wt_random_input_only_raises_wt_error():
    for b in blobs():
        for fn in (lambda x: decode_hello(x, S, bytes(16)), lambda x: decode_hello_ok(x, S, b"\xaa" * 8),
                   decode_nonce, decode_short, decode_frame):
            try:
                fn(b)
            except WtError:
                pass


def test_wt_head_magic_and_version_are_checked():
    good = encode_hello(Hello(Role.HOT, 1, 0, b"\xaa" * 8), S, bytes(16))
    with pytest.raises(WtError, match="magic"):
        decode_hello(b"XX" + good[2:], S, bytes(16))
    with pytest.raises(WtError, match="version"):
        decode_hello(good[:2] + b"\x09" + good[3:], S, bytes(16))
    ok = encode_hello_ok(7, S, b"\xaa" * 8)
    with pytest.raises(WtError, match="hmac"):
        decode_hello_ok(ok[:-1] + bytes([ok[-1] ^ 1]), S, b"\xaa" * 8)


def test_wt_frame_largest_values_round_trip():
    f = Frame(FrameType.HB, 0xFF, U32, U64)
    assert decode_frame(encode_frame(f)) == f


# ---------- DNS ----------
def _reply(qid=7):
    q = build_query(qid, "example.com")[12:]
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + b"\x5d\xb8\xd7\x0e"
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + q + rr


@pytest.mark.parametrize("data,why", [
    (b"\x00" * 11, "short"),
    (_reply()[:12] + b"\x07example", "past"),                    # the question's name runs off the end
    (_reply()[:-14] + b"\xc0", "pointer"),                       # an answer name cut inside its pointer
    (_reply()[:-12], "answer"),                                  # the fixed answer fields cut short
    (_reply()[:-2], "rdata"),
])
def test_dns_each_truncation_is_a_value_error(data, why):
    with pytest.raises(ValueError):
        parse_reply(data)


def test_dns_random_and_mutated_replies_only_raise_value_error():
    good = _reply()
    for b in blobs(top=120):
        try:
            parse_reply(b)
        except ValueError:
            pass
    for _ in range(3000):                                   # flip bytes of a real reply: counts, lengths, pointers
        b = bytearray(good)
        for _ in range(RNG.randint(1, 4)):
            b[RNG.randrange(len(b))] = RNG.randrange(256)
        try:
            parse_reply(bytes(b))
        except ValueError:
            pass


def test_dns_huge_counts_on_a_tiny_message_end_quickly():
    with pytest.raises(ValueError):
        parse_reply(struct.pack("!HHHHHH", 1, 0x8180, 65535, 65535, 0, 0))


def test_dns_tcp_length_split_across_reads():
    msg = _reply()
    framed = tcp_frame(msg)
    assert tcp_unframe(b"") is None and tcp_unframe(framed[:1]) is None and tcp_unframe(framed[:-1]) is None
    assert tcp_unframe(framed) == msg and tcp_unframe(framed + b"next") == msg


# ---------- STUN ----------
TX = bytes(range(12))


def _stun(attr_type, value, txid=TX):
    body = struct.pack("!HH", attr_type, len(value)) + value + b"\x00" * (-len(value) % 4)
    return struct.pack("!HHI12s", 0x0101, len(body), 0x2112A442, txid) + body


def test_stun_ipv6_mapping_is_not_misread_as_ipv4():
    v6 = b"\x00\x02" + (0x1234).to_bytes(2, "big") + bytes(16)
    assert parse_binding_response(_stun(0x0020, v6), TX) is None


def test_stun_length_field_longer_than_the_message_is_refused():
    msg = _stun(0x0020, b"\x00\x01" + bytes(6))
    assert parse_binding_response(msg[:2] + (len(msg)).to_bytes(2, "big") + msg[4:], TX) is None


def test_stun_random_input_never_raises():
    for b in blobs(top=100):
        assert parse_binding_response(b, TX) in (None,) or isinstance(parse_binding_response(b, TX), tuple)
    for _ in range(2000):                                   # right header and txid, random attributes
        body = RNG.randbytes(RNG.randint(0, 60))
        msg = struct.pack("!HHI12s", 0x0101, len(body), 0x2112A442, TX) + body
        r = parse_binding_response(msg, TX)
        assert r is None or (isinstance(r, tuple) and 0 <= r[1] <= 65535)


def test_stun_request_is_twenty_bytes_whatever_the_txid():
    assert all(len(build_binding(RNG.randbytes(12))) == 20 for _ in range(10))


# ---------- direction ----------
def test_direction_bit_for_each_distance():
    for gap in range(1, 33):                                # bit gap-1 of the later ECHO is seq's
        assert packet_direction(100, [Echo(100 + gap, 0, 1, 1 << (gap - 1))]) == "down"
        assert packet_direction(100, [Echo(100 + gap, 0, 1, U32 ^ (1 << (gap - 1)))]) == "up"
    assert packet_direction(100, [Echo(133, 0, 1, U32)]) == "unknown"       # 33 behind: outside the bitmap
    assert packet_direction(100, [Echo(100, 0, 1, U32)]) == "unknown"       # not later
