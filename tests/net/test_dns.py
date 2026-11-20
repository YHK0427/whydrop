import struct

import pytest

from whydrop.net.dns import build_query, is_success, parse_reply, tcp_frame, tcp_unframe, txt_strings


def answer(qid, rcode=0, rdata=b"\x5d\xb8\xd7\x0e", qtype=1, flags=0x8180):
    q = build_query(qid, "example.com", qtype)[12:]
    hdr = struct.pack("!HHHHHH", qid, flags | rcode, 1, 1, 0, 0)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(rdata)) + rdata  # name = pointer to the question
    return hdr + q + rr


def test_query_bytes():
    assert build_query(0x1234, "example.com") == bytes.fromhex(
        "123401000001000000000000") + b"\x07example\x03com\x00" + bytes.fromhex("00010001")


def test_parse_compressed_answer():
    r = parse_reply(answer(7))
    assert r.qid == 7 and r.rcode == 0 and not r.truncated and r.answers == (b"\x5d\xb8\xd7\x0e",)


def test_rejects_wrong_id_and_source():
    r = parse_reply(answer(7))
    assert is_success(r, 7) and not is_success(r, 8)


def test_servfail_is_failure_nxdomain_is_success():
    assert not is_success(parse_reply(answer(7, rcode=2, rdata=b"")), 7)
    assert is_success(parse_reply(answer(7, rcode=3, rdata=b"")), 7)
    assert not is_success(parse_reply(answer(7, rcode=5, rdata=b"")), 7)


def test_pointer_loop_raises():
    hdr = struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0)
    loop = b"\xc0\x0c"  # an answer whose name points at itself
    with pytest.raises(ValueError):
        parse_reply(hdr + loop + struct.pack("!HHIH", 1, 1, 1, 0))


def test_truncated_raises():
    with pytest.raises(ValueError):
        parse_reply(answer(7)[:-2])


def test_txt_strings():
    assert txt_strings(b"\x03abc\x02de") == ["abc", "de"]


def test_tcp_frame_roundtrip_and_partial():
    m = build_query(9, "example.com")
    framed = tcp_frame(m)
    assert framed[:2] == len(m).to_bytes(2, "big")
    assert tcp_unframe(framed[:5]) is None
    assert tcp_unframe(framed) == m


def test_chaos_and_txt_query():
    q = build_query(1, "id.server", qtype=16, qclass=3)
    assert q.endswith(b"\x00\x10\x00\x03")


def test_query_echo_is_not_success():  # a reflected query (QR=0) must not count as an answer
    assert not is_success(parse_reply(answer(7, flags=0x0100)), 7)


def test_bad_names_rejected():
    for bad in ("", "a" * 64 + ".com", "a..b"):
        with pytest.raises(ValueError):
            build_query(1, bad)
