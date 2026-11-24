"""L2 audit: the DNS interception check on the report card, against fake resolver answers."""
import asyncio
import struct

from whydrop.agent import report
from whydrop.net.dns import build_query


def txt_answer(query: bytes, *strings: str, rcode=0, qid_delta=0) -> bytes:
    qid = int.from_bytes(query[:2], "big") + qid_delta
    rdata = b"".join(bytes([len(s)]) + s.encode() for s in strings)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata
    return struct.pack("!HHHHHH", qid & 0xFFFF, 0x8180 | rcode, 1, 1, 0, 0) + query[12:] + rr


def run_with(monkeypatch, answer_for):
    """answer_for(server, query) -> bytes | None; `match` is applied as udp_exchange would."""
    async def fake(addr, data, timeout_s, *, match, **kw):
        reply = answer_for(addr[0], data)
        return (reply if reply is not None and match(reply, addr) else None), 1.0, {}
    monkeypatch.setattr(report, "udp_exchange", fake)
    return asyncio.run(report.dns_interception())


def test_real_answers_are_ok(monkeypatch):
    got = run_with(monkeypatch, lambda s, q: txt_answer(q, "icn06") if s == "1.1.1.1" else txt_answer(q, "74.125.1.2"))
    assert got == {"verdict": "ok"}


def test_a_middlebox_answering_for_cloudflare_is_suspect(monkeypatch):
    got = run_with(monkeypatch, lambda s, q: txt_answer(q, "dnsmasq-2.89") if s == "1.1.1.1" else None)
    assert got == {"verdict": "suspect"}


def test_no_answer_garbage_wrong_id_or_servfail_say_unknown_not_suspect(monkeypatch):
    for bad in (lambda s, q: None, lambda s, q: b"\x00\x01garbage", lambda s, q: txt_answer(q, "zzz", qid_delta=1),
                lambda s, q: txt_answer(q, "x", rcode=2)):
        assert run_with(monkeypatch, bad) == {"verdict": "unknown"}


def test_only_the_verdict_is_kept_never_the_strings(monkeypatch):
    got = run_with(monkeypatch, lambda s, q: txt_answer(q, "secret-resolver-name"))
    assert set(got) == {"verdict"}


def test_the_queries_are_txt_with_chaos_for_cloudflare(monkeypatch):
    seen = {}
    run_with(monkeypatch, lambda s, q: seen.setdefault(s, q) and None)
    assert seen["1.1.1.1"][-4:] == struct.pack("!HH", 16, 3) and seen["8.8.8.8"][-4:] == struct.pack("!HH", 16, 1)
    assert seen["1.1.1.1"][12:-4] == build_query(0, "id.server")[12:-4]
