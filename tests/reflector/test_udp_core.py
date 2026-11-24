import random

import pytest

from whydrop.proto.mac import hmac8
from whydrop.proto.wd import WdPacket, WdType, decode, encode
from whydrop.reflector.replay import Tombstones
from whydrop.reflector.udp import UdpReflector

S = b"s" * 32
EPOCH = 0x1234
A = ("192.0.2.10", 40000)
P = WdPacket(WdType.PROBE, 1, 1, 0)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def mk_clock():
    c = Clock()
    return UdpReflector(S, epoch=EPOCH, tombstones=Tombstones(None), clock=c), c


def mk():
    return mk_clock()[0]  # frozen clock unless the test advances it


def probe(sid, seq):
    return encode(WdPacket(WdType.PROBE, sid, seq, 777), S)


def natreq(sid, seq, delay):
    return encode(WdPacket(WdType.NAT_REQ, sid, seq, 888, arg=delay), S)


def test_probe_echo_fields():
    r = mk()
    [e] = r.handle(probe(sid=1, seq=1), A)
    p = decode(e, S)
    assert (p.type, p.session_id, p.seq, p.t_send_ns, p.recv_count, p.epoch) == (WdType.ECHO, 1, 1, 777, 1, EPOCH)
    assert len(e) == 44


def test_rx_bitmap():  # seqs 1, 2, 4 received, then 5
    r = mk()
    for s in (1, 2, 4):
        r.handle(probe(1, s), A)
    p = decode(r.handle(probe(1, 5), A)[0], S)
    assert p.rx_bitmap & 0b1111 == 0b1101 and p.recv_count == 4  # bit0=seq4, bit1=seq3 (missing), bit2=seq2, bit3=seq1


def test_echo_arg_carries_reflector_drops():
    r = mk()
    r.rxq_ovfl = 5
    assert decode(r.handle(probe(1, 1), A)[0], S).arg == 5


def test_duplicate_no_reply():
    r = mk()
    r.handle(probe(1, 1), A)
    assert r.handle(probe(1, 1), A) == [] and r.drops["replay"] == 1


@pytest.mark.parametrize("t", [WdType.ECHO, WdType.NAT_REPLY])
def test_inbound_reply_types_dropped(t):  # a valid reply sent back to us must not reflect
    r = mk()
    assert r.handle(encode(WdPacket(t, 1, 1, 0), S), A) == [] and r.drops["bad_type"] == 1


def test_bad_hmac_no_reply():
    r = mk()
    assert r.handle(encode(P, b"z" * 32), A) == [] and r.drops["bad_hmac"] == 1
    assert len(r.sessions) == 0  # no state before the MAC verifies


def test_reply_never_larger():
    r, clk = mk_clock()
    out = r.handle(probe(1, 1), A) + r.handle(natreq(2, 1, 10), A)
    clk.t += 10
    out += [pkt for _, pkt in r.due()]
    assert len(out) == 3 and all(len(x) <= 44 for x in out)  # ECHO, immediate and delayed NAT_REPLY


def test_nat_immediate_then_delayed():
    r, clk = mk_clock()
    [im] = r.handle(natreq(1, 1, 10), A)
    assert decode(im, S).type == WdType.NAT_REPLY and decode(im, S).arg == 0
    clk.t += 9.9
    assert r.due() == []
    clk.t += 0.2
    [(addr, d)] = r.due()
    assert addr == A and decode(d, S).arg == 1 and decode(d, S).seq == 1
    assert r.due() == []  # removed once returned


def test_nat_replace_restarts_delay():
    r, clk = mk_clock()
    r.handle(natreq(1, 1, 10), A)
    clk.t += 3
    r.handle(natreq(1, 2, 10), A)
    clk.t += 8
    assert r.due() == []
    clk.t += 2.1
    [(_, d)] = r.due()
    assert decode(d, S).seq == 2


def test_nat_bad_delay():
    r = mk()
    assert r.handle(natreq(1, 1, 11), A) == [] and r.drops["nat_delay"] == 1


def test_nat_cap_per_ip():
    r = mk()
    for sid in range(16):
        r.handle(natreq(sid, 1, 600), A)
    assert r.handle(natreq(99, 1, 600), A) == [] and r.drops["nat_cap"] == 1
    assert len(r.handle(natreq(99, 1, 600), ("192.0.2.11", 1))) == 1  # other IPs unaffected


def test_pre_hmac_rate_limit():
    r = mk()
    junk = encode(P, b"z" * 32)
    for _ in range(250):
        r.handle(junk, A)
    assert r.drops["pre_rate"] == 50 and r.drops["bad_hmac"] == 200


def test_post_hmac_rate_limit():
    r = mk()
    for s in range(1, 61):
        r.handle(probe(1, s), A)
    assert r.drops["post_rate"] == 10


def test_fuzz_never_replies_or_raises():
    r = mk()
    rnd = random.Random(1)
    for _ in range(1000):
        assert r.handle(rnd.randbytes(rnd.randrange(0, 1500)), (f"192.0.2.{rnd.randrange(1, 255)}", 9)) == []
    assert sum(r.drops.values()) == 1000


def test_fuzz_header_valid_bodies():  # random bodies past precheck, with a wrong and with a correct MAC
    r, clk = mk_clock()
    rnd = random.Random(2)
    for i in range(3000):
        body = b"WD\x01" + bytes([rnd.choice((1, 3))]) + rnd.randbytes(32)
        mac = hmac8(S, body) if i % 2 else rnd.randbytes(8)
        clk.t += 0.05  # stay under the post-MAC rate so valid packets reach the session code
        assert all(len(x) == 44 for x in r.handle(body + mac, (f"192.0.2.{i % 250}", 9)))
    assert r.drops["bad_hmac"] == 1500


def test_many_source_ips_memory_bounded():  # spoofed sources must not grow the per-IP buckets without limit
    r = mk()
    assert r._pre._max == r._post._max == 65_536  # about 20 MB at the cap
    r._pre._max = r._post._max = 100  # same eviction path, 100x fewer packets
    junk = encode(P, b"z" * 32)
    for i in range(5000):
        r.handle(junk, (f"2001:db8::{i:x}", 9))  # documentation prefix
    assert len(r._pre.buckets) == 100 and len(r._post.buckets) == 0 and len(r.sessions) == 0
    assert len(r.handle(probe(1, 1), ("2001:db8::ffff", 9))) == 1  # a fresh source is still served


def test_session_idle_sweep():
    r, clk = mk_clock()
    r.handle(probe(1, 1), A)
    clk.t += 86401
    r.sweep()
    assert len(r.sessions) == 0


def test_session_lru_bound():
    r = UdpReflector(S, epoch=1, tombstones=Tombstones(None), clock=Clock(), max_sessions=2)
    for sid in (1, 2, 3):
        r.handle(probe(sid, 1), A)
    assert list(r.sessions) == [2, 3]


def test_tombstone_floor_on_new_instance(tmp_path):
    t = Tombstones(tmp_path / "t.json")
    r = UdpReflector(S, epoch=1, tombstones=t)
    r.handle(probe(7, 5), A)
    t.flush()
    t2 = Tombstones(tmp_path / "t.json")
    t2.load()
    r2 = UdpReflector(S, epoch=2, tombstones=t2)
    assert r2.handle(probe(7, 5), A) == []
    [e] = r2.handle(probe(7, 6), A)
    assert decode(e, S).epoch == 2


def test_rejected_nat_leaves_no_session():
    r = mk()
    r.handle(natreq(1, 1, 11), A)
    for sid in range(2, 19):  # 17 requests: sids 2..17 fill the per-IP cap of 16, sid 18 is refused
        r.handle(natreq(sid, 1, 600), A)
    assert r.drops["nat_cap"] == 1 and 1 not in r.sessions and 18 not in r.sessions


def test_duplicate_nat_req_does_not_restart_delay():
    r, clk = mk_clock()
    r.handle(natreq(1, 1, 10), A)
    clk.t += 5
    assert r.handle(natreq(1, 1, 10), A) == [] and r.drops["replay"] == 1
    clk.t += 5.1
    assert len(r.due()) == 1


def test_nat_total_cap():
    r = mk()
    for ip in range(64):
        for sid in range(16):
            r.handle(natreq(ip * 100 + sid, 1, 600), (f"198.51.100.{ip}", 1))
    assert r.drops["nat_cap"] == 0
    assert r.handle(natreq(99999, 1, 600), ("203.0.113.1", 1)) == [] and r.drops["nat_cap"] == 1


def test_nat_takeover_counts_against_new_ip():
    r = mk()
    B = ("192.0.2.20", 1)
    for sid in range(16):
        r.handle(natreq(sid, 1, 600), B)
    r.handle(natreq(500, 1, 600), A)
    assert r.handle(natreq(500, 2, 600), B) == [] and r.drops["nat_cap"] == 1


def test_evicted_session_keeps_replay_floor():
    t = Tombstones(None)
    r = UdpReflector(S, epoch=1, tombstones=t, clock=Clock(), max_sessions=1)
    r.handle(probe(1, 5), A)
    r.handle(probe(2, 1), A)
    assert 1 not in r.sessions
    assert r.handle(probe(1, 5), A) == [] and len(r.handle(probe(1, 6), A)) == 1
