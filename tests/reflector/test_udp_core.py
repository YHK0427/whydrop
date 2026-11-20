import random

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


def test_inbound_echo_type_dropped():  # a valid ECHO sent back to us must not reflect
    r = mk()
    assert r.handle(encode(WdPacket(WdType.ECHO, 1, 1, 0), S), A) == [] and r.drops["bad_type"] == 1


def test_bad_hmac_no_reply():
    r = mk()
    assert r.handle(encode(P, b"z" * 32), A) == [] and r.drops["bad_hmac"] == 1
    assert len(r.sessions) == 0  # no state before the MAC verifies


def test_reply_never_larger():
    r = mk()
    assert all(len(x) <= 44 for x in r.handle(probe(1, 1), A) + r.handle(natreq(2, 1, 10), A))


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
