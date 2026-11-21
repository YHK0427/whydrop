from scen import T0, Scenario
from whydrop.agent.events import Event
from whydrop.analysis import texts
from whydrop.analysis.causes import Settler, classify, protocol_paragraph
from whydrop.analysis.conditions import Conditions
from whydrop.analysis.incidents import Incidents
from whydrop.analysis.segments import Segments

ROUTER, ISP = "dns_router:192.0.2.1:53/udp", "dns_isp:198.51.100.53:53/udp"
PUBLIC = {"dns_public:1.1.1.1:53/udp", "dns_public:8.8.8.8:53/udp"}


def run(s: Scenario, **ctx):
    c = s.ctx(**ctx)
    seg, cond, inc, settle = Segments(c), Conditions(c), Incidents(c), Settler(c)
    frames, finals, closed = s.frames(), [], []
    for f in frames:
        changes = inc.step(f, seg.step(f), cond.step(f, seg), seg)
        for ch in changes:
            if ch.op == "close":
                closed.append(ch.incident)
        finals += settle.step(f, changes, frames, cond)
    return closed, finals, frames, cond


def rules(s, **ctx):
    closed, finals, frames, cond = run(s, **ctx)
    return [f.cause.rule for f in finals]


def test_r1a_reassoc():           # scenario 3: 4 s re-association with good signal
    s = Scenario.default(200).event("reassoc", 30).fail(30, 34, probes={"wifi", "gateway"}).internet_down(30, 34)
    assert rules(s) == ["R1a"]


def test_r1c_link_flap():
    s = Scenario.default(200, link_kind="wired").event("link_flap", 30).internet_down(30, 35)
    assert rules(s, link_kind="wired") == ["R1c"]


def test_r1d_host_net():          # scenario 17
    s = Scenario.default(200).fail(30, 40, probes={"host_net"}).internet_down(30, 40, kind="local_fail")
    assert rules(s) == ["R1d"]


def test_r1b_router():
    s = Scenario.default(200).fail(30, 40, probes={"gateway"}).internet_down(30, 40)
    assert rules(s) == ["R1b"]


def test_r1b_not_with_unknown_link():
    s = Scenario.default(200).fail(30, 40, probes={"gateway"}).internet_down(30, 40)
    assert rules(s, link_kind="unknown") != ["R1b"]


def test_r2_line_with_direction():  # scenario 2 (precision): direction added after settle
    s = Scenario.default(260, mode="precision").internet_down(30, 76)
    s.event("udp_outage", 77, pair="reflector", from_seq=300, to_seq=760, lost_up=460, lost_down=0, status="ok")
    closed, finals, _, _ = run(s)
    [f] = finals
    assert f.cause.rule == "R2" and f.cause.evidence["direction"] == "upload"


def test_r3_router_dns():
    assert rules(Scenario.default(200).fail(30, 60, pairs={ROUTER})) == ["R3"]


def test_r3_kinds():
    _, finals, _, _ = run(Scenario.default(200).fail(30, 60, pairs={ISP}))
    assert "ISP DNS" in finals[0].cause.label
    _, finals, _, _ = run(Scenario.default(200).fail(30, 60, pairs={ROUTER, ISP}))
    assert "ISP DNS outage" in finals[0].cause.label     # scenario 7: ISP DNS out, reached via the router
    _, finals, _, _ = run(Scenario.default(200).fail(30, 60, pairs=PUBLIC))
    assert "public resolvers blocked" in finals[0].cause.label.lower()
    _, finals, _, _ = run(Scenario.default(200).fail(30, 60, pairs={ROUTER} | PUBLIC))
    assert "DNS-wide" in finals[0].cause.label


def test_r3_public_blocked_precision():  # scenario 20
    _, finals, _, _ = run(Scenario.default(300, mode="precision").fail(30, 120, pairs=PUBLIC))
    assert [f.cause.rule for f in finals] == ["R3"] and "public resolvers blocked" in finals[0].cause.label.lower()


def test_r4_point_ip_change():
    assert rules(Scenario.default(200).event("ip_change", 50)) == ["R4"]


def test_settle_r2_becomes_r4():
    s = Scenario.default(260).internet_down(30, 40).event("ip_change", 70)
    closed, finals, _, _ = run(s)
    [f] = finals
    assert f.cause.rule == "R4" and "R2" in f.cause.secondary and f.changed and f.provisional.rule == "R2"


def test_r5_point():
    s = Scenario.default(200, mode="precision").event("idle_state_lost", 60, interval_s=600, waited_s=605)
    assert rules(s) == ["R5"]


def test_r7_via_late_replies():     # scenario 6: saturated uplink, queueing 1.5–3 s
    s = Scenario.default(200).internet_down(30, 36, kind="late")
    assert rules(s) == ["R7"]


def test_queueing_first_before_r2():
    s = Scenario.default(4000).slow(3700, 3720, probes={"tcp_connect", "stun", "line_hb"}, rtt=400.0)
    s.internet_down(3720, 3725)
    assert rules(s) == ["R7"]


def test_every_cause_says_likely():
    for rule, (label, step) in texts.CAUSES.items():
        assert "likely" in label, rule
    for label in texts.R3_LABELS.values():
        assert "likely" in label
    assert "likely" in texts.ROUTER_RESTART and "likely" in texts.IN_HOME_QUEUEING


def test_protocol_paragraph_example():
    s = Scenario.default(260, mode="precision").internet_down(30, 76)
    s.event("udp_outage", 77, pair="reflector", from_seq=1201, to_seq=1660, lost_up=459, lost_down=0, status="ok")
    s.event("stall", 33, pair="reflector", phase="start", canary="hot")
    for i, rto in enumerate((200, 400, 800, 1600, 3200)):
        s.event("tcp_info", 34 + i, pair="reflector", rto_ms=rto, retransmits=i + 1, canary="hot")
    s.event("stall", 77, pair="reflector", phase="end", duration_s=44.0, canary="hot")
    closed, finals, frames, _ = run(s)
    text = protocol_paragraph(closed[0])
    assert "seq 1201–1660" in text and "all lost upstream" in text and "0.2 → 3.2 s" in text and "no RST" in text
