from scen import T0, Scenario
from whydrop.analysis.segments import Segments

ROUTER = "dns_router:192.0.2.1:53/udp"


def run(s: Scenario, **ctx):
    seg = Segments(s.ctx(**ctx))
    return seg, [c for f in s.frames() for c in seg.step(f)]


def of(changes, segment):
    return [((c.t_ms - T0) // 1000, c.state) for c in changes if c.segment == segment]


def test_3s_drop_one_line_down():
    _, ch = run(Scenario.default(90).internet_down(30, 33))
    assert of(ch, "line") == [(30, "down"), (33, "up")]


def test_single_provider_failure_is_not_line():
    _, ch = run(Scenario.default(90).fail(30, 60, providers={"google"}))
    assert of(ch, "line") == []


def test_start_backdated_and_end_is_first_success():
    _, ch = run(Scenario.default(90).internet_down(30, 41))
    assert of(ch, "line") == [(30, "down"), (41, "up")]


def test_lossy_gate_suppresses_short_down():
    s = Scenario.default(150).fail(10, 80, probes={"line_hb"}, frac=0.12).internet_down(80, 84)
    _, ch = run(s)
    assert [x for x in of(ch, "line") if x[1] != "burst"] == [] and [x[1] for x in of(ch, "line")] == ["burst"]


def test_lossy_gate_keeps_long_down():
    s = Scenario.default(150).fail(10, 80, probes={"line_hb"}, frac=0.12).internet_down(80, 100)
    _, ch = run(s)
    assert of(ch, "line") == [(80, "down"), (100, "up")]


def test_2s_blackhole_never_double_counted_3s_exactly_once():
    _, ch = run(Scenario.default(90).internet_down(30, 32))
    assert len([x for x in of(ch, "line") if x[1] == "down"]) <= 1
    _, ch = run(Scenario.default(90).internet_down(30, 33))
    assert len([x for x in of(ch, "line") if x[1] == "down"]) == 1


def test_dns_window_after_recovery():
    _, ch = run(Scenario.default(120).internet_down(30, 45))
    assert of(ch, "dns_public") == []


def test_lag_excluded():
    _, ch = run(Scenario.default(90).internet_down(30, 34).lag(29, 35))
    assert of(ch, "line") == []


def test_suspend_excluded():
    _, ch = run(Scenario.default(400).suspend(30, 100).internet_down(100, 110).fail(100, 110, probes={"wifi"}))
    assert [c for c in ch if c.state == "down"] == []  # failures right after waking (resume + 30 s) don't count
    _, ch = run(Scenario.default(400).internet_down(100, 110))
    assert [c.segment for c in ch if c.state == "down"] == ["line"]  # control


def test_router_dns_alone_is_dns_router_not_line():
    _, ch = run(Scenario.default(90).fail(30, 60, pairs={ROUTER}))
    assert of(ch, "line") == [] and of(ch, "dns_router") == [(30, "down"), (60, "up")]


def test_public_dns_class_down_needs_every_pair():
    _, ch = run(Scenario.default(90).fail(30, 60, pairs={"dns_public:8.8.8.8:53/udp"}))
    assert of(ch, "dns_public") == []
    _, ch = run(Scenario.default(90).fail(30, 60, pairs={"dns_public:8.8.8.8:53/udp", "dns_public:1.1.1.1:53/udp"}))
    assert of(ch, "dns_public")[0] == (32, "down") and of(ch, "line") == []


def test_precision_stream_with_partial_loss_blocks_line_down():
    s = Scenario.default(90, mode="precision").fail(30, 34, probes={"line_hb", "stun", "tcp_connect"})
    s.fail(30, 34, probes={"udp_stream"}, frac=0.3)  # 70 % still echoed: the line is up
    _, ch = run(s)
    assert of(ch, "line") == []


def test_precision_blackhole_line_down():
    _, ch = run(Scenario.default(90, mode="precision").internet_down(30, 34))
    assert of(ch, "line") == [(30, "down"), (34, "up")]


def test_queueing_evidence_from_late_replies():
    _, ch = run(Scenario.default(90).internet_down(30, 35, kind="late"))
    [down] = [c for c in ch if c.segment == "line" and c.state == "down"]
    assert down.detail["queueing_evidence"] is True


def test_end_ignores_the_canary():
    s = Scenario.default(120, mode="precision").internet_down(30, 40).fail(40, 45, probes={"canary"})
    _, ch = run(s)
    assert of(ch, "line") == [(30, "down"), (40, "up")]


def test_random_iid_loss_no_false_line_downs():
    """Spec §6.2 gate: random per-send loss must not read as line drops (simulated 0/0/2/0 per hour)."""
    for frac, allowed in ((0.05, 0), (0.10, 0), (0.20, 1), (0.30, 1)):
        s = Scenario.default(1200).fail(0, 1200, probes={"line_hb", "stun", "tcp_connect", "dns"}, frac=frac,
                                        rand=7)
        _, ch = run(s)
        downs = [c for c in ch if c.segment == "line" and c.state == "down"]
        assert len(downs) <= allowed, (frac, len(downs))
