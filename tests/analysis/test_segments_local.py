from scen import T0, Scenario
from whydrop.analysis.segments import Segments


def run(s: Scenario, **ctx):
    seg = Segments(s.ctx(**ctx))
    changes = [c for f in s.frames() for c in seg.step(f)]
    return seg, changes


def downs(changes, segment):
    return [((c.t_ms - T0) // 1000, c.state) for c in changes if c.segment == segment]


def test_host_net_needs_3s():
    _, ch = run(Scenario.default(30).fail(5, 7, probes={"host_net"}))
    assert downs(ch, "host_net") == []
    _, ch = run(Scenario.default(30).fail(5, 9, probes={"host_net"}))
    assert downs(ch, "host_net") == [(5, "down"), (9, "up")]  # start back-dated; end = first good second


def test_reassoc_is_wifi_down_roam_is_not():
    s = Scenario.default(40).event("roam", 5).fail(20, 24, probes={"wifi"}).event("reassoc", 20)
    _, ch = run(s)
    assert downs(ch, "wifi") == [(20, "down"), (24, "up")]


def test_reassoc_event_alone_is_down_until_held_up():
    _, ch = run(Scenario.default(30).event("reassoc", 10))
    assert downs(ch, "wifi") == [(10, "down"), (11, "up")]


def test_link_flap_wired():
    s = Scenario.default(30, link_kind="wired").event("link_flap", 8)
    _, ch = run(s)
    assert downs(ch, "link") == [(8, "down"), (9, "up")]


def test_lan_two_misses():
    _, ch = run(Scenario.default(30).fail(10, 11, probes={"gateway"}))
    assert downs(ch, "lan") == []
    _, ch = run(Scenario.default(30).fail(10, 14, probes={"gateway"}))
    assert downs(ch, "lan") == [(10, "down"), (14, "up")]


def test_lan_unobservable():
    seg, ch = run(Scenario.default(30).fail(10, 14, probes={"gateway"}), lan_observable=False)
    assert downs(ch, "lan") == [(0, "unobservable")] and seg.state("lan") == "unobservable"


def test_lan_not_judged_while_wifi_down():
    s = Scenario.default(40).fail(10, 20, probes={"wifi", "gateway"})
    seg, ch = run(s)
    assert downs(ch, "wifi") == [(10, "down"), (20, "up")] and downs(ch, "lan") == []


def test_lag_seconds_dont_count_as_misses():
    _, ch = run(Scenario.default(30).fail(10, 14, probes={"gateway"}).lag(9, 15))
    assert downs(ch, "lan") == []
