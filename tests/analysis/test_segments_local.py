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
    dead_router = Scenario.default(30).fail(10, 14, probes={"gateway"}).internet_down(10, 14)         .fail(10, 14, pairs={"dns_router:192.0.2.1:53/udp"})          # a dead router doesn't answer DNS either
    _, ch = run(dead_router)
    assert downs(ch, "lan") == [(10, "down"), (14, "up")]


def test_gateway_timeouts_while_the_internet_answers_are_not_a_router_drop():
    """Measured on a Wi-Fi home server: the gateway check timed out twice while line probes still answered
    through the router (600 ms RTT) — a latency spike, not a router outage."""
    _, ch = run(Scenario.default(30).fail(10, 14, probes={"gateway"}))
    assert downs(ch, "lan") == []


def test_late_replies_through_the_router_are_not_a_router_drop():
    """Measured: for 7 s everything came back after its timeout (Wi-Fi queueing, 0.5-1.2 s) and the gateway check,
    which doesn't record late replies, counted as lost. A late reply still crossed the router."""
    s = Scenario.default(30).fail(10, 17, probes={"gateway"}).fail(10, 17, probes={"line_hb", "stun", "dns", "tcp_connect"},
                                                                     kind="late")
    _, ch = run(s)
    assert downs(ch, "lan") == []


def test_lan_unobservable():
    seg, ch = run(Scenario.default(30).fail(0, 30, probes={"gateway"}), lan_observable=False)
    assert downs(ch, "lan") == [(0, "unobservable")] and seg.state("lan") == "unobservable"


def test_lan_not_judged_while_wifi_down():
    s = Scenario.default(40).fail(10, 20, probes={"wifi", "gateway"})
    seg, ch = run(s)
    assert downs(ch, "wifi") == [(10, "down"), (20, "up")] and downs(ch, "lan") == []


def test_lag_seconds_dont_count_as_misses():
    _, ch = run(Scenario.default(30).fail(10, 14, probes={"gateway"}).lag(9, 15))
    assert downs(ch, "lan") == []


def test_unobservable_lan_rearms_when_the_gateway_answers():
    seg, ch = run(Scenario.default(60).fail(0, 30, probes={"gateway"}), lan_observable=False)
    assert downs(ch, "lan") == [(0, "unobservable"), (30, "up")] and seg.state("lan") == "up"


def test_local_segment_never_up_never_goes_down():
    """A Wi-Fi probe that never once saw the link up (no adapter, wired host) is no evidence of a Wi-Fi outage."""
    _, ch = run(Scenario.default(120).fail(0, 120, probes={"wifi"}))
    assert downs(ch, "wifi") == []


def test_wifi_rows_all_failing_still_lets_line_drops_through():
    from whydrop.analysis.engine import Engine
    s = Scenario.default(400).fail(0, 400, probes={"wifi"}).internet_down(200, 260)
    eng = Engine(s.ctx(link_kind="unknown"))
    finals = [c for f in s.frames() for c in eng.step(f) if c.type == "final"]
    assert [f.cause.rule for f in finals] == ["R2"]


def test_down_segment_whose_probe_stops_goes_stale():
    s = Scenario.default(200).fail(10, 20, probes={"wifi"})
    s.streams = [x for x in s.streams if x.probe != "wifi"] + [__import__("scen").Stream("wifi", "wifi", None)]
    frames = s.frames()
    for f in frames[20:]:
        f.samples.pop(("wifi", "wifi"), None)          # the Wi-Fi probe went away (switched to a cable)
    seg = __import__("whydrop.analysis.segments", fromlist=["Segments"]).Segments(s.ctx())
    ch = [c for f in frames for c in seg.step(f)]
    assert downs(ch, "wifi")[0] == (10, "down") and downs(ch, "wifi")[-1][1] == "up" and seg.state("wifi") == "unknown"
