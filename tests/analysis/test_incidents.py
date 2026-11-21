from scen import T0, Scenario
from whydrop.analysis.conditions import Conditions
from whydrop.analysis.incidents import Incident, Incidents
from whydrop.analysis.segments import Segments


def run(s: Scenario, reopen=(), **ctx):
    c = s.ctx(**ctx)
    seg, cond, inc = Segments(c), Conditions(c), Incidents(c, reopen=list(reopen))
    out = []
    for f in s.frames():
        sc = seg.step(f)
        cc = cond.step(f, seg)
        out += inc.step(f, sc, cc, seg)
    return inc, out


def closed(changes):
    return [c.incident for c in changes if c.op == "close"]


def sec(ms):
    return (ms - T0) // 1000


def test_one_line_drop_one_incident():
    inc, ch = run(Scenario.default(120).internet_down(30, 34))
    [i] = closed(ch)
    assert (sec(i.start_ms), sec(i.end_ms), i.segments) == (30, 34, {"line"})


def test_merge_within_10s():
    inc, ch = run(Scenario.default(150).internet_down(30, 34).internet_down(40, 45))
    [i] = closed(ch)[-1:]
    assert len({id(x) for x in closed(ch)}) == 1 and sec(i.start_ms) == 30 and sec(i.end_ms) == 45


def test_not_merged_after_10s():
    _, ch = run(Scenario.default(150).internet_down(30, 34).internet_down(60, 65))
    assert len({id(x) for x in closed(ch)}) == 2


def test_merge_chain_router_restart():
    """Router reboot: Wi-Fi (and the router) gone, Wi-Fi back at 90 s, WAN back at 150 s."""
    s = Scenario.default(260)
    s.fail(10, 90, probes={"wifi", "gateway"}).event("reassoc", 10)
    s.internet_down(10, 150)
    s.fail(90, 100, probes={"gateway"})              # the router still booting after the AP is back
    inc, ch = run(s)
    ids = {id(x) for x in closed(ch)}
    [i] = closed(ch)[-1:]
    assert len(ids) == 1 and "router restart (likely)" in i.chain and {"wifi", "line"} <= i.segments


def test_long_outage_tag():
    _, ch = run(Scenario.default(3800).internet_down(30, 3700))
    [i] = closed(ch)
    assert "long_outage" in i.tags


def test_r5_point_incident():
    s = Scenario.default(120, mode="precision").event("idle_state_lost", 60, interval_s=600, waited_s=605)
    _, ch = run(s)
    [i] = closed(ch)
    assert i.point == "idle_state_lost" and sec(i.start_ms) == 60


def test_r5_not_when_hot_path_lost_too():
    s = Scenario.default(120, mode="precision").event("idle_state_lost", 60, interval_s=600, waited_s=605)
    s.fail(57, 62, probes={"udp_stream"})           # the hot path had an outage too
    _, ch = run(s)
    assert [i for i in closed(ch) if i.point == "idle_state_lost"] == []


def test_r5_repeat_becomes_finding():
    s = Scenario.default(200, mode="precision")
    s.event("idle_state_lost", 60, interval_s=600, waited_s=605).event("idle_state_lost", 150, interval_s=600, waited_s=605)
    _, ch = run(s)
    assert [i.point for i in closed(ch)] == ["idle_state_lost"] and [c.kind for c in ch if c.op == "finding"] == ["idle_expiry_repeat"]


def test_nat_state_reset_point():
    s = Scenario.default(120, mode="precision").event("rst", 50, pair="reflector", canary="hot")
    s.event("mapping_reset", 53, pair="stun:cloudflare:3478/udp")
    _, ch = run(s)
    assert [i.point for i in closed(ch)] == ["nat_reset"]


def test_nat_reset_needs_no_ip_change():
    s = Scenario.default(120, mode="precision").event("rst", 50, pair="reflector", canary="hot")
    s.event("mapping_reset", 53).event("ip_change", 52)
    _, ch = run(s)
    assert "nat_reset" not in [i.point for i in closed(ch)]


def test_roam_without_loss_no_incident():
    _, ch = run(Scenario.default(120).event("roam", 50))
    assert closed(ch) == []


def test_roam_with_loss_point_incident():
    _, ch = run(Scenario.default(120).event("roam", 50).fail(49, 52, probes={"line_hb"}))  # loss, but no segment down
    assert [i.point for i in closed(ch)] == ["roam_loss"]


def test_reflector_blackhole_no_incident():
    _, ch = run(Scenario.default(200, mode="precision").fail(30, 150, probes={"udp_stream", "canary"}))
    assert closed(ch) == []


def test_ip_change_alone_is_point_incident_and_joins_open_one():
    _, ch = run(Scenario.default(120).event("ip_change", 50))
    assert [i.point for i in closed(ch)] == ["ip_change"]
    _, ch = run(Scenario.default(150).internet_down(30, 40).event("ip_change", 70))
    [i] = closed(ch)[-1:]
    assert i.point is None and any(e.kind == "ip_change" for e in i.events)


def test_vpn_suspends_line_and_lan_incidents():
    _, ch = run(Scenario.default(120).internet_down(30, 40), vpn=True)
    assert closed(ch) == []


def test_open_incidents_closed_on_restart():
    left = Incident(start_ms=T0 - 60_000, segments={"line"})
    _, ch = run(Scenario.default(20), reopen=[left])
    [i] = closed(ch)
    assert "agent_restarted" in i.tags and i.end_ms == T0


def test_r5_not_suppressed_by_background_loss():
    s = Scenario.default(120, mode="precision").event("idle_state_lost", 60, interval_s=600, waited_s=605)
    s.fail(50, 65, probes={"udp_stream"}, frac=0.1)    # 1 in 10 lost: ordinary loss, not an outage
    _, ch = run(s)
    assert [i.point for i in closed(ch)] == ["idle_state_lost"]


def test_incident_open_across_sleep_ends_when_the_sleep_began():
    s = Scenario.default(400).internet_down(30, 55).suspend(55, 300).event("suspend", 300, slept_s=245)
    _, ch = run(s)
    [i] = closed(ch)
    assert sec(i.end_ms) == 55 and "host_slept" in i.tags and "long_outage" not in i.tags
