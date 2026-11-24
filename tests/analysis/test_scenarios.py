"""Spec §11.1 scenario tests 1–22, end to end through the Engine (one function per spec line)."""
from scen import Scenario
from whydrop.agent.store import SampleRow
from whydrop.analysis import texts
from whydrop.analysis.engine import Engine
from whydrop.measure.direction import Echo, outage_totals

ROUTER, ISP = "dns_router:192.0.2.1:53/udp", "dns_isp:198.51.100.53:53/udp"
PUBLIC = {"dns_public:1.1.1.1:53/udp", "dns_public:8.8.8.8:53/udp"}
QUORUM = {"line_hb", "stun", "tcp_connect", "dns"}


def run(s: Scenario, frames=None, **ctx):
    eng = Engine(s.ctx(**ctx))
    changes = [c for f in (frames or s.frames()) for c in eng.step(f)]
    finals = [c.obj for c in changes if c.type == "final"]
    return finals, changes, eng


def incidents(changes):
    return {id(c.obj.incident): c.obj.incident for c in changes if c.type == "incident"}


def outage(a_seq, a_rc, b_seq, b_rc):
    t = outage_totals(Echo(a_seq, a_rc, 1, 0), Echo(b_seq, b_rc, 1, 0), 1)
    return dict(from_seq=a_seq, to_seq=b_seq, lost_up=t.up, lost_down=t.down, status=t.status)


def with_loop(frames, ms):
    for f in frames:
        f.samples[("loop", "loop")] = SampleRow(f.t_ms, "loop", "loop", 1, 1, 0, rtt_p95=ms(f))
    return frames


def test_01_3s_line_drop_exactly_one_r2():
    finals, ch, _ = run(Scenario.default(200).internet_down(60, 63))
    assert [f.cause.rule for f in finals] == ["R2"] and len(incidents(ch)) == 1


def test_02_46s_isp_outage_precision_r2_with_direction():
    s = Scenario.default(300, mode="precision").internet_down(60, 106)
    s.event("udp_outage", 107, pair="reflector", **outage(600, 600, 1061, 601))
    finals, _, _ = run(s)
    [f] = finals
    assert f.cause.rule == "R2" and f.cause.evidence["direction"] == "upload"


def test_03_4s_reassociation_good_signal_r1a():
    s = Scenario.default(200).event("reassoc", 60).fail(60, 64, probes={"wifi", "gateway"}).internet_down(60, 64)
    finals, _, _ = run(s)
    assert [f.cause.rule for f in finals] == ["R1a"]


def test_04_router_reboot_one_incident():
    s = Scenario.default(400)
    s.event("reassoc", 10).fail(10, 90, probes={"wifi", "gateway"}).internet_down(10, 150)
    s.fail(90, 100, probes={"gateway"}).event("ip_change", 152)
    finals, ch, _ = run(s)
    [f] = finals
    assert len(incidents(ch)) == 1 and f.cause.rule == "R1a" and "R4" in f.cause.secondary
    assert "router restart (likely)" in f.incident.chain


def test_05_random_8pct_loss_is_r6_period_not_incident():
    s = Scenario.default(900).fail(60, 660, probes=QUORUM, frac=0.15, rand=3)   # ≈ 8 % each way, round trip
    finals, ch, _ = run(s)
    periods = [c for c in ch if c.type == "condition" and c.obj.kind == "loss" and c.obj.phase == "start"]
    assert finals == [] and periods and periods[0].cause.rule == "R6"


def test_loss_with_the_router_checks_failing_too_is_home_loss():
    """Seen on the home server: evening loss periods with line loss 6-28 % while 12-53 % of the router checks failed
    were all called a lossy line ('contact your ISP'). Loss the router shares starts at home."""
    s = Scenario.default(900).fail(60, 660, probes=QUORUM | {"gateway"}, frac=0.15, rand=3)
    finals, ch, _ = run(s)
    periods = [c for c in ch if c.type == "condition" and c.obj.kind == "loss" and c.obj.phase == "start"]
    assert finals == [] and periods and periods[0].cause.label == texts.CAUSES["R6_home"][0]
    line = Scenario.default(900).fail(60, 660, probes=QUORUM, frac=0.15, rand=3)
    first = next(c for c in run(line)[1] if c.type == "condition" and c.obj.kind == "loss")
    assert first.cause.label == texts.CAUSES["R6"][0]                       # router clean: still the line
    mute = Scenario.default(900).fail(0, 900, probes={"gateway"}).fail(60, 660, probes=QUORUM, frac=0.15, rand=3)
    first = next(c for c in run(mute)[1] if c.type == "condition" and c.obj.kind == "loss")
    assert first.cause.label == texts.CAUSES["R6"][0]                       # router never answers: can't tell


def test_06_saturated_uplink_r7_via_late_replies():
    finals, _, _ = run(Scenario.default(200).internet_down(60, 66, kind="late"))
    assert [f.cause.rule for f in finals] == ["R7"]


def test_07_isp_dns_outage_via_router_r3():
    finals, _, _ = run(Scenario.default(200).fail(60, 100, pairs={ROUTER, ISP}))
    assert [f.cause.rule for f in finals] == ["R3"] and "ISP DNS outage" in finals[0].cause.label


def test_08_one_flaky_public_resolver_no_incident():
    finals, ch, _ = run(Scenario.default(400).fail(60, 360, pairs={"dns_public:8.8.8.8:53/udp"}, frac=0.6, rand=1))
    assert incidents(ch) == {}


def test_09_agent_loop_stall_no_incident():
    _, ch, _ = run(Scenario.default(200).internet_down(60, 66).lag(59, 67))
    assert incidents(ch) == {}


def test_10_reflector_only_blackhole_no_incident():
    _, ch, _ = run(Scenario.default(300, mode="precision").fail(60, 200, probes={"udp_stream", "canary"}))
    assert incidents(ch) == {}


def test_11_roaming_without_loss_no_incident():
    _, ch, _ = run(Scenario.default(200).event("roam", 60))
    assert incidents(ch) == {}


def test_12_vpn_egress_suspends_r1b_r2():
    _, ch, _ = run(Scenario.default(200).internet_down(60, 70).fail(80, 90, probes={"gateway"}), vpn=True)
    assert incidents(ch) == {}


def test_13_idle_miss_alone_r5_point():
    finals, _, _ = run(Scenario.default(200, mode="precision").event("idle_state_lost", 60, interval_s=600, waited_s=605))
    assert [(f.cause.rule, f.incident.point) for f in finals] == [("R5", "idle_state_lost")]


def test_14_blackholes():
    _, ch, _ = run(Scenario.default(200).internet_down(60, 62))
    assert len(incidents(ch)) <= 1
    finals, ch, _ = run(Scenario.default(200).internet_down(60, 63))
    assert len(incidents(ch)) == 1


def test_15_long_line_drop_no_separate_r3_after():
    finals, ch, _ = run(Scenario.default(300).internet_down(60, 75))
    assert [f.cause.rule for f in finals] == ["R2"] and len(incidents(ch)) == 1


def test_16_host_suspended_5_min_no_incident():
    _, ch, _ = run(Scenario.default(600).suspend(60, 360).internet_down(360, 370))
    assert incidents(ch) == {}


def test_17_default_route_lost_wifi_up_r1d():
    s = Scenario.default(220).fail(60, 70, probes={"host_net"})       # final 130 s after the end
    s.fail(60, 70, probes=QUORUM | {"gateway"}, kind="local_fail")
    finals, _, _ = run(s)
    assert [f.cause.rule for f in finals] == ["R1d"]


def test_18_cloudflare_down_provider_outage_no_loss_condition():
    s = Scenario.default(600).fail(60, 500, providers={"cloudflare"})
    _, ch, _ = run(s, excluded_providers={"cloudflare"})   # Plan 2's provider-outage finding excludes it
    assert incidents(ch) == {} and not [c for c in ch if c.type == "condition"]


def test_19_steady_200ms_scheduling_delay_no_r7_agent_busy():
    s = Scenario.default(4300).slow(3700, 4200, probes={"tcp_connect", "stun", "line_hb"}, rtt=250.0)
    finals, ch, _ = run(s, with_loop(s.frames(), lambda f: 200.0))
    kinds = {c.obj.kind for c in ch if c.type == "condition" and c.obj.phase == "start"}
    assert "latency" not in kinds and "agent_busy" in kinds and finals == []


def test_20_precision_all_public_resolvers_fail_r3_public():
    finals, _, _ = run(Scenario.default(400, mode="precision").fail(60, 200, pairs=PUBLIC))
    assert [f.cause.rule for f in finals] == ["R3"] and "public resolvers blocked" in finals[0].cause.label.lower()


def test_21_cgnat_port_rebind_without_ip_change_nat_reset():
    s = Scenario.default(200, mode="precision").event("rst", 60, pair="reflector", canary="hot")
    s.event("mapping_reset", 62, pair="stun:cloudflare:3478/udp")
    finals, _, _ = run(s)
    assert [(f.cause.rule, f.incident.point) for f in finals] == [("R5", "nat_reset")]


def test_22_roam_to_new_bssid_roam_only():
    _, ch, eng = run(Scenario.default(200).event("roam", 60))
    downs = [c for c in ch if c.type == "segment" and c.obj.state == "down"]
    assert downs == [] and incidents(ch) == {}
