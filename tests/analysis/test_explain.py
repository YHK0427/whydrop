"""Each verdict carries the measurements behind it and why the other causes don't fit."""
from scen import Scenario
from whydrop.analysis.engine import Engine


def final_evidence(s):
    e = Engine(s.ctx())
    out = []
    for f in s.frames():
        out += [c.obj for c in e.step(f) if c.type == "final"]
    [x] = out
    ev = x.incident.evidence
    return x.cause.rule, {f["k"]: f for f in ev["facts"]}, {r["k"]: r for r in ev["ruled_out"]}


def test_in_home_queueing_shows_the_slow_router_and_late_replies():
    s = Scenario.default(260).slow(22, 30, probes={"gateway"}, rtt=400.0).internet_down(30, 36, kind="late")
    rule, facts, ruled = final_evidence(s)
    assert rule == "R7"
    assert facts["gw"]["peak"] == 400.0 and facts["gw"]["base"] == 20.0 and facts["gw"]["ok"] == facts["gw"]["sent"]
    assert facts["line"]["late"] > 0 and facts["line"]["lost"] == 0
    assert ruled["router"]["ok"] == facts["gw"]["sent"] and ruled["router"]["crossed"] == facts["line"]["ok"] + facts["line"]["late"]
    assert ruled["line_late"]["answered"] == facts["line"]["ok"] + facts["line"]["late"] and "local" in ruled


def test_a_line_drop_shows_the_loss_beyond_the_router_and_rules_out_the_router():
    rule, facts, ruled = final_evidence(Scenario.default(260).internet_down(30, 40))
    assert rule == "R2" and facts["line"]["lost"] > 0 and facts["dur"]["segs"] == ["line"]
    assert ruled["router"]["ok"] > 0 and "line_ok" not in ruled and "line_late" not in ruled


def test_a_wifi_drop_counts_the_reassociation_and_does_not_rule_wifi_out():
    s = Scenario.default(260).fail(30, 36, probes={"gateway", "line_hb", "stun", "tcp_connect", "dns"}).event("reassoc", 30)
    rule, facts, ruled = final_evidence(s)
    assert rule.startswith("R1a") and facts["wifi"]["n"] == 1 and "wifi" not in ruled
