"""docs/design.md thresholds at one step below, at, and one step above; each cause rule's nearest non-match."""
import json

import pytest

from scen import T0, Scenario
from whydrop.agent.store import SampleRow
from whydrop.analysis import constants as K
from whydrop.analysis import texts
from whydrop.analysis.causes import label_period
from whydrop.analysis.conditions import Conditions
from whydrop.analysis.engine import Engine
from whydrop.analysis.incidents import Incident
from whydrop.analysis.model import Context, Frame
from whydrop.analysis.segments import Segments

ROUTER = "dns_router:192.0.2.1:53/udp"
HB = "line_hb:x:3478/udp"


def sec(ms):
    return (ms - T0) // 1000


def seg_states(s, segment, frames=None, **ctx):
    seg = Segments(s.ctx(**ctx))
    return [(sec(c.t_ms), c.state) for f in frames or s.frames() for c in seg.step(f) if c.segment == segment]


def engine(s, frames=None, reopen=None, **ctx):
    eng = Engine(s.ctx(**ctx), reopen=reopen)
    return [(sec(f.t_ms), c) for f in frames or s.frames() for c in eng.step(f)]


def finals(s, **ctx):
    return [c.obj for _, c in engine(s, **ctx) if c.type == "final"]


def incidents(changes):
    return list({id(c.obj.incident): c.obj.incident for _, c in changes if c.type == "incident"}.values())


def router_drop(s, a, b):
    """The router dies: no gateway reply, nothing through it, no router DNS."""
    return s.fail(a, b, probes={"gateway"}).internet_down(a, b).fail(a, b, pairs={ROUTER})


def row(i, probe, pair, sent=1, lost=0, **kw):
    return SampleRow(T0 + i * 1000, probe, pair, sent, sent - lost, lost, **kw)


def frames_of(n, rows_at):
    return [Frame(T0 + i * 1000, {(r.probe, r.pair): r for r in rows_at(i)}) for i in range(n)]


def cond_run(frames, **ctx):
    c = Context(**ctx)
    seg, cond, out = Segments(c), Conditions(c), []
    for f in frames:
        seg.step(f)
        out += [(x.kind, x.phase) for x in cond.step(f, seg)]
    return cond, out


# ---------- segments ----------
@pytest.mark.parametrize("n, down", [(2, False), (3, True), (4, True)])
def test_local_hold_down(n, down):
    assert seg_states(Scenario.default(30).fail(5, 5 + n, probes={"host_net"}), "host_net") == \
        ([(5, "down"), (5 + n, "up")] if down else [])


@pytest.mark.parametrize("good, recovered", [(2, False), (3, True), (4, True)])
def test_local_hold_recovery(good, recovered):
    s = Scenario.default(60).fail(5, 15, probes={"host_net"}).fail(15 + good, 25 + good, probes={"host_net"})
    mid = [(15, "up"), (15 + good, "down")] if recovered else []
    assert seg_states(s, "host_net") == [(5, "down")] + mid + [(25 + good, "up")]


@pytest.mark.parametrize("misses, down", [(1, False), (2, True), (3, True)])
def test_lan_misses(misses, down):
    states = seg_states(router_drop(Scenario.default(40), 10, 10 + misses), "lan")
    assert states == ([(10, "down"), (10 + misses, "up")] if down else [])


@pytest.mark.parametrize("secs, downs", [(2, 0), (3, 1), (4, 1)])
def test_line_lookback(secs, downs):
    assert seg_states(Scenario.default(90).internet_down(30, 30 + secs), "line") == [(30, "down"), (30 + secs, "up")] * downs


@pytest.mark.parametrize("excluded, down", [({"google", "quad9"}, False), ({"quad9"}, True), (set(), True)])
def test_line_min_providers_with_providers_excluded(excluded, down):
    states = seg_states(Scenario.default(90).internet_down(30, 40), "line", excluded_providers=excluded)
    assert states == ([(30, "down"), (40, "up")] if down else [])


@pytest.mark.parametrize("sends, down", [(2, False), (3, True), (4, True)])
def test_line_min_sends(sends, down):
    s = Scenario(90).add("gateway", "gateway", None).add("wifi", "wifi", None)
    s.add("line_hb", "line_hb:cloudflare:3478/udp", "cloudflare", every_s=3)       # one of each in any 3 s window
    s.add("line_hb", "line_hb:google:3478/udp", "google", every_s=3, phase_s=1, per_send=sends - 1)
    states = seg_states(s.internet_down(30, 45), "line")
    assert bool(states) == down and (not down or states[0] == (30, "down"))


@pytest.mark.parametrize("good, downs", [(2, 1), (3, 2), (4, 2)])
def test_line_recover(good, downs):
    states = seg_states(Scenario.default(120).internet_down(30, 40).internet_down(40 + good, 60), "line")
    assert [x for x in states if x[1] == "down"] == [(30, "down"), (40 + good, "down")][:downs]


@pytest.mark.parametrize("frac, down", [(0.7, False), (0.8, True), (0.9, True)])
def test_stream_loss_frac(frac, down):
    s = Scenario.default(90, mode="precision").fail(30, 40, probes={"line_hb", "stun", "tcp_connect", "canary"})
    s.fail(30, 40, pairs={"dns_public:1.1.1.1:53/udp", "dns_public:8.8.8.8:53/udp"})
    assert bool(seg_states(s.fail(30, 40, probes={"udp_stream"}, frac=frac), "line")) == down


def lossy_before(s, seconds):
    for x in seconds:
        s.fail(x, x + 1, probes={"line_hb"})        # one line_hb send a second: each lost one is 1/60 of the window
    return s


@pytest.mark.parametrize("lost, gated", [(2, False), (3, True), (4, True)])    # 3 of 60 = GATE_LOSS_FRAC
def test_gate_loss_frac(lost, gated):
    s = lossy_before(Scenario.default(150), (50, 53, 56, 59)[:lost]).internet_down(80, 84)
    assert seg_states(s, "line") == ([(80, "burst")] if gated else [(80, "down"), (84, "up")])


@pytest.mark.parametrize("first, gated", [(19, False), (20, True), (21, True)])   # window [start − 60 s, start)
def test_gate_window(first, gated):
    s = lossy_before(Scenario.default(150), (first, 50, 53)).internet_down(80, 84)
    assert seg_states(s, "line") == ([(80, "burst")] if gated else [(80, "down"), (84, "up")])


@pytest.mark.parametrize("secs, burst", [(9, True), (10, False), (11, False)])  # "within 10 s": shorter than 10 s
def test_gate_short(secs, burst):
    s = Scenario.default(150).fail(10, 80, probes={"line_hb"}, frac=0.12).internet_down(80, 80 + secs)
    assert seg_states(s, "line") == ([(80, "burst")] if burst else [(80, "down"), (80 + secs, "up")])


def test_gate_ignores_the_loss_of_an_earlier_router_outage():
    """The router outage's own failed heartbeats are not a lossy period: a 5 s line drop after it is a drop, and it
    joins the router's incident as a restart."""
    s = router_drop(Scenario.default(300), 30, 40).internet_down(55, 60)
    assert seg_states(s, "line") == [(55, "down"), (60, "up")]
    [f] = finals(s)
    assert f.incident.segments == {"lan", "line"} and texts.ROUTER_RESTART in f.incident.chain


@pytest.mark.parametrize("attempts, down", [(2, False), (3, True), (4, True)])   # window = 3 × 5 s: 3 attempts
def test_dns_window(attempts, down):
    s = Scenario.default(120).fail(30, 30 + 5 * attempts - 4, pairs={ROUTER})
    assert seg_states(s, "dns_router")[:1] == ([(30, "down")] if down else [])


@pytest.mark.parametrize("every_s, down", [(16, False), (10, True), (7, True)])  # 1, 2, 3 attempts in 15 s
def test_dns_min_attempts(every_s, down):
    s = Scenario.default(150)
    s.streams = [x for x in s.streams if x.pair != ROUTER]
    s.add("dns", ROUTER, None, every_s=every_s).fail(30, 150, pairs={ROUTER})
    assert bool(seg_states(s, "dns_router")) == down


@pytest.mark.parametrize("late, lost, evidence", [(1, 2, False), (1, 1, True), (2, 1, True)])
def test_late_queueing_frac(late, lost, evidence):
    s = Scenario(60).add("gateway", "gateway", None).add("wifi", "wifi", None)
    s.add("line_hb", "line_hb:cloudflare:3478/udp", "cloudflare", per_send=late)
    s.add("line_hb", "line_hb:google:3478/udp", "google", per_send=lost)
    s.fail(30, 40, providers={"cloudflare"}, kind="late").fail(30, 40, providers={"google"})
    seg = Segments(s.ctx())
    [down] = [c for f in s.frames() for c in seg.step(f) if c.segment == "line" and c.state == "down"]
    assert down.detail["queueing_evidence"] is evidence


# ---------- conditions ----------
@pytest.mark.parametrize("lost, start", [(9, False), (10, True), (11, True)])   # of 200: 4.5 / 5 / 5.5 %
def test_loss_start(lost, start):
    _, ch = cond_run(frames_of(120, lambda i: [row(i, "line_hb", HB, 200, lost)]))
    assert (("loss", "start") in ch) == start


@pytest.mark.parametrize("lost, ends", [(4, True), (5, False), (6, False)])     # hysteresis: ends below 2.5 %
def test_loss_end_hysteresis(lost, ends):
    _, ch = cond_run(frames_of(320, lambda i: [row(i, "line_hb", HB, 200, 20 if i < 120 else lost)]))
    assert ch[0] == ("loss", "start") and (("loss", "end") in ch) == ends


@pytest.mark.parametrize("sent, start", [(19, False), (20, True), (21, True)])
def test_loss_min_sends(sent, start):
    _, ch = cond_run(frames_of(90, lambda i: [row(i, "line_hb", HB, sent, sent)] if i == 10 else []))
    assert (("loss", "start") in ch) == start


def wifi_rows(dbm_at):
    return lambda i: [row(i, "wifi", "wifi", extra_json=json.dumps({"signal_dbm": dbm_at(i)}))]


@pytest.mark.parametrize("weak_s, period", [(30, False), (31, True), (32, True)])  # lasting over 30 s
def test_degraded_after(weak_s, period):
    _, ch = cond_run(frames_of(200, wifi_rows(lambda i: -80 if 100 <= i < 100 + weak_s else -60)))
    assert (("weak_signal", "start") in ch) == period


@pytest.mark.parametrize("dbm, weak", [(-74, False), (-75, True), (-76, True)])
def test_weak_dbm(dbm, weak):
    _, ch = cond_run(frames_of(200, wifi_rows(lambda i: dbm if i >= 100 else -60)))
    assert (("weak_signal", "start") in ch) == weak


@pytest.mark.parametrize("median, weak", [(-71, False), (-70, True), (-69, True)])   # −80 dBm: 9 / 10 / 11 dB under
def test_weak_below_median(median, weak):
    _, ch = cond_run(frames_of(300, wifi_rows(lambda i: -80 if i >= 200 else median)))
    assert (("weak_signal", "start") in ch) == weak


@pytest.mark.parametrize("lost, on", [(9, False), (10, True), (11, True)])      # of 100 router checks
def test_wifi_lan_loss_frac(lost, on):
    _, ch = cond_run(frames_of(120, lambda i: [row(i, "gateway", "gateway", 100, lost), row(i, "line_hb", HB)]))
    assert (("wifi_lan_loss", "start") in ch) == on


@pytest.mark.parametrize("p95, busy", [(9.0, False), (10.0, True), (11.0, True)])
def test_busy_lag(p95, busy):
    _, ch = cond_run(frames_of(60, lambda i: [row(i, "loop", "loop", rtt_p95=p95)]))
    assert (("agent_busy", "start") in ch) == busy


@pytest.mark.parametrize("line_lost, gw_lost, home", [(20, 49, False), (20, 50, True), (20, 51, True),   # line 10 %
                                                      (40, 99, False), (40, 100, True), (40, 101, True)])  # line 20 %
def test_loss_at_home_fraction(line_lost, gw_lost, home):
    cond, _ = cond_run(frames_of(100, lambda i: [row(i, "gateway", "gateway", 1000, gw_lost),
                                                 row(i, "line_hb", HB, 200, line_lost)]))
    assert cond.loss_at_home() == home        # ≥ 5 % of the router checks and ≥ half the line's loss rate


@pytest.mark.parametrize("at, home", [(40, False), (41, True), (42, True)])        # judged at 100: (40, 100]
def test_loss_at_home_window(at, home):
    cond, _ = cond_run(frames_of(101, lambda i: [row(i, "gateway", "gateway", *((100, 50) if i == at else (1, 0))),
                                                 row(i, "line_hb", HB)]))
    assert cond.loss_at_home() == home


@pytest.mark.parametrize("lost, lossy", [(4, False), (5, True), (6, True)])       # of 200: 2 / 2.5 / 3 %
def test_r6_line_vs_path_in_precision(lost, lossy):
    cond, _ = cond_run(frames_of(100, lambda i: [row(i, "line_hb", HB, 200, lost)]), mode="precision")
    ctx = Context(mode="precision")
    assert cond.line_hb_lossy() == lossy
    assert label_period("loss", ctx, cond.line_hb_lossy()).label == texts.CAUSES["R6" if lossy else "R6_path"][0]
    assert label_period("loss", Context(mode="basic"), False).label == texts.CAUSES["R6"][0]   # basic: the line
    assert label_period("loss", ctx, True, True).label == texts.CAUSES["R6_home"][0]          # home beats line
    assert label_period("latency", ctx, True, True).rule == "R7"


def test_baseline_states_at_their_boundaries():
    cond = Conditions(Context())
    cond.first_ms = T0
    hour, day = K.BASELINE_NONE_S * 1000, K.BASELINE_LEARNING_S * 1000
    assert [cond.baseline_state(T0 + x) for x in (hour - 1000, hour, day - 1000, day)] == \
        ["none", "learning", "learning", "ready"]


def latency_run(monkeypatch, base, rtt, providers=("cloudflare", "google", "quad9")):
    monkeypatch.setattr(K, "BASELINE_NONE_S", 120)                  # the first hour has its own test above
    s = Scenario.default(400)
    for st in s.streams:
        st.rtt = base
    frames, ctx = s.frames(), s.ctx()
    for f in frames[200:300]:
        for r in f.samples.values():
            if r.probe in ("tcp_connect", "stun", "line_hb") and ctx.provider(r.probe, r.pair) in providers:
                r.rtt_min = r.rtt_avg = rtt
    seg, cond, out = Segments(ctx), Conditions(ctx), []
    for f in frames:
        seg.step(f)
        out += [c.phase for c in cond.step(f, seg) if c.kind == "latency"]
    return out


@pytest.mark.parametrize("rtt, slow", [(69.0, False), (70.0, True), (71.0, True)])   # base 20: + 50 ms rules
def test_latency_plus_ms(monkeypatch, rtt, slow):
    assert bool(latency_run(monkeypatch, 20.0, rtt)) == slow


@pytest.mark.parametrize("rtt, slow", [(119.0, False), (120.0, True), (121.0, True)])  # base 40: 3× rules
def test_latency_factor(monkeypatch, rtt, slow):
    assert bool(latency_run(monkeypatch, 40.0, rtt)) == slow


@pytest.mark.parametrize("providers, slow", [(("cloudflare",), False), (("cloudflare", "google"), True)])
def test_latency_min_providers(monkeypatch, providers, slow):
    assert bool(latency_run(monkeypatch, 20.0, 200.0, providers)) == slow


# ---------- incidents ----------
@pytest.mark.parametrize("gap, merged", [(9, True), (10, True), (11, False)])
def test_merge_after_end(gap, merged):
    assert len(incidents(engine(Scenario.default(200).internet_down(30, 34).internet_down(34 + gap, 40 + gap)))) == \
        (1 if merged else 2)


@pytest.mark.parametrize("gap, merged", [(119, True), (120, True), (121, False)])
def test_merge_after_router_recovery_is_a_router_restart(gap, merged):
    fs = finals(router_drop(Scenario.default(500), 30, 40).internet_down(40 + gap, 50 + gap))
    assert len(fs) == (1 if merged else 2) and (texts.ROUTER_RESTART in fs[0].incident.chain) == merged
    assert len({f.incident.key for f in fs}) == len(fs)              # each finalized once


def test_gated_line_drop_late_in_the_merge_window_still_joins():
    """A line down in a lossy period is confirmed only 10 s after its start: the router incident must wait for it."""
    s = router_drop(Scenario.default(500), 30, 40)
    s = lossy_before(s, range(100, 160, 10)).internet_down(155, 175)   # 6 of 60 heartbeats lost before it: gated
    [f] = finals(s)
    assert f.incident.segments == {"lan", "line"} and texts.ROUTER_RESTART in f.incident.chain


def test_line_drop_after_a_wifi_drop_joins_without_router_restart():
    [f] = finals(Scenario.default(400).event("reassoc", 30).fail(30, 40, probes={"wifi"}).internet_down(100, 110))
    assert f.incident.segments == {"wifi", "line"} and texts.ROUTER_RESTART not in f.incident.chain


@pytest.mark.parametrize("secs, tagged", [(59, False), (60, False), (61, True)])   # past LONG_OUTAGE_S
def test_long_outage(monkeypatch, secs, tagged):
    monkeypatch.setattr(K, "LONG_OUTAGE_S", 60)
    [i] = incidents(engine(Scenario.default(250).internet_down(30, 30 + secs)))
    assert sec(i.end_ms) - sec(i.start_ms) == secs and ("long_outage" in i.tags) == tagged


def test_settle():
    [(at, f)] = [(t, c.obj) for t, c in engine(Scenario.default(200).internet_down(30, 40)) if c.type == "final"]
    assert at - sec(f.incident.end_ms) == K.SETTLE_S


@pytest.mark.parametrize("after, joins", [(59, True), (60, True), (61, False)])
def test_r4_after_end(after, joins):
    fs = finals(Scenario.default(300).internet_down(30, 40).event("ip_change", 40 + after))
    assert [f.cause.rule for f in fs] == (["R4"] if joins else ["R2", "R4"])
    assert joins or fs[1].incident.point == "ip_change"


def idle():
    return Scenario.default(200, mode="precision").event("idle_state_lost", 60, interval_s=600, waited_s=605)


@pytest.mark.parametrize("offset, point", [(-11, True), (-10, False), (5, False), (6, True)])  # [−10 s, +5 s]
def test_r5_hot_path_window(offset, point):
    s = idle().fail(60 + offset, 61 + offset, probes={"udp_stream"})
    assert [f.incident.point for f in finals(s)] == (["idle_state_lost"] if point else [])


@pytest.mark.parametrize("limit, label", [(599, "R5_expiry"), (600, "R5_loss"), (601, "R5_loss")])  # exceeded: >
def test_r5_expiry_vs_loss(limit, label):
    [f] = finals(idle(), nat_tcp_timeout_s=limit)
    assert f.cause.label == texts.CAUSES[label][0]


@pytest.mark.parametrize("offset, point", [(-11, False), (-10, True), (10, True), (11, False)])
def test_nat_reset_window(offset, point):
    s = Scenario.default(200, mode="precision").event("rst", 60, pair="reflector", canary="hot")
    s.event("mapping_reset", 60 + offset, pair="stun:cloudflare:3478/udp")
    assert [f.incident.point for f in finals(s)] == (["nat_reset"] if point else [])


@pytest.mark.parametrize("offset, blocks", [(10, True), (11, False)])
def test_nat_reset_ip_change_window(offset, blocks):
    s = Scenario.default(200, mode="precision").event("rst", 60, pair="reflector", canary="hot")
    s.event("mapping_reset", 62).event("ip_change", 60 + offset)
    assert ("nat_reset" not in [f.incident.point for f in finals(s)]) == blocks


@pytest.mark.parametrize("offset, point", [(-6, False), (-5, True), (5, True), (6, False)])
def test_roam_loss_window(offset, point):
    s = Scenario.default(200).event("roam", 60).fail(60 + offset, 61 + offset, probes={"line_hb"})
    assert [f.incident.point for f in finals(s)] == (["roam_loss"] if point else [])


@pytest.mark.parametrize("offset, rule", [(15, "R1a"), (16, "R2")])
def test_r1a_wifi_down_window(offset, rule):
    s = Scenario.default(300).internet_down(60, 100).fail(60 + offset, 64 + offset, probes={"wifi"})
    assert [f.cause.rule for f in finals(s)] == [rule]


@pytest.mark.parametrize("offset, rule", [(5, "R1c"), (6, "R2")])
def test_r1c_window(offset, rule):
    s = Scenario.default(300, link_kind="wired").internet_down(60, 90).event("link_flap", 60 + offset)
    assert [f.cause.rule for f in finals(s, link_kind="wired")] == [rule]


def test_r1b_beats_r4():
    [f] = finals(router_drop(Scenario.default(300), 30, 40).event("ip_change", 50))
    assert f.cause.rule == "R1b" and "R4" in f.cause.secondary


@pytest.mark.parametrize("before, rule", [(11, "R1b"), (10, "R7"), (9, "R7")])  # queueing first looks back 10 s
def test_queueing_first_beats_r1b(monkeypatch, before, rule):
    monkeypatch.setattr(K, "BASELINE_NONE_S", 120)
    s = router_drop(Scenario.default(600).add("tcp_connect", "tcp:9.9.9.9:443/tcp", "quad9"), 300, 310)  # 2 pairs/s
    frames = s.frames()
    for r in frames[300 - before].samples.values():              # one second of every RTT at 20× baseline
        if r.probe in ("line_hb", "tcp_connect", "stun") and r.ok:
            r.rtt_min = r.rtt_avg = 400.0
    assert [c.cause.rule for _, c in engine(s, frames) if c.type == "final"] == [rule]


def test_restart_with_an_incident_open_is_finalized_once():
    left = Incident(start_ms=T0 - 60_000, segments={"line"})
    fs = [(t, c.obj) for t, c in engine(Scenario.default(200), reopen=[left]) if c.type == "final"]
    assert [(t, f.cause.rule) for t, f in fs] == [(K.SETTLE_S, "R2")] and "agent_restarted" in fs[0][1].incident.tags


def test_a_gap_in_frames_still_settles_once():
    """Frames resume after a gap (a clock step past the backlog, or replay over a stopped agent): windows are timed."""
    frames = Scenario.default(400).internet_down(30, 40).frames()
    fs = [c.obj for _, c in engine(Scenario.default(400), frames[:45] + frames[300:]) if c.type == "final"]
    assert [(f.cause.rule, sec(f.incident.end_ms)) for f in fs] == [("R2", 40)]
