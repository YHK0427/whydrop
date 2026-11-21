import json

from scen import T0, Scenario
from whydrop.analysis.conditions import Conditions
from whydrop.analysis.segments import Segments


def run(s: Scenario, frames=None, **ctx):
    c = s.ctx(**ctx)
    seg, cond = Segments(c), Conditions(c)
    out = []
    for f in frames or s.frames():
        seg.step(f)
        out += cond.step(f, seg)
    return cond, out


def periods(changes, kind):
    return [((c.t_ms - T0) // 1000, c.phase) for c in changes if c.kind == kind]


def test_random_loss_is_loss_condition():
    s = Scenario.default(400).fail(60, 300, probes={"line_hb"}, frac=0.10)
    _, ch = run(s)
    p = periods(ch, "loss")
    assert p[0][1] == "start" and 60 <= p[0][0] <= 120 and p[-1][1] == "end" and len(p) == 2


def test_a_couple_of_losses_are_not_a_condition():
    _, ch = run(Scenario.default(200).fail(60, 63, probes={"line_hb"}, frac=0.5))
    assert periods(ch, "loss") == []


def test_precision_loss_from_udp_stream():
    s = Scenario.default(200, mode="precision").fail(50, 150, probes={"udp_stream"}, frac=0.1)
    _, ch = run(s)
    assert [x[1] for x in periods(ch, "loss")] == ["start", "end"]


def test_provider_outage_no_loss_condition():
    s = Scenario.default(400).fail(60, 300, providers={"cloudflare"})
    _, ch = run(s, excluded_providers={"cloudflare"})
    assert periods(ch, "loss") == []


def with_signal(frames, dbm_at):
    for i, f in enumerate(frames):
        r = f.samples.get(("wifi", "wifi"))
        if r:
            r.extra_json = json.dumps({"signal_dbm": dbm_at(i)})
    return frames


def test_weak_signal_relative_to_median():
    s = Scenario.default(5000)
    frames = with_signal(s.frames(), lambda i: -60 if i < 4000 else -80)
    _, ch = run(s, frames)
    assert [x[1] for x in periods(ch, "weak_signal")] == ["start"]
    frames = with_signal(Scenario.default(5000).frames(), lambda i: -78)  # always weak: not "≥ 10 dB under median"
    _, ch = run(s, frames)
    assert periods(ch, "weak_signal") == []


def with_loop(frames, lag_at):
    from whydrop.agent.store import SampleRow
    for i, f in enumerate(frames):
        f.samples[("loop", "loop")] = SampleRow(f.t_ms, "loop", "loop", 1, 1, 0, rtt_p95=lag_at(i))
    return frames


def test_agent_busy_and_r7_needs_low_loop_lag():
    s = Scenario.default(4400).slow(3700, 4300, probes={"tcp_connect", "stun", "line_hb"}, rtt=200.0)
    frames = with_loop(s.frames(), lambda i: 200.0 if i >= 3650 else 0.5)
    _, ch = run(s, frames)
    assert periods(ch, "latency") == [] and periods(ch, "agent_busy")[0][1] == "start"


def test_latency_condition_after_first_hour():
    s = Scenario.default(4400).slow(3700, 4300, probes={"tcp_connect", "stun", "line_hb"}, rtt=200.0)
    cond, ch = run(s, with_loop(s.frames(), lambda i: 0.5))
    assert [x[1] for x in periods(ch, "latency")] == ["start", "end"] and cond.baseline_state() == "learning"


def test_baseline_learning_states():
    s = Scenario.default(100).slow(30, 90, probes={"tcp_connect", "stun", "line_hb"}, rtt=200.0)
    cond, ch = run(s)
    assert cond.baseline_state() == "none" and periods(ch, "latency") == []


def test_wifi_lan_loss():
    s = Scenario.default(300).fail(50, 250, probes={"gateway"}, frac=0.2)
    _, ch = run(s)
    assert periods(ch, "wifi_lan_loss")[0][1] == "start"


def test_weak_signal_with_sparse_wifi_rows():
    s = Scenario.default(5000)
    s.streams = [x for x in s.streams if x.probe != "wifi"]
    s.add("wifi", "wifi", None, every_s=2)                 # Windows reads Wi-Fi every 2 s
    frames = with_signal(s.frames(), lambda i: -60 if i < 4000 else -80)
    _, ch = run(s, frames)
    assert [x[1] for x in periods(ch, "weak_signal")] == ["start"]
