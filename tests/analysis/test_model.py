import pytest

from scen import T0, Scenario
from whydrop.agent.events import Event
from whydrop.agent.store import SampleRow
from whydrop.analysis import constants as K
from whydrop.analysis.model import Context, FrameBuilder, line_quorum


def row(t, probe="line_hb", pair="p"):
    return SampleRow(t, probe, pair, 1, 1, 0)


def test_frames_in_order_with_gaps_filled():
    fb = FrameBuilder(finalize_lag_ms=4000)
    fb.add_rows([row(T0), row(T0 + 3000)])
    frames = fb.ready(T0 + 9000)
    assert [f.t_ms - T0 for f in frames] == [0, 1000, 2000, 3000, 4000]
    assert [bool(f.samples) for f in frames] == [True, False, False, True, False]


def test_frame_waits_for_finalize_lag():
    fb = FrameBuilder(finalize_lag_ms=4000)
    fb.add_rows([row(T0)])
    assert fb.ready(T0 + 4999) == [] and len(fb.ready(T0 + 5000)) == 1


def test_row_for_judged_second_is_counted_late():
    fb = FrameBuilder(finalize_lag_ms=0)
    fb.add_rows([row(T0)])
    fb.ready(T0 + 2000)
    fb.add_rows([row(T0, pair="q")])
    assert fb.late_rows == 1 and all(not f.samples for f in fb.ready(T0 + 5000))


def test_late_event_lands_in_next_frame():
    fb = FrameBuilder(finalize_lag_ms=0)
    fb.add_rows([row(T0)])
    fb.ready(T0 + 2000)
    fb.add_events([Event("reassoc", T0 + 500)])
    [f] = fb.ready(T0 + 3000)
    assert f.t_ms == T0 + 2000 and f.events[0].kind == "reassoc"


def test_lag_and_suspend_flags():
    fb = FrameBuilder(finalize_lag_ms=0)
    fb.add_rows([row(T0)])
    fb.add_events([Event("agent_lag", T0 + 2500, detail={"phase": "start", "lag_ms": 500}),
                   Event("agent_lag", T0 + 3200, detail={"phase": "end"}),
                   Event("suspend", T0 + 10_000, detail={"slept_s": 4.0})])
    frames = fb.ready(T0 + 60_000)
    lag = [f.t_ms - T0 for f in frames if f.lag]
    sleep = [f.t_ms - T0 for f in frames if f.suspended]
    assert lag == [2000, 3000]
    assert sleep[0] == 6000 and sleep[-1] == 40_000  # slept 6–10 s, then 30 s of grace


def test_line_quorum_membership():
    ctx = Context(provider_of={"dns_public:1.1.1.1:53/udp": "cloudflare", "x": "google", "y": "quad9"}.get,
                  excluded_pairs={"x"}, excluded_providers={"quad9"})
    assert line_quorum("dns", "dns_public:1.1.1.1:53/udp", ctx)
    assert not line_quorum("dns", "dns_router:192.0.2.1:53/udp", ctx)
    assert not line_quorum("dns", "dns_isp:198.51.100.53:53/udp", ctx)
    assert not line_quorum("line_hb", "x", ctx) and not line_quorum("line_hb", "y", ctx)
    assert not line_quorum("udp_stream", "reflector", ctx)          # basic mode
    ctx.mode = "precision"
    assert line_quorum("udp_stream", "reflector", ctx) and ctx.provider("canary", "reflector") == "reflector"
    assert not line_quorum("gateway", "gateway", ctx)


def test_scenario_dsl_internet_down():
    s = Scenario.default(seconds=20).internet_down(5, 10)
    frames = s.frames()
    ok_at = lambda sec, probe: [r.ok for r in frames[sec].rows(probe)]
    assert ok_at(6, "line_hb") in ([0], []) and all(r.ok for r in frames[6].rows("gateway"))
    router = [r for f in frames[5:10] for r in f.rows("dns") if r.pair.startswith("dns_router")]
    assert router and all(r.ok for r in router)


def test_override_constant():
    old = K.SETTLE_S
    try:
        K.override("SETTLE_S", "40")
        assert K.SETTLE_S == 40 and isinstance(K.SETTLE_S, int)
        with pytest.raises(KeyError):
            K.override("TIMEOUT_S", "1")
    finally:
        K.SETTLE_S = old
