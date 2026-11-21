from scen import Scenario
from whydrop.analysis.engine import Engine


def test_engine_one_drop_one_final_cause():
    s = Scenario.default(200).internet_down(30, 34)
    eng = Engine(s.ctx())
    changes = [c for f in s.frames() for c in eng.step(f)]
    finals = [c for c in changes if c.type == "final"]
    opened = [c for c in changes if c.type == "incident" and c.obj.op == "open"]
    assert len(finals) == 1 and len(opened) == 1 and "likely" in finals[0].cause.label
    assert finals[0].obj.incident.evidence["provisional"] == "R2"


def test_engine_history_bounded():
    s = Scenario.default(1200)
    eng = Engine(s.ctx())
    for f in s.frames():
        eng.step(f)
    assert len(eng.frames) == 900
