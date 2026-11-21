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


def test_reflector_only_blackhole_is_not_a_loss_period():
    s = Scenario.default(300, mode="precision").fail(60, 200, probes={"udp_stream", "canary"})
    eng = Engine(s.ctx())
    conds = [c for f in s.frames() for c in eng.step(f) if c.type == "condition"]
    assert conds == []


def test_previous_run_leftovers_closed_with_their_cause(tmp_path):
    import asyncio
    import json

    from whydrop.agent.store import Store
    from whydrop.analysis.persist import Recorder

    async def go():
        s = Store(tmp_path / "w.db")
        await s.open()
        r1 = await s.run_start(1_000, "t", {})
        await s.run_heartbeat(r1, 50_000)
        await s.insert("incidents", start_ms=20_000, primary_cause="R1a", tags_json=json.dumps({"segments": ["wifi"]}))
        await s.insert("incidents", start_ms=5_000, end_ms=8_000, primary_cause="R2", tags_json="{}")
        await s.insert("conditions", kind="loss", start_ms=10_000, detail_json="{}")
        r2 = await s.run_start(9_000_000, "t", {})
        await Recorder(s).close_previous_run(r2)
        rows = await s.execute("select end_ms, cause_final, tags_json from incidents order by id")
        cond = await s.execute("select end_ms from conditions")
        await s.close()
        return rows, cond
    rows, cond = asyncio.run(go())
    assert rows[0][:2] == (50_000, "R1a") and "agent_restarted" in rows[0][2]   # ends at the last heartbeat, not 9 000 s
    assert rows[1][1] == "R2" and cond == [(50_000,)]


def test_a_line_drop_after_the_settle_does_not_reopen_a_final_incident():
    """Found replaying real data: a line down 80-120 s after a router recovery merged into the router incident after
    its cause was already final, and the same incident was finalized twice. Final means frozen: it starts a new one."""
    s = Scenario.default(400).fail(30, 40, probes={"gateway"}).internet_down(30, 40) \
        .fail(30, 40, pairs={"dns_router:192.0.2.1:53/udp"}).internet_down(140, 150)
    eng = Engine(s.ctx())
    finals = [c.obj for f in s.frames() for c in eng.step(f) if c.type == "final"]
    keys = [f.incident.key for f in finals]
    assert len(keys) == len(set(keys)) == 2, [(f.incident.start_ms, f.incident.end_ms, f.cause.rule) for f in finals]
