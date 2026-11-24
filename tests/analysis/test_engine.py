from scen import Scenario
from whydrop.analysis import texts
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


def test_a_line_drop_after_a_router_drop_is_finalized_once():
    """Found replaying real data: a line down 80-120 s after a router recovery merged into the router incident after
    its cause was already final, and the same incident was finalized twice. A local drop now settles only after the
    120 s merge window, and a final incident is frozen."""
    def finals(gap_s):
        s = Scenario.default(500).fail(30, 40, probes={"gateway"}).internet_down(30, 40) \
            .fail(30, 40, pairs={"dns_router:192.0.2.1:53/udp"}).internet_down(40 + gap_s, 50 + gap_s)
        eng = Engine(s.ctx())
        return [c.obj for f in s.frames() for c in eng.step(f) if c.type == "final"]
    joined = finals(100)                       # inside the 120 s window, after the 80 s settle: still one drop
    assert len(joined) == 1 and texts.ROUTER_RESTART in joined[0].incident.chain
    apart = finals(200)                        # past the window: two drops, each finalized once
    keys = [f.incident.key for f in apart]
    assert len(keys) == len(set(keys)) == 2, [(f.incident.start_ms, f.incident.end_ms, f.cause.rule) for f in apart]


def test_drops_settled_by_a_restart_still_alert_and_stale_findings_close(tmp_path):
    """Final review: a drop that ended under 80 s before a restart (or was open across it) got its cause frozen
    without the 'finalized' message, so it never alerted; findings a crashed run left open stayed open forever."""
    import asyncio
    import json

    from whydrop.agent.store import Store
    from whydrop.analysis.persist import Recorder
    from whydrop.web.bus import Bus

    async def go():
        s = Store(tmp_path / "w.db")
        await s.open()
        r1 = await s.run_start(1_000, "t", {})
        await s.run_heartbeat(r1, 50_000)
        await s.insert("incidents", start_ms=20_000, primary_cause="R1a", tags_json=json.dumps({"segments": ["wifi"]}))
        await s.insert("incidents", start_ms=5_000, end_ms=8_000, primary_cause="R2", tags_json="{}")
        await s.insert("incidents", start_ms=1_000, end_ms=2_000, primary_cause="R3", cause_final="R3", tags_json="{}")
        await s.insert("findings", kind="secret_mismatch", start_ms=30_000, detail_json="{}")
        bus = Bus()
        q = bus.subscribe({"incident"})
        r2 = await s.run_start(9_000_000, "t", {})
        await Recorder(s, bus=bus).close_previous_run(r2)
        got = [q.get_nowait() for _ in range(q.qsize())]
        open_findings = await s.execute("select count(*) from findings where end_ms is null")
        await s.close()
        return got, open_findings[0][0]
    got, open_findings = asyncio.run(go())
    assert sorted((m["data"]["op"], m["data"]["row"]["cause_final"]) for m in got) == [("finalized", "R1a"), ("finalized", "R2")]
    assert open_findings == 0
