import asyncio
import json
import time

from fastapi.testclient import TestClient

from whydrop.web.app import create_app
from whydrop.web.bus import QUEUE_MAX, Bus


def app(bus, **kw):
    return TestClient(create_app(None, bus, token=None, allowed_hosts=["testserver"], public_default=False, **kw))


def ws(c, path="/ws"):
    return c.websocket_connect(path, headers={"Origin": "http://testserver"}, subprotocols=["whydrop"])


def test_ws_receives_published_changes():
    bus = Bus()
    c = app(bus)
    with ws(c) as s:
        for _ in range(50):              # the subscription lands as the handler starts
            if bus._subs:
                break
            time.sleep(0.02)
        bus.publish("incident", {"op": "created", "row": {"id": 1, "start_ms": 1, "primary_cause": "R2"}})
        msg = s.receive_json()
        s.close()
    assert msg["type"] == "incident" and msg["data"]["row"]["primary_cause"] == "R2" and msg["ts"] > 0


def test_ws_public_masks():
    bus = Bus()
    c = app(bus)
    with ws(c, "/ws?public=1") as s:
        for _ in range(50):
            if bus._subs:
                break
            time.sleep(0.02)
        bus.publish("event", {"row": {"ts_ms": int(time.time() * 1000), "kind": "ip_change", "pair": None,
                                      "detail_json": json.dumps({"old": "203.0.113.7", "new": "203.0.113.9"})}})
        bus.publish("event", {"row": {"ts_ms": 1, "kind": "stall", "pair": "dns_isp:211.234.10.11:53/udp", "detail_json": "{}"}})
        a, b = s.receive_json(), s.receive_json()
        s.close()
    blob = json.dumps([a, b])
    assert "203.0.113" not in blob and "211.234" not in blob and b["data"]["row"]["pair"] == "dns_isp:hidden"


def test_slow_ws_client_doesnt_stall_agent():
    """A subscriber that never reads: publishing stays O(1), its queue stays bounded, the loop keeps its pace."""
    bus = Bus()

    async def main():
        q = bus.subscribe()
        lag = []

        async def ticker():
            for _ in range(20):
                t = time.perf_counter()
                await asyncio.sleep(0.01)
                lag.append(time.perf_counter() - t - 0.01)
        tick = asyncio.create_task(ticker())
        t0 = time.perf_counter()
        for i in range(10_000):
            bus.publish("sample", {"i": i})
            if i % 500 == 0:
                await asyncio.sleep(0)
        spent = time.perf_counter() - t0
        await tick
        return q.qsize(), spent, max(lag)
    size, spent, worst = asyncio.run(main())
    assert size == QUEUE_MAX and bus.dropped == 10_000 - QUEUE_MAX and spent < 0.5 and worst < 0.15  # Windows timers step 15.6 ms; a stall would be seconds


def test_recorder_publishes_lifecycle(tmp_path):
    from analysis.scen import Scenario
    from whydrop.agent.store import Store
    from whydrop.analysis.engine import Engine
    from whydrop.analysis.persist import Recorder
    bus = Bus()
    got = []
    bus.publish = lambda t, d: got.append((t, d.get("op")))

    async def go():
        s = Store(tmp_path / "w.db")
        await s.open()
        rec = Recorder(s, bus=bus)
        sc = Scenario.default(200).internet_down(30, 34)
        eng = Engine(sc.ctx())
        for f in sc.frames():
            await rec.write(eng.step(f))
        await s.close()
    asyncio.run(go())
    ops = [op for t, op in got if t == "incident"]
    assert ops[0] == "created" and ops[-1] == "finalized" and ("segment", None) in got
