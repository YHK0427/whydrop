"""The dashboard shares the agent's event loop: big answers must not stall it (plan 5 review focus 3)."""
import asyncio
import json
import socket
import time
import urllib.request

import pytest

from whydrop.agent.store import SampleRow, Store
from whydrop.web.app import create_app
from whydrop.web.bus import Bus

NOW = int(time.time() * 1000) // 1000 * 1000
PAIRS = [("line_hb", f"line_hb:p{i}") for i in range(3)] + [("stun", f"stun:s{i}") for i in range(2)] + \
        [("dns", f"dns_public:198.51.100.{i}:53/udp") for i in range(12)] + [("tcp_connect", f"tcp:t{i}") for i in range(4)] + \
        [("udp_stream", "reflector"), ("canary", "reflector"), ("gateway", "gateway"), ("wifi", "wifi")]


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    path = tmp_path_factory.mktemp("load") / "w.db"

    async def go():
        s = Store(path)
        await s.open()
        rows = [SampleRow(NOW - 3_600_000 + sec * 1000, p, pair, 1, 1, 0, rtt_avg=12.0)
                for sec in range(3600) for p, pair in PAIRS]
        await s.add_samples(rows)
        await s.flush()
        await s.close()
    asyncio.run(go())
    return path


def worst_lag_while(db, path):
    async def main():
        app = create_app(db, Bus(), token=None, allowed_hosts=["127.0.0.1"], public_default=False)
        import uvicorn
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
        serve = asyncio.create_task(server.serve(sockets=[sock]))
        while not server.started:
            await asyncio.sleep(0.01)
        lags, done = [], asyncio.Event()

        async def ticker():
            while not done.is_set():
                t = time.perf_counter()
                await asyncio.sleep(0.01)
                lags.append(time.perf_counter() - t - 0.01)
        tick = asyncio.create_task(ticker())
        body = await asyncio.to_thread(lambda: urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=30).read())
        done.set()
        await tick
        server.should_exit = True
        await serve
        return max(lags), len(body)
    return asyncio.run(main())


def test_chart_hour_is_small_and_doesnt_stall_the_loop(db):
    worst, size = worst_lag_while(db, f"/api/chart?from={NOW - 3_600_000}&to={NOW}")
    assert size < 400_000 and worst < 0.15, (size, worst)       # Windows timers step 15.6 ms


def test_public_samples_dont_stall_the_loop(db):
    worst, size = worst_lag_while(db, f"/api/samples?from={NOW - 3_600_000}&to={NOW}&step=1&public=1")
    assert worst < 0.15 and size < 2_000_000, (size, worst)   # step=1 is coarsened to keep it small


def test_export_streams(db):
    worst, size = worst_lag_while(db, f"/api/export/events.json?from={NOW - 3_600_000}&to={NOW}")
    assert worst < 0.15


def test_chart_values():
    from whydrop.web.queries import chart
    assert chart(None, 0, 3_600_000, 1)["x"] == []


def test_step_cap_holds_even_when_asked_for_1s():
    from whydrop.web.queries import CHART_POINTS, pick_step
    assert pick_step(0, 3 * 3_600_000, 1, CHART_POINTS) >= 10 and pick_step(0, 600_000, 1, CHART_POINTS) == 1


def test_chart_columns(db):
    from whydrop.web.queries import chart
    c = chart(db, NOW - 600_000, NOW, 10)
    assert c["step_s"] == 10 and len(c["x"]) in (60, 61) and c["rtt"][1] == 12.0 and c["tcp"][1] == 2
    assert json.dumps(c)
