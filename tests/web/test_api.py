import asyncio
import json
import re
import time

import pytest
from fastapi.testclient import TestClient

from whydrop.agent.events import Event
from whydrop.agent.store import SampleRow, Store
from whydrop.web.app import create_app
from whydrop.web.bus import Bus

NOW = int(time.time() * 1000) // 1000 * 1000
H = {"X-Whydrop": "1"}


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "w.db"

    async def go():
        s = Store(path)
        await s.open()
        r1 = await s.run_start(NOW - 7_200_000, "t", {"mode": "basic"})
        await s.run_heartbeat(r1, NOW - 5_000_000)
        await s.run_start(NOW - 4_000_000, "t", {"mode": "basic"})
        rows = []
        for sec in range(120):
            t = NOW - 600_000 + sec * 1000
            lost = 1 if 30 <= sec < 35 else 0
            rows.append(SampleRow(t, "line_hb", "line_hb:cloudflare", 1, 1 - lost, lost, rtt_avg=None if lost else 12.0))
            rows.append(SampleRow(t, "dns", "dns_router:192.168.0.1:53/udp", 1, 1, 0))
        await s.add_samples(rows)
        await s.add_events([Event("ip_change", NOW - 560_000, None, {"old": "203.0.113.7", "new": "203.0.113.9"}),
                            Event("stall", NOW - 569_000, "reflector", {"phase": "start"})])
        await s.flush()
        await s.insert("incidents", start_ms=NOW - 570_000, end_ms=NOW - 565_000, primary_cause="R2", cause_final="R2",
                       tags_json=json.dumps({"tags": [], "segments": ["line"], "chain": [], "point": None}),
                       evidence_json=json.dumps({"label": "Line drop in the ISP segment (likely)", "cause": "R2",
                                                 "next_step": "Save the evidence with export and contact your ISP",
                                                 "protocol": "UDP: sent seq 1–9 via 192.168.0.1 to 203.0.113.7"}))
        await s.insert("conditions", kind="loss", start_ms=NOW - 300_000, end_ms=None, detail_json=json.dumps({"loss": 0.07}))
        await s.close()
    asyncio.run(go())
    return path


def client(db, **kw):
    return TestClient(create_app(db, Bus(), token=None, allowed_hosts=["testserver"], public_default=False, **kw))


def test_samples_downsampling_keeps_loss(db):
    c = client(db)
    one = c.get(f"/api/samples?from={NOW - 600_000}&to={NOW}&step=1&probe=line_hb").json()
    ten = c.get(f"/api/samples?from={NOW - 600_000}&to={NOW}&step=10&probe=line_hb").json()
    assert one["step_s"] == 1 and ten["step_s"] == 10
    assert sum(r["lost"] for r in one["rows"]) == sum(r["lost"] for r in ten["rows"]) == 5


def test_auto_step_caps_points(db):
    r = client(db).get(f"/api/samples?from={NOW - 6 * 86_400_000}&to={NOW}").json()
    assert r["step_s"] >= 60


def test_incidents_list_detail_and_404(db):
    c = client(db)
    [inc] = c.get("/api/incidents").json()
    assert inc["primary_cause"] == "R2" and c.get(f"/api/incidents/{inc['id']}").json()["id"] == inc["id"]
    assert c.get("/api/incidents/999").status_code == 404


def test_public_view_masks_everything(db):
    c = client(db)
    blob = json.dumps([c.get(p + "?public=1").json() for p in
                       ("/api/incidents", "/api/events", "/api/samples", "/api/status", "/api/conditions")])
    assert "203.0.113" not in blob and "192.168.0.1" not in blob and "x.x.x.1" in blob
    assert not re.search(r"\b\d{10,}\b", blob)                    # no absolute epoch ms in public view


def test_summary_text(db):
    c = client(db)
    iid = c.get("/api/incidents").json()[0]["id"]
    t = c.get(f"/api/incidents/{iid}/summary").text
    assert "Likely cause: Line drop in the ISP segment (likely)" in t and re.search(r"[+-]\d{4}", t)
    assert "추정 원인" in c.get(f"/api/incidents/{iid}/summary?lang=ko").text


def test_annotations_roundtrip(db):
    c = client(db)
    assert c.post("/api/annotations", json={"start_ms": NOW - 1000, "label": "user-test"}, headers=H).json()["id"]
    assert c.post("/api/annotations", json={"start_ms": NOW, "label": "nope"}, headers=H).status_code == 400
    assert c.post("/api/annotations", json={"label": "user-test"}, headers=H).status_code == 400
    assert [a["label"] for a in c.get("/api/annotations").json()] == ["user-test"]


def test_nat_run_states(db):
    assert client(db).post("/api/nat/run", headers=H).status_code == 400
    assert client(db, nat_run=lambda: False).post("/api/nat/run", headers=H).status_code == 409
    assert client(db, nat_run=lambda: True).post("/api/nat/run", headers=H).json() == {"started": True}


def test_gaps_and_availability(db):
    c = client(db)
    [g] = c.get(f"/api/gaps?from={NOW - 8_000_000}&to={NOW}").json()
    assert (g["start_ms"], g["end_ms"]) == (NOW - 5_000_000, NOW - 4_000_000)
    m = c.get("/api/status").json()["month"]
    assert m["drops"] == 1 and m["down_s"] == 5 and 99.9 <= m["availability"] <= 100  # 5 s of a month


def test_exports(db):
    c = client(db)
    csv = c.get("/api/export/incidents.csv")
    assert csv.headers["content-type"].startswith("text/csv") and csv.text.splitlines()[0].startswith("cause_changed")
    pub = c.get("/api/export/events.json?public=1").text
    assert "203.0.113" not in pub and json.loads(pub)
    assert c.get("/api/export/secrets.csv").status_code == 404


def test_bugreport_is_public(db):
    c = client(db)
    iid = c.get("/api/incidents").json()[0]["id"]
    rep = c.get(f"/api/export/bugreport/{iid}")
    text = rep.text
    assert rep.status_code == 200 and "attachment" in rep.headers["content-disposition"]
    assert "203.0.113" not in text and "192.168.0.1" not in text and json.loads(text)["incident"]["cause"] == "R2"


def test_bad_range_400(db):
    assert client(db).get("/api/incidents?from=abc").status_code == 400
    assert client(db).get(f"/api/incidents?from={NOW}&to={NOW - 1}").status_code == 400
