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
    one = c.get(f"/api/samples?from={NOW - 600_000}&to={NOW - 300_000}&step=1&probe=line_hb").json()  # 300 points: 1 s holds
    ten = c.get(f"/api/samples?from={NOW - 600_000}&to={NOW - 300_000}&step=10&probe=line_hb").json()
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


def test_public_summary_has_no_absolute_time_or_address(db):
    c = client(db)
    iid = c.get("/api/incidents").json()[0]["id"]
    t = c.get(f"/api/incidents/{iid}/summary?public=1").text
    assert "min ago" in t and not re.search(r"\d{4}-\d{2}-\d{2}", t) and "192.168.0.1" not in t and "203.0.113" not in t


def test_in_home_summary_names_the_home_network(tmp_path):
    path = tmp_path / "w.db"

    async def go():
        s = Store(path)
        await s.open()
        await s.insert("incidents", start_ms=NOW - 9_000, end_ms=NOW - 1_000, primary_cause="R7", cause_final="R7",
                       tags_json=json.dumps({"tags": [], "segments": ["line"], "chain": [], "point": None}),
                       evidence_json=json.dumps({"label": "In-home queueing (likely)", "cause": "R7",
                                                 "cause_where": "home"}))
        await s.close()
    asyncio.run(go())
    c = client(path)
    iid = c.get("/api/incidents").json()[0]["id"]
    assert "8 s, Home network" in c.get(f"/api/incidents/{iid}/summary").text
    assert "8초, 집 안 네트워크" in c.get(f"/api/incidents/{iid}/summary?lang=ko").text
    assert c.get(f"/api/incidents/{iid}?public=1").json()["evidence"]["cause_where"] == "home"   # the demo needs it too


def test_korean_summary_uses_the_korean_protocol_story(tmp_path):
    path = tmp_path / "w.db"

    async def go():
        s = Store(path)
        await s.open()
        await s.insert("incidents", start_ms=NOW - 9_000, end_ms=NOW - 1_000, primary_cause="R2", cause_final="R2",
                       tags_json=json.dumps({"tags": [], "segments": ["line"], "chain": [], "point": None}),
                       evidence_json=json.dumps({"label": "Line drop in the ISP segment (likely)", "cause": "R2",
                                                 "protocol": "TCP: HB got no reply.", "protocol_ko": "TCP: HB에 응답이 없었어요."}))
        await s.close()
    asyncio.run(go())
    c = client(path)
    iid = c.get("/api/incidents").json()[0]["id"]
    assert "프로토콜로 보면: TCP: HB에 응답이 없었어요." in c.get(f"/api/incidents/{iid}/summary?lang=ko").text
    assert "In protocol terms: TCP: HB got no reply." in c.get(f"/api/incidents/{iid}/summary").text



def test_numbers_past_sqlite_integers_are_a_400_not_a_500(db):
    """L6 audit: from/to, incident ids and annotation times beyond 2^63 reached SQLite and came back as 500s."""
    c = TestClient(create_app(db, Bus(), token=None, allowed_hosts=["testserver"], public_default=False),
                   raise_server_exceptions=False)
    big = "99999999999999999999"
    for path in (f"/api/samples?from=-1&to={big}", f"/api/chart?from=0&to={big}", f"/api/events?from=0&to={big}",
                 f"/api/annotations?from=0&to={big}", f"/api/conditions?from=0&to={big}", f"/api/incidents?from=0&to={big}",
                 f"/api/export/events.csv?from=0&to={big}", f"/api/incidents/{big}", f"/api/incidents/{big}/strip",
                 f"/api/incidents/{big}/summary", f"/api/export/bugreport/{big}", "/api/chart?from=-5&to=10"):
        assert c.get(path).status_code in (400, 422), path
    r = c.post("/api/annotations", json={"start_ms": int(big), "label": "user-test"}, headers=H)
    assert r.status_code == 400


def test_csv_text_that_a_spreadsheet_would_run_is_made_literal(tmp_path):
    """L6 audit: a cell starting with = + - @ runs as a formula when the CSV is opened in a spreadsheet."""
    from whydrop.web.export import render
    rows = [{"id": 1, "kind": "=HYPERLINK(\"http://x.example\")", "note": "@SUM(1)", "neg": -5, "detail_json": "{\"a\": 1}"}]
    body, _ = render("events", rows, "csv", False, NOW)
    assert "'=HYPERLINK" in body and "'@SUM" in body and ",-5," in body and "\"{\"\"a\"\": 1}\"" in body


def test_summary_carries_the_measurements_behind_the_verdict(tmp_path):
    path = tmp_path / "w.db"
    facts = [{"k": "dur", "dur": 8, "segs": ["line"]}, {"k": "gw", "sent": 11, "ok": 11, "lost": 0, "late": 0, "base": 3.0, "peak": 412.0},
             {"k": "line", "sent": 24, "ok": 0, "late": 24, "lost": 0, "peak": None}]
    ruled = [{"k": "router", "ok": 11, "sent": 11, "crossed": 24}, {"k": "line_late", "answered": 24, "late": 24, "sent": 24}]

    async def go():
        s = Store(path)
        await s.open()
        await s.insert("incidents", start_ms=NOW - 9_000, end_ms=NOW - 1_000, primary_cause="R7", cause_final="R7",
                       tags_json=json.dumps({"tags": [], "segments": ["line"], "chain": [], "point": None}),
                       evidence_json=json.dumps({"label": "In-home queueing (likely)", "cause": "R7", "cause_where": "home",
                                                 "facts": facts, "ruled_out": ruled}))
        await s.close()
    asyncio.run(go())
    c = client(path)
    iid = c.get("/api/incidents").json()[0]["id"]
    ko = c.get(f"/api/incidents/{iid}/summary?lang=ko").text
    en = c.get(f"/api/incidents/{iid}/summary").text
    assert "판단 근거:" in ko and "공유기 확인: 11번 중 11번 응답, 평소 3.0 ms, 최대 412.0 ms" in ko and "회선 단절 아님" in ko
    assert "Why:" in en and "+ Router check: 11 of 11 answered" in en and "- Not a line outage: 24 of 24 probes beyond the router were answered" in en
    assert "- Not a router failure: 24 replies from beyond it crossed it" in en
    assert c.get(f"/api/incidents/{iid}?public=1").json()["evidence"]["facts"] == facts
