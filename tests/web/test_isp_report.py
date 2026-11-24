"""The ISP report lists only what happened beyond the router, with the home side's state at the same time."""
import asyncio
import json

from fastapi.testclient import TestClient

from test_api import NOW
from whydrop.agent.store import SampleRow, Store
from whydrop.web.app import create_app
from whydrop.web.bus import Bus


def _db(tmp_path):
    path = tmp_path / "w.db"

    async def go():
        s = Store(path)
        await s.open()
        await s.run_start(NOW - 3_600_000, "t", {"mode": "basic"})
        await s.add_samples([SampleRow(NOW - 3_000_000, "gateway", "gateway", 1, 1, 0), SampleRow(NOW - 880_000, "gateway", "gateway", 1, 1, 0)])
        await s.flush()
        inc = lambda start, rule, segs, ev: s.insert("incidents", start_ms=start, end_ms=start + 46_000, primary_cause=rule,
                                                     cause_final=rule, tags_json=json.dumps({"segments": segs, "point": None}),
                                                     evidence_json=json.dumps(ev))
        await inc(NOW - 2_000_000, "R2", ["line"], {"label": "Line drop in the ISP segment (likely)", "facts": [
            {"k": "gw", "sent": 46, "ok": 46, "lost": 0, "late": 0, "base": 2.0, "peak": 3.0},
            {"k": "line", "sent": 230, "ok": 0, "late": 0, "lost": 230, "peak": None}]})
        await inc(NOW - 1_500_000, "R1a", ["wifi"], {"label": "Wi-Fi problem (likely)"})
        await inc(NOW - 1_000_000, "R7", ["line"], {"label": "In-home queueing (likely)", "cause_where": "home"})
        await inc(NOW - 600_000, "R2", ["line"], {"label": "Line drop in the ISP segment (likely)"})   # injected below
        await s.insert("annotations", agent_id=1, start_ms=NOW - 610_000, end_ms=NOW - 500_000, label="injected", note="")
        await s.insert("conditions", kind="loss", start_ms=NOW - 900_000, end_ms=NOW - 853_000,
                       detail_json=json.dumps({"loss": 0.1, "where": "line", "cause": "R6"}))
        await s.close()
    asyncio.run(go())
    return path


def test_the_isp_report_lists_line_events_with_the_home_side_and_counts_the_rest(tmp_path):
    c = TestClient(create_app(_db(tmp_path), Bus(), token=None, allowed_hosts=["testserver"], public_default=False,
                              clock=lambda: NOW))
    en = c.get(f"/api/isp-report?from={NOW - 3_600_000}&to={NOW}").text
    assert "Line drops beyond the router: 1 (total 46 s)" in en
    assert "Line drop in the ISP segment\n    router answered 46 of 46 checks; beyond the router 0 of 230 answered (0 late)" in en
    assert "Lossy line periods: 1 (total 47 s, worst 10.0 %)" in en and "10.0 % loss beyond the router\n    router answered 1 of 1 checks" in en
    assert "Not included: 2 events on the home network (Wi-Fi, router, in-home), 1 marked as tests." in en
    assert "(likely)" not in en and "Wi-Fi problem" not in en and "queueing" not in en
    ko = c.get(f"/api/isp-report?from={NOW - 3_600_000}&to={NOW}&lang=ko").text
    assert "공유기 너머 회선 끊김: 1 (합계 46초)" in ko and "공유기는 확인 46번 중 46번 응답" in ko
