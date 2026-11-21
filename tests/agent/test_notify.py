import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from whydrop.agent.notify import Notifier, payload

ROW = {"id": 7, "start_ms": 1_800_000_000_000, "end_ms": 1_800_000_046_000, "primary_cause": "R2", "cause_final": "R2",
       "cause_changed": 0, "tags_json": json.dumps({"segments": ["line"], "tags": [], "chain": [], "point": None}),
       "evidence_json": json.dumps({"label": "Line drop in the ISP segment (likely)", "cause": "R2",
                                    "next_step": "Save the evidence with export and contact your ISP",
                                    "protocol": "UDP to 203.0.113.7 via 192.168.0.1"})}


class Sink:
    def __init__(self, fail=0):
        self.got, self.fail = [], fail
        sink = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["content-length"])).decode()
                if sink.fail > 0:
                    sink.fail -= 1
                    self.send_response(503)
                else:
                    sink.got.append((dict(self.headers), body))
                    self.send_response(204)
                self.end_headers()

            def log_message(self, *a):
                pass
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}/hook"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


def finalized(row=ROW):
    return {"type": "incident", "ts": 0, "data": {"op": "finalized", "row": row}}


def test_one_post_per_finalized_drop_none_for_provisional():
    sink = Sink()
    n = Notifier({"webhook_url": sink.url, "format": "json"}, now_ms=lambda: ROW["end_ms"] + 90_000)

    async def go():
        await n.handle({"type": "incident", "data": {"op": "created", "row": ROW}})
        await n.handle({"type": "incident", "data": {"op": "updated", "row": ROW}})
        await n.handle(finalized())
        await n.handle({"type": "sample", "data": {"row": {}}})
    asyncio.run(go())
    sink.close()
    [(h, body)] = sink.got
    doc = json.loads(body)
    assert doc["type"] == "whydrop.drop" and "likely" in doc["text"] and doc["drop"]["cause"] == "R2"


def test_bodies_have_no_raw_ips():
    for fmt in ("json", "ntfy", "discord"):
        body, headers = payload(ROW, fmt, now_ms=ROW["end_ms"])
        assert "203.0.113" not in body and "192.168.0.1" not in body, fmt


def test_formats():
    body, h = payload(ROW, "ntfy", now_ms=ROW["end_ms"])
    assert h["Title"].startswith("whydrop") and "46 s" in body
    body, h = payload(ROW, "discord", now_ms=ROW["end_ms"])
    assert json.loads(body)["content"].startswith("**")


def test_failure_retried_then_dropped_after_24h():
    sink = Sink(fail=2)
    now = [ROW["end_ms"]]
    n = Notifier({"webhook_url": sink.url, "format": "json"}, now_ms=lambda: now[0])

    async def go():
        await n.handle(finalized())                 # 503 → queued
        assert len(n.queue) == 1
        now[0] += 60_000
        await n.retry()                             # 503 again
        now[0] += 120_000
        await n.retry()                             # delivered
        assert n.queue == [] and len(sink.got) == 1
        sink.fail = 99
        await n.handle(finalized())
        now[0] += 25 * 3600_000
        await n.retry()                             # older than 24 h: dropped, not sent
        assert n.queue == []
    asyncio.run(go())
    sink.close()


def test_no_url_means_no_alerts():
    n = Notifier({}, now_ms=lambda: 0)
    asyncio.run(n.handle(finalized()))
    assert n.queue == [] and not n.enabled
