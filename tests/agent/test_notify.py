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


def test_in_home_queueing_alert_names_the_home_network_and_says_slowed():
    """Seen on the demo's incident 38: an in-home queueing verdict was sent as 'Internet line dropped'."""
    from whydrop.agent.notify import text
    row = {**ROW, "primary_cause": "R7", "cause_final": "R7",
           "evidence_json": json.dumps({"label": "In-home queueing (likely)", "cause": "R7", "cause_where": "home"})}
    title, sentence = text(row, ROW["end_ms"])
    assert title == "whydrop: Home network slowed down"
    assert sentence.startswith("Home network slowed down for 46 s. In-home queueing (likely).")
    r7 = {**row, "evidence_json": json.dumps({"label": "Queueing caused the timeouts (likely)", "cause": "R7"})}
    assert text(r7, ROW["end_ms"])[1].startswith("Internet line slowed down for 46 s.")   # queueing past the router


def test_alert_title_names_the_agent():
    """agent_name was documented as 'shown in alerts' but never was: with two agents you couldn't tell them apart."""
    body, headers = payload(ROW, "ntfy", ROW["end_ms"], name="parents")
    assert headers["Title"] == "whydrop parents: Internet line dropped"
    assert json.loads(payload(ROW, "discord", ROW["end_ms"], name="parents")[0])["content"].startswith("**whydrop parents:")
    blob = json.loads(payload(ROW, "json", ROW["end_ms"], name="parents")[0])
    assert blob["title"] == "whydrop parents: Internet line dropped" and "parents" not in json.dumps(blob["drop"])
    assert payload(ROW, "ntfy", ROW["end_ms"])[1]["Title"] == "whydrop: Internet line dropped"   # no name: as before


def test_korean_alert_uses_the_dashboard_wording():
    """Alerts were English only; with `[notify] lang = "ko"` they use the dashboard's Korean words."""
    import base64
    body, headers = payload(ROW, "ntfy", ROW["end_ms"], lang="ko")
    assert body == "인터넷 회선이 46초 동안 끊겼어요. ISP 구간의 회선 끊김 (추정). 내보내기로 증거를 저장하고 통신사에 문의하세요."
    title = headers["Title"]
    assert title.isascii() and title.startswith("=?UTF-8?B?")                      # a header must be Latin-1
    assert base64.b64decode(title[10:-2]).decode() == "whydrop: 인터넷 회선이 끊김"
    home = {**ROW, "primary_cause": "R7", "cause_final": "R7",
            "evidence_json": json.dumps({"label": "In-home queueing (likely)", "cause": "R7", "cause_where": "home"})}
    assert payload(home, "json", ROW["end_ms"], lang="ko")[0].count("집 안 네트워크가 46초 동안 느려졌어요.") == 1


def test_alert_title_header_survives_a_name_with_a_newline():
    _, headers = payload(ROW, "ntfy", ROW["end_ms"], name="a\r\nX-Evil: 1")
    assert "\n" not in headers["Title"] and "\r" not in headers["Title"]



def test_a_failed_retry_is_persisted_with_its_backoff():
    """A retry that failed again changed tries/next_ms but wasn't saved: after a restart the backoff started over."""
    saved = []
    sink = Sink(fail=99)
    now = [ROW["end_ms"]]
    n = Notifier({"webhook_url": sink.url}, now_ms=lambda: now[0], on_queue=lambda q: saved.append(json.dumps(q)))

    async def go():
        await n.handle(finalized())
        now[0] += 60_000
        await n.retry()
    asyncio.run(go())
    sink.close()
    assert json.loads(saved[-1])[0]["tries"] == 2


def test_the_retry_queue_is_bounded():
    now = [ROW["end_ms"]]
    n = Notifier({"webhook_url": "http://127.0.0.1:9/x"}, now_ms=lambda: now[0])

    async def fail(row):
        return False
    n._send = fail
    for i in range(150):
        asyncio.run(n.handle(finalized({**ROW, "id": i})))
        now[0] += 301_000                                               # under the hourly cap
    assert len(n.queue) == 100 and n.queue[0]["row"]["id"] == 50      # the newest 100 are kept


def test_a_storm_of_drops_is_capped_and_the_next_alert_says_how_many_were_held():
    """A flapping line finalized dozens of drops an hour, each one a phone notification."""
    sink = Sink()
    now = [ROW["end_ms"]]
    n = Notifier({"webhook_url": sink.url, "format": "ntfy"}, now_ms=lambda: now[0])

    async def go():
        for i in range(20):
            await n.handle(finalized({**ROW, "id": i}))
            now[0] += 60_000
        now[0] += 3600_000
        await n.handle(finalized({**ROW, "id": 99}))
    asyncio.run(go())
    sink.close()
    assert len(sink.got) == 13
    assert sink.got[-1][1].endswith("(+8 more drops not alerted; see the dashboard)")
    assert "more drops" not in sink.got[-2][1]
