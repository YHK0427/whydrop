"""GET /api/metrics: Prometheus text format, behind the token, no addresses in labels."""
import re

from fastapi.testclient import TestClient

from test_api import NOW, client, db  # noqa: F401  (db is a fixture)
from whydrop.web.app import create_app
from whydrop.web.bus import Bus

LINE = re.compile(r'^(# (HELP|TYPE) .+|[a-z_]+(\{([a-z_]+="[^"]*",?)+\})? -?[0-9.e+-]+)$')
STATUS = {"version": "9.9.9", "mode": "basic", "link": "wifi", "signal_dbm": -61,
          "segments": {"wifi": "up", "line": "down", "dns": "unknown"}, "bytes": {"line_hb": 1234}}


def test_metrics_report_the_last_complete_minute_without_addresses(db):
    c = client(db, status=lambda: STATUS, clock=lambda: NOW - 600_000 + 75_000)   # window: the first 60 s of samples
    r = c.get("/api/metrics")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert all(LINE.match(x) for x in body.strip().split("\n")), body
    assert 'whydrop_probe_loss_ratio{probe="line_hb",target="line_hb"} 0.083333' in body   # 5 of 60
    assert 'whydrop_probe_rtt_milliseconds{probe="line_hb",target="line_hb",stat="avg"} 12.0' in body
    assert 'whydrop_segment_up{segment="line"} 0' in body and 'whydrop_segment_up{segment="wifi"} 1' in body
    assert 'segment="dns"' not in body                                    # unknown is absent, not 0
    assert 'whydrop_last_drop_end_timestamp_seconds{cause="R2"}' in body
    assert 'whydrop_probe_bytes_total{probe="line_hb"} 1234' in body and "whydrop_wifi_signal_dbm -61" in body
    assert "192.168." not in body and 'target="dns_router"' in body


def test_metrics_need_the_token(db):
    c = TestClient(create_app(db, Bus(), token="t" * 20, allowed_hosts=["testserver"], public_default=False))
    assert c.get("/api/metrics").status_code == 401
    assert c.get("/api/metrics", headers={"authorization": "Bearer " + "t" * 20}).status_code == 200
