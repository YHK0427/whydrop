import logging
import os
import stat
import sys

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from whydrop.web.app import create_app
from whydrop.web.bus import Bus
from whydrop.web.guard import resolve_token

TOKEN = "t" * 32


def client(token=TOKEN, hosts=("testserver",), tmp_path=None, **kw):
    app = create_app(None, Bus(), token=token, allowed_hosts=list(hosts), public_default=False, **kw)
    return TestClient(app)


def test_health_open():
    assert client().get("/api/health").json() == {"ok": True}


def test_token_required_when_set():
    c = client()
    assert c.get("/api/status").status_code == 401
    assert c.get("/api/status", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200
    assert c.get("/api/status", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_no_token_needed_on_loopback_bind():
    assert client(token=None).get("/api/status").status_code == 200


def test_token_in_query_is_not_accepted_by_the_api():
    """The page moves ?token= into sessionStorage; the API itself never takes it from a URL (logs, history)."""
    assert client().get(f"/api/status?token={TOKEN}").status_code == 401


def test_token_never_logged(caplog):
    caplog.set_level(logging.DEBUG)
    c = client()
    c.get(f"/?token={TOKEN}")
    c.get("/api/status", headers={"Authorization": f"Bearer {TOKEN}"})
    ours = [r.getMessage() for r in caplog.records if not r.name.startswith("httpx")]  # httpx is the test client
    assert not any(TOKEN in m for m in ours)


def test_post_needs_x_whydrop():
    c = client(token=None)
    assert c.post("/api/annotations", json={}).status_code == 403
    assert c.post("/api/annotations", json={}, headers={"X-Whydrop": "1"}).status_code != 403


def test_untrusted_host_400():
    c = client(hosts=("whydrop.local",))
    assert c.get("/api/health", headers={"Host": "evil.example"}).status_code == 400


def test_no_cors_headers():
    r = client(token=None).get("/api/status", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_ws_needs_token_and_same_origin():
    c = client()
    good = lambda: {"Origin": "http://testserver"}  # noqa: E731  (TestClient mutates the dict it gets)
    with c.websocket_connect("/ws", headers=good(), subprotocols=["whydrop", TOKEN]) as ws:
        assert ws.accepted_subprotocol == "whydrop"
        ws.close()  # say goodbye first: TestClient's __exit__ otherwise races the app task on Linux/3.11
    for protos in (["whydrop", "wrong"], ["whydrop"], [TOKEN]):
        with pytest.raises(WebSocketDisconnect):
            with c.websocket_connect("/ws", headers=good(), subprotocols=protos):
                pass


def test_other_port_origin_rejected():
    """Another service on the same host (a different port) must not open the WebSocket."""
    c = client(token=None)
    for origin in ("http://testserver:8081", "https://testserver", "http://evil.example", "null"):
        with pytest.raises(WebSocketDisconnect):
            with c.websocket_connect("/ws", headers={"Origin": origin}, subprotocols=["whydrop"]):
                pass


def test_static_page_has_csp():
    r = client(token=None).get("/")
    assert r.status_code == 200 and "default-src 'self'" in r.headers["content-security-policy"]


def test_resolve_token(tmp_path):
    assert resolve_token("127.0.0.1", {}, tmp_path) is None
    assert resolve_token("0.0.0.0", {"WHYDROP_UI_TOKEN": "x" * 24}, tmp_path) == "x" * 24
    t1 = resolve_token("0.0.0.0", {}, tmp_path)
    assert t1 and len(t1) >= 24 and resolve_token("0.0.0.0", {}, tmp_path) == t1   # kept in the data dir
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(tmp_path / "ui-token").st_mode) == 0o600



def test_non_ascii_or_empty_bearer_is_401_not_500():
    c = client()
    assert c.get("/api/status", headers={"Authorization": "Bearer é".encode("utf-8")}).status_code == 401
    assert c.get("/api/status", headers={"Authorization": "Bearer "}).status_code == 401


def test_empty_token_file_is_replaced(tmp_path):
    (tmp_path / "ui-token").write_text("", encoding="utf-8")
    t = resolve_token("0.0.0.0", {}, tmp_path)
    assert len(t) >= 16 and (tmp_path / "ui-token").read_text(encoding="utf-8") == t


def test_short_env_token_refused(tmp_path):
    with pytest.raises(ValueError):
        resolve_token("0.0.0.0", {"WHYDROP_UI_TOKEN": "short"}, tmp_path)
