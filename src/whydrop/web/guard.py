"""Host, origin, token and write guards (spec §8 "Protections" and "Bind and token")."""
import hmac
import json
import os
import secrets
from pathlib import Path

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
OPEN_API = {"/api/health"}
SAFE_METHODS = {"GET", "HEAD"}
SECURITY_HEADERS = [
    (b"content-security-policy", b"default-src 'self'; img-src 'self' data: blob:; connect-src 'self'; "
                                 b"style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),       # the first page load carries ?token= : never pass it on
    (b"x-frame-options", b"DENY"),
]


def resolve_token(bind_host: str, env, data_dir: Path) -> str | None:
    """No token on a loopback bind; otherwise WHYDROP_UI_TOKEN, or one generated once and kept (mode 600)."""
    if env.get("WHYDROP_UI_TOKEN"):
        return env["WHYDROP_UI_TOKEN"]
    if bind_host in LOOPBACK:
        return None
    path = Path(data_dir) / "ui-token"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    token = secrets.token_urlsafe(24)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(token)
    return token


def allowed_hosts(bind_host: str, extra: list[str]) -> list[str]:
    """localhost + the bind address + configured names; 0.0.0.0 means every address of this host."""
    import socket
    hosts = {"localhost", "127.0.0.1", "::1", *extra}
    if bind_host in ("0.0.0.0", "::", ""):
        try:
            hosts.update(socket.gethostbyname_ex(socket.gethostname())[2])
            hosts.add(socket.gethostname())
        except OSError:
            pass
        from whydrop.agent.probes import host_net
        src = host_net.source_address()
        if src:
            hosts.add(src)
    else:
        hosts.add(bind_host)
    return sorted(hosts)


def _headers(scope) -> dict[bytes, bytes]:
    return {k.lower(): v for k, v in scope.get("headers", [])}


class Guard:
    """Pure ASGI middleware, so it also covers the WebSocket handshake and static files."""

    def __init__(self, app, token: str | None):
        self.app, self.token = app, token

    def _ok(self, presented: str | None) -> bool:
        return self.token is None or (presented is not None and hmac.compare_digest(presented, self.token))

    async def _deny(self, send, status: int, msg: str) -> None:
        body = json.dumps({"error": msg}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), *SECURITY_HEADERS]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            h, path = _headers(scope), scope["path"]
            if path.startswith("/api/") and path not in OPEN_API:
                auth = h.get(b"authorization", b"").decode("latin-1")
                if not self._ok(auth[7:] if auth.startswith("Bearer ") else None):
                    return await self._deny(send, 401, "token required")
                if scope["method"] not in SAFE_METHODS and h.get(b"x-whydrop") != b"1":
                    return await self._deny(send, 403, "missing X-Whydrop header")

            async def secured(msg):
                if msg["type"] == "http.response.start":
                    msg = {**msg, "headers": [*msg.get("headers", []), *SECURITY_HEADERS]}
                await send(msg)
            return await self.app(scope, receive, secured)
        if scope["type"] == "websocket":
            scope.setdefault("state", {})["ws_allowed"] = self.ws_allowed(scope)  # the endpoint closes if not
        await self.app(scope, receive, send)

    def ws_allowed(self, scope) -> bool:
        """Same scheme, host and port as the page, the whydrop subprotocol, and the token when one is set."""
        h = _headers(scope)
        scheme = "https" if scope.get("scheme") == "wss" else "http"
        same = h.get(b"origin", b"").decode("latin-1") == f"{scheme}://{h.get(b'host', b'').decode('latin-1')}"
        protos = scope.get("subprotocols", [])
        tok = next((p for p in protos if p != "whydrop"), None)
        return same and "whydrop" in protos and self._ok(tok)
