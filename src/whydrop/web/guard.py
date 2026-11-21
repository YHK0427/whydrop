"""Host, origin, token and write guards (spec §8 "Protections" and "Bind and token")."""
import hmac
import ipaddress
import json
import os
import re
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


MIN_TOKEN = 16
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,}$")   # survives URLs, headers and WebSocket subprotocols


def resolve_token(bind_host: str, env, data_dir: Path) -> str | None:
    """No token on a loopback bind; otherwise WHYDROP_UI_TOKEN (≥ 16 characters), or one generated once and kept
    (mode 600, written atomically)."""
    given = (env.get("WHYDROP_UI_TOKEN") or "").strip()
    if given and not TOKEN_RE.match(given):
        raise ValueError("WHYDROP_UI_TOKEN must be at least 16 characters of A-Z a-z 0-9 _ - "
                         "(e.g. python -c \"import secrets; print(secrets.token_urlsafe(32))\")")
    if given:
        return given
    if bind_host in LOOPBACK:
        return None
    path = Path(data_dir) / "ui-token"
    try:
        kept = path.read_text(encoding="utf-8").strip()
    except OSError:
        kept = ""
    if len(kept) >= MIN_TOKEN:
        return kept
    token = secrets.token_urlsafe(24)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".ui-token.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(token)
    os.replace(tmp, path)          # never a half-written (empty) token on disk
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
        if self.token is None:
            return True
        if not presented:
            return False
        return hmac.compare_digest(presented.encode("utf-8", "replace"), self.token.encode("utf-8"))  # bytes: any input

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


class HostGuard:
    """Host header check (DNS-rebinding defence): the configured names, or an IP literal equal to the address this
    connection actually arrived on — so a DHCP change or a router that came up after us doesn't lock the LAN out.
    Rebinding needs a hostname, never a literal."""

    def __init__(self, app, allowed_hosts: list[str]):
        self.app, self.allowed = app, {h.lower().strip("[]") for h in allowed_hosts}

    @staticmethod
    def _host(value: str) -> str:
        value = value.strip().lower()
        if value.startswith("["):                       # [v6]:port
            return value[1:value.find("]")] if "]" in value else value
        return value.rsplit(":", 1)[0] if value.count(":") == 1 else value

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            host = self._host(_headers(scope).get(b"host", b"").decode("latin-1"))
            arrived = (scope.get("server") or ("", 0))[0]
            literal_ok = False
            try:
                literal_ok = ipaddress.ip_address(host) == ipaddress.ip_address(arrived)
            except ValueError:
                pass
            if host not in self.allowed and not literal_ok:
                if scope["type"] == "websocket":
                    await receive()
                    await send({"type": "websocket.close", "code": 1008})
                    return
                await send({"type": "http.response.start", "status": 400,
                            "headers": [(b"content-type", b"text/plain"), *SECURITY_HEADERS]})
                await send({"type": "http.response.body", "body": b"Invalid host header"})
                return
        await self.app(scope, receive, send)
