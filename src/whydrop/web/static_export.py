"""`whydrop export-static`: a read-only copy of the dashboard for GitHub Pages (spec §8).

Every data file is produced by calling the real app (public view forced, no token) in process, so the demo shows exactly
what the live public view would, and nothing the public view hides. Times are relative to the export moment."""
import asyncio
import json
import shutil
import time
from pathlib import Path
from urllib.parse import urlencode

from whydrop.web.app import STATIC, create_app
from whydrop.web.bus import Bus

RANGES = (3600, 21600, 86400, 604800)          # the Now page's range buttons
LIST_SPANS = (30 * 86400, 90 * 86400)           # drop lists (Now: 30 d, Drops/Network: 90 d)


async def _get(app, path: str, query: dict | None = None) -> tuple[int, bytes]:
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "http",
             "path": path, "raw_path": path.encode(), "query_string": urlencode(query or {}).encode(),
             "headers": [(b"host", b"localhost")], "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 80)}
    out = {"status": 500, "body": b""}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
        elif msg["type"] == "http.response.body":
            out["body"] += msg.get("body", b"")
    await app(scope, receive, send)
    return out["status"], out["body"]


def key_for(path: str, span: int | None = None, incident: int | None = None, kind: str | None = None,
            lang: str | None = None) -> str:
    """The data file name the static frontend asks for (mirrors lib.js staticKey)."""
    k = path.removeprefix("/api/").replace("/", "_")
    if incident is not None:
        k += f"_incident_{incident}"
    elif span is not None:
        k += f"_{span}"
    if kind:
        k += f"_{kind}"
    if lang == "ko":
        k += "_ko"
    return k + ".json"


def _edge_ms(db: Path, fn: str) -> int | None:
    import sqlite3
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return con.execute(f"SELECT {fn}(t) FROM (SELECT {fn}(ts_ms) t FROM samples_1s UNION ALL SELECT {fn}(ts_ms) FROM samples_1m)").fetchone()[0]
    finally:
        con.close()


def _first_ms(db: Path) -> int | None:
    return _edge_ms(db, "MIN")


def export_static(db: Path, out: Path, from_ms: int | None = None, to_ms: int | None = None, status_extra: dict | None = None) -> dict:
    now = to_ms or _edge_ms(db, "MAX") or int(time.time() * 1000)   # the recording's end, not the export's moment
    app = create_app(db, Bus(), token=None, allowed_hosts=["localhost"], public_default=True, clock=lambda: now,
                     status=lambda: {"mode": (status_extra or {}).get("mode", "basic"), "baseline": "ready",
                                     "segments": {s: "up" for s in ("host_net", "wifi", "lan", "line", "dns")},
                                     "link": (status_extra or {}).get("link", "wifi"), **(status_extra or {})})
    if out.exists() and any(out.iterdir()):
        try:
            ours = json.loads((out / "static.json").read_text(encoding="utf-8")).get("static") is True
        except (OSError, ValueError, AttributeError):
            ours = False
        if not ours:   # never wipe a directory this command didn't write
            raise FileExistsError(f"{out} is not empty and is not an earlier export-static output")
        shutil.rmtree(out)
    elif out.exists():
        out.rmdir()
    shutil.copytree(STATIC, out)
    (out / "static.json").write_text(json.dumps({"static": True, "partial": True}), encoding="utf-8")  # ours, even half-done
    data = out / "data"
    data.mkdir()
    written = []

    async def grab(path, name, query=None):
        code, body = await _get(app, path, query)
        if code == 200:
            (data / name).write_bytes(body)
            written.append(name)
        return code, body

    async def main():
        await grab("/api/status", key_for("/api/status"))
        for path in ("/api/findings", "/api/selfcheck", "/api/nat", "/api/packets"):
            await grab(path, key_for(path))
        await grab("/api/isp-report", key_for("/api/isp-report"), {"format": "json"})   # the report page, as of the recording's end
        for span in LIST_SPANS:
            code, body = await grab("/api/incidents", key_for("/api/incidents", span), {"from": now - span * 1000, "to": now})
        incidents = json.loads(body) if code == 200 else []
        for span in RANGES:
            q = {"from": now - span * 1000, "to": now}
            await grab("/api/chart", key_for("/api/chart", span), q)
            await grab("/api/conditions", key_for("/api/conditions", span), q)
            await grab("/api/events", key_for("/api/events", span, kind="rst"), {**q, "kind": "rst"})
            await grab("/api/annotations", key_for("/api/annotations", span), q)   # scene tags on the Now page
        for inc in incidents:
            iid = inc["id"]
            await grab(f"/api/incidents/{iid}", key_for(f"/api/incidents/{iid}"))
            await grab(f"/api/incidents/{iid}/strip", key_for(f"/api/incidents/{iid}/strip"))
            for lang in ("en", "ko"):   # the copied summary, in the page's language
                await grab(f"/api/incidents/{iid}/summary", key_for(f"/api/incidents/{iid}/summary", lang=lang), {"lang": lang})
            start = now + inc["start_s"] * 1000
            end = now + (inc["end_s"] if inc["end_s"] is not None else 0) * 1000
            q = {"from": int(start - 60_000), "to": int(end + 60_000)}
            await grab("/api/chart", key_for("/api/chart", incident=iid), {**q, "step": 1})
            await grab("/api/events", key_for("/api/events", incident=iid), q)
            await grab("/api/annotations", key_for("/api/annotations", incident=iid), q)
    asyncio.run(main())
    for name in written:   # summaries are text: store them as JSON strings so the static fetch parses alike
        p = data / name
        if name.endswith("_summary.json"):
            p.write_text(json.dumps(p.read_text(encoding="utf-8"), ensure_ascii=False), encoding="utf-8")
    from datetime import datetime
    day = lambda ms: datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d")  # noqa: E731  the recorder's own calendar
    manifest = {"static": True, "files": len(written), "recorded": [day(from_ms or _first_ms(db) or now), day(now)]}
    (out / "static.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest
