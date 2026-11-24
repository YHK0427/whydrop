"""The FastAPI app: API routes, /ws and the static dashboard, behind the guards (spec §8).

Every response body is built and serialized in a worker thread: the app shares its event loop with the probes, and a
few megabytes of JSON encoded on the loop would delay them (and distort what the dashboard shows)."""
import asyncio
import json
import mimetypes
import sqlite3
import time
from pathlib import Path

from typing import Annotated

from fastapi import FastAPI, HTTPException, Path as FPath, Request, WebSocket
from fastapi.responses import PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from whydrop.web import export as X
from whydrop.web import queries as Q
from whydrop.web.bus import Bus
from whydrop.web.guard import Guard, HostGuard
from whydrop.web.public import public as to_public

STATIC = Path(__file__).with_name("static")
mimetypes.add_type("text/javascript", ".js")   # some Windows registries map .js to text/plain (ES modules then refuse to load)
mimetypes.add_type("application/manifest+json", ".webmanifest")

DAY_MS = 86_400_000
WS_KIND = {"segment": "segment", "incident": "incident", "condition": "condition", "event": "event",
           "finding": "finding", "annotation": "annotation"}


def public_message(msg: dict, now_ms: int) -> dict:
    """Envelope {type, ts, data:{op?, row}} with the row through the public allowlist; unknown types carry nothing."""
    kind = WS_KIND.get(msg["type"])
    data = msg.get("data") or {}
    row = to_public(data.get("row") or {}, kind, now_ms) if kind else {}
    return {"type": msg["type"], "ts": 0, "data": {"op": data.get("op"), "row": row}}


def _wall_now() -> int:
    return int(time.time() * 1000)


def _dumps(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")


MAX_MS = 2**53                                   # far past any real time, well inside SQLite integers
IncidentId = Annotated[int, FPath(ge=1, le=MAX_MS)]


def create_app(db_path, bus: Bus, *, token: str | None, allowed_hosts: list[str], public_default: bool,
               status=None, nat_run=None, nat_state=None, packets=None, clock=None) -> FastAPI:
    """clock: epoch-ms source; export-static pins it to the end of the exported range."""
    _now = clock or _wall_now
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db_path, app.state.bus, app.state.public_default = db_path, bus, public_default

    @app.get("/static.json")
    async def not_static():
        return {"static": False}   # the live dashboard; export-static writes a real static.json

    @app.get("/api/health")
    async def health():
        return {"ok": True}

    def is_public(request: Request) -> bool:
        return request.query_params.get("public") == "1" or public_default

    def span(request: Request, default_ms: int = DAY_MS) -> tuple[int, int]:
        q = request.query_params
        try:
            to = int(q.get("to") or _now())
            frm = int(q.get("from") or to - default_ms)
        except ValueError:
            raise HTTPException(400, "from/to are epoch milliseconds")
        if not 0 <= frm < to <= MAX_MS:   # SQLite integers end at 2^63: past that a query raised (a 500)
            raise HTTPException(400, "from must be before to, both epoch milliseconds")
        return frm, to

    async def reply(request: Request, fetch, kind: str | None = None, *, one: bool = False, headers=None) -> Response:
        """fetch() and, in public view, the allowlist and the JSON encoding all run in a worker thread."""
        pub, now = is_public(request), _now()

        def work():
            data = fetch()
            if data is None:
                return None
            if kind and pub:
                data = [to_public(r, kind, now) for r in data]
            if one:
                data = data[0] if data else None
            return _dumps(data)
        body = await asyncio.to_thread(work)
        if body is None or body == b"null":
            raise HTTPException(404, "not found")
        return Response(body, media_type="application/json", headers=headers)

    @app.get("/api/status")
    async def get_status(request: Request):
        st = {**(status() if status else {}), "public": is_public(request)}
        frm = int(time.mktime(time.localtime(_now() / 1000)[:2] + (1, 0, 0, 0, 0, 0, -1)) * 1000)  # month start (local)
        st["month"] = await asyncio.to_thread(Q.availability, db_path, frm, _now())
        if is_public(request):
            st = to_public(st, "status", _now()) | {"month": st["month"], "public": True}
        return Response(_dumps(st), media_type="application/json")

    @app.get("/api/chart")
    async def get_chart(request: Request):
        """What the lanes draw, already bucketed and columnar: a few kB instead of every per-pair row."""
        frm, to = span(request, 3_600_000)
        step = request.query_params.get("step")
        pub, now = is_public(request), _now()

        def work():
            res = Q.chart(db_path, frm, to, int(step) if step and step.isdigit() else None, now_ms=now)
            if pub:   # no absolute times in the public view: seconds relative to now, like every other public row
                res["x_rel"] = [x - now // 1000 for x in res.pop("x")]
            return _dumps(res)
        return Response(await asyncio.to_thread(work), media_type="application/json")

    @app.get("/api/samples")
    async def get_samples(request: Request):
        frm, to = span(request, 3_600_000)
        step = request.query_params.get("step")
        pub, now = is_public(request), _now()

        def work():
            res = Q.samples(db_path, frm, to, int(step) if step and step.isdigit() else None, request.query_params.get("probe"),
                            now_ms=now)
            if pub:
                res["rows"] = [to_public(r, "sample", now) for r in res["rows"]]
            return _dumps(res)
        return Response(await asyncio.to_thread(work), media_type="application/json")

    @app.get("/api/segments")
    async def get_segments(request: Request):
        frm, to = span(request)
        return await reply(request, lambda: Q.ranged(db_path, "segments", frm, to), "segment")

    @app.get("/api/incidents")
    async def get_incidents(request: Request):
        frm, to = span(request, 30 * DAY_MS)
        return await reply(request, lambda: Q.overlapping(db_path, "incidents", frm, to), "incident")

    @app.get("/api/incidents/{iid}")
    async def get_incident(iid: IncidentId, request: Request):
        return await reply(request, lambda: [r for r in [Q.incident(db_path, iid)] if r], "incident", one=True)

    @app.get("/api/incidents/{iid}/summary")
    async def get_summary(iid: IncidentId, request: Request):
        text = await asyncio.to_thread(X.summary, db_path, iid, request.query_params.get("lang", "en"), is_public(request), _now())
        if text is None:
            raise HTTPException(404, "no such drop")
        return PlainTextResponse(text)

    @app.get("/api/incidents/{iid}/strip")
    async def get_strip(iid: IncidentId, request: Request):
        """Per-packet record kept ±60 s around the drop (precision mode only)."""
        def fetch():
            inc = Q.incident(db_path, iid)
            if inc is None:
                return None
            a, b = inc["start_ms"] - 60_000, (inc["end_ms"] or _now()) + 60_000
            return Q.rows(db_path, "SELECT ts_ms, seq, echoed, dir FROM udp_seq_ring WHERE ts_ms >= ? AND ts_ms <= ? "
                                   "ORDER BY seq LIMIT 3000", (a, b))
        return await reply(request, fetch, "strip")

    @app.get("/api/conditions")
    async def get_conditions(request: Request):
        frm, to = span(request, 7 * DAY_MS)
        return await reply(request, lambda: Q.overlapping(db_path, "conditions", frm, to), "condition")

    @app.get("/api/events")
    async def get_events(request: Request):
        frm, to = span(request)
        kind = request.query_params.get("kind")
        extra, params = ("AND kind = ?", (kind,)) if kind else ("", ())
        return await reply(request, lambda: Q.ranged(db_path, "events", frm, to, "ts_ms", extra, params), "event")

    @app.get("/api/findings")
    async def get_findings(request: Request):
        frm, to = span(request, 365 * DAY_MS)
        return await reply(request, lambda: Q.overlapping(db_path, "findings", frm, to), "finding")

    @app.get("/api/selfcheck")
    async def get_selfcheck(request: Request):
        return await reply(request, lambda: Q.rows(db_path, "SELECT * FROM selfcheck ORDER BY id DESC LIMIT 1"), "selfcheck")

    @app.get("/api/nat")
    async def get_nat(request: Request):
        pub = is_public(request)

        def work():
            runs = Q.rows(db_path, "SELECT * FROM nat_runs ORDER BY id DESC LIMIT 5")
            results = Q.rows(db_path, "SELECT * FROM nat_results WHERE run_id = ?", (runs[0]["id"],)) if runs else []
            return _dumps({"running": nat_state() if nat_state else None, "last_run": runs[0] if runs and not pub else None,
                           "results": [to_public(r, "nat", 0) for r in results] if pub else results})
        return Response(await asyncio.to_thread(work), media_type="application/json")

    @app.post("/api/nat/run")
    async def post_nat_run():
        if nat_run is None:
            raise HTTPException(400, "nat-test needs precision mode (a reflector and WHYDROP_SECRET)")
        if not nat_run():
            raise HTTPException(409, "a NAT test is already running")
        return {"started": True}

    @app.get("/api/gaps")
    async def get_gaps(request: Request):
        frm, to = span(request, 30 * DAY_MS)
        return await reply(request, lambda: Q.gaps(db_path, frm, to), "gap")

    @app.get("/api/annotations")
    async def get_annotations(request: Request):
        frm, to = span(request, 30 * DAY_MS)
        return await reply(request, lambda: Q.rows(
            db_path, "SELECT * FROM annotations WHERE start_ms < ? AND COALESCE(end_ms, start_ms) >= ? ORDER BY start_ms",
            (to, frm)), "annotation")

    @app.post("/api/annotations")
    async def post_annotation(request: Request):
        try:
            if len(await request.body()) > 4096:
                raise ValueError("annotation too large")
            body = await request.json()
            start = int(body["start_ms"])
            end = int(body["end_ms"]) if body.get("end_ms") is not None else None
            if not 0 <= start <= MAX_MS or (end is not None and not start <= end <= MAX_MS):
                raise ValueError("start_ms/end_ms must be epoch milliseconds, start first")
            rid = await asyncio.to_thread(Q.add_annotation, db_path, start, end, str(body.get("label")), body.get("note"))
        except (KeyError, TypeError, ValueError, OverflowError, AttributeError) as e:
            raise HTTPException(400, str(e) or "bad annotation")
        except (FileNotFoundError, sqlite3.Error):
            raise HTTPException(503, "the database is not available right now")
        bus.publish("annotation", {"op": "created",
                                   "row": {"id": rid, "start_ms": start, "end_ms": end, "label": body.get("label")}})
        return {"id": rid}

    @app.get("/api/packets")
    async def get_packets(request: Request):
        return await reply(request, lambda: packets() if packets else [], "packet")

    @app.get("/api/export/bugreport/{iid}")
    async def get_bugreport(iid: IncidentId, request: Request):
        def work():
            rep = X.bugreport(db_path, iid, _now())
            return None if rep is None else _dumps(rep)
        body = await asyncio.to_thread(work)
        if body is None:
            raise HTTPException(404, "no such drop")
        return Response(body, media_type="application/json",
                        headers={"content-disposition": f'attachment; filename="whydrop-bugreport-{iid}.json"'})

    @app.get("/api/export/{name}.{fmt}")
    async def get_export(name: str, fmt: str, request: Request):
        if name not in X.TABLES or fmt not in ("csv", "json"):
            raise HTTPException(404, "export incidents|conditions|samples_1m|events as .csv or .json")
        frm, to = span(request, 30 * DAY_MS)
        # a sync generator: Starlette iterates it in a worker thread, row by row from the cursor (no big list in memory)
        return StreamingResponse(X.stream(db_path, name, frm, to, fmt, is_public(request), _now()),
                                 media_type="application/json" if fmt == "json" else "text/csv; charset=utf-8",
                                 headers={"content-disposition": f'attachment; filename="whydrop-{name}.{fmt}"'})

    @app.websocket("/ws")
    async def ws(socket: WebSocket):
        if not socket.scope.get("state", {}).get("ws_allowed"):
            await socket.close(code=1008)   # rejected before accept: the browser sees a failed handshake
            return
        await socket.accept(subprotocol="whydrop")
        q = bus.subscribe()
        pub = socket.query_params.get("public") == "1" or public_default

        async def pump():
            while True:
                msg = await q.get()
                if pub:
                    msg = public_message(msg, _now())
                await socket.send_json(msg)

        async def drain():  # notice the browser leaving even when nothing is being sent
            while (await socket.receive())["type"] != "websocket.disconnect":
                pass
        tasks = [asyncio.create_task(pump()), asyncio.create_task(drain())]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            bus.unsubscribe(q)

    app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
    app.add_middleware(Guard, token=token)
    app.add_middleware(HostGuard, allowed_hosts=allowed_hosts)  # added last = runs first
    import gc
    gc.freeze()   # modules and the app live forever: full collections (which hold the GIL, so the probes' loop too) skip them
    return app
