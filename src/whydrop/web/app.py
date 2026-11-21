"""The FastAPI app: API routes, /ws and the static dashboard, behind the guards (spec §8)."""
import asyncio
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from whydrop.web import export as X
from whydrop.web import queries as Q
from whydrop.web.bus import Bus
from whydrop.web.guard import Guard
from whydrop.web.public import public as to_public

STATIC = Path(__file__).with_name("static")


DAY_MS = 86_400_000
WS_KIND = {"sample": "sample", "segment": "segment", "incident": "incident", "condition": "condition",
           "event": "event", "finding": "finding", "annotation": "annotation"}


def public_message(msg: dict, now_ms: int) -> dict:
    """Envelope {type, ts, data:{op?, row}} with the row through the public allowlist; unknown types carry nothing."""
    kind = WS_KIND.get(msg["type"])
    data = msg.get("data") or {}
    row = to_public(data.get("row") or {}, kind, now_ms) if kind else {}
    return {"type": msg["type"], "ts": 0, "data": {"op": data.get("op"), "row": row}}


def _now() -> int:
    return int(time.time() * 1000)


def create_app(db_path, bus: Bus, *, token: str | None, allowed_hosts: list[str], public_default: bool,
               status=None, nat_run=None, nat_state=None, packets=None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db_path, app.state.bus, app.state.public_default = db_path, bus, public_default

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
        if frm >= to:
            raise HTTPException(400, "from must be before to")
        return frm, to

    def out(request: Request, rows, kind: str):
        if is_public(request):
            now = _now()
            return [to_public(r, kind, now) for r in rows]
        return rows

    async def run(fn, *a):
        return await asyncio.to_thread(fn, *a)

    @app.get("/api/status")
    async def get_status(request: Request):
        st = status() if status else {}
        frm = int(time.mktime(time.localtime()[:2] + (1, 0, 0, 0, 0, 0, -1)) * 1000)  # start of this month
        st = {**st, "month": await run(Q.availability, db_path, frm, _now())}
        return to_public(st, "status", _now()) | {"month": st["month"]} if is_public(request) else st

    @app.get("/api/samples")
    async def get_samples(request: Request):
        frm, to = span(request, 3_600_000)
        step = request.query_params.get("step")
        res = await run(Q.samples, db_path, frm, to, int(step) if step and step.isdigit() else None,
                        request.query_params.get("probe"))
        return {**res, "rows": out(request, res["rows"], "sample")}

    @app.get("/api/segments")
    async def get_segments(request: Request):
        frm, to = span(request)
        return out(request, await run(Q.ranged, db_path, "segments", frm, to), "segment")

    @app.get("/api/incidents")
    async def get_incidents(request: Request):
        frm, to = span(request, 30 * DAY_MS)
        return out(request, await run(Q.overlapping, db_path, "incidents", frm, to), "incident")

    @app.get("/api/incidents/{iid}")
    async def get_incident(iid: int, request: Request):
        inc = await run(Q.incident, db_path, iid)
        if inc is None:
            raise HTTPException(404, "no such drop")
        return out(request, [inc], "incident")[0]

    @app.get("/api/incidents/{iid}/summary")
    async def get_summary(iid: int, request: Request):
        text = await run(X.summary, db_path, iid, request.query_params.get("lang", "en"))
        if text is None:
            raise HTTPException(404, "no such drop")
        return PlainTextResponse(text)

    @app.get("/api/conditions")
    async def get_conditions(request: Request):
        frm, to = span(request, 7 * DAY_MS)
        return out(request, await run(Q.overlapping, db_path, "conditions", frm, to), "condition")

    @app.get("/api/events")
    async def get_events(request: Request):
        frm, to = span(request)
        kind = request.query_params.get("kind")
        extra, params = ("AND kind = ?", (kind,)) if kind else ("", ())
        return out(request, await run(Q.ranged, db_path, "events", frm, to, "ts_ms", extra, params), "event")

    @app.get("/api/findings")
    async def get_findings(request: Request):
        frm, to = span(request, 365 * DAY_MS)
        return out(request, await run(Q.overlapping, db_path, "findings", frm, to), "finding")

    @app.get("/api/selfcheck")
    async def get_selfcheck(request: Request):
        r = await run(Q.rows, db_path, "SELECT * FROM selfcheck ORDER BY id DESC LIMIT 1")
        return out(request, r, "selfcheck")

    @app.get("/api/nat")
    async def get_nat(request: Request):
        runs = await run(Q.rows, db_path, "SELECT * FROM nat_runs ORDER BY id DESC LIMIT 5")
        results = await run(Q.rows, db_path, "SELECT * FROM nat_results WHERE run_id = ?", (runs[0]["id"],)) if runs else []
        return {"running": nat_state() if nat_state else None, "last_run": runs[0] if runs and not is_public(request) else None,
                "results": out(request, results, "nat")}

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
        return await run(Q.gaps, db_path, frm, to)

    @app.get("/api/annotations")
    async def get_annotations(request: Request):
        frm, to = span(request, 30 * DAY_MS)
        r = await run(Q.rows, db_path, "SELECT * FROM annotations WHERE start_ms < ? AND COALESCE(end_ms, start_ms) >= ? "
                                       "ORDER BY start_ms", (to, frm))
        return out(request, r, "annotation")

    @app.post("/api/annotations")
    async def post_annotation(request: Request):
        try:
            body = await request.json()
            start = int(body["start_ms"])
            end = int(body["end_ms"]) if body.get("end_ms") is not None else None
            rid = await run(Q.add_annotation, db_path, start, end, str(body.get("label")), body.get("note"))
        except (KeyError, TypeError, ValueError) as e:
            raise HTTPException(400, str(e) or "bad annotation")
        bus.publish("annotation", {"id": rid, "start_ms": start, "end_ms": end, "label": body.get("label")})
        return {"id": rid}

    @app.get("/api/packets")
    async def get_packets():
        return packets() if packets else []

    @app.get("/api/export/bugreport/{iid}")
    async def get_bugreport(iid: int):
        rep = await run(X.bugreport, db_path, iid, _now())
        if rep is None:
            raise HTTPException(404, "no such drop")
        return JSONResponse(rep, headers={"content-disposition": f'attachment; filename="whydrop-bugreport-{iid}.json"'})

    @app.get("/api/export/{name}.{fmt}")
    async def get_export(name: str, fmt: str, request: Request):
        if name not in X.TABLES or fmt not in ("csv", "json"):
            raise HTTPException(404, "export incidents|conditions|samples_1m|events as .csv or .json")
        frm, to = span(request, 30 * DAY_MS)
        rows = await run(X.table_rows, db_path, name, frm, to)
        body, ctype = X.render(name, rows, fmt, is_public(request), _now())
        return Response(body, media_type=ctype,
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
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)  # added last = runs first
    return app
