"""The FastAPI app: API routes, /ws and the static dashboard, behind the guards (spec §8)."""
import asyncio
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from whydrop.web.bus import Bus
from whydrop.web.guard import Guard

STATIC = Path(__file__).with_name("static")


def create_app(db_path, bus: Bus, *, token: str | None, allowed_hosts: list[str], public_default: bool,
               status=None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db_path, app.state.bus, app.state.public_default = db_path, bus, public_default

    @app.get("/api/health")
    async def health():
        return {"ok": True}

    @app.get("/api/status")
    async def get_status():
        return status() if status else {}

    @app.post("/api/annotations")
    async def post_annotation(request: Request):
        return JSONResponse({"error": "not implemented yet"}, status_code=501)

    @app.websocket("/ws")
    async def ws(socket: WebSocket):
        await socket.accept(subprotocol="whydrop")
        q = bus.subscribe()

        async def pump():
            while True:
                await socket.send_json(await q.get())

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
