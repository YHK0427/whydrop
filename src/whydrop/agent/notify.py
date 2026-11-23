"""Alerts (spec §8): one webhook per **finalized** drop — nothing can be sent through a dead line, so we wait for
the cause to settle. Failures are retried for up to 24 h. Bodies go through the public-view allowlist, since ntfy
topics and Discord channels can be read by others. Stdlib only (urllib in a thread)."""
import asyncio
import json
import logging
import urllib.request

from whydrop.web.public import public, shown_segments, slowed

log = logging.getLogger(__name__)

KEEP_MS = 24 * 3600_000
BACKOFF_S = (30, 60, 120, 300, 600, 1800)
TIMEOUT_S = 10
WORDS = {"home": "Home network", "line": "Internet line", "lan": "Router", "wifi": "Wi-Fi", "link": "Cable", "host_net": "This device",
         "dns_router": "DNS", "dns_isp": "DNS", "dns_public": "DNS"}


def text(row: dict, now_ms: int) -> tuple[str, str]:
    """(title, sentence) in UI vocabulary: 'Internet line dropped for 46 s. Line drop … (likely).'"""
    p = public(row, "incident", now_ms)
    label = p["evidence"].get("label", "Likely cause unknown")
    dur = (p["end_s"] or 0) - (p["start_s"] or 0)
    segs, verb = shown_segments(p["segments"], p["evidence"]), "slowed down" if slowed(p["cause"]) else "dropped"
    where = ", ".join(dict.fromkeys(WORDS.get(s, s) for s in segs)) or (p["point"] or "Connection").replace("_", " ")
    title = f"whydrop: {where} {verb}" if segs else f"whydrop: {where}"
    sentence = (f"{where} {verb} for {dur} s. {label}." if segs else f"{label}.")
    step = p["evidence"].get("next_step")
    return title, sentence + (f" {step}." if step else "")


def payload(row: dict, fmt: str, now_ms: int) -> tuple[str, dict]:
    title, sentence = text(row, now_ms)
    if fmt == "ntfy":
        return sentence, {"Title": title, "Tags": "warning", "Content-Type": "text/plain; charset=utf-8"}
    if fmt == "discord":
        return json.dumps({"content": f"**{title}**\n{sentence}"}), {"Content-Type": "application/json"}
    return json.dumps({"type": "whydrop.drop", "title": title, "text": sentence, "drop": public(row, "incident", now_ms)},
                      ensure_ascii=False), {"Content-Type": "application/json"}


def _post(url: str, body: str, headers: dict) -> None:
    req = urllib.request.Request(url, data=body.encode("utf-8"), headers={"User-Agent": "whydrop", **headers},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
        if r.status >= 300:
            raise OSError(f"HTTP {r.status}")


class Notifier:
    def __init__(self, cfg_notify, now_ms, on_queue=None):
        self.on_queue = on_queue or (lambda q: None)   # persist after every change
        self.url = (cfg_notify or {}).get("webhook_url")
        self.fmt = (cfg_notify or {}).get("format", "json")
        self.kuma = (cfg_notify or {}).get("kuma_push_url")
        self.now_ms = now_ms
        self.queue: list[dict] = []          # {"row", "first_ms", "next_ms", "tries"}

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    async def _send(self, row: dict) -> bool:
        body, headers = payload(row, self.fmt, self.now_ms())
        try:
            await asyncio.to_thread(_post, self.url, body, headers)
            return True
        except Exception as e:   # OSError, http.client errors, …: log the type only (the URL may hold a token)
            log.warning("alert not delivered (%s); will retry", type(e).__name__)
            return False

    async def handle(self, msg: dict) -> None:
        data = msg.get("data") or {}
        if not self.enabled or msg.get("type") != "incident" or data.get("op") != "finalized":
            return
        if not await self._send(data["row"]):
            self.queue.append({"row": data["row"], "first_ms": self.now_ms(), "next_ms": self.now_ms() + BACKOFF_S[0] * 1000,
                               "tries": 1})
            self.on_queue(self.queue)

    async def retry(self) -> None:
        now, keep = self.now_ms(), []
        for item in self.queue:
            if now - item["first_ms"] > KEEP_MS:
                log.warning("alert dropped after 24 h of failed deliveries")
                continue
            if item["next_ms"] > now:
                keep.append(item)
            elif not await self._send(item["row"]):
                item["tries"] += 1
                item["next_ms"] = now + BACKOFF_S[min(item["tries"] - 1, len(BACKOFF_S) - 1)] * 1000
                keep.append(item)
        changed = len(keep) != len(self.queue)
        self.queue = keep
        if changed:
            self.on_queue(self.queue)

    async def kuma_push(self) -> None:
        """Optional Uptime Kuma push monitor: a heartbeat while the agent runs."""
        if self.kuma:
            try:
                await asyncio.to_thread(lambda: urllib.request.urlopen(self.kuma, timeout=TIMEOUT_S).close())
            except Exception:
                pass

    async def run(self, bus, stop: asyncio.Event) -> None:
        q = bus.subscribe({"incident"})   # samples and events can't push a finalized drop out
        try:
            while not stop.is_set():
                try:
                    msg = await asyncio.wait_for(q.get(), 30)
                except asyncio.TimeoutError:
                    msg = None
                if msg is not None:
                    await self.handle(msg)
                await self.retry()
        finally:
            bus.unsubscribe(q)
