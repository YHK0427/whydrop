"""Alerts (spec §8): one webhook per **finalized** drop — nothing can be sent through a dead line, so we wait for
the cause to settle. Failures are retried for up to 24 h. Bodies go through the public-view allowlist, since ntfy
topics and Discord channels can be read by others. Stdlib only (urllib in a thread)."""
import asyncio
import json
import logging
import urllib.request

from whydrop.analysis import texts
from whydrop.web.export import SEGMENT_WORDS
from whydrop.web.public import localized, public, shown_segments, slowed, subject_ko

log = logging.getLogger(__name__)

KEEP_MS = 24 * 3600_000
BACKOFF_S = (30, 60, 120, 300, 600, 1800)
TIMEOUT_S = 10
MAX_QUEUE = 100                     # undelivered alerts kept for retry; the oldest go first
MAX_PER_HOUR = 12                   # a flapping line must not become a notification every minute


def text(row: dict, now_ms: int, name: str | None = None, lang: str = "en", held: int = 0) -> tuple[str, str]:
    """(title, sentence) in the dashboard's words: 'Internet line dropped for 46 s. Line drop … (likely).'"""
    p = public(row, "incident", now_ms)
    ev = p["evidence"]
    label = localized(ev.get("label") or texts.CAUSES["unknown"][0], lang)   # a label the dashboard translates
    dur = (p["end_s"] or 0) - (p["start_s"] or 0)
    segs, slow = shown_segments(p["segments"], ev), slowed(p["cause"])
    where = ", ".join(dict.fromkeys(SEGMENT_WORDS[lang].get(s, s) for s in segs))
    head = f"whydrop {name}" if name else "whydrop"   # agent_name: which agent, when several alert one channel
    if not segs:   # a point event: its label says it all
        title = f"{head}: {label if lang == 'ko' else (p['point'] or 'Connection').replace('_', ' ')}"
        sentence = f"{label}."
    elif lang == "ko":
        title = f"{head}: {subject_ko(where)} {'느려짐' if slow else '끊김'}"
        sentence = f"{subject_ko(where)} {dur}초 동안 {'느려졌어요' if slow else '끊겼어요'}. {label}."
    else:
        verb = "slowed down" if slow else "dropped"
        title, sentence = f"{head}: {where} {verb}", f"{where} {verb} for {dur} s. {label}."
    step = ev.get("next_step")
    sentence += f" {localized(step, lang)}." if step else ""
    if held:   # drops the hourly cap held back
        sentence += (f" (알리지 않은 끊김 {held}개 더: 대시보드를 보세요)" if lang == "ko"
                     else f" (+{held} more drops not alerted; see the dashboard)")
    return " ".join(title.split()), sentence   # no CR/LF in a header   # no CR/LF in a header


def _header(v: str) -> str:
    """HTTP headers are Latin-1: anything else goes as an RFC 2047 encoded word, which ntfy decodes."""
    import base64
    return v if v.isascii() else "=?UTF-8?B?" + base64.b64encode(v.encode()).decode() + "?="


def payload(row: dict, fmt: str, now_ms: int, name: str | None = None, lang: str = "en",
            held: int = 0) -> tuple[str, dict]:
    title, sentence = text(row, now_ms, name, lang, held)
    if fmt == "ntfy":
        return sentence, {"Title": _header(title), "Tags": "warning", "Content-Type": "text/plain; charset=utf-8"}
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
    def __init__(self, cfg_notify, now_ms, on_queue=None, name: str | None = None):
        self.name, self.lang = name, (cfg_notify or {}).get("lang", "en")
        self.on_queue = on_queue or (lambda q: None)   # persist after every change
        self.url = (cfg_notify or {}).get("webhook_url")
        self.fmt = (cfg_notify or {}).get("format", "json")
        self.kuma = (cfg_notify or {}).get("kuma_push_url")
        self.now_ms = now_ms
        self.queue: list[dict] = []          # {"row", "first_ms", "next_ms", "tries"}
        self._recent: list[int] = []         # when the last alerts went out (the hourly cap)
        self.held = 0                        # drops not alerted because of the cap, told with the next one

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    async def _send(self, row: dict) -> bool:
        body, headers = payload(row, self.fmt, self.now_ms(), self.name, self.lang, self.held)
        try:
            await asyncio.to_thread(_post, self.url, body, headers)
            self.held = 0
            return True
        except Exception as e:   # OSError, http.client errors, …: log the type only (the URL may hold a token)
            log.warning("alert not delivered (%s); will retry", type(e).__name__)
            return False

    async def handle(self, msg: dict) -> None:
        data = msg.get("data") or {}
        if not self.enabled or msg.get("type") != "incident" or data.get("op") != "finalized":
            return
        now = self.now_ms()
        self._recent = [t for t in self._recent if now - t < 3600_000]
        if len(self._recent) >= MAX_PER_HOUR:
            self.held += 1
            log.info("alert held: %d alerts in the last hour", len(self._recent))
            return
        self._recent.append(now)
        if not await self._send(data["row"]):
            self.queue.append({"row": data["row"], "first_ms": now, "next_ms": now + BACKOFF_S[0] * 1000, "tries": 1})
            if len(self.queue) > MAX_QUEUE:
                log.warning("alert queue full: dropping the oldest undelivered alert")
                del self.queue[0]
            self.on_queue(self.queue)

    async def retry(self) -> None:
        now, keep, changed = self.now_ms(), [], False
        for item in self.queue:
            if now - item["first_ms"] > KEEP_MS:
                log.warning("alert dropped after 24 h of failed deliveries")
                continue
            if item["next_ms"] > now:
                keep.append(item)
            else:
                changed = True   # sent, or failed again with a new backoff: either way the saved queue is stale
                if not await self._send(item["row"]):
                    item["tries"] += 1
                    item["next_ms"] = now + BACKOFF_S[min(item["tries"] - 1, len(BACKOFF_S) - 1)] * 1000
                    keep.append(item)
        changed = changed or len(keep) != len(self.queue)
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
