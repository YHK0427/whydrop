"""Wired link state from /sys/class/net (spec §5.2 `link`): carrier, flaps, speed renegotiation."""
from pathlib import Path

from whydrop.agent.events import Event
from whydrop.agent.results import Result


def _read_int(p: Path) -> int | None:
    try:
        return int(p.read_text().strip())
    except (OSError, ValueError):
        return None


class LinkTracker:
    def __init__(self, iface: str, *, sys_root: Path = Path("/sys/class/net"), now_ms):
        self._dir = Path(sys_root) / iface
        self._now_ms = now_ms
        self._changes: int | None = None
        self._speed: int | None = None

    def probe(self) -> tuple[Result, list[Event]]:
        now = self._now_ms()
        carrier = _read_int(self._dir / "carrier")
        changes = _read_int(self._dir / "carrier_changes")
        speed = _read_int(self._dir / "speed")
        try:
            duplex = (self._dir / "duplex").read_text().strip()
        except OSError:
            duplex = None
        events: list[Event] = []
        if changes is not None and self._changes is not None and changes > self._changes:
            events.append(Event("link_flap", now, detail={"flaps": changes - self._changes}))
        if speed and speed > 0 and self._speed and speed != self._speed:
            events.append(Event("link_speed", now, detail={"from": self._speed, "to": speed}))
        self._changes = changes if changes is not None else self._changes
        self._speed = speed if speed and speed > 0 else self._speed
        return Result("link", "link", None, now, carrier == 1, None,
                      detail={"speed": speed, "duplex": duplex}), events
