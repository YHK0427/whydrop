"""The one event record every agent component emits (stored in the `events` table, spec §7)."""
from dataclasses import dataclass, field


@dataclass
class Event:
    kind: str
    ts_ms: int
    pair: str | None = None
    detail: dict = field(default_factory=dict)
