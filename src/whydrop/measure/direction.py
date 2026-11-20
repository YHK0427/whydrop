"""Which way a lost UDP packet was lost, from ECHO fields alone (spec §5.3 "Direction")."""
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

BITMAP_SPAN = 32


@dataclass(frozen=True)
class Echo:
    seq: int
    recv_count: int
    epoch: int
    rx_bitmap: int


@dataclass(frozen=True)
class OutageTotals:
    up: int | None
    down: int | None
    status: Literal["ok", "down_unmeasurable", "unknown"]


def packet_direction(seq: int, later: Iterable[Echo]) -> Literal["up", "down", "unknown"]:
    """For a seq that got no ECHO: the first later ECHO within 32 seqs says whether the reflector saw it."""
    for e in later:  # callers pass ECHOs from one reflector epoch; a restart starts a new comparison
        gap = e.seq - seq
        if 1 <= gap <= BITMAP_SPAN:
            return "down" if e.rx_bitmap >> (gap - 1) & 1 else "up"
    return "unknown"


def outage_totals(a: Echo, b: Echo, echoes_received_in_range: int) -> OutageTotals:
    """a = last ECHO before the outage, b = first after; echoes_received_in_range counts ECHOs for seqs in (a.seq, b.seq]."""
    reached = b.recv_count - a.recv_count
    if b.epoch != a.epoch or reached < 1:  # b's own PROBE must be counted, else the counters disagree
        return OutageTotals(None, None, "unknown")
    sent = b.seq - a.seq
    up = sent - reached
    if sent > 1 and reached == 1:  # only b's own PROBE got through: nothing to judge the way down by
        return OutageTotals(up, None, "down_unmeasurable")
    down = reached - echoes_received_in_range
    if down < 0:
        return OutageTotals(None, None, "unknown")
    return OutageTotals(up, down, "ok")
