import logging
import os
import time

import pytest

from whydrop.reflector.replay import ReplayWindow, Tombstones


def test_accept_once():
    w = ReplayWindow()
    assert w.accept(5) and not w.accept(5)


def test_out_of_order_inside_window():
    w = ReplayWindow()
    w.accept(100)
    assert w.accept(99) and w.accept(50) and not w.accept(99)


def test_too_old_rejected():
    w = ReplayWindow()
    w.accept(2000)
    assert not w.accept(2000 - 1024)
    assert w.accept(2000 - 1023)


def test_floor():
    w = ReplayWindow(floor=10)
    assert not w.accept(10) and not w.accept(3) and w.accept(11)


def test_huge_jump_is_fast():
    w = ReplayWindow()
    w.accept(5)
    t = time.perf_counter()
    assert w.accept(4_000_000_000)
    assert not w.accept(5)
    assert time.perf_counter() - t < 0.05


def test_seen():
    w = ReplayWindow()
    w.accept(7)
    assert w.seen(7) and not w.seen(6) and not w.seen(8)
    assert w.highest == 7


def test_tombstones_roundtrip(tmp_path):
    t = Tombstones(tmp_path / "t.json")
    t.update(1, 42)
    t.flush()
    u = Tombstones(tmp_path / "t.json")
    u.load()
    assert u.get(1) == 42


def test_expiry(tmp_path):
    now = [1000.0]
    t = Tombstones(tmp_path / "t.json", wall=lambda: now[0])
    t.update(1, 1)
    now[0] += 7 * 86400 + 1
    t.flush()
    u = Tombstones(tmp_path / "t.json", wall=lambda: now[0])
    u.load()
    assert u.get(1) is None


def test_cap_drops_oldest(tmp_path):
    now = [0.0]
    t = Tombstones(tmp_path / "t.json", cap=2, wall=lambda: now[0])
    for sid in (1, 2, 3):
        now[0] += 1
        t.update(sid, 1)
    t.flush()
    assert t.get(1) is None and t.get(2) == 1 and t.get(3) == 1


def test_missing_file_is_empty(tmp_path):
    t = Tombstones(tmp_path / "none.json")
    t.load()
    assert t.get(1) is None


def test_corrupt_file_starts_empty(tmp_path, caplog):
    p = tmp_path / "t.json"
    p.write_text('{"v": 1, "t": {"1": [4')
    t = Tombstones(p)
    with caplog.at_level(logging.WARNING):
        t.load()
    assert t.get(1) is None and "tombstone" in caplog.text


def test_flush_is_atomic(tmp_path, monkeypatch):  # a crash mid-write leaves the old file intact
    p = tmp_path / "t.json"
    t = Tombstones(p)
    t.update(1, 1)
    t.flush()

    def crash(*a):
        raise OSError("crash")
    monkeypatch.setattr(os, "replace", crash)
    t.update(1, 2)
    with pytest.raises(OSError):
        t.flush()
    monkeypatch.undo()
    u = Tombstones(p)
    u.load()
    assert u.get(1) == 1


def test_no_path_is_memory_only():
    t = Tombstones(None)
    t.update(1, 5)
    t.flush()
    assert t.get(1) == 5
