import whydrop
from whydrop.cli import main


def test_version_flag(capsys):
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"whydrop {whydrop.__version__}"


def test_nat_test_needs_reflector(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("WHYDROP_SECRET", "s" * 40)
    monkeypatch.delenv("WHYDROP_REFLECTOR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert main(["nat-test"]) == 2 and "reflector" in capsys.readouterr().err


def test_nat_test_delay_selection(monkeypatch, tmp_path):
    from whydrop.agent.precision import natprobe
    seen = {}

    async def fake(addr, secret, *, udp_delays, tcp_delays, on_progress):
        seen.update(addr=addr, udp=udp_delays, tcp=tcp_delays)
        return natprobe.NatReport([], [], (None, None), (None, None), {"udp": None, "tcp": None})
    monkeypatch.setattr(natprobe, "nat_test", fake)
    monkeypatch.setenv("WHYDROP_SECRET", "s" * 40)
    monkeypatch.setenv("WHYDROP_REFLECTOR", "192.0.2.9")
    monkeypatch.setenv("WHYDROP_DB_PATH", str(tmp_path / "none.db"))
    monkeypatch.chdir(tmp_path)
    assert main(["nat-test", "--udp-only", "--max-delay", "60"]) == 0
    assert seen == {"addr": ("192.0.2.9", 48100), "udp": (10, 20, 30, 45, 60), "tcp": ()}
    assert main(["nat-test", "--tcp-only"]) == 0 and seen["tcp"] == (60, 300, 600, 1200, 1800, 3600)
    assert main(["nat-test", "--tcp-only", "--enable-7500"]) == 0 and seen["tcp"][-1] == 7500
    assert main(["nat-test", "--tcp-only", "--enable-7500", "--max-delay", "9000"]) == 0 and seen["tcp"][-1] == 7500


def _db_with_drop(path):
    """A small recorded DB: steady probes, then a 5 s line drop."""
    import asyncio

    from whydrop.agent.store import SampleRow, Store
    t0 = 1_800_000_000_000

    async def go():
        s = Store(path)
        await s.open()
        rows = []
        for sec in range(200):
            down = 30 <= sec < 35
            for i, prov in enumerate(("cloudflare", "google", "quad9")):
                if sec % 3 == i:
                    rows.append(SampleRow(t0 + sec * 1000, "line_hb", f"line_hb:{prov}", 1, 0 if down else 1, 1 if down else 0))
            rows.append(SampleRow(t0 + sec * 1000, "gateway", "gateway", 1, 1, 0))
        await s.add_samples(rows)
        await s.meta_set("pair_providers", __import__("json").dumps({f"line_hb:{p}": p for p in ("cloudflare", "google", "quad9")}))
        await s.close()
    asyncio.run(go())


def test_replay_prints_incidents(tmp_path, capsys):
    _db_with_drop(tmp_path / "w.db")
    assert main(["replay", str(tmp_path / "w.db")]) == 0
    out = capsys.readouterr().out
    assert "R2" in out and "likely" in out and "1 incident(s)" in out


def test_replay_set_overrides_constant(tmp_path, capsys):
    from whydrop.analysis import constants as K
    _db_with_drop(tmp_path / "w.db")
    old = K.LINE_LOOKBACK_S
    try:
        assert main(["replay", str(tmp_path / "w.db"), "--set", "LINE_LOOKBACK_S=9"]) == 0  # a 5 s drop no longer counts
        assert "0 incident(s)" in capsys.readouterr().out
        assert main(["replay", str(tmp_path / "w.db"), "--set", "NOPE=1"]) == 2
    finally:
        K.LINE_LOOKBACK_S = old


def test_annotate_inserts_label(monkeypatch, tmp_path):
    import sqlite3
    monkeypatch.setenv("WHYDROP_DB_PATH", str(tmp_path / "w.db"))
    monkeypatch.chdir(tmp_path)
    assert main(["annotate", "--label", "reproduced", "--start", "2026-11-25T14:00:00+09:00"]) == 2  # no DB yet
    _db_with_drop(tmp_path / "w.db")
    assert main(["annotate", "--label", "reproduced", "--start", "2026-11-25T14:00:00+09:00",
                 "--end", "2026-11-25T14:01:00+09:00", "--note", "router reboot"]) == 0
    con = sqlite3.connect(tmp_path / "w.db")
    assert con.execute("select label, note, end_ms - start_ms from annotations").fetchall() == [("reproduced", "router reboot", 60000)]
    con.close()
    assert main(["annotate", "--label", "bogus", "--start", "2026-11-25T14:00:00"]) == 2


def test_replay_in_chunks_matches_one_pass(tmp_path, monkeypatch):
    from whydrop.analysis import replay as rp
    _db_with_drop(tmp_path / "w.db")
    whole = rp.summary(rp.replay(tmp_path / "w.db"))
    monkeypatch.setattr(rp, "CHUNK_MS", 40_000)
    assert rp.summary(rp.replay(tmp_path / "w.db")) == whole and len(whole) == 1
