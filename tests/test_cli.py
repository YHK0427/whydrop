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
