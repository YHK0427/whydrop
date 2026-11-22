"""The static demo: every screen's data present, nothing identifying, nothing that writes (plan 6 review focus 1)."""
import json
import re
import sqlite3
import threading
import time

import pytest

from whydrop.web.public import KNOWN_RESOLVERS
from whydrop.web.static_export import export_static

IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def build(tmp_path, now_ms=None):
    from fixture import build as fixture_build
    box = {}
    th = threading.Thread(target=lambda: box.update(st=fixture_build(tmp_path / "w.db", "precision", now_ms)))
    th.start()
    th.join()
    return box["st"]


def test_static_site_public_only(tmp_path):
    st = build(tmp_path)
    m = export_static(tmp_path / "w.db", tmp_path / "site", None, st["now_ms"], {"mode": "precision"})
    site = tmp_path / "site"
    data = {p.name: p.read_text(encoding="utf-8") for p in (site / "data").glob("*.json")}
    assert m["static"] and m["files"] == len(data)
    for need in ("status.json", "incidents_2592000.json", "incidents_7776000.json", "chart_3600.json", "incidents_1.json",
                 "incidents_1_strip.json", "chart_incident_1.json", "nat.json", "annotations_3600.json"):
        assert need in data, need
    blob = "\n".join(data.values())
    leaked = {ip for ip in IPV4.findall(blob) if ip not in KNOWN_RESOLVERS and not ip.startswith("x.x.x.")}
    assert not leaked, leaked
    assert '"agent"' not in data["status.json"] and json.loads(data["status.json"])["public"] is True
    assert not any(n.startswith("export") for n in data)          # no bug-report/raw exports in the demo
    assert (site / "index.html").exists() and json.loads((site / "static.json").read_text())["recorded"]


def test_cli_export_static(tmp_path, capsys):
    from whydrop.cli import main
    build(tmp_path)
    assert main(["export-static", str(tmp_path / "w.db"), "--out", str(tmp_path / "s")]) == 0
    assert "public view" in capsys.readouterr().out and (tmp_path / "s" / "data" / "status.json").exists()


PRIVATE = ("192.168.0.1", "211.234.10.11", "2400:abcd:12::5", "wlan0")


def seed_private(db, now_ms):
    """Identifying values in every place a row can carry text: a pair, event detail, evidence, an annotation."""
    con = sqlite3.connect(db)
    con.execute("INSERT INTO samples_1s (agent_id, ts_ms, probe, pair, sent, ok, lost) VALUES (1, ?, 'dns', "
                "'dns_isp:211.234.10.11:53/udp', 1, 1, 0)", (now_ms - 60_000,))
    con.execute("INSERT INTO events (agent_id, ts_ms, kind, pair, detail_json) VALUES (1, ?, 'net_change', 'wlan0', ?)",
                (now_ms - 41 * 60_000, json.dumps({"gateway": "192.168.0.1", "iface": "wlan0", "v6": "2400:abcd:12::5"})))
    ev = json.loads(con.execute("SELECT evidence_json FROM incidents WHERE id = 1").fetchone()[0])
    ev["protocol"] += " Router 192.168.0.1 on wlan0, public 211.234.10.11, v6 2400:abcd:12::5."
    con.execute("UPDATE incidents SET evidence_json = ? WHERE id = 1", (json.dumps(ev),))
    con.execute("UPDATE annotations SET label = 'reboot 192.168.0.1', note = 'wlan0 211.234.10.11'")
    con.commit()
    con.close()


def test_static_site_hides_private_values_and_pins_the_clock(tmp_path):
    then = int(time.time() * 1000) - 5 * 86_400_000          # exported five days after the recording ended
    st = build(tmp_path, then)
    seed_private(tmp_path / "w.db", st["now_ms"])
    export_static(tmp_path / "w.db", tmp_path / "site", None, st["now_ms"], {"mode": "precision"})
    data = {p.name: p.read_text(encoding="utf-8") for p in (tmp_path / "site" / "data").glob("*.json")}
    blob = "\n".join(data.values())
    assert not [v for v in PRIVATE if v in blob], [v for v in PRIVATE if v in blob]
    from scan_public import bad_addresses
    assert not bad_addresses(blob)
    chart = json.loads(data["chart_incident_1.json"])
    assert "x" not in chart and chart["x_rel"] and all(-3 * 3600 < x <= 0 for x in chart["x_rel"])   # relative, not epoch
    assert json.loads(data["events_incident_1.json"])                          # windows follow the pinned clock
    assert "40 min ago" in json.loads(data["incidents_1_summary.json"])


def test_export_static_refuses_a_directory_it_did_not_write(tmp_path):
    st = build(tmp_path)
    keep = tmp_path / "docs"
    keep.mkdir()
    (keep / "important.md").write_text("mine")
    with pytest.raises(FileExistsError):
        export_static(tmp_path / "w.db", keep, None, st["now_ms"])
    assert (keep / "important.md").read_text() == "mine"
    site = tmp_path / "site"
    export_static(tmp_path / "w.db", site, None, st["now_ms"])
    export_static(tmp_path / "w.db", site, None, st["now_ms"])                 # its own earlier output: replaced


def test_cli_export_static_refuses_cleanly(tmp_path, capsys):
    from whydrop.cli import main
    build(tmp_path)
    f = tmp_path / "a_file"
    f.write_text("keep")
    assert main(["export-static", str(tmp_path / "w.db"), "--out", str(f)]) == 2
    assert f.read_text() == "keep" and "whydrop:" in capsys.readouterr().err
