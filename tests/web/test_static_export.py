"""The static demo: every screen's data present, nothing identifying, nothing that writes (plan 6 review focus 1)."""
import json
import re
import threading

from whydrop.web.public import KNOWN_RESOLVERS
from whydrop.web.static_export import export_static

IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def build(tmp_path):
    from fixture import build as fixture_build
    box = {}
    th = threading.Thread(target=lambda: box.update(st=fixture_build(tmp_path / "w.db", "precision")))
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
                 "incidents_1_strip.json", "chart_incident_1.json", "nat.json"):
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
