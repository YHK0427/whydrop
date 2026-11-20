"""Wi-Fi and wired-link parsing and tracking. Every value here is synthetic (no real SSID or BSSID)."""
import asyncio

from whydrop.agent.probes import link, wifi
from whydrop.agent.probes.wifi import Snapshot, WifiTracker

NETSH_EN = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Example Wireless Adapter
    State                  : connected
    SSID                   : example-ssid
    AP BSSID               : 02:00:00:00:00:01
    Band                   : 5 GHz
    Channel                : 161
    Radio type             : 802.11ac
    Signal                 : 82%
    Rssi                   : -37
"""

NETSH_KO = """
시스템에 1 인터페이스가 있습니다.

    이름                   : Wi-Fi
    설명                   : Example Wireless Adapter
    상태                   : 연결됨
    SSID                   : example-ssid
    AP BSSID               : 02:00:00:00:00:02
    밴드                   : 5 GHz
    채널                   : 161
    송수신 장치 종류       : 802.11ac
    신호                   : 82%
    Rssi                   : -37
"""

PROC_WIRELESS = """Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
wlan0: 0000   70.  -40.  -256        0      0      0      0      0        0
"""

IW_LINK = """Connected to 02:00:00:00:00:03 (on wlan0)
\tSSID: example-ssid
\tfreq: 5180
\tsignal: -41 dBm
"""

IW_STATION = """Station 02:00:00:00:00:03 (on wlan0)
\tinactive time:\t120 ms
\ttx retries:\t17
\tsignal:  \t-41 dBm
\tconnected time:\t3600 seconds
\tbeacon loss:\t2
"""


def test_netsh_english_fixture():
    d = wifi.parse_netsh(NETSH_EN)
    assert d == {"state": "connected", "connected": True, "bssid": "02:00:00:00:00:01", "band": "5 GHz",
                 "channel": "161", "radio": "802.11ac", "signal_pct": 82, "rssi_dbm": -37}


def test_netsh_korean_fixture():
    d = wifi.parse_netsh(NETSH_KO)
    assert d["connected"] is True and d["bssid"] == "02:00:00:00:00:02" and d["rssi_dbm"] == -37
    assert d["band"] == "5 GHz" and d["channel"] == "161" and d["radio"] == "802.11ac" and d["signal_pct"] == 82


def test_netsh_never_returns_ssid():
    assert "ssid" not in wifi.parse_netsh(NETSH_EN) and "example-ssid" not in str(wifi.parse_netsh(NETSH_KO))


def test_netsh_garbage_is_empty_not_error():
    assert wifi.parse_netsh("no wireless interface\n") == {"connected": False}


def test_iw_parsers():
    assert wifi.parse_proc_wireless(PROC_WIRELESS, "wlan0") == -40.0
    assert wifi.parse_proc_wireless(PROC_WIRELESS, "wlan1") is None
    assert wifi.parse_iw_link(IW_LINK) == {"bssid": "02:00:00:00:00:03", "freq": 5180, "signal": -41.0}
    assert wifi.parse_iw_link("Not connected.\n") == {}
    assert wifi.parse_iw_station(IW_STATION) == {"connected_s": 3600, "tx_retries": 17, "beacon_loss": 2}


def snap(up=True, bssid="02:00:00:00:00:03", connected_s=100):
    return Snapshot(up=up, bssid=bssid, connected_s=connected_s, signal_dbm=-41.0, freq=5180)


def test_reassoc_on_connected_time_drop_same_bssid():
    t = WifiTracker(b"salt", now_ms=lambda: 1_000_000)
    assert t.update(snap(connected_s=500)) == []
    [e] = t.update(snap(connected_s=3))
    assert e.kind == "reassoc" and e.ts_ms == 1_000_000 - 3000 and e.detail["cause"] == "connected_time"


def test_reassoc_when_link_goes_down():
    t = WifiTracker(b"salt", now_ms=lambda: 5)
    t.update(snap())
    [e] = t.update(snap(up=False, bssid=None, connected_s=None))
    assert e.kind == "reassoc" and e.detail["cause"] == "down"


def test_roam_on_bssid_change_never_reassoc():
    t = WifiTracker(b"salt", now_ms=lambda: 5)
    t.update(snap(bssid="02:00:00:00:00:03", connected_s=900))
    [e] = t.update(snap(bssid="02:00:00:00:00:04", connected_s=1))  # new station entry restarts its time
    assert e.kind == "roam" and e.detail["from"] == "AP-1" and e.detail["to"] == "AP-2"


def test_bssid_never_stored_raw():
    t = WifiTracker(b"salt", now_ms=lambda: 5)
    t.update(snap(bssid="02:00:00:00:00:03"))
    [e] = t.update(snap(bssid="02:00:00:00:00:04"))
    assert "02:00" not in str(e.detail) and all(len(h) == 16 for h in t.labels)


def test_iw_missing_falls_back(monkeypatch, tmp_path):
    (tmp_path / "wlan0").mkdir()
    (tmp_path / "wlan0" / "operstate").write_text("up\n")

    async def no_iw(*a, **k):
        raise FileNotFoundError("iw")
    monkeypatch.setattr(wifi, "_run", no_iw)
    p = wifi.LinuxWifi("wlan0", sys_root=tmp_path, proc_wireless=tmp_path / "missing")
    s = asyncio.run(p.snapshot())
    assert s.up and s.bssid is None and s.signal_dbm is None and p.iw_missing


def test_link_flap_and_speed_change(tmp_path):
    d = tmp_path / "eth0"
    d.mkdir()
    for k, v in {"carrier": "1", "carrier_changes": "4", "speed": "1000", "duplex": "full"}.items():
        (d / k).write_text(v + "\n")
    lt = link.LinkTracker("eth0", sys_root=tmp_path, now_ms=lambda: 7)
    r, ev = lt.probe()
    assert r.ok and ev == []
    (d / "carrier_changes").write_text("6\n")
    (d / "speed").write_text("100\n")
    r, ev = lt.probe()
    assert sorted(e.kind for e in ev) == ["link_flap", "link_speed"]
    assert next(e for e in ev if e.kind == "link_speed").detail == {"from": 1000, "to": 100}
