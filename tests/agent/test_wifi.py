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


NETSH_JA = """
システムに 1 インターフェイスがあります:

    名前                   : Wi-Fi
    説明                   : Example Wireless Adapter
    物理アドレス           : 02:00:00:00:00:aa
    状態                   : 接続されました
    SSID                   : example-ssid
    BSSID                  : 02:00:00:00:00:05
    無線の種類             : 802.11ac
    チャネル               : 36
    シグナル               : 90%
    プロファイル           : example-ssid
"""
NETSH_EN_DOWN = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Physical address       : 02:00:00:00:00:aa
    State                  : disconnected
    Radio status           : Hardware On
"""


def test_netsh_unknown_locale_decides_by_bssid():
    d = wifi.parse_netsh(NETSH_JA)  # state word not known: a listed BSSID means associated
    assert d["connected"] is True and d["bssid"] == "02:00:00:00:00:05" and "signal_pct" not in d
    ja_down = "\n".join(x for x in NETSH_JA.splitlines() if "SSID" not in x).replace("接続されました", "切断されました")
    assert wifi.parse_netsh(ja_down)["connected"] is False
    de = NETSH_EN.replace("State      ", "Status     ").replace("connected", "Verbunden")
    assert wifi.parse_netsh(de)["connected"] is True


def test_netsh_variants_never_crash(monkeypatch):
    assert wifi.parse_netsh(NETSH_EN_DOWN) == {"connected": False, "state": "disconnected"}
    assert wifi.parse_netsh("There is no wireless interface on the system.\n") == {"connected": False}
    assert wifi.parse_netsh("") == {"connected": False}
    no_signal = "\n".join(x for x in NETSH_EN.splitlines() if "Signal" not in x and "Rssi" not in x)
    d = wifi.parse_netsh(no_signal)
    assert d["connected"] and "signal_pct" not in d and "rssi_dbm" not in d
    assert wifi.parse_netsh(NETSH_EN.replace("82%", "n/a").replace("-37", "?"))["connected"]
    roaming = NETSH_EN.replace(": connected", ": associating")  # mid-roam: not associated yet
    assert wifi.parse_netsh(roaming)["connected"] is False

    for text in (NETSH_EN_DOWN, NETSH_JA, roaming, "", "\xff\xfe garbage : : :"):
        async def fake_run(*a, text=text, **k):
            return text
        monkeypatch.setattr(wifi, "_run", fake_run)
        s = asyncio.run(wifi.WindowsWifi().snapshot())
        assert s is not None and (s.bssid is None) == (not s.up)


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


def test_without_iw_wifi_is_up_when_operstate_is_up():
    t = WifiTracker(b"salt", now_ms=lambda: 5)
    s = Snapshot(up=True, bssid=None, bssid_known=False)
    assert t.update(s) == [] and t.update(s) == []
    assert wifi.to_result(s, t, 5).ok


def test_one_empty_iw_answer_is_not_a_reassoc(monkeypatch, tmp_path):
    (tmp_path / "wlan0").mkdir()
    (tmp_path / "wlan0" / "operstate").write_text("up\n")
    answers = iter([IW_LINK, IW_STATION, ""])

    async def fake_run(*a, **k):
        return next(answers)
    monkeypatch.setattr(wifi, "_run", fake_run)
    p = wifi.LinuxWifi("wlan0", sys_root=tmp_path, proc_wireless=tmp_path / "none")
    t = WifiTracker(b"salt", now_ms=lambda: 5)
    first = asyncio.run(p.snapshot())
    p._last_iw = -1e9
    second = asyncio.run(p.snapshot())  # iw link came back empty once
    assert t.update(first) == [] and t.update(second) == [] and second.bssid == first.bssid

def test_iw_values_come_from_their_own_lines():
    tricky = IW_LINK.replace("example-ssid", "net freq: 2412 signal: -10 dBm")  # an SSID can hold any text
    assert wifi.parse_iw_link(tricky) == {"bssid": "02:00:00:00:00:03", "freq": 5180, "signal": -41.0}


SSID = "zq-made-up-ssid-41"


def test_ssid_never_stored_by_any_path(monkeypatch, tmp_path, caplog):
    import json
    import logging

    from whydrop.agent import run as runmod
    from whydrop.agent.config import load_config
    caplog.set_level(logging.DEBUG)
    netsh = [t.replace("example-ssid", SSID) for t in (NETSH_EN, NETSH_KO, NETSH_JA)]
    netsh.append(netsh[0].replace("02:00:00:00:00:01", "02:00:00:00:00:09"))  # a roam
    iw_link = IW_LINK.replace("example-ssid", SSID)
    returned = [wifi.parse_netsh(t) for t in netsh] + [wifi.parse_iw_link(iw_link), wifi.parse_iw_station(IW_STATION)]
    assert SSID not in repr(returned)
    queue = iter(netsh)

    async def fake_run(*args, **k):
        if args[0] == "netsh":
            return next(queue)
        return iw_link if args[-1] == "link" else IW_STATION
    monkeypatch.setattr(wifi, "_run", fake_run)
    (tmp_path / "sys" / "wlan0").mkdir(parents=True)
    (tmp_path / "sys" / "wlan0" / "operstate").write_text("up\n")

    async def main():
        cfg = load_config(None, {"WHYDROP_DB_PATH": str(tmp_path / "db" / "w.db")})
        a = runmod.Agent(cfg, asyncio.Event())
        await a.store.open()
        a.agg = runmod.Aggregator(a.store, a.now)
        a.findings = runmod.FindingsTracker(a.targets, a.now)
        a.wifi_tracker = WifiTracker(b"salt", a.now)
        snaps = [await wifi.WindowsWifi().snapshot() for _ in netsh]
        snaps.append(await wifi.LinuxWifi("wlan0", sys_root=tmp_path / "sys", proc_wireless=tmp_path / "x").snapshot())
        assert all(s.up for s in snaps) and SSID not in repr(snaps)
        for s in snaps:
            await a.record([wifi.to_result(s, a.wifi_tracker, a.now()), *a.wifi_tracker.update(s)])
        await a.agg.flush_ready(force=True)
        await a.store.meta_set("ap_labels", json.dumps(a.wifi_tracker.labels))
        await a.store.flush()
        kinds = [r[0] for r in await a.store.execute("select kind from events")]
        await a.store.close()
        return kinds
    assert "roam" in asyncio.run(main())  # events were written, so the grep below sees real rows
    for f in (tmp_path / "db").iterdir():
        data = f.read_bytes()
        assert SSID.encode() not in data and SSID.encode("utf-16-le") not in data, f.name
    assert SSID not in caplog.text
