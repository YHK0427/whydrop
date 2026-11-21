"""Wi-Fi state: Linux (/sys, /proc, iw) and Windows (netsh, English or Korean). Spec §5.2 "Wi-Fi".
The SSID is never read into memory we keep; BSSIDs leave this module only as salted hashes."""
import asyncio
import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path

from whydrop.agent.events import Event
from whydrop.agent.proc import run_cmd
from whydrop.agent.results import Result

IW_EVERY_S = 10.0

# netsh field names, English and Korean (Korean measured on a Korean Windows 11, 2026-11-20)
_NETSH_KEYS = {
    "state": ("State", "상태"),
    "bssid": ("AP BSSID", "BSSID"),
    "band": ("Band", "밴드"),
    "channel": ("Channel", "채널"),
    "radio": ("Radio type", "송수신 장치 종류"),
    "signal": ("Signal", "신호"),
    "rssi": ("Rssi",),
}
_CONNECTED = {"connected", "연결됨"}


def parse_netsh(text: str) -> dict:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        fields.setdefault(k.strip(), v.strip())
    pick = {name: next((fields[a] for a in aliases if a in fields), None) for name, aliases in _NETSH_KEYS.items()}
    out: dict = {"connected": (pick["state"] or "").lower() in _CONNECTED}
    if pick["state"] is not None:
        out["state"] = pick["state"]
    for name in ("bssid", "band", "channel", "radio"):
        if pick[name]:
            out[name] = pick[name]
    m = re.match(r"(\d+)\s*%", pick["signal"] or "")
    if m:
        out["signal_pct"] = int(m.group(1))
    m = re.match(r"-?\d+", pick["rssi"] or "")
    if m:
        out["rssi_dbm"] = int(m.group(0))
    return out


def parse_proc_wireless(text: str, iface: str) -> float | None:
    for line in text.splitlines()[2:]:
        name, _, rest = line.partition(":")
        if name.strip() == iface:
            cols = rest.split()
            try:
                return float(cols[2].rstrip("."))
            except (IndexError, ValueError):
                return None
    return None


def parse_iw_link(text: str) -> dict:
    m = re.search(r"Connected to ([0-9a-f:]{17})", text)
    if not m:
        return {}
    out: dict = {"bssid": m.group(1)}
    if f := re.search(r"freq:\s*(\d+)", text):
        out["freq"] = int(f.group(1))
    if s := re.search(r"signal:\s*(-?\d+)", text):
        out["signal"] = float(s.group(1))
    return out


def parse_iw_station(text: str) -> dict:
    out = {}
    for key, pat in (("connected_s", r"connected time:\s*(\d+)"), ("tx_retries", r"tx retries:\s*(\d+)"),
                     ("beacon_loss", r"beacon loss:\s*(\d+)")):
        if m := re.search(pat, text):
            out[key] = int(m.group(1))
    return out


@dataclass
class Snapshot:
    up: bool
    bssid: str | None = None
    connected_s: int | None = None
    signal_dbm: float | None = None
    freq: int | None = None
    band: str | None = None
    tx_retries: int | None = None
    beacon_loss: int | None = None
    bssid_known: bool = True  # False when iw is missing: no BSSID doesn't mean disconnected


class WifiTracker:
    """Turns successive snapshots into reassoc / roam events (spec §5.2: a BSSID change is a roam, never a
    re-association, even though the new station entry restarts its connected time)."""

    def __init__(self, salt: bytes, now_ms, labels: dict[str, str] | None = None):
        self._salt, self._now_ms = salt, now_ms
        self.labels: dict[str, str] = dict(labels or {})  # bssid hash → "AP-n"
        self._prev: Snapshot | None = None

    def ap(self, bssid: str) -> str:
        h = hashlib.sha256(self._salt + bssid.lower().encode()).hexdigest()[:16]
        if h not in self.labels:
            self.labels[h] = f"AP-{len(self.labels) + 1}"
        return self.labels[h]

    def update(self, s: Snapshot) -> list[Event]:
        prev, self._prev = self._prev, s
        now = self._now_ms()
        if s.bssid:
            self.ap(s.bssid)
        if prev is None:
            return []
        if not (prev.bssid_known and s.bssid_known):
            return [Event("reassoc", now, detail={"cause": "down"})] if prev.up and not s.up else []
        was_up, is_up = prev.up and prev.bssid, s.up and s.bssid
        if was_up and not is_up:
            return [Event("reassoc", now, detail={"cause": "down", "ap": self.ap(prev.bssid)})]
        if was_up and is_up and prev.bssid.lower() != s.bssid.lower():
            return [Event("roam", now, detail={"from": self.ap(prev.bssid), "to": self.ap(s.bssid),
                                               "freq": s.freq})]
        if (was_up and is_up and prev.connected_s is not None and s.connected_s is not None
                and s.connected_s < prev.connected_s):
            return [Event("reassoc", now - s.connected_s * 1000,
                          detail={"cause": "connected_time", "ap": self.ap(s.bssid)})]
        return []


async def _run(*args: str) -> str:
    out = await run_cmd(*args, timeout_s=5)
    for enc in ("utf-8", "mbcs", "cp949"):
        try:
            return out.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return out.decode("utf-8", "replace")


class LinuxWifi:
    def __init__(self, iface: str, *, sys_root: Path = Path("/sys/class/net"),
                 proc_wireless: Path = Path("/proc/net/wireless")):
        self.iface = iface
        self._sys, self._proc = Path(sys_root) / iface, Path(proc_wireless)
        self._last_iw = -1e9
        self._iw: dict = {}
        self._prev_up: bool | None = None
        self._misses = 0
        self.iw_missing = False

    async def snapshot(self) -> Snapshot | None:
        try:
            up = (self._sys / "operstate").read_text().strip() == "up"
        except OSError:
            return None  # no such interface (or unreadable): no evidence, not "down"
        try:
            signal = parse_proc_wireless(self._proc.read_text(), self.iface)
        except OSError:
            signal = None
        now = time.monotonic()
        if not self.iw_missing and (now - self._last_iw >= IW_EVERY_S or up != self._prev_up):
            self._last_iw = now
            try:
                link = parse_iw_link(await _run("iw", "dev", self.iface, "link"))
                station = parse_iw_station(await _run("iw", "dev", self.iface, "station", "dump")) if link else {}
                fresh = {**link, **station}
            except FileNotFoundError:
                self.iw_missing, fresh = True, {}
            except (OSError, asyncio.TimeoutError):
                fresh = {}
            if fresh or not up or self._misses >= 1 or self.iw_missing:
                self._iw, self._misses = fresh, 0
            else:
                self._misses += 1  # one empty answer while up (e.g. mid-scan): keep the last one
                self._last_iw = now - IW_EVERY_S + 1  # and ask again in a second
        self._prev_up = up
        iw = self._iw if up else {}
        return Snapshot(up, iw.get("bssid"), iw.get("connected_s"), signal if signal is not None else iw.get("signal"),
                        iw.get("freq"), None, iw.get("tx_retries"), iw.get("beacon_loss"), not self.iw_missing)


class WindowsWifi:
    async def snapshot(self) -> Snapshot | None:
        try:
            d = parse_netsh(await _run("netsh", "wlan", "show", "interfaces"))
        except (OSError, asyncio.TimeoutError):
            return None  # netsh failed or timed out: no evidence, not "disconnected"
        return Snapshot(d["connected"], d.get("bssid") if d["connected"] else None, None,
                        float(d["rssi_dbm"]) if "rssi_dbm" in d else None, None, d.get("band"))


def to_result(s: Snapshot, tracker: WifiTracker, t_send_ms: int) -> Result:
    detail = {"signal_dbm": s.signal_dbm, "band": s.band, "freq": s.freq,
              "ap": tracker.ap(s.bssid) if s.bssid else None,
              "tx_retries": s.tx_retries, "beacon_loss": s.beacon_loss}
    return Result("wifi", "wifi", None, t_send_ms, bool(s.up and (s.bssid or not s.bssid_known)), None,
                  detail={k: v for k, v in detail.items() if v is not None})
