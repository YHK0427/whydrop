"""The Wireshark dissector against real WD/WT bytes from proto/ (skipped when tshark isn't installed).
The pcap is written here with struct: Ethernet + IPv4 + UDP/TCP headers around the payloads."""
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from whydrop.proto import wd, wt
from whydrop.proto.wd import WdPacket, WdType

LUA = Path(__file__).resolve().parents[2] / "contrib" / "wireshark" / "whydrop.lua"
TSHARK = shutil.which("tshark") or next((p for p in (r"C:\Program Files\Wireshark\tshark.exe", "/usr/bin/tshark")
                                        if Path(p).exists()), None)
S = b"s" * 32


def _ip(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                      bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return hdr + payload


def udp(payload, sport=40000, dport=48100):
    return _ip("192.0.2.1", "198.51.100.2", 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)


def tcp(payload, sport=40001, dport=48100, seq=1):
    return _ip("192.0.2.1", "198.51.100.2", 6, struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 65535, 0, 0) + payload)


def pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))   # Ethernet
        for i, ip in enumerate(packets):
            frame = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip
            f.write(struct.pack("<IIII", 1_700_000_000 + i, 0, len(frame), len(frame)) + frame)


@pytest.mark.skipif(TSHARK is None, reason="tshark not installed")
def test_dissector_decodes_every_field(tmp_path):
    probe = wd.encode(WdPacket(WdType.PROBE, 0xABCDEF01, 1201, 123456789), S)
    echo = wd.encode(WdPacket(WdType.ECHO, 0xABCDEF01, 1202, 5, recv_count=900, epoch=0x1234, rx_bitmap=0b1011, arg=7), S)
    nat = wd.encode(WdPacket(WdType.NAT_REQ, 7, 3, 0, arg=600), S)
    nonce = wt.encode_nonce(b"n" * 16)
    hello = wt.encode_hello(wt.Hello(wt.Role.IDLE, 0x55, 600, b"a" * 8), S, b"n" * 16)
    ok = wt.encode_hello_ok(0x1234, S, b"a" * 8)
    hb = wt.encode_frame(wt.Frame(wt.FrameType.HB, 0, 88, 42))
    cap = tmp_path / "w.pcap"
    pcap(cap, [udp(probe), udp(echo, 48100, 40000), udp(nat, 40002, 5555), tcp(nonce, 48100, 40001),
               tcp(hello), tcp(ok, 48100, 40001, 21), tcp(hb + hb, seq=31)])
    lua = tmp_path / "whydrop.lua"   # next to the pcap: distro tshark profiles may refuse paths in a checkout
    shutil.copy(LUA, lua)
    out = subprocess.run([TSHARK, "-X", f"lua_script:{lua}", "-r", str(cap), "-T", "fields", "-E", "separator=|",
                          "-e", "_ws.col.Info", "-e", "whydrop.wd.seq", "-e", "whydrop.wd.recv_count", "-e", "whydrop.wd.rx_bitmap",
                          "-e", "whydrop.wd.arg", "-e", "whydrop.wt.role", "-e", "whydrop.wt.param_s", "-e", "whydrop.wt.epoch",
                          "-e", "whydrop.frame.seq"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    assert out.returncode == 0, out.stderr
    rows = [line.split("|") for line in out.stdout.strip().splitlines()]
    assert rows[0][0] == "WD PROBE seq=1201" and rows[0][1] == "1201"
    assert rows[1][0] == "WD ECHO seq=1202 rc=900" and rows[1][2] == "900" and rows[1][3] == "0x0000000b" and rows[1][4] == "7"
    assert rows[2][0] == "WD NAT_REQ seq=3 arg=600"          # found by the heuristic on another port
    assert rows[3][0] == "WT NONCE"
    assert rows[4][0] == "WT HELLO role=idle" and rows[4][5] == "2" and rows[4][6] == "600"
    assert rows[5][0] == "WT HELLO_OK" and rows[5][7] == "0x00001234"
    assert rows[6][0] == "WT HB seq=88, WT HB seq=88" and rows[6][8].startswith("88")


@pytest.mark.skipif(TSHARK is None, reason="tshark not installed")
def test_dissector_reassembles_a_frame_split_across_segments(tmp_path):
    hb = wt.encode_frame(wt.Frame(wt.FrameType.HB, 0, 99, 4242))
    hello = wt.encode_hello(wt.Hello(wt.Role.HOT, 0xABCD, 0, b"a" * 8), S, b"n" * 16)
    cap = tmp_path / "split.pcap"
    pcap(cap, [tcp(hello[:9], 40003, 48100, 1), tcp(hello[9:] + hb[:7], 40003, 48100, 10), tcp(hb[7:], 40003, 48100, 38)])
    lua = tmp_path / "whydrop.lua"
    shutil.copy(LUA, lua)
    out = subprocess.run([TSHARK, "-X", f"lua_script:{lua}", "-r", str(cap), "-T", "fields", "-E", "separator=|",
                          "-e", "_ws.col.Info", "-e", "whydrop.wt.session_id", "-e", "whydrop.frame.seq",
                          "-e", "whydrop.frame.t_send_ns"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    assert out.returncode == 0, out.stderr
    rows = [line.split("|") for line in out.stdout.strip().splitlines()]
    assert any(r[0] == "WT HELLO role=hot" and r[1] == "0x0000abcd" for r in rows), rows
    assert any(r[0] == "WT HB seq=99" and r[2] == "99" and r[3] == "4242" for r in rows), rows
