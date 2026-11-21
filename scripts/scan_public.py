"""Fail if a directory meant for the public (the static demo, the docs) contains an IP address that isn't a
documentation range, a loopback/unspecified address or a well-known public resolver. Masked forms (x.x.x.N) pass.
Every file is read; binary files (with a NUL byte) are skipped. A missing or empty directory fails, so a gate on it
can't pass by accident. Usage: scan_public.py DIR [DIR ...]"""
import ipaddress
import re
import sys
from pathlib import Path

KNOWN = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
         "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844"}
ALLOWED_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8",
                                                  "0.0.0.0/32", "2001:db8::/32", "::1/128", "::/128")]
V4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\w)(?!\.\d)")   # a trailing full stop still ends the address
V6 = re.compile(r"(?<![\w:.])((?:[0-9a-fA-F]{1,4}:){1,7}(?::[0-9a-fA-F]{1,4}){0,7}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
                r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})(?![\w:])")


def _v4(text: str):
    for ip in V4.findall(text):
        parts = [int(p) for p in ip.split(".")]
        if all(p <= 255 for p in parts):        # 192.168.000.001 is still an address; 300.1.2.3 isn't
            yield ".".join(map(str, parts)), ip


def _v6(text: str):
    for ip in V6.findall(text):
        if "::" not in ip and ip.count(":") < 7:
            continue                             # times like 12:30:45 and other colon runs
        try:
            yield str(ipaddress.ip_address(ip)), ip
        except ValueError:
            continue


def bad_addresses(text: str) -> set[str]:
    out = set()
    for norm, raw in (*_v4(text), *_v6(text)):
        a = ipaddress.ip_address(norm)
        if norm in KNOWN or any(a.version == n.version and a in n for n in ALLOWED_NETS):
            continue
        out.add(raw)
    return out


def scan(root: Path) -> dict[str, set[str]]:
    found = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        raw = p.read_bytes()
        if b"\0" in raw:
            continue
        bad = bad_addresses(raw.decode("utf-8", errors="replace"))
        if bad:
            found[str(p)] = bad
    return found


def main(dirs: list[str]) -> int:
    problems, rc = {}, 0
    for d in dirs:
        root = Path(d)
        if not root.is_dir() or not any(root.iterdir()):
            print(f"{d}: missing or empty")
            rc = 1
            continue
        problems.update(scan(root))
    for f, ips in problems.items():
        print(f"{f}: {sorted(ips)}")
    return 1 if problems or not dirs else rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
