"""Fail if a directory meant for the public (the static demo, docs, screenshots' text) contains an address that
isn't a documentation range, a well-known public resolver or a masked x.x.x.N. Usage: scan_public.py DIR [DIR ...]"""
import ipaddress
import re
import sys
from pathlib import Path

KNOWN = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"}
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8",
                                               "0.0.0.0/32", "2001:db8::/32")]
V4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
TEXT = {".json", ".md", ".html", ".js", ".css", ".txt", ".toml", ".yml", ".yaml", ".lua", ".py"}


def bad_addresses(text: str) -> set[str]:
    out = set()
    for ip in V4.findall(text):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip in KNOWN or any(a in n for n in DOC_NETS):
            continue
        out.add(ip)
    return out


def scan(root: Path) -> dict[str, set[str]]:
    found = {}
    for p in root.rglob("*"):
        if p.is_file() and p.suffix in TEXT and "vendor" not in p.parts:
            bad = bad_addresses(p.read_text(encoding="utf-8", errors="replace"))
            if bad:
                found[str(p)] = bad
    return found


if __name__ == "__main__":
    problems = {}
    for d in sys.argv[1:]:
        problems.update(scan(Path(d)))
    for f, ips in problems.items():
        print(f"{f}: {sorted(ips)}")
    sys.exit(1 if problems else 0)
