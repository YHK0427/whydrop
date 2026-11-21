"""The public scanner itself, and the docs that are already public."""
from pathlib import Path

from scan_public import bad_addresses, scan

ROOT = Path(__file__).resolve().parent.parent


def test_scanner_flags_real_addresses_only():
    assert bad_addresses("router 192.168.0.1, isp 211.234.10.11") == {"192.168.0.1", "211.234.10.11"}
    assert bad_addresses("dns 1.1.1.1, doc 192.0.2.7, masked x.x.x.53, version 3.12.1, 0.0.0.0") == set()


def test_public_docs_have_no_real_addresses():
    found = {}
    for d in ("docs", "contrib"):
        found.update(scan(ROOT / d))
    for f in ("README.md", "README.ko.md", "whydrop.example.toml", ".env.example", "compose.yaml"):
        p = ROOT / f
        if p.exists():
            bad = bad_addresses(p.read_text(encoding="utf-8"))
            if bad:
                found[f] = bad
    assert not found, found
