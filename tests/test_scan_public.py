"""The public scanner itself, and the docs that are already public."""
from pathlib import Path

from scan_public import bad_addresses, main, scan

ROOT = Path(__file__).resolve().parent.parent


def test_scanner_flags_real_addresses():
    assert bad_addresses("router 192.168.0.1, isp 211.234.10.11") == {"192.168.0.1", "211.234.10.11"}
    assert bad_addresses("the router at 192.168.0.1.") == {"192.168.0.1"}
    assert bad_addresses("padded 192.168.000.001") == {"192.168.000.001"}
    assert bad_addresses("v6 2400:abcd:12::5 and fe80::1") == {"2400:abcd:12::5", "fe80::1"}


def test_scanner_passes_documentation_and_public_resolvers():
    assert bad_addresses("dns 1.1.1.1, doc 192.0.2.7, masked x.x.x.53, version 3.12.1, 0.0.0.0, 300.1.2.3") == set()
    assert bad_addresses("doc 2001:db8::1, lo ::1, at 12:30:45, google 2001:4860:4860::8888") == set()


def test_missing_or_empty_dir_fails(tmp_path):
    assert main([str(tmp_path / "nope")]) == 1
    assert main([str(tmp_path)]) == 1
    (tmp_path / "a.webmanifest").write_text('{"x": "10.0.0.2"}')   # any extension is read
    assert main([str(tmp_path)]) == 1
    (tmp_path / "a.webmanifest").write_text('{"x": "x.x.x.2"}')
    assert main([str(tmp_path)]) == 0


def test_public_docs_have_no_real_addresses():
    found = {}
    for d in ("docs", "contrib", "src/whydrop/web/static"):
        found.update(scan(ROOT / d))
    for f in ("README.md", "README.ko.md", "SECURITY.md", "CONTRIBUTING.md", "ROADMAP.md", "CHANGELOG.md",
              "whydrop.example.toml", ".env.example", "compose.yaml"):
        p = ROOT / f
        if p.exists():
            bad = bad_addresses(p.read_text(encoding="utf-8"))
            if bad:
                found[f] = bad
    assert not found, found
