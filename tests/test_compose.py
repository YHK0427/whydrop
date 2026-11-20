"""compose.yaml must keep the hardening of spec §10. Plain text checks: no YAML dependency for one file we own."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / "compose.yaml").read_text(encoding="utf-8")
LINES = [line.split("#", 1)[0].rstrip() for line in TEXT.splitlines()]
BODY = "\n".join(LINES)


def has(pattern: str) -> bool:
    return re.search(pattern, BODY, re.M) is not None


def test_compose_hardening():
    for pattern in (r"^\s+network_mode:\s*host$", r'^\s+user:\s*"10001"$', r"^\s+read_only:\s*true$",
                    r"^\s+tmpfs:\s*\[/tmp\]$", r"^\s+cap_drop:\s*\[ALL\]$",
                    r'^\s+security_opt:\s*\["no-new-privileges:true"\]$', r"^\s+pids_limit:\s*64$",
                    r"^\s+mem_limit:\s*128m$", r"^\s+cpu_shares:\s*\d+$", r'max-size:\s*"10m"', r'max-file:\s*"3"',
                    r"^\s+restart:\s*unless-stopped$", r"^\s+- /run/systemd/resolve:/run/systemd/resolve:ro$"):
        assert has(pattern), pattern


def test_compose_forbidden():
    for bad in ("privileged", "NET_ADMIN", "NET_RAW", "cap_add", "/var/run/docker.sock", "pid: host"):
        assert bad not in BODY, bad


def test_only_two_mounts():
    mounts = [line for line in LINES if re.match(r"^\s+- [^ ]+:[^ ]+", line) and "volumes" not in line]
    assert len(mounts) == 2


def test_dockerfile_runs_as_10001_and_pins_base():
    d = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM python:3\.12-slim@sha256:[0-9a-f]{64}", d, re.M)
    assert re.search(r"^USER 10001$", d, re.M) and "iw=" in d
