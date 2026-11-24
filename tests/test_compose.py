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


def test_only_the_expected_mounts():
    mounts = [line.strip() for line in LINES if re.match(r"^\s+- [^ ]+:[^ ]+", line) and "volumes" not in line]
    assert mounts == ["- whydrop-data:/data", "- /run/systemd/resolve:/run/systemd/resolve:ro",
                      "- /etc/localtime:/etc/localtime:ro"]   # data, DNS config, time zone; nothing writable from the host


def test_dockerfile_runs_as_10001_and_pins_base():
    d = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM python:3\.12-slim@sha256:[0-9a-f]{64}", d, re.M)
    assert re.search(r"^USER 10001$", d, re.M) and "iw=" in d


def test_settings_in_whydrop_toml_win_over_compose_defaults(tmp_path):
    """Final review: compose passed WHYDROP_AGENT_NAME=home and WHYDROP_WEB_BIND=0.0.0.0:8790 whenever .env was silent,
    and the environment beats the file, so agent_name and [web] bind in a mounted whydrop.toml were ignored."""
    import re as _re
    from whydrop.agent.config import load_config
    env = {}
    for k, default in _re.findall(r"(WHYDROP_[A-Z_]+): \$\{WHYDROP_[A-Z_]+:-([^}]*)\}", BODY):
        env[k] = default                                     # what compose hands the agent with an empty .env
    env.update({k: v for k, v in _re.findall(r"^\s+(WHYDROP_[A-Z_]+): ([^$\s#][^\s#]*)", BODY, _re.M)})
    p = tmp_path / "whydrop.toml"
    p.write_text('agent_name = "office"\n[web]\nbind = "127.0.0.1:8790"\n')
    c = load_config(p, env)
    assert (c.agent_name, c.web.bind) == ("office", "127.0.0.1:8790")
    c = load_config(None, env)
    assert (c.agent_name, c.web.bind) == ("home", "0.0.0.0:8790")   # no file: the compose quick start stays LAN-reachable
