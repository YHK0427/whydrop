from pathlib import Path

import pytest

from whydrop.agent.config import ConfigError, load_config

ROOT = Path(__file__).resolve().parents[2]


def test_defaults_match_spec():
    c = load_config(None, {})
    dns = [t for t in c.targets if t.kind == "dns"]
    stun = [t for t in c.targets if t.kind == "stun"]
    tcp = [t for t in c.targets if t.kind == "tcp443"]
    assert {t.addr for t in dns} == {"1.0.0.1", "8.8.8.8", "208.67.222.222", "9.9.9.9", "1.1.1.1"}
    assert {(t.addr, t.port) for t in stun} == {("stun.cloudflare.com", 3478), ("stun.l.google.com", 19302)}
    assert [t.addr for t in tcp] == ["8.8.8.8", "1.0.0.1", "208.67.222.222"] and all(t.port == 443 for t in tcp)
    prov = {t.addr: t.provider for t in c.targets}
    assert prov["1.0.0.1"] == prov["1.1.1.1"] == prov["stun.cloudflare.com"] == "cloudflare"
    assert prov["8.8.8.8"] == prov["stun.l.google.com"] == "google"
    assert prov["208.67.222.222"] == "opendns" and prov["9.9.9.9"] == "quad9"
    assert c.canary_idle_interval_s == 600 and c.udp_stream_pps == 10 and c.web.bind == "127.0.0.1:8790"


def test_env_beats_file(tmp_path):
    p = tmp_path / "w.toml"
    p.write_text('agent_name = "a"\ndb_path = "x.db"\n')
    c = load_config(p, {"WHYDROP_AGENT_NAME": "b"})
    assert c.agent_name == "b" and c.db_path == Path("x.db")


def test_unknown_key_fails(tmp_path):
    p = tmp_path / "w.toml"
    p.write_text("agnet_name = 'typo'\n")
    with pytest.raises(ConfigError, match="agnet_name"):
        load_config(p, {})


def test_unknown_nested_key_fails(tmp_path):
    p = tmp_path / "w.toml"
    p.write_text("[web]\nbnd = '0.0.0.0:1'\n")
    with pytest.raises(ConfigError, match="web.bnd"):
        load_config(p, {})


@pytest.mark.parametrize("v", [29, 7501])
def test_idle_interval_range(tmp_path, v):
    p = tmp_path / "w.toml"
    p.write_text(f"[canary]\nidle_interval_s = {v}\n")
    with pytest.raises(ConfigError, match="idle_interval_s"):
        load_config(p, {})


def test_example_file_loads():
    c = load_config(ROOT / "whydrop.example.toml", {})
    assert c.agent_name == "home"


@pytest.mark.parametrize("toml", [
    "[canary]\nidle_interval_s = 'abc'\n",
    "isp_dns = '198.51.100.1'\n",
    "[nat]\nenable_7500 = 'false'\n",
    "intervals = 5\n",
    "[intervals]\ngateway = 0\n",
    "[udp_stream]\npps = -1\n",
    "db_path = 5\n",
    "[[targets]]\naddr = '9.9.9.9'\nporrt = 53\nport = 53\nkind = 'dns'\nprovider = 'quad9'\n",
])
def test_wrong_types_give_config_error(tmp_path, toml):
    p = tmp_path / "w.toml"
    p.write_text(toml)
    with pytest.raises(ConfigError):
        load_config(p, {})


def test_non_utf8_file(tmp_path):
    p = tmp_path / "w.toml"
    p.write_bytes(bytes([0x61, 0x20, 0x3d, 0x20, 0x27, 0xff, 0xfe, 0x27, 0x0a]))
    with pytest.raises(ConfigError):
        load_config(p, {})


def test_web_bind_env_targets_and_intervals(tmp_path):
    p = tmp_path / "w.toml"
    p.write_text("[intervals]\nstun = 20\n[[targets]]\naddr = '9.9.9.9'\nport = 53\nkind = 'dns'\nprovider = 'quad9'\n")
    c = load_config(p, {"WHYDROP_WEB_BIND": "0.0.0.0:8790"})
    assert c.web.bind == "0.0.0.0:8790" and c.intervals["stun"] == 20.0 and c.intervals["gateway"] == 1.0
    assert [t.addr for t in c.targets] == ["9.9.9.9"]
