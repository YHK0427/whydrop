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
