"""run_agent wiring with every network call replaced by fakes (no packets leave the machine)."""
import asyncio
import json
import sqlite3

import pytest

from whydrop.agent import run as runmod
from whydrop.agent.config import load_config
from whydrop.agent.env import EnvInfo
from whydrop.agent.results import Result
from whydrop.agent.selfcheck import SelfCheck
from whydrop.cli import main


def ok(probe, pair="p"):
    async def f(*a, **k):
        return Result(probe, pair, None, 0, True, 1.0)
    return f


@pytest.fixture
def fakes(monkeypatch, tmp_path):
    calls = {"selfcheck": 0, "env": 0}
    envs = [EnvInfo("eth0", "192.0.2.1", "wired", ("198.51.100.53",), False, False, "eth0")]

    async def detect_env(cfg):
        calls["env"] += 1
        return envs[min(calls["env"], len(envs)) - 1]

    async def selfcheck(*a, **k):
        calls["selfcheck"] += 1
        return SelfCheck("ok")

    async def none(*a, **k):
        return None

    async def route():
        return ("192.0.2.1", "eth0")

    async def synced(*a, **k):
        return True

    async def interception():
        return {"verdict": "unknown"}

    monkeypatch.setattr(runmod.envmod, "kernel_release", lambda: "6.8.0-generic")
    monkeypatch.setattr(runmod, "wait_time_sync", synced)
    monkeypatch.setattr(runmod.host_net, "default_route", route)
    monkeypatch.setattr(runmod.envmod, "detect_env", detect_env)
    monkeypatch.setattr(runmod, "run_selfcheck", selfcheck)
    monkeypatch.setattr(runmod, "nat_mapping", none)
    monkeypatch.setattr(runmod, "dns_interception", interception)
    monkeypatch.setattr(runmod.Targets, "resolve", lambda self: none())
    monkeypatch.setattr(runmod.gateway, "probe", ok("gateway", "gateway"))
    monkeypatch.setattr(runmod.line_hb, "probe", ok("line_hb"))
    monkeypatch.setattr(runmod.dns_probe, "udp", ok("dns"))
    monkeypatch.setattr(runmod.dns_probe, "tcp", ok("dns_tcp"))
    monkeypatch.setattr(runmod.dns_probe, "router_cache_check", ok("dns_cache"))
    monkeypatch.setattr(runmod.tcp_connect, "probe", ok("tcp_connect"))
    monkeypatch.setattr(runmod.host_net, "probe", ok("host_net", "host_net"))
    cfg = load_config(None, {"WHYDROP_DB_PATH": str(tmp_path / "w.db")})
    return cfg, calls, envs


def run_for(cfg, seconds):
    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(runmod.run_agent(cfg, stop=stop))
        await asyncio.sleep(seconds)
        stop.set()
        await asyncio.wait_for(task, 10)
    asyncio.run(go())


def db(cfg, sql):
    con = sqlite3.connect(cfg.db_path)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def test_startup_order_and_run_rows(fakes):
    cfg, calls, _ = fakes
    run_for(cfg, 1.5)
    [(start, hb, stop, tags)] = db(cfg, "select start_ms, heartbeat_ms, stop_ms, tags_json from agent_runs")
    assert stop >= start and json.loads(tags)["route_at_start"] is True
    probes = {r[0] for r in db(cfg, "select distinct probe from samples_1s")}
    assert {"gateway", "host_net"} <= probes
    assert db(cfg, "select count(*) from selfcheck")[0][0] == 1 and calls["selfcheck"] == 1


def test_starts_without_route(fakes, monkeypatch):
    cfg, _, _ = fakes

    async def no_route():
        return (None, None)
    monkeypatch.setattr(runmod.host_net, "default_route", no_route)
    monkeypatch.setattr(runmod, "ROUTE_WAIT_S", 1)
    run_for(cfg, 2.5)
    [(tags,)] = db(cfg, "select tags_json from agent_runs")
    assert json.loads(tags)["route_at_start"] is False


def test_net_change_reruns_selfcheck(fakes, monkeypatch):
    cfg, calls, envs = fakes
    envs.append(EnvInfo("wlan0", "192.0.2.254", "wired", (), False, False, "wlan0"))
    monkeypatch.setattr(runmod, "NETWATCH_EVERY_S", 0.3)
    run_for(cfg, 1.5)
    kinds = [r[0] for r in db(cfg, "select kind from events")]
    assert "net_change" in kinds and calls["selfcheck"] >= 2


def test_vm_refusal_exit_3(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(runmod.envmod, "kernel_release", lambda: "5.15.153.1-microsoft-standard-WSL2")
    monkeypatch.setenv("WHYDROP_DB_PATH", str(tmp_path / "w.db"))
    assert main(["agent"]) == 3
    assert "not yours" in capsys.readouterr().err


def test_excluded_pairs_are_not_probed(fakes, monkeypatch):
    cfg, _, _ = fakes
    probed = []

    async def dns_udp(addr, cls, provider, now_ms, **k):
        probed.append((cls, addr))
        return Result("dns", f"{cls}:{addr}:53/udp", provider, 0, True, 1.0)

    async def selfcheck(*a, **k):
        return SelfCheck("ok", {"dns_router:192.0.2.1:53/udp": "no answer on this network",
                                "dns_public:9.9.9.9:53/udp": "no answer on this network"})
    monkeypatch.setattr(runmod.dns_probe, "udp", dns_udp)
    monkeypatch.setattr(runmod, "run_selfcheck", selfcheck)
    monkeypatch.setattr(runmod, "NETWATCH_EVERY_S", 600)
    run_for(cfg, 6.5)
    assert ("dns_public", "8.8.8.8") in probed
    assert ("dns_router", "192.0.2.1") not in probed and ("dns_public", "9.9.9.9") not in probed
