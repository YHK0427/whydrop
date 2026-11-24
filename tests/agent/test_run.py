"""run_agent wiring with every network call replaced by fakes (no packets leave the machine)."""
import asyncio
import json
import socket
import sqlite3
import time

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


def run_until(cfg, done, timeout_s):
    """Run the agent until `done()` holds (checked every 0.5 s) or the timeout; returns the seconds it took."""
    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(runmod.run_agent(cfg, stop=stop))
        t = time.monotonic()
        while time.monotonic() - t < timeout_s and not task.done():
            await asyncio.sleep(0.5)
            if await asyncio.to_thread(done):
                break
        took = time.monotonic() - t
        stop.set()
        await asyncio.wait_for(task, 10)
        return took
    return asyncio.run(go())


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


def test_start_mid_outage_records_at_once_and_stops_quickly(fakes, monkeypatch):
    cfg, calls, _ = fakes

    async def inconclusive(*a, **k):
        calls["selfcheck"] += 1
        return SelfCheck("inconclusive")
    monkeypatch.setattr(runmod, "run_selfcheck", inconclusive)

    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(runmod.run_agent(cfg, stop=stop))
        await asyncio.sleep(2.0)
        stop.set()
        t0 = asyncio.get_running_loop().time()
        await asyncio.wait_for(task, 5)
        return asyncio.get_running_loop().time() - t0
    took = asyncio.run(go())
    assert took < 3  # the 30 s → 5 min self-check backoff does not hold up shutdown
    assert db(cfg, "select count(*) from samples_1s where probe = 'gateway'")[0][0] >= 1  # probes ran during it


def test_startup_failure_still_closes_the_store(fakes, monkeypatch):
    cfg, _, _ = fakes

    async def boom(c):
        raise RuntimeError("detect failed")
    monkeypatch.setattr(runmod.envmod, "detect_env", boom)
    with pytest.raises(RuntimeError):
        asyncio.run(runmod.run_agent(cfg, stop=asyncio.Event()))
    con = sqlite3.connect(cfg.db_path)  # closed cleanly: the file opens and isn't locked
    con.execute("BEGIN EXCLUSIVE")
    con.close()


def test_vpn_egress_is_a_standing_finding(fakes):
    cfg, _, envs = fakes
    envs[0] = EnvInfo("eth0", "192.0.2.1", "wired", (), True, False, "tailscale0")
    run_for(cfg, 1.0)
    assert db(cfg, "select kind from findings") == [("vpn_egress",)]


def test_route_appears_later_then_link_is_recorded(fakes, monkeypatch):
    cfg, calls, envs = fakes
    envs[0] = EnvInfo(None, None, "unknown", (), False, False, None)
    envs.append(EnvInfo("eth0", "192.0.2.1", "wired", (), False, False, "eth0"))
    monkeypatch.setattr(runmod, "NETWATCH_EVERY_S", 0.3)
    monkeypatch.setattr(runmod.sys, "platform", "linux")

    class FakeLink:  # this host has no /sys/class/net/eth0; an unreadable carrier now records nothing
        def __init__(self, iface, now_ms):
            self.now = now_ms

        def probe(self):
            return Result("link", "link", None, self.now(), True, None), []
    monkeypatch.setattr(runmod.link, "LinkTracker", FakeLink)
    run_for(cfg, 2.0)
    assert ("link",) in db(cfg, "select distinct probe from samples_1s")


def test_recheck_failures_open_no_findings(fakes, monkeypatch):
    cfg, _, _ = fakes

    async def fail(*a, **k):
        return Result("dns", "dns_public:9.9.9.9:53/udp", "quad9", 0, False, None)

    async def main():
        agent = runmod.Agent(cfg, asyncio.Event())
        agent.findings = runmod.FindingsTracker(agent.targets, agent.now)
        agent.targets.exclude("dns_public:9.9.9.9:53/udp", "no answer on this network")
        agent._sc_excluded = {"dns_public:9.9.9.9:53/udp"}
        monkeypatch.setattr(agent, "check_pairs",
                            lambda: [runmod.CheckPair("dns_public:9.9.9.9:53/udp", "quad9", "dns_public", "9.9.9.9", "udp", fail)])
        base = [0]
        monkeypatch.setattr(agent, "now", lambda: base[0])
        agent.findings._now_ms = lambda: base[0]
        for _ in range(4):
            base[0] += 600_000
            await agent.job_recheck()
        return agent.findings.check(), agent.targets.excluded
    events, excluded = asyncio.run(main())
    assert events == [] and excluded["dns_public:9.9.9.9:53/udp"] == "no answer on this network"


def test_selfcheck_keeps_retrying_past_the_backoff_list(fakes, monkeypatch):
    cfg, calls, _ = fakes

    async def inconclusive(*a, **k):
        calls["selfcheck"] += 1
        return SelfCheck("inconclusive")
    monkeypatch.setattr(runmod, "run_selfcheck", inconclusive)
    monkeypatch.setattr(runmod, "BACKOFF_S", (0.05, 0.05))
    run_for(cfg, 1.5)
    assert calls["selfcheck"] >= 6  # inline pass + background loop that does not give up


def test_boot_clock_step_during_startup_does_not_skew_run_start(fakes, monkeypatch):
    import time as _time
    from whydrop.agent.clock import TimeBase as RealTimeBase
    cfg, _, _ = fakes
    offset = [0.0]

    async def route_then_ntp_step():
        offset[0] = 3600.0  # time sync jumps the clock while the agent waits for the route
        return ("192.0.2.1", "eth0")
    monkeypatch.setattr(runmod.host_net, "default_route", route_then_ntp_step)
    monkeypatch.setattr(runmod, "TimeBase", lambda: RealTimeBase(wall=lambda: _time.time() + offset[0]))
    run_for(cfg, 1.0)
    [(start,)] = db(cfg, "select start_ms from agent_runs")
    assert abs(start / 1000 - (_time.time() + 3600)) < 30


def test_selfcheck_covers_tcp_for_every_tcp_probed_class(fakes):
    cfg, _, _ = fakes

    async def main():
        a = runmod.Agent(cfg, asyncio.Event())
        a.targets.router_dns, a.targets.isp_dns = "192.0.2.1", ("198.51.100.53",)
        names = {cp.pair for cp in a.check_pairs()}
        tcp_probed = {(c, addr) for c in ("dns_public", "dns_isp") for addr, _ in a.targets.dns_pairs(c)}
        return names, tcp_probed
    names, tcp_probed = asyncio.run(main())
    assert all(f"{c}:{addr}:53/tcp" in names for c, addr in tcp_probed)
    assert "dns_isp:198.51.100.53:53/tcp" in names  # found on the real home network: one ISP resolver refuses TCP



# ---------- precision mode against the real Plan 1 reflector on loopback ----------
SECRET = "s" * 40


async def _reflector(secret=SECRET):
    from whydrop.reflector.replay import Tombstones
    from whydrop.reflector.tcp import TcpReflector, serve_tcp
    from whydrop.reflector.udp import UdpReflector, serve_udp
    from helpers.ports import tcp_then_udp
    t, u, _ = await tcp_then_udp(lambda p: serve_tcp(TcpReflector(secret.encode(), epoch=3), "127.0.0.1", p),
                                 lambda p: serve_udp(UdpReflector(secret.encode(), epoch=3, tombstones=Tombstones(None)),
                                                     "127.0.0.1", p))
    return u, t


def precision_cfg(tmp_path, monkeypatch, port=9):   # with a reflector, run_with puts the port it really got
    monkeypatch.setenv("WHYDROP_SECRET", SECRET)
    return load_config(None, {"WHYDROP_DB_PATH": str(tmp_path / "w.db"), "WHYDROP_REFLECTOR": f"127.0.0.1:{port}"})


def run_with(cfg, seconds, reflector_secret=SECRET, with_reflector=True):
    async def go():
        from dataclasses import replace
        servers = await _reflector(reflector_secret) if with_reflector else None   # held open: no port reused later
        run_cfg = replace(cfg, reflector=f"127.0.0.1:{servers[0].port}") if servers else cfg
        stop = asyncio.Event()
        task = asyncio.create_task(runmod.run_agent(run_cfg, stop=stop))
        await asyncio.sleep(seconds)
        stop.set()
        await asyncio.wait_for(task, 10)
        if servers:
            await servers[0].close()
            servers[1].close()
    return asyncio.run(go())


def test_precision_e2e(fakes, monkeypatch, tmp_path):
    import sys
    cfg = precision_cfg(tmp_path, monkeypatch)
    run_with(cfg, 5.0)
    [(sent, ok, lost, late, local)] = db(cfg, "select sum(sent), sum(ok), sum(lost), sum(late), sum(local_fail) "
                                              "from samples_1s where probe = 'udp_stream'")
    assert 30 <= sent <= 55 and lost == 0 and local == 0 and ok + late == sent   # a loaded machine can be late, never lossy
    kinds = {k for (k,) in db(cfg, "select kind from events")}
    assert "auth_fail" not in kinds and ("tcp_info" in kinds) == sys.platform.startswith("linux")
    assert json.loads(db(cfg, "select tags_json from agent_runs")[0][0])["mode"] == "precision"
    assert db(cfg, "select kind from findings where kind != 'vpn_egress'") == []


def test_reflector_down_is_precision_degraded_not_incident(fakes, monkeypatch, tmp_path):
    monkeypatch.setattr(runmod, "PRECISION_EVERY_S", 0.3)
    monkeypatch.setattr(runmod, "DEGRADED_AFTER_S", 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    free = s.getsockname()[1]
    s.close()
    cfg = precision_cfg(tmp_path, monkeypatch, free)
    run_with(cfg, 3.5, with_reflector=False)
    found = [k for (k,) in db(cfg, "select kind from findings")]
    assert found == ["precision_degraded"]


def test_wrong_secret_is_secret_mismatch(fakes, monkeypatch, tmp_path):
    monkeypatch.setattr(runmod, "PRECISION_EVERY_S", 0.3)
    cfg = precision_cfg(tmp_path, monkeypatch)
    run_with(cfg, 2.0, reflector_secret="z" * 40)
    assert "secret_mismatch" in [k for (k,) in db(cfg, "select kind from findings")]



# ---------- live analysis (Plan 4) ----------
def test_incident_rows_written_live_and_replay_matches(fakes, monkeypatch, tmp_path):
    from whydrop.analysis import constants as K
    from whydrop.analysis.replay import replay
    monkeypatch.setattr(runmod, "ANALYSIS_START_S", 0)
    monkeypatch.setattr(K, "FINALIZE_LAG_MS", 6500)
    cfg, _, _ = fakes
    t0 = {}

    async def resolve(self):
        for s in self.by_kind("stun"):
            self.resolved[s.addr] = "192.0.2.10"
    monkeypatch.setattr(runmod.Targets, "resolve", resolve)

    async def line_hb(slot, now_ms, **k):
        t = now_ms()
        t0.setdefault("t", t)
        ok = not (3000 <= t - t0["t"] < 15000)   # 12 s: clear of the 10 s lossy-period gate and probe timing on a slow runner
        return Result("line_hb", f"line_hb:{slot.provider}", slot.provider, t, ok, 5.0 if ok else None)
    monkeypatch.setattr(runmod.line_hb, "probe", line_hb)
    async def no_link():
        return None
    monkeypatch.setattr(runmod.Agent, "job_link_layer", lambda self: no_link())  # CI runners have a real /sys link
    def written():
        try:
            return bool(db(cfg, "select 1 from incidents"))
        except sqlite3.OperationalError:   # the store hasn't made its tables yet
            return False
    run_until(cfg, written, 90)   # usually 14 s; a fixed 25 s once ran out on a loaded CI runner
    rows = db(cfg, "select start_ms, primary_cause, evidence_json, tags_json from incidents")
    assert len(rows) == 1 and rows[0][1] == "R2" and "likely" in json.loads(rows[0][2])["label"]
    assert json.loads(rows[0][3])["segments"] == ["line"]
    replayed = [c.obj.incident for c in replay(cfg.db_path) if c.type == "incident" and c.obj.op == "open"]
    assert [(i.start_ms, sorted(i.segments)) for i in replayed] == [(rows[0][0], ["line"])]


def test_packet_strip_saved_around_incident(fakes, tmp_path):
    from whydrop.analysis.incidents import Incident
    cfg, _, _ = fakes

    class Book:
        def ring_window(self, a, b):
            return [(a + 1000, 7, True, "ok"), (a + 2000, 8, False, "up"), (a + 3000, -1, False, "local")]

    async def go():
        agent = runmod.Agent(cfg, asyncio.Event())
        await agent.store.open()
        agent.stream = type("S", (), {"book": Book()})()
        agent._strip("open", Incident(start_ms=100_000))
        await asyncio.gather(*agent._bg)
        await agent.store.close()
    asyncio.run(go())
    assert db(cfg, "select seq, echoed, dir from udp_seq_ring order by seq") == [(7, 1, "ok"), (8, 0, "up")]



def test_dashboard_served_while_recording(fakes, monkeypatch):
    import socket
    import urllib.request
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    cfg, _, _ = fakes
    from dataclasses import replace
    cfg = replace(cfg, web=replace(cfg.web, bind=f"127.0.0.1:{port}"))
    got = {}

    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(runmod.run_agent(cfg, stop=stop))
        await asyncio.sleep(2.0)
        got["health"] = await asyncio.to_thread(
            lambda: urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=3).read())
        got["status"] = json.loads(await asyncio.to_thread(
            lambda: urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=3).read()))
        stop.set()
        await asyncio.wait_for(task, 10)
    asyncio.run(go())
    assert got["health"] == b'{"ok":true}' and got["status"]["mode"] == "basic"



def test_alert_sent_for_finalized_drop_through_the_agent(fakes, monkeypatch):
    from whydrop.agent import notify
    sent = []
    monkeypatch.setattr(notify, "_post", lambda url, body, headers: sent.append(json.loads(body)))
    cfg, _, _ = fakes
    from dataclasses import replace
    cfg = replace(cfg, notify={"webhook_url": "http://127.0.0.1:9/hook", "format": "json"})

    async def go():
        stop = asyncio.Event()
        agent = runmod.Agent(cfg, stop)
        task = asyncio.create_task(agent.run())
        await asyncio.sleep(1.5)
        agent.bus.publish("incident", {"op": "finalized", "row": {
            "id": 1, "start_ms": 0, "end_ms": 5000, "primary_cause": "R2", "cause_final": "R2",
            "tags_json": json.dumps({"segments": ["line"]}), "evidence_json": json.dumps({"label": "Line drop (likely)"})}})
        await asyncio.sleep(0.5)
        stop.set()
        await asyncio.wait_for(task, 10)
    asyncio.run(go())
    assert [m["drop"]["cause"] for m in sent] == ["R2"]



def test_dashboard_port_in_use_does_not_stop_recording(fakes, caplog):
    import socket
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen()
    port = busy.getsockname()[1]
    cfg, _, _ = fakes
    from dataclasses import replace
    cfg = replace(cfg, web=replace(cfg.web, bind=f"127.0.0.1:{port}"))
    try:
        run_for(cfg, 2.0)
    finally:
        busy.close()
    assert db(cfg, "select count(*) from samples_1s where probe = 'gateway'")[0][0] >= 1
    assert "dashboard off: can't listen" in caplog.text  # refused cleanly, not stolen (Windows SO_REUSEADDR) or exit()


def test_config_enable_7500_reaches_the_dashboard_run(fakes, monkeypatch):
    """The dashboard's "Run NAT test" never tried 7500 s, whatever `[nat] enable_7500` said."""
    from dataclasses import replace

    from whydrop.agent.precision import natprobe
    seen = {}

    class Stop(Exception):
        pass

    async def fake(addr, secret, *, tcp_delays=natprobe.TCP_DELAYS, on_progress=None, **k):
        seen["tcp"] = tcp_delays
        raise Stop
    monkeypatch.setattr(natprobe, "nat_test", fake)
    monkeypatch.setenv("WHYDROP_SECRET", "s" * 40)
    cfg, _, _ = fakes
    for enabled in (False, True):
        agent = runmod.Agent(replace(cfg, reflector="192.0.2.9:48100", nat_enable_7500=enabled), asyncio.Event())
        with pytest.raises(Stop):
            asyncio.run(agent._run_nat())
        assert (seen["tcp"][-1] == 7500) is enabled


def test_no_secret_or_url_token_ever_reaches_the_log(fakes, monkeypatch, tmp_path, caplog):
    """L2 audit: the reflector secret, the dashboard token and a token inside the webhook URL, through a run that
    fails every way it can (wrong secret at the reflector, an alert endpoint that refuses)."""
    import logging
    from dataclasses import replace
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(runmod, "PRECISION_EVERY_S", 0.3)
    ui = "uiTok_" + "u" * 20
    monkeypatch.setenv("WHYDROP_UI_TOKEN", ui)
    hook = "http://127.0.0.1:9/hook?auth=hookTok_" + "h" * 20
    cfg = replace(precision_cfg(tmp_path, monkeypatch), notify={"webhook_url": hook, "kuma_push_url": hook})
    run_with(cfg, 2.0, reflector_secret="z" * 40)
    text = caplog.text + "".join(str(r.args) for r in caplog.records)
    assert "finding: secret_mismatch" in caplog.text                      # the failing path really ran
    assert SECRET not in text and "z" * 40 not in text and ui not in text and "hookTok_" not in text
