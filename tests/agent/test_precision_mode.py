import asyncio
from collections import Counter

import pytest

from whydrop.agent import run as runmod
from whydrop.agent.config import load_config
from whydrop.agent.precision import precision_enabled, reflector_addr
from whydrop.agent.results import Result

SECRET = {"WHYDROP_SECRET": "s" * 40}


def test_precision_needs_reflector_and_secret():
    assert precision_enabled(load_config(None, {}), SECRET) == (False, "no reflector configured")
    cfg = load_config(None, {"WHYDROP_REFLECTOR": "reflector.example"})
    assert precision_enabled(cfg, {}) == (False, "WHYDROP_SECRET not set")
    assert precision_enabled(cfg, SECRET) == (True, None)


def test_bad_secret_is_a_reason_not_a_crash():
    cfg = load_config(None, {"WHYDROP_REFLECTOR": "reflector.example"})
    ok, why = precision_enabled(cfg, {"WHYDROP_SECRET": "short"})
    assert not ok and "32" in why


def test_reflector_addr_default_port():
    assert reflector_addr(load_config(None, {"WHYDROP_REFLECTOR": "reflector.example"})) == ("reflector.example", 48100)
    assert reflector_addr(load_config(None, {"WHYDROP_REFLECTOR": "192.0.2.9:5000"})) == ("192.0.2.9", 5000)


def test_public_dns_interval_doubles_in_precision(monkeypatch, tmp_path):
    seen = Counter()

    async def udp(addr, cls, provider, now_ms, **k):
        seen[(cls, addr)] += 1
        return Result("dns", f"{cls}:{addr}:53/udp", provider, 0, True, 1.0)
    monkeypatch.setattr(runmod.dns_probe, "udp", udp)

    async def main(precision):
        cfg = load_config(None, {"WHYDROP_DB_PATH": str(tmp_path / "w.db")})
        a = runmod.Agent(cfg, asyncio.Event())
        a.precision = precision
        a.targets.router_dns = "192.0.2.1"
        a.agg = runmod.Aggregator(None, a.now)
        a.findings = runmod.FindingsTracker(a.targets, a.now)
        for _ in range(20):
            await a.job_dns()

    asyncio.run(main(True))
    assert seen[("dns_router", "192.0.2.1")] == 4 and seen[("dns_public", "8.8.8.8")] == 2
    seen.clear()
    asyncio.run(main(False))
    assert seen[("dns_router", "192.0.2.1")] == 4 and seen[("dns_public", "8.8.8.8")] == 4


def test_line_hb_half_rate_only_with_open_gateway_port(monkeypatch, tmp_path):
    sent = []

    async def probe(slot, now_ms, **k):
        sent.append(slot.provider)
        return Result("line_hb", "p", slot.provider, 0, True, 1.0)
    monkeypatch.setattr(runmod.line_hb, "probe", probe)

    async def main(open_port):
        cfg = load_config(None, {"WHYDROP_DB_PATH": str(tmp_path / "w.db")})
        a = runmod.Agent(cfg, asyncio.Event())
        a.precision, a._gw_open = True, open_port
        for s in a.targets.by_kind("stun"):
            a.targets.resolved[s.addr] = "192.0.2.10"
        a.agg = runmod.Aggregator(None, a.now)
        a.findings = runmod.FindingsTracker(a.targets, a.now)
        for _ in range(10):
            await a.job_line_hb()
    asyncio.run(main(True))
    assert len(sent) == 5
    sent.clear()
    asyncio.run(main(False))
    assert len(sent) == 10


def test_bad_reflector_value_is_a_reason():
    cfg = load_config(None, {"WHYDROP_REFLECTOR": "host:abc"})
    assert precision_enabled(cfg, SECRET) == (False, "reflector must be host or host:port")


@pytest.mark.parametrize("v", [":48100", "a b", "r.example:0", "[2001:db8::1]:48100", "2001:db8::1"])
def test_other_unusable_reflector_values_turn_precision_off_with_the_reason(v):
    """These passed the check (port 0, an empty host, IPv6 on AF_INET sockets); basic mode keeps running."""
    cfg = load_config(None, {"WHYDROP_REFLECTOR": v})
    assert precision_enabled(cfg, SECRET) == (False, "reflector must be host or host:port")

