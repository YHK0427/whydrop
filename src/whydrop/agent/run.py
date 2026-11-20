"""`whydrop agent` (basic mode): startup order, probe schedule, persistence (spec §5.1, §5.2, §5.6)."""
import asyncio
import json
import logging
import secrets
import sys

from whydrop import __version__
from whydrop.agent import env as envmod
from whydrop.agent.clock import TimeBase, wait_time_sync
from whydrop.agent.config import Config
from whydrop.agent.housekeeping import housekeep
from whydrop.agent.probes import dns_probe, gateway, host_net, line_hb, link, tcp_connect, wifi
from whydrop.agent.probes.stun_probe import StunWatcher
from whydrop.agent.probes.targets import Targets, pair_id
from whydrop.agent.report import dns_interception, report_card
from whydrop.agent.results import Aggregator, Result
from whydrop.agent.scheduler import LagWatchdog, Scheduler
from whydrop.agent.selfcheck import CheckPair, FindingsTracker, nat_mapping, run_selfcheck
from whydrop.agent.store import Store

log = logging.getLogger("whydrop.agent")

ROUTE_WAIT_S = 30
TIME_SYNC_WAIT_S = 60
SELFCHECK_EVERY_S = 6 * 3600
RECHECK_EVERY_S = 600
NETWATCH_EVERY_S = 5
BACKOFF_S = (30, 60, 120, 300)


class VMRefused(RuntimeError):
    pass


def _mask(ip: str | None) -> str:
    return f"x.x.x.{ip.rsplit('.', 1)[-1]}" if ip else "-"


class Agent:
    def __init__(self, cfg: Config, stop: asyncio.Event):
        self.cfg, self.stop = cfg, stop
        self.tb = TimeBase()
        self.store = Store(cfg.db_path)
        self.targets = Targets(cfg)
        self.sched = Scheduler()
        self.tags: dict = {}
        self.env: envmod.EnvInfo | None = None
        self.stun: StunWatcher | None = None
        self._bg: set[asyncio.Task] = set()
        self._rot = {"line_hb": 0, "tcp": 0, "dns_tcp": 0}

    # ---------- small helpers ----------
    def now(self) -> int:
        return self.tb.now_ms()

    def spawn(self, coro) -> None:
        t = asyncio.create_task(coro)
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)

    def late_cb(self, probe: str, pair: str, t_ms: int):
        return lambda: self.spawn(self.agg.late(probe, pair, t_ms))

    async def record(self, items) -> None:
        events = []
        for x in items if isinstance(items, list) else [items]:
            if isinstance(x, Result):
                self.agg.add(x)
                self.findings.feed(x)
            else:
                events.append(x)
        if events:
            await self.store.add_events(events)

    # ---------- startup ----------
    async def wait_route(self) -> bool:
        for _ in range(ROUTE_WAIT_S):
            gw, iface = await host_net.default_route()
            if iface is not None:
                return True
            await asyncio.sleep(1)
        return False

    def check_pairs(self) -> list[CheckPair]:
        t, now = self.targets, self.now
        pairs = []
        for cls in ("dns_router", "dns_isp", "dns_public"):
            for addr, prov in t.dns_pairs(cls):
                pairs.append(CheckPair(pair_id(cls, addr, 53, "udp"), prov, cls, addr, "udp",
                                       lambda a=addr, c=cls, p=prov: dns_probe.udp(a, c, p, now)))
                if cls == "dns_public":
                    pairs.append(CheckPair(pair_id(cls, addr, 53, "tcp"), prov, cls, addr, "tcp",
                                           lambda a=addr, c=cls, p=prov: dns_probe.tcp(a, c, p, now)))
        for s in t.by_kind("stun"):
            ip = t.addr(s.addr)
            if ip:
                pairs.append(CheckPair(pair_id("line_hb", s.addr, s.port, "udp"), s.provider, "stun", s.addr, "udp",
                                       lambda s=s, ip=ip: line_hb.probe(s, now, addr=ip)))
        for s in t.by_kind("tcp443"):
            pairs.append(CheckPair(pair_id("tcp", s.addr, s.port, "tcp"), s.provider, "tcp", s.addr, "tcp",
                                   lambda s=s: tcp_connect.probe(s, now)))
        return pairs

    async def selfcheck(self) -> str:
        await self.targets.resolve()
        gw = self.env.gateway if self.env else None
        gw_probe = (lambda: gateway.probe(gw, self.cfg.gateway_port, self.now)) if gw else None
        sc = await run_selfcheck(self.check_pairs(), gw_probe)
        if sc.status == "ok":
            for k in [k for k in self.targets.excluded if k not in sc.excluded]:
                self.targets.include(k)
            for k, why in sc.excluded.items():
                self.targets.exclude(k, why)
        stuns = [(self.targets.addr(s.addr), s.port) for s in self.targets.by_kind("stun")]
        nat = await nat_mapping([s for s in stuns if s[0]]) if all(s[0] for s in stuns) else None
        card = report_card(self.env, sc, nat, interception=await dns_interception())
        await self.store.insert("selfcheck", ts_ms=self.now(), result_json=json.dumps(card))
        log.info("self-check %s; excluded: %s", sc.status,
                 ", ".join(f"{k} ({v})" for k, v in self.targets.excluded.items()) or "none")
        return sc.status

    async def selfcheck_with_backoff(self) -> None:
        for wait in (0, *BACKOFF_S):
            if wait:
                await asyncio.sleep(wait)
            if self.stop.is_set() or await self.selfcheck() == "ok":
                return

    # ---------- probe jobs ----------
    async def job_gateway(self):
        if self.env and self.env.gateway:
            await self.record(await gateway.probe(self.env.gateway, self.cfg.gateway_port, self.now))

    async def job_line_hb(self):
        rot = self.targets.line_hb_rotation()
        if not rot:
            return
        slot = rot[self._rot["line_hb"] % len(rot)]
        self._rot["line_hb"] += 1
        ip = self.targets.addr(slot.addr)
        if ip:
            t0 = self.now()
            await self.record(await line_hb.probe(slot, self.now, addr=ip, on_late=self.late_cb(
                "line_hb", pair_id("line_hb", slot.addr, slot.port, "udp"), t0)))

    def dns_job(self, cls: str, addr: str, provider: str | None):
        async def run():
            if pair_id(cls, addr, 53, "udp") in self.targets.excluded or provider in self.targets.excluded_providers:
                return  # excluded pairs are only re-tried by job_recheck
            t0 = self.now()
            await self.record(await dns_probe.udp(addr, cls, provider, self.now,
                                                  on_late=self.late_cb("dns", pair_id(cls, addr, 53, "udp"), t0)))
        return run

    async def job_dns_tcp(self):
        pairs = [(a, p) for a, p in self.targets.dns_pairs("dns_public") + self.targets.dns_pairs("dns_isp")
                 if pair_id("dns_public" if p else "dns_isp", a, 53, "tcp") not in self.targets.excluded]
        if pairs:
            addr, prov = pairs[self._rot["dns_tcp"] % len(pairs)]
            self._rot["dns_tcp"] += 1
            cls = "dns_public" if prov else "dns_isp"
            await self.record(await dns_probe.tcp(addr, cls, prov, self.now))

    async def job_router_cache(self):
        r = self.targets.router_dns
        if r and pair_id("dns_router", r, 53, "udp") not in self.targets.excluded:
            await self.record(await dns_probe.router_cache_check(self.targets.router_dns, self.now))

    async def job_stun(self):
        servers = [(self.targets.addr(s.addr), s.port, s.provider) for s in self.targets.by_kind("stun")]
        if not all(s[0] for s in servers):
            return
        if self.stun is None:
            self.stun = StunWatcher(servers, self.now)
        await self.record(await self.stun.probe())

    async def job_tcp(self):
        rot = self.targets.tcp_rotation()
        if rot:
            t = rot[self._rot["tcp"] % len(rot)]
            self._rot["tcp"] += 1
            await self.record(await tcp_connect.probe(t, self.now))

    async def job_host_net(self):
        await self.record(await host_net.probe(self.now))

    async def job_wifi(self):
        snap = await self.wifi_src.snapshot()
        events = self.wifi_tracker.update(snap)
        await self.record([wifi.to_result(snap, self.wifi_tracker, self.now()), *events])

    async def job_link(self):
        r, events = self.link_tracker.probe()
        await self.record([r, *events])

    async def job_tick(self):
        events = self.tb.check()
        if events:
            await self.store.add_events(events)

    async def job_findings(self):
        events = self.findings.check()
        for e in events:
            if e.detail.get("phase") == "start":
                await self.store.insert("findings", kind=e.detail["kind"], start_ms=e.ts_ms,
                                        detail_json=json.dumps({**e.detail, "pair": e.pair}))
        if events:
            await self.store.add_events(events)

    async def job_recheck(self):
        """Excluded pairs get one fresh try every 10 minutes (spec §5.1)."""
        for cp in self.check_pairs():
            if cp.pair in self.targets.excluded and (await cp.run()).ok:
                self.targets.include(cp.pair)
                log.info("%s answers again; back in decisions", cp.pair)

    async def job_netwatch(self):
        new = await envmod.detect_env(self.cfg)
        old = self.env
        if old and (new.gateway, new.iface, new.isp_dns, new.egress_vpn, new.egress_iface) != \
                (old.gateway, old.iface, old.isp_dns, old.egress_vpn, old.egress_iface):
            self.env = new
            self.targets.router_dns = self.cfg.router_dns or new.gateway
            self.targets.isp_dns = new.isp_dns
            from whydrop.agent.events import Event
            await self.store.add_events([Event("net_change", self.now(), detail={
                "gateway_changed": new.gateway != old.gateway, "iface": new.iface, "vpn": new.egress_vpn})])
            log.info("network changed; re-running self-check")
            self.spawn(self.selfcheck_with_backoff())

    async def job_flush(self):
        await self.agg.flush_ready()
        await self.store.flush()

    # ---------- main ----------
    async def run(self, on_ready=None) -> None:
        msg = envmod.vm_refusal(envmod.kernel_release(), None)
        if msg:
            raise VMRefused(msg)
        if not await wait_time_sync(TIME_SYNC_WAIT_S):
            self.tags["clock"] = "unsynced"
        self.tags["route_at_start"] = await self.wait_route()
        await self.store.open()
        salt = await self.store.meta_get("salt")
        if salt is None:
            salt = secrets.token_hex(16)
            await self.store.meta_set("salt", salt)
        labels = json.loads(await self.store.meta_get("ap_labels") or "{}")
        self.env = await envmod.detect_env(self.cfg)
        msg = envmod.vm_refusal(envmod.kernel_release(), self.env.gateway)
        if msg:
            await self.store.close()
            raise VMRefused(msg)
        self.targets.router_dns = self.cfg.router_dns or self.env.gateway
        self.targets.isp_dns = self.env.isp_dns
        self.agg = Aggregator(self.store, self.now)
        self.findings = FindingsTracker(self.targets, self.now)
        self.wifi_tracker = wifi.WifiTracker(bytes.fromhex(salt), self.now, labels)
        run_id = await self.store.run_start(self.now(), __version__, self.tags)
        await self.selfcheck_with_backoff() if self.tags["route_at_start"] else self.spawn(self.selfcheck_with_backoff())

        iv = self.cfg.intervals
        s = self.sched
        s.every("tick", 1.0, self.job_tick)
        s.every("host_net", iv["host_net"], self.job_host_net)
        s.every("gateway", iv["gateway"], self.job_gateway, phase_s=0.1, max_inflight=3)
        s.every("line_hb", iv["line_hb"], self.job_line_hb, phase_s=0.5, max_inflight=3)
        for cls in ("dns_router", "dns_isp", "dns_public"):
            for i, (addr, prov) in enumerate(self.targets.dns_pairs(cls)):
                s.every(f"dns:{cls}:{addr}", iv["dns"], self.dns_job(cls, addr, prov), phase_s=(i * 0.7) % iv["dns"],
                        max_inflight=2)
        s.every("dns_tcp", iv["dns_tcp"], self.job_dns_tcp, phase_s=2.5)
        s.every("dns_cache", 60.0, self.job_router_cache, phase_s=17)
        s.every("stun", iv["stun"], self.job_stun, phase_s=3.3)
        s.every("tcp_connect", iv["tcp_connect"], self.job_tcp, phase_s=1.3, max_inflight=2)
        if self.env.link == "wifi" and (sys.platform.startswith("linux") or sys.platform == "win32"):
            self.wifi_src = wifi.LinuxWifi(self.env.iface) if sys.platform.startswith("linux") else wifi.WindowsWifi()
            s.every("wifi", iv["wifi"] if sys.platform.startswith("linux") else iv["wifi_windows"], self.job_wifi)
        elif self.env.link == "wired" and self.env.iface:
            self.link_tracker = link.LinkTracker(self.env.iface, now_ms=self.now)
            s.every("link", iv["link"], self.job_link)
        s.every("flush", 1.0, self.job_flush, phase_s=0.9)
        s.every("findings", 5.0, self.job_findings, phase_s=4.1)
        s.every("recheck", RECHECK_EVERY_S, self.job_recheck, phase_s=RECHECK_EVERY_S)
        s.every("netwatch", NETWATCH_EVERY_S, self.job_netwatch, phase_s=NETWATCH_EVERY_S)
        s.every("selfcheck", SELFCHECK_EVERY_S, self.selfcheck_with_backoff, phase_s=SELFCHECK_EVERY_S)
        s.every("heartbeat", 30.0, lambda: self.store.run_heartbeat(run_id, self.now()), phase_s=30)
        s.every("housekeeping", 600.0, lambda: housekeep(self.store, self.now(),
                                                         min_free_mb=self.cfg.storage_min_free_mb), phase_s=60)
        watchdog = LagWatchdog(lambda e: self.spawn(self.store.add_events([e])), now_ms=self.now)
        self.tb.rebase()  # the self-check above took seconds; that is not a suspend

        log.info("watching: mode=basic link=%s gateway=%s isp_dns=%s excluded=%s",
                 self.env.link, _mask(self.env.gateway), ",".join(_mask(a) for a in self.env.isp_dns) or "unknown",
                 ", ".join(f"{k} ({v})" for k, v in self.targets.excluded.items()) or "none")
        if self.env.egress_vpn:
            log.warning("probes leave via VPN: line results describe the tunnel")
        if on_ready:
            on_ready(self)
        try:
            await asyncio.gather(s.run(self.stop), watchdog.run(self.stop))
        finally:
            for t in list(self._bg):
                t.cancel()
            await asyncio.gather(*self._bg, return_exceptions=True)
            await self.store.meta_set("ap_labels", json.dumps(self.wifi_tracker.labels))
            await self.agg.flush_ready(force=True)
            await self.store.run_stop(run_id, self.now())
            if self.stun:
                self.stun.close()
            await self.store.close()


async def run_agent(cfg: Config, *, stop: asyncio.Event, on_ready=None) -> None:
    await Agent(cfg, stop).run(on_ready)
