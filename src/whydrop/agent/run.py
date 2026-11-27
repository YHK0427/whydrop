"""`whydrop agent`: startup order, probe schedule, persistence (spec §5.1, §5.2, §5.6), and in precision mode
the udp_stream and TCP canaries to the reflector (§5.3)."""
import asyncio
import json
import logging
import os
import secrets
import sys

from whydrop import __version__
from whydrop.agent import env as envmod
from whydrop.agent.clock import TimeBase, wait_time_sync
from whydrop.agent.config import Config
from whydrop.agent.events import Event
from whydrop.agent.housekeeping import housekeep
from whydrop.agent.precision import precision_enabled, reflector_addr
from whydrop.agent.precision.canary import HotCanary, IdleCanary
from whydrop.agent.precision.udp_stream import UdpStream
from whydrop.agent.probes import dns_probe, gateway, host_net, line_hb, link, tcp_connect, wifi
from whydrop.agent.probes.stun_probe import StunWatcher
from whydrop.agent.probes.targets import Targets, mask_pair, pair_id
from whydrop.agent.report import dns_interception, report_card
from whydrop.agent.results import Aggregator, Result
from whydrop.agent.scheduler import LagWatchdog, Scheduler
from whydrop.agent.selfcheck import CheckPair, FindingsTracker, nat_mapping, run_selfcheck
from whydrop.agent.store import Store
from whydrop.analysis.engine import Engine
from whydrop.analysis.model import Context, FrameBuilder
from whydrop.analysis.persist import Recorder
from whydrop.proto.mac import load_secret

log = logging.getLogger("whydrop.agent")

ROUTE_WAIT_S = 30
TIME_SYNC_WAIT_S = 60
SELFCHECK_TIMEOUT_S = 90
SELFCHECK_EVERY_S = 6 * 3600
RECHECK_EVERY_S = 600
NETWATCH_EVERY_S = 5
STORE_FLUSH_S = 5
BACKOFF_S = (30, 60, 120, 300)
DNS_CLASSES = ("dns_router", "dns_isp", "dns_public")
PRECISION_EVERY_S = 5
ANALYSIS_START_S = 30   # first frames wait until we know whether the gateway ever answers
STRIP_MS = 60_000       # packet strip kept ±60 s around incidents (spec §7)
DEGRADED_AFTER_S = 30      # both precision paths failing this long, with the line fine → "precision degraded"
LINE_FRESH_MS = 15_000
ECHO_FRESH_MS = 10_000


class VMRefused(RuntimeError):
    pass


def _mask(ip: str | None) -> str:
    return f"x.x.x.{ip.rsplit('.', 1)[-1]}" if ip else "-"


def _excluded_text(excluded: dict) -> str:
    return ", ".join(f"{mask_pair(k)} ({v})" for k, v in excluded.items()) or "none"


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
        self.agg: Aggregator | None = None
        self.findings: FindingsTracker | None = None
        self.wifi_tracker: wifi.WifiTracker | None = None
        self._bg: set[asyncio.Task] = set()
        self._sc_task: asyncio.Task | None = None
        self._sc_excluded: set[str] = set()   # exclusions the self-check owns (findings own the rest)
        self._rot = {"line_hb": 0, "tcp": 0, "dns_tcp": 0, "dns": 0, "link": 0}
        self._stun_key: tuple | None = None
        self._ll_key: tuple | None = None
        self.wifi_src = None
        self.link_tracker = None
        self.run_id: int | None = None
        self.precision = False
        self._gw_open = False  # the gateway answers only on an open port (costs more bytes, spec §10)
        self.stream: UdpStream | None = None
        self.hot: HotCanary | None = None
        self.idle: IdleCanary | None = None
        self._line_ok_ms: int | None = None
        self._pfail_since: int | None = None
        self._standing: set[str] = set()
        self._canaries: list[asyncio.Task] = []
        self._providers: dict[str, str] = {}
        self._nat_tcp_lower: int | None = None
        self._signal_dbm = None
        self._run_started_ms = None
        self._web = None
        self._web_task = None
        self._nat_task: asyncio.Task | None = None
        self.notifier = None
        self._nat_progress: dict | None = None
        self._gw_seen = False
        self.fb = FrameBuilder()
        self.engine: Engine | None = None
        from whydrop.web.bus import Bus   # stdlib only: the bus exists even without the web extra
        self.bus = Bus()
        self.recorder = Recorder(self.store, on_incident=self._strip, bus=self.bus)
        self._started = None
        self.store.listeners.append(lambda rows, events: (self.fb.add_rows(rows), self.fb.add_events(events)))
        self.store.listeners.append(self._publish_recorded)
        self.store.late_listeners.append(self.fb.add_late)

    # ---------- helpers ----------
    def now(self) -> int:
        return self.tb.now_ms()

    def spawn(self, coro, name: str = "task") -> asyncio.Task:
        t = asyncio.create_task(coro)
        self._bg.add(t)

        def done(task: asyncio.Task):
            self._bg.discard(task)
            if not task.cancelled() and task.exception():
                log.error("%s failed", name, exc_info=task.exception())
        t.add_done_callback(done)
        return t

    def late_cb(self, probe: str, pair: str, t_ms: int):
        return lambda: self.spawn(self.agg.late(probe, pair, t_ms), "late")

    async def record(self, items) -> None:
        events = []
        for x in items if isinstance(items, list) else [items]:
            if isinstance(x, Result):
                self.agg.add(x)
                self.findings.feed(x)
                if x.provider:
                    self._providers[x.pair] = x.provider
                if x.probe == "gateway" and x.ok:
                    self._gw_seen = True
                if x.probe == "wifi":
                    self._signal_dbm = x.detail.get("signal_dbm")
                if x.ok and x.probe in ("line_hb", "tcp_connect", "stun"):  # basic external probes
                    self._line_ok_ms = self.now()
            else:
                events.append(x)
        if events:
            await self.store.add_events(events)

    async def pause(self, seconds: float) -> bool:
        """Sleep that wakes up on stop; returns True if stopping."""
        try:
            await asyncio.wait_for(self.stop.wait(), seconds)
            return True
        except asyncio.TimeoutError:
            return False

    # ---------- self-check ----------
    def check_pairs(self) -> list[CheckPair]:
        t, now = self.targets, self.now
        pairs = []
        for cls in DNS_CLASSES:
            for addr, prov in t.dns_pairs(cls, include_excluded=True):
                pairs.append(CheckPair(pair_id(cls, addr, 53, "udp"), prov, cls, addr, "udp",
                                       lambda a=addr, c=cls, p=prov: dns_probe.udp(a, c, p, now)))
                if cls in ("dns_public", "dns_isp"):  # every class job_dns_tcp probes is checked over TCP too
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
        try:
            await asyncio.wait_for(self.targets.resolve(), 20)
        except asyncio.TimeoutError:
            log.warning("resolving STUN hostnames timed out")
        gw = self.env.gateway if self.env else None
        gw_probe = (lambda: gateway.probe(gw, self.cfg.gateway_port, self.now)) if gw else None
        try:
            sc = await asyncio.wait_for(run_selfcheck(self.check_pairs(), gw_probe), SELFCHECK_TIMEOUT_S)
        except asyncio.TimeoutError:
            log.warning("self-check timed out; nothing excluded")
            return "inconclusive"
        if sc.status == "ok":
            for k in self._sc_excluded - set(sc.excluded):
                self.targets.include(k)
            for k, why in sc.excluded.items():
                self.targets.exclude(k, why)
            self._sc_excluded = set(sc.excluded)
        stuns = [(self.targets.addr(s.addr), s.port) for s in self.targets.by_kind("stun")]
        nat = await nat_mapping(stuns) if stuns and all(s[0] for s in stuns) else None
        card = report_card(self.env, sc, nat, interception=await dns_interception())
        await self.store.insert("selfcheck", ts_ms=self.now(), result_json=json.dumps(card))
        log.info("self-check %s; excluded: %s", sc.status, _excluded_text(self.targets.excluded))
        return sc.status

    async def selfcheck_with_backoff(self, first_attempt: int = 0) -> None:
        """30 s → 5 min backoff, then every 5 min until a check can decide (spec §5.1)."""
        attempt = first_attempt
        while not self.stop.is_set():
            wait = 0 if attempt == 0 else BACKOFF_S[min(attempt - 1, len(BACKOFF_S) - 1)]
            if wait and await self.pause(wait):
                return
            if await self.selfcheck() == "ok":
                return
            attempt += 1

    def start_selfcheck(self, *, after_failed: bool = False) -> None:
        """Only one self-check loop at a time; a newer trigger replaces the running one. `after_failed` skips the
        immediate attempt when a check just came back inconclusive."""
        if self._sc_task and not self._sc_task.done():
            self._sc_task.cancel()
        self._sc_task = self.spawn(self.selfcheck_with_backoff(1 if after_failed else 0), "self-check")

    # ---------- probe jobs ----------
    async def job_gateway(self):
        if self.env and self.env.gateway:
            r = await gateway.probe(self.env.gateway, self.cfg.gateway_port, self.now)
            self._gw_open = r.ok and r.detail.get("method") == "tcp" and not r.detail.get("rst")
            await self.record(r)

    async def job_line_hb(self):
        tick = self._rot.setdefault("line_hb_tick", 0)
        self._rot["line_hb_tick"] += 1
        if self.precision and self._gw_open and tick % 2:
            return  # 0.5 Hz keeps precision mode under 20 kbps; udp_stream covers the line (spec §10)
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

    def dns_now(self) -> list[tuple[str, str, str | None]]:
        """Current (class, address, provider) pairs, read at every tick so net changes and re-checks apply."""
        out = []
        for cls in DNS_CLASSES:
            for addr, prov in self.targets.dns_pairs(cls):
                if pair_id(cls, addr, 53, "udp") not in self.targets.excluded and \
                        prov not in self.targets.excluded_providers:
                    out.append((cls, addr, prov))
        return out

    async def job_dns(self):
        """Every pair once per dns interval, staggered: each 1 s tick serves the pairs in its slot."""
        base = max(1, int(self.cfg.intervals["dns"]))
        tick = self._rot["dns"]
        self._rot["dns"] += 1
        mine = []
        for i, p in enumerate(self.dns_now()):
            every = max(base, 10) if self.precision and p[0] == "dns_public" else base  # public DNS ≥ 10 s in precision
            if (tick - i) % every == 0:
                mine.append(p)

        async def one(cls, addr, prov):
            t0 = self.now()
            await self.record(await dns_probe.udp(addr, cls, prov, self.now,
                                                  on_late=self.late_cb("dns", pair_id(cls, addr, 53, "udp"), t0)))
        await asyncio.gather(*(one(*p) for p in mine))

    async def job_dns_tcp(self):
        pairs = [(c, a, p) for c in ("dns_public", "dns_isp") for a, p in self.targets.dns_pairs(c)
                 if pair_id(c, a, 53, "tcp") not in self.targets.excluded and p not in self.targets.excluded_providers]
        if pairs:
            cls, addr, prov = pairs[self._rot["dns_tcp"] % len(pairs)]
            self._rot["dns_tcp"] += 1
            await self.record(await dns_probe.tcp(addr, cls, prov, self.now))

    async def job_router_cache(self):
        r = self.targets.router_dns
        if r and pair_id("dns_router", r, 53, "udp") not in self.targets.excluded:
            await self.record(await dns_probe.router_cache_check(r, self.now))

    def stun_servers(self) -> tuple:
        t = self.targets
        return tuple((s.addr, t.addr(s.addr), s.port, s.provider) for s in t.by_kind("stun")
                     if t.addr(s.addr) and s.provider not in t.excluded_providers
                     and pair_id("line_hb", s.addr, s.port, "udp") not in t.excluded)

    async def job_stun(self):
        servers = self.stun_servers()
        if servers != self._stun_key:  # new IPs, an exclusion, or a network change: fresh sockets
            old_ip = self.stun.public_ip if self.stun else None
            if self.stun:
                self.stun.close()
            self.stun = StunWatcher(list(servers), self.now, public_ip=old_ip) if servers else None
            self._stun_key = servers
        if self.stun:
            await self.record(await self.stun.probe())

    async def job_tcp(self):
        rot = self.targets.tcp_rotation()
        if rot:
            t = rot[self._rot["tcp"] % len(rot)]
            self._rot["tcp"] += 1
            await self.record(await tcp_connect.probe(t, self.now))

    async def job_host_net(self):
        await self.record(await host_net.probe(self.now))

    def link_layer(self) -> tuple | None:
        e = self.env
        if sys.platform == "win32":
            return ("wifi", None) if e and e.link == "wifi" else None  # no wired tracker on Windows
        if e and e.iface and e.link == "wifi":
            return ("wifi", e.iface)
        if e and e.iface and e.link == "wired":
            return ("link", e.iface)
        return None

    async def job_link_layer(self):
        """Wi-Fi or wired link, whichever the current interface is (re-read every tick, so starting
        before DHCP or switching networks still gets recorded)."""
        key = self.link_layer()
        if key is None and self.env and not self.env.iface:
            key = self._ll_key   # no route at all (e.g. Wi-Fi switched off): keep watching the same adapter
        if key != self._ll_key:
            self._ll_key = key
            self.wifi_src = self.link_tracker = None
            if key and key[0] == "wifi":
                self.wifi_src = wifi.WindowsWifi() if key[1] is None else wifi.LinuxWifi(key[1])
            elif key:
                self.link_tracker = link.LinkTracker(key[1], now_ms=self.now)
        tick = self._rot["link"]
        self._rot["link"] += 1
        if self.wifi_src is not None:
            every = int(self.cfg.intervals["wifi_windows" if sys.platform == "win32" else "wifi"])
            if tick % max(1, every):
                return
            snap = await self.wifi_src.snapshot()
            if snap is None:
                return
            events = self.wifi_tracker.update(snap)
            await self.record([wifi.to_result(snap, self.wifi_tracker, self.now()), *events])
        elif self.link_tracker is not None:
            r, events = self.link_tracker.probe()
            await self.record([x for x in (r, *events) if x is not None])

    async def job_tick(self):
        events = self.tb.check()
        if self.idle and any(e.kind == "suspend" for e in events):
            self.idle.notify_suspend()  # a ping missed while the host slept says nothing about the NAT
            self.hot.notify_suspend()
            self.stream.reopen()
        if events:
            await self.store.add_events(events)

    async def job_findings(self):
        events = self.findings.check()
        for e in events:
            key = e.pair or e.detail.get("provider")
            detail = json.dumps({"key": key})
            if e.detail.get("phase") == "start":
                await self.store.insert("findings", kind=e.detail["kind"], start_ms=e.ts_ms, detail_json=detail)
            else:
                await self.store.execute("UPDATE findings SET end_ms = ? WHERE agent_id = ? AND kind = ? "
                                         "AND end_ms IS NULL AND detail_json = ?",
                                         (e.ts_ms, self.store.agent_id, e.detail["kind"], detail))
        if events:
            await self.store.add_events(events)

    async def job_recheck(self):
        """Excluded pairs and providers get one fresh try every 10 minutes (spec §5.1)."""
        if self.targets.unresolved():
            try:
                await asyncio.wait_for(self.targets.resolve(), 20)
            except asyncio.TimeoutError:
                pass
        ex, ex_prov = self.targets.excluded, self.targets.excluded_providers
        for cp in self.check_pairs():
            if cp.pair not in ex and cp.provider not in ex_prov:
                continue
            try:
                r = await cp.run()
            except Exception:
                log.exception("re-check of %s failed", mask_pair(cp.pair))
                continue
            if r.ok:
                self.findings.feed(r)  # lets a finding end; failures here would only invent new ones
            if r.ok and cp.pair in self._sc_excluded:
                self._sc_excluded.discard(cp.pair)
                self.targets.include(cp.pair)
                log.info("%s answers again; back in decisions", mask_pair(cp.pair))
        await self.job_findings()

    async def vpn_finding(self) -> None:
        if self.env.egress_vpn:
            log.warning("probes leave via VPN: line results describe the tunnel")
            await self.store.insert("findings", kind="vpn_egress", start_ms=self.now(), detail_json="{}")
        else:
            await self.store.execute("UPDATE findings SET end_ms = ? WHERE agent_id = ? AND kind = 'vpn_egress' "
                                     "AND end_ms IS NULL", (self.now(), self.store.agent_id))

    async def job_netwatch(self):
        new = await envmod.detect_env(self.cfg)
        old = self.env
        if (new.gateway, new.iface, new.isp_dns, new.egress_vpn, new.egress_iface) == \
                (old.gateway, old.iface, old.isp_dns, old.egress_vpn, old.egress_iface):
            return
        self.env = new
        if self.engine is not None:  # every analysis component holds this same object
            self.engine.ctx.vpn, self.engine.ctx.link_kind = new.egress_vpn, new.link
            self.engine.ctx.isp_dns_known = bool(new.isp_dns)
        self.targets.router_dns = self.cfg.router_dns or new.gateway
        self.targets.isp_dns = new.isp_dns
        await self.store.add_events([Event("net_change", self.now(), detail={
            "gateway_changed": new.gateway != old.gateway, "iface": new.iface, "vpn": new.egress_vpn})])
        if new.egress_vpn != old.egress_vpn:
            await self.vpn_finding()
        self._stun_key = None
        if self.stream:
            self.stream.reopen()  # a connected UDP socket keeps the old source address
        log.info("network changed; re-running self-check")
        self.start_selfcheck()

    async def job_aggregate(self):
        await self.agg.flush_ready()

    async def job_store(self):
        await self.store.flush()

    async def job_heartbeat(self):
        await self.store.run_heartbeat(self.run_id, self.now())
        await self.save_analysis_meta()
        await self.store.meta_set("ap_labels", json.dumps(self.wifi_tracker.labels))

    async def save_analysis_meta(self):
        """What replay needs to rebuild the analysis context."""
        await self.store.meta_set("pair_providers", json.dumps(self._providers))
        await self.store.meta_set("excluded", json.dumps({"pairs": sorted(self.targets.excluded),
                                                        "providers": sorted(self.targets.excluded_providers)}))
        await self.store.meta_set("analysis_context", json.dumps({
            "lan_observable": self._gw_seen, "vpn": bool(self.env and self.env.egress_vpn),
            "link_kind": self.env.link if self.env else "unknown", "intervals": dict(self.cfg.intervals),
            "isp_dns_known": bool(self.env and self.env.isp_dns)}))

    # ---------- precision mode ----------
    def pevent(self, e: Event) -> None:
        self.store.add_events_nowait([e])  # sync: works during shutdown too

    async def start_precision(self) -> None:
        secret = load_secret(os.environ, required=True)
        addr = reflector_addr(self.cfg)
        self.stream = UdpStream(addr, secret, self.store, self.tb, pps=self.cfg.udp_stream_pps, on_event=self.pevent)
        await self.stream.start()
        sid = self.stream.session_id
        self.hot = HotCanary(addr, secret, self.pevent, session_id=sid, timebase=self.tb,
                             udp_rtt=self.stream.rtt_median_ms, on_result=lambda r: self.agg.add(r))
        self.idle = IdleCanary(addr, secret, self.pevent, session_id=sid, timebase=self.tb,
                               interval_s=self.cfg.canary_idle_interval_s)
        self._canaries = [self.spawn(self.hot.run(self.stop), "hot canary"),
                          self.spawn(self.idle.run(self.stop), "idle canary")]
        self.sched.every("precision", PRECISION_EVERY_S, self.job_precision, phase_s=PRECISION_EVERY_S * 0.9)

    async def job_precision(self):
        """Standing findings about the reflector path (spec §6.2 reflector_path); never incidents."""
        now = self.now()
        line_ok = self._line_ok_ms is not None and now - self._line_ok_ms < LINE_FRESH_MS
        stream_ok = self.stream.last_echo_ms is not None and now - self.stream.last_echo_ms < ECHO_FRESH_MS
        failing = line_ok and not stream_ok and self.hot.state not in ("ok", "auth_failed")  # auth: secret_mismatch
        self._pfail_since = (self._pfail_since or now) if failing else None
        await self.standing("precision_degraded", failing and now - self._pfail_since >= DEGRADED_AFTER_S * 1000)
        await self.standing("secret_mismatch", self.hot.state == "auth_failed")
        await self.standing("tcp_middlebox", self.hot.middlebox)

    async def standing(self, kind: str, on: bool) -> None:
        if on == (kind in self._standing):
            return
        if on:
            self._standing.add(kind)
            log.warning("finding: %s", kind)
            await self.store.insert("findings", kind=kind, start_ms=self.now(), detail_json="{}")
        else:
            self._standing.discard(kind)
            await self.store.execute("UPDATE findings SET end_ms = ? WHERE agent_id = ? AND kind = ? AND end_ms IS NULL",
                                     (self.now(), self.store.agent_id, kind))

    # ---------- analysis ----------
    def analysis_context(self) -> Context:
        return Context(provider_of=self._providers.get, excluded_pairs=self.targets.excluded,
                       excluded_providers=self.targets.excluded_providers,
                       mode="precision" if self.precision else "basic", lan_observable=self._gw_seen,
                       vpn=bool(self.env and self.env.egress_vpn), link_kind=self.env.link if self.env else "unknown",
                       intervals=dict(self.cfg.intervals), isp_dns_known=bool(self.env and self.env.isp_dns),
                       nat_tcp_timeout_s=self._nat_tcp_lower)

    async def job_analysis(self):
        if self.engine is None:
            self._started = self._started or self.now()
            if self.now() - self._started < ANALYSIS_START_S * 1000:
                return
            try:
                await self.recorder.close_previous_run(self.run_id)
                self._nat_tcp_lower = await self.recorder.nat_tcp_lower()
                self.engine = Engine(self.analysis_context())
            except Exception:
                log.exception("analysis could not start; retrying")
                self.fb.ready(self.now())  # drop what it can't use yet, so memory stays bounded
                return
        for frame in self.fb.ready(self.now()):
            try:
                await self.recorder.write(self.engine.step(frame))
            except Exception:
                log.exception("analysis step failed at %s", frame.t_ms)  # the next frames still run

    def _strip(self, op: str, inc) -> None:
        """Keep the per-packet strip around incidents (the in-memory ring holds 120 s)."""
        if self.stream is None or op not in ("open", "close"):
            return
        at = inc.start_ms if op == "open" else inc.end_ms
        rows = self.stream.book.ring_window(at - STRIP_MS, at + STRIP_MS)
        if rows:
            self.spawn(self.store.executemany(
                "INSERT OR IGNORE INTO udp_seq_ring (agent_id, ts_ms, seq, echoed, dir) VALUES (?, ?, ?, ?, ?)",
                [(self.store.agent_id, t, q, int(e), d) for t, q, e, d in rows if q >= 0]), "packet strip")

    # ---------- alerts ----------
    async def start_notify(self) -> None:
        from whydrop.agent.notify import Notifier
        self.notifier = Notifier(dict(self.cfg.notify), self.now, name=self.cfg.agent_name,
                                 on_queue=lambda q: self.spawn(self.store.meta_set("notify_queue", json.dumps(q)),
                                                               "alert queue"))
        if not (self.notifier.enabled or self.notifier.kuma):
            return
        self.notifier.queue = json.loads(await self.store.meta_get("notify_queue") or "[]")  # survives restarts
        if self.notifier.enabled:
            self.spawn(self.notifier.run(self.bus, self.stop), "alerts")
        if self.notifier.kuma:
            self.sched.every("kuma", 60.0, self.notifier.kuma_push, phase_s=5)

    # ---------- dashboard ----------
    def _publish_recorded(self, rows, events) -> None:
        # samples are not pushed one by one (≈ 11/s per browser for nothing): the charts re-fetch /api/chart
        for e in events:
            if e.kind != "tcp_info":
                self.bus.publish("event", {"row": {"ts_ms": e.ts_ms, "kind": e.kind, "pair": e.pair,
                                                     "detail_json": json.dumps(e.detail)}})

    def status(self) -> dict:
        from whydrop.agent import traffic
        return {"version": __version__, "mode": self.tags.get("mode"), "agent": self.cfg.agent_name,
                "reflector": None if not self.precision else {"hot": self.hot.state if self.hot else None,
                                                              "stream_ok": bool(self.stream and self.stream.last_echo_ms)},
                "bytes": dict(traffic.BYTES), "baseline": self.engine.cond.baseline_state(self.now()) if self.engine else "none",
                "now_ms": self.now(), "segments": self._segment_states(), "signal_dbm": self._signal_dbm,
                "link": self.env.link if self.env else "unknown", "vpn": bool(self.env and self.env.egress_vpn),
                "since_ms": self._run_started_ms, "analysis_lag_s": 14}

    def _segment_states(self) -> dict:
        """What the path diagram shows: ok / down / unknown / unobservable / checking per hop."""
        if self.engine is None:
            return {s: "checking" for s in ("host_net", "wifi", "link", "lan", "line", "dns")}
        seg = self.engine.seg
        out = {s: seg.state(s) for s in ("host_net", "wifi", "link", "lan", "line")}
        dns = [seg.state(c) for c in ("dns_router", "dns_isp", "dns_public")]
        out["dns"] = "down" if "down" in dns else "up" if "up" in dns else "unknown"
        return out

    def web_nat_run(self) -> bool:
        """POST /api/nat/run: False while one is already running (→ 409)."""
        if self._nat_task is not None and not self._nat_task.done():
            return False
        self._nat_task = self.spawn(self._run_nat(), "nat-test")
        return True

    async def _run_nat(self) -> None:
        from whydrop.agent.precision import natprobe
        secret, start = load_secret(os.environ, required=True), self.now()
        tcp = natprobe.TCP_DELAYS + ((7500,) if self.cfg.nat_enable_7500 else ())   # the reflector must allow it too
        self._nat_progress = {"done": 0, "total": len(natprobe.UDP_DELAYS) + len(tcp), "last": None}

        def progress(r):
            self._nat_progress["done"] += 1
            self._nat_progress["last"] = {"proto": r.proto, "delay_s": r.delay_s, "alive": r.alive}
        try:
            rep = await natprobe.nat_test(reflector_addr(self.cfg), secret, tcp_delays=tcp, on_progress=progress)
            await natprobe.store_report(self.store, rep, start_ms=start, end_ms=self.now())
            self._nat_tcp_lower = rep.tcp_range[0]
            if self.engine is not None:
                self.engine.ctx.nat_tcp_timeout_s = rep.tcp_range[0]
        finally:
            self._nat_progress = None

    async def start_web(self) -> None:
        try:
            import contextlib
            import importlib

            # FastAPI takes ~1.5 s to import: do it off the event loop so probes never wait for the dashboard
            await asyncio.to_thread(importlib.import_module, "whydrop.web.app")
            import uvicorn

            from whydrop.web.app import create_app
            from whydrop.web.guard import LOOPBACK, allowed_hosts, resolve_token
        except ImportError:
            log.info("dashboard off: install whydrop[web] to get it")
            return
        host, _, port = self.cfg.web.bind.rpartition(":")
        host = host.strip("[]") or "127.0.0.1"
        generated = host not in LOOPBACK and not os.environ.get("WHYDROP_UI_TOKEN") \
            and not (self.cfg.db_path.parent / "ui-token").exists()
        try:
            token = resolve_token(host, os.environ, self.cfg.db_path.parent)
        except ValueError as e:
            log.error("dashboard off: %s", e)
            return
        app = create_app(self.cfg.db_path, self.bus, token=token, allowed_hosts=allowed_hosts(host, list(self.cfg.web.allowed_hosts) + [
                             h.strip() for h in os.environ.get("WHYDROP_WEB_ALLOWED_HOSTS", "").split(",") if h.strip()]),
                         public_default=self.cfg.web.public_view_default, status=self.status,
                         nat_run=self.web_nat_run if self.precision else None, nat_state=lambda: self._nat_progress,
                         packets=lambda: list(self.stream.packets) if self.stream else [])
        import socket as _socket
        try:  # bind ourselves: uvicorn's own bind failure calls sys.exit, which would take the agent down
            fam = _socket.AF_INET6 if ":" in host else _socket.AF_INET
            sock = _socket.socket(fam, _socket.SOCK_STREAM)
            if sys.platform != "win32":
                sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            sock.bind((host, int(port)))
        except (OSError, ValueError) as e:
            log.error("dashboard off: can't listen on %s:%s (%s); recording continues", host, port,
                      getattr(e, "strerror", None) or e)
            return
        from uvicorn.config import WS_PROTOCOLS
        ws = "websockets-sansio" if "websockets-sansio" in WS_PROTOCOLS else "auto"   # older uvicorn (the floor is 0.32) lacks it
        server = uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False, lifespan="off",
                                               ws=ws, timeout_graceful_shutdown=3))
        server.capture_signals = contextlib.nullcontext   # the agent owns SIGINT/SIGTERM
        self._web = server

        async def serve():
            try:
                await server.serve(sockets=[sock])
            except SystemExit:
                log.error("dashboard stopped unexpectedly; recording continues")
            finally:
                sock.close()
        self._web_task = self.spawn(serve(), "dashboard")
        if host in LOOPBACK:
            log.info("dashboard: http://%s:%s/", host, port)
        else:
            from whydrop.agent.probes import host_net
            where = host_net.source_address() or ("<this machine's address>" if host in ("0.0.0.0", "::") else host)
            if generated:  # the Jupyter way: shown once, when it is made (it is kept in the data volume)
                log.warning("dashboard: http://%s:%s/?token=%s", where, port, token)
            else:
                log.info("dashboard: http://%s:%s/?token=<your token> (WHYDROP_UI_TOKEN or ui-token in the data dir)",
                         where, port)

    # ---------- main ----------
    async def wait_route(self) -> bool:
        for _ in range(ROUTE_WAIT_S):
            _, iface = await host_net.default_route()
            if iface is not None:
                return True
            if await self.pause(1):
                return False
        return False

    def schedule(self) -> None:
        iv, s = self.cfg.intervals, self.sched
        s.every("tick", 1.0, self.job_tick)
        s.every("host_net", iv["host_net"], self.job_host_net)
        s.every("gateway", iv["gateway"], self.job_gateway, phase_s=0.1, max_inflight=3)
        s.every("line_hb", iv["line_hb"], self.job_line_hb, phase_s=0.5, max_inflight=3)
        s.every("dns", 1.0, self.job_dns, phase_s=0.3, max_inflight=3)
        s.every("dns_tcp", iv["dns_tcp"], self.job_dns_tcp, phase_s=2.5)
        s.every("dns_cache", 60.0, self.job_router_cache, phase_s=17)
        s.every("stun", iv["stun"], self.job_stun, phase_s=3.3)
        s.every("tcp_connect", iv["tcp_connect"], self.job_tcp, phase_s=1.3, max_inflight=2)
        s.every("link_layer", 1.0, self.job_link_layer, phase_s=0.7)
        s.every("aggregate", 1.0, self.job_aggregate, phase_s=0.9)
        s.every("store", STORE_FLUSH_S, self.job_store, phase_s=2.0)
        s.every("findings", 5.0, self.job_findings, phase_s=4.1)
        s.every("recheck", RECHECK_EVERY_S, self.job_recheck, phase_s=RECHECK_EVERY_S)
        s.every("netwatch", NETWATCH_EVERY_S, self.job_netwatch, phase_s=NETWATCH_EVERY_S)
        s.every("selfcheck", SELFCHECK_EVERY_S, self._periodic_selfcheck, phase_s=SELFCHECK_EVERY_S)
        s.every("heartbeat", 30.0, self.job_heartbeat, phase_s=30)
        s.every("analysis", 1.0, self.job_analysis, phase_s=0.95)
        s.every("housekeeping", 600.0, lambda: housekeep(self.store, self.now(),
                                                         min_free_mb=self.cfg.storage_min_free_mb), phase_s=60)

    async def _periodic_selfcheck(self):
        self.start_selfcheck()

    async def run(self, on_ready=None) -> None:
        msg = envmod.vm_refusal(envmod.kernel_release(), None)
        if msg:
            raise VMRefused(msg)
        if not await wait_time_sync(TIME_SYNC_WAIT_S):
            self.tags["clock"] = "unsynced"
        self.tags["route_at_start"] = await self.wait_route()
        self.tb.rebase()  # time sync may have stepped the clock while we waited: anchor before stamping anything
        await self.store.open()
        try:
            await self._run_opened(on_ready)
        finally:
            await self._shutdown()

    async def _run_opened(self, on_ready) -> None:
        salt = await self.store.meta_get("salt")
        if salt is None:
            salt = secrets.token_hex(16)
            await self.store.meta_set("salt", salt)
        labels = json.loads(await self.store.meta_get("ap_labels") or "{}")
        self.env = await envmod.detect_env(self.cfg)
        msg = envmod.vm_refusal(envmod.kernel_release(), self.env.gateway)
        if msg:
            raise VMRefused(msg)
        self.targets.router_dns = self.cfg.router_dns or self.env.gateway
        self.targets.isp_dns = self.env.isp_dns
        self.agg = Aggregator(self.store, self.now)
        self.findings = FindingsTracker(self.targets, self.now)
        self.wifi_tracker = wifi.WifiTracker(bytes.fromhex(salt), self.now, labels)
        self.precision, why_not = precision_enabled(self.cfg, os.environ)
        self.tags["mode"] = "precision" if self.precision else "basic"
        if why_not and self.cfg.reflector:
            log.warning("precision mode off: %s", why_not)
        self._run_started_ms = self.now()
        self.run_id = await self.store.run_start(self.now(), __version__, self.tags)
        await self.vpn_finding()
        # one bounded pass inline; if it can't decide (e.g. started mid-outage), keep retrying in the background
        # while the probes already record
        if not self.tags["route_at_start"]:
            self.start_selfcheck()
        elif await self.selfcheck() != "ok":
            self.start_selfcheck(after_failed=True)
        self.schedule()
        self.spawn(self.start_web(), "dashboard start")
        await self.start_notify()
        if self.precision:
            await self.start_precision()
        watchdog = LagWatchdog(lambda e: self.spawn(self.store.add_events([e]), "lag event"), now_ms=self.now,
                               on_sample=lambda lag: self.agg.add(Result("loop", "loop", None, self.now(), True,
                                                                        lag * 1000)))
        self.tb.rebase()  # the self-check above took seconds; that is not a suspend
        log.info("watching: mode=" + self.tags["mode"] + " link=%s gateway=%s isp_dns=%s excluded=%s", self.env.link,
                 _mask(self.env.gateway), ",".join(_mask(a) for a in self.env.isp_dns) or "unknown",
                 _excluded_text(self.targets.excluded))
        if on_ready:
            on_ready(self)
        await asyncio.gather(self.sched.run(self.stop), watchdog.run(self.stop))

    async def _shutdown(self) -> None:
        if self._web is not None:
            self._web.should_exit = True
            if self._web_task is not None:
                await asyncio.gather(self._web_task, return_exceptions=True)
        for t in self._canaries:  # first, so their last events (stall end) land before the store closes
            t.cancel()
        await asyncio.gather(*self._canaries, return_exceptions=True)
        for t in list(self._bg):
            t.cancel()
        await asyncio.gather(*self._bg, return_exceptions=True)
        steps = []
        if self.stream:
            steps.append(lambda: self.stream.stop(flush=True))
        for kind in list(self._standing):
            steps.append(lambda kind=kind: self.standing(kind, False))
        if self.wifi_tracker:
            steps.append(lambda: self.store.meta_set("ap_labels", json.dumps(self.wifi_tracker.labels)))
        if self.agg:
            steps.append(lambda: self.agg.flush_ready(force=True))
        if self.notifier is not None and (self.notifier.queue or self.notifier.enabled):
            steps.append(lambda: self.store.meta_set("notify_queue", json.dumps(self.notifier.queue)))
        if self.run_id is not None:
            steps.append(self.save_analysis_meta)
            steps.append(lambda: self.store.run_stop(self.run_id, self.now()))
        for step in steps:  # each on its own, so one failure can't skip closing the store
            try:
                await step()
            except Exception:
                log.exception("shutdown step failed")
        if self.stun:
            self.stun.close()
        await self.store.close()


async def run_agent(cfg: Config, *, stop: asyncio.Event, on_ready=None) -> None:
    await Agent(cfg, stop).run(on_ready)
