"""Scenario DSL: synthetic 1 s frames for analysis tests (spec §11.1 scenarios are written with it)."""
from dataclasses import dataclass, field

from whydrop.agent.events import Event
from whydrop.agent.store import SampleRow
from whydrop.analysis.model import Context, Frame

T0 = 1_800_000_000_000  # a round epoch ms


@dataclass
class Stream:
    probe: str
    pair: str
    provider: str | None
    every_s: int = 1
    per_send: int = 1        # sends per active second (udp_stream: 10)
    rtt: float = 20.0
    phase_s: int = 0


@dataclass
class Scenario:
    seconds: int = 120
    mode: str = "basic"
    link_kind: str = "wifi"
    streams: list[Stream] = field(default_factory=list)
    _fails: list = field(default_factory=list)       # (match, from_s, to_s, kind, frac)
    _events: list = field(default_factory=list)
    _lag: list = field(default_factory=list)
    _sleep: list = field(default_factory=list)
    _rtt: list = field(default_factory=list)

    @classmethod
    def default(cls, seconds=120, mode="basic", link_kind="wifi"):
        s = cls(seconds, mode, link_kind)
        s.add("gateway", "gateway", None)
        s.add("host_net", "host_net", None)
        s.add("wifi" if link_kind == "wifi" else "link", "wifi" if link_kind == "wifi" else "link", None)
        for i, prov in enumerate(("cloudflare", "google", "quad9")):
            s.add("line_hb", f"line_hb:{prov}:3478/udp", prov, every_s=3, phase_s=i)
        s.add("stun", "stun:cloudflare:3478/udp", "cloudflare", every_s=5)
        s.add("stun", "stun:google:19302/udp", "google", every_s=5, phase_s=2)
        s.add("dns", "dns_router:192.0.2.1:53/udp", None, every_s=5)
        s.add("dns", "dns_isp:198.51.100.53:53/udp", None, every_s=5, phase_s=1)
        s.add("dns", "dns_public:1.1.1.1:53/udp", "cloudflare", every_s=10 if mode == "precision" else 5, phase_s=2)
        s.add("dns", "dns_public:8.8.8.8:53/udp", "google", every_s=10 if mode == "precision" else 5, phase_s=3)
        s.add("tcp_connect", "tcp:1.1.1.1:443/tcp", "cloudflare", every_s=5, phase_s=4)
        s.add("tcp_connect", "tcp:8.8.8.8:443/tcp", "google", every_s=5, phase_s=1)
        if mode == "precision":
            s.add("udp_stream", "reflector", None, per_send=10)
            s.add("canary", "reflector", None)
        return s

    def add(self, probe, pair, provider, **kw) -> "Scenario":
        self.streams.append(Stream(probe, pair, provider, **kw))
        return self

    def fail(self, from_s, to_s, *, probes=None, pairs=None, providers=None, frac=1.0, kind="lost") -> "Scenario":
        """Sends in [from_s, to_s) fail (kind lost/late/local_fail); `frac` < 1 fails that share, spread evenly."""
        self._fails.append(((probes, pairs, providers), from_s, to_s, kind, frac))
        return self

    def internet_down(self, from_s, to_s, **kw) -> "Scenario":
        """Everything past the router fails (line + public DNS + reflector); router/ISP DNS keep answering from cache."""
        return self.fail(from_s, to_s, probes={"line_hb", "stun", "tcp_connect", "udp_stream", "canary"}, **kw) \
                   .fail(from_s, to_s, pairs={p.pair for p in self.streams if p.pair.startswith("dns_public")}, **kw)

    def slow(self, from_s, to_s, *, probes=None, rtt) -> "Scenario":
        self._rtt.append((probes, from_s, to_s, rtt))
        return self

    def event(self, kind, at_s, pair=None, **detail) -> "Scenario":
        self._events.append(Event(kind, T0 + int(at_s * 1000), pair, detail))
        return self

    def lag(self, from_s, to_s) -> "Scenario":
        self._lag.append((from_s, to_s))
        return self

    def suspend(self, from_s, to_s) -> "Scenario":
        self._sleep.append((from_s, to_s))
        return self

    def ctx(self, **kw) -> Context:
        prov = {s.pair: s.provider for s in self.streams}
        base = dict(provider_of=prov.get, mode=self.mode, link_kind=self.link_kind, intervals={"dns": 5})
        base.update(kw)
        return Context(**base)

    def _failing(self, st: Stream, sec: int):
        for (probes, pairs, providers), a, b, kind, frac in self._fails:
            if a <= sec < b and (probes is None or st.probe in probes) and (pairs is None or st.pair in pairs) \
                    and (providers is None or st.provider in providers):
                return kind, frac
        return None

    def frames(self) -> list[Frame]:
        out = []
        for sec in range(self.seconds):
            t = T0 + sec * 1000
            f = Frame(t, lag=any(a <= sec < b for a, b in self._lag),
                      suspended=any(a <= sec < b + 30 for a, b in self._sleep))
            if any(a <= sec < b for a, b in self._sleep):
                f.events = [e for e in self._events if t <= e.ts_ms < t + 1000]
                out.append(f)
                continue
            for st in self.streams:
                if (sec - st.phase_s) % st.every_s:
                    continue
                n = st.per_send
                ok, lost, late, local = n, 0, 0, 0
                hit = self._failing(st, sec)
                if hit:
                    kind, frac = hit
                    bad = round(n * frac) if n > 1 else int((sec * 7919 + sum(st.pair.encode()) % 97) % 100 < frac * 100)
                    ok -= bad
                    lost, late, local = (bad, 0, 0) if kind == "lost" else (0, bad, 0) if kind == "late" else (0, 0, bad)
                rtt = next((r for probes, a, b, r in self._rtt if a <= sec < b and (probes is None or st.probe in probes)),
                           st.rtt)
                f.samples[(st.probe, st.pair)] = SampleRow(
                    t, st.probe, st.pair, sent=n, ok=ok, lost=lost, late=late, local_fail=local,
                    lost_dir_unknown=lost, rtt_min=rtt if ok else None, rtt_avg=rtt if ok else None,
                    rtt_max=rtt if ok else None, rtt_p95=rtt if ok else None)
            f.events = [e for e in self._events if t <= e.ts_ms < t + 1000]
            out.append(f)
        return out
