"""Agent configuration: WHYDROP_* env > TOML file > defaults (spec §9). Unknown keys fail fast."""
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    addr: str
    port: int
    proto: Literal["udp", "tcp"]
    kind: Literal["dns", "stun", "tcp443"]
    provider: str


@dataclass(frozen=True)
class WebConfig:
    bind: str = "127.0.0.1:8790"
    allowed_hosts: tuple[str, ...] = ()
    public_view_default: bool = False


DEFAULT_TARGETS = (
    Target("1.0.0.1", 53, "udp", "dns", "cloudflare"),
    Target("8.8.8.8", 53, "udp", "dns", "google"),
    Target("208.67.222.222", 53, "udp", "dns", "opendns"),
    Target("9.9.9.9", 53, "udp", "dns", "quad9"),
    Target("1.1.1.1", 53, "udp", "dns", "cloudflare"),
    Target("stun.cloudflare.com", 3478, "udp", "stun", "cloudflare"),
    Target("stun.l.google.com", 19302, "udp", "stun", "google"),
    Target("8.8.8.8", 443, "tcp", "tcp443", "google"),
    Target("1.0.0.1", 443, "tcp", "tcp443", "cloudflare"),
    Target("208.67.222.222", 443, "tcp", "tcp443", "opendns"),
)

DEFAULT_INTERVALS = {"wifi": 1.0, "wifi_windows": 2.0, "link": 1.0, "gateway": 1.0, "line_hb": 1.0, "dns": 5.0,
                     "dns_tcp": 5.0, "stun": 10.0, "tcp_connect": 2.0, "host_net": 1.0}


@dataclass(frozen=True)
class Config:
    agent_name: str = "home"
    reflector: str | None = None
    db_path: Path = Path("./whydrop-data/whydrop.db")
    web: WebConfig = WebConfig()
    gateway: str | None = None
    gateway_port: int | None = None
    router_dns: str | None = None
    isp_dns: tuple[str, ...] = ()
    wifi_interface: str | None = None
    targets: tuple[Target, ...] = DEFAULT_TARGETS
    intervals: Mapping[str, float] = field(default_factory=lambda: dict(DEFAULT_INTERVALS))
    udp_stream_pps: int = 10
    canary_idle_interval_s: int = 600
    nat_enable_7500: bool = False
    notify: Mapping[str, str] = field(default_factory=dict)
    storage_min_free_mb: int | None = None


_TOP = {"agent_name", "reflector", "db_path", "gateway", "gateway_port", "router_dns", "isp_dns", "wifi_interface",
        "targets", "intervals", "web", "canary", "udp_stream", "nat", "notify", "storage"}
_NESTED = {"web": {"bind", "allowed_hosts", "public_view_default"}, "canary": {"idle_interval_s"},
           "intervals": set(DEFAULT_INTERVALS),
           "udp_stream": {"pps"}, "nat": {"enable_7500"}, "notify": {"webhook_url", "format", "kuma_push_url"},
           "storage": {"min_free_mb"}}
_ENV = {"WHYDROP_AGENT_NAME": "agent_name", "WHYDROP_REFLECTOR": "reflector", "WHYDROP_DB_PATH": "db_path"}


def _check_keys(raw: dict) -> None:
    for k, v in raw.items():
        if k not in _TOP:
            raise ConfigError(f"unknown config key: {k}")
        if k in _NESTED:
            if not isinstance(v, dict):
                raise ConfigError(f"[{k}] must be a table")
            for sub in v:
                if sub not in _NESTED[k]:
                    raise ConfigError(f"unknown config key: {k}.{sub}")


def _targets(items: list) -> tuple[Target, ...]:
    if not isinstance(items, list):
        raise ConfigError("targets must be an array of tables")
    out = []
    for i, t in enumerate(items):
        if not isinstance(t, dict) or set(t) - {"addr", "port", "proto", "kind", "provider"}:
            raise ConfigError(f"targets[{i}]: only addr, port, proto, kind, provider are allowed")
        try:
            out.append(Target(t["addr"], int(t["port"]), t.get("proto", "udp"), t["kind"], t["provider"]))
        except (KeyError, TypeError, ValueError) as e:
            raise ConfigError(f"targets[{i}] needs addr, port, kind, provider ({e})") from None
        if out[-1].kind not in ("dns", "stun", "tcp443") or out[-1].proto not in ("udp", "tcp"):
            raise ConfigError(f"targets[{i}]: bad kind or proto")
    return tuple(out)


def load_config(path: Path | None, env: Mapping[str, str]) -> Config:
    raw: dict = {}
    if path is not None:
        try:
            raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            raise ConfigError(f"cannot read config {path}: {e}") from None
    _check_keys(raw)
    try:
        c = _build(raw, env)
    except ConfigError:
        raise
    except (TypeError, ValueError) as e:
        raise ConfigError(f"bad config value: {e}") from None
    if not 30 <= c.canary_idle_interval_s <= 7500:
        raise ConfigError("canary.idle_interval_s must be 30–7500")
    if c.udp_stream_pps <= 0 or any(v <= 0 for v in c.intervals.values()):
        raise ConfigError("intervals and udp_stream.pps must be > 0")
    return c


def _str_list(v, key: str) -> tuple[str, ...]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f"{key} must be a list of strings")
    return tuple(v)


def _bool(v, key: str) -> bool:
    if not isinstance(v, bool):
        raise ConfigError(f"{key} must be true or false")
    return v


def _build(raw: dict, env: Mapping[str, str]) -> Config:
    c = Config()
    flat = {k: raw[k] for k in ("agent_name", "reflector", "gateway", "gateway_port", "router_dns", "wifi_interface")
            if k in raw}
    if "db_path" in raw:
        flat["db_path"] = Path(raw["db_path"])
    if "isp_dns" in raw:
        flat["isp_dns"] = _str_list(raw["isp_dns"], "isp_dns")
    if "targets" in raw:
        flat["targets"] = _targets(raw["targets"])
    if "intervals" in raw:
        flat["intervals"] = {**DEFAULT_INTERVALS, **{k: float(v) for k, v in raw["intervals"].items()}}
    w = raw.get("web", {})
    if w:
        flat["web"] = WebConfig(str(w.get("bind", c.web.bind)),
                                _str_list(w.get("allowed_hosts", []), "web.allowed_hosts"),
                                _bool(w.get("public_view_default", False), "web.public_view_default"))
    for table, key, attr, conv in (("canary", "idle_interval_s", "canary_idle_interval_s", int),
                                   ("udp_stream", "pps", "udp_stream_pps", int),
                                   ("nat", "enable_7500", "nat_enable_7500", lambda v: _bool(v, "nat.enable_7500")),
                                   ("storage", "min_free_mb", "storage_min_free_mb", int)):
        if key in raw.get(table, {}):
            flat[attr] = conv(raw[table][key])
    if raw.get("notify"):
        flat["notify"] = dict(raw["notify"])
    for var, key in _ENV.items():
        if env.get(var):
            flat[key] = Path(env[var]) if key == "db_path" else env[var]
    if env.get("WHYDROP_WEB_BIND"):
        flat["web"] = replace(flat.get("web", c.web), bind=env["WHYDROP_WEB_BIND"])
    return replace(c, **flat)
