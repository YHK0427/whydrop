"""Precision mode (spec §5.3): on when a reflector is configured and WHYDROP_SECRET is usable."""
from collections.abc import Mapping

from whydrop.proto.mac import SecretError, load_secret

DEFAULT_PORT = 48100


def precision_enabled(cfg, env: Mapping[str, str]) -> tuple[bool, str | None]:
    """(on, reason it is off). A bad secret turns precision mode off with a reason; basic mode keeps running."""
    if not cfg.reflector:
        return False, "no reflector configured"
    try:
        if load_secret(env, required=False) is None:
            return False, "WHYDROP_SECRET not set"
    except SecretError as e:
        return False, str(e)
    try:
        host, _ = reflector_addr(cfg)
    except ValueError:
        return False, "reflector must be host or host:port"
    if not host:
        return False, "reflector must be host or host:port"
    return True, None


def reflector_addr(cfg) -> tuple[str, int]:
    host, _, port = cfg.reflector.rpartition(":") if ":" in cfg.reflector else (cfg.reflector, "", "")
    return host, int(port) if port else DEFAULT_PORT
