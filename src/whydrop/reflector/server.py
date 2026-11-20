"""`whydrop reflector`: UDP + TCP on one port, tombstone persistence and drop-reason logs (spec §5.4)."""
import asyncio
import logging
import secrets
from collections.abc import Callable, Mapping
from pathlib import Path

from whydrop import __version__
from whydrop.proto.mac import load_secret
from whydrop.reflector.replay import Tombstones
from whydrop.reflector.tcp import TcpReflector, serve_tcp
from whydrop.reflector.udp import UdpReflector, serve_udp

log = logging.getLogger("whydrop.reflector")

FLUSH_EVERY_S = 10
STATS_EVERY_S = 60


async def _flush(tomb: Tombstones) -> None:
    try:
        await asyncio.to_thread(tomb.write, tomb.snapshot())
    except OSError as e:  # e.g. disk full: keep serving, replay protection degrades to in-memory
        log.warning("could not write tombstones: %s", e)


def _log_drops(udp: UdpReflector, tcp: TcpReflector) -> None:
    for name, counter in (("udp", udp.drops), ("tcp", tcp.drops)):
        if counter:
            log.info("drops %s %s", name, " ".join(f"{k}={v}" for k, v in sorted(counter.items())))
            counter.clear()


async def run_reflector(*, host: str, port: int, state_dir: Path, enable_7500: bool, env: Mapping[str, str],
                        stop: asyncio.Event, on_ready: Callable[[int, int], None] | None = None) -> None:
    secret = load_secret(env, required=True)
    epoch = secrets.randbits(32)
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    tomb = Tombstones(state_dir / "tombstones.json")
    tomb.load()
    udp_r = UdpReflector(secret, epoch=epoch, tombstones=tomb)
    tcp_r = TcpReflector(secret, epoch=epoch, enable_7500=enable_7500)
    udp = await serve_udp(udp_r, host, port)
    tcp = await serve_tcp(tcp_r, host, port)
    tcp_port = tcp.sockets[0].getsockname()[1]
    log.info("whydrop reflector %s listening udp :%d tcp :%d epoch=%08x", __version__, udp.port, tcp_port, epoch)
    if on_ready:
        on_ready(udp.port, tcp_port)

    async def periodic():
        ticks = 0
        while True:
            await asyncio.sleep(FLUSH_EVERY_S)
            ticks += 1
            await _flush(tomb)
            if ticks % (STATS_EVERY_S // FLUSH_EVERY_S) == 0:
                _log_drops(udp_r, tcp_r)

    task = asyncio.create_task(periodic())
    try:
        await stop.wait()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        tcp.close()
        await udp.close()
        await _flush(tomb)
        _log_drops(udp_r, tcp_r)
        log.info("whydrop reflector stopped")
