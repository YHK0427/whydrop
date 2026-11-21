import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

from whydrop import __version__


def _reflector(args: argparse.Namespace) -> int:
    from whydrop.proto.mac import SecretError
    from whydrop.reflector.server import run_reflector

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    async def run():
        stop = asyncio.Event()
        if sys.platform != "win32":  # Windows: Ctrl-C arrives as KeyboardInterrupt instead
            for sig in (signal.SIGINT, signal.SIGTERM):
                asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        await run_reflector(host=args.host, port=args.port, state_dir=args.state_dir, enable_7500=args.enable_7500,
                            env=os.environ, stop=stop)

    try:
        asyncio.run(run())
    except SecretError as e:
        print(f"whydrop: {e}", file=sys.stderr)
        return 2
    except OSError as e:  # e.g. the port is already in use
        print(f"whydrop: reflector failed to start ({args.host}:{args.port}, state {args.state_dir}): {e.strerror or e}",
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass
    return 0


def _agent(args: argparse.Namespace) -> int:
    from whydrop.agent.config import ConfigError, load_config
    from whydrop.agent.run import VMRefused, run_agent

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    path = args.config or (Path("whydrop.toml") if Path("whydrop.toml").exists() else None)
    try:
        cfg = load_config(path, os.environ)
    except ConfigError as e:
        print(f"whydrop: {e}", file=sys.stderr)
        return 2

    async def run():
        stop = asyncio.Event()
        if sys.platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        await run_agent(cfg, stop=stop)

    try:
        asyncio.run(run())
    except VMRefused as e:
        print(f"whydrop: {e}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        pass
    return 0


def _nat_test(args: argparse.Namespace) -> int:
    import time

    from whydrop.agent.config import ConfigError, load_config
    from whydrop.agent.precision import natprobe, reflector_addr
    from whydrop.proto.mac import SecretError, load_secret

    path = args.config or (Path("whydrop.toml") if Path("whydrop.toml").exists() else None)
    try:
        cfg = load_config(path, os.environ)
        secret = load_secret(os.environ, required=True)
    except (ConfigError, SecretError) as e:
        print(f"whydrop: {e}", file=sys.stderr)
        return 2
    if not cfg.reflector:
        print("whydrop: nat-test needs a reflector (WHYDROP_REFLECTOR or reflector = in the config)", file=sys.stderr)
        return 2
    udp = () if args.tcp_only else tuple(d for d in natprobe.UDP_DELAYS if d <= args.max_delay)
    tcp_all = natprobe.TCP_DELAYS + ((7500,) if args.enable_7500 else ())
    tcp = () if args.udp_only else tuple(d for d in tcp_all if d <= args.max_delay)
    longest = max(udp + tcp, default=0)
    print(f"whydrop nat-test: {len(udp)} UDP + {len(tcp)} TCP delays in parallel, about {longest // 60 + 1} min")

    def progress(r):
        state = {True: "alive", False: "forgotten", None: "inconclusive"}[r.alive]
        print(f"  {r.proto} {r.delay_s:>5} s  {state}", flush=True)

    start_ms = int(time.time() * 1000)
    try:
        rep = asyncio.run(natprobe.nat_test(reflector_addr(cfg), secret, udp_delays=udp, tcp_delays=tcp,
                                            on_progress=progress))
    except KeyboardInterrupt:
        return 130
    print()
    print(natprobe.format_report(rep))
    if cfg.db_path.exists():  # an agent is recording here: keep the result next to its data
        from whydrop.agent.store import Store

        async def save():
            store = Store(cfg.db_path)
            await store.open()
            try:
                await natprobe.store_report(store, rep, start_ms=start_ms, end_ms=int(time.time() * 1000))
            finally:
                await store.close()
        asyncio.run(save())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="whydrop")
    parser.add_argument("--version", action="version", version=f"whydrop {__version__}")
    sub = parser.add_subparsers(dest="cmd")
    r = sub.add_parser("reflector", help="run the UDP+TCP reflector (needs WHYDROP_SECRET)")
    r.add_argument("--host", default="0.0.0.0")
    r.add_argument("--port", type=int, default=48100)
    r.add_argument("--state-dir", type=Path, default=Path("./whydrop-state"))
    r.add_argument("--enable-7500", action="store_true", help="allow the 7500 s TCP nat-test delay")
    a = sub.add_parser("agent", help="record your connection (basic mode needs no secret)")
    a.add_argument("--config", type=Path, default=None, help="TOML file (default: ./whydrop.toml if present)")
    n = sub.add_parser("nat-test", help="measure how long the path keeps idle UDP/TCP state (needs a reflector)")
    n.add_argument("--config", type=Path, default=None)
    only = n.add_mutually_exclusive_group()
    only.add_argument("--udp-only", action="store_true")
    only.add_argument("--tcp-only", action="store_true")
    n.add_argument("--max-delay", type=int, default=3600, help="skip delays longer than this (seconds)")
    n.add_argument("--enable-7500", action="store_true", help="also test 7500 s TCP (reflector must allow it)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:  # argparse exits for --version/--help/errors; main returns the code instead
        return e.code if isinstance(e.code, int) else 1
    if args.cmd == "reflector":
        return _reflector(args)
    if args.cmd == "agent":
        return _agent(args)
    if args.cmd == "nat-test":
        return _nat_test(args)
    parser.print_help()
    return 0
