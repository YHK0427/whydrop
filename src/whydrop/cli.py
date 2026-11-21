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
    udp = () if args.tcp_only else natprobe.UDP_DELAYS
    tcp_all = natprobe.TCP_DELAYS + ((7500,) if args.enable_7500 else ())
    max_delay = args.max_delay if args.max_delay is not None else (7500 if args.enable_7500 else 3600)
    udp = tuple(d for d in udp if d <= max_delay)
    tcp = () if args.udp_only else tuple(d for d in tcp_all if d <= max_delay)
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
    refused = {r.detail.get("reason") for r in rep.tcp} & {"auth_fail", "version", "busy"}
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
    if refused:
        print(f"whydrop: the reflector refused the TCP test ({', '.join(sorted(refused))}); "
              "check WHYDROP_SECRET and the reflector version", file=sys.stderr)
        return 1
    return 0


def _iso_ms(text: str | None) -> int | None:
    from datetime import datetime
    if text is None:
        return None
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.astimezone()  # local time, like the dashboard shows
    return int(dt.timestamp() * 1000)


def _replay(args: argparse.Namespace) -> int:
    import json
    from datetime import datetime

    from whydrop.analysis import constants
    from whydrop.analysis.replay import replay, summary

    if not args.db.exists():
        print(f"whydrop: no such database: {args.db}", file=sys.stderr)
        return 2
    for item in args.set or []:
        name, _, value = item.partition("=")
        try:
            constants.override(name, value)
        except (KeyError, ValueError) as e:
            print(f"whydrop: --set {item}: {e}", file=sys.stderr)
            return 2
    rows = summary(replay(args.db, _iso_ms(args.from_), _iso_ms(args.to)))
    if args.json:
        print(json.dumps(rows, indent=1))
    else:
        for r in rows:
            start = datetime.fromtimestamp(r["start_ms"] / 1000).isoformat(timespec="seconds")
            secs = (r["end_ms"] - r["start_ms"]) / 1000 if r["end_ms"] else 0
            print(f"{start}  {secs:7.1f} s  {r['cause']:<4} {r['label']}")
        print(f"{len(rows)} incident(s); replay is approximate (1 s aggregates and events)")
    return 0


def _annotate(args: argparse.Namespace) -> int:
    from whydrop.agent.config import ConfigError, load_config
    from whydrop.agent.store import Store

    path = args.config or (Path("whydrop.toml") if Path("whydrop.toml").exists() else None)
    try:
        cfg = load_config(path, os.environ)
        start, end = _iso_ms(args.start), _iso_ms(args.end)
    except (ConfigError, ValueError) as e:
        print(f"whydrop: {e}", file=sys.stderr)
        return 2
    if not cfg.db_path.exists():
        print(f"whydrop: no database at {cfg.db_path} (is db_path right?)", file=sys.stderr)
        return 2
    if end is not None and end < start:
        print("whydrop: --end is before --start", file=sys.stderr)
        return 2

    async def save():
        store = Store(cfg.db_path)
        await store.open()
        try:
            await store.insert("annotations", start_ms=start, end_ms=end, label=args.label, note=args.note)
        finally:
            await store.close()
    asyncio.run(save())
    print(f"annotated {args.label} from {args.start}" + (f" to {args.end}" if args.end else ""))
    return 0


def _export_static(args: argparse.Namespace) -> int:
    try:
        from whydrop.web.static_export import export_static
    except ImportError:
        print("whydrop: export-static needs the web extra: pip install 'whydrop[web]'", file=sys.stderr)
        return 2
    if not args.db.exists():
        print(f"whydrop: no such database: {args.db}", file=sys.stderr)
        return 2
    try:
        m = export_static(args.db, args.out, _iso_ms(args.from_), _iso_ms(args.to), {"mode": args.mode})
    except FileExistsError as e:
        print(f"whydrop: {e}; choose an empty or new --out", file=sys.stderr)
        return 2
    except OSError as e:   # --out is a file, a link, unwritable…
        print(f"whydrop: can't write {args.out}: {e.strerror or e}", file=sys.stderr)
        return 2
    print(f"wrote {m['files']} data files to {args.out} (public view, read-only)")
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
    n.add_argument("--max-delay", type=int, default=None, help="skip delays longer than this (seconds)")
    n.add_argument("--enable-7500", action="store_true", help="also test 7500 s TCP (reflector must allow it)")
    rp = sub.add_parser("replay", help="re-run the analysis over a recorded database (approximate)")
    rp.add_argument("db", type=Path)
    rp.add_argument("--from", dest="from_", default=None, help="ISO time")
    rp.add_argument("--to", default=None, help="ISO time")
    rp.add_argument("--set", action="append", metavar="NAME=VALUE", help="override an analysis constant")
    rp.add_argument("--json", action="store_true")
    an = sub.add_parser("annotate", help="label a scene (reproduced / injected / user-test)")
    an.add_argument("--config", type=Path, default=None)
    an.add_argument("--label", required=True, choices=("reproduced", "injected", "user-test"))
    an.add_argument("--start", required=True, help="ISO time; add the offset (e.g. +09:00) inside containers")
    an.add_argument("--end", default=None, help="ISO time")
    an.add_argument("--note", default=None)
    ex = sub.add_parser("export-static", help="write a read-only public demo of the dashboard (for GitHub Pages)")
    ex.add_argument("db", type=Path)
    ex.add_argument("--out", type=Path, default=Path("site"))
    ex.add_argument("--from", dest="from_", default=None, help="ISO time (only shown as the recorded date range)")
    ex.add_argument("--to", default=None, help="ISO time; data is shown relative to it")
    ex.add_argument("--mode", choices=("basic", "precision"), default="basic")
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
    if args.cmd == "export-static":
        return _export_static(args)
    if args.cmd == "replay":
        return _replay(args)
    if args.cmd == "annotate":
        return _annotate(args)
    parser.print_help()
    return 0
