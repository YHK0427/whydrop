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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="whydrop")
    parser.add_argument("--version", action="version", version=f"whydrop {__version__}")
    sub = parser.add_subparsers(dest="cmd")
    r = sub.add_parser("reflector", help="run the UDP+TCP reflector (needs WHYDROP_SECRET)")
    r.add_argument("--host", default="0.0.0.0")
    r.add_argument("--port", type=int, default=48100)
    r.add_argument("--state-dir", type=Path, default=Path("./whydrop-state"))
    r.add_argument("--enable-7500", action="store_true", help="allow the 7500 s TCP nat-test delay")
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:  # argparse exits for --version/--help/errors; main returns the code instead
        return e.code if isinstance(e.code, int) else 1
    if args.cmd == "reflector":
        return _reflector(args)
    parser.print_help()
    return 0
