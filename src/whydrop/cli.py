import argparse

from whydrop import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="whydrop")
    parser.add_argument("--version", action="version", version=f"whydrop {__version__}")
    try:
        parser.parse_args(argv)  # subcommands are added by later tasks
    except SystemExit as e:  # argparse exits for --version/--help/errors; main returns the code instead
        return e.code if isinstance(e.code, int) else 1
    return 0
