import argparse

from signaltrace import __version__


def main() -> None:
    parser = argparse.ArgumentParser(prog="signaltrace")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.parse_args()
