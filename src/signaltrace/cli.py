import argparse

from signaltrace import __version__
from signaltrace.generator import generate_dataset


def main() -> None:
    parser = argparse.ArgumentParser(prog="signaltrace")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")
    generate_parser = subparsers.add_parser(
        "generate",
        help="generate a sample authentication log",
    )
    generate_parser.add_argument("--out", default="data/sample.jsonl")
    generate_parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.command == "generate":
        generate_dataset(args.out, args.seed)
