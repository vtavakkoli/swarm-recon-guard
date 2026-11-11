"""Backward-compatible entry point for complete reviewer evidence packaging.

Unlike the previous implementation, this fails rather than packaging partial
results or a run labeled with a contradictory Docker/Git source revision.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from swarmguard.experiment.publication import finalize


def package(run_dir: Path, output: Path) -> str:
    """Reconstruct all reviewer control outputs and return SHA-256 of the ZIP."""
    return finalize(run_dir, output)["sha256"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--prefixes", default="30,300")
    args = parser.parse_args()
    prefixes = tuple(sorted(set(int(v) for v in args.prefixes.split(",") if v.strip())))
    if not prefixes or min(prefixes) < 1:
        parser.error("all event-prefix budgets must be positive")
    result = finalize(args.run_dir, args.output, prefixes=prefixes)
    print(f"{args.output} SHA256 {result['sha256']}")


if __name__ == "__main__":
    main()
