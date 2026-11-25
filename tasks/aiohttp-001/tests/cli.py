"""Command-line interface for the Dojo Vulhub hard-oracle grader."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

try:
    from .grader import grade_files, write_metrics
except ImportError:
    from grader import grade_files, write_metrics


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--oracle-result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Runs the grader and always emits a Harbor reward file."""
    parsed = parse_arguments(arguments)
    metrics = grade_files(
        parsed.contract,
        parsed.submission,
        parsed.oracle_result,
    )
    write_metrics(parsed.output, metrics)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
