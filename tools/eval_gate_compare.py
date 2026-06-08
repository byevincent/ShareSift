"""Eval-gate comparison helper — used by .github/workflows/eval_gate.yml.

Reads two harness_results.json files (previous release tag's baseline
and this commit's result) and exits non-zero if either MIN regresses.

Lives as a separate script (not inline in the workflow YAML) because
embedding multi-line Python inside a YAML ``run: |`` block requires
careful indentation that breaks easily on edit. Standalone script
also gets tested.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_EPS = 1e-6


def _read_min_metrics(path: Path) -> tuple[float, float]:
    """Return (min_top_10, min_recall) from a harness results JSON file."""
    if not path.exists():
        return (0.0, 0.0)
    data = json.loads(path.read_text(encoding="utf-8") or "{}")
    headline = data.get("headline", {})
    top10 = headline.get("min_top_10_precision_across_primary") or 0.0
    recall = headline.get("min_recall_across_primary") or 0.0
    return (float(top10), float(recall))


def compare(prev_path: Path, new_path: Path) -> int:
    """Return exit code: 0 if no regression, 1 if either MIN dropped."""
    prev_top10, prev_recall = _read_min_metrics(prev_path)
    new_top10, new_recall = _read_min_metrics(new_path)

    print(f"Previous baseline: MIN top-10 = {prev_top10}  MIN recall = {prev_recall}")
    print(f"This commit:       MIN top-10 = {new_top10}  MIN recall = {new_recall}")

    failed = False
    if new_top10 + _EPS < prev_top10:
        print(f"::error::MIN top-10 precision regressed: {prev_top10} -> {new_top10}")
        failed = True
    if new_recall + _EPS < prev_recall:
        print(f"::error::MIN recall regressed: {prev_recall} -> {new_recall}")
        failed = True
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--previous", type=Path, required=True,
                   help="Previous baseline harness_results.json")
    p.add_argument("--current", type=Path, required=True,
                   help="This commit's harness_results.json")
    args = p.parse_args(argv)
    return compare(args.previous, args.current)


if __name__ == "__main__":
    raise SystemExit(main())
