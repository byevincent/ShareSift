r"""v0.25: visualise the harness MIN trajectory across releases.

Reads ``benchmarks/v0p22_eval/harness_history.jsonl`` and emits a
text-mode chart to stdout. No matplotlib dep, no PNG, no JS.

Each row is one release: two horizontal bars side by side, one for
MIN top-10 precision and one for MIN recall across primary held-out
sets.

Sample::

    ShareSift harness MIN trajectory
    ================================
                  MIN top-10         MIN recall
    v0.22.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
    v0.23.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
    v0.24.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
    v0.25.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90

Both axes are 0..1 over 10 cells. A change between releases is
visible immediately — drops, climbs, or flat lines.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_BAR_FILL = "▇"
_BAR_EMPTY = "░"
_BAR_WIDTH = 10


def _bar(fraction: float) -> str:
    fraction = max(0.0, min(1.0, fraction))
    filled = round(fraction * _BAR_WIDTH)
    return _BAR_FILL * filled + _BAR_EMPTY * (_BAR_WIDTH - filled)


def _load(history_path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in history_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def render(rows: list[dict]) -> str:
    if not rows:
        return "(no harness history yet)\n"
    label_width = max(len(r.get("version", "")) for r in rows)
    out_lines = [
        "ShareSift harness MIN trajectory",
        "================================",
        f"{' ':<{label_width}}     MIN top-10         MIN recall",
    ]
    for r in rows:
        version = r.get("version", "?")
        top10 = float(r.get("min_top_10_precision_across_primary") or 0.0)
        recall = float(r.get("min_recall_across_primary") or 0.0)
        out_lines.append(
            f"{version:<{label_width}}     "
            f"{_bar(top10)} {top10:.2f}     "
            f"{_bar(recall)} {recall:.2f}"
        )
    return "\n".join(out_lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--history",
        type=Path,
        default=REPO_ROOT / "benchmarks" / "v0p22_eval" / "harness_history.jsonl",
    )
    args = p.parse_args(argv)

    if not args.history.exists():
        print(f"no history file at {args.history}", file=sys.stderr)
        return 1

    rows = _load(args.history)
    sys.stdout.write(render(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
