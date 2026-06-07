"""Ingest raw LLM paste-dumps into ``data/synthetic/raw/`` JSONL.

Vincent generates synthetic training data by pasting a mega-prompt into
ChatGPT, DeepSeek, and Qwen, then copying each model's JSONL-shaped
output into ``data/synthetic/paste/{model}{N}.txt`` (one file per model
per pass). This module reads those paste-dumps and converts them to
normalized JSONL at ``data/synthetic/raw/{model}_pass{N}.jsonl`` for
the post-processor (`postprocess.py`) to consume.

Why this module exists separately from the post-processor:

* The three models emit JSONL in subtly different escape styles.
  ChatGPT emits invalid-JSON (lone ``\\S``); Qwen and DeepSeek emit
  proper JSON (``\\\\S``). A single regex extractor that ignores escape
  rules round-trips ChatGPT correctly by accident, but double-escapes
  Qwen/DeepSeek into malformed 4-leading-backslash UNCs. The fix is
  to try ``json.loads`` first (catches Qwen/DeepSeek correctly) and
  fall back to a tolerant regex for ChatGPT's invalid-escape style.
* A ``normalize_path`` safety net halves the backslash count of any
  already-over-escaped path (4-leading-backslash signature) — preserved
  here because the post-processor pipeline runs on the JSONL this
  module writes, so any escape-level bugs that creep in later get
  caught at the same boundary.

Parser-bug discovery: passes 1-5 silently emitted 893/1351 broken paths
(66%) before this fix landed. Backup of pre-fix raw at
``/tmp/raw_backup_before_fix`` at time of fix (2026-05-28).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_MODELS: tuple[str, ...] = ("chatgpt", "deepseek", "qwen")

# Tolerant fallback: greedy ``[^"]+`` for path, ``[^"]*`` for why
# (allows empty — schema validation in the post-processor drops empty
# whys; the parser preserves them so the count of generator regressions
# stays visible).
_LINE_RE = re.compile(
    r'\{\s*"path"\s*:\s*"([^"]+)"\s*,\s*"juicy"\s*:\s*(true|false)\s*,\s*"why"\s*:\s*"([^"]*)"\s*\}'
)


def normalize_path(p: str) -> str:
    """Halve consecutive backslash runs on over-escaped UNC paths.

    A correctly-formed UNC starts with exactly 2 backslashes. If we see
    4 leading backslashes, the value was over-escaped during prior
    round-tripping; halve every ``\\\\`` pair to recover the canonical
    form. No-op on correctly-formed paths and on Linux paths.
    """
    if p.startswith("\\\\\\\\"):
        return p.replace("\\\\", "\\")
    return p


def parse_line(line: str) -> dict | None:
    """Parse one raw JSONL line into a normalized record dict.

    Returns ``None`` for empty lines, ``//``-prefixed comments
    (``// BATCH N`` markers), and lines that don't match either the
    strict JSON or tolerant regex form. Lines with empty ``why`` are
    returned as-is — the post-processor's schema validator is the
    boundary that drops them.
    """
    line = line.strip()
    if not line or line.startswith("//"):
        return None
    try:
        rec = json.loads(line)
        if "path" in rec and "juicy" in rec:
            return {
                "path": normalize_path(rec["path"]),
                "juicy": bool(rec["juicy"]),
                "why": rec.get("why", "") or "",
            }
    except (json.JSONDecodeError, KeyError, TypeError):
        pass
    m = _LINE_RE.search(line)
    if not m:
        return None
    return {
        "path": normalize_path(m.group(1)),
        "juicy": m.group(2) == "true",
        "why": m.group(3),
    }


def parse_file(src: Path) -> list[dict]:
    recs: list[dict] = []
    with src.open() as f:
        for line in f:
            r = parse_line(line)
            if r is not None:
                recs.append(r)
    return recs


def write_jsonl(dst: Path, recs: list[dict]) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")


def ingest_pass(pass_n: int, paste_dir: Path, raw_dir: Path) -> dict[str, int]:
    """Read ``{paste_dir}/{model}{N}.txt`` for each model and write
    ``{raw_dir}/{model}_pass{N}.jsonl``. Returns per-model record counts.

    Missing model files are skipped with a warning (some passes may
    intentionally be partial). Other I/O errors propagate.
    """
    results: dict[str, int] = {}
    for model in _MODELS:
        src = paste_dir / f"{model}{pass_n}.txt"
        dst = raw_dir / f"{model}_pass{pass_n}.jsonl"
        if not src.exists():
            print(f"SKIP {model}: no file at {src}", file=sys.stderr)
            results[model] = 0
            continue
        recs = parse_file(src)
        write_jsonl(dst, recs)
        results[model] = len(recs)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Ingest paste-dumps from data/synthetic/paste/{model}{N}.txt "
            "into data/synthetic/raw/{model}_pass{N}.jsonl."
        )
    )
    parser.add_argument(
        "--pass",
        dest="pass_n",
        type=int,
        required=True,
        help="Pass number (positive integer).",
    )
    parser.add_argument(
        "--paste-dir",
        type=Path,
        default=Path("data/synthetic/paste"),
        help="Directory containing {model}{N}.txt files.",
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=Path("data/synthetic/raw"),
        help="Output directory for {model}_pass{N}.jsonl files.",
    )
    args = parser.parse_args(argv)

    if args.pass_n < 1:
        parser.error("--pass must be a positive integer")

    counts = ingest_pass(args.pass_n, args.paste_dir, args.raw_dir)
    total = sum(counts.values())
    for model, n in counts.items():
        print(f"pass {args.pass_n} {model}: {n} records")
    print(f"total: {total} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
